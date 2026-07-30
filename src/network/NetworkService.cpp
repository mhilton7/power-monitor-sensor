#include "network/NetworkService.h"

#include <algorithm>

#include <Arduino.h>
#include <ESP.h>
#include <ESPmDNS.h>
#include <WiFi.h>
#include <esp_sntp.h>

#include "build_config.h"
#include "diagnostics/DiagnosticCore.h"
#include "diagnostics/SerialLogger.h"
#include "network/NetworkPolicy.h"
#include "security/Crypto.h"
#include "version.h"

namespace pm {
namespace {

constexpr std::uint32_t kMinimumStationAttemptMs = 15'000U;
constexpr std::uint32_t kNtpRetryInitialMs = 30'000U;
constexpr std::uint32_t kNtpRetryMaximumMs = 300'000U;

std::string identitySuffix(const DeviceIdentity &identity) {
  if (identity.hardware_id.empty())
    return "sensor";
  return identity.hardware_id.size() <= 6U
             ? identity.hardware_id
             : identity.hardware_id.substr(identity.hardware_id.size() - 6U);
}

} // namespace

NetworkService::NetworkService(ConfigService &config, ClockService &clock)
    : config_(config), clock_(clock) {}

bool NetworkService::begin() {
  status_mutex_ = xSemaphoreCreateRecursiveMutex();
  if (status_mutex_ == nullptr) {
    PM_LOG_FATAL("NETWORK", "STATUS_MUTEX_CREATE_FAILED",
                 "error=PM-NETWORK-001");
    return false;
  }
  if (!lockStatus(pdMS_TO_TICKS(100))) {
    PM_LOG_FATAL("NETWORK", "STATUS_MUTEX_LOCK_FAILED",
                 "error=PM-NETWORK-002 phase=begin");
    return false;
  }
  PM_LOG_INFO("WIFI", "WIFI_INIT_BEGIN",
              "persistent=false auto_reconnect=false sleep=false "
              "reason=always_on_network_service");
  WiFi.persistent(false);
  WiFi.setAutoReconnect(false);
  // This is an always-on monitoring appliance. ESP32 station power saving can
  // add multi-second receive latency under concurrent TLS and AsyncTCP load,
  // which in turn makes local health checks look hung while a server request is
  // active. Keep the radio awake so the WebUI and ICMP remain responsive.
  WiFi.setSleep(false);
  WiFi.onEvent([this](const arduino_event_id_t event,
                      const arduino_event_info_t info) {
    switch (event) {
    case ARDUINO_EVENT_WIFI_STA_START:
      PM_LOG_DEBUG("WIFI", "STATION_STARTED", "driver=ready");
      break;
    case ARDUINO_EVENT_WIFI_STA_CONNECTED:
      PM_LOG_INFO("WIFI", "ASSOCIATED", "ssid=configured bssid=%s channel=%d",
                  diag::maskMac(std::string(WiFi.BSSIDstr().c_str())).c_str(),
                  WiFi.channel());
      break;
    case ARDUINO_EVENT_WIFI_STA_GOT_IP:
      PM_LOG_INFO("DHCP", "IP_ACQUIRED", "ip=%s gateway=%s subnet=%s dns=%s",
                  WiFi.localIP().toString().c_str(),
                  WiFi.gatewayIP().toString().c_str(),
                  WiFi.subnetMask().toString().c_str(),
                  WiFi.dnsIP().toString().c_str());
      break;
    case ARDUINO_EVENT_WIFI_STA_DISCONNECTED: {
      const std::uint16_t reason = info.wifi_sta_disconnected.reason;
      last_disconnect_reason_.store(reason, std::memory_order_relaxed);
      const diag::ReasonInfo translated = diag::wifiDisconnectReason(reason);
      PM_LOG_ERROR_CODE("WIFI", "DISCONNECTED", reason,
                        "error=%s reason=%s numeric=%u explanation=%s hint=%s",
                        translated.error_code, translated.name,
                        static_cast<unsigned>(reason), translated.explanation,
                        translated.hint[0] == '\0' ? "retry_with_backoff"
                                                   : translated.hint);
      break;
    }
    case ARDUINO_EVENT_WIFI_AP_START:
      PM_LOG_INFO("WIFI", "SETUP_AP_DRIVER_STARTED",
                  "channel=1 client_limit=4");
      break;
    case ARDUINO_EVENT_WIFI_AP_STOP:
      PM_LOG_INFO("WIFI", "SETUP_AP_DRIVER_STOPPED", "result=success");
      break;
    case ARDUINO_EVENT_WIFI_AP_STACONNECTED:
      PM_LOG_INFO("WIFI", "SETUP_CLIENT_JOINED", "client_identity=redacted");
      break;
    case ARDUINO_EVENT_WIFI_AP_STADISCONNECTED:
      PM_LOG_INFO("WIFI", "SETUP_CLIENT_LEFT", "client_identity=redacted");
      break;
    default:
      PM_LOG_TRACE("WIFI", "DRIVER_EVENT", "numeric=%d",
                   static_cast<int>(event));
      break;
    }
  });
  status_.hostname = config_.config().hostname + ".local";
  if (config_.hasWifiCredentials()) {
    transition(Phase::Idle, "credentials_present");
    connectStation();
  } else {
    transition(Phase::Unconfigured, "credentials_missing");
    startSetupAp();
  }
  PM_LOG_INFO("WIFI", "WIFI_INIT_COMPLETE", "station_configured=%s setup_ap=%s",
              config_.hasWifiCredentials() ? "true" : "false",
              status_.setup_ap_active ? "active" : "inactive");
  unlockStatus();
  return true;
}

void NetworkService::update() {
  clock_.update();
  if (!lockStatus(pdMS_TO_TICKS(100))) {
    if (diag::SerialLogger::instance().allow("network_status_lock", 60'000U)) {
      PM_LOG_ERROR("NETWORK", "STATUS_MUTEX_TIMEOUT",
                   "error=PM-NETWORK-002 phase=update timeout_ms=100");
    }
    return;
  }
  status_.time_synchronized = clock_.synchronized();
  const std::uint64_t now = clock_.monotonicMs();
  if (setup_activity_requested_.exchange(false, std::memory_order_acq_rel)) {
    setup_last_activity_ms_ = now;
  }
  if (setup_ap_restart_requested_.exchange(false, std::memory_order_acq_rel)) {
    setup_ap_restart_pending_ = true;
    startSetupAp();
    unlockStatus();
    return;
  }
  if (next_setup_ap_start_ms_ != 0U && now >= next_setup_ap_start_ms_ &&
      (setup_ap_restart_pending_ ||
       (!status_.setup_ap_active && !status_.station_connected))) {
    startSetupAp();
    unlockStatus();
    return;
  }
  const std::uint32_t server_generation =
      server_status_generation_.load(std::memory_order_acquire);
  if (server_generation != observed_server_status_generation_) {
    observed_server_status_generation_ = server_generation;
    status_.server_reachable =
        pending_server_reachable_.load(std::memory_order_relaxed);
    status_.server_authenticated =
        pending_server_authenticated_.load(std::memory_order_relaxed);
    if (status_.station_connected && clock_.synchronized()) {
      transition(status_.server_authenticated
                     ? Phase::Online
                     : (status_.server_reachable ? Phase::ServerValidation
                                                 : Phase::Degraded),
                 status_.server_authenticated
                     ? "server_authenticated"
                     : (status_.server_reachable ? "server_reachable"
                                                 : "server_unreachable"));
    }
  }
  updateScan();
  const std::uint32_t requested_generation =
      configuration_apply_generation_.load(std::memory_order_acquire);
  if (requested_generation != observed_configuration_generation_) {
    observed_configuration_generation_ = requested_generation;
    configuration_apply_at_ms_ =
        now + configuration_apply_delay_ms_.load(std::memory_order_relaxed);
  }
  if (configuration_apply_at_ms_ != 0 && now >= configuration_apply_at_ms_) {
    configuration_apply_at_ms_ = 0;
    applyConfiguration();
    // applyConfiguration/connectStation captures a newer monotonic timestamp.
    // Finish this iteration so no elapsed-time calculation can subtract that
    // future value from the stale `now` snapshot above.
    unlockStatus();
    return;
  }
  const bool connected = WiFi.status() == WL_CONNECTED;
  if (connected && !status_.station_connected) {
    onConnected();
  } else if (!connected && status_.station_connected) {
    status_.station_connected = false;
    status_.mdns_active = false;
    status_.server_reachable = false;
    status_.server_authenticated = false;
    MDNS.end();
    PM_LOG_WARN("MDNS", "MDNS_STOPPED", "reason=wifi_disconnected");
    transition(Phase::RetryWait, "station_disconnected");
    next_reconnect_ms_ = now + 1000U;
  }
  if (!connected && config_.hasWifiCredentials() && now >= next_reconnect_ms_) {
    ++status_.reconnect_count;
    connectStation();
  }
  const bool has_wifi_credentials = config_.hasWifiCredentials();
  const wl_status_t station_status = WiFi.status();
  const std::uint16_t disconnect_reason =
      last_disconnect_reason_.load(std::memory_order_relaxed);
  if (!connected && network_policy::shouldStartCredentialRecoveryAp(
                        has_wifi_credentials, status_.setup_ap_active, now,
                        station_connect_started_ms_, next_setup_recovery_ms_,
                        disconnect_reason, static_cast<int>(station_status))) {
    next_setup_recovery_ms_ = now + 300'000U;
    PM_LOG_WARN(
        "WIFI", "CREDENTIAL_RECOVERY_REQUIRED",
        "error=PM-WIFI-003 elapsed_ms=%llu status=%d status_name=%s "
        "disconnect_reason=%u recovery_ap=starting credentials_erased=false",
        static_cast<unsigned long long>(now - station_connect_started_ms_),
        static_cast<int>(station_status),
        diag::wifiStatusName(static_cast<int>(station_status)),
        static_cast<unsigned>(disconnect_reason));
    startSetupAp();
  } else if (!connected && has_wifi_credentials &&
             network_policy::elapsedAtLeast(now, station_connect_started_ms_,
                                            60'000U) &&
             diag::SerialLogger::instance().allow(
                 "station_unavailable_no_setup_ap", 60'000U)) {
    PM_LOG_WARN(
        "WIFI", "STATION_CONNECT_TIMEOUT",
        "error=PM-WIFI-006 elapsed_ms=%llu status=%d status_name=%s "
        "disconnect_reason=%u recovery_ap=not_started credentials_erased=false "
        "reason=credentials_not_proven_invalid",
        static_cast<unsigned long long>(now - station_connect_started_ms_),
        static_cast<int>(station_status),
        diag::wifiStatusName(static_cast<int>(station_status)),
        static_cast<unsigned>(disconnect_reason));
  }
  if (connected) {
    status_.rssi_dbm = WiFi.RSSI();
    const std::string current_ip = WiFi.localIP().toString().c_str();
    if (!status_.ip_address.empty() && current_ip != status_.ip_address) {
      status_.last_ip_address = status_.ip_address;
      ip_changed_ = true;
    }
    status_.ip_address = current_ip;
  }
  if (status_.setup_ap_active && config_.hasWifiCredentials() &&
      now >= setup_last_activity_ms_ &&
      now - setup_last_activity_ms_ >
          static_cast<std::uint64_t>(build::SETUP_AP_TTL_SECONDS) * 1000U) {
    stopSetupAp();
    next_setup_recovery_ms_ = now + 300'000U;
  }
  if (status_.setup_ap_active) {
    dns_server_.processNextRequest();
    if (setup_ready_serial_pending_ && now >= next_setup_ready_serial_ms_) {
      const std::string setup_ssid =
          "PowerMonitor-Setup-" + identitySuffix(config_.identity());
      setup_ready_serial_pending_ =
          !diag::SerialLogger::instance().writeSetupReady(setup_ssid.c_str());
      next_setup_ready_serial_ms_ = now + 1000U;
    }
  }
  if (connected && !clock_.synchronized() && now >= next_ntp_retry_ms_) {
    const auto ntp = config_.config().ntp_servers;
    const std::uint32_t exponent = std::min<std::uint32_t>(ntp_attempt_, 4U);
    const std::uint32_t retry_ms = std::min<std::uint32_t>(
        kNtpRetryInitialMs << exponent, kNtpRetryMaximumMs);
    ++ntp_attempt_;
    PM_LOG_WARN("TIME", "NTP_RETRY",
                "error=PM-TIME-002 attempt=%lu previous_timeout_ms=%lu "
                "next_retry_ms=%lu servers=3",
                static_cast<unsigned long>(ntp_attempt_),
                static_cast<unsigned long>(
                    next_ntp_retry_ms_ == 0 ? 0 : kNtpRetryInitialMs),
                static_cast<unsigned long>(retry_ms));
    configureNtp(ntp);
    next_ntp_retry_ms_ = now + retry_ms;
    transition(Phase::TimeSync, "ntp_retry");
  } else if (connected && clock_.synchronized() &&
             (phase_ == Phase::TimeSync || phase_ == Phase::Connected)) {
    transition(Phase::ServerValidation, "trusted_time_ready");
  }
  unlockStatus();
}

void NetworkService::touchSetupActivity() {
  setup_activity_requested_.store(true, std::memory_order_release);
}

void NetworkService::applyConfiguration() {
  const RuntimeConfig active_config = config_.config();
  PM_LOG_INFO("WIFI", "CONFIG_APPLY_BEGIN",
              "ssid=%s static_ipv4=%s recovery_timeout_ms=60000 "
              "credentials_erased=false",
              diag::maskSsid(active_config.wifi_ssid).c_str(),
              active_config.static_network_enabled ? "true" : "false");
  if (status_.setup_ap_active && config_.hasWifiCredentials()) {
    stopSetupAp();
  }
  if (status_.mdns_active) {
    MDNS.end();
    status_.mdns_active = false;
    PM_LOG_INFO("MDNS", "MDNS_STOPPED", "reason=configuration_changed");
  }
  status_.hostname = active_config.hostname + ".local";
  WiFi.disconnect(false, false);
  status_.station_connected = false;
  status_.server_reachable = false;
  status_.server_authenticated = false;
  station_connect_started_ms_ = 0;
  next_reconnect_ms_ = 0;
  next_setup_recovery_ms_ = 0;
  backoff_attempt_ = 0;
  last_disconnect_reason_.store(0, std::memory_order_release);
  if (!config_.hasWifiCredentials()) {
    if (!status_.setup_ap_active)
      startSetupAp();
    return;
  }
  connectStation();
}

void NetworkService::requestConfigurationApply(const std::uint32_t delay_ms) {
  configuration_apply_delay_ms_.store(delay_ms, std::memory_order_relaxed);
  configuration_apply_generation_.fetch_add(1, std::memory_order_release);
}

void NetworkService::requestSetupApRestart() {
  setup_ap_restart_requested_.store(true, std::memory_order_release);
}

void NetworkService::requestScan() {
  scan_requested_.store(true, std::memory_order_release);
}

NetworkStatus NetworkService::status() const {
  if (!lockStatus(pdMS_TO_TICKS(100))) {
    PM_LOG_ERROR("NETWORK", "STATUS_MUTEX_TIMEOUT",
                 "error=PM-NETWORK-002 phase=snapshot timeout_ms=100");
    return {};
  }
  const NetworkStatus snapshot = status_;
  unlockStatus();
  return snapshot;
}

bool NetworkService::ipChangedSinceHeartbeat() {
  return ip_changed_.exchange(false, std::memory_order_acq_rel);
}

void NetworkService::setServerStatus(const bool reachable,
                                     const bool authenticated) {
  pending_server_reachable_.store(reachable, std::memory_order_relaxed);
  pending_server_authenticated_.store(authenticated, std::memory_order_relaxed);
  server_status_generation_.fetch_add(1, std::memory_order_release);
}

bool NetworkService::startSetupAp() {
  const std::string suffix = identitySuffix(config_.identity());
  const std::string ssid = "PowerMonitor-Setup-" + suffix;
  std::string new_password = config_.ensureSetupPassword();
  if (new_password.empty()) {
    PM_LOG_ERROR("WIFI", "SETUP_AP_PASSWORD_UNAVAILABLE",
                 "error=PM-WIFI-011 recovery=retry_in_1000_ms "
                 "open_access_point=false");
    next_setup_ap_start_ms_ = clock_.monotonicMs() + 1000U;
    transition(Phase::Failed, "setup_credential_unavailable");
    return false;
  }
  if (status_.setup_ap_active) {
    stopSetupAp();
  }
  if (config_.setupPasswordNew()) {
    PM_LOG_WARN("WIFI", "SETUP_CREDENTIAL_CREATED",
                "ssid=%s result=generated secret_logged=false "
                "action=set_password_over_usb",
                ssid.c_str());
  }
  transition(Phase::Provisioning, "recovery_ap_requested");
  WiFi.mode(WIFI_AP_STA);
  status_.setup_ap_active =
      WiFi.softAP(ssid.c_str(), new_password.c_str(), 1, false, 4);
  std::fill(new_password.begin(), new_password.end(), '\0');
  new_password.clear();
  if (status_.setup_ap_active) {
    next_setup_ap_start_ms_ = 0;
    setup_ap_restart_pending_ = false;
    dns_server_.start(53, "*", WiFi.softAPIP());
    setup_ready_serial_pending_ =
        !diag::SerialLogger::instance().writeSetupReady(ssid.c_str());
    next_setup_ready_serial_ms_ = clock_.monotonicMs() + 1000U;
    PM_LOG_INFO("SECURITY", "SETUP_AP_CONTROL_STATUS",
                "ready_event_written=%s secret_logged=false",
                setup_ready_serial_pending_ ? "false" : "true");
    PM_LOG_INFO("DNS", "CAPTIVE_DNS_STARTED",
                "address=%s port=53 wildcard=true",
                WiFi.softAPIP().toString().c_str());
  } else {
    PM_LOG_ERROR("WIFI", "SETUP_AP_START_FAILED", "error=PM-WIFI-007");
    next_setup_ap_start_ms_ = clock_.monotonicMs() + 5000U;
    transition(Phase::Failed, "setup_ap_failed");
  }
  setup_last_activity_ms_ = clock_.monotonicMs();
  return status_.setup_ap_active;
}

void NetworkService::stopSetupAp() {
  dns_server_.stop();
  WiFi.softAPdisconnect(true);
  status_.setup_ap_active = false;
  setup_ready_serial_pending_ = false;
  next_setup_ready_serial_ms_ = 0;
  PM_LOG_INFO("DNS", "CAPTIVE_DNS_STOPPED", "result=success");
  if (WiFi.status() == WL_CONNECTED) {
    WiFi.mode(WIFI_STA);
    transition(connectedPhase(), "recovery_ap_stopped");
  }
}

void NetworkService::connectStation() {
  const RuntimeConfig active_config = config_.config();
  transition(Phase::Connecting, "connection_attempt");
  WiFi.mode(status_.setup_ap_active ? WIFI_AP_STA : WIFI_STA);
  WiFi.setHostname(active_config.hostname.c_str());
  if (active_config.static_network_enabled) {
    IPAddress address;
    IPAddress gateway;
    IPAddress subnet;
    IPAddress dns;
    address.fromString(active_config.static_ip.c_str());
    gateway.fromString(active_config.static_gateway.c_str());
    subnet.fromString(active_config.static_subnet.c_str());
    dns.fromString(active_config.static_dns.c_str());
    if (!WiFi.config(address, gateway, subnet, dns)) {
      PM_LOG_ERROR("DHCP", "STATIC_CONFIG_REJECTED", "error=PM-WIFI-008");
    } else {
      PM_LOG_INFO("DHCP", "STATIC_CONFIG_APPLIED",
                  "ip=%s gateway=%s subnet=%s dns=%s",
                  address.toString().c_str(), gateway.toString().c_str(),
                  subnet.toString().c_str(), dns.toString().c_str());
    }
  } else if (!WiFi.config(IPAddress(), IPAddress(), IPAddress(), IPAddress())) {
    PM_LOG_ERROR("DHCP", "DHCP_CONFIG_FAILED", "error=PM-WIFI-009");
  } else {
    PM_LOG_DEBUG("DHCP", "DHCP_CONFIGURED", "mode=automatic");
  }
  const std::string password = config_.wifiPassword();
  const std::uint64_t now = clock_.monotonicMs();
  if (station_connect_started_ms_ == 0) {
    station_connect_started_ms_ = now;
  }
  const wl_status_t start_status =
      WiFi.begin(active_config.wifi_ssid.c_str(), password.c_str());
  const std::uint32_t retry_ms =
      std::max(kMinimumStationAttemptMs, nextBackoffMs());
  next_reconnect_ms_ = now + retry_ms;
  PM_LOG_INFO(
      "WIFI", "CONNECT_ATTEMPT",
      "attempt=%lu ssid=%s status=%d status_name=%s connection_timeout_ms=%lu",
      static_cast<unsigned long>(status_.reconnect_count + 1U),
      diag::maskSsid(active_config.wifi_ssid).c_str(),
      static_cast<int>(start_status),
      diag::wifiStatusName(static_cast<int>(start_status)),
      static_cast<unsigned long>(retry_ms));
  PM_LOG_INFO("WIFI", "RECONNECT_SCHEDULED",
              "attempt=%lu delay_ms=%lu reason=connection_pending",
              static_cast<unsigned long>(status_.reconnect_count + 2U),
              static_cast<unsigned long>(retry_ms));
  transition(Phase::WaitingForIp, "wifi_begin_returned");
}

void NetworkService::onConnected() {
  const RuntimeConfig active_config = config_.config();
  const DeviceIdentity identity = config_.identity();
  status_.station_connected = true;
  status_.rssi_dbm = WiFi.RSSI();
  status_.ip_address = WiFi.localIP().toString().c_str();
  status_.subnet = WiFi.subnetMask().toString().c_str();
  status_.gateway = WiFi.gatewayIP().toString().c_str();
  status_.dns = WiFi.dnsIP().toString().c_str();
  if (!setup_ap_restart_pending_) {
    next_setup_ap_start_ms_ = 0;
  }
  PM_LOG_INFO("WIFI", "STATION_ONLINE", "ip=%s rssi_dbm=%ld channel=%d",
              status_.ip_address.c_str(), static_cast<long>(status_.rssi_dbm),
              WiFi.channel());
  transition(Phase::Connected, "dhcp_complete");
  if (status_.reconnect_count > 0) {
    PM_LOG_INFO(
        "WIFI", "RECONNECT_SUCCESS", "reconnect_count=%lu rssi_dbm=%ld ip=%s",
        static_cast<unsigned long>(status_.reconnect_count),
        static_cast<long>(status_.rssi_dbm), status_.ip_address.c_str());
  }
  if (status_.setup_ap_active && config_.hasWifiCredentials()) {
    stopSetupAp();
    PM_LOG_INFO("WIFI", "RECOVERY_AP_DISABLED", "reason=station_online");
  }
  backoff_attempt_ = 0;
  station_connect_started_ms_ = 0;
  PM_LOG_INFO(
      "TIME", "NTP_CONFIGURE",
      "attempt=1 servers=3 timezone=UTC0 trust_state=pending timeout_ms=%lu",
      static_cast<unsigned long>(kNtpRetryInitialMs));
  configureNtp(active_config.ntp_servers);
  ntp_attempt_ = 1;
  next_ntp_retry_ms_ = clock_.monotonicMs() + kNtpRetryInitialMs;
  MDNS.end();
  PM_LOG_INFO("MDNS", "MDNS_START_BEGIN", "hostname=%s.local service=%s",
              active_config.hostname.c_str(), build::MDNS_SERVICE);
  status_.mdns_active = MDNS.begin(active_config.hostname.c_str());
  if (status_.mdns_active) {
    MDNS.addService(build::MDNS_SERVICE, "tcp", 80);
    MDNS.addServiceTxt(build::MDNS_SERVICE, "tcp", "api", build::API_VERSION);
    MDNS.addServiceTxt(build::MDNS_SERVICE, "tcp", "firmware",
                       version::FIRMWARE);
    MDNS.addServiceTxt(build::MDNS_SERVICE, "tcp", "enrolled",
                       identity.enrolled ? "true" : "false");
    const std::string &device = identity.device_id;
    MDNS.addServiceTxt(build::MDNS_SERVICE, "tcp", "device",
                       device.empty()
                           ? "unassigned"
                           : device.substr(device.size() - 6).c_str());
    PM_LOG_INFO("MDNS", "MDNS_READY", "hostname=%s.local service=%s port=80",
                active_config.hostname.c_str(), build::MDNS_SERVICE);
  } else {
    PM_LOG_WARN("MDNS", "MDNS_START_FAILED",
                "error=PM-MDNS-001 hostname=%s.local",
                active_config.hostname.c_str());
  }
  PM_LOG_INFO("MEMORY", "POST_WIFI",
              "heap_free=%lu heap_min=%lu psram_free=%lu",
              static_cast<unsigned long>(ESP.getFreeHeap()),
              static_cast<unsigned long>(ESP.getMinFreeHeap()),
              static_cast<unsigned long>(ESP.getFreePsram()));
  transition(clock_.synchronized() ? Phase::ServerValidation : Phase::TimeSync,
             clock_.synchronized() ? "local_services_and_time_ready"
                                   : "local_services_ready_waiting_for_time");
}

void NetworkService::configureNtp(
    const std::array<std::string, 3> &servers) {
  // esp_sntp_setservername(), which configTzTime() uses, stores raw pointers
  // to these strings. Stop SNTP before replacing the backing storage so an
  // in-flight resolver cannot observe invalid or partially replaced names.
  if (esp_sntp_enabled()) {
    esp_sntp_stop();
  }
  active_ntp_servers_ = servers;
  configTzTime("UTC0", active_ntp_servers_[0].c_str(),
               active_ntp_servers_[1].c_str(),
               active_ntp_servers_[2].c_str());
}

void NetworkService::updateScan() {
  if (scan_requested_.exchange(false, std::memory_order_acq_rel) &&
      !scan_running_) {
    const int result = WiFi.scanNetworks(true, true);
    scan_running_ = result == WIFI_SCAN_RUNNING;
    scan_started_ms_ = clock_.monotonicMs();
    PM_LOG_INFO("WIFI", "SCAN_STARTED", "asynchronous=true result=%d", result);
    if (scan_running_)
      transition(Phase::Scanning, "diagnostic_scan");
  }
  if (!scan_running_)
    return;
  const int count = WiFi.scanComplete();
  if (count == WIFI_SCAN_RUNNING)
    return;
  scan_running_ = false;
  if (count < 0) {
    PM_LOG_ERROR("WIFI", "SCAN_FAILED", "error=PM-WIFI-010 result=%d", count);
  } else {
    int matches = 0;
    std::int32_t strongest_rssi = -127;
    int strongest_channel = 0;
    int strongest_encryption = 0;
    for (int index = 0; index < count; ++index) {
      if (std::string(WiFi.SSID(index).c_str()) == config_.config().wifi_ssid) {
        ++matches;
        if (WiFi.RSSI(index) > strongest_rssi) {
          strongest_rssi = WiFi.RSSI(index);
          strongest_channel = WiFi.channel(index);
          strongest_encryption = static_cast<int>(WiFi.encryptionType(index));
        }
      }
      PM_LOG_TRACE(
          "WIFI", "SCAN_RESULT",
          "index=%d ssid=%s rssi_dbm=%ld channel=%d encryption=%d", index,
          diag::maskSsid(std::string(WiFi.SSID(index).c_str())).c_str(),
          static_cast<long>(WiFi.RSSI(index)), WiFi.channel(index),
          static_cast<int>(WiFi.encryptionType(index)));
    }
    PM_LOG_INFO("WIFI", "SCAN_COMPLETE",
                "duration_ms=%llu networks=%d configured_ssid=%s "
                "configured_ssid_found=%s matches=%d duplicate_bssids=%s "
                "strongest_rssi_dbm=%ld channel=%d encryption=%d",
                static_cast<unsigned long long>(clock_.monotonicMs() -
                                                scan_started_ms_),
                count, diag::maskSsid(config_.config().wifi_ssid).c_str(),
                matches > 0 ? "true" : "false", matches,
                matches > 1 ? "true" : "false",
                static_cast<long>(strongest_rssi), strongest_channel,
                strongest_encryption);
  }
  WiFi.scanDelete();
  transition(status_.station_connected ? connectedPhase() : Phase::RetryWait,
             "diagnostic_scan_complete");
}

NetworkService::Phase NetworkService::connectedPhase() const {
  if (!status_.station_connected)
    return Phase::RetryWait;
  if (!clock_.synchronized())
    return Phase::TimeSync;
  if (!status_.server_reachable)
    return Phase::Degraded;
  if (!status_.server_authenticated)
    return Phase::ServerValidation;
  return Phase::Online;
}

void NetworkService::transition(const Phase next, const char *reason) {
  if (phase_ == next)
    return;
  PM_LOG_INFO("WIFI", "STATE_TRANSITION", "from=%s to=%s reason=%s",
              phaseName(phase_), phaseName(next),
              reason == nullptr ? "unspecified" : reason);
  phase_ = next;
}

const char *NetworkService::phaseName(const Phase phase) {
  switch (phase) {
  case Phase::Unconfigured:
    return "unconfigured";
  case Phase::Provisioning:
    return "provisioning";
  case Phase::Idle:
    return "idle";
  case Phase::Scanning:
    return "scanning";
  case Phase::Connecting:
    return "connecting";
  case Phase::WaitingForIp:
    return "waiting_for_ip";
  case Phase::Connected:
    return "connected";
  case Phase::TimeSync:
    return "time_sync";
  case Phase::ServerValidation:
    return "server_validation";
  case Phase::Online:
    return "online";
  case Phase::RetryWait:
    return "retry_wait";
  case Phase::Degraded:
    return "degraded";
  case Phase::Failed:
    return "failed";
  }
  return "unknown";
}

std::uint32_t NetworkService::nextBackoffMs() {
  std::array<std::uint8_t, 2> random{};
  crypto::secureRandom(random.data(), random.size());
  const std::uint16_t random_value =
      static_cast<std::uint16_t>(static_cast<std::uint16_t>(random[0]) << 8U) |
      random[1];
  return network_policy::reconnectBackoffMs(backoff_attempt_++, random_value);
}

bool NetworkService::lockStatus(const TickType_t timeout) const {
  return status_mutex_ != nullptr &&
         xSemaphoreTakeRecursive(status_mutex_, timeout) == pdTRUE;
}

void NetworkService::unlockStatus() const {
  if (status_mutex_ != nullptr) {
    xSemaphoreGiveRecursive(status_mutex_);
  }
}

} // namespace pm
