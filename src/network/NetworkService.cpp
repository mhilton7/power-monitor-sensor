#include "network/NetworkService.h"

#include <algorithm>

#include <Arduino.h>
#include <ESP.h>
#include <ESPmDNS.h>
#include <WiFi.h>

#include "build_config.h"
#include "diagnostics/DiagnosticCore.h"
#include "diagnostics/SerialLogger.h"
#include "security/Crypto.h"
#include "version.h"

namespace pm {
namespace {

constexpr std::uint32_t kMinimumStationAttemptMs = 15'000U;

}  // namespace

NetworkService::NetworkService(ConfigService& config, ClockService& clock)
    : config_(config), clock_(clock) {}

bool NetworkService::begin() {
  PM_LOG_INFO("WIFI", "WIFI_INIT_BEGIN",
              "persistent=false auto_reconnect=false sleep=true");
  WiFi.persistent(false);
  WiFi.setAutoReconnect(false);
  WiFi.setSleep(true);
  WiFi.onEvent(
      [this](const arduino_event_id_t event,
             const arduino_event_info_t info) {
        switch (event) {
          case ARDUINO_EVENT_WIFI_STA_START:
            PM_LOG_DEBUG("WIFI", "STATION_STARTED", "driver=ready");
            break;
          case ARDUINO_EVENT_WIFI_STA_CONNECTED:
            PM_LOG_INFO("WIFI", "ASSOCIATED",
                        "ssid=%s bssid=%s channel=%d",
                        diag::maskSsid(config_.config().wifi_ssid).c_str(),
                        diag::maskMac(
                            std::string(WiFi.BSSIDstr().c_str()))
                            .c_str(),
                        WiFi.channel());
            break;
          case ARDUINO_EVENT_WIFI_STA_GOT_IP:
            PM_LOG_INFO("DHCP", "IP_ACQUIRED",
                        "ip=%s gateway=%s subnet=%s dns=%s",
                        WiFi.localIP().toString().c_str(),
                        WiFi.gatewayIP().toString().c_str(),
                        WiFi.subnetMask().toString().c_str(),
                        WiFi.dnsIP().toString().c_str());
            break;
          case ARDUINO_EVENT_WIFI_STA_DISCONNECTED: {
            const std::uint16_t reason =
                info.wifi_sta_disconnected.reason;
            last_disconnect_reason_.store(reason, std::memory_order_relaxed);
            const diag::ReasonInfo translated =
                diag::wifiDisconnectReason(reason);
            PM_LOG_ERROR_CODE(
                "WIFI", "DISCONNECTED", reason,
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
            PM_LOG_INFO("WIFI", "SETUP_CLIENT_JOINED",
                        "client_identity=redacted");
            break;
          case ARDUINO_EVENT_WIFI_AP_STADISCONNECTED:
            PM_LOG_INFO("WIFI", "SETUP_CLIENT_LEFT",
                        "client_identity=redacted");
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
  PM_LOG_INFO("WIFI", "WIFI_INIT_COMPLETE",
              "station_configured=%s setup_ap=%s",
              config_.hasWifiCredentials() ? "true" : "false",
              status_.setup_ap_active ? "active" : "inactive");
  return true;
}

void NetworkService::update() {
  clock_.update();
  status_.time_synchronized = clock_.synchronized();
  const std::uint64_t now = clock_.monotonicMs();
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
  if (!connected && config_.hasWifiCredentials() &&
      now >= next_reconnect_ms_) {
    ++status_.reconnect_count;
    connectStation();
  }
  if (!connected && config_.hasWifiCredentials() &&
      !status_.setup_ap_active && station_connect_started_ms_ != 0 &&
      now - station_connect_started_ms_ >= 60'000U &&
      now >= next_setup_recovery_ms_) {
    const wl_status_t station_status = WiFi.status();
    PM_LOG_WARN(
        "WIFI", "STATION_CONNECT_TIMEOUT",
        "error=PM-WIFI-006 elapsed_ms=%llu status=%d status_name=%s recovery_ap=starting",
        static_cast<unsigned long long>(now - station_connect_started_ms_),
        static_cast<int>(station_status),
        diag::wifiStatusName(static_cast<int>(station_status)));
    startSetupAp();
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
  if (status_.setup_ap_active &&
      now - setup_last_activity_ms_ >
          static_cast<std::uint64_t>(build::SETUP_AP_TTL_SECONDS) * 1000U) {
    stopSetupAp();
    next_setup_recovery_ms_ = now + 300'000U;
  }
  if (status_.setup_ap_active) {
    dns_server_.processNextRequest();
  }
}

void NetworkService::touchSetupActivity() {
  setup_last_activity_ms_ = clock_.monotonicMs();
}

void NetworkService::applyConfiguration() {
  PM_LOG_INFO(
      "WIFI", "CONFIG_APPLY_BEGIN",
      "ssid=%s static_ipv4=%s recovery_timeout_ms=60000 credentials_erased=false",
      diag::maskSsid(config_.config().wifi_ssid).c_str(),
      config_.config().static_network_enabled ? "true" : "false");
  if (status_.setup_ap_active && config_.hasAdminPassword()) {
    stopSetupAp();
  }
  WiFi.disconnect(false, false);
  status_.station_connected = false;
  status_.server_reachable = false;
  status_.server_authenticated = false;
  connectStation();
}

void NetworkService::requestConfigurationApply(const std::uint32_t delay_ms) {
  configuration_apply_delay_ms_.store(delay_ms, std::memory_order_relaxed);
  configuration_apply_generation_.fetch_add(1, std::memory_order_release);
}

void NetworkService::requestScan() {
  scan_requested_.store(true, std::memory_order_release);
}

NetworkStatus NetworkService::status() const { return status_; }

bool NetworkService::ipChangedSinceHeartbeat() {
  const bool changed = ip_changed_;
  ip_changed_ = false;
  return changed;
}

void NetworkService::setServerStatus(const bool reachable,
                                     const bool authenticated) {
  status_.server_reachable = reachable;
  status_.server_authenticated = authenticated;
}

void NetworkService::startSetupAp() {
  const std::string suffix = config_.identity().hardware_id.substr(
      config_.identity().hardware_id.size() - 6);
  const std::string ssid = "PowerMonitor-Setup-" + suffix;
  const std::string new_password = config_.ensureSetupPassword();
  if (!new_password.empty() && config_.setupPasswordNew()) {
    PM_LOG_WARN(
        "WIFI", "SETUP_CREDENTIAL_CREATED",
        "ssid=%s credential=redacted shown_on_serial=false",
        diag::maskSsid(ssid).c_str());
  }
  transition(Phase::Provisioning, "recovery_ap_requested");
  WiFi.mode(WIFI_AP_STA);
  status_.setup_ap_active = WiFi.softAP(ssid.c_str(), new_password.c_str(), 1, false, 4);
  if (status_.setup_ap_active) {
    dns_server_.start(53, "*", WiFi.softAPIP());
    PM_LOG_INFO("DNS", "CAPTIVE_DNS_STARTED",
                "address=%s port=53 wildcard=true",
                WiFi.softAPIP().toString().c_str());
  } else {
    PM_LOG_ERROR("WIFI", "SETUP_AP_START_FAILED",
                 "error=PM-WIFI-007");
    transition(Phase::Failed, "setup_ap_failed");
  }
  setup_last_activity_ms_ = clock_.monotonicMs();
}

void NetworkService::stopSetupAp() {
  dns_server_.stop();
  WiFi.softAPdisconnect(true);
  status_.setup_ap_active = false;
  PM_LOG_INFO("DNS", "CAPTIVE_DNS_STOPPED", "result=success");
  if (WiFi.status() == WL_CONNECTED) {
    WiFi.mode(WIFI_STA);
    transition(Phase::Online, "recovery_ap_stopped");
  }
}

void NetworkService::connectStation() {
  transition(Phase::Connecting, "connection_attempt");
  WiFi.mode(status_.setup_ap_active ? WIFI_AP_STA : WIFI_STA);
  WiFi.setHostname(config_.config().hostname.c_str());
  if (config_.config().static_network_enabled) {
    IPAddress address;
    IPAddress gateway;
    IPAddress subnet;
    IPAddress dns;
    address.fromString(config_.config().static_ip.c_str());
    gateway.fromString(config_.config().static_gateway.c_str());
    subnet.fromString(config_.config().static_subnet.c_str());
    dns.fromString(config_.config().static_dns.c_str());
    if (!WiFi.config(address, gateway, subnet, dns)) {
      PM_LOG_ERROR("DHCP", "STATIC_CONFIG_REJECTED",
                   "error=PM-WIFI-008");
    } else {
      PM_LOG_INFO("DHCP", "STATIC_CONFIG_APPLIED",
                  "ip=%s gateway=%s subnet=%s dns=%s",
                  address.toString().c_str(), gateway.toString().c_str(),
                  subnet.toString().c_str(), dns.toString().c_str());
    }
  } else if (!WiFi.config(IPAddress(), IPAddress(), IPAddress(), IPAddress())) {
    PM_LOG_ERROR("DHCP", "DHCP_CONFIG_FAILED",
                 "error=PM-WIFI-009");
  } else {
    PM_LOG_DEBUG("DHCP", "DHCP_CONFIGURED", "mode=automatic");
  }
  const std::string password = config_.wifiPassword();
  const std::uint64_t now = clock_.monotonicMs();
  if (station_connect_started_ms_ == 0) {
    station_connect_started_ms_ = now;
  }
  const wl_status_t start_status =
      WiFi.begin(config_.config().wifi_ssid.c_str(), password.c_str());
  const std::uint32_t retry_ms =
      std::max(kMinimumStationAttemptMs, nextBackoffMs());
  next_reconnect_ms_ = now + retry_ms;
  PM_LOG_INFO(
      "WIFI", "CONNECT_ATTEMPT",
      "attempt=%lu ssid=%s status=%d status_name=%s connection_timeout_ms=%lu",
      static_cast<unsigned long>(status_.reconnect_count + 1U),
      diag::maskSsid(config_.config().wifi_ssid).c_str(),
      static_cast<int>(start_status),
      diag::wifiStatusName(static_cast<int>(start_status)),
      static_cast<unsigned long>(retry_ms));
  PM_LOG_INFO(
      "WIFI", "RECONNECT_SCHEDULED",
      "attempt=%lu delay_ms=%lu reason=connection_pending",
      static_cast<unsigned long>(status_.reconnect_count + 2U),
      static_cast<unsigned long>(retry_ms));
  transition(Phase::WaitingForIp, "wifi_begin_returned");
}

void NetworkService::onConnected() {
  status_.station_connected = true;
  status_.rssi_dbm = WiFi.RSSI();
  status_.ip_address = WiFi.localIP().toString().c_str();
  status_.subnet = WiFi.subnetMask().toString().c_str();
  status_.gateway = WiFi.gatewayIP().toString().c_str();
  status_.dns = WiFi.dnsIP().toString().c_str();
  PM_LOG_INFO("WIFI", "STATION_ONLINE",
              "ip=%s rssi_dbm=%ld channel=%d",
              status_.ip_address.c_str(), static_cast<long>(status_.rssi_dbm),
              WiFi.channel());
  transition(Phase::Connected, "dhcp_complete");
  if (status_.reconnect_count > 0) {
    PM_LOG_INFO("WIFI", "RECONNECT_SUCCESS",
                "reconnect_count=%lu rssi_dbm=%ld ip=%s",
                static_cast<unsigned long>(status_.reconnect_count),
                static_cast<long>(status_.rssi_dbm),
                status_.ip_address.c_str());
  }
  if (status_.setup_ap_active && config_.hasAdminPassword()) {
    stopSetupAp();
    PM_LOG_INFO("WIFI", "RECOVERY_AP_DISABLED",
                "reason=station_online");
  }
  backoff_attempt_ = 0;
  station_connect_started_ms_ = 0;
  const auto& ntp = config_.config().ntp_servers;
  transition(Phase::ValidatingNetwork, "dhcp_ready");
  PM_LOG_INFO("TIME", "NTP_CONFIGURE",
              "servers=3 timezone=UTC0 trust_state=pending");
  configTzTime("UTC0", ntp[0].c_str(), ntp[1].c_str(), ntp[2].c_str());
  MDNS.end();
  PM_LOG_INFO("MDNS", "MDNS_START_BEGIN", "hostname=%s.local service=%s",
              config_.config().hostname.c_str(), build::MDNS_SERVICE);
  status_.mdns_active = MDNS.begin(config_.config().hostname.c_str());
  if (status_.mdns_active) {
    MDNS.addService(build::MDNS_SERVICE, "tcp", 80);
    MDNS.addServiceTxt(build::MDNS_SERVICE, "tcp", "api", build::API_VERSION);
    MDNS.addServiceTxt(build::MDNS_SERVICE, "tcp", "firmware", version::FIRMWARE);
    MDNS.addServiceTxt(build::MDNS_SERVICE, "tcp", "enrolled",
                       config_.identity().enrolled ? "true" : "false");
    const std::string& device = config_.identity().device_id;
    MDNS.addServiceTxt(build::MDNS_SERVICE, "tcp", "device",
                       device.empty() ? "unassigned" : device.substr(device.size() - 6).c_str());
    PM_LOG_INFO("MDNS", "MDNS_READY",
                "hostname=%s.local service=%s port=80",
                config_.config().hostname.c_str(), build::MDNS_SERVICE);
  } else {
    PM_LOG_WARN("MDNS", "MDNS_START_FAILED",
                "error=PM-MDNS-001 hostname=%s.local",
                config_.config().hostname.c_str());
  }
  PM_LOG_INFO(
      "MEMORY", "POST_WIFI",
      "heap_free=%lu heap_min=%lu psram_free=%lu",
      static_cast<unsigned long>(ESP.getFreeHeap()),
      static_cast<unsigned long>(ESP.getMinFreeHeap()),
      static_cast<unsigned long>(ESP.getFreePsram()));
  transition(Phase::Online, "local_network_services_ready");
}

void NetworkService::updateScan() {
  if (scan_requested_.exchange(false, std::memory_order_acq_rel) &&
      !scan_running_) {
    const int result = WiFi.scanNetworks(true, true);
    scan_running_ = result == WIFI_SCAN_RUNNING;
    scan_started_ms_ = clock_.monotonicMs();
    PM_LOG_INFO("WIFI", "SCAN_STARTED", "asynchronous=true result=%d",
                result);
    if (scan_running_) transition(Phase::Scanning, "diagnostic_scan");
  }
  if (!scan_running_) return;
  const int count = WiFi.scanComplete();
  if (count == WIFI_SCAN_RUNNING) return;
  scan_running_ = false;
  if (count < 0) {
    PM_LOG_ERROR("WIFI", "SCAN_FAILED",
                 "error=PM-WIFI-010 result=%d", count);
  } else {
    int matches = 0;
    std::int32_t strongest_rssi = -127;
    int strongest_channel = 0;
    int strongest_encryption = 0;
    for (int index = 0; index < count; ++index) {
      if (std::string(WiFi.SSID(index).c_str()) ==
          config_.config().wifi_ssid) {
        ++matches;
        if (WiFi.RSSI(index) > strongest_rssi) {
          strongest_rssi = WiFi.RSSI(index);
          strongest_channel = WiFi.channel(index);
          strongest_encryption =
              static_cast<int>(WiFi.encryptionType(index));
        }
      }
      PM_LOG_TRACE(
          "WIFI", "SCAN_RESULT",
          "index=%d ssid=%s rssi_dbm=%ld channel=%d encryption=%d",
          index, diag::maskSsid(std::string(WiFi.SSID(index).c_str())).c_str(),
          static_cast<long>(WiFi.RSSI(index)), WiFi.channel(index),
          static_cast<int>(WiFi.encryptionType(index)));
    }
    PM_LOG_INFO(
        "WIFI", "SCAN_COMPLETE",
        "duration_ms=%llu networks=%d configured_ssid=%s configured_ssid_found=%s matches=%d duplicate_bssids=%s strongest_rssi_dbm=%ld channel=%d encryption=%d",
        static_cast<unsigned long long>(clock_.monotonicMs() -
                                        scan_started_ms_),
        count, diag::maskSsid(config_.config().wifi_ssid).c_str(),
        matches > 0 ? "true" : "false", matches,
        matches > 1 ? "true" : "false",
        static_cast<long>(strongest_rssi), strongest_channel,
        strongest_encryption);
  }
  WiFi.scanDelete();
  transition(status_.station_connected ? Phase::Online : Phase::RetryWait,
             "diagnostic_scan_complete");
}

void NetworkService::transition(const Phase next, const char* reason) {
  if (phase_ == next) return;
  PM_LOG_INFO("WIFI", "STATE_TRANSITION", "from=%s to=%s reason=%s",
              phaseName(phase_), phaseName(next),
              reason == nullptr ? "unspecified" : reason);
  phase_ = next;
}

const char* NetworkService::phaseName(const Phase phase) {
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
    case Phase::ValidatingNetwork:
      return "validating_network";
    case Phase::Online:
      return "online";
    case Phase::RetryWait:
      return "retry_wait";
    case Phase::Failed:
      return "failed";
  }
  return "unknown";
}

std::uint32_t NetworkService::nextBackoffMs() {
  const std::uint32_t exponent = std::min<std::uint32_t>(backoff_attempt_++, 8);
  const std::uint32_t base = std::min<std::uint32_t>(1000U << exponent, 300'000U);
  std::array<std::uint8_t, 2> random{};
  crypto::secureRandom(random.data(), random.size());
  const std::uint32_t jitter =
      (static_cast<std::uint32_t>(random[0]) << 8U | random[1]) % (base / 4U + 1U);
  return base + jitter;
}

}  // namespace pm
