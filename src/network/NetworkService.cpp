#include "network/NetworkService.h"

#include <algorithm>

#include <Arduino.h>
#include <ESPmDNS.h>
#include <WiFi.h>

#include "build_config.h"
#include "security/Crypto.h"
#include "version.h"

namespace pm {

NetworkService::NetworkService(ConfigService& config, ClockService& clock)
    : config_(config), clock_(clock) {}

bool NetworkService::begin() {
  WiFi.persistent(false);
  WiFi.setAutoReconnect(false);
  WiFi.setSleep(true);
  status_.hostname = config_.config().hostname + ".local";
  if (config_.hasWifiCredentials()) {
    connectStation();
  } else {
    startSetupAp();
  }
  return true;
}

void NetworkService::update() {
  clock_.update();
  status_.time_synchronized = clock_.synchronized();
  const bool connected = WiFi.status() == WL_CONNECTED;
  if (connected && !status_.station_connected) {
    onConnected();
  } else if (!connected && status_.station_connected) {
    status_.station_connected = false;
    status_.mdns_active = false;
    status_.server_reachable = false;
    status_.server_authenticated = false;
    MDNS.end();
    next_reconnect_ms_ = clock_.monotonicMs() + nextBackoffMs();
  }
  if (!connected && config_.hasWifiCredentials() &&
      clock_.monotonicMs() >= next_reconnect_ms_) {
    ++status_.reconnect_count;
    connectStation();
    next_reconnect_ms_ = clock_.monotonicMs() + nextBackoffMs();
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
      clock_.monotonicMs() - setup_last_activity_ms_ >
          static_cast<std::uint64_t>(build::SETUP_AP_TTL_SECONDS) * 1000U) {
    WiFi.softAPdisconnect(true);
    dns_server_.stop();
    status_.setup_ap_active = false;
  }
  if (status_.setup_ap_active) {
    dns_server_.processNextRequest();
  }
}

void NetworkService::touchSetupActivity() {
  setup_last_activity_ms_ = clock_.monotonicMs();
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
    Serial.println("Setup access point credentials (shown once; do not log or photograph):");
    Serial.printf("SSID: %s\n", ssid.c_str());
    Serial.printf("Password: %s\n", new_password.c_str());
  }
  WiFi.mode(WIFI_AP_STA);
  status_.setup_ap_active = WiFi.softAP(ssid.c_str(), new_password.c_str(), 1, false, 4);
  if (status_.setup_ap_active) {
    dns_server_.start(53, "*", WiFi.softAPIP());
  }
  setup_last_activity_ms_ = clock_.monotonicMs();
}

void NetworkService::connectStation() {
  WiFi.mode(status_.setup_ap_active ? WIFI_AP_STA : WIFI_STA);
  WiFi.setHostname(config_.config().hostname.c_str());
  const std::string password = config_.wifiPassword();
  WiFi.begin(config_.config().wifi_ssid.c_str(), password.c_str());
}

void NetworkService::onConnected() {
  status_.station_connected = true;
  status_.rssi_dbm = WiFi.RSSI();
  status_.ip_address = WiFi.localIP().toString().c_str();
  status_.subnet = WiFi.subnetMask().toString().c_str();
  status_.gateway = WiFi.gatewayIP().toString().c_str();
  status_.dns = WiFi.dnsIP().toString().c_str();
  backoff_attempt_ = 0;
  const auto& ntp = config_.config().ntp_servers;
  configTzTime("UTC0", ntp[0].c_str(), ntp[1].c_str(), ntp[2].c_str());
  MDNS.end();
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
  }
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
