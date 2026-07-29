#include "provisioning/ProvisioningService.h"

#include <cstring>

#include <ArduinoJson.h>

namespace pm {
namespace {
ConnectionMode requestedMode(const char* value) {
  if (value != nullptr && std::strcmp(value, "pull") == 0) {
    return ConnectionMode::Pull;
  }
  if (value != nullptr && std::strcmp(value, "push") == 0) {
    return ConnectionMode::Push;
  }
  return ConnectionMode::Hybrid;
}
}  // namespace

ProvisioningService::ProvisioningService(ConfigService& config) : config_(config) {}

ProvisioningResult ProvisioningService::apply(const std::string& json) {
  JsonDocument document;
  if (deserializeJson(document, json)) {
    return {false, "setup_json_invalid", "Setup body is not valid bounded JSON."};
  }
  const std::string ssid = document["wifi_ssid"] | "";
  const std::string wifi_password = document["wifi_password"] | "";
  const std::string enrollment_token = document["enrollment_token"] | "";
  const std::string admin_password = document["admin_password"] | "";
  const std::string server_url = document["server_url"] | "";
  const std::string server_ca_pem = document["server_ca_pem"] | "";
  const std::string server_fingerprint = document["server_fingerprint"] | "";
  const std::string friendly_name = document["friendly_name"] | "Unassigned Power Monitor";
  const float ct_rating_a = document["ct_rating_a"] | 0.0F;
  if (ssid.empty() || ssid.size() > 32 || wifi_password.size() < 8 ||
      wifi_password.size() > 63) {
    return {false, "wifi_credentials_invalid",
            "Wi-Fi SSID is required and the WPA/WPA2 password must contain 8 through 63 characters."};
  }
  if (enrollment_token.empty() || enrollment_token.size() > 256) {
    return {false, "enrollment_token_invalid", "A bounded one-time enrollment token is required."};
  }
  if (admin_password.size() < 12 || admin_password.size() > 128) {
    return {false, "admin_password_invalid", "Administrator password must contain 12 through 128 characters."};
  }
  if (server_url.rfind("https://", 0) != 0 || server_url.size() > 256) {
    return {false, "server_url_invalid", "Central server URL must be bounded HTTPS."};
  }
  if (server_ca_pem.empty()) {
    return {false, "server_ca_required",
            "A public server CA PEM is required; fingerprint-only TLS is not supported safely."};
  }
  if (server_ca_pem.size() > 8192 || server_fingerprint.size() > 128) {
    return {false, "tls_trust_too_large", "TLS trust material exceeds device limits."};
  }
  if (ct_rating_a < 1.0F || ct_rating_a > 1000.0F) {
    return {false, "ct_rating_invalid", "CT rating must be 1 through 1000 A and match the installed set."};
  }
  RuntimeConfig candidate = config_.config();
  candidate.wifi_ssid = ssid;
  candidate.static_network_enabled = document["static_network_enabled"] | false;
  candidate.static_ip = document["static_ip"] | "";
  candidate.static_gateway = document["static_gateway"] | "";
  candidate.static_subnet = document["static_subnet"] | "";
  candidate.static_dns = document["static_dns"] | "";
  candidate.server_url = server_url;
  candidate.server_ca_pem = server_ca_pem;
  candidate.server_fingerprint = server_fingerprint;
  candidate.friendly_name = friendly_name;
  candidate.ct_rating_a = ct_rating_a;
  candidate.connection_mode = requestedMode(document["connection_mode"] | "hybrid");
  const ConfigValidation validation = config_.validate(candidate, true);
  if (!validation.valid) {
    return {false, validation.code, validation.detail};
  }
  if (!config_.commitProvisioning(candidate, wifi_password, enrollment_token,
                                  admin_password)) {
    return {false, "setup_commit_failed", "Setup could not be committed atomically; previous configuration remains available."};
  }
  return {true, "setup_applied", "Setup was saved; the device will join Wi-Fi and enroll."};
}

}  // namespace pm
