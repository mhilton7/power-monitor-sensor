#include "config/ConfigService.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

#include <Arduino.h>
#include <ArduinoJson.h>
#include <ESP.h>

#include "build_config.h"
#include "diagnostics/DiagnosticCore.h"
#include "diagnostics/SerialLogger.h"

namespace pm {
namespace {

ConnectionMode parseMode(const char* value) {
  if (value != nullptr && std::strcmp(value, "pull") == 0) {
    return ConnectionMode::Pull;
  }
  if (value != nullptr && std::strcmp(value, "push") == 0) {
    return ConnectionMode::Push;
  }
  return ConnectionMode::Hybrid;
}

bool startsWith(const std::string& value, const char* prefix) {
  return value.rfind(prefix, 0) == 0;
}

bool validIpv4(const std::string& value) {
  IPAddress address;
  return !value.empty() && address.fromString(value.c_str());
}

bool validMeasurementRole(const std::string& value) {
  return value == "main" || value == "service-leg" || value == "branch" ||
         value == "submeter" || value == "other";
}

std::string defaultHostname(const DeviceIdentity& identity) {
  std::string source = identity.device_id.empty() ? identity.hardware_id : identity.device_id;
  source.erase(std::remove(source.begin(), source.end(), '-'), source.end());
  const std::string suffix = source.size() > 6 ? source.substr(source.size() - 6) : source;
  return "power-monitor-" + suffix;
}

}  // namespace

const char* connectionModeName(const ConnectionMode mode) {
  switch (mode) {
    case ConnectionMode::Pull:
      return "pull";
    case ConnectionMode::Push:
      return "push";
    case ConnectionMode::Hybrid:
      return "hybrid";
  }
  return "hybrid";
}

bool ConfigService::begin() {
  PM_LOG_INFO("CONFIG", "NVS_OPEN_BEGIN", "namespace=pm-agent");
  if (!preferences_.begin("pm-agent", false)) {
    PM_LOG_FATAL("CONFIG", "NVS_OPEN_FAILED",
                 "error=PM-CONFIG-001 namespace=pm-agent");
    return false;
  }
  initializeIdentity();
  bool defaults_created = false;
  if (!loadConfig("cfg", config_)) {
    config_ = RuntimeConfig{};
    config_.hostname = defaultHostname(identity_);
    if (!saveConfig("cfg", config_)) {
      PM_LOG_FATAL("CONFIG", "DEFAULT_SAVE_FAILED",
                   "error=PM-CONFIG-003");
      return false;
    }
    defaults_created = true;
  }
  if (config_.hostname.empty()) {
    config_.hostname = defaultHostname(identity_);
  }
  const std::uint32_t boot_failures = preferences_.getUInt("boot_fail", 0);
  safe_mode_ = boot_failures >= 3;
  safe_mode_reason_ = safe_mode_ ? "three_consecutive_incomplete_boots" : "";
  PM_LOG_INFO(
      "CONFIG", "NVS_OPEN_COMPLETE",
      "source=%s config_version=%lu boot_failures=%lu safe_mode=%s",
      defaults_created ? "defaults" : "persisted",
      static_cast<unsigned long>(config_.config_version),
      static_cast<unsigned long>(boot_failures),
      safe_mode_ ? "true" : "false");
  return true;
}

const RuntimeConfig& ConfigService::config() const { return config_; }

const DeviceIdentity& ConfigService::identity() const { return identity_; }

ConfigValidation ConfigService::validate(const RuntimeConfig& candidate,
                                         const bool ct_change_acknowledged) const {
  if (candidate.schema_version != 1) {
    return {false, "config_schema_unsupported", "Only configuration schema 1 is supported."};
  }
  if (candidate.friendly_name.empty() || candidate.friendly_name.size() > 64) {
    return {false, "friendly_name_invalid", "Friendly name must contain 1 through 64 characters."};
  }
  if (candidate.site_id.size() > 64 || candidate.circuit_id.size() > 64 ||
      candidate.parent_circuit_id.size() > 64 ||
      !validMeasurementRole(candidate.measurement_role)) {
    return {false, "circuit_metadata_invalid", "Site/circuit identifiers must be bounded and the measurement role must be supported."};
  }
  if (candidate.hostname.empty() || candidate.hostname.size() > 63 ||
      candidate.hostname.front() == '-' || candidate.hostname.back() == '-' ||
      !std::all_of(candidate.hostname.begin(), candidate.hostname.end(), [](const char value) {
        return (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') || value == '-';
      })) {
    return {false, "hostname_invalid", "Hostname must be a lowercase RFC 1123 label."};
  }
  if (candidate.wifi_ssid.size() > 32 || candidate.static_ip.size() > 15 ||
      candidate.static_gateway.size() > 15 ||
      candidate.static_subnet.size() > 15 || candidate.static_dns.size() > 15) {
    return {false, "network_string_too_large", "Wi-Fi and IPv4 configuration fields exceed device limits."};
  }
  if (candidate.server_url.size() > 256 ||
      (!candidate.server_url.empty() &&
       !startsWith(candidate.server_url, "https://"))) {
    return {false, "server_url_insecure", "The central server URL must use HTTPS."};
  }
  if (candidate.server_ca_pem.size() > 8192 ||
      candidate.server_fingerprint.size() > 128) {
    return {false, "tls_trust_too_large", "TLS trust material exceeds device limits."};
  }
  if (!candidate.server_url.empty() && candidate.server_ca_pem.empty() &&
      candidate.server_fingerprint.empty()) {
    return {false, "tls_trust_required", "A public server CA PEM or certificate fingerprint is required for the central server."};
  }
  if (candidate.static_network_enabled &&
      (!validIpv4(candidate.static_ip) || !validIpv4(candidate.static_gateway) ||
       !validIpv4(candidate.static_subnet) || !validIpv4(candidate.static_dns))) {
    return {false, "static_network_invalid", "Static IPv4 address, gateway, subnet mask, and DNS must all be valid."};
  }
  for (const auto& address : candidate.allowed_server_addresses) {
    if (address.size() > 253 || address.find('/') != std::string::npos) {
      return {false, "allowed_server_address_invalid", "Allowed server entries must be bounded hostnames or IP addresses without paths."};
    }
  }
  if (candidate.live_interval_seconds < 1 ||
      candidate.live_interval_seconds > 60 ||
      candidate.sync_interval_seconds < 5 ||
      candidate.sync_interval_seconds > 3600) {
    return {false, "network_interval_invalid", "Live and synchronization intervals are outside supported ranges."};
  }
  if (candidate.sample_interval_seconds < 1 || candidate.sample_interval_seconds > 30) {
    return {false, "sample_interval_invalid", "Sample interval must be 1 through 30 seconds."};
  }
  if (candidate.durable_log_interval_seconds < 10 ||
      candidate.durable_log_interval_seconds > 3600 ||
      candidate.durable_log_interval_seconds < candidate.sample_interval_seconds) {
    return {false, "log_interval_invalid", "Durable interval must be 10 through 3600 seconds and not shorter than sampling."};
  }
  if (candidate.heartbeat_interval_seconds < 5 ||
      candidate.heartbeat_interval_seconds > 3600) {
    return {false, "heartbeat_interval_invalid", "Heartbeat interval must be 5 through 3600 seconds."};
  }
  if (candidate.sync_retry_max_seconds < 1 ||
      candidate.sync_retry_max_seconds > 86400) {
    return {false, "sync_retry_limit_invalid", "Maximum synchronization retry delay must be 1 through 86400 seconds."};
  }
  if (candidate.pzem_timeout_ms < 100 || candidate.pzem_timeout_ms > 5000) {
    return {false, "pzem_timeout_invalid", "PZEM timeout must be 100 through 5000 milliseconds."};
  }
  if (candidate.ct_rating_a < 1.0F || candidate.ct_rating_a > 1000.0F) {
    return {false, "ct_rating_invalid", "CT rating must be 1 through 1000 amperes and match the installed set."};
  }
  if (candidate.ct_rating_a != config_.ct_rating_a && !ct_change_acknowledged) {
    return {false, "ct_change_ack_required", "Changing CT rating requires explicit physical-hardware acknowledgement."};
  }
  if (candidate.ct_warning_fraction <= 0.0F ||
      candidate.ct_warning_fraction >= candidate.ct_critical_fraction ||
      candidate.ct_critical_fraction > 1.0F ||
      candidate.ct_fault_fraction <= candidate.ct_critical_fraction ||
      candidate.ct_fault_fraction > 2.0F) {
    return {false, "ct_thresholds_invalid", "CT warning, critical, and fault thresholds must increase safely within supported bounds."};
  }
  if (candidate.voltage_minimum_v < 0.0F ||
      candidate.voltage_maximum_v <= candidate.voltage_minimum_v ||
      candidate.voltage_maximum_v > 600.0F) {
    return {false, "voltage_limits_invalid", "Voltage limits are inconsistent or outside supported bounds."};
  }
  if (candidate.frequency_minimum_hz < 0.0F ||
      candidate.frequency_maximum_hz <= candidate.frequency_minimum_hz ||
      candidate.frequency_maximum_hz > 100.0F) {
    return {false, "frequency_limits_invalid", "Frequency limits are inconsistent or outside supported bounds."};
  }
  if (candidate.sd_spi_hz < 1'000'000 || candidate.sd_spi_hz > build::MAX_SD_SPI_HZ) {
    return {false, "sd_spi_frequency_invalid", "SD SPI frequency must be 1 through 20 MHz."};
  }
  if (candidate.storage_warning_free_bytes < 1024U * 1024U ||
      candidate.storage_warning_free_bytes > 64ULL * 1024ULL * 1024ULL * 1024ULL) {
    return {false, "storage_warning_threshold_invalid", "Storage warning threshold must be 1 MiB through 64 GiB."};
  }
  if (candidate.retention_days < 1 || candidate.retention_days > 3650) {
    return {false, "retention_days_invalid", "Retention must be 1 through 3650 days when enabled."};
  }
  if (candidate.timezone.empty() || candidate.timezone.size() > 64) {
    return {false, "timezone_invalid", "Display timezone must contain 1 through 64 characters."};
  }
  for (const auto& server : candidate.ntp_servers) {
    if (server.empty() || server.size() > 253) {
      return {false, "ntp_server_invalid", "Exactly three bounded NTP server names are required."};
    }
  }
  if (candidate.local_session_timeout_seconds < 60 ||
      candidate.local_session_timeout_seconds > 86400) {
    return {false, "session_timeout_invalid", "Local session timeout must be 60 through 86400 seconds."};
  }
  if (candidate.ota_channel != "stable" && candidate.ota_channel != "beta") {
    return {false, "ota_channel_invalid", "OTA channel must be stable or beta."};
  }
  if (candidate.ota_update_window_start_hour > 23 ||
      candidate.ota_update_window_end_hour > 23 ||
      (candidate.ota_update_window_enabled &&
       candidate.ota_update_window_start_hour == candidate.ota_update_window_end_hour)) {
    return {false, "ota_update_window_invalid", "OTA update window hours must be distinct values from 0 through 23."};
  }
  if (candidate.diagnostic_log_level > 5) {
    return {false, "diagnostic_log_level_invalid", "Diagnostic log level must be 0 through 5."};
  }
  return {true, "ok", "Configuration is valid."};
}

bool ConfigService::stage(const RuntimeConfig& candidate,
                          const bool ct_change_acknowledged) {
  const ConfigValidation validation =
      validate(candidate, ct_change_acknowledged);
  if (!validation.valid) {
    PM_LOG_WARN("CONFIG", "STAGE_REJECTED",
                "error=PM-CONFIG-004 validation=%s",
                validation.code.c_str());
    return false;
  }
  staged_ = candidate;
  staged_.config_version = std::max(config_.config_version + 1,
                                    candidate.config_version);
  staged_valid_ = saveConfig("cfg_stage", staged_);
  PM_LOG_INFO(
      "CONFIG", "STAGE_COMPLETE",
      "result=%s from_version=%lu to_version=%lu friendly_name=%s wifi_ssid=%s server_configured=%s",
      staged_valid_ ? "success" : "failed",
      static_cast<unsigned long>(config_.config_version),
      static_cast<unsigned long>(staged_.config_version),
      staged_.friendly_name.c_str(),
      diag::maskSsid(staged_.wifi_ssid).c_str(),
      staged_.server_url.empty() ? "false" : "true");
  return staged_valid_;
}

bool ConfigService::commitStaged() {
  if (!staged_valid_) {
    PM_LOG_WARN("CONFIG", "COMMIT_REJECTED",
                "error=PM-CONFIG-005 staged=false");
    return false;
  }
  if (!saveConfig("cfg_prev", config_) || !saveConfig("cfg", staged_)) {
    return false;
  }
  config_ = staged_;
  preferences_.remove("cfg_stage");
  preferences_.remove("server_ca_stage");
  preferences_.remove("server_fp_stage");
  staged_valid_ = false;
  PM_LOG_INFO("CONFIG", "COMMIT_COMPLETE",
              "version=%lu friendly_name=%s",
              static_cast<unsigned long>(config_.config_version),
              config_.friendly_name.c_str());
  return true;
}

bool ConfigService::rollbackStaged() {
  preferences_.remove("cfg_stage");
  preferences_.remove("server_ca_stage");
  preferences_.remove("server_fp_stage");
  staged_valid_ = false;
  return true;
}

bool ConfigService::rollbackToPrevious() {
  RuntimeConfig previous;
  if (!loadConfig("cfg_prev", previous) || !saveConfig("cfg", previous)) {
    return false;
  }
  config_ = previous;
  return true;
}

bool ConfigService::updateFromJson(const std::string& json, const bool dry_run,
                                   const bool ct_change_acknowledged,
                                   ConfigValidation& result) {
  RuntimeConfig candidate = config_;
  if (!parseConfig(json, candidate, result)) {
    return false;
  }
  result = validate(candidate, ct_change_acknowledged);
  if (!result.valid || dry_run) {
    return result.valid;
  }
  return stage(candidate, ct_change_acknowledged) && commitStaged();
}

std::string ConfigService::redactedJson() const { return serializeConfig(config_); }

bool ConfigService::hasWifiCredentials() const {
  return !config_.wifi_ssid.empty() && preferences_.getBytesLength("wifi_pwd") > 0;
}

std::string ConfigService::wifiPassword() const {
  const std::size_t length = preferences_.getBytesLength("wifi_pwd");
  if (length == 0 || length > 128) {
    return {};
  }
  std::string password(length, '\0');
  preferences_.getBytes("wifi_pwd", password.data(), password.size());
  return password;
}

bool ConfigService::setWifiCredentials(const std::string& ssid,
                                       const std::string& password) {
  if (ssid.empty() || ssid.size() > 32 || password.size() < 8 ||
      password.size() > 63) {
    return false;
  }
  RuntimeConfig candidate = config_;
  candidate.wifi_ssid = ssid;
  if (!saveConfig("cfg_prev", config_) || !saveConfig("cfg", candidate)) {
    return false;
  }
  if (preferences_.putBytes("wifi_pwd", password.data(), password.size()) !=
      password.size()) {
    return false;
  }
  config_ = candidate;
  return true;
}

bool ConfigService::updateNetworkSettings(
    const RuntimeConfig& candidate, const std::string& wifi_password,
    const bool replace_wifi_password, ConfigValidation& result) {
  result = validate(candidate, true);
  if (!result.valid) {
    return false;
  }
  if (candidate.wifi_ssid.empty()) {
    result = {false, "wifi_ssid_required",
              "A Wi-Fi network name is required."};
    return false;
  }
  if (!replace_wifi_password && candidate.wifi_ssid != config_.wifi_ssid) {
    result = {false, "wifi_password_required",
              "Enter the password when changing the Wi-Fi network."};
    return false;
  }
  if (!replace_wifi_password && !hasWifiCredentials()) {
    result = {false, "wifi_credentials_missing",
              "The existing Wi-Fi password is unavailable; enter it again."};
    return false;
  }
  if (replace_wifi_password &&
      (wifi_password.size() < 8 || wifi_password.size() > 63)) {
    result = {false, "wifi_password_invalid",
              "Wi-Fi passwords must contain 8 through 63 characters."};
    return false;
  }

  const RuntimeConfig previous_config = config_;
  const std::string previous_password = wifiPassword();
  if (!stage(candidate, true)) {
    result = {false, "network_settings_stage_failed",
              "The network settings could not be staged in persistent storage."};
    return false;
  }

  const bool password_saved =
      !replace_wifi_password ||
      preferences_.putBytes("wifi_pwd", wifi_password.data(),
                            wifi_password.size()) == wifi_password.size();
  if (password_saved && commitStaged()) {
    result = {true, "ok", "Network and server settings were committed."};
    return true;
  }

  config_ = previous_config;
  saveConfig("cfg", previous_config);
  if (previous_password.empty()) {
    preferences_.remove("wifi_pwd");
  } else {
    preferences_.putBytes("wifi_pwd", previous_password.data(),
                          previous_password.size());
  }
  rollbackStaged();
  result = {false, "network_settings_commit_failed",
            "The network settings could not be committed; the previous settings were restored."};
  return false;
}

std::string ConfigService::enrollmentToken() const {
  const std::size_t length = preferences_.getBytesLength("enroll_tok");
  if (length == 0 || length > 256) {
    return {};
  }
  std::string token(length, '\0');
  preferences_.getBytes("enroll_tok", token.data(), token.size());
  return token;
}

bool ConfigService::setEnrollmentToken(const std::string& token) {
  return !token.empty() && token.size() <= 256 &&
         preferences_.putBytes("enroll_tok", token.data(), token.size()) == token.size();
}

void ConfigService::clearEnrollmentToken() { preferences_.remove("enroll_tok"); }

bool ConfigService::saveEnrollment(const std::string& device_id,
                                   const std::uint8_t* enrollment_secret,
                                   const std::size_t secret_length,
                                   const std::string& ota_public_key) {
  if (device_id.size() != 36 || secret_length < 32 || secret_length > 64 ||
      ota_public_key.size() > 4096) {
    return false;
  }
  const bool saved = preferences_.putString("device_id", device_id.c_str()) == device_id.size() &&
                     preferences_.putBytes("enroll_sec", enrollment_secret, secret_length) == secret_length &&
                     preferences_.putString("ota_pub", ota_public_key.c_str()) == ota_public_key.size() &&
                     preferences_.putUInt("server_cfg", 0) == sizeof(std::uint32_t);
  if (!saved) {
    return false;
  }
  identity_.device_id = device_id;
  identity_.enrolled = true;
  clearEnrollmentToken();
  if (config_.hostname.rfind("power-monitor-", 0) == 0) {
    config_.hostname = defaultHostname(identity_);
    saveConfig("cfg", config_);
  }
  return true;
}

bool ConfigService::directionalKeys(crypto::Key32& device_to_server,
                                    crypto::Key32& server_to_device) const {
  const std::size_t length = preferences_.getBytesLength("enroll_sec");
  if (!identity_.enrolled || length < 32 || length > 64) {
    return false;
  }
  std::array<std::uint8_t, 64> secret{};
  if (preferences_.getBytes("enroll_sec", secret.data(), length) != length) {
    return false;
  }
  device_to_server = crypto::hkdfSha256(secret.data(), length, "pm-device-to-server-v1");
  server_to_device = crypto::hkdfSha256(secret.data(), length, "pm-server-to-device-v1");
  std::fill(secret.begin(), secret.end(), 0U);
  return true;
}

std::string ConfigService::otaPublicKey() const {
  return std::string(preferences_.getString("ota_pub", "").c_str());
}

std::string ConfigService::ensureSetupPassword() {
  const std::size_t clear_length = preferences_.getBytesLength("setup_ap");
  if (clear_length >= 12 && clear_length <= 64) {
    std::string existing(clear_length, '\0');
    if (preferences_.getBytes("setup_ap", existing.data(), existing.size()) ==
        existing.size()) {
      setup_password_new_ = false;
      return existing;
    }
  }
  const std::string password = crypto::randomHex(8);
  const bool saved = saveCredential("setup_salt", "setup_hash", password) &&
                     preferences_.putBytes("setup_ap", password.data(), password.size()) ==
                         password.size();
  setup_password_new_ = saved;
  return saved ? password : std::string{};
}

bool ConfigService::setupPasswordNew() const { return setup_password_new_; }

bool ConfigService::hasAdminPassword() const {
  return preferences_.getBytesLength("admin_hash") == crypto::Key32{}.size() &&
         preferences_.getBytesLength("admin_salt") == 16;
}

bool ConfigService::verifySetupPassword(const std::string& password) const {
  return credentialMatches("setup_salt", "setup_hash", password);
}

bool ConfigService::setAdminPassword(const std::string& password) {
  if (password.size() < 12 || password.size() > 128) {
    return false;
  }
  return saveCredential("admin_salt", "admin_hash", password);
}

bool ConfigService::commitProvisioning(const RuntimeConfig& candidate,
                                       const std::string& wifi_password,
                                       const std::string& enrollment_token,
                                       const std::string& admin_password) {
  struct Snapshot {
    const char* key;
    std::vector<std::uint8_t> value;
  };
  std::array<Snapshot, 4> snapshots{{
      {"wifi_pwd", {}}, {"enroll_tok", {}}, {"admin_salt", {}},
      {"admin_hash", {}}}};
  for (auto& snapshot : snapshots) {
    const std::size_t length = preferences_.getBytesLength(snapshot.key);
    snapshot.value.resize(length);
    if (length != 0 && preferences_.getBytes(snapshot.key, snapshot.value.data(),
                                              length) != length) {
      return false;
    }
  }
  const RuntimeConfig previous_config = config_;
  const bool applied = stage(candidate, true) &&
                       setWifiCredentials(candidate.wifi_ssid, wifi_password) &&
                       setEnrollmentToken(enrollment_token) &&
                       setAdminPassword(admin_password) && commitStaged();
  if (applied) return true;

  config_ = previous_config;
  saveConfig("cfg", previous_config);
  for (const auto& snapshot : snapshots) {
    if (snapshot.value.empty()) {
      preferences_.remove(snapshot.key);
    } else {
      preferences_.putBytes(snapshot.key, snapshot.value.data(), snapshot.value.size());
    }
  }
  rollbackStaged();
  return false;
}

bool ConfigService::verifyAdminPassword(const std::string& password) const {
  return credentialMatches("admin_salt", "admin_hash", password);
}

bool ConfigService::networkReset() {
  preferences_.remove("wifi_pwd");
  preferences_.remove("setup_ap");
  preferences_.remove("setup_salt");
  preferences_.remove("setup_hash");
  setup_password_new_ = false;
  config_.wifi_ssid.clear();
  return saveConfig("cfg", config_);
}

bool ConfigService::beginReenrollment(const std::string& token) {
  if (token.empty() || token.size() > 256 || !setEnrollmentToken(token)) {
    return false;
  }
  const bool removed_device = preferences_.remove("device_id");
  const bool removed_secret = preferences_.remove("enroll_sec");
  preferences_.remove("ota_pub");
  preferences_.remove("server_ack");
  preferences_.remove("server_cfg");
  if (!removed_device || !removed_secret) {
    preferences_.remove("enroll_tok");
    return false;
  }
  identity_.device_id.clear();
  identity_.enrolled = false;
  return true;
}

bool ConfigService::factoryReset() {
  if (!preferences_.clear()) {
    return false;
  }
  config_ = RuntimeConfig{};
  identity_ = DeviceIdentity{};
  safe_mode_ = false;
  safe_mode_reason_.clear();
  initializeIdentity();
  config_.hostname = defaultHostname(identity_);
  return saveConfig("cfg", config_);
}

std::uint64_t ConfigService::serverAckSequence() const {
  return preferences_.getULong64("server_ack", 0);
}

bool ConfigService::setServerAckSequence(const std::uint64_t sequence) {
  const std::uint64_t current = serverAckSequence();
  return sequence >= current && preferences_.putULong64("server_ack", sequence) == sizeof(sequence);
}

std::uint32_t ConfigService::serverConfigVersion() const {
  return preferences_.getUInt("server_cfg", 0);
}

bool ConfigService::setServerConfigVersion(const std::uint32_t version) {
  const std::uint32_t current = serverConfigVersion();
  return version >= current &&
         preferences_.putUInt("server_cfg", version) == sizeof(version);
}

std::uint64_t ConfigService::energyOffsetWh() const {
  return preferences_.getULong64("energy_off", 0);
}

bool ConfigService::setEnergyOffsetWh(const std::uint64_t offset) {
  return offset >= energyOffsetWh() &&
         preferences_.putULong64("energy_off", offset) == sizeof(offset);
}

bool ConfigService::recordBootStarted() {
  const std::uint32_t failures = preferences_.getUInt("boot_fail", 0);
  return preferences_.putUInt("boot_fail", std::min<std::uint32_t>(failures + 1, 100)) == sizeof(std::uint32_t);
}

bool ConfigService::recordBootHealthy() {
  safe_mode_ = false;
  safe_mode_reason_.clear();
  return preferences_.putUInt("boot_fail", 0) == sizeof(std::uint32_t);
}

bool ConfigService::setDiagnosticLogLevel(const std::uint8_t level) {
  if (level > 5 || config_.diagnostic_log_level == level) {
    return level <= 5;
  }
  RuntimeConfig candidate = config_;
  candidate.diagnostic_log_level = level;
  return stage(candidate, true) && commitStaged();
}

bool ConfigService::safeMode() const { return safe_mode_; }

std::string ConfigService::safeModeReason() const { return safe_mode_reason_; }

bool ConfigService::loadConfig(const char* key, RuntimeConfig& output) const {
  const String value = preferences_.getString(key, "");
  if (value.isEmpty()) {
    return false;
  }
  ConfigValidation result;
  if (!parseConfig(std::string(value.c_str()), output, result) || !result.valid) {
    return false;
  }
  const bool previous = std::strcmp(key, "cfg_prev") == 0;
  output.server_ca_pem = std::string(preferences_.getString(
      previous ? "server_ca_prev" : "server_ca", "").c_str());
  output.server_fingerprint = std::string(preferences_.getString(
      previous ? "server_fp_prev" : "server_fp", "").c_str());
  return true;
}

bool ConfigService::saveConfig(const char* key, const RuntimeConfig& value) {
  const std::string json = serializeConfig(value);
  const bool config_saved = preferences_.putString(key, json.c_str()) == json.size();
  if (std::strcmp(key, "cfg") == 0 || std::strcmp(key, "cfg_stage") == 0 ||
      std::strcmp(key, "cfg_prev") == 0) {
    const bool staging = std::strcmp(key, "cfg_stage") == 0;
    const bool previous = std::strcmp(key, "cfg_prev") == 0;
    const char* ca_key = staging ? "server_ca_stage" :
                         (previous ? "server_ca_prev" : "server_ca");
    const char* fingerprint_key = staging ? "server_fp_stage" :
                                  (previous ? "server_fp_prev" : "server_fp");
    const bool ca_saved = preferences_.putString(ca_key, value.server_ca_pem.c_str()) ==
                          value.server_ca_pem.size();
    const bool fingerprint_saved =
        preferences_.putString(fingerprint_key, value.server_fingerprint.c_str()) ==
        value.server_fingerprint.size();
    return config_saved && ca_saved && fingerprint_saved;
  }
  return config_saved;
}

std::string ConfigService::serializeConfig(const RuntimeConfig& value) const {
  JsonDocument document;
  document["schema_version"] = value.schema_version;
  document["config_version"] = value.config_version;
  document["friendly_name"] = value.friendly_name;
  document["hostname"] = value.hostname;
  document["site_id"] = value.site_id;
  document["circuit_id"] = value.circuit_id;
  document["parent_circuit_id"] = value.parent_circuit_id;
  document["measurement_role"] = value.measurement_role;
  document["wifi_ssid"] = value.wifi_ssid;
  document["static_network_enabled"] = value.static_network_enabled;
  document["static_ip"] = value.static_ip;
  document["static_gateway"] = value.static_gateway;
  document["static_subnet"] = value.static_subnet;
  document["static_dns"] = value.static_dns;
  document["server_url"] = value.server_url;
  document["server_ca_configured"] = !value.server_ca_pem.empty();
  document["server_fingerprint_configured"] = !value.server_fingerprint.empty();
  document["connection_mode"] = connectionModeName(value.connection_mode);
  JsonArray allowed = document["allowed_server_addresses"].to<JsonArray>();
  for (const auto& address : value.allowed_server_addresses) {
    if (!address.empty()) allowed.add(address);
  }
  document["live_interval_seconds"] = value.live_interval_seconds;
  document["sample_interval_seconds"] = value.sample_interval_seconds;
  document["pzem_timeout_ms"] = value.pzem_timeout_ms;
  document["durable_log_interval_seconds"] = value.durable_log_interval_seconds;
  document["heartbeat_interval_seconds"] = value.heartbeat_interval_seconds;
  document["sync_interval_seconds"] = value.sync_interval_seconds;
  document["sync_retry_max_seconds"] = value.sync_retry_max_seconds;
  document["ct_rating_a"] = value.ct_rating_a;
  document["ct_warning_fraction"] = value.ct_warning_fraction;
  document["ct_critical_fraction"] = value.ct_critical_fraction;
  document["ct_fault_fraction"] = value.ct_fault_fraction;
  document["voltage_minimum_v"] = value.voltage_minimum_v;
  document["voltage_maximum_v"] = value.voltage_maximum_v;
  document["frequency_minimum_hz"] = value.frequency_minimum_hz;
  document["frequency_maximum_hz"] = value.frequency_maximum_hz;
  document["timezone"] = value.timezone;
  JsonArray ntp = document["ntp_servers"].to<JsonArray>();
  for (const auto& server : value.ntp_servers) {
    ntp.add(server);
  }
  document["sd_spi_hz"] = value.sd_spi_hz;
  document["storage_warning_free_bytes"] = value.storage_warning_free_bytes;
  document["retention_enabled"] = value.retention_enabled;
  document["retention_days"] = value.retention_days;
  document["local_session_timeout_seconds"] = value.local_session_timeout_seconds;
  document["ota_channel"] = value.ota_channel;
  document["ota_update_window_enabled"] = value.ota_update_window_enabled;
  document["ota_update_window_start_hour"] = value.ota_update_window_start_hour;
  document["ota_update_window_end_hour"] = value.ota_update_window_end_hour;
  document["diagnostic_log_level"] = value.diagnostic_log_level;
  std::string output;
  serializeJson(document, output);
  return output;
}

bool ConfigService::parseConfig(const std::string& json, RuntimeConfig& value,
                                ConfigValidation& result) const {
  JsonDocument document;
  const DeserializationError error = deserializeJson(document, json);
  if (error) {
    result = {false, "config_json_invalid", error.c_str()};
    return false;
  }
  value.schema_version = document["schema_version"] | value.schema_version;
  value.config_version = document["config_version"] | value.config_version;
  value.friendly_name = document["friendly_name"] | value.friendly_name.c_str();
  value.hostname = document["hostname"] | value.hostname.c_str();
  value.site_id = document["site_id"] | value.site_id.c_str();
  value.circuit_id = document["circuit_id"] | value.circuit_id.c_str();
  value.parent_circuit_id = document["parent_circuit_id"] | value.parent_circuit_id.c_str();
  value.measurement_role = document["measurement_role"] | value.measurement_role.c_str();
  value.wifi_ssid = document["wifi_ssid"] | value.wifi_ssid.c_str();
  value.static_network_enabled = document["static_network_enabled"] | value.static_network_enabled;
  value.static_ip = document["static_ip"] | value.static_ip.c_str();
  value.static_gateway = document["static_gateway"] | value.static_gateway.c_str();
  value.static_subnet = document["static_subnet"] | value.static_subnet.c_str();
  value.static_dns = document["static_dns"] | value.static_dns.c_str();
  value.server_url = document["server_url"] | value.server_url.c_str();
  if (document["server_ca_pem"].is<const char*>()) {
    value.server_ca_pem = document["server_ca_pem"].as<const char*>();
  }
  if (document["server_fingerprint"].is<const char*>()) {
    value.server_fingerprint = document["server_fingerprint"].as<const char*>();
  }
  value.connection_mode = parseMode(document["connection_mode"] | connectionModeName(value.connection_mode));
  if (document["allowed_server_addresses"].is<JsonArray>()) {
    value.allowed_server_addresses = {};
    std::size_t index = 0;
    for (JsonVariant item : document["allowed_server_addresses"].as<JsonArray>()) {
      if (index < value.allowed_server_addresses.size() && item.is<const char*>()) {
        value.allowed_server_addresses[index++] = item.as<const char*>();
      }
    }
  }
  value.live_interval_seconds = document["live_interval_seconds"] | value.live_interval_seconds;
  value.sample_interval_seconds = document["sample_interval_seconds"] | value.sample_interval_seconds;
  value.pzem_timeout_ms = document["pzem_timeout_ms"] | value.pzem_timeout_ms;
  value.durable_log_interval_seconds = document["durable_log_interval_seconds"] | value.durable_log_interval_seconds;
  value.heartbeat_interval_seconds = document["heartbeat_interval_seconds"] | value.heartbeat_interval_seconds;
  value.sync_interval_seconds = document["sync_interval_seconds"] | value.sync_interval_seconds;
  value.sync_retry_max_seconds = document["sync_retry_max_seconds"] | value.sync_retry_max_seconds;
  value.ct_rating_a = document["ct_rating_a"] | value.ct_rating_a;
  value.ct_warning_fraction = document["ct_warning_fraction"] | value.ct_warning_fraction;
  value.ct_critical_fraction = document["ct_critical_fraction"] | value.ct_critical_fraction;
  value.ct_fault_fraction = document["ct_fault_fraction"] | value.ct_fault_fraction;
  value.voltage_minimum_v = document["voltage_minimum_v"] | value.voltage_minimum_v;
  value.voltage_maximum_v = document["voltage_maximum_v"] | value.voltage_maximum_v;
  value.frequency_minimum_hz = document["frequency_minimum_hz"] | value.frequency_minimum_hz;
  value.frequency_maximum_hz = document["frequency_maximum_hz"] | value.frequency_maximum_hz;
  value.timezone = document["timezone"] | value.timezone.c_str();
  if (document["ntp_servers"].is<JsonArray>()) {
    std::size_t index = 0;
    for (JsonVariant item : document["ntp_servers"].as<JsonArray>()) {
      if (index < value.ntp_servers.size()) {
        value.ntp_servers[index++] = item.as<const char*>();
      }
    }
  }
  value.sd_spi_hz = document["sd_spi_hz"] | value.sd_spi_hz;
  value.storage_warning_free_bytes = document["storage_warning_free_bytes"] | value.storage_warning_free_bytes;
  value.retention_enabled = document["retention_enabled"] | value.retention_enabled;
  value.retention_days = document["retention_days"] | value.retention_days;
  value.local_session_timeout_seconds = document["local_session_timeout_seconds"] | value.local_session_timeout_seconds;
  value.ota_channel = document["ota_channel"] | value.ota_channel.c_str();
  value.ota_update_window_enabled = document["ota_update_window_enabled"] | value.ota_update_window_enabled;
  value.ota_update_window_start_hour = document["ota_update_window_start_hour"] | value.ota_update_window_start_hour;
  value.ota_update_window_end_hour = document["ota_update_window_end_hour"] | value.ota_update_window_end_hour;
  value.diagnostic_log_level = document["diagnostic_log_level"] | value.diagnostic_log_level;
  result = validate(value, true);
  return result.valid;
}

bool ConfigService::credentialMatches(const char* salt_key, const char* hash_key,
                                      const std::string& password) const {
  std::array<std::uint8_t, 16> salt{};
  crypto::Key32 expected{};
  if (preferences_.getBytes(salt_key, salt.data(), salt.size()) != salt.size() ||
      preferences_.getBytes(hash_key, expected.data(), expected.size()) != expected.size()) {
    return false;
  }
  const crypto::Key32 actual =
      crypto::passwordHash(password, salt, build::PBKDF2_ITERATIONS);
  const std::string expected_hex = crypto::hexEncode(expected.data(), expected.size());
  const std::string actual_hex = crypto::hexEncode(actual.data(), actual.size());
  return crypto::constantTimeEqual(expected_hex, actual_hex);
}

bool ConfigService::saveCredential(const char* salt_key, const char* hash_key,
                                   const std::string& password) {
  std::array<std::uint8_t, 16> salt{};
  crypto::secureRandom(salt.data(), salt.size());
  const crypto::Key32 hash =
      crypto::passwordHash(password, salt, build::PBKDF2_ITERATIONS);
  return preferences_.putBytes(salt_key, salt.data(), salt.size()) == salt.size() &&
         preferences_.putBytes(hash_key, hash.data(), hash.size()) == hash.size();
}

void ConfigService::initializeIdentity() {
  identity_.local_instance_id = std::string(preferences_.getString("local_id", "").c_str());
  if (identity_.local_instance_id.empty()) {
    identity_.local_instance_id = crypto::uuidV4();
    preferences_.putString("local_id", identity_.local_instance_id.c_str());
  }
  identity_.device_id = std::string(preferences_.getString("device_id", "").c_str());
  identity_.enrolled = identity_.device_id.size() == 36 &&
                       preferences_.getBytesLength("enroll_sec") >= 32;
  identity_.boot_id = crypto::uuidV4();
  const std::uint64_t efuse_mac = ESP.getEfuseMac();
  const auto* bytes = reinterpret_cast<const std::uint8_t*>(&efuse_mac);
  const std::string material = crypto::hexEncode(bytes, sizeof(efuse_mac)) + "pm-hardware-v1";
  const std::string digest = crypto::sha256Hex(
      reinterpret_cast<const std::uint8_t*>(material.data()), material.size());
  identity_.hardware_id = "esp32s3-" + digest.substr(0, 20);
}

}  // namespace pm
