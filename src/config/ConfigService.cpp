#include "config/ConfigService.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

#include <Arduino.h>
#include <ArduinoJson.h>
#include <ESP.h>

#include "build_config.h"

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
  if (!preferences_.begin("pm-agent", false)) {
    return false;
  }
  initializeIdentity();
  if (!loadConfig("cfg", config_)) {
    config_ = RuntimeConfig{};
    config_.hostname = defaultHostname(identity_);
    if (!saveConfig("cfg", config_)) {
      return false;
    }
  }
  if (config_.hostname.empty()) {
    config_.hostname = defaultHostname(identity_);
  }
  const std::uint32_t boot_failures = preferences_.getUInt("boot_fail", 0);
  safe_mode_ = boot_failures >= 3;
  safe_mode_reason_ = safe_mode_ ? "three_consecutive_incomplete_boots" : "";
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
  if (candidate.hostname.empty() || candidate.hostname.size() > 63 ||
      candidate.hostname.front() == '-' || candidate.hostname.back() == '-' ||
      !std::all_of(candidate.hostname.begin(), candidate.hostname.end(), [](const char value) {
        return (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') || value == '-';
      })) {
    return {false, "hostname_invalid", "Hostname must be a lowercase RFC 1123 label."};
  }
  if (!candidate.server_url.empty() && !startsWith(candidate.server_url, "https://")) {
    return {false, "server_url_insecure", "The central server URL must use HTTPS."};
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
  if (candidate.pzem_timeout_ms < 100 || candidate.pzem_timeout_ms > 5000) {
    return {false, "pzem_timeout_invalid", "PZEM timeout must be 100 through 5000 milliseconds."};
  }
  if (candidate.ct_rating_a < 1.0F || candidate.ct_rating_a > 1000.0F) {
    return {false, "ct_rating_invalid", "CT rating must be 1 through 1000 amperes and match the installed set."};
  }
  if (candidate.ct_rating_a != config_.ct_rating_a && !ct_change_acknowledged) {
    return {false, "ct_change_ack_required", "Changing CT rating requires explicit physical-hardware acknowledgement."};
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
  if (candidate.local_session_timeout_seconds < 60 ||
      candidate.local_session_timeout_seconds > 86400) {
    return {false, "session_timeout_invalid", "Local session timeout must be 60 through 86400 seconds."};
  }
  if (candidate.ota_channel != "stable" && candidate.ota_channel != "beta") {
    return {false, "ota_channel_invalid", "OTA channel must be stable or beta."};
  }
  return {true, "ok", "Configuration is valid."};
}

bool ConfigService::stage(const RuntimeConfig& candidate,
                          const bool ct_change_acknowledged) {
  if (!validate(candidate, ct_change_acknowledged).valid) {
    return false;
  }
  staged_ = candidate;
  staged_.config_version = std::max(config_.config_version + 1,
                                    candidate.config_version);
  staged_valid_ = saveConfig("cfg_stage", staged_);
  return staged_valid_;
}

bool ConfigService::commitStaged() {
  if (!staged_valid_) {
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
  return true;
}

bool ConfigService::rollbackStaged() {
  preferences_.remove("cfg_stage");
  preferences_.remove("server_ca_stage");
  preferences_.remove("server_fp_stage");
  staged_valid_ = false;
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
  if (ssid.empty() || ssid.size() > 32 || password.size() > 63) {
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
                     preferences_.putString("ota_pub", ota_public_key.c_str()) == ota_public_key.size();
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
  output.server_ca_pem = std::string(preferences_.getString("server_ca", "").c_str());
  output.server_fingerprint = std::string(preferences_.getString("server_fp", "").c_str());
  return true;
}

bool ConfigService::saveConfig(const char* key, const RuntimeConfig& value) {
  const std::string json = serializeConfig(value);
  const bool config_saved = preferences_.putString(key, json.c_str()) == json.size();
  if (std::strcmp(key, "cfg") == 0 || std::strcmp(key, "cfg_stage") == 0) {
    const bool staging = std::strcmp(key, "cfg_stage") == 0;
    const char* ca_key = staging ? "server_ca_stage" : "server_ca";
    const char* fingerprint_key = staging ? "server_fp_stage" : "server_fp";
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
  document["wifi_ssid"] = value.wifi_ssid;
  document["server_url"] = value.server_url;
  document["server_ca_configured"] = !value.server_ca_pem.empty();
  document["server_fingerprint_configured"] = !value.server_fingerprint.empty();
  document["connection_mode"] = connectionModeName(value.connection_mode);
  document["sample_interval_seconds"] = value.sample_interval_seconds;
  document["pzem_timeout_ms"] = value.pzem_timeout_ms;
  document["durable_log_interval_seconds"] = value.durable_log_interval_seconds;
  document["heartbeat_interval_seconds"] = value.heartbeat_interval_seconds;
  document["sync_retry_max_seconds"] = value.sync_retry_max_seconds;
  document["ct_rating_a"] = value.ct_rating_a;
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
  document["retention_enabled"] = value.retention_enabled;
  document["retention_days"] = value.retention_days;
  document["local_session_timeout_seconds"] = value.local_session_timeout_seconds;
  document["ota_channel"] = value.ota_channel;
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
  value.wifi_ssid = document["wifi_ssid"] | value.wifi_ssid.c_str();
  value.server_url = document["server_url"] | value.server_url.c_str();
  value.connection_mode = parseMode(document["connection_mode"] | connectionModeName(value.connection_mode));
  value.sample_interval_seconds = document["sample_interval_seconds"] | value.sample_interval_seconds;
  value.pzem_timeout_ms = document["pzem_timeout_ms"] | value.pzem_timeout_ms;
  value.durable_log_interval_seconds = document["durable_log_interval_seconds"] | value.durable_log_interval_seconds;
  value.heartbeat_interval_seconds = document["heartbeat_interval_seconds"] | value.heartbeat_interval_seconds;
  value.sync_retry_max_seconds = document["sync_retry_max_seconds"] | value.sync_retry_max_seconds;
  value.ct_rating_a = document["ct_rating_a"] | value.ct_rating_a;
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
  value.retention_enabled = document["retention_enabled"] | value.retention_enabled;
  value.retention_days = document["retention_days"] | value.retention_days;
  value.local_session_timeout_seconds = document["local_session_timeout_seconds"] | value.local_session_timeout_seconds;
  value.ota_channel = document["ota_channel"] | value.ota_channel.c_str();
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
