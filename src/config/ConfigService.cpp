#include "config/ConfigService.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <vector>

#include <Arduino.h>
#include <ArduinoJson.h>
#include <ESP.h>
#include <mbedtls/x509_crt.h>
#include <nvs_flash.h>

#include "build_config.h"
#include "config/ConfigRecovery.h"
#include "config/ConfigValidationHelpers.h"
#include "diagnostics/DiagnosticCore.h"
#include "diagnostics/SerialLogger.h"

namespace pm {
namespace {

constexpr char kLegacyNamespace[] = "pm-agent";
constexpr char kPersistentPartition[] = "pmconfig";
constexpr char kPersistentNamespace[] = "pm-state";
constexpr persistence::SlotKeys kConfigSlots{"cfg_a", "cfg_b", "cfg_active"};
constexpr persistence::SlotKeys kEnrollmentSlots{"enroll_a", "enroll_b",
                                                 "enroll_active"};
constexpr char kProvisioningTransactionKey[] = "provision_txn";
constexpr TickType_t kStateReadTimeout = pdMS_TO_TICKS(25);

class PreferencesBlobStore final : public persistence::BlobStore {
public:
  bool read(const char *key, std::vector<std::uint8_t> &value) override {
    Preferences preferences;
    if (!preferences.begin(kPersistentNamespace, true, kPersistentPartition)) {
      return false;
    }
    const std::size_t length = preferences.getBytesLength(key);
    value.resize(length);
    const bool read = length != 0 &&
                      preferences.getBytes(key, value.data(), length) == length;
    preferences.end();
    if (!read)
      value.clear();
    return read;
  }

  bool write(const char *key, const std::uint8_t *value,
             const std::size_t length) override {
    Preferences preferences;
    if (length == 0 ||
        !preferences.begin(kPersistentNamespace, false, kPersistentPartition)) {
      return false;
    }
    const bool written = preferences.putBytes(key, value, length) == length;
    preferences.end();
    return written;
  }

  bool erase(const char *key) override {
    Preferences preferences;
    if (!preferences.begin(kPersistentNamespace, false, kPersistentPartition)) {
      return false;
    }
    const bool absent = !preferences.isKey(key);
    const bool erased = absent || preferences.remove(key);
    preferences.end();
    return erased;
  }

  bool exists(const char *key) override {
    bool present = false;
    return keyPresence(key, present) && present;
  }

  bool keyPresence(const char *key, bool &present) {
    present = false;
    Preferences preferences;
    if (!preferences.begin(kPersistentNamespace, true, kPersistentPartition)) {
      return false;
    }
    present = preferences.isKey(key);
    preferences.end();
    return true;
  }
};

class RecursiveMutexGuard {
public:
  RecursiveMutexGuard(const SemaphoreHandle_t mutex, const TickType_t timeout)
      : mutex_(mutex),
        locked_(mutex != nullptr &&
                xSemaphoreTakeRecursive(mutex, timeout) == pdTRUE) {}

  ~RecursiveMutexGuard() {
    if (locked_)
      xSemaphoreGiveRecursive(mutex_);
  }

  explicit operator bool() const { return locked_; }

private:
  SemaphoreHandle_t mutex_{nullptr};
  bool locked_{false};
};

ConnectionMode parseMode(const char *value) {
  if (value != nullptr && std::strcmp(value, "pull") == 0) {
    return ConnectionMode::Pull;
  }
  if (value != nullptr && std::strcmp(value, "push") == 0) {
    return ConnectionMode::Push;
  }
  return ConnectionMode::Hybrid;
}

bool validIpv4(const std::string &value) {
  IPAddress address;
  return !value.empty() && address.fromString(value.c_str());
}

bool validMeasurementRole(const std::string &value) {
  return value == "main" || value == "service-leg" || value == "branch" ||
         value == "submeter" || value == "other";
}

bool validCaCertificateBundle(const std::string &pem) {
  if (pem.empty() || config_validation::containsPrivateKeyPem(pem)) {
    return false;
  }
  mbedtls_x509_crt certificates;
  mbedtls_x509_crt_init(&certificates);
  const int parsed = mbedtls_x509_crt_parse(
      &certificates, reinterpret_cast<const unsigned char *>(pem.c_str()),
      pem.size() + 1U);
  bool found_certificate = false;
  bool all_certificate_authorities = true;
  for (const mbedtls_x509_crt *certificate = &certificates;
       certificate != nullptr && certificate->version != 0;
       certificate = certificate->next) {
    found_certificate = true;
    if (certificate->ca_istrue == 0) {
      all_certificate_authorities = false;
      break;
    }
  }
  mbedtls_x509_crt_free(&certificates);
  return parsed == 0 && found_certificate && all_certificate_authorities;
}

std::string defaultHostname(const DeviceIdentity &identity) {
  std::string source =
      identity.device_id.empty() ? identity.hardware_id : identity.device_id;
  source.erase(std::remove(source.begin(), source.end(), '-'), source.end());
  const std::string suffix =
      source.size() > 6 ? source.substr(source.size() - 6) : source;
  return "power-monitor-" + suffix;
}

bool erasePreferenceChecked(Preferences &preferences, const char *key) {
  if (!preferences.isKey(key))
    return true;
  return preferences.remove(key) && !preferences.isKey(key);
}

bool validSetupPassword(const std::string &password) {
  return password.size() >= 12U && password.size() <= 63U &&
         std::all_of(password.begin(), password.end(), [](const char value) {
           const auto character = static_cast<unsigned char>(value);
           return character >= 0x21U && character <= 0x7eU;
         });
}

bool readSetupPassword(Preferences &preferences, const char *key,
                       std::string &password) {
  const std::size_t length = preferences.getBytesLength(key);
  if (length < 12U || length > 63U) {
    return false;
  }
  password.assign(length, '\0');
  if (preferences.getBytes(key, password.data(), password.size()) !=
          password.size() ||
      !validSetupPassword(password)) {
    std::fill(password.begin(), password.end(), '\0');
    password.clear();
    return false;
  }
  return true;
}

bool writeBytesChecked(Preferences &preferences, const char *key,
                       const std::uint8_t *value, const std::size_t length) {
  if (value == nullptr || length == 0U ||
      preferences.putBytes(key, value, length) != length ||
      preferences.getBytesLength(key) != length) {
    return false;
  }
  std::vector<std::uint8_t> readback(length);
  const bool verified =
      preferences.getBytes(key, readback.data(), readback.size()) ==
          readback.size() &&
      std::equal(readback.begin(), readback.end(), value);
  std::fill(readback.begin(), readback.end(), std::uint8_t{0});
  return verified;
}

bool writeUIntChecked(Preferences &preferences, const char *key,
                      const std::uint32_t value) {
  return preferences.putUInt(key, value) == sizeof(value) &&
         preferences.getUInt(key, value ^ 0xFFFFFFFFU) == value;
}

bool writeULong64Checked(Preferences &preferences, const char *key,
                         const std::uint64_t value) {
  return preferences.putULong64(key, value) == sizeof(value) &&
         preferences.getULong64(key, value ^ 0xFFFFFFFFFFFFFFFFULL) == value;
}

template <std::size_t N>
bool erasePreferencesChecked(Preferences &preferences,
                             const std::array<const char *, N> &keys) {
  bool erased = true;
  for (const char *key : keys) {
    erased = erasePreferenceChecked(preferences, key) && erased;
  }
  return erased;
}

bool eraseLegacyConfigCopies(Preferences &preferences) {
  constexpr std::array<const char *, 10> kLegacyConfigKeys{"cfg",
                                                           "cfg_prev",
                                                           "cfg_stage",
                                                           "wifi_pwd",
                                                           "server_ca",
                                                           "server_ca_prev",
                                                           "server_ca_stage",
                                                           "server_fp",
                                                           "server_fp_prev",
                                                           "server_fp_stage"};
  return erasePreferencesChecked(preferences, kLegacyConfigKeys);
}

bool eraseLegacyEnrollmentCopies(Preferences &preferences) {
  constexpr std::array<const char *, 3> kLegacyEnrollmentKeys{
      "device_id", "enroll_sec", "ota_pub"};
  return erasePreferencesChecked(preferences, kLegacyEnrollmentKeys);
}

} // namespace

const char *connectionModeName(const ConnectionMode mode) {
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
  if (!initializeMutexes()) {
    PM_LOG_FATAL("CONFIG", "MUTEX_INIT_FAILED", "error=PM-CONFIG-001");
    return false;
  }
  PM_LOG_INFO("CONFIG", "NVS_OPEN_BEGIN",
              "legacy_namespace=%s config_partition=%s config_namespace=%s",
              kLegacyNamespace, kPersistentPartition, kPersistentNamespace);
  if (!preferences_.begin(kLegacyNamespace, false)) {
    PM_LOG_FATAL("CONFIG", "NVS_OPEN_FAILED",
                 "error=PM-CONFIG-001 namespace=%s", kLegacyNamespace);
    return false;
  }
  if (!initializePersistentPartition()) {
    PM_LOG_FATAL("CONFIG", "PERSISTENT_PARTITION_INIT_FAILED",
                 "error=PM-CONFIG-018 partition=%s legacy_preserved=true",
                 kPersistentPartition);
    return false;
  }
  initializeIdentity();
  if (!recoverIncompleteProvisioning()) {
    PM_LOG_FATAL(
        "CONFIG", "PROVISIONING_RECOVERY_FAILED",
        "error=PM-CONFIG-031 recovery=fail_closed setup_state=unchanged");
    return false;
  }
  if (!loadOrMigrateEnrollment()) {
    PM_LOG_FATAL("CONFIG", "ENROLLMENT_STORE_INIT_FAILED",
                 "error=PM-CONFIG-010 partition=%s", kPersistentPartition);
    return false;
  }

  bool defaults_created = false;
  bool previous_recovered = false;
  bool migrated_legacy = false;
  RuntimeConfig loaded;
  std::string loaded_password;
  std::uint64_t loaded_generation = 0;
  if (!loadPersistentConfig(loaded, loaded_password, loaded_generation)) {
    PreferencesBlobStore store;
    if (persistence::anyDataPresent(store, kConfigSlots)) {
      PM_LOG_FATAL(
          "CONFIG", "PERSISTED_CONFIG_UNRECOVERABLE",
          "error=PM-CONFIG-011 partition=%s slots_present=true valid=false",
          kPersistentPartition);
      return false;
    }

    RuntimeConfig primary;
    const bool primary_loaded = loadLegacyConfig("cfg", primary);
    std::string legacy_password;
    const std::size_t password_length = preferences_.getBytesLength("wifi_pwd");
    if (password_length > 0 && password_length <= 128) {
      legacy_password.resize(password_length);
      if (preferences_.getBytes("wifi_pwd", legacy_password.data(),
                                legacy_password.size()) !=
          legacy_password.size()) {
        legacy_password.clear();
      }
    }
    const bool password_present = !legacy_password.empty();
    const bool possible_orphaned_credentials =
        primary_loaded && primary.wifi_ssid.empty() && password_present;
    RuntimeConfig previous;
    const bool previous_loaded =
        (!primary_loaded || possible_orphaned_credentials) &&
        loadLegacyConfig("cfg_prev", previous);
    if (shouldRecoverPreviousConfig(
            primary_loaded, primary_loaded && !primary.wifi_ssid.empty(),
            password_present, previous_loaded,
            previous_loaded && !previous.wifi_ssid.empty())) {
      loaded = previous;
      loaded_password = legacy_password;
      previous_recovered = true;
      PM_LOG_WARN("CONFIG", "LEGACY_CONFIG_RECOVERED",
                  "error=PM-CONFIG-007 source=cfg_prev reason=%s version=%lu "
                  "wifi_ssid=%s",
                  primary_loaded ? "orphaned_wifi_credentials"
                                 : "primary_invalid",
                  static_cast<unsigned long>(loaded.config_version),
                  diag::maskSsid(loaded.wifi_ssid).c_str());
    } else if (primary_loaded) {
      loaded = primary;
      loaded_password = legacy_password;
    } else {
      loaded = RuntimeConfig{};
      loaded.hostname = defaultHostname(identityUnsafe());
      loaded_password.clear();
      defaults_created = true;
    }
    if (legacyWifiPairNeedsQuarantine(!loaded.wifi_ssid.empty(),
                                      loaded_password.size(),
                                      possible_orphaned_credentials)) {
      PM_LOG_WARN("CONFIG", "LEGACY_WIFI_PAIR_QUARANTINED",
                  "error=PM-CONFIG-012 wifi_ssid=%s wifi_psk_state=%s "
                  "recovery=provisioning non_network_fields_preserved=true",
                  loaded.wifi_ssid.empty() ? "missing" : "present",
                  possible_orphaned_credentials ? "orphaned" : "invalid");
      loaded.wifi_ssid.clear();
      loaded.static_network_enabled = false;
      loaded.static_ip.clear();
      loaded.static_gateway.clear();
      loaded.static_subnet.clear();
      loaded.static_dns.clear();
      std::fill(loaded_password.begin(), loaded_password.end(), '\0');
      loaded_password.clear();
    }
    if (!commitPersistentConfig(loaded, loaded_password, &loaded_generation) ||
        !verifyPersistentConfig(loaded, loaded_password)) {
      PM_LOG_FATAL("CONFIG", "LEGACY_MIGRATION_FAILED",
                   "error=PM-CONFIG-013 legacy_preserved=true partition=%s",
                   kPersistentPartition);
      return false;
    }
    migrated_legacy = primary_loaded || previous_loaded;
    PM_LOG_INFO(
        "CONFIG", "LEGACY_MIGRATION_VERIFIED",
        "atomic_readback=verified legacy_cleanup=pending generation=%llu "
        "source=%s",
        static_cast<unsigned long long>(loaded_generation),
        defaults_created ? "defaults"
                         : (previous_recovered ? "cfg_prev" : "cfg"));
  }
  if (loaded.hostname.empty()) {
    loaded.hostname = defaultHostname(identityUnsafe());
    if (!commitPersistentConfig(loaded, loaded_password, &loaded_generation)) {
      return false;
    }
  }
  if (!publishPersistentConfig(loaded, loaded_password, loaded_generation)) {
    return false;
  }
  if (!eraseLegacyConfigCopies(preferences_)) {
    PM_LOG_FATAL(
        "CONFIG", "LEGACY_CONFIG_CLEANUP_FAILED",
        "error=PM-CONFIG-029 atomic_config_retained=true retry_on_boot=true");
    return false;
  }
  if (migrated_legacy) {
    PM_LOG_INFO(
        "CONFIG", "LEGACY_CONFIG_CLEANUP_COMPLETE",
        "atomic_config_retained=true duplicate_credentials_removed=true");
  }
  {
    RecursiveMutexGuard state(state_mutex_, pdMS_TO_TICKS(2000));
    if (!state)
      return false;
    admin_password_configured_ =
        preferences_.getBytesLength("admin_hash") == crypto::Key32{}.size() &&
        preferences_.getBytesLength("admin_salt") == 16;
    server_ack_sequence_ = preferences_.getULong64("server_ack", 0);
    server_config_version_ = preferences_.getUInt("server_cfg", 0);
    energy_offset_wh_ = preferences_.getULong64("energy_off", 0);
  }
  if (preferences_.putBool("pmcfg_init", true) != sizeof(bool) ||
      !preferences_.getBool("pmcfg_init", false)) {
    PM_LOG_FATAL("CONFIG", "PERSISTENT_PARTITION_MARKER_FAILED",
                 "error=PM-CONFIG-019 legacy_preserved=true");
    return false;
  }
  const std::uint32_t boot_failures = preferences_.getUInt("boot_fail", 0);
  safe_mode_ = boot_failures >= 3;
  safe_mode_reason_ = safe_mode_ ? "three_consecutive_incomplete_boots" : "";
  PM_LOG_INFO("CONFIG", "NVS_OPEN_COMPLETE",
              "source=%s config_version=%lu boot_failures=%lu safe_mode=%s",
              defaults_created
                  ? "defaults"
                  : (migrated_legacy ? (previous_recovered ? "migrated_previous"
                                                           : "migrated_legacy")
                                     : "atomic_slots"),
              static_cast<unsigned long>(loaded.config_version),
              static_cast<unsigned long>(boot_failures),
              safe_mode_ ? "true" : "false");
  return true;
}

RuntimeConfig ConfigService::config() const {
  RecursiveMutexGuard lock(state_mutex_, kStateReadTimeout);
  return lock ? config_ : RuntimeConfig{};
}

DeviceIdentity ConfigService::identity() const {
  RecursiveMutexGuard lock(state_mutex_, kStateReadTimeout);
  return lock ? identity_ : DeviceIdentity{};
}

ConfigValidation
ConfigService::validate(const RuntimeConfig &candidate,
                        const bool ct_change_acknowledged) const {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(2000));
  if (!mutation) {
    return {false, "config_busy", "Configuration is busy."};
  }
  if (candidate.schema_version != 1) {
    return {false, "config_schema_unsupported",
            "Only configuration schema 1 is supported."};
  }
  if (candidate.friendly_name.empty() || candidate.friendly_name.size() > 64) {
    return {false, "friendly_name_invalid",
            "Friendly name must contain 1 through 64 characters."};
  }
  if (candidate.site_id.size() > 64 || candidate.circuit_id.size() > 64 ||
      candidate.parent_circuit_id.size() > 64 ||
      !validMeasurementRole(candidate.measurement_role)) {
    return {false, "circuit_metadata_invalid",
            "Site/circuit identifiers must be bounded and the measurement role "
            "must be supported."};
  }
  if (candidate.hostname.empty() || candidate.hostname.size() > 63 ||
      candidate.hostname.front() == '-' || candidate.hostname.back() == '-' ||
      !std::all_of(candidate.hostname.begin(), candidate.hostname.end(),
                   [](const char value) {
                     return (value >= 'a' && value <= 'z') ||
                            (value >= '0' && value <= '9') || value == '-';
                   })) {
    return {false, "hostname_invalid",
            "Hostname must be a lowercase RFC 1123 label."};
  }
  if (candidate.wifi_ssid.size() > 32 || candidate.static_ip.size() > 15 ||
      candidate.static_gateway.size() > 15 ||
      candidate.static_subnet.size() > 15 || candidate.static_dns.size() > 15) {
    return {false, "network_string_too_large",
            "Wi-Fi and IPv4 configuration fields exceed device limits."};
  }
  if (candidate.server_url.size() > 256 ||
      (!candidate.server_url.empty() &&
       !config_validation::validHttpsBaseUrl(candidate.server_url))) {
    return {
        false, "server_url_invalid",
        "The central server URL must be an HTTPS origin with a valid host and "
        "optional port, without credentials, path, query, or fragment."};
  }
  if (candidate.server_ca_pem.size() > 8192 ||
      candidate.server_fingerprint.size() > 128) {
    return {false, "tls_trust_too_large",
            "TLS trust material exceeds device limits."};
  }
  if (!candidate.server_ca_pem.empty() &&
      config_validation::containsPrivateKeyPem(candidate.server_ca_pem)) {
    return {false, "tls_private_key_rejected",
            "TLS trust must contain CA certificates only, never private key "
            "material."};
  }
  if (!candidate.server_ca_pem.empty() &&
      !validCaCertificateBundle(candidate.server_ca_pem)) {
    return {false, "tls_ca_invalid",
            "TLS trust must be a well-formed PEM bundle containing only CA "
            "certificates."};
  }
  if (!candidate.server_url.empty() && candidate.server_ca_pem.empty()) {
    return {false, "tls_ca_required",
            "A public server CA PEM is required; fingerprint-only TLS is not "
            "supported because hostname and chain validation are mandatory."};
  }
  if (candidate.ota_signing_public_key_pem.size() > 1024U ||
      candidate.ota_signing_key_id.size() > 128U) {
    return {false, "ota_trust_too_large",
            "The OTA Ed25519 public key or signing-key identifier exceeds "
            "device limits."};
  }
  if (candidate.ota_signing_public_key_pem.empty() !=
      candidate.ota_signing_key_id.empty()) {
    return {false, "ota_trust_pair_incomplete",
            "OTA trust requires both an Ed25519 public-key PEM and its "
            "server signing-key identifier."};
  }
  if (!candidate.ota_signing_public_key_pem.empty() &&
      (config_validation::containsPrivateKeyPem(
           candidate.ota_signing_public_key_pem) ||
       !config_validation::validEd25519PublicKeyPem(
           candidate.ota_signing_public_key_pem))) {
    return {false, "ota_public_key_invalid",
            "OTA trust must be one Ed25519 SubjectPublicKeyInfo public PEM; "
            "private keys are never accepted."};
  }
  if (candidate.static_network_enabled &&
      (!validIpv4(candidate.static_ip) ||
       !validIpv4(candidate.static_gateway) ||
       !validIpv4(candidate.static_subnet) ||
       !validIpv4(candidate.static_dns))) {
    return {false, "static_network_invalid",
            "Static IPv4 address, gateway, subnet mask, and DNS must all be "
            "valid."};
  }
  for (const auto &address : candidate.allowed_server_addresses) {
    if (address.size() > 253 || address.find('/') != std::string::npos) {
      return {false, "allowed_server_address_invalid",
              "Allowed server entries must be bounded hostnames or IP "
              "addresses without paths."};
    }
  }
  if (candidate.live_interval_seconds < 1 ||
      candidate.live_interval_seconds > 60 ||
      candidate.sync_interval_seconds < 5 ||
      candidate.sync_interval_seconds > 3600) {
    return {false, "network_interval_invalid",
            "Live and synchronization intervals are outside supported ranges."};
  }
  if (candidate.sample_interval_seconds < 1 ||
      candidate.sample_interval_seconds > 30) {
    return {false, "sample_interval_invalid",
            "Sample interval must be 1 through 30 seconds."};
  }
  if (candidate.durable_log_interval_seconds < 10 ||
      candidate.durable_log_interval_seconds > 3600 ||
      candidate.durable_log_interval_seconds <
          candidate.sample_interval_seconds) {
    return {false, "log_interval_invalid",
            "Durable interval must be 10 through 3600 seconds and not shorter "
            "than sampling."};
  }
  if (candidate.heartbeat_interval_seconds < 5 ||
      candidate.heartbeat_interval_seconds > 3600) {
    return {false, "heartbeat_interval_invalid",
            "Heartbeat interval must be 5 through 3600 seconds."};
  }
  if (candidate.sync_retry_max_seconds < 1 ||
      candidate.sync_retry_max_seconds > 86400) {
    return {
        false, "sync_retry_limit_invalid",
        "Maximum synchronization retry delay must be 1 through 86400 seconds."};
  }
  if (candidate.pzem_timeout_ms < 100 || candidate.pzem_timeout_ms > 5000) {
    return {false, "pzem_timeout_invalid",
            "PZEM timeout must be 100 through 5000 milliseconds."};
  }
  if (candidate.ct_rating_a < 1.0F || candidate.ct_rating_a > 1000.0F) {
    return {false, "ct_rating_invalid",
            "CT rating must be 1 through 1000 amperes and match the installed "
            "set."};
  }
  if (candidate.ct_rating_a != config_.ct_rating_a && !ct_change_acknowledged) {
    return {false, "ct_change_ack_required",
            "Changing CT rating requires explicit physical-hardware "
            "acknowledgement."};
  }
  if (candidate.ct_warning_fraction <= 0.0F ||
      candidate.ct_warning_fraction >= candidate.ct_critical_fraction ||
      candidate.ct_critical_fraction > 1.0F ||
      candidate.ct_fault_fraction <= candidate.ct_critical_fraction ||
      candidate.ct_fault_fraction > 2.0F) {
    return {false, "ct_thresholds_invalid",
            "CT warning, critical, and fault thresholds must increase safely "
            "within supported bounds."};
  }
  if (candidate.voltage_minimum_v < 0.0F ||
      candidate.voltage_maximum_v <= candidate.voltage_minimum_v ||
      candidate.voltage_maximum_v > 400.0F) {
    return {false, "voltage_limits_invalid",
            "Voltage limits must increase within the shared 0 through 400 V "
            "reading domain."};
  }
  if (candidate.frequency_minimum_hz < 40.0F ||
      candidate.frequency_maximum_hz <= candidate.frequency_minimum_hz ||
      candidate.frequency_maximum_hz > 70.0F) {
    return {false, "frequency_limits_invalid",
            "Frequency limits must increase within the shared 40 through 70 "
            "Hz reading domain."};
  }
  if (candidate.sd_spi_hz < 1'000'000 ||
      candidate.sd_spi_hz > build::MAX_SD_SPI_HZ) {
    return {false, "sd_spi_frequency_invalid",
            "SD SPI frequency must be 1 through 20 MHz."};
  }
  if (candidate.storage_warning_free_bytes < 1024U * 1024U ||
      candidate.storage_warning_free_bytes >
          64ULL * 1024ULL * 1024ULL * 1024ULL) {
    return {false, "storage_warning_threshold_invalid",
            "Storage warning threshold must be 1 MiB through 64 GiB."};
  }
  if (candidate.retention_days < 1 || candidate.retention_days > 3650) {
    return {false, "retention_days_invalid",
            "Retention must be 1 through 3650 days when enabled."};
  }
  if (candidate.timezone.empty() || candidate.timezone.size() > 64) {
    return {false, "timezone_invalid",
            "Display timezone must contain 1 through 64 characters."};
  }
  for (const auto &server : candidate.ntp_servers) {
    if (server.empty() || server.size() > 253) {
      return {false, "ntp_server_invalid",
              "Exactly three bounded NTP server names are required."};
    }
  }
  if (candidate.local_session_timeout_seconds < 60 ||
      candidate.local_session_timeout_seconds > 86400) {
    return {false, "session_timeout_invalid",
            "Local session timeout must be 60 through 86400 seconds."};
  }
  if (candidate.ota_channel != "stable" && candidate.ota_channel != "beta" &&
      candidate.ota_channel != "canary" &&
      candidate.ota_channel != "development") {
    return {false, "ota_channel_invalid",
            "OTA channel must be stable, canary, development, or the legacy "
            "beta alias for canary."};
  }
  if (candidate.ota_update_window_start_hour > 23 ||
      candidate.ota_update_window_end_hour > 23 ||
      (candidate.ota_update_window_enabled &&
       candidate.ota_update_window_start_hour ==
           candidate.ota_update_window_end_hour)) {
    return {
        false, "ota_update_window_invalid",
        "OTA update window hours must be distinct values from 0 through 23."};
  }
  if (candidate.diagnostic_log_level > 5) {
    return {false, "diagnostic_log_level_invalid",
            "Diagnostic log level must be 0 through 5."};
  }
  return {true, "ok", "Configuration is valid."};
}

bool ConfigService::commitCandidate(const RuntimeConfig &candidate,
                                    const bool ct_change_acknowledged,
                                    std::uint64_t &committed_generation) {
  committed_generation = 0;
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(2000));
  if (!mutation)
    return false;
  RuntimeConfig normalized = candidate;
  normalized.server_ca_pem =
      config_validation::normalizePemLineEndings(normalized.server_ca_pem);
  normalized.ota_signing_public_key_pem =
      config_validation::normalizePemLineEndings(
          normalized.ota_signing_public_key_pem);
  const ConfigValidation validation =
      validate(normalized, ct_change_acknowledged);
  if (!validation.valid) {
    PM_LOG_WARN("CONFIG", "COMMIT_REJECTED",
                "error=PM-CONFIG-004 validation=%s", validation.code.c_str());
    return false;
  }
  // Do not make the slot marker durable unless publication to the in-memory
  // snapshot is guaranteed to complete in this same mutation.
  RecursiveMutexGuard state_reservation(state_mutex_, pdMS_TO_TICKS(2000));
  if (!state_reservation)
    return false;
  normalized.config_version =
      std::max(config_.config_version + 1U, normalized.config_version);
  const std::string committed_password = wifi_password_;
  std::uint64_t generation = 0;
  if (!commitPersistentConfig(normalized, committed_password, &generation)) {
    return false;
  }
  const bool verified = verifyPersistentConfig(normalized, committed_password);
  const bool published =
      verified &&
      publishPersistentConfig(normalized, committed_password, generation);
  if (!verified || !published) {
    PreferencesBlobStore store;
    persistence::LoadResult restored;
    const bool rolled_back = persistence::rollbackToPrevious(
        store, kConfigSlots, generation, restored);
    PM_LOG_ERROR("CONFIG", "COMMIT_FINALIZATION_FAILED",
                 "error=PM-CONFIG-031 generation=%llu verified=%s published=%s "
                 "previous_slot_restored=%s",
                 static_cast<unsigned long long>(generation),
                 verified ? "true" : "false", published ? "true" : "false",
                 rolled_back ? "true" : "false");
    return false;
  }
  committed_generation = generation;
  PM_LOG_INFO("CONFIG", "COMMIT_COMPLETE",
              "generation=%llu version=%lu friendly_name=%s wifi_ssid=%s "
              "server_configured=%s",
              static_cast<unsigned long long>(generation),
              static_cast<unsigned long>(normalized.config_version),
              normalized.friendly_name.c_str(),
              diag::maskSsid(normalized.wifi_ssid).c_str(),
              normalized.server_url.empty() ? "false" : "true");
  return true;
}

bool ConfigService::rollbackToPrevious(
    const std::uint64_t expected_current_generation,
    std::uint64_t *restored_generation) {
  if (restored_generation != nullptr)
    *restored_generation = 0;
  if (expected_current_generation == 0U)
    return false;
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(2000));
  if (!mutation)
    return false;
  const std::uint64_t current_generation = persistentGeneration();
  if (current_generation != expected_current_generation) {
    PM_LOG_WARN(
        "CONFIG", "ROLLBACK_CONFLICT",
        "error=PM-CONFIG-022 expected_generation=%llu current_generation=%llu",
        static_cast<unsigned long long>(expected_current_generation),
        static_cast<unsigned long long>(current_generation));
    return false;
  }
  PreferencesBlobStore store;
  persistence::LoadResult previous_record;
  if (!persistence::loadPrevious(
          store, kConfigSlots, expected_current_generation, previous_record)) {
    return false;
  }
  RuntimeConfig previous;
  std::string previous_password;
  ConfigValidation validation;
  const std::string payload(previous_record.payload.begin(),
                            previous_record.payload.end());
  if (!parsePersistentConfig(payload, previous, previous_password,
                             validation)) {
    return false;
  }
  // Reserve the state lock before changing the persistent marker so the RAM
  // publication cannot fail after the rollback has become durable.
  RecursiveMutexGuard state_reservation(state_mutex_, pdMS_TO_TICKS(2000));
  if (!state_reservation) {
    std::fill(previous_password.begin(), previous_password.end(), '\0');
    return false;
  }
  persistence::LoadResult activated;
  if (!persistence::rollbackToPrevious(
          store, kConfigSlots, expected_current_generation, activated) ||
      activated.generation != previous_record.generation ||
      activated.payload != previous_record.payload ||
      !publishPersistentConfig(previous, previous_password,
                               activated.generation)) {
    std::fill(previous_password.begin(), previous_password.end(), '\0');
    return false;
  }
  std::fill(previous_password.begin(), previous_password.end(), '\0');
  if (restored_generation != nullptr) {
    *restored_generation = activated.generation;
  }
  PM_LOG_WARN("CONFIG", "ROLLBACK_COMPLETE",
              "from_generation=%llu to_generation=%llu",
              static_cast<unsigned long long>(expected_current_generation),
              static_cast<unsigned long long>(activated.generation));
  return true;
}

std::uint64_t ConfigService::persistentGeneration() const {
  RecursiveMutexGuard state(state_mutex_, kStateReadTimeout);
  return state ? persistent_generation_ : 0U;
}

bool ConfigService::updateFromJson(const std::string &json, const bool dry_run,
                                   const bool ct_change_acknowledged,
                                   const bool trusted_server_update,
                                   ConfigValidation &result,
                                   std::uint64_t *committed_generation) {
  if (committed_generation != nullptr)
    *committed_generation = 0;
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(2000));
  if (!mutation) {
    result = {false, "config_busy", "Configuration is busy."};
    return false;
  }
  RuntimeConfig candidate = config_;
  if (!parseConfig(json, candidate, result)) {
    return false;
  }
  if (candidate.ota_signing_public_key_pem !=
          config_.ota_signing_public_key_pem ||
      candidate.ota_signing_key_id != config_.ota_signing_key_id) {
    result = {
        false, "ota_trust_local_route_required",
        "Offline OTA trust may be changed only through first-run provisioning "
        "or the authenticated local network-settings operation."};
    return false;
  }
  if (!trusted_server_update &&
      (candidate.wifi_ssid != config_.wifi_ssid ||
       candidate.static_network_enabled != config_.static_network_enabled ||
       candidate.static_ip != config_.static_ip ||
       candidate.static_gateway != config_.static_gateway ||
       candidate.static_subnet != config_.static_subnet ||
       candidate.static_dns != config_.static_dns ||
       candidate.server_url != config_.server_url ||
       candidate.server_ca_pem != config_.server_ca_pem ||
       candidate.server_fingerprint != config_.server_fingerprint ||
       candidate.connection_mode != config_.connection_mode ||
       candidate.allowed_server_addresses !=
           config_.allowed_server_addresses)) {
    result = {
        false, "network_settings_route_required",
        "Wi-Fi, IPv4, server URL, TLS trust, allowlist, and connection mode "
        "must be changed through the atomic network-settings operation."};
    return false;
  }
  result = validate(candidate, ct_change_acknowledged);
  if (!result.valid || dry_run) {
    return result.valid;
  }
  std::uint64_t generation = 0;
  if (!commitCandidate(candidate, ct_change_acknowledged, generation)) {
    result = {false, "config_commit_failed",
              "The validated configuration could not be committed."};
    return false;
  }
  if (committed_generation != nullptr) {
    *committed_generation = generation;
  }
  return true;
}

std::string ConfigService::redactedJson() const {
  return serializeConfig(config());
}

bool ConfigService::hasWifiCredentials() const {
  RecursiveMutexGuard state(state_mutex_, kStateReadTimeout);
  return state && !config_.wifi_ssid.empty() && wifi_password_.size() >= 8 &&
         wifi_password_.size() <= 63;
}

std::string ConfigService::wifiPassword() const {
  RecursiveMutexGuard state(state_mutex_, kStateReadTimeout);
  return state ? wifi_password_ : std::string{};
}

bool ConfigService::setWifiCredentials(const std::string &ssid,
                                       const std::string &password) {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(2000));
  if (!mutation)
    return false;
  if (ssid.empty() || ssid.size() > 32 || password.size() < 8 ||
      password.size() > 63) {
    return false;
  }
  RuntimeConfig candidate = config_;
  candidate.wifi_ssid = ssid;
  candidate.config_version =
      std::max(config_.config_version + 1U, candidate.config_version);
  std::uint64_t generation = 0;
  if (!commitPersistentConfig(candidate, password, &generation) ||
      !verifyPersistentConfig(candidate, password)) {
    return false;
  }
  return publishPersistentConfig(candidate, password, generation);
}

bool ConfigService::updateNetworkSettings(const RuntimeConfig &candidate,
                                          const std::string &wifi_password,
                                          const bool replace_wifi_password,
                                          ConfigValidation &result) {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(2000));
  if (!mutation) {
    result = {false, "config_busy", "Configuration is busy."};
    return false;
  }
  PM_LOG_INFO("CONFIG", "NETWORK_SETTINGS_COMMIT_BEGIN",
              "wifi_ssid=%s replace_psk=%s server_configured=%s",
              diag::maskSsid(candidate.wifi_ssid).c_str(),
              replace_wifi_password ? "true" : "false",
              candidate.server_url.empty() ? "false" : "true");
  RuntimeConfig normalized = candidate;
  normalized.server_ca_pem =
      config_validation::normalizePemLineEndings(normalized.server_ca_pem);
  normalized.ota_signing_public_key_pem =
      config_validation::normalizePemLineEndings(
          normalized.ota_signing_public_key_pem);
  result = validate(normalized, true);
  if (!result.valid) {
    return false;
  }
  if (normalized.wifi_ssid.empty()) {
    result = {false, "wifi_ssid_required", "A Wi-Fi network name is required."};
    return false;
  }
  if (!replace_wifi_password && normalized.wifi_ssid != config_.wifi_ssid) {
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

  RuntimeConfig committed = normalized;
  committed.config_version =
      std::max(config_.config_version + 1U, normalized.config_version);
  const std::string committed_password =
      replace_wifi_password ? wifi_password : wifi_password_;
  std::uint64_t generation = 0;
  if (commitPersistentConfig(committed, committed_password, &generation) &&
      verifyPersistentConfig(committed, committed_password)) {
    if (!publishPersistentConfig(committed, committed_password, generation)) {
      result = {false, "config_busy", "Configuration is busy."};
      return false;
    }
    result = {true, "ok", "Network and server settings were committed."};
    PM_LOG_INFO("CONFIG", "NETWORK_SETTINGS_COMMIT_VERIFIED",
                "version=%lu wifi_ssid=%s psk_state=present",
                static_cast<unsigned long>(committed.config_version),
                diag::maskSsid(committed.wifi_ssid).c_str());
    return true;
  }

  result = {false, "network_settings_commit_failed",
            "The network settings could not be committed; the previous atomic "
            "slot remains active."};
  return false;
}

std::string ConfigService::enrollmentToken() const {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(2000));
  if (!mutation)
    return {};
  {
    RecursiveMutexGuard state(state_mutex_, kStateReadTimeout);
    if (!state)
      return {};
    if (!pending_reenrollment_token_.empty()) {
      return pending_reenrollment_token_;
    }
  }
  const std::size_t length = preferences_.getBytesLength("enroll_tok");
  if (length < 32 || length > 256) {
    return {};
  }
  std::string token(length, '\0');
  if (preferences_.getBytes("enroll_tok", token.data(), token.size()) !=
      token.size()) {
    std::fill(token.begin(), token.end(), '\0');
    token.clear();
  }
  return token;
}

bool ConfigService::setEnrollmentToken(const std::string &token) {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(2000));
  if (!mutation)
    return false;
  return token.size() >= 32 && token.size() <= 256 &&
         writeBytesChecked(preferences_, "enroll_tok",
                           reinterpret_cast<const std::uint8_t *>(token.data()),
                           token.size());
}

bool ConfigService::clearEnrollmentToken() {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(2000));
  return mutation && erasePreferenceChecked(preferences_, "enroll_tok");
}

bool ConfigService::saveEnrollment(const std::string &device_id,
                                   const std::uint8_t *enrollment_secret,
                                   const std::size_t secret_length,
                                   const std::string &ota_public_key) {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(5000));
  if (!mutation)
    return false;
  if (device_id.size() != 36 || secret_length < 32 || secret_length > 64 ||
      enrollment_secret == nullptr || ota_public_key.size() > 4096) {
    return false;
  }
  const std::uint64_t reenrollment_generation = reenrollmentGeneration();
  if (!writeULong64Checked(preferences_, "server_ack", 0) ||
      !writeUIntChecked(preferences_, "server_cfg", 0)) {
    PM_LOG_ERROR("CONFIG", "ENROLLMENT_CURSOR_PREPARE_FAILED",
                 "error=PM-CONFIG-028 credentials_activated=false");
    return false;
  }
  if (!commitEnrollmentRecord(device_id, enrollment_secret, secret_length,
                              ota_public_key, reenrollment_generation)) {
    return false;
  }

  DeviceIdentity enrolled_identity = identityUnsafe();
  enrolled_identity.device_id = device_id;
  enrolled_identity.enrolled = true;
  const std::vector<std::uint8_t> secret(enrollment_secret,
                                         enrollment_secret + secret_length);
  if (!publishEnrollment(enrolled_identity, secret, ota_public_key, {},
                         reenrollment_generation)) {
    return false;
  }
  if (!eraseLegacyEnrollmentCopies(preferences_)) {
    PM_LOG_WARN(
        "CONFIG", "LEGACY_ENROLLMENT_CLEANUP_DEFERRED",
        "error=PM-CONFIG-030 enrollment_committed=true retry_on_boot=true");
  }
  {
    RecursiveMutexGuard state(state_mutex_, pdMS_TO_TICKS(2000));
    if (!state)
      return false;
    server_ack_sequence_ = 0;
    server_config_version_ = 0;
  }
  if (!clearEnrollmentToken()) {
    PM_LOG_WARN("CONFIG", "ENROLLMENT_TOKEN_CLEANUP_DEFERRED",
                "error=PM-CONFIG-024 enrollment_committed=true");
  }

  RuntimeConfig current = configUnsafe();
  if (current.hostname.rfind("power-monitor-", 0) == 0) {
    RuntimeConfig renamed = current;
    renamed.hostname = defaultHostname(enrolled_identity);
    renamed.config_version =
        std::max(current.config_version + 1U, renamed.config_version);
    std::uint64_t generation = 0;
    if (commitPersistentConfig(renamed, wifi_password_, &generation) &&
        verifyPersistentConfig(renamed, wifi_password_)) {
      if (!publishPersistentConfig(renamed, wifi_password_, generation)) {
        PM_LOG_WARN("CONFIG", "ENROLLMENT_HOSTNAME_UPDATE_DEFERRED",
                    "error=PM-CONFIG-014 enrollment_committed=true");
      }
    } else {
      PM_LOG_WARN("CONFIG", "ENROLLMENT_HOSTNAME_UPDATE_DEFERRED",
                  "error=PM-CONFIG-014 enrollment_committed=true");
    }
  }
  return true;
}

bool ConfigService::directionalKeys(crypto::Key32 &device_to_server,
                                    crypto::Key32 &server_to_device) const {
  std::vector<std::uint8_t> secret;
  {
    RecursiveMutexGuard state(state_mutex_, kStateReadTimeout);
    if (!state || !identity_.enrolled || enrollment_secret_.size() < 32 ||
        enrollment_secret_.size() > 64) {
      return false;
    }
    secret = enrollment_secret_;
  }
  if (secret.size() < 32 || secret.size() > 64) {
    return false;
  }
  device_to_server = crypto::hkdfSha256(secret.data(), secret.size(),
                                        "pm-device-to-server-v1");
  server_to_device = crypto::hkdfSha256(secret.data(), secret.size(),
                                        "pm-server-to-device-v1");
  std::fill(secret.begin(), secret.end(), std::uint8_t{0});
  return true;
}

std::string ConfigService::otaPublicKey() const {
  RecursiveMutexGuard state(state_mutex_, kStateReadTimeout);
  if (!state)
    return {};
  return config_.ota_signing_public_key_pem.empty()
             ? ota_public_key_
             : config_.ota_signing_public_key_pem;
}

std::string ConfigService::ensureSetupPassword() {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(250));
  if (!mutation)
    return {};
  std::string existing;
  if (readSetupPassword(preferences_, "setup_ap", existing)) {
    preferences_.remove("setup_next");
    preferences_.remove("setup_salt");
    preferences_.remove("setup_hash");
    setup_password_new_ = false;
    return existing;
  }
  std::string staged;
  if (readSetupPassword(preferences_, "setup_next", staged)) {
    const bool promoted = preferences_.putBytes("setup_ap", staged.data(),
                                                staged.size()) == staged.size();
    std::string readback;
    const bool verified =
        promoted && readSetupPassword(preferences_, "setup_ap", readback) &&
        crypto::constantTimeEqual(readback, staged);
    std::fill(readback.begin(), readback.end(), '\0');
    if (verified) {
      preferences_.remove("setup_next");
      preferences_.remove("setup_salt");
      preferences_.remove("setup_hash");
      setup_password_new_ = false;
      return staged;
    }
    std::fill(staged.begin(), staged.end(), '\0');
  }
  const std::string password = crypto::randomHex(8);
  if (preferences_.putBytes("setup_ap", password.data(), password.size()) !=
      password.size()) {
    setup_password_new_ = false;
    return {};
  }
  std::string readback(password.size(), '\0');
  const bool verified =
      preferences_.getBytes("setup_ap", readback.data(), readback.size()) ==
          readback.size() &&
      crypto::constantTimeEqual(readback, password);
  std::fill(readback.begin(), readback.end(), '\0');
  if (!verified) {
    preferences_.remove("setup_ap");
    setup_password_new_ = false;
    return {};
  }
  // setup_ap is already a random, device-local WPA2 credential and must be
  // retained in clear form for the radio. A PBKDF2 copy only adds watchdog
  // risk on NetworkTask, so remove legacy derived copies after readback.
  preferences_.remove("setup_salt");
  preferences_.remove("setup_hash");
  setup_password_new_ = true;
  return password;
}

bool ConfigService::setSetupPassword(const std::string &password) {
  if (!validSetupPassword(password)) {
    return false;
  }
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(5000));
  if (!mutation) {
    return false;
  }
  if (preferences_.putBytes("setup_next", password.data(), password.size()) !=
      password.size()) {
    return false;
  }
  std::string staged;
  const bool staged_verified =
      readSetupPassword(preferences_, "setup_next", staged) &&
      crypto::constantTimeEqual(staged, password);
  std::fill(staged.begin(), staged.end(), '\0');
  if (!staged_verified) {
    preferences_.remove("setup_next");
    return false;
  }
  if (preferences_.putBytes("setup_ap", password.data(), password.size()) !=
      password.size()) {
    return false;
  }
  std::string readback;
  const bool active_verified =
      readSetupPassword(preferences_, "setup_ap", readback) &&
      crypto::constantTimeEqual(readback, password);
  std::fill(readback.begin(), readback.end(), '\0');
  if (!active_verified) {
    return false;
  }
  if (!erasePreferenceChecked(preferences_, "setup_next")) {
    PM_LOG_WARN("CONFIG", "SETUP_PASSWORD_STAGE_CLEANUP_DEFERRED",
                "error=PM-CONFIG-031 active_readback_verified=true "
                "recovery=cleanup_on_next_boot");
  }
  preferences_.remove("setup_salt");
  preferences_.remove("setup_hash");
  setup_password_new_ = false;
  return true;
}

bool ConfigService::setupPasswordNew() const {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(2000));
  return mutation && setup_password_new_;
}

bool ConfigService::hasAdminPassword() const {
  RecursiveMutexGuard state(state_mutex_, kStateReadTimeout);
  return state && admin_password_configured_;
}

bool ConfigService::verifySetupPassword(const std::string &password) const {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(2000));
  if (!mutation)
    return false;
  std::string expected;
  if (!readSetupPassword(preferences_, "setup_ap", expected)) {
    return false;
  }
  const bool matches = crypto::constantTimeEqual(expected, password);
  std::fill(expected.begin(), expected.end(), '\0');
  return matches;
}

bool ConfigService::persistAdminVerifier(const std::string &password) {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(5000));
  if (!mutation)
    return false;
  if (password.size() < 12 || password.size() > 128) {
    return false;
  }
  if (!saveCredential("admin_salt", "admin_hash", password)) {
    return false;
  }
  RecursiveMutexGuard state(state_mutex_, pdMS_TO_TICKS(2000));
  if (!state)
    return false;
  admin_password_configured_ = true;
  return true;
}

#if PM_PHYSICAL_ADMIN_RECOVERY
AdminPasswordRecoveryResult
ConfigService::replaceAdminPasswordForPhysicalRecovery(
    const std::string &password) {
  const bool valid =
      password.size() >= 12U && password.size() <= 63U &&
      std::all_of(password.begin(), password.end(), [](const char value) {
        return value >= 0x21 && value <= 0x7e;
      });
  if (!valid) {
    return AdminPasswordRecoveryResult::RejectedPreserved;
  }
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(30'000));
  if (!mutation) {
    return AdminPasswordRecoveryResult::RejectedPreserved;
  }

  provisioning_transaction::Journal journal;
  const char *failed_step = "credential_journal";
  bool applied = prepareProvisioningTransaction(journal);
  if (applied) {
    failed_step = "administrator_hash";
    applied = persistAdminVerifier(password);
  }
  if (applied) {
    failed_step = "administrator_readback";
    applied = verifyAdminPassword(password);
  }
  if (applied) {
    failed_step = "transaction_commit";
    applied = clearProvisioningTransaction();
  }
  if (applied) {
    PM_LOG_WARN("SECURITY", "ADMIN_PASSWORD_PHYSICAL_RECOVERY_COMMITTED",
                "transport=physical_usb persisted=true "
                "readback_verified=true secret_logged=false "
                "configuration_preserved=true");
    provisioning_transaction::scrub(journal);
    return AdminPasswordRecoveryResult::Applied;
  }

  const bool recovered =
      recoverIncompleteProvisioning() && publishRecoveredProvisioningState();
  PM_LOG_ERROR("SECURITY", "ADMIN_PASSWORD_PHYSICAL_RECOVERY_ROLLED_BACK",
               "error=PM-CONFIG-032 failed_step=%s "
               "previous_credential_restored=%s configuration_preserved=%s "
               "secret_logged=false",
               failed_step, recovered ? "true" : "false",
               recovered ? "true" : "false");
  provisioning_transaction::scrub(journal);
  if (!recovered) {
    return AdminPasswordRecoveryResult::FailedUncertain;
  }
  // If journal removal committed but its verification probe failed, recovery
  // correctly observes no journal and the new verifier remains authoritative.
  return verifyAdminPassword(password)
             ? AdminPasswordRecoveryResult::Applied
             : AdminPasswordRecoveryResult::RejectedPreserved;
}
#endif

bool ConfigService::commitProvisioning(const RuntimeConfig &candidate,
                                       const std::string &wifi_password,
                                       const std::string &enrollment_token,
                                       const std::string &admin_password) {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(15000));
  if (!mutation)
    return false;
  RuntimeConfig normalized = candidate;
  normalized.server_ca_pem =
      config_validation::normalizePemLineEndings(normalized.server_ca_pem);
  normalized.ota_signing_public_key_pem =
      config_validation::normalizePemLineEndings(
          normalized.ota_signing_public_key_pem);
  ConfigValidation validation = validate(normalized, true);
  if (!validation.valid || normalized.wifi_ssid.empty() ||
      wifi_password.size() < 8 || wifi_password.size() > 63 ||
      enrollment_token.size() < 32 || enrollment_token.size() > 256 ||
      admin_password.size() < 12 || admin_password.size() > 128) {
    return false;
  }

  RuntimeConfig committed = normalized;
  committed.config_version =
      std::max(config_.config_version + 1U, normalized.config_version);
  PM_LOG_INFO("CONFIG", "PROVISIONING_COMMIT_BEGIN",
              "wifi_ssid=%s server_configured=%s enrollment_material=present",
              diag::maskSsid(committed.wifi_ssid).c_str(),
              committed.server_url.empty() ? "false" : "true");

  provisioning_transaction::Journal journal;
  const char *failed_step = "transaction_journal";
  bool applied = prepareProvisioningTransaction(journal);
  if (applied) {
    failed_step = "enrollment_token";
    applied = setEnrollmentToken(enrollment_token);
  }
  if (applied) {
    failed_step = "administrator_hash";
    applied = persistAdminVerifier(admin_password);
  }
  std::uint64_t generation = 0;
  if (applied) {
    failed_step = "config_commit";
    applied = commitPersistentConfig(committed, wifi_password, &generation);
  }
  if (applied) {
    failed_step = "persistence_verify";
    applied = verifyPersistentConfig(committed, wifi_password);
  }
  if (applied) {
    if (!publishPersistentConfig(committed, wifi_password, generation)) {
      applied = false;
      failed_step = "publish_state";
    }
  }
  if (applied) {
    // Journal removal is the transaction commit point. Until verified absent,
    // boot recovery treats every token, password, and config write as
    // provisional and restores the prior state.
    failed_step = "transaction_commit";
    applied = clearProvisioningTransaction();
  }
  if (applied) {
    PM_LOG_INFO("CONFIG", "PROVISIONING_COMMIT_VERIFIED",
                "version=%lu generation=%llu wifi_ssid=%s psk_state=present "
                "administrator_state=present transaction=committed",
                static_cast<unsigned long>(committed.config_version),
                static_cast<unsigned long long>(generation),
                diag::maskSsid(committed.wifi_ssid).c_str());
    provisioning_transaction::scrub(journal);
    return true;
  }

  const bool recovered =
      recoverIncompleteProvisioning() && publishRecoveredProvisioningState();
  PM_LOG_ERROR("CONFIG", "PROVISIONING_COMMIT_ROLLED_BACK",
               "error=PM-CONFIG-009 failed_step=%s previous_slot_preserved=%s "
               "credential_snapshot_restored=%s",
               failed_step, recovered ? "true" : "false",
               recovered ? "true" : "false");
  provisioning_transaction::scrub(journal);
  return false;
}

bool ConfigService::verifyAdminPassword(const std::string &password) const {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(5000));
  if (!mutation)
    return false;
  return credentialMatches("admin_salt", "admin_hash", password);
}

bool ConfigService::networkReset() {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(5000));
  if (!mutation)
    return false;
  RuntimeConfig reset = config_;
  reset.wifi_ssid.clear();
  reset.static_network_enabled = false;
  reset.static_ip.clear();
  reset.static_gateway.clear();
  reset.static_subnet.clear();
  reset.static_dns.clear();
  reset.config_version =
      std::max(config_.config_version + 1U, reset.config_version);
  std::uint64_t generation = 0;
  if (!commitPersistentConfig(reset, {}, &generation) ||
      !verifyPersistentConfig(reset, {})) {
    return false;
  }
  if (!publishPersistentConfig(reset, {}, generation))
    return false;
  const bool legacy_config_removed = eraseLegacyConfigCopies(preferences_);
  if (!legacy_config_removed) {
    PM_LOG_ERROR("CONFIG", "LEGACY_CONFIG_CLEANUP_FAILED",
                 "error=PM-CONFIG-029 network_reset_committed=true "
                 "retry_operation=true");
  }
  bool setup_credentials_removed = true;
  setup_credentials_removed =
      erasePreferenceChecked(preferences_, "setup_ap") &&
      setup_credentials_removed;
  setup_credentials_removed =
      erasePreferenceChecked(preferences_, "setup_next") &&
      setup_credentials_removed;
  setup_credentials_removed =
      erasePreferenceChecked(preferences_, "setup_salt") &&
      setup_credentials_removed;
  setup_credentials_removed =
      erasePreferenceChecked(preferences_, "setup_hash") &&
      setup_credentials_removed;
  if (!setup_credentials_removed) {
    PM_LOG_WARN("CONFIG", "SETUP_CREDENTIAL_CLEANUP_DEFERRED",
                "error=PM-CONFIG-025 network_reset_committed=true");
  }
  setup_password_new_ = false;
  return legacy_config_removed && setup_credentials_removed;
}

bool ConfigService::beginReenrollment(const std::string &token) {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(5000));
  if (!mutation || token.size() < 32 || token.size() > 256) {
    return false;
  }
  const std::uint64_t current_generation = reenrollmentGeneration();
  if (current_generation == std::numeric_limits<std::uint64_t>::max()) {
    return false;
  }
  const std::uint64_t next_generation = current_generation + 1U;

  const bool token_verified = setEnrollmentToken(token);
  const bool ack_cursor_verified =
      token_verified && writeULong64Checked(preferences_, "server_ack", 0);
  const bool config_cursor_verified =
      ack_cursor_verified && writeUIntChecked(preferences_, "server_cfg", 0);
  if (!reenrollmentPrerequisitesReady(token_verified, ack_cursor_verified,
                                      config_cursor_verified)) {
    PM_LOG_ERROR("CONFIG", "REENROLLMENT_PREPARE_FAILED",
                 "error=PM-CONFIG-026 credentials_retained=true");
    return false;
  }

  // The pending token and credential tombstone are one atomic record. A power
  // cut can therefore leave either the old enrolled identity or a resumable
  // reenrollment request, never a tokenless unenrolled identity.
  if (!commitReenrollmentPending(token, next_generation)) {
    return false;
  }
  DeviceIdentity identity = identityUnsafe();
  identity.device_id.clear();
  identity.enrolled = false;
  if (!publishEnrollment(identity, {}, {}, token, next_generation)) {
    return false;
  }
  {
    RecursiveMutexGuard state(state_mutex_, pdMS_TO_TICKS(2000));
    if (!state)
      return false;
    server_ack_sequence_ = 0;
    server_config_version_ = 0;
  }
  if (!clearEnrollmentToken()) {
    PM_LOG_WARN("CONFIG", "REENROLLMENT_LEGACY_TOKEN_CLEANUP_DEFERRED",
                "error=PM-CONFIG-027 reenrollment_pending=true generation=%llu",
                static_cast<unsigned long long>(next_generation));
  }
  PM_LOG_INFO("CONFIG", "REENROLLMENT_PREPARED",
              "generation=%llu credentials_tombstoned=true token_state=pending",
              static_cast<unsigned long long>(next_generation));
  return true;
}

std::uint64_t ConfigService::reenrollmentGeneration() const {
  RecursiveMutexGuard state(state_mutex_, kStateReadTimeout);
  return state ? reenrollment_generation_ : 0U;
}

bool ConfigService::factoryReset() {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(10000));
  if (!mutation || !clearPersistentNamespace() || !preferences_.clear()) {
    return false;
  }
  initializeIdentity();
  const DeviceIdentity reset_identity = identityUnsafe();
  RuntimeConfig reset;
  reset.hostname = defaultHostname(reset_identity);
  std::uint64_t generation = 0;
  if (!commitPersistentConfig(reset, {}, &generation) ||
      !commitEnrollmentTombstone(0)) {
    return false;
  }
  {
    RecursiveMutexGuard state(state_mutex_, pdMS_TO_TICKS(2000));
    if (!state)
      return false;
    config_ = reset;
    identity_ = reset_identity;
    wifi_password_.clear();
    std::fill(enrollment_secret_.begin(), enrollment_secret_.end(),
              std::uint8_t{0});
    enrollment_secret_.clear();
    ota_public_key_.clear();
    std::fill(pending_reenrollment_token_.begin(),
              pending_reenrollment_token_.end(), '\0');
    pending_reenrollment_token_.clear();
    reenrollment_generation_ = 0;
    persistent_generation_ = generation;
    admin_password_configured_ = false;
    server_ack_sequence_ = 0;
    server_config_version_ = 0;
    energy_offset_wh_ = 0;
    safe_mode_ = false;
    safe_mode_reason_.clear();
  }
  setup_password_new_ = false;
  return preferences_.putBool("pmcfg_init", true) == sizeof(bool) &&
         preferences_.getBool("pmcfg_init", false);
}

std::uint64_t ConfigService::serverAckSequence() const {
  RecursiveMutexGuard state(state_mutex_, kStateReadTimeout);
  return state ? server_ack_sequence_ : 0;
}

bool ConfigService::setServerAckSequence(const std::uint64_t sequence) {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(2000));
  if (!mutation)
    return false;
  const std::uint64_t current = serverAckSequence();
  if (sequence < current)
    return false;
  if (sequence == current)
    return true;
  if (!writeULong64Checked(preferences_, "server_ack", sequence)) {
    return false;
  }
  RecursiveMutexGuard state(state_mutex_, pdMS_TO_TICKS(2000));
  if (!state)
    return false;
  server_ack_sequence_ = sequence;
  return true;
}

std::uint32_t ConfigService::serverConfigVersion() const {
  RecursiveMutexGuard state(state_mutex_, kStateReadTimeout);
  return state ? server_config_version_ : 0;
}

bool ConfigService::setServerConfigVersion(const std::uint32_t version) {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(2000));
  if (!mutation)
    return false;
  const std::uint32_t current = serverConfigVersion();
  if (version < current)
    return false;
  if (version == current)
    return true;
  if (!writeUIntChecked(preferences_, "server_cfg", version)) {
    return false;
  }
  RecursiveMutexGuard state(state_mutex_, pdMS_TO_TICKS(2000));
  if (!state)
    return false;
  server_config_version_ = version;
  return true;
}

std::uint64_t ConfigService::energyOffsetWh() const {
  RecursiveMutexGuard state(state_mutex_, kStateReadTimeout);
  return state ? energy_offset_wh_ : 0;
}

bool ConfigService::setEnergyOffsetWh(const std::uint64_t offset) {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(2000));
  if (!mutation)
    return false;
  const std::uint64_t current = energyOffsetWh();
  if (offset < current)
    return false;
  if (offset == current)
    return true;
  if (preferences_.putULong64("energy_off", offset) != sizeof(offset)) {
    return false;
  }
  RecursiveMutexGuard state(state_mutex_, pdMS_TO_TICKS(2000));
  if (!state)
    return false;
  energy_offset_wh_ = offset;
  return true;
}

bool ConfigService::recordBootStarted() {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(2000));
  if (!mutation)
    return false;
  const std::uint32_t failures = preferences_.getUInt("boot_fail", 0);
  return preferences_.putUInt("boot_fail",
                              std::min<std::uint32_t>(failures + 1, 100)) ==
         sizeof(std::uint32_t);
}

bool ConfigService::recordBootHealthy() {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(2000));
  if (!mutation)
    return false;
  const bool saved =
      preferences_.putUInt("boot_fail", 0) == sizeof(std::uint32_t);
  if (saved) {
    RecursiveMutexGuard state(state_mutex_, pdMS_TO_TICKS(2000));
    if (!state)
      return false;
    safe_mode_ = false;
    safe_mode_reason_.clear();
  }
  return saved;
}

bool ConfigService::setDiagnosticLogLevel(const std::uint8_t level) {
  RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(5000));
  if (!mutation)
    return false;
  if (level > 5 || config_.diagnostic_log_level == level) {
    return level <= 5;
  }
  RuntimeConfig candidate = config_;
  candidate.diagnostic_log_level = level;
  std::uint64_t generation = 0;
  return commitCandidate(candidate, true, generation);
}

bool ConfigService::safeMode() const {
  RecursiveMutexGuard state(state_mutex_, kStateReadTimeout);
  return state && safe_mode_;
}

std::string ConfigService::safeModeReason() const {
  RecursiveMutexGuard state(state_mutex_, kStateReadTimeout);
  return state ? safe_mode_reason_ : std::string{};
}

bool ConfigService::loadEnrollmentRecord(
    const std::vector<std::uint8_t> &payload, std::string &device_id,
    std::vector<std::uint8_t> &enrollment_secret, std::string &ota_public_key,
    std::string &pending_reenrollment_token,
    std::uint64_t &reenrollment_generation) const {
  device_id.clear();
  std::fill(enrollment_secret.begin(), enrollment_secret.end(),
            std::uint8_t{0});
  enrollment_secret.clear();
  ota_public_key.clear();
  std::fill(pending_reenrollment_token.begin(),
            pending_reenrollment_token.end(), '\0');
  pending_reenrollment_token.clear();
  reenrollment_generation = 0;
  JsonDocument document;
  const DeserializationError error =
      deserializeJson(document, payload.data(), payload.size());
  if (error || (document["record_schema_version"] | 0U) != 1U ||
      !document["enrolled"].is<bool>()) {
    return false;
  }
  if (!document["reenrollment_generation"].isNull()) {
    if (!document["reenrollment_generation"].is<std::uint64_t>()) {
      return false;
    }
    reenrollment_generation =
        document["reenrollment_generation"].as<std::uint64_t>();
  }
  if (!document["enrolled"].as<bool>()) {
    if (!document["pending_reenrollment_token"].isNull()) {
      if (!document["pending_reenrollment_token"].is<const char *>()) {
        return false;
      }
      pending_reenrollment_token =
          document["pending_reenrollment_token"].as<const char *>();
      if (pending_reenrollment_token.size() < 32 ||
          pending_reenrollment_token.size() > 256 ||
          reenrollment_generation == 0U) {
        std::fill(pending_reenrollment_token.begin(),
                  pending_reenrollment_token.end(), '\0');
        pending_reenrollment_token.clear();
        reenrollment_generation = 0;
        return false;
      }
    }
    return true;
  }
  if (!document["pending_reenrollment_token"].isNull()) {
    return false;
  }
  if (!document["device_id"].is<const char *>() ||
      !document["secret_hex"].is<const char *>() ||
      !document["ota_public_key"].is<const char *>()) {
    return false;
  }
  device_id = document["device_id"].as<const char *>();
  const std::string secret_hex = document["secret_hex"].as<const char *>();
  ota_public_key = document["ota_public_key"].as<const char *>();
  if (device_id.size() != 36 ||
      !crypto::hexDecode(secret_hex, enrollment_secret) ||
      enrollment_secret.size() < 32 || enrollment_secret.size() > 64 ||
      ota_public_key.size() > 4096) {
    device_id.clear();
    std::fill(enrollment_secret.begin(), enrollment_secret.end(),
              std::uint8_t{0});
    enrollment_secret.clear();
    ota_public_key.clear();
    return false;
  }
  return true;
}

bool ConfigService::commitEnrollmentRecord(
    const std::string &device_id, const std::uint8_t *enrollment_secret,
    const std::size_t secret_length, const std::string &ota_public_key,
    const std::uint64_t reenrollment_generation) {
  if (device_id.size() != 36 || enrollment_secret == nullptr ||
      secret_length < 32 || secret_length > 64 ||
      ota_public_key.size() > 4096) {
    return false;
  }
  JsonDocument document;
  document["record_schema_version"] = 1;
  document["enrolled"] = true;
  document["device_id"] = device_id;
  document["secret_hex"] = crypto::hexEncode(enrollment_secret, secret_length);
  document["ota_public_key"] = ota_public_key;
  document["reenrollment_generation"] = reenrollment_generation;
  std::string serialized;
  serializeJson(document, serialized);
  const std::vector<std::uint8_t> payload(serialized.begin(), serialized.end());
  PreferencesBlobStore store;
  persistence::CommitResult committed;
  if (!persistence::commit(store, kEnrollmentSlots, payload, committed)) {
    return false;
  }
  persistence::LoadResult verified;
  if (!persistence::loadActive(store, kEnrollmentSlots, verified) ||
      verified.generation != committed.generation) {
    return false;
  }
  std::string verified_device;
  std::vector<std::uint8_t> verified_secret;
  std::string verified_key;
  std::string verified_pending_token;
  std::uint64_t verified_reenrollment_generation = 0;
  std::string verified_secret_hex;
  std::string expected_secret_hex;
  const bool valid =
      loadEnrollmentRecord(verified.payload, verified_device, verified_secret,
                           verified_key, verified_pending_token,
                           verified_reenrollment_generation) &&
      verified_device == device_id && verified_key == ota_public_key &&
      verified_pending_token.empty() &&
      verified_reenrollment_generation == reenrollment_generation &&
      verified_secret.size() == secret_length;
  bool secret_matches = false;
  if (valid) {
    verified_secret_hex =
        crypto::hexEncode(verified_secret.data(), verified_secret.size());
    expected_secret_hex = crypto::hexEncode(enrollment_secret, secret_length);
    secret_matches =
        crypto::constantTimeEqual(verified_secret_hex, expected_secret_hex);
  }
  std::fill(verified_secret.begin(), verified_secret.end(), std::uint8_t{0});
  std::fill(verified_secret_hex.begin(), verified_secret_hex.end(), '\0');
  std::fill(expected_secret_hex.begin(), expected_secret_hex.end(), '\0');
  return valid && secret_matches;
}

bool ConfigService::commitEnrollmentTombstone(
    const std::uint64_t reenrollment_generation) {
  JsonDocument document;
  document["record_schema_version"] = 1;
  document["enrolled"] = false;
  document["reenrollment_generation"] = reenrollment_generation;
  std::string serialized;
  serializeJson(document, serialized);
  const std::vector<std::uint8_t> payload(serialized.begin(), serialized.end());
  PreferencesBlobStore store;
  persistence::CommitResult committed;
  if (!persistence::commit(store, kEnrollmentSlots, payload, committed)) {
    return false;
  }
  persistence::LoadResult verified;
  std::string device_id;
  std::vector<std::uint8_t> secret;
  std::string public_key;
  std::string pending_token;
  std::uint64_t verified_reenrollment_generation = 0;
  return persistence::loadActive(store, kEnrollmentSlots, verified) &&
         verified.generation == committed.generation &&
         loadEnrollmentRecord(verified.payload, device_id, secret, public_key,
                              pending_token,
                              verified_reenrollment_generation) &&
         device_id.empty() && secret.empty() && public_key.empty() &&
         pending_token.empty() &&
         verified_reenrollment_generation == reenrollment_generation;
}

bool ConfigService::commitReenrollmentPending(
    const std::string &token, const std::uint64_t reenrollment_generation) {
  if (token.size() < 32 || token.size() > 256 ||
      reenrollment_generation == 0U) {
    return false;
  }
  JsonDocument document;
  document["record_schema_version"] = 1;
  document["enrolled"] = false;
  document["pending_reenrollment_token"] = token;
  document["reenrollment_generation"] = reenrollment_generation;
  std::string serialized;
  serializeJson(document, serialized);
  const std::vector<std::uint8_t> payload(serialized.begin(), serialized.end());
  PreferencesBlobStore store;
  persistence::CommitResult committed;
  if (!persistence::commit(store, kEnrollmentSlots, payload, committed) ||
      !committed.committed) {
    return false;
  }
  persistence::LoadResult verified;
  std::string device_id;
  std::vector<std::uint8_t> secret;
  std::string public_key;
  std::string verified_token;
  std::uint64_t verified_reenrollment_generation = 0;
  const bool valid =
      persistence::loadActive(store, kEnrollmentSlots, verified) &&
      verified.generation == committed.generation &&
      loadEnrollmentRecord(verified.payload, device_id, secret, public_key,
                           verified_token, verified_reenrollment_generation) &&
      device_id.empty() && secret.empty() && public_key.empty() &&
      verified_reenrollment_generation == reenrollment_generation &&
      crypto::constantTimeEqual(verified_token, token);
  std::fill(verified_token.begin(), verified_token.end(), '\0');
  return valid;
}

bool ConfigService::loadOrMigrateEnrollment() {
  PreferencesBlobStore store;
  persistence::LoadResult loaded;
  bool loaded_atomic = persistence::loadActive(store, kEnrollmentSlots, loaded);
  std::string device_id;
  std::vector<std::uint8_t> secret;
  std::string public_key;
  std::string pending_token;
  std::uint64_t reenrollment_generation = 0;
  if (loaded_atomic &&
      !loadEnrollmentRecord(loaded.payload, device_id, secret, public_key,
                            pending_token, reenrollment_generation)) {
    persistence::LoadResult previous;
    loaded_atomic =
        persistence::loadPrevious(store, kEnrollmentSlots, loaded.generation,
                                  previous) &&
        loadEnrollmentRecord(previous.payload, device_id, secret, public_key,
                             pending_token, reenrollment_generation);
    if (loaded_atomic) {
      persistence::LoadResult activated;
      loaded_atomic =
          persistence::rollbackToPrevious(store, kEnrollmentSlots,
                                          loaded.generation, activated) &&
          activated.generation == previous.generation &&
          activated.payload == previous.payload;
      if (loaded_atomic)
        loaded = activated;
    }
  }
  if (loaded_atomic) {
    if (!pending_token.empty()) {
      const bool token_verified = setEnrollmentToken(pending_token);
      const bool ack_cursor_verified =
          token_verified && writeULong64Checked(preferences_, "server_ack", 0);
      const bool config_cursor_verified =
          ack_cursor_verified &&
          writeUIntChecked(preferences_, "server_cfg", 0);
      if (!reenrollmentPrerequisitesReady(token_verified, ack_cursor_verified,
                                          config_cursor_verified)) {
        std::fill(pending_token.begin(), pending_token.end(), '\0');
        std::fill(secret.begin(), secret.end(), std::uint8_t{0});
        return false;
      }
    }
    DeviceIdentity identity = identityUnsafe();
    identity.device_id = device_id;
    identity.enrolled = !device_id.empty();
    if (!publishEnrollment(identity, secret, public_key, pending_token,
                           reenrollment_generation)) {
      std::fill(pending_token.begin(), pending_token.end(), '\0');
      std::fill(secret.begin(), secret.end(), std::uint8_t{0});
      return false;
    }
    if (!pending_token.empty()) {
      {
        RecursiveMutexGuard state(state_mutex_, pdMS_TO_TICKS(2000));
        if (!state)
          return false;
        server_ack_sequence_ = 0;
        server_config_version_ = 0;
      }
      if (!clearEnrollmentToken()) {
        PM_LOG_WARN(
            "CONFIG", "REENROLLMENT_LEGACY_TOKEN_CLEANUP_DEFERRED",
            "error=PM-CONFIG-027 reenrollment_pending=true generation=%llu",
            static_cast<unsigned long long>(reenrollment_generation));
      }
    } else if (identity.enrolled && !clearEnrollmentToken()) {
      PM_LOG_FATAL("CONFIG", "ENROLLMENT_TOKEN_CLEANUP_FAILED",
                   "error=PM-CONFIG-024 atomic_enrollment_retained=true "
                   "retry_on_boot=true");
      std::fill(secret.begin(), secret.end(), std::uint8_t{0});
      return false;
    }
    std::fill(pending_token.begin(), pending_token.end(), '\0');
    std::fill(secret.begin(), secret.end(), std::uint8_t{0});
    if (!eraseLegacyEnrollmentCopies(preferences_)) {
      PM_LOG_FATAL("CONFIG", "LEGACY_ENROLLMENT_CLEANUP_FAILED",
                   "error=PM-CONFIG-030 atomic_enrollment_retained=true "
                   "retry_on_boot=true");
      return false;
    }
    return true;
  }
  if (persistence::anyDataPresent(store, kEnrollmentSlots)) {
    std::fill(secret.begin(), secret.end(), std::uint8_t{0});
    std::fill(pending_token.begin(), pending_token.end(), '\0');
    return false;
  }

  const std::string legacy_device =
      std::string(preferences_.getString("device_id", "").c_str());
  const std::size_t legacy_secret_length =
      preferences_.getBytesLength("enroll_sec");
  std::vector<std::uint8_t> legacy_secret(legacy_secret_length);
  const bool secret_read =
      legacy_secret_length >= 32 && legacy_secret_length <= 64 &&
      preferences_.getBytes("enroll_sec", legacy_secret.data(),
                            legacy_secret.size()) == legacy_secret.size();
  const std::string legacy_key =
      std::string(preferences_.getString("ota_pub", "").c_str());
  const bool complete_legacy =
      legacy_device.size() == 36 && secret_read && legacy_key.size() <= 4096;
  if (complete_legacy) {
    if (!commitEnrollmentRecord(legacy_device, legacy_secret.data(),
                                legacy_secret.size(), legacy_key, 0)) {
      std::fill(legacy_secret.begin(), legacy_secret.end(), std::uint8_t{0});
      return false;
    }
    DeviceIdentity identity = identityUnsafe();
    identity.device_id = legacy_device;
    identity.enrolled = true;
    if (!publishEnrollment(identity, legacy_secret, legacy_key, {}, 0)) {
      std::fill(legacy_secret.begin(), legacy_secret.end(), std::uint8_t{0});
      return false;
    }
    if (!eraseLegacyEnrollmentCopies(preferences_)) {
      std::fill(legacy_secret.begin(), legacy_secret.end(), std::uint8_t{0});
      PM_LOG_FATAL("CONFIG", "LEGACY_ENROLLMENT_CLEANUP_FAILED",
                   "error=PM-CONFIG-030 atomic_enrollment_retained=true "
                   "retry_on_boot=true");
      return false;
    }
    if (!clearEnrollmentToken()) {
      std::fill(legacy_secret.begin(), legacy_secret.end(), std::uint8_t{0});
      PM_LOG_FATAL("CONFIG", "ENROLLMENT_TOKEN_CLEANUP_FAILED",
                   "error=PM-CONFIG-024 atomic_enrollment_retained=true "
                   "retry_on_boot=true");
      return false;
    }
    PM_LOG_INFO("CONFIG", "LEGACY_ENROLLMENT_MIGRATED",
                "legacy_cleanup=verified atomic_readback=verified");
    std::fill(legacy_secret.begin(), legacy_secret.end(), std::uint8_t{0});
    return true;
  }
  std::fill(legacy_secret.begin(), legacy_secret.end(), std::uint8_t{0});
  if (!commitEnrollmentTombstone())
    return false;
  DeviceIdentity identity = identityUnsafe();
  identity.device_id.clear();
  identity.enrolled = false;
  if (!publishEnrollment(identity, {}, {}, {}, 0))
    return false;
  if (!eraseLegacyEnrollmentCopies(preferences_)) {
    PM_LOG_FATAL("CONFIG", "LEGACY_ENROLLMENT_CLEANUP_FAILED",
                 "error=PM-CONFIG-030 atomic_enrollment_retained=true "
                 "retry_on_boot=true");
    return false;
  }
  return true;
}

bool ConfigService::clearPersistentNamespace() {
  Preferences preferences;
  if (!preferences.begin(kPersistentNamespace, false, kPersistentPartition)) {
    return false;
  }
  const bool cleared = preferences.clear();
  preferences.end();
  return cleared;
}

bool ConfigService::prepareProvisioningTransaction(
    provisioning_transaction::Journal &journal) {
  provisioning_transaction::scrub(journal);
  journal.previous_config_generation = persistentGeneration();
  if (journal.previous_config_generation == 0U)
    return false;
  struct SnapshotTarget {
    const char *key;
    std::vector<std::uint8_t> *value;
  };
  const std::array<SnapshotTarget, 3> targets{{
      {"enroll_tok", &journal.enrollment_token},
      {"admin_salt", &journal.admin_salt},
      {"admin_hash", &journal.admin_hash},
  }};
  for (const auto &target : targets) {
    const std::size_t length = preferences_.getBytesLength(target.key);
    target.value->resize(length);
    if (length != 0U && preferences_.getBytes(target.key, target.value->data(),
                                              length) != length) {
      provisioning_transaction::scrub(journal);
      return false;
    }
  }
  std::vector<std::uint8_t> encoded = provisioning_transaction::encode(journal);
  if (encoded.empty())
    return false;
  PreferencesBlobStore store;
  if (!store.write(kProvisioningTransactionKey, encoded.data(),
                   encoded.size())) {
    std::fill(encoded.begin(), encoded.end(), std::uint8_t{0});
    store.erase(kProvisioningTransactionKey);
    return false;
  }
  std::vector<std::uint8_t> readback;
  provisioning_transaction::Journal verified;
  const bool matches = store.read(kProvisioningTransactionKey, readback) &&
                       readback == encoded &&
                       provisioning_transaction::decode(readback, verified) &&
                       verified.previous_config_generation ==
                           journal.previous_config_generation &&
                       verified.enrollment_token == journal.enrollment_token &&
                       verified.admin_salt == journal.admin_salt &&
                       verified.admin_hash == journal.admin_hash;
  provisioning_transaction::scrub(verified);
  std::fill(encoded.begin(), encoded.end(), std::uint8_t{0});
  std::fill(readback.begin(), readback.end(), std::uint8_t{0});
  if (!matches) {
    store.erase(kProvisioningTransactionKey);
    return false;
  }
  return true;
}

bool ConfigService::clearProvisioningTransaction() {
  PreferencesBlobStore store;
  bool present = true;
  return store.erase(kProvisioningTransactionKey) &&
         store.keyPresence(kProvisioningTransactionKey, present) && !present;
}

bool ConfigService::recoverIncompleteProvisioning() {
  PreferencesBlobStore store;
  bool journal_present = false;
  if (!store.keyPresence(kProvisioningTransactionKey, journal_present)) {
    PM_LOG_ERROR("CONFIG", "PROVISIONING_JOURNAL_PROBE_FAILED",
                 "error=PM-CONFIG-031 recovery=fail_closed");
    return false;
  }
  if (!journal_present)
    return true;

  std::vector<std::uint8_t> encoded;
  provisioning_transaction::Journal journal;
  if (!store.read(kProvisioningTransactionKey, encoded) ||
      !provisioning_transaction::decode(encoded, journal)) {
    std::fill(encoded.begin(), encoded.end(), std::uint8_t{0});
    PM_LOG_ERROR("CONFIG", "PROVISIONING_JOURNAL_INVALID",
                 "error=PM-CONFIG-031 journal=present validation=failed "
                 "recovery=fail_closed");
    return false;
  }
  std::fill(encoded.begin(), encoded.end(), std::uint8_t{0});

  RuntimeConfig active;
  std::string active_password;
  std::uint64_t active_generation = 0;
  if (!loadPersistentConfig(active, active_password, active_generation)) {
    provisioning_transaction::scrub(journal);
    return false;
  }
  std::fill(active_password.begin(), active_password.end(), '\0');
  const provisioning_transaction::RecoveryAction action =
      provisioning_transaction::recoveryAction(
          journal.previous_config_generation, active_generation);
  if (action == provisioning_transaction::RecoveryAction::Conflict) {
    provisioning_transaction::scrub(journal);
    PM_LOG_ERROR(
        "CONFIG", "PROVISIONING_RECOVERY_CONFLICT",
        "error=PM-CONFIG-031 active_generation=%llu recovery=fail_closed",
        static_cast<unsigned long long>(active_generation));
    return false;
  }
  if (action == provisioning_transaction::RecoveryAction::
                    RollbackConfigAndRestoreCredentials) {
    persistence::LoadResult restored;
    if (!persistence::rollbackToPrevious(store, kConfigSlots, active_generation,
                                         restored) ||
        restored.generation != journal.previous_config_generation) {
      provisioning_transaction::scrub(journal);
      return false;
    }
  }

  struct SnapshotSource {
    const char *key;
    const std::vector<std::uint8_t> *value;
  };
  const std::array<SnapshotSource, 3> snapshots{{
      {"enroll_tok", &journal.enrollment_token},
      {"admin_salt", &journal.admin_salt},
      {"admin_hash", &journal.admin_hash},
  }};
  for (const auto &snapshot : snapshots) {
    const bool restored =
        snapshot.value->empty()
            ? erasePreferenceChecked(preferences_, snapshot.key)
            : writeBytesChecked(preferences_, snapshot.key,
                                snapshot.value->data(), snapshot.value->size());
    if (!restored) {
      provisioning_transaction::scrub(journal);
      return false;
    }
  }
  if (!clearProvisioningTransaction()) {
    provisioning_transaction::scrub(journal);
    return false;
  }
  PM_LOG_WARN(
      "CONFIG", "PROVISIONING_TRANSACTION_RECOVERED",
      "error=PM-CONFIG-009 config_rollback=%s credentials_restored=true "
      "journal_cleared=true",
      action == provisioning_transaction::RecoveryAction::
                    RollbackConfigAndRestoreCredentials
          ? "true"
          : "false");
  provisioning_transaction::scrub(journal);
  return true;
}

bool ConfigService::publishRecoveredProvisioningState() {
  RuntimeConfig recovered;
  std::string recovered_password;
  std::uint64_t recovered_generation = 0;
  if (!loadPersistentConfig(recovered, recovered_password,
                            recovered_generation) ||
      !publishPersistentConfig(recovered, recovered_password,
                               recovered_generation)) {
    std::fill(recovered_password.begin(), recovered_password.end(), '\0');
    return false;
  }
  std::fill(recovered_password.begin(), recovered_password.end(), '\0');
  RecursiveMutexGuard state(state_mutex_, pdMS_TO_TICKS(2000));
  if (!state)
    return false;
  admin_password_configured_ =
      preferences_.getBytesLength("admin_hash") == crypto::Key32{}.size() &&
      preferences_.getBytesLength("admin_salt") == 16;
  return true;
}

bool ConfigService::initializePersistentPartition() {
  const bool previously_initialized = preferences_.getBool("pmcfg_init", false);
  esp_err_t result = nvs_flash_init_partition(kPersistentPartition);
  if (result != ESP_OK) {
    // Never infer erase authority from a marker in another partition. A
    // missing/corrupt default-NVS marker must not authorize destruction of
    // the authoritative atomic configuration partition.
    PM_LOG_ERROR_CODE(
        "CONFIG", "PERSISTENT_PARTITION_REJECTED", result,
        "error=PM-CONFIG-018 initialized_before=%s auto_format=false "
        "recovery=explicit_factory_reset_or_flash_restore",
        previously_initialized ? "true" : "false");
    return false;
  }

  // Create the namespace once in write mode so subsequent boot/readback
  // operations can reopen it read-only without noisy NVS_NOT_FOUND errors.
  Preferences namespace_bootstrap;
  if (!namespace_bootstrap.begin(kPersistentNamespace, false,
                                 kPersistentPartition)) {
    return false;
  }
  namespace_bootstrap.end();
  return true;
}

std::string ConfigService::serializePersistentConfig(
    const RuntimeConfig &value, const std::string &wifi_password) const {
  JsonDocument document;
  const DeserializationError error =
      deserializeJson(document, serializeConfig(value));
  if (error)
    return {};
  document["persistence_format"] = 1;
  document["wifi_password"] = wifi_password;
  document["server_ca_pem"] = value.server_ca_pem;
  document["server_fingerprint"] = value.server_fingerprint;
  document["ota_signing_public_key_pem"] = value.ota_signing_public_key_pem;
  std::string output;
  serializeJson(document, output);
  return output;
}

bool ConfigService::parsePersistentConfig(const std::string &json,
                                          RuntimeConfig &value,
                                          std::string &wifi_password,
                                          ConfigValidation &result) const {
  JsonDocument document;
  const DeserializationError error = deserializeJson(document, json);
  if (error) {
    result = {false, "persisted_config_json_invalid", error.c_str()};
    return false;
  }
  if ((document["persistence_format"] | 0U) != 1U ||
      !document["wifi_password"].is<const char *>()) {
    result = {false, "persisted_config_format_invalid",
              "The atomic configuration record format is unsupported."};
    return false;
  }
  wifi_password = document["wifi_password"].as<const char *>();
  RuntimeConfig parsed;
  std::string config_json;
  serializeJson(document, config_json);
  if (!parseConfig(config_json, parsed, result) || !result.valid) {
    std::fill(wifi_password.begin(), wifi_password.end(), '\0');
    wifi_password.clear();
    return false;
  }
  if ((parsed.wifi_ssid.empty() && !wifi_password.empty()) ||
      (!parsed.wifi_ssid.empty() &&
       (wifi_password.size() < 8 || wifi_password.size() > 63))) {
    result = {false, "persisted_wifi_pair_invalid",
              "The persisted Wi-Fi SSID and password are incomplete."};
    std::fill(wifi_password.begin(), wifi_password.end(), '\0');
    wifi_password.clear();
    return false;
  }
  value = parsed;
  result = {true, "ok", "Atomic configuration record is valid."};
  return true;
}

bool ConfigService::loadPersistentConfig(RuntimeConfig &output,
                                         std::string &wifi_password,
                                         std::uint64_t &generation) const {
  PreferencesBlobStore store;
  persistence::LoadResult loaded;
  if (!persistence::loadActive(store, kConfigSlots, loaded)) {
    return false;
  }
  const std::string payload(loaded.payload.begin(), loaded.payload.end());
  ConfigValidation validation;
  if (parsePersistentConfig(payload, output, wifi_password, validation)) {
    generation = loaded.generation;
    if (loaded.recovered_fallback) {
      PM_LOG_WARN(
          "CONFIG", "ATOMIC_SLOT_FALLBACK",
          "error=PM-CONFIG-015 slot=%c generation=%llu reason=marker_or_crc",
          loaded.slot, static_cast<unsigned long long>(loaded.generation));
    }
    return true;
  }

  persistence::LoadResult previous;
  if (!persistence::loadPrevious(store, kConfigSlots, loaded.generation,
                                 previous)) {
    PM_LOG_ERROR("CONFIG", "ATOMIC_CONFIG_SEMANTIC_REJECT",
                 "error=PM-CONFIG-016 validation=%s", validation.code.c_str());
    return false;
  }
  const std::string previous_payload(previous.payload.begin(),
                                     previous.payload.end());
  if (!parsePersistentConfig(previous_payload, output, wifi_password,
                             validation)) {
    PM_LOG_ERROR("CONFIG", "ATOMIC_CONFIG_SEMANTIC_REJECT",
                 "error=PM-CONFIG-016 active_and_previous_invalid=true "
                 "validation=%s",
                 validation.code.c_str());
    return false;
  }
  persistence::LoadResult activated;
  if (!persistence::rollbackToPrevious(store, kConfigSlots, loaded.generation,
                                       activated) ||
      activated.generation != previous.generation ||
      activated.payload != previous.payload) {
    std::fill(wifi_password.begin(), wifi_password.end(), '\0');
    wifi_password.clear();
    return false;
  }
  generation = activated.generation;
  PM_LOG_WARN(
      "CONFIG", "ATOMIC_SLOT_FALLBACK",
      "error=PM-CONFIG-015 slot=%c generation=%llu reason=semantic_validation",
      activated.slot, static_cast<unsigned long long>(activated.generation));
  return true;
}

bool ConfigService::commitPersistentConfig(const RuntimeConfig &value,
                                           const std::string &wifi_password,
                                           std::uint64_t *generation) {
  ConfigValidation validation = validate(value, true);
  if (!validation.valid ||
      (value.wifi_ssid.empty() && !wifi_password.empty()) ||
      (!value.wifi_ssid.empty() &&
       (wifi_password.size() < 8 || wifi_password.size() > 63))) {
    return false;
  }
  const std::string serialized =
      serializePersistentConfig(value, wifi_password);
  if (serialized.empty())
    return false;
  const std::vector<std::uint8_t> payload(serialized.begin(), serialized.end());
  PreferencesBlobStore store;
  persistence::CommitResult committed;
  if (!persistence::commit(store, kConfigSlots, payload, committed) ||
      !committed.committed) {
    PM_LOG_ERROR("CONFIG", "ATOMIC_CONFIG_COMMIT_FAILED",
                 "error=PM-CONFIG-017 previous_slot_preserved=true");
    return false;
  }
  if (generation != nullptr)
    *generation = committed.generation;
  return true;
}

bool ConfigService::verifyPersistentConfig(
    const RuntimeConfig &expected, const std::string &expected_password) const {
  RuntimeConfig persisted;
  std::string persisted_password;
  std::uint64_t ignored_generation = 0;
  if (!loadPersistentConfig(persisted, persisted_password,
                            ignored_generation)) {
    return false;
  }
  const bool config_matches = serializePersistentConfig(persisted, {}) ==
                              serializePersistentConfig(expected, {});
  const bool password_matches =
      crypto::constantTimeEqual(persisted_password, expected_password);
  std::fill(persisted_password.begin(), persisted_password.end(), '\0');
  return config_matches && password_matches;
}

bool ConfigService::loadLegacyConfig(const char *key,
                                     RuntimeConfig &output) const {
  const String value = preferences_.getString(key, "");
  if (value.isEmpty()) {
    PM_LOG_DEBUG("CONFIG", "PERSISTED_CONFIG_ABSENT", "key=%s", key);
    return false;
  }
  const bool staging = std::strcmp(key, "cfg_stage") == 0;
  const bool previous = std::strcmp(key, "cfg_prev") == 0;
  const char *ca_key =
      staging ? "server_ca_stage" : (previous ? "server_ca_prev" : "server_ca");
  const char *fingerprint_key =
      staging ? "server_fp_stage" : (previous ? "server_fp_prev" : "server_fp");

  // TLS trust is deliberately stored outside the redacted configuration JSON.
  // Restore it before parsing because parseConfig validates that every HTTPS
  // server URL has usable trust material.
  output.server_ca_pem =
      std::string(preferences_.getString(ca_key, "").c_str());
  output.server_fingerprint =
      std::string(preferences_.getString(fingerprint_key, "").c_str());
  std::string legacy_json(value.c_str());
  JsonDocument legacy_document;
  if (!deserializeJson(legacy_document, legacy_json)) {
    const std::string legacy_url = legacy_document["server_url"] | "";
    const bool ca_valid = output.server_ca_pem.empty() ||
                          validCaCertificateBundle(output.server_ca_pem);
    const bool server_settings_valid =
        legacy_url.empty()
            ? ca_valid
            : (config_validation::validHttpsBaseUrl(legacy_url) &&
               !output.server_ca_pem.empty() && ca_valid);
    if (!server_settings_valid) {
      // Older releases could persist the Wi-Fi pair independently from
      // incomplete or fingerprint-only TLS data. Preserve station
      // provisioning during migration, but disable the unusable server target
      // until an administrator installs a verified CA through the dedicated
      // network-settings operation.
      legacy_document["server_url"] = "";
      output.server_ca_pem.clear();
      output.server_fingerprint.clear();
      serializeJson(legacy_document, legacy_json);
      PM_LOG_WARN(
          "CONFIG", "LEGACY_SERVER_SETTINGS_QUARANTINED",
          "error=PM-CONFIG-021 key=%s wifi_preserved=true server_url=cleared "
          "reason=invalid_or_unsupported_tls_trust",
          key);
    }
  }
  ConfigValidation result;
  if (!parseConfig(legacy_json, output, result) || !result.valid) {
    PM_LOG_WARN("CONFIG", "PERSISTED_CONFIG_REJECTED",
                "error=PM-CONFIG-008 key=%s validation=%s ca_present=%s "
                "fingerprint_present=%s",
                key, result.code.c_str(),
                output.server_ca_pem.empty() ? "false" : "true",
                output.server_fingerprint.empty() ? "false" : "true");
    return false;
  }
  PM_LOG_DEBUG("CONFIG", "PERSISTED_CONFIG_LOADED",
               "key=%s version=%lu wifi_ssid=%s ca_present=%s", key,
               static_cast<unsigned long>(output.config_version),
               diag::maskSsid(output.wifi_ssid).c_str(),
               output.server_ca_pem.empty() ? "false" : "true");
  return true;
}

std::string ConfigService::serializeConfig(const RuntimeConfig &value) const {
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
  for (const auto &address : value.allowed_server_addresses) {
    if (!address.empty())
      allowed.add(address);
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
  for (const auto &server : value.ntp_servers) {
    ntp.add(server);
  }
  document["sd_spi_hz"] = value.sd_spi_hz;
  document["storage_warning_free_bytes"] = value.storage_warning_free_bytes;
  document["retention_enabled"] = value.retention_enabled;
  document["retention_days"] = value.retention_days;
  document["local_session_timeout_seconds"] =
      value.local_session_timeout_seconds;
  document["ota_channel"] = value.ota_channel;
  document["ota_signing_key_configured"] =
      !value.ota_signing_public_key_pem.empty();
  document["ota_signing_key_id"] = value.ota_signing_key_id;
  document["ota_update_window_enabled"] = value.ota_update_window_enabled;
  document["ota_update_window_start_hour"] = value.ota_update_window_start_hour;
  document["ota_update_window_end_hour"] = value.ota_update_window_end_hour;
  document["diagnostic_log_level"] = value.diagnostic_log_level;
  std::string output;
  serializeJson(document, output);
  return output;
}

bool ConfigService::parseConfig(const std::string &json, RuntimeConfig &value,
                                ConfigValidation &result) const {
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
  value.parent_circuit_id =
      document["parent_circuit_id"] | value.parent_circuit_id.c_str();
  value.measurement_role =
      document["measurement_role"] | value.measurement_role.c_str();
  value.wifi_ssid = document["wifi_ssid"] | value.wifi_ssid.c_str();
  value.static_network_enabled =
      document["static_network_enabled"] | value.static_network_enabled;
  value.static_ip = document["static_ip"] | value.static_ip.c_str();
  value.static_gateway =
      document["static_gateway"] | value.static_gateway.c_str();
  value.static_subnet = document["static_subnet"] | value.static_subnet.c_str();
  value.static_dns = document["static_dns"] | value.static_dns.c_str();
  value.server_url = document["server_url"] | value.server_url.c_str();
  if (document["server_ca_pem"].is<const char *>()) {
    value.server_ca_pem = document["server_ca_pem"].as<const char *>();
  }
  if (document["server_fingerprint"].is<const char *>()) {
    value.server_fingerprint =
        document["server_fingerprint"].as<const char *>();
  }
  value.server_ca_pem =
      config_validation::normalizePemLineEndings(value.server_ca_pem);
  value.connection_mode = parseMode(document["connection_mode"] |
                                    connectionModeName(value.connection_mode));
  if (document["allowed_server_addresses"].is<JsonArray>()) {
    value.allowed_server_addresses = {};
    std::size_t index = 0;
    for (JsonVariant item :
         document["allowed_server_addresses"].as<JsonArray>()) {
      if (index >= value.allowed_server_addresses.size() ||
          !item.is<const char *>()) {
        result = {false, "server_allowlist_invalid",
                  "Server allowlist entries must be at most four strings."};
        return false;
      }
      value.allowed_server_addresses[index++] = item.as<const char *>();
    }
  }
  value.live_interval_seconds =
      document["live_interval_seconds"] | value.live_interval_seconds;
  value.sample_interval_seconds =
      document["sample_interval_seconds"] | value.sample_interval_seconds;
  value.pzem_timeout_ms = document["pzem_timeout_ms"] | value.pzem_timeout_ms;
  value.durable_log_interval_seconds =
      document["durable_log_interval_seconds"] |
      value.durable_log_interval_seconds;
  value.heartbeat_interval_seconds =
      document["heartbeat_interval_seconds"] | value.heartbeat_interval_seconds;
  value.sync_interval_seconds =
      document["sync_interval_seconds"] | value.sync_interval_seconds;
  value.sync_retry_max_seconds =
      document["sync_retry_max_seconds"] | value.sync_retry_max_seconds;
  value.ct_rating_a = document["ct_rating_a"] | value.ct_rating_a;
  value.ct_warning_fraction =
      document["ct_warning_fraction"] | value.ct_warning_fraction;
  value.ct_critical_fraction =
      document["ct_critical_fraction"] | value.ct_critical_fraction;
  value.ct_fault_fraction =
      document["ct_fault_fraction"] | value.ct_fault_fraction;
  value.voltage_minimum_v =
      document["voltage_minimum_v"] | value.voltage_minimum_v;
  value.voltage_maximum_v =
      document["voltage_maximum_v"] | value.voltage_maximum_v;
  value.frequency_minimum_hz =
      document["frequency_minimum_hz"] | value.frequency_minimum_hz;
  value.frequency_maximum_hz =
      document["frequency_maximum_hz"] | value.frequency_maximum_hz;
  value.timezone = document["timezone"] | value.timezone.c_str();
  if (document["ntp_servers"].is<JsonArray>()) {
    const JsonArray servers = document["ntp_servers"].as<JsonArray>();
    if (servers.size() != value.ntp_servers.size()) {
      result = {false, "ntp_server_invalid",
                "Exactly three bounded NTP server names are required."};
      return false;
    }
    std::size_t index = 0;
    for (JsonVariant item : servers) {
      if (!item.is<const char *>()) {
        result = {false, "ntp_server_invalid",
                  "NTP server entries must be strings."};
        return false;
      }
      value.ntp_servers[index++] = item.as<const char *>();
    }
  }
  value.sd_spi_hz = document["sd_spi_hz"] | value.sd_spi_hz;
  value.storage_warning_free_bytes =
      document["storage_warning_free_bytes"] | value.storage_warning_free_bytes;
  value.retention_enabled =
      document["retention_enabled"] | value.retention_enabled;
  value.retention_days = document["retention_days"] | value.retention_days;
  value.local_session_timeout_seconds =
      document["local_session_timeout_seconds"] |
      value.local_session_timeout_seconds;
  value.ota_channel = document["ota_channel"] | value.ota_channel.c_str();
  if (document["ota_signing_public_key_pem"].is<const char *>()) {
    value.ota_signing_public_key_pem =
        document["ota_signing_public_key_pem"].as<const char *>();
  }
  value.ota_signing_public_key_pem = config_validation::normalizePemLineEndings(
      value.ota_signing_public_key_pem);
  value.ota_signing_key_id =
      document["ota_signing_key_id"] | value.ota_signing_key_id.c_str();
  value.ota_update_window_enabled =
      document["ota_update_window_enabled"] | value.ota_update_window_enabled;
  value.ota_update_window_start_hour =
      document["ota_update_window_start_hour"] |
      value.ota_update_window_start_hour;
  value.ota_update_window_end_hour =
      document["ota_update_window_end_hour"] | value.ota_update_window_end_hour;
  value.diagnostic_log_level =
      document["diagnostic_log_level"] | value.diagnostic_log_level;
  result = validate(value, true);
  return result.valid;
}

bool ConfigService::credentialMatches(const char *salt_key,
                                      const char *hash_key,
                                      const std::string &password) const {
  std::array<std::uint8_t, 16> salt{};
  crypto::Key32 expected{};
  if (preferences_.getBytes(salt_key, salt.data(), salt.size()) !=
          salt.size() ||
      preferences_.getBytes(hash_key, expected.data(), expected.size()) !=
          expected.size()) {
    return false;
  }
  crypto::Key32 actual{};
  if (!crypto::passwordHash(password, salt, build::PBKDF2_ITERATIONS, actual,
                            15'000U)) {
    std::fill(expected.begin(), expected.end(), std::uint8_t{0});
    return false;
  }
  std::string expected_hex =
      crypto::hexEncode(expected.data(), expected.size());
  std::string actual_hex = crypto::hexEncode(actual.data(), actual.size());
  const bool matches = crypto::constantTimeEqual(expected_hex, actual_hex);
  std::fill(expected.begin(), expected.end(), std::uint8_t{0});
  std::fill(actual.begin(), actual.end(), std::uint8_t{0});
  std::fill(expected_hex.begin(), expected_hex.end(), '\0');
  std::fill(actual_hex.begin(), actual_hex.end(), '\0');
  return matches;
}

bool ConfigService::saveCredential(const char *salt_key, const char *hash_key,
                                   const std::string &password) {
  std::array<std::uint8_t, 16> salt{};
  crypto::secureRandom(salt.data(), salt.size());
  crypto::Key32 hash{};
  if (!crypto::passwordHash(password, salt, build::PBKDF2_ITERATIONS, hash,
                            15'000U)) {
    return false;
  }
  const bool saved =
      writeBytesChecked(preferences_, salt_key, salt.data(), salt.size()) &&
      writeBytesChecked(preferences_, hash_key, hash.data(), hash.size());
  std::fill(hash.begin(), hash.end(), std::uint8_t{0});
  return saved;
}

void ConfigService::initializeIdentity() {
  DeviceIdentity identity;
  identity.local_instance_id =
      std::string(preferences_.getString("local_id", "").c_str());
  if (identity.local_instance_id.empty()) {
    identity.local_instance_id = crypto::uuidV4();
    preferences_.putString("local_id", identity.local_instance_id.c_str());
  }
  identity.device_id.clear();
  identity.enrolled = false;
  identity.boot_id = crypto::uuidV4();
  const std::uint64_t efuse_mac = ESP.getEfuseMac();
  const auto *bytes = reinterpret_cast<const std::uint8_t *>(&efuse_mac);
  const std::string material =
      crypto::hexEncode(bytes, sizeof(efuse_mac)) + "pm-hardware-v1";
  const std::string digest = crypto::sha256Hex(
      reinterpret_cast<const std::uint8_t *>(material.data()), material.size());
  identity.hardware_id = "esp32s3-" + digest.substr(0, 20);
  publishIdentity(identity);
}

bool ConfigService::initializeMutexes() {
  if (mutation_mutex_ == nullptr) {
    mutation_mutex_ = xSemaphoreCreateRecursiveMutex();
  }
  if (state_mutex_ == nullptr) {
    state_mutex_ = xSemaphoreCreateRecursiveMutex();
  }
  if (mutation_mutex_ == nullptr || state_mutex_ == nullptr) {
    if (mutation_mutex_ != nullptr) {
      vSemaphoreDelete(mutation_mutex_);
      mutation_mutex_ = nullptr;
    }
    if (state_mutex_ != nullptr) {
      vSemaphoreDelete(state_mutex_);
      state_mutex_ = nullptr;
    }
    return false;
  }
  return true;
}

RuntimeConfig ConfigService::configUnsafe() const {
  RecursiveMutexGuard state(state_mutex_, pdMS_TO_TICKS(2000));
  return state ? config_ : RuntimeConfig{};
}

DeviceIdentity ConfigService::identityUnsafe() const {
  RecursiveMutexGuard state(state_mutex_, pdMS_TO_TICKS(2000));
  return state ? identity_ : DeviceIdentity{};
}

void ConfigService::publishIdentity(const DeviceIdentity &value) {
  RecursiveMutexGuard state(state_mutex_, pdMS_TO_TICKS(2000));
  if (state)
    identity_ = value;
}

bool ConfigService::publishPersistentConfig(const RuntimeConfig &value,
                                            const std::string &wifi_password,
                                            const std::uint64_t generation) {
  RecursiveMutexGuard state(state_mutex_, pdMS_TO_TICKS(2000));
  if (!state)
    return false;
  std::fill(wifi_password_.begin(), wifi_password_.end(), '\0');
  config_ = value;
  wifi_password_ = wifi_password;
  persistent_generation_ = generation;
  return true;
}

bool ConfigService::publishEnrollment(
    const DeviceIdentity &identity,
    const std::vector<std::uint8_t> &enrollment_secret,
    const std::string &ota_public_key,
    const std::string &pending_reenrollment_token,
    const std::uint64_t reenrollment_generation) {
  RecursiveMutexGuard state(state_mutex_, pdMS_TO_TICKS(2000));
  if (!state)
    return false;
  std::fill(enrollment_secret_.begin(), enrollment_secret_.end(),
            std::uint8_t{0});
  std::fill(pending_reenrollment_token_.begin(),
            pending_reenrollment_token_.end(), '\0');
  identity_ = identity;
  enrollment_secret_ = enrollment_secret;
  ota_public_key_ = ota_public_key;
  pending_reenrollment_token_ = pending_reenrollment_token;
  reenrollment_generation_ = reenrollment_generation;
  return true;
}

} // namespace pm
