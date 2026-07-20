#pragma once

#include <array>
#include <cstdint>
#include <string>

#include <Preferences.h>

#include "security/Crypto.h"

namespace pm {

enum class ConnectionMode : std::uint8_t { Pull, Push, Hybrid };

struct RuntimeConfig {
  std::uint32_t schema_version{1};
  std::uint32_t config_version{1};
  std::string friendly_name{"Unassigned Power Monitor"};
  std::string hostname;
  std::string site_id;
  std::string circuit_id;
  std::string parent_circuit_id;
  std::string measurement_role{"branch"};
  std::string wifi_ssid;
  bool static_network_enabled{false};
  std::string static_ip;
  std::string static_gateway;
  std::string static_subnet;
  std::string static_dns;
  std::string server_url;
  std::string server_ca_pem;
  std::string server_fingerprint;
  ConnectionMode connection_mode{ConnectionMode::Hybrid};
  std::array<std::string, 4> allowed_server_addresses{};
  std::uint32_t live_interval_seconds{2};
  std::uint32_t sample_interval_seconds{1};
  std::uint32_t pzem_timeout_ms{750};
  std::uint32_t durable_log_interval_seconds{60};
  std::uint32_t heartbeat_interval_seconds{15};
  std::uint32_t sync_interval_seconds{300};
  std::uint32_t sync_retry_max_seconds{900};
  float ct_rating_a{100.0F};
  float ct_warning_fraction{0.8F};
  float ct_critical_fraction{0.9F};
  float ct_fault_fraction{1.1F};
  float voltage_minimum_v{80.0F};
  float voltage_maximum_v{280.0F};
  float frequency_minimum_hz{45.0F};
  float frequency_maximum_hz{65.0F};
  std::string timezone{"America/Los_Angeles"};
  std::array<std::string, 3> ntp_servers{"time.cloudflare.com", "time.google.com", "pool.ntp.org"};
  std::uint32_t sd_spi_hz{4'000'000};
  std::uint64_t storage_warning_free_bytes{64ULL * 1024ULL * 1024ULL};
  bool retention_enabled{false};
  std::uint16_t retention_days{365};
  std::uint32_t local_session_timeout_seconds{900};
  std::string ota_channel{"stable"};
  bool ota_update_window_enabled{false};
  std::uint8_t ota_update_window_start_hour{2};
  std::uint8_t ota_update_window_end_hour{5};
  std::uint8_t diagnostic_log_level{1};
};

struct DeviceIdentity {
  std::string hardware_id;
  std::string local_instance_id;
  std::string device_id;
  std::string boot_id;
  bool enrolled{false};
};

struct ConfigValidation {
  bool valid{false};
  std::string code;
  std::string detail;
};

class ConfigService {
 public:
  bool begin();
  const RuntimeConfig& config() const;
  const DeviceIdentity& identity() const;
  ConfigValidation validate(const RuntimeConfig& candidate,
                            bool ct_change_acknowledged) const;
  bool stage(const RuntimeConfig& candidate, bool ct_change_acknowledged);
  bool commitStaged();
  bool rollbackStaged();
  bool rollbackToPrevious();
  bool updateFromJson(const std::string& json, bool dry_run,
                      bool ct_change_acknowledged, ConfigValidation& result);
  std::string redactedJson() const;

  bool hasWifiCredentials() const;
  std::string wifiPassword() const;
  bool setWifiCredentials(const std::string& ssid, const std::string& password);
  std::string enrollmentToken() const;
  bool setEnrollmentToken(const std::string& token);
  void clearEnrollmentToken();
  bool saveEnrollment(const std::string& device_id,
                      const std::uint8_t* enrollment_secret,
                      std::size_t secret_length,
                      const std::string& ota_public_key);
  bool directionalKeys(crypto::Key32& device_to_server,
                       crypto::Key32& server_to_device) const;
  std::string otaPublicKey() const;

  std::string ensureSetupPassword();
  bool setupPasswordNew() const;
  bool hasAdminPassword() const;
  bool verifySetupPassword(const std::string& password) const;
  bool setAdminPassword(const std::string& password);
  bool commitProvisioning(const RuntimeConfig& candidate,
                          const std::string& wifi_password,
                          const std::string& enrollment_token,
                          const std::string& admin_password);
  bool verifyAdminPassword(const std::string& password) const;
  bool networkReset();
  bool beginReenrollment(const std::string& token);
  bool factoryReset();

  std::uint64_t serverAckSequence() const;
  bool setServerAckSequence(std::uint64_t sequence);
  std::uint64_t energyOffsetWh() const;
  bool setEnergyOffsetWh(std::uint64_t offset);
  bool recordBootStarted();
  bool recordBootHealthy();
  bool safeMode() const;
  std::string safeModeReason() const;

 private:
  bool loadConfig(const char* key, RuntimeConfig& output) const;
  bool saveConfig(const char* key, const RuntimeConfig& value);
  std::string serializeConfig(const RuntimeConfig& value) const;
  bool parseConfig(const std::string& json, RuntimeConfig& value,
                   ConfigValidation& result) const;
  bool credentialMatches(const char* salt_key, const char* hash_key,
                         const std::string& password) const;
  bool saveCredential(const char* salt_key, const char* hash_key,
                      const std::string& password);
  void initializeIdentity();

  mutable Preferences preferences_;
  RuntimeConfig config_;
  RuntimeConfig staged_;
  DeviceIdentity identity_;
  bool staged_valid_{false};
  bool safe_mode_{false};
  std::string safe_mode_reason_;
  bool setup_password_new_{false};
};

const char* connectionModeName(ConnectionMode mode);

}  // namespace pm
