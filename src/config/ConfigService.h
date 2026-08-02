#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include <Preferences.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include "build_config.h"
#include "config/AtomicConfigStore.h"
#include "config/ProvisioningTransaction.h"
#include "security/Crypto.h"
#include "storage/StoragePolicy.h"

namespace pm {

enum class ConnectionMode : std::uint8_t { Pull, Push, Hybrid };

#if PM_PHYSICAL_ADMIN_RECOVERY
enum class AdminPasswordRecoveryResult : std::uint8_t {
  Applied,
  RejectedPreserved,
  FailedUncertain,
};
#endif

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
  ConnectionMode connection_mode{ConnectionMode::Push};
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
  std::array<std::string, 3> ntp_servers{"time.cloudflare.com",
                                         "time.google.com", "pool.ntp.org"};
  std::uint32_t sd_spi_hz{4'000'000};
  std::uint64_t storage_warning_free_bytes{64ULL * 1024ULL * 1024ULL};
  // Legacy fields remain serialized during the migration window so older
  // servers and local exports can still understand the effective policy.
  bool retention_enabled{false};
  std::uint16_t retention_days{365};
  StoragePolicy storage_policy{};
  std::string storage_cleanup_request_id;
  std::string storage_cleanup_reason;
  std::string storage_prepare_removal_request_id;
  std::uint32_t local_session_timeout_seconds{900};
  std::string ota_channel{"stable"};
  // Offline firmware-signing trust is local-only configuration. The public
  // key is intentionally write-only in the local API and is never accepted
  // from desired configuration returned by the central server.
  std::string ota_signing_public_key_pem;
  std::string ota_signing_key_id;
  bool ota_update_window_enabled{false};
  std::uint8_t ota_update_window_start_hour{2};
  std::uint8_t ota_update_window_end_hour{5};
  std::uint8_t diagnostic_log_level{PM_RELEASE_BUILD ? 2U : 1U};
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

// A deliberately narrow, short-lived copy for the outbound TLS transport.
// Keeping this separate from RuntimeConfig prevents every heartbeat from
// copying unrelated Wi-Fi, OTA, timezone, and metering strings into the
// already stack/heap-sensitive TLS path.
struct ServerTransportConfig {
  std::string server_url;
  std::string server_ca_pem;
  std::string server_fingerprint;
  std::array<std::string, 4> allowed_server_addresses{};
};

struct SensorStatusConfig {
  std::string friendly_name;
};

struct CompactSensorStatusConfig {
  std::array<char, 65> friendly_name{};
  std::uint32_t heartbeat_interval_seconds{15U};
  std::uint64_t server_ack_sequence{0U};
  bool truncated{false};
};

// Hot-path configuration snapshots intentionally exclude the CA, OTA key,
// and unrelated strings. RuntimeConfig can contain several KiB of PEM data;
// copying it from a 250 ms network loop or every meter sample needlessly
// fragments internal heap and inflates the caller's stack frame.
struct NetworkRuntimeConfig {
  std::string hostname;
  std::string wifi_ssid;
  bool static_network_enabled{false};
  std::string static_ip;
  std::string static_gateway;
  std::string static_subnet;
  std::string static_dns;
  std::array<std::string, 3> ntp_servers{};
};

struct MeasurementRuntimeConfig {
  std::string friendly_name;
  std::uint32_t sample_interval_seconds{1};
  std::uint32_t durable_log_interval_seconds{60};
  std::uint32_t pzem_timeout_ms{750};
  std::uint32_t sd_spi_hz{4'000'000};
  float ct_rating_a{100.0F};
  float ct_warning_fraction{0.8F};
  float ct_critical_fraction{0.9F};
  float ct_fault_fraction{1.1F};
  float voltage_minimum_v{80.0F};
  float voltage_maximum_v{280.0F};
  float frequency_minimum_hz{45.0F};
  float frequency_maximum_hz{65.0F};
  bool retention_enabled{false};
  std::uint16_t retention_days{365};
  StoragePolicy storage_policy{};
  std::string storage_cleanup_request_id;
  std::string storage_cleanup_reason;
  std::string storage_prepare_removal_request_id;
  std::uint8_t diagnostic_log_level{PM_RELEASE_BUILD ? 2U : 1U};
};

struct ServerSyncRuntimeConfig {
  std::string friendly_name;
  std::string ota_channel;
  bool server_configured{false};
  ConnectionMode connection_mode{ConnectionMode::Push};
  std::uint32_t heartbeat_interval_seconds{15};
  std::uint32_t sync_interval_seconds{300};
  std::uint32_t sync_retry_max_seconds{900};
};

// Allocation-free snapshot for the recurring server-sync path. Stable text
// such as the friendly name and OTA channel remains available through the
// full snapshot for infrequent operations, but is not copied every tick or
// heartbeat.
struct CompactServerSyncRuntimeConfig {
  bool server_configured{false};
  ConnectionMode connection_mode{ConnectionMode::Push};
  std::uint32_t heartbeat_interval_seconds{15};
  std::uint32_t sync_interval_seconds{300};
  std::uint32_t sync_retry_max_seconds{900};
  StoragePolicy storage_policy{};
};

class ConfigService {
public:
  bool begin();
  RuntimeConfig config() const;
  ServerTransportConfig serverTransportConfig() const;
  SensorStatusConfig sensorStatusConfig() const;
  CompactSensorStatusConfig compactSensorStatusConfig() const;
  NetworkRuntimeConfig networkRuntimeConfig() const;
  MeasurementRuntimeConfig measurementRuntimeConfig() const;
  ServerSyncRuntimeConfig serverSyncRuntimeConfig() const;
  CompactServerSyncRuntimeConfig compactServerSyncRuntimeConfig() const;
  DeviceIdentity identity() const;
  ConfigValidation validate(const RuntimeConfig &candidate,
                            bool ct_change_acknowledged) const;
  // Validates, persists, verifies, and publishes one candidate while holding
  // the mutation lock. The returned generation identifies this exact commit.
  bool commitCandidate(const RuntimeConfig &candidate,
                       bool ct_change_acknowledged,
                       std::uint64_t &committed_generation);
  // Compare-and-swap rollback: a later commit makes this request a conflict
  // instead of allowing a delayed caller to undo newer configuration.
  bool rollbackToPrevious(std::uint64_t expected_current_generation,
                          std::uint64_t *restored_generation = nullptr);
  std::uint64_t persistentGeneration() const;
  bool updateFromJson(const std::string &json, bool dry_run,
                      bool ct_change_acknowledged, bool trusted_server_update,
                      ConfigValidation &result,
                      std::uint64_t *committed_generation = nullptr);
  std::string redactedJson() const;

  bool hasWifiCredentials() const;
  std::string wifiPassword() const;
  bool setWifiCredentials(const std::string &ssid, const std::string &password);
  bool updateNetworkSettings(const RuntimeConfig &candidate,
                             const std::string &wifi_password,
                             bool replace_wifi_password,
                             ConfigValidation &result);
  std::string enrollmentToken() const;
  bool setEnrollmentToken(const std::string &token);
  bool clearEnrollmentToken();
  bool saveEnrollment(const std::string &device_id,
                      const std::uint8_t *enrollment_secret,
                      std::size_t secret_length,
                      const std::string &ota_public_key);
  bool directionalKeys(crypto::Key32 &device_to_server,
                       crypto::Key32 &server_to_device) const;
  std::string otaPublicKey() const;

  std::string ensureSetupPassword();
  bool setSetupPassword(const std::string &password);
  bool setupPasswordNew() const;
  bool hasAdminPassword() const;
  bool verifySetupPassword(const std::string &password) const;
#if PM_PHYSICAL_ADMIN_RECOVERY
  AdminPasswordRecoveryResult
  replaceAdminPasswordForPhysicalRecovery(const std::string &password);
#endif
  bool commitProvisioning(const RuntimeConfig &candidate,
                          const std::string &wifi_password,
                          const std::string &enrollment_token,
                          const std::string &admin_password);
  bool verifyAdminPassword(const std::string &password) const;
  bool networkReset();
  bool beginReenrollment(const std::string &token);
  std::uint64_t reenrollmentGeneration() const;
  bool factoryReset();

  std::uint64_t serverAckSequence() const;
  bool setServerAckSequence(std::uint64_t sequence);
  std::uint64_t serverMaximumSeenSequence() const;
  bool setServerMaximumSeenSequence(std::uint64_t sequence);
  std::uint64_t preparedRemovalSequence() const;
  bool setPreparedRemovalSequence(std::uint64_t sequence);
  std::uint64_t serverEventAckSequence() const;
  bool setServerEventAckSequence(std::uint64_t sequence);
  std::uint32_t serverConfigVersion() const;
  bool setServerConfigVersion(std::uint32_t version);
  std::uint64_t energyOffsetWh() const;
  bool setEnergyOffsetWh(std::uint64_t offset);
  bool recordBootStarted();
  bool recordBootHealthy();
  bool setDiagnosticLogLevel(std::uint8_t level);
  bool safeMode() const;
  std::string safeModeReason() const;

private:
  bool loadLegacyConfig(const char *key, RuntimeConfig &output) const;
  bool loadPersistentConfig(RuntimeConfig &output, std::string &wifi_password,
                            std::uint64_t &generation) const;
  bool commitPersistentConfig(const RuntimeConfig &value,
                              const std::string &wifi_password,
                              std::uint64_t *generation = nullptr);
  bool verifyPersistentConfig(const RuntimeConfig &expected,
                              const std::string &expected_password) const;
  std::string serializePersistentConfig(const RuntimeConfig &value,
                                        const std::string &wifi_password) const;
  bool parsePersistentConfig(const std::string &json, RuntimeConfig &value,
                             std::string &wifi_password,
                             ConfigValidation &result) const;
  bool loadOrMigrateEnrollment();
  bool initializePersistentPartition();
  bool commitEnrollmentRecord(const std::string &device_id,
                              const std::uint8_t *enrollment_secret,
                              std::size_t secret_length,
                              const std::string &ota_public_key,
                              std::uint64_t reenrollment_generation);
  bool commitEnrollmentTombstone(std::uint64_t reenrollment_generation = 0);
  bool commitReenrollmentPending(const std::string &token,
                                 std::uint64_t reenrollment_generation);
  bool loadEnrollmentRecord(const std::vector<std::uint8_t> &payload,
                            std::string &device_id,
                            std::vector<std::uint8_t> &enrollment_secret,
                            std::string &ota_public_key,
                            std::string &pending_reenrollment_token,
                            std::uint64_t &reenrollment_generation) const;
  bool clearPersistentNamespace();
  bool
  prepareProvisioningTransaction(provisioning_transaction::Journal &journal);
  bool recoverIncompleteProvisioning();
  bool clearProvisioningTransaction();
  bool publishRecoveredProvisioningState();
  std::string serializeConfig(const RuntimeConfig &value) const;
  bool parseConfig(const std::string &json, RuntimeConfig &value,
                   ConfigValidation &result) const;
  bool credentialMatches(const char *salt_key, const char *hash_key,
                         const std::string &password) const;
  bool persistAdminVerifier(const std::string &password);
  bool saveCredential(const char *salt_key, const char *hash_key,
                      const std::string &password);
  void initializeIdentity();
  bool initializeMutexes();
  RuntimeConfig configUnsafe() const;
  DeviceIdentity identityUnsafe() const;
  void publishIdentity(const DeviceIdentity &value);
  bool publishPersistentConfig(const RuntimeConfig &value,
                               const std::string &wifi_password,
                               std::uint64_t generation);
  bool publishEnrollment(const DeviceIdentity &identity,
                         const std::vector<std::uint8_t> &enrollment_secret,
                         const std::string &ota_public_key,
                         const std::string &pending_reenrollment_token,
                         std::uint64_t reenrollment_generation);

  mutable Preferences preferences_;
  RuntimeConfig config_;
  DeviceIdentity identity_;
  bool safe_mode_{false};
  std::string safe_mode_reason_;
  bool setup_password_new_{false};
  bool admin_password_configured_{false};
  std::string wifi_password_;
  std::vector<std::uint8_t> enrollment_secret_;
  std::string ota_public_key_;
  std::string pending_reenrollment_token_;
  std::uint64_t reenrollment_generation_{0};
  std::uint64_t persistent_generation_{0};
  std::uint64_t server_ack_sequence_{0};
  std::uint64_t server_maximum_seen_sequence_{0};
  std::uint64_t prepared_removal_sequence_{0};
  std::uint64_t server_event_ack_sequence_{0};
  std::uint32_t server_config_version_{0};
  std::uint64_t energy_offset_wh_{0};
  mutable SemaphoreHandle_t mutation_mutex_{nullptr};
  mutable SemaphoreHandle_t state_mutex_{nullptr};
};

const char *connectionModeName(ConnectionMode mode);

} // namespace pm
