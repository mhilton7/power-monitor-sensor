#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pm {

enum class RetentionMode : std::uint8_t {
  Disabled,
  StrictAge,
  ContinuousProtected,
};

enum class StoragePressureState : std::uint8_t {
  Healthy,
  Notice,
  Warning,
  Critical,
  Emergency,
  CleanupQueued,
  CleanupRunning,
  CleanupRecovering,
  CleanupBlockedUnacknowledged,
  CleanupBlockedUntrusted,
  ReadOnly,
  Full,
  Failed,
  PreparedForRemoval,
};

struct StoragePolicy {
  RetentionMode mode{RetentionMode::ContinuousProtected};
  std::uint16_t retention_days{730};
  std::uint16_t minimum_local_history_days{30};
  std::uint8_t notice_percent{20};
  std::uint8_t warning_percent{10};
  std::uint8_t critical_percent{5};
  std::uint8_t emergency_percent{2};
  std::uint64_t emergency_reserve_bytes{512ULL * 1024ULL * 1024ULL};
  std::uint8_t cleanup_target_percent{10};
  std::uint64_t cleanup_target_bytes{1024ULL * 1024ULL * 1024ULL};
  std::uint16_t event_retention_days{730};
};

struct StoragePolicyValidation {
  bool valid{false};
  const char *code{"storage_policy_invalid"};
};

bool resetCardBindingMatches(std::uint64_t actual_generation,
                             const std::string &actual_device_id,
                             std::uint64_t expected_generation,
                             const std::string &expected_device_id);
bool resetManifestBindingMatches(
    std::uint32_t schema_version, std::uint64_t actual_generation,
    const std::string &actual_device_id,
    const std::string &actual_hardware_fingerprint,
    std::uint64_t expected_generation,
    const std::string &expected_device_id,
    const std::string &expected_hardware_fingerprint);

struct SegmentMetadata {
  std::string record_path;
  std::string index_path;
  std::uint64_t first_sequence{0};
  std::uint64_t last_sequence{0};
  std::uint64_t first_utc_ms{0};
  std::uint64_t last_utc_ms{0};
  std::uint64_t payload_bytes{0};
  std::uint64_t index_bytes{0};
  std::uint32_t record_count{0};
  std::uint32_t integrity_crc{0};
  bool all_times_trusted{false};
  bool complete{false};
  bool index_valid{false};
  bool closed{false};
  bool active{false};
  bool cleanup_active{false};
  bool minimum_window_protected{false};
};

enum class SegmentEligibility : std::uint8_t {
  EligibleAge,
  EligibleEmergency,
  Active,
  Incomplete,
  CorruptOrMissingIndex,
  SequenceUnknown,
  Unacknowledged,
  TooRecent,
  TimeUntrusted,
  CleanupActive,
  MinimumWindow,
};

struct RetentionContext {
  RetentionMode mode{RetentionMode::Disabled};
  bool emergency_pressure{false};
  bool acknowledgement_verified{false};
  std::uint64_t server_ack_sequence{0};
  std::uint64_t retention_cutoff_utc_ms{0};
  std::uint64_t minimum_history_cutoff_utc_ms{0};
};

struct CleanupPlan {
  std::vector<std::size_t> candidate_indexes;
  std::uint64_t eligible_bytes{0};
  std::uint64_t protected_unacknowledged_bytes{0};
  std::uint64_t protected_untrusted_bytes{0};
  std::uint64_t expected_reclaimed_bytes{0};
};

enum class CleanupRecoveryAction : std::uint8_t {
  ClearJournal,
  ReverseMoves,
  ForwardDelete,
  Block,
};

struct CleanupRecoverySnapshot {
  std::string stage;
  bool has_index{false};
  bool record_original_exists{false};
  bool record_trash_exists{false};
  bool index_original_exists{false};
  bool index_trash_exists{false};
};

StoragePolicyValidation validateStoragePolicy(const StoragePolicy &policy);
StoragePressureState classifyStoragePressure(std::uint64_t capacity_bytes,
                                             std::uint64_t free_bytes,
                                             const StoragePolicy &policy);
std::uint64_t cleanupTargetFreeBytes(std::uint64_t capacity_bytes,
                                     const StoragePolicy &policy);
std::uint64_t conservativeWriteReserveBytes(std::size_t record_bytes);
SegmentEligibility segmentEligibility(const SegmentMetadata &segment,
                                      const RetentionContext &context);
CleanupPlan buildCleanupPlan(const std::vector<SegmentMetadata> &segments,
                             const RetentionContext &context,
                             std::uint64_t free_bytes,
                             std::uint64_t target_free_bytes);
CleanupRecoveryAction
cleanupRecoveryAction(const CleanupRecoverySnapshot &snapshot);
const char *retentionModeName(RetentionMode mode);
bool parseRetentionMode(const std::string &value, RetentionMode &mode);
const char *storagePressureStateName(StoragePressureState state);

class StorageGrowthEstimator {
public:
  void observe(std::uint64_t used_bytes, std::uint64_t monotonic_ms);
  void recordCleanup(std::uint64_t reclaimed_bytes);
  std::uint64_t bytesPerDay() const;
  std::int64_t estimatedDaysRemaining(std::uint64_t free_bytes,
                                      std::uint64_t reserve_bytes) const;

private:
  std::uint64_t previous_used_bytes_{0};
  std::uint64_t previous_monotonic_ms_{0};
  double bytes_per_day_{0.0};
  std::uint64_t cleanup_bytes_{0};
  std::uint8_t observations_{0};
};

} // namespace pm
