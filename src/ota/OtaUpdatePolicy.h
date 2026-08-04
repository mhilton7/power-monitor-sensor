#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "ota/OtaManifestV2.h"

namespace pm {
namespace ota_v2 {

enum class StreamFailure : std::uint8_t {
  None,
  Timeout,
  ConnectionReset,
  Truncated,
  ExtraBytes,
  Sha256Mismatch,
  PartitionWriteFailure,
};

const char *streamFailureCode(StreamFailure failure);

class StreamTracker {
public:
  explicit StreamTracker(std::uint32_t expected_size)
      : expected_size_(expected_size) {}

  bool accept(std::size_t bytes, bool partition_write_succeeded = true);
  void timeout();
  void connectionReset();
  bool finish(bool sha256_matches, bool extra_bytes = false);
  std::uint32_t received() const { return received_; }
  StreamFailure failure() const { return failure_; }

private:
  void fail(StreamFailure failure);

  std::uint32_t expected_size_{0U};
  std::uint32_t received_{0U};
  StreamFailure failure_{StreamFailure::None};
};

enum class PostBootAction : std::uint8_t {
  None,
  Defer,
  Block,
  Validate,
  Rollback,
  ReportRollback,
  FailUnexpectedImage,
};

enum class PostBootHealthClass : std::uint8_t {
  Healthy,
  HealthyExternalDegraded,
  RetryableLocalInitialization,
  LocalInitializationBlocked,
  FatalLocalRuntime,
};

enum class RunningImageCheckResult : std::uint8_t {
  NotPending,
  ValidationDeferred,
  ValidationBlocked,
  Validated,
  ValidatedRecoverySaveFailed,
  RollbackInitiated,
  RollbackUnavailable,
  RollbackMarkFailed,
  PartitionStateUnavailable,
  RecoveryCheckpointFailed,
};

enum class RollbackResult : std::uint8_t {
  Initiated,
  NotPossible,
  RecoveryCheckpointFailed,
  MarkFailed,
};

// A PENDING_VERIFY image whose authenticated recovery identity cannot be
// loaded must never enter the normal measurement/synchronization runtime.
// ESP-IDF rollback is always attempted first.  Only a rollback call that is
// expected to reboot may stop here; every non-rebooting outcome is routed to
// the deliberately restricted local recovery runtime.
enum class PreServiceRecoveryAction : std::uint8_t {
  RollbackRebooting,
  RestrictedLocalRecovery,
};

const char *runningImageCheckResultName(RunningImageCheckResult result);
const char *rollbackResultName(RollbackResult result);
PreServiceRecoveryAction
classifyPreServiceRecovery(RunningImageCheckResult rollback_result);

struct PostBootHealthEvidence {
  bool core_primitives_ready{false};
  bool heap_integrity_ok{false};
  bool meter_task_progressed{false};
  bool aggregation_task_progressed{false};
  bool network_task_progressed{false};
  bool sync_task_progressed{false};
  bool observation_window_expired{false};
  // Local subsystem initialization is a bounded validation gate. Temporary
  // Wi-Fi, clock, DNS, and server outages are external conditions and do not
  // invalidate an otherwise healthy firmware image.
  bool storage_available{false};
  bool meter_hardware_available{false};
  bool network_initialized{false};
  bool wifi_connected{false};
  bool time_trusted{false};
  bool server_reachable{false};
};

PostBootHealthClass
classifyPostBootHealth(const PostBootHealthEvidence &evidence);
const char *postBootHealthClassName(PostBootHealthClass health);

struct PartitionVerificationEvidence {
  bool expected_present{false};
  bool selected_present{false};
  bool running_present{false};
  bool expected_is_ota_app{false};
  bool selected_not_running{false};
  bool selected_state_available{false};
  bool selected_state_new{false};
  bool descriptor_available{false};
  std::uint8_t expected_type{0U};
  std::uint8_t selected_type{0U};
  std::uint8_t expected_subtype{0U};
  std::uint8_t selected_subtype{0U};
  std::uint32_t expected_address{0U};
  std::uint32_t selected_address{0U};
  std::uint32_t expected_size{0U};
  std::uint32_t selected_size{0U};
  std::string expected_label;
  std::string selected_label;
  std::string project_name;
  std::string version;
  std::string build_hash;
};

bool validateSelectedPartition(
    const PartitionVerificationEvidence &evidence,
    const std::string &expected_project, const std::string &expected_version,
    const std::string &expected_build_hash, std::uint32_t image_size,
    std::string &error);

PostBootAction classifyPostBoot(
    bool pending_image, PostBootHealthClass health,
    const std::string &running_version, const std::string &running_build_hash,
    const std::string &target_version, const std::string &target_build_hash,
    const std::string &previous_version,
    const std::string &previous_build_hash, bool recovery_pending_reboot);

const char *reportMilestoneForState(State state);
const char *nextReportMilestone(const std::string &last_reported,
                                const std::string &desired);
bool reportStateAcceptsFailureEvidence(const std::string &state);

} // namespace ota_v2
} // namespace pm
