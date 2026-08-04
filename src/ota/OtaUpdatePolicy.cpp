#include "ota/OtaUpdatePolicy.h"

#include <array>
#include <cstring>
#include <limits>

namespace pm {
namespace ota_v2 {

const char *streamFailureCode(const StreamFailure failure) {
  switch (failure) {
  case StreamFailure::None:
    return "";
  case StreamFailure::Timeout:
    return "ota_image_stream_timeout";
  case StreamFailure::ConnectionReset:
    return "ota_image_connection_reset";
  case StreamFailure::Truncated:
    return "ota_image_truncated";
  case StreamFailure::ExtraBytes:
    return "ota_image_extra_bytes";
  case StreamFailure::Sha256Mismatch:
    return "ota_image_sha256_mismatch";
  case StreamFailure::PartitionWriteFailure:
    return "ota_partition_write_failed";
  }
  return "ota_stream_failure";
}

bool StreamTracker::accept(const std::size_t bytes,
                           const bool partition_write_succeeded) {
  if (failure_ != StreamFailure::None)
    return false;
  if (!partition_write_succeeded) {
    fail(StreamFailure::PartitionWriteFailure);
    return false;
  }
  if (bytes > std::numeric_limits<std::uint32_t>::max() - received_ ||
      received_ + static_cast<std::uint32_t>(bytes) > expected_size_) {
    fail(StreamFailure::ExtraBytes);
    return false;
  }
  received_ += static_cast<std::uint32_t>(bytes);
  return true;
}

void StreamTracker::timeout() { fail(StreamFailure::Timeout); }

void StreamTracker::connectionReset() {
  fail(StreamFailure::ConnectionReset);
}

bool StreamTracker::finish(const bool sha256_matches,
                           const bool extra_bytes) {
  if (failure_ != StreamFailure::None)
    return false;
  if (extra_bytes) {
    fail(StreamFailure::ExtraBytes);
  } else if (received_ != expected_size_) {
    fail(StreamFailure::Truncated);
  } else if (!sha256_matches) {
    fail(StreamFailure::Sha256Mismatch);
  }
  return failure_ == StreamFailure::None;
}

void StreamTracker::fail(const StreamFailure failure) {
  if (failure_ == StreamFailure::None)
    failure_ = failure;
}

PostBootHealthClass
classifyPostBootHealth(const PostBootHealthEvidence &evidence) {
  if (!evidence.core_primitives_ready || !evidence.heap_integrity_ok) {
    return PostBootHealthClass::FatalLocalRuntime;
  }
  const bool local_tasks_progressed =
      evidence.meter_task_progressed &&
      evidence.aggregation_task_progressed &&
      evidence.network_task_progressed && evidence.sync_task_progressed;
  if (!local_tasks_progressed) {
    return evidence.observation_window_expired
               ? PostBootHealthClass::FatalLocalRuntime
               : PostBootHealthClass::RetryableLocalInitialization;
  }
  const bool local_initialization_pending =
      !evidence.storage_available || !evidence.meter_hardware_available ||
      !evidence.network_initialized;
  if (local_initialization_pending) {
    return evidence.observation_window_expired
               ? PostBootHealthClass::LocalInitializationBlocked
               : PostBootHealthClass::RetryableLocalInitialization;
  }
  const bool external_degraded =
      !evidence.wifi_connected || !evidence.time_trusted ||
      !evidence.server_reachable;
  return external_degraded
             ? PostBootHealthClass::HealthyExternalDegraded
             : PostBootHealthClass::Healthy;
}

const char *postBootHealthClassName(const PostBootHealthClass health) {
  switch (health) {
  case PostBootHealthClass::Healthy: return "healthy";
  case PostBootHealthClass::HealthyExternalDegraded:
    return "healthy_external_degraded";
  case PostBootHealthClass::RetryableLocalInitialization:
    return "retryable_local_initialization";
  case PostBootHealthClass::LocalInitializationBlocked:
    return "local_initialization_blocked";
  case PostBootHealthClass::FatalLocalRuntime:
    return "fatal_local_runtime";
  }
  return "unknown";
}

const char *runningImageCheckResultName(
    const RunningImageCheckResult result) {
  switch (result) {
  case RunningImageCheckResult::NotPending: return "not_pending";
  case RunningImageCheckResult::ValidationDeferred:
    return "validation_deferred";
  case RunningImageCheckResult::ValidationBlocked:
    return "validation_blocked";
  case RunningImageCheckResult::Validated: return "validated";
  case RunningImageCheckResult::ValidatedRecoverySaveFailed:
    return "validated_recovery_save_failed";
  case RunningImageCheckResult::RollbackInitiated:
    return "rollback_initiated";
  case RunningImageCheckResult::RollbackUnavailable:
    return "rollback_unavailable";
  case RunningImageCheckResult::RollbackMarkFailed:
    return "rollback_mark_failed";
  case RunningImageCheckResult::PartitionStateUnavailable:
    return "partition_state_unavailable";
  case RunningImageCheckResult::RecoveryCheckpointFailed:
    return "recovery_checkpoint_failed";
  }
  return "unknown";
}

const char *rollbackResultName(const RollbackResult result) {
  switch (result) {
  case RollbackResult::Initiated: return "initiated";
  case RollbackResult::NotPossible: return "not_possible";
  case RollbackResult::RecoveryCheckpointFailed:
    return "recovery_checkpoint_failed";
  case RollbackResult::MarkFailed: return "mark_failed";
  }
  return "unknown";
}

PreServiceRecoveryAction classifyPreServiceRecovery(
    const RunningImageCheckResult rollback_result) {
  return rollback_result == RunningImageCheckResult::RollbackInitiated
             ? PreServiceRecoveryAction::RollbackRebooting
             : PreServiceRecoveryAction::RestrictedLocalRecovery;
}

bool validateSelectedPartition(
    const PartitionVerificationEvidence &evidence,
    const std::string &expected_project, const std::string &expected_version,
    const std::string &expected_build_hash, const std::uint32_t image_size,
    std::string &error) {
  if (!evidence.expected_present || !evidence.selected_present ||
      !evidence.running_present) {
    error = "ota_partition_identity_unavailable";
    return false;
  }
  if (!evidence.expected_is_ota_app) {
    error = "ota_target_partition_not_ota_app";
    return false;
  }
  if (!evidence.selected_not_running) {
    error = "ota_target_partition_is_running";
    return false;
  }
  if (evidence.selected_address != evidence.expected_address) {
    error = "ota_boot_partition_address_mismatch";
    return false;
  }
  if (evidence.selected_label != evidence.expected_label) {
    error = "ota_boot_partition_label_mismatch";
    return false;
  }
  if (evidence.selected_type != evidence.expected_type) {
    error = "ota_boot_partition_type_mismatch";
    return false;
  }
  if (evidence.selected_subtype != evidence.expected_subtype) {
    error = "ota_boot_partition_subtype_mismatch";
    return false;
  }
  if (evidence.selected_size != evidence.expected_size ||
      image_size == 0U || image_size > evidence.selected_size) {
    error = "ota_boot_partition_size_mismatch";
    return false;
  }
  if (!evidence.selected_state_available || !evidence.selected_state_new) {
    error = "ota_boot_partition_state_invalid";
    return false;
  }
  if (!evidence.descriptor_available) {
    error = "ota_boot_partition_descriptor_unavailable";
    return false;
  }
  if (evidence.project_name != expected_project) {
    error = "ota_boot_partition_project_mismatch";
    return false;
  }
  if (evidence.version != expected_version) {
    error = "ota_boot_partition_version_mismatch";
    return false;
  }
  if (evidence.build_hash != expected_build_hash) {
    error = "ota_boot_partition_build_hash_mismatch";
    return false;
  }
  error.clear();
  return true;
}

PostBootAction classifyPostBoot(
    const bool pending_image, const PostBootHealthClass health,
    const std::string &running_version,
    const std::string &running_build_hash,
    const std::string &target_version, const std::string &target_build_hash,
    const std::string &previous_version,
    const std::string &previous_build_hash,
    const bool recovery_pending_reboot) {
  const bool target_matches = recovery_pending_reboot &&
                              !target_version.empty() &&
                              !target_build_hash.empty() &&
                              running_version == target_version &&
                              running_build_hash == target_build_hash;
  if (pending_image) {
    if (!target_matches)
      return PostBootAction::Rollback;
    if (health == PostBootHealthClass::RetryableLocalInitialization)
      return PostBootAction::Defer;
    if (health == PostBootHealthClass::LocalInitializationBlocked)
      return PostBootAction::Block;
    return health == PostBootHealthClass::Healthy ||
                   health == PostBootHealthClass::HealthyExternalDegraded
               ? PostBootAction::Validate
               : PostBootAction::Rollback;
  }
  if (!recovery_pending_reboot)
    return PostBootAction::None;
  if (target_matches)
    return PostBootAction::Validate;
  if (!previous_version.empty() && !previous_build_hash.empty() &&
      running_version == previous_version &&
      running_build_hash == previous_build_hash) {
    return PostBootAction::ReportRollback;
  }
  return PostBootAction::FailUnexpectedImage;
}

namespace {

constexpr std::array<const char *, 8U> kInstallMilestones{{
    "manifest_authenticated", "download_started", "downloading",
    "binary_verified",        "partition_written", "rebooting",
    "post_boot_validation",   "validated",
}};

int milestoneIndex(const std::string &value) {
  for (std::size_t index = 0U; index < kInstallMilestones.size(); ++index) {
    if (value == kInstallMilestones[index])
      return static_cast<int>(index);
  }
  return -1;
}

} // namespace

const char *reportMilestoneForState(const State state) {
  switch (state) {
  case State::ManifestAuthenticated: return "manifest_authenticated";
  case State::WaitingForSchedule: return "waiting_for_schedule";
  case State::DownloadStarting:
    return "download_started";
  case State::Downloading:
  case State::BinaryVerifying:
    return "downloading";
  case State::PartitionWriting:
    return "binary_verified";
  case State::PartitionWritten:
  case State::RebootPending:
    return "partition_written";
  case State::Rebooting:
    return "rebooting";
  case State::PostBootValidation:
    return "post_boot_validation";
  case State::Validated:
  case State::Completed:
    return "validated";
  case State::Failed:
    return "failed";
  case State::RollbackDetected:
  case State::RolledBack:
    return "rolled_back";
  default:
    return "";
  }
}

const char *nextReportMilestone(const std::string &last_reported,
                                const std::string &desired) {
  if (desired.empty() || last_reported == desired)
    return nullptr;
  // Waiting for an administrator's update window is an optional durable
  // milestone. Immediate installs must not fabricate it, while a device that
  // really waited must replay it before download evidence after a reboot.
  if (desired == "waiting_for_schedule") {
    if (last_reported.empty())
      return "manifest_authenticated";
    return last_reported == "manifest_authenticated"
               ? "waiting_for_schedule"
               : nullptr;
  }
  if (desired == "failed")
    return last_reported == "failed" ? nullptr : "failed";
  if (desired == "rolled_back") {
    if (last_reported == "rolled_back" || last_reported == "failed")
      return nullptr;
    if (last_reported == "rollback_detected")
      return "rolled_back";
    const int delivered =
        last_reported == "waiting_for_schedule"
            ? milestoneIndex("manifest_authenticated")
            : milestoneIndex(last_reported);
    const int rebooting = milestoneIndex("rebooting");
    if (delivered < rebooting)
      return kInstallMilestones[static_cast<std::size_t>(delivered + 1)];
    return "rollback_detected";
  }
  const int target = milestoneIndex(desired);
  const int delivered =
      last_reported == "waiting_for_schedule"
          ? milestoneIndex("manifest_authenticated")
          : milestoneIndex(last_reported);
  if (target < 0 || delivered >= target)
    return nullptr;
  return kInstallMilestones[static_cast<std::size_t>(delivered + 1)];
}

bool reportStateAcceptsFailureEvidence(const std::string &state) {
  return state == "failed" || state == "rollback_detected" ||
         state == "rolled_back";
}

} // namespace ota_v2
} // namespace pm
