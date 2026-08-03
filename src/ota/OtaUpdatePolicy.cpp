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

PostBootAction classifyPostBoot(
    const bool pending_image, const bool health_checks_passed,
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
    return health_checks_passed && target_matches
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
  case State::ManifestAuthenticated:
  case State::WaitingForSchedule:
    return "manifest_authenticated";
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
  if (desired == "failed")
    return last_reported == "failed" ? nullptr : "failed";
  if (desired == "rolled_back") {
    if (last_reported == "rolled_back" || last_reported == "failed")
      return nullptr;
    if (last_reported == "rollback_detected")
      return "rolled_back";
    const int delivered = milestoneIndex(last_reported);
    const int rebooting = milestoneIndex("rebooting");
    if (delivered < rebooting)
      return kInstallMilestones[static_cast<std::size_t>(delivered + 1)];
    return "rollback_detected";
  }
  const int target = milestoneIndex(desired);
  const int delivered = milestoneIndex(last_reported);
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
