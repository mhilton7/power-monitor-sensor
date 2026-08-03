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
  Validate,
  Rollback,
  ReportRollback,
  FailUnexpectedImage,
};

PostBootAction classifyPostBoot(
    bool pending_image, bool health_checks_passed,
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
