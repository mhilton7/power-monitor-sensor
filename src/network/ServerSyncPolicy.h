#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

namespace pm {
namespace sync_policy {

constexpr std::size_t kMaximumResponseBytes = 24U * 1024U;
constexpr std::size_t kReadingBatchPayloadBytes = 8U * 1024U;
constexpr std::size_t kEventBatchPayloadBytes = 16U * 1024U;
constexpr std::uint32_t kMinimumInternalHeapBytes = 80U * 1024U;
constexpr std::uint32_t kMinimumLargestInternalBlockBytes = 42U * 1024U;
constexpr std::uint32_t kMinimumPostResponseInternalHeapBytes = 24U * 1024U;

enum class QueueResult : std::uint8_t {
  Queued,
  Coalesced,
};

enum class HttpDisposition : std::uint8_t {
  Success,
  AuthenticationRejected,
  RateLimited,
  Retryable,
  PermanentFailure,
  TransportFailure,
};

enum class AcknowledgementDisposition : std::uint8_t {
  Invalid,
  Current,
  Advance,
  AdvanceSequenceFloor,
};

// The server-sync task is the only transport owner, but local actions can ask
// for work from other tasks. This gate makes that boundary explicit: at most
// one transport is active and at most one pending request is retained.
class SingleFlightGate {
public:
  QueueResult queue();
  bool consumePending();
  bool tryBegin();
  void finish();
  bool active() const;
  bool pending() const;

private:
  std::atomic<bool> active_{false};
  std::atomic<bool> pending_{false};
};

// A successful lookup is reused while the configured endpoint is unchanged.
// This avoids repeatedly entering Arduino's process-global, blocking DNS wait
// during the frequent heartbeat path. Two consecutive transport failures
// invalidate the address so DHCP/DNS changes are still recovered.
class EndpointAddressCache {
public:
  bool lookup(const std::string &host, std::uint16_t port,
              std::uint32_t &address) const;
  void update(const std::string &host, std::uint16_t port,
              std::uint32_t address);
  bool recordTransportFailure();
  void recordTransportSuccess();
  bool configured() const;

private:
  static constexpr std::uint8_t kFailureLimit = 2U;
  std::string host_;
  std::uint32_t address_{0U};
  std::uint16_t port_{0U};
  std::uint8_t transport_failures_{0U};
};

std::uint32_t stackMarginPercent(std::uint32_t allocated_bytes,
                                 std::uint32_t high_water_bytes);
bool tlsMemoryReserveAvailable(std::uint32_t free_internal_bytes,
                               std::uint32_t largest_internal_block_bytes);
bool responseLengthAllowed(int response_size, int status);
bool responseAllocationAvailable(std::uint32_t free_internal_bytes,
                                 std::uint32_t largest_internal_block_bytes,
                                 int response_size);
HttpDisposition classifyHttpStatus(int status);
constexpr AcknowledgementDisposition classifyAcknowledgement(
    const std::uint64_t current_acknowledgement,
    const std::uint64_t newest_stored_sequence,
    const std::uint64_t server_acknowledgement) {
  if (server_acknowledgement < current_acknowledgement) {
    return AcknowledgementDisposition::Invalid;
  }
  if (server_acknowledgement == current_acknowledgement) {
    return AcknowledgementDisposition::Current;
  }
  return server_acknowledgement <= newest_stored_sequence
             ? AcknowledgementDisposition::Advance
             : AcknowledgementDisposition::AdvanceSequenceFloor;
}
constexpr bool shouldReleaseReadingBackoff(
    const bool immediate_sync_requested, const std::uint64_t acknowledgement,
    const std::uint64_t newest_stored_sequence) {
  return immediate_sync_requested && acknowledgement < newest_stored_sequence;
}
constexpr bool secondaryOperationsAllowed(
    const bool durable_reading_backlog) {
  return !durable_reading_backlog;
}

} // namespace sync_policy
} // namespace pm
