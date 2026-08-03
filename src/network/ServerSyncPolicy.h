#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

#include "core/HeapTelemetry.h"
#include "core/MemoryPressurePolicy.h"
#include "core/StringView.h"

namespace pm {
namespace sync_policy {

constexpr std::size_t kMaximumResponseBytes = 24U * 1024U;
constexpr std::size_t kHeartbeatResponseBytes = 8U * 1024U;
constexpr std::size_t kEnrollmentResponseBytes = 16U * 1024U;
constexpr std::size_t kReadingBatchResponseBytes = 12U * 1024U;
constexpr std::size_t kEventBatchResponseBytes = 8U * 1024U;
constexpr std::size_t kReadingBatchPayloadBytes = 8U * 1024U;
constexpr std::size_t kEventBatchPayloadBytes = 16U * 1024U;
// The circular-storage and sequence-reconciliation runtime has been measured
// at 72,348 free internal bytes immediately before a heartbeat. TLS consumes
// about 41 KiB on this target, so a 64 KiB admission floor leaves roughly
// 23 KiB after the handshake while the independent response-allocation guard
// below preserves 24 KiB after allocating the bounded response body. Keeping
// the older 78 KiB floor made every valid steady-state heartbeat impossible.
constexpr std::uint32_t kMinimumInternalHeapBytes = 64U * 1024U;
// A prior deployed build reported a 33,780-byte largest internal block beside
// a live PZEM sample. Retain the conservative 32 KiB contiguous admission
// requirement while this exact binary awaits separate physical validation;
// the independent total-heap guard preserves the remaining network/UI reserve.
constexpr std::uint32_t kMinimumLargestInternalBlockBytes = 32U * 1024U;
static_assert(kMinimumInternalHeapBytes == kTlsMinimumFreeInternalBytes,
              "TLS total-heap guard must match memory diagnostics");
static_assert(kMinimumLargestInternalBlockBytes ==
                  kTlsMinimumLargestInternalBlockBytes,
              "TLS contiguous-block guard must match memory diagnostics");
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

enum class TlsMemoryAdmission : std::uint8_t {
  Available,
  LowTotalMemory,
  Fragmented,
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
bool stackMarginHealthy(std::uint32_t allocated_bytes,
                        std::uint32_t high_water_bytes,
                        std::uint32_t minimum_margin_percent);
bool tlsMemoryReserveAvailable(std::uint32_t free_internal_bytes,
                               std::uint32_t largest_internal_block_bytes);
TlsMemoryAdmission classifyTlsMemory(const HeapSnapshot &snapshot);
bool tlsMemoryReserveAvailable(const HeapSnapshot &snapshot);
bool responseLengthAllowed(int response_size, int status);
std::size_t maximumResponseBytes(StringView endpoint);
std::size_t maximumRequestBytes(StringView endpoint);
bool responseLengthAllowed(StringView endpoint, int response_size,
                           int status);
constexpr bool responseBodyFitsBuffer(const int response_size,
                                      const std::size_t capacity) {
  // HTTPClient reports -1 when a valid response has no Content-Length. A 204
  // is allowed to take that path, so never cast a non-positive sentinel to an
  // unsigned size while enforcing the bounded response buffer.
  return response_size <= 0 ||
         static_cast<std::size_t>(response_size) <= capacity;
}
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
  // The acknowledgement is persisted independently from microSD history. If
  // the card is repaired, replaced, or reset while the enrolled identity is
  // preserved, the stored acknowledgement can already equal the server's
  // response while still sitting ahead of the local sequence journal. Advance
  // the storage floor in that case so new durable records resume above the
  // immutable server cursor instead of being mistaken for an empty backlog.
  if (server_acknowledgement > newest_stored_sequence) {
    return AcknowledgementDisposition::AdvanceSequenceFloor;
  }
  if (server_acknowledgement == current_acknowledgement) {
    return AcknowledgementDisposition::Current;
  }
  return AcknowledgementDisposition::Advance;
}
constexpr std::uint64_t requiredSequenceFloor(
    const std::uint64_t local_record_high_water,
    const std::uint64_t journal_high_water,
    const std::uint64_t persisted_acknowledgement,
    const std::uint64_t persisted_maximum_seen,
    const std::uint64_t server_maximum_seen,
    const std::uint64_t prepared_removal_high_water = 0U) {
  const std::uint64_t local = local_record_high_water > journal_high_water
                                  ? local_record_high_water
                                  : journal_high_water;
  const std::uint64_t persisted =
      persisted_acknowledgement > persisted_maximum_seen
          ? persisted_acknowledgement
          : persisted_maximum_seen;
  const std::uint64_t remote = persisted > server_maximum_seen
                                   ? persisted
                                   : server_maximum_seen;
  return local > remote
             ? (local > prepared_removal_high_water ? local
                                                     : prepared_removal_high_water)
             : (remote > prepared_removal_high_water
                    ? remote
                    : prepared_removal_high_water);
}
constexpr bool sequenceCursorContractValid(
    const std::uint64_t top_level_acknowledgement,
    const std::uint64_t nested_acknowledgement,
    const std::uint64_t maximum_seen_sequence,
    const std::uint64_t next_sequence_floor) {
  return top_level_acknowledgement == nested_acknowledgement &&
         maximum_seen_sequence >= nested_acknowledgement &&
         maximum_seen_sequence != UINT64_MAX &&
         next_sequence_floor == maximum_seen_sequence + 1U;
}
constexpr bool shouldReleaseReadingBackoff(
    const bool immediate_sync_requested, const std::uint64_t acknowledgement,
    const std::uint64_t newest_stored_sequence,
    const bool previous_release_recorded,
    const std::uint64_t previous_release_acknowledgement) {
  return immediate_sync_requested &&
         acknowledgement < newest_stored_sequence &&
         (!previous_release_recorded ||
          acknowledgement != previous_release_acknowledgement);
}
constexpr bool secondaryOperationsAllowed(
    const bool durable_reading_backlog) {
  return !durable_reading_backlog;
}
constexpr bool shouldScheduleEventIdleDelay(
    const bool operation_succeeded, const bool page_job_pending) {
  return operation_succeeded && !page_job_pending;
}
constexpr std::uint64_t manifestPollDeadline(
    const bool firmware_release_available,
    const std::uint64_t current_deadline_ms, const std::uint64_t now_ms) {
  // Heartbeat and manifest requests share the server-sync single-flight
  // owner. Moving the deadline to now schedules the manifest for the next
  // tick, after the heartbeat transport has been destroyed. A false signal
  // preserves any existing deadline or deployment work.
  return firmware_release_available && current_deadline_ms > now_ms
             ? now_ms
             : current_deadline_ms;
}

} // namespace sync_policy
} // namespace pm
