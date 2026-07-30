#include "network/ServerSyncPolicy.h"

#include <algorithm>

namespace pm {
namespace sync_policy {

QueueResult SingleFlightGate::queue() {
  bool expected = false;
  if (pending_.compare_exchange_strong(expected, true,
                                       std::memory_order_acq_rel)) {
    return QueueResult::Queued;
  }
  return QueueResult::Coalesced;
}

bool SingleFlightGate::consumePending() {
  return pending_.exchange(false, std::memory_order_acq_rel);
}

bool SingleFlightGate::tryBegin() {
  bool expected = false;
  return active_.compare_exchange_strong(expected, true,
                                         std::memory_order_acq_rel);
}

void SingleFlightGate::finish() {
  active_.store(false, std::memory_order_release);
}

bool SingleFlightGate::active() const {
  return active_.load(std::memory_order_acquire);
}

bool SingleFlightGate::pending() const {
  return pending_.load(std::memory_order_acquire);
}

bool EndpointAddressCache::lookup(const std::string &host,
                                  const std::uint16_t port,
                                  std::uint32_t &address) const {
  if (address_ == 0U || host_ != host || port_ != port) {
    address = 0U;
    return false;
  }
  address = address_;
  return true;
}

void EndpointAddressCache::update(const std::string &host,
                                  const std::uint16_t port,
                                  const std::uint32_t address) {
  host_ = host;
  port_ = port;
  address_ = address;
  transport_failures_ = 0U;
}

bool EndpointAddressCache::recordTransportFailure() {
  if (address_ == 0U) {
    return false;
  }
  ++transport_failures_;
  if (transport_failures_ < kFailureLimit) {
    return false;
  }
  host_.clear();
  address_ = 0U;
  port_ = 0U;
  transport_failures_ = 0U;
  return true;
}

void EndpointAddressCache::recordTransportSuccess() {
  transport_failures_ = 0U;
}

bool EndpointAddressCache::configured() const {
  return address_ != 0U;
}

std::uint32_t stackMarginPercent(const std::uint32_t allocated_bytes,
                                 const std::uint32_t high_water_bytes) {
  if (allocated_bytes == 0U) {
    return 0U;
  }
  const std::uint64_t bounded =
      std::min<std::uint32_t>(allocated_bytes, high_water_bytes);
  return static_cast<std::uint32_t>((bounded * 100U) / allocated_bytes);
}

bool tlsMemoryReserveAvailable(
    const std::uint32_t free_internal_bytes,
    const std::uint32_t largest_internal_block_bytes) {
  return free_internal_bytes >= kMinimumInternalHeapBytes &&
         largest_internal_block_bytes >= kMinimumLargestInternalBlockBytes;
}

bool responseLengthAllowed(const int response_size, const int status) {
  if (status == 204) {
    return response_size <= 0;
  }
  return response_size >= 0 &&
         static_cast<std::size_t>(response_size) <= kMaximumResponseBytes;
}

bool responseAllocationAvailable(
    const std::uint32_t free_internal_bytes,
    const std::uint32_t largest_internal_block_bytes, const int response_size) {
  if (response_size <= 0) {
    return true;
  }
  const std::uint32_t requested = static_cast<std::uint32_t>(response_size);
  const std::uint64_t required = static_cast<std::uint64_t>(requested) +
                                 kMinimumPostResponseInternalHeapBytes;
  return free_internal_bytes >= required &&
         largest_internal_block_bytes >= requested;
}

HttpDisposition classifyHttpStatus(const int status) {
  if (status < 0) {
    return HttpDisposition::TransportFailure;
  }
  if (status >= 200 && status < 300) {
    return HttpDisposition::Success;
  }
  if (status == 401 || status == 403) {
    return HttpDisposition::AuthenticationRejected;
  }
  if (status == 429) {
    return HttpDisposition::RateLimited;
  }
  if (status == 408 || status == 425 || status == 502 || status == 503 ||
      status == 504 || status >= 500) {
    return HttpDisposition::Retryable;
  }
  return HttpDisposition::PermanentFailure;
}

} // namespace sync_policy
} // namespace pm
