#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace pm {

enum class DebugAllocationScopeId : std::uint8_t {
  UiStatus,
  UiSetup,
  UiDiagnostics,
  BrowserSession,
  HeartbeatJson,
  ReadingBatchJson,
  EventBatchJson,
  RequestSigning,
  HttpResponse,
  TlsTransport,
  StoragePage,
  Ota,
};

enum class DebugAllocationRegion : std::uint8_t { Internal, Psram };

struct DebugAllocationScopeSnapshot {
  DebugAllocationScopeId scope{DebugAllocationScopeId::UiStatus};
  DebugAllocationRegion preferred_region{DebugAllocationRegion::Internal};
  std::size_t allocation_count{0U};
  std::size_t allocated_bytes{0U};
  std::size_t freed_bytes{0U};
  std::size_t outstanding_allocations{0U};
  std::size_t outstanding_bytes{0U};
  std::size_t largest_single_allocation_bytes{0U};
  std::size_t peak_simultaneous_bytes{0U};
  std::size_t internal_allocation_count{0U};
  std::size_t internal_allocated_bytes{0U};
  std::size_t psram_allocation_count{0U};
  std::size_t psram_allocated_bytes{0U};
  std::size_t non_preferred_allocation_count{0U};
  std::size_t largest_internal_block_at_start{0U};
  std::size_t largest_internal_block_at_end{0U};
  std::size_t largest_psram_block_at_start{0U};
  std::size_t largest_psram_block_at_end{0U};
  bool operation_started{false};
  bool operation_ended{false};
  bool capacity_exhausted{false};
  bool accounting_error{false};

  bool balanced() const {
    return operation_started && operation_ended && !capacity_exhausted &&
           !accounting_error && outstanding_allocations == 0U &&
           outstanding_bytes == 0U && allocated_bytes == freed_bytes;
  }
};

// Fixed-capacity accounting for deterministic native tests and explicitly
// enabled debug instrumentation. It does not intercept malloc/new and it is
// not a physical allocator trace. Callers record only allocations owned by
// the operation being tested; bookkeeping never allocates dynamically.
template <std::size_t MaximumOutstandingAllocations = 16U>
class DebugAllocationScope {
public:
  static_assert(MaximumOutstandingAllocations > 0U,
                "an allocation scope needs at least one record");

  void begin(const DebugAllocationScopeId scope,
             const DebugAllocationRegion preferred_region,
             const std::size_t largest_internal_block,
             const std::size_t largest_psram_block) {
    records_ = {};
    snapshot_ = {};
    snapshot_.scope = scope;
    snapshot_.preferred_region = preferred_region;
    snapshot_.largest_internal_block_at_start = largest_internal_block;
    snapshot_.largest_internal_block_at_end = largest_internal_block;
    snapshot_.largest_psram_block_at_start = largest_psram_block;
    snapshot_.largest_psram_block_at_end = largest_psram_block;
    snapshot_.operation_started = true;
  }

  bool recordAllocation(const std::uint32_t allocation_id,
                        const std::size_t bytes,
                        const DebugAllocationRegion region) {
    if (!snapshot_.operation_started || snapshot_.operation_ended ||
        allocation_id == 0U || bytes == 0U || find(allocation_id) != nullptr) {
      snapshot_.accounting_error = true;
      return false;
    }
    Record *record = freeRecord();
    if (record == nullptr) {
      snapshot_.capacity_exhausted = true;
      return false;
    }
    *record = {allocation_id, bytes, region, true};
    ++snapshot_.allocation_count;
    snapshot_.allocated_bytes += bytes;
    ++snapshot_.outstanding_allocations;
    snapshot_.outstanding_bytes += bytes;
    if (bytes > snapshot_.largest_single_allocation_bytes) {
      snapshot_.largest_single_allocation_bytes = bytes;
    }
    if (snapshot_.outstanding_bytes > snapshot_.peak_simultaneous_bytes) {
      snapshot_.peak_simultaneous_bytes = snapshot_.outstanding_bytes;
    }
    if (region == DebugAllocationRegion::Internal) {
      ++snapshot_.internal_allocation_count;
      snapshot_.internal_allocated_bytes += bytes;
    } else {
      ++snapshot_.psram_allocation_count;
      snapshot_.psram_allocated_bytes += bytes;
    }
    if (region != snapshot_.preferred_region) {
      ++snapshot_.non_preferred_allocation_count;
    }
    return true;
  }

  bool recordFree(const std::uint32_t allocation_id) {
    if (!snapshot_.operation_started || snapshot_.operation_ended ||
        allocation_id == 0U) {
      snapshot_.accounting_error = true;
      return false;
    }
    Record *record = find(allocation_id);
    if (record == nullptr || !record->active ||
        snapshot_.outstanding_allocations == 0U ||
        snapshot_.outstanding_bytes < record->bytes) {
      snapshot_.accounting_error = true;
      return false;
    }
    snapshot_.freed_bytes += record->bytes;
    --snapshot_.outstanding_allocations;
    snapshot_.outstanding_bytes -= record->bytes;
    *record = {};
    return true;
  }

  void end(const std::size_t largest_internal_block,
           const std::size_t largest_psram_block) {
    if (!snapshot_.operation_started || snapshot_.operation_ended) {
      snapshot_.accounting_error = true;
      return;
    }
    snapshot_.largest_internal_block_at_end = largest_internal_block;
    snapshot_.largest_psram_block_at_end = largest_psram_block;
    snapshot_.operation_ended = true;
  }

  const DebugAllocationScopeSnapshot &snapshot() const { return snapshot_; }

private:
  struct Record {
    std::uint32_t allocation_id{0U};
    std::size_t bytes{0U};
    DebugAllocationRegion region{DebugAllocationRegion::Internal};
    bool active{false};
  };

  Record *find(const std::uint32_t allocation_id) {
    for (Record &record : records_) {
      if (record.active && record.allocation_id == allocation_id) {
        return &record;
      }
    }
    return nullptr;
  }

  Record *freeRecord() {
    for (Record &record : records_) {
      if (!record.active) {
        return &record;
      }
    }
    return nullptr;
  }

  std::array<Record, MaximumOutstandingAllocations> records_{};
  DebugAllocationScopeSnapshot snapshot_{};
};

} // namespace pm
