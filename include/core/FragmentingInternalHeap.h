#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace pm {

using HeapAllocationId = std::uint32_t;
constexpr HeapAllocationId kInvalidHeapAllocation = 0U;

struct FragmentingHeapSnapshot {
  std::size_t arena_bytes{0};
  std::size_t free_bytes{0};
  std::size_t largest_free_block_bytes{0};
  std::size_t allocation_count{0};
  bool integrity_ok{false};
};

// A deterministic fixed-capacity first-fit arena used only by policy/native
// tests. Free extents are derived from live allocations, so adjacent space
// coalesces automatically and simulator bookkeeping cannot itself leak.
template <std::size_t MaximumAllocations = 128U>
class FragmentingInternalHeap {
public:
  explicit FragmentingInternalHeap(const std::size_t arena_bytes)
      : arena_bytes_(arena_bytes) {}

  HeapAllocationId allocate(const std::size_t bytes,
                            const std::size_t alignment = 8U) {
    if (bytes == 0U || !validAlignment(alignment)) {
      return kInvalidHeapAllocation;
    }
    std::size_t cursor = 0U;
    while (cursor <= arena_bytes_) {
      const std::size_t aligned = alignUp(cursor, alignment);
      if (aligned > arena_bytes_ || bytes > arena_bytes_ - aligned) {
        return kInvalidHeapAllocation;
      }
      const Allocation *next = allocationAtOrAfter(aligned);
      if (next == nullptr || aligned + bytes <= next->offset) {
        return insert(aligned, bytes);
      }
      cursor = next->offset + next->bytes;
    }
    return kInvalidHeapAllocation;
  }

  HeapAllocationId allocateAt(const std::size_t offset,
                              const std::size_t bytes) {
    if (bytes == 0U || offset > arena_bytes_ ||
        bytes > arena_bytes_ - offset || overlaps(offset, bytes)) {
      return kInvalidHeapAllocation;
    }
    return insert(offset, bytes);
  }

  bool release(const HeapAllocationId id) {
    if (id == kInvalidHeapAllocation) {
      return false;
    }
    for (Allocation &allocation : allocations_) {
      if (allocation.used && allocation.id == id) {
        allocation = {};
        return true;
      }
    }
    return false;
  }

  std::size_t freeBytes() const {
    std::size_t allocated = 0U;
    for (const Allocation &allocation : allocations_) {
      allocated += allocation.used ? allocation.bytes : 0U;
    }
    return allocated <= arena_bytes_ ? arena_bytes_ - allocated : 0U;
  }

  std::size_t largestFreeBlock() const {
    std::size_t cursor = 0U;
    std::size_t largest = 0U;
    for (;;) {
      const Allocation *next = allocationAtOrAfter(cursor);
      const std::size_t end = next == nullptr ? arena_bytes_ : next->offset;
      if (end >= cursor && end - cursor > largest) {
        largest = end - cursor;
      }
      if (next == nullptr) {
        break;
      }
      cursor = next->offset + next->bytes;
    }
    return largest;
  }

  bool canAllocate(const std::size_t bytes) const {
    return bytes != 0U && largestFreeBlock() >= bytes;
  }

  std::size_t allocationCount() const {
    std::size_t count = 0U;
    for (const Allocation &allocation : allocations_) {
      count += allocation.used ? 1U : 0U;
    }
    return count;
  }

  bool integrityOk() const {
    std::size_t total = 0U;
    for (std::size_t left = 0U; left < allocations_.size(); ++left) {
      const Allocation &a = allocations_[left];
      if (!a.used) {
        continue;
      }
      if (a.bytes == 0U || a.offset > arena_bytes_ ||
          a.bytes > arena_bytes_ - a.offset) {
        return false;
      }
      total += a.bytes;
      if (total > arena_bytes_) {
        return false;
      }
      for (std::size_t right = left + 1U; right < allocations_.size();
           ++right) {
        const Allocation &b = allocations_[right];
        if (b.used && rangesOverlap(a.offset, a.bytes, b.offset, b.bytes)) {
          return false;
        }
      }
    }
    return true;
  }

  FragmentingHeapSnapshot snapshot() const {
    return {arena_bytes_, freeBytes(), largestFreeBlock(), allocationCount(),
            integrityOk()};
  }

  bool writeCsv(char *output, const std::size_t capacity) const {
    if (output == nullptr || capacity == 0U) {
      return false;
    }
    const FragmentingHeapSnapshot value = snapshot();
    const int written = std::snprintf(
        output, capacity,
        "arena_bytes,free_bytes,largest_free_block_bytes,allocation_count,"
        "integrity_ok\n%zu,%zu,%zu,%zu,%s\n",
        value.arena_bytes, value.free_bytes, value.largest_free_block_bytes,
        value.allocation_count, value.integrity_ok ? "true" : "false");
    return written >= 0 && static_cast<std::size_t>(written) < capacity;
  }

  bool writeJson(char *output, const std::size_t capacity) const {
    if (output == nullptr || capacity == 0U) {
      return false;
    }
    const FragmentingHeapSnapshot value = snapshot();
    const int written = std::snprintf(
        output, capacity,
        "{\"arena_bytes\":%zu,\"free_bytes\":%zu,"
        "\"largest_free_block_bytes\":%zu,\"allocation_count\":%zu,"
        "\"integrity_ok\":%s}",
        value.arena_bytes, value.free_bytes, value.largest_free_block_bytes,
        value.allocation_count, value.integrity_ok ? "true" : "false");
    return written >= 0 && static_cast<std::size_t>(written) < capacity;
  }

private:
  struct Allocation {
    std::size_t offset{0U};
    std::size_t bytes{0U};
    HeapAllocationId id{kInvalidHeapAllocation};
    bool used{false};
  };

  static bool validAlignment(const std::size_t alignment) {
    return alignment != 0U && (alignment & (alignment - 1U)) == 0U;
  }

  static std::size_t alignUp(const std::size_t value,
                             const std::size_t alignment) {
    return (value + alignment - 1U) & ~(alignment - 1U);
  }

  static bool rangesOverlap(const std::size_t left_offset,
                            const std::size_t left_bytes,
                            const std::size_t right_offset,
                            const std::size_t right_bytes) {
    return left_offset < right_offset + right_bytes &&
           right_offset < left_offset + left_bytes;
  }

  bool overlaps(const std::size_t offset, const std::size_t bytes) const {
    for (const Allocation &allocation : allocations_) {
      if (allocation.used &&
          rangesOverlap(offset, bytes, allocation.offset, allocation.bytes)) {
        return true;
      }
    }
    return false;
  }

  const Allocation *allocationAtOrAfter(const std::size_t offset) const {
    const Allocation *next = nullptr;
    for (const Allocation &allocation : allocations_) {
      if (!allocation.used || allocation.offset < offset) {
        continue;
      }
      if (next == nullptr || allocation.offset < next->offset) {
        next = &allocation;
      }
    }
    return next;
  }

  HeapAllocationId insert(const std::size_t offset, const std::size_t bytes) {
    for (Allocation &allocation : allocations_) {
      if (!allocation.used) {
        const HeapAllocationId id = next_id_++;
        if (next_id_ == kInvalidHeapAllocation) {
          next_id_ = 1U;
        }
        allocation = {offset, bytes, id, true};
        return id;
      }
    }
    return kInvalidHeapAllocation;
  }

  std::size_t arena_bytes_{0U};
  std::array<Allocation, MaximumAllocations> allocations_{};
  HeapAllocationId next_id_{1U};
};

} // namespace pm
