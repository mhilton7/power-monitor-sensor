#pragma once

#include <cstdint>

namespace pm {

struct HeapSnapshot {
  std::uint32_t free_total_bytes{0};
  std::uint32_t minimum_free_total_bytes{0};
  std::uint32_t free_internal_bytes{0};
  std::uint32_t minimum_free_internal_bytes{0};
  std::uint32_t largest_internal_block_bytes{0};
  std::uint32_t free_psram_bytes{0};
  std::uint32_t largest_psram_block_bytes{0};
  bool integrity_ok{false};
};

class IHeapTelemetry {
public:
  virtual ~IHeapTelemetry() = default;
  virtual HeapSnapshot snapshot() const = 0;
};

// Stateless production adapter. Constructing it does not allocate; each
// snapshot is read directly from the ESP-IDF capability allocator.
class EspHeapTelemetry final : public IHeapTelemetry {
public:
  HeapSnapshot snapshot() const override;
};

// Deterministic native-test adapter for exact allocator states.
class SimulatedHeapTelemetry final : public IHeapTelemetry {
public:
  explicit SimulatedHeapTelemetry(const HeapSnapshot value = {})
      : value_(value) {}

  HeapSnapshot snapshot() const override { return value_; }
  void set(const HeapSnapshot value) { value_ = value; }

private:
  HeapSnapshot value_{};
};

} // namespace pm
