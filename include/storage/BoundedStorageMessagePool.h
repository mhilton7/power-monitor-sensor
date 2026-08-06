#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

#include "core/Models.h"
#include "core/StringView.h"

namespace pm {

constexpr std::uint16_t kInvalidStoragePoolSlot =
    std::numeric_limits<std::uint16_t>::max();

template <std::size_t Capacity>
bool copyStorageText(std::array<char, Capacity> &target,
                     const std::string &source) {
  static_assert(Capacity > 1U, "storage text needs terminator capacity");
  if (source.size() >= target.size()) {
    target[0] = '\0';
    return false;
  }
  const int written =
      std::snprintf(target.data(), target.size(), "%s", source.c_str());
  return written >= 0 && static_cast<std::size_t>(written) < target.size();
}

template <std::size_t Capacity>
bool copyStorageText(std::array<char, Capacity> &target,
                     const StringView source) {
  static_assert(Capacity > 1U, "storage text needs terminator capacity");
  if (source.size() >= target.size()) {
    target[0] = '\0';
    return false;
  }
  if (!source.empty()) {
    std::memcpy(target.data(), source.data(), source.size());
  }
  target[source.size()] = '\0';
  return true;
}

// Queue payloads contain only fixed-capacity arrays and scalar values. The
// recurring producer path therefore performs no new/delete and no hidden
// std::string allocation while a TLS or OTA operation owns internal DRAM.
struct FixedIntervalRecord {
  std::uint32_t schema_version{1U};
  std::uint64_t data_generation{0U};
  std::array<char, 40U> device_id{};
  std::array<char, 65U> friendly_name{};
  std::uint64_t sequence{0U};
  std::array<char, 65U> boot_id{};
  std::uint64_t start_utc_ms{0U};
  std::uint64_t end_utc_ms{0U};
  std::uint64_t start_monotonic_ms{0U};
  std::uint64_t end_monotonic_ms{0U};
  bool time_trusted{false};
  std::uint32_t sample_count{0U};
  std::uint32_t valid_sample_count{0U};
  float avg_voltage_v{0.0F};
  float min_voltage_v{0.0F};
  float max_voltage_v{0.0F};
  float avg_current_a{0.0F};
  float min_current_a{0.0F};
  float max_current_a{0.0F};
  float avg_active_power_w{0.0F};
  float min_active_power_w{0.0F};
  float max_active_power_w{0.0F};
  float avg_power_factor{0.0F};
  float avg_frequency_hz{0.0F};
  std::uint64_t raw_energy_start_wh{0U};
  std::uint64_t raw_energy_end_wh{0U};
  std::uint64_t device_lifetime_energy_wh{0U};
  double interval_energy_wh{0.0};
  std::array<char, 33U> energy_method{};
  float ct_rating_a{100.0F};
  std::uint32_t quality_flags{QualityNone};
  std::array<char, 33U> firmware_version{};

  bool assign(const IntervalRecord &source) {
    const bool text_ok = copyStorageText(device_id, source.device_id) &&
                         copyStorageText(friendly_name, source.friendly_name) &&
                         copyStorageText(boot_id, source.boot_id) &&
                         copyStorageText(energy_method, source.energy_method) &&
                         copyStorageText(firmware_version,
                                         source.firmware_version);
    if (!text_ok) {
      return false;
    }
    schema_version = source.schema_version;
    data_generation = source.data_generation;
    sequence = source.sequence;
    start_utc_ms = source.start_utc_ms;
    end_utc_ms = source.end_utc_ms;
    start_monotonic_ms = source.start_monotonic_ms;
    end_monotonic_ms = source.end_monotonic_ms;
    time_trusted = source.time_trusted;
    sample_count = source.sample_count;
    valid_sample_count = source.valid_sample_count;
    avg_voltage_v = source.avg_voltage_v;
    min_voltage_v = source.min_voltage_v;
    max_voltage_v = source.max_voltage_v;
    avg_current_a = source.avg_current_a;
    min_current_a = source.min_current_a;
    max_current_a = source.max_current_a;
    avg_active_power_w = source.avg_active_power_w;
    min_active_power_w = source.min_active_power_w;
    max_active_power_w = source.max_active_power_w;
    avg_power_factor = source.avg_power_factor;
    avg_frequency_hz = source.avg_frequency_hz;
    raw_energy_start_wh = source.raw_energy_start_wh;
    raw_energy_end_wh = source.raw_energy_end_wh;
    device_lifetime_energy_wh = source.device_lifetime_energy_wh;
    interval_energy_wh = source.interval_energy_wh;
    ct_rating_a = source.ct_rating_a;
    quality_flags = source.quality_flags;
    return true;
  }

  void materialize(IntervalRecord &target) const {
    target.schema_version = schema_version;
    target.data_generation = data_generation;
    target.device_id.assign(device_id.data());
    target.friendly_name.assign(friendly_name.data());
    target.sequence = sequence;
    target.boot_id.assign(boot_id.data());
    target.start_utc_ms = start_utc_ms;
    target.end_utc_ms = end_utc_ms;
    target.start_monotonic_ms = start_monotonic_ms;
    target.end_monotonic_ms = end_monotonic_ms;
    target.time_trusted = time_trusted;
    target.sample_count = sample_count;
    target.valid_sample_count = valid_sample_count;
    target.avg_voltage_v = avg_voltage_v;
    target.min_voltage_v = min_voltage_v;
    target.max_voltage_v = max_voltage_v;
    target.avg_current_a = avg_current_a;
    target.min_current_a = min_current_a;
    target.max_current_a = max_current_a;
    target.avg_active_power_w = avg_active_power_w;
    target.min_active_power_w = min_active_power_w;
    target.max_active_power_w = max_active_power_w;
    target.avg_power_factor = avg_power_factor;
    target.avg_frequency_hz = avg_frequency_hz;
    target.raw_energy_start_wh = raw_energy_start_wh;
    target.raw_energy_end_wh = raw_energy_end_wh;
    target.device_lifetime_energy_wh = device_lifetime_energy_wh;
    target.interval_energy_wh = interval_energy_wh;
    target.energy_method.assign(energy_method.data());
    target.ct_rating_a = ct_rating_a;
    target.quality_flags = quality_flags;
    target.firmware_version.assign(firmware_version.data());
  }
};

struct FixedEventData {
  std::array<char, 65U> code{};
  std::array<char, 17U> severity{};
  std::array<char, 513U> detail{};
  std::array<char, 65U> boot_id{};
  std::uint64_t utc_ms{0U};
  // Unique within boot_id and assigned before the event enters the queue.
  // Reset cleanup carries this identity into its NVS journal and SD envelope
  // so byte-identical events cannot consume one another across retries.
  std::uint64_t source_event_id{0U};

  bool assign(const StringView source_code, const StringView source_severity,
              const StringView source_detail, const std::uint64_t source_utc,
              const StringView source_boot_id,
              const std::uint64_t source_identity = 0U) {
    if (!copyStorageText(code, source_code) ||
        !copyStorageText(severity, source_severity) ||
        !copyStorageText(detail, source_detail) ||
        !copyStorageText(boot_id, source_boot_id)) {
      return false;
    }
    utc_ms = source_utc;
    source_event_id = source_identity;
    return true;
  }
};

template <typename Value> struct BoundedStorageSlot {
  Value value{};
  std::atomic<bool> in_use{false};
};

struct BoundedStoragePoolMetrics {
  std::uint16_t capacity{0U};
  std::uint16_t active{0U};
  std::uint16_t peak_active{0U};
  std::uint64_t exhaustions{0U};
};

template <typename Value> class BoundedStoragePool {
public:
  using Slot = BoundedStorageSlot<Value>;

  BoundedStoragePool() = default;
  BoundedStoragePool(Slot *slots, const std::uint16_t capacity)
      : slots_(slots), capacity_(capacity) {}

  void reset(Slot *slots, const std::uint16_t capacity) {
    slots_ = slots;
    capacity_ = capacity;
    active_.store(0U, std::memory_order_release);
    peak_active_.store(0U, std::memory_order_release);
    exhaustions_.store(0U, std::memory_order_release);
  }

  std::uint16_t acquire() {
    for (std::uint16_t index = 0U; index < capacity_; ++index) {
      bool expected = false;
      if (!slots_[index].in_use.compare_exchange_strong(
              expected, true, std::memory_order_acq_rel)) {
        continue;
      }
      const std::uint16_t active = static_cast<std::uint16_t>(
          active_.fetch_add(1U, std::memory_order_acq_rel) + 1U);
      std::uint16_t peak = peak_active_.load(std::memory_order_acquire);
      while (active > peak && !peak_active_.compare_exchange_weak(
                                  peak, active, std::memory_order_acq_rel)) {
      }
      return index;
    }
    exhaustions_.fetch_add(1U, std::memory_order_relaxed);
    return kInvalidStoragePoolSlot;
  }

  Value *get(const std::uint16_t index) {
    return slots_ == nullptr || index >= capacity_ ||
                   !slots_[index].in_use.load(std::memory_order_acquire)
               ? nullptr
               : &slots_[index].value;
  }

  void release(const std::uint16_t index) {
    if (slots_ == nullptr || index >= capacity_) {
      return;
    }
    bool expected = true;
    if (slots_[index].in_use.compare_exchange_strong(
            expected, false, std::memory_order_acq_rel)) {
      active_.fetch_sub(1U, std::memory_order_acq_rel);
    }
  }

  BoundedStoragePoolMetrics metrics() const {
    return {capacity_, active_.load(std::memory_order_acquire),
            peak_active_.load(std::memory_order_acquire),
            exhaustions_.load(std::memory_order_acquire)};
  }

private:
  Slot *slots_{nullptr};
  std::uint16_t capacity_{0U};
  std::atomic<std::uint16_t> active_{0U};
  std::atomic<std::uint16_t> peak_active_{0U};
  std::atomic<std::uint64_t> exhaustions_{0U};
};

} // namespace pm
