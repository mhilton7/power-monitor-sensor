#pragma once

#include <cstdint>

namespace pm {

enum class MemoryPressureState : std::uint8_t {
  Normal,
  PressureWarning,
  LowMemory,
  Recovering,
};

inline const char *memoryPressureStateName(const MemoryPressureState state) {
  switch (state) {
  case MemoryPressureState::Normal:
    return "normal";
  case MemoryPressureState::PressureWarning:
    return "pressure_warning";
  case MemoryPressureState::LowMemory:
    return "low_memory";
  case MemoryPressureState::Recovering:
    return "recovering";
  }
  return "unknown";
}

struct MemoryPressureUpdate {
  MemoryPressureState previous{MemoryPressureState::Normal};
  MemoryPressureState current{MemoryPressureState::Normal};
  bool changed{false};
};

struct MemoryPressureMetrics {
  MemoryPressureState state{MemoryPressureState::Normal};
  std::uint64_t state_since_ms{0};
  std::uint64_t cumulative_pressure_ms{0};
  std::uint64_t longest_pressure_episode_ms{0};
  std::uint32_t entry_count{0};
  std::uint32_t recovery_count{0};
  std::uint32_t transition_count{0};
  std::uint32_t lowest_free_internal_bytes{0};
  std::uint32_t lowest_largest_internal_block_bytes{0};
};

// Bounded, allocation-free hysteresis for internal DMA-capable heap pressure.
// The one-second caller cadence is intentional: transient TLS allocations do
// not immediately toggle global UI/synchronization policy.
class MemoryPressurePolicy {
public:
  MemoryPressureUpdate update(const std::uint32_t free_internal,
                              const std::uint32_t largest_internal,
                              const std::uint64_t now_ms) {
    lowest_free_internal_bytes_ =
        lowest_free_internal_bytes_ == 0U
            ? free_internal
            : (free_internal < lowest_free_internal_bytes_
                   ? free_internal
                   : lowest_free_internal_bytes_);
    lowest_largest_internal_block_bytes_ =
        lowest_largest_internal_block_bytes_ == 0U
            ? largest_internal
            : (largest_internal < lowest_largest_internal_block_bytes_
                   ? largest_internal
                   : lowest_largest_internal_block_bytes_);
    const MemoryPressureState previous = state_;
    const bool warning = free_internal < 80U * 1024U ||
                         largest_internal < 32U * 1024U;
    const bool low = free_internal < 72U * 1024U ||
                     largest_internal < 28U * 1024U;
    const bool critical = free_internal < 56U * 1024U ||
                          largest_internal < 20U * 1024U;
    const bool recovered = free_internal >= 84U * 1024U &&
                           largest_internal >= 36U * 1024U;

    low_samples_ = low
                       ? (low_samples_ < 255U
                              ? static_cast<std::uint8_t>(low_samples_ + 1U)
                              : low_samples_)
                       : 0U;
    recovered_samples_ =
        recovered
            ? (recovered_samples_ < 255U
                   ? static_cast<std::uint8_t>(recovered_samples_ + 1U)
                   : recovered_samples_)
            : 0U;

    switch (state_) {
    case MemoryPressureState::Normal:
      if (critical || low_samples_ >= 3U) {
        transition(MemoryPressureState::LowMemory, now_ms);
      } else if (warning) {
        transition(MemoryPressureState::PressureWarning, now_ms);
      }
      break;
    case MemoryPressureState::PressureWarning:
      if (critical || low_samples_ >= 3U) {
        transition(MemoryPressureState::LowMemory, now_ms);
      } else if (!warning && recovered_samples_ >= 5U) {
        transition(MemoryPressureState::Normal, now_ms);
      }
      break;
    case MemoryPressureState::LowMemory:
      if (recovered_samples_ >= 10U && now_ms - state_since_ms_ >= 30'000U) {
        transition(MemoryPressureState::Recovering, now_ms);
      }
      break;
    case MemoryPressureState::Recovering:
      if (critical || low_samples_ >= 3U) {
        transition(MemoryPressureState::LowMemory, now_ms);
      } else if (recovered && now_ms - state_since_ms_ >= 30'000U) {
        transition(MemoryPressureState::Normal, now_ms);
      }
      break;
    }
    return {previous, state_, previous != state_};
  }

  MemoryPressureState state() const { return state_; }
  std::uint64_t stateSinceMs() const { return state_since_ms_; }
  std::uint32_t transitions() const { return transitions_; }

  MemoryPressureMetrics metrics(const std::uint64_t now_ms) const {
    std::uint64_t cumulative = cumulative_pressure_ms_;
    std::uint64_t longest = longest_pressure_episode_ms_;
    if (pressure_episode_started_ms_ != 0U &&
        now_ms >= pressure_episode_started_ms_) {
      const std::uint64_t active = now_ms - pressure_episode_started_ms_;
      cumulative += active;
      if (active > longest) {
        longest = active;
      }
    }
    return {state_,
            state_since_ms_,
            cumulative,
            longest,
            entry_count_,
            recovery_count_,
            transitions_,
            lowest_free_internal_bytes_,
            lowest_largest_internal_block_bytes_};
  }

private:
  void transition(const MemoryPressureState next, const std::uint64_t now_ms) {
    if (next == state_) {
      return;
    }
    const MemoryPressureState previous = state_;
    if (previous == MemoryPressureState::Normal &&
        next != MemoryPressureState::Normal) {
      pressure_episode_started_ms_ = now_ms;
    }
    if (next == MemoryPressureState::LowMemory &&
        previous != MemoryPressureState::LowMemory) {
      ++entry_count_;
    }
    if (next == MemoryPressureState::Normal &&
        previous != MemoryPressureState::Normal) {
      if (pressure_episode_started_ms_ != 0U &&
          now_ms >= pressure_episode_started_ms_) {
        const std::uint64_t duration = now_ms - pressure_episode_started_ms_;
        cumulative_pressure_ms_ += duration;
        if (duration > longest_pressure_episode_ms_) {
          longest_pressure_episode_ms_ = duration;
        }
      }
      pressure_episode_started_ms_ = 0U;
      ++recovery_count_;
    }
    state_ = next;
    state_since_ms_ = now_ms;
    ++transitions_;
    low_samples_ = 0U;
    recovered_samples_ = 0U;
  }

  MemoryPressureState state_{MemoryPressureState::Normal};
  std::uint64_t state_since_ms_{0};
  std::uint32_t transitions_{0};
  std::uint32_t entry_count_{0};
  std::uint32_t recovery_count_{0};
  std::uint64_t pressure_episode_started_ms_{0};
  std::uint64_t cumulative_pressure_ms_{0};
  std::uint64_t longest_pressure_episode_ms_{0};
  std::uint32_t lowest_free_internal_bytes_{0};
  std::uint32_t lowest_largest_internal_block_bytes_{0};
  std::uint8_t low_samples_{0};
  std::uint8_t recovered_samples_{0};
};

} // namespace pm
