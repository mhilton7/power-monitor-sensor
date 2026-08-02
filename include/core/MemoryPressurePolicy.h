#pragma once

#include <cstdint>

namespace pm {

enum class MemoryPressureState : std::uint8_t {
  Normal,
  PressureWarning,
  Fragmented,
  LowTotalMemory,
  Recovering,
};

inline const char *memoryPressureStateName(const MemoryPressureState state) {
  switch (state) {
  case MemoryPressureState::Normal:
    return "normal";
  case MemoryPressureState::PressureWarning:
    return "pressure_warning";
  case MemoryPressureState::Fragmented:
    return "fragmented";
  case MemoryPressureState::LowTotalMemory:
    return "low_total_memory";
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
  std::uint32_t fragmentation_entry_count{0};
  std::uint32_t fragmentation_recovery_count{0};
  std::uint64_t current_fragmentation_episode_ms{0};
  std::uint64_t longest_fragmentation_episode_ms{0};
  std::uint32_t free_internal_at_fragmentation_entry_bytes{0};
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
    const bool fragmented = free_internal >= 64U * 1024U &&
                            largest_internal < 32U * 1024U;
    const bool low_total = free_internal < 64U * 1024U;
    const bool critical_total = free_internal < 56U * 1024U;
    const bool recovered = free_internal >= 84U * 1024U &&
                           largest_internal >= 36U * 1024U;

    updateFragmentationEpisode(fragmented, free_internal, now_ms);

    low_samples_ = low_total
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
      if (critical_total || low_samples_ >= 3U) {
        transition(MemoryPressureState::LowTotalMemory, now_ms);
      } else if (fragmented) {
        transition(MemoryPressureState::Fragmented, now_ms);
      } else if (warning) {
        transition(MemoryPressureState::PressureWarning, now_ms);
      }
      break;
    case MemoryPressureState::PressureWarning:
      if (critical_total || low_samples_ >= 3U) {
        transition(MemoryPressureState::LowTotalMemory, now_ms);
      } else if (fragmented) {
        transition(MemoryPressureState::Fragmented, now_ms);
      } else if (!warning && recovered_samples_ >= 5U) {
        transition(MemoryPressureState::Normal, now_ms);
      }
      break;
    case MemoryPressureState::Fragmented:
      if (critical_total || low_samples_ >= 3U) {
        transition(MemoryPressureState::LowTotalMemory, now_ms);
      } else if (recovered_samples_ >= 10U &&
                 now_ms - state_since_ms_ >= 30'000U) {
        transition(MemoryPressureState::Recovering, now_ms);
      }
      break;
    case MemoryPressureState::LowTotalMemory:
      if (recovered_samples_ >= 10U && now_ms - state_since_ms_ >= 30'000U) {
        transition(MemoryPressureState::Recovering, now_ms);
      } else if (!low_total && fragmented) {
        transition(MemoryPressureState::Fragmented, now_ms);
      }
      break;
    case MemoryPressureState::Recovering:
      if (critical_total || low_samples_ >= 3U) {
        transition(MemoryPressureState::LowTotalMemory, now_ms);
      } else if (fragmented) {
        transition(MemoryPressureState::Fragmented, now_ms);
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
    const std::uint64_t current_fragmentation =
        fragmentation_episode_started_ms_ != 0U &&
                now_ms >= fragmentation_episode_started_ms_
            ? now_ms - fragmentation_episode_started_ms_
            : 0U;
    const std::uint64_t longest_fragmentation =
        current_fragmentation > longest_fragmentation_episode_ms_
            ? current_fragmentation
            : longest_fragmentation_episode_ms_;
    return {state_,
            state_since_ms_,
            cumulative,
            longest,
            entry_count_,
            recovery_count_,
            transitions_,
            lowest_free_internal_bytes_,
            lowest_largest_internal_block_bytes_,
            fragmentation_entry_count_,
            fragmentation_recovery_count_,
            current_fragmentation,
            longest_fragmentation,
            free_internal_at_fragmentation_entry_bytes_};
  }

private:
  void updateFragmentationEpisode(const bool fragmented,
                                  const std::uint32_t free_internal,
                                  const std::uint64_t now_ms) {
    if (fragmented && fragmentation_episode_started_ms_ == 0U) {
      fragmentation_episode_started_ms_ = now_ms == 0U ? 1U : now_ms;
      free_internal_at_fragmentation_entry_bytes_ = free_internal;
      ++fragmentation_entry_count_;
      return;
    }
    if (!fragmented && fragmentation_episode_started_ms_ != 0U) {
      const std::uint64_t duration =
          now_ms >= fragmentation_episode_started_ms_
              ? now_ms - fragmentation_episode_started_ms_
              : 0U;
      if (duration > longest_fragmentation_episode_ms_) {
        longest_fragmentation_episode_ms_ = duration;
      }
      fragmentation_episode_started_ms_ = 0U;
      ++fragmentation_recovery_count_;
    }
  }

  void transition(const MemoryPressureState next, const std::uint64_t now_ms) {
    if (next == state_) {
      return;
    }
    const MemoryPressureState previous = state_;
    if (previous == MemoryPressureState::Normal &&
        next != MemoryPressureState::Normal) {
      pressure_episode_started_ms_ = now_ms;
    }
    if (next == MemoryPressureState::LowTotalMemory &&
        previous != MemoryPressureState::LowTotalMemory) {
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
  std::uint32_t fragmentation_entry_count_{0};
  std::uint32_t fragmentation_recovery_count_{0};
  std::uint64_t fragmentation_episode_started_ms_{0};
  std::uint64_t longest_fragmentation_episode_ms_{0};
  std::uint32_t free_internal_at_fragmentation_entry_bytes_{0};
  std::uint8_t low_samples_{0};
  std::uint8_t recovered_samples_{0};
};

} // namespace pm
