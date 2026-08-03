#pragma once

#include <cstdint>

namespace pm {

enum class MemoryOperationContext : std::uint8_t {
  Idle,
  TlsPreparing,
  TlsActive,
  OtaActive,
  HeavyLocalUi,
  DiagnosticsActive,
  StorageMaintenance,
};

inline const char *memoryOperationContextName(
    const MemoryOperationContext context) {
  switch (context) {
  case MemoryOperationContext::Idle:
    return "idle";
  case MemoryOperationContext::TlsPreparing:
    return "tls_preparing";
  case MemoryOperationContext::TlsActive:
    return "tls_active";
  case MemoryOperationContext::OtaActive:
    return "ota_active";
  case MemoryOperationContext::HeavyLocalUi:
    return "heavy_local_ui";
  case MemoryOperationContext::DiagnosticsActive:
    return "diagnostics_active";
  case MemoryOperationContext::StorageMaintenance:
    return "storage_maintenance";
  }
  return "idle";
}

inline bool isExpectedHighMemoryContext(const MemoryOperationContext context) {
  return context == MemoryOperationContext::TlsPreparing ||
         context == MemoryOperationContext::TlsActive ||
         context == MemoryOperationContext::OtaActive;
}

inline bool memoryOperationTransitionAllowed(
    const MemoryOperationContext current,
    const MemoryOperationContext next) {
  return current == MemoryOperationContext::TlsPreparing &&
         next == MemoryOperationContext::TlsActive;
}

inline bool requiresPostOperationMemoryGrace(
    const MemoryOperationContext context) {
  return context == MemoryOperationContext::TlsActive ||
         context == MemoryOperationContext::OtaActive;
}

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

inline const char *memoryPressureSeverityName(
    const MemoryPressureState state) {
  switch (state) {
  case MemoryPressureState::Normal:
    return "normal";
  case MemoryPressureState::LowTotalMemory:
    return "critical";
  case MemoryPressureState::PressureWarning:
  case MemoryPressureState::Fragmented:
  case MemoryPressureState::Recovering:
    return "warning";
  }
  return "warning";
}

inline bool memoryPressureIsLowMemory(const MemoryPressureState state) {
  return state == MemoryPressureState::LowTotalMemory;
}

constexpr std::uint32_t kMemoryNormalFreeInternalBytes = 68U * 1024U;
constexpr std::uint32_t kMemoryNormalLargestInternalBlockBytes =
    32U * 1024U;
constexpr std::uint32_t kMemoryFragmentationFreeInternalBytes =
    64U * 1024U;
constexpr std::uint32_t kMemoryLowTotalBytes = 56U * 1024U;
constexpr std::uint32_t kMemoryEmergencyFreeInternalBytes =
    32U * 1024U;
constexpr std::uint32_t kTlsMinimumFreeInternalBytes = 64U * 1024U;
constexpr std::uint32_t kTlsMinimumLargestInternalBlockBytes =
    32U * 1024U;
constexpr std::uint64_t kMemoryPostOperationGraceMs = 3'000U;
constexpr std::uint8_t kMemoryLowSamplesRequired = 3U;
constexpr std::uint8_t kMemorySafeSamplesRequired = 3U;

inline bool memoryTlsReady(const std::uint32_t free_internal,
                           const std::uint32_t largest_internal,
                           const bool integrity_ok = true) {
  return integrity_ok && free_internal >= kTlsMinimumFreeInternalBytes &&
         largest_internal >= kTlsMinimumLargestInternalBlockBytes;
}

struct MemoryPressureUpdate {
  MemoryPressureState previous{MemoryPressureState::Normal};
  MemoryPressureState current{MemoryPressureState::Normal};
  bool changed{false};
};

struct MemoryPressureMetrics {
  MemoryPressureState state{MemoryPressureState::Normal};
  MemoryOperationContext operation_context{MemoryOperationContext::Idle};
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
  std::uint32_t tls_transient_minimum_free_internal_bytes{0};
  std::uint32_t ota_transient_minimum_free_internal_bytes{0};
  bool tls_ready{false};
  bool heap_integrity_ok{true};
};

// Allocation-free, one-second-cadence policy for internal DMA-capable heap.
// Expected TLS/OTA dips are recorded as transient evidence and are classified
// only after the operation has released its objects and a bounded grace has
// elapsed. Genuine emergencies remain immediate in every operation context.
class MemoryPressurePolicy {
public:
  MemoryPressureUpdate update(
      const std::uint32_t free_internal,
      const std::uint32_t largest_internal, const std::uint64_t now_ms,
      const MemoryOperationContext context = MemoryOperationContext::Idle,
      const bool integrity_ok = true,
      const std::uint64_t last_operation_completed_ms = 0U,
      const bool critical_allocation_failed = false) {
    operation_context_ = context;
    heap_integrity_ok_ = integrity_ok;
    tls_ready_ = memoryTlsReady(free_internal, largest_internal, integrity_ok);
    recordMinimum(lowest_free_internal_bytes_, free_internal);
    recordMinimum(lowest_largest_internal_block_bytes_, largest_internal);

    const MemoryPressureState previous = state_;
    const bool emergency = !integrity_ok || critical_allocation_failed ||
                           free_internal <
                               kMemoryEmergencyFreeInternalBytes;
    if (emergency) {
      updateFragmentationEpisode(false, free_internal, now_ms);
      transition(MemoryPressureState::LowTotalMemory, now_ms);
      return {previous, state_, previous != state_};
    }

    if (isExpectedHighMemoryContext(context)) {
      if (context == MemoryOperationContext::OtaActive) {
        recordMinimum(ota_transient_minimum_free_internal_bytes_,
                      free_internal);
      } else {
        recordMinimum(tls_transient_minimum_free_internal_bytes_,
                      free_internal);
      }
      low_samples_ = 0U;
      safe_samples_ = 0U;
      return {previous, state_, false};
    }

    const bool in_post_operation_grace =
        last_operation_completed_ms != 0U &&
        now_ms >= last_operation_completed_ms &&
        now_ms - last_operation_completed_ms < kMemoryPostOperationGraceMs;
    if (in_post_operation_grace) {
      low_samples_ = 0U;
      safe_samples_ = 0U;
      return {previous, state_, false};
    }

    const bool fragmented =
        free_internal >= kMemoryFragmentationFreeInternalBytes &&
        largest_internal < kMemoryNormalLargestInternalBlockBytes;
    const bool low_total = free_internal < kMemoryLowTotalBytes;
    const bool safe = free_internal >= kMemoryNormalFreeInternalBytes &&
                      largest_internal >=
                          kMemoryNormalLargestInternalBlockBytes;
    updateFragmentationEpisode(fragmented, free_internal, now_ms);

    low_samples_ = low_total ? increment(low_samples_) : 0U;
    safe_samples_ = safe ? increment(safe_samples_) : 0U;

    if (low_total) {
      if (state_ == MemoryPressureState::LowTotalMemory ||
          low_samples_ >= kMemoryLowSamplesRequired) {
        transition(MemoryPressureState::LowTotalMemory, now_ms);
      } else {
        transition(MemoryPressureState::PressureWarning, now_ms);
      }
    } else if (fragmented) {
      if (state_ != MemoryPressureState::LowTotalMemory) {
        transition(MemoryPressureState::Fragmented, now_ms);
      }
    } else if (safe) {
      switch (state_) {
      case MemoryPressureState::Normal:
        break;
      case MemoryPressureState::PressureWarning:
        if (safe_samples_ >= kMemorySafeSamplesRequired) {
          transition(MemoryPressureState::Normal, now_ms);
        }
        break;
      case MemoryPressureState::Fragmented:
      case MemoryPressureState::LowTotalMemory:
        if (safe_samples_ >= kMemorySafeSamplesRequired) {
          transition(MemoryPressureState::Recovering, now_ms);
        }
        break;
      case MemoryPressureState::Recovering:
        if (safe_samples_ >= kMemorySafeSamplesRequired) {
          transition(MemoryPressureState::Normal, now_ms);
        }
        break;
      }
    } else if (state_ != MemoryPressureState::LowTotalMemory) {
      transition(MemoryPressureState::PressureWarning, now_ms);
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
            operation_context_,
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
            free_internal_at_fragmentation_entry_bytes_,
            tls_transient_minimum_free_internal_bytes_,
            ota_transient_minimum_free_internal_bytes_,
            tls_ready_,
            heap_integrity_ok_};
  }

private:
  static std::uint8_t increment(const std::uint8_t value) {
    return value == 255U ? value : static_cast<std::uint8_t>(value + 1U);
  }

  static void recordMinimum(std::uint32_t &minimum,
                            const std::uint32_t value) {
    minimum = minimum == 0U || value < minimum ? value : minimum;
  }

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
      pressure_episode_started_ms_ = now_ms == 0U ? 1U : now_ms;
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
    if (next == MemoryPressureState::LowTotalMemory) {
      low_samples_ = 0U;
    }
    if (next == MemoryPressureState::Recovering ||
        next == MemoryPressureState::Normal) {
      safe_samples_ = 0U;
    }
  }

  MemoryPressureState state_{MemoryPressureState::Normal};
  MemoryOperationContext operation_context_{MemoryOperationContext::Idle};
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
  std::uint32_t tls_transient_minimum_free_internal_bytes_{0};
  std::uint32_t ota_transient_minimum_free_internal_bytes_{0};
  std::uint8_t low_samples_{0};
  std::uint8_t safe_samples_{0};
  bool tls_ready_{false};
  bool heap_integrity_ok_{true};
};

} // namespace pm
