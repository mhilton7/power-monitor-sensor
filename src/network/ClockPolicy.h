#pragma once

#include <cstdint>

namespace pm {
namespace clock_policy {

enum class CandidateDisposition : std::uint8_t {
  Accept,
  RequireConfirmation,
  RejectImplausible,
};

constexpr std::uint64_t kMinimumUtcMs = 1'704'067'200'000ULL; // 2024-01-01
constexpr std::uint64_t kMaximumUtcMs = 4'102'444'800'000ULL; // 2100-01-01
constexpr std::uint64_t kRollbackToleranceMs = 300'000ULL;
constexpr std::uint64_t kMaximumAnchoredForwardStepMs =
    45ULL * 24ULL * 60ULL * 60ULL * 1000ULL;
constexpr std::uint64_t kMaximumInitialBuildAdvanceMs =
    400ULL * 24ULL * 60ULL * 60ULL * 1000ULL;
constexpr std::uint64_t kMaximumInitialBuildRollbackMs =
    30ULL * 24ULL * 60ULL * 60ULL * 1000ULL;
constexpr std::uint64_t kCandidateConsistencyToleranceMs = 300'000ULL;
constexpr std::uint8_t kRequiredConsistentSamples = 3U;

inline bool exceeds(const std::uint64_t newer, const std::uint64_t older,
                    const std::uint64_t allowance) {
  return newer > older && newer - older > allowance;
}

inline CandidateDisposition
classifyCandidate(const std::uint64_t candidate_utc_ms,
                  const std::uint64_t previous_trusted_utc_ms,
                  const std::uint64_t build_utc_ms) {
  if (candidate_utc_ms < kMinimumUtcMs || candidate_utc_ms > kMaximumUtcMs) {
    return CandidateDisposition::RejectImplausible;
  }

  if (previous_trusted_utc_ms != 0U) {
    if (exceeds(previous_trusted_utc_ms, candidate_utc_ms,
                kRollbackToleranceMs) ||
        exceeds(candidate_utc_ms, previous_trusted_utc_ms,
                kMaximumAnchoredForwardStepMs)) {
      return CandidateDisposition::RequireConfirmation;
    }
    return CandidateDisposition::Accept;
  }

  if (build_utc_ms != 0U && (exceeds(build_utc_ms, candidate_utc_ms,
                                     kMaximumInitialBuildRollbackMs) ||
                             exceeds(candidate_utc_ms, build_utc_ms,
                                     kMaximumInitialBuildAdvanceMs))) {
    return CandidateDisposition::RequireConfirmation;
  }
  return CandidateDisposition::Accept;
}

inline bool
candidatesConsistent(const std::uint64_t previous_candidate_utc_ms,
                     const std::uint64_t previous_candidate_monotonic_ms,
                     const std::uint64_t candidate_utc_ms,
                     const std::uint64_t candidate_monotonic_ms) {
  if (previous_candidate_utc_ms == 0U ||
      candidate_monotonic_ms < previous_candidate_monotonic_ms ||
      candidate_utc_ms < previous_candidate_utc_ms) {
    return false;
  }
  const std::uint64_t utc_elapsed =
      candidate_utc_ms - previous_candidate_utc_ms;
  const std::uint64_t monotonic_elapsed =
      candidate_monotonic_ms - previous_candidate_monotonic_ms;
  const std::uint64_t difference = utc_elapsed > monotonic_elapsed
                                       ? utc_elapsed - monotonic_elapsed
                                       : monotonic_elapsed - utc_elapsed;
  return difference <= kCandidateConsistencyToleranceMs;
}

} // namespace clock_policy
} // namespace pm
