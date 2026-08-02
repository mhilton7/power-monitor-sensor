#include "network/ClockService.h"

#include <atomic>
#include <cstdio>
#include <ctime>

#include <Preferences.h>
#include <esp_sntp.h>
#include <esp_timer.h>

#include "diagnostics/SerialLogger.h"
#include "network/ClockPolicy.h"
#include "version.h"

namespace pm {
namespace {

std::atomic<bool> sntp_completion_observed{false};

void onSntpSynchronized(struct timeval *) {
  sntp_completion_observed.store(true, std::memory_order_release);
}

} // namespace

void ClockService::begin() {
  esp_sntp_set_time_sync_notification_cb(onSntpSynchronized);
  Preferences preferences;
  if (preferences.begin("pm-clock", true)) {
    persisted_trusted_utc_ms_ = preferences.getULong64("last_utc", 0);
    last_trusted_utc_ms_.store(persisted_trusted_utc_ms_,
                               std::memory_order_release);
    preferences.end();
  }
  PM_LOG_INFO("TIME", "CLOCK_INIT", "state=untrusted persisted_utc_ms=%llu",
              static_cast<unsigned long long>(
                  last_trusted_utc_ms_.load(std::memory_order_acquire)));
}

void ClockService::update() {
  const std::time_t now = std::time(nullptr);
  // 2024-01-01. Reject build defaults and implausible pre-NTP clocks.
  const bool was_synchronized = synchronized_.load(std::memory_order_acquire);
  const std::uint64_t previous_trusted_utc_ms =
      last_trusted_utc_ms_.load(std::memory_order_acquire);
  const bool plausible = now >= 1'704'067'200;
  const bool completed =
      sntp_completion_observed.exchange(false, std::memory_order_acq_rel);
  const std::uint64_t candidate_utc_ms =
      plausible ? static_cast<std::uint64_t>(now) * 1000U : 0U;
  const std::uint64_t candidate_monotonic_ms = monotonicMs();
  const auto disposition =
      clock_policy::classifyCandidate(candidate_utc_ms, previous_trusted_utc_ms,
                                      version::BUILD_UNIX_SECONDS * 1000ULL);
  bool candidate_accepted = completed && plausible;
  bool step_confirmed = false;
  if (completed &&
      disposition == clock_policy::CandidateDisposition::RejectImplausible) {
    candidate_accepted = false;
    sntp_confirmed_ = false;
    PM_LOG_ERROR("TIME", "NTP_CANDIDATE_REJECTED",
                 "error=PM-TIME-004 candidate_utc_ms=%llu minimum_utc_ms=%llu "
                 "maximum_utc_ms=%llu trust_state=revoked",
                 static_cast<unsigned long long>(candidate_utc_ms),
                 static_cast<unsigned long long>(clock_policy::kMinimumUtcMs),
                 static_cast<unsigned long long>(clock_policy::kMaximumUtcMs));
  } else if (completed &&
             disposition ==
                 clock_policy::CandidateDisposition::RequireConfirmation) {
    if (clock_policy::candidatesConsistent(
            pending_candidate_utc_ms_, pending_candidate_monotonic_ms_,
            candidate_utc_ms, candidate_monotonic_ms)) {
      ++pending_candidate_count_;
    } else {
      pending_candidate_count_ = 1U;
    }
    pending_candidate_utc_ms_ = candidate_utc_ms;
    pending_candidate_monotonic_ms_ = candidate_monotonic_ms;
    step_confirmed =
        pending_candidate_count_ >= clock_policy::kRequiredConsistentSamples;
    candidate_accepted = step_confirmed;
    if (!step_confirmed) {
      sntp_confirmed_ = false;
      PM_LOG_WARN(
          "TIME", "NTP_STEP_PENDING_CONFIRMATION",
          "error=PM-TIME-003 candidate_utc_ms=%llu "
          "previous_trusted_utc_ms=%llu consistent_samples=%u required=%u "
          "trust_state=revoked",
          static_cast<unsigned long long>(candidate_utc_ms),
          static_cast<unsigned long long>(previous_trusted_utc_ms),
          static_cast<unsigned>(pending_candidate_count_),
          static_cast<unsigned>(clock_policy::kRequiredConsistentSamples));
    }
  }
  if (candidate_accepted) {
    sntp_confirmed_ = true;
    last_sync_monotonic_ms_ = candidate_monotonic_ms;
    ++sync_count_;
    const char *server = esp_sntp_getservername(0);
    PM_LOG_INFO(
        "TIME", "NTP_SYNC_COMPLETE",
        "source=sntp server=%s sync_count=%lu utc_ms=%llu monotonic_ms=%llu "
        "large_step_confirmed=%s",
        server == nullptr ? "configured_pool" : server,
        static_cast<unsigned long>(sync_count_),
        static_cast<unsigned long long>(candidate_utc_ms),
        static_cast<unsigned long long>(last_sync_monotonic_ms_),
        step_confirmed ? "true" : "false");
    pending_candidate_utc_ms_ = 0U;
    pending_candidate_monotonic_ms_ = 0U;
    pending_candidate_count_ = 0U;
  }
  const bool synchronized = plausible && sntp_confirmed_;
  synchronized_.store(synchronized, std::memory_order_release);
  if (synchronized) {
    const std::uint64_t trusted_utc_ms =
        static_cast<std::uint64_t>(now) * 1000U;
    last_trusted_utc_ms_.store(trusted_utc_ms, std::memory_order_release);
    if (!was_synchronized) {
      PM_LOG_INFO(
          "TIME", "TIME_TRUSTED",
          "source=sntp proof=sync_callback utc_ms=%llu monotonic_ms=%llu",
          static_cast<unsigned long long>(trusted_utc_ms),
          static_cast<unsigned long long>(monotonicMs()));
    }
    if (last_persist_monotonic_ms_ == 0U ||
        monotonicMs() >= last_persist_monotonic_ms_ + 3'600'000U) {
      Preferences preferences;
      if (preferences.begin("pm-clock", false)) {
        const bool persisted =
            preferences.putULong64("last_utc", trusted_utc_ms) ==
            sizeof(trusted_utc_ms);
        preferences.end();
        if (persisted) {
          persisted_trusted_utc_ms_ = trusted_utc_ms;
        }
        PM_LOG_DEBUG("TIME", "TRUSTED_TIME_PERSISTED", "result=%s utc_ms=%llu",
                     persisted ? "success" : "failed",
                     static_cast<unsigned long long>(trusted_utc_ms));
      }
      last_persist_monotonic_ms_ = monotonicMs();
    }
  } else if (was_synchronized) {
    PM_LOG_WARN("TIME", "TIME_TRUST_LOST",
                "error=PM-TIME-001 last_trusted_utc_ms=%llu",
                static_cast<unsigned long long>(
                    last_trusted_utc_ms_.load(std::memory_order_acquire)));
  }
}

bool ClockService::synchronized() const {
  return synchronized_.load(std::memory_order_acquire);
}

std::uint64_t ClockService::utcMs() const {
  return synchronized() ? static_cast<std::uint64_t>(std::time(nullptr)) * 1000U
                        : 0;
}

std::uint64_t ClockService::monotonicMs() const {
  return static_cast<std::uint64_t>(esp_timer_get_time()) / 1000U;
}

std::string ClockService::utcIso8601() const {
  char output[80]{};
  return formatUtcIso8601(output, sizeof(output)) ? output : "";
}

bool ClockService::formatUtcIso8601(char *output,
                                    const std::size_t capacity) const {
  if (output == nullptr || capacity == 0U) {
    return false;
  }
  output[0] = '\0';
  if (!synchronized()) {
    return true;
  }
  const std::time_t now = std::time(nullptr);
  struct tm broken_down{};
  gmtime_r(&now, &broken_down);
  const int written =
      std::snprintf(output, capacity, "%04d-%02d-%02dT%02d:%02d:%02dZ",
                    broken_down.tm_year + 1900, broken_down.tm_mon + 1,
                    broken_down.tm_mday, broken_down.tm_hour,
                    broken_down.tm_min, broken_down.tm_sec);
  return written >= 0 && static_cast<std::size_t>(written) < capacity;
}

std::uint64_t ClockService::lastTrustedUtcMs() const {
  return last_trusted_utc_ms_.load(std::memory_order_acquire);
}

} // namespace pm
