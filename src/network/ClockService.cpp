#include "network/ClockService.h"

#include <cstdio>
#include <ctime>

#include <Preferences.h>
#include <esp_timer.h>

#include "diagnostics/SerialLogger.h"

namespace pm {

void ClockService::begin() {
  Preferences preferences;
  if (preferences.begin("pm-clock", true)) {
    last_trusted_utc_ms_ = preferences.getULong64("last_utc", 0);
    preferences.end();
  }
  PM_LOG_INFO("TIME", "CLOCK_INIT",
              "state=untrusted persisted_utc_ms=%llu",
              static_cast<unsigned long long>(last_trusted_utc_ms_));
}

void ClockService::update() {
  const std::time_t now = std::time(nullptr);
  // 2024-01-01. Reject build defaults and implausible pre-NTP clocks.
  const bool was_synchronized = synchronized_;
  synchronized_ = now >= 1'704'067'200;
  if (synchronized_) {
    last_trusted_utc_ms_ = static_cast<std::uint64_t>(now) * 1000U;
    if (!was_synchronized) {
      PM_LOG_INFO(
          "TIME", "TIME_TRUSTED",
          "source=sntp utc_ms=%llu monotonic_ms=%llu",
          static_cast<unsigned long long>(last_trusted_utc_ms_),
          static_cast<unsigned long long>(monotonicMs()));
    }
    if (monotonicMs() - last_persist_monotonic_ms_ >= 3'600'000U) {
      Preferences preferences;
      if (preferences.begin("pm-clock", false)) {
        const bool persisted =
            preferences.putULong64("last_utc", last_trusted_utc_ms_) ==
            sizeof(last_trusted_utc_ms_);
        preferences.end();
        PM_LOG_DEBUG("TIME", "TRUSTED_TIME_PERSISTED",
                     "result=%s utc_ms=%llu",
                     persisted ? "success" : "failed",
                     static_cast<unsigned long long>(last_trusted_utc_ms_));
      }
      last_persist_monotonic_ms_ = monotonicMs();
    }
  } else if (was_synchronized) {
    PM_LOG_WARN("TIME", "TIME_TRUST_LOST",
                "error=PM-TIME-001 last_trusted_utc_ms=%llu",
                static_cast<unsigned long long>(last_trusted_utc_ms_));
  }
}

bool ClockService::synchronized() const { return synchronized_; }

std::uint64_t ClockService::utcMs() const {
  return synchronized_ ? static_cast<std::uint64_t>(std::time(nullptr)) * 1000U : 0;
}

std::uint64_t ClockService::monotonicMs() const {
  return static_cast<std::uint64_t>(esp_timer_get_time()) / 1000U;
}

std::string ClockService::utcIso8601() const {
  if (!synchronized_) {
    return "";
  }
  const std::time_t now = std::time(nullptr);
  struct tm broken_down {};
  gmtime_r(&now, &broken_down);
  char output[80]{};
  std::snprintf(output, sizeof(output), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                broken_down.tm_year + 1900, broken_down.tm_mon + 1,
                broken_down.tm_mday, broken_down.tm_hour, broken_down.tm_min,
                broken_down.tm_sec);
  return output;
}

std::uint64_t ClockService::lastTrustedUtcMs() const {
  return last_trusted_utc_ms_;
}

}  // namespace pm
