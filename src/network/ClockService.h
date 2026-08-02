#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

namespace pm {

class ClockService {
public:
  void begin();
  void update();
  [[nodiscard]] bool synchronized() const;
  [[nodiscard]] std::uint64_t utcMs() const;
  [[nodiscard]] std::uint64_t monotonicMs() const;
  [[nodiscard]] std::string utcIso8601() const;
  [[nodiscard]] bool formatUtcIso8601(char *output,
                                      std::size_t capacity) const;
  [[nodiscard]] std::uint64_t lastTrustedUtcMs() const;

private:
  std::atomic<bool> synchronized_{false};
  bool sntp_confirmed_{false};
  std::atomic<std::uint64_t> last_trusted_utc_ms_{0};
  std::uint64_t persisted_trusted_utc_ms_{0};
  std::uint64_t last_sync_monotonic_ms_{0};
  std::uint64_t last_persist_monotonic_ms_{0};
  std::uint64_t pending_candidate_utc_ms_{0};
  std::uint64_t pending_candidate_monotonic_ms_{0};
  std::uint32_t sync_count_{0};
  std::uint8_t pending_candidate_count_{0};
};

} // namespace pm
