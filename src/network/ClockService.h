#pragma once

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
  [[nodiscard]] std::uint64_t lastTrustedUtcMs() const;

 private:
  bool synchronized_{false};
  std::uint64_t last_trusted_utc_ms_{0};
  std::uint64_t last_persist_monotonic_ms_{0};
};

}  // namespace pm

