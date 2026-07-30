#pragma once

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <string>

namespace pm {
namespace auth_policy {

inline bool parseTimestamp(const std::string &value, std::int64_t &parsed) {
  if (value.empty())
    return false;
  errno = 0;
  char *end = nullptr;
  const long long candidate = std::strtoll(value.c_str(), &end, 10);
  if (errno == ERANGE || end == value.c_str() || *end != '\0')
    return false;
  parsed = static_cast<std::int64_t>(candidate);
  return true;
}

inline bool timestampWithinWindow(const std::int64_t timestamp,
                                  const std::int64_t now,
                                  const std::uint32_t window_seconds) {
  const std::int64_t window = static_cast<std::int64_t>(window_seconds);
  const std::int64_t minimum =
      now < std::numeric_limits<std::int64_t>::min() + window
          ? std::numeric_limits<std::int64_t>::min()
          : now - window;
  const std::int64_t maximum =
      now > std::numeric_limits<std::int64_t>::max() - window
          ? std::numeric_limits<std::int64_t>::max()
          : now + window;
  return timestamp >= minimum && timestamp <= maximum;
}

} // namespace auth_policy
} // namespace pm
