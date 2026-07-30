#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace pm {
namespace diag {

enum class LogLevel : std::uint8_t {
  Trace = 0,
  Debug = 1,
  Info = 2,
  Warn = 3,
  Error = 4,
  Fatal = 5,
};

struct ReasonInfo {
  const char *name;
  const char *explanation;
  const char *hint;
  const char *error_code;
};

struct ErrorRecord {
  std::uint64_t monotonic_ms{0};
  LogLevel level{LogLevel::Warn};
  std::int32_t numeric_code{0};
  std::array<char, 16> subsystem{};
  std::array<char, 40> event{};
  std::array<char, 160> detail{};
};

const char *levelName(LogLevel level);
bool parseLogLevel(const char *value, LogLevel &level);
bool shouldLog(LogLevel configured_level, LogLevel message_level);
bool sensitiveKey(const char *key);
void redactSensitiveAssignments(const char *input, char *output,
                                std::size_t output_size);
std::string maskSsid(const std::string &value);
std::string maskIdentifier(const std::string &value);
std::string maskMac(const std::string &value);
ReasonInfo wifiDisconnectReason(std::uint16_t reason);
const char *wifiStatusName(int status);
const char *resetReasonName(int reason);
const char *wakeupReasonName(int reason);
const char *tlsErrorCategory(const char *error);
const char *httpStatusCategory(int status);
std::size_t formatLine(char *output, std::size_t output_size,
                       std::uint64_t monotonic_ms, LogLevel level,
                       const char *subsystem, const char *event,
                       const char *detail);

template <std::size_t Capacity> class ErrorRing {
public:
  void push(const ErrorRecord &value) {
    records_[next_] = value;
    next_ = (next_ + 1U) % Capacity;
    if (size_ < Capacity)
      ++size_;
  }

  std::size_t size() const { return size_; }

  ErrorRecord at(const std::size_t index) const {
    if (index >= size_)
      return {};
    const std::size_t oldest = size_ == Capacity ? next_ : 0U;
    return records_[(oldest + index) % Capacity];
  }

private:
  std::array<ErrorRecord, Capacity> records_{};
  std::size_t next_{0};
  std::size_t size_{0};
};

class RateLimiter {
public:
  bool allow(const char *key, std::uint64_t now_ms, std::uint32_t interval_ms);

private:
  struct Slot {
    std::array<char, 40> key{};
    std::uint64_t next_allowed_ms{0};
    bool used{false};
  };
  std::array<Slot, 16> slots_{};
};

} // namespace diag
} // namespace pm
