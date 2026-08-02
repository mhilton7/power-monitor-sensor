#pragma once

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace pm {

struct BoundedTextView {
  BoundedTextView() = default;
  BoundedTextView(const char *value)
      : data(value == nullptr ? "" : value),
        size(value == nullptr ? 0U : std::strlen(value)) {}
  BoundedTextView(const char *value, const std::size_t length)
      : data(value == nullptr ? "" : value), size(value == nullptr ? 0U
                                                                    : length) {}

  const char *data{""};
  std::size_t size{0U};
};

class BoundedJsonWriter {
public:
  BoundedJsonWriter(char *buffer, const std::size_t capacity)
      : buffer_(buffer), capacity_(capacity) {
    terminate();
  }

  bool literal(const BoundedTextView value) {
    return append(value.data, value.size);
  }

  bool string(const BoundedTextView value) {
    if (!character('"')) {
      return false;
    }
    for (std::size_t index = 0U; index < value.size;) {
      const std::uint8_t byte = static_cast<std::uint8_t>(value.data[index]);
      switch (byte) {
      case '"':
        if (!literal("\\\""))
          return false;
        ++index;
        continue;
      case '\\':
        if (!literal("\\\\"))
          return false;
        ++index;
        continue;
      case '\b':
        if (!literal("\\b"))
          return false;
        ++index;
        continue;
      case '\f':
        if (!literal("\\f"))
          return false;
        ++index;
        continue;
      case '\n':
        if (!literal("\\n"))
          return false;
        ++index;
        continue;
      case '\r':
        if (!literal("\\r"))
          return false;
        ++index;
        continue;
      case '\t':
        if (!literal("\\t"))
          return false;
        ++index;
        continue;
      default:
        break;
      }
      if (byte < 0x20U) {
        char escaped[7]{};
        std::snprintf(escaped, sizeof(escaped), "\\u%04x",
                      static_cast<unsigned>(byte));
        if (!literal(escaped))
          return false;
        ++index;
        continue;
      }
      const std::size_t sequence = utf8SequenceLength(value, index);
      if (sequence == 0U) {
        if (!literal("\\ufffd"))
          return false;
        ++index;
        continue;
      }
      if (!append(value.data + index, sequence)) {
        return false;
      }
      index += sequence;
    }
    return character('"');
  }

  bool nullValue() { return literal("null"); }
  bool boolean(const bool value) { return literal(value ? "true" : "false"); }

  bool unsignedValue(const std::uint64_t value) {
    char digits[32]{};
    const int written = std::snprintf(
        digits, sizeof(digits), "%llu",
        static_cast<unsigned long long>(value));
    return written > 0 && static_cast<std::size_t>(written) < sizeof(digits) &&
           append(digits, static_cast<std::size_t>(written));
  }

  bool signedValue(const std::int64_t value) {
    char digits[32]{};
    const int written = std::snprintf(digits, sizeof(digits), "%lld",
                                      static_cast<long long>(value));
    return written > 0 && static_cast<std::size_t>(written) < sizeof(digits) &&
           append(digits, static_cast<std::size_t>(written));
  }

  bool number(const double value, const unsigned precision = 6U) {
    if (!std::isfinite(value) || precision > 9U) {
      return nullValue();
    }
    char digits[48]{};
    const int written =
        std::snprintf(digits, sizeof(digits), "%.*f",
                      static_cast<int>(precision), value == 0.0 ? 0.0 : value);
    return written > 0 && static_cast<std::size_t>(written) < sizeof(digits) &&
           append(digits, static_cast<std::size_t>(written));
  }

  bool ok() const { return !overflow_; }
  bool overflowed() const { return overflow_; }
  std::size_t size() const { return size_; }
  const char *data() const { return buffer_; }

private:
  bool character(const char value) { return append(&value, 1U); }

  bool append(const char *data, const std::size_t bytes) {
    if (overflow_ || buffer_ == nullptr || capacity_ == 0U ||
        bytes > capacity_ - 1U || size_ > capacity_ - 1U - bytes) {
      overflow_ = true;
      terminate();
      return false;
    }
    if (bytes != 0U) {
      std::memcpy(buffer_ + size_, data, bytes);
      size_ += bytes;
    }
    terminate();
    return true;
  }

  void terminate() {
    if (buffer_ != nullptr && capacity_ != 0U) {
      buffer_[size_ < capacity_ ? size_ : capacity_ - 1U] = '\0';
    }
  }

  static std::size_t utf8SequenceLength(const BoundedTextView value,
                                        const std::size_t index) {
    const std::uint8_t lead = static_cast<std::uint8_t>(value.data[index]);
    if (lead < 0x80U) {
      return 1U;
    }
    std::size_t length = 0U;
    std::uint32_t codepoint = 0U;
    if (lead >= 0xC2U && lead <= 0xDFU) {
      length = 2U;
      codepoint = lead & 0x1FU;
    } else if (lead >= 0xE0U && lead <= 0xEFU) {
      length = 3U;
      codepoint = lead & 0x0FU;
    } else if (lead >= 0xF0U && lead <= 0xF4U) {
      length = 4U;
      codepoint = lead & 0x07U;
    } else {
      return 0U;
    }
    if (index + length > value.size) {
      return 0U;
    }
    for (std::size_t offset = 1U; offset < length; ++offset) {
      const std::uint8_t continuation =
          static_cast<std::uint8_t>(value.data[index + offset]);
      if ((continuation & 0xC0U) != 0x80U) {
        return 0U;
      }
      codepoint = (codepoint << 6U) | (continuation & 0x3FU);
    }
    if ((length == 3U && codepoint < 0x800U) ||
        (length == 4U && codepoint < 0x10000U) || codepoint > 0x10FFFFU ||
        (codepoint >= 0xD800U && codepoint <= 0xDFFFU)) {
      return 0U;
    }
    return length;
  }

  char *buffer_{nullptr};
  std::size_t capacity_{0U};
  std::size_t size_{0U};
  bool overflow_{false};
};

} // namespace pm
