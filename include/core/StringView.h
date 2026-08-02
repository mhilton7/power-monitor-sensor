#pragma once

#include <cstddef>
#include <cstring>
#include <string>

namespace pm {

// C++17 std::string_view is unavailable in the repository's pinned native
// MinGW 5.1 verifier. This equivalent non-owning view keeps firmware call
// sites allocation-free while remaining buildable in every supported target.
struct StringView {
  StringView() = default;
  StringView(const char *value)
      : data_(value == nullptr ? "" : value),
        size_(value == nullptr ? 0U : std::strlen(value)) {}
  StringView(const char *value, const std::size_t size)
      : data_(value == nullptr ? "" : value),
        size_(value == nullptr ? 0U : size) {}
  template <std::size_t Size>
  StringView(const char (&value)[Size])
      : data_(value), size_(Size == 0U ? 0U : Size - 1U) {}
  StringView(const std::string &value)
      : data_(value.data()), size_(value.size()) {}
  template <typename View>
  StringView(const View &value)
      : data_(value.data()), size_(value.size()) {}

  const char *data() const { return data_; }
  std::size_t size() const { return size_; }
  bool empty() const { return size_ == 0U; }

private:
  const char *data_{""};
  std::size_t size_{0U};
};

inline bool operator==(const StringView left, const StringView right) {
  return left.size() == right.size() &&
         (left.size() == 0U ||
          std::memcmp(left.data(), right.data(), left.size()) == 0);
}

inline bool operator!=(const StringView left, const StringView right) {
  return !(left == right);
}

} // namespace pm
