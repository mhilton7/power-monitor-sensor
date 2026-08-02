#pragma once

#include <array>
#include <cstddef>
#include <cstring>

#include "core/StringView.h"

namespace pm {

// Recurring local UI requests must not allocate attacker-controlled cookie
// values from the ESP32 internal heap. This request-local value owns a fixed
// copy and exposes only a view into that storage. Oversized values remain
// marked as presented but return an empty view so authentication fails closed.
template <std::size_t Capacity> struct BoundedCookieValue {
  std::array<char, Capacity + 1U> storage{};
  std::size_t size{0U};
  bool found{false};
  bool overflow{false};

  StringView view() const {
    return overflow ? StringView{} : StringView(storage.data(), size);
  }

  bool presented() const { return found && (size != 0U || overflow); }
};

template <std::size_t Capacity>
BoundedCookieValue<Capacity>
parseBoundedCookie(const char *cookies, const std::size_t cookies_size,
                   const StringView name) {
  BoundedCookieValue<Capacity> result;
  if (cookies == nullptr || cookies_size == 0U || name.empty()) {
    return result;
  }

  std::size_t cursor = 0U;
  while (cursor < cookies_size) {
    while (cursor < cookies_size &&
           (cookies[cursor] == ';' || cookies[cursor] == ' ' ||
            cookies[cursor] == '\t')) {
      ++cursor;
    }
    const std::size_t pair_start = cursor;
    while (cursor < cookies_size && cookies[cursor] != ';') {
      ++cursor;
    }
    const std::size_t pair_end = cursor;
    std::size_t equals = pair_end;
    for (std::size_t index = pair_start; index < pair_end; ++index) {
      if (cookies[index] == '=') {
        equals = index;
        break;
      }
    }
    if (equals != pair_end && equals - pair_start == name.size() &&
        std::memcmp(cookies + pair_start, name.data(), name.size()) == 0) {
      result.found = true;
      const std::size_t value_size = pair_end - equals - 1U;
      if (value_size > Capacity) {
        result.overflow = true;
        return result;
      }
      if (value_size != 0U) {
        std::memcpy(result.storage.data(), cookies + equals + 1U, value_size);
      }
      result.storage[value_size] = '\0';
      result.size = value_size;
      return result;
    }
    if (cursor < cookies_size) {
      ++cursor;
    }
  }
  return result;
}

} // namespace pm
