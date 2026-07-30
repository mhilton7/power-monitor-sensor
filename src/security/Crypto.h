#pragma once

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace pm {
namespace crypto {

using Key32 = std::array<std::uint8_t, 32>;

Key32 sha256(const std::uint8_t *data, std::size_t length);
std::string hexEncode(const std::uint8_t *data, std::size_t length);
bool hexDecode(const std::string &hex, std::vector<std::uint8_t> &output);
std::string sha256Hex(const std::uint8_t *data, std::size_t length);
Key32 hmacSha256(const std::uint8_t *key, std::size_t key_length,
                 const std::uint8_t *data, std::size_t data_length);
std::string hmacSha256Hex(const std::uint8_t *key, std::size_t key_length,
                          const std::string &data);
Key32 hkdfSha256(const std::uint8_t *secret, std::size_t secret_length,
                 const std::string &info);
bool constantTimeEqual(const std::string &left, const std::string &right);

inline bool constantTimeEqualPortable(const std::string &left,
                                      const std::string &right) {
  const std::size_t maximum = std::max(left.size(), right.size());
  std::size_t length_difference = left.size() ^ right.size();
  std::uint8_t difference = 0U;
  while (length_difference != 0U) {
    difference |= static_cast<std::uint8_t>(length_difference & 0xFFU);
    length_difference >>= 8U;
  }
  for (std::size_t index = 0; index < maximum; ++index) {
    const std::uint8_t a =
        index < left.size() ? static_cast<std::uint8_t>(left[index]) : 0U;
    const std::uint8_t b =
        index < right.size() ? static_cast<std::uint8_t>(right[index]) : 0U;
    difference |= static_cast<std::uint8_t>(a ^ b);
  }
  return difference == 0U;
}
void secureRandom(std::uint8_t *output, std::size_t length);
std::string randomHex(std::size_t bytes);
std::string uuidV4();

inline bool asciiUnreserved(const unsigned char character) {
  return (character >= 'a' && character <= 'z') ||
         (character >= 'A' && character <= 'Z') ||
         (character >= '0' && character <= '9') || character == '-' ||
         character == '.' || character == '_' || character == '~';
}

inline std::string percentEncode(const std::string &input) {
  static constexpr char digits[] = "0123456789ABCDEF";
  std::string output;
  output.reserve(input.size());
  for (const unsigned char character : input) {
    if (asciiUnreserved(character)) {
      output.push_back(static_cast<char>(character));
    } else {
      output.push_back('%');
      output.push_back(digits[character >> 4U]);
      output.push_back(digits[character & 0x0FU]);
    }
  }
  return output;
}

inline std::uint8_t percentNibble(const char value) {
  if (value >= '0' && value <= '9') {
    return static_cast<std::uint8_t>(value - '0');
  }
  if (value >= 'a' && value <= 'f') {
    return static_cast<std::uint8_t>(value - 'a' + 10);
  }
  if (value >= 'A' && value <= 'F') {
    return static_cast<std::uint8_t>(value - 'A' + 10);
  }
  return 0xFFU;
}

// Query strings use application/x-www-form-urlencoded decoding before the
// protocol's RFC 3986 encoding and sorting step. Decode exactly once so an
// existing "%2F" escape canonicalizes to "%2F", not "%252F".
inline bool percentDecodeQueryComponent(const std::string &input,
                                        std::string &output) {
  output.clear();
  output.reserve(input.size());
  for (std::size_t index = 0; index < input.size(); ++index) {
    const char character = input[index];
    if (character == '+') {
      output.push_back(' ');
      continue;
    }
    if (character != '%') {
      output.push_back(character);
      continue;
    }
    if (index + 2U >= input.size()) {
      output.clear();
      return false;
    }
    const std::uint8_t high = percentNibble(input[index + 1U]);
    const std::uint8_t low = percentNibble(input[index + 2U]);
    if (high == 0xFFU || low == 0xFFU) {
      output.clear();
      return false;
    }
    output.push_back(static_cast<char>((high << 4U) | low));
    index += 2U;
  }
  return true;
}

inline bool
splitCanonicalTarget(const std::string &target, std::string &path,
                     std::vector<std::pair<std::string, std::string>> &query) {
  path.clear();
  query.clear();
  if (target.empty() || target.front() != '/' ||
      target.find('#') != std::string::npos) {
    return false;
  }
  const std::size_t question = target.find('?');
  path = target.substr(0, question);
  if (question == std::string::npos || question + 1U >= target.size()) {
    return true;
  }
  std::size_t cursor = question + 1U;
  while (cursor <= target.size()) {
    const std::size_t ampersand = target.find('&', cursor);
    const std::string item = target.substr(cursor, ampersand - cursor);
    if (!item.empty()) {
      const std::size_t equals = item.find('=');
      std::string key;
      std::string value;
      if (!percentDecodeQueryComponent(item.substr(0, equals), key) ||
          !percentDecodeQueryComponent(equals == std::string::npos
                                           ? std::string{}
                                           : item.substr(equals + 1U),
                                       value)) {
        path.clear();
        query.clear();
        return false;
      }
      query.emplace_back(std::move(key), std::move(value));
    }
    if (ampersand == std::string::npos) {
      break;
    }
    cursor = ampersand + 1U;
  }
  return true;
}

inline std::string canonicalPathQuery(
    const std::string &path,
    const std::vector<std::pair<std::string, std::string>> &query) {
  std::vector<std::pair<std::string, std::string>> encoded;
  encoded.reserve(query.size());
  for (const auto &item : query) {
    encoded.emplace_back(percentEncode(item.first), percentEncode(item.second));
  }
  std::sort(encoded.begin(), encoded.end());
  if (encoded.empty()) {
    return path;
  }
  std::string result = path + "?";
  for (std::size_t index = 0; index < encoded.size(); ++index) {
    if (index != 0) {
      result.push_back('&');
    }
    result += encoded[index].first + "=" + encoded[index].second;
  }
  return result;
}

inline bool canonicalTarget(const std::string &target, std::string &output) {
  std::string path;
  std::vector<std::pair<std::string, std::string>> query;
  if (!splitCanonicalTarget(target, path, query)) {
    output.clear();
    return false;
  }
  output = canonicalPathQuery(path, query);
  return true;
}

inline std::string canonicalRequest(const std::string &method,
                                    const std::string &path_query,
                                    const std::string &timestamp,
                                    const std::string &nonce,
                                    const std::string &body_hash) {
  std::string uppercase_method = method;
  std::transform(uppercase_method.begin(), uppercase_method.end(),
                 uppercase_method.begin(), [](const unsigned char character) {
                   return static_cast<char>(std::toupper(character));
                 });
  return "PM-HMAC-SHA256-V1\n" + uppercase_method + "\n" + path_query + "\n" +
         timestamp + "\n" + nonce + "\n" + body_hash;
}

bool passwordHash(const std::string &password,
                  const std::array<std::uint8_t, 16> &salt,
                  std::uint32_t iterations, Key32 &output,
                  std::uint32_t timeout_ms);

} // namespace crypto
} // namespace pm
