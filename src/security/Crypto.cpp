#include "security/Crypto.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

#include <esp_system.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>

namespace pm::crypto {
namespace {

const mbedtls_md_info_t* sha256Info() {
  return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
}

std::uint8_t hexNibble(const char character) {
  if (character >= '0' && character <= '9') {
    return static_cast<std::uint8_t>(character - '0');
  }
  if (character >= 'a' && character <= 'f') {
    return static_cast<std::uint8_t>(character - 'a' + 10);
  }
  if (character >= 'A' && character <= 'F') {
    return static_cast<std::uint8_t>(character - 'A' + 10);
  }
  return 0xFFU;
}

}  // namespace

Key32 sha256(const std::uint8_t* data, const std::size_t length) {
  Key32 output{};
  mbedtls_sha256_ret(data, length, output.data(), 0);
  return output;
}

std::string hexEncode(const std::uint8_t* data, const std::size_t length) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string output(length * 2U, '0');
  for (std::size_t index = 0; index < length; ++index) {
    output[index * 2U] = digits[data[index] >> 4U];
    output[index * 2U + 1U] = digits[data[index] & 0x0FU];
  }
  return output;
}

bool hexDecode(const std::string& hex, std::vector<std::uint8_t>& output) {
  if ((hex.size() & 1U) != 0U) {
    return false;
  }
  output.resize(hex.size() / 2U);
  for (std::size_t index = 0; index < output.size(); ++index) {
    const std::uint8_t high = hexNibble(hex[index * 2U]);
    const std::uint8_t low = hexNibble(hex[index * 2U + 1U]);
    if (high == 0xFFU || low == 0xFFU) {
      output.clear();
      return false;
    }
    output[index] = static_cast<std::uint8_t>((high << 4U) | low);
  }
  return true;
}

std::string sha256Hex(const std::uint8_t* data, const std::size_t length) {
  const Key32 digest = sha256(data, length);
  return hexEncode(digest.data(), digest.size());
}

Key32 hmacSha256(const std::uint8_t* key, const std::size_t key_length,
                 const std::uint8_t* data, const std::size_t data_length) {
  Key32 output{};
  mbedtls_md_hmac(sha256Info(), key, key_length, data, data_length, output.data());
  return output;
}

std::string hmacSha256Hex(const std::uint8_t* key,
                          const std::size_t key_length,
                          const std::string& data) {
  const Key32 digest = hmacSha256(
      key, key_length, reinterpret_cast<const std::uint8_t*>(data.data()),
      data.size());
  return hexEncode(digest.data(), digest.size());
}

Key32 hkdfSha256(const std::uint8_t* secret,
                 const std::size_t secret_length, const std::string& info) {
  // RFC 5869 with an omitted salt (HashLen zero octets). A single expansion
  // block is sufficient because the caller requests exactly SHA-256 length.
  Key32 zero_salt{};
  const Key32 pseudorandom_key =
      hmacSha256(zero_salt.data(), zero_salt.size(), secret, secret_length);
  std::vector<std::uint8_t> expansion(info.begin(), info.end());
  expansion.push_back(1U);
  return hmacSha256(pseudorandom_key.data(), pseudorandom_key.size(),
                    expansion.data(), expansion.size());
}

bool constantTimeEqual(const std::string& left, const std::string& right) {
  const std::size_t maximum = std::max(left.size(), right.size());
  std::uint8_t difference = static_cast<std::uint8_t>(left.size() ^ right.size());
  for (std::size_t index = 0; index < maximum; ++index) {
    const std::uint8_t a = index < left.size() ? left[index] : 0U;
    const std::uint8_t b = index < right.size() ? right[index] : 0U;
    difference |= static_cast<std::uint8_t>(a ^ b);
  }
  return difference == 0U;
}

void secureRandom(std::uint8_t* output, const std::size_t length) {
  esp_fill_random(output, length);
}

std::string randomHex(const std::size_t bytes) {
  std::vector<std::uint8_t> random(bytes);
  secureRandom(random.data(), random.size());
  return hexEncode(random.data(), random.size());
}

std::string uuidV4() {
  std::array<std::uint8_t, 16> bytes{};
  secureRandom(bytes.data(), bytes.size());
  bytes[6] = static_cast<std::uint8_t>((bytes[6] & 0x0FU) | 0x40U);
  bytes[8] = static_cast<std::uint8_t>((bytes[8] & 0x3FU) | 0x80U);
  char output[37]{};
  std::snprintf(output, sizeof(output),
                "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
                "%02x%02x%02x%02x%02x%02x",
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
                bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15]);
  return output;
}

std::string percentEncode(const std::string& input) {
  static constexpr char digits[] = "0123456789ABCDEF";
  std::string output;
  output.reserve(input.size());
  for (const unsigned char character : input) {
    if (std::isalnum(character) != 0 || character == '-' || character == '.' ||
        character == '_' || character == '~') {
      output.push_back(static_cast<char>(character));
    } else {
      output.push_back('%');
      output.push_back(digits[character >> 4U]);
      output.push_back(digits[character & 0x0FU]);
    }
  }
  return output;
}

std::string canonicalPathQuery(
    const std::string& path,
    const std::vector<std::pair<std::string, std::string>>& query) {
  std::vector<std::pair<std::string, std::string>> encoded;
  encoded.reserve(query.size());
  for (const auto& item : query) {
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

std::string canonicalRequest(const std::string& method,
                             const std::string& path_query,
                             const std::string& timestamp,
                             const std::string& nonce,
                             const std::string& body_hash) {
  std::string uppercase_method = method;
  std::transform(uppercase_method.begin(), uppercase_method.end(),
                 uppercase_method.begin(),
                 [](const unsigned char character) {
                   return static_cast<char>(std::toupper(character));
                 });
  return "PM-HMAC-SHA256-V1\n" + uppercase_method + "\n" + path_query + "\n" +
         timestamp + "\n" + nonce + "\n" + body_hash;
}

Key32 passwordHash(const std::string& password,
                   const std::array<std::uint8_t, 16>& salt,
                   const std::uint32_t iterations) {
  Key32 output{};
  mbedtls_md_context_t context;
  mbedtls_md_init(&context);
  if (mbedtls_md_setup(&context, sha256Info(), 1) == 0) {
    mbedtls_pkcs5_pbkdf2_hmac(
        &context, reinterpret_cast<const std::uint8_t*>(password.data()),
        password.size(), salt.data(), salt.size(), iterations, output.size(),
        output.data());
  }
  mbedtls_md_free(&context);
  return output;
}

}  // namespace pm::crypto
