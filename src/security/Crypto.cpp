#include "security/Crypto.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

#include <esp_system.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

namespace pm::crypto {
namespace {

const mbedtls_md_info_t *sha256Info() {
  return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
}

bool derivePasswordHash(const std::string &password,
                        const std::array<std::uint8_t, 16> &salt,
                        const std::uint32_t iterations, Key32 &output,
                        const std::uint32_t timeout_ms) {
  output.fill(0);
  if (iterations == 0 || timeout_ms == 0)
    return false;
  const std::int64_t started_us = esp_timer_get_time();
  const std::int64_t budget_us = static_cast<std::int64_t>(timeout_ms) * 1000;
  mbedtls_md_context_t context;
  mbedtls_md_init(&context);
  bool derived =
      mbedtls_md_setup(&context, sha256Info(), 1) == 0 &&
      mbedtls_md_hmac_starts(
          &context, reinterpret_cast<const std::uint8_t *>(password.data()),
          password.size()) == 0;
  std::array<std::uint8_t, 32> block{};
  std::array<std::uint8_t, 32> accumulator{};
  const std::array<std::uint8_t, 4> block_index{0U, 0U, 0U, 1U};
  if (derived) {
    derived = mbedtls_md_hmac_update(&context, salt.data(), salt.size()) == 0 &&
              mbedtls_md_hmac_update(&context, block_index.data(),
                                     block_index.size()) == 0 &&
              mbedtls_md_hmac_finish(&context, block.data()) == 0;
    accumulator = block;
  }
  for (std::uint32_t iteration = 1; derived && iteration < iterations;
       ++iteration) {
    derived =
        mbedtls_md_hmac_reset(&context) == 0 &&
        mbedtls_md_hmac_update(&context, block.data(), block.size()) == 0 &&
        mbedtls_md_hmac_finish(&context, block.data()) == 0;
    if (derived) {
      for (std::size_t index = 0; index < accumulator.size(); ++index) {
        accumulator[index] ^= block[index];
      }
    }
    if ((iteration & 0xFFU) == 0U) {
      // PBKDF2 remains 120,000 rounds, but periodically yielding lets the
      // ESP32-S3 USB/TCP tasks and task watchdog make progress.
      vTaskDelay(pdMS_TO_TICKS(1));
      if (esp_timer_get_time() - started_us >= budget_us) {
        derived = false;
      }
    }
  }
  if (derived && esp_timer_get_time() - started_us < budget_us) {
    output = accumulator;
  } else {
    derived = false;
    output.fill(0);
  }
  std::fill(block.begin(), block.end(), 0U);
  std::fill(accumulator.begin(), accumulator.end(), 0U);
  mbedtls_md_free(&context);
  return derived;
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

} // namespace

Key32 sha256(const std::uint8_t *data, const std::size_t length) {
  Key32 output{};
  mbedtls_sha256_ret(data, length, output.data(), 0);
  return output;
}

std::string hexEncode(const std::uint8_t *data, const std::size_t length) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string output(length * 2U, '0');
  for (std::size_t index = 0; index < length; ++index) {
    output[index * 2U] = digits[data[index] >> 4U];
    output[index * 2U + 1U] = digits[data[index] & 0x0FU];
  }
  return output;
}

bool hexDecode(const std::string &hex, std::vector<std::uint8_t> &output) {
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

std::string sha256Hex(const std::uint8_t *data, const std::size_t length) {
  const Key32 digest = sha256(data, length);
  return hexEncode(digest.data(), digest.size());
}

Key32 hmacSha256(const std::uint8_t *key, const std::size_t key_length,
                 const std::uint8_t *data, const std::size_t data_length) {
  Key32 output{};
  mbedtls_md_hmac(sha256Info(), key, key_length, data, data_length,
                  output.data());
  return output;
}

std::string hmacSha256Hex(const std::uint8_t *key, const std::size_t key_length,
                          const std::string &data) {
  const Key32 digest = hmacSha256(
      key, key_length, reinterpret_cast<const std::uint8_t *>(data.data()),
      data.size());
  return hexEncode(digest.data(), digest.size());
}

Key32 hkdfSha256(const std::uint8_t *secret, const std::size_t secret_length,
                 const std::string &info) {
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

bool constantTimeEqual(const std::string &left, const std::string &right) {
  return constantTimeEqualPortable(left, right);
}

void secureRandom(std::uint8_t *output, const std::size_t length) {
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

bool passwordHash(const std::string &password,
                  const std::array<std::uint8_t, 16> &salt,
                  const std::uint32_t iterations, Key32 &output,
                  const std::uint32_t timeout_ms) {
  return derivePasswordHash(password, salt, iterations, output, timeout_ms);
}

} // namespace pm::crypto
