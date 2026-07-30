#include "config/ProvisioningTransaction.h"

#include <algorithm>
#include <cstddef>

#include "config/AtomicConfigStore.h"

namespace pm {
namespace provisioning_transaction {
namespace {

constexpr std::uint32_t kMagic = 0x54504D50U; // PMPT
constexpr std::uint16_t kVersion = 1U;
constexpr std::size_t kHeaderSize = 20U;
constexpr std::size_t kMaximumTokenLength = 256U;
constexpr std::size_t kMaximumCredentialPartLength = 64U;

void appendU16(std::vector<std::uint8_t> &output, const std::uint16_t value) {
  output.push_back(static_cast<std::uint8_t>(value));
  output.push_back(static_cast<std::uint8_t>(value >> 8U));
}

void appendU32(std::vector<std::uint8_t> &output, const std::uint32_t value) {
  for (std::uint8_t shift = 0; shift < 32U; shift += 8U) {
    output.push_back(static_cast<std::uint8_t>(value >> shift));
  }
}

void appendU64(std::vector<std::uint8_t> &output, const std::uint64_t value) {
  for (std::uint8_t shift = 0; shift < 64U; shift += 8U) {
    output.push_back(static_cast<std::uint8_t>(value >> shift));
  }
}

bool readU16(const std::vector<std::uint8_t> &input, const std::size_t offset,
             std::uint16_t &value) {
  if (offset + 2U > input.size())
    return false;
  value = static_cast<std::uint16_t>(input[offset]) |
          static_cast<std::uint16_t>(input[offset + 1U]) << 8U;
  return true;
}

bool readU32(const std::vector<std::uint8_t> &input, const std::size_t offset,
             std::uint32_t &value) {
  if (offset + 4U > input.size())
    return false;
  value = 0;
  for (std::uint8_t shift = 0; shift < 32U; shift += 8U) {
    value |= static_cast<std::uint32_t>(input[offset + shift / 8U]) << shift;
  }
  return true;
}

bool readU64(const std::vector<std::uint8_t> &input, const std::size_t offset,
             std::uint64_t &value) {
  if (offset + 8U > input.size())
    return false;
  value = 0;
  for (std::uint8_t shift = 0; shift < 64U; shift += 8U) {
    value |= static_cast<std::uint64_t>(input[offset + shift / 8U]) << shift;
  }
  return true;
}

bool takeField(const std::vector<std::uint8_t> &input, std::size_t &cursor,
               const std::size_t maximum, std::vector<std::uint8_t> &output) {
  std::uint16_t length = 0;
  if (!readU16(input, cursor, length) || length > maximum ||
      cursor + 2U + length > input.size() - 4U) {
    return false;
  }
  cursor += 2U;
  output.assign(input.begin() + static_cast<std::ptrdiff_t>(cursor),
                input.begin() + static_cast<std::ptrdiff_t>(cursor + length));
  cursor += length;
  return true;
}

void appendField(std::vector<std::uint8_t> &output,
                 const std::vector<std::uint8_t> &value) {
  appendU16(output, static_cast<std::uint16_t>(value.size()));
  output.insert(output.end(), value.begin(), value.end());
}

} // namespace

std::vector<std::uint8_t> encode(const Journal &journal) {
  if (journal.previous_config_generation == 0U ||
      journal.enrollment_token.size() > kMaximumTokenLength ||
      journal.admin_salt.size() > kMaximumCredentialPartLength ||
      journal.admin_hash.size() > kMaximumCredentialPartLength) {
    return {};
  }
  std::vector<std::uint8_t> output;
  output.reserve(kHeaderSize + journal.enrollment_token.size() +
                 journal.admin_salt.size() + journal.admin_hash.size());
  appendU32(output, kMagic);
  appendU16(output, kVersion);
  appendU16(output, 0U);
  appendU64(output, journal.previous_config_generation);
  appendField(output, journal.enrollment_token);
  appendField(output, journal.admin_salt);
  appendField(output, journal.admin_hash);
  appendU32(output, persistence::crc32(output.data(), output.size()));
  return output;
}

bool decode(const std::vector<std::uint8_t> &encoded, Journal &journal) {
  scrub(journal);
  if (encoded.size() < kHeaderSize)
    return false;
  std::uint32_t magic = 0;
  std::uint16_t version = 0;
  std::uint64_t previous_generation = 0;
  std::uint32_t expected_crc = 0;
  if (!readU32(encoded, 0, magic) || !readU16(encoded, 4, version) ||
      !readU64(encoded, 8, previous_generation) ||
      !readU32(encoded, encoded.size() - 4U, expected_crc) || magic != kMagic ||
      version != kVersion || previous_generation == 0U ||
      persistence::crc32(encoded.data(), encoded.size() - 4U) != expected_crc) {
    return false;
  }
  std::size_t cursor = 16U;
  if (!takeField(encoded, cursor, kMaximumTokenLength,
                 journal.enrollment_token) ||
      !takeField(encoded, cursor, kMaximumCredentialPartLength,
                 journal.admin_salt) ||
      !takeField(encoded, cursor, kMaximumCredentialPartLength,
                 journal.admin_hash) ||
      cursor != encoded.size() - 4U) {
    scrub(journal);
    return false;
  }
  journal.previous_config_generation = previous_generation;
  return true;
}

RecoveryAction recoveryAction(const std::uint64_t previous_config_generation,
                              const std::uint64_t active_config_generation) {
  if (previous_config_generation == 0U ||
      active_config_generation < previous_config_generation) {
    return RecoveryAction::Conflict;
  }
  if (active_config_generation == previous_config_generation) {
    return RecoveryAction::RestoreCredentials;
  }
  return RecoveryAction::RollbackConfigAndRestoreCredentials;
}

void scrub(Journal &journal) {
  std::fill(journal.enrollment_token.begin(), journal.enrollment_token.end(),
            std::uint8_t{0});
  std::fill(journal.admin_salt.begin(), journal.admin_salt.end(),
            std::uint8_t{0});
  std::fill(journal.admin_hash.begin(), journal.admin_hash.end(),
            std::uint8_t{0});
  journal = {};
}

} // namespace provisioning_transaction
} // namespace pm
