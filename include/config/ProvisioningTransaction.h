#pragma once

#include <cstdint>
#include <vector>

namespace pm {
namespace provisioning_transaction {

struct Journal {
  std::uint64_t previous_config_generation{0};
  std::vector<std::uint8_t> enrollment_token;
  std::vector<std::uint8_t> admin_salt;
  std::vector<std::uint8_t> admin_hash;
};

enum class RecoveryAction : std::uint8_t {
  RestoreCredentials,
  RollbackConfigAndRestoreCredentials,
  Conflict,
};

std::vector<std::uint8_t> encode(const Journal &journal);
bool decode(const std::vector<std::uint8_t> &encoded, Journal &journal);
RecoveryAction recoveryAction(std::uint64_t previous_config_generation,
                              std::uint64_t active_config_generation);
void scrub(Journal &journal);

} // namespace provisioning_transaction
} // namespace pm
