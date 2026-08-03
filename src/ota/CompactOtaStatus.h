#pragma once

#include <array>
#include <cstdint>

namespace pm {

struct CompactOtaStatus {
  std::uint8_t protocol_version{2U};
  std::array<char, 32U> authentication_mode{};
  std::array<char, 32U> state{};
  std::array<char, 37U> deployment_id{};
  std::array<char, 32U> target_version{};
  std::array<char, 65U> target_sha256{};
  std::uint32_t bytes_received{0U};
  std::uint32_t image_size{0U};
  std::uint8_t progress_percent{0U};
  std::array<char, 17U> running_partition{};
  std::array<char, 17U> target_partition{};
  bool in_progress{false};
  bool pending_reboot{false};
  bool rollback_supported{true};
  std::array<char, 32U> last_result{};
  bool rollback_detected{false};
  bool truncated{false};
};

} // namespace pm
