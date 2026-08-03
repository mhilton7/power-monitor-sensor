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
  std::array<char, 32U> lifecycle_stage{};
  std::array<char, 24U> lifecycle_operation_context{};
  std::array<char, 17U> lifecycle_task{};
  std::array<char, 32U> previous_boot_stage{};
  std::array<char, 65U> previous_boot_id{};
  std::array<char, 32U> previous_boot_firmware{};
  std::array<char, 65U> previous_boot_build_hash{};
  std::array<char, 37U> previous_boot_deployment_id{};
  std::array<char, 49U> previous_boot_last_error{};
  std::uint32_t lifecycle_stack_high_water_bytes{0U};
  std::uint32_t previous_boot_bytes_received{0U};
  std::uint32_t previous_boot_attempt{0U};
  std::uint32_t previous_boot_reset_reason_code{0U};
  bool previous_boot_update_open{false};
  bool previous_boot_reboot_expected{false};
  bool rollback_detected{false};
  bool truncated{false};
};

} // namespace pm
