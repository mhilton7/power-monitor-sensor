#pragma once

#include <cstdint>

#ifndef PM_OTA_FAULT_STAGE
#define PM_OTA_FAULT_STAGE -1
#endif

namespace pm {
namespace ota_fault {

enum class Point : std::int8_t {
  BeforeFirstByte = 0,
  AfterMetadata = 1,
  AfterUpdateBegin = 2,
  HalfwayThroughDownload = 3,
  AfterCompleteDownload = 4,
  BeforeUpdateEnd = 5,
  AfterUpdateEnd = 6,
  BeforeReboot = 7,
  BeforeRecoveryPersist = 8,
  AfterRecoveryPersist = 9,
  BeforeRecoveryReadback = 10,
  RecoveryReadbackMismatch = 11,
  AfterBootPartitionSelect = 12,
  BeforePostBootValidation = 13,
  BeforeMarkValid = 14,
  MarkValidFailure = 15,
  BeforeRollbackMark = 16,
  RollbackMarkFailure = 17,
};

constexpr std::int8_t kConfiguredPoint = PM_OTA_FAULT_STAGE;

inline constexpr bool shouldInject(const std::int8_t configured,
                                   const Point point) {
  return configured == static_cast<std::int8_t>(point);
}

inline constexpr bool configured(const Point point) {
  return shouldInject(kConfiguredPoint, point);
}

inline constexpr const char *failureCode(const Point point) {
  switch (point) {
  case Point::BeforeFirstByte: return "ota_fault_before_first_byte";
  case Point::AfterMetadata: return "ota_fault_after_metadata";
  case Point::AfterUpdateBegin: return "ota_fault_after_update_begin";
  case Point::HalfwayThroughDownload: return "ota_fault_mid_download";
  case Point::AfterCompleteDownload: return "ota_fault_after_download";
  case Point::BeforeUpdateEnd: return "ota_fault_before_update_end";
  case Point::AfterUpdateEnd: return "ota_fault_after_update_end";
  case Point::BeforeReboot: return "ota_fault_before_reboot";
  case Point::BeforeRecoveryPersist:
    return "ota_fault_before_recovery_persist";
  case Point::AfterRecoveryPersist:
    return "ota_fault_after_recovery_persist";
  case Point::BeforeRecoveryReadback:
    return "ota_fault_before_recovery_readback";
  case Point::RecoveryReadbackMismatch:
    return "ota_fault_recovery_readback_mismatch";
  case Point::AfterBootPartitionSelect:
    return "ota_fault_after_boot_partition_select";
  case Point::BeforePostBootValidation:
    return "ota_fault_before_post_boot_validation";
  case Point::BeforeMarkValid: return "ota_fault_before_mark_valid";
  case Point::MarkValidFailure: return "ota_fault_mark_valid_failure";
  case Point::BeforeRollbackMark: return "ota_fault_before_rollback_mark";
  case Point::RollbackMarkFailure:
    return "ota_fault_rollback_mark_failure";
  }
  return "ota_fault_unknown";
}

} // namespace ota_fault
} // namespace pm
