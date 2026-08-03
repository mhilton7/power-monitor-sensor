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
  }
  return "ota_fault_unknown";
}

} // namespace ota_fault
} // namespace pm
