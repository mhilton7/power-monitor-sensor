#pragma once

#include <cstdint>

namespace pm::task_config {

// ESP-IDF's FreeRTOS port interprets xTaskCreatePinnedToCore stack depth in
// bytes, not StackType_t words. uxTaskGetStackHighWaterMark also returns bytes.
// Keep these names explicit so diagnostics and safety-margin calculations do
// not accidentally apply vanilla FreeRTOS word conversions.
inline constexpr std::uint32_t kMeterStackBytes = 6144U;
inline constexpr std::uint32_t kDiagnosticLoggerStackBytes = 4096U;
inline constexpr std::uint32_t kAggregationStackBytes = 8192U;
inline constexpr std::uint32_t kStorageStackBytes = 8192U;
inline constexpr std::uint32_t kNetworkStackBytes = 6144U;
inline constexpr std::uint32_t kServerSyncStackBytes = 16U * 1024U;
inline constexpr std::uint32_t kHealthStackBytes = 6144U;
inline constexpr std::uint32_t kMaintenanceStackBytes = 12U * 1024U;
inline constexpr std::uint32_t kSerialCommandStackBytes = 8192U;

inline constexpr std::uint32_t kMinimumStackMarginPercent = 25U;

} // namespace pm::task_config
