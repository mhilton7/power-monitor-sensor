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
// Storage recovery may scan a large card at the 400 kHz recovery clock.
// Keep it below AggregationTask so a long scan cannot starve the watchdog-
// supervised measurement pipeline even when same-priority time slicing is
// unavailable or an SD operation spans multiple scheduler ticks.
inline constexpr std::uint32_t kAggregationPriority = 3U;
inline constexpr std::uint32_t kStoragePriority = 2U;
inline constexpr std::uint32_t kNetworkStackBytes = 6144U;
// mbedTLS certificate verification and HTTP/HMAC framing share this task.
// Production traces showed fewer than 1 KiB remaining during a heartbeat at
// 16 KiB, which could corrupt the AsyncWebServer task instead of returning a
// recoverable request error.
inline constexpr std::uint32_t kServerSyncStackBytes = 24U * 1024U;
inline constexpr std::uint32_t kMinimumTlsStackHighWaterBytes = 12U * 1024U;
inline constexpr std::uint32_t kHealthStackBytes = 6144U;
inline constexpr std::uint32_t kMaintenanceStackBytes = 12U * 1024U;
// Serial configuration commands persist and verify the full atomic
// configuration, including parsing the private Caddy CA with mbedTLS. An
// 8 KiB task double-faulted in mbedtls_pem_read_buffer while applying a
// harmless log-level change on production hardware.
inline constexpr std::uint32_t kSerialCommandStackBytes = 24U * 1024U;

inline constexpr std::uint32_t kMinimumStackMarginPercent = 25U;

} // namespace pm::task_config
