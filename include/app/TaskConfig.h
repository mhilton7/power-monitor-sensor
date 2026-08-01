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
// Segment reconciliation and retention hold several bounded path/metadata
// objects at once. Physical recovery telemetry left only a 17% margin with an
// 8 KiB allocation, below the mandatory 25% soak threshold.
inline constexpr std::uint32_t kStorageStackBytes = 12288U;
// Storage recovery may scan a large card at the 400 kHz recovery clock.
// Keep it at the idle priority and pin it away from the measurement core. FAT
// directory iteration performs a blocking stat() for every entry; a positive-
// priority storage task can therefore starve ESP-IDF's monitored IDLE0 task
// even though interrupts and the measurement core remain healthy. At priority
// zero the scheduler time-slices recovery with IDLE0 while every online task
// preempts it.
inline constexpr std::uint32_t kAggregationPriority = 3U;
inline constexpr std::uint32_t kStoragePriority = 0U;
// Production reconnect/mDNS traces consumed roughly 5,124 bytes from the old
// 6,144-byte allocation (16% remaining). An 8 KiB allocation gives the same
// measured path a 37% margin while NetworkService scratch lifetimes are kept
// bounded.
inline constexpr std::uint32_t kNetworkStackBytes = 8192U;
// mbedTLS certificate verification and HTTP/HMAC framing share this task.
// Production traces showed fewer than 1 KiB remaining during a heartbeat at
// 16 KiB, which could corrupt the AsyncWebServer task instead of returning a
// recoverable request error.
inline constexpr std::uint32_t kServerSyncStackBytes = 24U * 1024U;
// Physical 1.0.6 traces left only 516-724 bytes (8-11%) after the health
// task captured task metrics and persisted the disconnect flight recorder.
// Eight KiB keeps that measured path above the mandatory 25% margin without
// changing task priority or any primary measurement/synchronization work.
// HealthTask formats the widest retention/memory diagnostics and samples every
// task's watermark. Physical release telemetry left only a 19% margin with an
// 8 KiB stack, below the repository's 25% soak requirement. The 12 KiB bound
// restores headroom without changing task priority or allocating per cycle.
inline constexpr std::uint32_t kHealthStackBytes = 12288U;
inline constexpr std::uint32_t kMaintenanceStackBytes = 12U * 1024U;
// Serial configuration commands persist and verify the full atomic
// configuration, including parsing the private Caddy CA with mbedTLS. An
// 8 KiB task double-faulted in mbedtls_pem_read_buffer while applying a
// harmless log-level change on production hardware.
inline constexpr std::uint32_t kSerialCommandStackBytes = 24U * 1024U;
inline constexpr std::uint32_t kPasswordJobStackBytes = 16U * 1024U;

inline constexpr std::uint32_t kMinimumStackMarginPercent = 25U;

} // namespace pm::task_config
