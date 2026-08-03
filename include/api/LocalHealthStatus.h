#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "api/BoundedJsonWriter.h"

namespace pm {

struct LocalHealthSnapshot {
  const char *protocol{""};
  const char *firmware_version{""};
  const char *git_commit{""};
  const char *build_timestamp{""};
  const char *high_memory_context{"idle"};
  const char *memory_state{"normal"};
  const char *memory_severity{"normal"};
  std::array<char, 65U> boot_id{};
  std::array<char, 33U> last_heartbeat_result{};
  std::array<char, 65U> last_local_deferral_reason{};
  std::array<char, 65U> last_sync_error{};
  std::uint64_t uptime_seconds{0U};
  std::uint64_t heartbeat_requests_sent{0U};
  std::uint64_t heartbeat_successes{0U};
  std::uint64_t heartbeat_failures{0U};
  std::uint64_t reading_batch_successes{0U};
  std::uint64_t reading_batch_failures{0U};
  std::uint64_t transactions_started{0U};
  std::uint64_t transactions_completed{0U};
  std::uint64_t transactions_failed{0U};
  std::uint64_t local_resource_deferrals{0U};
  std::uint64_t fragmentation_deferrals{0U};
  std::uint64_t fragmentation_recoveries{0U};
  std::uint64_t tls_requests_admitted{0U};
  std::uint64_t tls_requests_rejected_heap{0U};
  std::uint64_t last_heartbeat_utc_ms{0U};
  std::uint64_t last_heartbeat_attempt_monotonic_ms{0U};
  std::uint64_t last_heartbeat_success_monotonic_ms{0U};
  std::uint64_t last_sync_utc_ms{0U};
  std::uint64_t server_ack_sequence{0U};
  std::uint64_t oldest_stored_sequence{0U};
  std::uint64_t oldest_syncable_sequence{0U};
  std::uint64_t newest_stored_sequence{0U};
  std::uint64_t newest_syncable_sequence{0U};
  std::uint64_t durable_backlog_count{0U};
  std::uint64_t storage_dropped{0U};
  std::uint64_t action_dropped{0U};
  std::uint64_t record_pool_exhaustions{0U};
  std::uint64_t event_pool_exhaustions{0U};
  std::uint64_t cumulative_pressure_ms{0U};
  std::uint64_t longest_pressure_episode_ms{0U};
  std::uint32_t free_heap_bytes{0U};
  std::uint32_t minimum_free_heap_bytes{0U};
  std::uint32_t free_internal_heap_bytes{0U};
  std::uint32_t minimum_free_internal_heap_bytes{0U};
  std::uint32_t largest_internal_block_bytes{0U};
  std::uint32_t lowest_free_internal_bytes{0U};
  std::uint32_t lowest_largest_internal_block_bytes{0U};
  std::uint32_t tls_transient_minimum_free_internal_bytes{0U};
  std::uint32_t ota_transient_minimum_free_internal_bytes{0U};
  std::uint32_t stack_high_water_bytes{0U};
  std::uint32_t stack_margin_percent{0U};
  std::uint32_t storage_queue_depth{0U};
  std::uint32_t action_queue_depth{0U};
  std::uint16_t record_pool_capacity{0U};
  std::uint16_t record_pool_active{0U};
  std::uint16_t record_pool_peak_active{0U};
  std::uint16_t event_pool_capacity{0U};
  std::uint16_t event_pool_active{0U};
  std::uint16_t event_pool_peak_active{0U};
  bool wifi_connected{false};
  bool time_trusted{false};
  bool storage_present{false};
  bool storage_mounted{false};
  bool storage_writable{false};
  bool storage_index_healthy{false};
  bool meter_healthy{false};
  bool sync_in_progress{false};
  bool sync_pending{false};
  bool durable_reading_backlog{false};
  bool tls_ready{false};
  bool heap_integrity_ok{true};
};

struct LocalHealthSerializationResult {
  bool success{false};
  std::size_t bytes{0U};
};

namespace local_health_detail {
inline bool prefix(BoundedJsonWriter &writer, bool &first, const char *name) {
  if (!first && !writer.literal(","))
    return false;
  first = false;
  return writer.string(name) && writer.literal(":");
}
inline bool text(BoundedJsonWriter &writer, bool &first, const char *name,
                 const char *value) {
  return prefix(writer, first, name) && writer.string(value);
}
inline bool boolean(BoundedJsonWriter &writer, bool &first, const char *name,
                    const bool value) {
  return prefix(writer, first, name) && writer.boolean(value);
}
inline bool number(BoundedJsonWriter &writer, bool &first, const char *name,
                   const std::uint64_t value) {
  return prefix(writer, first, name) && writer.unsignedValue(value);
}
} // namespace local_health_detail

inline LocalHealthSerializationResult
serializeLocalHealth(const LocalHealthSnapshot &value, char *output,
                     const std::size_t capacity) {
  BoundedJsonWriter writer(output, capacity);
  bool first = true;
  using namespace local_health_detail;
  const bool ok = writer.literal("{") &&
      number(writer, first, "schema_version", 2U) &&
      text(writer, first, "protocol", value.protocol) &&
      text(writer, first, "firmware_version", value.firmware_version) &&
      text(writer, first, "git_commit", value.git_commit) &&
      text(writer, first, "build_timestamp", value.build_timestamp) &&
      text(writer, first, "boot_id", value.boot_id.data()) &&
      number(writer, first, "uptime_seconds", value.uptime_seconds) &&
      boolean(writer, first, "wifi_connected", value.wifi_connected) &&
      boolean(writer, first, "time_trusted", value.time_trusted) &&
      boolean(writer, first, "storage_present", value.storage_present) &&
      boolean(writer, first, "storage_mounted", value.storage_mounted) &&
      boolean(writer, first, "storage_writable", value.storage_writable) &&
      boolean(writer, first, "storage_index_healthy", value.storage_index_healthy) &&
      boolean(writer, first, "meter_healthy", value.meter_healthy) &&
      text(writer, first, "high_memory_context", value.high_memory_context) &&
      text(writer, first, "high_memory_owner", value.high_memory_context) &&
      text(writer, first, "memory_state", value.memory_state) &&
      text(writer, first, "memory_severity", value.memory_severity) &&
      boolean(writer, first, "tls_ready", value.tls_ready) &&
      boolean(writer, first, "heap_integrity_ok", value.heap_integrity_ok) &&
      number(writer, first, "free_heap_bytes", value.free_heap_bytes) &&
      number(writer, first, "minimum_free_heap_bytes", value.minimum_free_heap_bytes) &&
      number(writer, first, "free_internal_heap_bytes", value.free_internal_heap_bytes) &&
      number(writer, first, "minimum_free_internal_heap_bytes", value.minimum_free_internal_heap_bytes) &&
      number(writer, first, "largest_internal_block_bytes", value.largest_internal_block_bytes) &&
      number(writer, first, "lowest_free_internal_bytes", value.lowest_free_internal_bytes) &&
      number(writer, first, "lowest_largest_internal_block_bytes", value.lowest_largest_internal_block_bytes) &&
      number(writer, first, "tls_transient_minimum_free_internal_bytes", value.tls_transient_minimum_free_internal_bytes) &&
      number(writer, first, "ota_transient_minimum_free_internal_bytes", value.ota_transient_minimum_free_internal_bytes) &&
      number(writer, first, "cumulative_pressure_ms", value.cumulative_pressure_ms) &&
      number(writer, first, "longest_pressure_episode_ms", value.longest_pressure_episode_ms) &&
      boolean(writer, first, "sync_in_progress", value.sync_in_progress) &&
      boolean(writer, first, "sync_pending", value.sync_pending) &&
      number(writer, first, "heartbeat_requests_sent", value.heartbeat_requests_sent) &&
      number(writer, first, "heartbeat_successes", value.heartbeat_successes) &&
      number(writer, first, "heartbeat_failures", value.heartbeat_failures) &&
      number(writer, first, "reading_batch_successes", value.reading_batch_successes) &&
      number(writer, first, "reading_batch_failures", value.reading_batch_failures) &&
      number(writer, first, "transactions_started", value.transactions_started) &&
      number(writer, first, "transactions_completed", value.transactions_completed) &&
      number(writer, first, "transactions_failed", value.transactions_failed) &&
      number(writer, first, "local_resource_deferrals", value.local_resource_deferrals) &&
      number(writer, first, "fragmentation_deferrals", value.fragmentation_deferrals) &&
      number(writer, first, "fragmentation_recoveries", value.fragmentation_recoveries) &&
      number(writer, first, "tls_requests_admitted", value.tls_requests_admitted) &&
      number(writer, first, "tls_requests_rejected_heap", value.tls_requests_rejected_heap) &&
      number(writer, first, "last_heartbeat_utc_ms", value.last_heartbeat_utc_ms) &&
      number(writer, first, "last_heartbeat_attempt_monotonic_ms", value.last_heartbeat_attempt_monotonic_ms) &&
      number(writer, first, "last_heartbeat_success_monotonic_ms", value.last_heartbeat_success_monotonic_ms) &&
      number(writer, first, "last_sync_utc_ms", value.last_sync_utc_ms) &&
      text(writer, first, "last_heartbeat_result", value.last_heartbeat_result.data()) &&
      text(writer, first, "last_local_deferral_reason", value.last_local_deferral_reason.data()) &&
      text(writer, first, "last_sync_error", value.last_sync_error.data()) &&
      number(writer, first, "server_ack_sequence", value.server_ack_sequence) &&
      number(writer, first, "oldest_stored_sequence", value.oldest_stored_sequence) &&
      number(writer, first, "oldest_syncable_sequence", value.oldest_syncable_sequence) &&
      number(writer, first, "newest_stored_sequence", value.newest_stored_sequence) &&
      number(writer, first, "newest_syncable_sequence", value.newest_syncable_sequence) &&
      number(writer, first, "durable_backlog_count", value.durable_backlog_count) &&
      boolean(writer, first, "durable_reading_backlog", value.durable_reading_backlog) &&
      number(writer, first, "stack_high_water_bytes", value.stack_high_water_bytes) &&
      number(writer, first, "stack_margin_percent", value.stack_margin_percent) &&
      number(writer, first, "storage_queue_depth", value.storage_queue_depth) &&
      number(writer, first, "action_queue_depth", value.action_queue_depth) &&
      number(writer, first, "storage_dropped", value.storage_dropped) &&
      number(writer, first, "action_dropped", value.action_dropped) &&
      number(writer, first, "record_pool_capacity", value.record_pool_capacity) &&
      number(writer, first, "record_pool_active", value.record_pool_active) &&
      number(writer, first, "record_pool_peak_active", value.record_pool_peak_active) &&
      number(writer, first, "record_pool_exhaustions", value.record_pool_exhaustions) &&
      number(writer, first, "event_pool_capacity", value.event_pool_capacity) &&
      number(writer, first, "event_pool_active", value.event_pool_active) &&
      number(writer, first, "event_pool_peak_active", value.event_pool_peak_active) &&
      number(writer, first, "event_pool_exhaustions", value.event_pool_exhaustions) &&
      writer.literal("}");
  return {ok && writer.ok(), writer.size()};
}

} // namespace pm
