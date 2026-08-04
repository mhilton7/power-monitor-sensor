#include "api/CompactUiStatus.h"

#include <algorithm>
#include <cmath>

#include "api/BoundedJsonWriter.h"

namespace pm {
namespace {

template <std::size_t Capacity>
BoundedTextView text(const std::array<char, Capacity> &value) {
  std::size_t length = 0U;
  while (length < value.size() && value[length] != '\0') {
    ++length;
  }
  return {value.data(), length};
}

const char *safe(const char *value) {
  return value == nullptr ? "unavailable" : value;
}

const char *legacyServerState(const ServerFreshnessState state) {
  switch (state) {
  case ServerFreshnessState::Live:
    return "connected";
  case ServerFreshnessState::Delayed:
    return "delayed";
  case ServerFreshnessState::Stale:
    return "stale";
  case ServerFreshnessState::Unauthenticated:
    return "unauthenticated";
  case ServerFreshnessState::NeverConnected:
  case ServerFreshnessState::Offline:
    return "offline";
  }
  return "offline";
}

bool nullableUnsigned(BoundedJsonWriter &writer, const bool available,
                      const std::uint64_t value) {
  return available ? writer.unsignedValue(value) : writer.nullValue();
}

bool nullableNumber(BoundedJsonWriter &writer, const bool available,
                    const float value, const unsigned precision) {
  return available ? writer.number(value, precision) : writer.nullValue();
}

} // namespace

const char *serverFreshnessStateName(const ServerFreshnessState state) {
  switch (state) {
  case ServerFreshnessState::NeverConnected:
    return "never_connected";
  case ServerFreshnessState::Live:
    return "live";
  case ServerFreshnessState::Delayed:
    return "delayed";
  case ServerFreshnessState::Stale:
    return "stale";
  case ServerFreshnessState::Offline:
    return "offline";
  case ServerFreshnessState::Unauthenticated:
    return "unauthenticated";
  }
  return "offline";
}

std::uint64_t serverHeartbeatAgeSeconds(
    const std::uint64_t last_success_monotonic_ms,
    const std::uint64_t now_monotonic_ms) {
  if (last_success_monotonic_ms == 0U ||
      now_monotonic_ms < last_success_monotonic_ms) {
    return 0U;
  }
  return (now_monotonic_ms - last_success_monotonic_ms) / 1000U;
}

ServerFreshnessState classifyServerFreshness(
    const bool wifi_connected, const bool server_reachable,
    const bool authenticated, const std::uint64_t last_success_monotonic_ms,
    const std::uint64_t now_monotonic_ms,
    const ServerFreshnessPolicy &policy) {
  if (!wifi_connected) {
    return ServerFreshnessState::Offline;
  }
  if (server_reachable && !authenticated) {
    return ServerFreshnessState::Unauthenticated;
  }
  if (last_success_monotonic_ms == 0U) {
    return ServerFreshnessState::NeverConnected;
  }
  const std::uint64_t age =
      serverHeartbeatAgeSeconds(last_success_monotonic_ms, now_monotonic_ms);
  if (age <= policy.expected_heartbeat_seconds) {
    return ServerFreshnessState::Live;
  }
  if (age < policy.stale_after_seconds) {
    return ServerFreshnessState::Delayed;
  }
  // The central server may use offline_after_seconds to age its own
  // server-received heartbeat state. Locally, Wi-Fi is still present and the
  // last successful transaction is known, so report the truthful stale state
  // rather than inventing a confirmed network outage.
  return ServerFreshnessState::Stale;
}

CompactUiSerializationResult serializeCompactUiStatus(
    const CompactUiStatusSnapshot &snapshot,
    const CompactUiBuildMetadata &metadata, char *output,
    const std::size_t capacity) {
  BoundedJsonWriter writer(output, capacity);
  const std::uint64_t age_seconds = serverHeartbeatAgeSeconds(
      snapshot.last_heartbeat_success_monotonic_ms,
      snapshot.current_monotonic_ms);
  const double fragmentation_ratio =
      snapshot.heap.free_internal_bytes == 0U
          ? 0.0
          : 1.0 - static_cast<double>(
                      std::min(snapshot.heap.free_internal_bytes,
                               snapshot.heap.largest_internal_block_bytes)) /
                      static_cast<double>(snapshot.heap.free_internal_bytes);
  const bool low_memory = memoryPressureIsLowMemory(snapshot.memory.state);
  const bool tls_ready = memoryTlsReady(
      snapshot.heap.free_internal_bytes,
      snapshot.heap.largest_internal_block_bytes,
      snapshot.heap.integrity_ok);

  bool ok = writer.literal("{\"schema_version\":1,\"server_now\":") &&
            writer.string(text(snapshot.server_now)) &&
            writer.literal(",\"device\":{\"friendly_name\":") &&
            writer.string(text(snapshot.friendly_name)) &&
            writer.literal(",\"firmware\":") &&
            writer.string(safe(metadata.firmware)) &&
            writer.literal(",\"git_commit\":") &&
            writer.string(safe(metadata.git_commit)) &&
            writer.literal(",\"build_timestamp\":") &&
            writer.string(safe(metadata.build_timestamp)) &&
            writer.literal(",\"platformio_environment\":") &&
            writer.string(safe(metadata.platformio_environment)) &&
            writer.literal(",\"uptime_seconds\":") &&
            writer.unsignedValue(snapshot.uptime_seconds) &&
            writer.literal(",\"web_assets\":{\"index_html_sha256\":") &&
            writer.string(safe(metadata.index_html_sha256)) &&
            writer.literal(",\"app_js_sha256\":") &&
            writer.string(safe(metadata.app_js_sha256)) &&
            writer.literal(",\"style_css_sha256\":") &&
            writer.string(safe(metadata.style_css_sha256)) &&
            writer.literal("}},\"reading\":{\"measured_at_utc_ms\":") &&
            nullableUnsigned(writer, snapshot.reading_available,
                             snapshot.measured_at_utc_ms) &&
            writer.literal(",\"power_w\":") &&
            nullableNumber(writer, snapshot.reading_available,
                           snapshot.power_w, 3U) &&
            writer.literal(",\"voltage_v\":") &&
            nullableNumber(writer, snapshot.reading_available,
                           snapshot.voltage_v, 3U) &&
            writer.literal(",\"current_a\":") &&
            nullableNumber(writer, snapshot.reading_available,
                           snapshot.current_a, 4U) &&
            writer.literal(",\"frequency_hz\":") &&
            nullableNumber(writer, snapshot.reading_available,
                           snapshot.frequency_hz, 3U) &&
            writer.literal(",\"power_factor\":") &&
            nullableNumber(writer, snapshot.reading_available,
                           snapshot.power_factor, 4U) &&
            writer.literal("},\"health\":{\"wifi\":") &&
            writer.string(snapshot.wifi_connected ? "connected" : "offline") &&
            writer.literal(",\"rssi_dbm\":") &&
            writer.signedValue(snapshot.rssi_dbm) &&
            writer.literal(",\"ip_address\":") &&
            writer.string(text(snapshot.ip_address)) &&
            writer.literal(",\"server\":") &&
            writer.string(legacyServerState(snapshot.server_state)) &&
            writer.literal(",\"storage\":") &&
            writer.string(snapshot.storage_writable ? "writable" : "degraded") &&
            writer.literal(",\"meter\":") &&
             writer.string(snapshot.meter_healthy ? "healthy" : "degraded") &&
             writer.literal(",\"low_memory\":") && writer.boolean(low_memory) &&
             writer.literal(",\"memory_state\":") &&
             writer.string(memoryPressureStateName(snapshot.memory.state)) &&
             writer.literal(",\"memory_severity\":") &&
             writer.string(memoryPressureSeverityName(snapshot.memory.state)) &&
             writer.literal(",\"tls_ready\":") && writer.boolean(tls_ready) &&
             writer.literal(",\"operation_context\":") &&
             writer.string(
                 memoryOperationContextName(snapshot.operation_context)) &&
             writer.literal("},\"sync\":{\"last_success_utc_ms\":") &&
            nullableUnsigned(writer,
                             snapshot.last_heartbeat_success_utc_ms != 0U,
                             snapshot.last_heartbeat_success_utc_ms) &&
            writer.literal(",\"newest_sequence\":") &&
            writer.unsignedValue(snapshot.newest_sequence) &&
            writer.literal(",\"acknowledged_sequence\":") &&
            writer.unsignedValue(snapshot.acknowledged_sequence) &&
            writer.literal(",\"backlog\":") &&
            writer.unsignedValue(snapshot.backlog) &&
            writer.literal(",\"last_safe_error\":") &&
            writer.string(text(snapshot.last_safe_error)) &&
            writer.literal("},\"server\":{\"state\":") &&
            writer.string(serverFreshnessStateName(snapshot.server_state)) &&
            writer.literal(",\"last_success_utc_ms\":") &&
            nullableUnsigned(writer,
                             snapshot.last_heartbeat_success_utc_ms != 0U,
                             snapshot.last_heartbeat_success_utc_ms) &&
            writer.literal(",\"age_seconds\":") &&
            nullableUnsigned(
                writer,
                snapshot.last_heartbeat_success_monotonic_ms != 0U,
                age_seconds) &&
            writer.literal(",\"expected_heartbeat_seconds\":") &&
            writer.unsignedValue(
                snapshot.freshness_policy.expected_heartbeat_seconds) &&
            writer.literal(",\"stale_after_seconds\":") &&
            writer.unsignedValue(snapshot.freshness_policy.stale_after_seconds) &&
            writer.literal(",\"offline_after_seconds\":") &&
            writer.unsignedValue(
                snapshot.freshness_policy.offline_after_seconds) &&
            writer.literal(",\"last_attempt_result\":") &&
            writer.string(text(snapshot.last_attempt_result)) &&
            writer.literal(",\"last_safe_error\":") &&
            writer.string(text(snapshot.last_safe_error)) &&
             writer.literal("},\"memory\":{\"state\":") &&
             writer.string(memoryPressureStateName(snapshot.memory.state)) &&
             writer.literal(",\"severity\":") &&
             writer.string(memoryPressureSeverityName(snapshot.memory.state)) &&
             writer.literal(",\"tls_ready\":") && writer.boolean(tls_ready) &&
             writer.literal(",\"operation_context\":") &&
             writer.string(
                 memoryOperationContextName(snapshot.operation_context)) &&
             writer.literal(",\"free_internal_bytes\":") &&
            writer.unsignedValue(snapshot.heap.free_internal_bytes) &&
            writer.literal(",\"largest_internal_block_bytes\":") &&
            writer.unsignedValue(snapshot.heap.largest_internal_block_bytes) &&
            writer.literal(",\"fragmentation_ratio\":") &&
            writer.number(fragmentation_ratio, 4U) &&
            writer.literal(",\"fragmentation_entry_count\":") &&
            writer.unsignedValue(snapshot.memory.fragmentation_entry_count) &&
            writer.literal(",\"fragmentation_recovery_count\":") &&
            writer.unsignedValue(snapshot.memory.fragmentation_recovery_count) &&
            writer.literal(",\"truncated\":") &&
            writer.boolean(snapshot.truncated) &&
            writer.literal("},\"ota\":{\"protocol_version\":") &&
            writer.unsignedValue(snapshot.ota.protocol_version) &&
            writer.literal(",\"authentication_mode\":") &&
            writer.string(text(snapshot.ota.authentication_mode)) &&
            writer.literal(",\"state\":") &&
            writer.string(text(snapshot.ota.state)) &&
            writer.literal(",\"deployment_id\":") &&
            writer.string(text(snapshot.ota.deployment_id)) &&
            writer.literal(",\"target_version\":") &&
            writer.string(text(snapshot.ota.target_version)) &&
            writer.literal(",\"target_sha256\":") &&
            writer.string(text(snapshot.ota.target_sha256)) &&
            writer.literal(",\"bytes_received\":") &&
            writer.unsignedValue(snapshot.ota.bytes_received) &&
            writer.literal(",\"image_size\":") &&
            writer.unsignedValue(snapshot.ota.image_size) &&
            writer.literal(",\"progress_percent\":") &&
            writer.unsignedValue(snapshot.ota.progress_percent) &&
            writer.literal(",\"running_partition\":") &&
            writer.string(text(snapshot.ota.running_partition)) &&
            writer.literal(",\"target_partition\":") &&
            writer.string(text(snapshot.ota.target_partition)) &&
            writer.literal(",\"in_progress\":") &&
            writer.boolean(snapshot.ota.in_progress) &&
            writer.literal(",\"pending_reboot\":") &&
            writer.boolean(snapshot.ota.pending_reboot) &&
            writer.literal(",\"rollback_supported\":") &&
            writer.boolean(snapshot.ota.rollback_supported) &&
            writer.literal(",\"last_result\":") &&
            writer.string(text(snapshot.ota.last_result)) &&
            writer.literal(",\"lifecycle_stage\":") &&
            writer.string(text(snapshot.ota.lifecycle_stage)) &&
            writer.literal(",\"lifecycle_operation_context\":") &&
            writer.string(text(snapshot.ota.lifecycle_operation_context)) &&
            writer.literal(",\"lifecycle_task\":") &&
            writer.string(text(snapshot.ota.lifecycle_task)) &&
            writer.literal(",\"lifecycle_stack_high_water_bytes\":") &&
            writer.unsignedValue(
                snapshot.ota.lifecycle_stack_high_water_bytes) &&
            writer.literal(",\"rollback_detected\":") &&
            writer.boolean(snapshot.ota.rollback_detected) &&
            writer.literal(",\"restricted_recovery_mode\":") &&
            writer.boolean(snapshot.ota.restricted_recovery_mode) &&
            writer.literal("}}") &&
            writer.ok();
  return {writer.size(), ok};
}

} // namespace pm
