#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "core/HeapTelemetry.h"
#include "core/MemoryPressurePolicy.h"
#include "ota/CompactOtaStatus.h"

namespace pm {

enum class ServerFreshnessState : std::uint8_t {
  NeverConnected,
  Live,
  Delayed,
  Stale,
  Offline,
  Unauthenticated,
};

const char *serverFreshnessStateName(ServerFreshnessState state);

struct ServerFreshnessPolicy {
  std::uint32_t expected_heartbeat_seconds{15U};
  std::uint32_t stale_after_seconds{30U};
  std::uint32_t offline_after_seconds{30U};
};

struct CompactUiStatusSnapshot {
  std::array<char, 65> friendly_name{};
  std::array<char, 16> ip_address{};
  std::array<char, 25> server_now{};
  std::array<char, 65> last_safe_error{};
  std::array<char, 33> last_attempt_result{};

  std::uint64_t uptime_seconds{0U};
  std::uint64_t generated_utc_ms{0U};
  std::uint64_t measured_at_utc_ms{0U};
  std::uint64_t last_heartbeat_success_utc_ms{0U};
  std::uint64_t last_heartbeat_success_monotonic_ms{0U};
  std::uint64_t current_monotonic_ms{0U};
  std::uint64_t newest_sequence{0U};
  std::uint64_t acknowledged_sequence{0U};
  std::uint64_t backlog{0U};

  float power_w{0.0F};
  float voltage_v{0.0F};
  float current_a{0.0F};
  float frequency_hz{0.0F};
  float power_factor{0.0F};
  std::int32_t rssi_dbm{-127};

  bool reading_available{false};
  bool wifi_connected{false};
  bool storage_writable{false};
  bool meter_healthy{false};
  bool authenticated{false};
  bool server_reachable{false};
  bool truncated{false};

  HeapSnapshot heap{};
  MemoryPressureMetrics memory{};
  MemoryOperationContext operation_context{MemoryOperationContext::Idle};
  CompactOtaStatus ota{};
  ServerFreshnessPolicy freshness_policy{};
  ServerFreshnessState server_state{ServerFreshnessState::NeverConnected};
};

struct CompactUiBuildMetadata {
  const char *firmware{nullptr};
  const char *git_commit{nullptr};
  const char *build_timestamp{nullptr};
  const char *platformio_environment{nullptr};
  const char *index_html_sha256{nullptr};
  const char *app_js_sha256{nullptr};
  const char *style_css_sha256{nullptr};
};

struct CompactUiSerializationResult {
  std::size_t bytes{0U};
  bool success{false};
};

ServerFreshnessState classifyServerFreshness(
    bool wifi_connected, bool server_reachable, bool authenticated,
    std::uint64_t last_success_monotonic_ms, std::uint64_t now_monotonic_ms,
    const ServerFreshnessPolicy &policy);

std::uint64_t serverHeartbeatAgeSeconds(
    std::uint64_t last_success_monotonic_ms,
    std::uint64_t now_monotonic_ms);

CompactUiSerializationResult serializeCompactUiStatus(
    const CompactUiStatusSnapshot &snapshot,
    const CompactUiBuildMetadata &metadata, char *output,
    std::size_t capacity);

template <std::size_t Capacity>
bool copyCompactText(std::array<char, Capacity> &target,
                     const char *value) {
  static_assert(Capacity > 0U, "compact text requires a terminator");
  const std::size_t source_length =
      value == nullptr ? 0U : std::strlen(value);
  const std::size_t length =
      source_length < Capacity - 1U ? source_length : Capacity - 1U;
  for (std::size_t index = 0U; index < length; ++index) {
    target[index] = value[index];
  }
  target[length] = '\0';
  return length == source_length;
}

} // namespace pm
