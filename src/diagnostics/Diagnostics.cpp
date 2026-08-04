#include "diagnostics/Diagnostics.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include <Arduino.h>
#include <ArduinoJson.h>
#include <ESP.h>
#include <esp_ota_ops.h>
#include <esp_heap_caps.h>
#include <esp_partition.h>
#include <esp_system.h>
#include <esp_timer.h>

#include "build_config.h"
#include "diagnostics/SerialLogger.h"
#include "ui/embedded_assets.h"
#include "version.h"

namespace pm {
namespace {

std::string runningFirmwareSha256() {
  const esp_partition_t *partition = esp_ota_get_running_partition();
  if (partition == nullptr) {
    return {};
  }
  std::uint8_t digest[32]{};
  if (esp_partition_get_sha256(partition, digest) != ESP_OK) {
    return {};
  }
  static constexpr char kHex[] = "0123456789abcdef";
  std::string value(64U, '0');
  for (std::size_t index = 0; index < sizeof(digest); ++index) {
    value[index * 2U] = kHex[(digest[index] >> 4U) & 0x0fU];
    value[index * 2U + 1U] = kHex[digest[index] & 0x0fU];
  }
  return value;
}

} // namespace

const char *tlsLifecycleStageName(const TlsLifecycleStage stage) {
  switch (stage) {
  case TlsLifecycleStage::BeforeClientConstruction:
    return "before_client_construction";
  case TlsLifecycleStage::AfterTlsConfiguration:
    return "after_tls_configuration";
  case TlsLifecycleStage::AfterHttpBegin:
    return "after_http_begin";
  case TlsLifecycleStage::AfterRequest:
    return "after_request";
  case TlsLifecycleStage::AfterHttpEnd:
    return "after_http_end";
  case TlsLifecycleStage::AfterClientDestruction:
    return "after_client_destruction";
  case TlsLifecycleStage::AfterHighMemoryLeaseRelease:
    return "after_high_memory_lease_release";
  }
  return "unknown";
}

Diagnostics::Diagnostics() {
  mutex_ = xSemaphoreCreateMutex();
  high_memory_mutex_ = xSemaphoreCreateMutex();
}

void Diagnostics::setLatest(const MeasurementSnapshot &sample) {
  if (lock()) {
    latest_ = sample;
    has_latest_ = true;
    unlock();
  }
}

bool Diagnostics::latest(MeasurementSnapshot &sample) const {
  if (!lock()) {
    return false;
  }
  const bool available = has_latest_;
  if (available) {
    sample = latest_;
  }
  unlock();
  return available;
}

void Diagnostics::setCommittedSequence(const std::uint64_t sequence) {
  if (lock()) {
    committed_sequence_ = sequence;
    unlock();
  }
}

std::uint64_t Diagnostics::committedSequence() const {
  if (!lock()) {
    return 0;
  }
  const std::uint64_t value = committed_sequence_;
  unlock();
  return value;
}

void Diagnostics::setQueueDepths(const std::uint32_t storage_depth,
                                 const std::uint32_t action_depth,
                                 const std::uint64_t storage_dropped,
                                 const std::uint64_t action_dropped) {
  if (lock()) {
    storage_queue_depth_ = storage_depth;
    action_queue_depth_ = action_depth;
    storage_dropped_ = storage_dropped;
    action_dropped_ = action_dropped;
    unlock();
  }
}

QueueMetrics Diagnostics::queueMetrics() const {
  if (!lock()) {
    return {};
  }
  const QueueMetrics copy{storage_queue_depth_, action_queue_depth_,
                          storage_dropped_, action_dropped_};
  unlock();
  return copy;
}

void Diagnostics::setSyncMetrics(const SyncMetrics &metrics) {
  if (lock()) {
    sync_ = metrics;
    unlock();
  }
}

SyncMetrics Diagnostics::syncMetrics() const {
  if (!lock()) {
    return {};
  }
  const SyncMetrics copy = sync_;
  unlock();
  return copy;
}

CompactSyncMetrics Diagnostics::compactSyncMetrics() const {
  CompactSyncMetrics output;
  if (!lock()) {
    return output;
  }
  output.heartbeat_requests_sent = sync_.heartbeat_requests_sent;
  output.heartbeat_successes = sync_.heartbeat_successes;
  output.heartbeat_failures = sync_.heartbeat_failures;
  output.batch_successes = sync_.batch_successes;
  output.batch_failures = sync_.batch_failures;
  output.transactions_started = sync_.transactions_started;
  output.transactions_completed = sync_.transactions_completed;
  output.transactions_failed = sync_.transactions_failed;
  output.local_resource_deferrals = sync_.local_resource_deferrals;
  output.fragmentation_deferrals = sync_.fragmentation_deferrals;
  output.fragmentation_recoveries = sync_.fragmentation_recoveries;
  output.tls_requests_admitted = sync_.tls_requests_admitted;
  output.tls_requests_rejected_heap = sync_.tls_requests_rejected_heap;
  output.last_heartbeat_utc_ms = sync_.last_heartbeat_utc_ms;
  output.last_sync_utc_ms = sync_.last_sync_utc_ms;
  output.last_heartbeat_attempt_monotonic_ms =
      sync_.last_heartbeat_attempt_monotonic_ms;
  output.last_heartbeat_success_monotonic_ms =
      sync_.last_heartbeat_success_monotonic_ms;
  output.active_request_id = sync_.active_request_id;
  output.stack_high_water_bytes = sync_.stack_high_water_bytes;
  output.stack_margin_percent = sync_.stack_margin_percent;
  output.largest_internal_before_tls = sync_.largest_internal_before_tls;
  output.largest_internal_after_tls = sync_.largest_internal_after_tls;
  output.largest_internal_after_cleanup = sync_.largest_internal_after_cleanup;
  output.consecutive_local_deferrals = sync_.consecutive_local_deferrals;
  output.sync_in_progress = sync_.sync_in_progress;
  output.sync_pending = sync_.sync_pending;
  output.durable_reading_backlog = sync_.durable_reading_backlog;
  const auto copy = [&output](auto &target, const std::string &source) {
    const int written = std::snprintf(target.data(), target.size(), "%s",
                                      source.c_str());
    output.truncated = output.truncated || written < 0 ||
                       static_cast<std::size_t>(written) >= target.size();
  };
  copy(output.last_heartbeat_result, sync_.last_heartbeat_result);
  copy(output.last_local_deferral_reason,
       sync_.last_local_deferral_reason);
  copy(output.last_error, sync_.last_error);
  unlock();
  return output;
}

void Diagnostics::setMemoryPressureMetrics(
    const MemoryPressureMetrics &metrics) {
  if (lock()) {
    memory_pressure_ = metrics;
    unlock();
  }
}

MemoryPressureMetrics Diagnostics::memoryPressureMetrics() const {
  if (!lock()) {
    return {};
  }
  const MemoryPressureMetrics copy = memory_pressure_;
  unlock();
  return copy;
}

bool Diagnostics::acquireHighMemoryOperation(
    const MemoryOperationContext context, const TickType_t timeout) const {
  if (context == MemoryOperationContext::Idle ||
      high_memory_mutex_ == nullptr ||
      xSemaphoreTake(high_memory_mutex_, timeout) != pdTRUE) {
    return false;
  }
  high_memory_context_.store(static_cast<std::uint8_t>(context),
                             std::memory_order_release);
  return true;
}

bool Diagnostics::transitionHighMemoryOperation(
    const MemoryOperationContext expected,
    const MemoryOperationContext next) const {
  if (!memoryOperationTransitionAllowed(expected, next)) {
    return false;
  }
  std::uint8_t expected_value = static_cast<std::uint8_t>(expected);
  return high_memory_context_.compare_exchange_strong(
      expected_value, static_cast<std::uint8_t>(next),
      std::memory_order_acq_rel);
}

void Diagnostics::releaseHighMemoryOperation() const {
  if (high_memory_mutex_ != nullptr) {
    const MemoryOperationContext completed = memoryOperationContext();
    if (requiresPostOperationMemoryGrace(completed)) {
      high_memory_completed_ms_.store(
          static_cast<std::uint64_t>(esp_timer_get_time()) / 1000U,
          std::memory_order_release);
    }
    high_memory_context_.store(
        static_cast<std::uint8_t>(MemoryOperationContext::Idle),
        std::memory_order_release);
    xSemaphoreGive(high_memory_mutex_);
  }
}

MemoryOperationContext Diagnostics::memoryOperationContext() const {
  return static_cast<MemoryOperationContext>(
      high_memory_context_.load(std::memory_order_acquire));
}

std::uint64_t Diagnostics::lastMemoryOperationCompletedMs() const {
  return high_memory_completed_ms_.load(std::memory_order_acquire);
}

void Diagnostics::recordTlsLifecycleCheckpoint(
    const std::uint32_t request_id, const char *const endpoint,
    const std::size_t endpoint_size,
    const TlsLifecycleStage stage) const {
  if (!lock(pdMS_TO_TICKS(25))) {
    return;
  }
  TlsLifecycleCheckpoint &checkpoint =
      tls_lifecycle_checkpoints_[tls_lifecycle_checkpoint_next_];
  checkpoint = {};
  checkpoint.request_id = request_id;
  checkpoint.monotonic_ms =
      static_cast<std::uint64_t>(esp_timer_get_time()) / 1000U;
  checkpoint.free_internal_heap_bytes = static_cast<std::uint32_t>(
      heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
  checkpoint.largest_internal_block_bytes = static_cast<std::uint32_t>(
      heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
  checkpoint.context = memoryOperationContext();
  checkpoint.stage = stage;
  const std::size_t endpoint_length =
      endpoint == nullptr
          ? 0U
          : std::min(endpoint_size, checkpoint.endpoint.size() - 1U);
  if (endpoint_length != 0U && endpoint != nullptr) {
    std::memcpy(checkpoint.endpoint.data(), endpoint, endpoint_length);
  }
  checkpoint.endpoint[endpoint_length] = '\0';
  tls_lifecycle_checkpoint_next_ =
      (tls_lifecycle_checkpoint_next_ + 1U) %
      tls_lifecycle_checkpoints_.size();
  tls_lifecycle_checkpoint_count_ =
      std::min(tls_lifecycle_checkpoint_count_ + 1U,
               tls_lifecycle_checkpoints_.size());
  ++tls_lifecycle_checkpoint_total_;
  unlock();
}

TlsLifecycleCheckpointSnapshot Diagnostics::tlsLifecycleCheckpoints() const {
  TlsLifecycleCheckpointSnapshot snapshot;
  if (!lock()) {
    return snapshot;
  }
  snapshot.count = tls_lifecycle_checkpoint_count_;
  snapshot.total = tls_lifecycle_checkpoint_total_;
  const std::size_t first =
      (tls_lifecycle_checkpoint_next_ + tls_lifecycle_checkpoints_.size() -
       tls_lifecycle_checkpoint_count_) %
      tls_lifecycle_checkpoints_.size();
  for (std::size_t index = 0U; index < snapshot.count; ++index) {
    snapshot.entries[index] = tls_lifecycle_checkpoints_[
        (first + index) % tls_lifecycle_checkpoints_.size()];
  }
  unlock();
  return snapshot;
}

void Diagnostics::recordHttpStatus(const int status,
                                   const bool rejected_signature,
                                   const bool rate_limited) {
  if (!lock()) {
    return;
  }
  ++http_.requests;
  if (status >= 200 && status < 300) {
    ++http_.status_2xx;
  } else if (status >= 400 && status < 500) {
    ++http_.status_4xx;
  } else if (status >= 500) {
    ++http_.status_5xx;
  }
  http_.rejected_signatures += rejected_signature ? 1U : 0U;
  http_.rate_limited += rate_limited ? 1U : 0U;
  unlock();
}

void Diagnostics::recordBrowserSessionRejection() {
  if (lock()) {
    ++http_.browser_session_rejections;
    unlock();
  }
}

void Diagnostics::recordMalformedAuthHeaderRejection() {
  if (lock()) {
    ++http_.malformed_auth_header_rejections;
    unlock();
  }
}

void Diagnostics::recordBrowserAuth(const BrowserAuthMetric result) {
  if (!lock()) {
    return;
  }
  switch (result) {
  case BrowserAuthMetric::Accepted:
    ++http_.browser_requests_accepted;
    break;
  case BrowserAuthMetric::SessionExpired:
    ++http_.browser_requests_session_expired;
    break;
  case BrowserAuthMetric::SessionInvalid:
    ++http_.browser_requests_session_invalid;
    break;
  case BrowserAuthMetric::CsrfRejected:
    ++http_.browser_requests_csrf_rejected;
    break;
  }
  unlock();
}

void Diagnostics::recordServerHmac(const ServerHmacMetric result) {
  if (!lock()) {
    return;
  }
  switch (result) {
  case ServerHmacMetric::Accepted:
    ++http_.server_hmac_requests_accepted;
    break;
  case ServerHmacMetric::HeadersIncomplete:
    ++http_.server_hmac_headers_incomplete;
    break;
  case ServerHmacMetric::ProtocolMismatch:
    ++http_.server_hmac_protocol_mismatch;
    break;
  case ServerHmacMetric::DeviceMismatch:
    ++http_.server_hmac_device_mismatch;
    break;
  case ServerHmacMetric::TimestampRejected:
    ++http_.server_hmac_timestamp_rejected;
    break;
  case ServerHmacMetric::NonceRejected:
    ++http_.server_hmac_nonce_rejected;
    break;
  case ServerHmacMetric::BodyHashRejected:
    ++http_.server_hmac_body_hash_rejected;
    break;
  case ServerHmacMetric::SignatureRejected:
    ++http_.server_hmac_signature_rejected;
    break;
  }
  unlock();
}

void Diagnostics::recordAuthRateLimit(const bool browser_session) {
  if (lock()) {
    if (browser_session) {
      ++http_.browser_rate_limited;
    } else {
      ++http_.server_hmac_rate_limited;
    }
    unlock();
  }
}

HttpMetrics Diagnostics::httpMetrics() const {
  if (!lock()) {
    return {};
  }
  const HttpMetrics copy = http_;
  unlock();
  return copy;
}

void Diagnostics::setTaskMetrics(
    const std::array<TaskRuntimeMetric, kTaskRuntimeMetricCapacity> &metrics)
    const {
  if (lock()) {
    task_metrics_ = metrics;
    unlock();
  }
}

std::array<TaskRuntimeMetric, kTaskRuntimeMetricCapacity>
Diagnostics::taskMetrics() const {
  if (!lock()) {
    return {};
  }
  const auto copy = task_metrics_;
  unlock();
  return copy;
}

void Diagnostics::recordUiRequest(const UiRequestKind kind) {
  if (!lock()) {
    return;
  }
  switch (kind) {
  case UiRequestKind::Status:
    ++http_.ui_status_requests;
    break;
  case UiRequestKind::Setup:
    ++http_.ui_setup_requests;
    break;
  case UiRequestKind::Diagnostics:
    ++http_.ui_diagnostics_requests;
    break;
  }
  // AsyncWebServer callbacks execute serially per event-loop callback. This
  // counter intentionally captures callback-level concurrency without
  // retaining response/request pointers after the callback returns.
  http_.peak_local_http_requests =
      std::max<std::uint32_t>(http_.peak_local_http_requests, 1U);
  unlock();
}

void Diagnostics::recordUiStatusResponse(
    const std::size_t bytes, const std::uint32_t largest_internal_before,
    const std::uint32_t largest_internal_after,
    const std::uint32_t largest_before_response_object,
    const std::uint32_t largest_after_response_object,
    const std::size_t response_object_bytes) {
  if (lock()) {
    ++http_.ui_status_responses;
    http_.ui_status_response_bytes += bytes;
    ++http_.ui_status_response_object_allocations;
    http_.ui_status_response_object_bytes =
        static_cast<std::uint32_t>(response_object_bytes);
    http_.largest_internal_before_ui = largest_internal_before;
    http_.largest_internal_after_ui = largest_internal_after;
    http_.largest_internal_before_ui_response_object =
        largest_before_response_object;
    http_.largest_internal_after_ui_response_object =
        largest_after_response_object;
    unlock();
  }
}

void Diagnostics::recordUiStatusResponseObjectRelease() {
  if (lock()) {
    ++http_.ui_status_response_object_releases;
    unlock();
  }
}

void Diagnostics::recordUiStatusPoolExhaustion() {
  if (lock()) {
    ++http_.ui_status_pool_exhaustions;
    unlock();
  }
}

void Diagnostics::recordUiStatusDynamicAllocationFailure() {
  if (lock()) {
    ++http_.ui_status_dynamic_allocation_failures;
    unlock();
  }
}

void Diagnostics::recordHeavyUiDeferral() {
  if (lock()) {
    ++http_.ui_heavy_requests_deferred;
    unlock();
  }
}

void Diagnostics::recordLocalResponseAllocationFailure() {
  if (lock()) {
    ++http_.local_response_allocation_failures;
    unlock();
  }
}

std::string Diagnostics::healthJson(const ConfigService &config,
                                    const NetworkStatus &network,
                                    const ClockService &clock,
                                    const StorageHealth &storage,
                                    const MeterMetrics &meter) const {
  MeasurementSnapshot latest;
  const bool has_latest = this->latest(latest);
  const SyncMetrics sync = syncMetrics();
  const RuntimeConfig active_config = config.config();
  const DeviceIdentity identity = config.identity();
  JsonDocument document;
  document["schema_version"] = 1;
  document["protocol"] = version::PROTOCOL;
  document["device_id"] = identity.device_id;
  document["friendly_name"] = active_config.friendly_name;
  document["site_id"] = active_config.site_id;
  document["circuit_id"] = active_config.circuit_id;
  document["parent_circuit_id"] = active_config.parent_circuit_id;
  document["measurement_role"] = active_config.measurement_role;
  const bool storage_healthy =
      storage.writable && storage.sequence_floor_ready &&
      storage.free_bytes >= active_config.storage_warning_free_bytes;
  document["status"] =
      config.safeMode()
          ? "safe_mode"
          : (storage_healthy && meter.last_error == MeterError::None
                 ? "healthy"
                 : "degraded");
  document["uptime_seconds"] = clock.monotonicMs() / 1000U;
  document["boot_id"] = identity.boot_id;
  document["firmware_version"] = version::FIRMWARE;
  document["api_version"] = build::API_VERSION;
  document["safe_mode_reason"] = config.safeModeReason();
  JsonObject wifi = document["wifi"].to<JsonObject>();
  wifi["connected"] = network.station_connected;
  wifi["rssi_dbm"] = network.rssi_dbm;
  wifi["ip_address"] = network.ip_address;
  wifi["subnet"] = network.subnet;
  wifi["gateway"] = network.gateway;
  wifi["dns"] = network.dns;
  wifi["hostname"] = network.hostname;
  JsonObject time = document["time"].to<JsonObject>();
  time["synchronized"] = clock.synchronized();
  time["utc"] = clock.utcIso8601();
  time["last_trusted_utc_ms"] = clock.lastTrustedUtcMs();
  JsonObject meter_json = document["meter"].to<JsonObject>();
  meter_json["connected"] = meter.last_error == MeterError::None;
  meter_json["last_valid_reading_utc"] =
      has_latest && latest.valid ? latest.utc_ms : 0;
  meter_json["consecutive_errors"] = meter.consecutive_errors;
  meter_json["last_error"] = meterErrorCode(meter.last_error);
  JsonObject storage_json = document["storage"].to<JsonObject>();
  storage_json["present"] = storage.present;
  storage_json["mounted"] = storage.mounted;
  storage_json["writable"] = storage.writable;
  storage_json["index_healthy"] = storage.index_healthy;
  storage_json["reading_index_healthy"] = storage.index_healthy;
  storage_json["event_log_healthy"] = storage.event_log_healthy;
  storage_json["event_log_integrity_status"] =
      storage.event_log_integrity_status;
  storage_json["last_error"] = storage.last_error;
  storage_json["sequence_floor_ready"] = storage.sequence_floor_ready;
  storage_json["sequence_reconciliation_in_progress"] =
      storage.sequence_reconciliation_in_progress;
  storage_json["sequence_conflict"] = storage.sequence_conflict;
  storage_json["sequence_floor"] = storage.sequence_floor;
  storage_json["next_sequence"] = storage.next_sequence;
  storage_json["local_record_count"] = storage.local_record_count;
  storage_json["card_empty"] = storage.local_record_count == 0U;
  storage_json["card_replaced_or_initialized"] =
      storage.card_replaced_or_initialized;
  storage_json["card_identity_status"] = storage.card_identity_status;
  storage_json["card_generation"] = storage.card_generation;
  storage_json["last_self_test_passed"] = storage.last_self_test_passed;
  storage_json["free_bytes"] = storage.free_bytes;
  storage_json["warning_free_bytes"] = active_config.storage_warning_free_bytes;
  storage_json["low_space"] =
      storage.mounted &&
      storage.free_bytes < active_config.storage_warning_free_bytes;
  storage_json["last_write_utc"] = storage.last_write_utc_ms;
  storage_json["oldest_sequence"] = storage.oldest_sequence;
  storage_json["newest_sequence"] = storage.newest_sequence;
  storage_json["server_ack_sequence"] = config.serverAckSequence();
  storage_json["server_maximum_seen_sequence"] =
      config.serverMaximumSeenSequence();
  storage_json["prepared_removal_sequence"] =
      config.preparedRemovalSequence();
  storage_json["sequence_floor_advances"] = storage.sequence_floor_advances;
  storage_json["sequence_floor_write_failures"] =
      storage.sequence_floor_write_failures;
  storage_json["sequence_floor_verify_failures"] =
      storage.sequence_floor_verify_failures;
  JsonObject server = document["server"].to<JsonObject>();
  server["configured"] = !active_config.server_url.empty();
  server["reachable"] = network.server_reachable;
  server["authenticated"] = network.server_authenticated;
  server["last_heartbeat_utc"] = sync.last_heartbeat_utc_ms;
  server["sync_in_progress"] = sync.sync_in_progress;
  server["sync_pending"] = sync.sync_pending;
  server["active_request_id"] = sync.active_request_id;
  std::string output;
  serializeJson(document, output);
  return output;
}

std::string Diagnostics::liveJson(const ConfigService &config,
                                  const ClockService &clock,
                                  const char *meter_method) const {
  MeasurementSnapshot sample;
  if (!latest(sample)) {
    return {};
  }
  JsonDocument document;
  document["schema_version"] = 1;
  document["device_id"] = config.identity().device_id;
  document["friendly_name"] = config.config().friendly_name;
  document["sequence"] = committedSequence();
  document["boot_id"] = config.identity().boot_id;
  document["timestamp_utc"] = sample.time_trusted ? clock.utcIso8601() : "";
  document["timestamp_trusted"] = sample.time_trusted;
  document["monotonic_ms"] = sample.monotonic_ms;
  document["voltage_v"] = sample.voltage_v;
  document["current_a"] = sample.current_a;
  document["active_power_w"] = sample.active_power_w;
  document["meter_energy_total_wh"] = sample.raw_energy_wh;
  document["device_lifetime_energy_wh"] = sample.device_lifetime_energy_wh;
  document["frequency_hz"] = sample.frequency_hz;
  document["power_factor"] = sample.power_factor;
  document["ct_rating_a"] = config.config().ct_rating_a;
  JsonObject quality = document["quality"].to<JsonObject>();
  quality["valid"] = sample.valid;
  quality["method"] = meter_method;
  quality["flags_bitmask"] = sample.quality_flags;
  quality["error"] = meterErrorCode(sample.error);
  std::string output;
  serializeJson(document, output);
  return output;
}

std::string Diagnostics::metricsJson(const StorageHealth &storage,
                                     const MeterMetrics &meter) const {
  const QueueMetrics queue = queueMetrics();
  const SyncMetrics sync_metrics = syncMetrics();
  const HttpMetrics http_metrics = httpMetrics();
  const MemoryPressureMetrics memory_pressure = memoryPressureMetrics();
  JsonDocument document;
  document["schema_version"] = 1;
  document["free_heap_bytes"] = ESP.getFreeHeap();
  document["minimum_free_heap_bytes"] = ESP.getMinFreeHeap();
  document["psram_size_bytes"] = ESP.getPsramSize();
  document["free_psram_bytes"] = ESP.getFreePsram();
  JsonObject pressure = document["memory_pressure"].to<JsonObject>();
  pressure["state"] = memoryPressureStateName(memory_pressure.state);
  pressure["state_since_ms"] = memory_pressure.state_since_ms;
  pressure["entry_count"] = memory_pressure.entry_count;
  pressure["recovery_count"] = memory_pressure.recovery_count;
  pressure["transition_count"] = memory_pressure.transition_count;
  pressure["cumulative_pressure_ms"] =
      memory_pressure.cumulative_pressure_ms;
  pressure["longest_pressure_episode_ms"] =
      memory_pressure.longest_pressure_episode_ms;
  pressure["lowest_free_internal_bytes"] =
      memory_pressure.lowest_free_internal_bytes;
  pressure["lowest_largest_internal_block_bytes"] =
      memory_pressure.lowest_largest_internal_block_bytes;
  JsonObject queues = document["queues"].to<JsonObject>();
  queues["storage_depth"] = queue.storage_depth;
  queues["action_depth"] = queue.action_depth;
  queues["storage_dropped"] = queue.storage_dropped;
  queues["action_dropped"] = queue.action_dropped;
  JsonObject pzem = document["pzem"].to<JsonObject>();
  pzem["requests"] = meter.requests;
  pzem["successes"] = meter.successes;
  pzem["crc_errors"] = meter.crc_errors;
  pzem["timeouts"] = meter.timeouts;
  pzem["last_latency_ms"] = meter.last_latency_ms;
  JsonObject sd = document["sd"].to<JsonObject>();
  sd["writes"] = storage.writes;
  sd["reads"] = storage.reads;
  sd["reading_record_reads"] = storage.reading_record_reads;
  sd["event_record_reads"] = storage.event_record_reads;
  sd["write_failures"] = storage.write_failures;
  sd["read_failures"] = storage.read_failures;
  sd["mount_cycles"] = storage.mount_cycles;
  sd["repair_count"] = storage.repair_count;
  JsonObject sync = document["sync"].to<JsonObject>();
  sync["heartbeat_requests_sent"] = sync_metrics.heartbeat_requests_sent;
  sync["heartbeat_http_200"] = sync_metrics.heartbeat_http_200;
  sync["heartbeat_server_accepted"] =
      sync_metrics.heartbeat_server_accepted;
  sync["heartbeat_successes"] = sync_metrics.heartbeat_successes;
  sync["heartbeat_failures"] = sync_metrics.heartbeat_failures;
  sync["heartbeat_transport_successes"] =
      sync_metrics.heartbeat_transport_successes;
  sync["heartbeat_contract_failures"] =
      sync_metrics.heartbeat_contract_failures;
  sync["heartbeat_transport_failures"] =
      sync_metrics.heartbeat_transport_failures;
  sync["heartbeat_authentication_failures"] =
      sync_metrics.heartbeat_authentication_failures;
  sync["sequence_reconciliation_requests"] =
      sync_metrics.sequence_reconciliation_requests;
  sync["sequence_reconciliation_deferred"] =
      sync_metrics.sequence_reconciliation_deferred;
  sync["sequence_reconciliation_failures"] =
      sync_metrics.sequence_reconciliation_failures;
  sync["sequence_cursor_conflicts"] =
      sync_metrics.sequence_cursor_conflicts;
  sync["sequence_cursor_regressions"] =
      sync_metrics.sequence_cursor_regressions;
  sync["batch_successes"] = sync_metrics.batch_successes;
  sync["batch_failures"] = sync_metrics.batch_failures;
  sync["authentication_rejections"] = sync_metrics.authentication_rejections;
  sync["transactions_started"] = sync_metrics.transactions_started;
  sync["transactions_completed"] = sync_metrics.transactions_completed;
  sync["transactions_failed"] = sync_metrics.transactions_failed;
  sync["local_resource_deferrals"] =
      sync_metrics.local_resource_deferrals;
  sync["tls_requests_admitted"] = sync_metrics.tls_requests_admitted;
  sync["tls_requests_rejected_heap"] =
      sync_metrics.tls_requests_rejected_heap;
  sync["tls_requests_rejected_stack"] =
      sync_metrics.tls_requests_rejected_stack;
  sync["in_progress"] = sync_metrics.sync_in_progress;
  sync["pending"] = sync_metrics.sync_pending;
  sync["durable_reading_backlog"] =
      sync_metrics.durable_reading_backlog;
  sync["active_request_id"] = sync_metrics.active_request_id;
  sync["stack_allocated_bytes"] = sync_metrics.stack_allocated_bytes;
  sync["stack_high_water_bytes"] = sync_metrics.stack_high_water_bytes;
  sync["stack_margin_percent"] = sync_metrics.stack_margin_percent;
  sync["free_internal_heap_bytes"] = sync_metrics.free_internal_heap_bytes;
  sync["largest_internal_block_bytes"] =
      sync_metrics.largest_internal_block_bytes;
  sync["minimum_free_internal_heap_bytes"] =
      sync_metrics.minimum_free_internal_heap_bytes;
  JsonObject http = document["http"].to<JsonObject>();
  http["requests"] = http_metrics.requests;
  http["status_2xx"] = http_metrics.status_2xx;
  http["status_4xx"] = http_metrics.status_4xx;
  http["status_5xx"] = http_metrics.status_5xx;
  http["rejected_signatures"] = http_metrics.rejected_signatures;
  http["browser_session_rejections"] =
      http_metrics.browser_session_rejections;
  http["malformed_auth_header_rejections"] =
      http_metrics.malformed_auth_header_rejections;
  http["browser_rate_limited"] = http_metrics.browser_rate_limited;
  http["server_hmac_rate_limited"] =
      http_metrics.server_hmac_rate_limited;
  http["browser_requests_accepted"] = http_metrics.browser_requests_accepted;
  http["browser_requests_session_expired"] =
      http_metrics.browser_requests_session_expired;
  http["browser_requests_session_invalid"] =
      http_metrics.browser_requests_session_invalid;
  http["browser_requests_csrf_rejected"] =
      http_metrics.browser_requests_csrf_rejected;
  http["server_hmac_requests_accepted"] =
      http_metrics.server_hmac_requests_accepted;
  http["server_hmac_headers_incomplete"] =
      http_metrics.server_hmac_headers_incomplete;
  http["server_hmac_protocol_mismatch"] =
      http_metrics.server_hmac_protocol_mismatch;
  http["server_hmac_device_mismatch"] =
      http_metrics.server_hmac_device_mismatch;
  http["server_hmac_timestamp_rejected"] =
      http_metrics.server_hmac_timestamp_rejected;
  http["server_hmac_nonce_rejected"] =
      http_metrics.server_hmac_nonce_rejected;
  http["server_hmac_body_hash_rejected"] =
      http_metrics.server_hmac_body_hash_rejected;
  http["server_hmac_signature_rejected"] =
      http_metrics.server_hmac_signature_rejected;
  http["ui_status_requests"] = http_metrics.ui_status_requests;
  http["ui_status_responses"] = http_metrics.ui_status_responses;
  http["ui_status_response_bytes"] = http_metrics.ui_status_response_bytes;
  http["ui_status_pool_exhaustions"] =
      http_metrics.ui_status_pool_exhaustions;
  http["ui_status_dynamic_allocation_failures"] =
      http_metrics.ui_status_dynamic_allocation_failures;
  http["ui_status_response_object_allocations"] =
      http_metrics.ui_status_response_object_allocations;
  http["ui_status_response_object_releases"] =
      http_metrics.ui_status_response_object_releases;
  http["ui_status_response_object_bytes"] =
      http_metrics.ui_status_response_object_bytes;
  http["largest_internal_before_ui"] =
      http_metrics.largest_internal_before_ui;
  http["largest_internal_after_ui"] =
      http_metrics.largest_internal_after_ui;
  http["largest_internal_before_ui_response_object"] =
      http_metrics.largest_internal_before_ui_response_object;
  http["largest_internal_after_ui_response_object"] =
      http_metrics.largest_internal_after_ui_response_object;
  http["ui_setup_requests"] = http_metrics.ui_setup_requests;
  http["ui_diagnostics_requests"] =
      http_metrics.ui_diagnostics_requests;
  http["ui_heavy_requests_deferred"] =
      http_metrics.ui_heavy_requests_deferred;
  http["local_response_allocation_failures"] =
      http_metrics.local_response_allocation_failures;
  http["peak_local_http_requests"] = http_metrics.peak_local_http_requests;
  std::string output;
  serializeJson(document, output);
  return output;
}

std::string Diagnostics::redactedBundle(const ConfigService &config,
                                        const NetworkStatus &network,
                                        const ClockService &clock,
                                        const StorageHealth &storage,
                                        const MeterMetrics &meter,
                                        const LocalSessionDiagnostics &sessions,
                                        const WifiDisconnectSnapshot &wifi_events) const {
  JsonDocument document;
  document["generated_utc"] = clock.utcIso8601();
  JsonDocument health;
  JsonDocument metrics;
  JsonDocument redacted_config;
  JsonDocument recent_errors;
  deserializeJson(health, healthJson(config, network, clock, storage, meter));
  deserializeJson(metrics, metricsJson(storage, meter));
  deserializeJson(redacted_config, config.redactedJson());
  deserializeJson(recent_errors,
                  diag::SerialLogger::instance().recentErrorsJson());
  document["health"] = health.as<JsonVariantConst>();
  document["metrics"] = metrics.as<JsonVariantConst>();
  document["config"] = redacted_config.as<JsonVariantConst>();
  document["recent_errors"] = recent_errors.as<JsonVariantConst>();
  JsonObject identity = document["build_identity"].to<JsonObject>();
  identity["firmware_version"] = version::FIRMWARE;
  identity["protocol_version"] = version::PROTOCOL;
  identity["git_commit"] = version::GIT_COMMIT;
  identity["build_timestamp"] = version::BUILD_TIMESTAMP;
  identity["platformio_environment"] = version::PLATFORMIO_ENVIRONMENT;
  identity["framework_version"] = ESP.getSdkVersion();
  identity["hardware_target"] = version::HARDWARE_TARGET;
  identity["partition_layout"] = "esp32-s3-n16r8-dual-ota";
  const std::string firmware_sha256 = runningFirmwareSha256();
  if (firmware_sha256.empty()) {
    identity["firmware_binary_sha256"] = nullptr;
    identity["firmware_binary_sha256_reason"] =
        "running_partition_hash_unavailable";
  } else {
    identity["firmware_binary_sha256"] = firmware_sha256;
  }
  identity["elf_sha256"] = nullptr;
  identity["elf_sha256_reason"] =
      "host_only_artifact_see_release_build_provenance";
  JsonObject flags = identity["compile_time_feature_flags"].to<JsonObject>();
  flags["release_build"] = PM_RELEASE_BUILD != 0;
  flags["simulated_meter"] = PM_SIMULATED_METER != 0;
  flags["physical_admin_recovery"] = PM_PHYSICAL_ADMIN_RECOVERY != 0;
  flags["serial_trace"] = PM_SERIAL_TRACE_ENABLED != 0;
  JsonObject dependencies = identity["dependencies"].to<JsonObject>();
  dependencies["platform_espressif32"] = "6.13.0";
  dependencies["arduino_json"] = "7.4.3";
  dependencies["async_tcp"] = "3.4.10";
  dependencies["esp_async_web_server"] = "3.11.2";
  JsonObject assets = identity["embedded_web_assets"].to<JsonObject>();
  const ui::Asset *index_asset = ui::findAsset("/index.html");
  const ui::Asset *script_asset = ui::findAsset("/assets/app.js");
  const ui::Asset *style_asset = ui::findAsset("/assets/style.css");
  assets["index_html_sha256"] =
      index_asset == nullptr ? nullptr : index_asset->sha256;
  assets["app_js_sha256"] =
      script_asset == nullptr ? nullptr : script_asset->sha256;
  assets["style_css_sha256"] =
      style_asset == nullptr ? nullptr : style_asset->sha256;
  JsonObject reset = document["reset_evidence"].to<JsonObject>();
  const int current_reset_reason = static_cast<int>(esp_reset_reason());
  reset["current_reason"] = diag::resetReasonName(current_reset_reason);
  reset["current_reason_code"] = current_reset_reason;
  reset["previous_reason"] = nullptr;
  reset["previous_reason_reason"] =
      "platform_does_not_retain_prior_boot_reset_reason";
  reset["boot_count"] = diag::SerialLogger::instance().bootCount();
  reset["abnormal_reset_count"] =
      diag::SerialLogger::instance().abnormalResetCount();
  JsonObject session_table = document["local_sessions"].to<JsonObject>();
  session_table["capacity"] = sessions.capacity;
  session_table["active"] = sessions.active;
  session_table["peak_active"] = sessions.peak_active;
  session_table["created"] = sessions.created;
  session_table["reused"] = sessions.reused;
  session_table["refreshed"] = sessions.refreshed;
  session_table["expired"] = sessions.expired;
  session_table["invalid"] = sessions.invalid;
  session_table["revoked"] = sessions.revoked;
  session_table["capacity_rejections"] = sessions.capacity_rejections;
  JsonObject flight = document["flight_recorder_excerpt"].to<JsonObject>();
  flight["transition_total"] = wifi_events.total;
  flight["persistent_archive"] =
      "microSD CRC-protected EVT_WIFI_TRANSITION event records";
  JsonArray flight_events = flight["recent_transitions"].to<JsonArray>();
  for (std::size_t index = 0; index < wifi_events.count; ++index) {
    const WifiDisconnectEvent &event = wifi_events.events[index];
    const diag::ReasonInfo reason = diag::wifiDisconnectReason(event.reason);
    JsonObject row = flight_events.add<JsonObject>();
    row["transition_number"] = event.transition_number;
    row["event"] = wifiEventKindName(event.kind);
    row["monotonic_ms"] = event.monotonic_ms;
    row["reason"] = event.reason == 0U ? "none" : reason.name;
    row["reason_code"] = event.reason;
    row["rssi_dbm"] = event.rssi_dbm;
    row["channel"] = event.channel;
    row["bssid"] = diag::maskMac(std::string(event.bssid.data()));
    row["ip_address"] = event.ip_address.data();
    row["gateway"] = event.gateway.data();
    row["dns"] = event.dns.data();
    row["dhcp_duration_ms"] = event.dhcp_duration_ms;
    row["free_internal_heap_bytes"] = event.free_internal_heap_bytes;
    row["largest_internal_block_bytes"] =
        event.largest_internal_block_bytes;
  }
  JsonArray tasks = document["tasks"].to<JsonArray>();
  for (const auto &task : taskMetrics()) {
    if (task.name.empty()) {
      continue;
    }
    JsonObject row = tasks.add<JsonObject>();
    row["name"] = task.name;
    row["core"] = task.core;
    row["priority"] = task.priority;
    row["configured_stack_bytes"] = task.configured_stack_bytes;
    row["high_water_bytes"] = task.high_water_bytes;
    row["margin_percent"] = task.margin_percent;
    row["running"] = task.running;
    row["watchdog"] = task.watchdog;
  }
  document["serial_log_level"] =
      diag::levelName(diag::SerialLogger::instance().level());
  document["serial_log_dropped"] = diag::SerialLogger::instance().dropped();
  document["redaction"] =
      "Wi-Fi passwords, enrollment material, HMAC keys, session tokens, setup "
      "credentials, and signatures are excluded.";
  std::string output;
  serializeJson(document, output);
  return output;
}

bool Diagnostics::lock(const TickType_t timeout) const {
  return mutex_ != nullptr && xSemaphoreTake(mutex_, timeout) == pdTRUE;
}

void Diagnostics::unlock() const { xSemaphoreGive(mutex_); }

} // namespace pm
