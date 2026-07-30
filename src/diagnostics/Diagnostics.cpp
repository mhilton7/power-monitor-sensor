#include "diagnostics/Diagnostics.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <ESP.h>

#include "build_config.h"
#include "diagnostics/SerialLogger.h"
#include "version.h"

namespace pm {

Diagnostics::Diagnostics() { mutex_ = xSemaphoreCreateMutex(); }

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

HttpMetrics Diagnostics::httpMetrics() const {
  if (!lock()) {
    return {};
  }
  const HttpMetrics copy = http_;
  unlock();
  return copy;
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
      storage.writable &&
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
  storage_json["free_bytes"] = storage.free_bytes;
  storage_json["warning_free_bytes"] = active_config.storage_warning_free_bytes;
  storage_json["low_space"] =
      storage.mounted &&
      storage.free_bytes < active_config.storage_warning_free_bytes;
  storage_json["last_write_utc"] = storage.last_write_utc_ms;
  storage_json["oldest_sequence"] = storage.oldest_sequence;
  storage_json["newest_sequence"] = storage.newest_sequence;
  storage_json["server_ack_sequence"] = config.serverAckSequence();
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
  JsonDocument document;
  document["schema_version"] = 1;
  document["free_heap_bytes"] = ESP.getFreeHeap();
  document["minimum_free_heap_bytes"] = ESP.getMinFreeHeap();
  document["psram_size_bytes"] = ESP.getPsramSize();
  document["free_psram_bytes"] = ESP.getFreePsram();
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
  sd["write_failures"] = storage.write_failures;
  sd["read_failures"] = storage.read_failures;
  sd["mount_cycles"] = storage.mount_cycles;
  sd["repair_count"] = storage.repair_count;
  JsonObject sync = document["sync"].to<JsonObject>();
  sync["heartbeat_successes"] = sync_metrics.heartbeat_successes;
  sync["heartbeat_failures"] = sync_metrics.heartbeat_failures;
  sync["batch_successes"] = sync_metrics.batch_successes;
  sync["batch_failures"] = sync_metrics.batch_failures;
  sync["authentication_rejections"] = sync_metrics.authentication_rejections;
  sync["transactions_started"] = sync_metrics.transactions_started;
  sync["transactions_completed"] = sync_metrics.transactions_completed;
  sync["transactions_failed"] = sync_metrics.transactions_failed;
  sync["in_progress"] = sync_metrics.sync_in_progress;
  sync["pending"] = sync_metrics.sync_pending;
  sync["active_request_id"] = sync_metrics.active_request_id;
  sync["stack_allocated_bytes"] = sync_metrics.stack_allocated_bytes;
  sync["stack_high_water_bytes"] = sync_metrics.stack_high_water_bytes;
  sync["stack_margin_percent"] = sync_metrics.stack_margin_percent;
  sync["free_internal_heap_bytes"] = sync_metrics.free_internal_heap_bytes;
  sync["largest_internal_block_bytes"] =
      sync_metrics.largest_internal_block_bytes;
  JsonObject http = document["http"].to<JsonObject>();
  http["requests"] = http_metrics.requests;
  http["status_2xx"] = http_metrics.status_2xx;
  http["status_4xx"] = http_metrics.status_4xx;
  http["status_5xx"] = http_metrics.status_5xx;
  http["rejected_signatures"] = http_metrics.rejected_signatures;
  std::string output;
  serializeJson(document, output);
  return output;
}

std::string Diagnostics::redactedBundle(const ConfigService &config,
                                        const NetworkStatus &network,
                                        const ClockService &clock,
                                        const StorageHealth &storage,
                                        const MeterMetrics &meter) const {
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
