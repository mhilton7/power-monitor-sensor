#include "network/ServerSync.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <vector>

#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <esp_system.h>
#include <mbedtls/base64.h>

#include "security/Crypto.h"
#include "version.h"

namespace pm {
namespace {

std::string joinUrl(const std::string& base, const std::string& endpoint) {
  if (!base.empty() && base.back() == '/' && !endpoint.empty() && endpoint.front() == '/') {
    return base.substr(0, base.size() - 1) + endpoint;
  }
  return base + endpoint;
}

void splitEndpoint(const std::string& endpoint, std::string& path,
                   std::vector<std::pair<std::string, std::string>>& query) {
  const std::size_t question = endpoint.find('?');
  path = endpoint.substr(0, question);
  if (question == std::string::npos) {
    return;
  }
  std::size_t cursor = question + 1;
  while (cursor <= endpoint.size()) {
    const std::size_t ampersand = endpoint.find('&', cursor);
    const std::string item = endpoint.substr(cursor, ampersand - cursor);
    const std::size_t equals = item.find('=');
    query.emplace_back(item.substr(0, equals),
                       equals == std::string::npos ? "" : item.substr(equals + 1));
    if (ampersand == std::string::npos) {
      break;
    }
    cursor = ampersand + 1;
  }
}

bool parseHttpsTarget(const std::string& url, std::string& host,
                      std::uint16_t& port) {
  if (url.rfind("https://", 0) != 0) return false;
  const std::size_t start = 8;
  const std::size_t end = url.find('/', start);
  const std::string authority = url.substr(start, end - start);
  if (authority.empty() || authority.find('@') != std::string::npos) return false;
  const std::size_t colon = authority.rfind(':');
  host = colon == std::string::npos ? authority : authority.substr(0, colon);
  port = colon == std::string::npos
             ? 443
             : static_cast<std::uint16_t>(std::strtoul(
                   authority.substr(colon + 1).c_str(), nullptr, 10));
  return !host.empty() && port != 0;
}

const char* resetReasonName() {
  switch (esp_reset_reason()) {
    case ESP_RST_POWERON: return "power_on";
    case ESP_RST_EXT: return "external_reset";
    case ESP_RST_SW: return "software_reset";
    case ESP_RST_PANIC: return "panic";
    case ESP_RST_INT_WDT: return "interrupt_watchdog";
    case ESP_RST_TASK_WDT: return "task_watchdog";
    case ESP_RST_WDT: return "watchdog";
    case ESP_RST_DEEPSLEEP: return "deep_sleep";
    case ESP_RST_BROWNOUT: return "brownout";
    case ESP_RST_SDIO: return "sdio";
    case ESP_RST_UNKNOWN:
    default: return "unknown";
  }
}

bool networkCriticalChanged(const RuntimeConfig& before,
                            const RuntimeConfig& after) {
  return before.server_url != after.server_url ||
         before.server_ca_pem != after.server_ca_pem ||
         before.server_fingerprint != after.server_fingerprint ||
         before.connection_mode != after.connection_mode ||
         before.allowed_server_addresses != after.allowed_server_addresses;
}

bool stationConfigurationChanged(const RuntimeConfig& before,
                                 const RuntimeConfig& after) {
  return before.wifi_ssid != after.wifi_ssid ||
         before.static_network_enabled != after.static_network_enabled ||
         before.static_ip != after.static_ip ||
         before.static_gateway != after.static_gateway ||
         before.static_subnet != after.static_subnet ||
         before.static_dns != after.static_dns;
}

bool hostAllowed(const RuntimeConfig& config, const std::string& host) {
  bool constrained = false;
  for (const auto& allowed : config.allowed_server_addresses) {
    if (allowed.empty()) continue;
    constrained = true;
    if (allowed == host) return true;
  }
  return !constrained;
}

}  // namespace

ServerSync::ServerSync(ConfigService& config, NetworkService& network,
                       ClockService& clock, SdStorage& storage,
                       Diagnostics& diagnostics, IMeter& meter)
    : config_(config),
      network_(network),
      clock_(clock),
      storage_(storage),
      diagnostics_(diagnostics),
      meter_(meter) {}

void ServerSync::tick() {
  const std::uint64_t now = clock_.monotonicMs();
  const NetworkStatus network = network_.status();
  if (!network.station_connected || !clock_.synchronized() ||
      config_.config().server_url.empty() || now < next_retry_ms_) {
    return;
  }
  if (!config_.identity().enrolled) {
    if (!config_.enrollmentToken().empty() && !enroll()) {
      next_retry_ms_ = now + retryDelayMs();
    }
    diagnostics_.setSyncMetrics(metrics_);
    return;
  }
  if (pending_config_validation_) {
    if (network.station_connected && now >= next_config_validation_attempt_ms_ &&
        now - pending_config_started_ms_ >= 2000U &&
        reportConfiguration(pending_config_version_, "applied",
                            "post_apply_connectivity_validated")) {
      pending_config_validation_ = false;
    } else if (now - pending_config_started_ms_ >= 30'000U) {
      const bool restored = config_.rollbackToPrevious();
      pending_config_validation_ = false;
      pending_config_rollback_report_ = restored;
      metrics_.last_error = restored ? "network_config_rolled_back"
                                     : "network_config_rollback_failed";
      if (restored) network_.applyConfiguration();
    } else {
      next_config_validation_attempt_ms_ = now + 2000U;
    }
    diagnostics_.setSyncMetrics(metrics_);
    return;
  }
  if (pending_config_rollback_report_ && network.station_connected &&
      now >= next_config_validation_attempt_ms_) {
    pending_config_rollback_report_ =
        !reportConfiguration(pending_config_version_, "rolled_back",
                             "post_apply_connectivity_failed");
    next_config_validation_attempt_ms_ = now + 5000U;
  }
  if (now >= next_heartbeat_ms_) {
    if (heartbeat()) {
      retry_attempt_ = 0;
      next_heartbeat_ms_ = now + heartbeatDelayMs();
    } else {
      next_retry_ms_ = now + retryDelayMs();
    }
  }
  const ConnectionMode mode = config_.config().connection_mode;
  if ((mode == ConnectionMode::Push || mode == ConnectionMode::Hybrid ||
       immediate_sync_) &&
      config_.serverAckSequence() < storage_.health().newest_sequence) {
    immediate_sync_ = !pushReadings();
  }
  if ((mode == ConnectionMode::Push || mode == ConnectionMode::Hybrid ||
       immediate_sync_) && now >= next_event_push_ms_) {
    if (pushEvents()) {
      next_event_push_ms_ = now + 30'000U;
    } else {
      next_event_push_ms_ = now + retryDelayMs();
    }
  }
  if (now >= next_config_poll_ms_) {
    fetchConfiguration();
    next_config_poll_ms_ = now +
        static_cast<std::uint64_t>(config_.config().sync_interval_seconds) * 1000U;
  }
  if (!config_.safeMode() && now >= next_manifest_poll_ms_) {
    checkFirmwareManifest();
    next_manifest_poll_ms_ = now + 3'600'000U;
  }
  diagnostics_.setSyncMetrics(metrics_);
}

void ServerSync::requestImmediateSync() { immediate_sync_ = true; }

SyncMetrics ServerSync::metrics() const { return metrics_; }

std::string ServerSync::availableFirmwareVersion() const {
  return available_firmware_version_;
}

bool ServerSync::enroll() {
  JsonDocument document;
  document["schema_version"] = 1;
  document["protocol"] = version::PROTOCOL;
  document["enrollment_token"] = config_.enrollmentToken();
  document["local_instance_id"] = config_.identity().local_instance_id;
  document["hardware_id"] = config_.identity().hardware_id;
  document["friendly_name"] = config_.config().friendly_name;
  JsonObject capabilities = document["capabilities"].to<JsonObject>();
  capabilities["hardware_target"] = version::HARDWARE_TARGET;
  capabilities["firmware_version"] = version::FIRMWARE;
  capabilities["micro_sd"] = true;
  capabilities["pull"] = true;
  capabilities["push"] = true;
  capabilities["hybrid"] = true;
  capabilities["signed_ota"] = true;
  std::string body;
  serializeJson(document, body);
  const HttpResult response =
      request("POST", "/api/v1/device-enrollment/claim", body, false);
  if (response.status != 200) {
    metrics_.last_error = response.error.empty() ? "enrollment_rejected" : response.error;
    network_.setServerStatus(response.status > 0, false);
    return false;
  }
  JsonDocument result;
  if (deserializeJson(result, response.body) ||
      std::string(result["protocol"] | "") != version::PROTOCOL) {
    metrics_.last_error = "enrollment_response_invalid";
    return false;
  }
  const std::string device_id = result["device_id"] | "";
  const std::string encoded_secret = result["enrollment_secret"] | "";
  const std::string ota_public_key = result["ota_signing_public_key"] | "";
  RuntimeConfig assigned = config_.config();
  assigned.friendly_name = result["friendly_name"] | assigned.friendly_name.c_str();
  assigned.site_id = result["site_id"] | assigned.site_id.c_str();
  assigned.circuit_id = result["circuit_id"] | assigned.circuit_id.c_str();
  assigned.parent_circuit_id =
      result["parent_circuit_id"] | assigned.parent_circuit_id.c_str();
  assigned.measurement_role =
      result["measurement_role"] | assigned.measurement_role.c_str();
  if (assigned.hostname.rfind("power-monitor-", 0) == 0 &&
      device_id.size() == 36) {
    std::string suffix = device_id;
    suffix.erase(std::remove(suffix.begin(), suffix.end(), '-'), suffix.end());
    assigned.hostname = "power-monitor-" + suffix.substr(suffix.size() - 6);
  }
  assigned.config_version = result["config_version"] | assigned.config_version;
  const std::uint32_t heartbeat_policy =
      result["policy"]["heartbeat_interval_seconds"] |
      (result["heartbeat_interval_seconds"] | assigned.heartbeat_interval_seconds);
  if (heartbeat_policy >= 5U && heartbeat_policy <= 3600U) {
    assigned.heartbeat_interval_seconds = heartbeat_policy;
  }
  const char* policy_mode = result["policy"]["connection_mode"] | nullptr;
  if (policy_mode != nullptr) {
    assigned.connection_mode = std::strcmp(policy_mode, "pull") == 0
                                   ? ConnectionMode::Pull
                                   : (std::strcmp(policy_mode, "push") == 0
                                          ? ConnectionMode::Push
                                          : ConnectionMode::Hybrid);
  }
  const ConfigValidation assigned_validation = config_.validate(assigned, true);
  if (!assigned_validation.valid) {
    metrics_.last_error = "enrollment_assignment_invalid";
    return false;
  }
  std::array<std::uint8_t, 64> secret{};
  std::size_t secret_length = 0;
  if (mbedtls_base64_decode(secret.data(), secret.size(), &secret_length,
                            reinterpret_cast<const std::uint8_t*>(encoded_secret.data()),
                            encoded_secret.size()) != 0 ||
      !config_.saveEnrollment(device_id, secret.data(), secret_length,
                              ota_public_key) ||
      !config_.stage(assigned, true) || !config_.commitStaged()) {
    std::fill(secret.begin(), secret.end(), 0U);
    metrics_.last_error = "enrollment_credentials_invalid";
    return false;
  }
  std::fill(secret.begin(), secret.end(), 0U);
  network_.setServerStatus(true, true);
  next_heartbeat_ms_ = 0;
  return heartbeat();
}

bool ServerSync::heartbeat() {
  const HttpResult response =
      request("POST", "/api/v1/device-heartbeats", heartbeatBody(), true);
  if (response.status != 200) {
    ++metrics_.heartbeat_failures;
    metrics_.last_error = response.error.empty() ? "heartbeat_failed" : response.error;
    network_.setServerStatus(response.status > 0, false);
    if (response.status == 401 || response.status == 403) {
      ++metrics_.authentication_rejections;
    }
    return false;
  }
  JsonDocument document;
  if (deserializeJson(document, response.body)) {
    ++metrics_.heartbeat_failures;
    metrics_.last_error = "heartbeat_response_invalid";
    return false;
  }
  const std::uint64_t acknowledgement = document["ack_sequence"] | 0;
  if (acknowledgement <= storage_.health().newest_sequence) {
    config_.setServerAckSequence(acknowledgement);
  }
  immediate_sync_ = document["synchronize_now"] | immediate_sync_;
  const std::uint32_t recommended =
      document["recommended_heartbeat_interval_seconds"] | 0U;
  heartbeat_interval_override_seconds_ =
      recommended >= 5U && recommended <= 3600U ? recommended : 0U;
  const std::string available = document["available_firmware_version"] | "";
  if (!available.empty()) {
    available_firmware_version_ = available;
  }
  ++metrics_.heartbeat_successes;
  metrics_.last_heartbeat_utc_ms = clock_.utcMs();
  metrics_.last_error.clear();
  network_.setServerStatus(true, true);
  network_.ipChangedSinceHeartbeat();
  return true;
}

bool ServerSync::pushReadings() {
  HistoryQuery query;
  query.after_sequence = config_.serverAckSequence();
  query.limit = 500;
  query.maximum_payload_bytes = 96 * 1024;
  const HistoryPage page = storage_.readPage(query);
  if (!page.ok || page.records.empty()) {
    return page.ok;
  }
  JsonDocument document;
  document["schema_version"] = 1;
  document["protocol"] = version::PROTOCOL;
  document["device_id"] = config_.identity().device_id;
  JsonArray records = document["records"].to<JsonArray>();
  for (const auto& encoded : page.records) {
    JsonDocument record_document;
    if (deserializeJson(record_document, encoded)) {
      metrics_.last_error = "stored_record_json_invalid";
      ++metrics_.batch_failures;
      return false;
    }
    records.add(record_document.as<JsonVariantConst>());
  }
  std::string body;
  serializeJson(document, body);
  const HttpResult response =
      request("POST", "/api/v1/device-readings/batch", body, true);
  if (response.status != 200) {
    ++metrics_.batch_failures;
    metrics_.last_error = response.status == 409 || response.status == 422
                              ? "batch_protocol_fault"
                              : "batch_transient_failure";
    return false;
  }
  JsonDocument result;
  if (deserializeJson(result, response.body)) {
    ++metrics_.batch_failures;
    metrics_.last_error = "batch_response_invalid";
    return false;
  }
  const std::uint64_t acknowledgement = result["ack_sequence"] | 0;
  if (acknowledgement < config_.serverAckSequence() ||
      acknowledgement > storage_.health().newest_sequence ||
      !config_.setServerAckSequence(acknowledgement)) {
    ++metrics_.batch_failures;
    metrics_.last_error = "batch_ack_invalid";
    return false;
  }
  ++metrics_.batch_successes;
  metrics_.last_sync_utc_ms = clock_.utcMs();
  return true;
}

bool ServerSync::pushEvents() {
  HistoryQuery query;
  query.after_sequence = event_cursor_;
  query.limit = 100;
  const HistoryPage page = storage_.readEvents(query);
  if (!page.ok || page.records.empty()) {
    return page.ok;
  }
  JsonDocument document;
  document["schema_version"] = 1;
  document["protocol"] = version::PROTOCOL;
  document["device_id"] = config_.identity().device_id;
  JsonArray events = document["events"].to<JsonArray>();
  for (const auto& encoded : page.records) {
    JsonDocument event_document;
    if (!deserializeJson(event_document, encoded)) {
      events.add(event_document.as<JsonVariantConst>());
    }
  }
  std::string body;
  serializeJson(document, body);
  const HttpResult response =
      request("POST", "/api/v1/device-events/batch", body, true);
  if (response.status == 200 || response.status == 204) {
    event_cursor_ = page.last_sequence;
    ++metrics_.events_successes;
    return true;
  }
  ++metrics_.events_failures;
  return false;
}

bool ServerSync::fetchConfiguration() {
  const HttpResult response =
      request("GET", "/api/v1/device-config/effective", "", true);
  if (response.status != 200) {
    return false;
  }
  JsonDocument document;
  if (deserializeJson(document, response.body)) {
    return false;
  }
  const std::uint32_t requested_version = document["config_version"] | 0;
  if (requested_version <= config_.config().config_version) {
    return true;
  }
  const RuntimeConfig previous = config_.config();
  ConfigValidation validation;
  const bool applied = config_.updateFromJson(response.body, false, false, validation);
  if (applied && stationConfigurationChanged(previous, config_.config())) {
    pending_config_version_ = requested_version;
    pending_config_started_ms_ = clock_.monotonicMs();
    next_config_validation_attempt_ms_ = pending_config_started_ms_ + 2000U;
    pending_config_validation_ = true;
    network_.applyConfiguration();
    return true;
  }
  JsonDocument report;
  report["config_version"] = requested_version;
  report["status"] = applied ? "applied" : "rejected";
  report["detail"] = validation.code;
  std::string body;
  serializeJson(report, body);
  const HttpResult report_response =
      request("POST", "/api/v1/device-config/report", body, true);
  if (applied && networkCriticalChanged(previous, config_.config()) &&
      report_response.status != 200 && report_response.status != 204) {
    const bool restored = config_.rollbackToPrevious();
    report["status"] = "rolled_back";
    report["detail"] = restored ? "server_connectivity_validation_failed"
                                 : "configuration_rollback_failed";
    body.clear();
    serializeJson(report, body);
    request("POST", "/api/v1/device-config/report", body, true);
    metrics_.last_error = restored ? "network_config_rolled_back"
                                   : "network_config_rollback_failed";
    return false;
  }
  return applied &&
         (report_response.status == 200 || report_response.status == 204);
}

bool ServerSync::reportConfiguration(const std::uint32_t version,
                                     const char* status,
                                     const char* detail) {
  JsonDocument report;
  report["config_version"] = version;
  report["status"] = status;
  report["detail"] = detail;
  std::string body;
  serializeJson(report, body);
  const HttpResult response =
      request("POST", "/api/v1/device-config/report", body, true);
  return response.status == 200 || response.status == 204;
}

bool ServerSync::checkFirmwareManifest() {
  const std::string endpoint = "/api/v1/device-firmware/manifest?channel=" +
                               crypto::percentEncode(config_.config().ota_channel) +
                               "&current=" + crypto::percentEncode(version::FIRMWARE);
  const HttpResult response = request("GET", endpoint, "", true);
  if (response.status == 204) {
    available_firmware_version_.clear();
    return true;
  }
  if (response.status != 200) {
    return false;
  }
  JsonDocument document;
  if (deserializeJson(document, response.body)) {
    return false;
  }
  available_firmware_version_ = std::string(document["firmware_version"] | "");
  return !available_firmware_version_.empty();
}

ServerSync::HttpResult ServerSync::request(const char* method,
                                           const std::string& endpoint,
                                           const std::string& body,
                                           const bool authenticated) {
  HttpResult result;
  if (config_.config().server_ca_pem.empty() &&
      config_.config().server_fingerprint.empty()) {
    result.error = "tls_trust_not_configured";
    return result;
  }
  WiFiClientSecure client;
  client.setHandshakeTimeout(8);
  const bool fingerprint_only = config_.config().server_ca_pem.empty();
  if (!fingerprint_only) {
    client.setCACert(config_.config().server_ca_pem.c_str());
  } else {
    client.setInsecure();
  }
  HTTPClient http;
  http.setConnectTimeout(5000);
  http.setTimeout(10000);
  http.setReuse(false);
  const std::string url = joinUrl(config_.config().server_url, endpoint);
  std::string target_host;
  std::uint16_t target_port = 443;
  if (!parseHttpsTarget(url, target_host, target_port) ||
      !hostAllowed(config_.config(), target_host)) {
    result.error = "server_address_not_allowed";
    return result;
  }
  if (!http.begin(client, url.c_str())) {
    result.error = "http_begin_failed";
    return result;
  }
  if (fingerprint_only) {
    std::string host;
    std::uint16_t port = 443;
    if (!parseHttpsTarget(url, host, port) ||
        !client.connect(host.c_str(), port, 5000) ||
        !client.verify(config_.config().server_fingerprint.c_str(), host.c_str())) {
      client.stop();
      http.end();
      result.error = "tls_fingerprint_verification_failed";
      return result;
    }
  }
  http.addHeader("Content-Type", "application/json");
  if (authenticated) {
    crypto::Key32 outbound{};
    crypto::Key32 inbound{};
    if (!config_.directionalKeys(outbound, inbound)) {
      http.end();
      result.error = "device_credentials_unavailable";
      return result;
    }
    const std::string timestamp = std::to_string(std::time(nullptr));
    const std::string nonce = crypto::randomHex(16);
    const std::string body_hash = crypto::sha256Hex(
        reinterpret_cast<const std::uint8_t*>(body.data()), body.size());
    std::string path;
    std::vector<std::pair<std::string, std::string>> query;
    splitEndpoint(endpoint, path, query);
    const std::string canonical = crypto::canonicalRequest(
        method, crypto::canonicalPathQuery(path, query), timestamp, nonce,
        body_hash);
    http.addHeader("X-PM-Protocol", version::PROTOCOL);
    http.addHeader("X-PM-Device-ID", config_.identity().device_id.c_str());
    http.addHeader("X-PM-Timestamp", timestamp.c_str());
    http.addHeader("X-PM-Nonce", nonce.c_str());
    http.addHeader("X-PM-Content-SHA256", body_hash.c_str());
    http.addHeader("X-PM-Signature",
                   crypto::hmacSha256Hex(outbound.data(), outbound.size(), canonical).c_str());
  } else {
    http.addHeader("X-PM-Protocol", version::PROTOCOL);
  }
  if (std::string(method) == "GET") {
    result.status = http.GET();
  } else {
    result.status = http.sendRequest(method,
                                     reinterpret_cast<std::uint8_t*>(const_cast<char*>(body.data())),
                                     body.size());
  }
  if (result.status > 0) {
    const String response = http.getString();
    if (response.length() <= 128 * 1024) {
      result.body = response.c_str();
    } else {
      result.error = "response_too_large";
      result.status = -1;
    }
  } else {
    result.error = HTTPClient::errorToString(result.status).c_str();
  }
  http.end();
  return result;
}

std::string ServerSync::heartbeatBody() const {
  const NetworkStatus network = network_.status();
  const StorageHealth storage = storage_.health();
  const MeterMetrics meter = meter_.metrics();
  MeasurementSnapshot latest;
  const bool has_latest = diagnostics_.latest(latest);
  JsonDocument document;
  document["schema_version"] = 1;
  document["protocol"] = version::PROTOCOL;
  document["device_id"] = config_.identity().device_id;
  document["boot_id"] = config_.identity().boot_id;
  document["firmware_version"] = version::FIRMWARE;
  document["build_hash"] = version::GIT_COMMIT;
  document["uptime_seconds"] = clock_.monotonicMs() / 1000U;
  document["reboot_reason"] = resetReasonName();
  document["configuration_version"] = config_.config().config_version;
  JsonObject wifi = document["wifi"].to<JsonObject>();
  wifi["connected"] = network.station_connected;
  wifi["ip_address"] = network.ip_address;
  wifi["hostname"] = network.hostname;
  wifi["rssi_dbm"] = network.rssi_dbm;
  JsonObject time = document["time"].to<JsonObject>();
  time["synchronized"] = clock_.synchronized();
  time["utc"] = clock_.utcIso8601();
  JsonObject meter_json = document["meter"].to<JsonObject>();
  meter_json["connected"] = meter.last_error == MeterError::None;
  meter_json["consecutive_errors"] = meter.consecutive_errors;
  meter_json["last_error"] = meterErrorCode(meter.last_error);
  if (has_latest) {
    JsonObject live = document["latest"].to<JsonObject>();
    live["timestamp_utc_ms"] = latest.utc_ms;
    live["timestamp_trusted"] = latest.time_trusted;
    live["voltage_v"] = latest.voltage_v;
    live["current_a"] = latest.current_a;
    live["active_power_w"] = latest.active_power_w;
    live["meter_energy_total_wh"] = latest.raw_energy_wh;
    live["device_lifetime_energy_wh"] = latest.device_lifetime_energy_wh;
    live["frequency_hz"] = latest.frequency_hz;
    live["power_factor"] = latest.power_factor;
    live["quality_flags"] = latest.quality_flags;
  }
  JsonObject storage_json = document["storage"].to<JsonObject>();
  storage_json["present"] = storage.present;
  storage_json["mounted"] = storage.mounted;
  storage_json["writable"] = storage.writable;
  storage_json["free_bytes"] = storage.free_bytes;
  storage_json["oldest_sequence"] = storage.oldest_sequence;
  storage_json["newest_sequence"] = storage.newest_sequence;
  JsonObject sync = document["sync"].to<JsonObject>();
  sync["server_ack_sequence"] = config_.serverAckSequence();
  sync["backlog_estimate"] = storage.newest_sequence >= config_.serverAckSequence()
                                  ? storage.newest_sequence - config_.serverAckSequence()
                                  : 0;
  sync["mode"] = connectionModeName(config_.config().connection_mode);
  JsonObject resources = document["resources"].to<JsonObject>();
  resources["free_heap_bytes"] = ESP.getFreeHeap();
  resources["minimum_free_heap_bytes"] = ESP.getMinFreeHeap();
  JsonObject queues = resources["queue_depths"].to<JsonObject>();
  const QueueMetrics queue_metrics = diagnostics_.queueMetrics();
  queues["storage"] = queue_metrics.storage_depth;
  queues["actions"] = queue_metrics.action_depth;
  queues["storage_dropped"] = queue_metrics.storage_dropped;
  queues["actions_dropped"] = queue_metrics.action_dropped;
  std::string output;
  serializeJson(document, output);
  return output;
}

std::uint32_t ServerSync::heartbeatDelayMs() const {
  const std::uint32_t seconds = heartbeat_interval_override_seconds_ == 0
                                    ? config_.config().heartbeat_interval_seconds
                                    : heartbeat_interval_override_seconds_;
  const std::uint32_t base = seconds * 1000U;
  std::array<std::uint8_t, 2> random{};
  crypto::secureRandom(random.data(), random.size());
  const std::uint32_t jitter =
      ((static_cast<std::uint32_t>(random[0]) << 8U) | random[1]) %
      (base / 10U + 1U);
  return base + jitter;
}

std::uint32_t ServerSync::retryDelayMs() {
  const std::uint32_t exponent = std::min<std::uint32_t>(retry_attempt_++, 10);
  const std::uint32_t maximum = config_.config().sync_retry_max_seconds * 1000U;
  const std::uint32_t base = std::min<std::uint32_t>(1000U << exponent, maximum);
  std::array<std::uint8_t, 2> random{};
  crypto::secureRandom(random.data(), random.size());
  const std::uint32_t jitter =
      ((static_cast<std::uint32_t>(random[0]) << 8U) | random[1]) % (base / 5U + 1U);
  return base + jitter;
}

}  // namespace pm
