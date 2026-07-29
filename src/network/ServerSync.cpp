#include "network/ServerSync.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <vector>

#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <esp_system.h>
#include <mbedtls/base64.h>
#include <mbedtls/x509_crt.h>

#include "diagnostics/DiagnosticCore.h"
#include "diagnostics/SerialLogger.h"
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

void logCaMetadata(const std::string& pem) {
  mbedtls_x509_crt certificate;
  mbedtls_x509_crt_init(&certificate);
  const int result = mbedtls_x509_crt_parse(
      &certificate, reinterpret_cast<const unsigned char*>(pem.c_str()),
      pem.size() + 1U);
  if (result != 0) {
    PM_LOG_ERROR_CODE("TLS", "CA_PARSE_FAILED", result,
                      "error=PM-TLS-002 category=CA_PEM_INVALID mbedtls=%d",
                      result);
    mbedtls_x509_crt_free(&certificate);
    return;
  }
  char subject[192]{};
  char issuer[192]{};
  mbedtls_x509_dn_gets(subject, sizeof(subject), &certificate.subject);
  mbedtls_x509_dn_gets(issuer, sizeof(issuer), &certificate.issuer);
  const std::string fingerprint = crypto::sha256Hex(
      certificate.raw.p, certificate.raw.len);
  PM_LOG_DEBUG(
      "TLS", "CA_METADATA",
      "subject=%s issuer=%s valid_from=%04d-%02d-%02d valid_to=%04d-%02d-%02d sha256_prefix=%s",
      subject, issuer, certificate.valid_from.year,
      certificate.valid_from.mon, certificate.valid_from.day,
      certificate.valid_to.year, certificate.valid_to.mon,
      certificate.valid_to.day, fingerprint.substr(0, 16).c_str());
  mbedtls_x509_crt_free(&certificate);
}

std::string isoUtc(const std::uint64_t utc_ms) {
  const std::time_t seconds = static_cast<std::time_t>(utc_ms / 1000U);
  std::tm broken_down{};
  gmtime_r(&seconds, &broken_down);
  char output[25]{};
  std::strftime(output, sizeof(output), "%Y-%m-%dT%H:%M:%SZ",
                &broken_down);
  return output;
}

void addQualityFlags(const std::uint32_t flags, JsonArray output) {
  const std::array<std::pair<std::uint32_t, const char*>, 11> names{{
      {TimeUntrusted, "time_untrusted"},
      {MeterGap, "meter_gap"},
      {EnergyIntegrated, "energy_integrated"},
      {EnergyIncomplete, "energy_incomplete"},
      {CounterReset, "counter_reset"},
      {CtWarning80, "ct_warning_80"},
      {CtWarning90, "ct_warning_90"},
      {CtOverRange, "ct_over_range"},
      {VoltageOutOfRange, "voltage_out_of_range"},
      {FrequencyOutOfRange, "frequency_out_of_range"},
      {CounterRollover, "counter_rollover"},
  }};
  for (const auto& item : names) {
    if ((flags & item.first) != 0U) {
      output.add(item.second);
    }
  }
}

const char* eventCategory(const std::string& code) {
  if (code.find("BOOT") != std::string::npos) return "boot";
  if (code.find("PZEM") != std::string::npos ||
      code.find("METER") != std::string::npos) {
    return "pzem";
  }
  if (code.find("CT_") != std::string::npos) return "ct_limit";
  if (code.find("SD_") != std::string::npos ||
      code.find("STORAGE") != std::string::npos) {
    return "sd";
  }
  if (code.find("TIME") != std::string::npos ||
      code.find("NTP") != std::string::npos) {
    return "time";
  }
  if (code.find("CONFIG") != std::string::npos) return "configuration";
  if (code.find("OTA") != std::string::npos) return "ota";
  if (code.find("AUTH") != std::string::npos ||
      code.find("CREDENTIAL") != std::string::npos ||
      code.find("TLS") != std::string::npos) {
    return "security";
  }
  return "network";
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
    if (offline_since_ms_ == 0) offline_since_ms_ = now;
    if (diag::SerialLogger::instance().allow("server_offline", 60'000U)) {
      PM_LOG_INFO(
          "SERVER", "OFFLINE_SUMMARY",
          "duration_ms=%llu wifi=%s time_trusted=%s configured=%s retry_in_ms=%llu retry_attempt=%lu backlog=%llu",
          static_cast<unsigned long long>(now - offline_since_ms_),
          network.station_connected ? "connected" : "offline",
          clock_.synchronized() ? "true" : "false",
          config_.config().server_url.empty() ? "false" : "true",
          static_cast<unsigned long long>(
              now < next_retry_ms_ ? next_retry_ms_ - now : 0),
          static_cast<unsigned long>(retry_attempt_),
          static_cast<unsigned long long>(
              storage_.health().newest_sequence >= config_.serverAckSequence()
                  ? storage_.health().newest_sequence -
                        config_.serverAckSequence()
                  : 0));
    }
    return;
  }
  if (offline_since_ms_ != 0) {
    PM_LOG_INFO("SERVER", "SYNC_RESUMED",
                "offline_duration_ms=%llu retry_attempt=%lu",
                static_cast<unsigned long long>(now - offline_since_ms_),
                static_cast<unsigned long>(retry_attempt_));
    offline_since_ms_ = 0;
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

void ServerSync::requestImmediateSync() {
  immediate_sync_ = true;
  PM_LOG_INFO("SYNC", "IMMEDIATE_SYNC_REQUESTED", "source=local_action");
}

SyncMetrics ServerSync::metrics() const { return metrics_; }

std::string ServerSync::availableFirmwareVersion() const {
  return available_firmware_version_;
}

bool ServerSync::enroll() {
  PM_LOG_INFO(
      "ENROLL", "ENROLLMENT_BEGIN",
      "local_instance=%s hardware=%s protocol=%s token=redacted",
      diag::maskIdentifier(config_.identity().local_instance_id).c_str(),
      diag::maskIdentifier(config_.identity().hardware_id).c_str(),
      version::PROTOCOL);
  JsonDocument document;
  document["token"] = config_.enrollmentToken();
  document["protocol_version"] = version::PROTOCOL;
  document["hardware_id"] = config_.identity().hardware_id;
  document["requested_name"] = config_.config().friendly_name;
  JsonObject capabilities = document["capabilities"].to<JsonObject>();
  capabilities["hardware_target"] = version::HARDWARE_TARGET;
  capabilities["pzem_model"] = "PZEM-004T V4";
  capabilities["sd_present"] = true;
  capabilities["sd_required"] = true;
  JsonArray endpoints = capabilities["supported_endpoints"].to<JsonArray>();
  endpoints.add("/api/v1/health");
  endpoints.add("/api/v1/live");
  endpoints.add("/api/v1/readings");
  endpoints.add("/api/v1/config");
  endpoints.add("/api/v1/firmware");
  std::string body;
  serializeJson(document, body);
  const HttpResult response =
      request("POST", "/api/v1/device-enrollment/claim", body, false);
  if (response.status != 201 && response.status != 200) {
    metrics_.last_error = response.error.empty() ? "enrollment_rejected" : response.error;
    network_.setServerStatus(response.status > 0, false);
    PM_LOG_ERROR(
        "ENROLL", "ENROLLMENT_REJECTED",
        "error=PM-ENROLL-001 http_status=%d category=%s transport=%s",
        response.status, diag::httpStatusCategory(response.status),
        response.error.empty() ? "none" : response.error.c_str());
    return false;
  }
  JsonDocument result;
  if (deserializeJson(result, response.body)) {
    metrics_.last_error = "enrollment_response_invalid";
    PM_LOG_ERROR("ENROLL", "RESPONSE_INVALID",
                 "error=PM-ENROLL-002 protocol_match=false");
    return false;
  }
  const bool current_contract = result["protocol_version"].is<const char*>();
  const std::string response_protocol =
      current_contract ? std::string(result["protocol_version"] | "")
                       : std::string(result["protocol"] | "");
  if (response_protocol != version::PROTOCOL) {
    metrics_.last_error = "enrollment_response_invalid";
    PM_LOG_ERROR("ENROLL", "RESPONSE_INVALID",
                 "error=PM-ENROLL-002 protocol_match=false");
    return false;
  }
  const std::string device_id = result["device_id"] | "";
  const std::string encoded_secret = result["enrollment_secret"] | "";
  std::string ota_public_key = result["server_ota_signing_public_key"] | "";
  if (ota_public_key.empty()) {
    ota_public_key = result["ota_signing_public_key"] | "";
  }
  RuntimeConfig assigned = config_.config();
  JsonObjectConst metadata = result["effective_metadata"].as<JsonObjectConst>();
  if (!metadata.isNull()) {
    assigned.friendly_name = metadata["name"] | assigned.friendly_name.c_str();
    assigned.site_id = metadata["site_id"] | assigned.site_id.c_str();
    assigned.circuit_id = metadata["circuit_id"] | assigned.circuit_id.c_str();
    assigned.measurement_role =
        metadata["measurement_role"] | assigned.measurement_role.c_str();
    if (!metadata["ct_rating_amps"].isNull()) {
      assigned.ct_rating_a = metadata["ct_rating_amps"].as<float>();
    }
  } else {
    assigned.friendly_name = result["friendly_name"] | assigned.friendly_name.c_str();
    assigned.site_id = result["site_id"] | assigned.site_id.c_str();
    assigned.circuit_id = result["circuit_id"] | assigned.circuit_id.c_str();
    assigned.parent_circuit_id =
        result["parent_circuit_id"] | assigned.parent_circuit_id.c_str();
    assigned.measurement_role =
        result["measurement_role"] | assigned.measurement_role.c_str();
  }
  if (assigned.hostname.rfind("power-monitor-", 0) == 0 &&
      device_id.size() == 36) {
    std::string suffix = device_id;
    suffix.erase(std::remove(suffix.begin(), suffix.end(), '-'), suffix.end());
    assigned.hostname = "power-monitor-" + suffix.substr(suffix.size() - 6);
  }
  assigned.config_version = result["config_version"] | assigned.config_version;
  const std::uint32_t heartbeat_policy =
      result["heartbeat_policy"]["expected_seconds"] |
      (result["policy"]["heartbeat_interval_seconds"] |
       (result["heartbeat_interval_seconds"] |
        assigned.heartbeat_interval_seconds));
  if (heartbeat_policy >= 5U && heartbeat_policy <= 3600U) {
    assigned.heartbeat_interval_seconds = heartbeat_policy;
  }
  const std::uint32_t durable_policy =
      result["sync_policy"]["durable_interval_seconds"] | 0U;
  if (durable_policy >= 10U && durable_policy <= 3600U) {
    assigned.durable_log_interval_seconds = durable_policy;
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
    PM_LOG_ERROR("ENROLL", "ASSIGNMENT_REJECTED",
                 "error=PM-ENROLL-003 validation=%s",
                 assigned_validation.code.c_str());
    return false;
  }
  std::array<std::uint8_t, 64> secret{};
  std::size_t secret_length = 0;
  bool secret_valid = false;
  if (current_contract && encoded_secret.size() >= 32U &&
      encoded_secret.size() <= secret.size()) {
    secret_length = encoded_secret.size();
    std::memcpy(secret.data(), encoded_secret.data(), secret_length);
    secret_valid = true;
  } else if (!current_contract &&
             mbedtls_base64_decode(
                 secret.data(), secret.size(), &secret_length,
                 reinterpret_cast<const std::uint8_t*>(encoded_secret.data()),
                 encoded_secret.size()) == 0) {
    secret_valid = true;
  }
  if (!secret_valid ||
      !config_.saveEnrollment(device_id, secret.data(), secret_length,
                              ota_public_key) ||
      !config_.stage(assigned, true) || !config_.commitStaged()) {
    std::fill(secret.begin(), secret.end(), 0U);
    metrics_.last_error = "enrollment_credentials_invalid";
    PM_LOG_ERROR("ENROLL", "CREDENTIAL_SAVE_FAILED",
                 "error=PM-ENROLL-004 credentials=redacted");
    return false;
  }
  std::fill(secret.begin(), secret.end(), 0U);
  network_.setServerStatus(true, true);
  PM_LOG_INFO(
      "ENROLL", "ENROLLMENT_COMPLETE",
      "device=%s friendly_name=%s config_version=%lu credentials=stored",
      diag::maskIdentifier(device_id).c_str(),
      assigned.friendly_name.c_str(),
      static_cast<unsigned long>(assigned.config_version));
  next_heartbeat_ms_ = 0;
  return heartbeat();
}

bool ServerSync::heartbeat() {
  PM_LOG_DEBUG("HEARTBEAT", "HEARTBEAT_BEGIN",
               "ack_sequence=%llu",
               static_cast<unsigned long long>(config_.serverAckSequence()));
  const HttpResult response =
      request("POST", "/api/v1/device-heartbeats", heartbeatBody(), true);
  if (response.status != 200) {
    ++metrics_.heartbeat_failures;
    metrics_.last_error = response.error.empty() ? "heartbeat_failed" : response.error;
    network_.setServerStatus(response.status > 0, false);
    if (response.status == 401 || response.status == 403) {
      ++metrics_.authentication_rejections;
    }
    PM_LOG_WARN(
        "HEARTBEAT", "HEARTBEAT_FAILED",
        "error=PM-SERVER-001 status=%d category=%s failures=%llu retry_attempt=%lu",
        response.status, diag::httpStatusCategory(response.status),
        static_cast<unsigned long long>(metrics_.heartbeat_failures),
        static_cast<unsigned long>(retry_attempt_));
    return false;
  }
  JsonDocument document;
  if (deserializeJson(document, response.body)) {
    ++metrics_.heartbeat_failures;
    metrics_.last_error = "heartbeat_response_invalid";
    PM_LOG_ERROR("HEARTBEAT", "RESPONSE_INVALID",
                 "error=PM-SERVER-002");
    return false;
  }
  const std::uint64_t acknowledgement =
      document["highest_contiguous_accepted_sequence"] |
      (document["ack_sequence"] | 0);
  if (acknowledgement <= storage_.health().newest_sequence) {
    config_.setServerAckSequence(acknowledgement);
  }
  immediate_sync_ =
      document["immediate_sync_requested"] |
      (document["synchronize_now"] | immediate_sync_);
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
  PM_LOG_INFO(
      "HEARTBEAT", "HEARTBEAT_COMPLETE",
      "successes=%llu ack_sequence=%llu synchronize_now=%s next_interval_ms=%lu",
      static_cast<unsigned long long>(metrics_.heartbeat_successes),
      static_cast<unsigned long long>(acknowledgement),
      immediate_sync_ ? "true" : "false",
      static_cast<unsigned long>(heartbeatDelayMs()));
  return true;
}

bool ServerSync::pushReadings() {
  HistoryQuery query;
  query.after_sequence = config_.serverAckSequence();
  query.limit = 500;
  query.maximum_payload_bytes = 96 * 1024;
  const HistoryPage page = storage_.readPage(query);
  if (!page.ok || page.records.empty()) {
    if (!page.ok) {
      PM_LOG_WARN("SYNC", "READ_BATCH_LOAD_FAILED",
                  "error=PM-SYNC-001 storage_error=%s",
                  page.error_code.c_str());
    }
    return page.ok;
  }
  PM_LOG_INFO(
      "SYNC", "READ_BATCH_BEGIN",
      "records=%u first_sequence=%llu last_sequence=%llu has_more=%s",
      static_cast<unsigned>(page.records.size()),
      static_cast<unsigned long long>(page.first_sequence),
      static_cast<unsigned long long>(page.last_sequence),
      page.has_more ? "true" : "false");
  JsonDocument document;
  document["schema_version"] = "reading-batch/1.0.0";
  document["protocol_version"] = version::PROTOCOL;
  document["device_id"] = config_.identity().device_id;
  JsonArray records = document["readings"].to<JsonArray>();
  for (const auto& encoded : page.records) {
    JsonDocument record_document;
    if (deserializeJson(record_document, encoded)) {
      metrics_.last_error = "stored_record_json_invalid";
      ++metrics_.batch_failures;
      PM_LOG_ERROR("SYNC", "STORED_RECORD_INVALID",
                   "error=PM-SYNC-002");
      return false;
    }
    JsonObject record = records.add<JsonObject>();
    record["sequence"] = record_document["sequence"];
    record["boot_id"] = record_document["boot_id"];
    record["interval_start"] = record_document["start_utc"];
    record["interval_end"] = record_document["end_utc"];
    record["time_trusted"] = record_document["time_trusted"];
    record["voltage_avg"] = record_document["voltage_v"]["average"];
    record["voltage_min"] = record_document["voltage_v"]["minimum"];
    record["voltage_max"] = record_document["voltage_v"]["maximum"];
    record["current_avg"] = record_document["current_a"]["average"];
    record["current_min"] = record_document["current_a"]["minimum"];
    record["current_max"] = record_document["current_a"]["maximum"];
    record["power_avg"] = record_document["active_power_w"]["average"];
    record["power_min"] = record_document["active_power_w"]["minimum"];
    record["power_max"] = record_document["active_power_w"]["maximum"];
    record["power_factor"] = record_document["average_power_factor"];
    record["frequency_hz"] = record_document["average_frequency_hz"];
    record["pzem_energy_start_wh"] = record_document["raw_energy_start_wh"];
    record["pzem_energy_end_wh"] = record_document["raw_energy_end_wh"];
    record["device_lifetime_energy_wh"] =
        record_document["device_lifetime_energy_wh"];
    record["interval_energy_wh"] = record_document["interval_energy_wh"];
    record["energy_method"] = record_document["energy_method"];
    record["ct_rating_amps"] = record_document["ct_rating_a"];
    addQualityFlags(record_document["quality_flags"] | 0U,
                    record["quality_flags"].to<JsonArray>());
    record["firmware_version"] = record_document["firmware_version"];
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
    PM_LOG_WARN(
        "SYNC", "READ_BATCH_FAILED",
        "error=PM-SYNC-003 status=%d category=%s records=%u failures=%llu",
        response.status, diag::httpStatusCategory(response.status),
        static_cast<unsigned>(page.records.size()),
        static_cast<unsigned long long>(metrics_.batch_failures));
    return false;
  }
  JsonDocument result;
  if (deserializeJson(result, response.body)) {
    ++metrics_.batch_failures;
    metrics_.last_error = "batch_response_invalid";
    return false;
  }
  const std::uint64_t acknowledgement =
      result["highest_contiguous_accepted_sequence"] |
      (result["ack_sequence"] | 0);
  if (acknowledgement < config_.serverAckSequence() ||
      acknowledgement > storage_.health().newest_sequence ||
      !config_.setServerAckSequence(acknowledgement)) {
    ++metrics_.batch_failures;
    metrics_.last_error = "batch_ack_invalid";
    return false;
  }
  ++metrics_.batch_successes;
  metrics_.last_sync_utc_ms = clock_.utcMs();
  PM_LOG_INFO(
      "SYNC", "READ_BATCH_COMPLETE",
      "records=%u ack_sequence=%llu has_more=%s successes=%llu",
      static_cast<unsigned>(page.records.size()),
      static_cast<unsigned long long>(acknowledgement),
      page.has_more ? "true" : "false",
      static_cast<unsigned long long>(metrics_.batch_successes));
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
  PM_LOG_INFO("SYNC", "EVENT_BATCH_BEGIN",
              "events=%u first_sequence=%llu last_sequence=%llu",
              static_cast<unsigned>(page.records.size()),
              static_cast<unsigned long long>(page.first_sequence),
              static_cast<unsigned long long>(page.last_sequence));
  JsonDocument document;
  document["protocol_version"] = version::PROTOCOL;
  document["device_id"] = config_.identity().device_id;
  JsonArray events = document["events"].to<JsonArray>();
  for (const auto& encoded : page.records) {
    JsonDocument event_document;
    if (!deserializeJson(event_document, encoded)) {
      const std::uint64_t sequence = event_document["event_sequence"] | 0U;
      const std::string boot_id = event_document["boot_id"] | "";
      const std::string code = event_document["code"] | "EVT_UNKNOWN";
      JsonObject event = events.add<JsonObject>();
      event["event_id"] = boot_id + "-" + std::to_string(sequence);
      event["occurred_at"] = event_document["timestamp_utc"];
      event["category"] = eventCategory(code);
      event["severity"] = event_document["severity"];
      JsonObject evidence = event["evidence"].to<JsonObject>();
      evidence["code"] = code;
      evidence["detail"] = event_document["detail"];
      evidence["boot_id"] = boot_id;
      evidence["event_sequence"] = sequence;
    }
  }
  std::string body;
  serializeJson(document, body);
  const HttpResult response =
      request("POST", "/api/v1/device-events/batch", body, true);
  if (response.status == 200 || response.status == 204) {
    event_cursor_ = page.last_sequence;
    ++metrics_.events_successes;
    PM_LOG_INFO(
        "SYNC", "EVENT_BATCH_COMPLETE",
        "events=%u cursor=%llu successes=%llu",
        static_cast<unsigned>(page.records.size()),
        static_cast<unsigned long long>(event_cursor_),
        static_cast<unsigned long long>(metrics_.events_successes));
    return true;
  }
  ++metrics_.events_failures;
  PM_LOG_WARN("SYNC", "EVENT_BATCH_FAILED",
              "error=PM-SYNC-004 status=%d failures=%llu",
              response.status,
              static_cast<unsigned long long>(metrics_.events_failures));
  return false;
}

bool ServerSync::fetchConfiguration() {
  PM_LOG_DEBUG("CONFIG", "REMOTE_FETCH_BEGIN",
               "current_server_version=%lu",
               static_cast<unsigned long>(config_.serverConfigVersion()));
  const HttpResult response =
      request("GET", "/api/v1/device-config/effective", "", true);
  if (response.status != 200) {
    return false;
  }
  JsonDocument document;
  if (deserializeJson(document, response.body)) {
    PM_LOG_ERROR("CONFIG", "REMOTE_RESPONSE_INVALID",
                 "error=PM-CONFIG-006 category=json_invalid");
    return false;
  }
  const bool current_contract = document["settings"].is<JsonObject>();
  const std::uint32_t requested_version =
      current_contract ? (document["version"] | 0U)
                       : (document["config_version"] | 0U);
  if (requested_version <= config_.serverConfigVersion()) {
    PM_LOG_DEBUG("CONFIG", "REMOTE_UNCHANGED",
                 "requested_version=%lu current_server_version=%lu",
                 static_cast<unsigned long>(requested_version),
                 static_cast<unsigned long>(config_.serverConfigVersion()));
    return true;
  }
  PM_LOG_INFO("CONFIG", "REMOTE_UPDATE_RECEIVED",
              "requested_version=%lu current_server_version=%lu",
              static_cast<unsigned long>(requested_version),
              static_cast<unsigned long>(config_.serverConfigVersion()));
  std::string config_body = response.body;
  if (current_contract) {
    JsonDocument translated;
    translated["config_version"] = requested_version;
    JsonObjectConst settings = document["settings"].as<JsonObjectConst>();
    for (JsonPairConst setting : settings) {
      translated[setting.key()] = setting.value();
    }
    if (!settings["live_update_interval_seconds"].isNull()) {
      translated["live_interval_seconds"] =
          settings["live_update_interval_seconds"];
    }
    if (!settings["ct_rating_amps"].isNull()) {
      translated["ct_rating_a"] = settings["ct_rating_amps"];
    }
    config_body.clear();
    serializeJson(translated, config_body);
  }
  const RuntimeConfig previous = config_.config();
  ConfigValidation validation;
  const bool applied =
      config_.updateFromJson(config_body, false, false, validation);
  if (applied && stationConfigurationChanged(previous, config_.config())) {
    pending_config_version_ = requested_version;
    pending_config_started_ms_ = clock_.monotonicMs();
    next_config_validation_attempt_ms_ = pending_config_started_ms_ + 2000U;
    pending_config_validation_ = true;
    PM_LOG_INFO(
        "CONFIG", "REMOTE_NETWORK_UPDATE_STAGED",
        "version=%lu validation_window_ms=30000 rollback=automatic",
        static_cast<unsigned long>(requested_version));
    network_.applyConfiguration();
    return true;
  }
  const bool report_ok =
      reportConfiguration(requested_version, applied ? "applied" : "rejected",
                          validation.code.c_str());
  if (applied && networkCriticalChanged(previous, config_.config()) &&
      !report_ok) {
    const bool restored = config_.rollbackToPrevious();
    reportConfiguration(requested_version, "rolled_back",
                        restored ? "server_connectivity_validation_failed"
                                 : "configuration_rollback_failed");
    metrics_.last_error = restored ? "network_config_rolled_back"
                                   : "network_config_rollback_failed";
    PM_LOG_ERROR(
        "CONFIG", "REMOTE_CONNECTIVITY_ROLLBACK",
        "error=PM-CONFIG-007 version=%lu restored=%s",
        static_cast<unsigned long>(requested_version),
        restored ? "true" : "false");
    return false;
  }
  PM_LOG_INFO(
      "CONFIG", "REMOTE_UPDATE_COMPLETE",
      "version=%lu applied=%s report=%s validation=%s",
      static_cast<unsigned long>(requested_version),
      applied ? "true" : "false", report_ok ? "success" : "failed",
      validation.code.c_str());
  return applied && report_ok;
}

bool ServerSync::reportConfiguration(const std::uint32_t version,
                                     const char* status,
                                     const char* detail) {
  JsonDocument report;
  report["protocol_version"] = version::PROTOCOL;
  report["device_id"] = config_.identity().device_id;
  report["version"] = version;
  report["status"] = status;
  if (std::strcmp(status, "applied") == 0) {
    report["applied"].to<JsonArray>().add("configuration");
    report["rejected"].to<JsonObject>();
  } else {
    report["applied"].to<JsonArray>();
    report["rejected"].to<JsonObject>()["configuration"] = detail;
  }
  std::string body;
  serializeJson(report, body);
  const HttpResult response =
      request("POST", "/api/v1/device-config/report", body, true);
  const bool recorded = response.status == 200 || response.status == 204;
  if (recorded && std::strcmp(status, "applied") == 0) {
    return config_.setServerConfigVersion(version);
  }
  return recorded;
}

bool ServerSync::checkFirmwareManifest() {
  PM_LOG_DEBUG("OTA", "REMOTE_MANIFEST_CHECK_BEGIN",
               "channel=%s current=%s",
               config_.config().ota_channel.c_str(), version::FIRMWARE);
  const std::string endpoint = "/api/v1/device-firmware/manifest?channel=" +
                               crypto::percentEncode(config_.config().ota_channel) +
                               "&current=" + crypto::percentEncode(version::FIRMWARE);
  const HttpResult response = request("GET", endpoint, "", true);
  if (response.status != 200) {
    return false;
  }
  JsonDocument document;
  if (deserializeJson(document, response.body)) {
    return false;
  }
  if (!(document["available"] | false)) {
    available_firmware_version_.clear();
    PM_LOG_INFO("OTA", "REMOTE_MANIFEST_CURRENT",
                "update_available=false");
    return true;
  }
  available_firmware_version_ = std::string(
      document["version"] | (document["firmware_version"] | ""));
  PM_LOG_INFO("OTA", "REMOTE_MANIFEST_AVAILABLE",
              "update_available=%s target_version=%s",
              available_firmware_version_.empty() ? "false" : "true",
              available_firmware_version_.empty()
                  ? "none"
                  : available_firmware_version_.c_str());
  return !available_firmware_version_.empty();
}

ServerSync::HttpResult ServerSync::request(const char* method,
                                           const std::string& endpoint,
                                           const std::string& body,
                                           const bool authenticated) {
  HttpResult result;
  const std::uint32_t request_id = ++request_sequence_;
  const std::uint64_t started_ms = clock_.monotonicMs();
  PM_LOG_INFO(
      "HTTP", "REQUEST_BEGIN",
      "request_id=%lu method=%s endpoint=%s authenticated=%s request_bytes=%u",
      static_cast<unsigned long>(request_id), method, endpoint.c_str(),
      authenticated ? "true" : "false", static_cast<unsigned>(body.size()));
  if (!clock_.synchronized()) {
    result.error = "tls_time_not_trusted";
    PM_LOG_ERROR(
        "TLS", "TIME_NOT_TRUSTED",
        "error=PM-TLS-003 request_id=%lu category=TIME_NOT_TRUSTED",
        static_cast<unsigned long>(request_id));
    return result;
  }
  if (config_.config().server_ca_pem.empty()) {
    result.error = config_.config().server_fingerprint.empty()
                       ? "tls_ca_not_configured"
                       : "tls_fingerprint_only_rejected";
    PM_LOG_ERROR(
        "TLS", "CA_REQUIRED",
        "error=PM-TLS-001 request_id=%lu category=CA_MISSING fingerprint_configured=%s insecure_mode=false",
        static_cast<unsigned long>(request_id),
        config_.config().server_fingerprint.empty() ? "false" : "true");
    return result;
  }
  if (diag::SerialLogger::instance().allow("tls_ca_metadata", 3'600'000U)) {
    logCaMetadata(config_.config().server_ca_pem);
  }
  WiFiClientSecure client;
  client.setHandshakeTimeout(8);
  client.setCACert(config_.config().server_ca_pem.c_str());
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
    PM_LOG_ERROR("SERVER", "TARGET_REJECTED",
                 "error=PM-SERVER-003 request_id=%lu host=%s port=%u",
                 static_cast<unsigned long>(request_id),
                 target_host.empty() ? "invalid" : target_host.c_str(),
                 static_cast<unsigned>(target_port));
    return result;
  }
  IPAddress resolved;
  const std::uint64_t dns_started = clock_.monotonicMs();
  PM_LOG_DEBUG("DNS", "LOOKUP_BEGIN", "request_id=%lu host=%s",
               static_cast<unsigned long>(request_id), target_host.c_str());
  if (WiFi.hostByName(target_host.c_str(), resolved) != 1) {
    result.error = "dns_resolution_failed";
    PM_LOG_ERROR(
        "DNS", "LOOKUP_FAILED",
        "error=PM-DNS-001 request_id=%lu host=%s elapsed_ms=%llu",
        static_cast<unsigned long>(request_id), target_host.c_str(),
        static_cast<unsigned long long>(clock_.monotonicMs() - dns_started));
    return result;
  }
  PM_LOG_INFO(
      "DNS", "LOOKUP_COMPLETE",
      "request_id=%lu host=%s address=%s elapsed_ms=%llu",
      static_cast<unsigned long>(request_id), target_host.c_str(),
      resolved.toString().c_str(),
      static_cast<unsigned long long>(clock_.monotonicMs() - dns_started));
  PM_LOG_INFO(
      "TLS", "HANDSHAKE_BEGIN",
      "request_id=%lu host=%s port=%u ca_validation=true hostname_validation=true timeout_s=8 heap_free=%lu psram_free=%lu",
      static_cast<unsigned long>(request_id), target_host.c_str(),
      static_cast<unsigned>(target_port),
      static_cast<unsigned long>(ESP.getFreeHeap()),
      static_cast<unsigned long>(ESP.getFreePsram()));
  if (!http.begin(client, url.c_str())) {
    result.error = "http_begin_failed";
    PM_LOG_ERROR(
        "TLS", "CLIENT_BEGIN_FAILED",
        "error=PM-TLS-004 request_id=%lu category=TLS_NEGOTIATION_FAILED elapsed_ms=%llu",
        static_cast<unsigned long>(request_id),
        static_cast<unsigned long long>(clock_.monotonicMs() - started_ms));
    return result;
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
  const std::uint64_t elapsed_ms = clock_.monotonicMs() - started_ms;
  if (result.status > 0) {
    PM_LOG_INFO(
        "HTTP", "REQUEST_COMPLETE",
        "request_id=%lu method=%s endpoint=%s status=%d category=%s response_bytes=%u elapsed_ms=%llu phases=combined_dns_tcp_tls_http",
        static_cast<unsigned long>(request_id), method, endpoint.c_str(),
        result.status, diag::httpStatusCategory(result.status),
        static_cast<unsigned>(result.body.size()),
        static_cast<unsigned long long>(elapsed_ms));
    PM_LOG_DEBUG(
        "TLS", "HANDSHAKE_VERIFIED",
        "request_id=%lu host=%s ca_validation=true hostname_validation=true heap_free=%lu heap_min=%lu",
        static_cast<unsigned long>(request_id), target_host.c_str(),
        static_cast<unsigned long>(ESP.getFreeHeap()),
        static_cast<unsigned long>(ESP.getMinFreeHeap()));
  } else {
    PM_LOG_ERROR(
        "HTTP", "REQUEST_FAILED",
        "error=PM-HTTP-001 request_id=%lu method=%s endpoint=%s transport=%s tls_category=%s elapsed_ms=%llu",
        static_cast<unsigned long>(request_id), method, endpoint.c_str(),
        result.error.empty() ? "unknown" : result.error.c_str(),
        diag::tlsErrorCategory(result.error.c_str()),
        static_cast<unsigned long long>(elapsed_ms));
  }
  return result;
}

std::string ServerSync::heartbeatBody() const {
  const NetworkStatus network = network_.status();
  const StorageHealth storage = storage_.health();
  const MeterMetrics meter = meter_.metrics();
  MeasurementSnapshot latest;
  const bool has_latest = diagnostics_.latest(latest);
  JsonDocument document;
  document["schema_version"] = "heartbeat/1.0.0";
  document["protocol_version"] = version::PROTOCOL;
  document["device_id"] = config_.identity().device_id;
  document["boot_id"] = config_.identity().boot_id;
  document["firmware_version"] = version::FIRMWARE;
  document["firmware_build_hash"] = version::GIT_COMMIT;
  document["uptime_seconds"] = clock_.monotonicMs() / 1000U;
  document["reboot_reason"] = resetReasonName();
  document["current_ip"] = network.ip_address;
  document["hostname"] = network.hostname;
  document["rssi_dbm"] = network.rssi_dbm;
  document["connection_mode"] =
      connectionModeName(config_.config().connection_mode);
  document["configuration_version"] = config_.serverConfigVersion();
  JsonObject time = document["time"].to<JsonObject>();
  time["trusted"] = clock_.synchronized();
  time["source"] = clock_.synchronized() ? "sntp" : "untrusted";
  time["offset_ms"] = 0;
  if (clock_.synchronized()) {
    time["last_sync_at"] = clock_.utcIso8601();
  }
  JsonObject meter_json = document["pzem"].to<JsonObject>();
  const bool meter_ok = meter.last_error == MeterError::None;
  meter_json["ok"] = meter_ok;
  meter_json["status"] =
      meter_ok ? "healthy" : meterErrorCode(meter.last_error);
  meter_json["error_count"] = meter.consecutive_errors;
  JsonObject meter_details = meter_json["details"].to<JsonObject>();
  meter_details["last_error"] = meterErrorCode(meter.last_error);
  if (has_latest && latest.valid) {
    JsonObject live = document["latest"].to<JsonObject>();
    live["measured_at"] = isoUtc(latest.utc_ms);
    live["voltage_v"] = latest.voltage_v;
    live["current_a"] = latest.current_a;
    live["power_w"] = latest.active_power_w;
    live["frequency_hz"] = latest.frequency_hz;
    live["power_factor"] = latest.power_factor;
    live["energy_wh"] = latest.device_lifetime_energy_wh;
  }
  JsonObject storage_json = document["sd"].to<JsonObject>();
  const bool storage_ok = storage.present && storage.mounted && storage.writable;
  storage_json["ok"] = storage_ok;
  storage_json["status"] =
      storage_ok ? "healthy" : "storage_unavailable";
  storage_json["error_count"] = storage.write_failures;
  JsonObject storage_details = storage_json["details"].to<JsonObject>();
  storage_details["present"] = storage.present;
  storage_details["mounted"] = storage.mounted;
  storage_details["writable"] = storage.writable;
  storage_details["free_bytes"] = storage.free_bytes;
  storage_details["last_error"] = storage.last_error;
  document["oldest_stored_sequence"] = storage.oldest_sequence;
  document["newest_stored_sequence"] = storage.newest_sequence;
  document["server_ack_sequence"] = config_.serverAckSequence();
  document["backlog_estimate"] =
      storage.newest_sequence >= config_.serverAckSequence()
          ? storage.newest_sequence - config_.serverAckSequence()
          : 0;
  JsonObject resources = document["resources"].to<JsonObject>();
  resources["free_heap_bytes"] = ESP.getFreeHeap();
  resources["minimum_free_heap_bytes"] = ESP.getMinFreeHeap();
  JsonObject queues = document["queue"].to<JsonObject>();
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
  const std::uint32_t delay_ms = base + jitter;
  PM_LOG_WARN("SERVER", "RETRY_SCHEDULED",
              "attempt=%lu base_ms=%lu jitter_ms=%lu delay_ms=%lu maximum_ms=%lu",
              static_cast<unsigned long>(retry_attempt_),
              static_cast<unsigned long>(base),
              static_cast<unsigned long>(jitter),
              static_cast<unsigned long>(delay_ms),
              static_cast<unsigned long>(maximum));
  return delay_ms;
}

}  // namespace pm
