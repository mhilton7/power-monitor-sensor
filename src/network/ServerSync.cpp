#include "network/ServerSync.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <limits>
#include <utility>
#include <vector>

#include <ArduinoJson.h>
#include <ESPmDNS.h>
#include <HTTPClient.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <esp_heap_caps.h>
#include <esp_system.h>
#include <mbedtls/x509_crt.h>

#include "app/TaskConfig.h"
#include "diagnostics/DiagnosticCore.h"
#include "diagnostics/SerialLogger.h"
#include "network/ReadingWireFormat.h"
#include "security/Crypto.h"
#include "version.h"

namespace pm {
namespace {

constexpr std::uint32_t kDnsExpectedTimeoutMs = 8000U;
constexpr std::uint32_t kTcpConnectTimeoutMs = 5000U;
constexpr std::uint32_t kTlsHandshakeTimeoutSeconds = 8U;
constexpr std::uint32_t kHttpResponseTimeoutMs = 10'000U;
constexpr std::uint32_t kHttpBodyTimeoutMs = 5000U;
constexpr std::uint32_t kOverallRequestTimeoutMs = 30'000U;
constexpr std::uint32_t kResponseReadPollMs = 10U;
constexpr std::size_t kReadingBatchRecordLimit = 8U;
constexpr std::size_t kEventBatchRecordLimit = 24U;

struct TransportConfig {
  std::string server_url;
  std::string server_ca_pem;
  std::string server_fingerprint;
  std::array<std::string, 4> allowed_server_addresses{};
};

TransportConfig transportConfig(const ConfigService &config) {
  // Limit the live request frame to transport-owned fields. RuntimeConfig has
  // many strings and public-key values that TLS does not need.
  RuntimeConfig active = config.config();
  return {std::move(active.server_url), std::move(active.server_ca_pem),
          std::move(active.server_fingerprint),
          std::move(active.allowed_server_addresses)};
}

std::string enrolledDeviceId(const ConfigService &config) {
  return config.identity().device_id;
}

void recordSyncTaskCheckpoint(SyncMetrics &metrics, Diagnostics &diagnostics,
                              const char *checkpoint) {
  const std::uint32_t high_water_bytes =
      static_cast<std::uint32_t>(uxTaskGetStackHighWaterMark(nullptr));
  const std::uint32_t free_internal =
      heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  const std::uint32_t largest_internal =
      heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  metrics.stack_allocated_bytes = task_config::kServerSyncStackBytes;
  metrics.stack_high_water_bytes = high_water_bytes;
  metrics.stack_margin_percent = sync_policy::stackMarginPercent(
      task_config::kServerSyncStackBytes, high_water_bytes);
  metrics.free_internal_heap_bytes = free_internal;
  metrics.largest_internal_block_bytes = largest_internal;
  diagnostics.setSyncMetrics(metrics);
  PM_LOG_DEBUG(
      "TASK", "SYNC_TASK_STACK",
      "checkpoint=%s stack_allocated_bytes=%lu stack_high_water_bytes=%lu "
      "estimated_stack_used_bytes=%lu margin_percent=%lu core=%d priority=%u "
      "heap_free=%lu heap_min=%lu heap_largest=%lu free_internal_heap=%lu "
      "largest_internal_block=%lu free_psram=%lu",
      checkpoint,
      static_cast<unsigned long>(task_config::kServerSyncStackBytes),
      static_cast<unsigned long>(high_water_bytes),
      static_cast<unsigned long>(
          task_config::kServerSyncStackBytes -
          std::min(task_config::kServerSyncStackBytes, high_water_bytes)),
      static_cast<unsigned long>(metrics.stack_margin_percent),
      xPortGetCoreID(), static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
      static_cast<unsigned long>(ESP.getFreeHeap()),
      static_cast<unsigned long>(ESP.getMinFreeHeap()),
      static_cast<unsigned long>(
          heap_caps_get_largest_free_block(MALLOC_CAP_8BIT)),
      static_cast<unsigned long>(free_internal),
      static_cast<unsigned long>(largest_internal),
      static_cast<unsigned long>(ESP.getFreePsram()));
  if (metrics.stack_margin_percent < task_config::kMinimumStackMarginPercent &&
      diag::SerialLogger::instance().allow("server_sync_stack_low", 30'000U)) {
    PM_LOG_WARN(
        "TASK", "STACK_LOW",
        "error=PM-TASK-002 task=ServerSyncTask checkpoint=%s "
        "allocated_bytes=%lu high_water_bytes=%lu margin_percent=%lu "
        "threshold_percent=%lu",
        checkpoint,
        static_cast<unsigned long>(task_config::kServerSyncStackBytes),
        static_cast<unsigned long>(high_water_bytes),
        static_cast<unsigned long>(metrics.stack_margin_percent),
        static_cast<unsigned long>(task_config::kMinimumStackMarginPercent));
  }
}

class TransportCleanup final {
public:
  TransportCleanup(HTTPClient &http, WiFiClientSecure &client,
                   const std::uint32_t request_id)
      : http_(http), client_(client), request_id_(request_id) {}

  void markHttpBegun() { http_begun_ = true; }

  ~TransportCleanup() {
    PM_LOG_DEBUG("SYNC", "SYNC_CLEANUP_BEGIN", "request_id=%lu",
                 static_cast<unsigned long>(request_id_));
    if (http_begun_) {
      http_.end();
    }
    client_.stop();
    PM_LOG_DEBUG("SYNC", "SYNC_CLEANUP_COMPLETE",
                 "request_id=%lu http_ended=%s tls_stopped=true",
                 static_cast<unsigned long>(request_id_),
                 http_begun_ ? "true" : "not_started");
  }

private:
  HTTPClient &http_;
  WiFiClientSecure &client_;
  std::uint32_t request_id_;
  bool http_begun_{false};
};

class SyncTransactionCleanup final {
public:
  SyncTransactionCleanup(sync_policy::SingleFlightGate &gate,
                         SyncMetrics &metrics, Diagnostics &diagnostics,
                         ClockService &clock, const std::uint32_t request_id,
                         const char *method, const std::string &endpoint,
                         const int &status, const std::string &error,
                         const std::string &problem_code,
                         const std::string &tls_category,
                         const std::uint32_t &retry_after_ms,
                         const std::string &response_body,
                         const std::uint64_t started_ms)
      : gate_(gate), metrics_(metrics), diagnostics_(diagnostics),
        clock_(clock), request_id_(request_id), method_(method),
        endpoint_(endpoint), status_(status), error_(error),
        problem_code_(problem_code), tls_category_(tls_category),
        retry_after_ms_(retry_after_ms), response_body_(response_body),
        started_ms_(started_ms) {}

  ~SyncTransactionCleanup() {
    const std::uint64_t elapsed_ms = clock_.monotonicMs() - started_ms_;
    const bool success = status_ >= 200 && status_ < 300;
    if (success) {
      ++metrics_.transactions_completed;
    } else {
      ++metrics_.transactions_failed;
      if (!error_.empty()) {
        metrics_.last_error = error_;
      } else if (!problem_code_.empty()) {
        metrics_.last_error = problem_code_;
      }
    }
    gate_.finish();
    metrics_.sync_in_progress = false;
    metrics_.sync_pending = gate_.pending();
    metrics_.active_request_id = 0U;
    recordSyncTaskCheckpoint(metrics_, diagnostics_,
                             success ? "TRANSACTION_COMPLETE"
                                     : "TRANSACTION_FAILED");
    if (status_ > 0) {
      PM_LOG_INFO(
          "HTTP", "HTTP_COMPLETE",
          "request_id=%lu method=%s endpoint=%s status=%d category=%s "
          "problem=%s retry_after_ms=%lu response_bytes=%u elapsed_ms=%llu "
          "phases=dns,tcp,tls,http",
          static_cast<unsigned long>(request_id_), method_, endpoint_.c_str(),
          status_, diag::httpStatusCategory(status_),
          problem_code_.empty() ? "none" : problem_code_.c_str(),
          static_cast<unsigned long>(retry_after_ms_),
          static_cast<unsigned>(response_body_.size()),
          static_cast<unsigned long long>(elapsed_ms));
    } else {
      const char *category = tls_category_.empty()
                                 ? diag::tlsErrorCategory(error_.c_str())
                                 : tls_category_.c_str();
      PM_LOG_ERROR("HTTP", "HTTP_FAILED",
                   "error=PM-HTTP-001 request_id=%lu method=%s endpoint=%s "
                   "transport=%s tls_category=%s elapsed_ms=%llu",
                   static_cast<unsigned long>(request_id_), method_,
                   endpoint_.c_str(),
                   error_.empty() ? "unknown" : error_.c_str(), category,
                   static_cast<unsigned long long>(elapsed_ms));
    }
    const bool timed_out = error_.find("timeout") != std::string::npos;
    PM_LOG_INFO(
        "SYNC",
        success ? "SYNC_COMPLETE"
                : (timed_out ? "SYNC_TIMEOUT" : "SYNC_FAILED"),
        "request_id=%lu status=%d elapsed_ms=%llu pending=%s "
        "transactions_started=%llu transactions_completed=%llu "
        "transactions_failed=%llu",
        static_cast<unsigned long>(request_id_), status_,
        static_cast<unsigned long long>(elapsed_ms),
        metrics_.sync_pending ? "true" : "false",
        static_cast<unsigned long long>(metrics_.transactions_started),
        static_cast<unsigned long long>(metrics_.transactions_completed),
        static_cast<unsigned long long>(metrics_.transactions_failed));
  }

private:
  sync_policy::SingleFlightGate &gate_;
  SyncMetrics &metrics_;
  Diagnostics &diagnostics_;
  ClockService &clock_;
  std::uint32_t request_id_;
  const char *method_;
  const std::string &endpoint_;
  const int &status_;
  const std::string &error_;
  const std::string &problem_code_;
  const std::string &tls_category_;
  const std::uint32_t &retry_after_ms_;
  const std::string &response_body_;
  std::uint64_t started_ms_;
};

class HighMemoryLease final {
public:
  explicit HighMemoryLease(Diagnostics &diagnostics,
                           const TickType_t timeout = pdMS_TO_TICKS(5000))
      : diagnostics_(diagnostics),
        acquired_(diagnostics_.acquireHighMemoryOperation(timeout)) {}

  ~HighMemoryLease() {
    if (acquired_) {
      diagnostics_.releaseHighMemoryOperation();
    }
  }

  explicit operator bool() const { return acquired_; }

private:
  Diagnostics &diagnostics_;
  bool acquired_{false};
};

bool readBoundedResponseBody(HTTPClient &http, ClockService &clock,
                             const int response_size, std::string &body,
                             std::string &error) {
  body.clear();
  if (response_size == 0) {
    return true;
  }
  body.resize(static_cast<std::size_t>(response_size));
  WiFiClient *const stream = http.getStreamPtr();
  if (stream == nullptr) {
    body.clear();
    error = "response_stream_unavailable";
    return false;
  }
  const std::uint64_t deadline = clock.monotonicMs() + kHttpBodyTimeoutMs;
  std::size_t received = 0U;
  while (received < body.size()) {
    const int available = stream->available();
    if (available > 0) {
      const std::size_t remaining = body.size() - received;
      const std::size_t requested =
          std::min<std::size_t>(remaining, static_cast<std::size_t>(available));
      const int count = stream->read(
          reinterpret_cast<std::uint8_t *>(body.data() + received), requested);
      if (count <= 0) {
        body.clear();
        error = "response_connection_closed";
        return false;
      }
      received += static_cast<std::size_t>(count);
      continue;
    }
    if (!stream->connected()) {
      body.clear();
      error = "response_truncated";
      return false;
    }
    if (clock.monotonicMs() >= deadline) {
      body.clear();
      error = "response_body_timeout";
      return false;
    }
    vTaskDelay(pdMS_TO_TICKS(kResponseReadPollMs));
  }
  return true;
}

std::string joinUrl(const std::string &base, const std::string &endpoint) {
  if (!base.empty() && base.back() == '/' && !endpoint.empty() &&
      endpoint.front() == '/') {
    return base.substr(0, base.size() - 1) + endpoint;
  }
  return base + endpoint;
}

bool parseHttpsTarget(const std::string &url, std::string &host,
                      std::uint16_t &port) {
  host.clear();
  port = 443;
  if (url.rfind("https://", 0) != 0 || url.size() <= 8U)
    return false;
  const std::size_t start = 8;
  const std::size_t end = url.find_first_of("/?#", start);
  const std::string authority = url.substr(start, end - start);
  if (authority.empty() || authority.find('@') != std::string::npos ||
      authority.front() == '[' || authority.find(']') != std::string::npos) {
    return false;
  }
  if (end != std::string::npos && url.substr(end) != "/") {
    return false;
  }
  const std::size_t colon = authority.rfind(':');
  host = colon == std::string::npos ? authority : authority.substr(0, colon);
  if (host.empty() || host.find(':') != std::string::npos ||
      std::any_of(host.begin(), host.end(), [](const unsigned char value) {
        return std::isspace(value) != 0;
      })) {
    return false;
  }
  if (colon == std::string::npos)
    return true;
  const std::string port_text = authority.substr(colon + 1U);
  if (port_text.empty() || !std::all_of(port_text.begin(), port_text.end(),
                                        [](const unsigned char value) {
                                          return value >= '0' && value <= '9';
                                        })) {
    return false;
  }
  char *parse_end = nullptr;
  const unsigned long parsed = std::strtoul(port_text.c_str(), &parse_end, 10);
  if (parse_end == port_text.c_str() || *parse_end != '\0' || parsed == 0 ||
      parsed > std::numeric_limits<std::uint16_t>::max()) {
    return false;
  }
  port = static_cast<std::uint16_t>(parsed);
  return true;
}

bool dotLocalHost(const std::string &host) {
  static constexpr char suffix[] = ".local";
  if (host.size() <= sizeof(suffix) - 1U)
    return false;
  const std::size_t offset = host.size() - (sizeof(suffix) - 1U);
  for (std::size_t index = 0; index < sizeof(suffix) - 1U; ++index) {
    if (static_cast<char>(std::tolower(static_cast<unsigned char>(
            host[offset + index]))) != suffix[index]) {
      return false;
    }
  }
  return true;
}

bool safeProblemCode(const std::string &value) {
  return !value.empty() && value.size() <= 80U &&
         std::all_of(value.begin(), value.end(), [](const unsigned char item) {
           return (item >= 'a' && item <= 'z') ||
                  (item >= 'A' && item <= 'Z') ||
                  (item >= '0' && item <= '9') || item == '_' || item == '-' ||
                  item == '.';
         });
}

std::string problemCode(const std::string &body) {
  if (body.empty() || body.size() > sync_policy::kMaximumResponseBytes)
    return {};
  JsonDocument document;
  if (deserializeJson(document, body) || !document["code"].is<const char *>()) {
    return {};
  }
  const std::string code = document["code"].as<const char *>();
  return safeProblemCode(code) ? code : std::string{};
}

std::uint32_t retryAfterMilliseconds(const String &header) {
  if (header.isEmpty() || header.length() > 10U)
    return 0;
  const std::string value = header.c_str();
  if (!std::all_of(value.begin(), value.end(), [](const unsigned char item) {
        return item >= '0' && item <= '9';
      })) {
    return 0;
  }
  char *parse_end = nullptr;
  errno = 0;
  const unsigned long long seconds =
      std::strtoull(value.c_str(), &parse_end, 10);
  if (errno == ERANGE || parse_end == value.c_str() || *parse_end != '\0' ||
      seconds == 0) {
    return 0;
  }
  const std::uint64_t milliseconds =
      static_cast<std::uint64_t>(seconds) * 1000U;
  return static_cast<std::uint32_t>(std::min<std::uint64_t>(
      milliseconds, std::numeric_limits<std::uint32_t>::max()));
}

bool lowercaseHex(const std::string &value, const std::size_t length) {
  return value.size() == length &&
         std::all_of(value.begin(), value.end(), [](const unsigned char item) {
           return (item >= '0' && item <= '9') || (item >= 'a' && item <= 'f');
         });
}

bool lowercaseUuid(const std::string &value) {
  if (value.size() != 36U)
    return false;
  for (std::size_t index = 0; index < value.size(); ++index) {
    if (index == 8U || index == 13U || index == 18U || index == 23U) {
      if (value[index] != '-')
        return false;
    } else if (!((value[index] >= '0' && value[index] <= '9') ||
                 (value[index] >= 'a' && value[index] <= 'f'))) {
      return false;
    }
  }
  return true;
}

bool urlSafeSecret(const std::string &value) {
  return value.size() >= 32U && value.size() <= 64U &&
         std::all_of(value.begin(), value.end(), [](const unsigned char item) {
           return (item >= 'a' && item <= 'z') ||
                  (item >= 'A' && item <= 'Z') ||
                  (item >= '0' && item <= '9') || item == '-' || item == '_';
         });
}

const char *resetReasonName() {
  switch (esp_reset_reason()) {
  case ESP_RST_POWERON:
    return "power_on";
  case ESP_RST_EXT:
    return "external_reset";
  case ESP_RST_SW:
    return "software_reset";
  case ESP_RST_PANIC:
    return "panic";
  case ESP_RST_INT_WDT:
    return "interrupt_watchdog";
  case ESP_RST_TASK_WDT:
    return "task_watchdog";
  case ESP_RST_WDT:
    return "watchdog";
  case ESP_RST_DEEPSLEEP:
    return "deep_sleep";
  case ESP_RST_BROWNOUT:
    return "brownout";
  case ESP_RST_SDIO:
    return "sdio";
  case ESP_RST_UNKNOWN:
  default:
    return "unknown";
  }
}

bool networkCriticalChanged(const RuntimeConfig &before,
                            const RuntimeConfig &after) {
  return before.server_url != after.server_url ||
         before.server_ca_pem != after.server_ca_pem ||
         before.server_fingerprint != after.server_fingerprint ||
         before.connection_mode != after.connection_mode ||
         before.allowed_server_addresses != after.allowed_server_addresses;
}

bool stationConfigurationChanged(const RuntimeConfig &before,
                                 const RuntimeConfig &after) {
  return before.wifi_ssid != after.wifi_ssid ||
         before.static_network_enabled != after.static_network_enabled ||
         before.static_ip != after.static_ip ||
         before.static_gateway != after.static_gateway ||
         before.static_subnet != after.static_subnet ||
         before.static_dns != after.static_dns;
}

bool hostAllowed(const TransportConfig &config, const std::string &host) {
  bool constrained = false;
  for (const auto &allowed : config.allowed_server_addresses) {
    if (allowed.empty())
      continue;
    constrained = true;
    if (allowed == host)
      return true;
  }
  return !constrained;
}

void logCaMetadata(const std::string &pem) {
  mbedtls_x509_crt certificate;
  mbedtls_x509_crt_init(&certificate);
  const int result = mbedtls_x509_crt_parse(
      &certificate, reinterpret_cast<const unsigned char *>(pem.c_str()),
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
  const std::string fingerprint =
      crypto::sha256Hex(certificate.raw.p, certificate.raw.len);
  PM_LOG_DEBUG("TLS", "CA_METADATA",
               "subject=%s issuer=%s valid_from=%04d-%02d-%02d "
               "valid_to=%04d-%02d-%02d sha256_prefix=%s",
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
  std::strftime(output, sizeof(output), "%Y-%m-%dT%H:%M:%SZ", &broken_down);
  return output;
}

const char *eventCategory(const std::string &code) {
  if (code.find("BOOT") != std::string::npos)
    return "boot";
  if (code.find("PZEM") != std::string::npos ||
      code.find("METER") != std::string::npos) {
    return "pzem";
  }
  if (code.find("CT_") != std::string::npos)
    return "ct_limit";
  if (code.find("SD_") != std::string::npos ||
      code.find("STORAGE") != std::string::npos) {
    return "sd";
  }
  if (code.find("TIME") != std::string::npos ||
      code.find("NTP") != std::string::npos) {
    return "time";
  }
  if (code.find("CONFIG") != std::string::npos)
    return "configuration";
  if (code.find("OTA") != std::string::npos)
    return "ota";
  if (code.find("AUTH") != std::string::npos ||
      code.find("CREDENTIAL") != std::string::npos ||
      code.find("TLS") != std::string::npos) {
    return "security";
  }
  return "network";
}

} // namespace

ServerSync::ServerSync(ConfigService &config, NetworkService &network,
                       ClockService &clock, SdStorage &storage,
                       StorageCoordinator &storage_coordinator,
                       Diagnostics &diagnostics, IMeter &meter,
                       QueueHandle_t maintenance_queue)
    : config_(config), network_(network), clock_(clock), storage_(storage),
      storage_coordinator_(storage_coordinator), diagnostics_(diagnostics),
      meter_(meter),
      maintenance_queue_(maintenance_queue) {}

void ServerSync::logTaskCheckpoint(const char *checkpoint) {
  recordSyncTaskCheckpoint(metrics_, diagnostics_, checkpoint);
  if (std::strcmp(checkpoint, "BEFORE_RESPONSE_PARSE") == 0) {
    PM_LOG_DEBUG("HTTP", "RESPONSE_PARSE_BEGIN", "request_id=%lu bounded=true",
                 static_cast<unsigned long>(metrics_.active_request_id));
  } else if (std::strcmp(checkpoint, "AFTER_RESPONSE_PARSE") == 0) {
    PM_LOG_DEBUG("HTTP", "RESPONSE_PARSE_COMPLETE",
                 "request_id=%lu bounded=true",
                 static_cast<unsigned long>(metrics_.active_request_id));
  }
}

void ServerSync::tick() {
  if (metrics_.stack_allocated_bytes == 0U) {
    PM_LOG_INFO("SYNC", "SYNC_TASK_STARTED",
                "owner=ServerSyncTask stack_bytes=%lu core=%d priority=%u "
                "single_flight=true transport_shared=false",
                static_cast<unsigned long>(task_config::kServerSyncStackBytes),
                xPortGetCoreID(),
                static_cast<unsigned>(uxTaskPriorityGet(nullptr)));
    logTaskCheckpoint("TASK_START");
  }
  const std::uint64_t now = clock_.monotonicMs();
  metrics_.durable_reading_backlog =
      config_.serverAckSequence() < storage_.health().newest_sequence;
  const std::uint64_t reenrollment_generation =
      config_.reenrollmentGeneration();
  if (reenrollment_generation != observed_reenrollment_generation_) {
    observed_reenrollment_generation_ = reenrollment_generation;
    retry_attempt_ = 0;
    reading_retry_attempt_ = 0;
    event_retry_attempt_ = 0;
    next_heartbeat_ms_ = 0;
    next_config_poll_ms_ = 0;
    next_manifest_poll_ms_ = 0;
    next_reading_push_ms_ = 0;
    next_event_push_ms_ = 0;
    if (now >= retry_after_gate_ms_) {
      next_retry_ms_ = 0;
      retry_after_gate_ms_ = 0;
    } else {
      next_retry_ms_ = std::max(next_retry_ms_, retry_after_gate_ms_);
    }
    PM_LOG_INFO("ENROLL", "REENROLLMENT_STATE_OBSERVED",
                "generation=%llu retry_gate_preserved=%s",
                static_cast<unsigned long long>(reenrollment_generation),
                now < retry_after_gate_ms_ ? "true" : "false");
  }
  if (single_flight_.consumePending()) {
    immediate_sync_ = true;
    next_heartbeat_ms_ = 0;
    if (now >= retry_after_gate_ms_) {
      next_retry_ms_ = 0;
      PM_LOG_INFO("SERVER", "RETRY_BYPASSED",
                  "reason=local_diagnostic retry_attempt=%lu",
                  static_cast<unsigned long>(retry_attempt_));
    } else {
      next_retry_ms_ = std::max(next_retry_ms_, retry_after_gate_ms_);
      PM_LOG_WARN("SERVER", "RETRY_BYPASS_DEFERRED",
                  "reason=server_retry_after retry_in_ms=%llu",
                  static_cast<unsigned long long>(retry_after_gate_ms_ - now));
    }
  }
  const NetworkStatus network = network_.status();

  // Validate a remotely changed station configuration even while the new
  // configuration is offline. Keeping this state behind the normal online
  // gate would strand the device forever on an unusable network.
  if (pending_config_validation_) {
    const std::uint64_t current_generation = config_.persistentGeneration();
    if (current_generation != pending_config_generation_) {
      PM_LOG_WARN("CONFIG", "REMOTE_NETWORK_UPDATE_SUPERSEDED",
                  "version=%lu staged_generation=%llu current_generation=%llu "
                  "rollback_skipped=true",
                  static_cast<unsigned long>(pending_config_version_),
                  static_cast<unsigned long long>(pending_config_generation_),
                  static_cast<unsigned long long>(current_generation));
      pending_config_validation_ = false;
      pending_config_generation_ = 0;
      pending_config_rollback_report_ = true;
      pending_config_report_detail_ = "superseded_by_newer_configuration";
      next_config_validation_attempt_ms_ = now;
    } else if (network.station_connected && clock_.synchronized() &&
               now >= next_config_validation_attempt_ms_ &&
               now - pending_config_started_ms_ >= 2000U &&
               reportConfiguration(pending_config_version_, "applied",
                                   "post_apply_connectivity_validated")) {
      pending_config_validation_ = false;
      pending_config_generation_ = 0;
    } else if (now - pending_config_started_ms_ >= 30'000U) {
      std::uint64_t restored_generation = 0;
      const bool restored = config_.rollbackToPrevious(
          pending_config_generation_, &restored_generation);
      pending_config_validation_ = false;
      pending_config_generation_ = 0;
      pending_config_rollback_report_ = restored;
      pending_config_report_detail_ = restored
                                          ? "post_apply_connectivity_failed"
                                          : "configuration_rollback_conflict";
      metrics_.last_error = restored ? "network_config_rolled_back"
                                     : "network_config_rollback_failed";
      PM_LOG_WARN("CONFIG", "REMOTE_NETWORK_VALIDATION_EXPIRED",
                  "version=%lu restored=%s restored_generation=%llu",
                  static_cast<unsigned long>(pending_config_version_),
                  restored ? "true" : "false",
                  static_cast<unsigned long long>(restored_generation));
      if (restored)
        network_.requestConfigurationApply(0);
    } else if (now >= next_config_validation_attempt_ms_) {
      next_config_validation_attempt_ms_ = now + 2000U;
    }
    diagnostics_.setSyncMetrics(metrics_);
    if (pending_config_validation_ || !network.station_connected ||
        !clock_.synchronized()) {
      return;
    }
  }

  const ConnectionMode configured_mode = config_.config().connection_mode;
  if (configured_mode != ConnectionMode::Push) {
    metrics_.last_error = "connection_mode_unsupported";
    network_.setServerStatus(false, false);
    if (diag::SerialLogger::instance().allow("unsupported_connection_mode",
                                             60'000U)) {
      PM_LOG_ERROR("SERVER", "CONNECTION_MODE_REJECTED",
                   "error=PM-SERVER-004 configured_mode=%s supported_mode=push "
                   "sync_blocked=true hint=save_network_settings_with_push",
                   connectionModeName(configured_mode));
    }
    diagnostics_.setSyncMetrics(metrics_);
    return;
  }

  if (!network.station_connected || !clock_.synchronized() ||
      config_.config().server_url.empty() || now < next_retry_ms_) {
    if (offline_since_ms_ == 0)
      offline_since_ms_ = now;
    if (diag::SerialLogger::instance().allow("server_offline", 60'000U)) {
      PM_LOG_INFO(
          "SERVER", "OFFLINE_SUMMARY",
          "duration_ms=%llu wifi=%s time_trusted=%s configured=%s "
          "retry_in_ms=%llu retry_attempt=%lu backlog=%llu",
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
    std::uint32_t retry_after_ms = 0;
    if (!config_.enrollmentToken().empty() && !enroll(retry_after_ms)) {
      const std::uint32_t retry_delay_ms = retryDelayMs(retry_after_ms);
      next_retry_ms_ = now + retry_delay_ms;
      retry_after_gate_ms_ = retry_after_ms == 0U ? 0U : next_retry_ms_;
    }
    diagnostics_.setSyncMetrics(metrics_);
    return;
  }
  if (pending_config_rollback_report_ && network.station_connected &&
      now >= next_config_validation_attempt_ms_) {
    pending_config_rollback_report_ =
        !reportConfiguration(pending_config_version_, "rolled_back",
                             pending_config_report_detail_.c_str());
    next_config_validation_attempt_ms_ = now + 5000U;
  }
  if (now >= next_heartbeat_ms_) {
    PM_LOG_INFO("HEARTBEAT", "HEARTBEAT_SCHEDULED",
                "due_ms=%llu interval_seconds=%lu automatic=true",
                static_cast<unsigned long long>(next_heartbeat_ms_),
                static_cast<unsigned long>(
                    config_.config().heartbeat_interval_seconds));
    std::uint32_t retry_after_ms = 0;
    if (heartbeat(retry_after_ms)) {
      retry_attempt_ = 0;
      retry_after_gate_ms_ = 0;
      next_heartbeat_ms_ = now + heartbeatDelayMs();
    } else {
      const std::uint32_t retry_delay_ms = retryDelayMs(retry_after_ms);
      next_retry_ms_ = now + retry_delay_ms;
      retry_after_gate_ms_ = retry_after_ms == 0U ? 0U : next_retry_ms_;
      PM_LOG_WARN("SERVER", "RETRY_GATE_ACTIVE",
                  "reason=heartbeat_failed remaining_operations=deferred "
                  "retry_in_ms=%lu retry_after_ms=%lu",
                  static_cast<unsigned long>(retry_delay_ms),
                  static_cast<unsigned long>(retry_after_ms));
      diagnostics_.setSyncMetrics(metrics_);
      return;
    }
    diagnostics_.setSyncMetrics(metrics_);
    return;
  }
  const bool durable_reading_backlog = metrics_.durable_reading_backlog;
  if (now >= next_reading_push_ms_ && durable_reading_backlog) {
    immediate_sync_ = !pushReadings();
    diagnostics_.setSyncMetrics(metrics_);
    return;
  }
  if (!sync_policy::secondaryOperationsAllowed(durable_reading_backlog)) {
    // A page load may be executing on StorageTask while this task waits for
    // its short polling deadline. Do not fall through into another TLS
    // transaction: FATFS scanning plus mbedTLS fragmented internal RAM and
    // previously invalidated an active Arduino File handle.
    diagnostics_.setSyncMetrics(metrics_);
    return;
  }
  // Diagnostic events remain durable on microSD, but they must not compete
  // with the primary measurement path. In particular, a server that has not
  // advanced the reading acknowledgement cursor can otherwise trigger a
  // long FAT directory scan during reading retry backoff and temporarily
  // consume the heap needed for heartbeat TLS.
  if (!durable_reading_backlog && now >= next_event_push_ms_) {
    if (pushEvents()) {
      next_event_push_ms_ = now + 30'000U;
    }
    diagnostics_.setSyncMetrics(metrics_);
    return;
  }
  if (now >= next_config_poll_ms_) {
    fetchConfiguration();
    next_config_poll_ms_ = now + static_cast<std::uint64_t>(
                                     config_.config().sync_interval_seconds) *
                                     1000U;
    diagnostics_.setSyncMetrics(metrics_);
    return;
  }
  if (!config_.safeMode() && now >= next_manifest_poll_ms_) {
    checkFirmwareManifest();
    next_manifest_poll_ms_ = now + 3'600'000U;
    diagnostics_.setSyncMetrics(metrics_);
    return;
  }
  diagnostics_.setSyncMetrics(metrics_);
}

void ServerSync::requestImmediateSync() {
  const sync_policy::QueueResult disposition = single_flight_.queue();
  PM_LOG_INFO("SYNC",
              disposition == sync_policy::QueueResult::Queued
                  ? "SYNC_QUEUED"
                  : "SYNC_COALESCED",
              "source=local_action active=%s pending=true queue_capacity=1",
              single_flight_.active() ? "true" : "false");
}

SyncMetrics ServerSync::metrics() const { return metrics_; }

std::string ServerSync::availableFirmwareVersion() const {
  return available_firmware_version_;
}

bool ServerSync::enroll(std::uint32_t &retry_after_ms) {
  retry_after_ms = 0;
  const StorageHealth storage = storage_.health();
  const bool storage_ready =
      storage.present && storage.mounted && storage.writable;
  if (!storage_ready) {
    metrics_.last_error = "enrollment_storage_unavailable";
    PM_LOG_ERROR("ENROLL", "ENROLLMENT_PREREQUISITE_FAILED",
                 "error=PM-ENROLL-005 reason=required_storage_unavailable "
                 "sd_present=%s sd_mounted=%s sd_writable=%s",
                 storage.present ? "true" : "false",
                 storage.mounted ? "true" : "false",
                 storage.writable ? "true" : "false");
    return false;
  }
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
  capabilities["sd_present"] = storage_ready;
  capabilities["sd_required"] = true;
  JsonArray endpoints = capabilities["supported_endpoints"].to<JsonArray>();
  endpoints.add("/api/v1/health");
  endpoints.add("/api/v1/live");
  endpoints.add("/api/v1/readings");
  endpoints.add("/api/v1/config");
  endpoints.add("/api/v1/firmware");
  std::string body;
  serializeJson(document, body);
  const HttpResult response = request("POST", "/api/v1/device-enrollment/claim",
                                      std::move(body), false);
  retry_after_ms = response.retry_after_ms;
  if (response.status != 201) {
    metrics_.last_error =
        !response.problem_code.empty()
            ? response.problem_code
            : (response.error.empty() ? "enrollment_rejected" : response.error);
    network_.setServerStatus(response.status > 0, false);
    PM_LOG_ERROR("ENROLL", "ENROLLMENT_REJECTED",
                 "error=PM-ENROLL-001 http_status=%d category=%s problem=%s "
                 "transport=%s",
                 response.status, diag::httpStatusCategory(response.status),
                 response.problem_code.empty() ? "none"
                                               : response.problem_code.c_str(),
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
  if (!result["protocol_version"].is<const char *>() ||
      !result["device_id"].is<const char *>() ||
      !result["enrollment_secret"].is<const char *>() ||
      !result["credential_fingerprint"].is<const char *>() ||
      !result["effective_metadata"].is<JsonObject>() ||
      !result["heartbeat_policy"].is<JsonObject>() ||
      !result["sync_policy"].is<JsonObject>() ||
      std::string(result["protocol_version"].as<const char *>()) !=
          version::PROTOCOL) {
    metrics_.last_error = "enrollment_response_invalid";
    PM_LOG_ERROR(
        "ENROLL", "RESPONSE_INVALID",
        "error=PM-ENROLL-002 protocol_match=false contract_shape=false");
    return false;
  }
  const std::string device_id = result["device_id"] | "";
  const std::string encoded_secret = result["enrollment_secret"] | "";
  const std::string credential_fingerprint =
      result["credential_fingerprint"] | "";
  std::string ota_public_key = result["server_ota_signing_public_key"] | "";
  if (ota_public_key.empty()) {
    ota_public_key = result["ota_signing_public_key"] | "";
  }
  if (!lowercaseUuid(device_id) || !urlSafeSecret(encoded_secret) ||
      credential_fingerprint.empty() || credential_fingerprint.size() > 128U ||
      ota_public_key.size() > 4096U) {
    metrics_.last_error = "enrollment_credentials_invalid";
    PM_LOG_ERROR("ENROLL", "RESPONSE_INVALID",
                 "error=PM-ENROLL-002 protocol_match=true contract_shape=true "
                 "credentials_valid=false");
    return false;
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
    assigned.friendly_name =
        result["friendly_name"] | assigned.friendly_name.c_str();
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
  const char *policy_mode = result["policy"]["connection_mode"] | nullptr;
  if (policy_mode != nullptr) {
    if (std::strcmp(policy_mode, "push") != 0) {
      metrics_.last_error = "enrollment_connection_mode_unsupported";
      PM_LOG_ERROR(
          "ENROLL", "ASSIGNMENT_REJECTED",
          "error=PM-ENROLL-003 validation=connection_mode_unsupported "
          "requested_mode=%s supported_mode=push credentials_saved=false",
          policy_mode);
      return false;
    }
    assigned.connection_mode = ConnectionMode::Push;
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
  const std::size_t secret_length = encoded_secret.size();
  std::memcpy(secret.data(), encoded_secret.data(), secret_length);
  if (!config_.saveEnrollment(device_id, secret.data(), secret_length,
                              ota_public_key)) {
    std::fill(secret.begin(), secret.end(), 0U);
    metrics_.last_error = "enrollment_credentials_invalid";
    PM_LOG_ERROR("ENROLL", "CREDENTIAL_SAVE_FAILED",
                 "error=PM-ENROLL-004 credentials=redacted");
    return false;
  }
  std::fill(secret.begin(), secret.end(), 0U);
  std::uint64_t assigned_generation = 0;
  if (!config_.commitCandidate(assigned, true, assigned_generation)) {
    // The one-time token has already been consumed. Keep the atomically saved
    // credentials active and continue with the heartbeat; the effective
    // configuration poll can reconcile metadata on the next successful sync.
    PM_LOG_WARN(
        "ENROLL", "ASSIGNMENT_SAVE_DEFERRED",
        "error=PM-ENROLL-006 credentials_stored=true metadata_deferred=true");
  }
  network_.setServerStatus(true, true);
  PM_LOG_INFO("ENROLL", "ENROLLMENT_COMPLETE",
              "device=%s friendly_name=%s config_version=%lu "
              "config_generation=%llu credentials=stored",
              diag::maskIdentifier(device_id).c_str(),
              config_.config().friendly_name.c_str(),
              static_cast<unsigned long>(config_.config().config_version),
              static_cast<unsigned long long>(assigned_generation));
  next_heartbeat_ms_ = 0;
  return heartbeat(retry_after_ms);
}

bool ServerSync::heartbeat(std::uint32_t &retry_after_ms) {
  retry_after_ms = 0;
  PM_LOG_DEBUG("HEARTBEAT", "HEARTBEAT_BEGIN", "ack_sequence=%llu",
               static_cast<unsigned long long>(config_.serverAckSequence()));
  logTaskCheckpoint("BEFORE_JSON_BUILD");
  const std::string heartbeat_body = heartbeatBody();
  logTaskCheckpoint("AFTER_JSON_BUILD");
  const HttpResult response = request("POST", "/api/v1/device-heartbeats",
                                      std::move(heartbeat_body), true);
  retry_after_ms = response.retry_after_ms;
  if (response.status != 200) {
    ++metrics_.heartbeat_failures;
    metrics_.last_error =
        !response.problem_code.empty()
            ? response.problem_code
            : (response.error.empty() ? "heartbeat_failed" : response.error);
    network_.setServerStatus(response.status > 0, false);
    if (response.status == 401 || response.status == 403) {
      ++metrics_.authentication_rejections;
    }
    PM_LOG_WARN("HEARTBEAT", "HEARTBEAT_FAILED",
                "error=PM-SERVER-001 status=%d category=%s problem=%s "
                "failures=%llu retry_attempt=%lu",
                response.status, diag::httpStatusCategory(response.status),
                response.problem_code.empty() ? "none"
                                              : response.problem_code.c_str(),
                static_cast<unsigned long long>(metrics_.heartbeat_failures),
                static_cast<unsigned long>(retry_attempt_));
    return false;
  }
  logTaskCheckpoint("BEFORE_RESPONSE_PARSE");
  JsonDocument document;
  if (deserializeJson(document, response.body)) {
    ++metrics_.heartbeat_failures;
    metrics_.last_error = "heartbeat_response_invalid";
    PM_LOG_ERROR("HEARTBEAT", "RESPONSE_INVALID", "error=PM-SERVER-002");
    logTaskCheckpoint("AFTER_RESPONSE_PARSE");
    return false;
  }
  if (!document["server_receive_time"].is<const char *>() ||
      !document["highest_contiguous_accepted_sequence"].is<std::uint64_t>() ||
      !document["gap_ranges"].is<JsonArray>() ||
      !document["desired_configuration_version"].is<std::uint32_t>() ||
      !document["firmware_release_available"].is<bool>() ||
      !document["recommended_heartbeat_interval_seconds"].is<std::uint32_t>() ||
      !document["immediate_sync_requested"].is<bool>()) {
    ++metrics_.heartbeat_failures;
    metrics_.last_error = "heartbeat_response_contract_invalid";
    PM_LOG_ERROR("HEARTBEAT", "RESPONSE_INVALID",
                 "error=PM-SERVER-002 category=contract_shape_invalid");
    logTaskCheckpoint("AFTER_RESPONSE_PARSE");
    return false;
  }
  const std::uint64_t acknowledgement =
      document["highest_contiguous_accepted_sequence"].as<std::uint64_t>();
  const std::uint64_t current_ack = config_.serverAckSequence();
  const std::uint64_t newest_sequence = storage_.health().newest_sequence;
  const sync_policy::AcknowledgementDisposition acknowledgement_disposition =
      sync_policy::classifyAcknowledgement(current_ack, newest_sequence,
                                           acknowledgement);
  const bool sequence_floor_ready =
      acknowledgement_disposition !=
          sync_policy::AcknowledgementDisposition::AdvanceSequenceFloor ||
      storage_.advanceSequenceFloor(acknowledgement);
  const bool acknowledgement_valid =
      acknowledgement_disposition !=
          sync_policy::AcknowledgementDisposition::Invalid &&
      sequence_floor_ready;
  const bool acknowledgement_persisted =
      acknowledgement_valid && (acknowledgement == current_ack ||
                                config_.setServerAckSequence(acknowledgement));
  if (!acknowledgement_persisted) {
    ++metrics_.heartbeat_failures;
    metrics_.last_error = "heartbeat_ack_invalid";
    PM_LOG_ERROR("HEARTBEAT", "RESPONSE_INVALID",
                 "error=PM-SERVER-002 category=ack_invalid current_ack=%llu "
                 "response_ack=%llu newest=%llu",
                 static_cast<unsigned long long>(current_ack),
                 static_cast<unsigned long long>(acknowledgement),
                 static_cast<unsigned long long>(newest_sequence));
    logTaskCheckpoint("AFTER_RESPONSE_PARSE");
    return false;
  }
  immediate_sync_ = document["immediate_sync_requested"].as<bool>();
  if (sync_policy::shouldReleaseReadingBackoff(
          immediate_sync_, acknowledgement, newest_sequence)) {
    const bool was_deferred = next_reading_push_ms_ > clock_.monotonicMs();
    next_reading_push_ms_ = 0;
    PM_LOG_INFO(
        "SYNC", "READING_BACKOFF_RELEASED",
        "source=heartbeat_server_request acknowledgement=%llu newest=%llu "
        "was_deferred=%s retry_attempt=%lu",
        static_cast<unsigned long long>(acknowledgement),
        static_cast<unsigned long long>(newest_sequence),
        was_deferred ? "true" : "false",
        static_cast<unsigned long>(reading_retry_attempt_));
  }
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
  PM_LOG_INFO("HEARTBEAT", "HEARTBEAT_COMPLETE",
              "successes=%llu ack_sequence=%llu synchronize_now=%s "
              "next_interval_ms=%lu",
              static_cast<unsigned long long>(metrics_.heartbeat_successes),
              static_cast<unsigned long long>(acknowledgement),
              immediate_sync_ ? "true" : "false",
              static_cast<unsigned long>(heartbeatDelayMs()));
  logTaskCheckpoint("AFTER_RESPONSE_PARSE");
  return true;
}

bool ServerSync::pushReadings() {
  HistoryQuery query;
  query.after_sequence = config_.serverAckSequence();
  query.limit = kReadingBatchRecordLimit;
  query.maximum_payload_bytes = sync_policy::kReadingBatchPayloadBytes;
  query.require_syncable = true;
  if (reading_page_job_id_.empty()) {
    reading_page_job_id_ =
        storage_coordinator_.queueHistory(query, false, true);
    if (reading_page_job_id_.empty()) {
      next_reading_push_ms_ =
          clock_.monotonicMs() +
          operationRetryDelayMs(reading_retry_attempt_, 0, "readings");
      PM_LOG_WARN("SYNC", "READ_BATCH_LOAD_FAILED",
                  "error=PM-SYNC-001 storage_error=storage_queue_unavailable");
      return false;
    }
    next_reading_push_ms_ = clock_.monotonicMs() + 250U;
    PM_LOG_DEBUG("SYNC", "READ_BATCH_LOAD_QUEUED",
                 "job=%s owner=StorageTask", reading_page_job_id_.c_str());
    return true;
  }
  HistoryPage page;
  bool complete = false;
  if (!storage_coordinator_.historyResult(reading_page_job_id_, page, complete,
                                          true)) {
    PM_LOG_WARN("SYNC", "READ_BATCH_LOAD_FAILED",
                "error=PM-SYNC-001 storage_error=storage_job_expired job=%s",
                reading_page_job_id_.c_str());
    reading_page_job_id_.clear();
    next_reading_push_ms_ =
        clock_.monotonicMs() +
        operationRetryDelayMs(reading_retry_attempt_, 0, "readings");
    return false;
  }
  if (!complete) {
    next_reading_push_ms_ = clock_.monotonicMs() + 250U;
    return true;
  }
  PM_LOG_DEBUG("SYNC", "READ_BATCH_LOAD_COMPLETE",
               "job=%s records=%u owner=StorageTask",
               reading_page_job_id_.c_str(),
               static_cast<unsigned>(page.records.size()));
  reading_page_job_id_.clear();
  if (!page.ok ||
      (page.records.empty() && page.unavailable_sequence_ranges.empty())) {
    if (!page.ok) {
      PM_LOG_WARN("SYNC", "READ_BATCH_LOAD_FAILED",
                  "error=PM-SYNC-001 storage_error=%s",
                  page.error_code.c_str());
      next_reading_push_ms_ =
          clock_.monotonicMs() +
          operationRetryDelayMs(reading_retry_attempt_, 0, "readings");
    } else {
      reading_retry_attempt_ = 0;
      next_reading_push_ms_ = 0;
    }
    return page.ok;
  }
  PM_LOG_INFO("SYNC", "READ_BATCH_BEGIN",
              "records=%u unavailable_ranges=%u first_sequence=%llu "
              "last_sequence=%llu has_more=%s",
              static_cast<unsigned>(page.records.size()),
              static_cast<unsigned>(
                  page.unavailable_sequence_ranges.size()),
              static_cast<unsigned long long>(page.first_sequence),
              static_cast<unsigned long long>(page.last_sequence),
              page.has_more ? "true" : "false");
  PM_LOG_INFO(
      "HISTORY", "sensor.reading_batch_started",
      "record_count=%u first_sequence=%llu last_sequence=%llu backlog=%llu",
      static_cast<unsigned>(page.records.size()),
      static_cast<unsigned long long>(page.first_sequence),
      static_cast<unsigned long long>(page.last_sequence),
      static_cast<unsigned long long>(
          storage_.health().newest_sequence >= config_.serverAckSequence()
              ? storage_.health().newest_sequence -
                    config_.serverAckSequence()
              : 0));
  if (page.has_more) {
    PM_LOG_INFO(
        "HISTORY", "history.backfill_started",
        "first_sequence=%llu last_sequence=%llu newest_stored=%llu",
        static_cast<unsigned long long>(page.first_sequence),
        static_cast<unsigned long long>(page.last_sequence),
        static_cast<unsigned long long>(storage_.health().newest_sequence));
  }
  const std::size_t record_count = page.records.size();
  const bool page_has_more = page.has_more;
  logTaskCheckpoint("BEFORE_JSON_BUILD");
  std::string body;
  {
    JsonDocument document;
    document["schema_version"] = "reading-batch/1.0.0";
    document["protocol_version"] = version::PROTOCOL;
    document["device_id"] = enrolledDeviceId(config_);
    JsonArray unavailable =
        document["unavailable_sequence_ranges"].to<JsonArray>();
    for (const auto &range : page.unavailable_sequence_ranges) {
      JsonObject encoded_range = unavailable.add<JsonObject>();
      encoded_range["start_sequence"] = range.start_sequence;
      encoded_range["end_sequence"] = range.end_sequence;
    }
    JsonArray records = document["readings"].to<JsonArray>();
    for (const auto &encoded : page.records) {
      if (!reading_wire::append(records, encoded)) {
        metrics_.last_error = "stored_record_json_invalid";
        ++metrics_.batch_failures;
        PM_LOG_ERROR("SYNC", "STORED_RECORD_INVALID", "error=PM-SYNC-002");
        next_reading_push_ms_ =
            clock_.monotonicMs() +
            operationRetryDelayMs(reading_retry_attempt_, 0, "readings");
        return false;
      }
    }
    serializeJson(document, body);
  }
  // Do not retain the raw SD page and ArduinoJson tree while mbedTLS requests
  // its internal-RAM working set. The body is the only request payload owner.
  std::vector<std::string>().swap(page.records);
  logTaskCheckpoint("AFTER_JSON_BUILD");
  const HttpResult response =
      request("POST", "/api/v1/device-readings/batch", std::move(body), true);
  if (response.status != 200) {
    ++metrics_.batch_failures;
    metrics_.last_error =
        !response.problem_code.empty()
            ? response.problem_code
            : (response.status == 409 || response.status == 422
                   ? "batch_protocol_fault"
                   : "batch_transient_failure");
    next_reading_push_ms_ =
        clock_.monotonicMs() + operationRetryDelayMs(reading_retry_attempt_,
                                                     response.retry_after_ms,
                                                     "readings");
    PM_LOG_WARN("SYNC", "READ_BATCH_FAILED",
                "error=PM-SYNC-003 status=%d category=%s problem=%s records=%u "
                "failures=%llu retry_in_ms=%llu",
                response.status, diag::httpStatusCategory(response.status),
                response.problem_code.empty() ? "none"
                                              : response.problem_code.c_str(),
                static_cast<unsigned>(record_count),
                static_cast<unsigned long long>(metrics_.batch_failures),
                static_cast<unsigned long long>(next_reading_push_ms_ -
                                                clock_.monotonicMs()));
    PM_LOG_WARN(
        "HISTORY", "sensor.reading_batch_failed",
        "record_count=%u first_sequence=%llu last_sequence=%llu status=%d "
        "problem=%s",
        static_cast<unsigned>(record_count),
        static_cast<unsigned long long>(page.first_sequence),
        static_cast<unsigned long long>(page.last_sequence), response.status,
        response.problem_code.empty() ? "none"
                                      : response.problem_code.c_str());
    return false;
  }
  logTaskCheckpoint("BEFORE_RESPONSE_PARSE");
  JsonDocument result;
  if (deserializeJson(result, response.body)) {
    ++metrics_.batch_failures;
    metrics_.last_error = "batch_response_invalid";
    next_reading_push_ms_ =
        clock_.monotonicMs() +
        operationRetryDelayMs(reading_retry_attempt_, 0, "readings");
    logTaskCheckpoint("AFTER_RESPONSE_PARSE");
    return false;
  }
  if (!result["accepted"].is<JsonArray>() ||
      !result["duplicates"].is<JsonArray>() ||
      !result["rejected"].is<JsonArray>() ||
      !result["highest_contiguous_accepted_sequence"].is<std::uint64_t>() ||
      !result["missing_ranges"].is<JsonArray>()) {
    ++metrics_.batch_failures;
    metrics_.last_error = "batch_response_contract_invalid";
    next_reading_push_ms_ =
        clock_.monotonicMs() +
        operationRetryDelayMs(reading_retry_attempt_, 0, "readings");
    logTaskCheckpoint("AFTER_RESPONSE_PARSE");
    return false;
  }
  const std::size_t rejected_count =
      result["rejected"].as<JsonArrayConst>().size();
  if (rejected_count != 0U) {
    ++metrics_.batch_failures;
    metrics_.last_error = "batch_records_rejected";
    const std::uint64_t now = clock_.monotonicMs();
    next_reading_push_ms_ =
        now + operationRetryDelayMs(reading_retry_attempt_, 0, "readings");
    PM_LOG_ERROR("SYNC", "READ_BATCH_REJECTED",
                 "error=PM-SYNC-006 rejected=%u records=%u "
                 "cursor_retained=%llu failures=%llu retry_in_ms=%llu",
                 static_cast<unsigned>(rejected_count),
                 static_cast<unsigned>(record_count),
                 static_cast<unsigned long long>(config_.serverAckSequence()),
                 static_cast<unsigned long long>(metrics_.batch_failures),
                 static_cast<unsigned long long>(next_reading_push_ms_ - now));
    logTaskCheckpoint("AFTER_RESPONSE_PARSE");
    return false;
  }
  const std::uint64_t acknowledgement =
      result["highest_contiguous_accepted_sequence"].as<std::uint64_t>();
  const std::uint64_t current_ack = config_.serverAckSequence();
  const std::uint64_t newest_sequence = storage_.health().newest_sequence;
  if (acknowledgement == current_ack) {
    ++metrics_.batch_failures;
    metrics_.last_error = "batch_ack_stalled";
    const std::uint64_t now = clock_.monotonicMs();
    next_reading_push_ms_ =
        now + operationRetryDelayMs(reading_retry_attempt_, 0, "readings");
    PM_LOG_WARN("SYNC", "READ_BATCH_NO_PROGRESS",
                "error=PM-SYNC-007 records=%u cursor_retained=%llu "
                "missing_ranges=%u failures=%llu retry_in_ms=%llu",
                static_cast<unsigned>(record_count),
                static_cast<unsigned long long>(current_ack),
                static_cast<unsigned>(
                    result["missing_ranges"].as<JsonArrayConst>().size()),
                static_cast<unsigned long long>(metrics_.batch_failures),
                static_cast<unsigned long long>(next_reading_push_ms_ - now));
    logTaskCheckpoint("AFTER_RESPONSE_PARSE");
    return false;
  }
  const bool acknowledgement_valid =
      acknowledgement >= current_ack && acknowledgement <= newest_sequence;
  const bool acknowledgement_persisted =
      acknowledgement_valid && (acknowledgement == current_ack ||
                                config_.setServerAckSequence(acknowledgement));
  if (!acknowledgement_persisted) {
    ++metrics_.batch_failures;
    metrics_.last_error = "batch_ack_invalid";
    next_reading_push_ms_ =
        clock_.monotonicMs() +
        operationRetryDelayMs(reading_retry_attempt_, 0, "readings");
    logTaskCheckpoint("AFTER_RESPONSE_PARSE");
    return false;
  }
  reading_retry_attempt_ = 0;
  next_reading_push_ms_ = 0;
  ++metrics_.batch_successes;
  metrics_.last_sync_utc_ms = clock_.utcMs();
  PM_LOG_INFO("SYNC", "READ_BATCH_COMPLETE",
              "records=%u ack_sequence=%llu has_more=%s successes=%llu",
              static_cast<unsigned>(record_count),
              static_cast<unsigned long long>(acknowledgement),
              page_has_more ? "true" : "false",
              static_cast<unsigned long long>(metrics_.batch_successes));
  PM_LOG_INFO(
      "HISTORY", "sensor.reading_batch_accepted",
      "record_count=%u first_sequence=%llu last_sequence=%llu "
      "acknowledged_sequence=%llu backlog=%llu",
      static_cast<unsigned>(record_count),
      static_cast<unsigned long long>(page.first_sequence),
      static_cast<unsigned long long>(page.last_sequence),
      static_cast<unsigned long long>(acknowledgement),
      static_cast<unsigned long long>(
          newest_sequence >= acknowledgement
              ? newest_sequence - acknowledgement
              : 0));
  PM_LOG_INFO(
      "HISTORY", "sensor.backlog_updated",
      "acknowledged_sequence=%llu newest_stored=%llu backlog=%llu",
      static_cast<unsigned long long>(acknowledgement),
      static_cast<unsigned long long>(newest_sequence),
      static_cast<unsigned long long>(
          newest_sequence >= acknowledgement
              ? newest_sequence - acknowledgement
              : 0));
  if (newest_sequence <= acknowledgement) {
    PM_LOG_INFO(
        "HISTORY", "history.backfill_completed",
        "acknowledged_sequence=%llu newest_stored=%llu backlog=0",
        static_cast<unsigned long long>(acknowledgement),
        static_cast<unsigned long long>(newest_sequence));
  }
  logTaskCheckpoint("AFTER_RESPONSE_PARSE");
  return true;
}

bool ServerSync::pushEvents() {
  HistoryQuery query;
  query.after_sequence = event_cursor_;
  query.limit = kEventBatchRecordLimit;
  query.maximum_payload_bytes = sync_policy::kEventBatchPayloadBytes;
  if (event_page_job_id_.empty()) {
    event_page_job_id_ = storage_coordinator_.queueHistory(query, true, true);
    if (event_page_job_id_.empty()) {
      next_event_push_ms_ =
          clock_.monotonicMs() +
          operationRetryDelayMs(event_retry_attempt_, 0, "events");
      PM_LOG_WARN("SYNC", "EVENT_BATCH_LOAD_FAILED",
                  "error=PM-SYNC-001 storage_error=storage_queue_unavailable");
      return false;
    }
    next_event_push_ms_ = clock_.monotonicMs() + 250U;
    PM_LOG_DEBUG("SYNC", "EVENT_BATCH_LOAD_QUEUED",
                 "job=%s owner=StorageTask", event_page_job_id_.c_str());
    return true;
  }
  HistoryPage page;
  bool complete = false;
  if (!storage_coordinator_.historyResult(event_page_job_id_, page, complete,
                                          true)) {
    PM_LOG_WARN("SYNC", "EVENT_BATCH_LOAD_FAILED",
                "error=PM-SYNC-001 storage_error=storage_job_expired job=%s",
                event_page_job_id_.c_str());
    event_page_job_id_.clear();
    next_event_push_ms_ =
        clock_.monotonicMs() +
        operationRetryDelayMs(event_retry_attempt_, 0, "events");
    return false;
  }
  if (!complete) {
    next_event_push_ms_ = clock_.monotonicMs() + 250U;
    return true;
  }
  PM_LOG_DEBUG("SYNC", "EVENT_BATCH_LOAD_COMPLETE",
               "job=%s records=%u owner=StorageTask",
               event_page_job_id_.c_str(),
               static_cast<unsigned>(page.records.size()));
  event_page_job_id_.clear();
  if (!page.ok || page.records.empty()) {
    if (!page.ok) {
      next_event_push_ms_ =
          clock_.monotonicMs() +
          operationRetryDelayMs(event_retry_attempt_, 0, "events");
    } else {
      event_retry_attempt_ = 0;
    }
    return page.ok;
  }
  PM_LOG_INFO("SYNC", "EVENT_BATCH_BEGIN",
              "events=%u first_sequence=%llu last_sequence=%llu",
              static_cast<unsigned>(page.records.size()),
              static_cast<unsigned long long>(page.first_sequence),
              static_cast<unsigned long long>(page.last_sequence));
  const std::size_t event_count = page.records.size();
  const std::uint64_t page_last_sequence = page.last_sequence;
  logTaskCheckpoint("BEFORE_JSON_BUILD");
  std::string body;
  {
    JsonDocument document;
    document["protocol_version"] = version::PROTOCOL;
    document["device_id"] = enrolledDeviceId(config_);
    JsonArray events = document["events"].to<JsonArray>();
    for (const auto &encoded : page.records) {
      JsonDocument event_document;
      if (deserializeJson(event_document, encoded) ||
          !event_document["event_sequence"].is<std::uint64_t>() ||
          !event_document["boot_id"].is<const char *>() ||
          !event_document["timestamp_utc"].is<const char *>() ||
          !event_document["code"].is<const char *>() ||
          !event_document["severity"].is<const char *>()) {
        ++metrics_.events_failures;
        metrics_.last_error = "stored_event_json_invalid";
        next_event_push_ms_ =
            clock_.monotonicMs() +
            operationRetryDelayMs(event_retry_attempt_, 0, "events");
        PM_LOG_ERROR("SYNC", "STORED_EVENT_INVALID",
                     "error=PM-SYNC-005 event=retained");
        return false;
      }
      const std::uint64_t sequence =
          event_document["event_sequence"].as<std::uint64_t>();
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
    serializeJson(document, body);
  }
  std::vector<std::string>().swap(page.records);
  logTaskCheckpoint("AFTER_JSON_BUILD");
  const HttpResult response =
      request("POST", "/api/v1/device-events/batch", std::move(body), true);
  if (response.status == 200) {
    logTaskCheckpoint("BEFORE_RESPONSE_PARSE");
    JsonDocument result;
    if (deserializeJson(result, response.body) ||
        !result["accepted"].is<JsonArray>() ||
        !result["duplicates"].is<JsonArray>() ||
        (!result["rejected"].isNull() && !result["rejected"].is<JsonArray>())) {
      ++metrics_.events_failures;
      metrics_.last_error = "event_response_contract_invalid";
      next_event_push_ms_ =
          clock_.monotonicMs() +
          operationRetryDelayMs(event_retry_attempt_, 0, "events");
      logTaskCheckpoint("AFTER_RESPONSE_PARSE");
      return false;
    }
    const std::size_t rejected_count =
        result["rejected"].isNull()
            ? 0U
            : result["rejected"].as<JsonArrayConst>().size();
    if (rejected_count != 0U) {
      ++metrics_.events_failures;
      metrics_.last_error = "event_records_rejected";
      const std::uint64_t now = clock_.monotonicMs();
      next_event_push_ms_ =
          now + operationRetryDelayMs(event_retry_attempt_, 0, "events");
      PM_LOG_ERROR("SYNC", "EVENT_BATCH_REJECTED",
                   "error=PM-SYNC-008 rejected=%u events=%u "
                   "cursor_retained=%llu failures=%llu retry_in_ms=%llu",
                   static_cast<unsigned>(rejected_count),
                   static_cast<unsigned>(event_count),
                   static_cast<unsigned long long>(event_cursor_),
                   static_cast<unsigned long long>(metrics_.events_failures),
                   static_cast<unsigned long long>(next_event_push_ms_ - now));
      logTaskCheckpoint("AFTER_RESPONSE_PARSE");
      return false;
    }
    event_cursor_ = page_last_sequence;
    event_retry_attempt_ = 0;
    ++metrics_.events_successes;
    PM_LOG_INFO("SYNC", "EVENT_BATCH_COMPLETE",
                "events=%u cursor=%llu successes=%llu",
                static_cast<unsigned>(event_count),
                static_cast<unsigned long long>(event_cursor_),
                static_cast<unsigned long long>(metrics_.events_successes));
    logTaskCheckpoint("AFTER_RESPONSE_PARSE");
    return true;
  }
  ++metrics_.events_failures;
  metrics_.last_error = response.problem_code.empty() ? "event_batch_failed"
                                                      : response.problem_code;
  next_event_push_ms_ =
      clock_.monotonicMs() + operationRetryDelayMs(event_retry_attempt_,
                                                   response.retry_after_ms,
                                                   "events");
  PM_LOG_WARN(
      "SYNC", "EVENT_BATCH_FAILED",
      "error=PM-SYNC-004 status=%d problem=%s failures=%llu retry_in_ms=%llu",
      response.status,
      response.problem_code.empty() ? "none" : response.problem_code.c_str(),
      static_cast<unsigned long long>(metrics_.events_failures),
      static_cast<unsigned long long>(next_event_push_ms_ -
                                      clock_.monotonicMs()));
  return false;
}

bool ServerSync::fetchConfiguration() {
  PM_LOG_DEBUG("CONFIG", "REMOTE_FETCH_BEGIN", "current_server_version=%lu",
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
  if (!document["protocol_version"].is<const char *>() ||
      std::string(document["protocol_version"].as<const char *>()) !=
          version::PROTOCOL ||
      !document["device_id"].is<const char *>() ||
      !crypto::constantTimeEqual(
          std::string(document["device_id"].as<const char *>()),
          config_.identity().device_id) ||
      !document["version"].is<std::uint32_t>() ||
      !document["settings"].is<JsonObject>() ||
      !document["sha256"].is<const char *>() ||
      !lowercaseHex(document["sha256"].as<const char *>(), 64U)) {
    PM_LOG_ERROR("CONFIG", "REMOTE_RESPONSE_INVALID",
                 "error=PM-CONFIG-006 category=contract_shape_invalid");
    return false;
  }
  const std::uint32_t requested_version =
      document["version"].as<std::uint32_t>();
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
  JsonDocument translated;
  translated["config_version"] = requested_version;
  JsonObjectConst settings = document["settings"].as<JsonObjectConst>();
  if (!settings["connection_mode"].isNull() &&
      (!settings["connection_mode"].is<const char *>() ||
       std::strcmp(settings["connection_mode"].as<const char *>(), "push") !=
           0)) {
    metrics_.last_error = "remote_connection_mode_unsupported";
    PM_LOG_ERROR("CONFIG", "REMOTE_UPDATE_REJECTED",
                 "error=PM-CONFIG-031 version=%lu "
                 "validation=connection_mode_unsupported "
                 "supported_mode=push configuration_changed=false",
                 static_cast<unsigned long>(requested_version));
    reportConfiguration(requested_version, "rejected",
                        "connection_mode_unsupported");
    return false;
  }
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
  std::string config_body;
  serializeJson(translated, config_body);
  const RuntimeConfig previous = config_.config();
  ConfigValidation validation;
  std::uint64_t applied_generation = 0;
  const bool applied = config_.updateFromJson(config_body, false, false, true,
                                              validation, &applied_generation);
  if (applied && stationConfigurationChanged(previous, config_.config())) {
    pending_config_version_ = requested_version;
    pending_config_generation_ = applied_generation;
    pending_config_started_ms_ = clock_.monotonicMs();
    next_config_validation_attempt_ms_ = pending_config_started_ms_ + 2000U;
    pending_config_validation_ = true;
    pending_config_rollback_report_ = false;
    pending_config_report_detail_ = "post_apply_connectivity_failed";
    PM_LOG_INFO("CONFIG", "REMOTE_NETWORK_UPDATE_STAGED",
                "version=%lu generation=%llu validation_window_ms=30000 "
                "rollback=automatic",
                static_cast<unsigned long>(requested_version),
                static_cast<unsigned long long>(applied_generation));
    network_.requestConfigurationApply(0);
    return true;
  }
  const bool report_ok =
      reportConfiguration(requested_version, applied ? "applied" : "rejected",
                          validation.code.c_str());
  if (applied && networkCriticalChanged(previous, config_.config()) &&
      !report_ok) {
    const bool restored = config_.rollbackToPrevious(applied_generation);
    reportConfiguration(requested_version, "rolled_back",
                        restored ? "server_connectivity_validation_failed"
                                 : "configuration_rollback_failed");
    metrics_.last_error = restored ? "network_config_rolled_back"
                                   : "network_config_rollback_failed";
    PM_LOG_ERROR("CONFIG", "REMOTE_CONNECTIVITY_ROLLBACK",
                 "error=PM-CONFIG-007 version=%lu restored=%s",
                 static_cast<unsigned long>(requested_version),
                 restored ? "true" : "false");
    return false;
  }
  PM_LOG_INFO("CONFIG", "REMOTE_UPDATE_COMPLETE",
              "version=%lu applied=%s report=%s validation=%s",
              static_cast<unsigned long>(requested_version),
              applied ? "true" : "false", report_ok ? "success" : "failed",
              validation.code.c_str());
  return applied && report_ok;
}

bool ServerSync::reportConfiguration(const std::uint32_t version,
                                     const char *status, const char *detail) {
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
      request("POST", "/api/v1/device-config/report", std::move(body), true);
  bool recorded = response.status == 204;
  if (response.status == 200) {
    JsonDocument result;
    recorded = !deserializeJson(result, response.body) &&
               result["recorded"].is<bool>() && result["recorded"].as<bool>();
  }
  if (recorded && std::strcmp(status, "applied") == 0) {
    return config_.setServerConfigVersion(version);
  }
  return recorded;
}

bool ServerSync::checkFirmwareManifest() {
  PM_LOG_DEBUG("OTA", "REMOTE_MANIFEST_CHECK_BEGIN", "channel=%s current=%s",
               config_.config().ota_channel.c_str(), version::FIRMWARE);
  const std::string endpoint =
      "/api/v1/device-firmware/manifest?channel=" +
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
  if (!document["available"].is<bool>() ||
      (!document["protocol_version"].isNull() &&
       (!document["protocol_version"].is<const char *>() ||
        std::string(document["protocol_version"].as<const char *>()) !=
            version::PROTOCOL))) {
    PM_LOG_ERROR("OTA", "REMOTE_MANIFEST_INVALID",
                 "error=PM-OTA-003 category=contract_shape_invalid");
    return false;
  }
  if (!document["available"].as<bool>()) {
    available_firmware_version_.clear();
    PM_LOG_INFO("OTA", "REMOTE_MANIFEST_CURRENT", "update_available=false");
    return true;
  }
  if (!document["version"].is<const char *>() ||
      std::string(document["version"].as<const char *>()).empty() ||
      !document["channel"].is<const char *>() ||
      !document["hardware_target"].is<const char *>() ||
      std::string(document["hardware_target"].as<const char *>()) !=
          version::HARDWARE_TARGET ||
      !document["protocol_min"].is<const char *>() ||
      !document["protocol_max"].is<const char *>() ||
      !document["size_bytes"].is<std::uint32_t>() ||
      document["size_bytes"].as<std::uint32_t>() == 0U ||
      document["size_bytes"].as<std::uint32_t>() > 0x600000U ||
      !document["sha256"].is<const char *>() ||
      !lowercaseHex(document["sha256"].as<const char *>(), 64U) ||
      !document["signature"].is<const char *>() ||
      !document["signing_key_id"].is<const char *>() ||
      std::string(document["signing_key_id"].as<const char *>()).empty() ||
      !document["release_notes"].is<const char *>() ||
      !document["download_path"].is<const char *>() ||
      std::string(document["download_path"].as<const char *>())
              .rfind("/api/v1/device-firmware/", 0) != 0) {
    PM_LOG_ERROR("OTA", "REMOTE_MANIFEST_INVALID",
                 "error=PM-OTA-003 category=signed_fields_missing_or_invalid "
                 "fail_closed=true");
    return false;
  }
  available_firmware_version_ = document["version"].as<const char *>();
  PM_LOG_INFO("OTA", "REMOTE_MANIFEST_AVAILABLE",
              "update_available=%s target_version=%s",
              available_firmware_version_.empty() ? "false" : "true",
              available_firmware_version_.empty()
                  ? "none"
                  : available_firmware_version_.c_str());
  const RuntimeConfig active_config = config_.config();
  const std::string signing_key_id =
      document["signing_key_id"].as<const char *>();
  if (config_.otaPublicKey().empty()) {
    PM_LOG_ERROR("OTA", "REMOTE_UPDATE_DISABLED",
                 "error=PM-OTA-005 reason=public_key_unavailable "
                 "provisioning=authenticated_local_only");
    return false;
  }
  if (!active_config.ota_signing_key_id.empty() &&
      active_config.ota_signing_key_id != signing_key_id) {
    PM_LOG_ERROR("OTA", "REMOTE_UPDATE_DISABLED",
                 "error=PM-OTA-005 reason=key_id_mismatch expected=%s "
                 "received=%s",
                 active_config.ota_signing_key_id.c_str(),
                 signing_key_id.c_str());
    return false;
  }
  if (maintenance_queue_ == nullptr) {
    PM_LOG_ERROR("OTA", "REMOTE_UPDATE_QUEUE_FAILED",
                 "error=PM-OTA-010 reason=queue_unavailable");
    return false;
  }
  MaintenanceMessage message;
  message.action = MaintenanceAction::ApplyOta;
  const std::string manifest_url =
      active_config.server_url + "/api/v1/device-firmware/manifest";
  const int written = std::snprintf(message.argument, sizeof(message.argument),
                                    "%s", manifest_url.c_str());
  if (written < 0 ||
      static_cast<std::size_t>(written) >= sizeof(message.argument) ||
      xQueueSend(maintenance_queue_, &message, 0) != pdTRUE) {
    PM_LOG_ERROR("OTA", "REMOTE_UPDATE_QUEUE_FAILED",
                 "error=PM-OTA-010 reason=queue_full_or_url_too_large");
    return false;
  }
  PM_LOG_INFO("OTA", "REMOTE_UPDATE_QUEUED",
              "target_version=%s key_id=%s source=central_manifest",
              available_firmware_version_.c_str(), signing_key_id.c_str());
  return true;
}

ServerSync::HttpResult ServerSync::request(const char *method,
                                           const std::string &endpoint,
                                           std::string body,
                                           const bool authenticated) {
  HttpResult result;
  const std::uint32_t request_id = ++request_sequence_;
  const std::uint64_t started_ms = clock_.monotonicMs();
  if (!single_flight_.tryBegin()) {
    result.error = "sync_transaction_in_progress";
    metrics_.sync_pending = single_flight_.pending();
    diagnostics_.setSyncMetrics(metrics_);
    PM_LOG_WARN("SYNC", "SYNC_COALESCED",
                "request_id=%lu reason=single_flight_active pending=%s",
                static_cast<unsigned long>(request_id),
                metrics_.sync_pending ? "true" : "false");
    return result;
  }
  metrics_.sync_in_progress = true;
  metrics_.sync_pending = single_flight_.pending();
  metrics_.active_request_id = request_id;
  ++metrics_.transactions_started;
  logTaskCheckpoint("TRANSACTION_START");
  PM_LOG_INFO("SYNC", "SYNC_STARTED",
              "request_id=%lu owner=ServerSyncTask pending=%s "
              "transactions_started=%llu",
              static_cast<unsigned long>(request_id),
              metrics_.sync_pending ? "true" : "false",
              static_cast<unsigned long long>(metrics_.transactions_started));
  PM_LOG_INFO("SYNC", "SYNC_BEGIN",
              "request_id=%lu endpoint=%s overall_timeout_ms=%lu",
              static_cast<unsigned long>(request_id), endpoint.c_str(),
              static_cast<unsigned long>(kOverallRequestTimeoutMs));
  SyncTransactionCleanup transaction(
      single_flight_, metrics_, diagnostics_, clock_, request_id, method,
      endpoint, result.status, result.error, result.problem_code,
      result.tls_category, result.retry_after_ms, result.body, started_ms);
  // StorageTask bounds and bulk-reads every history page, but it may already
  // own the shared FATFS/TLS memory gate when a heartbeat becomes due.  The
  // server-sync task is intentionally excluded from the task watchdog because
  // a verified TLS transaction can also exceed five seconds.  Wait for the
  // bounded storage operation instead of reporting a false transport outage
  // and delaying the authoritative heartbeat behind exponential backoff.
  HighMemoryLease high_memory_lease(diagnostics_, pdMS_TO_TICKS(5000));
  if (!high_memory_lease) {
    result.error = "high_memory_operation_busy";
    result.tls_category = "MEMORY_EXHAUSTED";
    PM_LOG_WARN("MEMORY", "HIGH_MEMORY_GATE_TIMEOUT",
                "error=PM-TLS-006 request_id=%lu retryable=true",
                static_cast<unsigned long>(request_id));
    return result;
  }
  PM_LOG_INFO(
      "HTTP", "HTTP_BEGIN",
      "request_id=%lu method=%s endpoint=%s authenticated=%s request_bytes=%u",
      static_cast<unsigned long>(request_id), method, endpoint.c_str(),
      authenticated ? "true" : "false", static_cast<unsigned>(body.size()));
  if (body.size() > sync_policy::kMaximumResponseBytes) {
    result.error = "request_body_too_large";
    PM_LOG_ERROR("HTTP", "REQUEST_BODY_REJECTED",
                 "error=PM-HTTP-003 request_id=%lu request_bytes=%u "
                 "maximum_bytes=%u",
                 static_cast<unsigned long>(request_id),
                 static_cast<unsigned>(body.size()),
                 static_cast<unsigned>(sync_policy::kMaximumResponseBytes));
    return result;
  }
  if (!clock_.synchronized()) {
    result.error = "tls_time_not_trusted";
    PM_LOG_ERROR("TLS", "TIME_NOT_TRUSTED",
                 "error=PM-TLS-003 request_id=%lu category=TIME_NOT_TRUSTED",
                 static_cast<unsigned long>(request_id));
    return result;
  }
  const TransportConfig active_config = transportConfig(config_);
  if (active_config.server_ca_pem.empty()) {
    result.error = active_config.server_fingerprint.empty()
                       ? "tls_ca_not_configured"
                       : "tls_fingerprint_only_rejected";
    PM_LOG_ERROR("TLS", "CA_REQUIRED",
                 "error=PM-TLS-001 request_id=%lu category=CA_MISSING "
                 "fingerprint_configured=%s insecure_mode=false",
                 static_cast<unsigned long>(request_id),
                 active_config.server_fingerprint.empty() ? "false" : "true");
    return result;
  }
  const std::uint32_t initial_free_internal =
      heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  const std::uint32_t initial_largest_internal =
      heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  if (!sync_policy::tlsMemoryReserveAvailable(initial_free_internal,
                                              initial_largest_internal)) {
    result.error = "internal_heap_reserve_low";
    result.tls_category = "MEMORY_EXHAUSTED";
    PM_LOG_WARN(
        "MEMORY", "HEAP_LOW",
        "error=PM-TLS-006 request_id=%lu stage=preflight "
        "free_internal_heap=%lu largest_internal_block=%lu "
        "minimum_free_internal=%lu minimum_largest_block=%lu",
        static_cast<unsigned long>(request_id),
        static_cast<unsigned long>(initial_free_internal),
        static_cast<unsigned long>(initial_largest_internal),
        static_cast<unsigned long>(sync_policy::kMinimumInternalHeapBytes),
        static_cast<unsigned long>(
            sync_policy::kMinimumLargestInternalBlockBytes));
    return result;
  }
  if (diag::SerialLogger::instance().allow("tls_ca_metadata", 3'600'000U)) {
    logCaMetadata(active_config.server_ca_pem);
  }
  std::string canonical_target;
  if (!crypto::canonicalTarget(endpoint, canonical_target)) {
    result.error = "request_target_invalid";
    PM_LOG_ERROR("HTTP", "TARGET_INVALID",
                 "error=PM-HTTP-002 request_id=%lu method=%s endpoint=%s",
                 static_cast<unsigned long>(request_id), method,
                 endpoint.c_str());
    return result;
  }
  std::string target_host;
  std::uint16_t target_port = 443;
  if (!parseHttpsTarget(active_config.server_url, target_host, target_port) ||
      !hostAllowed(active_config, target_host)) {
    result.error = "server_address_not_allowed";
    PM_LOG_ERROR("SERVER", "TARGET_REJECTED",
                 "error=PM-SERVER-003 request_id=%lu host=%s port=%u",
                 static_cast<unsigned long>(request_id),
                 target_host.empty() ? "invalid" : target_host.c_str(),
                 static_cast<unsigned>(target_port));
    return result;
  }
  const std::string url = joinUrl(active_config.server_url, endpoint);
  IPAddress resolved;
  const bool literal_address = resolved.fromString(target_host.c_str());
  std::uint32_t cached_address_value = 0U;
  const bool cached_address =
      !literal_address &&
      endpoint_address_cache_.lookup(target_host, target_port,
                                     cached_address_value);
  if (cached_address) {
    resolved = cached_address_value;
  }
  const char *resolution_method =
      literal_address ? "literal" : (cached_address ? "cache" : "dns");
  const std::uint64_t dns_started = clock_.monotonicMs();
  logTaskCheckpoint("BEFORE_DNS");
  PM_LOG_DEBUG(
      "DNS", "DNS_BEGIN", "request_id=%lu host=%s method=%s mdns_fallback=%s",
      static_cast<unsigned long>(request_id), target_host.c_str(),
      resolution_method, dotLocalHost(target_host) ? "enabled" : "disabled");
  bool resolved_ok =
      literal_address || cached_address ||
      (WiFi.hostByName(target_host.c_str(), resolved) == 1 &&
       static_cast<std::uint32_t>(resolved) != 0U && resolved != INADDR_NONE);
  if (!resolved_ok && dotLocalHost(target_host)) {
    const std::string mdns_host =
        target_host.substr(0, target_host.size() - std::strlen(".local"));
    PM_LOG_INFO("DNS", "MDNS_FALLBACK_BEGIN",
                "request_id=%lu host=%s query=%s reason=unicast_dns_failed",
                static_cast<unsigned long>(request_id), target_host.c_str(),
                mdns_host.c_str());
    resolved = MDNS.queryHost(mdns_host.c_str(), 2000U);
    resolved_ok =
        static_cast<std::uint32_t>(resolved) != 0U && resolved != INADDR_NONE;
    if (resolved_ok)
      resolution_method = "mdns";
  }
  if (!resolved_ok) {
    result.error = "dns_resolution_failed";
    PM_LOG_ERROR(
        "DNS", "DNS_FAILED",
        "error=PM-DNS-001 request_id=%lu host=%s methods=dns,mdns_if_local "
        "elapsed_ms=%llu",
        static_cast<unsigned long>(request_id), target_host.c_str(),
        static_cast<unsigned long long>(clock_.monotonicMs() - dns_started));
    return result;
  }
  const std::uint64_t dns_elapsed_ms = clock_.monotonicMs() - dns_started;
  if (dns_elapsed_ms > kDnsExpectedTimeoutMs) {
    result.error = "dns_timeout";
    PM_LOG_ERROR("DNS", "DNS_FAILED",
                 "error=PM-DNS-002 request_id=%lu host=%s elapsed_ms=%llu "
                 "deadline_ms=%lu",
                 static_cast<unsigned long>(request_id), target_host.c_str(),
                 static_cast<unsigned long long>(dns_elapsed_ms),
                 static_cast<unsigned long>(kDnsExpectedTimeoutMs));
    return result;
  }
  if (!literal_address && !cached_address) {
    endpoint_address_cache_.update(target_host, target_port,
                                   static_cast<std::uint32_t>(resolved));
    PM_LOG_DEBUG("DNS", "DNS_CACHE_UPDATED",
                 "request_id=%lu host=%s address=%s port=%u",
                 static_cast<unsigned long>(request_id), target_host.c_str(),
                 resolved.toString().c_str(),
                 static_cast<unsigned>(target_port));
  }
  PM_LOG_INFO("DNS", "DNS_SUCCESS",
              "request_id=%lu host=%s address=%s method=%s elapsed_ms=%llu",
              static_cast<unsigned long>(request_id), target_host.c_str(),
              resolved.toString().c_str(), resolution_method,
              static_cast<unsigned long long>(dns_elapsed_ms));
  logTaskCheckpoint("AFTER_DNS");
  const std::uint32_t free_internal =
      heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  const std::uint32_t largest_internal =
      heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  if (!sync_policy::tlsMemoryReserveAvailable(free_internal,
                                              largest_internal)) {
    result.error = "internal_heap_reserve_low";
    result.tls_category = "MEMORY_EXHAUSTED";
    PM_LOG_WARN(
        "MEMORY", "HEAP_LOW",
        "error=PM-TLS-006 request_id=%lu stage=before_tls "
        "free_internal_heap=%lu largest_internal_block=%lu "
        "minimum_free_internal=%lu minimum_largest_block=%lu",
        static_cast<unsigned long>(request_id),
        static_cast<unsigned long>(free_internal),
        static_cast<unsigned long>(largest_internal),
        static_cast<unsigned long>(sync_policy::kMinimumInternalHeapBytes),
        static_cast<unsigned long>(
            sync_policy::kMinimumLargestInternalBlockBytes));
    return result;
  }
  if (clock_.monotonicMs() - started_ms >= kOverallRequestTimeoutMs) {
    result.error = "request_overall_timeout";
    result.tls_category = "TIMEOUT";
    return result;
  }
  const std::uint32_t pre_tls_stack_bytes =
      static_cast<std::uint32_t>(uxTaskGetStackHighWaterMark(nullptr));
  if (pre_tls_stack_bytes <
      task_config::kMinimumTlsStackHighWaterBytes) {
    result.error = "sync_stack_reserve_low";
    result.tls_category = "MEMORY_EXHAUSTED";
    PM_LOG_ERROR(
        "TASK", "TLS_STACK_PREFLIGHT_REJECTED",
        "error=PM-TASK-003 request_id=%lu high_water_bytes=%lu "
        "minimum_high_water_bytes=%lu action=request_deferred web_ui_preserved=true",
        static_cast<unsigned long>(request_id),
        static_cast<unsigned long>(pre_tls_stack_bytes),
        static_cast<unsigned long>(
            task_config::kMinimumTlsStackHighWaterBytes));
    return result;
  }
  WiFiClientSecure client;
  client.setHandshakeTimeout(kTlsHandshakeTimeoutSeconds);
  client.setTimeout(kTcpConnectTimeoutMs / 1000U);
  client.setCACert(active_config.server_ca_pem.c_str());
  HTTPClient http;
  TransportCleanup transport(http, client, request_id);
  http.setConnectTimeout(kTcpConnectTimeoutMs);
  http.setTimeout(kHttpResponseTimeoutMs);
  http.setReuse(false);
  if (!http.begin(client, url.c_str())) {
    result.error = "http_begin_failed";
    result.tls_category = "TLS_NEGOTIATION_FAILED";
    PM_LOG_ERROR(
        "TLS", "CLIENT_BEGIN_FAILED",
        "error=PM-TLS-004 request_id=%lu category=%s elapsed_ms=%llu",
        static_cast<unsigned long>(request_id), result.tls_category.c_str(),
        static_cast<unsigned long long>(clock_.monotonicMs() - started_ms));
    return result;
  }
  transport.markHttpBegun();
  static constexpr char retry_after_header[] = "Retry-After";
  const char *response_headers[] = {retry_after_header};
  http.collectHeaders(response_headers, 1U);
  logTaskCheckpoint("BEFORE_TLS");
  PM_LOG_INFO("TCP", "TCP_BEGIN",
              "request_id=%lu host=%s address=%s port=%u timeout_ms=%lu "
              "transport=secure_client_combined",
              static_cast<unsigned long>(request_id), target_host.c_str(),
              resolved.toString().c_str(), static_cast<unsigned>(target_port),
              static_cast<unsigned long>(kTcpConnectTimeoutMs));
  PM_LOG_INFO(
      "TLS", "TLS_BEGIN",
      "request_id=%lu host=%s port=%u ca_validation=true "
      "hostname_validation=true timeout_s=%lu heap_free=%lu "
      "free_internal_heap=%lu largest_internal_block=%lu psram_free=%lu",
      static_cast<unsigned long>(request_id), target_host.c_str(),
      static_cast<unsigned>(target_port),
      static_cast<unsigned long>(kTlsHandshakeTimeoutSeconds),
      static_cast<unsigned long>(ESP.getFreeHeap()),
      static_cast<unsigned long>(free_internal),
      static_cast<unsigned long>(largest_internal),
      static_cast<unsigned long>(ESP.getFreePsram()));
  errno = 0;
  const bool tls_connected =
      client.connect(resolved, target_port, target_host.c_str(),
                     active_config.server_ca_pem.c_str(), nullptr,
                     nullptr) == 1;
  const int socket_error = errno;
  if (!tls_connected) {
    std::array<char, 192> tls_error{};
    const int tls_error_code =
        client.lastError(tls_error.data(), tls_error.size());
    std::string detail =
        tls_error_code == 0 ? std::string{} : std::string(tls_error.data());
    if ((detail.empty() || tls_error_code == -1) && socket_error != 0) {
      detail = std::strerror(socket_error);
    }
    if (detail.empty())
      detail = "tls_connection_failed";
    result.error = detail;
    result.tls_category = diag::tlsErrorCategory(detail.c_str());
    PM_LOG_ERROR(
        "TCP", "TCP_FAILED",
        "error=PM-TCP-001 request_id=%lu host=%s port=%u category=%s "
        "socket_error=%d elapsed_ms=%llu transport=secure_client_combined",
        static_cast<unsigned long>(request_id), target_host.c_str(),
        static_cast<unsigned>(target_port), result.tls_category.c_str(),
        socket_error,
        static_cast<unsigned long long>(clock_.monotonicMs() - started_ms));
    PM_LOG_ERROR(
        "TLS", "TLS_FAILED",
        "error=PM-TLS-004 request_id=%lu host=%s port=%u category=%s "
        "tls_error=%d socket_error=%d detail=%s elapsed_ms=%llu",
        static_cast<unsigned long>(request_id), target_host.c_str(),
        static_cast<unsigned>(target_port), result.tls_category.c_str(),
        tls_error_code, socket_error, detail.c_str(),
        static_cast<unsigned long long>(clock_.monotonicMs() - started_ms));
    if (cached_address) {
      if (endpoint_address_cache_.recordTransportFailure()) {
        PM_LOG_WARN("DNS", "DNS_CACHE_INVALIDATED",
                    "request_id=%lu host=%s address=%s "
                    "consecutive_transport_failures=2",
                    static_cast<unsigned long>(request_id),
                    target_host.c_str(), resolved.toString().c_str());
      }
    }
    return result;
  }
  endpoint_address_cache_.recordTransportSuccess();
  PM_LOG_INFO("TCP", "TCP_CONNECTED",
              "request_id=%lu address=%s port=%u "
              "transport=secure_client_combined",
              static_cast<unsigned long>(request_id),
              resolved.toString().c_str(), static_cast<unsigned>(target_port));
  client.setTimeout(kHttpResponseTimeoutMs / 1000U);
  PM_LOG_INFO(
      "TLS", "TLS_SUCCESS",
      "request_id=%lu host=%s address=%s port=%u ca_validation=true "
      "hostname_validation=true heap_free=%lu heap_min=%lu elapsed_ms=%llu",
      static_cast<unsigned long>(request_id), target_host.c_str(),
      resolved.toString().c_str(), static_cast<unsigned>(target_port),
      static_cast<unsigned long>(ESP.getFreeHeap()),
      static_cast<unsigned long>(ESP.getMinFreeHeap()),
      static_cast<unsigned long long>(clock_.monotonicMs() - started_ms));
  logTaskCheckpoint("AFTER_TLS");
  if (clock_.monotonicMs() - started_ms >= kOverallRequestTimeoutMs) {
    result.error = "request_overall_timeout";
    result.tls_category = "TIMEOUT";
    return result;
  }
  http.addHeader("Content-Type", "application/json");
  if (authenticated) {
    logTaskCheckpoint("BEFORE_HMAC");
    crypto::Key32 outbound{};
    crypto::Key32 inbound{};
    if (!config_.directionalKeys(outbound, inbound)) {
      result.error = "device_credentials_unavailable";
      return result;
    }
    const std::string device_id = enrolledDeviceId(config_);
    const std::string timestamp = std::to_string(std::time(nullptr));
    const std::string nonce = crypto::randomHex(16);
    const std::string body_hash = crypto::sha256Hex(
        reinterpret_cast<const std::uint8_t *>(body.data()), body.size());
    const std::string canonical = crypto::canonicalRequest(
        method, canonical_target, timestamp, nonce, body_hash);
    http.addHeader("X-PM-Protocol", version::PROTOCOL);
    http.addHeader("X-PM-Device-ID", device_id.c_str());
    http.addHeader("X-PM-Timestamp", timestamp.c_str());
    http.addHeader("X-PM-Nonce", nonce.c_str());
    http.addHeader("X-PM-Content-SHA256", body_hash.c_str());
    const std::string signature =
        crypto::hmacSha256Hex(outbound.data(), outbound.size(), canonical);
    http.addHeader("X-PM-Signature", signature.c_str());
    std::fill(outbound.begin(), outbound.end(), 0U);
    std::fill(inbound.begin(), inbound.end(), 0U);
    logTaskCheckpoint("AFTER_HMAC");
  } else {
    http.addHeader("X-PM-Protocol", version::PROTOCOL);
  }
  logTaskCheckpoint("BEFORE_HTTP_SEND");
  if (std::string(method) == "GET") {
    result.status = http.GET();
  } else {
    result.status = http.sendRequest(
        method,
        reinterpret_cast<std::uint8_t *>(const_cast<char *>(body.data())),
        body.size());
  }
  // HTTPClient::sendRequest is synchronous. Once it returns, the signed bytes
  // have been sent and the outbound buffer can be released before a response
  // allocation is attempted.
  std::string().swap(body);
  logTaskCheckpoint("AFTER_HTTP_SEND");
  if (clock_.monotonicMs() - started_ms >= kOverallRequestTimeoutMs) {
    result.error = "request_overall_timeout";
    result.tls_category = "TIMEOUT";
    result.status = -1;
    return result;
  }
  if (result.status > 0) {
    PM_LOG_INFO(
        "HTTP", "HTTP_HEADERS_RECEIVED",
        "request_id=%lu status=%d content_length=%d elapsed_ms=%llu",
        static_cast<unsigned long>(request_id), result.status, http.getSize(),
        static_cast<unsigned long long>(clock_.monotonicMs() - started_ms));
    result.retry_after_ms =
        retryAfterMilliseconds(http.header(retry_after_header));
    const int response_size = http.getSize();
    if (!sync_policy::responseLengthAllowed(response_size, result.status)) {
      result.error =
          response_size < 0 ? "response_length_required" : "response_too_large";
      result.status = -1;
    } else if (!sync_policy::responseAllocationAvailable(
                   heap_caps_get_free_size(MALLOC_CAP_INTERNAL |
                                           MALLOC_CAP_8BIT),
                   heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL |
                                                    MALLOC_CAP_8BIT),
                   response_size)) {
      result.error = "response_memory_reserve_low";
      result.tls_category = "MEMORY_EXHAUSTED";
      result.status = -1;
      PM_LOG_WARN("MEMORY", "HEAP_LOW",
                  "error=PM-TLS-006 request_id=%lu stage=response_allocation "
                  "response_bytes=%d minimum_post_response_internal=%lu",
                  static_cast<unsigned long>(request_id), response_size,
                  static_cast<unsigned long>(
                      sync_policy::kMinimumPostResponseInternalHeapBytes));
    } else if (result.status != 204 &&
               !readBoundedResponseBody(http, clock_, response_size,
                                        result.body, result.error)) {
      result.tls_category = diag::tlsErrorCategory(result.error.c_str());
      result.status = -1;
    } else if (result.status < 200 || result.status >= 300) {
      result.problem_code = problemCode(result.body);
    }
  } else {
    result.error = HTTPClient::errorToString(result.status).c_str();
    result.tls_category = diag::tlsErrorCategory(result.error.c_str());
  }
  return result;
}

std::string ServerSync::heartbeatBody() const {
  const NetworkStatus network = network_.status();
  const StorageHealth storage = storage_.health();
  const MeterMetrics meter = meter_.metrics();
  const RuntimeConfig active_config = config_.config();
  const DeviceIdentity identity = config_.identity();
  MeasurementSnapshot latest;
  const bool has_latest = diagnostics_.latest(latest);
  JsonDocument document;
  document["schema_version"] = "heartbeat/1.0.0";
  document["protocol_version"] = version::PROTOCOL;
  document["device_id"] = identity.device_id;
  document["boot_id"] = identity.boot_id;
  document["firmware_version"] = version::FIRMWARE;
  document["firmware_build_hash"] = version::GIT_COMMIT;
  document["uptime_seconds"] = clock_.monotonicMs() / 1000U;
  document["reboot_reason"] = resetReasonName();
  document["current_ip"] = network.ip_address;
  document["hostname"] = network.hostname;
  document["rssi_dbm"] = network.rssi_dbm;
  document["connection_mode"] =
      connectionModeName(active_config.connection_mode);
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
  const bool storage_ok =
      storage.present && storage.mounted && storage.writable;
  storage_json["ok"] = storage_ok;
  storage_json["status"] = storage_ok ? "healthy" : "storage_unavailable";
  storage_json["error_count"] = storage.write_failures;
  JsonObject storage_details = storage_json["details"].to<JsonObject>();
  storage_details["present"] = storage.present;
  storage_details["mounted"] = storage.mounted;
  storage_details["writable"] = storage.writable;
  storage_details["free_bytes"] = storage.free_bytes;
  storage_details["last_error"] = storage.last_error;
  document["oldest_stored_sequence"] = storage.oldest_sequence;
  document["oldest_syncable_sequence"] = storage.oldest_syncable_sequence;
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
  const std::uint32_t seconds =
      heartbeat_interval_override_seconds_ == 0
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

std::uint32_t ServerSync::retryDelayMs(const std::uint32_t retry_after_ms) {
  const std::uint32_t exponent = std::min<std::uint32_t>(retry_attempt_, 10U);
  if (retry_attempt_ != std::numeric_limits<std::uint32_t>::max()) {
    ++retry_attempt_;
  }
  const std::uint64_t configured_maximum =
      static_cast<std::uint64_t>(config_.config().sync_retry_max_seconds) *
      1000U;
  const std::uint32_t maximum =
      static_cast<std::uint32_t>(std::min<std::uint64_t>(
          std::max<std::uint64_t>(configured_maximum, 1000U),
          std::numeric_limits<std::uint32_t>::max()));
  const bool server_directed = retry_after_ms != 0U;
  const std::uint32_t effective_maximum =
      server_directed ? std::numeric_limits<std::uint32_t>::max() : maximum;
  const std::uint32_t base =
      server_directed ? retry_after_ms
                      : std::min<std::uint32_t>(1000U << exponent, maximum);
  std::uint32_t jitter = 0;
  if (!server_directed) {
    const std::uint32_t jitter_ceiling =
        std::min<std::uint32_t>(base / 5U, maximum - base);
    std::array<std::uint8_t, 2> random{};
    crypto::secureRandom(random.data(), random.size());
    jitter = ((static_cast<std::uint32_t>(random[0]) << 8U) | random[1]) %
             (jitter_ceiling + 1U);
  }
  const std::uint32_t delay_ms = base + jitter;
  PM_LOG_WARN("SERVER", "SYNC_RETRY_SCHEDULED",
              "attempt=%lu source=%s base_ms=%lu jitter_ms=%lu delay_ms=%lu "
              "maximum_ms=%lu",
              static_cast<unsigned long>(retry_attempt_),
              server_directed ? "retry_after" : "exponential_backoff",
              static_cast<unsigned long>(base),
              static_cast<unsigned long>(jitter),
              static_cast<unsigned long>(delay_ms),
              static_cast<unsigned long>(effective_maximum));
  return delay_ms;
}

std::uint32_t
ServerSync::operationRetryDelayMs(std::uint32_t &attempt,
                                  const std::uint32_t retry_after_ms,
                                  const char *operation) {
  const std::uint64_t configured_maximum =
      static_cast<std::uint64_t>(config_.config().sync_retry_max_seconds) *
      1000U;
  const std::uint32_t maximum =
      static_cast<std::uint32_t>(std::min<std::uint64_t>(
          std::max<std::uint64_t>(configured_maximum, 1000U),
          std::numeric_limits<std::uint32_t>::max()));
  const std::uint32_t exponent = std::min<std::uint32_t>(attempt, 10U);
  if (attempt != std::numeric_limits<std::uint32_t>::max())
    ++attempt;

  std::uint32_t base = 0;
  std::uint32_t jitter = 0;
  const char *source = "exponential_backoff";
  if (retry_after_ms != 0U) {
    base = retry_after_ms;
    source = "retry_after";
  } else {
    base = std::min<std::uint32_t>(1000U << exponent, maximum);
    const std::uint32_t jitter_ceiling =
        std::min<std::uint32_t>(base / 5U, maximum - base);
    if (jitter_ceiling != 0U) {
      std::array<std::uint8_t, 2> random{};
      crypto::secureRandom(random.data(), random.size());
      jitter = ((static_cast<std::uint32_t>(random[0]) << 8U) | random[1]) %
               (jitter_ceiling + 1U);
    }
  }
  const std::uint32_t delay_ms = base + jitter;
  PM_LOG_WARN(
      "SERVER", "SYNC_RETRY_SCHEDULED",
      "operation=%s attempt=%lu source=%s base_ms=%lu jitter_ms=%lu "
      "delay_ms=%lu maximum_ms=%lu",
      operation, static_cast<unsigned long>(attempt), source,
      static_cast<unsigned long>(base), static_cast<unsigned long>(jitter),
      static_cast<unsigned long>(delay_ms),
      static_cast<unsigned long>(retry_after_ms != 0U
                                     ? std::numeric_limits<std::uint32_t>::max()
                                     : maximum));
  return delay_ms;
}

} // namespace pm
