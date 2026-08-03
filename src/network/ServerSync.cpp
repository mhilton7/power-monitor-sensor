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
#include "network/ResolvedTlsClient.h"
#include "ota/OtaManifestV2.h"
#include "ota/OtaService.h"
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
constexpr std::uint32_t kHeartbeatStorageWaitMs = 20'000U;
// Local memory/storage contention is not an external outage. Give the owning
// task time to release its bounded allocation before rebuilding another JSON
// request; rapid 1.5-second retries fragmented the steady-state heap.
constexpr std::uint32_t kLocalResourceRetryMs = 5000U;
constexpr std::uint32_t kTransportScratchRetryMs = 5000U;
constexpr std::uint32_t kResponseReadPollMs = 10U;
constexpr std::size_t kReadingBatchRecordLimit = 8U;
constexpr std::size_t kEventBatchRecordLimit = 24U;

int printLength(const StringView value) {
  return static_cast<int>(std::min<std::size_t>(
      value.size(), static_cast<std::size_t>(std::numeric_limits<int>::max())));
}

bool containsCharacter(const StringView value, const char expected) {
  return value.data() != nullptr &&
         std::memchr(value.data(), expected, value.size()) != nullptr;
}

class PsramJsonAllocator final : public ArduinoJson::Allocator {
public:
  void *allocate(const std::size_t size) override {
    return heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  }

  void deallocate(void *pointer) override { heap_caps_free(pointer); }

  void *reallocate(void *pointer, const std::size_t size) override {
    return heap_caps_realloc(pointer, size,
                             MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  }
};

ArduinoJson::Allocator *psramJsonAllocator() {
  static PsramJsonAllocator allocator;
  return &allocator;
}

void recordSyncTaskCheckpoint(SyncMetrics &metrics, Diagnostics &diagnostics,
                              const IHeapTelemetry &heap_telemetry,
                              const char *checkpoint) {
  const std::uint32_t high_water_bytes =
      static_cast<std::uint32_t>(uxTaskGetStackHighWaterMark(nullptr));
  const HeapSnapshot heap = heap_telemetry.snapshot();
  const std::uint32_t free_internal = heap.free_internal_bytes;
  const std::uint32_t largest_internal =
      heap.largest_internal_block_bytes;
  metrics.stack_allocated_bytes = task_config::kServerSyncStackBytes;
  metrics.stack_high_water_bytes = high_water_bytes;
  metrics.stack_margin_percent = sync_policy::stackMarginPercent(
      task_config::kServerSyncStackBytes, high_water_bytes);
  metrics.free_internal_heap_bytes = free_internal;
  metrics.largest_internal_block_bytes = largest_internal;
  if (metrics.minimum_free_internal_heap_bytes == 0U ||
      free_internal < metrics.minimum_free_internal_heap_bytes) {
    metrics.minimum_free_internal_heap_bytes = free_internal;
  }
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
      static_cast<unsigned long>(heap.free_total_bytes),
      static_cast<unsigned long>(heap.minimum_free_total_bytes),
      static_cast<unsigned long>(
          heap_caps_get_largest_free_block(MALLOC_CAP_8BIT)),
      static_cast<unsigned long>(free_internal),
      static_cast<unsigned long>(largest_internal),
      static_cast<unsigned long>(heap.free_psram_bytes));
  if (!sync_policy::stackMarginHealthy(
          task_config::kServerSyncStackBytes, high_water_bytes,
          task_config::kMinimumStackMarginPercent) &&
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
                   Diagnostics &diagnostics,
                   const std::uint32_t request_id,
                   const StringView endpoint)
      : http_(http), client_(client), diagnostics_(diagnostics),
        request_id_(request_id), endpoint_(endpoint) {}

  void markHttpBegun() { http_begun_ = true; }

  ~TransportCleanup() {
    PM_LOG_DEBUG("SYNC", "SYNC_CLEANUP_BEGIN", "request_id=%lu",
                 static_cast<unsigned long>(request_id_));
    if (http_begun_) {
      http_.end();
    } else {
      client_.stop();
    }
    diagnostics_.recordTlsLifecycleCheckpoint(
        request_id_, endpoint_.data(), endpoint_.size(),
        TlsLifecycleStage::AfterHttpEnd);
    PM_LOG_DEBUG("SYNC", "SYNC_CLEANUP_COMPLETE",
                 "request_id=%lu http_ended=%s tls_stopped=true",
                 static_cast<unsigned long>(request_id_),
                 http_begun_ ? "true" : "not_started");
  }

private:
  HTTPClient &http_;
  WiFiClientSecure &client_;
  Diagnostics &diagnostics_;
  std::uint32_t request_id_;
  StringView endpoint_;
  bool http_begun_{false};
};

class SyncTransactionCleanup final {
public:
  SyncTransactionCleanup(sync_policy::SingleFlightGate &gate,
                         SyncMetrics &metrics, Diagnostics &diagnostics,
                         ClockService &clock,
                         const IHeapTelemetry &heap_telemetry,
                         const std::uint32_t request_id,
                         const char *method, const StringView endpoint,
                         const int &status, const std::string &error,
                         const std::string &problem_code,
                         const std::string &tls_category,
                         const std::uint32_t &retry_after_ms,
                         const bool &local_resource_deferred,
                         const std::size_t &response_body_size,
                         const std::uint64_t started_ms)
      : gate_(gate), metrics_(metrics), diagnostics_(diagnostics),
        clock_(clock), heap_telemetry_(heap_telemetry),
        request_id_(request_id), method_(method),
        endpoint_(endpoint), status_(status), error_(error),
        problem_code_(problem_code), tls_category_(tls_category),
        retry_after_ms_(retry_after_ms),
        local_resource_deferred_(local_resource_deferred),
        response_body_size_(response_body_size),
        started_ms_(started_ms) {}

  ~SyncTransactionCleanup() {
    const std::uint64_t elapsed_ms = clock_.monotonicMs() - started_ms_;
    const bool success = status_ >= 200 && status_ < 300;
    if (success) {
      ++metrics_.transactions_completed;
    } else if (local_resource_deferred_) {
      ++metrics_.local_resource_deferrals;
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
    const HeapSnapshot after_cleanup = heap_telemetry_.snapshot();
    metrics_.largest_internal_after_cleanup =
        after_cleanup.largest_internal_block_bytes;
    recordSyncTaskCheckpoint(metrics_, diagnostics_, heap_telemetry_,
                             success
                                 ? "TRANSACTION_COMPLETE"
                                 : (local_resource_deferred_
                                        ? "TRANSACTION_DEFERRED"
                                        : "TRANSACTION_FAILED"));
    if (local_resource_deferred_) {
      PM_LOG_WARN(
          "SYNC", "LOCAL_RESOURCE_DEFERRED",
          "request_id=%lu method=%s endpoint=%.*s reason=%s retry_in_ms=%lu "
          "external_failure=false",
          static_cast<unsigned long>(request_id_), method_,
          printLength(endpoint_), endpoint_.data(),
          error_.empty() ? "local_resource_unavailable" : error_.c_str(),
          static_cast<unsigned long>(kLocalResourceRetryMs));
    } else if (status_ > 0) {
      PM_LOG_INFO(
          "HTTP", "HTTP_COMPLETE",
          "request_id=%lu method=%s endpoint=%.*s status=%d category=%s "
          "problem=%s retry_after_ms=%lu response_bytes=%u elapsed_ms=%llu "
          "phases=dns,tcp,tls,http",
          static_cast<unsigned long>(request_id_), method_,
          printLength(endpoint_), endpoint_.data(),
          status_, diag::httpStatusCategory(status_),
          problem_code_.empty() ? "none" : problem_code_.c_str(),
          static_cast<unsigned long>(retry_after_ms_),
          static_cast<unsigned>(response_body_size_),
          static_cast<unsigned long long>(elapsed_ms));
    } else {
      const char *category = tls_category_.empty()
                                 ? diag::tlsErrorCategory(error_.c_str())
                                 : tls_category_.c_str();
      PM_LOG_ERROR("HTTP", "HTTP_FAILED",
                   "error=PM-HTTP-001 request_id=%lu method=%s endpoint=%.*s "
                   "transport=%s tls_category=%s elapsed_ms=%llu",
                   static_cast<unsigned long>(request_id_), method_,
                   printLength(endpoint_), endpoint_.data(),
                   error_.empty() ? "unknown" : error_.c_str(), category,
                   static_cast<unsigned long long>(elapsed_ms));
    }
    const bool timed_out = error_.find("timeout") != std::string::npos;
    PM_LOG_INFO(
        "SYNC",
        success ? "SYNC_COMPLETE"
                : (local_resource_deferred_ ? "SYNC_DEFERRED"
                                            : (timed_out ? "SYNC_TIMEOUT"
                                                         : "SYNC_FAILED")),
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
  const IHeapTelemetry &heap_telemetry_;
  std::uint32_t request_id_;
  const char *method_;
  StringView endpoint_;
  const int &status_;
  const std::string &error_;
  const std::string &problem_code_;
  const std::string &tls_category_;
  const std::uint32_t &retry_after_ms_;
  const bool &local_resource_deferred_;
  const std::size_t &response_body_size_;
  std::uint64_t started_ms_;
};

class HighMemoryLease final {
public:
  explicit HighMemoryLease(Diagnostics &diagnostics,
                           const std::uint32_t request_id,
                           const StringView endpoint,
                           const TickType_t timeout = pdMS_TO_TICKS(5000))
      : diagnostics_(diagnostics),
        request_id_(request_id), endpoint_(endpoint),
        acquired_(diagnostics_.acquireHighMemoryOperation(
            MemoryOperationContext::TlsPreparing, timeout)) {}

  ~HighMemoryLease() {
    if (acquired_) {
      if (client_constructed_) {
        diagnostics_.recordTlsLifecycleCheckpoint(
            request_id_, endpoint_.data(), endpoint_.size(),
            TlsLifecycleStage::AfterClientDestruction);
      }
      diagnostics_.releaseHighMemoryOperation();
      diagnostics_.recordTlsLifecycleCheckpoint(
          request_id_, endpoint_.data(), endpoint_.size(),
          TlsLifecycleStage::AfterHighMemoryLeaseRelease);
    }
  }

  explicit operator bool() const { return acquired_; }

  void markClientConstructed() { client_constructed_ = true; }

  bool transitionToTlsActive() {
    if (!acquired_) {
      return false;
    }
    if (tls_active_) {
      return true;
    }
    tls_active_ = diagnostics_.transitionHighMemoryOperation(
        MemoryOperationContext::TlsPreparing,
        MemoryOperationContext::TlsActive);
    return tls_active_;
  }

private:
  Diagnostics &diagnostics_;
  std::uint32_t request_id_{0U};
  StringView endpoint_{};
  bool acquired_{false};
  bool tls_active_{false};
  bool client_constructed_{false};
};

bool readBoundedResponseBody(HTTPClient &http, ClockService &clock,
                             const int response_size, ServerSyncBuffer &body,
                             std::string &error) {
  body.clear();
  if (response_size == 0) {
    return true;
  }
  if (response_size < 0 ||
      static_cast<std::size_t>(response_size) > body.capacity()) {
    error = "response_buffer_capacity_exceeded";
    return false;
  }
  WiFiClient *const stream = http.getStreamPtr();
  if (stream == nullptr) {
    body.clear();
    error = "response_stream_unavailable";
    return false;
  }
  const std::uint64_t deadline = clock.monotonicMs() + kHttpBodyTimeoutMs;
  const std::size_t expected = static_cast<std::size_t>(response_size);
  std::size_t received = 0U;
  while (received < expected) {
    const int available = stream->available();
    if (available > 0) {
      const std::size_t remaining = expected - received;
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
  return body.prepare(received);
}

bool joinUrl(const std::string &base, const StringView endpoint,
             ServerSyncBuffer &output) {
  output.clear();
  const std::size_t base_size =
      !base.empty() && base.back() == '/' && !endpoint.empty() &&
              endpoint.data()[0] == '/'
          ? base.size() - 1U
          : base.size();
  return output.write(base.data(), base_size) == base_size &&
         output.write(endpoint.data(), endpoint.size()) == endpoint.size();
}

bool hexEncodeFixed(const std::uint8_t *data, const std::size_t length,
                    char *output, const std::size_t output_capacity) {
  static constexpr char digits[] = "0123456789abcdef";
  if (data == nullptr || output == nullptr ||
      output_capacity < length * 2U + 1U) {
    return false;
  }
  for (std::size_t index = 0U; index < length; ++index) {
    output[index * 2U] = digits[data[index] >> 4U];
    output[index * 2U + 1U] = digits[data[index] & 0x0FU];
  }
  output[length * 2U] = '\0';
  return true;
}

bool buildCanonicalRequest(const char *method, const StringView target,
                           const char *timestamp, const char *nonce,
                           const char *body_hash, ServerSyncBuffer &output) {
  output.clear();
  if (!output.writeText("PM-HMAC-SHA256-V1\n")) {
    return false;
  }
  for (const char *cursor = method; cursor != nullptr && *cursor != '\0';
       ++cursor) {
    const std::uint8_t value = static_cast<std::uint8_t>(
        std::toupper(static_cast<unsigned char>(*cursor)));
    if (output.write(value) != 1U) {
      return false;
    }
  }
  return output.writeText("\n") &&
         output.write(target.data(), target.size()) == target.size() &&
         output.writeText("\n") && output.writeText(timestamp) &&
         output.writeText("\n") && output.writeText(nonce) &&
         output.writeText("\n") && output.writeText(body_hash);
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

std::string problemCode(const char *body, const std::size_t body_size) {
  if (body == nullptr || body_size == 0U ||
      body_size > sync_policy::kMaximumResponseBytes) {
    return {};
  }
  JsonDocument document(psramJsonAllocator());
  if (deserializeJson(document, body, body_size) ||
      !document["code"].is<const char *>()) {
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

bool hostAllowed(const ServerTransportConfig &config,
                 const std::string &host) {
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

bool formatIsoUtc(const std::uint64_t utc_ms, char *output,
                  const std::size_t capacity) {
  if (utc_ms == 0U || output == nullptr || capacity < 21U) {
    return false;
  }
  const std::time_t seconds = static_cast<std::time_t>(utc_ms / 1000U);
  std::tm broken_down{};
  gmtime_r(&seconds, &broken_down);
  return std::strftime(output, capacity, "%Y-%m-%dT%H:%M:%SZ",
                       &broken_down) == 20U;
}

const char *eventCategory(const char *code) {
  if (code != nullptr && std::strstr(code, "BOOT") != nullptr)
    return "boot";
  if (code != nullptr && (std::strstr(code, "PZEM") != nullptr ||
                          std::strstr(code, "METER") != nullptr)) {
    return "pzem";
  }
  if (code != nullptr && std::strstr(code, "CT_") != nullptr)
    return "ct_limit";
  if (code != nullptr && (std::strstr(code, "SD_") != nullptr ||
                          std::strstr(code, "STORAGE") != nullptr)) {
    return "sd";
  }
  if (code != nullptr && (std::strstr(code, "TIME") != nullptr ||
                          std::strstr(code, "NTP") != nullptr)) {
    return "time";
  }
  if (code != nullptr && std::strstr(code, "CONFIG") != nullptr)
    return "configuration";
  if (code != nullptr && std::strstr(code, "OTA") != nullptr)
    return "ota";
  if (code != nullptr && (std::strstr(code, "AUTH") != nullptr ||
                          std::strstr(code, "CREDENTIAL") != nullptr ||
                          std::strstr(code, "TLS") != nullptr)) {
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
      maintenance_queue_(maintenance_queue),
      event_cursor_(config.serverEventAckSequence()) {
  metrics_.last_heartbeat_result.reserve(32U);
  metrics_.last_local_deferral_reason.reserve(64U);
  metrics_.last_error.reserve(64U);
  if (!transport_scratch_.begin()) {
    metrics_.last_error = "transport_psram_buffer_unavailable";
    PM_LOG_ERROR("MEMORY", "TRANSPORT_BUFFER_ALLOCATION_FAILED",
                 "error=PM-TLS-006 storage=psram request_capacity=%u "
                 "response_capacity=%u canonical_capacity=%u url_capacity=%u",
                 static_cast<unsigned>(ServerSyncScratch::kRequestCapacity),
                 static_cast<unsigned>(ServerSyncScratch::kResponseCapacity),
                 static_cast<unsigned>(ServerSyncScratch::kCanonicalCapacity),
                 static_cast<unsigned>(ServerSyncScratch::kUrlCapacity));
  }
  (void)refreshTransportConfig();
}

bool ServerSync::ensureTransportScratch() {
  if (transport_scratch_.ready()) {
    return true;
  }
  const std::uint64_t now = clock_.monotonicMs();
  if (now < next_transport_scratch_retry_ms_) {
    return false;
  }
  if (transport_scratch_.begin()) {
    next_transport_scratch_retry_ms_ = 0U;
    if (metrics_.last_error == "transport_psram_buffer_unavailable") {
      metrics_.last_error.clear();
    }
    PM_LOG_INFO("MEMORY", "TRANSPORT_BUFFER_ALLOCATION_RECOVERED",
                "storage=psram retryable=true ready=true");
    return true;
  }
  next_transport_scratch_retry_ms_ = now + kTransportScratchRetryMs;
  metrics_.last_error = "transport_psram_buffer_unavailable";
  if (diag::SerialLogger::instance().allow("transport_scratch_retry", 30'000U)) {
    PM_LOG_WARN("MEMORY", "TRANSPORT_BUFFER_ALLOCATION_RETRY",
                "error=PM-TLS-006 storage=psram retry_in_ms=%lu "
                "external_failure=false",
                static_cast<unsigned long>(kTransportScratchRetryMs));
  }
  return false;
}

bool ServerSync::refreshTransportConfig() {
  const std::uint64_t generation = config_.persistentGeneration();
  if (transport_config_generation_ == generation &&
      !transport_config_.server_url.empty() && !transport_host_.empty()) {
    return true;
  }
  ServerTransportConfig replacement = config_.serverTransportConfig();
  if (replacement.server_url.empty()) {
    return false;
  }
  std::string replacement_host;
  std::uint16_t replacement_port = 443U;
  if (!parseHttpsTarget(replacement.server_url, replacement_host,
                        replacement_port) ||
      !hostAllowed(replacement, replacement_host)) {
    return false;
  }
  const DeviceIdentity identity = config_.identity();
  const CompactServerSyncRuntimeConfig runtime_config =
      config_.compactServerSyncRuntimeConfig();
  std::string replacement_device_id = identity.device_id;
  std::string replacement_boot_id = identity.boot_id;
  transport_config_ = std::move(replacement);
  transport_runtime_config_ = runtime_config;
  transport_host_ = std::move(replacement_host);
  transport_device_id_ = std::move(replacement_device_id);
  transport_boot_id_ = std::move(replacement_boot_id);
  transport_port_ = replacement_port;
  transport_config_generation_ = generation;
  endpoint_address_cache_ = sync_policy::EndpointAddressCache{};
  PM_LOG_INFO("CONFIG", "TRANSPORT_CONFIG_CACHE_UPDATED",
              "generation=%llu ca_cached=true secrets_logged=false",
              static_cast<unsigned long long>(generation));
  return true;
}

void ServerSync::logTaskCheckpoint(const char *checkpoint) {
    recordSyncTaskCheckpoint(metrics_, diagnostics_, heap_telemetry_,
                             checkpoint);
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
  const CompactStorageHealth storage_health = storage_.compactHealth();
  metrics_.durable_reading_backlog =
      config_.serverAckSequence() <
      storage_health.newest_syncable_sequence;
  metrics_.primary_storage_pending = !reading_page_job_id_.empty() ||
                                     !event_page_job_id_.empty();
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
  const CompactNetworkStatus network = network_.compactStatus();
  const CompactServerSyncRuntimeConfig sync_config =
      config_.compactServerSyncRuntimeConfig();

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

  const ConnectionMode configured_mode = sync_config.connection_mode;
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
      !sync_config.server_configured || now < next_retry_ms_) {
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
          sync_config.server_configured ? "true" : "false",
          static_cast<unsigned long long>(
              now < next_retry_ms_ ? next_retry_ms_ - now : 0),
          static_cast<unsigned long>(retry_attempt_),
          static_cast<unsigned long long>(
              storage_health.newest_syncable_sequence >=
                      config_.serverAckSequence()
                  ? storage_health.newest_syncable_sequence -
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
      if (last_operation_locally_deferred_) {
        next_retry_ms_ = now + kLocalResourceRetryMs;
        retry_after_gate_ms_ = 0U;
      } else {
        const std::uint32_t retry_delay_ms = retryDelayMs(retry_after_ms);
        next_retry_ms_ = now + retry_delay_ms;
        retry_after_gate_ms_ = retry_after_ms == 0U ? 0U : next_retry_ms_;
      }
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
                    sync_config.heartbeat_interval_seconds));
    std::uint32_t retry_after_ms = 0;
    if (heartbeat(retry_after_ms)) {
      retry_attempt_ = 0;
      retry_after_gate_ms_ = 0;
      next_heartbeat_ms_ = now + heartbeatDelayMs();
    } else {
      if (last_operation_locally_deferred_) {
        next_heartbeat_ms_ = now + kLocalResourceRetryMs;
        PM_LOG_WARN("SERVER", "LOCAL_RESOURCE_RETRY_SCHEDULED",
                    "operation=heartbeat retry_in_ms=%lu "
                    "external_backoff_unchanged=true",
                    static_cast<unsigned long>(kLocalResourceRetryMs));
        diagnostics_.setSyncMetrics(metrics_);
        return;
      }
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
    metrics_.primary_storage_pending = !reading_page_job_id_.empty() ||
                                       !event_page_job_id_.empty();
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
  if (now >= next_config_poll_ms_) {
    fetchConfiguration();
    next_config_poll_ms_ =
        now + (last_operation_locally_deferred_
                   ? kLocalResourceRetryMs
                   : static_cast<std::uint64_t>(
                         sync_config.sync_interval_seconds) *
                         1000U);
    diagnostics_.setSyncMetrics(metrics_);
    return;
  }
  if (!config_.safeMode() && now >= next_manifest_poll_ms_) {
    checkFirmwareManifest();
    next_manifest_poll_ms_ =
        now + (last_operation_locally_deferred_ ? kLocalResourceRetryMs
                                                : 3'600'000U);
    diagnostics_.setSyncMetrics(metrics_);
    return;
  }
  // Diagnostic events remain durable on microSD, but configuration,
  // firmware policy, and the primary measurement path have priority. A
  // server that has not advanced the reading acknowledgement cursor can
  // otherwise trigger a long FAT directory scan during reading retry
  // backoff and temporarily consume the heap needed for heartbeat TLS.
  if (!durable_reading_backlog && now >= next_event_push_ms_) {
    const bool event_operation_succeeded = pushEvents();
    // pushEvents owns the short 250 ms deadline while its StorageTask page
    // job is pending. Overwriting that deadline with the idle interval made
    // completed pages expire before they were consumed, retriggering the
    // same expensive scan indefinitely.
    if (sync_policy::shouldScheduleEventIdleDelay(
            event_operation_succeeded, !event_page_job_id_.empty())) {
      next_event_push_ms_ = now + 30'000U;
    }
    metrics_.primary_storage_pending = !reading_page_job_id_.empty() ||
                                       !event_page_job_id_.empty();
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
  last_operation_locally_deferred_ = false;
  retry_after_ms = 0;
  const CompactStorageHealth storage = storage_.compactHealth();
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
  JsonDocument document(psramJsonAllocator());
  document["token"] = config_.enrollmentToken();
  document["protocol_version"] = version::PROTOCOL;
  document["hardware_id"] = config_.identity().hardware_id;
  document["requested_name"] = config_.sensorStatusConfig().friendly_name;
  JsonObject capabilities = document["capabilities"].to<JsonObject>();
  capabilities["hardware_target"] = version::HARDWARE_TARGET;
  capabilities["pzem_model"] = "PZEM-004T V4";
  capabilities["sd_present"] = storage_ready;
  capabilities["sd_required"] = true;
  JsonObject ota = capabilities["ota"].to<JsonObject>();
  ota["supported"] = true;
  ota["protocol_version"] = ota_v2::kProtocolVersion;
  ota["authentication_mode"] = ota_v2::kAuthenticationMode;
  ota["rollback_supported"] = true;
  ota["partition_size_bytes"] = OtaService::updatePartitionSize();
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
  last_operation_locally_deferred_ = response.local_resource_deferred;
  retry_after_ms = response.retry_after_ms;
  if (response.status != 201) {
    if (response.local_resource_deferred) {
      PM_LOG_WARN("ENROLL", "ENROLLMENT_DEFERRED",
                  "reason=%s retry_in_ms=%lu external_failure=false",
                  response.error.c_str(),
                  static_cast<unsigned long>(kLocalResourceRetryMs));
      return false;
    }
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
  JsonDocument result(psramJsonAllocator());
  if (deserializeJson(result, response.body, response.body_size)) {
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
              config_.sensorStatusConfig().friendly_name.c_str(),
              static_cast<unsigned long>(config_.config().config_version),
              static_cast<unsigned long long>(assigned_generation));
  next_heartbeat_ms_ = 0;
  return heartbeat(retry_after_ms);
}

bool ServerSync::heartbeat(std::uint32_t &retry_after_ms) {
  last_operation_locally_deferred_ = false;
  retry_after_ms = 0;
  metrics_.last_heartbeat_attempt_monotonic_ms = clock_.monotonicMs();
  metrics_.last_heartbeat_result = "attempting";
  PM_LOG_DEBUG("HEARTBEAT", "HEARTBEAT_BEGIN", "ack_sequence=%llu",
               static_cast<unsigned long long>(config_.serverAckSequence()));
  if (!ensureTransportScratch()) {
    last_operation_locally_deferred_ = true;
    ++metrics_.local_resource_deferrals;
    ++metrics_.consecutive_local_deferrals;
    metrics_.last_heartbeat_result = "local_resource_deferred";
    metrics_.last_local_deferral_reason =
        "transport_psram_buffer_unavailable";
    return false;
  }
  if (!refreshTransportConfig()) {
    metrics_.last_heartbeat_result = "configuration_unavailable";
    metrics_.last_error = "server_transport_configuration_unavailable";
    return false;
  }
  logTaskCheckpoint("BEFORE_JSON_BUILD");
  ServerSyncBuffer &heartbeat_body = transport_scratch_.request_body;
  heartbeat_body.clear();
  if (!heartbeatBody(heartbeat_body)) {
    ++transport_scratch_.unexpected_growths;
    ++metrics_.heartbeat_buffer_growths;
    last_operation_locally_deferred_ = true;
    ++metrics_.local_resource_deferrals;
    ++metrics_.consecutive_local_deferrals;
    metrics_.last_heartbeat_result = "local_resource_deferred";
    metrics_.last_local_deferral_reason = "heartbeat_buffer_unavailable";
    metrics_.last_error = "heartbeat_buffer_unavailable";
    PM_LOG_WARN("HEARTBEAT", "HEARTBEAT_DEFERRED",
                "reason=bounded_request_buffer_unavailable retry_in_ms=%lu "
                "external_failure=false",
                static_cast<unsigned long>(kLocalResourceRetryMs));
    return false;
  }
  ++transport_scratch_.request_reuses;
  ++metrics_.heartbeat_buffer_reuses;
  logTaskCheckpoint("AFTER_JSON_BUILD");
  ++metrics_.heartbeat_requests_sent;
  const HttpResult response =
      request("POST", "/api/v1/device-heartbeats", heartbeat_body.data(),
              heartbeat_body.size(), true);
  last_operation_locally_deferred_ = response.local_resource_deferred;
  retry_after_ms = response.retry_after_ms;
  if (response.status != 200) {
    if (response.local_resource_deferred) {
      ++metrics_.consecutive_local_deferrals;
      metrics_.last_heartbeat_result = "local_resource_deferred";
      metrics_.last_local_deferral_reason =
          response.error.empty() ? "internal_resource_unavailable"
                                 : response.error;
      PM_LOG_WARN("HEARTBEAT", "HEARTBEAT_DEFERRED",
                  "reason=%s retry_in_ms=%lu external_failure=false",
                  response.error.c_str(),
                  static_cast<unsigned long>(kLocalResourceRetryMs));
      return false;
    }
    metrics_.consecutive_local_deferrals = 0U;
    metrics_.last_local_deferral_reason.clear();
    ++metrics_.heartbeat_failures;
    ++metrics_.heartbeat_transport_failures;
    metrics_.last_error =
        !response.problem_code.empty()
            ? response.problem_code
            : (response.error.empty() ? "heartbeat_failed" : response.error);
    network_.setServerStatus(response.status > 0, false);
    if (response.status == 401 || response.status == 403) {
      metrics_.last_heartbeat_result = "authentication_rejected";
      ++metrics_.authentication_rejections;
      ++metrics_.heartbeat_authentication_failures;
    } else {
      metrics_.last_heartbeat_result = "transport_failed";
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
  metrics_.consecutive_local_deferrals = 0U;
  metrics_.last_local_deferral_reason.clear();
  ++metrics_.heartbeat_http_200;
  logTaskCheckpoint("BEFORE_RESPONSE_PARSE");
  JsonDocument document(psramJsonAllocator());
  if (deserializeJson(document, response.body, response.body_size)) {
    ++metrics_.heartbeat_failures;
    ++metrics_.heartbeat_contract_failures;
    metrics_.last_heartbeat_result = "contract_failed";
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
    ++metrics_.heartbeat_contract_failures;
    metrics_.last_heartbeat_result = "contract_failed";
    metrics_.last_error = "heartbeat_response_contract_invalid";
    PM_LOG_ERROR("HEARTBEAT", "RESPONSE_INVALID",
                 "error=PM-SERVER-002 category=contract_shape_invalid");
    logTaskCheckpoint("AFTER_RESPONSE_PARSE");
    return false;
  }
  ++metrics_.heartbeat_transport_successes;
  ++metrics_.heartbeat_server_accepted;
  metrics_.last_heartbeat_utc_ms = clock_.utcMs();
  metrics_.last_heartbeat_success_monotonic_ms = clock_.monotonicMs();
  metrics_.last_heartbeat_result = "success";
  network_.setServerStatus(true, true);
  const std::uint64_t acknowledgement =
      document["highest_contiguous_accepted_sequence"].as<std::uint64_t>();
  const std::uint64_t current_ack = config_.serverAckSequence();
  std::uint64_t maximum_seen = acknowledgement;
  bool cursor_contract_valid = true;
  if (document["sequence_cursor"].is<JsonObjectConst>()) {
    const JsonObjectConst cursor = document["sequence_cursor"].as<JsonObjectConst>();
    if (!cursor["highest_contiguous_accepted_sequence"].is<std::uint64_t>() ||
        !cursor["maximum_seen_sequence"].is<std::uint64_t>() ||
        !cursor["next_sequence_floor"].is<std::uint64_t>()) {
      ++metrics_.heartbeat_contract_failures;
      ++metrics_.sequence_cursor_conflicts;
      metrics_.last_error = "heartbeat_cursor_contract_invalid";
      PM_LOG_ERROR("HEARTBEAT", "RESPONSE_INVALID",
                   "error=PM-SERVER-002 category=cursor_shape_invalid "
                   "heartbeat_accepted=true external_failure=false");
      cursor_contract_valid = false;
      maximum_seen = config_.serverMaximumSeenSequence();
    } else {
      const std::uint64_t nested_ack =
          cursor["highest_contiguous_accepted_sequence"].as<std::uint64_t>();
      maximum_seen = cursor["maximum_seen_sequence"].as<std::uint64_t>();
      const std::uint64_t next_floor =
          cursor["next_sequence_floor"].as<std::uint64_t>();
      if (!sync_policy::sequenceCursorContractValid(
              acknowledgement, nested_ack, maximum_seen, next_floor)) {
        ++metrics_.heartbeat_contract_failures;
        ++metrics_.sequence_cursor_conflicts;
        metrics_.last_error = "heartbeat_cursor_contract_invalid";
        PM_LOG_ERROR(
            "HEARTBEAT", "RESPONSE_INVALID",
            "error=PM-SERVER-002 category=cursor_values_invalid ack=%llu "
            "nested_ack=%llu maximum_seen=%llu next_floor=%llu "
            "heartbeat_accepted=true external_failure=false",
            static_cast<unsigned long long>(acknowledgement),
            static_cast<unsigned long long>(nested_ack),
            static_cast<unsigned long long>(maximum_seen),
            static_cast<unsigned long long>(next_floor));
        cursor_contract_valid = false;
        maximum_seen = config_.serverMaximumSeenSequence();
      }
    }
  }
  const SequenceState sequence_state = storage_.sequenceState(
      current_ack, config_.serverMaximumSeenSequence(),
      config_.preparedRemovalSequence());
  const std::uint64_t newest_sequence =
      sequence_state.local_newest_sequence;
  PM_LOG_INFO(
      "SYNC", "ACK_RECONCILIATION_BEGIN",
      "request_id=%lu current_ack=%llu response_ack=%llu "
      "response_maximum_seen=%llu local_newest=%llu local_floor=%llu "
      "next_sequence=%llu mounted=%s writable=%s",
      static_cast<unsigned long>(metrics_.active_request_id),
      static_cast<unsigned long long>(current_ack),
      static_cast<unsigned long long>(acknowledgement),
      static_cast<unsigned long long>(maximum_seen),
      static_cast<unsigned long long>(sequence_state.local_newest_sequence),
      static_cast<unsigned long long>(
          sequence_state.local_journal_high_water),
      static_cast<unsigned long long>(sequence_state.next_sequence),
      sequence_state.storage_mounted ? "true" : "false",
      sequence_state.storage_writable ? "true" : "false");
  const sync_policy::AcknowledgementDisposition acknowledgement_disposition =
      sync_policy::classifyAcknowledgement(current_ack, newest_sequence,
                                           acknowledgement);
  PM_LOG_INFO(
      "SYNC", "ACK_DISPOSITION_SELECTED",
      "disposition=%u current_ack=%llu response_ack=%llu local_newest=%llu",
      static_cast<unsigned>(acknowledgement_disposition),
      static_cast<unsigned long long>(current_ack),
      static_cast<unsigned long long>(acknowledgement),
      static_cast<unsigned long long>(newest_sequence));
  const bool cursor_regressed = !cursor_contract_valid ||
      acknowledgement_disposition ==
          sync_policy::AcknowledgementDisposition::Invalid ||
      maximum_seen < config_.serverMaximumSeenSequence();
  if (cursor_regressed) {
    if (cursor_contract_valid) {
      ++metrics_.sequence_cursor_conflicts;
      ++metrics_.sequence_cursor_regressions;
      metrics_.last_error = "server_sequence_cursor_regressed";
    }
    PM_LOG_ERROR(
        "SYNC", "SEQUENCE_CURSOR_CONFLICT",
        "reason=%s current_ack=%llu response_ack=%llu "
        "current_maximum_seen=%llu response_maximum_seen=%llu "
        "heartbeat_accepted=true external_failure=false",
        cursor_contract_valid ? "server_cursor_regression"
                              : "cursor_contract_invalid",
        static_cast<unsigned long long>(current_ack),
        static_cast<unsigned long long>(acknowledgement),
        static_cast<unsigned long long>(config_.serverMaximumSeenSequence()),
        static_cast<unsigned long long>(maximum_seen));
  } else {
    const bool acknowledgement_persisted =
        acknowledgement == current_ack ||
        config_.setServerAckSequence(acknowledgement);
    const bool maximum_seen_persisted =
        maximum_seen == config_.serverMaximumSeenSequence() ||
        config_.setServerMaximumSeenSequence(maximum_seen);
    if (!acknowledgement_persisted || !maximum_seen_persisted) {
      metrics_.last_error = "server_sequence_cursor_persist_failed";
      PM_LOG_ERROR(
          "SYNC", "SEQUENCE_CURSOR_PERSIST_FAILED",
          "ack_persisted=%s maximum_seen_persisted=%s "
          "heartbeat_accepted=true",
          acknowledgement_persisted ? "true" : "false",
          maximum_seen_persisted ? "true" : "false");
    }
  }
  const std::uint64_t required_sequence_floor =
      sync_policy::requiredSequenceFloor(
          sequence_state.local_newest_sequence,
          sequence_state.local_journal_high_water, current_ack,
          config_.serverMaximumSeenSequence(), maximum_seen);
  if (!cursor_regressed && sequence_state.storage_mounted &&
      required_sequence_floor > sequence_state.local_journal_high_water) {
    ++metrics_.sequence_reconciliation_requests;
    if (!storage_coordinator_.queueSequenceReconciliation(
            required_sequence_floor)) {
      ++metrics_.sequence_reconciliation_failures;
      metrics_.last_error = "sequence_reconciliation_queue_unavailable";
      PM_LOG_ERROR("SYNC", "SEQUENCE_RECONCILIATION_QUEUE_FAILED",
                   "required_floor=%llu heartbeat_accepted=true",
                   static_cast<unsigned long long>(required_sequence_floor));
    } else {
      ++metrics_.sequence_reconciliation_deferred;
    }
  } else if (!cursor_regressed && !sequence_state.storage_mounted &&
             required_sequence_floor >
                 sequence_state.local_journal_high_water) {
    PM_LOG_INFO(
        "SYNC", "SEQUENCE_RECONCILIATION_DEFERRED",
        "reason=storage_unmounted required_floor=%llu "
        "local_floor=%llu heartbeat_accepted=true",
        static_cast<unsigned long long>(required_sequence_floor),
        static_cast<unsigned long long>(
            sequence_state.local_journal_high_water));
  }
  immediate_sync_ = document["immediate_sync_requested"].as<bool>();
  const bool firmware_release_available =
      document["firmware_release_available"].as<bool>();
  next_manifest_poll_ms_ = sync_policy::manifestPollDeadline(
      firmware_release_available, next_manifest_poll_ms_,
      clock_.monotonicMs());
  if (firmware_release_available) {
    PM_LOG_INFO("OTA", "MANIFEST_POLL_RELEASED",
                "source=heartbeat next_tick=true concurrent_tls=false");
  }
  if (!cursor_regressed && sync_policy::shouldReleaseReadingBackoff(
          immediate_sync_, acknowledgement, newest_sequence,
          immediate_sync_release_recorded_,
          last_immediate_sync_release_ack_)) {
    const bool was_deferred = next_reading_push_ms_ > clock_.monotonicMs();
    immediate_sync_release_recorded_ = true;
    last_immediate_sync_release_ack_ = acknowledgement;
    next_reading_push_ms_ = 0;
    PM_LOG_INFO(
        "SYNC", "READING_BACKOFF_RELEASED",
        "source=heartbeat_server_request acknowledgement=%llu newest=%llu "
        "was_deferred=%s retry_attempt=%lu",
        static_cast<unsigned long long>(acknowledgement),
        static_cast<unsigned long long>(newest_sequence),
        was_deferred ? "true" : "false",
        static_cast<unsigned long>(reading_retry_attempt_));
  } else if (immediate_sync_ && acknowledgement < newest_sequence &&
             next_reading_push_ms_ > clock_.monotonicMs()) {
    PM_LOG_DEBUG(
        "SYNC", "READING_BACKOFF_RETAINED",
        "reason=acknowledgement_unchanged acknowledgement=%llu newest=%llu "
        "retry_in_ms=%llu retry_attempt=%lu",
        static_cast<unsigned long long>(acknowledgement),
        static_cast<unsigned long long>(newest_sequence),
        static_cast<unsigned long long>(next_reading_push_ms_ -
                                        clock_.monotonicMs()),
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
  if (!cursor_regressed &&
      metrics_.last_error != "server_sequence_cursor_persist_failed" &&
      metrics_.last_error != "sequence_reconciliation_queue_unavailable") {
    metrics_.last_error.clear();
  }
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
    metrics_.primary_storage_pending = true;
    diagnostics_.setSyncMetrics(metrics_);
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
  const CompactStorageHealth batch_storage = storage_.compactHealth();
  PM_LOG_INFO(
      "HISTORY", "sensor.reading_batch_started",
      "record_count=%u first_sequence=%llu last_sequence=%llu backlog=%llu",
      static_cast<unsigned>(page.records.size()),
      static_cast<unsigned long long>(page.first_sequence),
      static_cast<unsigned long long>(page.last_sequence),
      static_cast<unsigned long long>(
          batch_storage.newest_syncable_sequence >=
                  config_.serverAckSequence()
              ? batch_storage.newest_syncable_sequence -
                    config_.serverAckSequence()
              : 0));
  if (page.has_more) {
    PM_LOG_INFO(
        "HISTORY", "history.backfill_started",
        "first_sequence=%llu last_sequence=%llu newest_stored=%llu",
        static_cast<unsigned long long>(page.first_sequence),
        static_cast<unsigned long long>(page.last_sequence),
        static_cast<unsigned long long>(batch_storage.newest_sequence));
  }
  const std::size_t record_count = page.records.size();
  const bool page_has_more = page.has_more;
  if (!ensureTransportScratch() || !refreshTransportConfig()) {
    next_reading_push_ms_ = clock_.monotonicMs() + kLocalResourceRetryMs;
    return true;
  }
  logTaskCheckpoint("BEFORE_JSON_BUILD");
  ServerSyncBuffer &body = transport_scratch_.request_body;
  body.clear();
  {
    JsonDocument document(psramJsonAllocator());
    document["schema_version"] = "reading-batch/1.0.0";
    document["protocol_version"] = version::PROTOCOL;
    document["device_id"] = transport_device_id_;
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
    if (document.overflowed()) {
      body.clear();
      metrics_.last_error = "reading_batch_json_document_overflow";
      ++metrics_.batch_failures;
      ++transport_scratch_.unexpected_growths;
      next_reading_push_ms_ =
          clock_.monotonicMs() +
          operationRetryDelayMs(reading_retry_attempt_, 0, "readings");
      PM_LOG_ERROR("SYNC", "READ_BATCH_DOCUMENT_REJECTED",
                   "error=PM-HTTP-003 reason=json_document_overflow");
      return false;
    }
    const std::size_t written = serializeJson(document, body);
    if (written == 0U || body.overflowed()) {
      metrics_.last_error = "reading_batch_buffer_capacity_exceeded";
      ++metrics_.batch_failures;
      ++transport_scratch_.unexpected_growths;
      next_reading_push_ms_ =
          clock_.monotonicMs() +
          operationRetryDelayMs(reading_retry_attempt_, 0, "readings");
      PM_LOG_ERROR("SYNC", "READ_BATCH_BUFFER_REJECTED",
                   "error=PM-HTTP-003 maximum_bytes=%u",
                   static_cast<unsigned>(body.capacity()));
      return false;
    }
  }
  // Do not retain the raw SD page and ArduinoJson tree while mbedTLS requests
  // its internal-RAM working set. The body is the only request payload owner.
  std::vector<std::string>().swap(page.records);
  logTaskCheckpoint("AFTER_JSON_BUILD");
  ++transport_scratch_.request_reuses;
  const HttpResult response =
      request("POST", "/api/v1/device-readings/batch", body.data(),
              body.size(), true);
  if (response.status != 200) {
    if (response.local_resource_deferred) {
      next_reading_push_ms_ = clock_.monotonicMs() + kLocalResourceRetryMs;
      PM_LOG_WARN("SYNC", "READ_BATCH_DEFERRED",
                  "reason=%s retry_in_ms=%lu external_failure=false",
                  response.error.c_str(),
                  static_cast<unsigned long>(kLocalResourceRetryMs));
      return true;
    }
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
  JsonDocument result(psramJsonAllocator());
  if (deserializeJson(result, response.body, response.body_size)) {
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
  const std::uint64_t newest_sequence =
      storage_.compactHealth().newest_syncable_sequence;
  if (acknowledgement == current_ack) {
    ++metrics_.batch_failures;
    metrics_.last_error = "batch_ack_stalled";
    const std::uint64_t now = clock_.monotonicMs();
    next_reading_push_ms_ =
        now + operationRetryDelayMs(reading_retry_attempt_, 0, "readings");
    const JsonArrayConst missing_ranges =
        result["missing_ranges"].as<JsonArrayConst>();
    std::uint64_t first_missing_start = 0;
    std::uint64_t first_missing_end = 0;
    if (!missing_ranges.isNull() && missing_ranges.size() != 0U) {
      const JsonArrayConst first_range = missing_ranges[0].as<JsonArrayConst>();
      if (first_range.size() == 2U) {
        first_missing_start = first_range[0].as<std::uint64_t>();
        first_missing_end = first_range[1].as<std::uint64_t>();
      }
    }
    PM_LOG_WARN(
        "SYNC", "READ_BATCH_NO_PROGRESS",
        "error=PM-SYNC-007 records=%u first_sequence=%llu last_sequence=%llu "
        "cursor_retained=%llu missing_ranges=%u first_missing_start=%llu "
        "first_missing_end=%llu failures=%llu retry_in_ms=%llu",
        static_cast<unsigned>(record_count),
        static_cast<unsigned long long>(page.first_sequence),
        static_cast<unsigned long long>(page.last_sequence),
        static_cast<unsigned long long>(current_ack),
        static_cast<unsigned>(missing_ranges.size()),
        static_cast<unsigned long long>(first_missing_start),
        static_cast<unsigned long long>(first_missing_end),
        static_cast<unsigned long long>(metrics_.batch_failures),
        static_cast<unsigned long long>(next_reading_push_ms_ - now));
    if (reading_retry_attempt_ == 1U) {
      for (std::size_t index = 0;
           index < page.unavailable_sequence_ranges.size(); ++index) {
        const auto &range = page.unavailable_sequence_ranges[index];
        PM_LOG_WARN(
            "SYNC", "READ_BATCH_UNAVAILABLE_RANGE",
            "index=%u start_sequence=%llu end_sequence=%llu",
            static_cast<unsigned>(index),
            static_cast<unsigned long long>(range.start_sequence),
            static_cast<unsigned long long>(range.end_sequence));
      }
    }
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
    metrics_.primary_storage_pending = true;
    diagnostics_.setSyncMetrics(metrics_);
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
  const HeartbeatStorageHealth storage_health = storage_.heartbeatHealth();
  if (!ensureTransportScratch() || !refreshTransportConfig()) {
    next_event_push_ms_ = clock_.monotonicMs() + kLocalResourceRetryMs;
    return true;
  }
  logTaskCheckpoint("BEFORE_JSON_BUILD");
  ServerSyncBuffer &body = transport_scratch_.request_body;
  body.clear();
  {
    JsonDocument document(psramJsonAllocator());
    document["protocol_version"] = version::PROTOCOL;
    document["device_id"] = transport_device_id_;
    if (storage_health.oldest_event_sequence != 0U) {
      document["first_stored_event_sequence"] =
          storage_health.oldest_event_sequence;
    }
    JsonArray events = document["events"].to<JsonArray>();
    for (const auto &encoded : page.records) {
      JsonDocument event_document(psramJsonAllocator());
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
      const char *boot_id = event_document["boot_id"] | "";
      const char *code = event_document["code"] | "EVT_UNKNOWN";
      std::array<char, 128U> event_id{};
      const int event_id_length =
          std::snprintf(event_id.data(), event_id.size(), "%s-%llu", boot_id,
                        static_cast<unsigned long long>(sequence));
      if (event_id_length < 0 ||
          static_cast<std::size_t>(event_id_length) >= event_id.size()) {
        ++metrics_.events_failures;
        metrics_.last_error = "stored_event_id_capacity_exceeded";
        next_event_push_ms_ =
            clock_.monotonicMs() +
            operationRetryDelayMs(event_retry_attempt_, 0, "events");
        return false;
      }
      JsonObject event = events.add<JsonObject>();
      event["event_id"] = event_id.data();
      event["occurred_at"] = event_document["timestamp_utc"];
      event["category"] = eventCategory(code);
      event["severity"] = event_document["severity"];
      JsonObject evidence = event["evidence"].to<JsonObject>();
      evidence["code"] = code;
      evidence["detail"] = event_document["detail"];
      evidence["boot_id"] = boot_id;
      evidence["event_sequence"] = sequence;
    }
    if (document.overflowed()) {
      body.clear();
      ++metrics_.events_failures;
      ++transport_scratch_.unexpected_growths;
      metrics_.last_error = "event_batch_json_document_overflow";
      next_event_push_ms_ =
          clock_.monotonicMs() +
          operationRetryDelayMs(event_retry_attempt_, 0, "events");
      PM_LOG_ERROR("SYNC", "EVENT_BATCH_DOCUMENT_REJECTED",
                   "error=PM-HTTP-003 reason=json_document_overflow");
      return false;
    }
    const std::size_t written = serializeJson(document, body);
    if (written == 0U || body.overflowed()) {
      ++metrics_.events_failures;
      ++transport_scratch_.unexpected_growths;
      metrics_.last_error = "event_batch_buffer_capacity_exceeded";
      next_event_push_ms_ =
          clock_.monotonicMs() +
          operationRetryDelayMs(event_retry_attempt_, 0, "events");
      PM_LOG_ERROR("SYNC", "EVENT_BATCH_BUFFER_REJECTED",
                   "error=PM-HTTP-003 maximum_bytes=%u",
                   static_cast<unsigned>(body.capacity()));
      return false;
    }
  }
  std::vector<std::string>().swap(page.records);
  logTaskCheckpoint("AFTER_JSON_BUILD");
  ++transport_scratch_.request_reuses;
  const HttpResult response =
      request("POST", "/api/v1/device-events/batch", body.data(),
              body.size(), true);
  if (response.local_resource_deferred) {
    next_event_push_ms_ = clock_.monotonicMs() + kLocalResourceRetryMs;
    PM_LOG_WARN("SYNC", "EVENT_BATCH_DEFERRED",
                "reason=%s retry_in_ms=%lu external_failure=false",
                response.error.c_str(),
                static_cast<unsigned long>(kLocalResourceRetryMs));
    return true;
  }
  if (response.status == 200) {
    logTaskCheckpoint("BEFORE_RESPONSE_PARSE");
    JsonDocument result(psramJsonAllocator());
    if (deserializeJson(result, response.body, response.body_size) ||
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
    const std::uint64_t acknowledged_event_sequence =
        result["highest_contiguous_event_sequence"].is<std::uint64_t>()
            ? result["highest_contiguous_event_sequence"].as<std::uint64_t>()
            : event_cursor_;
    if (acknowledged_event_sequence < page_last_sequence ||
        !config_.setServerEventAckSequence(acknowledged_event_sequence)) {
      ++metrics_.events_failures;
      metrics_.last_error = "event_acknowledgement_persist_failed";
      next_event_push_ms_ =
          clock_.monotonicMs() +
          operationRetryDelayMs(event_retry_attempt_, 0, "events");
      PM_LOG_ERROR("SYNC", "EVENT_ACK_PERSIST_FAILED",
                   "page_last=%llu acknowledged=%llu cursor_retained=%llu",
                   static_cast<unsigned long long>(page_last_sequence),
                   static_cast<unsigned long long>(acknowledged_event_sequence),
                   static_cast<unsigned long long>(event_cursor_));
      logTaskCheckpoint("AFTER_RESPONSE_PARSE");
      return false;
    }
    event_cursor_ = acknowledged_event_sequence;
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
  JsonDocument document(psramJsonAllocator());
  if (deserializeJson(document, response.body, response.body_size)) {
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
    JsonDocument result(psramJsonAllocator());
    recorded = !deserializeJson(result, response.body, response.body_size) &&
               result["recorded"].is<bool>() && result["recorded"].as<bool>();
  }
  if (recorded && std::strcmp(status, "applied") == 0) {
    return config_.setServerConfigVersion(version);
  }
  return recorded;
}

bool ServerSync::checkFirmwareManifest() {
  const ServerSyncRuntimeConfig sync_config = config_.serverSyncRuntimeConfig();
  PM_LOG_DEBUG("OTA", "REMOTE_MANIFEST_CHECK_BEGIN", "channel=%s current=%s",
               sync_config.ota_channel.c_str(), version::FIRMWARE);
  const std::string endpoint = "/api/v1/device-firmware/manifest";
  const HttpResult response = request("GET", endpoint, "", true);
  if (response.status != 200) {
    return false;
  }
  JsonDocument document(psramJsonAllocator());
  if (deserializeJson(document, response.body, response.body_size)) {
    return false;
  }
  if (document["available"].is<bool>() &&
      !document["available"].as<bool>() &&
      document.as<JsonObjectConst>().size() == 2U &&
      document["protocol_version"].is<const char *>() &&
      std::string(document["protocol_version"].as<const char *>()) ==
          version::PROTOCOL) {
    available_firmware_version_.clear();
    PM_LOG_INFO("OTA", "REMOTE_MANIFEST_CURRENT", "update_available=false");
    return true;
  }
  std::string manifest_json(response.body, response.body_size);
  ota_v2::Manifest manifest;
  std::string manifest_error;
  if (!ota_v2::parseManifest(manifest_json, manifest, manifest_error)) {
    PM_LOG_ERROR("OTA", "REMOTE_MANIFEST_INVALID",
                 "error=PM-OTA-003 category=%s fail_closed=true",
                 manifest_error.c_str());
    return false;
  }
  available_firmware_version_ = manifest.version;
  PM_LOG_INFO("OTA", "REMOTE_MANIFEST_AVAILABLE",
              "update_available=%s target_version=%s",
              available_firmware_version_.empty() ? "false" : "true",
              available_firmware_version_.empty()
                  ? "none"
                  : available_firmware_version_.c_str());
  const RuntimeConfig active_config = config_.config();
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
              "target_version=%s authentication=existing_device_hmac "
              "source=central_manifest",
              available_firmware_version_.c_str());
  return true;
}

ServerSync::HttpResult ServerSync::request(const char *method,
                                           const StringView endpoint,
                                           const char *body,
                                           const std::size_t body_size,
                                           const bool authenticated) {
  last_operation_locally_deferred_ = false;
  HttpResult result;
  if (!ensureTransportScratch()) {
    result.error = "transport_psram_buffer_unavailable";
    result.tls_category = "LOCAL_RESOURCE_DEFERRED";
    result.local_resource_deferred = true;
    last_operation_locally_deferred_ = true;
    return result;
  }
  if (!refreshTransportConfig()) {
    result.error = "server_transport_configuration_unavailable";
    return result;
  }
  transport_scratch_.response_body.clear();
  result.body = transport_scratch_.response_body.data();
  const std::uint32_t request_id = ++request_sequence_;
  std::array<char, 96U> correlation_id{};
  const int correlation_length =
      std::snprintf(correlation_id.data(), correlation_id.size(), "pm-%s-%lu",
                    transport_boot_id_.c_str(),
                    static_cast<unsigned long>(request_id));
  if (correlation_length < 0 ||
      static_cast<std::size_t>(correlation_length) >= correlation_id.size()) {
    result.error = "correlation_id_capacity_exceeded";
    result.local_resource_deferred = true;
    return result;
  }
  const std::uint64_t started_ms = clock_.monotonicMs();
  if (!single_flight_.tryBegin()) {
    result.error = "sync_transaction_in_progress";
    result.local_resource_deferred = true;
    last_operation_locally_deferred_ = true;
    ++metrics_.local_resource_deferrals;
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
              "request_id=%lu correlation_id=%s owner=ServerSyncTask pending=%s "
              "transactions_started=%llu",
              static_cast<unsigned long>(request_id), correlation_id.data(),
              metrics_.sync_pending ? "true" : "false",
              static_cast<unsigned long long>(metrics_.transactions_started));
  PM_LOG_INFO("SYNC", "SYNC_BEGIN",
              "request_id=%lu endpoint=%.*s overall_timeout_ms=%lu",
              static_cast<unsigned long>(request_id), printLength(endpoint),
              endpoint.data(),
              static_cast<unsigned long>(kOverallRequestTimeoutMs));
  SyncTransactionCleanup transaction(
      single_flight_, metrics_, diagnostics_, clock_, heap_telemetry_,
      request_id, method,
      endpoint, result.status, result.error, result.problem_code,
      result.tls_category, result.retry_after_ms,
      result.local_resource_deferred, result.body_size, started_ms);
  // StorageTask bounds and bulk-reads every history page, but it may already
  // own the shared FATFS/TLS memory gate when a heartbeat becomes due.  The
  // server-sync task is intentionally excluded from the task watchdog because
  // a verified TLS transaction can also exceed five seconds.  Wait for the
  // bounded storage operation instead of reporting a false transport outage
  // and delaying the authoritative heartbeat behind exponential backoff.
  const TickType_t high_memory_wait =
      endpoint == "/api/v1/device-heartbeats"
          ? pdMS_TO_TICKS(kHeartbeatStorageWaitMs)
          : pdMS_TO_TICKS(5000);
  HighMemoryLease high_memory_lease(diagnostics_, request_id, endpoint,
                                    high_memory_wait);
  if (!high_memory_lease) {
    result.error = "high_memory_operation_busy";
    result.tls_category = "LOCAL_RESOURCE_DEFERRED";
    result.local_resource_deferred = true;
    last_operation_locally_deferred_ = true;
    PM_LOG_WARN("MEMORY", "HIGH_MEMORY_GATE_TIMEOUT",
                "error=PM-TLS-006 request_id=%lu retryable=true",
                static_cast<unsigned long>(request_id));
    return result;
  }
  PM_LOG_INFO(
      "HTTP", "HTTP_BEGIN",
      "request_id=%lu correlation_id=%s method=%s endpoint=%.*s "
      "authenticated=%s request_bytes=%u",
      static_cast<unsigned long>(request_id), correlation_id.data(), method,
      printLength(endpoint), endpoint.data(),
      authenticated ? "true" : "false", static_cast<unsigned>(body_size));
  const std::size_t maximum_request_bytes =
      sync_policy::maximumRequestBytes(endpoint);
  if (body_size > maximum_request_bytes ||
      (body_size != 0U && body == nullptr)) {
    result.error = "request_body_too_large";
    PM_LOG_ERROR("HTTP", "REQUEST_BODY_REJECTED",
                 "error=PM-HTTP-003 request_id=%lu request_bytes=%u "
                 "maximum_bytes=%u",
                 static_cast<unsigned long>(request_id),
                 static_cast<unsigned>(body_size),
                 static_cast<unsigned>(maximum_request_bytes));
    return result;
  }
  if (!clock_.synchronized()) {
    result.error = "tls_time_not_trusted";
    PM_LOG_ERROR("TLS", "TIME_NOT_TRUSTED",
                 "error=PM-TLS-003 request_id=%lu category=TIME_NOT_TRUSTED",
                 static_cast<unsigned long>(request_id));
    return result;
  }
  const ServerTransportConfig &active_config = transport_config_;
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
  const HeapSnapshot initial_heap = heap_telemetry_.snapshot();
  const std::uint32_t initial_free_internal = initial_heap.free_internal_bytes;
  const std::uint32_t initial_largest_internal =
      initial_heap.largest_internal_block_bytes;
  const sync_policy::TlsMemoryAdmission initial_admission =
      sync_policy::classifyTlsMemory(initial_heap);
  if (initial_admission != sync_policy::TlsMemoryAdmission::Available) {
    ++metrics_.tls_requests_rejected_heap;
    if (initial_free_internal >= sync_policy::kMinimumInternalHeapBytes &&
        initial_largest_internal <
            sync_policy::kMinimumLargestInternalBlockBytes) {
      ++metrics_.fragmentation_deferrals;
      fragmentation_deferred_ = true;
    }
    result.error =
        initial_admission == sync_policy::TlsMemoryAdmission::Fragmented
            ? "internal_heap_fragmented"
            : "internal_heap_reserve_low";
    result.tls_category = "LOCAL_RESOURCE_DEFERRED";
    result.local_resource_deferred = true;
    last_operation_locally_deferred_ = true;
    PM_LOG_WARN(
        "MEMORY", "HEAP_LOW",
        "error=PM-TLS-006 request_id=%lu stage=preflight "
        "free_internal_heap=%lu largest_internal_block=%lu "
        "minimum_free_internal=%lu minimum_largest_block=%lu state=%s",
        static_cast<unsigned long>(request_id),
        static_cast<unsigned long>(initial_free_internal),
        static_cast<unsigned long>(initial_largest_internal),
        static_cast<unsigned long>(sync_policy::kMinimumInternalHeapBytes),
        static_cast<unsigned long>(
            sync_policy::kMinimumLargestInternalBlockBytes),
        initial_admission == sync_policy::TlsMemoryAdmission::Fragmented
            ? "fragmented"
            : "low_total_memory");
    return result;
  }
  if (diag::SerialLogger::instance().allow("tls_ca_metadata", 3'600'000U)) {
    logCaMetadata(active_config.server_ca_pem);
  }
  if (endpoint.size() > ServerSyncScratch::kCanonicalTargetCapacity) {
    result.error = "request_target_capacity_exceeded";
    result.local_resource_deferred = true;
    return result;
  }
  StringView canonical_target = endpoint;
  // All recurring device endpoints are already canonical paths. Avoid the
  // query parser's temporary containers in that hot path; retain the normative
  // parser for the bounded, infrequent query-string case.
  if (containsCharacter(endpoint, '?') || endpoint.empty() ||
      endpoint.data()[0] != '/' || containsCharacter(endpoint, '#')) {
    const std::string endpoint_text(endpoint.data(), endpoint.size());
    if (!crypto::canonicalTarget(endpoint_text,
                                 transport_scratch_.canonical_target)) {
      result.error = "request_target_invalid";
      PM_LOG_ERROR(
          "HTTP", "TARGET_INVALID",
          "error=PM-HTTP-002 request_id=%lu method=%s endpoint=%.*s",
          static_cast<unsigned long>(request_id), method,
          printLength(endpoint), endpoint.data());
      return result;
    }
    canonical_target = transport_scratch_.canonical_target;
  }
  const std::string &target_host = transport_host_;
  const std::uint16_t target_port = transport_port_;
  if (target_host.empty()) {
    result.error = "server_address_not_allowed";
    PM_LOG_ERROR("SERVER", "TARGET_REJECTED",
                 "error=PM-SERVER-003 request_id=%lu host=%s port=%u",
                 static_cast<unsigned long>(request_id),
                 target_host.empty() ? "invalid" : target_host.c_str(),
                 static_cast<unsigned>(target_port));
    return result;
  }
  if (!joinUrl(active_config.server_url, endpoint, transport_scratch_.url)) {
    ++transport_scratch_.unexpected_growths;
    result.error = "request_url_capacity_exceeded";
    result.local_resource_deferred = true;
    return result;
  }
  ++transport_scratch_.url_reuses;
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
       static_cast<std::uint32_t>(resolved) != 0U &&
       static_cast<std::uint32_t>(resolved) !=
           static_cast<std::uint32_t>(INADDR_NONE));
  if (!resolved_ok && dotLocalHost(target_host)) {
    const std::string mdns_host =
        target_host.substr(0, target_host.size() - std::strlen(".local"));
    PM_LOG_INFO("DNS", "MDNS_FALLBACK_BEGIN",
                "request_id=%lu host=%s query=%s reason=unicast_dns_failed",
                static_cast<unsigned long>(request_id), target_host.c_str(),
                mdns_host.c_str());
    resolved = MDNS.queryHost(mdns_host.c_str(), 2000U);
    resolved_ok =
        static_cast<std::uint32_t>(resolved) != 0U &&
        static_cast<std::uint32_t>(resolved) !=
            static_cast<std::uint32_t>(INADDR_NONE);
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
  const HeapSnapshot before_tls_heap = heap_telemetry_.snapshot();
  const std::uint32_t free_internal = before_tls_heap.free_internal_bytes;
  const std::uint32_t largest_internal =
      before_tls_heap.largest_internal_block_bytes;
  const sync_policy::TlsMemoryAdmission before_tls_admission =
      sync_policy::classifyTlsMemory(before_tls_heap);
  if (before_tls_admission != sync_policy::TlsMemoryAdmission::Available) {
    ++metrics_.tls_requests_rejected_heap;
    if (free_internal >= sync_policy::kMinimumInternalHeapBytes &&
        largest_internal <
            sync_policy::kMinimumLargestInternalBlockBytes) {
      ++metrics_.fragmentation_deferrals;
      fragmentation_deferred_ = true;
    }
    result.error =
        before_tls_admission == sync_policy::TlsMemoryAdmission::Fragmented
            ? "internal_heap_fragmented"
            : "internal_heap_reserve_low";
    result.tls_category = "LOCAL_RESOURCE_DEFERRED";
    result.local_resource_deferred = true;
    last_operation_locally_deferred_ = true;
    PM_LOG_WARN(
        "MEMORY", "HEAP_LOW",
        "error=PM-TLS-006 request_id=%lu stage=before_tls "
        "free_internal_heap=%lu largest_internal_block=%lu "
        "minimum_free_internal=%lu minimum_largest_block=%lu state=%s",
        static_cast<unsigned long>(request_id),
        static_cast<unsigned long>(free_internal),
        static_cast<unsigned long>(largest_internal),
        static_cast<unsigned long>(sync_policy::kMinimumInternalHeapBytes),
        static_cast<unsigned long>(
            sync_policy::kMinimumLargestInternalBlockBytes),
        before_tls_admission == sync_policy::TlsMemoryAdmission::Fragmented
            ? "fragmented"
            : "low_total_memory");
    return result;
  }
  if (clock_.monotonicMs() - started_ms >= kOverallRequestTimeoutMs) {
    result.error = "request_overall_timeout";
    result.tls_category = "TIMEOUT";
    return result;
  }
  // A stack high-water mark is historical telemetry, not currently free
  // stack. It must never become a latching admission gate. The checkpoint
  // above records and warns on the measured margin without disabling future
  // heartbeats.
  if (!high_memory_lease.transitionToTlsActive()) {
    result.error = "high_memory_context_transition_failed";
    result.tls_category = "LOCAL_RESOURCE_DEFERRED";
    result.local_resource_deferred = true;
    last_operation_locally_deferred_ = true;
    PM_LOG_ERROR("MEMORY", "HIGH_MEMORY_CONTEXT_FAILED",
                 "error=PM-TLS-006 request_id=%lu expected=tls_preparing "
                 "next=tls_active",
                 static_cast<unsigned long>(request_id));
    return result;
  }
  // The lease was declared before these transport objects, so reverse-order
  // destruction runs TransportCleanup, HTTPClient, and ResolvedTlsClient
  // before release records the post-TLS grace timestamp.
  diagnostics_.recordTlsLifecycleCheckpoint(
      request_id, endpoint.data(), endpoint.size(),
      TlsLifecycleStage::BeforeClientConstruction);
  ResolvedTlsClient client;
  high_memory_lease.markClientConstructed();
  if (fragmentation_deferred_) {
    ++metrics_.fragmentation_recoveries;
    fragmentation_deferred_ = false;
  }
  metrics_.largest_internal_before_tls = largest_internal;
  ++metrics_.tls_requests_admitted;
  client.setResolvedEndpoint(resolved, target_host, target_port);
  client.setHandshakeTimeout(kTlsHandshakeTimeoutSeconds);
  client.setTimeout(kTcpConnectTimeoutMs / 1000U);
  client.setCACert(active_config.server_ca_pem.c_str());
  diagnostics_.recordTlsLifecycleCheckpoint(
      request_id, endpoint.data(), endpoint.size(),
      TlsLifecycleStage::AfterTlsConfiguration);
  HTTPClient http;
  TransportCleanup transport(http, client, diagnostics_, request_id,
                             endpoint);
  http.setConnectTimeout(kTcpConnectTimeoutMs);
  http.setTimeout(kHttpResponseTimeoutMs);
  http.setReuse(false);
  if (!http.begin(client, transport_scratch_.url.data())) {
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
  diagnostics_.recordTlsLifecycleCheckpoint(
      request_id, endpoint.data(), endpoint.size(),
      TlsLifecycleStage::AfterHttpBegin);
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
  // HTTPClient owns the one and only connect call. ResolvedTlsClient routes
  // that call to the already-resolved address while preserving the original
  // host for SNI and certificate hostname verification. Manually connecting
  // here and then calling sendRequest caused intermittent
  // "Connection already in progress" failures after a successful request.
  http.addHeader("Content-Type", "application/json");
  // The server already treats X-Request-ID as a bounded correlation
  // identifier. It is intentionally not a credential and is not part of the
  // pm-protocol canonical signature, so existing HMAC vectors remain stable.
  http.addHeader("X-Request-ID", correlation_id.data());
  if (authenticated) {
    logTaskCheckpoint("BEFORE_HMAC");
    crypto::Key32 outbound{};
    crypto::Key32 inbound{};
    if (!config_.directionalKeys(outbound, inbound)) {
      result.error = "device_credentials_unavailable";
      return result;
    }
    const std::string &device_id = transport_device_id_;
    std::array<char, 24U> timestamp{};
    const int timestamp_length =
        std::snprintf(timestamp.data(), timestamp.size(), "%lld",
                      static_cast<long long>(std::time(nullptr)));
    std::array<std::uint8_t, 16U> nonce_bytes{};
    std::array<char, 33U> nonce{};
    std::array<char, 65U> body_hash{};
    std::array<char, 65U> signature{};
    crypto::secureRandom(nonce_bytes.data(), nonce_bytes.size());
    const crypto::Key32 body_digest = crypto::sha256(
        reinterpret_cast<const std::uint8_t *>(body), body_size);
    if (timestamp_length <= 0 ||
        static_cast<std::size_t>(timestamp_length) >= timestamp.size() ||
        !hexEncodeFixed(nonce_bytes.data(), nonce_bytes.size(), nonce.data(),
                        nonce.size()) ||
        !hexEncodeFixed(body_digest.data(), body_digest.size(), body_hash.data(),
                        body_hash.size()) ||
        !buildCanonicalRequest(method, canonical_target, timestamp.data(),
                               nonce.data(), body_hash.data(),
                               transport_scratch_.canonical_request)) {
      std::fill(outbound.begin(), outbound.end(), 0U);
      std::fill(inbound.begin(), inbound.end(), 0U);
      std::fill(nonce_bytes.begin(), nonce_bytes.end(), 0U);
      result.error = "canonical_request_capacity_exceeded";
      result.local_resource_deferred = true;
      ++transport_scratch_.unexpected_growths;
      return result;
    }
    ++transport_scratch_.canonical_reuses;
    const crypto::Key32 signature_digest = crypto::hmacSha256(
        outbound.data(), outbound.size(),
        reinterpret_cast<const std::uint8_t *>(
            transport_scratch_.canonical_request.data()),
        transport_scratch_.canonical_request.size());
    if (!hexEncodeFixed(signature_digest.data(), signature_digest.size(),
                        signature.data(), signature.size())) {
      std::fill(outbound.begin(), outbound.end(), 0U);
      std::fill(inbound.begin(), inbound.end(), 0U);
      result.error = "signature_buffer_capacity_exceeded";
      result.local_resource_deferred = true;
      return result;
    }
    http.addHeader("X-PM-Protocol", version::PROTOCOL);
    http.addHeader("X-PM-Device-ID", device_id.c_str());
    http.addHeader("X-PM-Timestamp", timestamp.data());
    http.addHeader("X-PM-Nonce", nonce.data());
    http.addHeader("X-PM-Content-SHA256", body_hash.data());
    http.addHeader("X-PM-Signature", signature.data());
    std::fill(outbound.begin(), outbound.end(), 0U);
    std::fill(inbound.begin(), inbound.end(), 0U);
    std::fill(nonce_bytes.begin(), nonce_bytes.end(), 0U);
    std::fill(nonce.begin(), nonce.end(), '\0');
    std::fill(body_hash.begin(), body_hash.end(), '\0');
    std::fill(signature.begin(), signature.end(), '\0');
    std::memset(transport_scratch_.canonical_request.data(), 0,
                transport_scratch_.canonical_request.size());
    transport_scratch_.canonical_request.clear();
    logTaskCheckpoint("AFTER_HMAC");
  } else {
    http.addHeader("X-PM-Protocol", version::PROTOCOL);
  }
  logTaskCheckpoint("BEFORE_HTTP_SEND");
  if (std::strcmp(method, "GET") == 0) {
    result.status = http.GET();
  } else {
    result.status = http.sendRequest(
        method,
        reinterpret_cast<std::uint8_t *>(const_cast<char *>(body)), body_size);
  }
  diagnostics_.recordTlsLifecycleCheckpoint(
      request_id, endpoint.data(), endpoint.size(),
      TlsLifecycleStage::AfterRequest);
  if (result.status > 0) {
    endpoint_address_cache_.recordTransportSuccess();
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
  } else {
    result.error = HTTPClient::errorToString(result.status).c_str();
    result.tls_category = diag::tlsErrorCategory(result.error.c_str());
    if (endpoint_address_cache_.recordTransportFailure()) {
      PM_LOG_WARN("DNS", "DNS_CACHE_INVALIDATED",
                  "request_id=%lu host=%s address=%s "
                  "consecutive_transport_failures=2",
                  static_cast<unsigned long>(request_id), target_host.c_str(),
                  resolved.toString().c_str());
    }
    PM_LOG_ERROR(
        "TLS", "TLS_FAILED",
        "error=PM-TLS-004 request_id=%lu host=%s port=%u category=%s "
        "detail=%s elapsed_ms=%llu",
        static_cast<unsigned long>(request_id), target_host.c_str(),
        static_cast<unsigned>(target_port), result.tls_category.c_str(),
        result.error.c_str(),
        static_cast<unsigned long long>(clock_.monotonicMs() - started_ms));
  }
  // HTTPClient::sendRequest is synchronous. The task-owned request buffer may
  // now be reused by the next operation; it deliberately retains its bounded
  // PSRAM allocation so recurring requests do not churn internal DRAM.
  metrics_.largest_internal_after_tls =
      heap_telemetry_.snapshot().largest_internal_block_bytes;
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
    const bool response_body_fits = sync_policy::responseBodyFitsBuffer(
        response_size, transport_scratch_.response_body.capacity());
    if (!sync_policy::responseLengthAllowed(endpoint, response_size,
                                             result.status)) {
      result.error =
          response_size < 0 ? "response_length_required" : "response_too_large";
      result.status = -1;
    } else if (!response_body_fits ||
               heap_telemetry_.snapshot().free_internal_bytes <
                   sync_policy::kMinimumPostResponseInternalHeapBytes) {
      if (!response_body_fits) {
        ++transport_scratch_.unexpected_growths;
        ++metrics_.response_buffer_growths;
      }
      result.error = "response_memory_reserve_low";
      result.tls_category = "LOCAL_RESOURCE_DEFERRED";
      result.local_resource_deferred = true;
      last_operation_locally_deferred_ = true;
      result.status = -1;
      PM_LOG_WARN("MEMORY", "HEAP_LOW",
                  "error=PM-TLS-006 request_id=%lu stage=response_allocation "
                  "response_bytes=%d response_storage=psram "
                  "minimum_post_response_internal=%lu",
                  static_cast<unsigned long>(request_id), response_size,
                  static_cast<unsigned long>(
                      sync_policy::kMinimumPostResponseInternalHeapBytes));
    } else if (result.status != 204 &&
               !readBoundedResponseBody(http, clock_, response_size,
                                        transport_scratch_.response_body,
                                        result.error)) {
      result.tls_category = diag::tlsErrorCategory(result.error.c_str());
      result.status = -1;
    } else if (result.status < 200 || result.status >= 300) {
      ++transport_scratch_.response_reuses;
      ++metrics_.response_buffer_reuses;
      result.body_size = transport_scratch_.response_body.size();
      result.problem_code = problemCode(result.body, result.body_size);
    }
    if (result.status >= 200 && result.status < 300) {
      if (result.status != 204) {
        ++transport_scratch_.response_reuses;
        ++metrics_.response_buffer_reuses;
      }
      result.body_size = transport_scratch_.response_body.size();
    }
  }
  return result;
}

bool ServerSync::heartbeatBody(ServerSyncBuffer &output) const {
  const CompactNetworkStatus network = network_.compactStatus();
  const HeartbeatStorageHealth storage = storage_.heartbeatHealth();
  const MeterMetrics meter = meter_.metrics();
  const StoragePolicy &storage_policy = transport_runtime_config_.storage_policy;
  MeasurementSnapshot latest;
  const bool has_latest = diagnostics_.latest(latest);
  std::array<char, 21U> last_sync_at{};
  std::array<char, 21U> measured_at{};
  std::array<char, 21U> last_cleanup_at{};
  std::array<char, 21U> first_dropped_interval_at{};
  std::array<char, 21U> last_dropped_interval_at{};
  const bool has_last_sync_at =
      clock_.synchronized() &&
      clock_.formatUtcIso8601(last_sync_at.data(), last_sync_at.size());
  const bool has_measured_at =
      has_latest && latest.valid &&
      formatIsoUtc(latest.utc_ms, measured_at.data(), measured_at.size());
  const bool has_last_cleanup_at =
      formatIsoUtc(storage.last_cleanup_utc_ms, last_cleanup_at.data(),
                   last_cleanup_at.size());
  const bool has_first_dropped_interval_at =
      formatIsoUtc(storage.first_dropped_interval_utc_ms,
                   first_dropped_interval_at.data(),
                   first_dropped_interval_at.size());
  const bool has_last_dropped_interval_at =
      formatIsoUtc(storage.last_dropped_interval_utc_ms,
                   last_dropped_interval_at.data(),
                   last_dropped_interval_at.size());
  JsonDocument document(psramJsonAllocator());
  document["schema_version"] = "heartbeat/1.0.0";
  document["protocol_version"] = version::PROTOCOL;
  document["device_id"] = transport_device_id_;
  document["boot_id"] = transport_boot_id_;
  document["firmware_version"] = version::FIRMWARE;
  document["firmware_build_hash"] = OtaService::runningBuildHash();
  JsonObject ota = document["ota"].to<JsonObject>();
  ota["supported"] = true;
  ota["protocol_version"] = ota_v2::kProtocolVersion;
  ota["authentication_mode"] = ota_v2::kAuthenticationMode;
  ota["rollback_supported"] = true;
  ota["partition_size_bytes"] = OtaService::updatePartitionSize();
  document["uptime_seconds"] = clock_.monotonicMs() / 1000U;
  document["reboot_reason"] = resetReasonName();
  document["current_ip"] = network.ip_address.data();
  document["hostname"] = network.hostname.data();
  document["rssi_dbm"] = network.rssi_dbm;
  document["connection_mode"] =
      connectionModeName(transport_runtime_config_.connection_mode);
  document["configuration_version"] = config_.serverConfigVersion();
  JsonObject time = document["time"].to<JsonObject>();
  time["trusted"] = clock_.synchronized();
  time["source"] = clock_.synchronized() ? "sntp" : "untrusted";
  time["offset_ms"] = 0;
  if (has_last_sync_at) {
    time["last_sync_at"] = last_sync_at.data();
  }
  JsonObject meter_json = document["pzem"].to<JsonObject>();
  const bool meter_ok = meter.last_error == MeterError::None;
  meter_json["ok"] = meter_ok;
  meter_json["status"] =
      meter_ok ? "healthy" : meterErrorCode(meter.last_error);
  meter_json["error_count"] = meter.consecutive_errors;
  JsonObject meter_details = meter_json["details"].to<JsonObject>();
  meter_details["last_error"] = meterErrorCode(meter.last_error);
  if (has_latest && latest.valid && has_measured_at) {
    JsonObject live = document["latest"].to<JsonObject>();
    live["measured_at"] = measured_at.data();
    live["voltage_v"] = latest.voltage_v;
    live["current_a"] = latest.current_a;
    live["power_w"] = latest.active_power_w;
    live["frequency_hz"] = latest.frequency_hz;
    live["power_factor"] = latest.power_factor;
    live["energy_wh"] = latest.device_lifetime_energy_wh;
  }
  JsonObject storage_json = document["sd"].to<JsonObject>();
  const bool storage_ok = storage.present && storage.mounted &&
                          storage.writable && storage.sequence_floor_ready;
  storage_json["ok"] = storage_ok;
  storage_json["status"] =
      storage.sequence_reconciliation_in_progress
          ? "sequence_reconciling"
          : (storage_ok
                 ? (storage.index_healthy ? storage.pressure_state.data()
                                          : "history_integrity_degraded")
                 : "storage_degraded");
  storage_json["error_count"] = storage.write_failures;
  JsonObject storage_details = storage_json["details"].to<JsonObject>();
  storage_details["present"] = storage.present;
  storage_details["mounted"] = storage.mounted;
  storage_details["writable"] = storage.writable;
  storage_details["history_integrity_verified"] = storage.index_healthy;
  storage_details["sequence_floor_ready"] = storage.sequence_floor_ready;
  storage_details["sequence_reconciliation_in_progress"] =
      storage.sequence_reconciliation_in_progress;
  storage_details["sequence_conflict"] = storage.sequence_conflict;
  storage_details["sequence_cursor_conflict"] =
      metrics_.last_error == "server_sequence_cursor_regressed" ||
      metrics_.last_error == "heartbeat_cursor_contract_invalid";
  storage_details["sequence_floor"] = storage.sequence_floor;
  storage_details["next_sequence"] = storage.next_sequence;
  storage_details["local_record_count"] = storage.local_record_count;
  storage_details["card_empty"] = storage.local_record_count == 0U;
  storage_details["card_replaced_or_initialized"] =
      storage.card_replaced_or_initialized;
  storage_details["card_identity_status"] =
      storage.card_identity_status.data();
  storage_details["card_generation"] = storage.card_generation;
  storage_details["last_self_test_passed"] = storage.last_self_test_passed;
  storage_details["prepared_for_removal"] = storage.prepared_for_removal;
  storage_details["card_type"] = storage.card_type.data();
  storage_details["filesystem"] = storage.filesystem.data();
  storage_details["capacity_bytes"] = storage.capacity_bytes;
  storage_details["used_bytes"] = storage.used_bytes;
  storage_details["free_bytes"] = storage.free_bytes;
  storage_details["free_percent"] = storage.free_percent;
  storage_details["pressure_state"] = storage.pressure_state.data();
  storage_details["pressure_reason"] = storage.pressure_reason.data();
  storage_details["storage_full"] = storage.storage_full;
  storage_details["retention_mode"] =
      retentionModeName(storage_policy.mode);
  storage_details["retention_days"] =
      storage_policy.retention_days;
  storage_details["minimum_local_history_days"] =
      storage_policy.minimum_local_history_days;
  storage_details["storage_notice_percent"] =
      storage_policy.notice_percent;
  storage_details["storage_warning_percent"] =
      storage_policy.warning_percent;
  storage_details["storage_critical_percent"] =
      storage_policy.critical_percent;
  storage_details["storage_emergency_percent"] =
      storage_policy.emergency_percent;
  storage_details["storage_emergency_reserve_bytes"] =
      storage_policy.emergency_reserve_bytes;
  storage_details["storage_cleanup_target_percent"] =
      storage_policy.cleanup_target_percent;
  storage_details["storage_cleanup_target_bytes"] =
      storage_policy.cleanup_target_bytes;
  storage_details["event_retention_days"] =
      storage_policy.event_retention_days;
  storage_details["server_ack_sequence"] = config_.serverAckSequence();
  storage_details["server_maximum_seen_sequence"] =
      config_.serverMaximumSeenSequence();
  storage_details["event_ack_sequence"] = config_.serverEventAckSequence();
  storage_details["acknowledgement_verified"] =
      storage.acknowledgement_verified;
  storage_details["oldest_record_sequence"] = storage.oldest_sequence;
  storage_details["newest_record_sequence"] = storage.newest_sequence;
  storage_details["oldest_event_sequence"] = storage.oldest_event_sequence;
  storage_details["newest_event_sequence"] = storage.newest_event_sequence;
  storage_details["unacknowledged_record_count"] =
      storage.newest_syncable_sequence >= config_.serverAckSequence()
          ? storage.newest_syncable_sequence - config_.serverAckSequence()
          : 0U;
  storage_details["reclaimable_bytes"] = storage.reclaimable_bytes;
  storage_details["protected_unacknowledged_bytes"] =
      storage.protected_unacknowledged_bytes;
  storage_details["protected_untrusted_bytes"] =
      storage.protected_untrusted_bytes;
  storage_details["segment_count"] = storage.segment_count;
  storage_details["eligible_segment_count"] =
      storage.eligible_segment_count;
  storage_details["protected_segment_count"] =
      storage.protected_segment_count;
  storage_details["open_segment_count"] = storage.open_segment_count;
  storage_details["closed_segment_count"] = storage.closed_segment_count;
  storage_details["untrusted_segment_count"] =
      storage.untrusted_segment_count;
  storage_details["event_segment_count"] = storage.event_segment_count;
  storage_details["export_count"] = storage.export_count;
  storage_details["repair_artifact_count"] =
      storage.repair_artifact_count;
  storage_details["temporary_artifact_count"] =
      storage.temporary_artifact_count;
  storage_details["cleanup_in_progress"] = storage.cleanup_in_progress;
  storage_details["cleanup_recovery_required"] =
      storage.cleanup_recovery_required;
  storage_details["last_cleanup_at"] =
      has_last_cleanup_at ? last_cleanup_at.data() : "";
  storage_details["last_cleanup_reclaimed_bytes"] =
      storage.last_cleanup_reclaimed_bytes;
  storage_details["last_cleanup_result"] =
      storage.last_cleanup_result.data();
  storage_details["last_cleanup_reason"] =
      storage.last_cleanup_reason.data();
  storage_details["dropped_interval_count"] =
      storage.dropped_interval_count;
  storage_details["first_dropped_interval_at"] =
      has_first_dropped_interval_at ? first_dropped_interval_at.data() : "";
  storage_details["last_dropped_interval_at"] =
      has_last_dropped_interval_at ? last_dropped_interval_at.data() : "";
  storage_details["growth_bytes_per_day"] = storage.growth_bytes_per_day;
  storage_details["estimated_days_remaining"] =
      storage.estimated_days_remaining;
  storage_details["last_error"] = storage.last_error.data();
  document["oldest_stored_sequence"] = storage.oldest_sequence;
  document["oldest_syncable_sequence"] = storage.oldest_syncable_sequence;
  document["newest_syncable_sequence"] = storage.newest_syncable_sequence;
  document["newest_stored_sequence"] = storage.newest_sequence;
  document["server_ack_sequence"] = config_.serverAckSequence();
  document["server_maximum_seen_sequence"] =
      config_.serverMaximumSeenSequence();
  document["backlog_estimate"] =
      storage.newest_syncable_sequence >= config_.serverAckSequence()
          ? storage.newest_syncable_sequence - config_.serverAckSequence()
          : 0;
  JsonObject resources = document["resources"].to<JsonObject>();
  resources["free_heap_bytes"] = ESP.getFreeHeap();
  resources["minimum_free_heap_bytes"] = ESP.getMinFreeHeap();
  JsonObject synchronization = resources["synchronization"].to<JsonObject>();
  synchronization["last_heartbeat_result"] = metrics_.last_heartbeat_result;
  synchronization["last_local_deferral_reason"] =
      metrics_.last_local_deferral_reason;
  synchronization["consecutive_local_deferrals"] =
      metrics_.consecutive_local_deferrals;
  synchronization["heartbeat_buffer_reuses"] =
      metrics_.heartbeat_buffer_reuses;
  synchronization["response_buffer_reuses"] =
      metrics_.response_buffer_reuses;
  JsonObject queues = document["queue"].to<JsonObject>();
  const QueueMetrics queue_metrics = diagnostics_.queueMetrics();
  queues["storage"] = queue_metrics.storage_depth;
  queues["actions"] = queue_metrics.action_depth;
  queues["storage_dropped"] = queue_metrics.storage_dropped;
  queues["actions_dropped"] = queue_metrics.action_dropped;
  output.clear();
  if (document.overflowed()) {
    return false;
  }
  const std::size_t written = serializeJson(document, output);
  return written != 0U && !output.overflowed();
}

std::uint32_t ServerSync::heartbeatDelayMs() const {
  const std::uint32_t seconds =
      heartbeat_interval_override_seconds_ == 0
          ? config_.compactServerSyncRuntimeConfig()
                .heartbeat_interval_seconds
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
      static_cast<std::uint64_t>(
          config_.compactServerSyncRuntimeConfig().sync_retry_max_seconds) *
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
      static_cast<std::uint64_t>(
          config_.compactServerSyncRuntimeConfig().sync_retry_max_seconds) *
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
