#include "api/HttpApi.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <functional>
#include <utility>
#include <vector>

#include <ArduinoJson.h>
#include <ESP.h>
#include <esp_heap_caps.h>

#include "board_pins.h"
#include "app/TaskConfig.h"
#include "build_config.h"
#include "diagnostics/SerialLogger.h"
#include "network/ReadingWireFormat.h"
#include "security/Crypto.h"
#include "ui/embedded_assets.h"
#include "version.h"

namespace pm {
namespace {

// ESP-IDF expresses task stack depth and high-water marks in bytes. Network
// settings exercise PEM validation plus atomic serialize/verify paths and need
// more headroom than password hashing alone.
constexpr std::uint32_t kMinimumLightUiInternalHeapBytes = 40U * 1024U;
constexpr std::uint32_t kMinimumHeavyUiInternalHeapBytes = 72U * 1024U;
constexpr std::uint32_t kMinimumHeavyUiLargestBlockBytes = 28U * 1024U;

struct DeferredHttpResult {
  int status{200};
  std::string content_type{"application/json"};
  std::string body;
};

bool constantTimeDigestEqual(const crypto::Key32 &left,
                             const crypto::Key32 &right) {
  std::uint8_t difference = 0U;
  for (std::size_t index = 0; index < left.size(); ++index) {
    difference |= static_cast<std::uint8_t>(left[index] ^ right[index]);
  }
  return difference == 0U;
}

// A response-owned deferred state machine. It keeps no request pointer and
// never waits in AsyncTCP: poll() must be a try-only lookup. HTTP headers are
// assembled only after the worker result is ready, preserving the synchronous
// pm-protocol/1.0.0 response contract without doing storage/NVS work in the
// request callback.
class DeferredWorkerResponse final : public AsyncWebServerResponse {
public:
  using Poller = std::function<bool(DeferredHttpResult &)>;

  DeferredWorkerResponse(Poller poller, const std::uint32_t timeout_ms)
      : poller_(std::move(poller)), deadline_ms_(millis() + timeout_ms) {
    _code = 200;
  }

  bool _sourceValid() const override { return static_cast<bool>(poller_); }

  void _respond(AsyncWebServerRequest *) override {
    _state = RESPONSE_WAIT_ACK;
  }

  size_t _ack(AsyncWebServerRequest *request, const size_t len,
              const std::uint32_t) override {
    _ackedLength += len;
    if (_state == RESPONSE_WAIT_ACK) {
      DeferredHttpResult result;
      if (!poller_(result)) {
        if (static_cast<std::int32_t>(millis() - deadline_ms_) < 0) {
          return 0;
        }
        result.status = 503;
        result.content_type = "application/problem+json";
        result.body =
            "{\"type\":\"https://powermonitor.local/problems/"
            "deferred_operation_timeout\",\"title\":\"deferred_operation_"
            "timeout\",\"status\":503,\"detail\":\"The bounded worker did "
            "not complete before the response deadline.\",\"code\":"
            "\"deferred_operation_timeout\"}";
      }
      prepare(std::move(result), request->version());
    }

    size_t written = 0;
    if (_state == RESPONSE_HEADERS) {
      const size_t added = request->client()->add(
          assembled_headers_.c_str() + written_headers_,
          assembled_headers_.length() - written_headers_);
      written_headers_ += added;
      _writtenLength += added;
      written += added;
      if (written_headers_ < assembled_headers_.length()) {
        request->client()->send();
        return written;
      }
      assembled_headers_ = String();
      _state = RESPONSE_CONTENT;
    }
    if (_state == RESPONSE_CONTENT) {
      const size_t remaining = body_.size() - _sentLength;
      const size_t added =
          request->client()->write(body_.data() + _sentLength, remaining);
      _sentLength += added;
      _writtenLength += added;
      written += added;
      if (_sentLength >= body_.size())
        _state = RESPONSE_END;
    }
    request->client()->send();
    return written;
  }

private:
  void prepare(DeferredHttpResult result, const std::uint8_t http_version) {
    body_ = std::move(result.body);
    _code = result.status;
    _contentType = result.content_type.c_str();
    _contentLength = body_.size();
    _sendContentLength = true;
    addHeader("Content-Type", _contentType);
    addHeader("Content-Length", static_cast<long>(_contentLength));
    addHeader("Cache-Control", "no-store");
    addHeader("X-Content-Type-Options", "nosniff");
    addHeader("Connection", "close", false);
    _assembleHead(assembled_headers_, http_version);
    _state = RESPONSE_HEADERS;
    poller_ = nullptr;
  }

  Poller poller_;
  std::uint32_t deadline_ms_{0};
  std::string body_;
  String assembled_headers_;
  size_t written_headers_{0};
};

bool prefersAsync(AsyncWebServerRequest *request) {
  return request->hasHeader("Prefer") &&
         request->getHeader("Prefer")->value().indexOf("respond-async") >= 0;
}

} // namespace

HttpApi::HttpApi(ConfigService &config, NetworkService &network,
                 ClockService &clock, SdStorage &storage,
                 StorageCoordinator &coordinator, Diagnostics &diagnostics,
                 IMeter &meter, OtaService &ota,
                 const QueueHandle_t maintenance_queue)
    : config_(config), network_(network), clock_(clock), storage_(storage),
      coordinator_(coordinator), diagnostics_(diagnostics), meter_(meter),
      ota_(ota), provisioning_(config), maintenance_queue_(maintenance_queue) {}

void HttpApi::begin() {
  password_job_queue_ =
      xQueueCreate(kPasswordJobQueueCapacity, sizeof(PasswordJob *));
  password_result_mutex_ = xSemaphoreCreateMutex();
  const bool worker_started =
      password_job_queue_ != nullptr && password_result_mutex_ != nullptr &&
      xTaskCreatePinnedToCore(passwordJobTaskEntry, "PasswordJobTask",
                              task_config::kPasswordJobStackBytes, this, 1,
                              &password_job_task_, 1) == pdPASS;
  if (!worker_started) {
    PM_LOG_ERROR("PASSWORD", "WORKER_INIT_FAILED",
                 "error=PM-PASSWORD-001 queue=%s mutex=%s",
                 password_job_queue_ == nullptr ? "failed" : "ready",
                 password_result_mutex_ == nullptr ? "failed" : "ready");
  } else {
    PM_LOG_INFO("PASSWORD", "WORKER_READY",
                "queue_capacity=%u result_capacity=%u core=1 priority=1 "
                "stack_bytes=%lu watchdog=false",
                static_cast<unsigned>(kPasswordJobQueueCapacity),
                static_cast<unsigned>(kPasswordResultCapacity),
                static_cast<unsigned long>(task_config::kPasswordJobStackBytes));
  }
  registerReadRoutes();
  registerMutationRoutes();
  server_.on("/", HTTP_GET, [this](AsyncWebServerRequest *request) {
    network_.touchSetupActivity();
    const ui::Asset *asset = ui::findAsset("/index.html");
    if (asset == nullptr) {
      sendProblem(request, 500, "ui_asset_missing",
                  "Embedded UI asset is unavailable.");
      return;
    }
    AsyncWebServerResponse *response = request->beginResponse(
        200, asset->content_type, asset->data, asset->size);
    response->addHeader("Content-Encoding", "gzip");
    response->addHeader("Cache-Control", "no-cache");
    response->addHeader(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; object-src "
        "'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    response->addHeader("X-Content-Type-Options", "nosniff");
    response->addHeader("Referrer-Policy", "no-referrer");
    response->addHeader("Connection", "close", false);
    request->send(response);
  });
  server_.on("/assets/app.js", HTTP_GET,
             [this](AsyncWebServerRequest *request) {
               network_.touchSetupActivity();
               const ui::Asset *asset = ui::findAsset("/assets/app.js");
               if (asset == nullptr) {
                 request->send(404);
                 return;
               }
               AsyncWebServerResponse *response = request->beginResponse(
                   200, asset->content_type, asset->data, asset->size);
               response->addHeader("Content-Encoding", "gzip");
               response->addHeader("Cache-Control",
                                   "public, max-age=31536000, immutable");
               response->addHeader("Connection", "close", false);
               request->send(response);
             });
  server_.on("/assets/style.css", HTTP_GET,
             [this](AsyncWebServerRequest *request) {
               network_.touchSetupActivity();
               const ui::Asset *asset = ui::findAsset("/assets/style.css");
               if (asset == nullptr) {
                 request->send(404);
                 return;
               }
               AsyncWebServerResponse *response = request->beginResponse(
                   200, asset->content_type, asset->data, asset->size);
               response->addHeader("Content-Encoding", "gzip");
               response->addHeader("Cache-Control",
                                   "public, max-age=31536000, immutable");
               response->addHeader("Connection", "close", false);
               request->send(response);
             });
  server_.onNotFound([this](AsyncWebServerRequest *request) {
    sendProblem(request, 404, "not_found",
                "The requested local API or UI resource does not exist.");
  });
  server_.begin();
  PM_LOG_INFO("WEB", "SERVER_STARTED",
              "port=80 tls=false local_only=true ui=embedded "
              "authentication=session_or_hmac");
}

void HttpApi::passwordJobTaskEntry(void *context) {
  static_cast<HttpApi *>(context)->passwordJobTask();
}

const char *HttpApi::passwordJobKindName(const PasswordJobKind kind) {
  switch (kind) {
  case PasswordJobKind::Login:
    return "login";
  case PasswordJobKind::Setup:
    return "setup";
  case PasswordJobKind::ConfigUpdate:
    return "config_update";
  case PasswordJobKind::NetworkSettings:
    return "network_settings";
  case PasswordJobKind::SyncAcknowledgement:
    return "sync_acknowledgement";
  case PasswordJobKind::Reenrollment:
    return "reenrollment";
  }
  return "unknown";
}

void HttpApi::passwordJobTask() {
  PM_LOG_INFO(
      "TASK", "TASK_STARTED",
      "name=PasswordJobTask core=%d priority=%u stack_bytes=%lu watchdog=false",
      xPortGetCoreID(), static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
      static_cast<unsigned long>(task_config::kPasswordJobStackBytes));
  PasswordJob *job = nullptr;
  for (;;) {
    if (xQueueReceive(password_job_queue_, &job, pdMS_TO_TICKS(1000)) !=
            pdTRUE ||
        job == nullptr) {
      continue;
    }
    const std::uint64_t started = clock_.monotonicMs();
    const std::uint64_t queue_wait_ms = started - job->queued_ms;
    const char *kind_name = passwordJobKindName(job->kind);
    PM_LOG_INFO(
        "PASSWORD", "JOB_STARTED",
        "kind=%s queue_wait_ms=%llu core=%d priority=%u heap_free=%lu",
        kind_name, static_cast<unsigned long long>(started - job->queued_ms),
        xPortGetCoreID(), static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
        static_cast<unsigned long>(ESP.getFreeHeap()));
    bool success = false;
    bool apply_network_after_result = false;
    std::string code;
    std::string detail;
    std::string response_json;
    int failure_status = 422;
    if (queue_wait_ms > 30'000U) {
      code = "password_job_queue_timeout";
      failure_status = 503;
      detail =
          "The operation expired in the bounded worker queue before it could "
          "start.";
    } else if (job->kind == PasswordJobKind::Login) {
      failure_status = 401;
      JsonDocument document;
      if (deserializeJson(document, job->body) ||
          !document["password"].is<const char *>()) {
        code = "login_json_invalid";
        detail = "Login body is invalid.";
      } else {
        const std::string password = document["password"].as<const char *>();
        success = config_.hasAdminPassword()
                      ? config_.verifyAdminPassword(password)
                      : config_.verifySetupPassword(password);
        code = success ? "ok" : "login_rejected";
        detail = success ? "Administrator credentials were accepted."
                         : "Administrator credentials were rejected.";
      }
    } else if (job->kind == PasswordJobKind::Setup) {
      const ProvisioningResult result = provisioning_.apply(job->body);
      success = result.ok;
      code = result.code;
      detail = result.detail;
      if (success) {
        apply_network_after_result = true;
        JsonDocument response;
        response["status"] = "setup_applied";
        response["saved"] = true;
        response["verified"] = true;
        response["generation"] = config_.config().config_version;
        response["config_version"] = config_.config().config_version;
        response["network_apply_queued"] = true;
        response["reboot_queued"] = false;
        response["reboot_required"] = false;
        serializeJson(response, response_json);
      }
    } else if (job->kind == PasswordJobKind::ConfigUpdate) {
      const float previous_ct_rating = config_.config().ct_rating_a;
      ConfigValidation result;
      success = config_.updateFromJson(
          job->body, job->dry_run, job->ct_change_acknowledged, false, result);
      code = result.code;
      detail = result.detail;
      if (success) {
        if (!job->dry_run &&
            previous_ct_rating != config_.config().ct_rating_a) {
          coordinator_.enqueueEvent(
              "EVT_CT_RATING_CHANGED", "warning",
              "CT rating changed after explicit installed-hardware "
              "acknowledgement.",
              clock_.utcMs(), config_.identity().boot_id);
        }
        JsonDocument response;
        response["valid"] = true;
        response["saved"] = !job->dry_run;
        response["verified"] = !job->dry_run;
        response["dry_run"] = job->dry_run;
        response["generation"] = config_.config().config_version;
        response["config_version"] = config_.config().config_version;
        response["reboot_required"] = false;
        serializeJson(response, response_json);
      }
    } else if (job->kind == PasswordJobKind::NetworkSettings) {
      success = applyNetworkSettings(job->body, code, detail, response_json);
      apply_network_after_result = success;
    } else if (job->kind == PasswordJobKind::SyncAcknowledgement) {
      JsonDocument document;
      if (deserializeJson(document, job->body) ||
          !document["ack_sequence"].is<std::uint64_t>()) {
        code = "ack_json_invalid";
        failure_status = 400;
        detail = "Acknowledgement body is invalid.";
      } else {
        const std::uint64_t sequence =
            document["ack_sequence"].as<std::uint64_t>();
        const StorageHealth storage = storage_.health();
        const std::uint64_t current = config_.serverAckSequence();
        success =
            sequence >= current && sequence <= storage.newest_sequence &&
            (sequence == current || config_.setServerAckSequence(sequence));
        code = success ? "ok" : "ack_sequence_invalid";
        failure_status = 409;
        detail = success ? "The monotonic acknowledgement was committed."
                         : "Acknowledgement must advance monotonically within "
                           "available history.";
        if (success) {
          JsonDocument response;
          response["status"] = "acknowledged";
          response["saved"] = true;
          response["verified"] = config_.serverAckSequence() == sequence;
          response["ack_sequence"] = sequence;
          success = response["verified"].as<bool>();
          if (!success) {
            code = "ack_persistence_failed";
            detail =
                "The acknowledgement could not be verified after persistence.";
          } else {
            serializeJson(response, response_json);
          }
        }
      }
    } else if (job->kind == PasswordJobKind::Reenrollment) {
      JsonDocument document;
      if (deserializeJson(document, job->body) ||
          !document["enrollment_token"].is<const char *>()) {
        code = "reenrollment_json_invalid";
        detail = "Reenrollment body is invalid.";
      } else {
        const std::string token =
            document["enrollment_token"].as<const char *>();
        success = token.size() >= 32U && token.size() <= 256U &&
                  config_.beginReenrollment(token);
        code = success ? "ok" : "reenrollment_failed";
        detail =
            success
                ? "Existing credentials were atomically revoked and "
                  "reenrollment is pending."
                : "The one-time token could not replace existing credentials.";
        if (success) {
          coordinator_.enqueueEvent(
              "EVT_REENROLLMENT_REQUESTED", "warning",
              "Authorized credential revocation and reenrollment requested.",
              clock_.utcMs(), config_.identity().boot_id);
          JsonDocument response;
          response["status"] = "reenrollment_pending";
          response["saved"] = true;
          response["verified"] = !config_.identity().enrolled;
          success = response["verified"].as<bool>();
          if (!success) {
            code = "reenrollment_persistence_failed";
            detail = "Credential revocation could not be verified after "
                     "persistence.";
          } else {
            serializeJson(response, response_json);
          }
        }
      }
    }
    const std::uint64_t duration = clock_.monotonicMs() - started;
    if (job->kind == PasswordJobKind::Login) {
      if (success) {
        login_failures_.store(0, std::memory_order_relaxed);
        login_allowed_at_ms_.store(0, std::memory_order_release);
      } else {
        const std::uint32_t failures =
            login_failures_.fetch_add(1, std::memory_order_relaxed) + 1U;
        const std::uint32_t exponent = std::min<std::uint32_t>(failures, 8U);
        const std::uint32_t delay_ms = 250U << exponent;
        login_allowed_at_ms_.store(clock_.monotonicMs() + delay_ms,
                                   std::memory_order_release);
        PM_LOG_WARN("AUTH", "LOGIN_REJECTED",
                    "error=PM-AUTH-001 failures=%lu next_allowed_in_ms=%lu "
                    "duration_ms=%llu",
                    static_cast<unsigned long>(failures),
                    static_cast<unsigned long>(delay_ms),
                    static_cast<unsigned long long>(duration));
      }
      login_job_pending_.store(false, std::memory_order_release);
    }
    std::fill(job->body.begin(), job->body.end(), '\0');
    job->body.clear();
    bool result_published = false;
    const std::uint64_t publish_deadline = clock_.monotonicMs() + 2'000U;
    while (!result_published && clock_.monotonicMs() < publish_deadline) {
      if (password_result_mutex_ != nullptr &&
          xSemaphoreTake(password_result_mutex_, pdMS_TO_TICKS(50)) == pdTRUE) {
        for (auto &result : password_results_) {
          if (result.used && result.id == job->id) {
            result.complete = true;
            result.success = success;
            result.code = code;
            result.detail = detail;
            result.response_json = response_json;
            result.failure_status = failure_status;
            result.duration_ms = duration;
            result.expires_ms = clock_.monotonicMs() + 300'000U;
            result_published = true;
            break;
          }
        }
        xSemaphoreGive(password_result_mutex_);
      }
      if (!result_published)
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    if (!result_published) {
      PM_LOG_ERROR(
          "PASSWORD", "JOB_RESULT_PUBLISH_FAILED",
          "error=PM-PASSWORD-005 kind=%s committed=%s retry_budget_ms=2000",
          kind_name, success ? "possibly_true" : "false");
    }
    PM_LOG_INFO("PASSWORD", "JOB_COMPLETE",
                "kind=%s result=%s code=%s duration_ms=%llu over_budget=%s "
                "high_water_bytes=%u heap_free=%lu",
                kind_name, success ? "success" : "failed", code.c_str(),
                static_cast<unsigned long long>(duration),
                duration > 15'000U ? "true" : "false",
                static_cast<unsigned>(uxTaskGetStackHighWaterMark(nullptr)),
                static_cast<unsigned long>(ESP.getFreeHeap()));
    if (apply_network_after_result) {
      // Make the verified result pollable before changing station/AP state.
      // The worker delay is bounded and does not run on async_tcp.
      vTaskDelay(pdMS_TO_TICKS(1500));
      network_.requestConfigurationApply();
      PM_LOG_INFO("NETWORK", "CONFIG_APPLY_DEFERRED",
                  "delay_ms=1500 reason=allow_http_job_ack");
    }
    if (duration > 2'000U) {
      PM_LOG_WARN(
          "PASSWORD", "JOB_SLOW",
          "error=PM-PASSWORD-002 kind=%s duration_ms=%llu budget_ms=15000",
          kind_name, static_cast<unsigned long long>(duration));
    }
    std::fill(job->body.begin(), job->body.end(), '\0');
    delete job;
    job = nullptr;
  }
}

std::string
HttpApi::queuePasswordJob(const PasswordJobKind kind, const std::string &body,
                          const bool dry_run, const bool ct_change_acknowledged,
                          const std::string &creator_session_token) {
  if (password_job_queue_ == nullptr || password_result_mutex_ == nullptr) {
    return {};
  }
  const bool login_reserved =
      kind == PasswordJobKind::Login &&
      !login_job_pending_.exchange(true, std::memory_order_acq_rel);
  if (kind == PasswordJobKind::Login && !login_reserved) {
    PM_LOG_WARN("PASSWORD", "LOGIN_ALREADY_PENDING",
                "error=PM-PASSWORD-007 duplicate_hash_queued=false");
    return {};
  }
  const std::uint64_t now = clock_.monotonicMs();
  const std::string id = crypto::randomHex(16);
  if (xSemaphoreTake(password_result_mutex_, pdMS_TO_TICKS(50)) != pdTRUE) {
    if (login_reserved) {
      login_job_pending_.store(false, std::memory_order_release);
    }
    return {};
  }
  PasswordJobResult *slot = nullptr;
  for (auto &result : password_results_) {
    if (!result.used || result.expires_ms <= now) {
      slot = &result;
      break;
    }
  }
  if (slot == nullptr) {
    // Completed results remain pollable for dropped-response retries, but they
    // must never permanently prevent a fresh bounded operation. Under unusual
    // pressure, evict only the oldest completed result; pending work is never
    // displaced.
    for (auto &result : password_results_) {
      if (result.complete &&
          (slot == nullptr || result.expires_ms < slot->expires_ms)) {
        slot = &result;
      }
    }
    if (slot != nullptr) {
      PM_LOG_WARN("PASSWORD", "RESULT_EVICTED",
                  "error=PM-PASSWORD-006 reason=completed_table_pressure "
                  "result_id=redacted");
    }
  }
  if (slot != nullptr) {
    *slot = {};
    slot->used = true;
    slot->kind = kind;
    slot->id = id;
    slot->expires_ms = now + 300'000U;
    if (!creator_session_token.empty()) {
      slot->creator_session_digest = crypto::sha256(
          reinterpret_cast<const std::uint8_t *>(creator_session_token.data()),
          creator_session_token.size());
      slot->creator_session_bound = true;
    }
  }
  xSemaphoreGive(password_result_mutex_);
  if (slot == nullptr) {
    PM_LOG_WARN("PASSWORD", "RESULT_TABLE_FULL",
                "error=PM-PASSWORD-003 capacity=%u",
                static_cast<unsigned>(password_results_.size()));
    if (login_reserved) {
      login_job_pending_.store(false, std::memory_order_release);
    }
    return {};
  }
  auto *job = new (std::nothrow) PasswordJob{};
  if (job != nullptr) {
    job->kind = kind;
    job->id = id;
    job->body = body;
    job->queued_ms = now;
    job->dry_run = dry_run;
    job->ct_change_acknowledged = ct_change_acknowledged;
  }
  const bool priority_mutation = kind == PasswordJobKind::SyncAcknowledgement ||
                                 kind == PasswordJobKind::Reenrollment;
  const BaseType_t queued =
      job == nullptr
          ? pdFALSE
          : (priority_mutation ? xQueueSendToFront(password_job_queue_, &job, 0)
                               : xQueueSend(password_job_queue_, &job, 0));
  if (job == nullptr || queued != pdTRUE) {
    if (job != nullptr) {
      std::fill(job->body.begin(), job->body.end(), '\0');
    }
    delete job;
    if (login_reserved) {
      login_job_pending_.store(false, std::memory_order_release);
    }
    if (xSemaphoreTake(password_result_mutex_, pdMS_TO_TICKS(50)) == pdTRUE) {
      slot->used = false;
      slot->id.clear();
      xSemaphoreGive(password_result_mutex_);
    }
    PM_LOG_WARN("PASSWORD", "JOB_QUEUE_FULL",
                "error=PM-PASSWORD-004 capacity=%u depth=%lu dropped=true",
                static_cast<unsigned>(kPasswordJobQueueCapacity),
                static_cast<unsigned long>(
                    uxQueueMessagesWaiting(password_job_queue_)));
    return {};
  }
  PM_LOG_INFO(
      "PASSWORD", "JOB_QUEUED",
      "kind=%s queue_depth=%lu capacity=%u priority=%s body=redacted",
      passwordJobKindName(kind),
      static_cast<unsigned long>(uxQueueMessagesWaiting(password_job_queue_)),
      static_cast<unsigned>(kPasswordJobQueueCapacity),
      priority_mutation ? "server_critical" : "fifo");
  return id;
}

bool HttpApi::passwordJobResult(const std::string &id,
                                PasswordJobResult &result, const bool consume,
                                const TickType_t lock_timeout) {
  if (password_result_mutex_ == nullptr ||
      xSemaphoreTake(password_result_mutex_, lock_timeout) != pdTRUE) {
    return false;
  }
  const std::uint64_t now = clock_.monotonicMs();
  bool found = false;
  for (auto &candidate : password_results_) {
    if (candidate.used && candidate.expires_ms <= now) {
      candidate = {};
      continue;
    }
    if (candidate.used && candidate.id == id) {
      result = candidate;
      found = true;
      if (consume && candidate.complete)
        candidate = {};
      break;
    }
  }
  xSemaphoreGive(password_result_mutex_);
  return found;
}

void HttpApi::sendPasswordJobAccepted(AsyncWebServerRequest *request,
                                      const std::string &id,
                                      const bool asynchronous) {
  if (asynchronous) {
    JsonDocument response;
    response["status"] = "queued";
    response["job_id"] = id;
    std::string body;
    serializeJson(response, body);
    sendJson(request, 202, body);
    return;
  }

  const std::string instance = request->url().c_str();
  auto *response = new (std::nothrow) DeferredWorkerResponse(
      [this, id, instance](DeferredHttpResult &output) {
        PasswordJobResult result;
        if (!passwordJobResult(id, result, false, 0) || !result.complete) {
          return false;
        }
        output.status = result.success ? 200 : result.failure_status;
        if (result.success) {
          output.content_type = "application/json";
          output.body = result.response_json.empty()
                            ? "{\"status\":\"completed\",\"saved\":true,"
                              "\"verified\":true}"
                            : result.response_json;
        } else {
          output.content_type = "application/problem+json";
          JsonDocument problem;
          problem["type"] =
              std::string("https://powermonitor.local/problems/") + result.code;
          problem["title"] = result.code;
          problem["status"] = output.status;
          problem["detail"] = result.detail;
          problem["instance"] = instance;
          problem["code"] = result.code;
          serializeJson(problem, output.body);
        }
        diagnostics_.recordHttpStatus(output.status);
        return true;
      },
      30'000U);
  if (response == nullptr) {
    diagnostics_.recordLocalResponseAllocationFailure();
    sendProblem(request, 503, "response_allocation_failed",
                "The deferred response could not be allocated.");
    return;
  }
  request->send(response);
}

void HttpApi::sendHistoryJobAccepted(AsyncWebServerRequest *request,
                                     const std::string &id, const bool ndjson,
                                     const bool asynchronous) {
  if (asynchronous) {
    JsonDocument document;
    document["status"] = "queued";
    document["job_id"] = id;
    document["result_path"] = "/api/v1/history-jobs";
    std::string body;
    serializeJson(document, body);
    sendJson(request, 202, body);
    return;
  }

  const std::string instance = request->url().c_str();
  auto *response = new (std::nothrow) DeferredWorkerResponse(
      [this, id, ndjson, instance](DeferredHttpResult &output) {
        HistoryPage page;
        bool complete = false;
        if (!coordinator_.historyResult(id, page, complete, false, 0) ||
            !complete) {
          return false;
        }
        buildPagePayload(page, ndjson, instance, output.status,
                         output.content_type, output.body);
        diagnostics_.recordHttpStatus(output.status);
        return true;
      },
      5'000U);
  if (response == nullptr) {
    diagnostics_.recordLocalResponseAllocationFailure();
    sendProblem(request, 503, "response_allocation_failed",
                "The deferred response could not be allocated.");
    return;
  }
  request->send(response);
}

bool HttpApi::applyNetworkSettings(const std::string &body, std::string &code,
                                   std::string &detail,
                                   std::string &response_json) {
  JsonDocument document;
  if (deserializeJson(document, body) ||
      !document["wifi_ssid"].is<const char *>() ||
      !document["static_network_enabled"].is<bool>() ||
      !document["static_ip"].is<const char *>() ||
      !document["static_gateway"].is<const char *>() ||
      !document["static_subnet"].is<const char *>() ||
      !document["static_dns"].is<const char *>() ||
      !document["server_url"].is<const char *>() ||
      !document["tls_trust_action"].is<const char *>() ||
      !document["connection_mode"].is<const char *>()) {
    code = "network_settings_json_invalid";
    detail =
        "Network settings are missing required fields or use invalid types.";
    return false;
  }

  const std::string mode = document["connection_mode"].as<const char *>();
  if (mode != "pull" && mode != "push" && mode != "hybrid") {
    code = "connection_mode_invalid";
    detail = "Connection mode must be pull, push, or hybrid.";
    return false;
  }
  if (mode != "push") {
    code = "connection_mode_unsupported";
    detail =
        "This firmware supports outbound push synchronization only. Pull and "
        "hybrid remain pm-protocol/1.0.0 values but are rejected until the "
        "device exposes a mutually authenticated HTTPS listener.";
    return false;
  }
  const bool replace_wifi_password = !document["wifi_password"].isNull();
  if (replace_wifi_password && !document["wifi_password"].is<const char *>()) {
    code = "wifi_password_invalid";
    detail = "The replacement Wi-Fi password must be a string.";
    return false;
  }

  RuntimeConfig candidate = config_.config();
  candidate.wifi_ssid = document["wifi_ssid"].as<const char *>();
  candidate.static_network_enabled =
      document["static_network_enabled"].as<bool>();
  candidate.static_ip = document["static_ip"].as<const char *>();
  candidate.static_gateway = document["static_gateway"].as<const char *>();
  candidate.static_subnet = document["static_subnet"].as<const char *>();
  candidate.static_dns = document["static_dns"].as<const char *>();
  candidate.server_url = document["server_url"].as<const char *>();
  candidate.connection_mode = ConnectionMode::Push;

  const std::string trust_action =
      document["tls_trust_action"].as<const char *>();
  if (trust_action == "keep") {
    if (!document["server_ca_pem"].isNull() ||
        !document["server_fingerprint"].isNull()) {
      code = "tls_trust_action_invalid";
      detail = "Keep trust must not include replacement trust material.";
      return false;
    }
    if (candidate.server_ca_pem.empty()) {
      code = "server_ca_required";
      detail =
          "Fingerprint-only TLS is not supported safely; replace trust with "
          "a CA PEM.";
      return false;
    }
  } else if (trust_action == "replace_ca") {
    if (!document["server_ca_pem"].is<const char *>() ||
        !document["server_fingerprint"].isNull()) {
      code = "server_ca_required";
      detail = "Replacing TLS trust with a CA requires only a PEM certificate.";
      return false;
    }
    candidate.server_ca_pem = document["server_ca_pem"].as<const char *>();
    candidate.server_fingerprint.clear();
  } else if (trust_action == "replace_fingerprint") {
    code = "server_ca_required";
    detail = "Fingerprint-only TLS is rejected because secure CA and hostname "
             "validation are mandatory.";
    return false;
  } else {
    code = "tls_trust_action_invalid";
    detail = "TLS trust action must keep or replace the configured trust.";
    return false;
  }

  const std::string ota_trust_action = document["ota_trust_action"] | "keep";
  if (ota_trust_action == "keep") {
    if (!document["ota_signing_public_key_pem"].isNull() ||
        !document["ota_signing_key_id"].isNull()) {
      code = "ota_trust_action_invalid";
      detail = "Keeping OTA trust must not include replacement key material.";
      return false;
    }
  } else if (ota_trust_action == "replace") {
    if (!document["ota_signing_public_key_pem"].is<const char *>() ||
        !document["ota_signing_key_id"].is<const char *>()) {
      code = "ota_trust_pair_incomplete";
      detail = "Replacing OTA trust requires the verified Ed25519 public-key "
               "PEM and its server signing-key identifier.";
      return false;
    }
    candidate.ota_signing_public_key_pem =
        document["ota_signing_public_key_pem"].as<const char *>();
    candidate.ota_signing_key_id =
        document["ota_signing_key_id"].as<const char *>();
  } else {
    code = "ota_trust_action_invalid";
    detail = "OTA trust action must keep or replace the configured key.";
    return false;
  }

  const std::string wifi_password =
      replace_wifi_password ? document["wifi_password"].as<const char *>()
                            : std::string{};
  ConfigValidation result;
  if (!config_.updateNetworkSettings(candidate, wifi_password,
                                     replace_wifi_password, result)) {
    code = result.code;
    detail = result.detail;
    return false;
  }
  coordinator_.enqueueEvent(
      "EVT_NETWORK_SETTINGS_CHANGED", "warning",
      "Authorized Wi-Fi or central server settings changed; live network "
      "reconfiguration requested.",
      clock_.utcMs(), config_.identity().boot_id);
  JsonDocument response;
  response["status"] = "network_settings_applied";
  response["saved"] = true;
  response["verified"] = true;
  response["generation"] = config_.config().config_version;
  response["config_version"] = config_.config().config_version;
  response["network_apply_queued"] = true;
  response["reboot_queued"] = false;
  response["reboot_required"] = false;
  serializeJson(response, response_json);
  code = "ok";
  detail = "Network and server settings were committed and verified.";
  return true;
}

void HttpApi::registerReadRoutes() {
  server_.on(
      "/api/v1/auth/password-jobs", HTTP_GET,
      [this](AsyncWebServerRequest *request) {
        network_.touchSetupActivity();
        // Browser GET requests do not consistently carry Origin. A supplied
        // Origin must still be exact; the login POST itself always requires
        // it before an opaque job identifier is issued.
        const bool same_origin =
            !request->hasHeader("Origin") || sameOrigin(request);
        if (!request->hasParam("job_id")) {
          sendProblem(
              request, 400, "password_job_request_invalid",
              "A password or configuration job identifier is required.");
          return;
        }
        PasswordJobResult result;
        const std::string id = request->getParam("job_id")->value().c_str();
        if (!passwordJobResult(id, result, false, pdMS_TO_TICKS(50))) {
          sendProblem(request, 404, "password_job_not_found",
                      "The password job is unknown or expired.");
          return;
        }
        if (result.kind == PasswordJobKind::Login) {
          if (!same_origin) {
            sendProblem(request, 403, "job_not_authorized",
                        "Login job polling must remain same-origin.");
            return;
          }
          const std::string session_token = cookieValue(request, "pm_session");
          const crypto::Key32 session_digest = crypto::sha256(
              reinterpret_cast<const std::uint8_t *>(session_token.data()),
              session_token.size());
          if (!result.creator_session_bound || session_token.empty() ||
              sessions_.validate(session_token, clock_.monotonicMs()) !=
                  LocalSessionResult::Ok ||
              !constantTimeDigestEqual(session_digest,
                                       result.creator_session_digest)) {
            sendProblem(request, 403, "job_not_authorized",
                        "Login job polling is restricted to the nonprivileged "
                        "session that requested password verification.");
            return;
          }
        } else if (result.kind == PasswordJobKind::SyncAcknowledgement) {
          if (!authorize(request, "", false, false))
            return;
        } else if (!localSession(request, false)) {
          // A server-to-device HMAC client normally omits the browser Origin
          // header, so same-origin classification alone must never bypass HMAC.
          if (!authorize(request, "", false))
            return;
        }
        if (!result.complete) {
          sendJson(request, 202, "{\"status\":\"pending\"}");
          return;
        }
        if (result.kind == PasswordJobKind::Login) {
          if (!result.success) {
            sendProblem(request, 401, "login_rejected",
                        "Administrator credentials were rejected.");
            return;
          }
          PM_LOG_INFO("AUTH", "LOGIN_ACCEPTED",
                      "duration_ms=%llu session=creating",
                      static_cast<unsigned long long>(result.duration_ms));
          passwordJobResult(id, result, true, pdMS_TO_TICKS(50));
          createLocalSession(request, true);
          return;
        }
        if (!result.success) {
          sendProblem(request, result.failure_status, result.code.c_str(),
                      result.detail.c_str());
          return;
        }
        sendJson(
            request, 200,
            result.response_json.empty()
                ? "{\"status\":\"completed\",\"saved\":true,\"verified\":true}"
                : result.response_json);
      });
  server_.on(
      "/api/v1/ui/status", HTTP_GET,
      [this](AsyncWebServerRequest *request) {
        if (!authorize(request, "", false))
          return;
        diagnostics_.recordUiRequest(UiRequestKind::Status);
        const NetworkStatus network = network_.status();
        const StorageHealth storage = storage_.health();
        const MeterMetrics meter = meter_.metrics();
        const SyncMetrics sync = diagnostics_.syncMetrics();
        const SensorStatusConfig status_config = config_.sensorStatusConfig();
        MeasurementSnapshot latest;
        const bool has_latest = diagnostics_.latest(latest) && latest.valid;
        const std::uint64_t acknowledgement = config_.serverAckSequence();
        const std::uint64_t backlog =
            storage.newest_syncable_sequence >= acknowledgement
                ? storage.newest_syncable_sequence - acknowledgement
                : 0U;
        const std::uint32_t free_internal =
            heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        const std::uint32_t largest_internal =
            heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL |
                                             MALLOC_CAP_8BIT);
        JsonDocument document;
        document["schema_version"] = 1;
        document["server_now"] = clock_.utcIso8601();
        JsonObject device = document["device"].to<JsonObject>();
        device["friendly_name"] = status_config.friendly_name;
        device["firmware"] = version::FIRMWARE;
        device["git_commit"] = version::GIT_COMMIT;
        device["build_timestamp"] = version::BUILD_TIMESTAMP;
        device["platformio_environment"] = version::PLATFORMIO_ENVIRONMENT;
        device["uptime_seconds"] = clock_.monotonicMs() / 1000U;
        JsonObject web_assets = device["web_assets"].to<JsonObject>();
        const ui::Asset *index_asset = ui::findAsset("/index.html");
        const ui::Asset *script_asset = ui::findAsset("/assets/app.js");
        const ui::Asset *style_asset = ui::findAsset("/assets/style.css");
        web_assets["index_html_sha256"] =
            index_asset == nullptr ? "unavailable" : index_asset->sha256;
        web_assets["app_js_sha256"] =
            script_asset == nullptr ? "unavailable" : script_asset->sha256;
        web_assets["style_css_sha256"] =
            style_asset == nullptr ? "unavailable" : style_asset->sha256;
        JsonObject reading = document["reading"].to<JsonObject>();
        if (has_latest) {
          reading["measured_at_utc_ms"] = latest.utc_ms;
          reading["power_w"] = latest.active_power_w;
          reading["voltage_v"] = latest.voltage_v;
          reading["current_a"] = latest.current_a;
          reading["frequency_hz"] = latest.frequency_hz;
          reading["power_factor"] = latest.power_factor;
        } else {
          reading["measured_at_utc_ms"] = nullptr;
          reading["power_w"] = nullptr;
          reading["voltage_v"] = nullptr;
          reading["current_a"] = nullptr;
          reading["frequency_hz"] = nullptr;
          reading["power_factor"] = nullptr;
        }
        JsonObject health = document["health"].to<JsonObject>();
        health["wifi"] = network.station_connected ? "connected" : "offline";
        health["rssi_dbm"] = network.rssi_dbm;
        health["ip_address"] = network.ip_address;
        health["server"] =
            network.server_authenticated
                ? "connected"
                : (network.server_reachable ? "unauthenticated" : "offline");
        health["storage"] = storage.writable ? "writable" : "degraded";
        health["meter"] =
            meter.last_error == MeterError::None ? "healthy" : "degraded";
        health["low_memory"] =
            free_internal < kMinimumLightUiInternalHeapBytes ||
            largest_internal < kMinimumHeavyUiLargestBlockBytes;
        JsonObject sync_json = document["sync"].to<JsonObject>();
        if (sync.last_heartbeat_utc_ms == 0U) {
          sync_json["last_success_utc_ms"] = nullptr;
        } else {
          sync_json["last_success_utc_ms"] = sync.last_heartbeat_utc_ms;
        }
        sync_json["newest_sequence"] = storage.newest_sequence;
        sync_json["acknowledged_sequence"] = acknowledgement;
        sync_json["backlog"] = backlog;
        sync_json["last_safe_error"] = sync.last_error;
        std::string body;
        serializeJson(document, body);
        sendJson(request, 200, body);
      });
  server_.on(
      "/api/v1/ui/diagnostics", HTTP_GET,
      [this](AsyncWebServerRequest *request) {
        if (!authorize(request, "", false))
          return;
        diagnostics_.recordUiRequest(UiRequestKind::Diagnostics);
        const StorageHealth storage = storage_.health();
        const SyncMetrics sync = diagnostics_.syncMetrics();
        const HttpMetrics http = diagnostics_.httpMetrics();
        const std::uint64_t acknowledgement = config_.serverAckSequence();
        JsonDocument document;
        document["schema_version"] = 1;
        JsonObject memory = document["memory"].to<JsonObject>();
        memory["free_heap_bytes"] = ESP.getFreeHeap();
        memory["minimum_free_heap_bytes"] = ESP.getMinFreeHeap();
        memory["free_internal_heap_bytes"] =
            heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        memory["minimum_free_internal_heap_bytes"] =
            heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL |
                                            MALLOC_CAP_8BIT);
        memory["largest_internal_block_bytes"] =
            heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL |
                                             MALLOC_CAP_8BIT);
        memory["free_psram_bytes"] = ESP.getFreePsram();
        memory["largest_psram_block_bytes"] =
            heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM |
                                             MALLOC_CAP_8BIT);
        memory["heap_integrity_ok"] = heap_caps_check_integrity_all(false);
        const MemoryPressureMetrics pressure =
            diagnostics_.memoryPressureMetrics();
        memory["pressure_state"] = memoryPressureStateName(pressure.state);
        memory["pressure_state_since_ms"] = pressure.state_since_ms;
        memory["pressure_entry_count"] = pressure.entry_count;
        memory["pressure_recovery_count"] = pressure.recovery_count;
        memory["pressure_transition_count"] = pressure.transition_count;
        memory["cumulative_pressure_ms"] = pressure.cumulative_pressure_ms;
        memory["longest_pressure_episode_ms"] =
            pressure.longest_pressure_episode_ms;
        memory["lowest_free_internal_bytes"] =
            pressure.lowest_free_internal_bytes;
        memory["lowest_largest_internal_block_bytes"] =
            pressure.lowest_largest_internal_block_bytes;
        JsonObject tasks = document["tasks"].to<JsonObject>();
        tasks["server_sync_stack_bytes"] = sync.stack_allocated_bytes;
        tasks["server_sync_high_water_bytes"] = sync.stack_high_water_bytes;
        tasks["server_sync_margin_percent"] = sync.stack_margin_percent;
        tasks["network_margin_percent"] = nullptr;
        JsonArray task_table = tasks["table"].to<JsonArray>();
        for (const auto &task : diagnostics_.taskMetrics()) {
          if (task.name.empty()) {
            continue;
          }
          JsonObject row = task_table.add<JsonObject>();
          row["name"] = task.name;
          row["core"] = task.core;
          row["priority"] = task.priority;
          row["configured_stack_bytes"] = task.configured_stack_bytes;
          row["high_water_bytes"] = task.high_water_bytes;
          row["margin_percent"] = task.margin_percent;
          row["running"] = task.running;
          row["watchdog"] = task.watchdog;
          if (task.name == "NetworkTask") {
            tasks["network_margin_percent"] = task.margin_percent;
          }
        }
        JsonObject sync_json = document["sync"].to<JsonObject>();
        sync_json["heartbeat_successes"] = sync.heartbeat_successes;
        sync_json["heartbeat_failures"] = sync.heartbeat_failures;
        sync_json["batch_successes"] = sync.batch_successes;
        sync_json["batch_failures"] = sync.batch_failures;
        sync_json["local_resource_deferrals"] =
            sync.local_resource_deferrals;
        sync_json["tls_requests_admitted"] = sync.tls_requests_admitted;
        sync_json["tls_requests_rejected_heap"] =
            sync.tls_requests_rejected_heap;
        sync_json["tls_requests_rejected_stack"] =
            sync.tls_requests_rejected_stack;
        sync_json["acknowledged_sequence"] = acknowledgement;
        sync_json["newest_sequence"] = storage.newest_sequence;
        sync_json["backlog"] =
            storage.newest_syncable_sequence >= acknowledgement
                ? storage.newest_syncable_sequence - acknowledgement
                : 0U;
        sync_json["last_safe_error"] = sync.last_error;
        JsonObject local_http = document["local_http"].to<JsonObject>();
        local_http["ui_status_requests"] = http.ui_status_requests;
        local_http["ui_setup_requests"] = http.ui_setup_requests;
        local_http["ui_diagnostics_requests"] =
            http.ui_diagnostics_requests;
        local_http["ui_heavy_requests_deferred"] =
            http.ui_heavy_requests_deferred;
        local_http["peak_requests"] = http.peak_local_http_requests;
        local_http["browser_session_rejections"] =
            http.browser_session_rejections;
        local_http["malformed_auth_header_rejections"] =
            http.malformed_auth_header_rejections;
        local_http["browser_rate_limited"] = http.browser_rate_limited;
        local_http["server_hmac_rate_limited"] =
            http.server_hmac_rate_limited;
        local_http["browser_requests_accepted"] =
            http.browser_requests_accepted;
        local_http["browser_requests_session_expired"] =
            http.browser_requests_session_expired;
        local_http["browser_requests_session_invalid"] =
            http.browser_requests_session_invalid;
        local_http["browser_requests_csrf_rejected"] =
            http.browser_requests_csrf_rejected;
        local_http["server_hmac_requests_accepted"] =
            http.server_hmac_requests_accepted;
        local_http["server_hmac_headers_incomplete"] =
            http.server_hmac_headers_incomplete;
        local_http["server_hmac_protocol_mismatch"] =
            http.server_hmac_protocol_mismatch;
        local_http["server_hmac_device_mismatch"] =
            http.server_hmac_device_mismatch;
        local_http["server_hmac_timestamp_rejected"] =
            http.server_hmac_timestamp_rejected;
        local_http["server_hmac_nonce_rejected"] =
            http.server_hmac_nonce_rejected;
        local_http["server_hmac_body_hash_rejected"] =
            http.server_hmac_body_hash_rejected;
        local_http["server_hmac_signature_rejected"] =
            http.server_hmac_signature_rejected;
        const SessionManager::Metrics session_metrics =
            sessions_.metrics(clock_.monotonicMs());
        JsonObject local_sessions =
            document["local_sessions"].to<JsonObject>();
        local_sessions["capacity"] = session_metrics.capacity;
        local_sessions["active"] = session_metrics.active;
        local_sessions["peak_active"] = session_metrics.peak_active;
        local_sessions["created"] = session_metrics.created;
        local_sessions["reused"] = session_metrics.reused;
        local_sessions["refreshed"] = session_metrics.refreshed;
        local_sessions["expired"] = session_metrics.expired;
        local_sessions["invalid"] = session_metrics.invalid;
        local_sessions["revoked"] = session_metrics.revoked;
        local_sessions["capacity_rejections"] =
            session_metrics.capacity_rejections;
        const WifiDisconnectSnapshot disconnects =
            network_.wifiDisconnectEvents();
        JsonObject wifi_disconnects =
            document["wifi_disconnects"].to<JsonObject>();
        wifi_disconnects["total"] = disconnects.total;
        wifi_disconnects["description"] =
            "Recent RAM tail; CRC-protected transitions are also archived on microSD.";
        JsonArray disconnect_events =
            wifi_disconnects["events"].to<JsonArray>();
        for (std::size_t index = 0; index < disconnects.count; ++index) {
          const WifiDisconnectEvent &event = disconnects.events[index];
          const diag::ReasonInfo reason =
              diag::wifiDisconnectReason(event.reason);
          JsonObject row = disconnect_events.add<JsonObject>();
          row["event"] = wifiEventKindName(event.kind);
          row["transition_number"] = event.transition_number;
          row["monotonic_ms"] = event.monotonic_ms;
          row["reason"] = event.reason == 0U ? "none" : reason.name;
          row["reason_code"] = event.reason;
          row["rssi_dbm"] = event.rssi_dbm;
          row["disconnect_number"] = event.reconnect_count;
          row["free_internal_heap_bytes"] =
              event.free_internal_heap_bytes;
          row["largest_internal_block_bytes"] =
              event.largest_internal_block_bytes;
          row["channel"] = event.channel;
          row["bssid"] = diag::maskMac(std::string(event.bssid.data()));
          row["ip_address"] = event.ip_address.data();
          row["gateway"] = event.gateway.data();
          row["dns"] = event.dns.data();
          row["dhcp_duration_ms"] = event.dhcp_duration_ms;
        }
        std::string body;
        serializeJson(document, body);
        sendJson(request, 200, body);
      });
  server_.on(
      "/api/v1/diagnostics/disconnect-flight-recorder", HTTP_GET,
      [this](AsyncWebServerRequest *request) {
        if (!authorize(request, "", false))
          return;
        const WifiDisconnectSnapshot disconnects =
            network_.wifiDisconnectEvents();
        const SyncMetrics sync = diagnostics_.syncMetrics();
        const HttpMetrics http = diagnostics_.httpMetrics();
        const SessionManager::Metrics sessions =
            sessions_.metrics(clock_.monotonicMs());
        JsonDocument document;
        document["schema_version"] = 1;
        document["captured_at"] = clock_.utcIso8601();
        document["wifi_transition_total"] = disconnects.total;
        document["persistence"] =
            "CRC-protected EVT_WIFI_TRANSITION records are retained in the rotating microSD event archive.";
        JsonArray events = document["wifi_disconnects"].to<JsonArray>();
        for (std::size_t index = 0; index < disconnects.count; ++index) {
          const WifiDisconnectEvent &event = disconnects.events[index];
          const diag::ReasonInfo reason =
              diag::wifiDisconnectReason(event.reason);
          JsonObject row = events.add<JsonObject>();
          row["event"] = wifiEventKindName(event.kind);
          row["transition_number"] = event.transition_number;
          row["monotonic_ms"] = event.monotonic_ms;
          row["reason"] = event.reason == 0U ? "none" : reason.name;
          row["reason_code"] = event.reason;
          row["rssi_dbm"] = event.rssi_dbm;
          row["free_internal_heap_bytes"] =
              event.free_internal_heap_bytes;
          row["largest_internal_block_bytes"] =
              event.largest_internal_block_bytes;
          row["channel"] = event.channel;
          row["bssid"] = diag::maskMac(std::string(event.bssid.data()));
          row["ip_address"] = event.ip_address.data();
          row["gateway"] = event.gateway.data();
          row["dns"] = event.dns.data();
          row["dhcp_duration_ms"] = event.dhcp_duration_ms;
        }
        JsonObject synchronization = document["synchronization"].to<JsonObject>();
        synchronization["heartbeat_successes"] = sync.heartbeat_successes;
        synchronization["heartbeat_failures"] = sync.heartbeat_failures;
        synchronization["batch_successes"] = sync.batch_successes;
        synchronization["batch_failures"] = sync.batch_failures;
        synchronization["tls_requests_rejected_heap"] =
            sync.tls_requests_rejected_heap;
        JsonObject authentication = document["authentication"].to<JsonObject>();
        authentication["server_signature_rejections"] =
            http.rejected_signatures;
        authentication["browser_session_rejections"] =
            http.browser_session_rejections;
        authentication["browser_requests_accepted"] =
            http.browser_requests_accepted;
        authentication["browser_requests_session_expired"] =
            http.browser_requests_session_expired;
        authentication["browser_requests_session_invalid"] =
            http.browser_requests_session_invalid;
        authentication["browser_requests_csrf_rejected"] =
            http.browser_requests_csrf_rejected;
        authentication["server_hmac_requests_accepted"] =
            http.server_hmac_requests_accepted;
        authentication["server_hmac_headers_incomplete"] =
            http.server_hmac_headers_incomplete;
        authentication["server_hmac_protocol_mismatch"] =
            http.server_hmac_protocol_mismatch;
        authentication["server_hmac_device_mismatch"] =
            http.server_hmac_device_mismatch;
        authentication["server_hmac_timestamp_rejected"] =
            http.server_hmac_timestamp_rejected;
        authentication["server_hmac_nonce_rejected"] =
            http.server_hmac_nonce_rejected;
        authentication["server_hmac_body_hash_rejected"] =
            http.server_hmac_body_hash_rejected;
        authentication["server_hmac_signature_rejected"] =
            http.server_hmac_signature_rejected;
        authentication["local_sessions_active"] = sessions.active;
        authentication["local_sessions_capacity"] = sessions.capacity;
        std::string body;
        serializeJson(document, body);
        AsyncWebServerResponse *response = request->beginResponse(
            200, "application/json", body.c_str());
        response->addHeader(
            "Content-Disposition",
            "attachment; filename=power-monitor-disconnect-flight-recorder.json");
        response->addHeader("Cache-Control", "no-store");
        response->addHeader("Connection", "close", false);
        diagnostics_.recordHttpStatus(200);
        request->send(response);
      });
  server_.on("/api/v1/diagnostics/recent-errors", HTTP_GET,
             [this](AsyncWebServerRequest *request) {
               if (!authorize(request, "", false))
                 return;
               if (!beginHeavyLocalOperation(request))
                 return;
               const std::string body =
                   diag::SerialLogger::instance().recentErrorsJson();
               endHeavyLocalOperation();
               sendJson(request, 200, body);
             });
  server_.on(
      "/api/v1/health", HTTP_GET, [this](AsyncWebServerRequest *request) {
        if (!authorize(request, "", false))
          return;
        sendJson(request, 200,
                 diagnostics_.healthJson(config_, network_.status(), clock_,
                                         storage_.health(), meter_.metrics()));
      });
  server_.on(
      "/api/local/health", HTTP_GET, [this](AsyncWebServerRequest *request) {
        // This deliberately avoids authentication, server traffic, history
        // reads, and long worker waits. It is a local liveness probe that must
        // remain useful while DNS, TLS, or the central server is unavailable.
        const NetworkStatus network = network_.status();
        const StorageHealth storage = storage_.health();
        const MeterMetrics meter = meter_.metrics();
        const SyncMetrics sync = diagnostics_.syncMetrics();
        JsonDocument document;
        document["schema_version"] = 1;
        document["protocol"] = version::PROTOCOL;
        document["uptime_seconds"] = clock_.monotonicMs() / 1000U;
        document["wifi_connected"] = network.station_connected;
        document["time_trusted"] = clock_.synchronized();
        document["storage_writable"] = storage.writable;
        document["meter_healthy"] = meter.last_error == MeterError::None;
        document["sync_in_progress"] = sync.sync_in_progress;
        document["sync_pending"] = sync.sync_pending;
        document["heartbeat_successes"] = sync.heartbeat_successes;
        document["heartbeat_failures"] = sync.heartbeat_failures;
        document["reading_batch_successes"] = sync.batch_successes;
        document["reading_batch_failures"] = sync.batch_failures;
        document["last_sync_utc_ms"] = sync.last_sync_utc_ms;
        document["server_ack_sequence"] = config_.serverAckSequence();
        document["oldest_stored_sequence"] = storage.oldest_sequence;
        document["oldest_syncable_sequence"] =
            storage.oldest_syncable_sequence;
        document["newest_stored_sequence"] = storage.newest_sequence;
        document["newest_syncable_sequence"] =
            storage.newest_syncable_sequence;
        document["durable_backlog_count"] =
            storage.newest_syncable_sequence >= config_.serverAckSequence()
                ? storage.newest_syncable_sequence -
                      config_.serverAckSequence()
                : 0;
        document["durable_reading_backlog"] =
            sync.durable_reading_backlog;
        document["last_sync_error"] = sync.last_error;
        document["stack_high_water_bytes"] = sync.stack_high_water_bytes;
        document["stack_margin_percent"] = sync.stack_margin_percent;
        document["free_heap_bytes"] = ESP.getFreeHeap();
        document["free_internal_heap_bytes"] =
            heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        document["largest_internal_block_bytes"] =
            heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL |
                                             MALLOC_CAP_8BIT);
        std::string body;
        serializeJson(document, body);
        sendJson(request, 200, body);
        if (diag::SerialLogger::instance().allow("webui_health", 30'000U)) {
          PM_LOG_INFO("WEB", "WEBUI_HEALTH",
                      "status=200 sync_in_progress=%s heap_free=%lu",
                      sync.sync_in_progress ? "true" : "false",
                      static_cast<unsigned long>(ESP.getFreeHeap()));
        }
      });
  server_.on("/api/v1/info", HTTP_GET, [this](AsyncWebServerRequest *request) {
    if (!authorize(request, "", false))
      return;
    JsonDocument document;
    document["schema_version"] = 1;
    document["product"] = build::PRODUCT_NAME;
    document["protocol"] = version::PROTOCOL;
    document["api_version"] = build::API_VERSION;
    document["firmware_version"] = version::FIRMWARE;
    document["git_commit"] = version::GIT_COMMIT;
    document["build_timestamp"] = version::BUILD_TIMESTAMP;
    document["hardware_target"] = version::HARDWARE_TARGET;
    document["hardware_id"] = config_.identity().hardware_id;
    document["local_instance_id"] = config_.identity().local_instance_id;
    document["device_id"] = config_.identity().device_id;
    document["boot_id"] = config_.identity().boot_id;
    JsonObject capabilities = document["capabilities"].to<JsonObject>();
    capabilities["pzem_uart"] = "9600-8N1";
    capabilities["micro_sd_authoritative"] = true;
    capabilities["connection_modes"] = "push";
    capabilities["signed_ota"] = true;
    capabilities["monitoring_only"] = true;
    std::string body;
    serializeJson(document, body);
    sendJson(request, 200, body);
  });
  server_.on("/api/v1/live", HTTP_GET, [this](AsyncWebServerRequest *request) {
    if (!authorize(request, "", false))
      return;
    const std::string body =
        diagnostics_.liveJson(config_, clock_, meter_.methodName());
    if (body.empty()) {
      sendProblem(request, 503, "live_unavailable",
                  "No meter snapshot has completed yet.");
      return;
    }
    sendJson(request, 200, body);
  });
  server_.on(
      "/api/v1/history-jobs", HTTP_GET, [this](AsyncWebServerRequest *request) {
        if (!authorize(request, "", false))
          return;
        if (!request->hasParam("job_id")) {
          sendProblem(request, 400, "history_job_request_invalid",
                      "A history job identifier is required.");
          return;
        }
        const std::string id = request->getParam("job_id")->value().c_str();
        HistoryPage page;
        bool complete = false;
        if (!coordinator_.historyResult(id, page, complete, true)) {
          sendProblem(request, 404, "history_job_not_found",
                      "The history job is unknown or expired.");
          return;
        }
        if (!complete) {
          sendJson(request, 202, "{\"status\":\"pending\"}");
          return;
        }
        const bool ndjson = request->hasHeader("Accept") &&
                            request->getHeader("Accept")->value().indexOf(
                                "application/x-ndjson") >= 0;
        sendPage(request, page, ndjson);
      });
  server_.on(
      "/api/v1/readings", HTTP_GET, [this](AsyncWebServerRequest *request) {
        if (!authorize(request, "", false))
          return;
        if (!beginHeavyLocalOperation(request))
          return;
        endHeavyLocalOperation();
        if (clock_.monotonicMs() < history_allowed_at_ms_) {
          sendProblem(request, 429, "history_rate_limited",
                      "Wait before issuing another storage history request.",
                      false, true);
          return;
        }
        history_allowed_at_ms_ = clock_.monotonicMs() + 250U;
        const std::string job_id =
            coordinator_.queueHistory(parseHistoryQuery(request));
        if (job_id.empty()) {
          sendProblem(request, 503, "history_worker_busy",
                      "The bounded storage history queue is busy.");
          return;
        }
        const bool ndjson = request->hasHeader("Accept") &&
                            request->getHeader("Accept")->value().indexOf(
                                "application/x-ndjson") >= 0;
        sendHistoryJobAccepted(request, job_id, ndjson, prefersAsync(request));
      });
  server_.on(
      "/api/v1/events", HTTP_GET, [this](AsyncWebServerRequest *request) {
        if (!authorize(request, "", false))
          return;
        if (!beginHeavyLocalOperation(request))
          return;
        endHeavyLocalOperation();
        if (clock_.monotonicMs() < history_allowed_at_ms_) {
          sendProblem(request, 429, "history_rate_limited",
                      "Wait before issuing another storage history request.",
                      false, true);
          return;
        }
        history_allowed_at_ms_ = clock_.monotonicMs() + 250U;
        const std::string job_id =
            coordinator_.queueHistory(parseHistoryQuery(request), true);
        if (job_id.empty()) {
          sendProblem(request, 503, "history_worker_busy",
                      "The bounded storage history queue is busy.");
          return;
        }
        sendHistoryJobAccepted(request, job_id, false, prefersAsync(request));
      });
  server_.on("/api/v1/storage", HTTP_GET,
             [this](AsyncWebServerRequest *request) {
               if (!authorize(request, "", false))
                 return;
               const StorageHealth value = storage_.health();
               JsonDocument document;
               document["schema_version"] = 1;
               document["present"] = value.present;
               document["mounted"] = value.mounted;
               document["writable"] = value.writable;
               document["prepared_for_removal"] = value.prepared_for_removal;
               document["card_type"] = value.card_type;
               document["filesystem"] = value.filesystem;
               document["capacity_bytes"] = value.capacity_bytes;
               document["used_bytes"] = value.used_bytes;
               document["free_bytes"] = value.free_bytes;
               document["current_file"] = value.current_file;
               document["last_write_utc_ms"] = value.last_write_utc_ms;
               document["last_write_latency_ms"] = value.last_write_latency_ms;
               document["index_healthy"] = value.index_healthy;
               document["repair_count"] = value.repair_count;
               document["oldest_sequence"] = value.oldest_sequence;
               document["newest_sequence"] = value.newest_sequence;
               document["newest_syncable_sequence"] =
                   value.newest_syncable_sequence;
               document["server_ack_sequence"] = config_.serverAckSequence();
               document["event_ack_sequence"] =
                   config_.serverEventAckSequence();
               document["unsynchronized_estimate"] =
                   value.newest_syncable_sequence >=
                           config_.serverAckSequence()
                       ? value.newest_syncable_sequence -
                             config_.serverAckSequence()
                       : 0;
               document["spi_hz"] = value.spi_hz;
               document["pressure_state"] = value.pressure_state;
               document["pressure_reason"] = value.pressure_reason;
               document["retention_mode"] =
                   retentionModeName(config_.measurementRuntimeConfig()
                                         .storage_policy.mode);
               document["retention_days"] = config_.measurementRuntimeConfig()
                                                  .storage_policy.retention_days;
               document["minimum_local_history_days"] =
                   config_.measurementRuntimeConfig()
                       .storage_policy.minimum_local_history_days;
               document["segment_count"] = value.segment_count;
               document["open_segment_count"] = value.open_segment_count;
               document["closed_segment_count"] = value.closed_segment_count;
               document["eligible_segment_count"] =
                   value.eligible_segment_count;
               document["protected_segment_count"] =
                   value.protected_segment_count;
               document["untrusted_segment_count"] =
                   value.untrusted_segment_count;
               document["event_segment_count"] = value.event_segment_count;
               document["export_count"] = value.export_count;
               document["repair_artifact_count"] =
                   value.repair_artifact_count;
               document["temporary_artifact_count"] =
                   value.temporary_artifact_count;
               document["cleanup_journal_state"] =
                   value.cleanup_recovery_required ? "recovery_required"
                                                   : "clear";
               document["last_cleanup_result"] = value.last_cleanup_result;
               document["last_cleanup_utc_ms"] = value.last_cleanup_utc_ms;
               document["last_cleanup_reclaimed_bytes"] =
                   value.last_cleanup_reclaimed_bytes;
               document["write_failures"] = value.write_failures;
               document["read_failures"] = value.read_failures;
               document["estimated_growth_bytes_per_day"] =
                   value.growth_bytes_per_day;
               document["estimated_days_remaining"] =
                   value.estimated_days_remaining;
               document["dropped_interval_count"] =
                   value.dropped_interval_count;
               document["first_dropped_interval_utc_ms"] =
                   value.first_dropped_interval_utc_ms;
               document["last_dropped_interval_utc_ms"] =
                   value.last_dropped_interval_utc_ms;
               document["last_error"] = value.last_error;
               std::string body;
               serializeJson(document, body);
               sendJson(request, 200, body);
             });
  server_.on(
      "/api/v1/sync-status", HTTP_GET, [this](AsyncWebServerRequest *request) {
        if (!authorize(request, "", false))
          return;
        const StorageHealth storage = storage_.health();
        const SyncMetrics sync = diagnostics_.syncMetrics();
        JsonDocument document;
        document["schema_version"] = 1;
        document["mode"] = connectionModeName(config_.config().connection_mode);
        document["server_ack_sequence"] = config_.serverAckSequence();
        document["newest_sequence"] = storage.newest_sequence;
        document["newest_syncable_sequence"] =
            storage.newest_syncable_sequence;
        document["backlog_estimate"] =
            storage.newest_syncable_sequence >= config_.serverAckSequence()
                ? storage.newest_syncable_sequence -
                      config_.serverAckSequence()
                : 0;
        document["last_heartbeat_utc_ms"] = sync.last_heartbeat_utc_ms;
        document["last_sync_utc_ms"] = sync.last_sync_utc_ms;
        document["last_error"] = sync.last_error;
        std::string body;
        serializeJson(document, body);
        sendJson(request, 200, body);
      });
  server_.on("/api/v1/config", HTTP_GET,
             [this](AsyncWebServerRequest *request) {
               if (!authorize(request, "", false))
                 return;
               diagnostics_.recordUiRequest(UiRequestKind::Setup);
               sendJson(request, 200, config_.redactedJson());
             });
  server_.on(
      "/api/v1/metrics", HTTP_GET, [this](AsyncWebServerRequest *request) {
        if (!authorize(request, "", false))
          return;
        if (!beginHeavyLocalOperation(request))
          return;
        const std::string body =
            diagnostics_.metricsJson(storage_.health(), meter_.metrics());
        endHeavyLocalOperation();
        sendJson(request, 200, body);
      });
  server_.on("/api/v1/ota/status", HTTP_GET,
             [this](AsyncWebServerRequest *request) {
               if (!authorize(request, "", false))
                 return;
               const OtaStatus status = ota_.status();
               JsonDocument document;
               document["schema_version"] = 1;
               document["in_progress"] = status.in_progress;
               document["pending_reboot"] = status.pending_reboot;
               document["bytes_received"] = status.bytes_received;
               document["image_size"] = status.image_size;
               document["target_version"] = status.target_version;
               document["last_result"] = status.last_result;
               document["last_error"] = status.last_error;
               std::string body;
               serializeJson(document, body);
               sendJson(request, 200, body);
             });
  server_.on("/api/v1/diagnostics/bundle", HTTP_GET,
             [this](AsyncWebServerRequest *request) {
               if (!authorize(request, "", false))
                 return;
               if (!beginHeavyLocalOperation(request))
                 return;
               const SessionManager::Metrics session_metrics =
                   sessions_.metrics(clock_.monotonicMs());
               const LocalSessionDiagnostics session_diagnostics{
                   session_metrics.capacity,
                   session_metrics.active,
                   session_metrics.peak_active,
                   session_metrics.created,
                   session_metrics.reused,
                   session_metrics.refreshed,
                   session_metrics.expired,
                   session_metrics.invalid,
                   session_metrics.revoked,
                   session_metrics.capacity_rejections};
               const std::string body = diagnostics_.redactedBundle(
                   config_, network_.status(), clock_, storage_.health(),
                   meter_.metrics(), session_diagnostics,
                   network_.wifiDisconnectEvents());
               endHeavyLocalOperation();
               AsyncWebServerResponse *response = request->beginResponse(
                   200, "application/json", body.c_str());
               response->addHeader(
                   "Content-Disposition",
                   "attachment; filename=power-monitor-diagnostics.json");
               response->addHeader("Cache-Control", "no-store");
               response->addHeader("Connection", "close", false);
               request->send(response);
             });
}

void HttpApi::registerMutationRoutes() {
  registerBodyRoute("/api/v1/auth/session", HTTP_POST,
                    [this](AsyncWebServerRequest *request) {
                      network_.touchSetupActivity();
                      takeBody(request);
                      if (!sameOrigin(request)) {
                        sendProblem(
                            request, 403, "origin_rejected",
                            "Cross-origin session creation is not allowed.");
                        return;
                      }
                      createLocalSession(request, false);
                    });
  registerBodyRoute(
      "/api/v1/auth/login", HTTP_POST, [this](AsyncWebServerRequest *request) {
        network_.touchSetupActivity();
        const std::string body = takeBody(request);
        if (!sameOrigin(request)) {
          sendProblem(request, 403, "origin_rejected",
                      "Cross-origin login is not allowed.");
          return;
        }
        if (!localSession(request, true)) {
          sendProblem(request, 401, "login_session_required",
                      "Open a nonprivileged local session before requesting "
                      "administrator verification.");
          return;
        }
        if (clock_.monotonicMs() <
            login_allowed_at_ms_.load(std::memory_order_acquire)) {
          sendProblem(request, 429, "login_throttled",
                      "Wait before another login attempt.", false, true);
          return;
        }
        JsonDocument document;
        if (body.size() > 1024 || deserializeJson(document, body) ||
            !document["password"].is<const char *>()) {
          sendProblem(request, 400, "login_json_invalid",
                      "Login body is invalid.");
          return;
        }
        const std::string creator_session = cookieValue(request, "pm_session");
        const std::string job_id = queuePasswordJob(
            PasswordJobKind::Login, body, false, false, creator_session);
        if (job_id.empty()) {
          sendProblem(request, 503, "password_worker_busy",
                      "The bounded password worker queue is busy.");
          return;
        }
        JsonDocument response_document;
        response_document["status"] = "queued";
        response_document["job_id"] = job_id;
        std::string response;
        serializeJson(response_document, response);
        sendJson(request, 202, response);
      });
  registerBodyRoute(
      "/api/v1/auth/logout", HTTP_POST, [this](AsyncWebServerRequest *request) {
        const std::string body = takeBody(request);
        if (!authorize(request, body, true))
          return;
        sessions_.invalidate(cookieValue(request, "pm_session"),
                             clock_.monotonicMs());
        coordinator_.enqueueEvent("EVT_LOCAL_SESSION_REVOKED", "info",
                                  "scope=requesting_session_only",
                                  clock_.utcMs(),
                                  config_.identity().boot_id);
        AsyncWebServerResponse *response = request->beginResponse(204);
        response->addHeader(
            "Set-Cookie",
            "pm_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
        response->addHeader(
            "Set-Cookie", "pm_csrf=; SameSite=Strict; Path=/; Max-Age=0",
            false);
        response->addHeader("Connection", "close", false);
        request->send(response);
      });
  registerBodyRoute(
      "/api/v1/config", HTTP_PUT, [this](AsyncWebServerRequest *request) {
        const std::string body = takeBody(request);
        if (!authorize(request, body, true, true, true))
          return;
        const bool dry_run = request->hasParam("dry_run") &&
                             request->getParam("dry_run")->value() == "true";
        const bool ct_ack =
            request->hasHeader("X-PM-CT-Change-Acknowledged") &&
            request->getHeader("X-PM-CT-Change-Acknowledged")->value() ==
                "true";
        const std::string job_id = queuePasswordJob(
            PasswordJobKind::ConfigUpdate, body, dry_run, ct_ack);
        if (job_id.empty()) {
          sendProblem(request, 503, "configuration_worker_busy",
                      "The bounded configuration worker queue is busy.");
          return;
        }
        sendPasswordJobAccepted(request, job_id, prefersAsync(request));
      });
  registerBodyRoute(
      "/api/v1/network-settings", HTTP_PUT,
      [this](AsyncWebServerRequest *request) {
        const std::string body = takeBody(request);
        if (!authorize(request, body, true, true, true))
          return;
        const std::string job_id =
            queuePasswordJob(PasswordJobKind::NetworkSettings, body);
        if (job_id.empty()) {
          sendProblem(request, 503, "configuration_worker_busy",
                      "The bounded configuration worker queue is busy.");
          return;
        }
        sendPasswordJobAccepted(request, job_id, prefersAsync(request));
      });
  registerBodyRoute(
      "/api/v1/setup/apply", HTTP_POST, [this](AsyncWebServerRequest *request) {
        network_.touchSetupActivity();
        const std::string body = takeBody(request);
        if (!sameOrigin(request) || !localSession(request, true) ||
            (config_.hasAdminPassword() && config_.hasWifiCredentials())) {
          sendProblem(request, 403, "setup_not_authorized",
                      "First-run setup requires the setup session and closes "
                      "after administrator creation.");
          return;
        }
        const std::string job_id =
            queuePasswordJob(PasswordJobKind::Setup, body);
        if (job_id.empty()) {
          sendProblem(request, 503, "password_worker_busy",
                      "The bounded password worker queue is busy.");
          return;
        }
        sendPasswordJobAccepted(request, job_id, prefersAsync(request));
      });
  registerBodyRoute(
      "/api/v1/sync/ack", HTTP_POST, [this](AsyncWebServerRequest *request) {
        const std::string body = takeBody(request);
        if (!authorize(request, body, true, false))
          return;
        JsonDocument document;
        if (deserializeJson(document, body)) {
          sendProblem(request, 400, "ack_json_invalid",
                      "Acknowledgement body is invalid.");
          return;
        }
        const bool has_ack = document["ack_sequence"].is<std::uint64_t>();
        const bool has_contiguous =
            document["highest_contiguous_sequence"].is<std::uint64_t>();
        if (has_ack == has_contiguous) {
          sendProblem(request, 400, "ack_json_invalid",
                      "Provide exactly one acknowledgement sequence field.");
          return;
        }
        JsonDocument normalized;
        normalized["ack_sequence"] =
            has_ack
                ? document["ack_sequence"].as<std::uint64_t>()
                : document["highest_contiguous_sequence"].as<std::uint64_t>();
        std::string normalized_body;
        serializeJson(normalized, normalized_body);
        const std::string job_id = queuePasswordJob(
            PasswordJobKind::SyncAcknowledgement, normalized_body);
        if (job_id.empty()) {
          sendProblem(request, 503, "configuration_worker_busy",
                      "The bounded persistence worker queue is busy.");
          return;
        }
        sendPasswordJobAccepted(request, job_id, prefersAsync(request));
      });
  registerBodyRoute(
      "/api/v1/enrollment/reenroll", HTTP_POST,
      [this](AsyncWebServerRequest *request) {
        const std::string body = takeBody(request);
        const bool local_request = localSession(request, true, true);
        if (!authorize(request, body, true, true, true))
          return;
        if (!request->hasHeader("X-PM-Action-Token") ||
            request->getHeader("X-PM-Action-Token")->value() != "REENROLL") {
          sendProblem(
              request, 403, "action_confirmation_required",
              "The exact short-lived reenrollment confirmation is required.");
          return;
        }
        JsonDocument document;
        if (deserializeJson(document, body)) {
          sendProblem(request, 400, "reenrollment_json_invalid",
                      "Reenrollment body is invalid.");
          return;
        }
        if (!document["enrollment_token"].is<const char *>()) {
          sendProblem(request, 400, "reenrollment_json_invalid",
                      "Reenrollment token is missing or invalid.");
          return;
        }
        const std::string token =
            document["enrollment_token"].as<const char *>();
        if (token.size() < 32U || token.size() > 256U) {
          sendProblem(request, 422, "enrollment_token_invalid",
                      "Enrollment tokens must contain 32 through 256 "
                      "characters.");
          return;
        }
        if (prefersAsync(request) && !local_request) {
          sendProblem(
              request, 409, "async_reenrollment_requires_local_session",
              "HMAC reenrollment completes on its original deferred response; "
              "only a local session may poll after credential revocation.");
          return;
        }
        const std::string job_id =
            queuePasswordJob(PasswordJobKind::Reenrollment, body);
        if (job_id.empty()) {
          sendProblem(request, 503, "configuration_worker_busy",
                      "The bounded persistence worker queue is busy.");
          return;
        }
        sendPasswordJobAccepted(request, job_id, prefersAsync(request));
      });
  registerAction("/api/v1/actions/test-pzem", MaintenanceAction::TestPzem);
  registerAction("/api/v1/actions/test-sd", MaintenanceAction::TestSd);
  registerAction("/api/v1/actions/remount-sd", MaintenanceAction::RemountSd);
  registerAction("/api/v1/actions/rebuild-index",
                 MaintenanceAction::RebuildIndex);
  registerAction("/api/v1/actions/prepare-card-removal",
                 MaintenanceAction::PrepareCardRemoval);
  registerAction("/api/v1/actions/test-dns", MaintenanceAction::TestDns);
  registerAction("/api/v1/actions/test-ntp", MaintenanceAction::TestNtp);
  registerAction("/api/v1/actions/test-server-tls",
                 MaintenanceAction::TestServerTls);
  registerAction("/api/v1/actions/test-heartbeat",
                 MaintenanceAction::TestHeartbeat);
  registerAction("/api/v1/actions/reboot", MaintenanceAction::Reboot, "REBOOT");
  registerAction("/api/v1/actions/network-reset",
                 MaintenanceAction::NetworkReset, "RESET NETWORK", true);
  registerAction("/api/v1/actions/factory-reset",
                 MaintenanceAction::FactoryReset, "FACTORY RESET", true);
  registerAction("/api/v1/actions/rollback-ota", MaintenanceAction::RollbackOta,
                 "ROLLBACK OTA", true);
  registerBodyRoute("/api/v1/ota/apply", HTTP_POST,
                    [this](AsyncWebServerRequest *request) {
                      const std::string body = takeBody(request);
                      if (!authorize(request, body, true, true, true))
                        return;
                      JsonDocument document;
                      if (deserializeJson(document, body)) {
                        sendProblem(request, 400, "ota_json_invalid",
                                    "OTA action body is invalid.");
                        return;
                      }
                      const std::string url = document["manifest_url"] | "";
                      if (url.rfind("https://", 0) != 0 ||
                          !queueMaintenance(MaintenanceAction::ApplyOta, url)) {
                        sendProblem(request, 422, "ota_request_invalid",
                                    "A bounded HTTPS manifest URL is required "
                                    "and the action queue must have capacity.");
                        return;
                      }
                      sendJson(request, 202, "{\"status\":\"queued\"}");
                    });
}

void HttpApi::registerAction(const char *path, const MaintenanceAction action,
                             const char *confirmation,
                             const bool require_elevated_local) {
  registerBodyRoute(
      path, HTTP_POST,
      [this, action, confirmation,
       require_elevated_local](AsyncWebServerRequest *request) {
        const std::string body = takeBody(request);
        if (!authorize(request, body, true, true, require_elevated_local))
          return;
        if (confirmation != nullptr &&
            (!request->hasHeader("X-PM-Action-Token") ||
             request->getHeader("X-PM-Action-Token")->value() !=
                 confirmation)) {
          sendProblem(
              request, 403, "action_confirmation_required",
              "The exact short-lived local action confirmation is required.");
          return;
        }
        if (!queueMaintenance(action)) {
          sendProblem(request, 429, "action_queue_full",
                      "The bounded maintenance queue is full.", false, true);
          return;
        }
        sendJson(request, 202, "{\"status\":\"queued\"}");
      });
}

void HttpApi::registerBodyRoute(const char *path, const WebRequestMethod method,
                                ArRequestHandlerFunction handler) {
  PM_LOG_DEBUG("WEB", "ROUTE_REGISTERED", "path=%s method_mask=%u", path,
               static_cast<unsigned>(method));
  server_.on(
      path, method, std::move(handler), nullptr,
      [](AsyncWebServerRequest *request, std::uint8_t *data,
         const std::size_t length, const std::size_t index,
         const std::size_t total) {
        if (index == 0) {
          request->_tempObject = new (std::nothrow) BodyBuffer{};
          auto *buffer = static_cast<BodyBuffer *>(request->_tempObject);
          if (buffer != nullptr) {
            request->onDisconnect([request]() {
              auto *abandoned = static_cast<BodyBuffer *>(request->_tempObject);
              request->_tempObject = nullptr;
              delete abandoned;
            });
          }
          if (buffer != nullptr && total <= build::MAX_JSON_BODY) {
            buffer->body.reserve(total);
          }
        }
        auto *buffer = static_cast<BodyBuffer *>(request->_tempObject);
        if (buffer == nullptr)
          return;
        if (total > build::MAX_JSON_BODY ||
            buffer->body.size() + length > build::MAX_JSON_BODY) {
          buffer->overflow = true;
          if (diag::SerialLogger::instance().allow("http_body_overflow",
                                                   10'000U)) {
            PM_LOG_WARN("HTTP", "BODY_REJECTED",
                        "error=PM-HTTP-002 maximum_bytes=%u body=redacted",
                        static_cast<unsigned>(build::MAX_JSON_BODY));
          }
          return;
        }
        buffer->body.append(reinterpret_cast<const char *>(data), length);
      });
}

std::string HttpApi::takeBody(AsyncWebServerRequest *request) const {
  auto *buffer = static_cast<BodyBuffer *>(request->_tempObject);
  request->_tempObject = nullptr;
  if (buffer == nullptr)
    return {};
  std::string body = buffer->overflow ? std::string{} : std::move(buffer->body);
  delete buffer;
  return body;
}

RequestAuthMode
HttpApi::classifyAuthMode(AsyncWebServerRequest *request) const {
  static constexpr std::array<const char *, 6> hmac_headers = {
      "X-PM-Protocol",       "X-PM-Device-ID", "X-PM-Timestamp",
      "X-PM-Nonce",          "X-PM-Content-SHA256",
      "X-PM-Signature",
  };
  std::size_t hmac_header_count = 0U;
  for (const char *name : hmac_headers) {
    hmac_header_count += request->hasHeader(name) ? 1U : 0U;
  }
  if (hmac_header_count == hmac_headers.size()) {
    return RequestAuthMode::ServerToDeviceHmac;
  }
  if (hmac_header_count != 0U) {
    return RequestAuthMode::MalformedMixedAuthentication;
  }
  if (!cookieValue(request, "pm_session").empty()) {
    return RequestAuthMode::LocalBrowserSession;
  }
  return RequestAuthMode::Unauthenticated;
}

bool HttpApi::authorize(AsyncWebServerRequest *request, const std::string &body,
                        const bool mutation, const bool allow_local_session,
                        const bool require_elevated_local) {
  if (network_.status().setup_ap_active) {
    network_.touchSetupActivity();
  }
  const std::uint64_t now = clock_.monotonicMs();
  const RequestAuthMode mode = classifyAuthMode(request);
  PM_LOG_DEBUG("AUTH", "AUTH_MODE_CLASSIFIED",
               "route=%s method=%s mode=%s cookie_present=%s",
               request->url().c_str(), request->methodToString(),
               requestAuthModeName(mode),
               cookieValue(request, "pm_session").empty() ? "false" : "true");
  std::uint64_t *window_started = &hmac_api_window_started_ms_;
  std::uint16_t *requests_in_window = &hmac_api_requests_in_window_;
  const bool browser_mode = mode == RequestAuthMode::LocalBrowserSession;
  if (browser_mode) {
    window_started = &browser_api_window_started_ms_;
    requests_in_window = &browser_api_requests_in_window_;
  }
  if (*window_started == 0 || now - *window_started >= 1000U) {
    *window_started = now;
    *requests_in_window = 0;
  }
  if (*requests_in_window >= 60U) {
    PM_LOG_WARN("AUTH", "API_RATE_LIMITED",
                "error=PM-AUTH-002 class=%s window_ms=1000 limit=60 route=%s",
                browser_mode ? "browser" : "server_hmac",
                request->url().c_str());
    diagnostics_.recordAuthRateLimit(browser_mode);
    sendProblem(
        request, 429, "api_rate_limited",
        "The authenticated API request rate exceeded the bounded limit.", false,
        true);
    return false;
  }
  ++(*requests_in_window);
  const bool origin_present = request->hasHeader("Origin");
  if (origin_present && !sameOrigin(request)) {
    PM_LOG_WARN("AUTH", "ORIGIN_REJECTED",
                "error=PM-AUTH-003 route=%s method=%s", request->url().c_str(),
                request->methodToString());
    sendProblem(request, 403, "origin_rejected",
                "Cross-origin API access is not allowed.");
    return false;
  }

  if (mode == RequestAuthMode::MalformedMixedAuthentication) {
    PM_LOG_WARN("AUTH", "AUTHENTICATION_HEADERS_INCOMPLETE",
                "error=PM-AUTH-008 route=%s method=%s",
                request->url().c_str(), request->methodToString());
    diagnostics_.recordMalformedAuthHeaderRejection();
    diagnostics_.recordServerHmac(ServerHmacMetric::HeadersIncomplete);
    if (diag::SerialLogger::instance().allow("flight_partial_hmac", 10'000U)) {
      coordinator_.enqueueEvent(
          "EVT_AUTH_HEADERS_INCOMPLETE", "warning",
          std::string("route=") + request->url().c_str() +
              " method=" + request->methodToString() +
              " credential_material=redacted",
          clock_.utcMs(), config_.identity().boot_id);
    }
    sendProblem(request, 400, "authentication_headers_incomplete",
                "Server HMAC authentication headers must be supplied as one "
                "complete set. Browser sessions must not send a partial set.");
    return false;
  }

  if (mode == RequestAuthMode::LocalBrowserSession) {
    if (!allow_local_session) {
      sendProblem(request, 401, "server_hmac_required",
                  "This route requires a complete server-to-device HMAC "
                  "request and does not accept a browser session.");
      return false;
    }
    if (mutation && !origin_present) {
      PM_LOG_WARN("AUTH", "ORIGIN_REQUIRED",
                  "error=PM-AUTH-006 route=%s method=%s",
                  request->url().c_str(), request->methodToString());
      sendProblem(request, 403, "origin_required",
                  "Mutating browser requests must include the exact local "
                  "Origin header.");
      return false;
    }
    const LocalSessionResult session_result =
        localSessionResult(request, mutation, require_elevated_local);
    if (session_result != LocalSessionResult::Ok) {
      const bool forbidden =
          session_result == LocalSessionResult::CsrfRejected ||
          session_result == LocalSessionResult::ElevationRequired;
      PM_LOG_WARN("AUTH", "LOCAL_SESSION_REJECTED",
                  "error=PM-AUTH-009 route=%s method=%s reason=%s",
                  request->url().c_str(), request->methodToString(),
                  localSessionResultCode(session_result));
      const char *detail =
          session_result == LocalSessionResult::ElevationRequired
              ? "Administrator verification is required for this "
                "security-sensitive operation."
          : session_result == LocalSessionResult::CsrfRejected
              ? "The browser CSRF value is missing, expired, or invalid."
          : session_result == LocalSessionResult::Expired
              ? "The local browser session expired and must be renewed."
              : "The local browser session is invalid and must be renewed.";
      diagnostics_.recordBrowserSessionRejection();
      if (session_result == LocalSessionResult::Expired) {
        diagnostics_.recordBrowserAuth(BrowserAuthMetric::SessionExpired);
      } else if (session_result == LocalSessionResult::CsrfRejected) {
        diagnostics_.recordBrowserAuth(BrowserAuthMetric::CsrfRejected);
      } else {
        diagnostics_.recordBrowserAuth(BrowserAuthMetric::SessionInvalid);
      }
      PM_LOG_INFO("AUTH", "BROWSER_HMAC_FALLBACK_PREVENTED",
                  "route=%s method=%s local_result=%s hmac_attempted=false",
                  request->url().c_str(), request->methodToString(),
                  localSessionResultCode(session_result));
      if (diag::SerialLogger::instance().allow("flight_local_session_rejected",
                                               10'000U)) {
        const std::string detail =
            std::string("route=") + request->url().c_str() +
            " method=" + request->methodToString() +
            " auth_mode=local_browser_session result=" +
            localSessionResultCode(session_result) +
            " hmac_attempted=false";
        coordinator_.enqueueEvent("EVT_LOCAL_SESSION_REJECTED", "warning",
                                  detail, clock_.utcMs(),
                                  config_.identity().boot_id);
      }
      if (session_result == LocalSessionResult::Expired ||
          session_result == LocalSessionResult::Invalid) {
        sendLocalSessionProblem(request, 401,
                                localSessionResultCode(session_result), detail);
      } else {
        sendProblem(request, forbidden ? 403 : 401,
                    localSessionResultCode(session_result), detail);
      }
      return false;
    }
    PM_LOG_DEBUG("AUTH", "LOCAL_SESSION_ACCEPTED",
                 "route=%s method=%s mutation=%s elevated_required=%s",
                 request->url().c_str(), request->methodToString(),
                 mutation ? "true" : "false",
                  require_elevated_local ? "true" : "false");
    diagnostics_.recordBrowserAuth(BrowserAuthMetric::Accepted);
    return true;
  }

  if (mode == RequestAuthMode::Unauthenticated) {
    PM_LOG_WARN("AUTH", "AUTHENTICATION_REQUIRED",
                "error=PM-AUTH-004 route=%s class=unauthenticated",
                request->url().c_str());
    sendProblem(request, 401, "authentication_required",
                "A local browser session or a complete enrolled-server HMAC "
                "request is required.");
    return false;
  }

  crypto::Key32 outbound{};
  crypto::Key32 inbound{};
  if (!config_.directionalKeys(outbound, inbound)) {
    PM_LOG_WARN(
        "AUTH", "AUTHENTICATION_REQUIRED",
        "error=PM-AUTH-004 route=%s local_session=false enrolled_keys=false",
        request->url().c_str());
    sendProblem(request, 401, "authentication_required",
                "The sensor is not enrolled with server HMAC keys.");
    return false;
  }
  AuthHeaders headers;
  auto header = [request](const char *name) -> std::string {
    return request->hasHeader(name) ? request->getHeader(name)->value().c_str()
                                    : "";
  };
  headers.protocol = header("X-PM-Protocol");
  headers.device_id = header("X-PM-Device-ID");
  headers.timestamp = header("X-PM-Timestamp");
  headers.nonce = header("X-PM-Nonce");
  headers.content_sha256 = header("X-PM-Content-SHA256");
  headers.signature = header("X-PM-Signature");
  std::vector<std::pair<std::string, std::string>> query;
  for (std::size_t index = 0; index < request->params(); ++index) {
    const AsyncWebParameter *parameter = request->getParam(index);
    if (!parameter->isPost() && !parameter->isFile()) {
      query.emplace_back(parameter->name().c_str(), parameter->value().c_str());
    }
  }
  const AuthResult result = authenticator_.verify(
      request->methodToString(), request->url().c_str(), query,
      reinterpret_cast<const std::uint8_t *>(body.data()), body.size(), headers,
      config_.identity().device_id, inbound, std::time(nullptr),
      clock_.synchronized());
  if (result != AuthResult::Ok) {
    switch (result) {
    case AuthResult::MissingHeader:
      diagnostics_.recordServerHmac(ServerHmacMetric::HeadersIncomplete);
      break;
    case AuthResult::ProtocolMismatch:
      diagnostics_.recordServerHmac(ServerHmacMetric::ProtocolMismatch);
      break;
    case AuthResult::DeviceMismatch:
      diagnostics_.recordServerHmac(ServerHmacMetric::DeviceMismatch);
      break;
    case AuthResult::TimestampInvalid:
    case AuthResult::TimestampOutsideWindow:
      diagnostics_.recordServerHmac(ServerHmacMetric::TimestampRejected);
      break;
    case AuthResult::NonceInvalid:
    case AuthResult::NonceReplayed:
    case AuthResult::NonceCapacityExceeded:
      diagnostics_.recordServerHmac(ServerHmacMetric::NonceRejected);
      break;
    case AuthResult::BodyHashMismatch:
      diagnostics_.recordServerHmac(ServerHmacMetric::BodyHashRejected);
      break;
    case AuthResult::SignatureMismatch:
      diagnostics_.recordServerHmac(ServerHmacMetric::SignatureRejected);
      break;
    case AuthResult::Ok:
      break;
    }
    PM_LOG_WARN(
        "AUTH", "SERVER_SIGNATURE_REJECTED",
        "error=PM-AUTH-005 route=%s method=%s reason=%s signature=redacted",
        request->url().c_str(), request->methodToString(),
        authResultCode(result));
    if (diag::SerialLogger::instance().allow("flight_server_hmac_rejected",
                                             10'000U)) {
      const std::string detail =
          std::string("route=") + request->url().c_str() +
          " method=" + request->methodToString() + " result=" +
          authResultCode(result) + " credential_material=redacted";
      coordinator_.enqueueEvent("EVT_SERVER_HMAC_REJECTED", "warning",
                                detail, clock_.utcMs(),
                                config_.identity().boot_id);
    }
    const int status =
        result == AuthResult::ProtocolMismatch
            ? 409
            : (result == AuthResult::NonceCapacityExceeded ? 429 : 401);
    sendProblem(request, status, authResultCode(result),
                result == AuthResult::NonceCapacityExceeded
                    ? "The bounded signed-request replay window is full; "
                      "retry after an accepted nonce expires."
                    : "Server-to-device signature verification failed.",
                true, result == AuthResult::NonceCapacityExceeded);
    return false;
  }
  PM_LOG_INFO("AUTH", "SERVER_SIGNATURE_ACCEPTED",
              "route=%s method=%s nonce=redacted", request->url().c_str(),
              request->methodToString());
  diagnostics_.recordServerHmac(ServerHmacMetric::Accepted);
  return true;
}

LocalSessionResult
HttpApi::localSessionResult(AsyncWebServerRequest *request,
                            const bool mutation,
                            const bool require_elevated) const {
  const std::string token = cookieValue(request, "pm_session");
  if (!mutation) {
    return sessions_.validate(token, clock_.monotonicMs(), require_elevated);
  }
  const std::string csrf =
      request->hasHeader("X-PM-CSRF")
          ? request->getHeader("X-PM-CSRF")->value().c_str()
          : "";
  return sessions_.validateMutation(token, csrf, clock_.monotonicMs(),
                                    require_elevated);
}

bool HttpApi::localSession(AsyncWebServerRequest *request, const bool mutation,
                           const bool require_elevated) const {
  return localSessionResult(request, mutation, require_elevated) ==
         LocalSessionResult::Ok;
}

bool HttpApi::sameOrigin(AsyncWebServerRequest *request) const {
  if (!request->hasHeader("Origin"))
    return false;
  const String origin = request->getHeader("Origin")->value();
  const String host = request->host();
  return origin == "http://" + host || origin == "https://" + host;
}

void HttpApi::createLocalSession(AsyncWebServerRequest *request,
                                 const bool elevated) {
  const std::string current_token = cookieValue(request, "pm_session");
  const SessionManager::Session session =
      elevated
          ? sessions_.elevate(current_token, clock_.monotonicMs(),
                              config_.config().local_session_timeout_seconds,
                              300U)
          : sessions_.open(current_token, clock_.monotonicMs(),
                           config_.config().local_session_timeout_seconds);
  if (session.capacity_reached) {
    coordinator_.enqueueEvent("EVT_LOCAL_SESSION_CAPACITY_REACHED", "warning",
                              "capacity=6 active_sessions_preserved=true",
                              clock_.utcMs(), config_.identity().boot_id);
    sendProblem(request, 503, "local_session_capacity_reached",
                "All bounded browser-session slots are active. Sign out one "
                "client or wait for a session to expire.");
    return;
  }
  if (session.token.empty() || session.csrf.empty()) {
    sendProblem(request, 401, "local_session_invalid",
                "The local browser session could not be refreshed.");
    return;
  }
  JsonDocument document;
  document["csrf"] = session.csrf;
  document["expires_in_seconds"] =
      config_.config().local_session_timeout_seconds;
  document["setup_required"] = !config_.hasAdminPassword();
  document["elevated"] = session.elevated;
  std::string body;
  serializeJson(document, body);
  AsyncWebServerResponse *response =
      request->beginResponse(200, "application/json", body.c_str());
  const std::string cookie =
      "pm_session=" + session.token +
      "; HttpOnly; SameSite=Strict; Path=/; Max-Age=" +
      std::to_string(config_.config().local_session_timeout_seconds);
  response->addHeader("Set-Cookie", cookie.c_str());
  const std::string csrf_cookie =
      "pm_csrf=" + session.csrf + "; SameSite=Strict; Path=/; Max-Age=" +
      std::to_string(config_.config().local_session_timeout_seconds);
  // ESPAsyncWebServer replaces an existing header unless replaceExisting is
  // explicitly disabled. Keep both cookies: losing pm_session makes the
  // successful session response unusable, while losing pm_csrf breaks every
  // authenticated mutation.
  response->addHeader("Set-Cookie", csrf_cookie.c_str(), false);
  response->addHeader("Cache-Control", "no-store");
  response->addHeader("Connection", "close", false);
  diagnostics_.recordHttpStatus(200);
  request->send(response);
  PM_LOG_INFO(
      "AUTH", session.refreshed ? "SESSION_REFRESHED" : "SESSION_CREATED",
      "expires_in_seconds=%lu setup_required=%s elevated=%s reused=%s "
      "token=redacted csrf=redacted",
      static_cast<unsigned long>(
          config_.config().local_session_timeout_seconds),
      config_.hasAdminPassword() ? "false" : "true",
      session.elevated ? "true" : "false",
      session.reused ? "true" : "false");
  coordinator_.enqueueEvent(
      session.refreshed ? "EVT_LOCAL_SESSION_REFRESHED"
                        : "EVT_LOCAL_SESSION_CREATED",
      "info",
      std::string("elevated=") + (session.elevated ? "true" : "false") +
          " reused=" + (session.reused ? "true" : "false") +
          " token=redacted csrf=redacted",
      clock_.utcMs(), config_.identity().boot_id);
}

std::string HttpApi::cookieValue(AsyncWebServerRequest *request,
                                 const char *name) const {
  if (!request->hasHeader("Cookie"))
    return {};
  const std::string cookies = request->getHeader("Cookie")->value().c_str();
  const std::string prefix = std::string(name) + "=";
  std::size_t position = cookies.find(prefix);
  while (position != std::string::npos && position > 0 &&
         cookies[position - 1] != ' ' && cookies[position - 1] != ';') {
    position = cookies.find(prefix, position + prefix.size());
  }
  if (position == std::string::npos)
    return {};
  const std::size_t start = position + prefix.size();
  const std::size_t end = cookies.find(';', start);
  return cookies.substr(start, end - start);
}

void HttpApi::sendJson(AsyncWebServerRequest *request, const int status,
                       const std::string &body, const char *content_type) {
  AsyncWebServerResponse *response =
      request->beginResponse(status, content_type, body.c_str());
  response->addHeader("Cache-Control", "no-store");
  response->addHeader("X-Content-Type-Options", "nosniff");
  response->addHeader("Connection", "close", false);
  diagnostics_.recordHttpStatus(status);
  request->send(response);
  PM_LOG_DEBUG("HTTP", "LOCAL_RESPONSE",
               "method=%s route=%s status=%d category=%s response_bytes=%u",
               request->methodToString(), request->url().c_str(), status,
               diag::httpStatusCategory(status),
               static_cast<unsigned>(body.size()));
}

void HttpApi::sendProblem(AsyncWebServerRequest *request, const int status,
                          const char *code, const char *detail,
                          const bool rejected_signature,
                          const bool rate_limited) {
  JsonDocument document;
  document["type"] = std::string("https://powermonitor.local/problems/") + code;
  document["title"] = code;
  document["status"] = status;
  document["detail"] = detail;
  document["instance"] = request->url();
  document["code"] = code;
  std::string body;
  serializeJson(document, body);
  diagnostics_.recordHttpStatus(status, rejected_signature, rate_limited);
  AsyncWebServerResponse *response =
      request->beginResponse(status, "application/problem+json", body.c_str());
  response->addHeader("Cache-Control", "no-store");
  response->addHeader("Connection", "close", false);
  request->send(response);
  PM_LOG_WARN("HTTP", "LOCAL_PROBLEM",
              "method=%s route=%s status=%d category=%s error=%s "
              "signature_rejected=%s rate_limited=%s",
              request->methodToString(), request->url().c_str(), status,
              diag::httpStatusCategory(status), code,
              rejected_signature ? "true" : "false",
              rate_limited ? "true" : "false");
}

void HttpApi::sendLocalSessionProblem(AsyncWebServerRequest *request,
                                      const int status, const char *code,
                                      const char *detail) {
  JsonDocument document;
  document["type"] = std::string("https://powermonitor.local/problems/") + code;
  document["title"] = code;
  document["status"] = status;
  document["detail"] = detail;
  document["instance"] = request->url();
  document["code"] = code;
  std::string body;
  serializeJson(document, body);
  diagnostics_.recordHttpStatus(status);
  AsyncWebServerResponse *response =
      request->beginResponse(status, "application/problem+json", body.c_str());
  response->addHeader("Cache-Control", "no-store");
  response->addHeader(
      "Set-Cookie",
      "pm_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
  response->addHeader("Set-Cookie",
                      "pm_csrf=; SameSite=Strict; Path=/; Max-Age=0", false);
  response->addHeader("Connection", "close", false);
  request->send(response);
}

bool HttpApi::beginHeavyLocalOperation(AsyncWebServerRequest *request) {
  const SyncMetrics sync = diagnostics_.syncMetrics();
  const std::uint32_t free_internal =
      heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  const std::uint32_t largest_internal =
      heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  const bool low_memory = free_internal < kMinimumHeavyUiInternalHeapBytes ||
                          largest_internal <
                              kMinimumHeavyUiLargestBlockBytes;
  if (sync.sync_in_progress || sync.primary_storage_pending ||
      sync.durable_reading_backlog || low_memory ||
      !diagnostics_.acquireHighMemoryOperation(0)) {
    diagnostics_.recordHeavyUiDeferral();
    const char body[] =
        "{\"type\":\"https://powermonitor.local/problems/local_resource_"
        "deferred\",\"title\":\"local_resource_deferred\",\"status\":503,"
        "\"detail\":\"The primary measurement or synchronization path needs "
        "the available local resources. Retry shortly.\",\"code\":"
        "\"local_resource_deferred\"}";
    AsyncWebServerResponse *response = request->beginResponse(
        503, "application/problem+json", body);
    response->addHeader("Cache-Control", "no-store");
    response->addHeader("Retry-After", "2");
    response->addHeader("Connection", "close", false);
    diagnostics_.recordHttpStatus(503);
    request->send(response);
    PM_LOG_WARN(
        "WEB", "HEAVY_REQUEST_DEFERRED",
        "route=%s sync_active=%s storage_pending=%s backlog=%s "
        "low_memory=%s free_internal=%lu largest_internal=%lu",
        request->url().c_str(), sync.sync_in_progress ? "true" : "false",
        sync.primary_storage_pending ? "true" : "false",
        sync.durable_reading_backlog ? "true" : "false",
        low_memory ? "true" : "false",
        static_cast<unsigned long>(free_internal),
        static_cast<unsigned long>(largest_internal));
    if (diag::SerialLogger::instance().allow("flight_heavy_ui_deferred",
                                             30'000U)) {
      const std::string detail =
          std::string("route=") + request->url().c_str() +
          " sync_active=" + (sync.sync_in_progress ? "true" : "false") +
          " storage_pending=" +
          (sync.primary_storage_pending ? "true" : "false") +
          " backlog=" + (sync.durable_reading_backlog ? "true" : "false") +
          " low_memory=" + (low_memory ? "true" : "false");
      coordinator_.enqueueEvent("EVT_HEAVY_UI_DEFERRED", "warning", detail,
                                clock_.utcMs(),
                                config_.identity().boot_id);
    }
    return false;
  }
  return true;
}

void HttpApi::endHeavyLocalOperation() {
  diagnostics_.releaseHighMemoryOperation();
}

void HttpApi::sendPage(AsyncWebServerRequest *request, const HistoryPage &page,
                       const bool ndjson) {
  int status = 200;
  std::string content_type;
  std::string body;
  buildPagePayload(page, ndjson, request->url().c_str(), status, content_type,
                   body);
  sendJson(request, status, body, content_type.c_str());
}

void HttpApi::buildPagePayload(const HistoryPage &page, const bool ndjson,
                               const std::string &instance, int &status,
                               std::string &content_type,
                               std::string &body) const {
  if (page.gone) {
    JsonDocument document;
    document["type"] = "https://powermonitor.local/problems/history-expired";
    document["title"] = "Requested history is no longer available";
    document["status"] = 410;
    document["detail"] =
        "The requested sequence predates retained acknowledged history.";
    document["instance"] = instance;
    document["code"] = "history_expired";
    document["oldest_sequence"] = page.first_sequence;
    document["newest_sequence"] = page.last_sequence;
    serializeJson(document, body);
    status = 410;
    content_type = "application/problem+json";
    return;
  }
  if (!page.ok) {
    JsonDocument document;
    document["type"] =
        std::string("https://powermonitor.local/problems/") + page.error_code;
    document["title"] = page.error_code;
    document["status"] = 503;
    document["detail"] = "History storage request failed or timed out.";
    document["instance"] = instance;
    document["code"] = page.error_code;
    serializeJson(document, body);
    status = 503;
    content_type = "application/problem+json";
    return;
  }
  if (ndjson) {
    for (const auto &record : page.records) {
      body.append(record);
      body.push_back('\n');
    }
    status = 200;
    content_type = "application/x-ndjson";
    return;
  }
  JsonDocument document;
  document["schema_version"] = 1;
  document["protocol_version"] = version::PROTOCOL;
  document["device_id"] = config_.identity().device_id;
  document["first_sequence"] = page.first_sequence;
  document["last_sequence"] = page.last_sequence;
  document["oldest_sequence"] = page.first_sequence;
  document["newest_sequence"] = page.last_sequence;
  document["has_more"] = page.has_more;
  document["next_after_sequence"] = page.next_after_sequence;
  JsonArray records = document["records"].to<JsonArray>();
  JsonArray readings = document["readings"].to<JsonArray>();
  JsonArray events = document["events"].to<JsonArray>();
  for (const auto &encoded : page.records) {
    JsonDocument record;
    if (!deserializeJson(record, encoded)) {
      records.add(record.as<JsonVariantConst>());
      if (record["event_sequence"].is<std::uint64_t>()) {
        events.add(record.as<JsonVariantConst>());
      } else {
        reading_wire::append(readings, encoded);
      }
    }
  }
  serializeJson(document, body);
  status = 200;
  content_type = "application/json";
}

HistoryQuery HttpApi::parseHistoryQuery(AsyncWebServerRequest *request) const {
  HistoryQuery query;
  // The completed page is retained briefly for polling. Bound each local
  // result below the storage layer's general-purpose limit so two abandoned
  // browser jobs cannot exhaust internal RAM.
  query.maximum_payload_bytes = 8U * 1024U;
  if (request->hasParam("after_sequence")) {
    query.after_sequence = std::strtoull(
        request->getParam("after_sequence")->value().c_str(), nullptr, 10);
  }
  if (request->hasParam("limit")) {
    query.limit = static_cast<std::uint16_t>(
        std::clamp(request->getParam("limit")->value().toInt(), 1L,
                   static_cast<long>(build::MAX_HISTORY_PAGE)));
  }
  if (request->hasParam("from_utc"))
    query.from_utc_ms = parseUtc(request->getParam("from_utc")->value());
  if (request->hasParam("to_utc"))
    query.to_utc_ms = parseUtc(request->getParam("to_utc")->value());
  return query;
}

bool HttpApi::queueMaintenance(const MaintenanceAction action,
                               const std::string &argument) {
  MaintenanceMessage message;
  if (maintenance_queue_ == nullptr ||
      argument.size() >= sizeof(message.argument)) {
    PM_LOG_WARN("QUEUE", "MAINTENANCE_REJECTED",
                "error=PM-QUEUE-004 reason=unavailable_or_argument_too_large "
                "argument=redacted");
    return false;
  }
  message.action = action;
  std::memcpy(message.argument, argument.c_str(), argument.size());
  message.argument[argument.size()] = '\0';
  const bool queued = xQueueSend(maintenance_queue_, &message, 0) == pdTRUE;
  PM_LOG_INFO(
      "QUEUE", "MAINTENANCE_QUEUED",
      "action=%u result=%s depth=%lu capacity=%u argument=redacted",
      static_cast<unsigned>(action), queued ? "success" : "full",
      static_cast<unsigned long>(uxQueueMessagesWaiting(maintenance_queue_)),
      static_cast<unsigned>(build::ACTION_QUEUE_DEPTH));
  return queued;
}

std::uint64_t HttpApi::parseUtc(const String &value) {
  int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
  if (std::sscanf(value.c_str(), "%d-%d-%dT%d:%d:%dZ", &year, &month, &day,
                  &hour, &minute, &second) != 6)
    return 0;
  const bool leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
  const int month_days[] = {
      0, 31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  if (year < 1970 || month < 1 || month > 12 || day < 1 ||
      day > month_days[month] || hour < 0 || hour > 23 || minute < 0 ||
      minute > 59 || second < 0 || second > 60)
    return 0;
  int adjusted_year = year - (month <= 2 ? 1 : 0);
  const int era = adjusted_year / 400;
  const unsigned year_of_era = static_cast<unsigned>(adjusted_year - era * 400);
  const unsigned day_of_year = static_cast<unsigned>(
      (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1);
  const unsigned day_of_era =
      year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
  const std::int64_t days =
      static_cast<std::int64_t>(era) * 146097 + day_of_era - 719468;
  const std::uint64_t timestamp = static_cast<std::uint64_t>(days) * 86400U +
                                  static_cast<std::uint64_t>(hour) * 3600U +
                                  static_cast<std::uint64_t>(minute) * 60U +
                                  static_cast<std::uint64_t>(second);
  return timestamp * 1000U;
}

} // namespace pm
