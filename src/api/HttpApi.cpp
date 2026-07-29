#include "api/HttpApi.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <vector>

#include <ArduinoJson.h>
#include <ESP.h>

#include "board_pins.h"
#include "build_config.h"
#include "diagnostics/SerialLogger.h"
#include "security/Crypto.h"
#include "ui/embedded_assets.h"
#include "version.h"

namespace pm {

HttpApi::HttpApi(ConfigService& config, NetworkService& network,
                 ClockService& clock, SdStorage& storage,
                 StorageCoordinator& coordinator, Diagnostics& diagnostics,
                 IMeter& meter, OtaService& ota,
                 const QueueHandle_t maintenance_queue)
    : config_(config),
      network_(network),
      clock_(clock),
      storage_(storage),
      coordinator_(coordinator),
      diagnostics_(diagnostics),
      meter_(meter),
      ota_(ota),
      provisioning_(config),
      maintenance_queue_(maintenance_queue) {}

void HttpApi::begin() {
  password_job_queue_ = xQueueCreate(4, sizeof(PasswordJob*));
  password_result_mutex_ = xSemaphoreCreateMutex();
  const bool worker_started =
      password_job_queue_ != nullptr && password_result_mutex_ != nullptr &&
      xTaskCreatePinnedToCore(passwordJobTaskEntry, "PasswordJobTask", 8192,
                              this, 1, &password_job_task_, 1) == pdPASS;
  if (!worker_started) {
    PM_LOG_ERROR("PASSWORD", "WORKER_INIT_FAILED",
                 "error=PM-PASSWORD-001 queue=%s mutex=%s",
                 password_job_queue_ == nullptr ? "failed" : "ready",
                 password_result_mutex_ == nullptr ? "failed" : "ready");
  } else {
    PM_LOG_INFO("PASSWORD", "WORKER_READY",
                "queue_capacity=4 core=1 priority=1 stack_words=8192 watchdog=false");
  }
  registerReadRoutes();
  registerMutationRoutes();
  server_.on("/", HTTP_GET, [this](AsyncWebServerRequest* request) {
    network_.touchSetupActivity();
    const ui::Asset* asset = ui::findAsset("/index.html");
    if (asset == nullptr) {
      sendProblem(request, 500, "ui_asset_missing", "Embedded UI asset is unavailable.");
      return;
    }
    AsyncWebServerResponse* response = request->beginResponse(
        200, asset->content_type, asset->data, asset->size);
    response->addHeader("Content-Encoding", "gzip");
    response->addHeader("Cache-Control", "no-cache");
    response->addHeader("Content-Security-Policy",
                        "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    response->addHeader("X-Content-Type-Options", "nosniff");
    response->addHeader("Referrer-Policy", "no-referrer");
    request->send(response);
  });
  server_.on("/assets/app.js", HTTP_GET, [this](AsyncWebServerRequest* request) {
    network_.touchSetupActivity();
    const ui::Asset* asset = ui::findAsset("/assets/app.js");
    if (asset == nullptr) {
      request->send(404);
      return;
    }
    AsyncWebServerResponse* response = request->beginResponse(
        200, asset->content_type, asset->data, asset->size);
    response->addHeader("Content-Encoding", "gzip");
    response->addHeader("Cache-Control", "public, max-age=31536000, immutable");
    request->send(response);
  });
  server_.on("/assets/style.css", HTTP_GET, [this](AsyncWebServerRequest* request) {
    network_.touchSetupActivity();
    const ui::Asset* asset = ui::findAsset("/assets/style.css");
    if (asset == nullptr) {
      request->send(404);
      return;
    }
    AsyncWebServerResponse* response = request->beginResponse(
        200, asset->content_type, asset->data, asset->size);
    response->addHeader("Content-Encoding", "gzip");
    response->addHeader("Cache-Control", "public, max-age=31536000, immutable");
    request->send(response);
  });
  server_.onNotFound([this](AsyncWebServerRequest* request) {
    sendProblem(request, 404, "not_found", "The requested local API or UI resource does not exist.");
  });
  server_.begin();
  PM_LOG_INFO("WEB", "SERVER_STARTED",
              "port=80 tls=false local_only=true ui=embedded authentication=session_or_hmac");
}

void HttpApi::passwordJobTaskEntry(void* context) {
  static_cast<HttpApi*>(context)->passwordJobTask();
}

void HttpApi::passwordJobTask() {
  PM_LOG_INFO(
      "TASK", "TASK_STARTED",
      "name=PasswordJobTask core=%d priority=%u stack_words=%u watchdog=false",
      xPortGetCoreID(), static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
      8192U);
  PasswordJob* job = nullptr;
  for (;;) {
    if (xQueueReceive(password_job_queue_, &job, pdMS_TO_TICKS(1000)) !=
            pdTRUE ||
        job == nullptr) {
      continue;
    }
    const std::uint64_t started = clock_.monotonicMs();
    PM_LOG_INFO(
        "PASSWORD", "JOB_STARTED",
        "kind=%s queue_wait_ms=%llu core=%d priority=%u heap_free=%lu",
        job->kind == PasswordJobKind::Login ? "login" : "setup",
        static_cast<unsigned long long>(started - job->queued_ms),
        xPortGetCoreID(), static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
        static_cast<unsigned long>(ESP.getFreeHeap()));
    bool success = false;
    std::string code;
    std::string detail;
    if (job->kind == PasswordJobKind::Login) {
      JsonDocument document;
      if (deserializeJson(document, job->body) ||
          !document["password"].is<const char*>()) {
        code = "login_json_invalid";
        detail = "Login body is invalid.";
      } else {
        const std::string password =
            document["password"].as<const char*>();
        success = config_.hasAdminPassword()
                      ? config_.verifyAdminPassword(password)
                      : config_.verifySetupPassword(password);
        code = success ? "ok" : "login_rejected";
        detail = success
                     ? "Administrator credentials were accepted."
                     : "Administrator credentials were rejected.";
      }
    } else {
      const ProvisioningResult result = provisioning_.apply(job->body);
      success = result.ok;
      code = result.code;
      detail = result.detail;
      if (success) {
        network_.requestConfigurationApply();
      }
    }
    const std::uint64_t duration = clock_.monotonicMs() - started;
    if (duration > 15'000U) {
      success = false;
      code = "password_job_timeout";
      detail = "The bounded password operation exceeded its time budget.";
    }
    std::fill(job->body.begin(), job->body.end(), '\0');
    job->body.clear();
    if (password_result_mutex_ != nullptr &&
        xSemaphoreTake(password_result_mutex_, pdMS_TO_TICKS(100)) ==
            pdTRUE) {
      for (auto& result : password_results_) {
        if (result.used && result.id == job->id) {
          result.complete = true;
          result.success = success;
          result.code = code;
          result.detail = detail;
          result.duration_ms = duration;
          result.expires_ms = clock_.monotonicMs() + 60'000U;
          break;
        }
      }
      xSemaphoreGive(password_result_mutex_);
    }
    PM_LOG_INFO(
        "PASSWORD", "JOB_COMPLETE",
        "kind=%s result=%s duration_ms=%llu timeout=%s high_water_words=%u heap_free=%lu",
        job->kind == PasswordJobKind::Login ? "login" : "setup",
        success ? "success" : "failed",
        static_cast<unsigned long long>(duration),
        duration > 15'000U ? "true" : "false",
        static_cast<unsigned>(uxTaskGetStackHighWaterMark(nullptr)),
        static_cast<unsigned long>(ESP.getFreeHeap()));
    if (duration > 2'000U) {
      PM_LOG_WARN(
          "PASSWORD", "JOB_SLOW",
          "error=PM-PASSWORD-002 kind=%s duration_ms=%llu budget_ms=15000",
          job->kind == PasswordJobKind::Login ? "login" : "setup",
          static_cast<unsigned long long>(duration));
    }
    delete job;
    job = nullptr;
  }
}

std::string HttpApi::queuePasswordJob(const PasswordJobKind kind,
                                      const std::string& body) {
  if (password_job_queue_ == nullptr || password_result_mutex_ == nullptr) {
    return {};
  }
  const std::uint64_t now = clock_.monotonicMs();
  const std::string id = crypto::randomHex(16);
  if (xSemaphoreTake(password_result_mutex_, pdMS_TO_TICKS(50)) != pdTRUE) {
    return {};
  }
  PasswordJobResult* slot = nullptr;
  for (auto& result : password_results_) {
    if (!result.used || result.expires_ms <= now) {
      slot = &result;
      break;
    }
  }
  if (slot != nullptr) {
    *slot = {};
    slot->used = true;
    slot->kind = kind;
    slot->id = id;
    slot->expires_ms = now + 60'000U;
  }
  xSemaphoreGive(password_result_mutex_);
  if (slot == nullptr) {
    PM_LOG_WARN("PASSWORD", "RESULT_TABLE_FULL",
                "error=PM-PASSWORD-003 capacity=%u",
                static_cast<unsigned>(password_results_.size()));
    return {};
  }
  auto* job = new (std::nothrow) PasswordJob{kind, id, body, now};
  if (job == nullptr ||
      xQueueSend(password_job_queue_, &job, 0) != pdTRUE) {
    delete job;
    if (xSemaphoreTake(password_result_mutex_, pdMS_TO_TICKS(50)) == pdTRUE) {
      slot->used = false;
      slot->id.clear();
      xSemaphoreGive(password_result_mutex_);
    }
    PM_LOG_WARN(
        "PASSWORD", "JOB_QUEUE_FULL",
        "error=PM-PASSWORD-004 capacity=4 depth=%lu dropped=true",
        static_cast<unsigned long>(
            uxQueueMessagesWaiting(password_job_queue_)));
    return {};
  }
  PM_LOG_INFO(
      "PASSWORD", "JOB_QUEUED",
      "kind=%s queue_depth=%lu capacity=4 body=redacted",
      kind == PasswordJobKind::Login ? "login" : "setup",
      static_cast<unsigned long>(
          uxQueueMessagesWaiting(password_job_queue_)));
  return id;
}

bool HttpApi::passwordJobResult(const std::string& id,
                                PasswordJobResult& result,
                                const bool consume) {
  if (password_result_mutex_ == nullptr ||
      xSemaphoreTake(password_result_mutex_, pdMS_TO_TICKS(50)) != pdTRUE) {
    return false;
  }
  const std::uint64_t now = clock_.monotonicMs();
  bool found = false;
  for (auto& candidate : password_results_) {
    if (candidate.used && candidate.expires_ms <= now) {
      candidate = {};
      continue;
    }
    if (candidate.used && candidate.id == id) {
      result = candidate;
      found = true;
      if (consume && candidate.complete) candidate = {};
      break;
    }
  }
  xSemaphoreGive(password_result_mutex_);
  return found;
}

void HttpApi::registerReadRoutes() {
  server_.on("/api/v1/auth/password-jobs", HTTP_GET,
             [this](AsyncWebServerRequest* request) {
    network_.touchSetupActivity();
    if (!sameOrigin(request) || !request->hasParam("job_id")) {
      sendProblem(request, 400, "password_job_request_invalid",
                  "A same-origin password job identifier is required.");
      return;
    }
    PasswordJobResult result;
    const std::string id =
        request->getParam("job_id")->value().c_str();
    if (!passwordJobResult(id, result, false)) {
      sendProblem(request, 404, "password_job_not_found",
                  "The password job is unknown or expired.");
      return;
    }
    if (result.kind == PasswordJobKind::Setup &&
        !localSession(request, false)) {
      sendProblem(request, 403, "setup_not_authorized",
                  "The setup session is required.");
      return;
    }
    if (!result.complete) {
      sendJson(request, 202, "{\"status\":\"pending\"}");
      return;
    }
    passwordJobResult(id, result, true);
    if (result.kind == PasswordJobKind::Login) {
      if (!result.success) {
        ++login_failures_;
        const std::uint32_t exponent =
            std::min<std::uint32_t>(login_failures_, 8);
        login_allowed_at_ms_ =
            clock_.monotonicMs() + (250U << exponent);
        PM_LOG_WARN(
            "AUTH", "LOGIN_REJECTED",
            "error=PM-AUTH-001 failures=%lu next_allowed_in_ms=%lu duration_ms=%llu",
            static_cast<unsigned long>(login_failures_),
            static_cast<unsigned long>(250U << exponent),
            static_cast<unsigned long long>(result.duration_ms));
        sendProblem(request, 401, "login_rejected",
                    "Administrator credentials were rejected.");
        return;
      }
      login_failures_ = 0;
      login_allowed_at_ms_ = 0;
      PM_LOG_INFO("AUTH", "LOGIN_ACCEPTED",
                  "duration_ms=%llu session=creating",
                  static_cast<unsigned long long>(result.duration_ms));
      createLocalSession(request);
      return;
    }
    if (!result.success) {
      sendProblem(request, 422, result.code.c_str(),
                  result.detail.c_str());
      return;
    }
    JsonDocument response_document;
    response_document["status"] = "setup_applied";
    response_document["network_apply_queued"] = true;
    response_document["reboot_queued"] = false;
    std::string response;
    serializeJson(response_document, response);
    sendJson(request, 200, response);
  });
  server_.on("/api/v1/diagnostics/recent-errors", HTTP_GET,
             [this](AsyncWebServerRequest* request) {
    if (!authorize(request, "", false)) return;
    sendJson(request, 200,
             diag::SerialLogger::instance().recentErrorsJson());
  });
  server_.on("/api/v1/health", HTTP_GET, [this](AsyncWebServerRequest* request) {
    if (!authorize(request, "", false)) return;
    sendJson(request, 200,
             diagnostics_.healthJson(config_, network_.status(), clock_,
                                     storage_.health(), meter_.metrics()));
  });
  server_.on("/api/v1/info", HTTP_GET, [this](AsyncWebServerRequest* request) {
    if (!authorize(request, "", false)) return;
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
    capabilities["connection_modes"] = "pull,push,hybrid";
    capabilities["signed_ota"] = true;
    capabilities["monitoring_only"] = true;
    std::string body;
    serializeJson(document, body);
    sendJson(request, 200, body);
  });
  server_.on("/api/v1/live", HTTP_GET, [this](AsyncWebServerRequest* request) {
    if (!authorize(request, "", false)) return;
    const std::string body = diagnostics_.liveJson(config_, clock_, meter_.methodName());
    if (body.empty()) {
      sendProblem(request, 503, "live_unavailable", "No meter snapshot has completed yet.");
      return;
    }
    sendJson(request, 200, body);
  });
  server_.on("/api/v1/readings", HTTP_GET, [this](AsyncWebServerRequest* request) {
    if (!authorize(request, "", false)) return;
    if (clock_.monotonicMs() < history_allowed_at_ms_) {
      sendProblem(request, 429, "history_rate_limited",
                  "Wait before issuing another storage history request.",
                  false, true);
      return;
    }
    history_allowed_at_ms_ = clock_.monotonicMs() + 250U;
    const HistoryPage page = coordinator_.requestHistory(parseHistoryQuery(request));
    const bool ndjson = request->hasHeader("Accept") &&
                        request->getHeader("Accept")->value().indexOf("application/x-ndjson") >= 0;
    sendPage(request, page, ndjson);
  });
  server_.on("/api/v1/events", HTTP_GET, [this](AsyncWebServerRequest* request) {
    if (!authorize(request, "", false)) return;
    if (clock_.monotonicMs() < history_allowed_at_ms_) {
      sendProblem(request, 429, "history_rate_limited",
                  "Wait before issuing another storage history request.",
                  false, true);
      return;
    }
    history_allowed_at_ms_ = clock_.monotonicMs() + 250U;
    sendPage(request,
             coordinator_.requestHistory(parseHistoryQuery(request), true), false);
  });
  server_.on("/api/v1/storage", HTTP_GET, [this](AsyncWebServerRequest* request) {
    if (!authorize(request, "", false)) return;
    const StorageHealth value = storage_.health();
    JsonDocument document;
    document["schema_version"] = 1;
    document["present"] = value.present;
    document["mounted"] = value.mounted;
    document["writable"] = value.writable;
    document["prepared_for_removal"] = value.prepared_for_removal;
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
    document["server_ack_sequence"] = config_.serverAckSequence();
    document["unsynchronized_estimate"] =
        value.newest_sequence >= config_.serverAckSequence()
            ? value.newest_sequence - config_.serverAckSequence()
            : 0;
    document["spi_hz"] = value.spi_hz;
    document["last_error"] = value.last_error;
    std::string body;
    serializeJson(document, body);
    sendJson(request, 200, body);
  });
  server_.on("/api/v1/sync-status", HTTP_GET, [this](AsyncWebServerRequest* request) {
    if (!authorize(request, "", false)) return;
    const StorageHealth storage = storage_.health();
    const SyncMetrics sync = diagnostics_.syncMetrics();
    JsonDocument document;
    document["schema_version"] = 1;
    document["mode"] = connectionModeName(config_.config().connection_mode);
    document["server_ack_sequence"] = config_.serverAckSequence();
    document["newest_sequence"] = storage.newest_sequence;
    document["backlog_estimate"] = storage.newest_sequence >= config_.serverAckSequence()
                                             ? storage.newest_sequence - config_.serverAckSequence()
                                             : 0;
    document["last_heartbeat_utc_ms"] = sync.last_heartbeat_utc_ms;
    document["last_sync_utc_ms"] = sync.last_sync_utc_ms;
    document["last_error"] = sync.last_error;
    std::string body;
    serializeJson(document, body);
    sendJson(request, 200, body);
  });
  server_.on("/api/v1/config", HTTP_GET, [this](AsyncWebServerRequest* request) {
    if (!authorize(request, "", false)) return;
    sendJson(request, 200, config_.redactedJson());
  });
  server_.on("/api/v1/metrics", HTTP_GET, [this](AsyncWebServerRequest* request) {
    if (!authorize(request, "", false)) return;
    sendJson(request, 200,
             diagnostics_.metricsJson(storage_.health(), meter_.metrics()));
  });
  server_.on("/api/v1/ota/status", HTTP_GET,
             [this](AsyncWebServerRequest* request) {
    if (!authorize(request, "", false)) return;
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
             [this](AsyncWebServerRequest* request) {
    if (!authorize(request, "", false)) return;
    AsyncWebServerResponse* response = request->beginResponse(
        200, "application/json",
        diagnostics_.redactedBundle(config_, network_.status(), clock_,
                                    storage_.health(), meter_.metrics()).c_str());
    response->addHeader("Content-Disposition", "attachment; filename=power-monitor-diagnostics.json");
    response->addHeader("Cache-Control", "no-store");
    request->send(response);
  });
}

void HttpApi::registerMutationRoutes() {
  registerBodyRoute("/api/v1/auth/session", HTTP_POST,
                    [this](AsyncWebServerRequest* request) {
    network_.touchSetupActivity();
    takeBody(request);
    if (!sameOrigin(request)) {
      sendProblem(request, 403, "origin_rejected",
                  "Cross-origin session creation is not allowed.");
      return;
    }
    createLocalSession(request);
  });
  registerBodyRoute("/api/v1/auth/login", HTTP_POST,
                    [this](AsyncWebServerRequest* request) {
    network_.touchSetupActivity();
    const std::string body = takeBody(request);
    if (!sameOrigin(request)) {
      sendProblem(request, 403, "origin_rejected", "Cross-origin login is not allowed.");
      return;
    }
    if (clock_.monotonicMs() < login_allowed_at_ms_) {
      sendProblem(request, 429, "login_throttled", "Wait before another login attempt.", false, true);
      return;
    }
    JsonDocument document;
    if (body.size() > 1024 || deserializeJson(document, body) ||
        !document["password"].is<const char*>()) {
      sendProblem(request, 400, "login_json_invalid", "Login body is invalid.");
      return;
    }
    const std::string job_id =
        queuePasswordJob(PasswordJobKind::Login, body);
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
  registerBodyRoute("/api/v1/auth/logout", HTTP_POST,
                    [this](AsyncWebServerRequest* request) {
    const std::string body = takeBody(request);
    if (!authorize(request, body, true)) return;
    sessions_.invalidate();
    AsyncWebServerResponse* response = request->beginResponse(204);
    response->addHeader("Set-Cookie", "pm_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    request->send(response);
  });
  registerBodyRoute("/api/v1/config", HTTP_PUT,
                    [this](AsyncWebServerRequest* request) {
    const std::string body = takeBody(request);
    if (!authorize(request, body, true)) return;
    const bool dry_run = request->hasParam("dry_run") &&
                         request->getParam("dry_run")->value() == "true";
    const bool ct_ack = request->hasHeader("X-PM-CT-Change-Acknowledged") &&
                        request->getHeader("X-PM-CT-Change-Acknowledged")->value() == "true";
    const float previous_ct_rating = config_.config().ct_rating_a;
    ConfigValidation result;
    if (!config_.updateFromJson(body, dry_run, ct_ack, result)) {
      sendProblem(request, 422, result.code.c_str(), result.detail.c_str());
      return;
    }
    if (!dry_run && previous_ct_rating != config_.config().ct_rating_a) {
      coordinator_.enqueueEvent(
          "EVT_CT_RATING_CHANGED", "warning",
          "CT rating changed after explicit installed-hardware acknowledgement.",
          clock_.utcMs(), config_.identity().boot_id);
    }
    JsonDocument document;
    document["valid"] = true;
    document["dry_run"] = dry_run;
    document["config_version"] = config_.config().config_version;
    std::string response;
    serializeJson(document, response);
    sendJson(request, 200, response);
  });
  registerBodyRoute("/api/v1/network-settings", HTTP_PUT,
                    [this](AsyncWebServerRequest* request) {
    const std::string body = takeBody(request);
    if (!authorize(request, body, true)) return;
    JsonDocument document;
    if (deserializeJson(document, body) ||
        !document["wifi_ssid"].is<const char*>() ||
        !document["static_network_enabled"].is<bool>() ||
        !document["static_ip"].is<const char*>() ||
        !document["static_gateway"].is<const char*>() ||
        !document["static_subnet"].is<const char*>() ||
        !document["static_dns"].is<const char*>() ||
        !document["server_url"].is<const char*>() ||
        !document["tls_trust_action"].is<const char*>() ||
        !document["connection_mode"].is<const char*>()) {
      sendProblem(request, 400, "network_settings_json_invalid",
                  "Network settings are missing required fields or use invalid types.");
      return;
    }

    const std::string mode = document["connection_mode"].as<const char*>();
    if (mode != "pull" && mode != "push" && mode != "hybrid") {
      sendProblem(request, 422, "connection_mode_invalid",
                  "Connection mode must be pull, push, or hybrid.");
      return;
    }
    const bool replace_wifi_password =
        !document["wifi_password"].isNull();
    if (replace_wifi_password &&
        !document["wifi_password"].is<const char*>()) {
      sendProblem(request, 400, "wifi_password_invalid",
                  "The replacement Wi-Fi password must be a string.");
      return;
    }

    RuntimeConfig candidate = config_.config();
    candidate.wifi_ssid = document["wifi_ssid"].as<const char*>();
    candidate.static_network_enabled =
        document["static_network_enabled"].as<bool>();
    candidate.static_ip = document["static_ip"].as<const char*>();
    candidate.static_gateway = document["static_gateway"].as<const char*>();
    candidate.static_subnet = document["static_subnet"].as<const char*>();
    candidate.static_dns = document["static_dns"].as<const char*>();
    candidate.server_url = document["server_url"].as<const char*>();
    candidate.connection_mode =
        mode == "pull" ? ConnectionMode::Pull
                       : (mode == "push" ? ConnectionMode::Push
                                         : ConnectionMode::Hybrid);

    const std::string trust_action =
        document["tls_trust_action"].as<const char*>();
    if (trust_action == "keep") {
      if (!document["server_ca_pem"].isNull() ||
          !document["server_fingerprint"].isNull()) {
        sendProblem(request, 422, "tls_trust_action_invalid",
                    "Keep trust must not include replacement trust material.");
        return;
      }
      if (candidate.server_ca_pem.empty()) {
        sendProblem(
            request, 422, "server_ca_required",
            "Fingerprint-only TLS is not supported safely; replace trust with a CA PEM.");
        return;
      }
    } else if (trust_action == "replace_ca") {
      if (!document["server_ca_pem"].is<const char*>() ||
          !document["server_fingerprint"].isNull()) {
        sendProblem(request, 422, "server_ca_required",
                    "Replacing TLS trust with a CA requires only a PEM certificate.");
        return;
      }
      candidate.server_ca_pem = document["server_ca_pem"].as<const char*>();
      candidate.server_fingerprint.clear();
    } else if (trust_action == "replace_fingerprint") {
      sendProblem(
          request, 422, "server_ca_required",
          "Fingerprint-only TLS is rejected because secure CA and hostname validation are mandatory.");
      return;
    } else {
      sendProblem(request, 422, "tls_trust_action_invalid",
                  "TLS trust action must keep or replace the configured trust.");
      return;
    }

    const std::string wifi_password =
        replace_wifi_password
            ? document["wifi_password"].as<const char*>()
            : std::string{};
    ConfigValidation result;
    if (!config_.updateNetworkSettings(candidate, wifi_password,
                                       replace_wifi_password, result)) {
      sendProblem(request, 422, result.code.c_str(), result.detail.c_str());
      return;
    }
    coordinator_.enqueueEvent(
        "EVT_NETWORK_SETTINGS_CHANGED", "warning",
        "Authorized Wi-Fi or central server settings changed; live network "
        "reconfiguration requested.",
        clock_.utcMs(), config_.identity().boot_id);
    network_.requestConfigurationApply();
    JsonDocument response_document;
    response_document["status"] = "network_settings_applied";
    response_document["config_version"] = config_.config().config_version;
    response_document["network_apply_queued"] = true;
    response_document["reboot_queued"] = false;
    std::string response;
    serializeJson(response_document, response);
    sendJson(request, 200, response);
  });
  registerBodyRoute("/api/v1/setup/apply", HTTP_POST,
                    [this](AsyncWebServerRequest* request) {
    network_.touchSetupActivity();
    const std::string body = takeBody(request);
    if (!localSession(request, true) || config_.hasAdminPassword()) {
      sendProblem(request, 403, "setup_not_authorized", "First-run setup requires the setup session and closes after administrator creation.");
      return;
    }
    const std::string job_id =
        queuePasswordJob(PasswordJobKind::Setup, body);
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
  registerBodyRoute("/api/v1/sync/ack", HTTP_POST,
                    [this](AsyncWebServerRequest* request) {
    const std::string body = takeBody(request);
    if (!authorize(request, body, true)) return;
    JsonDocument document;
    if (deserializeJson(document, body)) {
      sendProblem(request, 400, "ack_json_invalid", "Acknowledgement body is invalid.");
      return;
    }
    const std::uint64_t sequence = document["ack_sequence"] | 0;
    const StorageHealth storage = storage_.health();
    if (sequence < config_.serverAckSequence() || sequence > storage.newest_sequence ||
        !config_.setServerAckSequence(sequence)) {
      sendProblem(request, 409, "ack_sequence_invalid", "Acknowledgement must advance monotonically within available history.");
      return;
    }
    sendJson(request, 200, "{\"status\":\"acknowledged\"}");
  });
  registerBodyRoute("/api/v1/enrollment/reenroll", HTTP_POST,
                    [this](AsyncWebServerRequest* request) {
    const std::string body = takeBody(request);
    if (!authorize(request, body, true)) return;
    if (!request->hasHeader("X-PM-Action-Token") ||
        request->getHeader("X-PM-Action-Token")->value() != "REENROLL") {
      sendProblem(request, 403, "action_confirmation_required",
                  "The exact short-lived reenrollment confirmation is required.");
      return;
    }
    JsonDocument document;
    if (deserializeJson(document, body)) {
      sendProblem(request, 400, "reenrollment_json_invalid",
                  "Reenrollment body is invalid.");
      return;
    }
    const std::string token = document["enrollment_token"] | "";
    if (!config_.beginReenrollment(token)) {
      sendProblem(request, 422, "reenrollment_failed",
                  "The one-time token could not replace existing credentials.");
      return;
    }
    coordinator_.enqueueEvent(
        "EVT_REENROLLMENT_REQUESTED", "warning",
        "Authorized credential revocation and reenrollment requested.",
        clock_.utcMs(), config_.identity().boot_id);
    sendJson(request, 200, "{\"status\":\"reenrollment_pending\"}");
  });
  registerAction("/api/v1/actions/test-pzem", MaintenanceAction::TestPzem);
  registerAction("/api/v1/actions/test-sd", MaintenanceAction::TestSd);
  registerAction("/api/v1/actions/remount-sd", MaintenanceAction::RemountSd);
  registerAction("/api/v1/actions/rebuild-index", MaintenanceAction::RebuildIndex);
  registerAction("/api/v1/actions/prepare-card-removal", MaintenanceAction::PrepareCardRemoval);
  registerAction("/api/v1/actions/test-dns", MaintenanceAction::TestDns);
  registerAction("/api/v1/actions/test-ntp", MaintenanceAction::TestNtp);
  registerAction("/api/v1/actions/test-server-tls", MaintenanceAction::TestServerTls);
  registerAction("/api/v1/actions/test-heartbeat", MaintenanceAction::TestHeartbeat);
  registerAction("/api/v1/actions/reboot", MaintenanceAction::Reboot, "REBOOT");
  registerAction("/api/v1/actions/network-reset", MaintenanceAction::NetworkReset, "RESET NETWORK");
  registerAction("/api/v1/actions/factory-reset", MaintenanceAction::FactoryReset, "FACTORY RESET");
  registerAction("/api/v1/actions/rollback-ota", MaintenanceAction::RollbackOta, "ROLLBACK OTA");
  registerBodyRoute("/api/v1/ota/apply", HTTP_POST,
                    [this](AsyncWebServerRequest* request) {
    const std::string body = takeBody(request);
    if (!authorize(request, body, true)) return;
    JsonDocument document;
    if (deserializeJson(document, body)) {
      sendProblem(request, 400, "ota_json_invalid", "OTA action body is invalid.");
      return;
    }
    const std::string url = document["manifest_url"] | "";
    if (url.rfind("https://", 0) != 0 || !queueMaintenance(MaintenanceAction::ApplyOta, url)) {
      sendProblem(request, 422, "ota_request_invalid", "A bounded HTTPS manifest URL is required and the action queue must have capacity.");
      return;
    }
    sendJson(request, 202, "{\"status\":\"queued\"}");
  });
}

void HttpApi::registerAction(const char* path, const MaintenanceAction action,
                             const char* confirmation) {
  registerBodyRoute(path, HTTP_POST,
                    [this, action, confirmation](AsyncWebServerRequest* request) {
    const std::string body = takeBody(request);
    if (!authorize(request, body, true)) return;
    if (confirmation != nullptr &&
        (!request->hasHeader("X-PM-Action-Token") ||
         request->getHeader("X-PM-Action-Token")->value() != confirmation)) {
      sendProblem(request, 403, "action_confirmation_required", "The exact short-lived local action confirmation is required.");
      return;
    }
    if (!queueMaintenance(action)) {
      sendProblem(request, 429, "action_queue_full", "The bounded maintenance queue is full.", false, true);
      return;
    }
    sendJson(request, 202, "{\"status\":\"queued\"}");
  });
}

void HttpApi::registerBodyRoute(const char* path, const WebRequestMethod method,
                                ArRequestHandlerFunction handler) {
  PM_LOG_DEBUG("WEB", "ROUTE_REGISTERED", "path=%s method_mask=%u",
               path, static_cast<unsigned>(method));
  server_.on(path, method, std::move(handler), nullptr,
             [](AsyncWebServerRequest* request, std::uint8_t* data,
                const std::size_t length, const std::size_t index,
                const std::size_t total) {
    if (index == 0) {
      request->_tempObject = new (std::nothrow) BodyBuffer{};
      auto* buffer = static_cast<BodyBuffer*>(request->_tempObject);
      if (buffer != nullptr && total <= build::MAX_JSON_BODY) {
        buffer->body.reserve(total);
      }
    }
    auto* buffer = static_cast<BodyBuffer*>(request->_tempObject);
    if (buffer == nullptr) return;
    if (total > build::MAX_JSON_BODY || buffer->body.size() + length > build::MAX_JSON_BODY) {
      buffer->overflow = true;
      if (diag::SerialLogger::instance().allow("http_body_overflow",
                                                10'000U)) {
        PM_LOG_WARN(
            "HTTP", "BODY_REJECTED",
            "error=PM-HTTP-002 maximum_bytes=%u body=redacted",
            static_cast<unsigned>(build::MAX_JSON_BODY));
      }
      return;
    }
    buffer->body.append(reinterpret_cast<const char*>(data), length);
  });
}

std::string HttpApi::takeBody(AsyncWebServerRequest* request) const {
  auto* buffer = static_cast<BodyBuffer*>(request->_tempObject);
  request->_tempObject = nullptr;
  if (buffer == nullptr) return {};
  std::string body = buffer->overflow ? std::string{} : std::move(buffer->body);
  delete buffer;
  return body;
}

bool HttpApi::authorize(AsyncWebServerRequest* request, const std::string& body,
                        const bool mutation) {
  if (network_.status().setup_ap_active) {
    network_.touchSetupActivity();
  }
  const std::uint64_t now = clock_.monotonicMs();
  if (api_window_started_ms_ == 0 || now - api_window_started_ms_ >= 1000U) {
    api_window_started_ms_ = now;
    api_requests_in_window_ = 0;
  }
  if (api_requests_in_window_ >= 60U) {
    PM_LOG_WARN("AUTH", "API_RATE_LIMITED",
                "error=PM-AUTH-002 window_ms=1000 limit=60 route=%s",
                request->url().c_str());
    sendProblem(request, 429, "api_rate_limited",
                "The authenticated API request rate exceeded the bounded limit.",
                false, true);
    return false;
  }
  ++api_requests_in_window_;
  if (!sameOrigin(request)) {
    PM_LOG_WARN("AUTH", "ORIGIN_REJECTED",
                "error=PM-AUTH-003 route=%s method=%s",
                request->url().c_str(), request->methodToString());
    sendProblem(request, 403, "origin_rejected", "Cross-origin API access is not allowed.");
    return false;
  }
  if (localSession(request, mutation)) {
    PM_LOG_DEBUG("AUTH", "LOCAL_SESSION_ACCEPTED",
                 "route=%s method=%s mutation=%s",
                 request->url().c_str(), request->methodToString(),
                 mutation ? "true" : "false");
    return true;
  }
  crypto::Key32 outbound{};
  crypto::Key32 inbound{};
  if (!config_.directionalKeys(outbound, inbound)) {
    PM_LOG_WARN("AUTH", "AUTHENTICATION_REQUIRED",
                "error=PM-AUTH-004 route=%s local_session=false enrolled_keys=false",
                request->url().c_str());
    sendProblem(request, 401, "authentication_required", "A local session or enrolled server signature is required.", true);
    return false;
  }
  AuthHeaders headers;
  auto header = [request](const char* name) -> std::string {
    return request->hasHeader(name) ? request->getHeader(name)->value().c_str() : "";
  };
  headers.protocol = header("X-PM-Protocol");
  headers.device_id = header("X-PM-Device-ID");
  headers.timestamp = header("X-PM-Timestamp");
  headers.nonce = header("X-PM-Nonce");
  headers.content_sha256 = header("X-PM-Content-SHA256");
  headers.signature = header("X-PM-Signature");
  std::vector<std::pair<std::string, std::string>> query;
  for (std::size_t index = 0; index < request->params(); ++index) {
    const AsyncWebParameter* parameter = request->getParam(index);
    if (!parameter->isPost() && !parameter->isFile()) {
      query.emplace_back(parameter->name().c_str(), parameter->value().c_str());
    }
  }
  const AuthResult result = authenticator_.verify(
      request->methodToString(), request->url().c_str(), query,
      reinterpret_cast<const std::uint8_t*>(body.data()), body.size(), headers,
      config_.identity().device_id, inbound, std::time(nullptr),
      clock_.synchronized());
  if (result != AuthResult::Ok) {
    PM_LOG_WARN(
        "AUTH", "SERVER_SIGNATURE_REJECTED",
        "error=PM-AUTH-005 route=%s method=%s reason=%s signature=redacted",
        request->url().c_str(), request->methodToString(),
        authResultCode(result));
    sendProblem(request, result == AuthResult::ProtocolMismatch ? 409 : 401,
                authResultCode(result), "Server-to-device signature verification failed.", true);
    return false;
  }
  PM_LOG_INFO("AUTH", "SERVER_SIGNATURE_ACCEPTED",
              "route=%s method=%s nonce=redacted",
              request->url().c_str(), request->methodToString());
  return true;
}

bool HttpApi::localSession(AsyncWebServerRequest* request,
                           const bool mutation) const {
  const std::string token = cookieValue(request, "pm_session");
  if (token.empty()) return false;
  if (!mutation) return sessions_.validate(token, clock_.monotonicMs());
  const std::string csrf = request->hasHeader("X-PM-CSRF")
                               ? request->getHeader("X-PM-CSRF")->value().c_str()
                               : "";
  return sessions_.validateMutation(token, csrf, clock_.monotonicMs());
}

bool HttpApi::sameOrigin(AsyncWebServerRequest* request) const {
  if (!request->hasHeader("Origin")) return true;
  const String origin = request->getHeader("Origin")->value();
  const String host = request->host();
  return origin == "http://" + host || origin == "https://" + host;
}

void HttpApi::createLocalSession(AsyncWebServerRequest* request) {
  const SessionManager::Session session = sessions_.create(
      clock_.monotonicMs(), config_.config().local_session_timeout_seconds);
  JsonDocument document;
  document["csrf"] = session.csrf;
  document["expires_in_seconds"] =
      config_.config().local_session_timeout_seconds;
  document["setup_required"] = !config_.hasAdminPassword();
  std::string body;
  serializeJson(document, body);
  AsyncWebServerResponse* response =
      request->beginResponse(200, "application/json", body.c_str());
  const std::string cookie =
      "pm_session=" + session.token +
      "; HttpOnly; SameSite=Strict; Path=/; Max-Age=" +
      std::to_string(config_.config().local_session_timeout_seconds);
  response->addHeader("Set-Cookie", cookie.c_str());
  response->addHeader("Cache-Control", "no-store");
  diagnostics_.recordHttpStatus(200);
  request->send(response);
  PM_LOG_INFO("AUTH", "SESSION_CREATED",
              "expires_in_seconds=%lu setup_required=%s token=redacted csrf=redacted",
              static_cast<unsigned long>(
                  config_.config().local_session_timeout_seconds),
              config_.hasAdminPassword() ? "false" : "true");
}

std::string HttpApi::cookieValue(AsyncWebServerRequest* request,
                                 const char* name) const {
  if (!request->hasHeader("Cookie")) return {};
  const std::string cookies = request->getHeader("Cookie")->value().c_str();
  const std::string prefix = std::string(name) + "=";
  std::size_t position = cookies.find(prefix);
  while (position != std::string::npos && position > 0 &&
         cookies[position - 1] != ' ' && cookies[position - 1] != ';') {
    position = cookies.find(prefix, position + prefix.size());
  }
  if (position == std::string::npos) return {};
  const std::size_t start = position + prefix.size();
  const std::size_t end = cookies.find(';', start);
  return cookies.substr(start, end - start);
}

void HttpApi::sendJson(AsyncWebServerRequest* request, const int status,
                       const std::string& body, const char* content_type) {
  AsyncWebServerResponse* response = request->beginResponse(status, content_type, body.c_str());
  response->addHeader("Cache-Control", "no-store");
  response->addHeader("X-Content-Type-Options", "nosniff");
  diagnostics_.recordHttpStatus(status);
  request->send(response);
  PM_LOG_DEBUG(
      "HTTP", "LOCAL_RESPONSE",
      "method=%s route=%s status=%d category=%s response_bytes=%u",
      request->methodToString(), request->url().c_str(), status,
      diag::httpStatusCategory(status), static_cast<unsigned>(body.size()));
}

void HttpApi::sendProblem(AsyncWebServerRequest* request, const int status,
                          const char* code, const char* detail,
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
  AsyncWebServerResponse* response = request->beginResponse(
      status, "application/problem+json", body.c_str());
  response->addHeader("Cache-Control", "no-store");
  request->send(response);
  PM_LOG_WARN(
      "HTTP", "LOCAL_PROBLEM",
      "method=%s route=%s status=%d category=%s error=%s signature_rejected=%s rate_limited=%s",
      request->methodToString(), request->url().c_str(), status,
      diag::httpStatusCategory(status), code,
      rejected_signature ? "true" : "false",
      rate_limited ? "true" : "false");
}

void HttpApi::sendPage(AsyncWebServerRequest* request, const HistoryPage& page,
                       const bool ndjson) {
  if (page.gone) {
    JsonDocument document;
    document["type"] = "https://powermonitor.local/problems/history-expired";
    document["title"] = "Requested history is no longer available";
    document["status"] = 410;
    document["detail"] = "The requested sequence predates retained acknowledged history.";
    document["instance"] = request->url();
    document["code"] = "history_expired";
    document["oldest_sequence"] = page.first_sequence;
    document["newest_sequence"] = page.last_sequence;
    std::string body;
    serializeJson(document, body);
    sendJson(request, 410, body, "application/problem+json");
    return;
  }
  if (!page.ok) {
    sendProblem(request, 503, page.error_code.c_str(), "History storage request failed or timed out.");
    return;
  }
  if (ndjson) {
    AsyncResponseStream* response =
        request->beginResponseStream("application/x-ndjson");
    response->setCode(200);
    response->addHeader("Cache-Control", "no-store");
    response->addHeader("X-Content-Type-Options", "nosniff");
    for (const auto& record : page.records) {
      response->print(record.c_str());
      response->print('\n');
    }
    diagnostics_.recordHttpStatus(200);
    request->send(response);
    return;
  }
  JsonDocument document;
  document["schema_version"] = 1;
  document["first_sequence"] = page.first_sequence;
  document["last_sequence"] = page.last_sequence;
  document["has_more"] = page.has_more;
  document["next_after_sequence"] = page.next_after_sequence;
  JsonArray records = document["records"].to<JsonArray>();
  for (const auto& encoded : page.records) {
    JsonDocument record;
    if (!deserializeJson(record, encoded)) records.add(record.as<JsonVariantConst>());
  }
  std::string body;
  serializeJson(document, body);
  sendJson(request, 200, body);
}

HistoryQuery HttpApi::parseHistoryQuery(AsyncWebServerRequest* request) const {
  HistoryQuery query;
  if (request->hasParam("after_sequence")) {
    query.after_sequence = std::strtoull(request->getParam("after_sequence")->value().c_str(), nullptr, 10);
  }
  if (request->hasParam("limit")) {
    query.limit = static_cast<std::uint16_t>(std::clamp(
        request->getParam("limit")->value().toInt(), 1L,
        static_cast<long>(build::MAX_HISTORY_PAGE)));
  }
  if (request->hasParam("from_utc")) query.from_utc_ms = parseUtc(request->getParam("from_utc")->value());
  if (request->hasParam("to_utc")) query.to_utc_ms = parseUtc(request->getParam("to_utc")->value());
  return query;
}

bool HttpApi::queueMaintenance(const MaintenanceAction action,
                               const std::string& argument) {
  MaintenanceMessage message;
  if (maintenance_queue_ == nullptr ||
      argument.size() >= sizeof(message.argument)) {
    PM_LOG_WARN("QUEUE", "MAINTENANCE_REJECTED",
                "error=PM-QUEUE-004 reason=unavailable_or_argument_too_large argument=redacted");
    return false;
  }
  message.action = action;
  std::memcpy(message.argument, argument.c_str(), argument.size());
  message.argument[argument.size()] = '\0';
  const bool queued =
      xQueueSend(maintenance_queue_, &message, 0) == pdTRUE;
  PM_LOG_INFO(
      "QUEUE", "MAINTENANCE_QUEUED",
      "action=%u result=%s depth=%lu capacity=%u argument=redacted",
      static_cast<unsigned>(action), queued ? "success" : "full",
      static_cast<unsigned long>(
          uxQueueMessagesWaiting(maintenance_queue_)),
      static_cast<unsigned>(build::ACTION_QUEUE_DEPTH));
  return queued;
}

std::uint64_t HttpApi::parseUtc(const String& value) {
  int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
  if (std::sscanf(value.c_str(), "%d-%d-%dT%d:%d:%dZ", &year, &month, &day,
                  &hour, &minute, &second) != 6) return 0;
  const bool leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
  const int month_days[] = {0, 31, leap ? 29 : 28, 31, 30, 31, 30,
                            31, 31, 30, 31, 30, 31};
  if (year < 1970 || month < 1 || month > 12 || day < 1 ||
      day > month_days[month] || hour < 0 || hour > 23 || minute < 0 ||
      minute > 59 || second < 0 || second > 60) return 0;
  int adjusted_year = year - (month <= 2 ? 1 : 0);
  const int era = adjusted_year / 400;
  const unsigned year_of_era = static_cast<unsigned>(adjusted_year - era * 400);
  const unsigned day_of_year = static_cast<unsigned>(
      (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1);
  const unsigned day_of_era = year_of_era * 365 + year_of_era / 4 -
                              year_of_era / 100 + day_of_year;
  const std::int64_t days = static_cast<std::int64_t>(era) * 146097 +
                            day_of_era - 719468;
  const std::uint64_t timestamp = static_cast<std::uint64_t>(days) * 86400U +
      static_cast<std::uint64_t>(hour) * 3600U +
      static_cast<std::uint64_t>(minute) * 60U + static_cast<std::uint64_t>(second);
  return timestamp * 1000U;
}

}  // namespace pm
