#include "api/HttpApi.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <vector>

#include <ArduinoJson.h>

#include "board_pins.h"
#include "build_config.h"
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
  registerReadRoutes();
  registerMutationRoutes();
  server_.on("/", HTTP_GET, [this](AsyncWebServerRequest* request) {
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
  server_.on("/assets/app.js", HTTP_GET, [](AsyncWebServerRequest* request) {
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
  server_.on("/assets/style.css", HTTP_GET, [](AsyncWebServerRequest* request) {
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
}

void HttpApi::registerReadRoutes() {
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
    const HistoryPage page = coordinator_.requestHistory(parseHistoryQuery(request));
    const bool ndjson = request->hasHeader("Accept") &&
                        request->getHeader("Accept")->value().indexOf("application/x-ndjson") >= 0;
    sendPage(request, page, ndjson);
  });
  server_.on("/api/v1/events", HTTP_GET, [this](AsyncWebServerRequest* request) {
    if (!authorize(request, "", false)) return;
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
  registerBodyRoute("/api/v1/auth/login", HTTP_POST,
                    [this](AsyncWebServerRequest* request) {
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
    if (body.size() > 1024 || deserializeJson(document, body)) {
      sendProblem(request, 400, "login_json_invalid", "Login body is invalid.");
      return;
    }
    const std::string password = document["password"] | "";
    const bool accepted = config_.hasAdminPassword()
                              ? config_.verifyAdminPassword(password)
                              : config_.verifySetupPassword(password);
    if (!accepted) {
      ++login_failures_;
      const std::uint32_t exponent = std::min<std::uint32_t>(login_failures_, 8);
      login_allowed_at_ms_ = clock_.monotonicMs() + (250U << exponent);
      sendProblem(request, 401, "login_rejected", "Administrator credentials were rejected.");
      return;
    }
    login_failures_ = 0;
    login_allowed_at_ms_ = 0;
    const SessionManager::Session session = sessions_.create(
        clock_.monotonicMs(), config_.config().local_session_timeout_seconds);
    JsonDocument response_document;
    response_document["csrf"] = session.csrf;
    response_document["expires_in_seconds"] = config_.config().local_session_timeout_seconds;
    response_document["setup_required"] = !config_.hasAdminPassword();
    std::string response_body;
    serializeJson(response_document, response_body);
    AsyncWebServerResponse* response = request->beginResponse(200, "application/json", response_body.c_str());
    const std::string cookie = "pm_session=" + session.token +
                               "; HttpOnly; SameSite=Strict; Path=/; Max-Age=" +
                               std::to_string(config_.config().local_session_timeout_seconds);
    response->addHeader("Set-Cookie", cookie.c_str());
    response->addHeader("Cache-Control", "no-store");
    diagnostics_.recordHttpStatus(200);
    request->send(response);
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
    ConfigValidation result;
    if (!config_.updateFromJson(body, dry_run, ct_ack, result)) {
      sendProblem(request, 422, result.code.c_str(), result.detail.c_str());
      return;
    }
    JsonDocument document;
    document["valid"] = true;
    document["dry_run"] = dry_run;
    document["config_version"] = config_.config().config_version;
    std::string response;
    serializeJson(document, response);
    sendJson(request, 200, response);
  });
  registerBodyRoute("/api/v1/setup/apply", HTTP_POST,
                    [this](AsyncWebServerRequest* request) {
    const std::string body = takeBody(request);
    if (!localSession(request, true) || config_.hasAdminPassword()) {
      sendProblem(request, 403, "setup_not_authorized", "First-run setup requires the setup session and closes after administrator creation.");
      return;
    }
    const ProvisioningResult result = provisioning_.apply(body);
    if (!result.ok) {
      sendProblem(request, 422, result.code.c_str(), result.detail.c_str());
      return;
    }
    sendJson(request, 200, "{\"status\":\"setup_applied\"}");
    queueMaintenance(MaintenanceAction::Reboot);
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
  if (!sameOrigin(request)) {
    sendProblem(request, 403, "origin_rejected", "Cross-origin API access is not allowed.");
    return false;
  }
  if (localSession(request, mutation)) return true;
  crypto::Key32 outbound{};
  crypto::Key32 inbound{};
  if (!config_.directionalKeys(outbound, inbound)) {
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
    sendProblem(request, result == AuthResult::ProtocolMismatch ? 409 : 401,
                authResultCode(result), "Server-to-device signature verification failed.", true);
    return false;
  }
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
    std::string body;
    for (const auto& record : page.records) body += record + "\n";
    sendJson(request, 200, body, "application/x-ndjson");
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
  if (maintenance_queue_ == nullptr || argument.size() >= sizeof(message.argument)) return false;
  message.action = action;
  std::memcpy(message.argument, argument.c_str(), argument.size());
  message.argument[argument.size()] = '\0';
  return xQueueSend(maintenance_queue_, &message, 0) == pdTRUE;
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
