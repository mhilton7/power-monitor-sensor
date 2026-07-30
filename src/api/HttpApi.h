#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <string>

#include <ESPAsyncWebServer.h>

#include "app/Maintenance.h"
#include "config/ConfigService.h"
#include "diagnostics/Diagnostics.h"
#include "meter/IMeter.h"
#include "network/ClockService.h"
#include "network/NetworkService.h"
#include "ota/OtaService.h"
#include "provisioning/ProvisioningService.h"
#include "security/AuthService.h"
#include "storage/SdStorage.h"
#include "storage/StorageCoordinator.h"

namespace pm {

class HttpApi {
public:
  HttpApi(ConfigService &config, NetworkService &network, ClockService &clock,
          SdStorage &storage, StorageCoordinator &coordinator,
          Diagnostics &diagnostics, IMeter &meter, OtaService &ota,
          QueueHandle_t maintenance_queue);
  void begin();

private:
  static constexpr std::size_t kPasswordResultCapacity = 16U;
  static constexpr UBaseType_t kPasswordJobQueueCapacity = 8U;

  struct BodyBuffer {
    std::string body;
    bool overflow{false};
  };

  enum class PasswordJobKind : std::uint8_t {
    Login,
    Setup,
    ConfigUpdate,
    NetworkSettings,
    SyncAcknowledgement,
    Reenrollment,
  };

  struct PasswordJob {
    PasswordJobKind kind{PasswordJobKind::Login};
    std::string id;
    std::string body;
    std::uint64_t queued_ms{0};
    bool dry_run{false};
    bool ct_change_acknowledged{false};
  };

  struct PasswordJobResult {
    bool used{false};
    bool complete{false};
    bool success{false};
    PasswordJobKind kind{PasswordJobKind::Login};
    std::string id;
    std::string code;
    std::string detail;
    std::string response_json;
    int failure_status{422};
    std::uint64_t expires_ms{0};
    std::uint64_t duration_ms{0};
    crypto::Key32 creator_session_digest{};
    bool creator_session_bound{false};
  };

  static void passwordJobTaskEntry(void *context);
  static const char *passwordJobKindName(PasswordJobKind kind);
  void passwordJobTask();
  std::string queuePasswordJob(PasswordJobKind kind, const std::string &body,
                               bool dry_run = false,
                               bool ct_change_acknowledged = false,
                               const std::string &creator_session_token = {});
  bool passwordJobResult(const std::string &id, PasswordJobResult &result,
                         bool consume, TickType_t lock_timeout);
  void sendPasswordJobAccepted(AsyncWebServerRequest *request,
                               const std::string &id, bool asynchronous);
  void sendHistoryJobAccepted(AsyncWebServerRequest *request,
                              const std::string &id, bool ndjson,
                              bool asynchronous);
  bool applyNetworkSettings(const std::string &body, std::string &code,
                            std::string &detail, std::string &response_json);
  void registerReadRoutes();
  void registerMutationRoutes();
  void registerAction(const char *path, MaintenanceAction action,
                      const char *confirmation = nullptr,
                      bool require_elevated_local = false);
  void registerBodyRoute(const char *path, WebRequestMethod method,
                         ArRequestHandlerFunction handler);
  std::string takeBody(AsyncWebServerRequest *request) const;
  bool authorize(AsyncWebServerRequest *request, const std::string &body,
                 bool mutation, bool allow_local_session = true,
                 bool require_elevated_local = false);
  bool localSession(AsyncWebServerRequest *request, bool mutation,
                    bool require_elevated = false) const;
  bool sameOrigin(AsyncWebServerRequest *request) const;
  void createLocalSession(AsyncWebServerRequest *request, bool elevated);
  std::string cookieValue(AsyncWebServerRequest *request,
                          const char *name) const;
  void sendJson(AsyncWebServerRequest *request, int status,
                const std::string &body,
                const char *content_type = "application/json");
  void sendProblem(AsyncWebServerRequest *request, int status, const char *code,
                   const char *detail, bool rejected_signature = false,
                   bool rate_limited = false);
  void sendPage(AsyncWebServerRequest *request, const HistoryPage &page,
                bool ndjson);
  void buildPagePayload(const HistoryPage &page, bool ndjson,
                        const std::string &instance, int &status,
                        std::string &content_type, std::string &body) const;
  HistoryQuery parseHistoryQuery(AsyncWebServerRequest *request) const;
  bool queueMaintenance(MaintenanceAction action,
                        const std::string &argument = "");
  static std::uint64_t parseUtc(const String &value);

  ConfigService &config_;
  NetworkService &network_;
  ClockService &clock_;
  SdStorage &storage_;
  StorageCoordinator &coordinator_;
  Diagnostics &diagnostics_;
  IMeter &meter_;
  OtaService &ota_;
  ProvisioningService provisioning_;
  QueueHandle_t maintenance_queue_;
  QueueHandle_t password_job_queue_{nullptr};
  SemaphoreHandle_t password_result_mutex_{nullptr};
  TaskHandle_t password_job_task_{nullptr};
  std::array<PasswordJobResult, kPasswordResultCapacity> password_results_{};
  AsyncWebServer server_{80};
  RequestAuthenticator authenticator_;
  SessionManager sessions_;
  std::atomic<bool> login_job_pending_{false};
  std::atomic<std::uint32_t> login_failures_{0};
  std::atomic<std::uint64_t> login_allowed_at_ms_{0};
  std::uint64_t history_allowed_at_ms_{0};
  std::uint64_t api_window_started_ms_{0};
  std::uint16_t api_requests_in_window_{0};
};

} // namespace pm
