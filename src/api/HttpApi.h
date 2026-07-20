#pragma once

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
  HttpApi(ConfigService& config, NetworkService& network, ClockService& clock,
          SdStorage& storage, StorageCoordinator& coordinator,
          Diagnostics& diagnostics, IMeter& meter, OtaService& ota,
          QueueHandle_t maintenance_queue);
  void begin();

 private:
  struct BodyBuffer {
    std::string body;
    bool overflow{false};
  };

  void registerReadRoutes();
  void registerMutationRoutes();
  void registerAction(const char* path, MaintenanceAction action,
                      const char* confirmation = nullptr);
  void registerBodyRoute(const char* path, WebRequestMethod method,
                         ArRequestHandlerFunction handler);
  std::string takeBody(AsyncWebServerRequest* request) const;
  bool authorize(AsyncWebServerRequest* request, const std::string& body,
                 bool mutation);
  bool localSession(AsyncWebServerRequest* request, bool mutation) const;
  bool sameOrigin(AsyncWebServerRequest* request) const;
  std::string cookieValue(AsyncWebServerRequest* request, const char* name) const;
  void sendJson(AsyncWebServerRequest* request, int status,
                const std::string& body, const char* content_type = "application/json");
  void sendProblem(AsyncWebServerRequest* request, int status, const char* code,
                   const char* detail, bool rejected_signature = false,
                   bool rate_limited = false);
  void sendPage(AsyncWebServerRequest* request, const HistoryPage& page,
                bool ndjson);
  HistoryQuery parseHistoryQuery(AsyncWebServerRequest* request) const;
  bool queueMaintenance(MaintenanceAction action,
                        const std::string& argument = "");
  static std::uint64_t parseUtc(const String& value);

  ConfigService& config_;
  NetworkService& network_;
  ClockService& clock_;
  SdStorage& storage_;
  StorageCoordinator& coordinator_;
  Diagnostics& diagnostics_;
  IMeter& meter_;
  OtaService& ota_;
  ProvisioningService provisioning_;
  QueueHandle_t maintenance_queue_;
  AsyncWebServer server_{80};
  RequestAuthenticator authenticator_;
  SessionManager sessions_;
  std::uint32_t login_failures_{0};
  std::uint64_t login_allowed_at_ms_{0};
  std::uint64_t history_allowed_at_ms_{0};
  std::uint64_t api_window_started_ms_{0};
  std::uint16_t api_requests_in_window_{0};
};

}  // namespace pm
