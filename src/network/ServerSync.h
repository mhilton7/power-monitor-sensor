#pragma once

#include <cstdint>
#include <string>

#include "config/ConfigService.h"
#include "diagnostics/Diagnostics.h"
#include "meter/IMeter.h"
#include "network/ClockService.h"
#include "network/NetworkService.h"
#include "storage/SdStorage.h"

namespace pm {

class ServerSync {
 public:
  ServerSync(ConfigService& config, NetworkService& network,
             ClockService& clock, SdStorage& storage, Diagnostics& diagnostics,
             IMeter& meter);
  void tick();
  void requestImmediateSync();
  SyncMetrics metrics() const;
  std::string availableFirmwareVersion() const;

 private:
  struct HttpResult {
    int status{-1};
    std::string body;
    std::string error;
  };

  bool enroll();
  bool heartbeat();
  bool pushReadings();
  bool pushEvents();
  bool fetchConfiguration();
  bool reportConfiguration(std::uint32_t version, const char* status,
                           const char* detail);
  bool checkFirmwareManifest();
  HttpResult request(const char* method, const std::string& endpoint,
                     const std::string& body, bool authenticated);
  std::string heartbeatBody() const;
  std::uint32_t heartbeatDelayMs() const;
  std::uint32_t retryDelayMs();

  ConfigService& config_;
  NetworkService& network_;
  ClockService& clock_;
  SdStorage& storage_;
  Diagnostics& diagnostics_;
  IMeter& meter_;
  SyncMetrics metrics_;
  std::uint64_t next_heartbeat_ms_{0};
  std::uint64_t next_retry_ms_{0};
  std::uint64_t next_config_poll_ms_{0};
  std::uint64_t next_manifest_poll_ms_{0};
  std::uint64_t next_event_push_ms_{0};
  std::uint64_t event_cursor_{0};
  std::uint32_t retry_attempt_{0};
  std::uint32_t heartbeat_interval_override_seconds_{0};
  std::uint32_t pending_config_version_{0};
  std::uint64_t pending_config_started_ms_{0};
  std::uint64_t next_config_validation_attempt_ms_{0};
  bool pending_config_validation_{false};
  bool pending_config_rollback_report_{false};
  bool immediate_sync_{false};
  std::string available_firmware_version_;
};

}  // namespace pm
