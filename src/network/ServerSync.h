#pragma once

#include <cstdint>
#include <string>

#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

#include "app/Maintenance.h"
#include "config/ConfigService.h"
#include "diagnostics/Diagnostics.h"
#include "meter/IMeter.h"
#include "network/ClockService.h"
#include "network/NetworkService.h"
#include "network/ServerSyncPolicy.h"
#include "storage/SdStorage.h"

namespace pm {

class ServerSync {
public:
  ServerSync(ConfigService &config, NetworkService &network,
             ClockService &clock, SdStorage &storage, Diagnostics &diagnostics,
             IMeter &meter, QueueHandle_t maintenance_queue);
  void tick();
  void requestImmediateSync();
  SyncMetrics metrics() const;
  std::string availableFirmwareVersion() const;

private:
  struct HttpResult {
    int status{-1};
    std::string body;
    std::string error;
    std::string problem_code;
    std::string tls_category;
    std::uint32_t retry_after_ms{0};
  };

  bool enroll(std::uint32_t &retry_after_ms);
  bool heartbeat(std::uint32_t &retry_after_ms);
  bool pushReadings();
  bool pushEvents();
  bool fetchConfiguration();
  bool reportConfiguration(std::uint32_t version, const char *status,
                           const char *detail);
  bool checkFirmwareManifest();
  HttpResult request(const char *method, const std::string &endpoint,
                     std::string body, bool authenticated);
  std::string heartbeatBody() const;
  std::uint32_t heartbeatDelayMs() const;
  std::uint32_t retryDelayMs(std::uint32_t retry_after_ms);
  std::uint32_t operationRetryDelayMs(std::uint32_t &attempt,
                                      std::uint32_t retry_after_ms,
                                      const char *operation);
  void logTaskCheckpoint(const char *checkpoint);

  ConfigService &config_;
  NetworkService &network_;
  ClockService &clock_;
  SdStorage &storage_;
  Diagnostics &diagnostics_;
  IMeter &meter_;
  QueueHandle_t maintenance_queue_{nullptr};
  SyncMetrics metrics_;
  std::uint64_t next_heartbeat_ms_{0};
  std::uint64_t next_retry_ms_{0};
  std::uint64_t retry_after_gate_ms_{0};
  std::uint64_t next_config_poll_ms_{0};
  std::uint64_t next_manifest_poll_ms_{0};
  std::uint64_t next_reading_push_ms_{0};
  std::uint64_t next_event_push_ms_{0};
  std::uint64_t offline_since_ms_{0};
  std::uint64_t event_cursor_{0};
  std::uint32_t request_sequence_{0};
  std::uint32_t retry_attempt_{0};
  std::uint32_t reading_retry_attempt_{0};
  std::uint32_t event_retry_attempt_{0};
  std::uint32_t heartbeat_interval_override_seconds_{0};
  std::uint32_t pending_config_version_{0};
  std::uint64_t pending_config_generation_{0};
  std::uint64_t pending_config_started_ms_{0};
  std::uint64_t next_config_validation_attempt_ms_{0};
  std::uint64_t observed_reenrollment_generation_{0};
  bool pending_config_validation_{false};
  bool pending_config_rollback_report_{false};
  std::string pending_config_report_detail_{"post_apply_connectivity_failed"};
  sync_policy::SingleFlightGate single_flight_;
  sync_policy::EndpointAddressCache endpoint_address_cache_;
  bool immediate_sync_{false};
  std::string available_firmware_version_;
};

} // namespace pm
