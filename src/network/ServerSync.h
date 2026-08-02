#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

#include "app/Maintenance.h"
#include "config/ConfigService.h"
#include "core/HeapTelemetry.h"
#include "core/StringView.h"
#include "diagnostics/Diagnostics.h"
#include "meter/IMeter.h"
#include "network/ClockService.h"
#include "network/NetworkService.h"
#include "network/ServerSyncPolicy.h"
#include "network/ServerSyncScratch.h"
#include "storage/SdStorage.h"
#include "storage/StorageCoordinator.h"

namespace pm {

class ServerSync {
public:
  ServerSync(ConfigService &config, NetworkService &network,
             ClockService &clock, SdStorage &storage,
             StorageCoordinator &storage_coordinator,
             Diagnostics &diagnostics, IMeter &meter,
             QueueHandle_t maintenance_queue);
  void tick();
  void requestImmediateSync();
  SyncMetrics metrics() const;
  std::string availableFirmwareVersion() const;

private:
  struct HttpResult {
    int status{-1};
    const char *body{nullptr};
    std::size_t body_size{0U};
    std::string error;
    std::string problem_code;
    std::string tls_category;
    std::uint32_t retry_after_ms{0};
    bool local_resource_deferred{false};
  };

  bool enroll(std::uint32_t &retry_after_ms);
  bool heartbeat(std::uint32_t &retry_after_ms);
  bool pushReadings();
  bool pushEvents();
  bool fetchConfiguration();
  bool reportConfiguration(std::uint32_t version, const char *status,
                           const char *detail);
  bool checkFirmwareManifest();
  HttpResult request(const char *method, StringView endpoint,
                     const char *body, std::size_t body_size,
                     bool authenticated);
  HttpResult request(const char *method, StringView endpoint,
                     const char *body, bool authenticated) {
    return request(method, endpoint, body,
                   body == nullptr ? 0U : std::char_traits<char>::length(body),
                   authenticated);
  }
  HttpResult request(const char *method, StringView endpoint,
                     const std::string &body, bool authenticated) {
    return request(method, endpoint, body.data(), body.size(), authenticated);
  }
  bool heartbeatBody(ServerSyncBuffer &output) const;
  bool ensureTransportScratch();
  bool refreshTransportConfig();
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
  StorageCoordinator &storage_coordinator_;
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
  std::uint64_t last_immediate_sync_release_ack_{0};
  std::string reading_page_job_id_;
  std::string event_page_job_id_;
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
  ServerSyncScratch transport_scratch_;
  EspHeapTelemetry heap_telemetry_;
  ServerTransportConfig transport_config_;
  CompactServerSyncRuntimeConfig transport_runtime_config_{};
  std::string transport_host_;
  std::string transport_device_id_;
  std::string transport_boot_id_;
  std::uint16_t transport_port_{443U};
  std::uint64_t transport_config_generation_{0U};
  std::uint64_t next_transport_scratch_retry_ms_{0U};
  bool immediate_sync_{false};
  bool immediate_sync_release_recorded_{false};
  bool last_operation_locally_deferred_{false};
  bool fragmentation_deferred_{false};
  std::string available_firmware_version_;
};

} // namespace pm
