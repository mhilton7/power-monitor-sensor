#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "config/ConfigService.h"
#include "core/MemoryPressurePolicy.h"
#include "core/Models.h"
#include "meter/IMeter.h"
#include "network/ClockService.h"
#include "network/NetworkService.h"
#include "storage/SdStorage.h"

namespace pm {

struct SyncMetrics {
  std::uint64_t heartbeat_requests_sent{0};
  std::uint64_t heartbeat_http_200{0};
  std::uint64_t heartbeat_server_accepted{0};
  std::uint64_t heartbeat_successes{0};
  std::uint64_t heartbeat_failures{0};
  std::uint64_t heartbeat_transport_successes{0};
  std::uint64_t heartbeat_contract_failures{0};
  std::uint64_t heartbeat_transport_failures{0};
  std::uint64_t heartbeat_authentication_failures{0};
  std::uint64_t sequence_reconciliation_requests{0};
  std::uint64_t sequence_reconciliation_deferred{0};
  std::uint64_t sequence_reconciliation_failures{0};
  std::uint64_t sequence_cursor_conflicts{0};
  std::uint64_t sequence_cursor_regressions{0};
  std::uint64_t batch_successes{0};
  std::uint64_t batch_failures{0};
  std::uint64_t events_successes{0};
  std::uint64_t events_failures{0};
  std::uint64_t authentication_rejections{0};
  std::uint64_t last_heartbeat_utc_ms{0};
  std::uint64_t last_heartbeat_attempt_monotonic_ms{0};
  std::uint64_t last_heartbeat_success_monotonic_ms{0};
  std::uint64_t last_sync_utc_ms{0};
  std::uint64_t transactions_started{0};
  std::uint64_t transactions_completed{0};
  std::uint64_t transactions_failed{0};
  std::uint64_t local_resource_deferrals{0};
  std::uint64_t fragmentation_deferrals{0};
  std::uint64_t fragmentation_recoveries{0};
  std::uint64_t heartbeat_buffer_reuses{0};
  std::uint64_t heartbeat_buffer_growths{0};
  std::uint64_t response_buffer_reuses{0};
  std::uint64_t response_buffer_growths{0};
  std::uint64_t tls_requests_admitted{0};
  std::uint64_t tls_requests_rejected_heap{0};
  std::uint64_t tls_requests_rejected_stack{0};
  std::uint32_t active_request_id{0};
  std::uint32_t stack_allocated_bytes{0};
  std::uint32_t stack_high_water_bytes{0};
  std::uint32_t stack_margin_percent{0};
  std::uint32_t free_internal_heap_bytes{0};
  std::uint32_t largest_internal_block_bytes{0};
  std::uint32_t minimum_free_internal_heap_bytes{0};
  std::uint32_t largest_internal_before_tls{0};
  std::uint32_t largest_internal_after_tls{0};
  std::uint32_t largest_internal_after_cleanup{0};
  std::uint32_t consecutive_local_deferrals{0};
  bool sync_in_progress{false};
  bool sync_pending{false};
  bool primary_storage_pending{false};
  bool durable_reading_backlog{false};
  std::string last_heartbeat_result{"never_attempted"};
  std::string last_local_deferral_reason;
  std::string last_error;
};

struct CompactSyncMetrics {
  std::uint64_t last_heartbeat_utc_ms{0U};
  std::uint64_t last_heartbeat_attempt_monotonic_ms{0U};
  std::uint64_t last_heartbeat_success_monotonic_ms{0U};
  std::uint32_t consecutive_local_deferrals{0U};
  std::array<char, 33> last_heartbeat_result{};
  std::array<char, 65> last_local_deferral_reason{};
  std::array<char, 65> last_error{};
  bool truncated{false};
};

struct HttpMetrics {
  std::uint64_t requests{0};
  std::uint64_t status_2xx{0};
  std::uint64_t status_4xx{0};
  std::uint64_t status_5xx{0};
  std::uint64_t rejected_signatures{0};
  std::uint64_t rate_limited{0};
  std::uint64_t browser_session_rejections{0};
  std::uint64_t malformed_auth_header_rejections{0};
  std::uint64_t browser_rate_limited{0};
  std::uint64_t server_hmac_rate_limited{0};
  std::uint64_t browser_requests_accepted{0};
  std::uint64_t browser_requests_session_expired{0};
  std::uint64_t browser_requests_session_invalid{0};
  std::uint64_t browser_requests_csrf_rejected{0};
  std::uint64_t server_hmac_requests_accepted{0};
  std::uint64_t server_hmac_headers_incomplete{0};
  std::uint64_t server_hmac_protocol_mismatch{0};
  std::uint64_t server_hmac_device_mismatch{0};
  std::uint64_t server_hmac_timestamp_rejected{0};
  std::uint64_t server_hmac_nonce_rejected{0};
  std::uint64_t server_hmac_body_hash_rejected{0};
  std::uint64_t server_hmac_signature_rejected{0};
  std::uint64_t ui_status_requests{0};
  std::uint64_t ui_status_responses{0};
  std::uint64_t ui_status_response_bytes{0};
  std::uint64_t ui_status_pool_exhaustions{0};
  std::uint64_t ui_status_dynamic_allocation_failures{0};
  std::uint64_t ui_status_response_object_allocations{0};
  std::uint64_t ui_status_response_object_releases{0};
  std::uint32_t ui_status_response_object_bytes{0};
  std::uint32_t largest_internal_before_ui{0};
  std::uint32_t largest_internal_after_ui{0};
  std::uint32_t largest_internal_before_ui_response_object{0};
  std::uint32_t largest_internal_after_ui_response_object{0};
  std::uint64_t ui_setup_requests{0};
  std::uint64_t ui_diagnostics_requests{0};
  std::uint64_t ui_heavy_requests_deferred{0};
  std::uint64_t local_response_allocation_failures{0};
  std::uint32_t peak_local_http_requests{0};
};

enum class UiRequestKind : std::uint8_t { Status, Setup, Diagnostics };

enum class BrowserAuthMetric : std::uint8_t {
  Accepted,
  SessionExpired,
  SessionInvalid,
  CsrfRejected,
};

enum class ServerHmacMetric : std::uint8_t {
  Accepted,
  HeadersIncomplete,
  ProtocolMismatch,
  DeviceMismatch,
  TimestampRejected,
  NonceRejected,
  BodyHashRejected,
  SignatureRejected,
};

struct QueueMetrics {
  std::uint32_t storage_depth{0};
  std::uint32_t action_depth{0};
  std::uint64_t storage_dropped{0};
  std::uint64_t action_dropped{0};
};

struct LocalSessionDiagnostics {
  std::uint32_t capacity{0};
  std::uint32_t active{0};
  std::uint32_t peak_active{0};
  std::uint64_t created{0};
  std::uint64_t reused{0};
  std::uint64_t refreshed{0};
  std::uint64_t expired{0};
  std::uint64_t invalid{0};
  std::uint64_t revoked{0};
  std::uint64_t capacity_rejections{0};
};

struct TaskRuntimeMetric {
  std::string name;
  std::uint32_t configured_stack_bytes{0};
  std::uint32_t high_water_bytes{0};
  std::uint32_t margin_percent{0};
  std::uint32_t priority{0};
  std::int8_t core{-1};
  bool running{false};
  bool watchdog{false};
};

inline constexpr std::size_t kTaskRuntimeMetricCapacity = 10U;

class Diagnostics {
public:
  Diagnostics();
  void setLatest(const MeasurementSnapshot &sample);
  bool latest(MeasurementSnapshot &sample) const;
  void setCommittedSequence(std::uint64_t sequence);
  std::uint64_t committedSequence() const;
  void setQueueDepths(std::uint32_t storage_depth, std::uint32_t action_depth,
                      std::uint64_t storage_dropped,
                      std::uint64_t action_dropped);
  QueueMetrics queueMetrics() const;
  void setSyncMetrics(const SyncMetrics &metrics);
  SyncMetrics syncMetrics() const;
  CompactSyncMetrics compactSyncMetrics() const;
  void setMemoryPressureMetrics(const MemoryPressureMetrics &metrics);
  MemoryPressureMetrics memoryPressureMetrics() const;
  bool acquireHighMemoryOperation(
      TickType_t timeout = pdMS_TO_TICKS(5000)) const;
  void releaseHighMemoryOperation() const;
  void recordHttpStatus(int status, bool rejected_signature = false,
                        bool rate_limited = false);
  void recordBrowserSessionRejection();
  void recordMalformedAuthHeaderRejection();
  void recordBrowserAuth(BrowserAuthMetric result);
  void recordServerHmac(ServerHmacMetric result);
  void recordAuthRateLimit(bool browser_session);
  void recordUiRequest(UiRequestKind kind);
  void recordUiStatusResponse(std::size_t bytes,
                              std::uint32_t largest_internal_before,
                              std::uint32_t largest_internal_after,
                              std::uint32_t largest_before_response_object,
                              std::uint32_t largest_after_response_object,
                              std::size_t response_object_bytes);
  void recordUiStatusResponseObjectRelease();
  void recordUiStatusPoolExhaustion();
  void recordUiStatusDynamicAllocationFailure();
  void recordHeavyUiDeferral();
  void recordLocalResponseAllocationFailure();
  HttpMetrics httpMetrics() const;
  void setTaskMetrics(
      const std::array<TaskRuntimeMetric, kTaskRuntimeMetricCapacity> &metrics)
      const;
  std::array<TaskRuntimeMetric, kTaskRuntimeMetricCapacity>
  taskMetrics() const;
  std::string healthJson(const ConfigService &config,
                         const NetworkStatus &network,
                         const ClockService &clock,
                         const StorageHealth &storage,
                         const MeterMetrics &meter) const;
  std::string liveJson(const ConfigService &config, const ClockService &clock,
                       const char *meter_method) const;
  std::string metricsJson(const StorageHealth &storage,
                          const MeterMetrics &meter) const;
  std::string redactedBundle(const ConfigService &config,
                             const NetworkStatus &network,
                             const ClockService &clock,
                             const StorageHealth &storage,
                             const MeterMetrics &meter,
                             const LocalSessionDiagnostics &sessions,
                             const WifiDisconnectSnapshot &wifi_events) const;

private:
  bool lock(TickType_t timeout = pdMS_TO_TICKS(100)) const;
  void unlock() const;

  mutable SemaphoreHandle_t mutex_{nullptr};
  mutable SemaphoreHandle_t high_memory_mutex_{nullptr};
  MeasurementSnapshot latest_;
  bool has_latest_{false};
  std::uint64_t committed_sequence_{0};
  std::uint32_t storage_queue_depth_{0};
  std::uint32_t action_queue_depth_{0};
  std::uint64_t storage_dropped_{0};
  std::uint64_t action_dropped_{0};
  SyncMetrics sync_;
  MemoryPressureMetrics memory_pressure_;
  HttpMetrics http_;
  mutable std::array<TaskRuntimeMetric, kTaskRuntimeMetricCapacity>
      task_metrics_{};
};

} // namespace pm
