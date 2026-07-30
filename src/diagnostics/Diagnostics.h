#pragma once

#include <cstdint>
#include <string>

#include "config/ConfigService.h"
#include "core/Models.h"
#include "meter/IMeter.h"
#include "network/ClockService.h"
#include "network/NetworkService.h"
#include "storage/SdStorage.h"

namespace pm {

struct SyncMetrics {
  std::uint64_t heartbeat_successes{0};
  std::uint64_t heartbeat_failures{0};
  std::uint64_t batch_successes{0};
  std::uint64_t batch_failures{0};
  std::uint64_t events_successes{0};
  std::uint64_t events_failures{0};
  std::uint64_t authentication_rejections{0};
  std::uint64_t last_heartbeat_utc_ms{0};
  std::uint64_t last_sync_utc_ms{0};
  std::uint64_t transactions_started{0};
  std::uint64_t transactions_completed{0};
  std::uint64_t transactions_failed{0};
  std::uint32_t active_request_id{0};
  std::uint32_t stack_allocated_bytes{0};
  std::uint32_t stack_high_water_bytes{0};
  std::uint32_t stack_margin_percent{0};
  std::uint32_t free_internal_heap_bytes{0};
  std::uint32_t largest_internal_block_bytes{0};
  bool sync_in_progress{false};
  bool sync_pending{false};
  std::string last_error;
};

struct HttpMetrics {
  std::uint64_t requests{0};
  std::uint64_t status_2xx{0};
  std::uint64_t status_4xx{0};
  std::uint64_t status_5xx{0};
  std::uint64_t rejected_signatures{0};
  std::uint64_t rate_limited{0};
};

struct QueueMetrics {
  std::uint32_t storage_depth{0};
  std::uint32_t action_depth{0};
  std::uint64_t storage_dropped{0};
  std::uint64_t action_dropped{0};
};

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
  void recordHttpStatus(int status, bool rejected_signature = false,
                        bool rate_limited = false);
  HttpMetrics httpMetrics() const;
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
                             const MeterMetrics &meter) const;

private:
  bool lock(TickType_t timeout = pdMS_TO_TICKS(100)) const;
  void unlock() const;

  mutable SemaphoreHandle_t mutex_{nullptr};
  MeasurementSnapshot latest_;
  bool has_latest_{false};
  std::uint64_t committed_sequence_{0};
  std::uint32_t storage_queue_depth_{0};
  std::uint32_t action_queue_depth_{0};
  std::uint64_t storage_dropped_{0};
  std::uint64_t action_dropped_{0};
  SyncMetrics sync_;
  HttpMetrics http_;
};

} // namespace pm
