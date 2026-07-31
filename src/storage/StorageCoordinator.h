#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <string>

#include "diagnostics/Diagnostics.h"
#include "storage/SdStorage.h"

namespace pm {

class StorageCoordinator {
public:
  StorageCoordinator(SdStorage &storage, Diagnostics &diagnostics);
  bool begin();
  bool enqueueRecord(const IntervalRecord &record);
  bool enqueueEvent(const std::string &code, const std::string &severity,
                    const std::string &detail, std::uint64_t utc_ms,
                    const std::string &boot_id);
  std::string queueHistory(const HistoryQuery &query, bool events = false,
                           bool primary_sync = false);
  bool historyResult(const std::string &id, HistoryPage &page, bool &complete,
                     bool consume = false,
                     TickType_t lock_timeout = pdMS_TO_TICKS(25));
  void taskLoop();
  std::uint32_t depth() const;
  std::uint64_t dropped() const;

private:
  enum class Type : std::uint8_t { Record, Event, History, Remount };
  struct EventData {
    std::string code;
    std::string severity;
    std::string detail;
    std::string boot_id;
    std::uint64_t utc_ms{0};
  };
  struct HistoryData {
    std::string id;
    HistoryQuery query;
    bool events{false};
    bool primary_sync{false};
  };
  struct HistoryResult {
    bool used{false};
    bool complete{false};
    std::string id;
    HistoryPage page;
    std::uint64_t expires_ms{0};
  };
  struct Message {
    Type type;
    void *payload;
  };

  bool remountStorage();

  SdStorage &storage_;
  Diagnostics &diagnostics_;
  QueueHandle_t write_queue_{nullptr};
  QueueHandle_t control_queue_{nullptr};
  SemaphoreHandle_t history_mutex_{nullptr};
  // Each local API result is bounded to 12 KiB. Two slots keep
  // concurrent UI/export work possible without allowing abandoned jobs to
  // retain more payload memory than the ESP32-S3 internal heap can sustain.
  std::array<HistoryResult, 2> history_results_{};
  std::atomic<std::uint32_t> next_history_id_{1};
  std::atomic<std::uint64_t> dropped_{0};
};

} // namespace pm
