#pragma once

#include <cstdint>

#include "diagnostics/Diagnostics.h"
#include "storage/SdStorage.h"

namespace pm {

class StorageCoordinator {
 public:
  StorageCoordinator(SdStorage& storage, Diagnostics& diagnostics);
  bool begin();
  bool enqueueRecord(const IntervalRecord& record);
  bool enqueueEvent(const std::string& code, const std::string& severity,
                    const std::string& detail, std::uint64_t utc_ms,
                    const std::string& boot_id);
  HistoryPage requestHistory(const HistoryQuery& query, bool events = false,
                             std::uint32_t timeout_ms = 5000);
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
    HistoryQuery query;
    HistoryPage page;
    bool events{false};
    SemaphoreHandle_t completed{nullptr};
    volatile bool caller_waiting{true};
  };
  struct Message {
    Type type;
    void* payload;
  };

  SdStorage& storage_;
  Diagnostics& diagnostics_;
  QueueHandle_t queue_{nullptr};
  std::uint64_t dropped_{0};
};

}  // namespace pm

