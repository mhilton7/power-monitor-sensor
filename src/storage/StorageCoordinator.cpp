#include "storage/StorageCoordinator.h"

#include <new>

#include "build_config.h"
#include "diagnostics/SerialLogger.h"

namespace pm {

StorageCoordinator::StorageCoordinator(SdStorage& storage,
                                       Diagnostics& diagnostics)
    : storage_(storage), diagnostics_(diagnostics) {}

bool StorageCoordinator::begin() {
  queue_ = xQueueCreate(build::OFFLINE_RECORD_QUEUE_DEPTH, sizeof(Message));
  PM_LOG_INFO("STORAGE", "COORDINATOR_INIT",
              "result=%s queue_capacity=%u ownership=microSD",
              queue_ == nullptr ? "failed" : "success",
              static_cast<unsigned>(build::OFFLINE_RECORD_QUEUE_DEPTH));
  return queue_ != nullptr;
}

bool StorageCoordinator::enqueueRecord(const IntervalRecord& record) {
  auto* copy = new (std::nothrow) IntervalRecord(record);
  if (copy == nullptr) {
    ++dropped_;
    PM_LOG_ERROR("QUEUE", "STORAGE_ALLOC_FAILED",
                 "error=PM-QUEUE-002 type=record dropped=%llu",
                 static_cast<unsigned long long>(dropped_));
    return false;
  }
  const Message message{Type::Record, copy};
  if (xQueueSend(queue_, &message, 0) != pdTRUE) {
    delete copy;
    ++dropped_;
    if (diag::SerialLogger::instance().allow("storage_queue_full", 10'000U)) {
      PM_LOG_ERROR(
          "QUEUE", "STORAGE_QUEUE_FULL",
          "error=PM-QUEUE-003 type=record depth=%lu capacity=%u dropped=%llu",
          static_cast<unsigned long>(depth()),
          static_cast<unsigned>(build::OFFLINE_RECORD_QUEUE_DEPTH),
          static_cast<unsigned long long>(dropped_));
    }
    return false;
  }
  return true;
}

bool StorageCoordinator::enqueueEvent(const std::string& code,
                                      const std::string& severity,
                                      const std::string& detail,
                                      const std::uint64_t utc_ms,
                                      const std::string& boot_id) {
  auto* event = new (std::nothrow) EventData{code, severity, detail, boot_id, utc_ms};
  if (event == nullptr) {
    ++dropped_;
    PM_LOG_ERROR("QUEUE", "STORAGE_ALLOC_FAILED",
                 "error=PM-QUEUE-002 type=event dropped=%llu",
                 static_cast<unsigned long long>(dropped_));
    return false;
  }
  const Message message{Type::Event, event};
  if (xQueueSend(queue_, &message, 0) != pdTRUE) {
    delete event;
    ++dropped_;
    if (diag::SerialLogger::instance().allow("event_queue_full", 10'000U)) {
      PM_LOG_ERROR(
          "QUEUE", "STORAGE_QUEUE_FULL",
          "error=PM-QUEUE-003 type=event depth=%lu capacity=%u dropped=%llu",
          static_cast<unsigned long>(depth()),
          static_cast<unsigned>(build::OFFLINE_RECORD_QUEUE_DEPTH),
          static_cast<unsigned long long>(dropped_));
    }
    return false;
  }
  return true;
}

HistoryPage StorageCoordinator::requestHistory(const HistoryQuery& query,
                                               const bool events,
                                               const std::uint32_t timeout_ms) {
  auto* request = new (std::nothrow) HistoryData{};
  if (request == nullptr) {
    PM_LOG_ERROR("STORAGE", "HISTORY_ALLOC_FAILED",
                 "error=PM-STORAGE-010");
    return {false, false, 0, 0, false, 0, {}, "out_of_memory"};
  }
  request->query = query;
  request->events = events;
  request->completed = xSemaphoreCreateBinary();
  if (request->completed == nullptr) {
    PM_LOG_ERROR("STORAGE", "HISTORY_SIGNAL_ALLOC_FAILED",
                 "error=PM-STORAGE-010");
    delete request;
    return {false, false, 0, 0, false, 0, {}, "out_of_memory"};
  }
  const Message message{Type::History, request};
  if (xQueueSend(queue_, &message, pdMS_TO_TICKS(100)) != pdTRUE) {
    PM_LOG_WARN("QUEUE", "HISTORY_QUEUE_FULL",
                "error=PM-QUEUE-003 depth=%lu",
                static_cast<unsigned long>(depth()));
    vSemaphoreDelete(request->completed);
    delete request;
    return {false, false, 0, 0, false, 0, {}, "storage_queue_full"};
  }
  if (xSemaphoreTake(request->completed, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
    request->caller_waiting = false;
    PM_LOG_WARN("STORAGE", "HISTORY_TIMEOUT",
                "error=PM-STORAGE-011 timeout_ms=%lu",
                static_cast<unsigned long>(timeout_ms));
    return {false, false, 0, 0, false, 0, {}, "storage_timeout"};
  }
  HistoryPage page = std::move(request->page);
  vSemaphoreDelete(request->completed);
  delete request;
  return page;
}

void StorageCoordinator::taskLoop() {
  PM_LOG_INFO(
      "TASK", "TASK_STARTED",
      "name=StorageTask core=%d priority=%u stack_words=%u watchdog=false",
      xPortGetCoreID(), static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
      8192U);
  Message message{};
  IntervalRecord* pending_record = nullptr;
  std::uint64_t next_remount_ms = 0;
  for (;;) {
    if (pending_record != nullptr) {
      if (storage_.append(*pending_record)) {
        diagnostics_.setCommittedSequence(pending_record->sequence);
        PM_LOG_TRACE("STORAGE", "RECORD_COMMITTED",
                     "sequence=%llu queue_depth=%lu",
                     static_cast<unsigned long long>(
                         pending_record->sequence),
                     static_cast<unsigned long>(depth()));
        delete pending_record;
        pending_record = nullptr;
      } else {
        const std::uint64_t now = millis();
        if (now >= next_remount_ms) {
          PM_LOG_WARN("STORAGE", "REMOUNT_SCHEDULED",
                      "error=PM-SD-002 retry_interval_ms=30000");
          storage_.remount(storage_.health().spi_hz);
          next_remount_ms = now + 30'000U;
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
        continue;
      }
    }
    if (xQueueReceive(queue_, &message, pdMS_TO_TICKS(250)) != pdTRUE) {
      continue;
    }
    switch (message.type) {
      case Type::Record:
        pending_record = static_cast<IntervalRecord*>(message.payload);
        break;
      case Type::Event: {
        auto* event = static_cast<EventData*>(message.payload);
        storage_.appendEvent(event->code, event->severity, event->detail,
                             event->utc_ms, event->boot_id);
        delete event;
        break;
      }
      case Type::History: {
        auto* request = static_cast<HistoryData*>(message.payload);
        request->page = request->events ? storage_.readEvents(request->query)
                                       : storage_.readPage(request->query);
        if (request->caller_waiting) {
          xSemaphoreGive(request->completed);
        } else {
          vSemaphoreDelete(request->completed);
          delete request;
        }
        break;
      }
      case Type::Remount:
        storage_.remount(storage_.health().spi_hz);
        break;
    }
  }
}

std::uint32_t StorageCoordinator::depth() const {
  return queue_ == nullptr ? 0 : uxQueueMessagesWaiting(queue_);
}

std::uint64_t StorageCoordinator::dropped() const { return dropped_; }

}  // namespace pm
