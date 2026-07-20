#include "storage/StorageCoordinator.h"

#include <new>

#include "build_config.h"

namespace pm {

StorageCoordinator::StorageCoordinator(SdStorage& storage,
                                       Diagnostics& diagnostics)
    : storage_(storage), diagnostics_(diagnostics) {}

bool StorageCoordinator::begin() {
  queue_ = xQueueCreate(build::OFFLINE_RECORD_QUEUE_DEPTH, sizeof(Message));
  return queue_ != nullptr;
}

bool StorageCoordinator::enqueueRecord(const IntervalRecord& record) {
  auto* copy = new (std::nothrow) IntervalRecord(record);
  if (copy == nullptr) {
    ++dropped_;
    return false;
  }
  const Message message{Type::Record, copy};
  if (xQueueSend(queue_, &message, 0) != pdTRUE) {
    delete copy;
    ++dropped_;
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
    return false;
  }
  const Message message{Type::Event, event};
  if (xQueueSend(queue_, &message, 0) != pdTRUE) {
    delete event;
    ++dropped_;
    return false;
  }
  return true;
}

HistoryPage StorageCoordinator::requestHistory(const HistoryQuery& query,
                                               const bool events,
                                               const std::uint32_t timeout_ms) {
  auto* request = new (std::nothrow) HistoryData{};
  if (request == nullptr) {
    return {false, false, 0, 0, false, 0, {}, "out_of_memory"};
  }
  request->query = query;
  request->events = events;
  request->completed = xSemaphoreCreateBinary();
  if (request->completed == nullptr) {
    delete request;
    return {false, false, 0, 0, false, 0, {}, "out_of_memory"};
  }
  const Message message{Type::History, request};
  if (xQueueSend(queue_, &message, pdMS_TO_TICKS(100)) != pdTRUE) {
    vSemaphoreDelete(request->completed);
    delete request;
    return {false, false, 0, 0, false, 0, {}, "storage_queue_full"};
  }
  if (xSemaphoreTake(request->completed, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
    request->caller_waiting = false;
    return {false, false, 0, 0, false, 0, {}, "storage_timeout"};
  }
  HistoryPage page = std::move(request->page);
  vSemaphoreDelete(request->completed);
  delete request;
  return page;
}

void StorageCoordinator::taskLoop() {
  Message message{};
  IntervalRecord* pending_record = nullptr;
  std::uint64_t next_remount_ms = 0;
  for (;;) {
    if (pending_record != nullptr) {
      if (storage_.append(*pending_record)) {
        diagnostics_.setCommittedSequence(pending_record->sequence);
        delete pending_record;
        pending_record = nullptr;
      } else {
        const std::uint64_t now = millis();
        if (now >= next_remount_ms) {
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
