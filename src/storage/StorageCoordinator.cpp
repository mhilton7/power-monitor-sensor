#include "storage/StorageCoordinator.h"

#include <cstdio>
#include <new>

#include <esp_timer.h>

#include "app/TaskConfig.h"
#include "build_config.h"
#include "diagnostics/SerialLogger.h"

namespace pm {
namespace {

std::uint64_t monotonicMs() {
  return static_cast<std::uint64_t>(esp_timer_get_time()) / 1000U;
}

class HighMemoryLease final {
public:
  explicit HighMemoryLease(Diagnostics &diagnostics,
                           const TickType_t timeout = pdMS_TO_TICKS(5000))
      : diagnostics_(diagnostics),
        acquired_(diagnostics_.acquireHighMemoryOperation(timeout)) {}

  ~HighMemoryLease() {
    if (acquired_) {
      diagnostics_.releaseHighMemoryOperation();
    }
  }

  explicit operator bool() const { return acquired_; }

private:
  Diagnostics &diagnostics_;
  bool acquired_{false};
};

} // namespace

StorageCoordinator::StorageCoordinator(SdStorage &storage,
                                       Diagnostics &diagnostics)
    : storage_(storage), diagnostics_(diagnostics) {}

bool StorageCoordinator::begin() {
  write_queue_ =
      xQueueCreate(build::OFFLINE_RECORD_QUEUE_DEPTH, sizeof(Message));
  control_queue_ = xQueueCreate(8, sizeof(Message));
  history_mutex_ = xSemaphoreCreateMutex();
  const bool ready = write_queue_ != nullptr && control_queue_ != nullptr &&
                     history_mutex_ != nullptr;
  PM_LOG_INFO("STORAGE", "COORDINATOR_INIT",
              "result=%s write_queue_capacity=%u control_queue_capacity=8 "
              "ownership=microSD",
              ready ? "success" : "failed",
              static_cast<unsigned>(build::OFFLINE_RECORD_QUEUE_DEPTH));
  return ready;
}

bool StorageCoordinator::enqueueRecord(const IntervalRecord &record) {
  auto *copy = new (std::nothrow) IntervalRecord(record);
  if (copy == nullptr) {
    dropped_.fetch_add(1, std::memory_order_relaxed);
    PM_LOG_ERROR("QUEUE", "STORAGE_ALLOC_FAILED",
                 "error=PM-QUEUE-002 type=record dropped=%llu",
                 static_cast<unsigned long long>(dropped()));
    return false;
  }
  const Message message{Type::Record, copy};
  if (xQueueSend(write_queue_, &message, 0) != pdTRUE) {
    delete copy;
    dropped_.fetch_add(1, std::memory_order_relaxed);
    if (diag::SerialLogger::instance().allow("storage_queue_full", 10'000U)) {
      PM_LOG_ERROR(
          "QUEUE", "STORAGE_QUEUE_FULL",
          "error=PM-QUEUE-003 type=record depth=%lu capacity=%u dropped=%llu",
          static_cast<unsigned long>(depth()),
          static_cast<unsigned>(build::OFFLINE_RECORD_QUEUE_DEPTH),
          static_cast<unsigned long long>(dropped()));
    }
    return false;
  }
  return true;
}

bool StorageCoordinator::enqueueEvent(const std::string &code,
                                      const std::string &severity,
                                      const std::string &detail,
                                      const std::uint64_t utc_ms,
                                      const std::string &boot_id) {
  auto *event =
      new (std::nothrow) EventData{code, severity, detail, boot_id, utc_ms};
  if (event == nullptr) {
    dropped_.fetch_add(1, std::memory_order_relaxed);
    PM_LOG_ERROR("QUEUE", "STORAGE_ALLOC_FAILED",
                 "error=PM-QUEUE-002 type=event dropped=%llu",
                 static_cast<unsigned long long>(dropped()));
    return false;
  }
  const Message message{Type::Event, event};
  if (xQueueSend(write_queue_, &message, 0) != pdTRUE) {
    delete event;
    dropped_.fetch_add(1, std::memory_order_relaxed);
    if (diag::SerialLogger::instance().allow("event_queue_full", 10'000U)) {
      PM_LOG_ERROR(
          "QUEUE", "STORAGE_QUEUE_FULL",
          "error=PM-QUEUE-003 type=event depth=%lu capacity=%u dropped=%llu",
          static_cast<unsigned long>(depth()),
          static_cast<unsigned>(build::OFFLINE_RECORD_QUEUE_DEPTH),
          static_cast<unsigned long long>(dropped()));
    }
    return false;
  }
  return true;
}

std::string StorageCoordinator::queueHistory(const HistoryQuery &query,
                                             const bool events,
                                             const bool primary_sync) {
  if (control_queue_ == nullptr || history_mutex_ == nullptr) {
    return {};
  }
  const std::uint64_t now = monotonicMs();
  if (xSemaphoreTake(history_mutex_, pdMS_TO_TICKS(25)) != pdTRUE) {
    PM_LOG_WARN("STORAGE", "HISTORY_RESULT_LOCK_TIMEOUT",
                "error=PM-STORAGE-012 phase=queue");
    return {};
  }
  HistoryResult *slot = nullptr;
  for (auto &candidate : history_results_) {
    // A FAT directory scan can legitimately take longer than the completed
    // result retention window. Never recycle an in-progress slot: doing so
    // loses the only handle to the running StorageTask job and causes the
    // caller to queue the same expensive scan again.
    if (!candidate.used ||
        (candidate.complete && candidate.expires_ms <= now)) {
      slot = &candidate;
      break;
    }
  }
  if (slot == nullptr) {
    xSemaphoreGive(history_mutex_);
    PM_LOG_WARN("STORAGE", "HISTORY_RESULT_TABLE_FULL",
                "error=PM-STORAGE-013 capacity=%u",
                static_cast<unsigned>(history_results_.size()));
    return {};
  }
  char id[25]{};
  const std::uint32_t sequence =
      next_history_id_.fetch_add(1, std::memory_order_relaxed);
  std::snprintf(id, sizeof(id), "%08lx%08lx",
                static_cast<unsigned long>(now & 0xFFFFFFFFULL),
                static_cast<unsigned long>(sequence));
  *slot = {};
  slot->used = true;
  slot->id = id;
  // expires_ms applies only after StorageTask publishes a completed result.
  // In-progress jobs remain addressable for however long the bounded scan
  // takes.
  slot->expires_ms = 0;
  xSemaphoreGive(history_mutex_);

  auto *request = new (std::nothrow) HistoryData{};
  if (request == nullptr) {
    PM_LOG_ERROR("STORAGE", "HISTORY_ALLOC_FAILED", "error=PM-STORAGE-010");
    if (xSemaphoreTake(history_mutex_, pdMS_TO_TICKS(25)) == pdTRUE) {
      if (slot->used && slot->id == id)
        *slot = {};
      xSemaphoreGive(history_mutex_);
    }
    return {};
  }
  request->id = id;
  request->query = query;
  request->events = events;
  request->primary_sync = primary_sync;
  const Message message{Type::History, request};
  const BaseType_t queued =
      primary_sync ? xQueueSendToFront(control_queue_, &message, 0)
                   : xQueueSend(control_queue_, &message, 0);
  if (queued != pdTRUE) {
    PM_LOG_WARN(
        "QUEUE", "HISTORY_QUEUE_FULL", "error=PM-QUEUE-003 control_depth=%lu",
        static_cast<unsigned long>(uxQueueMessagesWaiting(control_queue_)));
    delete request;
    if (xSemaphoreTake(history_mutex_, pdMS_TO_TICKS(25)) == pdTRUE) {
      if (slot->used && slot->id == id)
        *slot = {};
      xSemaphoreGive(history_mutex_);
    }
    return {};
  }
  PM_LOG_DEBUG(
      "STORAGE", "HISTORY_JOB_QUEUED", "job=%s events=%s control_depth=%lu", id,
      events ? "true" : "false",
      static_cast<unsigned long>(uxQueueMessagesWaiting(control_queue_)));
  return id;
}

bool StorageCoordinator::historyResult(const std::string &id, HistoryPage &page,
                                       bool &complete, const bool consume,
                                       const TickType_t lock_timeout) {
  complete = false;
  if (id.empty() || history_mutex_ == nullptr ||
      xSemaphoreTake(history_mutex_, lock_timeout) != pdTRUE) {
    return false;
  }
  const std::uint64_t now = monotonicMs();
  bool found = false;
  for (auto &candidate : history_results_) {
    if (candidate.used && candidate.complete &&
        candidate.expires_ms <= now) {
      candidate = {};
      continue;
    }
    if (candidate.used && candidate.id == id) {
      found = true;
      complete = candidate.complete;
      if (complete) {
        if (consume) {
          page = std::move(candidate.page);
        } else {
          page = candidate.page;
        }
      }
      if (consume && complete)
        candidate = {};
      break;
    }
  }
  xSemaphoreGive(history_mutex_);
  return found;
}

void StorageCoordinator::taskLoop() {
  PM_LOG_INFO(
      "TASK", "TASK_STARTED",
      "name=StorageTask core=%d priority=%u stack_bytes=%u watchdog=false",
      xPortGetCoreID(), static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
      static_cast<unsigned>(task_config::kStorageStackBytes));
  Message message{};
  IntervalRecord *pending_record = nullptr;
  std::uint64_t next_remount_ms = 0;
  std::uint64_t next_record_retry_ms = 0;
  for (;;) {
    if (xQueueReceive(control_queue_, &message, 0) == pdTRUE) {
      if (message.type == Type::History) {
        auto *request = static_cast<HistoryData *>(message.payload);
        HistoryPage page;
        const SyncMetrics sync = diagnostics_.syncMetrics();
        const bool local_deferred =
            !request->primary_sync &&
            (sync.last_heartbeat_utc_ms == 0U ||
             sync.durable_reading_backlog);
        if (local_deferred) {
          page.error_code = "primary_sync_has_priority";
          PM_LOG_INFO(
              "STORAGE", "LOCAL_HISTORY_DEFERRED",
              "reason=%s events=%s retryable=true",
              sync.last_heartbeat_utc_ms == 0U ? "first_heartbeat_pending"
                                               : "reading_backlog_active",
              request->events ? "true" : "false");
        } else {
          HighMemoryLease memory_lease(diagnostics_);
          if (memory_lease) {
            page = request->events ? storage_.readEvents(request->query)
                                   : storage_.readPage(request->query);
          } else {
            page.error_code = "high_memory_operation_busy";
            PM_LOG_WARN(
                "STORAGE", "HISTORY_MEMORY_GATE_TIMEOUT",
                "error=PM-STORAGE-014 events=%s retryable=true",
                request->events ? "true" : "false");
          }
        }
        bool published = false;
        const std::uint64_t publish_deadline = monotonicMs() + 2'000U;
        while (!published && monotonicMs() < publish_deadline) {
          if (xSemaphoreTake(history_mutex_, pdMS_TO_TICKS(50)) == pdTRUE) {
            for (auto &result : history_results_) {
              if (result.used && result.id == request->id) {
                result.page = std::move(page);
                result.complete = true;
                result.expires_ms = monotonicMs() + 15'000U;
                published = true;
                break;
              }
            }
            xSemaphoreGive(history_mutex_);
          }
          if (!published)
            vTaskDelay(pdMS_TO_TICKS(10));
        }
        if (!published) {
          PM_LOG_ERROR(
              "STORAGE", "HISTORY_RESULT_PUBLISH_FAILED",
              "error=PM-STORAGE-012 phase=complete retry_budget_ms=2000");
        }
        delete request;
      } else if (message.type == Type::Remount) {
        storage_.remount(storage_.health().spi_hz);
      }
      continue;
    }

    const std::uint64_t now = millis();
    if (pending_record != nullptr && now >= next_record_retry_ms) {
      if (storage_.append(*pending_record)) {
        diagnostics_.setCommittedSequence(pending_record->sequence);
        PM_LOG_TRACE("STORAGE", "RECORD_COMMITTED",
                     "sequence=%llu queue_depth=%lu",
                     static_cast<unsigned long long>(pending_record->sequence),
                     static_cast<unsigned long>(depth()));
        PM_LOG_INFO(
            "HISTORY", "sensor.sample_recorded",
            "sequence=%llu measured_start_ms=%llu measured_end_ms=%llu "
            "power_w=%.5f interval_energy_wh=%.9f time_trusted=%s",
            static_cast<unsigned long long>(pending_record->sequence),
            static_cast<unsigned long long>(pending_record->start_utc_ms),
            static_cast<unsigned long long>(pending_record->end_utc_ms),
            static_cast<double>(pending_record->avg_active_power_w),
            pending_record->interval_energy_wh,
            pending_record->time_trusted ? "true" : "false");
        delete pending_record;
        pending_record = nullptr;
        next_record_retry_ms = 0;
      } else {
        PM_LOG_WARN("HISTORY", "sensor.sample_rejected",
                    "reason=storage_append_failed retry_ms=1000");
        if (now >= next_remount_ms) {
          PM_LOG_WARN("STORAGE", "REMOUNT_SCHEDULED",
                      "error=PM-SD-002 retry_interval_ms=30000");
          storage_.remount(storage_.health().spi_hz);
          next_remount_ms = now + 30'000U;
        }
        next_record_retry_ms = now + 1000U;
      }
    }
    if (pending_record != nullptr) {
      vTaskDelay(pdMS_TO_TICKS(10));
      continue;
    }
    if (xQueueReceive(write_queue_, &message, pdMS_TO_TICKS(250)) != pdTRUE) {
      continue;
    }
    switch (message.type) {
    case Type::Record:
      pending_record = static_cast<IntervalRecord *>(message.payload);
      break;
    case Type::Event: {
      auto *event = static_cast<EventData *>(message.payload);
      storage_.appendEvent(event->code, event->severity, event->detail,
                           event->utc_ms, event->boot_id);
      delete event;
      break;
    }
    case Type::History:
      // History messages use the dedicated control queue.
      delete static_cast<HistoryData *>(message.payload);
      break;
    case Type::Remount:
      storage_.remount(storage_.health().spi_hz);
      break;
    }
  }
}

std::uint32_t StorageCoordinator::depth() const {
  const std::uint32_t writes =
      write_queue_ == nullptr ? 0 : uxQueueMessagesWaiting(write_queue_);
  const std::uint32_t control =
      control_queue_ == nullptr ? 0 : uxQueueMessagesWaiting(control_queue_);
  return writes + control;
}

std::uint64_t StorageCoordinator::dropped() const {
  return dropped_.load(std::memory_order_relaxed);
}

} // namespace pm
