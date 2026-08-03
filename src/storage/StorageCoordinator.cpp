#include "storage/StorageCoordinator.h"

#include <algorithm>
#include <cstdio>
#include <new>

#include <esp_heap_caps.h>
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
  explicit HighMemoryLease(
      Diagnostics &diagnostics,
      const MemoryOperationContext context =
          MemoryOperationContext::StorageMaintenance,
      const TickType_t timeout = pdMS_TO_TICKS(5000))
      : diagnostics_(diagnostics),
        acquired_(diagnostics_.acquireHighMemoryOperation(context, timeout)) {}

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
  record_slots_ = static_cast<BoundedStoragePool<FixedIntervalRecord>::Slot *>(
      heap_caps_calloc(kRecordPoolCapacity,
                       sizeof(BoundedStoragePool<FixedIntervalRecord>::Slot),
                       MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
  event_slots_ = static_cast<BoundedStoragePool<FixedEventData>::Slot *>(
      heap_caps_calloc(kEventPoolCapacity,
                       sizeof(BoundedStoragePool<FixedEventData>::Slot),
                       MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
  if (record_slots_ != nullptr) {
    for (std::uint16_t index = 0U; index < kRecordPoolCapacity; ++index) {
      new (&record_slots_[index])
          BoundedStoragePool<FixedIntervalRecord>::Slot{};
    }
    record_pool_.reset(record_slots_, kRecordPoolCapacity);
  }
  if (event_slots_ != nullptr) {
    for (std::uint16_t index = 0U; index < kEventPoolCapacity; ++index) {
      new (&event_slots_[index]) BoundedStoragePool<FixedEventData>::Slot{};
    }
    event_pool_.reset(event_slots_, kEventPoolCapacity);
  }
  write_queue_ =
      xQueueCreate(build::OFFLINE_RECORD_QUEUE_DEPTH, sizeof(Message));
  control_queue_ = xQueueCreate(8, sizeof(Message));
  history_mutex_ = xSemaphoreCreateMutex();
  const bool ready = record_slots_ != nullptr && event_slots_ != nullptr &&
                     write_queue_ != nullptr && control_queue_ != nullptr &&
                     history_mutex_ != nullptr;
  PM_LOG_INFO("STORAGE", "COORDINATOR_INIT",
              "result=%s write_queue_capacity=%u control_queue_capacity=8 "
              "record_pool_capacity=%u event_pool_capacity=%u "
              "pool_storage=psram ownership=microSD",
              ready ? "success" : "failed",
              static_cast<unsigned>(build::OFFLINE_RECORD_QUEUE_DEPTH),
              static_cast<unsigned>(kRecordPoolCapacity),
              static_cast<unsigned>(kEventPoolCapacity));
  return ready;
}

bool StorageCoordinator::queueSequenceReconciliation(
    const std::uint64_t required_sequence_floor) {
  std::uint64_t current =
      required_sequence_floor_.load(std::memory_order_acquire);
  while (required_sequence_floor > current &&
         !required_sequence_floor_.compare_exchange_weak(
             current, required_sequence_floor, std::memory_order_acq_rel)) {
  }
  bool expected = false;
  if (!sequence_reconciliation_queued_.compare_exchange_strong(
          expected, true, std::memory_order_acq_rel)) {
    return true;
  }
  const Message message{Type::ReconcileSequence, nullptr};
  if (xQueueSendToFront(control_queue_, &message, 0) != pdTRUE) {
    sequence_reconciliation_queued_.store(false, std::memory_order_release);
    return false;
  }
  PM_LOG_INFO("STORAGE", "SEQUENCE_RECONCILIATION_QUEUED",
              "required_floor=%llu ownership=StorageTask",
              static_cast<unsigned long long>(required_sequence_floor));
  return true;
}

bool StorageCoordinator::enqueueRecord(const IntervalRecord &record) {
  const std::uint16_t slot_index = record_pool_.acquire();
  FixedIntervalRecord *const slot = record_pool_.get(slot_index);
  if (slot == nullptr || !slot->assign(record)) {
    record_pool_.release(slot_index);
    dropped_.fetch_add(1, std::memory_order_relaxed);
    recordDroppedInterval(record);
    PM_LOG_ERROR("QUEUE", "STORAGE_ALLOC_FAILED",
                 "error=PM-QUEUE-002 type=record reason=%s dropped=%llu",
                 slot == nullptr ? "bounded_pool_exhausted"
                                 : "bounded_field_capacity_exceeded",
                 static_cast<unsigned long long>(dropped()));
    return false;
  }
  const Message message{Type::Record, nullptr, slot_index};
  if (xQueueSend(write_queue_, &message, 0) != pdTRUE) {
    record_pool_.release(slot_index);
    dropped_.fetch_add(1, std::memory_order_relaxed);
    recordDroppedInterval(record);
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

void StorageCoordinator::recordDroppedInterval(const IntervalRecord &record) {
  dropped_record_intervals_.fetch_add(1, std::memory_order_relaxed);
  std::uint64_t first = first_dropped_interval_utc_ms_.load(
      std::memory_order_relaxed);
  while ((first == 0U || record.start_utc_ms < first) &&
         !first_dropped_interval_utc_ms_.compare_exchange_weak(
             first, record.start_utc_ms, std::memory_order_relaxed)) {
  }
  std::uint64_t last = last_dropped_interval_utc_ms_.load(
      std::memory_order_relaxed);
  while (record.end_utc_ms > last &&
         !last_dropped_interval_utc_ms_.compare_exchange_weak(
             last, record.end_utc_ms, std::memory_order_relaxed)) {
  }
  PM_LOG_ERROR(
      "HISTORY", "storage.interval_dropped",
      "reason=bounded_storage_queue_exhausted count=%llu first_utc_ms=%llu "
      "last_utc_ms=%llu history_gap_required=true",
      static_cast<unsigned long long>(
          dropped_record_intervals_.load(std::memory_order_relaxed)),
      static_cast<unsigned long long>(
          first_dropped_interval_utc_ms_.load(std::memory_order_relaxed)),
      static_cast<unsigned long long>(
          last_dropped_interval_utc_ms_.load(std::memory_order_relaxed)));
}

bool StorageCoordinator::enqueueEvent(const StringView code,
                                      const StringView severity,
                                      const StringView detail,
                                      const std::uint64_t utc_ms,
                                      const StringView boot_id) {
  const std::uint16_t slot_index = event_pool_.acquire();
  FixedEventData *const event = event_pool_.get(slot_index);
  if (event == nullptr ||
      !event->assign(code, severity, detail, utc_ms, boot_id)) {
    event_pool_.release(slot_index);
    dropped_.fetch_add(1, std::memory_order_relaxed);
    PM_LOG_ERROR("QUEUE", "STORAGE_ALLOC_FAILED",
                 "error=PM-QUEUE-002 type=event reason=%s dropped=%llu",
                 event == nullptr ? "bounded_pool_exhausted"
                                  : "bounded_field_capacity_exceeded",
                 static_cast<unsigned long long>(dropped()));
    return false;
  }
  const Message message{Type::Event, nullptr, slot_index};
  if (xQueueSend(write_queue_, &message, 0) != pdTRUE) {
    event_pool_.release(slot_index);
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

bool StorageCoordinator::queueRetention(
    const std::uint64_t server_ack_sequence,
    const bool acknowledgement_verified,
    const std::uint64_t event_ack_sequence,
    const std::uint64_t now_utc_ms, const StoragePolicy &policy,
    const std::string &reason, const bool high_priority) {
  if (control_queue_ == nullptr) {
    return false;
  }
  if (retention_queued_.exchange(true, std::memory_order_acq_rel)) {
    return false;
  }
  auto *request = new (std::nothrow)
      RetentionData{server_ack_sequence, event_ack_sequence, now_utc_ms,
                    policy, reason, acknowledgement_verified};
  if (request == nullptr) {
    retention_queued_.store(false, std::memory_order_release);
    return false;
  }
  const Message message{Type::Retention, request};
  const BaseType_t queued =
      high_priority ? xQueueSendToFront(control_queue_, &message, 0)
                    : xQueueSend(control_queue_, &message, 0);
  if (queued != pdTRUE) {
    delete request;
    retention_queued_.store(false, std::memory_order_release);
    return false;
  }
  PM_LOG_INFO("STORAGE", "CLEANUP_QUEUED",
              "reason=%s priority=%s ack=%llu",
              reason.c_str(), high_priority ? "high" : "normal",
              static_cast<unsigned long long>(server_ack_sequence));
  PM_LOG_INFO("STORAGE", "storage.cleanup_queued",
              "reason=%s priority=%s server_ack=%llu event_ack=%llu",
              reason.c_str(), high_priority ? "high" : "normal",
              static_cast<unsigned long long>(server_ack_sequence),
              static_cast<unsigned long long>(event_ack_sequence));
  return true;
}

bool StorageCoordinator::queuePrepareRemoval() {
  if (control_queue_ == nullptr) {
    return false;
  }
  if (prepare_removal_queued_.exchange(true, std::memory_order_acq_rel)) {
    return false;
  }
  const Message message{Type::PrepareRemoval, nullptr};
  if (xQueueSendToFront(control_queue_, &message, 0) != pdTRUE) {
    prepare_removal_queued_.store(false, std::memory_order_release);
    return false;
  }
  return true;
}

bool StorageCoordinator::queueSelfTest() {
  if (control_queue_ == nullptr) {
    return false;
  }
  const Message message{Type::SelfTest, nullptr};
  return xQueueSendToFront(control_queue_, &message, 0) == pdTRUE;
}

bool StorageCoordinator::queueRemount() {
  if (control_queue_ == nullptr) {
    return false;
  }
  const Message message{Type::Remount, nullptr};
  return xQueueSendToFront(control_queue_, &message, 0) == pdTRUE;
}

bool StorageCoordinator::queueRebuildIndexes() {
  if (control_queue_ == nullptr) {
    return false;
  }
  const Message message{Type::RebuildIndexes, nullptr};
  return xQueueSendToFront(control_queue_, &message, 0) == pdTRUE;
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

bool StorageCoordinator::remountStorage() {
  HighMemoryLease memory_lease(diagnostics_);
  if (!memory_lease) {
    PM_LOG_WARN("STORAGE", "REMOUNT_MEMORY_GATE_TIMEOUT",
                "error=PM-STORAGE-014 retryable=true");
    return false;
  }
  // A failed mount leaves health().spi_hz at the final 400 kHz recovery
  // attempt. Retrying that observed value forever makes every history scan
  // unnecessarily slow. Preserve the configured preferred speed and retry
  // the complete preferred/fallback/recovery ladder on each mount cycle.
  return storage_.remountPreferred();
}

void StorageCoordinator::taskLoop() {
  PM_LOG_INFO(
      "TASK", "TASK_STARTED",
      "name=StorageTask core=%d priority=%u stack_bytes=%u watchdog=false",
      xPortGetCoreID(), static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
      static_cast<unsigned>(task_config::kStorageStackBytes));
  Message message{};
  IntervalRecord pending_record_storage;
  pending_record_storage.device_id.reserve(39U);
  pending_record_storage.friendly_name.reserve(64U);
  pending_record_storage.boot_id.reserve(64U);
  pending_record_storage.energy_method.reserve(32U);
  pending_record_storage.firmware_version.reserve(32U);
  IntervalRecord *pending_record = nullptr;
  std::uint64_t pending_gap_count = 0;
  std::uint64_t pending_gap_first_utc_ms = 0;
  std::uint64_t pending_gap_last_utc_ms = 0;
  std::uint64_t next_remount_ms = 0;
  std::uint64_t next_record_retry_ms = 0;
  for (;;) {
    const StorageHealth scheduling_health = storage_.health();
    const bool pending_capacity_blocked =
        pending_record != nullptr &&
        scheduling_health.last_error.find("reserve_unavailable") !=
            std::string::npos;
    const bool control_allowed =
        pending_capacity_blocked ||
        (pending_record == nullptr &&
         uxQueueMessagesWaiting(write_queue_) == 0U);
    if (control_allowed &&
        xQueueReceive(control_queue_, &message, 0) == pdTRUE) {
      if (message.type == Type::History) {
        auto *request = static_cast<HistoryData *>(message.payload);
        HistoryPage page;
        const SyncMetrics sync = diagnostics_.syncMetrics();
        const bool local_deferred =
            !request->primary_sync &&
            (sync.last_heartbeat_utc_ms == 0U ||
             sync.durable_reading_backlog ||
             sync.primary_storage_pending);
        if (local_deferred) {
          page.error_code = "primary_sync_has_priority";
          PM_LOG_INFO(
              "STORAGE", "LOCAL_HISTORY_DEFERRED",
              "reason=%s events=%s retryable=true",
              sync.last_heartbeat_utc_ms == 0U
                  ? "first_heartbeat_pending"
                  : (sync.durable_reading_backlog
                         ? "reading_backlog_active"
                         : "server_storage_page_active"),
              request->events ? "true" : "false");
        } else {
          const StorageHealth storage_health = storage_.health();
          const bool recovery_speed =
              storage_health.spi_hz != 0U &&
              storage_health.spi_hz <= 400'000U;
          const bool preserve_primary_path =
              recovery_speed && (request->events || !request->primary_sync);
          if (preserve_primary_path) {
            page.error_code = "storage_recovery_speed";
            PM_LOG_INFO(
                "STORAGE", "HISTORY_DEFERRED_AT_RECOVERY_SPEED",
                "spi_hz=%lu events=%s primary_sync=%s retryable=true "
                "reason=preserve_heartbeat_and_reading_sync",
                static_cast<unsigned long>(storage_health.spi_hz),
                request->events ? "true" : "false",
                request->primary_sync ? "true" : "false");
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
        remountStorage();
      } else if (message.type == Type::SelfTest) {
        storage_.selfTest();
      } else if (message.type == Type::RebuildIndexes) {
        HighMemoryLease memory_lease(diagnostics_);
        if (memory_lease) {
          storage_.rebuildIndexes();
        } else {
          PM_LOG_WARN("STORAGE", "REBUILD_MEMORY_GATE_TIMEOUT",
                      "error=PM-STORAGE-014 retryable=true");
        }
      } else if (message.type == Type::Retention) {
        auto *request = static_cast<RetentionData *>(message.payload);
        storage_.applyRetention(
            request->server_ack_sequence, request->acknowledgement_verified,
            request->event_ack_sequence, request->now_utc_ms, request->policy,
            request->reason);
        delete request;
        retention_queued_.store(false, std::memory_order_release);
      } else if (message.type == Type::PrepareRemoval) {
        storage_.prepareRemoval();
        prepare_removal_queued_.store(false, std::memory_order_release);
      } else if (message.type == Type::ReconcileSequence) {
        const std::uint64_t requested =
            required_sequence_floor_.load(std::memory_order_acquire);
        const bool reconciled = storage_.advanceSequenceFloor(requested);
        sequence_reconciliation_queued_.store(false,
                                              std::memory_order_release);
        const std::uint64_t latest =
            required_sequence_floor_.load(std::memory_order_acquire);
        PM_LOG_INFO(
            "STORAGE", "SEQUENCE_RECONCILIATION_COMPLETE",
            "result=%s required_floor=%llu latest_requested_floor=%llu",
            reconciled ? "success" : "degraded",
            static_cast<unsigned long long>(requested),
            static_cast<unsigned long long>(latest));
        if (latest > requested) {
          queueSequenceReconciliation(latest);
        }
      }
      continue;
    }

    const std::uint64_t now = millis();
    if (pending_record != nullptr && now >= next_record_retry_ms) {
      const std::uint64_t new_gap_count =
          dropped_record_intervals_.exchange(0, std::memory_order_acq_rel);
      if (new_gap_count > 0U) {
        const std::uint64_t new_first =
            first_dropped_interval_utc_ms_.exchange(0,
                                                    std::memory_order_acq_rel);
        const std::uint64_t new_last =
            last_dropped_interval_utc_ms_.exchange(0,
                                                   std::memory_order_acq_rel);
        pending_gap_count += new_gap_count;
        pending_gap_first_utc_ms =
            pending_gap_first_utc_ms == 0U
                ? new_first
                : std::min(pending_gap_first_utc_ms, new_first);
        pending_gap_last_utc_ms =
            std::max(pending_gap_last_utc_ms, new_last);
      }
      if (pending_gap_count > 0U &&
          !storage_.reserveUnavailableIntervals(
              pending_gap_count, pending_gap_first_utc_ms,
              pending_gap_last_utc_ms)) {
        PM_LOG_ERROR(
            "HISTORY", "storage.interval_gap_reservation_blocked",
            "count=%llu first_utc_ms=%llu last_utc_ms=%llu retry_ms=30000",
            static_cast<unsigned long long>(pending_gap_count),
            static_cast<unsigned long long>(pending_gap_first_utc_ms),
            static_cast<unsigned long long>(pending_gap_last_utc_ms));
        next_record_retry_ms = now + 30'000U;
        vTaskDelay(pdMS_TO_TICKS(10));
        continue;
      }
      if (pending_gap_count > 0U) {
        pending_gap_count = 0U;
        pending_gap_first_utc_ms = 0U;
        pending_gap_last_utc_ms = 0U;
      }
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
        pending_record = nullptr;
        next_record_retry_ms = 0;
      } else {
        const StorageHealth failed_health = storage_.health();
        PM_LOG_WARN("HISTORY", "sensor.sample_rejected",
                    "reason=%s retry_ms=%lu",
                    failed_health.last_error.c_str(),
                    static_cast<unsigned long>(
                        failed_health.last_error.find("reserve_unavailable") !=
                                std::string::npos
                            ? 30'000U
                            : 1000U));
        const bool capacity_blocked =
            failed_health.last_error.find("reserve_unavailable") !=
            std::string::npos;
        if (!capacity_blocked && now >= next_remount_ms) {
          PM_LOG_WARN("STORAGE", "REMOUNT_SCHEDULED",
                      "error=PM-SD-002 retry_interval_ms=30000");
          remountStorage();
          next_remount_ms = now + 30'000U;
        }
        next_record_retry_ms = now + (capacity_blocked ? 30'000U : 1000U);
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
      if (FixedIntervalRecord *const record =
              record_pool_.get(message.pool_slot)) {
        record->materialize(pending_record_storage);
        record_pool_.release(message.pool_slot);
        pending_record = &pending_record_storage;
      } else {
        PM_LOG_ERROR("QUEUE", "STORAGE_POOL_SLOT_INVALID",
                     "error=PM-QUEUE-004 type=record slot=%u",
                     static_cast<unsigned>(message.pool_slot));
      }
      break;
    case Type::Event: {
      FixedEventData *const event = event_pool_.get(message.pool_slot);
      if (event != nullptr) {
        storage_.appendEvent(event->code.data(), event->severity.data(),
                             event->detail.data(), event->utc_ms,
                             event->boot_id.data());
        event_pool_.release(message.pool_slot);
      } else {
        PM_LOG_ERROR("QUEUE", "STORAGE_POOL_SLOT_INVALID",
                     "error=PM-QUEUE-004 type=event slot=%u",
                     static_cast<unsigned>(message.pool_slot));
      }
      break;
    }
    case Type::History:
      // History messages use the dedicated control queue.
      delete static_cast<HistoryData *>(message.payload);
      break;
    case Type::Remount:
      remountStorage();
      break;
    case Type::SelfTest:
      storage_.selfTest();
      break;
    case Type::RebuildIndexes: {
      HighMemoryLease memory_lease(diagnostics_);
      if (memory_lease) {
        storage_.rebuildIndexes();
      }
      break;
    }
    case Type::Retention:
      // Retention messages use the dedicated control queue.
      delete static_cast<RetentionData *>(message.payload);
      retention_queued_.store(false, std::memory_order_release);
      break;
    case Type::PrepareRemoval:
      prepare_removal_queued_.store(false, std::memory_order_release);
      break;
    case Type::ReconcileSequence:
      sequence_reconciliation_queued_.store(false,
                                            std::memory_order_release);
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

StorageCoordinator::PoolMetrics StorageCoordinator::poolMetrics() const {
  return {record_pool_.metrics(), event_pool_.metrics()};
}

} // namespace pm
