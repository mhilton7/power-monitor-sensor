#include "storage/StorageCoordinator.h"

#include <algorithm>
#include <cstdio>
#include <limits>
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
  data_reset_mutex_ = xSemaphoreCreateMutex();
  const bool ready = record_slots_ != nullptr && event_slots_ != nullptr &&
                     write_queue_ != nullptr && control_queue_ != nullptr &&
                     history_mutex_ != nullptr && data_reset_mutex_ != nullptr;
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

bool StorageCoordinator::queueDataResetSequenceReconciliation(
    const std::uint64_t required_sequence_floor,
    const std::uint64_t expected_card_generation,
    const std::string &expected_card_device_id) {
  if (control_queue_ == nullptr || required_sequence_floor == 0U ||
      expected_card_generation == 0U || expected_card_device_id.empty()) {
    return false;
  }
  bool expected = false;
  if (!data_reset_sequence_reconciliation_queued_.compare_exchange_strong(
          expected, true, std::memory_order_acq_rel)) {
    return true;
  }
  auto *request = new (std::nothrow) DataResetReconcileData{
      required_sequence_floor, expected_card_generation,
      expected_card_device_id};
  if (request == nullptr) {
    data_reset_sequence_reconciliation_queued_.store(
        false, std::memory_order_release);
    return false;
  }
  const Message message{Type::DataResetReconcileSequence, request};
  if (xQueueSendToFront(control_queue_, &message, 0) != pdTRUE) {
    delete request;
    data_reset_sequence_reconciliation_queued_.store(
        false, std::memory_order_release);
    return false;
  }
  return true;
}

bool StorageCoordinator::enqueueRecord(const IntervalRecord &record) {
  if (!record_writes_enabled_.load(std::memory_order_seq_cst)) {
    return false;
  }
  record_enqueues_in_flight_.fetch_add(1U, std::memory_order_seq_cst);
  if (!record_writes_enabled_.load(std::memory_order_seq_cst)) {
    record_enqueues_in_flight_.fetch_sub(1U, std::memory_order_seq_cst);
    return false;
  }
  const std::uint16_t slot_index = record_pool_.acquire();
  FixedIntervalRecord *const slot = record_pool_.get(slot_index);
  if (slot == nullptr || !slot->assign(record)) {
    record_pool_.release(slot_index);
    record_enqueues_in_flight_.fetch_sub(1U, std::memory_order_seq_cst);
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
    record_enqueues_in_flight_.fetch_sub(1U, std::memory_order_seq_cst);
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
  record_enqueues_in_flight_.fetch_sub(1U, std::memory_order_seq_cst);
  return true;
}

bool StorageCoordinator::stageRecordsForDataReset(
    const std::array<IntervalRecord, 2U> &records,
    const std::uint64_t record_count,
    const std::uint64_t proposed_energy_offset_wh) {
  if (record_count == 0U || record_count > records.size() ||
      !data_reset_producer_barrier_active_.load(std::memory_order_seq_cst) ||
      record_writes_enabled_.load(std::memory_order_seq_cst)) {
    return false;
  }
  record_enqueues_in_flight_.fetch_add(1U, std::memory_order_seq_cst);
  if (!data_reset_producer_barrier_active_.load(std::memory_order_seq_cst) ||
      record_writes_enabled_.load(std::memory_order_seq_cst)) {
    record_enqueues_in_flight_.fetch_sub(1U, std::memory_order_seq_cst);
    return false;
  }
  data_reset::DrainRecord staged;
  staged.state = data_reset::DrainState::Staged;
  staged.operation_id = data_reset_operation_id_;
  staged.device_id = data_reset_device_id_;
  staged.source_generation = data_reset_source_generation_;
  staged.target_generation = data_reset_target_generation_;
  staged.card_generation = data_reset_card_generation_;
  staged.proposed_energy_offset_wh = proposed_energy_offset_wh;
  staged.interval_count = record_count;
  for (std::size_t index = 0U; index < record_count; ++index) {
    staged.intervals[index] = records[index];
    staged.intervals[index].sequence = 0U;
    staged.interval_crc32[index] =
        data_reset::drainIntervalCrc32(staged.intervals[index]);
  }
  const DataResetStoreResult persisted =
      data_reset_drain_store_.saveAndVerify(staged);
  record_enqueues_in_flight_.fetch_sub(1U, std::memory_order_seq_cst);
  if (persisted != DataResetStoreResult::SavedAndVerified) {
    PM_LOG_ERROR("RESET", "RESET_DRAIN_STAGE_FAILED", "error=%s",
                 dataResetStoreResultName(persisted));
    return false;
  }
  PM_LOG_INFO("RESET", "RESET_DRAIN_STAGED",
              "operation=%s generation=%llu samples=%lu durable=true",
              staged.operation_id.c_str(),
              static_cast<unsigned long long>(staged.source_generation),
              static_cast<unsigned long>(staged.interval_count));
  return true;
}

void StorageCoordinator::beginDataResetProducerBarrier(
    const std::string &operation_id, const std::string &device_id,
    const std::uint64_t source_generation,
    const std::uint64_t target_generation,
    const std::uint64_t card_generation) {
  data_reset_operation_id_ = operation_id;
  data_reset_device_id_ = device_id;
  data_reset_source_generation_ = source_generation;
  data_reset_target_generation_ = target_generation;
  data_reset_card_generation_ = card_generation;
  data_reset_prepare_durable_.store(false, std::memory_order_seq_cst);
  data_reset_producer_quiesced_.store(false, std::memory_order_seq_cst);
  data_reset_producer_barrier_active_.store(true, std::memory_order_seq_cst);
}

void StorageCoordinator::markDataResetProducerQuiesced() {
  if (data_reset_producer_barrier_active_.load(std::memory_order_seq_cst)) {
    data_reset_producer_quiesced_.store(true, std::memory_order_seq_cst);
  }
}

void StorageCoordinator::markDataResetPrepareDurable() {
  if (data_reset_producer_barrier_active_.load(std::memory_order_seq_cst)) {
    data_reset_prepare_durable_.store(true, std::memory_order_seq_cst);
  }
}

bool StorageCoordinator::dataResetProducerQuiesced() const {
  return data_reset_producer_barrier_active_.load(std::memory_order_acquire) &&
         data_reset_producer_quiesced_.load(std::memory_order_acquire);
}

void StorageCoordinator::markDataResetMeterProjectionActivity() {
  data_reset_meter_projection_epoch_.fetch_add(1U,
                                                std::memory_order_acq_rel);
}

std::uint64_t StorageCoordinator::dataResetMeterProjectionEpoch() const {
  return data_reset_meter_projection_epoch_.load(std::memory_order_acquire);
}

void StorageCoordinator::publishDataResetAggregationProjection(
    const bool stable, const std::uint64_t drain_records,
    const std::uint64_t syncable_records, const bool syncable_prefix,
    const std::uint64_t meter_epoch) {
  data_reset_projection_version_.fetch_add(1U, std::memory_order_acq_rel);
  data_reset_aggregation_projection_stable_.store(stable,
                                                   std::memory_order_relaxed);
  data_reset_projection_drain_records_.store(drain_records,
                                              std::memory_order_relaxed);
  data_reset_projection_syncable_records_.store(
      syncable_records, std::memory_order_relaxed);
  data_reset_projection_syncable_prefix_.store(syncable_prefix,
                                                std::memory_order_relaxed);
  data_reset_projection_meter_epoch_.store(meter_epoch,
                                            std::memory_order_relaxed);
  data_reset_projection_version_.fetch_add(1U, std::memory_order_release);
}

StorageCoordinator::DataResetPrepareProjection
StorageCoordinator::dataResetPrepareProjection() const {
  DataResetPrepareProjection result;
  const std::uint64_t projection_version_before =
      data_reset_projection_version_.load(std::memory_order_acquire);
  const bool projected_stable =
      data_reset_aggregation_projection_stable_.load(
          std::memory_order_relaxed);
  const std::uint64_t drain_records =
      data_reset_projection_drain_records_.load(std::memory_order_relaxed);
  const std::uint64_t syncable_records =
      data_reset_projection_syncable_records_.load(
          std::memory_order_relaxed);
  const bool syncable_prefix =
      data_reset_projection_syncable_prefix_.load(
          std::memory_order_relaxed);
  const std::uint64_t projected_meter_epoch =
      data_reset_projection_meter_epoch_.load(std::memory_order_relaxed);
  const std::uint64_t projection_version_after =
      data_reset_projection_version_.load(std::memory_order_acquire);
  const bool source_stable =
      projected_stable && (projection_version_before & 1U) == 0U &&
      projection_version_before == projection_version_after;
  const std::uint64_t meter_epoch_before =
      data_reset_meter_projection_epoch_.load(std::memory_order_acquire);
  const StorageHealth health = storage_.health();
  const PoolMetrics pools = poolMetrics();
  const bool queue_empty =
      write_queue_ != nullptr && uxQueueMessagesWaiting(write_queue_) == 0U;
  const bool record_ingress_idle =
      record_enqueues_in_flight_.load(std::memory_order_seq_cst) == 0U;
  const bool pending_record =
      storage_pending_record_active_.load(std::memory_order_seq_cst);
  const bool dropped_record =
      dropped_record_intervals_.load(std::memory_order_seq_cst) != 0U;
  const bool reset_barrier =
      data_reset_producer_barrier_active_.load(
          std::memory_order_seq_cst);
  const std::uint64_t meter_epoch_after =
      data_reset_meter_projection_epoch_.load(std::memory_order_acquire);
  const bool meter_snapshot_stable =
      (meter_epoch_before & 1U) == 0U &&
      meter_epoch_before == meter_epoch_after &&
      projected_meter_epoch == meter_epoch_before;
  const bool arithmetic_valid =
      drain_records <= 2U && syncable_records <= drain_records &&
      health.next_sequence > 0U &&
      drain_records <= std::numeric_limits<std::uint64_t>::max() -
                           health.next_sequence &&
      drain_records <= std::numeric_limits<std::uint64_t>::max() -
                           health.local_record_count;
  result.consistent =
      source_stable && meter_snapshot_stable && syncable_prefix &&
      arithmetic_valid && record_ingress_idle && pools.records.active == 0U &&
      queue_empty && !pending_record && !dropped_record && !reset_barrier &&
      health.present && health.mounted && health.writable &&
      health.card_identity_status == "verified";
  if (!result.consistent) {
    return result;
  }
  result.drain_records = drain_records;
  result.drain_syncable_records = syncable_records;
  result.local_record_count = health.local_record_count + drain_records;
  result.next_sequence = health.next_sequence + drain_records;
  result.newest_sequence = health.newest_sequence;
  result.newest_syncable_sequence = health.newest_syncable_sequence;
  if (drain_records > 0U) {
    result.drain_sequence_range_set = true;
    result.drain_first_sequence = health.next_sequence;
    result.drain_last_sequence = health.next_sequence + drain_records - 1U;
    result.newest_sequence = result.drain_last_sequence;
    if (syncable_records > 0U) {
      result.newest_syncable_sequence =
          result.drain_first_sequence + syncable_records - 1U;
    }
  }
  return result;
}

bool StorageCoordinator::dataResetDrainSafeToCancel(
    const std::string &operation_id, const std::string &device_id,
    const std::uint64_t source_generation,
    const std::uint64_t target_generation,
    const std::uint64_t card_generation,
    const std::uint64_t installed_energy_offset_wh) const {
  if (!dataResetProducerQuiesced())
    return false;
  data_reset::DrainRecord journal;
  const DataResetStoreResult loaded = data_reset_drain_store_.load(journal);
  if (loaded == DataResetStoreResult::NotFound)
    return true;
  if (loaded != DataResetStoreResult::Loaded)
    return false;
  if (journal.operation_id != operation_id)
    return journal.state == data_reset::DrainState::Completed;
  return journal.device_id == device_id &&
         journal.source_generation == source_generation &&
         journal.target_generation == target_generation &&
         (card_generation == 0U ||
          journal.card_generation == card_generation) &&
         journal.state == data_reset::DrainState::Completed &&
         journal.proposed_energy_offset_wh == installed_energy_offset_wh;
}

bool StorageCoordinator::recoverOrphanedDataResetDrain(
    const data_reset::Record *const durable_reset,
    const std::string &device_id,
    const std::uint64_t data_generation,
    const std::uint64_t card_generation,
    std::uint64_t &recovered_energy_offset_wh, bool &recovered,
    std::string &error) {
  recovered_energy_offset_wh = 0U;
  recovered = false;
  error.clear();
  data_reset::DrainRecord journal;
  const DataResetStoreResult loaded = data_reset_drain_store_.load(journal);
  if (loaded == DataResetStoreResult::NotFound)
    return true;
  if (loaded != DataResetStoreResult::Loaded) {
    error = "data_reset_orphan_journal_load_failed";
    return false;
  }
  const bool durable_reset_owns_journal =
      durable_reset != nullptr &&
      !data_reset::terminalState(durable_reset->state) &&
      durable_reset->prepare.operation_id == journal.operation_id &&
      durable_reset->prepare.device_id == journal.device_id &&
      durable_reset->prepare.target_generation == journal.target_generation &&
      journal.source_generation + 1U == journal.target_generation;
  if (durable_reset_owns_journal) {
    return true;
  }
  if (data_reset::completedDrainFromDifferentDevice(journal, device_id)) {
    return true;
  }
  if (data_reset::completedDrainMatchesCurrentGeneration(
          journal, device_id, data_generation)) {
    if (data_reset_drain_store_.scrubCompletedPayloadCopies(journal) !=
        DataResetStoreResult::SavedAndVerified) {
      error = "data_reset_orphan_payload_scrub_failed";
      return false;
    }
    return true;
  }
  if (data_generation == std::numeric_limits<std::uint64_t>::max() ||
      journal.device_id != device_id ||
      journal.source_generation != data_generation ||
      journal.target_generation != data_generation + 1U ||
      journal.card_generation != card_generation || card_generation == 0U) {
    error = "data_reset_orphan_journal_binding_changed";
    return false;
  }
  data_reset_operation_id_ = journal.operation_id;
  data_reset_device_id_ = journal.device_id;
  data_reset_source_generation_ = journal.source_generation;
  data_reset_target_generation_ = journal.target_generation;
  data_reset_card_generation_ = journal.card_generation;
  DataResetStorageResult result;
  if (!completeDataResetDrain(result, error)) {
    if (error.empty())
      error = "data_reset_orphan_drain_recovery_failed";
    return false;
  }
  recovered_energy_offset_wh = result.prepare_drain_energy_offset_wh;
  // A Completed journal also carries the proposed offset for a zero-delta
  // closed interval. Reinstalling it is idempotent and avoids separating the
  // measurement value from its durable handoff on a terminal-cancel reboot.
  recovered = true;
  return true;
}

void StorageCoordinator::endDataResetProducerBarrier() {
  data_reset_prepare_durable_.store(false, std::memory_order_seq_cst);
  data_reset_producer_quiesced_.store(true, std::memory_order_seq_cst);
  data_reset_producer_barrier_active_.store(false, std::memory_order_seq_cst);
}

void StorageCoordinator::setRecordWritesEnabled(const bool enabled) {
  record_writes_enabled_.store(enabled, std::memory_order_seq_cst);
}

bool StorageCoordinator::recordWritesEnabled() const {
  return record_writes_enabled_.load(std::memory_order_acquire);
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
  std::uint64_t source_event_id =
      next_source_event_id_.fetch_add(1U, std::memory_order_relaxed);
  if (source_event_id == 0U) {
    source_event_id =
        next_source_event_id_.fetch_add(1U, std::memory_order_relaxed);
  }
  if (event == nullptr || source_event_id == 0U || boot_id.empty() ||
      !event->assign(code, severity, detail, utc_ms, boot_id,
                     source_event_id)) {
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
  if (control_queue_ == nullptr ||
      !record_writes_enabled_.load(std::memory_order_acquire)) {
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
  if (control_queue_ == nullptr ||
      !record_writes_enabled_.load(std::memory_order_acquire)) {
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
  if (control_queue_ == nullptr ||
      !record_writes_enabled_.load(std::memory_order_acquire)) {
    return false;
  }
  const Message message{Type::SelfTest, nullptr};
  return xQueueSendToFront(control_queue_, &message, 0) == pdTRUE;
}

bool StorageCoordinator::queueRemount() {
  if (control_queue_ == nullptr ||
      !record_writes_enabled_.load(std::memory_order_acquire)) {
    return false;
  }
  const Message message{Type::Remount, nullptr};
  return xQueueSendToFront(control_queue_, &message, 0) == pdTRUE;
}

bool StorageCoordinator::queueRebuildIndexes() {
  if (control_queue_ == nullptr ||
      !record_writes_enabled_.load(std::memory_order_acquire)) {
    return false;
  }
  const Message message{Type::RebuildIndexes, nullptr};
  return xQueueSendToFront(control_queue_, &message, 0) == pdTRUE;
}

bool StorageCoordinator::queueDataResetBarrier(const std::uint32_t request_id,
                                               const bool cleanup,
                                               const std::uint64_t
                                                   expected_card_generation,
                                               const std::string &
                                                   expected_card_device_id,
                                               const std::string &operation_id,
                                               const std::uint64_t
                                                   source_generation,
                                               const std::uint64_t
                                                   target_generation) {
  if (request_id == 0U || control_queue_ == nullptr ||
      data_reset_mutex_ == nullptr ||
      record_writes_enabled_.load(std::memory_order_seq_cst) ||
      (cleanup &&
       (expected_card_generation == 0U ||
        expected_card_device_id.empty() || operation_id.empty() ||
        target_generation == 0U ||
        source_generation ==
            std::numeric_limits<std::uint64_t>::max() ||
        target_generation != source_generation + 1U))) {
    return false;
  }
  bool expected = false;
  if (!data_reset_barrier_queued_.compare_exchange_strong(
          expected, true, std::memory_order_acq_rel)) {
    return false;
  }
  auto *request = new (std::nothrow) DataResetBarrierData{
      request_id, cleanup, expected_card_generation, expected_card_device_id,
      operation_id, source_generation, target_generation};
  if (request == nullptr) {
    data_reset_barrier_queued_.store(false, std::memory_order_release);
    return false;
  }
  if (xSemaphoreTake(data_reset_mutex_, pdMS_TO_TICKS(25)) != pdTRUE) {
    delete request;
    data_reset_barrier_queued_.store(false, std::memory_order_release);
    return false;
  }
  data_reset_result_ = {};
  data_reset_result_.request_id = request_id;
  data_reset_result_.cleanup_requested = cleanup;
  xSemaphoreGive(data_reset_mutex_);

  const Message message{Type::DataResetBarrier, request};
  if (xQueueSend(control_queue_, &message, 0) != pdTRUE) {
    delete request;
    data_reset_barrier_queued_.store(false, std::memory_order_release);
    return false;
  }
  return true;
}

bool StorageCoordinator::dataResetStorageResult(
    const std::uint32_t request_id, DataResetStorageResult &result) const {
  if (request_id == 0U || data_reset_mutex_ == nullptr ||
      xSemaphoreTake(data_reset_mutex_, pdMS_TO_TICKS(25)) != pdTRUE) {
    return false;
  }
  const bool found = data_reset_result_.request_id == request_id;
  if (found) {
    result = data_reset_result_;
  }
  xSemaphoreGive(data_reset_mutex_);
  return found;
}

bool StorageCoordinator::clearReadingHistoryResults() {
  if (history_mutex_ == nullptr ||
      xSemaphoreTake(history_mutex_, pdMS_TO_TICKS(250)) != pdTRUE) {
    return false;
  }
  for (auto &result : history_results_) {
    if (result.used && !result.events) {
      result = {};
    }
  }
  xSemaphoreGive(history_mutex_);
  return true;
}

std::string StorageCoordinator::queueHistory(const HistoryQuery &query,
                                             const bool events,
                                             const bool primary_sync) {
  if (control_queue_ == nullptr || history_mutex_ == nullptr) {
    return {};
  }
  if (!events && !record_writes_enabled_.load(std::memory_order_acquire)) {
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
  slot->events = events;
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

bool StorageCoordinator::completeDataResetDrain(
    DataResetStorageResult &result, std::string &error) {
  data_reset::DrainRecord journal;
  const DataResetStoreResult loaded = data_reset_drain_store_.load(journal);
  if (loaded == DataResetStoreResult::NotFound) {
    if (data_reset_card_generation_ == 0U ||
        data_reset_device_id_.empty() ||
        !storage_.verifyDataResetCardBinding(data_reset_card_generation_,
                                             data_reset_device_id_)) {
      error = "data_reset_drain_storage_identity_changed";
      return false;
    }
    return true;
  }
  if (loaded != DataResetStoreResult::Loaded) {
    error = "data_reset_drain_journal_load_failed";
    return false;
  }
  if (journal.operation_id != data_reset_operation_id_) {
    // Completed evidence from an earlier operation is retained as a tombstone
    // until a later partial interval atomically replaces it. It is not part of
    // the current prepare. Any unfinished foreign record fails closed.
    if (journal.state == data_reset::DrainState::Completed) {
      if (data_reset_card_generation_ == 0U ||
          data_reset_device_id_.empty() ||
          !storage_.verifyDataResetCardBinding(data_reset_card_generation_,
                                               data_reset_device_id_)) {
        error = "data_reset_drain_storage_identity_changed";
        return false;
      }
      return true;
    }
    error = "data_reset_drain_journal_conflict";
    return false;
  }
  if (journal.device_id != data_reset_device_id_ ||
      journal.source_generation != data_reset_source_generation_ ||
      journal.target_generation != data_reset_target_generation_ ||
      journal.card_generation != data_reset_card_generation_) {
    error = "data_reset_drain_journal_binding_changed";
    return false;
  }
  const StorageHealth health = storage_.health();
  if (!health.present || !health.mounted || !health.writable ||
      health.card_identity_status != "verified" ||
      health.card_generation != journal.card_generation ||
      health.card_device_id != journal.device_id) {
    error = "data_reset_drain_storage_identity_changed";
    return false;
  }
  if (journal.state == data_reset::DrainState::Staged) {
    if (health.next_sequence == 0U || journal.interval_count == 0U ||
        health.next_sequence > data_reset::kMaximumResetBoundary ||
        journal.interval_count - 1U >
            data_reset::kMaximumResetBoundary - health.next_sequence) {
      error = "data_reset_drain_sequence_exhausted";
      return false;
    }
    data_reset::DrainRecord assigned = journal;
    assigned.state = data_reset::DrainState::Assigned;
    assigned.assigned_first_sequence = health.next_sequence;
    const DataResetStoreResult saved =
        data_reset_drain_store_.saveAndVerify(assigned);
    if (saved != DataResetStoreResult::SavedAndVerified) {
      error = "data_reset_drain_assignment_persistence_failed";
      return false;
    }
    journal = std::move(assigned);
  }

  if (journal.state == data_reset::DrainState::Assigned) {
    std::uint64_t syncable_records = 0U;
    for (std::size_t index = 0U; index < journal.interval_count; ++index) {
      const std::uint64_t assigned_sequence =
          journal.assigned_first_sequence + index;
      bool durable = storage_.containsDataResetDrainRecord(
          journal.intervals[index], assigned_sequence,
          journal.card_generation, journal.device_id);
      const StorageHealth before_append = storage_.health();
      if (!durable && before_append.next_sequence == assigned_sequence) {
        IntervalRecord interval = journal.intervals[index];
        if (!storage_.append(interval, journal.card_generation,
                             journal.device_id) ||
            interval.sequence != assigned_sequence) {
          // append() can fail after media state changes. Verify the exact
          // envelope once more before deciding that recovery is required.
          durable = storage_.containsDataResetDrainRecord(
              journal.intervals[index], assigned_sequence,
              journal.card_generation, journal.device_id);
        } else {
          durable = storage_.containsDataResetDrainRecord(
              journal.intervals[index], assigned_sequence,
              journal.card_generation, journal.device_id);
          if (durable)
            diagnostics_.setCommittedSequence(interval.sequence);
        }
      }
      if (!durable) {
        error = "data_reset_drain_append_verification_failed";
        return false;
      }
      const IntervalRecord &interval = journal.intervals[index];
      if (interval.time_trusted && interval.start_utc_ms != 0U &&
          interval.end_utc_ms > interval.start_utc_ms) {
        ++syncable_records;
      }
    }
    data_reset::DrainRecord completed = journal;
    completed.state = data_reset::DrainState::Completed;
    completed.syncable_records_added = syncable_records;
    // The exact interval is now durable in the reading tree. Replace the NVS
    // handoff atomically with scalar/digest evidence so reset-scope
    // measurement payload is not retained in a second store.
    completed.intervals = {};
    const DataResetStoreResult saved =
        data_reset_drain_store_.saveAndVerify(completed);
    if (saved != DataResetStoreResult::SavedAndVerified) {
      error = "data_reset_drain_completion_persistence_failed";
      return false;
    }
    journal = std::move(completed);
  }

  if (journal.state != data_reset::DrainState::Completed) {
    error = "data_reset_drain_completion_verification_failed";
    return false;
  }
  if (data_reset_drain_store_.scrubCompletedPayloadCopies(journal) !=
      DataResetStoreResult::SavedAndVerified) {
    error = "data_reset_drain_payload_scrub_failed";
    return false;
  }
  result.prepare_drain_records_added = journal.interval_count;
  result.prepare_drain_sequence_range_set = true;
  result.prepare_drain_first_sequence = journal.assigned_first_sequence;
  result.prepare_drain_last_sequence =
      journal.assigned_first_sequence + journal.interval_count - 1U;
  result.prepare_drain_syncable_records_added =
      journal.syncable_records_added;
  result.prepare_drain_energy_offset_wh =
      journal.proposed_energy_offset_wh;
  return true;
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
  std::array<Message, kEventPoolCapacity> pending_reset_events{};
  std::size_t pending_reset_event_count = 0U;
  std::uint64_t next_remount_ms = 0;
  std::uint64_t next_record_retry_ms = 0;
  for (;;) {
    if (pending_reset_event_count > 0U) {
      FixedEventData *const event =
          event_pool_.get(pending_reset_events[0].pool_slot);
      if (event != nullptr &&
          storage_.appendEvent(event->code.data(), event->severity.data(),
                               event->detail.data(), event->utc_ms,
                               event->boot_id.data(), 0U, {},
                               event->source_event_id)) {
        event_pool_.release(pending_reset_events[0].pool_slot);
        for (std::size_t index = 1U; index < pending_reset_event_count;
             ++index) {
          pending_reset_events[index - 1U] = pending_reset_events[index];
        }
        pending_reset_events[--pending_reset_event_count] = {};
      } else {
        // Keep ownership, but do not block a queued commit-cleanup barrier.
        // Cleanup may be exactly what frees enough card space to persist this
        // event; the barrier appends it before publishing success below.
        vTaskDelay(pdMS_TO_TICKS(10));
      }
    }
    const StorageHealth scheduling_health = storage_.health();
    const bool pending_capacity_blocked =
        pending_record != nullptr &&
        scheduling_health.last_error.find("reserve_unavailable") !=
            std::string::npos;
    const bool control_allowed =
        pending_capacity_blocked ||
        pending_reset_event_count > 0U ||
        (!record_writes_enabled_.load(std::memory_order_acquire) &&
         data_reset_barrier_queued_.load(std::memory_order_acquire)) ||
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
        if (record_writes_enabled_.load(std::memory_order_acquire)) {
          remountStorage();
        }
      } else if (message.type == Type::SelfTest) {
        if (record_writes_enabled_.load(std::memory_order_acquire)) {
          storage_.selfTest();
        }
      } else if (message.type == Type::RebuildIndexes) {
        if (record_writes_enabled_.load(std::memory_order_acquire)) {
          HighMemoryLease memory_lease(diagnostics_);
          if (memory_lease) {
            storage_.rebuildIndexes();
          } else {
            PM_LOG_WARN("STORAGE", "REBUILD_MEMORY_GATE_TIMEOUT",
                        "error=PM-STORAGE-014 retryable=true");
          }
        }
      } else if (message.type == Type::Retention) {
        auto *request = static_cast<RetentionData *>(message.payload);
        if (record_writes_enabled_.load(std::memory_order_acquire)) {
          storage_.applyRetention(
              request->server_ack_sequence, request->acknowledgement_verified,
              request->event_ack_sequence, request->now_utc_ms,
              request->policy, request->reason);
        }
        delete request;
        retention_queued_.store(false, std::memory_order_release);
      } else if (message.type == Type::PrepareRemoval) {
        if (record_writes_enabled_.load(std::memory_order_acquire)) {
          storage_.prepareRemoval();
        }
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
      } else if (message.type == Type::DataResetReconcileSequence) {
        auto *request =
            static_cast<DataResetReconcileData *>(message.payload);
        if (request != nullptr) {
          storage_.advanceSequenceFloor(
              request->required_sequence_floor,
              request->expected_card_generation,
              request->expected_card_device_id);
          delete request;
        }
        data_reset_sequence_reconciliation_queued_.store(
            false, std::memory_order_release);
      } else if (message.type == Type::DataResetBarrier) {
        auto *request = static_cast<DataResetBarrierData *>(message.payload);
        DataResetStorageResult result{};
        result.request_id = request->request_id;
        result.cleanup_requested = request->cleanup;

        // setRecordWritesEnabled(false) precedes every reset barrier. Wait for
        // producers that observed the old gate value to finish their second
        // check/enqueue, then consume a fixed snapshot of the write queue.
        // No record can arrive after the in-flight count reaches zero; events
        // remain allowed and are durably appended while the snapshot drains.
        const std::uint64_t quiesce_deadline = monotonicMs() + 250U;
        while (record_enqueues_in_flight_.load(std::memory_order_seq_cst) !=
                   0U &&
               monotonicMs() < quiesce_deadline) {
          vTaskDelay(pdMS_TO_TICKS(1));
        }
        const bool producers_quiesced =
            record_enqueues_in_flight_.load(std::memory_order_seq_cst) == 0U;
        std::uint32_t discarded_records = 0U;
        std::uint32_t flushed_records = 0U;
        bool readings_drained = true;
        // A cleanup barrier may use retained in-memory ownership to cross a
        // full-card condition, because cleanup itself frees the space needed
        // to append the event before success is published. Reversible prepare
        // still requires every event to be durable first.
        bool events_preserved =
            request->cleanup || pending_reset_event_count == 0U;
        data_reset::EventJournalRecord event_journal{};
        std::array<bool, kEventPoolCapacity> pending_event_in_journal{};
        bool event_journal_ready = !request->cleanup;
        if (producers_quiesced) {
          if (request->cleanup) {
            if (pending_record != nullptr) {
              pending_record = nullptr;
              storage_pending_record_active_.store(
                  false, std::memory_order_seq_cst);
              ++discarded_records;
            }
            next_record_retry_ms = 0U;
            // Only irreversible cleanup may purge old reading-gap state.
            pending_gap_count = 0U;
            pending_gap_first_utc_ms = 0U;
            pending_gap_last_utc_ms = 0U;
            dropped_record_intervals_.store(0U, std::memory_order_release);
            first_dropped_interval_utc_ms_.store(0U,
                                                 std::memory_order_release);
            last_dropped_interval_utc_ms_.store(0U,
                                                std::memory_order_release);
          } else {
            // Prepare is reversible. First make all pre-gate unavailable-range
            // evidence durable, then flush every drainable record. A
            // capacity-blocked record remains owned by pending_record so a
            // cancel can reopen normal retention/retry without data loss.
            const std::uint64_t new_gap_count =
                dropped_record_intervals_.exchange(
                    0U, std::memory_order_acq_rel);
            if (new_gap_count > 0U) {
              const std::uint64_t new_first =
                  first_dropped_interval_utc_ms_.exchange(
                      0U, std::memory_order_acq_rel);
              const std::uint64_t new_last =
                  last_dropped_interval_utc_ms_.exchange(
                      0U, std::memory_order_acq_rel);
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
                    pending_gap_last_utc_ms,
                    request->expected_card_generation,
                    request->expected_card_device_id)) {
              readings_drained = false;
              result.error = "data_reset_prepare_capacity_blocked";
            } else if (pending_gap_count > 0U) {
              pending_gap_count = 0U;
              pending_gap_first_utc_ms = 0U;
              pending_gap_last_utc_ms = 0U;
            }
            if (readings_drained && pending_record != nullptr) {
              if (storage_.append(*pending_record,
                                  request->expected_card_generation,
                                  request->expected_card_device_id)) {
                diagnostics_.setCommittedSequence(pending_record->sequence);
                pending_record = nullptr;
                storage_pending_record_active_.store(
                    false, std::memory_order_seq_cst);
                next_record_retry_ms = 0U;
                ++flushed_records;
              } else {
                readings_drained = false;
                result.error =
                    storage_.health().last_error.find("reserve_unavailable") !=
                            std::string::npos
                        ? "data_reset_prepare_capacity_blocked"
                        : "data_reset_prepare_record_flush_failed";
              }
            }
          }

          const UBaseType_t queued_before_barrier =
              uxQueueMessagesWaiting(write_queue_);
          for (UBaseType_t index = 0U;
               readings_drained && index < queued_before_barrier; ++index) {
            Message queued{};
            if (xQueueReceive(write_queue_, &queued, 0) != pdTRUE) {
              break;
            }
            if (queued.type == Type::Record) {
              if (request->cleanup) {
                record_pool_.release(queued.pool_slot);
                ++discarded_records;
                continue;
              }
              FixedIntervalRecord *const record =
                  record_pool_.get(queued.pool_slot);
              if (record == nullptr) {
                readings_drained = false;
                result.error = "data_reset_prepare_record_slot_invalid";
                continue;
              }
              record->materialize(pending_record_storage);
              pending_record = &pending_record_storage;
              storage_pending_record_active_.store(
                  true, std::memory_order_seq_cst);
              record_pool_.release(queued.pool_slot);
              if (storage_.append(*pending_record,
                                  request->expected_card_generation,
                                  request->expected_card_device_id)) {
                diagnostics_.setCommittedSequence(pending_record->sequence);
                pending_record = nullptr;
                storage_pending_record_active_.store(
                    false, std::memory_order_seq_cst);
                ++flushed_records;
              } else {
                readings_drained = false;
                result.error =
                    storage_.health().last_error.find("reserve_unavailable") !=
                            std::string::npos
                        ? "data_reset_prepare_capacity_blocked"
                        : "data_reset_prepare_record_flush_failed";
              }
              continue;
            }
            if (queued.type == Type::Event) {
              FixedEventData *const event = event_pool_.get(queued.pool_slot);
              if (event != nullptr) {
                if (storage_.appendEvent(
                        event->code.data(), event->severity.data(),
                        event->detail.data(), event->utc_ms,
                        event->boot_id.data(), 0U, {},
                        event->source_event_id)) {
                  event_pool_.release(queued.pool_slot);
                } else {
                  // Retain ownership and retry outside the barrier. Events are
                  // never classified as reset data and must not be discarded.
                  bool retained = false;
                  if (pending_reset_event_count <
                      pending_reset_events.size()) {
                    pending_reset_events[pending_reset_event_count++] = queued;
                    retained = true;
                  }
                  events_preserved =
                      events_preserved && retained && request->cleanup;
                  if (!request->cleanup || !retained) {
                    break;
                  }
                  // Continue consuming the fixed snapshot so every reading
                  // behind this event is discarded before card cleanup.
                  continue;
                }
              } else {
                events_preserved = false;
              }
            }
          }
        }

        if (request->cleanup && producers_quiesced && readings_drained &&
            events_preserved) {
          const DataResetStoreResult loaded =
              data_reset_event_store_.load(event_journal);
          const bool replace_completed =
              loaded == DataResetStoreResult::Loaded &&
              event_journal.operation_id != request->operation_id &&
              event_journal.state ==
                  data_reset::EventJournalState::Completed;
          if (loaded == DataResetStoreResult::NotFound || replace_completed) {
            event_journal = {};
            event_journal.operation_id = request->operation_id;
            event_journal.device_id = request->expected_card_device_id;
            event_journal.source_generation = request->source_generation;
            event_journal.target_generation = request->target_generation;
            event_journal.card_generation =
                request->expected_card_generation;
          } else if (loaded != DataResetStoreResult::Loaded) {
            result.error = "data_reset_event_journal_load_failed";
          } else if (event_journal.operation_id != request->operation_id) {
            result.error = "data_reset_event_journal_conflict";
          }

          if (result.error.empty() &&
              (event_journal.device_id !=
                   request->expected_card_device_id ||
               event_journal.source_generation !=
                   request->source_generation ||
               event_journal.target_generation !=
                   request->target_generation ||
               event_journal.card_generation !=
                   request->expected_card_generation)) {
            result.error = "data_reset_event_journal_binding_changed";
          }
          const bool can_extend_event_journal =
              loaded == DataResetStoreResult::NotFound || replace_completed;
          bool event_journal_changed = can_extend_event_journal;
          std::array<bool, data_reset::kMaximumPreservedResetEvents>
              journal_entry_claimed{};
          for (std::size_t pending_index = 0U;
               result.error.empty() &&
               pending_index < pending_reset_event_count;
               ++pending_index) {
            FixedEventData *const pending = event_pool_.get(
                pending_reset_events[pending_index].pool_slot);
            if (pending == nullptr) {
              result.error = "data_reset_event_journal_slot_invalid";
              break;
            }
            data_reset::PreservedEvent candidate{
                pending->code.data(), pending->severity.data(),
                pending->detail.data(), pending->boot_id.data(),
                pending->utc_ms, pending->source_event_id, 1U};
            bool already_staged = false;
            for (std::size_t index = 0U;
                 index < event_journal.event_count; ++index) {
              const auto &existing = event_journal.events[index];
              already_staged =
                  !journal_entry_claimed[index] &&
                  existing.code == candidate.code &&
                  existing.severity == candidate.severity &&
                  existing.detail == candidate.detail &&
                  existing.boot_id == candidate.boot_id &&
                  existing.utc_ms == candidate.utc_ms &&
                  existing.source_event_id == candidate.source_event_id;
              if (already_staged) {
                journal_entry_claimed[index] = true;
                pending_event_in_journal[pending_index] = true;
                break;
              }
            }
            if (already_staged)
              continue;
            // Avoid a second worst-case staged NVS blob. A retry cleans using
            // the fixed durable batch. Unmatched newer RAM events retain
            // their pool ownership and are appended normally after cleanup
            // frees card capacity.
            if (!can_extend_event_journal ||
                event_journal.state ==
                    data_reset::EventJournalState::Completed) {
              continue;
            }
            if (event_journal.event_count >= event_journal.events.size()) {
              result.error = "data_reset_event_journal_full";
              break;
            }
            const std::uint32_t candidate_crc =
                data_reset::preservedEventCrc32(candidate);
            const std::size_t index = event_journal.event_count++;
            event_journal.events[index] = std::move(candidate);
            event_journal.event_crc32[index] = candidate_crc;
            pending_event_in_journal[pending_index] = true;
            event_journal_changed = true;
          }
          if (result.error.empty() && event_journal_changed &&
              data_reset_event_store_.saveAndVerify(event_journal) !=
                  DataResetStoreResult::SavedAndVerified) {
            result.error = "data_reset_event_journal_persistence_failed";
          }
          event_journal_ready = result.error.empty();
        }

        if (!producers_quiesced) {
          result.error = "data_reset_record_producer_busy";
        } else if (!readings_drained) {
          if (result.error.empty()) {
            result.error = "data_reset_prepare_record_flush_failed";
          }
        } else if (!events_preserved) {
          result.error = "data_reset_event_flush_failed";
        } else if (request->cleanup && !event_journal_ready) {
          if (result.error.empty())
            result.error = "data_reset_event_journal_persistence_failed";
        } else if (!request->cleanup &&
                   !completeDataResetDrain(result, result.error)) {
          if (result.error.empty())
            result.error = "data_reset_drain_commit_failed";
        } else if (!clearReadingHistoryResults()) {
          result.error = "data_reset_history_cache_clear_failed";
        } else {
          if (request->cleanup) {
            result.cleanup = storage_.clearReadingDataForReset(
                request->operation_id, request->source_generation,
                request->target_generation,
                request->expected_card_generation,
                request->expected_card_device_id);
            result.ok = result.cleanup.ok;
            result.error = result.cleanup.error_code;
            if (result.ok &&
                event_journal.state ==
                    data_reset::EventJournalState::Staged) {
              for (std::size_t index = 0U;
                   result.ok && index < event_journal.event_count; ++index) {
                const auto &event = event_journal.events[index];
                std::uint64_t occurrences = 0U;
                if (!storage_.countExactEvents(
                        event.code, event.severity, event.detail,
                        event.utc_ms, event.boot_id,
                        request->expected_card_generation,
                        request->expected_card_device_id,
                        event.source_event_id, occurrences)) {
                  result.ok = false;
                  result.error = "data_reset_event_inventory_failed";
                  break;
                }
                while (result.ok &&
                       occurrences < event.required_occurrences) {
                  // appendEvent may report a degraded sequence-journal write
                  // after the event envelope itself is durable. Verify the
                  // occurrence count independently before deciding to retry.
                  storage_.appendEvent(event.code, event.severity,
                                       event.detail, event.utc_ms,
                                       event.boot_id,
                                       request->expected_card_generation,
                                       request->expected_card_device_id,
                                       event.source_event_id);
                  std::uint64_t verified_occurrences = 0U;
                  if (!storage_.countExactEvents(
                          event.code, event.severity, event.detail,
                          event.utc_ms, event.boot_id,
                          request->expected_card_generation,
                          request->expected_card_device_id,
                          event.source_event_id,
                          verified_occurrences) ||
                      verified_occurrences <= occurrences) {
                    result.ok = false;
                    result.error = "data_reset_event_flush_failed";
                    break;
                  }
                  occurrences = verified_occurrences;
                }
              }
              if (result.ok) {
                data_reset::EventJournalRecord completed = event_journal;
                completed.state =
                    data_reset::EventJournalState::Completed;
                completed.events = {};
                if (data_reset_event_store_.saveAndVerify(completed) !=
                    DataResetStoreResult::SavedAndVerified) {
                  result.ok = false;
                  result.error =
                      "data_reset_event_completion_persistence_failed";
                } else {
                  event_journal = std::move(completed);
                }
              }
            }
            if (result.ok &&
                event_journal.state ==
                    data_reset::EventJournalState::Completed &&
                data_reset_event_store_.scrubCompletedPayloadCopies(
                    event_journal) !=
                    DataResetStoreResult::SavedAndVerified) {
              result.ok = false;
              result.error = "data_reset_event_payload_scrub_failed";
            }
            if (result.ok && !storage_.verifyDataResetCardBinding(
                                 request->expected_card_generation,
                                 request->expected_card_device_id)) {
              result.ok = false;
              result.error = "data_reset_storage_identity_changed";
            }
            for (std::size_t reverse = pending_reset_event_count;
                 result.ok && reverse > 0U; --reverse) {
              const std::size_t pending_index = reverse - 1U;
              if (!pending_event_in_journal[pending_index]) {
                continue;
              }
              if (event_pool_.get(
                      pending_reset_events[pending_index].pool_slot) ==
                  nullptr) {
                result.ok = false;
                result.error = "data_reset_event_journal_slot_invalid";
                break;
              }
              event_pool_.release(
                  pending_reset_events[pending_index].pool_slot);
              for (std::size_t index = pending_index + 1U;
                   index < pending_reset_event_count; ++index) {
                pending_reset_events[index - 1U] =
                    pending_reset_events[index];
                pending_event_in_journal[index - 1U] =
                    pending_event_in_journal[index];
              }
              pending_reset_events[--pending_reset_event_count] = {};
              pending_event_in_journal[pending_reset_event_count] = false;
            }
          } else {
            result.ok = true;
          }
        }
        if (discarded_records > 0U) {
          PM_LOG_WARN(
              "RESET", "RESET_VOLATILE_READINGS_DISCARDED",
              "count=%lu phase=commit reason=storage_barrier_pre_generation",
              static_cast<unsigned long>(discarded_records));
        }
        if (flushed_records > 0U) {
          PM_LOG_INFO("RESET", "RESET_PREPARE_RECORDS_FLUSHED", "count=%lu",
                      static_cast<unsigned long>(flushed_records));
        }
        result.complete = true;
        bool result_published = false;
        while (!result_published) {
          if (xSemaphoreTake(data_reset_mutex_, pdMS_TO_TICKS(250)) == pdTRUE) {
            data_reset_result_ = std::move(result);
            xSemaphoreGive(data_reset_mutex_);
            result_published = true;
          } else {
            // Never destroy the request or clear the queued marker before the
            // only consumer can observe this terminal barrier result. The
            // mutex is held only for a bounded copy/read, so retrying here is
            // safer than orphaning a coordinator checkpoint forever.
            if (diag::SerialLogger::instance().allow(
                    "data_reset_result_publish_wait", 5000U)) {
              PM_LOG_WARN("RESET", "RESET_RESULT_PUBLISH_WAIT",
                          "request_id=%lu retryable=true",
                          static_cast<unsigned long>(request->request_id));
            }
            vTaskDelay(pdMS_TO_TICKS(10));
          }
        }
        delete request;
        data_reset_barrier_queued_.store(false, std::memory_order_release);
      }
      continue;
    }

    if (pending_reset_event_count > 0U) {
      // The event could not yet be persisted. Do not consume ordinary record
      // writes out of order, but loop so reset/retention control retains
      // priority and can make progress.
      vTaskDelay(pdMS_TO_TICKS(100));
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
        storage_pending_record_active_.store(false,
                                             std::memory_order_seq_cst);
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
        pending_record = &pending_record_storage;
        storage_pending_record_active_.store(true,
                                             std::memory_order_seq_cst);
        record_pool_.release(message.pool_slot);
      } else {
        PM_LOG_ERROR("QUEUE", "STORAGE_POOL_SLOT_INVALID",
                     "error=PM-QUEUE-004 type=record slot=%u",
                     static_cast<unsigned>(message.pool_slot));
      }
      break;
    case Type::Event: {
      FixedEventData *const event = event_pool_.get(message.pool_slot);
      if (event != nullptr) {
        const bool appended = storage_.appendEvent(
            event->code.data(), event->severity.data(), event->detail.data(),
            event->utc_ms, event->boot_id.data(), 0U, {},
            event->source_event_id);
        if (appended) {
          event_pool_.release(message.pool_slot);
        } else if (!record_writes_enabled_.load(std::memory_order_acquire)) {
          // A prepared reset intentionally disables reading writes while
          // diagnostic events remain in scope for preservation. Keep the pool
          // slot owned until commit cleanup creates space and flushes it.
          if (pending_reset_event_count < pending_reset_events.size()) {
            pending_reset_events[pending_reset_event_count++] = message;
          } else {
            // The pending array and event pool have the same capacity, so a
            // live current slot makes this unreachable unless ownership is
            // already corrupt. Fail closed by retaining rather than releasing
            // the event and surfacing the invariant violation.
            PM_LOG_ERROR("RESET", "RESET_EVENT_BUFFER_INVARIANT_FAILED",
                         "error=data_reset_event_buffer_full slot=%u",
                         static_cast<unsigned>(message.pool_slot));
          }
        } else {
          event_pool_.release(message.pool_slot);
        }
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
    case Type::DataResetReconcileSequence:
      delete static_cast<DataResetReconcileData *>(message.payload);
      data_reset_sequence_reconciliation_queued_.store(
          false, std::memory_order_release);
      break;
    case Type::DataResetBarrier:
      delete static_cast<DataResetBarrierData *>(message.payload);
      data_reset_barrier_queued_.store(false, std::memory_order_release);
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
