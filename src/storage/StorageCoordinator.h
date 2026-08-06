#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <string>

#include "diagnostics/Diagnostics.h"
#include "reset/DataResetDrainStore.h"
#include "reset/DataResetEventStore.h"
#include "storage/BoundedStorageMessagePool.h"
#include "storage/SdStorage.h"

namespace pm {

class StorageCoordinator {
public:
  static constexpr std::uint16_t kRecordPoolCapacity = 120U;
  static constexpr std::uint16_t kEventPoolCapacity = 16U;

  struct PoolMetrics {
    BoundedStoragePoolMetrics records{};
    BoundedStoragePoolMetrics events{};
  };

  struct DataResetPrepareProjection {
    bool consistent{false};
    std::uint64_t local_record_count{0U};
    std::uint64_t next_sequence{0U};
    std::uint64_t newest_sequence{0U};
    std::uint64_t newest_syncable_sequence{0U};
    std::uint64_t drain_records{0U};
    bool drain_sequence_range_set{false};
    std::uint64_t drain_first_sequence{0U};
    std::uint64_t drain_last_sequence{0U};
    std::uint64_t drain_syncable_records{0U};
  };

  struct DataResetStorageResult {
    std::uint32_t request_id{0};
    bool complete{false};
    bool ok{false};
    bool cleanup_requested{false};
    std::uint64_t prepare_drain_records_added{0U};
    bool prepare_drain_sequence_range_set{false};
    std::uint64_t prepare_drain_first_sequence{0U};
    std::uint64_t prepare_drain_last_sequence{0U};
    std::uint64_t prepare_drain_syncable_records_added{0U};
    std::uint64_t prepare_drain_energy_offset_wh{0U};
    DataResetCleanupResult cleanup{};
    std::string error;
  };

  StorageCoordinator(SdStorage &storage, Diagnostics &diagnostics);
  bool begin();
  bool enqueueRecord(const IntervalRecord &record);
  // The aggregation task uses this one-shot path only after ordinary record
  // writes are closed. It transfers the fully closed pre-reset interval into
  // the same FIFO that the prepare barrier drains, without reopening normal
  // producers or converting a retry into a history gap.
  bool stageRecordsForDataReset(
      const std::array<IntervalRecord, 2U> &records,
      std::uint64_t record_count,
      std::uint64_t proposed_energy_offset_wh);
  void beginDataResetProducerBarrier(const std::string &operation_id,
                                     const std::string &device_id,
                                     std::uint64_t source_generation,
                                     std::uint64_t target_generation,
                                     std::uint64_t card_generation);
  void markDataResetProducerQuiesced();
  void markDataResetPrepareDurable();
  bool dataResetProducerQuiesced() const;
  void markDataResetMeterProjectionActivity();
  std::uint64_t dataResetMeterProjectionEpoch() const;
  void publishDataResetAggregationProjection(bool stable,
                                             std::uint64_t drain_records,
                                             std::uint64_t syncable_records,
                                             bool syncable_prefix,
                                             std::uint64_t meter_epoch);
  DataResetPrepareProjection dataResetPrepareProjection() const;
  bool dataResetDrainSafeToCancel(const std::string &operation_id,
                                  const std::string &device_id,
                                  std::uint64_t source_generation,
                                  std::uint64_t target_generation,
                                  std::uint64_t card_generation,
                                  std::uint64_t installed_energy_offset_wh) const;
  bool recoverOrphanedDataResetDrain(
      const data_reset::Record *durable_reset, const std::string &device_id,
      std::uint64_t data_generation, std::uint64_t card_generation,
      std::uint64_t &recovered_energy_offset_wh, bool &recovered,
      std::string &error);
  void endDataResetProducerBarrier();
  void setRecordWritesEnabled(bool enabled);
  bool recordWritesEnabled() const;
  bool enqueueEvent(StringView code, StringView severity, StringView detail,
                    std::uint64_t utc_ms, StringView boot_id);
  bool queueRetention(std::uint64_t server_ack_sequence,
                      bool acknowledgement_verified,
                      std::uint64_t event_ack_sequence,
                      std::uint64_t now_utc_ms,
                      const StoragePolicy &policy,
                      const std::string &reason,
                      bool high_priority = false);
  bool queuePrepareRemoval();
  bool queueSelfTest();
  bool queueRemount();
  bool queueRebuildIndexes();
  bool queueSequenceReconciliation(std::uint64_t required_sequence_floor);
  bool queueDataResetSequenceReconciliation(
      std::uint64_t required_sequence_floor,
      std::uint64_t expected_card_generation,
      const std::string &expected_card_device_id);
  bool queueDataResetBarrier(std::uint32_t request_id, bool cleanup,
                             std::uint64_t expected_card_generation = 0U,
                             const std::string &expected_card_device_id = {},
                             const std::string &operation_id = {},
                             std::uint64_t source_generation = 0U,
                             std::uint64_t target_generation = 0U);
  bool dataResetStorageResult(std::uint32_t request_id,
                              DataResetStorageResult &result) const;
  bool clearReadingHistoryResults();
  std::string queueHistory(const HistoryQuery &query, bool events = false,
                           bool primary_sync = false);
  bool historyResult(const std::string &id, HistoryPage &page, bool &complete,
                     bool consume = false,
                     TickType_t lock_timeout = pdMS_TO_TICKS(25));
  void taskLoop();
  std::uint32_t depth() const;
  std::uint64_t dropped() const;
  PoolMetrics poolMetrics() const;

private:
  enum class Type : std::uint8_t {
    Record,
    Event,
    History,
    Remount,
    SelfTest,
    RebuildIndexes,
    Retention,
    PrepareRemoval,
    ReconcileSequence,
    DataResetReconcileSequence,
    DataResetBarrier,
  };
  struct HistoryData {
    std::string id;
    HistoryQuery query;
    bool events{false};
    bool primary_sync{false};
  };
  struct RetentionData {
    std::uint64_t server_ack_sequence{0};
    std::uint64_t event_ack_sequence{0};
    std::uint64_t now_utc_ms{0};
    StoragePolicy policy{};
    std::string reason;
    bool acknowledgement_verified{false};
  };
  struct HistoryResult {
    bool used{false};
    bool complete{false};
    std::string id;
    HistoryPage page;
    std::uint64_t expires_ms{0};
    bool events{false};
  };
  struct DataResetBarrierData {
    std::uint32_t request_id{0};
    bool cleanup{false};
    std::uint64_t expected_card_generation{0U};
    std::string expected_card_device_id;
    std::string operation_id;
    std::uint64_t source_generation{0U};
    std::uint64_t target_generation{0U};
  };
  struct DataResetReconcileData {
    std::uint64_t required_sequence_floor{0U};
    std::uint64_t expected_card_generation{0U};
    std::string expected_card_device_id;
  };
  struct Message {
    Type type;
    void *payload;
    std::uint16_t pool_slot{kInvalidStoragePoolSlot};
  };

  bool remountStorage();
  void recordDroppedInterval(const IntervalRecord &record);
  bool completeDataResetDrain(DataResetStorageResult &result,
                              std::string &error);

  SdStorage &storage_;
  Diagnostics &diagnostics_;
  QueueHandle_t write_queue_{nullptr};
  QueueHandle_t control_queue_{nullptr};
  SemaphoreHandle_t history_mutex_{nullptr};
  SemaphoreHandle_t data_reset_mutex_{nullptr};
  // Each local API result is bounded to 12 KiB. Two slots keep
  // concurrent UI/export work possible without allowing abandoned jobs to
  // retain more payload memory than the ESP32-S3 internal heap can sustain.
  std::array<HistoryResult, 2> history_results_{};
  std::atomic<std::uint32_t> next_history_id_{1};
  std::atomic<std::uint64_t> dropped_{0};
  std::atomic<std::uint64_t> next_source_event_id_{1U};
  std::atomic<std::uint64_t> dropped_record_intervals_{0};
  std::atomic<std::uint64_t> first_dropped_interval_utc_ms_{0};
  std::atomic<std::uint64_t> last_dropped_interval_utc_ms_{0};
  std::atomic<bool> retention_queued_{false};
  std::atomic<bool> prepare_removal_queued_{false};
  std::atomic<bool> sequence_reconciliation_queued_{false};
  std::atomic<bool> data_reset_sequence_reconciliation_queued_{false};
  std::atomic<bool> record_writes_enabled_{true};
  // Closing the reset gate and waiting for this counter to reach zero forms
  // the producer side of the storage barrier. The second gate check in
  // enqueueRecord() prevents a producer that raced with gate closure from
  // publishing a record after the barrier has drained the queue.
  std::atomic<std::uint32_t> record_enqueues_in_flight_{0};
  // MeterTask is the only writer. It increments once before and once after
  // each poll/publication transaction, so odd means in flight. Aggregation
  // publishes the even epoch it observed with an empty ingress queue.
  std::atomic<std::uint64_t> data_reset_meter_projection_epoch_{0U};
  // Single-writer seqlock for the aggregation projection. Odd values mean a
  // publication is in progress; an equal even value before and after the
  // payload reads proves the fields came from one publication.
  std::atomic<std::uint64_t> data_reset_projection_version_{0U};
  std::atomic<bool> data_reset_aggregation_projection_stable_{false};
  std::atomic<std::uint64_t> data_reset_projection_drain_records_{0U};
  std::atomic<std::uint64_t> data_reset_projection_syncable_records_{0U};
  std::atomic<bool> data_reset_projection_syncable_prefix_{true};
  std::atomic<std::uint64_t> data_reset_projection_meter_epoch_{0U};
  std::atomic<bool> storage_pending_record_active_{false};
  std::atomic<bool> data_reset_producer_barrier_active_{false};
  std::atomic<bool> data_reset_producer_quiesced_{true};
  std::atomic<bool> data_reset_prepare_durable_{false};
  std::string data_reset_operation_id_;
  std::string data_reset_device_id_;
  std::uint64_t data_reset_source_generation_{0U};
  std::uint64_t data_reset_target_generation_{0U};
  std::uint64_t data_reset_card_generation_{0U};
  DataResetDrainStore data_reset_drain_store_{};
  DataResetEventStore data_reset_event_store_{};
  std::atomic<bool> data_reset_barrier_queued_{false};
  DataResetStorageResult data_reset_result_{};
  std::atomic<std::uint64_t> required_sequence_floor_{0};
  BoundedStoragePool<FixedIntervalRecord>::Slot *record_slots_{nullptr};
  BoundedStoragePool<FixedEventData>::Slot *event_slots_{nullptr};
  BoundedStoragePool<FixedIntervalRecord> record_pool_{};
  BoundedStoragePool<FixedEventData> event_pool_{};
};

} // namespace pm
