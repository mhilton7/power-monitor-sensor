#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <FS.h>
#include <SPI.h>

#include "core/Models.h"
#include "storage/StoragePolicy.h"
#include "storage/SyncCoverage.h"

namespace pm {

struct StorageHealth {
  bool present{false};
  bool mounted{false};
  bool writable{false};
  bool prepared_for_removal{false};
  bool sequence_floor_ready{false};
  bool sequence_reconciliation_in_progress{false};
  bool sequence_conflict{false};
  bool last_self_test_passed{false};
  bool card_replaced_or_initialized{false};
  bool index_healthy{false};
  std::uint64_t capacity_bytes{0};
  std::uint64_t used_bytes{0};
  std::uint64_t free_bytes{0};
  std::uint64_t oldest_sequence{0};
  std::uint64_t oldest_syncable_sequence{0};
  std::uint64_t newest_syncable_sequence{0};
  std::uint64_t newest_sequence{0};
  std::uint64_t local_record_count{0};
  std::uint64_t oldest_event_sequence{0};
  std::uint64_t newest_event_sequence{0};
  std::uint64_t writes{0};
  std::uint64_t reads{0};
  std::uint64_t reading_record_reads{0};
  std::uint64_t event_record_reads{0};
  std::uint64_t write_failures{0};
  std::uint64_t read_failures{0};
  std::uint32_t mount_cycles{0};
  std::uint32_t repair_count{0};
  std::uint32_t last_write_latency_ms{0};
  std::uint32_t spi_hz{0};
  std::uint64_t last_write_utc_ms{0};
  std::uint64_t server_ack_sequence{0};
  std::uint64_t sequence_floor{0};
  std::uint64_t next_sequence{1};
  std::uint64_t sequence_floor_advances{0};
  std::uint64_t sequence_floor_write_failures{0};
  std::uint64_t sequence_floor_verify_failures{0};
  std::uint64_t card_generation{0};
  std::uint64_t event_ack_sequence{0};
  std::uint64_t reclaimable_bytes{0};
  std::uint64_t protected_unacknowledged_bytes{0};
  std::uint64_t protected_untrusted_bytes{0};
  std::uint64_t last_cleanup_utc_ms{0};
  std::uint64_t last_cleanup_reclaimed_bytes{0};
  std::uint64_t dropped_interval_count{0};
  std::uint64_t first_dropped_interval_utc_ms{0};
  std::uint64_t last_dropped_interval_utc_ms{0};
  std::uint64_t growth_bytes_per_day{0};
  std::int64_t estimated_days_remaining{-1};
  std::uint32_t segment_count{0};
  std::uint32_t eligible_segment_count{0};
  std::uint32_t protected_segment_count{0};
  std::uint32_t open_segment_count{0};
  std::uint32_t closed_segment_count{0};
  std::uint32_t untrusted_segment_count{0};
  std::uint32_t event_segment_count{0};
  std::uint32_t export_count{0};
  std::uint32_t repair_artifact_count{0};
  std::uint32_t temporary_artifact_count{0};
  std::uint8_t free_percent{0};
  bool acknowledgement_verified{false};
  bool cleanup_in_progress{false};
  bool cleanup_recovery_required{false};
  bool storage_full{false};
  std::string filesystem{"FAT32"};
  std::string card_type{"unknown"};
  std::string card_identity_status{"unknown"};
  std::string card_device_id;
  std::string current_file;
  std::string pressure_state{"failed"};
  std::string pressure_reason{"not_initialized"};
  std::string last_cleanup_result{"never"};
  std::string last_cleanup_reason;
  std::string last_error;
};

struct SequenceState {
  bool storage_present{false};
  bool storage_mounted{false};
  bool storage_writable{false};
  bool card_empty{true};
  bool sequence_floor_ready{false};
  bool sequence_reconciliation_in_progress{false};
  bool sequence_conflict{false};
  std::uint64_t local_record_count{0};
  std::uint64_t local_oldest_sequence{0};
  std::uint64_t local_newest_sequence{0};
  std::uint64_t local_journal_high_water{0};
  std::uint64_t prepared_removal_high_water{0};
  std::uint64_t persisted_server_ack{0};
  std::uint64_t persisted_server_max_seen{0};
  std::uint64_t effective_sequence_floor{0};
  std::uint64_t next_sequence{1};
  std::uint64_t card_generation{0};
  std::string card_identity_status{"unknown"};
};

struct HistoryQuery {
  std::uint64_t after_sequence{0};
  std::uint64_t from_utc_ms{0};
  std::uint64_t to_utc_ms{0};
  std::uint16_t limit{100};
  std::size_t maximum_payload_bytes{48 * 1024};
  bool require_syncable{false};
};

struct HistoryPage {
  bool ok{false};
  bool gone{false};
  std::uint64_t first_sequence{0};
  std::uint64_t last_sequence{0};
  bool has_more{false};
  std::uint64_t next_after_sequence{0};
  std::vector<std::string> records;
  std::string error_code;
  std::vector<SequenceRange> unavailable_sequence_ranges;
};

class SdStorage {
public:
  SdStorage();
  bool begin(std::uint32_t spi_hz, const std::string &device_id,
             const std::string &hardware_fingerprint,
             std::uint64_t required_sequence_floor);
  bool remount(std::uint32_t spi_hz);
  bool remountPreferred();
  bool append(IntervalRecord &record);
  bool appendEvent(const std::string &code, const std::string &severity,
                   const std::string &detail, std::uint64_t utc_ms,
                   const std::string &boot_id);
  HistoryPage readPage(const HistoryQuery &query);
  HistoryPage readEvents(const HistoryQuery &query);
  bool selfTest();
  bool rebuildIndexes();
  bool applyRetention(std::uint64_t server_ack_sequence,
                      bool acknowledgement_verified,
                      std::uint64_t event_ack_sequence,
                      std::uint64_t now_utc_ms,
                      const StoragePolicy &policy,
                      const std::string &reason);
  bool prepareRemoval();
  bool reserveUnavailableIntervals(std::uint64_t count,
                                   std::uint64_t first_utc_ms,
                                   std::uint64_t last_utc_ms);
  StorageHealth health() const;
  SequenceState sequenceState(std::uint64_t persisted_server_ack,
                              std::uint64_t persisted_server_max_seen,
                              std::uint64_t prepared_removal_high_water) const;
  std::uint64_t nextSequence() const;
  bool advanceSequenceFloor(std::uint64_t acknowledged_sequence);

private:
  bool initializeLayout();
  bool recover();
  bool recoverCleanupJournal();
  bool recoverFile(const std::string &path, std::uint64_t &maximum_sequence);
  bool writeManifest();
  bool loadSequenceJournal(const char *path, std::uint64_t &value) const;
  bool persistSequence(std::uint64_t committed_sequence);
  bool persistEventSequence(std::uint64_t committed_sequence);
  bool ensureDirectory(const std::string &path);
  std::string recordPath(const IntervalRecord &record) const;
  std::string indexPath(const IntervalRecord &record) const;
  std::string eventPath(std::uint64_t utc_ms, const std::string &boot_id) const;
  std::string serializeRecord(const IntervalRecord &record) const;
  void collectFiles(const std::string &directory, const char *suffix,
                    std::vector<std::string> &output) const;
  HistoryPage readEnvelopeFiles(const std::vector<std::string> &paths,
                                const HistoryQuery &query,
                                const char *sequence_field);
  bool appendIndex(const std::string &path, std::uint64_t sequence,
                   std::uint64_t utc_ms, std::uint64_t offset,
                   std::uint32_t payload_crc);
  void updateCapacity();
  bool loadSegmentMetadata(const std::string &path, bool event_segment,
                           SegmentMetadata &metadata) const;
  SegmentMetadata inspectSegment(const std::string &path) const;
  SegmentMetadata inspectEventSegment(const std::string &path) const;
  bool persistSegmentMetadata(const SegmentMetadata &metadata) const;
  bool removeSegmentTransactionally(const SegmentMetadata &metadata,
                                    std::uint64_t server_ack_sequence,
                                    std::uint64_t now_utc_ms,
                                    const std::string &reason);
  bool persistCleanupJournal(const SegmentMetadata &metadata,
                             const std::string &record_trash,
                             const std::string &index_trash,
                             std::uint64_t server_ack_sequence,
                             std::uint64_t now_utc_ms,
                             const std::string &reason,
                             const char *stage) const;
  bool clearCleanupJournal() const;
  void cleanupTemporaryArtifacts(std::uint64_t now_utc_ms);
  std::string metadataPath(const std::string &record_path) const;
  bool lock(TickType_t timeout = pdMS_TO_TICKS(5000)) const;
  void unlock() const;
  void publishHealthSnapshot(const StorageHealth &snapshot) const;

  SPIClass spi_;
  mutable SemaphoreHandle_t mutex_{nullptr};
  mutable SemaphoreHandle_t health_snapshot_mutex_{nullptr};
  StorageHealth health_;
  mutable StorageHealth last_health_snapshot_;
  std::uint64_t next_sequence_{1};
  std::uint64_t next_event_sequence_{1};
  std::uint64_t required_sequence_floor_{0};
  std::string device_id_;
  std::string hardware_fingerprint_;
  std::uint32_t preferred_spi_hz_{0};
  StoragePolicy active_policy_{};
  StorageGrowthEstimator growth_estimator_{};
};

} // namespace pm
