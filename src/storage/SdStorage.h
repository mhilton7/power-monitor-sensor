#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <FS.h>
#include <SPI.h>

#include "core/Models.h"

namespace pm {

struct StorageHealth {
  bool present{false};
  bool mounted{false};
  bool writable{false};
  bool prepared_for_removal{false};
  bool index_healthy{false};
  std::uint64_t capacity_bytes{0};
  std::uint64_t used_bytes{0};
  std::uint64_t free_bytes{0};
  std::uint64_t oldest_sequence{0};
  std::uint64_t oldest_syncable_sequence{0};
  std::uint64_t newest_sequence{0};
  std::uint64_t writes{0};
  std::uint64_t reads{0};
  std::uint64_t write_failures{0};
  std::uint64_t read_failures{0};
  std::uint32_t mount_cycles{0};
  std::uint32_t repair_count{0};
  std::uint32_t last_write_latency_ms{0};
  std::uint32_t spi_hz{0};
  std::uint64_t last_write_utc_ms{0};
  std::string filesystem{"FAT32"};
  std::string current_file;
  std::string last_error;
};

struct HistoryQuery {
  std::uint64_t after_sequence{0};
  std::uint64_t from_utc_ms{0};
  std::uint64_t to_utc_ms{0};
  std::uint16_t limit{100};
  std::size_t maximum_payload_bytes{48 * 1024};
  bool require_syncable{false};
};

struct SequenceRange {
  std::uint64_t start_sequence{0};
  std::uint64_t end_sequence{0};
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
  bool begin(std::uint32_t spi_hz);
  bool remount(std::uint32_t spi_hz);
  bool append(IntervalRecord &record);
  bool appendEvent(const std::string &code, const std::string &severity,
                   const std::string &detail, std::uint64_t utc_ms,
                   const std::string &boot_id);
  HistoryPage readPage(const HistoryQuery &query);
  HistoryPage readEvents(const HistoryQuery &query);
  bool selfTest();
  bool rebuildIndexes();
  bool applyRetention(std::uint64_t server_ack_sequence,
                      std::uint64_t now_utc_ms, std::uint16_t retention_days);
  bool prepareRemoval();
  StorageHealth health() const;
  std::uint64_t nextSequence() const;

private:
  bool initializeLayout();
  bool recover();
  bool recoverFile(const std::string &path, std::uint64_t &maximum_sequence);
  bool writeManifest();
  bool persistSequence(std::uint64_t committed_sequence);
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
  bool lock(TickType_t timeout = pdMS_TO_TICKS(5000)) const;
  void unlock() const;

  SPIClass spi_;
  mutable SemaphoreHandle_t mutex_{nullptr};
  StorageHealth health_;
  std::uint64_t next_sequence_{1};
};

} // namespace pm
