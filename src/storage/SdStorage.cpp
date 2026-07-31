#include "storage/SdStorage.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <limits>

#include <Arduino.h>
#include <ArduinoJson.h>
#include <SD.h>

#include "board_pins.h"
#include "build_config.h"
#include "core/Algorithms.h"
#include "diagnostics/SerialLogger.h"
#include "storage/RecordFormat.h"
#include "version.h"

namespace pm {
namespace {

std::string isoUtc(const std::uint64_t utc_ms) {
  if (utc_ms == 0) {
    return "1970-01-01T00:00:00Z";
  }
  const std::time_t seconds = static_cast<std::time_t>(utc_ms / 1000U);
  struct tm broken_down{};
  gmtime_r(&seconds, &broken_down);
  char output[80]{};
  std::snprintf(output, sizeof(output), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                broken_down.tm_year + 1900, broken_down.tm_mon + 1,
                broken_down.tm_mday, broken_down.tm_hour, broken_down.tm_min,
                broken_down.tm_sec);
  return output;
}

std::string datedPath(const char *category, const char *extension,
                      const std::uint64_t utc_ms, const std::string &fallback) {
  if (utc_ms == 0) {
    return std::string("/POWERMON/") + category + "/untrusted/" + fallback +
           extension;
  }
  const std::time_t seconds = static_cast<std::time_t>(utc_ms / 1000U);
  struct tm broken_down{};
  gmtime_r(&seconds, &broken_down);
  char output[96]{};
  std::snprintf(output, sizeof(output),
                "/POWERMON/%s/%04d/%02d/%04d-%02d-%02d%s", category,
                broken_down.tm_year + 1900, broken_down.tm_mon + 1,
                broken_down.tm_year + 1900, broken_down.tm_mon + 1,
                broken_down.tm_mday, extension);
  return output;
}

bool endsWith(const std::string &value, const char *suffix) {
  const std::size_t suffix_length = std::char_traits<char>::length(suffix);
  return value.size() >= suffix_length &&
         value.compare(value.size() - suffix_length, suffix_length, suffix) ==
             0;
}

const char *cardTypeName(const std::uint8_t type) {
  switch (type) {
  case CARD_MMC:
    return "MMC";
  case CARD_SD:
    return "SDSC";
  case CARD_SDHC:
    return "SDHC";
  case CARD_NONE:
    return "none";
  default:
    return "unknown";
  }
}

constexpr std::uint32_t kSdRecoveryClockHz = 400'000U;
constexpr std::uint32_t kSdFallbackClockHz = 1'000'000U;
constexpr std::size_t kSdIdleClockBytes = 10U;
constexpr std::uint64_t kSyncCoverageWindow = 500U;
constexpr std::size_t kCooperativeScanRecords = 8U;
constexpr std::size_t kCooperativeScanBytes = 256U;

bool syncableInterval(const std::uint64_t start_utc_ms,
                      const std::uint64_t end_utc_ms,
                      const bool time_trusted) {
  return time_trusted && start_utc_ms != 0U && end_utc_ms > start_utc_ms;
}

bool syncableRecord(const IntervalRecord &record) {
  return syncableInterval(record.start_utc_ms, record.end_utc_ms,
                          record.time_trusted);
}

bool syncableDocument(const JsonDocument &document) {
  return syncableInterval(document["start_utc_ms"] | 0ULL,
                          document["end_utc_ms"] | 0ULL,
                          document["time_trusted"] | false);
}

void prepareSdSpiBus(SPIClass &spi) {
  // A CPU/USB reset does not power-cycle the card. If reset interrupted a
  // transfer, explicitly deassert CS and provide the 80 idle clocks required
  // for an SD card to return to a command-ready SPI state before SD.begin().
  pinMode(pins::SD_CS, OUTPUT);
  digitalWrite(pins::SD_CS, HIGH);
  delay(10U);
  spi.begin(pins::SD_SCK, pins::SD_MISO, pins::SD_MOSI, pins::SD_CS);
  spi.beginTransaction(SPISettings(kSdRecoveryClockHz, MSBFIRST, SPI_MODE0));
  for (std::size_t index = 0; index < kSdIdleClockBytes; ++index) {
    spi.transfer(0xFFU);
  }
  spi.endTransaction();
  delay(2U);
}

} // namespace

SdStorage::SdStorage() : spi_(FSPI) {
  mutex_ = xSemaphoreCreateRecursiveMutex();
  health_snapshot_mutex_ = xSemaphoreCreateMutex();
}

bool SdStorage::begin(const std::uint32_t spi_hz) {
  preferred_spi_hz_ = std::min(spi_hz, build::MAX_SD_SPI_HZ);
  return remountPreferred();
}

bool SdStorage::remount(const std::uint32_t spi_hz) {
  preferred_spi_hz_ = std::min(spi_hz, build::MAX_SD_SPI_HZ);
  return remountPreferred();
}

bool SdStorage::remountPreferred() {
  const std::uint32_t requested_hz =
      preferred_spi_hz_ == 0U ? kSdRecoveryClockHz : preferred_spi_hz_;
  PM_LOG_INFO("SD", "MOUNT_BEGIN",
              "bus=FSPI cs_gpio=%d sck_gpio=%d miso_gpio=%d mosi_gpio=%d "
              "requested_hz=%lu",
              pins::SD_CS, pins::SD_SCK, pins::SD_MISO, pins::SD_MOSI,
              static_cast<unsigned long>(requested_hz));
  if (!lock()) {
    PM_LOG_WARN("SD", "MOUNT_LOCK_TIMEOUT", "error=PM-SD-010");
    return false;
  }
  SD.end();
  spi_.end();
  pinMode(pins::SD_CS, OUTPUT);
  digitalWrite(pins::SD_CS, HIGH);
  health_.mounted = health_.writable = health_.present = false;
  health_.prepared_for_removal = false;
  const std::array<std::uint32_t, 3> attempt_hz{
      requested_hz, std::min(requested_hz, kSdFallbackClockHz),
      std::min(requested_hz, kSdRecoveryClockHz)};
  ++health_.mount_cycles;
  bool mounted = false;
  std::size_t attempt = 0U;
  for (const std::uint32_t candidate_hz : attempt_hz) {
    ++attempt;
    health_.spi_hz = candidate_hz;
    prepareSdSpiBus(spi_);
    PM_LOG_INFO("SD", "MOUNT_ATTEMPT",
                "attempt=%u maximum_attempts=3 spi_hz=%lu "
                "recovery_idle_clocks=80 format_on_failure=false",
                static_cast<unsigned>(attempt),
                static_cast<unsigned long>(candidate_hz));
    if (SD.begin(pins::SD_CS, spi_, candidate_hz, "/sd", 8, false)) {
      mounted = true;
      break;
    }
    SD.end();
    spi_.end();
    digitalWrite(pins::SD_CS, HIGH);
    // Do not collapse repeated frequencies. A configuration already at the
    // 400 kHz recovery speed still needs three independent command/reset
    // attempts after a CPU-only reset interrupts an SD transaction.
    delay(static_cast<std::uint32_t>(attempt) * 25U);
  }
  if (!mounted) {
    health_.last_error = "sd_mount_failed";
    PM_LOG_ERROR(
        "SD", "MOUNT_FAILED",
        "error=PM-SD-001 attempts=%u final_spi_hz=%lu "
        "format_attempted=false hint=check_card_fat32_wiring_and_power",
        static_cast<unsigned>(attempt),
        static_cast<unsigned long>(health_.spi_hz));
    publishHealthSnapshot(health_);
    unlock();
    return false;
  }
  health_.present = true;
  health_.mounted = true;
  const bool layout_ok = initializeLayout();
  const bool self_test_ok = layout_ok && selfTest();
  const bool recovery_ok = self_test_ok && recover();
  health_.writable = layout_ok && self_test_ok && recovery_ok;
  updateCapacity();
  PM_LOG_INFO(
      "SD", "MOUNT_COMPLETE",
      "result=%s card_type=%s filesystem=%s spi_hz=%lu capacity=%llu used=%llu "
      "free=%llu layout=%s self_test=%s recovery=%s next_sequence=%llu",
      health_.writable ? "success" : "degraded", cardTypeName(SD.cardType()),
      health_.filesystem.c_str(), static_cast<unsigned long>(health_.spi_hz),
      static_cast<unsigned long long>(health_.capacity_bytes),
      static_cast<unsigned long long>(health_.used_bytes),
      static_cast<unsigned long long>(health_.free_bytes),
      layout_ok ? "ok" : "failed", self_test_ok ? "ok" : "failed",
      recovery_ok ? "ok" : "failed",
      static_cast<unsigned long long>(next_sequence_));
  publishHealthSnapshot(health_);
  unlock();
  return health_.writable;
}

bool SdStorage::append(IntervalRecord &record) {
  if (!lock()) {
    return false;
  }
  if (!health_.mounted || !health_.writable || health_.prepared_for_removal) {
    ++health_.write_failures;
    health_.last_error = "sd_not_writable";
    if (diag::SerialLogger::instance().allow("sd_not_writable", 10'000U)) {
      PM_LOG_ERROR("SD", "WRITE_REJECTED",
                   "error=PM-SD-002 mounted=%s writable=%s "
                   "prepared_for_removal=%s failures=%llu",
                   health_.mounted ? "true" : "false",
                   health_.writable ? "true" : "false",
                   health_.prepared_for_removal ? "true" : "false",
                   static_cast<unsigned long long>(health_.write_failures));
    }
    unlock();
    return false;
  }
  record.sequence = next_sequence_;
  const std::string payload = serializeRecord(record);
  const std::string envelope = record::encodeEnvelope(payload);
  const std::string path = recordPath(record);
  const std::size_t slash = path.find_last_of('/');
  if (slash == std::string::npos || !ensureDirectory(path.substr(0, slash))) {
    ++health_.write_failures;
    health_.last_error = "record_directory_failed";
    PM_LOG_ERROR("SD", "RECORD_DIRECTORY_FAILED",
                 "error=PM-SD-003 sequence=%llu",
                 static_cast<unsigned long long>(record.sequence));
    unlock();
    return false;
  }
  const std::uint32_t started = millis();
  File file = SD.open(path.c_str(), FILE_APPEND);
  if (!file) {
    ++health_.write_failures;
    health_.last_error = "record_open_failed";
    PM_LOG_ERROR("SD", "RECORD_OPEN_FAILED", "error=PM-SD-004 sequence=%llu",
                 static_cast<unsigned long long>(record.sequence));
    unlock();
    return false;
  }
  const std::uint64_t offset = file.size();
  const std::size_t written = file.write(
      reinterpret_cast<const std::uint8_t *>(envelope.data()), envelope.size());
  file.flush();
  file.close();
  if (written != envelope.size()) {
    ++health_.write_failures;
    health_.writable = false;
    health_.last_error = "record_write_incomplete";
    PM_LOG_ERROR(
        "SD", "RECORD_WRITE_INCOMPLETE",
        "error=PM-SD-005 sequence=%llu expected_bytes=%u written_bytes=%u",
        static_cast<unsigned long long>(record.sequence),
        static_cast<unsigned>(envelope.size()), static_cast<unsigned>(written));
    unlock();
    return false;
  }
  const std::uint32_t payload_crc = record::crc32(
      reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size());
  if (!appendIndex(indexPath(record), record.sequence, record.start_utc_ms,
                   offset, payload_crc)) {
    health_.index_healthy = false;
    health_.last_error = "index_append_failed";
    PM_LOG_WARN("SD", "INDEX_APPEND_FAILED",
                "error=PM-SD-006 sequence=%llu recovery=rebuild_indexes",
                static_cast<unsigned long long>(record.sequence));
  }
  if (!persistSequence(record.sequence)) {
    ++health_.write_failures;
    health_.last_error = "sequence_journal_failed";
    PM_LOG_ERROR("SD", "SEQUENCE_JOURNAL_FAILED",
                 "error=PM-SD-007 sequence=%llu",
                 static_cast<unsigned long long>(record.sequence));
    unlock();
    return false;
  }
  health_.oldest_sequence =
      health_.oldest_sequence == 0
          ? record.sequence
          : std::min(health_.oldest_sequence, record.sequence);
  if (syncableRecord(record)) {
    health_.oldest_syncable_sequence =
        health_.oldest_syncable_sequence == 0
            ? record.sequence
            : std::min(health_.oldest_syncable_sequence, record.sequence);
  }
  health_.newest_sequence = record.sequence;
  ++next_sequence_;
  ++health_.writes;
  health_.last_write_latency_ms = millis() - started;
  health_.last_write_utc_ms = record.end_utc_ms;
  health_.current_file = path;
  updateCapacity();
  PM_LOG_TRACE("SD", "RECORD_WRITE_COMPLETE",
               "sequence=%llu bytes=%u latency_ms=%lu file=%s free=%llu",
               static_cast<unsigned long long>(record.sequence),
               static_cast<unsigned>(envelope.size()),
               static_cast<unsigned long>(health_.last_write_latency_ms),
               health_.current_file.c_str(),
               static_cast<unsigned long long>(health_.free_bytes));
  if (diag::SerialLogger::instance().allow("sd_write_summary", 60'000U)) {
    PM_LOG_INFO("SD", "WRITE_SUMMARY",
                "writes=%llu failures=%llu last_latency_ms=%lu "
                "newest_sequence=%llu free=%llu index_healthy=%s",
                static_cast<unsigned long long>(health_.writes),
                static_cast<unsigned long long>(health_.write_failures),
                static_cast<unsigned long>(health_.last_write_latency_ms),
                static_cast<unsigned long long>(health_.newest_sequence),
                static_cast<unsigned long long>(health_.free_bytes),
                health_.index_healthy ? "true" : "false");
  }
  publishHealthSnapshot(health_);
  unlock();
  return true;
}

bool SdStorage::appendEvent(const std::string &code,
                            const std::string &severity,
                            const std::string &detail,
                            const std::uint64_t utc_ms,
                            const std::string &boot_id) {
  if (!lock()) {
    return false;
  }
  if (!health_.mounted || !health_.writable || code.size() > 64 ||
      severity.size() > 16 || detail.size() > 512) {
    unlock();
    return false;
  }
  JsonDocument document;
  document["schema_version"] = 1;
  document["event_sequence"] = static_cast<std::uint64_t>(health_.writes + 1);
  document["timestamp_utc"] = isoUtc(utc_ms);
  document["timestamp_utc_ms"] = utc_ms;
  document["boot_id"] = boot_id;
  document["code"] = code;
  document["severity"] = severity;
  document["detail"] = detail;
  std::string payload;
  serializeJson(document, payload);
  const std::string envelope = record::encodeEnvelope(payload);
  const std::string path = eventPath(utc_ms, boot_id);
  const std::size_t slash = path.find_last_of('/');
  const bool directory_ok =
      slash != std::string::npos && ensureDirectory(path.substr(0, slash));
  File file = directory_ok ? SD.open(path.c_str(), FILE_APPEND) : File{};
  const bool ok =
      file &&
      file.write(reinterpret_cast<const std::uint8_t *>(envelope.data()),
                 envelope.size()) == envelope.size();
  if (file) {
    file.flush();
    file.close();
  }
  ok ? ++health_.writes : ++health_.write_failures;
  unlock();
  return ok;
}

HistoryPage SdStorage::readPage(const HistoryQuery &query) {
  if (!lock()) {
    return {false, false, 0, 0, false, 0, {}, "storage_busy", {}};
  }
  if (query.after_sequence != 0 && health_.oldest_sequence != 0 &&
      query.after_sequence + 1 < health_.oldest_sequence) {
    HistoryPage gone;
    gone.gone = true;
    gone.error_code = "history_expired";
    gone.first_sequence = health_.oldest_sequence;
    gone.last_sequence = health_.newest_sequence;
    unlock();
    return gone;
  }
  std::vector<std::string> files;
  collectFiles("/POWERMON/records", ".pmr", files);
  std::sort(files.begin(), files.end());
  HistoryPage page = readEnvelopeFiles(files, query, "sequence");
  unlock();
  return page;
}

HistoryPage SdStorage::readEvents(const HistoryQuery &query) {
  if (!lock()) {
    return {false, false, 0, 0, false, 0, {}, "storage_busy", {}};
  }
  std::vector<std::string> files;
  collectFiles("/POWERMON/events", ".events", files);
  std::sort(files.begin(), files.end());
  HistoryPage page = readEnvelopeFiles(files, query, "event_sequence");
  unlock();
  return page;
}

bool SdStorage::selfTest() {
  if (!lock()) {
    return false;
  }
  if (!health_.mounted) {
    unlock();
    return false;
  }
  const std::string path = "/POWERMON/recovery/.self-test";
  const std::string expected = "pm-sd-self-test-v1-" + std::to_string(millis());
  File write_file = SD.open(path.c_str(), FILE_WRITE);
  bool ok =
      write_file &&
      write_file.write(reinterpret_cast<const std::uint8_t *>(expected.data()),
                       expected.size()) == expected.size();
  if (write_file) {
    write_file.flush();
    write_file.close();
  }
  File read_file = ok ? SD.open(path.c_str(), FILE_READ) : File{};
  std::string actual;
  while (read_file && read_file.available() > 0 &&
         actual.size() <= expected.size()) {
    actual.push_back(static_cast<char>(read_file.read()));
  }
  if (read_file) {
    read_file.close();
  }
  ok = ok && actual == expected;
  SD.remove(path.c_str());
  health_.writable = ok;
  health_.last_error = ok ? "" : "sd_self_test_failed";
  if (ok) {
    PM_LOG_INFO("SD", "SELF_TEST_COMPLETE", "result=success readback=verified");
  } else {
    PM_LOG_ERROR("SD", "SELF_TEST_FAILED",
                 "error=PM-SD-008 hint=check_card_write_protection_and_fat32");
  }
  unlock();
  return ok;
}

bool SdStorage::rebuildIndexes() {
  if (!lock()) {
    return false;
  }
  if (!health_.mounted) {
    unlock();
    return false;
  }
  PM_LOG_INFO("SD", "INDEX_REBUILD_BEGIN", "reason=authorized_or_recovery");
  std::vector<std::string> files;
  collectFiles("/POWERMON/records", ".pmr", files);
  bool ok = true;
  for (const auto &data_path : files) {
    std::string index_path = data_path;
    const std::size_t records_pos = index_path.find("/records/");
    if (records_pos == std::string::npos) {
      continue;
    }
    index_path.replace(records_pos, 9, "/indexes/");
    index_path.replace(index_path.size() - 4, 4, ".idx");
    const std::size_t slash = index_path.find_last_of('/');
    ensureDirectory(index_path.substr(0, slash));
    SD.remove(index_path.c_str());
    File input = SD.open(data_path.c_str(), FILE_READ);
    std::uint64_t offset = 0;
    while (input && input.available() > 0) {
      std::string line;
      while (input.available() > 0) {
        const char value = static_cast<char>(input.read());
        line.push_back(value);
        if (value == '\n') {
          break;
        }
      }
      std::string payload;
      std::uint32_t checksum = 0;
      if (!record::decodeEnvelope(line, payload, checksum)) {
        ok = false;
        break;
      }
      JsonDocument document;
      if (deserializeJson(document, payload)) {
        ok = false;
        break;
      }
      ok = appendIndex(index_path, document["sequence"].as<std::uint64_t>(),
                       document["start_utc_ms"].as<std::uint64_t>(), offset,
                       checksum) &&
           ok;
      offset += line.size();
    }
    if (input) {
      input.close();
    }
  }
  health_.index_healthy = ok;
  if (ok) {
    ++health_.repair_count;
  }
  PM_LOG_INFO("SD", "INDEX_REBUILD_COMPLETE",
              "result=%s files=%u repair_count=%lu", ok ? "success" : "failed",
              static_cast<unsigned>(files.size()),
              static_cast<unsigned long>(health_.repair_count));
  unlock();
  return ok;
}

bool SdStorage::applyRetention(const std::uint64_t server_ack_sequence,
                               const std::uint64_t now_utc_ms,
                               const std::uint16_t retention_days) {
  if (!lock())
    return false;
  PM_LOG_INFO("SD", "RETENTION_BEGIN",
              "server_ack_sequence=%llu now_utc_ms=%llu retention_days=%u",
              static_cast<unsigned long long>(server_ack_sequence),
              static_cast<unsigned long long>(now_utc_ms),
              static_cast<unsigned>(retention_days));
  if (!health_.mounted || retention_days == 0 || now_utc_ms == 0) {
    unlock();
    return false;
  }
  const std::uint64_t retention_ms =
      static_cast<std::uint64_t>(retention_days) * 86'400'000ULL;
  const std::uint64_t cutoff =
      now_utc_ms > retention_ms ? now_utc_ms - retention_ms : 0;
  std::vector<std::string> files;
  collectFiles("/POWERMON/records", ".pmr", files);
  bool ok = true;
  bool removed = false;
  for (const auto &path : files) {
    File input = SD.open(path.c_str(), FILE_READ);
    bool complete = static_cast<bool>(input);
    bool trusted = true;
    std::uint64_t newest_sequence = 0;
    std::uint64_t newest_utc_ms = 0;
    while (complete && input.available() > 0) {
      std::string line;
      while (input.available() > 0 && line.size() <= 8192) {
        const char value = static_cast<char>(input.read());
        line.push_back(value);
        if (value == '\n')
          break;
      }
      std::string payload;
      std::uint32_t checksum = 0;
      JsonDocument document;
      if (!record::decodeEnvelope(line, payload, checksum) ||
          deserializeJson(document, payload)) {
        complete = false;
        break;
      }
      newest_sequence =
          std::max(newest_sequence, document["sequence"].as<std::uint64_t>());
      newest_utc_ms =
          std::max(newest_utc_ms, document["end_utc_ms"].as<std::uint64_t>());
      trusted = trusted && (document["time_trusted"] | false);
    }
    if (input)
      input.close();
    if (!retentionEligible(complete, trusted, newest_sequence,
                           server_ack_sequence, newest_utc_ms, cutoff)) {
      continue;
    }
    std::string index_path = path;
    const std::size_t records_pos = index_path.find("/records/");
    if (records_pos != std::string::npos) {
      index_path.replace(records_pos, 9, "/indexes/");
      index_path.replace(index_path.size() - 4, 4, ".idx");
    }
    const bool record_removed = SD.remove(path.c_str());
    const bool index_removed =
        !SD.exists(index_path.c_str()) || SD.remove(index_path.c_str());
    ok = record_removed && index_removed && ok;
    removed = record_removed || removed;
  }
  if (removed) {
    ok = recover() && ok;
    updateCapacity();
  }
  PM_LOG_INFO("SD", "RETENTION_COMPLETE",
              "result=%s removed=%s scanned_files=%u",
              ok ? "success" : "failed", removed ? "true" : "false",
              static_cast<unsigned>(files.size()));
  unlock();
  return ok;
}

bool SdStorage::prepareRemoval() {
  if (!lock()) {
    return false;
  }
  health_.prepared_for_removal = true;
  health_.writable = false;
  SD.end();
  spi_.end();
  health_.mounted = false;
  PM_LOG_INFO("SD", "CARD_REMOVAL_READY", "buffers_flushed=true mounted=false");
  publishHealthSnapshot(health_);
  unlock();
  return true;
}

StorageHealth SdStorage::health() const {
  if (!lock(pdMS_TO_TICKS(100))) {
    // A remount/recovery scan updates the sequence bounds in stages while it
    // owns the storage mutex. Never expose that partial state: for example,
    // oldest_sequence may already be populated while newest_sequence is not,
    // which makes an otherwise valid heartbeat fail the server contract.
    // Return the last complete snapshot through its independent mutex. This
    // remains race-free without turning an active, writable card into a false
    // outage merely because a bounded scan currently owns the SD mutex.
    if (health_snapshot_mutex_ != nullptr &&
        xSemaphoreTake(health_snapshot_mutex_, pdMS_TO_TICKS(25)) == pdTRUE) {
      const StorageHealth snapshot = last_health_snapshot_;
      xSemaphoreGive(health_snapshot_mutex_);
      return snapshot;
    }
    StorageHealth unavailable;
    unavailable.spi_hz = kSdRecoveryClockHz;
    unavailable.last_error = "storage_health_snapshot_busy";
    return unavailable;
  }
  const StorageHealth copy = health_;
  unlock();
  publishHealthSnapshot(copy);
  return copy;
}

void SdStorage::publishHealthSnapshot(const StorageHealth &snapshot) const {
  if (health_snapshot_mutex_ != nullptr &&
      xSemaphoreTake(health_snapshot_mutex_, pdMS_TO_TICKS(25)) == pdTRUE) {
    last_health_snapshot_ = snapshot;
    xSemaphoreGive(health_snapshot_mutex_);
  }
}

std::uint64_t SdStorage::nextSequence() const { return next_sequence_; }

bool SdStorage::advanceSequenceFloor(
    const std::uint64_t acknowledged_sequence) {
  if (!lock()) {
    return false;
  }
  const bool valid =
      health_.mounted && health_.writable &&
      acknowledged_sequence >= health_.newest_sequence &&
      acknowledged_sequence >= next_sequence_ - 1U;
  if (!valid || acknowledged_sequence == next_sequence_ - 1U) {
    unlock();
    return valid;
  }
  const bool persisted = persistSequence(acknowledged_sequence);
  if (persisted) {
    next_sequence_ = acknowledged_sequence + 1U;
    PM_LOG_WARN(
        "SYNC", "SEQUENCE_FLOOR_ADVANCED",
        "server_ack=%llu newest_stored=%llu next_sequence=%llu "
        "reason=server_cursor_ahead",
        static_cast<unsigned long long>(acknowledged_sequence),
        static_cast<unsigned long long>(health_.newest_sequence),
        static_cast<unsigned long long>(next_sequence_));
  } else {
    ++health_.write_failures;
    health_.last_error = "sequence_floor_persist_failed";
  }
  unlock();
  return persisted;
}

bool SdStorage::initializeLayout() {
  static constexpr const char *directories[] = {"/POWERMON",
                                                "/POWERMON/records",
                                                "/POWERMON/indexes",
                                                "/POWERMON/events",
                                                "/POWERMON/state",
                                                "/POWERMON/exports",
                                                "/POWERMON/recovery",
                                                "/POWERMON/records/untrusted",
                                                "/POWERMON/indexes/untrusted",
                                                "/POWERMON/events/untrusted"};
  for (const char *directory : directories) {
    if (!ensureDirectory(directory)) {
      health_.last_error = "layout_create_failed";
      return false;
    }
  }
  return writeManifest();
}

bool SdStorage::recover() {
  std::uint64_t maximum_sequence = 0;
  std::vector<std::string> files;
  collectFiles("/POWERMON/records", ".pmr", files);
  std::sort(files.begin(), files.end());
  PM_LOG_INFO("SD", "RECOVERY_SCAN_BEGIN", "record_files=%u",
              static_cast<unsigned>(files.size()));
  bool all_valid = true;
  health_.oldest_syncable_sequence = 0;
  for (const auto &path : files) {
    all_valid = recoverFile(path, maximum_sequence) && all_valid;
  }
  File journal = SD.open("/POWERMON/state/sequence.journal", FILE_READ);
  std::uint64_t journal_sequence = 0;
  if (journal) {
    const String value = journal.readStringUntil('\n');
    journal_sequence = std::strtoull(value.c_str(), nullptr, 10);
    journal.close();
  }
  const std::uint64_t committed = std::max(maximum_sequence, journal_sequence);
  next_sequence_ = committed + 1;
  health_.newest_sequence = maximum_sequence;
  health_.oldest_sequence = 0;
  if (maximum_sequence > 0) {
    HistoryQuery query;
    query.limit = 1;
    query.maximum_payload_bytes = 4096;
    HistoryPage first = readEnvelopeFiles(files, query, "sequence");
    health_.oldest_sequence = first.first_sequence;
  }
  health_.index_healthy = all_valid;
  PM_LOG_INFO("SD", "RECOVERY_SCAN_COMPLETE",
              "result=%s files=%u oldest_sequence=%llu newest_sequence=%llu "
              "oldest_syncable_sequence=%llu journal_sequence=%llu "
              "next_sequence=%llu repairs=%lu",
              all_valid ? "success" : "corruption_detected",
              static_cast<unsigned>(files.size()),
              static_cast<unsigned long long>(health_.oldest_sequence),
              static_cast<unsigned long long>(health_.newest_sequence),
              static_cast<unsigned long long>(
                  health_.oldest_syncable_sequence),
              static_cast<unsigned long long>(journal_sequence),
              static_cast<unsigned long long>(next_sequence_),
              static_cast<unsigned long>(health_.repair_count));
  return all_valid;
}

bool SdStorage::recoverFile(const std::string &path,
                            std::uint64_t &maximum_sequence) {
  File file = SD.open(path.c_str(), FILE_READ);
  if (!file) {
    return false;
  }
  std::uint64_t valid_end = 0;
  bool complete_corruption = false;
  std::size_t scanned_records = 0;
  std::size_t scanned_bytes = 0;
  while (file.available() > 0) {
    std::string line;
    bool newline = false;
    while (file.available() > 0) {
      const char value = static_cast<char>(file.read());
      line.push_back(value);
      ++scanned_bytes;
      if (scanned_bytes % kCooperativeScanBytes == 0U) {
        vTaskDelay(pdMS_TO_TICKS(1));
      }
      if (value == '\n') {
        newline = true;
        break;
      }
      if (line.size() > 8192) {
        complete_corruption = true;
        break;
      }
    }
    if (!newline) {
      file.close();
      const std::string temporary = path + ".repair";
      SD.remove(temporary.c_str());
      File source = SD.open(path.c_str(), FILE_READ);
      File repair = SD.open(temporary.c_str(), FILE_WRITE);
      std::array<std::uint8_t, 512> copy_buffer{};
      std::uint64_t remaining = valid_end;
      bool repaired = source && repair;
      std::size_t copied_chunks = 0;
      while (repaired && remaining > 0) {
        const std::size_t wanted =
            std::min<std::uint64_t>(copy_buffer.size(), remaining);
        const int read = source.read(copy_buffer.data(), wanted);
        repaired = read > 0 && repair.write(copy_buffer.data(), read) ==
                                   static_cast<std::size_t>(read);
        if (read > 0)
          remaining -= static_cast<std::uint64_t>(read);
        ++copied_chunks;
        if (copied_chunks % kCooperativeScanRecords == 0U) {
          vTaskDelay(pdMS_TO_TICKS(1));
        }
      }
      if (repair)
        repair.flush();
      if (source)
        source.close();
      if (repair)
        repair.close();
      repaired = repaired && remaining == 0;
      if (repaired) {
        repaired = SD.remove(path.c_str()) &&
                   SD.rename(temporary.c_str(), path.c_str());
      } else {
        SD.remove(temporary.c_str());
      }
      if (repaired) {
        ++health_.repair_count;
        PM_LOG_WARN("SD", "PARTIAL_RECORD_REPAIRED",
                    "error=PM-SD-009 file=%s valid_bytes=%llu repair_count=%lu",
                    path.c_str(), static_cast<unsigned long long>(valid_end),
                    static_cast<unsigned long>(health_.repair_count));
      } else {
        PM_LOG_ERROR("SD", "PARTIAL_RECORD_REPAIR_FAILED",
                     "error=PM-SD-009 file=%s valid_bytes=%llu", path.c_str(),
                     static_cast<unsigned long long>(valid_end));
      }
      return repaired;
    }
    std::string payload;
    std::uint32_t checksum = 0;
    if (!record::decodeEnvelope(line, payload, checksum)) {
      complete_corruption = true;
      break;
    }
    JsonDocument document;
    if (deserializeJson(document, payload)) {
      complete_corruption = true;
      break;
    }
    maximum_sequence =
        std::max(maximum_sequence, document["sequence"].as<std::uint64_t>());
    if (syncableDocument(document)) {
      const std::uint64_t sequence = document["sequence"].as<std::uint64_t>();
      health_.oldest_syncable_sequence =
          health_.oldest_syncable_sequence == 0
              ? sequence
              : std::min(health_.oldest_syncable_sequence, sequence);
    }
    valid_end += line.size();
    ++scanned_records;
    if (scanned_records % kCooperativeScanRecords == 0U) {
      vTaskDelay(pdMS_TO_TICKS(1));
    }
  }
  file.close();
  if (complete_corruption) {
    health_.last_error = "complete_record_corruption_detected";
    PM_LOG_ERROR("SD", "RECORD_CORRUPTION", "error=PM-SD-009 file=%s",
                 path.c_str());
  }
  return !complete_corruption;
}

bool SdStorage::writeManifest() {
  if (SD.exists("/POWERMON/manifest.json")) {
    return true;
  }
  JsonDocument document;
  document["schema_version"] = 1;
  document["record_format"] = "PMR1";
  document["protocol"] = version::PROTOCOL;
  document["authoritative_store"] = "microSD";
  std::string payload;
  serializeJson(document, payload);
  File file = SD.open("/POWERMON/manifest.json", FILE_WRITE);
  const bool ok =
      file && file.write(reinterpret_cast<const std::uint8_t *>(payload.data()),
                         payload.size()) == payload.size();
  if (file) {
    file.flush();
    file.close();
  }
  return ok;
}

bool SdStorage::persistSequence(const std::uint64_t committed_sequence) {
  const std::string value = std::to_string(committed_sequence) + "\n";
  const char *temporary = "/POWERMON/state/sequence.journal.tmp";
  const char *target = "/POWERMON/state/sequence.journal";
  SD.remove(temporary);
  File file = SD.open(temporary, FILE_WRITE);
  const bool written =
      file && file.write(reinterpret_cast<const std::uint8_t *>(value.data()),
                         value.size()) == value.size();
  if (file) {
    file.flush();
    file.close();
  }
  if (!written) {
    SD.remove(temporary);
    return false;
  }
  SD.remove(target);
  return SD.rename(temporary, target);
}

bool SdStorage::ensureDirectory(const std::string &path) {
  if (path.empty() || path[0] != '/') {
    return false;
  }
  std::size_t cursor = 1;
  while (cursor <= path.size()) {
    const std::size_t slash = path.find('/', cursor);
    const std::string current = path.substr(0, slash);
    if (!current.empty() && !SD.exists(current.c_str()) &&
        !SD.mkdir(current.c_str())) {
      return false;
    }
    if (slash == std::string::npos) {
      break;
    }
    cursor = slash + 1;
  }
  return true;
}

std::string SdStorage::recordPath(const IntervalRecord &record_value) const {
  return datedPath("records", ".pmr", record_value.start_utc_ms,
                   record_value.boot_id);
}

std::string SdStorage::indexPath(const IntervalRecord &record_value) const {
  return datedPath("indexes", ".idx", record_value.start_utc_ms,
                   record_value.boot_id);
}

std::string SdStorage::eventPath(const std::uint64_t utc_ms,
                                 const std::string &boot_id) const {
  return datedPath("events", ".events", utc_ms, boot_id);
}

std::string SdStorage::serializeRecord(const IntervalRecord &value) const {
  JsonDocument document;
  document["schema_version"] = value.schema_version;
  document["protocol"] = version::PROTOCOL;
  document["device_id"] = value.device_id;
  document["friendly_name"] = value.friendly_name;
  document["sequence"] = value.sequence;
  document["boot_id"] = value.boot_id;
  document["start_utc"] = isoUtc(value.start_utc_ms);
  document["end_utc"] = isoUtc(value.end_utc_ms);
  document["start_utc_ms"] = value.start_utc_ms;
  document["end_utc_ms"] = value.end_utc_ms;
  document["start_monotonic_ms"] = value.start_monotonic_ms;
  document["end_monotonic_ms"] = value.end_monotonic_ms;
  document["time_trusted"] = value.time_trusted;
  document["sample_count"] = value.sample_count;
  document["valid_sample_count"] = value.valid_sample_count;
  JsonObject voltage = document["voltage_v"].to<JsonObject>();
  voltage["average"] = value.avg_voltage_v;
  voltage["minimum"] = value.min_voltage_v;
  voltage["maximum"] = value.max_voltage_v;
  JsonObject current = document["current_a"].to<JsonObject>();
  current["average"] = value.avg_current_a;
  current["minimum"] = value.min_current_a;
  current["maximum"] = value.max_current_a;
  JsonObject power = document["active_power_w"].to<JsonObject>();
  power["average"] = value.avg_active_power_w;
  power["minimum"] = value.min_active_power_w;
  power["maximum"] = value.max_active_power_w;
  document["average_power_factor"] = value.avg_power_factor;
  document["average_frequency_hz"] = value.avg_frequency_hz;
  document["raw_energy_start_wh"] = value.raw_energy_start_wh;
  document["raw_energy_end_wh"] = value.raw_energy_end_wh;
  document["device_lifetime_energy_wh"] = value.device_lifetime_energy_wh;
  document["interval_energy_wh"] = value.interval_energy_wh;
  document["energy_method"] = value.energy_method;
  document["ct_rating_a"] = value.ct_rating_a;
  document["quality_flags"] = value.quality_flags;
  document["firmware_version"] = value.firmware_version;
  std::string payload;
  serializeJson(document, payload);
  return payload;
}

void SdStorage::collectFiles(const std::string &directory, const char *suffix,
                             std::vector<std::string> &output) const {
  File root = SD.open(directory.c_str(), FILE_READ);
  if (!root || !root.isDirectory()) {
    return;
  }
  std::size_t scanned_entries = 0;
  File entry = root.openNextFile();
  while (entry) {
    const std::string path = entry.path();
    const bool directory_entry = entry.isDirectory();
    entry.close();
    if (directory_entry) {
      collectFiles(path, suffix, output);
    } else if (endsWith(path, suffix)) {
      output.push_back(path);
    }
    ++scanned_entries;
    if (scanned_entries % kCooperativeScanRecords == 0U) {
      vTaskDelay(pdMS_TO_TICKS(1));
    }
    entry = root.openNextFile();
  }
  root.close();
}

HistoryPage SdStorage::readEnvelopeFiles(const std::vector<std::string> &paths,
                                         const HistoryQuery &query,
                                         const char *sequence_field) {
  struct Candidate {
    std::uint64_t sequence{0};
    std::string payload;
  };

  HistoryPage page;
  const std::size_t limit =
      std::min<std::size_t>(query.limit, build::MAX_HISTORY_PAGE);
  std::vector<Candidate> candidates;
  candidates.reserve(limit);
  std::vector<std::uint64_t> observed_syncable_sequences;
  if (query.require_syncable) {
    observed_syncable_sequences.reserve(kSyncCoverageWindow);
  }
  std::size_t payload_bytes = 0;
  std::size_t eligible_records = 0;
  std::size_t scanned_records = 0;
  const std::uint64_t scan_ceiling =
      query.require_syncable &&
              query.after_sequence <=
                  std::numeric_limits<std::uint64_t>::max() -
                      kSyncCoverageWindow
          ? query.after_sequence + kSyncCoverageWindow
          : std::numeric_limits<std::uint64_t>::max();

  const auto process_line = [&](const std::string &line) {
    std::string payload;
    std::uint32_t checksum = 0;
    if (!record::decodeEnvelope(line, payload, checksum)) {
      ++health_.read_failures;
      page.error_code = "record_corrupt";
      return false;
    }
    JsonDocument document;
    if (deserializeJson(document, payload)) {
      ++health_.read_failures;
      page.error_code = "record_json_invalid";
      return false;
    }
    const std::uint64_t sequence =
        document[sequence_field].as<std::uint64_t>();
    const std::uint64_t start =
        document["start_utc_ms"].is<std::uint64_t>()
            ? document["start_utc_ms"].as<std::uint64_t>()
            : document["timestamp_utc_ms"] | 0ULL;
    ++scanned_records;
    if (sequence <= query.after_sequence ||
        (query.from_utc_ms != 0 && start < query.from_utc_ms) ||
        (query.to_utc_ms != 0 && start > query.to_utc_ms) ||
        sequence > scan_ceiling) {
      return true;
    }
    if (query.require_syncable && !syncableDocument(document)) {
      return true;
    }
    if (query.require_syncable) {
      observed_syncable_sequences.push_back(sequence);
    }
    ++eligible_records;
    if (payload.size() > query.maximum_payload_bytes) {
      ++health_.read_failures;
      page.error_code = "record_exceeds_page_limit";
      return false;
    }

    const auto position = std::lower_bound(
        candidates.begin(), candidates.end(), sequence,
        [](const Candidate &candidate, const std::uint64_t value) {
          return candidate.sequence < value;
        });
    if (candidates.size() >= limit && position == candidates.end()) {
      return true;
    }
    payload_bytes += payload.size();
    candidates.insert(position, Candidate{sequence, std::move(payload)});
    while (candidates.size() > limit ||
           payload_bytes > query.maximum_payload_bytes) {
      payload_bytes -= candidates.back().payload.size();
      candidates.pop_back();
    }
    ++health_.reads;
    if (std::strcmp(sequence_field, "event_sequence") == 0) {
      ++health_.event_record_reads;
    } else {
      ++health_.reading_record_reads;
    }
    return true;
  };

  for (const auto &path : paths) {
    File file = SD.open(path.c_str(), FILE_READ);
    if (!file) {
      ++health_.read_failures;
      continue;
    }
    std::array<std::uint8_t, 1024> read_buffer{};
    std::string line;
    line.reserve(1024);
    for (;;) {
      const int read_count = file.read(read_buffer.data(), read_buffer.size());
      if (read_count < 0) {
        ++health_.read_failures;
        page.error_code = "storage_read_failed";
        file.close();
        return page;
      }
      if (read_count == 0) {
        break;
      }
      for (int index = 0; index < read_count; ++index) {
        line.push_back(static_cast<char>(read_buffer[index]));
        if (line.size() > 8192) {
          ++health_.read_failures;
          page.error_code = "record_exceeds_line_limit";
          file.close();
          return page;
        }
        if (read_buffer[index] == '\n') {
          if (!process_line(line)) {
            file.close();
            return page;
          }
          line.clear();
        }
      }
      vTaskDelay(pdMS_TO_TICKS(1));
    }
    if (!line.empty()) {
      ++health_.read_failures;
      page.error_code = "storage_read_incomplete";
      file.close();
      return page;
    }
    file.close();
  }

  if (query.require_syncable) {
    std::vector<std::uint64_t> selected_syncable_sequences;
    selected_syncable_sequences.reserve(candidates.size());
    for (const auto &candidate : candidates) {
      selected_syncable_sequences.push_back(candidate.sequence);
    }
    const std::uint64_t maximum_scanned_sequence =
        std::min(health_.newest_sequence, scan_ceiling);
    const SyncCoveragePlan coverage = deriveSyncCoverage(
        query.after_sequence, maximum_scanned_sequence,
        selected_syncable_sequences, observed_syncable_sequences, 500U);
    candidates.erase(
        std::remove_if(candidates.begin(), candidates.end(),
                       [&coverage](const Candidate &candidate) {
                         return candidate.sequence > coverage.end_sequence;
                       }),
        candidates.end());
    page.unavailable_sequence_ranges =
        coverage.unavailable_sequence_ranges;
  }

  page.records.reserve(candidates.size());
  for (auto &candidate : candidates) {
    if (page.records.empty()) {
      page.first_sequence = candidate.sequence;
    }
    page.last_sequence = candidate.sequence;
    page.records.push_back(std::move(candidate.payload));
  }
  if (query.require_syncable &&
      !page.unavailable_sequence_ranges.empty()) {
    if (page.first_sequence == 0U) {
      page.first_sequence =
          page.unavailable_sequence_ranges.front().start_sequence;
    }
    page.last_sequence =
        std::max(page.last_sequence,
                 page.unavailable_sequence_ranges.back().end_sequence);
  }
  page.has_more =
      query.require_syncable
          ? (health_.newest_sequence > page.last_sequence)
          : (eligible_records > page.records.size());
  page.ok = true;
  page.next_after_sequence = page.last_sequence;
  return page;
}

bool SdStorage::appendIndex(const std::string &path,
                            const std::uint64_t sequence,
                            const std::uint64_t utc_ms,
                            const std::uint64_t offset,
                            const std::uint32_t payload_crc) {
  const std::size_t slash = path.find_last_of('/');
  if (slash == std::string::npos || !ensureDirectory(path.substr(0, slash))) {
    return false;
  }
  char line[96]{};
  const int length =
      std::snprintf(line, sizeof(line), "%llu,%llu,%llu,%08x\n",
                    static_cast<unsigned long long>(sequence),
                    static_cast<unsigned long long>(utc_ms),
                    static_cast<unsigned long long>(offset), payload_crc);
  if (length <= 0 || static_cast<std::size_t>(length) >= sizeof(line)) {
    return false;
  }
  File file = SD.open(path.c_str(), FILE_APPEND);
  const bool ok =
      file && file.write(reinterpret_cast<const std::uint8_t *>(line),
                         static_cast<std::size_t>(length)) ==
                  static_cast<std::size_t>(length);
  if (file) {
    file.flush();
    file.close();
  }
  return ok;
}

void SdStorage::updateCapacity() {
  health_.capacity_bytes = SD.totalBytes();
  health_.used_bytes = SD.usedBytes();
  health_.free_bytes = health_.capacity_bytes >= health_.used_bytes
                           ? health_.capacity_bytes - health_.used_bytes
                           : 0;
}

bool SdStorage::lock(const TickType_t timeout) const {
  return mutex_ != nullptr &&
         xSemaphoreTakeRecursive(mutex_, timeout) == pdTRUE;
}

void SdStorage::unlock() const { xSemaphoreGiveRecursive(mutex_); }

} // namespace pm
