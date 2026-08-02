#include "storage/SdStorage.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <limits>
#include <numeric>

#include <Arduino.h>
#include <ArduinoJson.h>
#include <SD.h>
#include <esp_system.h>
#include <esp_task_wdt.h>

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
constexpr const char *kCleanupJournalPath =
    "/POWERMON/state/retention.journal";
constexpr const char *kCleanupTrashDirectory =
    "/POWERMON/recovery/retention-trash";

// Arduino's FAT directory iterator calls f_stat()/f_open() while the SD SPI
// driver owns the calling core. A slow or recovering card can remain inside a
// single openNextFile() call longer than ESP-IDF's five-second idle-task
// watchdog interval. The storage task itself is deliberately not watched and
// all primary metering runs on the other core, so suspend only the current
// core's IDLE-task subscription for the bounded directory walk and restore it
// immediately afterward. This does not disable the interrupt watchdog or any
// application-task watchdog.
class ScopedFatDirectoryWatchdogGuard {
public:
  ScopedFatDirectoryWatchdogGuard() {
    const BaseType_t core = xPortGetCoreID();
    if (core < 0 || core >= portNUM_PROCESSORS) {
      return;
    }
    idle_task_ = xTaskGetIdleTaskHandleForCPU(static_cast<UBaseType_t>(core));
    if (idle_task_ != nullptr && esp_task_wdt_delete(idle_task_) == ESP_OK) {
      removed_ = true;
    }
  }

  ~ScopedFatDirectoryWatchdogGuard() {
    if (removed_ && esp_task_wdt_add(idle_task_) != ESP_OK) {
      PM_LOG_ERROR("SD", "FAT_WATCHDOG_RESTORE_FAILED",
                   "error=PM-SD-025 idle_task_subscription=missing");
    }
  }

  ScopedFatDirectoryWatchdogGuard(const ScopedFatDirectoryWatchdogGuard &) =
      delete;
  ScopedFatDirectoryWatchdogGuard &
  operator=(const ScopedFatDirectoryWatchdogGuard &) = delete;

private:
  TaskHandle_t idle_task_{nullptr};
  bool removed_{false};
};

std::string pairedIndexPath(const std::string &record_path) {
  std::string output = record_path;
  const std::size_t records_pos = output.find("/records/");
  if (records_pos == std::string::npos || !endsWith(output, ".pmr")) {
    return {};
  }
  output.replace(records_pos, 9, "/indexes/");
  output.replace(output.size() - 4U, 4U, ".idx");
  return output;
}

std::string pathToken(const std::string &path) {
  const std::uint32_t checksum = record::crc32(
      reinterpret_cast<const std::uint8_t *>(path.data()), path.size());
  char token[16]{};
  std::snprintf(token, sizeof(token), "%08lx",
                static_cast<unsigned long>(checksum));
  return token;
}

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

bool SdStorage::begin(const std::uint32_t spi_hz,
                      const std::string &device_id,
                      const std::string &hardware_fingerprint,
                      const std::uint64_t required_sequence_floor) {
  preferred_spi_hz_ = std::min(spi_hz, build::MAX_SD_SPI_HZ);
  device_id_ = device_id;
  hardware_fingerprint_ = hardware_fingerprint;
  required_sequence_floor_ = required_sequence_floor;
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
  health_.sequence_floor_ready = false;
  health_.sequence_reconciliation_in_progress = false;
  health_.sequence_conflict = false;
  health_.card_replaced_or_initialized = false;
  // Retry the configured speed once after issuing the SD recovery clocks.
  // A CPU-only reset can leave a card mid-transaction: the first standard
  // Arduino initialization may fail even though the same card immediately
  // succeeds after the 80-clock recovery sequence. Dropping directly to
  // 1 MHz made a production 13-segment recovery occupy the storage memory
  // gate for more than a minute and unnecessarily defer heartbeats.
  const std::array<std::uint32_t, 4> attempt_hz{
      requested_hz, requested_hz, std::min(requested_hz, kSdFallbackClockHz),
      std::min(requested_hz, kSdRecoveryClockHz)};
  ++health_.mount_cycles;
  bool mounted = false;
  std::size_t attempt = 0U;
  for (const std::uint32_t candidate_hz : attempt_hz) {
    ++attempt;
    health_.spi_hz = candidate_hz;
    // Keep the first attempt on the Arduino SD library's proven initialization
    // path.  Sending a transaction before sdcard_init() caused some cards to
    // remain in an indeterminate command state after a CPU-only reset.  The
    // explicit 80-clock recovery sequence is intentionally reserved for the
    // slower fallback attempts.
    const bool recovery_attempt = attempt > 1U;
    if (recovery_attempt) {
      prepareSdSpiBus(spi_);
    } else {
      spi_.begin(pins::SD_SCK, pins::SD_MISO, pins::SD_MOSI, pins::SD_CS);
    }
    PM_LOG_INFO("SD", "MOUNT_ATTEMPT",
                "attempt=%u maximum_attempts=4 spi_hz=%lu "
                "strategy=%s recovery_idle_clocks=%u "
                "format_on_failure=false",
                static_cast<unsigned>(attempt),
                static_cast<unsigned long>(candidate_hz),
                recovery_attempt ? "recovery" : "standard",
                recovery_attempt ? 80U : 0U);
    if (SD.begin(pins::SD_CS, spi_, candidate_hz, "/sd", 8, false)) {
      mounted = true;
      break;
    }
    SD.end();
    spi_.end();
    digitalWrite(pins::SD_CS, HIGH);
    // Do not collapse repeated frequencies. Even a configuration already at
    // the 400 kHz recovery speed still needs
    // independent command/reset attempts after an interrupted transaction.
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
  health_.card_type = cardTypeName(SD.cardType());
  const bool layout_ok = initializeLayout();
  const bool self_test_ok = layout_ok && selfTest();
  const bool cleanup_recovery_ok = self_test_ok && recoverCleanupJournal();
  const bool recovery_ok = cleanup_recovery_ok && recover();
  health_.writable = layout_ok && self_test_ok && recovery_ok;
  if (health_.writable) {
    health_.sequence_reconciliation_in_progress =
        required_sequence_floor_ > health_.sequence_floor;
    health_.sequence_floor_ready =
        !health_.sequence_reconciliation_in_progress ||
        advanceSequenceFloor(required_sequence_floor_);
    health_.sequence_reconciliation_in_progress =
        !health_.sequence_floor_ready;
  }
  updateCapacity();
  PM_LOG_INFO(
      "SD", "MOUNT_COMPLETE",
      "result=%s card_type=%s filesystem=%s spi_hz=%lu capacity=%llu used=%llu "
      "free=%llu layout=%s self_test=%s recovery=%s history_integrity=%s "
      "next_sequence=%llu sequence_floor=%llu floor_ready=%s card_identity=%s",
      !health_.writable
          ? "failed"
          : (health_.index_healthy ? "success" : "degraded_writable"),
      cardTypeName(SD.cardType()),
      health_.filesystem.c_str(), static_cast<unsigned long>(health_.spi_hz),
      static_cast<unsigned long long>(health_.capacity_bytes),
      static_cast<unsigned long long>(health_.used_bytes),
      static_cast<unsigned long long>(health_.free_bytes),
      layout_ok ? "ok" : "failed", self_test_ok ? "ok" : "failed",
      recovery_ok ? "ok" : "failed",
      health_.index_healthy ? "verified" : "degraded_preserved",
      static_cast<unsigned long long>(next_sequence_),
      static_cast<unsigned long long>(health_.sequence_floor),
      health_.sequence_floor_ready ? "true" : "false",
      health_.card_identity_status.c_str());
  publishHealthSnapshot(health_);
  unlock();
  return health_.writable;
}

bool SdStorage::append(IntervalRecord &record) {
  if (!lock()) {
    return false;
  }
  if (!health_.mounted || !health_.writable || health_.prepared_for_removal ||
      !health_.sequence_floor_ready ||
      next_sequence_ == std::numeric_limits<std::uint64_t>::max()) {
    ++health_.write_failures;
    health_.last_error = !health_.sequence_floor_ready
                             ? "sequence_reconciliation_required"
                             : "sd_not_writable";
    if (diag::SerialLogger::instance().allow("sd_not_writable", 10'000U)) {
      PM_LOG_ERROR("SD", "WRITE_REJECTED",
                   "error=PM-SD-002 mounted=%s writable=%s "
                   "prepared_for_removal=%s sequence_floor_ready=%s "
                   "failures=%llu",
                   health_.mounted ? "true" : "false",
                   health_.writable ? "true" : "false",
                   health_.prepared_for_removal ? "true" : "false",
                   health_.sequence_floor_ready ? "true" : "false",
                   static_cast<unsigned long long>(health_.write_failures));
    }
    unlock();
    return false;
  }
  record.sequence = next_sequence_;
  const std::string payload = serializeRecord(record);
  const std::string envelope = record::encodeEnvelope(payload);
  updateCapacity();
  const std::uint64_t write_reserve =
      conservativeWriteReserveBytes(envelope.size());
  if (health_.free_bytes < write_reserve) {
    ++health_.write_failures;
    health_.last_error = "storage_write_reserve_unavailable";
    health_.pressure_state = storagePressureStateName(
        health_.free_bytes == 0U ? StoragePressureState::Full
                                : StoragePressureState::Emergency);
    health_.pressure_reason = "record_index_journal_reserve_unavailable";
    PM_LOG_ERROR(
        "SD", "WRITE_RESERVE_BLOCKED",
        "error=PM-SD-021 sequence=%llu free=%llu required_reserve=%llu "
        "partial_write_attempted=false",
        static_cast<unsigned long long>(record.sequence),
        static_cast<unsigned long long>(health_.free_bytes),
        static_cast<unsigned long long>(write_reserve));
    publishHealthSnapshot(health_);
    unlock();
    return false;
  }
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
  const bool sequence_journal_persisted = persistSequence(record.sequence);
  if (!sequence_journal_persisted) {
    ++health_.write_failures;
    health_.last_error = "sequence_journal_degraded";
    PM_LOG_ERROR(
        "SD", "SEQUENCE_JOURNAL_DEGRADED",
        "error=PM-SD-007 sequence=%llu record_durable=true "
        "next_sequence_advanced=true recovery=scan_record_floor",
        static_cast<unsigned long long>(record.sequence));
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
    health_.newest_syncable_sequence =
        std::max(health_.newest_syncable_sequence, record.sequence);
  }
  health_.newest_sequence = record.sequence;
  ++health_.local_record_count;
  ++next_sequence_;
  health_.sequence_floor = record.sequence;
  health_.next_sequence = next_sequence_;
  health_.sequence_floor_ready = true;
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
  const std::uint64_t event_sequence = next_event_sequence_;
  document["event_sequence"] = event_sequence;
  document["timestamp_utc"] = isoUtc(utc_ms);
  document["timestamp_utc_ms"] = utc_ms;
  document["boot_id"] = boot_id;
  document["code"] = code;
  document["severity"] = severity;
  document["detail"] = detail;
  std::string payload;
  serializeJson(document, payload);
  const std::string envelope = record::encodeEnvelope(payload);
  updateCapacity();
  if (health_.free_bytes < conservativeWriteReserveBytes(envelope.size())) {
    ++health_.write_failures;
    health_.last_error = "storage_event_write_reserve_unavailable";
    health_.pressure_state = storagePressureStateName(
        health_.free_bytes == 0U ? StoragePressureState::Full
                                : StoragePressureState::Emergency);
    publishHealthSnapshot(health_);
    unlock();
    return false;
  }
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
  const bool event_journal_persisted =
      ok && persistEventSequence(event_sequence);
  if (ok) {
    health_.oldest_event_sequence =
        health_.oldest_event_sequence == 0U
            ? event_sequence
            : std::min(health_.oldest_event_sequence, event_sequence);
    health_.newest_event_sequence = event_sequence;
    ++next_event_sequence_;
    ++health_.writes;
    if (!event_journal_persisted) {
      ++health_.write_failures;
      health_.last_error = "event_sequence_journal_degraded";
      PM_LOG_ERROR(
          "SD", "EVENT_SEQUENCE_JOURNAL_DEGRADED",
          "event_sequence=%llu event_durable=true "
          "next_event_sequence_advanced=true recovery=scan_event_floor",
          static_cast<unsigned long long>(event_sequence));
    }
  } else {
    ++health_.write_failures;
  }
  unlock();
  return ok && health_.newest_event_sequence == event_sequence;
}

bool SdStorage::reserveUnavailableIntervals(const std::uint64_t count,
                                            const std::uint64_t first_utc_ms,
                                            const std::uint64_t last_utc_ms) {
  if (count == 0U) {
    return true;
  }
  if (!lock()) {
    return false;
  }
  if (!health_.mounted || !health_.writable ||
      health_.prepared_for_removal ||
      count > std::numeric_limits<std::uint64_t>::max() - next_sequence_) {
    unlock();
    return false;
  }
  updateCapacity();
  if (health_.free_bytes < conservativeWriteReserveBytes(0U)) {
    health_.last_error = "storage_gap_journal_reserve_unavailable";
    health_.pressure_state = storagePressureStateName(
        health_.free_bytes == 0U ? StoragePressureState::Full
                                : StoragePressureState::Emergency);
    publishHealthSnapshot(health_);
    unlock();
    return false;
  }
  const std::uint64_t first_sequence = next_sequence_;
  const std::uint64_t last_sequence = first_sequence + count - 1U;
  if (!persistSequence(last_sequence)) {
    ++health_.write_failures;
    health_.last_error = "dropped_interval_sequence_journal_failed";
    publishHealthSnapshot(health_);
    unlock();
    return false;
  }
  next_sequence_ = last_sequence + 1U;
  health_.newest_sequence = std::max(health_.newest_sequence, last_sequence);
  health_.dropped_interval_count += count;
  if (first_utc_ms != 0U) {
    health_.first_dropped_interval_utc_ms =
        health_.first_dropped_interval_utc_ms == 0U
            ? first_utc_ms
            : std::min(health_.first_dropped_interval_utc_ms, first_utc_ms);
  }
  health_.last_dropped_interval_utc_ms =
      std::max(health_.last_dropped_interval_utc_ms, last_utc_ms);
  health_.last_error = "durable_intervals_dropped";
  PM_LOG_ERROR(
      "HISTORY", "storage.interval_gap_reserved",
      "first_sequence=%llu last_sequence=%llu count=%llu first_utc_ms=%llu "
      "last_utc_ms=%llu",
      static_cast<unsigned long long>(first_sequence),
      static_cast<unsigned long long>(last_sequence),
      static_cast<unsigned long long>(count),
      static_cast<unsigned long long>(first_utc_ms),
      static_cast<unsigned long long>(last_utc_ms));
  publishHealthSnapshot(health_);
  unlock();
  return true;
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
  // A manual test is diagnostic evidence only. It must not overwrite the
  // lifecycle state established by mount, recovery, and sequence
  // reconciliation.
  health_.last_self_test_passed = ok;
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

SegmentMetadata SdStorage::inspectSegment(const std::string &path) const {
  SegmentMetadata metadata;
  metadata.record_path = path;
  metadata.index_path = pairedIndexPath(path);
  File input = SD.open(path.c_str(), FILE_READ);
  metadata.complete = static_cast<bool>(input);
  metadata.all_times_trusted = true;
  metadata.closed = true;
  if (input) {
    metadata.payload_bytes = input.size();
  }
  while (metadata.complete && input && input.available() > 0) {
    std::string line;
    bool newline = false;
    while (input.available() > 0 && line.size() <= 8192U) {
      const char value = static_cast<char>(input.read());
      line.push_back(value);
      if (value == '\n') {
        newline = true;
        break;
      }
    }
    std::string payload;
    std::uint32_t checksum = 0;
    JsonDocument document;
    if (!newline || !record::decodeEnvelope(line, payload, checksum) ||
        deserializeJson(document, payload) ||
        !document["sequence"].is<std::uint64_t>()) {
      metadata.complete = false;
      break;
    }
    const std::uint64_t sequence =
        document["sequence"].as<std::uint64_t>();
    const std::uint64_t start = document["start_utc_ms"] | 0ULL;
    const std::uint64_t end = document["end_utc_ms"] | 0ULL;
    metadata.first_sequence = metadata.first_sequence == 0U
                                  ? sequence
                                  : std::min(metadata.first_sequence, sequence);
    metadata.last_sequence = std::max(metadata.last_sequence, sequence);
    if (start != 0U) {
      metadata.first_utc_ms = metadata.first_utc_ms == 0U
                                  ? start
                                  : std::min(metadata.first_utc_ms, start);
    }
    metadata.last_utc_ms = std::max(metadata.last_utc_ms, end);
    metadata.all_times_trusted =
        metadata.all_times_trusted && (document["time_trusted"] | false);
    metadata.integrity_crc ^= checksum;
    ++metadata.record_count;
    if (metadata.record_count % kCooperativeScanRecords == 0U) {
      vTaskDelay(pdMS_TO_TICKS(1));
    }
  }
  if (input) {
    input.close();
  }
  metadata.complete = metadata.complete && metadata.record_count > 0U;

  File index = metadata.index_path.empty()
                   ? File{}
                   : SD.open(metadata.index_path.c_str(), FILE_READ);
  std::uint32_t index_count = 0U;
  std::uint64_t index_first = 0U;
  std::uint64_t index_last = 0U;
  bool index_well_formed = static_cast<bool>(index);
  if (index) {
    metadata.index_bytes = index.size();
  }
  while (index_well_formed && index && index.available() > 0) {
    const String raw = index.readStringUntil('\n');
    unsigned long long sequence = 0U;
    unsigned long long timestamp = 0U;
    unsigned long long offset = 0U;
    unsigned checksum = 0U;
    if (std::sscanf(raw.c_str(), "%llu,%llu,%llu,%x", &sequence, &timestamp,
                    &offset, &checksum) != 4) {
      index_well_formed = false;
      break;
    }
    const std::uint64_t value = static_cast<std::uint64_t>(sequence);
    index_first = index_first == 0U ? value : std::min(index_first, value);
    index_last = std::max(index_last, value);
    ++index_count;
    if (index_count % kCooperativeScanRecords == 0U) {
      vTaskDelay(pdMS_TO_TICKS(1));
    }
  }
  if (index) {
    index.close();
  }
  metadata.index_valid = index_well_formed && index_count == metadata.record_count &&
                         index_first == metadata.first_sequence &&
                         index_last == metadata.last_sequence;
  return metadata;
}

SegmentMetadata SdStorage::inspectEventSegment(const std::string &path) const {
  SegmentMetadata metadata;
  metadata.record_path = path;
  metadata.index_valid = true;
  metadata.all_times_trusted = true;
  metadata.closed = true;
  File input = SD.open(path.c_str(), FILE_READ);
  metadata.complete = static_cast<bool>(input);
  if (input) {
    metadata.payload_bytes = input.size();
  }
  while (metadata.complete && input && input.available() > 0) {
    const String raw = input.readStringUntil('\n');
    std::string payload;
    std::uint32_t checksum = 0U;
    JsonDocument document;
    if (!record::decodeEnvelope(raw.c_str(), payload, checksum) ||
        deserializeJson(document, payload) ||
        !document["event_sequence"].is<std::uint64_t>()) {
      metadata.complete = false;
      break;
    }
    const std::uint64_t sequence =
        document["event_sequence"].as<std::uint64_t>();
    const std::uint64_t timestamp = document["timestamp_utc_ms"] | 0ULL;
    metadata.first_sequence = metadata.first_sequence == 0U
                                  ? sequence
                                  : std::min(metadata.first_sequence, sequence);
    metadata.last_sequence = std::max(metadata.last_sequence, sequence);
    if (timestamp != 0U) {
      metadata.first_utc_ms = metadata.first_utc_ms == 0U
                                  ? timestamp
                                  : std::min(metadata.first_utc_ms, timestamp);
    }
    metadata.last_utc_ms = std::max(metadata.last_utc_ms, timestamp);
    metadata.all_times_trusted =
        metadata.all_times_trusted && timestamp != 0U;
    metadata.integrity_crc ^= checksum;
    ++metadata.record_count;
    if (metadata.record_count % kCooperativeScanRecords == 0U) {
      vTaskDelay(pdMS_TO_TICKS(1));
    }
  }
  if (input) {
    input.close();
  }
  metadata.complete = metadata.complete && metadata.record_count > 0U;
  return metadata;
}

bool SdStorage::loadSegmentMetadata(const std::string &path,
                                    const bool event_segment,
                                    SegmentMetadata &metadata) const {
  const std::string stored_path = metadataPath(path);
  File input = SD.open(stored_path.c_str(), FILE_READ);
  const String raw = input ? input.readStringUntil('\n') : String{};
  if (input) {
    input.close();
  }
  std::string payload;
  std::uint32_t checksum = 0U;
  JsonDocument document;
  if (!record::decodeEnvelope(raw.c_str(), payload, checksum) ||
      deserializeJson(document, payload) ||
      (document["schema_version"] | 0) != 1 ||
      (document["record_path"] | "") != path ||
      !(document["closed"] | false) ||
      !(document["complete"] | false)) {
    return false;
  }

  const std::string expected_index =
      event_segment ? std::string{} : pairedIndexPath(path);
  if ((document["index_path"] | "") != expected_index) {
    return false;
  }
  File record_file = SD.open(path.c_str(), FILE_READ);
  if (!record_file) {
    return false;
  }
  const std::uint64_t record_size = record_file.size();
  record_file.close();
  const std::uint64_t stored_record_size = document["payload_bytes"] | 0ULL;
  if (stored_record_size == 0U || record_size != stored_record_size) {
    return false;
  }

  std::uint64_t index_size = 0U;
  if (!event_segment) {
    File index_file = SD.open(expected_index.c_str(), FILE_READ);
    if (!index_file) {
      return false;
    }
    index_size = index_file.size();
    index_file.close();
    if (!(document["index_valid"] | false) ||
        index_size != (document["index_bytes"] | 0ULL)) {
      return false;
    }
  }

  metadata.record_path = path;
  metadata.index_path = expected_index;
  metadata.first_sequence = document["first_sequence"] | 0ULL;
  metadata.last_sequence = document["last_sequence"] | 0ULL;
  metadata.first_utc_ms = document["first_utc_ms"] | 0ULL;
  metadata.last_utc_ms = document["last_utc_ms"] | 0ULL;
  metadata.payload_bytes = stored_record_size;
  metadata.index_bytes = index_size;
  metadata.record_count = document["record_count"] | 0U;
  metadata.integrity_crc = document["integrity_crc"] | 0U;
  metadata.all_times_trusted = document["all_times_trusted"] | false;
  metadata.complete = true;
  metadata.index_valid = event_segment || (document["index_valid"] | false);
  metadata.closed = true;
  return metadata.record_count > 0U && metadata.first_sequence > 0U &&
         metadata.last_sequence >= metadata.first_sequence;
}

std::string SdStorage::metadataPath(const std::string &record_path) const {
  return std::string("/POWERMON/state/segments/") + pathToken(record_path) +
         ".json";
}

bool SdStorage::persistSegmentMetadata(
    const SegmentMetadata &metadata) const {
  JsonDocument document;
  document["schema_version"] = 1;
  document["record_path"] = metadata.record_path;
  document["index_path"] = metadata.index_path;
  document["first_sequence"] = metadata.first_sequence;
  document["last_sequence"] = metadata.last_sequence;
  document["first_utc_ms"] = metadata.first_utc_ms;
  document["last_utc_ms"] = metadata.last_utc_ms;
  document["payload_bytes"] = metadata.payload_bytes;
  document["index_bytes"] = metadata.index_bytes;
  document["record_count"] = metadata.record_count;
  document["integrity_crc"] = metadata.integrity_crc;
  document["all_times_trusted"] = metadata.all_times_trusted;
  document["complete"] = metadata.complete;
  document["index_valid"] = metadata.index_valid;
  document["closed"] = metadata.closed;
  std::string payload;
  serializeJson(document, payload);
  const std::string envelope = record::encodeEnvelope(payload);
  const std::string target = metadataPath(metadata.record_path);
  const std::string temporary = target + ".tmp";
  SD.remove(temporary.c_str());
  File output = SD.open(temporary.c_str(), FILE_WRITE);
  const bool written =
      output &&
      output.write(reinterpret_cast<const std::uint8_t *>(envelope.data()),
                   envelope.size()) == envelope.size();
  if (output) {
    output.flush();
    output.close();
  }
  if (!written) {
    SD.remove(temporary.c_str());
    return false;
  }
  File verify = SD.open(temporary.c_str(), FILE_READ);
  const String raw = verify ? verify.readStringUntil('\n') : String{};
  if (verify) {
    verify.close();
  }
  std::string verified_payload;
  std::uint32_t checksum = 0U;
  if (!record::decodeEnvelope(raw.c_str(), verified_payload, checksum) ||
      verified_payload != payload) {
    SD.remove(temporary.c_str());
    return false;
  }
  SD.remove(target.c_str());
  return SD.rename(temporary.c_str(), target.c_str());
}

bool SdStorage::persistCleanupJournal(
    const SegmentMetadata &metadata, const std::string &record_trash,
    const std::string &index_trash, const std::uint64_t server_ack_sequence,
    const std::uint64_t now_utc_ms, const std::string &reason,
    const char *stage) const {
  JsonDocument document;
  document["schema_version"] = 1;
  document["stage"] = stage;
  document["record_path"] = metadata.record_path;
  document["index_path"] = metadata.index_path;
  document["record_trash"] = record_trash;
  document["index_trash"] = index_trash;
  document["first_sequence"] = metadata.first_sequence;
  document["last_sequence"] = metadata.last_sequence;
  document["server_ack_sequence"] = server_ack_sequence;
  document["started_utc_ms"] = now_utc_ms;
  document["reason"] = reason;
  std::string payload;
  serializeJson(document, payload);
  const std::string envelope = record::encodeEnvelope(payload);
  const std::string temporary = std::string(kCleanupJournalPath) + ".tmp";
  SD.remove(temporary.c_str());
  File output = SD.open(temporary.c_str(), FILE_WRITE);
  const bool written =
      output &&
      output.write(reinterpret_cast<const std::uint8_t *>(envelope.data()),
                   envelope.size()) == envelope.size();
  if (output) {
    output.flush();
    output.close();
  }
  if (!written) {
    SD.remove(temporary.c_str());
    return false;
  }
  SD.remove(kCleanupJournalPath);
  return SD.rename(temporary.c_str(), kCleanupJournalPath);
}

bool SdStorage::clearCleanupJournal() const {
  const std::string temporary = std::string(kCleanupJournalPath) + ".tmp";
  const bool target_ok = !SD.exists(kCleanupJournalPath) ||
                         SD.remove(kCleanupJournalPath);
  const bool temporary_ok = !SD.exists(temporary.c_str()) ||
                            SD.remove(temporary.c_str());
  return target_ok && temporary_ok;
}

bool SdStorage::recoverCleanupJournal() {
  const auto recover_atomic_temp = [](const std::string &target) {
    const std::string temporary = target + ".tmp";
    if (!SD.exists(temporary.c_str())) {
      return true;
    }
    if (SD.exists(target.c_str())) {
      return SD.remove(temporary.c_str());
    }
    return SD.rename(temporary.c_str(), target.c_str());
  };
  // The reading-sequence journal is recovered later by recover(), which
  // validates target, temporary, and backup and preserves the greatest value.
  // Never apply the generic target-wins cleanup here: after a power loss the
  // temporary copy can be the only durable record of a newly advanced floor.
  bool temporary_recovery_ok =
      recover_atomic_temp("/POWERMON/state/event-sequence.journal") &&
      recover_atomic_temp(kCleanupJournalPath);
  std::vector<std::string> metadata_temps;
  collectFiles("/POWERMON/state/segments", ".tmp", metadata_temps);
  for (const auto &temporary : metadata_temps) {
    const std::string target =
        temporary.substr(0U, temporary.size() - std::strlen(".tmp"));
    temporary_recovery_ok =
        (SD.exists(target.c_str()) ? SD.remove(temporary.c_str())
                                  : SD.rename(temporary.c_str(), target.c_str())) &&
        temporary_recovery_ok;
  }
  std::vector<std::string> repair_temps;
  collectFiles("/POWERMON/records", ".repair", repair_temps);
  for (const auto &temporary : repair_temps) {
    const std::string target =
        temporary.substr(0U, temporary.size() - std::strlen(".repair"));
    temporary_recovery_ok =
        (SD.exists(target.c_str()) ? SD.remove(temporary.c_str())
                                  : SD.rename(temporary.c_str(), target.c_str())) &&
        temporary_recovery_ok;
  }
  if (!temporary_recovery_ok) {
    health_.last_error = "temporary_artifact_recovery_failed";
    health_.pressure_state = storagePressureStateName(StoragePressureState::ReadOnly);
    return false;
  }
  if (!SD.exists(kCleanupJournalPath)) {
    health_.cleanup_recovery_required = false;
    return true;
  }
  health_.cleanup_recovery_required = true;
  health_.pressure_state = storagePressureStateName(
      StoragePressureState::CleanupRecovering);
  File input = SD.open(kCleanupJournalPath, FILE_READ);
  const String raw = input ? input.readStringUntil('\n') : String{};
  if (input) {
    input.close();
  }
  std::string payload;
  std::uint32_t checksum = 0U;
  JsonDocument document;
  if (!record::decodeEnvelope(raw.c_str(), payload, checksum) ||
      deserializeJson(document, payload)) {
    health_.last_error = "cleanup_journal_invalid";
    health_.pressure_state = storagePressureStateName(StoragePressureState::ReadOnly);
    PM_LOG_ERROR("SD", "CLEANUP_RECOVERY_BLOCKED",
                 "error=PM-SD-020 reason=journal_invalid action=preserve_all_files");
    return false;
  }
  const std::string stage = document["stage"] | "";
  const std::string record_path = document["record_path"] | "";
  const std::string index_path = document["index_path"] | "";
  const std::string record_trash = document["record_trash"] | "";
  const std::string index_trash = document["index_trash"] | "";
  const bool event_segment =
      record_path.rfind("/POWERMON/events/", 0U) == 0U;
  const bool paths_safe =
      (record_path.rfind("/POWERMON/records/", 0U) == 0U || event_segment) &&
      ((event_segment && index_path.empty() && index_trash.empty()) ||
       (index_path.rfind("/POWERMON/indexes/", 0U) == 0U &&
        index_trash.rfind(kCleanupTrashDirectory, 0U) == 0U)) &&
      record_trash.rfind(kCleanupTrashDirectory, 0U) == 0U &&
      !record_trash.empty();
  if (!paths_safe) {
    health_.last_error = "cleanup_journal_path_invalid";
    health_.pressure_state = storagePressureStateName(StoragePressureState::ReadOnly);
    PM_LOG_ERROR("SD", "CLEANUP_RECOVERY_BLOCKED",
                 "error=PM-SD-020 reason=unsafe_path action=preserve_all_files");
    return false;
  }

  const CleanupRecoverySnapshot snapshot{
      stage,
      !index_path.empty(),
      SD.exists(record_path.c_str()),
      SD.exists(record_trash.c_str()),
      !index_path.empty() && SD.exists(index_path.c_str()),
      !index_trash.empty() && SD.exists(index_trash.c_str()),
  };
  const CleanupRecoveryAction action = cleanupRecoveryAction(snapshot);
  bool ok = action != CleanupRecoveryAction::Block;
  if (action == CleanupRecoveryAction::ReverseMoves) {
    if (snapshot.record_trash_exists) {
      ok = SD.rename(record_trash.c_str(), record_path.c_str()) && ok;
    }
    if (snapshot.has_index && snapshot.index_trash_exists) {
      ok = SD.rename(index_trash.c_str(), index_path.c_str()) && ok;
    }
  } else if (action == CleanupRecoveryAction::ForwardDelete) {
    if (snapshot.record_trash_exists) {
      ok = SD.remove(record_trash.c_str()) && ok;
    }
    if (snapshot.has_index && snapshot.index_trash_exists) {
      ok = SD.remove(index_trash.c_str()) && ok;
    }
  }
  if (ok) {
    ok = clearCleanupJournal();
  }
  health_.cleanup_recovery_required = !ok;
  health_.last_cleanup_result = ok ? "recovered" : "recovery_blocked";
  if (!ok) {
    health_.last_error = "cleanup_recovery_failed";
    health_.pressure_state = storagePressureStateName(StoragePressureState::ReadOnly);
  }
  PM_LOG_INFO("SD", "CLEANUP_RECOVERY_COMPLETE",
              "result=%s stage=%s", ok ? "success" : "blocked",
              stage.c_str());
  return ok;
}

bool SdStorage::removeSegmentTransactionally(
    const SegmentMetadata &metadata, const std::uint64_t server_ack_sequence,
    const std::uint64_t now_utc_ms, const std::string &reason) {
  const std::string token = pathToken(metadata.record_path);
  const std::string record_trash =
      std::string(kCleanupTrashDirectory) + "/" + token + ".pmr.trash";
  const std::string index_trash =
      metadata.index_path.empty()
          ? std::string{}
          : std::string(kCleanupTrashDirectory) + "/" + token + ".idx.trash";
  const bool has_index = !metadata.index_path.empty();
  PM_LOG_INFO(
      "STORAGE", "storage.cleanup_candidate_verified",
      "transaction_id=%s first_sequence=%llu last_sequence=%llu "
      "server_ack=%llu expected_bytes=%llu reason=%s",
      token.c_str(), static_cast<unsigned long long>(metadata.first_sequence),
      static_cast<unsigned long long>(metadata.last_sequence),
      static_cast<unsigned long long>(server_ack_sequence),
      static_cast<unsigned long long>(metadata.payload_bytes +
                                      metadata.index_bytes),
      reason.c_str());
  if (!SD.exists(metadata.record_path.c_str()) ||
      (has_index && !SD.exists(metadata.index_path.c_str())) ||
      SD.exists(record_trash.c_str()) ||
      (has_index && SD.exists(index_trash.c_str())) ||
      !persistCleanupJournal(metadata, record_trash, index_trash,
                             server_ack_sequence, now_utc_ms, reason,
                             "planned")) {
    return false;
  }
  const bool record_moved =
      SD.rename(metadata.record_path.c_str(), record_trash.c_str());
  const bool index_moved =
      record_moved &&
      (!has_index ||
       SD.rename(metadata.index_path.c_str(), index_trash.c_str()));
  if (!record_moved || !index_moved) {
    recoverCleanupJournal();
    return false;
  }
  PM_LOG_INFO(
      "STORAGE", "storage.cleanup_segment_staged",
      "transaction_id=%s first_sequence=%llu last_sequence=%llu",
      token.c_str(), static_cast<unsigned long long>(metadata.first_sequence),
      static_cast<unsigned long long>(metadata.last_sequence));
  if (!persistCleanupJournal(metadata, record_trash, index_trash,
                             server_ack_sequence, now_utc_ms, reason,
                             "files_moved")) {
    recoverCleanupJournal();
    return false;
  }
  if (!SD.remove(record_trash.c_str()) ||
      !persistCleanupJournal(metadata, record_trash, index_trash,
                             server_ack_sequence, now_utc_ms, reason,
                             "record_deleted") ||
      (has_index && !SD.remove(index_trash.c_str()))) {
    health_.cleanup_recovery_required = true;
    return false;
  }
  SD.remove(metadataPath(metadata.record_path).c_str());
  if (!persistCleanupJournal(metadata, record_trash, index_trash,
                             server_ack_sequence, now_utc_ms, reason,
                             "complete")) {
    health_.cleanup_recovery_required = true;
    return false;
  }
  const bool cleared = clearCleanupJournal();
  if (cleared) {
    PM_LOG_INFO(
        "STORAGE", "storage.cleanup_segment_removed",
        "transaction_id=%s first_sequence=%llu last_sequence=%llu",
        token.c_str(), static_cast<unsigned long long>(metadata.first_sequence),
        static_cast<unsigned long long>(metadata.last_sequence));
  }
  return cleared;
}

bool SdStorage::applyRetention(
    const std::uint64_t server_ack_sequence,
    const bool acknowledgement_verified,
    const std::uint64_t event_ack_sequence,
    const std::uint64_t now_utc_ms, const StoragePolicy &policy,
    const std::string &reason) {
  if (!lock()) {
    return false;
  }
  active_policy_ = policy;
  health_.server_ack_sequence = server_ack_sequence;
  health_.event_ack_sequence = event_ack_sequence;
  health_.acknowledgement_verified = acknowledgement_verified;
  updateCapacity();
  PM_LOG_INFO(
      "SD", "RETENTION_BEGIN",
      "mode=%s reason=%s server_ack_sequence=%llu ack_verified=%s "
      "event_ack_sequence=%llu free=%llu capacity=%llu",
      retentionModeName(policy.mode), reason.c_str(),
      static_cast<unsigned long long>(server_ack_sequence),
      acknowledgement_verified ? "true" : "false",
      static_cast<unsigned long long>(event_ack_sequence),
      static_cast<unsigned long long>(health_.free_bytes),
      static_cast<unsigned long long>(health_.capacity_bytes));
  if (!health_.mounted || !validateStoragePolicy(policy).valid) {
    health_.last_cleanup_result = "invalid_request";
    health_.last_cleanup_reason = reason;
    unlock();
    return false;
  }

  std::vector<std::string> files;
  collectFiles("/POWERMON/records", ".pmr", files);
  std::vector<SegmentMetadata> segments;
  segments.reserve(files.size());
  std::vector<bool> segment_metadata_loaded;
  segment_metadata_loaded.reserve(files.size());
  std::uint64_t newest_sequence = 0U;
  for (const auto &path : files) {
    SegmentMetadata metadata;
    const bool loaded = loadSegmentMetadata(path, false, metadata);
    if (!loaded) {
      metadata = inspectSegment(path);
    }
    newest_sequence = std::max(newest_sequence, metadata.last_sequence);
    segments.push_back(std::move(metadata));
    segment_metadata_loaded.push_back(loaded);
    // SD/FAT directory and segment scans can hold the SPI implementation in
    // long polling sections. Explicitly release the core between files so the
    // watchdog-protected meter and aggregation tasks remain schedulable.
    vTaskDelay(pdMS_TO_TICKS(1));
  }
  for (std::size_t index = 0; index < segments.size(); ++index) {
    auto &metadata = segments[index];
    metadata.active = metadata.record_path == health_.current_file ||
                      (newest_sequence != 0U &&
                       metadata.last_sequence == newest_sequence);
    metadata.closed = !metadata.active;
    const bool metadata_unchanged =
        segment_metadata_loaded[index] && metadata.closed;
    if (!metadata_unchanged && !persistSegmentMetadata(metadata)) {
      PM_LOG_WARN("SD", "SEGMENT_METADATA_PERSIST_FAILED",
                  "file=%s deletion_protected=true",
                  metadata.record_path.c_str());
      metadata.complete = false;
    }
    vTaskDelay(pdMS_TO_TICKS(1));
  }
  health_.open_segment_count = 0U;
  health_.closed_segment_count = 0U;
  health_.untrusted_segment_count = 0U;
  for (const auto &metadata : segments) {
    if (metadata.active) {
      ++health_.open_segment_count;
    } else {
      ++health_.closed_segment_count;
    }
    if (!metadata.all_times_trusted) {
      ++health_.untrusted_segment_count;
    }
  }
  // Time-untrusted files cannot use an age window. Preserve the two newest
  // closed files as a bounded sequence/file window even during emergency
  // continuous cleanup.
  std::vector<std::size_t> by_newest_sequence(segments.size());
  std::iota(by_newest_sequence.begin(), by_newest_sequence.end(), 0U);
  std::sort(by_newest_sequence.begin(), by_newest_sequence.end(),
            [&segments](const std::size_t left, const std::size_t right) {
              return segments[left].last_sequence >
                     segments[right].last_sequence;
            });
  std::size_t protected_closed = 0U;
  for (const std::size_t index : by_newest_sequence) {
    if (!segments[index].active && protected_closed < 2U) {
      segments[index].minimum_window_protected = true;
      ++protected_closed;
    }
  }

  const std::uint64_t retention_ms =
      static_cast<std::uint64_t>(policy.retention_days) * 86'400'000ULL;
  const std::uint64_t minimum_ms =
      static_cast<std::uint64_t>(policy.minimum_local_history_days) *
      86'400'000ULL;
  const StoragePressureState pressure = classifyStoragePressure(
      health_.capacity_bytes, health_.free_bytes, policy);
  RetentionContext context;
  context.mode = policy.mode;
  context.emergency_pressure =
      pressure == StoragePressureState::Critical ||
      pressure == StoragePressureState::Emergency ||
      pressure == StoragePressureState::Full;
  context.acknowledgement_verified = acknowledgement_verified;
  context.server_ack_sequence = server_ack_sequence;
  context.retention_cutoff_utc_ms =
      now_utc_ms > retention_ms ? now_utc_ms - retention_ms : 0U;
  context.minimum_history_cutoff_utc_ms =
      now_utc_ms > minimum_ms ? now_utc_ms - minimum_ms : 0U;
  const std::uint64_t target = cleanupTargetFreeBytes(
      health_.capacity_bytes, policy);
  CleanupPlan plan = buildCleanupPlan(segments, context, health_.free_bytes,
                                      context.emergency_pressure ? target : 0U);
  health_.segment_count = static_cast<std::uint32_t>(segments.size());
  health_.eligible_segment_count =
      static_cast<std::uint32_t>(plan.candidate_indexes.size());
  health_.protected_unacknowledged_bytes =
      plan.protected_unacknowledged_bytes;
  health_.protected_untrusted_bytes = plan.protected_untrusted_bytes;
  health_.reclaimable_bytes = plan.eligible_bytes;
  health_.protected_segment_count = 0U;
  for (const auto &metadata : segments) {
    const SegmentEligibility eligibility = segmentEligibility(metadata, context);
    if (eligibility != SegmentEligibility::EligibleAge &&
        eligibility != SegmentEligibility::EligibleEmergency) {
      ++health_.protected_segment_count;
    }
  }

  bool ok = true;
  std::uint64_t reclaimed = 0U;
  health_.cleanup_in_progress =
      policy.mode != RetentionMode::Disabled &&
      !plan.candidate_indexes.empty();
  if (health_.cleanup_in_progress) {
    health_.pressure_state =
        storagePressureStateName(StoragePressureState::CleanupRunning);
    PM_LOG_INFO("STORAGE", "storage.cleanup_started",
                "reason=%s candidates=%u target_free_bytes=%llu",
                reason.c_str(),
                static_cast<unsigned>(plan.candidate_indexes.size()),
                static_cast<unsigned long long>(target));
  }
  for (const std::size_t index : plan.candidate_indexes) {
    if (policy.mode == RetentionMode::Disabled || index >= segments.size()) {
      break;
    }
    const SegmentMetadata &metadata = segments[index];
    SegmentMetadata verified = inspectSegment(metadata.record_path);
    verified.active = metadata.active;
    verified.closed = metadata.closed;
    verified.cleanup_active = metadata.cleanup_active;
    verified.minimum_window_protected = metadata.minimum_window_protected;
    const bool metadata_matches =
        verified.first_sequence == metadata.first_sequence &&
        verified.last_sequence == metadata.last_sequence &&
        verified.payload_bytes == metadata.payload_bytes &&
        verified.index_bytes == metadata.index_bytes &&
        verified.record_count == metadata.record_count &&
        verified.integrity_crc == metadata.integrity_crc;
    const SegmentEligibility eligibility =
        metadata_matches ? segmentEligibility(verified, context)
                         : SegmentEligibility::CorruptOrMissingIndex;
    if (eligibility != SegmentEligibility::EligibleAge &&
        eligibility != SegmentEligibility::EligibleEmergency) {
      ok = false;
      health_.last_error = metadata_matches
                               ? "cleanup_eligibility_changed"
                               : "cleanup_candidate_integrity_changed";
      PM_LOG_ERROR(
          "STORAGE", "storage.cleanup_candidate_rejected",
          "first_sequence=%llu last_sequence=%llu reason=%s",
          static_cast<unsigned long long>(metadata.first_sequence),
          static_cast<unsigned long long>(metadata.last_sequence),
          health_.last_error.c_str());
      break;
    }
    const std::uint64_t before = health_.free_bytes;
    if (!removeSegmentTransactionally(verified, server_ack_sequence,
                                      now_utc_ms, reason)) {
      ok = false;
      health_.last_error = "cleanup_transaction_failed";
      break;
    }
    updateCapacity();
    const std::uint64_t actual = health_.free_bytes > before
                                     ? health_.free_bytes - before
                                     : metadata.payload_bytes +
                                           metadata.index_bytes;
    reclaimed += actual;
    growth_estimator_.recordCleanup(actual);
  }

  // Event evidence has its own acknowledgement cursor and age window. It is
  // never made eligible merely because reading data was acknowledged.
  std::vector<std::string> event_files;
  collectFiles("/POWERMON/events", ".events", event_files);
  std::vector<SegmentMetadata> event_segments;
  event_segments.reserve(event_files.size());
  std::vector<bool> event_metadata_loaded;
  event_metadata_loaded.reserve(event_files.size());
  std::uint64_t newest_event_sequence = 0U;
  for (const auto &path : event_files) {
    SegmentMetadata metadata;
    const bool loaded = loadSegmentMetadata(path, true, metadata);
    if (!loaded) {
      metadata = inspectEventSegment(path);
    }
    newest_event_sequence =
        std::max(newest_event_sequence, metadata.last_sequence);
    event_segments.push_back(std::move(metadata));
    event_metadata_loaded.push_back(loaded);
    vTaskDelay(pdMS_TO_TICKS(1));
  }
  for (std::size_t index = 0; index < event_segments.size(); ++index) {
    auto &metadata = event_segments[index];
    metadata.active = newest_event_sequence != 0U &&
                      metadata.last_sequence == newest_event_sequence;
    metadata.closed = !metadata.active;
    const bool metadata_unchanged =
        event_metadata_loaded[index] && metadata.closed;
    if (!metadata_unchanged && !persistSegmentMetadata(metadata)) {
      metadata.complete = false;
    }
    vTaskDelay(pdMS_TO_TICKS(1));
  }
  health_.event_segment_count =
      static_cast<std::uint32_t>(event_segments.size());
  std::vector<std::size_t> event_by_newest(event_segments.size());
  std::iota(event_by_newest.begin(), event_by_newest.end(), 0U);
  std::sort(event_by_newest.begin(), event_by_newest.end(),
            [&event_segments](const std::size_t left,
                              const std::size_t right) {
              return event_segments[left].last_sequence >
                     event_segments[right].last_sequence;
            });
  protected_closed = 0U;
  for (const std::size_t index : event_by_newest) {
    if (!event_segments[index].active && protected_closed < 2U) {
      event_segments[index].minimum_window_protected = true;
      ++protected_closed;
    }
  }
  RetentionContext event_context = context;
  event_context.acknowledgement_verified = event_ack_sequence > 0U;
  event_context.server_ack_sequence = event_ack_sequence;
  const std::uint64_t event_retention_ms =
      static_cast<std::uint64_t>(policy.event_retention_days) *
      86'400'000ULL;
  event_context.retention_cutoff_utc_ms =
      now_utc_ms > event_retention_ms ? now_utc_ms - event_retention_ms : 0U;
  const CleanupPlan event_plan =
      buildCleanupPlan(event_segments, event_context, health_.free_bytes,
                       context.emergency_pressure ? target : 0U);
  health_.segment_count +=
      static_cast<std::uint32_t>(event_segments.size());
  health_.eligible_segment_count +=
      static_cast<std::uint32_t>(event_plan.candidate_indexes.size());
  health_.reclaimable_bytes += event_plan.eligible_bytes;
  health_.protected_unacknowledged_bytes +=
      event_plan.protected_unacknowledged_bytes;
  health_.protected_untrusted_bytes +=
      event_plan.protected_untrusted_bytes;
  for (const auto &metadata : event_segments) {
    const SegmentEligibility eligibility =
        segmentEligibility(metadata, event_context);
    if (eligibility != SegmentEligibility::EligibleAge &&
        eligibility != SegmentEligibility::EligibleEmergency) {
      ++health_.protected_segment_count;
    }
  }
  for (const std::size_t index : event_plan.candidate_indexes) {
    if (!ok || policy.mode == RetentionMode::Disabled ||
        index >= event_segments.size()) {
      break;
    }
    const SegmentMetadata &metadata = event_segments[index];
    SegmentMetadata verified = inspectEventSegment(metadata.record_path);
    verified.active = metadata.active;
    verified.closed = metadata.closed;
    verified.cleanup_active = metadata.cleanup_active;
    verified.minimum_window_protected = metadata.minimum_window_protected;
    const bool metadata_matches =
        verified.first_sequence == metadata.first_sequence &&
        verified.last_sequence == metadata.last_sequence &&
        verified.payload_bytes == metadata.payload_bytes &&
        verified.record_count == metadata.record_count &&
        verified.integrity_crc == metadata.integrity_crc;
    const SegmentEligibility eligibility =
        metadata_matches ? segmentEligibility(verified, event_context)
                         : SegmentEligibility::CorruptOrMissingIndex;
    if (eligibility != SegmentEligibility::EligibleAge &&
        eligibility != SegmentEligibility::EligibleEmergency) {
      ok = false;
      health_.last_error = metadata_matches
                               ? "event_cleanup_eligibility_changed"
                               : "event_cleanup_candidate_integrity_changed";
      PM_LOG_ERROR(
          "STORAGE", "storage.cleanup_event_candidate_rejected",
          "first_event_sequence=%llu last_event_sequence=%llu reason=%s",
          static_cast<unsigned long long>(metadata.first_sequence),
          static_cast<unsigned long long>(metadata.last_sequence),
          health_.last_error.c_str());
      break;
    }
    const std::uint64_t before = health_.free_bytes;
    if (!removeSegmentTransactionally(verified, event_ack_sequence,
                                      now_utc_ms, reason + "_events")) {
      ok = false;
      health_.last_error = "event_cleanup_transaction_failed";
      break;
    }
    updateCapacity();
    const std::uint64_t actual =
        health_.free_bytes > before ? health_.free_bytes - before
                                    : metadata.payload_bytes;
    reclaimed += actual;
    growth_estimator_.recordCleanup(actual);
  }
  cleanupTemporaryArtifacts(now_utc_ms);
  health_.cleanup_in_progress = false;
  health_.last_cleanup_utc_ms = now_utc_ms;
  health_.last_cleanup_reclaimed_bytes = reclaimed;
  health_.last_cleanup_reason = reason;
  if (policy.mode == RetentionMode::Disabled) {
    health_.last_cleanup_result = "disabled";
  } else if (!ok) {
    health_.last_cleanup_result = "failed";
  } else if (reclaimed == 0U &&
             (plan.protected_unacknowledged_bytes +
                  event_plan.protected_unacknowledged_bytes >
              0U) &&
             context.emergency_pressure) {
    health_.last_cleanup_result = "blocked_unacknowledged";
    health_.pressure_state = storagePressureStateName(
        StoragePressureState::CleanupBlockedUnacknowledged);
  } else if (reclaimed == 0U &&
             (plan.protected_untrusted_bytes +
                  event_plan.protected_untrusted_bytes >
              0U)) {
    health_.last_cleanup_result = "blocked_untrusted";
    health_.pressure_state = storagePressureStateName(
        StoragePressureState::CleanupBlockedUntrusted);
  } else {
    health_.last_cleanup_result = reclaimed == 0U ? "not_needed" : "completed";
  }
  if (reclaimed > 0U) {
    ok = recover() && ok;
    updateCapacity();
  }
  publishHealthSnapshot(health_);
  PM_LOG_INFO(
      "SD", "RETENTION_COMPLETE",
      "result=%s cleanup_result=%s scanned_segments=%u eligible=%u "
      "reclaimed=%llu protected_unacknowledged=%llu protected_untrusted=%llu "
      "free=%llu",
      ok ? "success" : "failed", health_.last_cleanup_result.c_str(),
      static_cast<unsigned>(segments.size()),
      static_cast<unsigned>(plan.candidate_indexes.size()),
      static_cast<unsigned long long>(reclaimed),
      static_cast<unsigned long long>(plan.protected_unacknowledged_bytes),
      static_cast<unsigned long long>(plan.protected_untrusted_bytes),
      static_cast<unsigned long long>(health_.free_bytes));
  if (health_.last_cleanup_result == "blocked_unacknowledged") {
    PM_LOG_WARN(
        "STORAGE", "storage.cleanup_blocked_unacknowledged",
        "server_ack=%llu protected_bytes=%llu free_bytes=%llu reason=%s",
        static_cast<unsigned long long>(server_ack_sequence),
        static_cast<unsigned long long>(
            health_.protected_unacknowledged_bytes),
        static_cast<unsigned long long>(health_.free_bytes), reason.c_str());
  } else if (health_.last_cleanup_result == "blocked_untrusted") {
    PM_LOG_WARN(
        "STORAGE", "storage.cleanup_blocked_untrusted",
        "protected_bytes=%llu free_bytes=%llu reason=%s",
        static_cast<unsigned long long>(health_.protected_untrusted_bytes),
        static_cast<unsigned long long>(health_.free_bytes), reason.c_str());
  } else if (health_.last_cleanup_result == "completed") {
    PM_LOG_INFO(
        "STORAGE", "storage.cleanup_completed",
        "reclaimed_bytes=%llu free_bytes=%llu reason=%s",
        static_cast<unsigned long long>(health_.last_cleanup_reclaimed_bytes),
        static_cast<unsigned long long>(health_.free_bytes), reason.c_str());
  }
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
  PM_LOG_INFO("SD", "storage.card_prepared",
              "buffers_flushed=true mounted=false power_down_required=true");
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

CompactStorageHealth SdStorage::compactHealth() const {
  const auto compact = [](const StorageHealth &health) {
    return CompactStorageHealth{health.present, health.mounted, health.writable,
                                health.newest_sequence,
                                health.newest_syncable_sequence};
  };
  if (!lock(pdMS_TO_TICKS(100))) {
    if (health_snapshot_mutex_ != nullptr &&
        xSemaphoreTake(health_snapshot_mutex_, pdMS_TO_TICKS(25)) == pdTRUE) {
      const CompactStorageHealth snapshot = compact(last_health_snapshot_);
      xSemaphoreGive(health_snapshot_mutex_);
      return snapshot;
    }
    return {};
  }
  const CompactStorageHealth snapshot = compact(health_);
  unlock();
  return snapshot;
}

HeartbeatStorageHealth SdStorage::heartbeatHealth() const {
  const auto compact = [](const StorageHealth &source) {
    HeartbeatStorageHealth output;
    output.present = source.present;
    output.mounted = source.mounted;
    output.writable = source.writable;
    output.prepared_for_removal = source.prepared_for_removal;
    output.sequence_floor_ready = source.sequence_floor_ready;
    output.sequence_reconciliation_in_progress =
        source.sequence_reconciliation_in_progress;
    output.sequence_conflict = source.sequence_conflict;
    output.last_self_test_passed = source.last_self_test_passed;
    output.card_replaced_or_initialized = source.card_replaced_or_initialized;
    output.index_healthy = source.index_healthy;
    output.acknowledgement_verified = source.acknowledgement_verified;
    output.cleanup_in_progress = source.cleanup_in_progress;
    output.cleanup_recovery_required = source.cleanup_recovery_required;
    output.storage_full = source.storage_full;
    output.capacity_bytes = source.capacity_bytes;
    output.used_bytes = source.used_bytes;
    output.free_bytes = source.free_bytes;
    output.oldest_sequence = source.oldest_sequence;
    output.oldest_syncable_sequence = source.oldest_syncable_sequence;
    output.newest_syncable_sequence = source.newest_syncable_sequence;
    output.newest_sequence = source.newest_sequence;
    output.local_record_count = source.local_record_count;
    output.oldest_event_sequence = source.oldest_event_sequence;
    output.newest_event_sequence = source.newest_event_sequence;
    output.write_failures = source.write_failures;
    output.sequence_floor = source.sequence_floor;
    output.next_sequence = source.next_sequence;
    output.card_generation = source.card_generation;
    output.reclaimable_bytes = source.reclaimable_bytes;
    output.protected_unacknowledged_bytes =
        source.protected_unacknowledged_bytes;
    output.protected_untrusted_bytes = source.protected_untrusted_bytes;
    output.last_cleanup_utc_ms = source.last_cleanup_utc_ms;
    output.last_cleanup_reclaimed_bytes =
        source.last_cleanup_reclaimed_bytes;
    output.dropped_interval_count = source.dropped_interval_count;
    output.first_dropped_interval_utc_ms =
        source.first_dropped_interval_utc_ms;
    output.last_dropped_interval_utc_ms = source.last_dropped_interval_utc_ms;
    output.growth_bytes_per_day = source.growth_bytes_per_day;
    output.estimated_days_remaining = source.estimated_days_remaining;
    output.segment_count = source.segment_count;
    output.eligible_segment_count = source.eligible_segment_count;
    output.protected_segment_count = source.protected_segment_count;
    output.open_segment_count = source.open_segment_count;
    output.closed_segment_count = source.closed_segment_count;
    output.untrusted_segment_count = source.untrusted_segment_count;
    output.event_segment_count = source.event_segment_count;
    output.export_count = source.export_count;
    output.repair_artifact_count = source.repair_artifact_count;
    output.temporary_artifact_count = source.temporary_artifact_count;
    output.free_percent = source.free_percent;
    const auto copy_text = [&output](auto &destination,
                                     const std::string &value) {
      const int written = std::snprintf(destination.data(), destination.size(),
                                        "%s", value.c_str());
      output.truncated =
          output.truncated || written < 0 ||
          static_cast<std::size_t>(written) >= destination.size();
    };
    copy_text(output.filesystem, source.filesystem);
    copy_text(output.card_type, source.card_type);
    copy_text(output.card_identity_status, source.card_identity_status);
    copy_text(output.pressure_state, source.pressure_state);
    copy_text(output.pressure_reason, source.pressure_reason);
    copy_text(output.last_cleanup_result, source.last_cleanup_result);
    copy_text(output.last_cleanup_reason, source.last_cleanup_reason);
    copy_text(output.last_error, source.last_error);
    return output;
  };
  if (!lock(pdMS_TO_TICKS(100))) {
    if (health_snapshot_mutex_ != nullptr &&
        xSemaphoreTake(health_snapshot_mutex_, pdMS_TO_TICKS(25)) == pdTRUE) {
      const HeartbeatStorageHealth snapshot = compact(last_health_snapshot_);
      xSemaphoreGive(health_snapshot_mutex_);
      return snapshot;
    }
    HeartbeatStorageHealth unavailable;
    std::snprintf(unavailable.last_error.data(), unavailable.last_error.size(),
                  "%s", "storage_health_snapshot_busy");
    return unavailable;
  }
  const HeartbeatStorageHealth snapshot = compact(health_);
  unlock();
  return snapshot;
}

SequenceState SdStorage::sequenceState(
    const std::uint64_t persisted_server_ack,
    const std::uint64_t persisted_server_max_seen,
    const std::uint64_t prepared_removal_high_water) const {
  SequenceState state;
  StorageHealth snapshot;
  bool have_snapshot = false;
  if (lock(pdMS_TO_TICKS(100))) {
    snapshot = health_;
    unlock();
    publishHealthSnapshot(snapshot);
    have_snapshot = true;
  } else if (health_snapshot_mutex_ != nullptr &&
             xSemaphoreTake(health_snapshot_mutex_, pdMS_TO_TICKS(25)) ==
                 pdTRUE) {
    // Retention and recovery intentionally own the SD mutex for the complete
    // filesystem transaction.  A heartbeat must not interpret that temporary
    // lock contention as a removed card with sequence zero: doing so queues a
    // spurious floor advance while the real high-water mark is still valid.
    // The independently protected snapshot is published only after complete
    // storage mutations, so it is safe and internally consistent here.
    snapshot = last_health_snapshot_;
    xSemaphoreGive(health_snapshot_mutex_);
    have_snapshot = true;
  }
  if (!have_snapshot) {
    state.persisted_server_ack = persisted_server_ack;
    state.persisted_server_max_seen = persisted_server_max_seen;
    state.prepared_removal_high_water = prepared_removal_high_water;
    state.effective_sequence_floor =
        std::max({persisted_server_ack, persisted_server_max_seen,
                  prepared_removal_high_water});
    state.next_sequence =
        state.effective_sequence_floor ==
                std::numeric_limits<std::uint64_t>::max()
            ? state.effective_sequence_floor
            : state.effective_sequence_floor + 1U;
    state.sequence_reconciliation_in_progress = true;
    return state;
  }
  state.storage_present = snapshot.present;
  state.storage_mounted = snapshot.mounted;
  state.storage_writable = snapshot.writable;
  state.card_empty = snapshot.local_record_count == 0U;
  state.sequence_floor_ready = snapshot.sequence_floor_ready;
  state.sequence_reconciliation_in_progress =
      snapshot.sequence_reconciliation_in_progress;
  state.sequence_conflict = snapshot.sequence_conflict;
  state.local_record_count = snapshot.local_record_count;
  state.local_oldest_sequence = snapshot.oldest_sequence;
  state.local_newest_sequence = snapshot.newest_sequence;
  state.local_journal_high_water = snapshot.sequence_floor;
  state.prepared_removal_high_water = prepared_removal_high_water;
  state.persisted_server_ack = persisted_server_ack;
  state.persisted_server_max_seen = persisted_server_max_seen;
  state.effective_sequence_floor = std::max(
      {state.local_newest_sequence, state.local_journal_high_water,
       persisted_server_ack, persisted_server_max_seen,
       prepared_removal_high_water});
  state.next_sequence = snapshot.next_sequence;
  state.card_generation = snapshot.card_generation;
  state.card_identity_status = snapshot.card_identity_status;
  return state;
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
    PM_LOG_ERROR("STORAGE", "SEQUENCE_FLOOR_ADVANCE_FAILED",
                 "reason=storage_lock_timeout required_floor=%llu",
                 static_cast<unsigned long long>(acknowledged_sequence));
    return false;
  }
  PM_LOG_INFO(
      "STORAGE", "SEQUENCE_FLOOR_ADVANCE_BEGIN",
      "required_floor=%llu current_floor=%llu local_newest=%llu "
      "mounted=%s writable=%s",
      static_cast<unsigned long long>(acknowledged_sequence),
      static_cast<unsigned long long>(next_sequence_ - 1U),
      static_cast<unsigned long long>(health_.newest_sequence),
      health_.mounted ? "true" : "false",
      health_.writable ? "true" : "false");
  const std::uint64_t current_floor = next_sequence_ - 1U;
  // A requested floor is a lower bound, not an equality assertion. A queued
  // request may become stale while StorageTask is completing retention or a
  // remount. If the durable journal has already advanced beyond that request,
  // continuity is satisfied and must never be downgraded to a conflict.
  if (health_.mounted && health_.writable &&
      acknowledged_sequence <= current_floor) {
    health_.sequence_conflict = false;
    health_.sequence_floor_ready = true;
    health_.sequence_reconciliation_in_progress = false;
    health_.sequence_floor = current_floor;
    health_.next_sequence = next_sequence_;
    publishHealthSnapshot(health_);
    PM_LOG_INFO(
        "STORAGE", "SEQUENCE_FLOOR_ADVANCE_COMPLETE",
        "result=already_reconciled reason=current_floor_satisfies_required "
        "required_floor=%llu final_floor=%llu next_sequence=%llu",
        static_cast<unsigned long long>(acknowledged_sequence),
        static_cast<unsigned long long>(current_floor),
        static_cast<unsigned long long>(next_sequence_));
    unlock();
    return true;
  }
  const bool valid =
      health_.mounted && health_.writable &&
      acknowledged_sequence >= health_.newest_sequence &&
      acknowledged_sequence >= current_floor &&
      acknowledged_sequence != std::numeric_limits<std::uint64_t>::max();
  if (!valid || acknowledged_sequence == current_floor) {
    const bool unavailable = !health_.mounted || !health_.writable;
    health_.sequence_conflict = !valid && !unavailable;
    health_.sequence_floor_ready = valid;
    health_.sequence_reconciliation_in_progress = unavailable;
    health_.sequence_floor = current_floor;
    health_.next_sequence = next_sequence_;
    publishHealthSnapshot(health_);
    PM_LOG_INFO(
        "STORAGE",
        valid ? "SEQUENCE_FLOOR_ADVANCE_COMPLETE"
              : "SEQUENCE_FLOOR_ADVANCE_FAILED",
        "result=%s reason=%s required_floor=%llu final_floor=%llu "
        "next_sequence=%llu",
        valid ? "already_reconciled" : "failed",
        unavailable ? "storage_unavailable" : "cursor_conflict",
        static_cast<unsigned long long>(acknowledged_sequence),
        static_cast<unsigned long long>(health_.sequence_floor),
        static_cast<unsigned long long>(health_.next_sequence));
    unlock();
    return valid;
  }
  health_.sequence_reconciliation_in_progress = true;
  const bool persisted = persistSequence(acknowledged_sequence);
  if (persisted) {
    const bool blank_or_replaced_card = health_.newest_sequence == 0U;
    next_sequence_ = acknowledged_sequence + 1U;
    health_.sequence_floor = acknowledged_sequence;
    health_.next_sequence = next_sequence_;
    health_.sequence_floor_ready = true;
    health_.sequence_reconciliation_in_progress = false;
    health_.sequence_conflict = false;
    ++health_.sequence_floor_advances;
    PM_LOG_WARN(
        "SYNC", "SEQUENCE_FLOOR_ADVANCED",
        "server_ack=%llu newest_stored=%llu next_sequence=%llu "
        "reason=server_cursor_ahead",
        static_cast<unsigned long long>(acknowledged_sequence),
        static_cast<unsigned long long>(health_.newest_sequence),
        static_cast<unsigned long long>(next_sequence_));
    PM_LOG_WARN(
        "STORAGE", "storage.sequence_floor_restored",
        "server_ack=%llu next_sequence=%llu blank_or_replaced_card=%s",
        static_cast<unsigned long long>(acknowledged_sequence),
        static_cast<unsigned long long>(next_sequence_),
        blank_or_replaced_card ? "true" : "false");
    if (blank_or_replaced_card) {
      PM_LOG_WARN("STORAGE", "storage.card_replaced",
                  "sequence_continuity=restored next_sequence=%llu",
                  static_cast<unsigned long long>(next_sequence_));
    }
    PM_LOG_INFO(
        "STORAGE", "SEQUENCE_FLOOR_ADVANCE_COMPLETE",
        "result=reconciled required_floor=%llu final_floor=%llu "
        "next_sequence=%llu",
        static_cast<unsigned long long>(acknowledged_sequence),
        static_cast<unsigned long long>(health_.sequence_floor),
        static_cast<unsigned long long>(health_.next_sequence));
  } else {
    ++health_.write_failures;
    if (health_.last_error.empty()) {
      health_.last_error = "sequence_floor_persist_failed";
    }
    health_.sequence_floor_ready = false;
    health_.sequence_reconciliation_in_progress = true;
    PM_LOG_ERROR(
        "STORAGE", "SEQUENCE_FLOOR_ADVANCE_FAILED",
        "reason=%s required_floor=%llu current_floor=%llu local_newest=%llu",
        health_.last_error.c_str(),
        static_cast<unsigned long long>(acknowledged_sequence),
        static_cast<unsigned long long>(health_.sequence_floor),
        static_cast<unsigned long long>(health_.newest_sequence));
  }
  publishHealthSnapshot(health_);
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
                                                "/POWERMON/recovery/retention-trash",
                                                "/POWERMON/state/segments",
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
  health_.oldest_sequence = 0U;
  health_.oldest_syncable_sequence = 0;
  health_.newest_syncable_sequence = 0;
  health_.local_record_count = 0U;
  for (const auto &path : files) {
    SegmentMetadata metadata;
    // Closed segments were fully inspected when their immutable, checksummed
    // sidecar was written. Revalidate that sidecar and both file sizes instead
    // of rereading every historical byte after a CPU-only reset. Active,
    // untrusted, incomplete, or changed segments still take the conservative
    // repair scan below.
    const bool recovered_from_metadata =
        loadSegmentMetadata(path, false, metadata) && metadata.closed &&
        metadata.complete && metadata.index_valid &&
        metadata.all_times_trusted;
    if (recovered_from_metadata) {
      maximum_sequence = std::max(maximum_sequence, metadata.last_sequence);
      health_.oldest_sequence =
          health_.oldest_sequence == 0U
              ? metadata.first_sequence
              : std::min(health_.oldest_sequence, metadata.first_sequence);
      health_.oldest_syncable_sequence =
          health_.oldest_syncable_sequence == 0U
              ? metadata.first_sequence
              : std::min(health_.oldest_syncable_sequence,
                         metadata.first_sequence);
      health_.newest_syncable_sequence = std::max(
          health_.newest_syncable_sequence, metadata.last_sequence);
      health_.local_record_count += metadata.record_count;
      PM_LOG_TRACE(
          "SD", "RECOVERY_SEGMENT_METADATA_ACCEPTED",
          "first_sequence=%llu last_sequence=%llu records=%lu",
          static_cast<unsigned long long>(metadata.first_sequence),
          static_cast<unsigned long long>(metadata.last_sequence),
          static_cast<unsigned long>(metadata.record_count));
    } else {
      all_valid = recoverFile(path, maximum_sequence) && all_valid;
    }
    vTaskDelay(pdMS_TO_TICKS(1));
  }
  std::uint64_t journal_sequence = 0;
  std::uint64_t temporary_sequence = 0;
  std::uint64_t backup_sequence = 0;
  loadSequenceJournal("/POWERMON/state/sequence.journal", journal_sequence);
  loadSequenceJournal("/POWERMON/state/sequence.journal.tmp",
                      temporary_sequence);
  loadSequenceJournal("/POWERMON/state/sequence.journal.bak",
                      backup_sequence);
  journal_sequence =
      std::max({journal_sequence, temporary_sequence, backup_sequence});
  if ((temporary_sequence != 0U || backup_sequence != 0U) &&
      !persistSequence(journal_sequence)) {
    health_.last_error = "sequence_journal_recovery_failed";
    return false;
  }
  const std::uint64_t committed = std::max(maximum_sequence, journal_sequence);
  if (committed == std::numeric_limits<std::uint64_t>::max()) {
    health_.sequence_conflict = true;
    health_.last_error = "sequence_space_exhausted";
    return false;
  }
  next_sequence_ = committed + 1;
  health_.sequence_floor = committed;
  health_.next_sequence = next_sequence_;
  health_.newest_sequence = maximum_sequence;
  std::uint64_t maximum_event_sequence = 0U;
  std::uint64_t minimum_event_sequence = 0U;
  std::vector<std::string> event_files;
  collectFiles("/POWERMON/events", ".events", event_files);
  for (const auto &path : event_files) {
    SegmentMetadata metadata;
    if (loadSegmentMetadata(path, true, metadata) && metadata.closed &&
        metadata.complete && metadata.all_times_trusted) {
      minimum_event_sequence =
          minimum_event_sequence == 0U
              ? metadata.first_sequence
              : std::min(minimum_event_sequence, metadata.first_sequence);
      maximum_event_sequence =
          std::max(maximum_event_sequence, metadata.last_sequence);
      vTaskDelay(pdMS_TO_TICKS(1));
      continue;
    }
    File event_file = SD.open(path.c_str(), FILE_READ);
    std::size_t scanned_event_records = 0U;
    while (event_file && event_file.available() > 0) {
      const String raw = event_file.readStringUntil('\n');
      std::string event_payload;
      std::uint32_t event_checksum = 0U;
      JsonDocument event_document;
      if (!record::decodeEnvelope(raw.c_str(), event_payload, event_checksum) ||
          deserializeJson(event_document, event_payload) ||
          !event_document["event_sequence"].is<std::uint64_t>()) {
        all_valid = false;
        health_.last_error = "event_record_corruption_detected";
        break;
      }
      const std::uint64_t sequence =
          event_document["event_sequence"].as<std::uint64_t>();
      minimum_event_sequence = minimum_event_sequence == 0U
                                   ? sequence
                                   : std::min(minimum_event_sequence, sequence);
      maximum_event_sequence = std::max(maximum_event_sequence, sequence);
      ++scanned_event_records;
      if (scanned_event_records % kCooperativeScanRecords == 0U) {
        vTaskDelay(pdMS_TO_TICKS(1));
      }
    }
    if (event_file) {
      event_file.close();
    }
    vTaskDelay(pdMS_TO_TICKS(1));
  }
  File event_journal =
      SD.open("/POWERMON/state/event-sequence.journal", FILE_READ);
  std::uint64_t event_journal_sequence = 0U;
  if (event_journal) {
    const String value = event_journal.readStringUntil('\n');
    event_journal_sequence = std::strtoull(value.c_str(), nullptr, 10);
    event_journal.close();
  }
  next_event_sequence_ =
      std::max(maximum_event_sequence, event_journal_sequence) + 1U;
  health_.oldest_event_sequence = minimum_event_sequence;
  health_.newest_event_sequence = maximum_event_sequence;
  // Reading and event history share the public integrity state. Publish it
  // only after both scans so an event-record fault cannot be mislabeled as a
  // fully verified card in MOUNT_COMPLETE or the heartbeat health payload.
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
  // A corrupt historical segment is preserved and excluded from synchronization,
  // but it must not make a card that passed the filesystem self-test read-only.
  // The sequence floor is still safe because it is the maximum of every valid
  // record plus the target/temp/backup journals and the persisted server cursor.
  // Hard failures above (journal installation or sequence exhaustion) continue
  // to fail closed.
  return true;
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
    const std::uint64_t sequence =
        document["sequence"].as<std::uint64_t>();
    health_.oldest_sequence =
        health_.oldest_sequence == 0U
            ? sequence
            : std::min(health_.oldest_sequence, sequence);
    maximum_sequence = std::max(maximum_sequence, sequence);
    ++health_.local_record_count;
    if (syncableDocument(document)) {
      health_.oldest_syncable_sequence =
          health_.oldest_syncable_sequence == 0
              ? sequence
              : std::min(health_.oldest_syncable_sequence, sequence);
      health_.newest_syncable_sequence =
          std::max(health_.newest_syncable_sequence, sequence);
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
  const char *target = "/POWERMON/manifest.json";
  if (SD.exists(target)) {
    File existing = SD.open(target, FILE_READ);
    JsonDocument stored;
    const DeserializationError error = deserializeJson(stored, existing);
    if (existing) {
      existing.close();
    }
    if (error) {
      health_.card_identity_status = "manifest_invalid";
      health_.last_error = "storage_manifest_invalid";
      return false;
    }
    const std::uint32_t schema = stored["schema_version"] | 1U;
    if (schema >= 2U) {
      const std::string stored_device = stored["device_id"] | "";
      const std::string stored_fingerprint =
          stored["hardware_id_fingerprint"] |
          (stored["hardware_fingerprint"] | "");
      if ((!stored_device.empty() && stored_device != device_id_) ||
          (!stored_fingerprint.empty() &&
           stored_fingerprint != hardware_fingerprint_)) {
        health_.card_identity_status = "wrong_sensor";
        health_.card_device_id = stored_device;
        health_.last_error = "storage_card_identity_mismatch";
        PM_LOG_ERROR(
            "STORAGE", "CARD_IDENTITY_MISMATCH",
            "expected_device=%s stored_device=%s action=read_only",
            diag::maskIdentifier(device_id_).c_str(),
            diag::maskIdentifier(stored_device).c_str());
        return false;
      }
      health_.card_identity_status = "verified";
      health_.card_device_id = stored_device;
      health_.card_generation = stored["card_generation"] | 0ULL;
      health_.card_replaced_or_initialized = false;
      return true;
    }
    // Schema 1 cards predate identity binding. Upgrade in place without
    // touching readings or sequence history.
  }
  JsonDocument document;
  document["schema_version"] = 2;
  document["record_format"] = "PMR1";
  document["protocol"] = version::PROTOCOL;
  document["authoritative_store"] = "microSD";
  document["device_id"] = device_id_;
  document["hardware_id_fingerprint"] = hardware_fingerprint_;
  const std::uint64_t generation =
      (static_cast<std::uint64_t>(esp_random()) << 32U) | esp_random();
  document["card_generation"] = generation;
  const std::time_t created_at = std::time(nullptr);
  if (created_at >= 1'600'000'000) {
    document["created_at"] =
        isoUtc(static_cast<std::uint64_t>(created_at) * 1000U);
  } else {
    document["created_at"] = nullptr;
  }
  document["created_monotonic_ms"] = millis();
  std::string payload;
  serializeJson(document, payload);
  const char *temporary = "/POWERMON/manifest.json.tmp";
  SD.remove(temporary);
  File file = SD.open(temporary, FILE_WRITE);
  const bool ok =
      file && file.write(reinterpret_cast<const std::uint8_t *>(payload.data()),
                         payload.size()) == payload.size();
  if (file) {
    file.flush();
    file.close();
  }
  if (!ok) {
    SD.remove(temporary);
    return false;
  }
  File verify = SD.open(temporary, FILE_READ);
  JsonDocument verified;
  const bool verified_ok = verify && !deserializeJson(verified, verify) &&
                           verified["schema_version"].as<unsigned>() == 2U &&
                           std::string(verified["device_id"] | "") == device_id_;
  if (verify) {
    verify.close();
  }
  if (!verified_ok) {
    SD.remove(temporary);
    return false;
  }
  SD.remove(target);
  const bool installed = SD.rename(temporary, target);
  health_.card_identity_status = installed ? "verified" : "manifest_write_failed";
  health_.card_device_id = installed ? device_id_ : "";
  health_.card_generation = installed ? generation : 0U;
  health_.card_replaced_or_initialized = installed;
  return installed;
}

bool SdStorage::loadSequenceJournal(const char *path,
                                    std::uint64_t &value) const {
  value = 0U;
  File file = SD.open(path, FILE_READ);
  if (!file) {
    return false;
  }
  const String raw = file.readStringUntil('\n');
  file.close();
  if (raw.isEmpty()) {
    return false;
  }
  char *end = nullptr;
  const unsigned long long parsed = std::strtoull(raw.c_str(), &end, 10);
  if (end == raw.c_str() || (*end != '\0' && *end != '\r')) {
    return false;
  }
  value = static_cast<std::uint64_t>(parsed);
  return true;
}

bool SdStorage::persistSequence(const std::uint64_t committed_sequence) {
  const std::string value = std::to_string(committed_sequence) + "\n";
  const char *temporary = "/POWERMON/state/sequence.journal.tmp";
  const char *target = "/POWERMON/state/sequence.journal";
  const char *backup = "/POWERMON/state/sequence.journal.bak";
  if (SD.exists(temporary) && !SD.remove(temporary)) {
    health_.last_error = "sequence_journal_temporary_remove_failed";
    ++health_.sequence_floor_write_failures;
    return false;
  }
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
    health_.last_error = "sequence_journal_temporary_write_failed";
    ++health_.sequence_floor_write_failures;
    return false;
  }
  std::uint64_t verified_sequence = 0U;
  if (!loadSequenceJournal(temporary, verified_sequence) ||
      verified_sequence != committed_sequence) {
    SD.remove(temporary);
    health_.last_error = "sequence_journal_temporary_verify_failed";
    ++health_.sequence_floor_verify_failures;
    return false;
  }
  if (SD.exists(backup) && !SD.remove(backup)) {
    SD.remove(temporary);
    health_.last_error = "sequence_journal_backup_remove_failed";
    ++health_.sequence_floor_write_failures;
    return false;
  }
  const bool had_target = SD.exists(target);
  if (had_target && !SD.rename(target, backup)) {
    SD.remove(temporary);
    health_.last_error = "sequence_journal_backup_rename_failed";
    ++health_.sequence_floor_write_failures;
    return false;
  }
  if (!SD.rename(temporary, target)) {
    if (had_target) {
      SD.rename(backup, target);
    }
    health_.last_error = "sequence_journal_install_rename_failed";
    ++health_.sequence_floor_write_failures;
    return false;
  }
  verified_sequence = 0U;
  const bool installed = loadSequenceJournal(target, verified_sequence) &&
                         verified_sequence == committed_sequence;
  if (installed) {
    SD.remove(backup);
    return true;
  }
  SD.remove(target);
  if (had_target) {
    SD.rename(backup, target);
  }
  health_.last_error = "sequence_journal_final_verify_failed";
  ++health_.sequence_floor_verify_failures;
  return false;
}

bool SdStorage::persistEventSequence(
    const std::uint64_t committed_sequence) {
  const std::string value = std::to_string(committed_sequence) + "\n";
  const char *temporary = "/POWERMON/state/event-sequence.journal.tmp";
  const char *target = "/POWERMON/state/event-sequence.journal";
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
  ScopedFatDirectoryWatchdogGuard watchdog_guard;
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

void SdStorage::cleanupTemporaryArtifacts(const std::uint64_t now_utc_ms) {
  constexpr std::uint64_t kExportTtlMs = 86'400'000ULL;
  std::vector<std::string> exports;
  collectFiles("/POWERMON/exports", "", exports);
  health_.export_count = static_cast<std::uint32_t>(exports.size());
  health_.temporary_artifact_count = 0U;
  for (const auto &path : exports) {
    if (endsWith(path, ".tmp")) {
      ++health_.temporary_artifact_count;
    }
    File artifact = SD.open(path.c_str(), FILE_READ);
    const std::uint64_t modified_ms =
        artifact ? static_cast<std::uint64_t>(artifact.getLastWrite()) * 1000U
                 : 0U;
    if (artifact) {
      artifact.close();
    }
    if (modified_ms != 0U && now_utc_ms > modified_ms &&
        now_utc_ms - modified_ms >= kExportTtlMs) {
      if (SD.remove(path.c_str())) {
        --health_.export_count;
        if (endsWith(path, ".tmp") &&
            health_.temporary_artifact_count > 0U) {
          --health_.temporary_artifact_count;
        }
        PM_LOG_INFO("STORAGE", "storage.temporary_artifact_removed",
                    "kind=export age_ms=%llu",
                    static_cast<unsigned long long>(now_utc_ms - modified_ms));
      }
    }
  }
  std::vector<std::string> repairs;
  collectFiles("/POWERMON/records", ".repair", repairs);
  health_.repair_artifact_count =
      static_cast<std::uint32_t>(repairs.size());
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
  const bool event_records =
      std::strcmp(sequence_field, "event_sequence") == 0;

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
    // Closed segment metadata is immutable after recovery/rotation. Use its
    // verified sequence bounds to avoid rereading every acknowledged segment
    // for each small synchronization page. This is especially important on a
    // card mounted at the conservative recovery speed: a complete scan can
    // otherwise hold the storage memory lease across several heartbeat
    // intervals and make a healthy sensor appear offline.
    //
    // Active segments and any segment with missing/incomplete metadata still
    // take the full conservative scan path. The optimization can therefore
    // never hide newly appended or unverifiable records.
    SegmentMetadata segment;
    if (loadSegmentMetadata(path, event_records, segment) && segment.closed &&
        segment.complete &&
        (segment.last_sequence <= query.after_sequence ||
         segment.first_sequence > scan_ceiling)) {
      PM_LOG_TRACE(
          "STORAGE", "HISTORY_SEGMENT_SKIPPED",
          "kind=%s first_sequence=%llu last_sequence=%llu after=%llu "
          "scan_ceiling=%llu reason=verified_closed_range",
          event_records ? "events" : "readings",
          static_cast<unsigned long long>(segment.first_sequence),
          static_cast<unsigned long long>(segment.last_sequence),
          static_cast<unsigned long long>(query.after_sequence),
          static_cast<unsigned long long>(scan_ceiling));
      continue;
    }
    std::uint64_t indexed_start_offset = 0U;
    bool indexed_start_found = false;
    bool index_well_formed = false;
    if (!event_records) {
      const std::string index_path = pairedIndexPath(path);
      File index = index_path.empty()
                       ? File{}
                       : SD.open(index_path.c_str(), FILE_READ);
      index_well_formed = static_cast<bool>(index);
      std::size_t indexed_records = 0U;
      while (index_well_formed && index && index.available() > 0) {
        const String raw = index.readStringUntil('\n');
        unsigned long long sequence = 0U;
        unsigned long long timestamp = 0U;
        unsigned long long offset = 0U;
        unsigned checksum = 0U;
        if (std::sscanf(raw.c_str(), "%llu,%llu,%llu,%x", &sequence,
                        &timestamp, &offset, &checksum) != 4) {
          index_well_formed = false;
          break;
        }
        ++indexed_records;
        if (sequence > query.after_sequence && sequence <= scan_ceiling) {
          indexed_start_offset = static_cast<std::uint64_t>(offset);
          indexed_start_found = true;
          break;
        }
        if (sequence > scan_ceiling) {
          break;
        }
        if (indexed_records % kCooperativeScanRecords == 0U) {
          vTaskDelay(pdMS_TO_TICKS(1));
        }
      }
      if (index) {
        index.close();
      }
      // A well-formed index with no sequence in the requested window proves
      // that this segment cannot contribute. If the index is absent or
      // malformed, preserve the conservative full-record scan.
      if (index_well_formed && indexed_records > 0U &&
          !indexed_start_found) {
        PM_LOG_TRACE("STORAGE", "HISTORY_SEGMENT_SKIPPED",
                     "kind=readings after=%llu scan_ceiling=%llu "
                     "reason=index_range_empty",
                     static_cast<unsigned long long>(query.after_sequence),
                     static_cast<unsigned long long>(scan_ceiling));
        continue;
      }
    }
    File file = SD.open(path.c_str(), FILE_READ);
    if (!file) {
      ++health_.read_failures;
      continue;
    }
    if (indexed_start_found &&
        !file.seek(static_cast<std::uint32_t>(indexed_start_offset))) {
      ++health_.read_failures;
      page.error_code = "storage_index_seek_failed";
      file.close();
      return page;
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
  health_.free_percent =
      health_.capacity_bytes == 0U
          ? 0U
          : static_cast<std::uint8_t>(std::min<std::uint64_t>(
                100U, health_.free_bytes * 100U / health_.capacity_bytes));
  health_.storage_full = health_.capacity_bytes != 0U && health_.free_bytes == 0U;
  const StoragePressureState pressure =
      health_.prepared_for_removal
          ? StoragePressureState::PreparedForRemoval
          : (!health_.mounted
                 ? StoragePressureState::Failed
                 : classifyStoragePressure(health_.capacity_bytes,
                                           health_.free_bytes,
                                           active_policy_));
  health_.pressure_state = storagePressureStateName(pressure);
  health_.pressure_reason =
      pressure == StoragePressureState::Healthy
          ? "capacity_available"
          : (pressure == StoragePressureState::PreparedForRemoval
                 ? "operator_prepared_card_removal"
                 : "free_capacity_threshold_crossed");
  growth_estimator_.observe(health_.used_bytes, millis());
  health_.growth_bytes_per_day = growth_estimator_.bytesPerDay();
  health_.estimated_days_remaining = growth_estimator_.estimatedDaysRemaining(
      health_.free_bytes, active_policy_.emergency_reserve_bytes);
}

bool SdStorage::lock(const TickType_t timeout) const {
  return mutex_ != nullptr &&
         xSemaphoreTakeRecursive(mutex_, timeout) == pdTRUE;
}

void SdStorage::unlock() const { xSemaphoreGiveRecursive(mutex_); }

} // namespace pm
