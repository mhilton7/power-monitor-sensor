#include "diagnostics/SerialLogger.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include <Arduino.h>
#include <ArduinoJson.h>
#include <esp_attr.h>
#include <esp_timer.h>

#include "app/TaskConfig.h"

namespace pm {
namespace diag {
namespace {

constexpr std::uint32_t kCrashMagic = 0x504D4447U;

struct CrashMetadata {
  std::uint32_t magic{0};
  std::uint32_t boot_count{0};
  std::uint32_t abnormal_resets{0};
  char last_subsystem[16]{};
  char last_event[40]{};
};

RTC_DATA_ATTR CrashMetadata crash_metadata;

void copyText(char *output, const std::size_t size, const char *value) {
  if (output == nullptr || size == 0)
    return;
  std::snprintf(output, size, "%s", value == nullptr ? "" : value);
}

bool abnormalReset(const int reason) {
  return reason == 4 || reason == 5 || reason == 6 || reason == 7 ||
         reason == 9;
}

bool validRequestId(const char *request_id) {
  if (request_id == nullptr || std::strlen(request_id) != 16U) {
    return false;
  }
  for (std::size_t index = 0; index < 16U; ++index) {
    const char value = request_id[index];
    if (!((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'))) {
      return false;
    }
  }
  return true;
}

} // namespace

SerialLogger &SerialLogger::instance() {
  static SerialLogger logger;
  return logger;
}

bool SerialLogger::begin(const LogLevel level) {
  setLevel(level);
  if (queue_ != nullptr)
    return true;
  queue_ = xQueueCreate(32, sizeof(Message));
  history_mutex_ = xSemaphoreCreateMutex();
  dump_mutex_ = xSemaphoreCreateMutex();
  rate_mutex_ = xSemaphoreCreateMutex();
  output_mutex_ = xSemaphoreCreateMutex();
  if (queue_ == nullptr || history_mutex_ == nullptr ||
      dump_mutex_ == nullptr || rate_mutex_ == nullptr ||
      output_mutex_ == nullptr) {
    return false;
  }
  return xTaskCreatePinnedToCore(taskEntry, "DiagLogTask",
                                 task_config::kDiagnosticLoggerStackBytes, this,
                                 tskIDLE_PRIORITY + 1, &task_, 0) == pdPASS;
}

void SerialLogger::setLevel(const LogLevel level) {
  level_.store(static_cast<std::uint8_t>(level), std::memory_order_release);
}

LogLevel SerialLogger::level() const {
  return static_cast<LogLevel>(level_.load(std::memory_order_acquire));
}

bool SerialLogger::enabled(const LogLevel level) const {
  return shouldLog(
      static_cast<LogLevel>(level_.load(std::memory_order_relaxed)), level);
}

void SerialLogger::log(const LogLevel level, const char *subsystem,
                       const char *event, const char *format, ...) {
  va_list arguments;
  va_start(arguments, format);
  enqueue(level, subsystem, event, 0, format, arguments);
  va_end(arguments);
}

void SerialLogger::logNumeric(const LogLevel level, const char *subsystem,
                              const char *event,
                              const std::int32_t numeric_code,
                              const char *format, ...) {
  va_list arguments;
  va_start(arguments, format);
  enqueue(level, subsystem, event, numeric_code, format, arguments);
  va_end(arguments);
}

bool SerialLogger::writeSetupReady(const char *ssid) {
  if (ssid == nullptr || std::strncmp(ssid, "PowerMonitor-Setup-", 19U) != 0 ||
      std::strlen(ssid) > 40U) {
    return false;
  }
  for (const char *cursor = ssid; *cursor != '\0'; ++cursor) {
    const char value = *cursor;
    if (!((value >= '0' && value <= '9') || (value >= 'A' && value <= 'Z') ||
          (value >= 'a' && value <= 'z') || value == '-')) {
      return false;
    }
  }
  char detail[192]{};
  std::snprintf(detail, sizeof(detail),
                "ssid=\"%s\" authentication=wpa2 credential_output=disabled "
                "action=run_Set-SensorSetupPassword.ps1_over_physical_usb",
                ssid);
  return writeControlLine("SETUP_AP_READY", detail);
}

bool SerialLogger::writeSetupPasswordResult(const char *request_id,
                                            const bool applied) {
  if (!validRequestId(request_id)) {
    return false;
  }
  char detail[192]{};
  std::snprintf(detail, sizeof(detail),
                applied ? "request_id=%s persisted=true readback_verified=true "
                          "ap_restart=scheduled secret_logged=false"
                        : "request_id=%s persisted=false secret_logged=false "
                          "requirement=12_to_63_printable_non_whitespace",
                request_id);
  return writeControlLine(applied ? "SETUP_AP_PASSWORD_APPLIED"
                                  : "SETUP_AP_PASSWORD_REJECTED",
                          detail);
}

#if PM_PHYSICAL_ADMIN_RECOVERY
bool SerialLogger::writeAdminPasswordRecoveryReady(
    const char *request_id, const std::uint32_t window_ms) {
  if (!validRequestId(request_id)) {
    return false;
  }
  char detail[192]{};
  std::snprintf(detail, sizeof(detail),
                "request_id=%s window_ms=%lu transport=physical_usb "
                "secret_requested=false",
                request_id, static_cast<unsigned long>(window_ms));
  return writeControlLine("ADMIN_PASSWORD_RECOVERY_READY", detail);
}

bool SerialLogger::writeAdminPasswordRecoveryResult(
    const char *request_id, const bool applied,
    const bool configuration_preserved) {
  if (!validRequestId(request_id)) {
    return false;
  }
  char detail[224]{};
  if (applied) {
    std::snprintf(
        detail, sizeof(detail),
        "request_id=%s persisted=true readback_verified=true "
        "configuration_preserved=true production_restore_required=true "
        "secret_logged=false",
        request_id);
  } else {
    std::snprintf(detail, sizeof(detail),
                  "request_id=%s persisted=false configuration_preserved=%s "
                  "secret_logged=false "
                  "requirement=12_to_63_printable_non_whitespace",
                  request_id, configuration_preserved ? "true" : "unverified");
  }
  return writeControlLine(applied ? "ADMIN_PASSWORD_RECOVERY_APPLIED"
                                  : "ADMIN_PASSWORD_RECOVERY_REJECTED",
                          detail);
}
#endif

bool SerialLogger::writeControlLine(const char *event, const char *detail) {
  if (output_mutex_ == nullptr || event == nullptr || detail == nullptr) {
    return false;
  }
  char line[512]{};
  formatLine(line, sizeof(line),
             static_cast<std::uint64_t>(esp_timer_get_time()) / 1000U,
             LogLevel::Info, "CONTROL", event, detail);
  for (std::uint8_t attempt = 0; attempt < 3U; ++attempt) {
    if (xSemaphoreTake(output_mutex_, pdMS_TO_TICKS(100)) == pdTRUE) {
      const bool written = Serial.println(line) > 0U;
      xSemaphoreGive(output_mutex_);
      std::fill(line, line + sizeof(line), '\0');
      return written;
    }
    vTaskDelay(pdMS_TO_TICKS(10));
  }
  std::fill(line, line + sizeof(line), '\0');
  return false;
}

void SerialLogger::enqueue(const LogLevel level, const char *subsystem,
                           const char *event, const std::int32_t numeric_code,
                           const char *format, va_list arguments) {
  if (!enabled(level))
    return;
  char unredacted[384]{};
  if (format != nullptr) {
    std::vsnprintf(unredacted, sizeof(unredacted), format, arguments);
  }
  Message message;
  message.monotonic_ms =
      static_cast<std::uint64_t>(esp_timer_get_time()) / 1000U;
  message.level = level;
  message.numeric_code = numeric_code;
  copyText(message.subsystem, sizeof(message.subsystem), subsystem);
  copyText(message.event, sizeof(message.event), event);
  redactSensitiveAssignments(unredacted, message.detail,
                             sizeof(message.detail));

  copyText(crash_metadata.last_subsystem, sizeof(crash_metadata.last_subsystem),
           message.subsystem);
  copyText(crash_metadata.last_event, sizeof(crash_metadata.last_event),
           message.event);

  if (queue_ == nullptr || xQueueSend(queue_, &message, 0) != pdTRUE) {
    dropped_.fetch_add(1, std::memory_order_relaxed);
  }
}

bool SerialLogger::allow(const char *key, const std::uint32_t interval_ms) {
  if (rate_mutex_ == nullptr || xSemaphoreTake(rate_mutex_, 0) != pdTRUE) {
    return false;
  }
  const bool allowed = rate_limiter_.allow(
      key, static_cast<std::uint64_t>(esp_timer_get_time()) / 1000U,
      interval_ms);
  xSemaphoreGive(rate_mutex_);
  return allowed;
}

void SerialLogger::taskEntry(void *context) {
  static_cast<SerialLogger *>(context)->taskLoop();
}

void SerialLogger::taskLoop() {
  Message message;
  for (;;) {
    if (xQueueReceive(queue_, &message, pdMS_TO_TICKS(1000)) != pdTRUE) {
      continue;
    }
    char line[512]{};
    formatLine(line, sizeof(line), message.monotonic_ms, message.level,
               message.subsystem, message.event, message.detail);
    if (output_mutex_ != nullptr &&
        xSemaphoreTake(output_mutex_, pdMS_TO_TICKS(100)) == pdTRUE) {
      Serial.println(line);
      xSemaphoreGive(output_mutex_);
    } else {
      dropped_.fetch_add(1, std::memory_order_relaxed);
    }
    if (static_cast<std::uint8_t>(message.level) >=
        static_cast<std::uint8_t>(LogLevel::Warn)) {
      remember(message);
    }
  }
}

void SerialLogger::remember(const Message &message) {
  if (history_mutex_ == nullptr ||
      xSemaphoreTake(history_mutex_, pdMS_TO_TICKS(10)) != pdTRUE) {
    return;
  }
  ErrorRecord record;
  record.monotonic_ms = message.monotonic_ms;
  record.level = message.level;
  record.numeric_code = message.numeric_code;
  copyText(record.subsystem.data(), record.subsystem.size(), message.subsystem);
  copyText(record.event.data(), record.event.size(), message.event);
  copyText(record.detail.data(), record.detail.size(), message.detail);
  history_.push(record);
  xSemaphoreGive(history_mutex_);
}

void SerialLogger::dumpRecentErrors() {
  if (dump_mutex_ == nullptr ||
      xSemaphoreTake(dump_mutex_, pdMS_TO_TICKS(50)) != pdTRUE) {
    PM_LOG_WARN("SYSTEM", "ERROR_DUMP_BUSY",
                "error=PM-TASK-002 dump=already_in_progress");
    return;
  }
  if (history_mutex_ == nullptr ||
      xSemaphoreTake(history_mutex_, pdMS_TO_TICKS(50)) != pdTRUE) {
    xSemaphoreGive(dump_mutex_);
    PM_LOG_WARN("SYSTEM", "ERROR_HISTORY_BUSY",
                "error=PM-TASK-002 history=unavailable");
    return;
  }
  const std::size_t count = history_.size();
  for (std::size_t index = 0; index < count; ++index) {
    dump_snapshot_[index] = history_.at(index);
  }
  xSemaphoreGive(history_mutex_);
  for (std::size_t index = 0; index < count; ++index) {
    const ErrorRecord &record = dump_snapshot_[index];
    char line[512]{};
    formatLine(line, sizeof(line), record.monotonic_ms, record.level,
               record.subsystem.data(), record.event.data(),
               record.detail.data());
    if (output_mutex_ != nullptr &&
        xSemaphoreTake(output_mutex_, pdMS_TO_TICKS(100)) == pdTRUE) {
      Serial.println(line);
      xSemaphoreGive(output_mutex_);
    } else {
      dropped_.fetch_add(1, std::memory_order_relaxed);
    }
  }
  xSemaphoreGive(dump_mutex_);
}

std::string SerialLogger::recentErrorsJson() const {
  if (history_mutex_ == nullptr ||
      xSemaphoreTake(history_mutex_, pdMS_TO_TICKS(50)) != pdTRUE) {
    return "[]";
  }
  JsonDocument document;
  JsonArray records = document.to<JsonArray>();
  for (std::size_t index = 0; index < history_.size(); ++index) {
    const ErrorRecord record = history_.at(index);
    JsonObject item = records.add<JsonObject>();
    item["monotonic_ms"] = record.monotonic_ms;
    item["level"] = levelName(record.level);
    item["subsystem"] = record.subsystem.data();
    item["event"] = record.event.data();
    item["numeric_code"] = record.numeric_code;
    item["detail"] = record.detail.data();
  }
  std::string output;
  serializeJson(document, output);
  xSemaphoreGive(history_mutex_);
  return output;
}

std::uint32_t SerialLogger::dropped() const {
  return dropped_.load(std::memory_order_relaxed);
}

void SerialLogger::initializeBoot(const int reset_reason) {
  if (crash_metadata.magic != kCrashMagic) {
    crash_metadata = {};
    crash_metadata.magic = kCrashMagic;
  }
  ++crash_metadata.boot_count;
  if (abnormalReset(reset_reason)) {
    ++crash_metadata.abnormal_resets;
  } else if (reset_reason == 1) {
    crash_metadata.abnormal_resets = 0;
  }
}

void SerialLogger::markBootHealthy() { crash_metadata.abnormal_resets = 0; }

std::uint32_t SerialLogger::bootCount() const {
  return crash_metadata.boot_count;
}

std::uint32_t SerialLogger::abnormalResetCount() const {
  return crash_metadata.abnormal_resets;
}

const char *SerialLogger::previousSubsystem() const {
  return crash_metadata.last_subsystem[0] == '\0'
             ? "unknown"
             : crash_metadata.last_subsystem;
}

const char *SerialLogger::previousEvent() const {
  return crash_metadata.last_event[0] == '\0' ? "unknown"
                                              : crash_metadata.last_event;
}

} // namespace diag
} // namespace pm
