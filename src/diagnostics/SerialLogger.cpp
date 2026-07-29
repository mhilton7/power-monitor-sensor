#include "diagnostics/SerialLogger.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include <Arduino.h>
#include <ArduinoJson.h>
#include <esp_attr.h>
#include <esp_timer.h>

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

void copyText(char* output, const std::size_t size, const char* value) {
  if (output == nullptr || size == 0) return;
  std::snprintf(output, size, "%s", value == nullptr ? "" : value);
}

bool abnormalReset(const int reason) {
  return reason == 4 || reason == 5 || reason == 6 || reason == 7 ||
         reason == 9;
}

}  // namespace

SerialLogger& SerialLogger::instance() {
  static SerialLogger logger;
  return logger;
}

bool SerialLogger::begin(const LogLevel level) {
  setLevel(level);
  if (queue_ != nullptr) return true;
  queue_ = xQueueCreate(32, sizeof(Message));
  history_mutex_ = xSemaphoreCreateMutex();
  rate_mutex_ = xSemaphoreCreateMutex();
  if (queue_ == nullptr || history_mutex_ == nullptr ||
      rate_mutex_ == nullptr) {
    return false;
  }
  return xTaskCreatePinnedToCore(taskEntry, "DiagLogTask", 4096, this,
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

void SerialLogger::log(const LogLevel level, const char* subsystem,
                       const char* event, const char* format, ...) {
  va_list arguments;
  va_start(arguments, format);
  enqueue(level, subsystem, event, 0, format, arguments);
  va_end(arguments);
}

void SerialLogger::logNumeric(const LogLevel level, const char* subsystem,
                              const char* event,
                              const std::int32_t numeric_code,
                              const char* format, ...) {
  va_list arguments;
  va_start(arguments, format);
  enqueue(level, subsystem, event, numeric_code, format, arguments);
  va_end(arguments);
}

void SerialLogger::enqueue(const LogLevel level, const char* subsystem,
                           const char* event,
                           const std::int32_t numeric_code,
                           const char* format, va_list arguments) {
  if (!enabled(level)) return;
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

  copyText(crash_metadata.last_subsystem,
           sizeof(crash_metadata.last_subsystem), message.subsystem);
  copyText(crash_metadata.last_event, sizeof(crash_metadata.last_event),
           message.event);

  if (queue_ == nullptr || xQueueSend(queue_, &message, 0) != pdTRUE) {
    dropped_.fetch_add(1, std::memory_order_relaxed);
  }
}

bool SerialLogger::allow(const char* key, const std::uint32_t interval_ms) {
  if (rate_mutex_ == nullptr ||
      xSemaphoreTake(rate_mutex_, 0) != pdTRUE) {
    return false;
  }
  const bool allowed = rate_limiter_.allow(
      key, static_cast<std::uint64_t>(esp_timer_get_time()) / 1000U,
      interval_ms);
  xSemaphoreGive(rate_mutex_);
  return allowed;
}

void SerialLogger::taskEntry(void* context) {
  static_cast<SerialLogger*>(context)->taskLoop();
}

void SerialLogger::taskLoop() {
  Message message;
  for (;;) {
    if (xQueueReceive(queue_, &message, portMAX_DELAY) != pdTRUE) continue;
    char line[512]{};
    formatLine(line, sizeof(line), message.monotonic_ms, message.level,
               message.subsystem, message.event, message.detail);
    Serial.println(line);
    if (static_cast<std::uint8_t>(message.level) >=
        static_cast<std::uint8_t>(LogLevel::Warn)) {
      remember(message);
    }
  }
}

void SerialLogger::remember(const Message& message) {
  if (history_mutex_ == nullptr ||
      xSemaphoreTake(history_mutex_, pdMS_TO_TICKS(10)) != pdTRUE) {
    return;
  }
  ErrorRecord record;
  record.monotonic_ms = message.monotonic_ms;
  record.level = message.level;
  record.numeric_code = message.numeric_code;
  copyText(record.subsystem.data(), record.subsystem.size(),
           message.subsystem);
  copyText(record.event.data(), record.event.size(), message.event);
  copyText(record.detail.data(), record.detail.size(), message.detail);
  history_.push(record);
  xSemaphoreGive(history_mutex_);
}

void SerialLogger::dumpRecentErrors() {
  if (history_mutex_ == nullptr ||
      xSemaphoreTake(history_mutex_, pdMS_TO_TICKS(50)) != pdTRUE) {
    PM_LOG_WARN("SYSTEM", "ERROR_HISTORY_BUSY",
                "error=PM-TASK-002 history=unavailable");
    return;
  }
  const std::size_t count = history_.size();
  for (std::size_t index = 0; index < count; ++index) {
    const ErrorRecord record = history_.at(index);
    char line[512]{};
    formatLine(line, sizeof(line), record.monotonic_ms, record.level,
               record.subsystem.data(), record.event.data(),
               record.detail.data());
    Serial.println(line);
  }
  xSemaphoreGive(history_mutex_);
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

const char* SerialLogger::previousSubsystem() const {
  return crash_metadata.last_subsystem[0] == '\0'
             ? "unknown"
             : crash_metadata.last_subsystem;
}

const char* SerialLogger::previousEvent() const {
  return crash_metadata.last_event[0] == '\0' ? "unknown"
                                               : crash_metadata.last_event;
}

}  // namespace diag
}  // namespace pm
