#pragma once

#include <atomic>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <string>

#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <freertos/task.h>

#include "diagnostics/DiagnosticCore.h"

#ifndef PM_SERIAL_LOG_LEVEL
#define PM_SERIAL_LOG_LEVEL 2
#endif

#ifndef PM_SERIAL_TRACE_ENABLED
#define PM_SERIAL_TRACE_ENABLED 0
#endif

namespace pm {
namespace diag {

class SerialLogger {
 public:
  static SerialLogger& instance();

  bool begin(LogLevel level =
                 static_cast<LogLevel>(PM_SERIAL_LOG_LEVEL));
  void setLevel(LogLevel level);
  LogLevel level() const;
  bool enabled(LogLevel level) const;
  void log(LogLevel level, const char* subsystem, const char* event,
           const char* format, ...) __attribute__((format(printf, 5, 6)));
  void logNumeric(LogLevel level, const char* subsystem, const char* event,
                  std::int32_t numeric_code, const char* format, ...)
      __attribute__((format(printf, 6, 7)));
  bool allow(const char* key, std::uint32_t interval_ms);
  void dumpRecentErrors();
  std::string recentErrorsJson() const;
  std::uint32_t dropped() const;
  std::uint32_t bootCount() const;
  std::uint32_t abnormalResetCount() const;
  const char* previousSubsystem() const;
  const char* previousEvent() const;
  void initializeBoot(int reset_reason);
  void markBootHealthy();

 private:
  struct Message {
    std::uint64_t monotonic_ms{0};
    LogLevel level{LogLevel::Info};
    std::int32_t numeric_code{0};
    char subsystem[16]{};
    char event[40]{};
    char detail[384]{};
  };

  static void taskEntry(void* context);
  void taskLoop();
  void enqueue(LogLevel level, const char* subsystem, const char* event,
               std::int32_t numeric_code, const char* format, va_list arguments);
  void remember(const Message& message);

  QueueHandle_t queue_{nullptr};
  SemaphoreHandle_t history_mutex_{nullptr};
  SemaphoreHandle_t rate_mutex_{nullptr};
  TaskHandle_t task_{nullptr};
  ErrorRing<32> history_;
  RateLimiter rate_limiter_;
  std::atomic<std::uint8_t> level_{
      static_cast<std::uint8_t>(PM_SERIAL_LOG_LEVEL)};
  std::atomic<std::uint32_t> dropped_{0};
};

}  // namespace diag
}  // namespace pm

#if PM_SERIAL_TRACE_ENABLED
#define PM_LOG_TRACE(subsystem, event, format, ...)                         \
  ::pm::diag::SerialLogger::instance().log(                                 \
      ::pm::diag::LogLevel::Trace, subsystem, event, format, ##__VA_ARGS__)
#else
#define PM_LOG_TRACE(subsystem, event, format, ...) \
  do {                                               \
  } while (false)
#endif

#define PM_LOG_DEBUG(subsystem, event, format, ...)                         \
  ::pm::diag::SerialLogger::instance().log(                                 \
      ::pm::diag::LogLevel::Debug, subsystem, event, format, ##__VA_ARGS__)
#define PM_LOG_INFO(subsystem, event, format, ...)                          \
  ::pm::diag::SerialLogger::instance().log(                                 \
      ::pm::diag::LogLevel::Info, subsystem, event, format, ##__VA_ARGS__)
#define PM_LOG_WARN(subsystem, event, format, ...)                          \
  ::pm::diag::SerialLogger::instance().log(                                 \
      ::pm::diag::LogLevel::Warn, subsystem, event, format, ##__VA_ARGS__)
#define PM_LOG_ERROR(subsystem, event, format, ...)                         \
  ::pm::diag::SerialLogger::instance().log(                                 \
      ::pm::diag::LogLevel::Error, subsystem, event, format, ##__VA_ARGS__)
#define PM_LOG_FATAL(subsystem, event, format, ...)                         \
  ::pm::diag::SerialLogger::instance().log(                                 \
      ::pm::diag::LogLevel::Fatal, subsystem, event, format, ##__VA_ARGS__)

#define PM_LOG_ERROR_CODE(subsystem, event, numeric, format, ...)           \
  ::pm::diag::SerialLogger::instance().logNumeric(                          \
      ::pm::diag::LogLevel::Error, subsystem, event, numeric, format,       \
      ##__VA_ARGS__)
