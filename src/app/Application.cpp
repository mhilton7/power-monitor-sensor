#include "app/Application.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <new>

#include <Arduino.h>
#include <ESP.h>
#include <WiFi.h>
#include <esp_chip_info.h>
#include <esp_heap_caps.h>
#include <esp_sleep.h>
#include <esp_system.h>
#include <esp_task_wdt.h>

#include "board_pins.h"
#include "build_config.h"
#include "diagnostics/DiagnosticCore.h"
#include "diagnostics/SerialLogger.h"
#include "meter/PzemMeter.h"
#include "meter/SimulatedMeter.h"
#include "version.h"

namespace pm {
namespace {

void registerWatchdog() {
  esp_task_wdt_add(nullptr);
}

void feedWatchdog() {
  esp_task_wdt_reset();
}

bool takeSemaphoreWithWatchdog(const SemaphoreHandle_t semaphore,
                               const std::uint32_t timeout_ms) {
  const TickType_t timeout_ticks = pdMS_TO_TICKS(timeout_ms);
  const TickType_t maximum_slice = pdMS_TO_TICKS(500);
  TickType_t waited = 0;
  while (waited < timeout_ticks) {
    const TickType_t slice =
        std::min(maximum_slice, static_cast<TickType_t>(timeout_ticks - waited));
    if (xSemaphoreTake(semaphore, slice) == pdTRUE) {
      return true;
    }
    waited += slice;
    feedWatchdog();
  }
  return false;
}

void delayUntilWithWatchdog(TickType_t* const previous_wake,
                            const TickType_t interval) {
  const TickType_t maximum_slice = pdMS_TO_TICKS(1000);
  TickType_t remaining = interval;
  while (remaining > 0) {
    const TickType_t slice = std::min(maximum_slice, remaining);
    vTaskDelayUntil(previous_wake, slice);
    remaining -= slice;
    feedWatchdog();
  }
}

void warnLowStack(const TaskHandle_t task, const char* name) {
  if (task == nullptr) return;
  const UBaseType_t high_water = uxTaskGetStackHighWaterMark(task);
  if (high_water >= 512U) return;
  char key[48]{};
  std::snprintf(key, sizeof(key), "low_stack_%s", name);
  if (diag::SerialLogger::instance().allow(key, 60'000U)) {
    PM_LOG_WARN("TASK", "LOW_STACK",
                "error=PM-TASK-002 task=%s high_water_words=%u threshold_words=512",
                name, static_cast<unsigned>(high_water));
  }
}

}  // namespace

Application::Application()
    : network_(config_, clock_),
      storage_coordinator_(storage_, diagnostics_),
      ota_(config_) {}

bool Application::begin() {
  Serial.begin(pins::SERIAL_BAUD);
  const std::uint64_t serial_wait_started = millis();
  while (!Serial && millis() - serial_wait_started < 1500U) {
    delay(10);
  }
  auto& logger = diag::SerialLogger::instance();
  if (!logger.begin()) {
    Serial.println("[000000000][FATAL][LOGGER   ][LOGGER_INIT_FAILED] error=PM-TASK-001");
    return false;
  }
  const int reset_reason = static_cast<int>(esp_reset_reason());
  const std::string previous_subsystem = logger.previousSubsystem();
  const std::string previous_event = logger.previousEvent();
  logger.initializeBoot(reset_reason);
  esp_chip_info_t chip{};
  esp_chip_info(&chip);
  char mac[18]{};
  const std::uint64_t efuse_mac = ESP.getEfuseMac();
  std::snprintf(
      mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
      static_cast<unsigned>((efuse_mac >> 40U) & 0xffU),
      static_cast<unsigned>((efuse_mac >> 32U) & 0xffU),
      static_cast<unsigned>((efuse_mac >> 24U) & 0xffU),
      static_cast<unsigned>((efuse_mac >> 16U) & 0xffU),
      static_cast<unsigned>((efuse_mac >> 8U) & 0xffU),
      static_cast<unsigned>(efuse_mac & 0xffU));
  PM_LOG_INFO(
      "BOOT", "BOOT_START",
      "product=%s firmware=%s protocol=%s build=%s build_timestamp=%s git_commit=%s boot_count=%lu",
      build::PRODUCT_NAME, version::FIRMWARE, version::PROTOCOL,
      PM_RELEASE_BUILD ? "release" : "diagnostic",
      version::BUILD_TIMESTAMP, version::GIT_COMMIT,
      static_cast<unsigned long>(logger.bootCount()));
  PM_LOG_INFO(
      "BOOT", "RESET_CAUSE",
      "reason=%s numeric=%d abnormal_count=%lu previous_subsystem=%s previous_event=%s",
      diag::resetReasonName(reset_reason), reset_reason,
      static_cast<unsigned long>(logger.abnormalResetCount()),
      previous_subsystem.c_str(), previous_event.c_str());
  PM_LOG_INFO(
      "BOOT", "WAKEUP_CAUSE",
      "reason=%s numeric=%d",
      diag::wakeupReasonName(
          static_cast<int>(esp_sleep_get_wakeup_cause())),
      static_cast<int>(esp_sleep_get_wakeup_cause()));
  if (logger.abnormalResetCount() >= 3U) {
    PM_LOG_FATAL(
        "BOOT", "REBOOT_LOOP_DETECTED",
        "error=PM-BOOT-001 abnormal_resets=%lu configuration_erased=false safe_mode=preserved",
        static_cast<unsigned long>(logger.abnormalResetCount()));
  }
  PM_LOG_INFO(
      "BOOT", "HARDWARE",
      "model=%s revision=%u cores=%u cpu_mhz=%u flash_bytes=%lu flash_mode=%u psram_detected=%s psram_bytes=%lu mac=%s",
      ESP.getChipModel(), static_cast<unsigned>(chip.revision),
      static_cast<unsigned>(chip.cores), ESP.getCpuFreqMHz(),
      static_cast<unsigned long>(ESP.getFlashChipSize()),
      static_cast<unsigned>(ESP.getFlashChipMode()),
      ESP.getPsramSize() > 0 ? "true" : "false",
      static_cast<unsigned long>(ESP.getPsramSize()),
      diag::maskMac(mac).c_str());
  PM_LOG_INFO(
      "MEMORY", "BOOT_MEMORY",
      "heap_free=%lu heap_min=%lu heap_largest=%lu psram_free=%lu sketch_bytes=%lu sketch_free=%lu",
      static_cast<unsigned long>(ESP.getFreeHeap()),
      static_cast<unsigned long>(ESP.getMinFreeHeap()),
      static_cast<unsigned long>(
          heap_caps_get_largest_free_block(MALLOC_CAP_8BIT)),
      static_cast<unsigned long>(ESP.getFreePsram()),
      static_cast<unsigned long>(ESP.getSketchSize()),
      static_cast<unsigned long>(ESP.getFreeSketchSpace()));
  PM_LOG_INFO("BOOT", "SAFETY_SCOPE",
              "monitoring_only=true switching=false billing=false");
  if (!config_.begin()) {
    PM_LOG_FATAL("CONFIG", "CONFIG_INIT_FAILED",
                 "error=PM-CONFIG-001 storage=nvs");
    return false;
  }
  logger.setLevel(
      static_cast<diag::LogLevel>(config_.config().diagnostic_log_level));
  PM_LOG_INFO(
      "CONFIG", "CONFIG_LOADED",
      "version=%lu friendly_name=%s hostname=%s wifi_ssid=%s server_configured=%s mode=%s log_level=%s safe_mode=%s",
      static_cast<unsigned long>(config_.config().config_version),
      config_.config().friendly_name.c_str(), config_.config().hostname.c_str(),
      diag::maskSsid(config_.config().wifi_ssid).c_str(),
      config_.config().server_url.empty() ? "false" : "true",
      connectionModeName(config_.config().connection_mode),
      diag::levelName(logger.level()), config_.safeMode() ? "true" : "false");
  PM_LOG_INFO(
      "CONFIG", "CATEGORY_SUMMARY",
      "wifi_ssid=%s wifi_password=%s server_url=%s https_required=true ca_certificate=%s fingerprint_legacy=%s enrollment=%s device_id=%s device_credentials=%s administrator=%s timezone=%s micro_sd=required pzem=valid",
      config_.config().wifi_ssid.empty() ? "missing" : "present",
      config_.hasWifiCredentials() ? "present" : "missing",
      config_.config().server_url.empty() ? "missing" : "present",
      config_.config().server_ca_pem.empty() ? "missing" : "present",
      config_.config().server_fingerprint.empty() ? "not_configured"
                                                   : "configured_unusable",
      config_.identity().enrolled ? "completed" : "not_completed",
      config_.identity().device_id.empty() ? "missing" : "present",
      config_.identity().enrolled ? "present" : "missing",
      config_.hasAdminPassword() ? "configured" : "not_configured",
      config_.config().timezone.empty() ? "missing" : "configured");
  config_.recordBootStarted();
  clock_.begin();
  clock_.update();
  const bool storage_started = storage_.begin(config_.config().sd_spi_hz);
  if (!storage_coordinator_.begin()) {
    PM_LOG_FATAL("STORAGE", "QUEUE_INIT_FAILED",
                 "error=PM-STORAGE-001 depth=%u",
                 static_cast<unsigned>(build::STORAGE_QUEUE_DEPTH));
    return false;
  }
#if PM_SIMULATED_METER
  meter_ = std::unique_ptr<IMeter>(new (std::nothrow) SimulatedMeter());
#else
  meter_ = std::unique_ptr<IMeter>(new (std::nothrow) PzemMeter(
      pzem_serial_, config_.config().pzem_timeout_ms, 2));
#endif
  const bool meter_started = meter_ != nullptr && meter_->begin();
  if (!meter_started) {
    PM_LOG_ERROR("PZEM", "METER_INIT_DEGRADED",
                 "error=PM-PZEM-001 recovery_api=true");
  }
  const bool network_started = network_.begin();
  if (!network_started) {
    PM_LOG_ERROR("WIFI", "NETWORK_INIT_DEGRADED",
                 "error=PM-WIFI-001 local_recovery=true");
  }
  sample_queue_ = xQueueCreate(8, sizeof(MeasurementSnapshot));
  maintenance_queue_ = xQueueCreate(build::ACTION_QUEUE_DEPTH,
                                    sizeof(MaintenanceMessage));
  meter_mutex_ = xSemaphoreCreateMutex();
  if (sample_queue_ == nullptr || maintenance_queue_ == nullptr ||
      meter_mutex_ == nullptr) {
    PM_LOG_FATAL("TASK", "RUNTIME_PRIMITIVE_FAILED",
                 "error=PM-TASK-001 sample_queue=%s action_queue=%s meter_mutex=%s",
                 sample_queue_ == nullptr ? "failed" : "ready",
                 maintenance_queue_ == nullptr ? "failed" : "ready",
                 meter_mutex_ == nullptr ? "failed" : "ready");
    return false;
  }
  sync_ = std::unique_ptr<ServerSync>(new (std::nothrow) ServerSync(
      config_, network_, clock_, storage_, diagnostics_, *meter_));
  http_ = std::unique_ptr<HttpApi>(new (std::nothrow) HttpApi(
      config_, network_, clock_, storage_, storage_coordinator_, diagnostics_,
      *meter_, ota_, maintenance_queue_));
  if (sync_ == nullptr || http_ == nullptr || !createTasks()) {
    PM_LOG_FATAL("TASK", "RUNTIME_START_FAILED",
                 "error=PM-TASK-001 sync=%s http=%s",
                 sync_ == nullptr ? "failed" : "ready",
                 http_ == nullptr ? "failed" : "ready");
    return false;
  }
  http_->begin();
  if (ota_.runningImagePendingVerification()) {
    const std::uint64_t deadline = millis() + 8000U;
    while (millis() < deadline &&
           (meter_progress_.load() == 0 || aggregation_progress_.load() == 0 ||
            network_progress_.load() == 0 || sync_progress_.load() == 0)) {
      delay(25);
    }
    const bool post_boot_healthy =
        storage_started && storage_.health().writable && meter_started &&
        network_started && meter_progress_.load() != 0 &&
        aggregation_progress_.load() != 0 && network_progress_.load() != 0 &&
        sync_progress_.load() != 0;
    if (!ota_.checkRunningImage(post_boot_healthy)) {
      PM_LOG_FATAL("OTA", "POST_BOOT_VALIDATION_FAILED",
                   "error=PM-OTA-006 rollback=automatic");
      delay(250);
      ESP.restart();
      return false;
    }
  } else if (!ota_.checkRunningImage(true)) {
    PM_LOG_WARN("OTA", "PARTITION_STATE_UNAVAILABLE",
                "error=PM-OTA-007");
  }
  config_.recordBootHealthy();
  logger.markBootHealthy();
  storage_coordinator_.enqueueEvent(
      "EVT_BOOT_COMPLETE", "info",
      config_.safeMode() ? "Booted into safe mode." : "Runtime services started.",
      clock_.utcMs(), config_.identity().boot_id);
  PM_LOG_INFO(
      "BOOT", "STARTUP_COMPLETE",
      "storage=%s meter=%s network=%s http=ready safe_mode=%s free_heap=%lu",
      storage_started ? "ready" : "degraded",
      meter_started ? "ready" : "degraded",
      network_started ? "ready" : "degraded",
      config_.safeMode() ? "true" : "false",
      static_cast<unsigned long>(ESP.getFreeHeap()));
  return true;
}

void Application::meterTaskEntry(void* context) {
  static_cast<Application*>(context)->meterTask();
}

void Application::aggregationTaskEntry(void* context) {
  static_cast<Application*>(context)->aggregationTask();
}

void Application::storageTaskEntry(void* context) {
  static_cast<Application*>(context)->storage_coordinator_.taskLoop();
}

void Application::networkTaskEntry(void* context) {
  static_cast<Application*>(context)->networkTask();
}

void Application::syncTaskEntry(void* context) {
  static_cast<Application*>(context)->syncTask();
}

void Application::healthTaskEntry(void* context) {
  static_cast<Application*>(context)->healthTask();
}

void Application::maintenanceTaskEntry(void* context) {
  static_cast<Application*>(context)->maintenanceTask();
}

void Application::serialCommandTaskEntry(void* context) {
  static_cast<Application*>(context)->serialCommandTask();
}

void Application::meterTask() {
  registerWatchdog();
  PM_LOG_INFO("TASK", "TASK_STARTED",
              "name=MeterTask core=%d priority=%u stack_words=%u watchdog=true",
              xPortGetCoreID(), static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
              6144U);
  TickType_t last_wake = xTaskGetTickCount();
  for (;;) {
    MeasurementSnapshot sample;
    if (takeSemaphoreWithWatchdog(meter_mutex_, 5000)) {
      sample = meter_->poll(clock_.utcMs(), clock_.monotonicMs(),
                            clock_.synchronized(), feedWatchdog);
      xSemaphoreGive(meter_mutex_);
    } else {
      sample.monotonic_ms = clock_.monotonicMs();
      sample.error = MeterError::UartFailure;
      sample.quality_flags = MeterGap;
    }
    Limits limits;
    limits.ct_rating_a = config_.config().ct_rating_a;
    limits.ct_warning_fraction = config_.config().ct_warning_fraction;
    limits.ct_critical_fraction = config_.config().ct_critical_fraction;
    limits.ct_fault_fraction = config_.config().ct_fault_fraction;
    limits.minimum_voltage_v = config_.config().voltage_minimum_v;
    limits.maximum_voltage_v = config_.config().voltage_maximum_v;
    limits.minimum_frequency_hz = config_.config().frequency_minimum_hz;
    limits.maximum_frequency_hz = config_.config().frequency_maximum_hz;
    if (sample.error == MeterError::None) {
      validateMeasurement(sample, limits);
      sample.device_lifetime_energy_wh =
          config_.energyOffsetWh() + sample.raw_energy_wh;
    }
    diagnostics_.setLatest(sample);
    if (xQueueSend(sample_queue_, &sample, 0) != pdTRUE) {
      ++sample_dropped_;
      if (diag::SerialLogger::instance().allow("sample_queue_full", 30'000U)) {
        PM_LOG_WARN("QUEUE", "SAMPLE_QUEUE_FULL",
                    "error=PM-QUEUE-001 dropped=%llu depth=%u",
                    static_cast<unsigned long long>(sample_dropped_),
                    static_cast<unsigned>(uxQueueMessagesWaiting(sample_queue_)));
      }
    }
    ++meter_progress_;
    feedWatchdog();
    delayUntilWithWatchdog(
        &last_wake,
        pdMS_TO_TICKS(config_.config().sample_interval_seconds * 1000U));
  }
}

void Application::aggregationTask() {
  registerWatchdog();
  PM_LOG_INFO(
      "TASK", "TASK_STARTED",
      "name=AggregationTask core=%d priority=%u stack_words=%u watchdog=true",
      xPortGetCoreID(), static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
      8192U);
  Limits limits;
  limits.ct_rating_a = config_.config().ct_rating_a;
  limits.ct_warning_fraction = config_.config().ct_warning_fraction;
  limits.ct_critical_fraction = config_.config().ct_critical_fraction;
  limits.ct_fault_fraction = config_.config().ct_fault_fraction;
  limits.minimum_voltage_v = config_.config().voltage_minimum_v;
  limits.maximum_voltage_v = config_.config().voltage_maximum_v;
  limits.minimum_frequency_hz = config_.config().frequency_minimum_hz;
  limits.maximum_frequency_hz = config_.config().frequency_maximum_hz;
  IntervalAggregator aggregator(limits);
  EnergyNormalizer energy(config_.energyOffsetWh());
  bool started = false;
  std::uint64_t interval_started_ms = 0;
  MeasurementSnapshot sample;
  for (;;) {
    if (xQueueReceive(sample_queue_, &sample, pdMS_TO_TICKS(1000)) == pdTRUE) {
      limits.ct_rating_a = config_.config().ct_rating_a;
      limits.ct_warning_fraction = config_.config().ct_warning_fraction;
      limits.ct_critical_fraction = config_.config().ct_critical_fraction;
      limits.ct_fault_fraction = config_.config().ct_fault_fraction;
      limits.minimum_voltage_v = config_.config().voltage_minimum_v;
      limits.maximum_voltage_v = config_.config().voltage_maximum_v;
      limits.minimum_frequency_hz = config_.config().frequency_minimum_hz;
      limits.maximum_frequency_hz = config_.config().frequency_maximum_hz;
      aggregator.setLimits(limits);
      if (!started) {
        aggregator.reset(sample.utc_ms, sample.monotonic_ms);
        interval_started_ms = sample.monotonic_ms;
        started = true;
      }
      aggregator.add(sample);
      const std::uint64_t interval_ms =
          static_cast<std::uint64_t>(config_.config().durable_log_interval_seconds) * 1000U;
      if (sample.monotonic_ms - interval_started_ms >= interval_ms &&
          aggregator.hasSamples()) {
        IntervalRecord record = aggregator.finish(
            config_.identity().device_id.empty() ? config_.identity().local_instance_id
                                                  : config_.identity().device_id,
            config_.config().friendly_name, config_.identity().boot_id,
            version::FIRMWARE, sample.utc_ms, sample.monotonic_ms, energy);
        if (!storage_coordinator_.enqueueRecord(record)) {
          ++sample_dropped_;
        }
        config_.setEnergyOffsetWh(energy.offsetWh());
        aggregator.reset(sample.utc_ms, sample.monotonic_ms);
        interval_started_ms = sample.monotonic_ms;
      }
      ++aggregation_progress_;
    }
    feedWatchdog();
  }
}

void Application::networkTask() {
  registerWatchdog();
  PM_LOG_INFO("TASK", "TASK_STARTED",
              "name=NetworkTask core=%d priority=%u stack_words=%u watchdog=true",
              xPortGetCoreID(), static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
              6144U);
  for (;;) {
    network_.update();
    ++network_progress_;
    feedWatchdog();
    vTaskDelay(pdMS_TO_TICKS(250));
  }
}

void Application::syncTask() {
  // TLS connect/read operations have their own bounded timeouts that can
  // legitimately exceed the framework's five-second task watchdog.
  PM_LOG_INFO(
      "TASK", "TASK_STARTED",
      "name=ServerSyncTask core=%d priority=%u stack_words=%u watchdog=false",
      xPortGetCoreID(), static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
      12288U);
  for (;;) {
    sync_->tick();
    ++sync_progress_;
    vTaskDelay(pdMS_TO_TICKS(250));
  }
}

void Application::healthTask() {
  // Hourly retention can scan a large on-card history. It is bounded by the
  // stored files, but it is not a five-second operation.
  PM_LOG_INFO("TASK", "TASK_STARTED",
              "name=HealthTask core=%d priority=%u stack_words=%u watchdog=false",
              xPortGetCoreID(), static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
              6144U);
  std::uint64_t last_retention_ms = 0;
  std::uint64_t last_health_ms = 0;
  for (;;) {
    diagnostics_.setQueueDepths(
        storage_coordinator_.depth(), uxQueueMessagesWaiting(maintenance_queue_),
        storage_coordinator_.dropped() + sample_dropped_, action_dropped_);
    const std::uint64_t now = clock_.monotonicMs();
    const auto requested_level = static_cast<diag::LogLevel>(
        config_.config().diagnostic_log_level);
    if (diag::SerialLogger::instance().level() != requested_level) {
      diag::SerialLogger::instance().setLevel(requested_level);
      PM_LOG_INFO("LOGGER", "LOG_LEVEL_APPLIED", "level=%s source=config",
                  diag::levelName(requested_level));
    }
    if (last_health_ms == 0 || now - last_health_ms >= 60'000U) {
      const NetworkStatus network = network_.status();
      const StorageHealth storage = storage_.health();
      const MeterMetrics meter = meter_->metrics();
      const QueueMetrics queues = diagnostics_.queueMetrics();
      PM_LOG_INFO(
          "HEALTH", "PERIODIC_SUMMARY",
          "uptime_s=%llu wifi=%s rssi_dbm=%ld time_trusted=%s storage=%s sd_free=%llu meter_error=%s meter_consecutive=%lu sync_reachable=%s storage_queue=%lu action_queue=%lu dropped_logs=%lu heap_free=%lu heap_min=%lu",
          static_cast<unsigned long long>(now / 1000U),
          network.station_connected ? "connected" : "offline",
          static_cast<long>(network.rssi_dbm),
          clock_.synchronized() ? "true" : "false",
          storage.writable ? "writable" : "degraded",
          static_cast<unsigned long long>(storage.free_bytes),
          meterErrorCode(meter.last_error),
          static_cast<unsigned long>(meter.consecutive_errors),
          network.server_reachable ? "true" : "false",
          static_cast<unsigned long>(queues.storage_depth),
          static_cast<unsigned long>(queues.action_depth),
          static_cast<unsigned long>(
              diag::SerialLogger::instance().dropped()),
          static_cast<unsigned long>(ESP.getFreeHeap()),
          static_cast<unsigned long>(ESP.getMinFreeHeap()));
      warnLowStack(meter_task_, "MeterTask");
      warnLowStack(aggregation_task_, "AggregationTask");
      warnLowStack(storage_task_, "StorageTask");
      warnLowStack(network_task_, "NetworkTask");
      warnLowStack(sync_task_, "ServerSyncTask");
      warnLowStack(health_task_, "HealthTask");
      warnLowStack(maintenance_task_, "OtaMaintenanceTask");
      warnLowStack(serial_command_task_, "SerialCommandTask");
      last_health_ms = now;
    }
    if (ESP.getFreeHeap() < 32'768U &&
        diag::SerialLogger::instance().allow("low_heap", 30'000U)) {
      PM_LOG_WARN(
          "MEMORY", "LOW_HEAP",
          "error=PM-MEM-001 free_bytes=%lu minimum_bytes=%lu largest_block=%lu threshold_bytes=32768",
          static_cast<unsigned long>(ESP.getFreeHeap()),
          static_cast<unsigned long>(ESP.getMinFreeHeap()),
          static_cast<unsigned long>(
              heap_caps_get_largest_free_block(MALLOC_CAP_8BIT)));
    }
    if (!config_.safeMode() && config_.config().retention_enabled &&
        clock_.synchronized() &&
        (last_retention_ms == 0 || now - last_retention_ms >= 3'600'000U)) {
      storage_.applyRetention(config_.serverAckSequence(), clock_.utcMs(),
                              config_.config().retention_days);
      last_retention_ms = now;
    }
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}

void Application::maintenanceTask() {
  // Signed OTA downloads and explicit index rebuilds are bounded maintenance
  // operations that can run longer than the task watchdog interval.
  PM_LOG_INFO(
      "TASK", "TASK_STARTED",
      "name=OtaMaintenanceTask core=%d priority=%u stack_words=%u watchdog=false",
      xPortGetCoreID(), static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
      12288U);
  MaintenanceMessage message;
  for (;;) {
    if (xQueueReceive(maintenance_queue_, &message, pdMS_TO_TICKS(1000)) == pdTRUE) {
      executeMaintenance(message);
    }
  }
}

void Application::serialCommandTask() {
  PM_LOG_INFO(
      "TASK", "TASK_STARTED",
      "name=SerialCommandTask core=%d priority=%u stack_words=%u watchdog=false",
      xPortGetCoreID(), static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
      4096U);
  PM_LOG_INFO("COMMAND", "CONSOLE_READY",
              "prompt=pm> type=help line_limit=95");
  std::string line;
  line.reserve(96);
  bool overflow = false;
  for (;;) {
    while (Serial.available() > 0) {
      const int next = Serial.read();
      if (next < 0) break;
      const char character = static_cast<char>(next);
      if (character == '\r' || character == '\n') {
        if (overflow) {
          PM_LOG_WARN("COMMAND", "COMMAND_TOO_LONG",
                      "error=PM-COMMAND-001 maximum_bytes=95");
        } else if (!line.empty()) {
          handleSerialCommand(line);
        }
        line.clear();
        overflow = false;
      } else if (!overflow && character >= 0x20 && character <= 0x7e) {
        if (line.size() < 95U) {
          line.push_back(character);
        } else {
          overflow = true;
        }
      }
    }
    vTaskDelay(pdMS_TO_TICKS(25));
  }
}

void Application::handleSerialCommand(const std::string& command) {
  std::string normalized = command;
  normalized.erase(
      normalized.begin(),
      std::find_if(normalized.begin(), normalized.end(),
                   [](const unsigned char value) { return !std::isspace(value); }));
  normalized.erase(
      std::find_if(normalized.rbegin(), normalized.rend(),
                   [](const unsigned char value) { return !std::isspace(value); })
          .base(),
      normalized.end());
  std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                 [](const unsigned char value) {
                   return static_cast<char>(std::tolower(value));
                 });
  PM_LOG_DEBUG("COMMAND", "COMMAND_RECEIVED", "command=%s",
               normalized.rfind("loglevel ", 0) == 0 ? "loglevel <value>"
                                                     : normalized.c_str());
  if (normalized == "help") {
    PM_LOG_INFO(
        "COMMAND", "HELP",
        "commands=help,status,wifi,network,time,tls,server,tasks,memory,sd,pzem,errors,loglevel_<trace|debug|info|warn|error|fatal>,reconnect");
  } else if (normalized == "status") {
    reportStatus();
  } else if (normalized == "wifi" || normalized == "network") {
    if (normalized == "wifi") network_.requestScan();
    const NetworkStatus state = network_.status();
    PM_LOG_INFO(
        "COMMAND", normalized == "wifi" ? "WIFI_REPORT" : "NETWORK_REPORT",
        "station=%s setup_ap=%s ssid=%s rssi_dbm=%ld ip=%s subnet=%s gateway=%s dns=%s hostname=%s reconnects=%lu mdns=%s",
        state.station_connected ? "connected" : "offline",
        state.setup_ap_active ? "active" : "inactive",
        diag::maskSsid(config_.config().wifi_ssid).c_str(),
        static_cast<long>(state.rssi_dbm),
        state.ip_address.empty() ? "unassigned" : state.ip_address.c_str(),
        state.subnet.empty() ? "unassigned" : state.subnet.c_str(),
        state.gateway.empty() ? "unassigned" : state.gateway.c_str(),
        state.dns.empty() ? "unassigned" : state.dns.c_str(),
        state.hostname.c_str(),
        static_cast<unsigned long>(state.reconnect_count),
        state.mdns_active ? "active" : "inactive");
  } else if (normalized == "time") {
    PM_LOG_INFO(
        "COMMAND", "TIME_REPORT",
        "trusted=%s utc=%s monotonic_ms=%llu last_trusted_utc_ms=%llu",
        clock_.synchronized() ? "true" : "false",
        clock_.synchronized() ? clock_.utcIso8601().c_str() : "unavailable",
        static_cast<unsigned long long>(clock_.monotonicMs()),
        static_cast<unsigned long long>(clock_.lastTrustedUtcMs()));
  } else if (normalized == "tls") {
    PM_LOG_INFO(
        "COMMAND", "TLS_REPORT",
        "server_configured=%s ca_configured=%s fingerprint_configured=%s time_trusted=%s validation=required insecure_mode=false",
        config_.config().server_url.empty() ? "false" : "true",
        config_.config().server_ca_pem.empty() ? "false" : "true",
        config_.config().server_fingerprint.empty() ? "false" : "true",
        clock_.synchronized() ? "true" : "false");
  } else if (normalized == "server") {
    const NetworkStatus state = network_.status();
    const SyncMetrics metrics = diagnostics_.syncMetrics();
    PM_LOG_INFO(
        "COMMAND", "SERVER_REPORT",
        "configured=%s reachable=%s authenticated=%s heartbeat_ok=%llu heartbeat_failed=%llu batch_ok=%llu batch_failed=%llu last_error=%s",
        config_.config().server_url.empty() ? "false" : "true",
        state.server_reachable ? "true" : "false",
        state.server_authenticated ? "true" : "false",
        static_cast<unsigned long long>(metrics.heartbeat_successes),
        static_cast<unsigned long long>(metrics.heartbeat_failures),
        static_cast<unsigned long long>(metrics.batch_successes),
        static_cast<unsigned long long>(metrics.batch_failures),
        metrics.last_error.empty() ? "none" : metrics.last_error.c_str());
  } else if (normalized == "tasks") {
    reportTasks();
  } else if (normalized == "memory") {
    reportMemory();
  } else if (normalized == "sd") {
    const StorageHealth state = storage_.health();
    PM_LOG_INFO(
        "COMMAND", "SD_REPORT",
        "present=%s mounted=%s writable=%s prepared=%s filesystem=%s spi_hz=%lu capacity=%llu used=%llu free=%llu writes=%llu write_failures=%llu reads=%llu read_failures=%llu repairs=%lu last_error=%s",
        state.present ? "true" : "false", state.mounted ? "true" : "false",
        state.writable ? "true" : "false",
        state.prepared_for_removal ? "true" : "false",
        state.filesystem.c_str(), static_cast<unsigned long>(state.spi_hz),
        static_cast<unsigned long long>(state.capacity_bytes),
        static_cast<unsigned long long>(state.used_bytes),
        static_cast<unsigned long long>(state.free_bytes),
        static_cast<unsigned long long>(state.writes),
        static_cast<unsigned long long>(state.write_failures),
        static_cast<unsigned long long>(state.reads),
        static_cast<unsigned long long>(state.read_failures),
        static_cast<unsigned long>(state.repair_count),
        state.last_error.empty() ? "none" : state.last_error.c_str());
  } else if (normalized == "pzem") {
    const MeterMetrics state = meter_->metrics();
    PM_LOG_INFO(
        "COMMAND", "PZEM_REPORT",
        "method=%s requests=%llu successes=%llu timeouts=%llu crc_errors=%llu invalid_frames=%llu consecutive_errors=%lu last_error=%s last_latency_ms=%lu",
        meter_->methodName(), static_cast<unsigned long long>(state.requests),
        static_cast<unsigned long long>(state.successes),
        static_cast<unsigned long long>(state.timeouts),
        static_cast<unsigned long long>(state.crc_errors),
        static_cast<unsigned long long>(state.invalid_frames),
        static_cast<unsigned long>(state.consecutive_errors),
        meterErrorCode(state.last_error),
        static_cast<unsigned long>(state.last_latency_ms));
  } else if (normalized == "errors") {
    diag::SerialLogger::instance().dumpRecentErrors();
  } else if (normalized == "reconnect") {
    network_.requestConfigurationApply(0);
    PM_LOG_INFO("COMMAND", "RECONNECT_REQUESTED",
                "credentials_erased=false network_reset=false");
  } else if (normalized.rfind("loglevel ", 0) == 0) {
    diag::LogLevel requested;
    const std::string value = normalized.substr(9);
    if (!diag::parseLogLevel(value.c_str(), requested)) {
      PM_LOG_WARN("COMMAND", "LOG_LEVEL_REJECTED",
                  "error=PM-COMMAND-002 accepted=trace,debug,info,warn,error,fatal");
    } else if (!config_.setDiagnosticLogLevel(
                   static_cast<std::uint8_t>(requested))) {
      PM_LOG_ERROR("CONFIG", "LOG_LEVEL_SAVE_FAILED",
                   "error=PM-CONFIG-002 requested=%s",
                   diag::levelName(requested));
    } else {
      diag::SerialLogger::instance().setLevel(requested);
      PM_LOG_INFO("LOGGER", "LOG_LEVEL_CHANGED",
                  "level=%s persisted=true source=serial",
                  diag::levelName(requested));
    }
  } else {
    PM_LOG_WARN("COMMAND", "UNKNOWN_COMMAND",
                "error=PM-COMMAND-003 command=%s hint=type_help",
                normalized.c_str());
  }
}

void Application::reportStatus() const {
  const NetworkStatus network = network_.status();
  const StorageHealth storage = storage_.health();
  const MeterMetrics meter = meter_->metrics();
  const QueueMetrics queues = diagnostics_.queueMetrics();
  PM_LOG_INFO(
      "COMMAND", "STATUS_REPORT",
      "firmware=%s protocol=%s uptime_s=%llu safe_mode=%s enrolled=%s wifi=%s time_trusted=%s storage=%s meter=%s server=%s storage_queue=%lu action_queue=%lu",
      version::FIRMWARE, version::PROTOCOL,
      static_cast<unsigned long long>(clock_.monotonicMs() / 1000U),
      config_.safeMode() ? "true" : "false",
      config_.identity().enrolled ? "true" : "false",
      network.station_connected ? "connected" : "offline",
      clock_.synchronized() ? "true" : "false",
      storage.writable ? "writable" : "degraded",
      meterErrorCode(meter.last_error),
      network.server_reachable ? "reachable" : "offline",
      static_cast<unsigned long>(queues.storage_depth),
      static_cast<unsigned long>(queues.action_depth));
}

void Application::reportTasks() const {
  struct TaskReport {
    const char* name;
    TaskHandle_t handle;
    std::uint32_t configured_stack_words;
    bool watchdog;
  };
  const std::array<TaskReport, 9> tasks{{
      {"DiagLogTask", xTaskGetHandle("DiagLogTask"), 4096, false},
      {"MeterTask", meter_task_, 6144, true},
      {"AggregationTask", aggregation_task_, 8192, true},
      {"StorageTask", storage_task_, 8192, false},
      {"NetworkTask", network_task_, 6144, true},
      {"ServerSyncTask", sync_task_, 12288, false},
      {"HealthTask", health_task_, 6144, false},
      {"OtaMaintenanceTask", maintenance_task_, 12288, false},
      {"SerialCommandTask", serial_command_task_, 4096, false},
  }};
  for (const auto& task : tasks) {
    PM_LOG_INFO(
        "TASK", "TASK_REPORT",
        "name=%s running=%s priority=%u stack_words=%lu high_water_words=%u watchdog=%s",
        task.name, task.handle == nullptr ? "false" : "true",
        task.handle == nullptr
            ? 0U
            : static_cast<unsigned>(uxTaskPriorityGet(task.handle)),
        static_cast<unsigned long>(task.configured_stack_words),
        task.handle == nullptr
            ? 0U
            : static_cast<unsigned>(uxTaskGetStackHighWaterMark(task.handle)),
        task.watchdog ? "true" : "false");
  }
}

void Application::reportMemory() const {
  const std::uint32_t heap_free = ESP.getFreeHeap();
  const std::uint32_t heap_largest =
      heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
  const std::uint32_t fragmentation =
      heap_free == 0
          ? 0
          : 100U - static_cast<std::uint32_t>(
                       (static_cast<std::uint64_t>(heap_largest) * 100U) /
                       heap_free);
  PM_LOG_INFO(
      "MEMORY", "MEMORY_REPORT",
      "heap_total=%lu heap_free=%lu heap_min=%lu heap_largest=%lu fragmentation_percent=%lu psram_total=%lu psram_free=%lu",
      static_cast<unsigned long>(ESP.getHeapSize()),
      static_cast<unsigned long>(heap_free),
      static_cast<unsigned long>(ESP.getMinFreeHeap()),
      static_cast<unsigned long>(heap_largest),
      static_cast<unsigned long>(fragmentation),
      static_cast<unsigned long>(ESP.getPsramSize()),
      static_cast<unsigned long>(ESP.getFreePsram()));
}

void Application::executeMaintenance(const MaintenanceMessage& message) {
  bool ok = false;
  const char* code = "EVT_MAINTENANCE_COMPLETE";
  const std::uint64_t started_ms = clock_.monotonicMs();
  PM_LOG_INFO("MAINTENANCE", "ACTION_BEGIN",
              "action=%u argument=redacted heap_free=%lu",
              static_cast<unsigned>(message.action),
              static_cast<unsigned long>(ESP.getFreeHeap()));
  switch (message.action) {
    case MaintenanceAction::TestPzem:
      if (xSemaphoreTake(meter_mutex_, pdMS_TO_TICKS(5000)) == pdTRUE) {
        ok = meter_->poll(clock_.utcMs(), clock_.monotonicMs(),
                          clock_.synchronized())
                 .error == MeterError::None;
        xSemaphoreGive(meter_mutex_);
      }
      break;
    case MaintenanceAction::TestSd:
      ok = storage_.selfTest();
      break;
    case MaintenanceAction::RemountSd:
      ok = storage_.remount(config_.config().sd_spi_hz);
      break;
    case MaintenanceAction::RebuildIndex:
      ok = storage_.rebuildIndexes();
      break;
    case MaintenanceAction::PrepareCardRemoval:
      ok = storage_.prepareRemoval();
      break;
    case MaintenanceAction::TestDns: {
      IPAddress address;
      ok = WiFi.hostByName("pool.ntp.org", address) == 1;
      break;
    }
    case MaintenanceAction::TestNtp:
      ok = clock_.synchronized();
      break;
    case MaintenanceAction::TestServerTls:
    case MaintenanceAction::TestHeartbeat:
      sync_->requestImmediateSync();
      ok = true;
      break;
    case MaintenanceAction::Reboot:
      storage_coordinator_.enqueueEvent("EVT_REBOOT_REQUESTED", "warning",
                                        "Authorized local reboot requested.",
                                        clock_.utcMs(), config_.identity().boot_id);
      // AsyncWebServer queues the setup response before this maintenance
      // message is consumed. Leave enough time for TCP to transmit it so the
      // browser can show the network-transition instructions.
      delay(1000);
      ESP.restart();
      return;
    case MaintenanceAction::NetworkReset:
      ok = config_.networkReset();
      if (ok) {
        delay(250);
        ESP.restart();
      }
      break;
    case MaintenanceAction::FactoryReset:
      ok = config_.factoryReset();
      if (ok) {
        delay(250);
        ESP.restart();
      }
      break;
    case MaintenanceAction::ApplyOta:
      ota_.applyFromManifestUrl(message.argument);
      return;
    case MaintenanceAction::RollbackOta:
      ota_.rollbackAndReboot();
      return;
  }
  storage_coordinator_.enqueueEvent(
      ok ? code : "EVT_MAINTENANCE_FAILED", ok ? "info" : "error",
      ok ? "Authorized maintenance action completed."
         : "Authorized maintenance action failed; inspect diagnostics.",
      clock_.utcMs(), config_.identity().boot_id);
  PM_LOG_INFO(
      "MAINTENANCE", "ACTION_COMPLETE",
      "action=%u result=%s duration_ms=%llu heap_free=%lu",
      static_cast<unsigned>(message.action), ok ? "success" : "failed",
      static_cast<unsigned long long>(clock_.monotonicMs() - started_ms),
      static_cast<unsigned long>(ESP.getFreeHeap()));
}

bool Application::createTasks() {
  BaseType_t ok = pdPASS;
  ok &= xTaskCreatePinnedToCore(meterTaskEntry, "MeterTask", 6144, this, 4,
                                &meter_task_, 1);
  ok &= xTaskCreatePinnedToCore(aggregationTaskEntry, "AggregationTask", 8192,
                                this, 3, &aggregation_task_, 1);
  ok &= xTaskCreatePinnedToCore(storageTaskEntry, "StorageTask", 8192, this, 3,
                                &storage_task_, 1);
  ok &= xTaskCreatePinnedToCore(networkTaskEntry, "NetworkTask", 6144, this, 2,
                                &network_task_, 0);
  ok &= xTaskCreatePinnedToCore(syncTaskEntry, "ServerSyncTask", 12288, this, 2,
                                &sync_task_, 0);
  ok &= xTaskCreatePinnedToCore(healthTaskEntry, "HealthTask", 6144, this, 1,
                                &health_task_, 0);
  ok &= xTaskCreatePinnedToCore(maintenanceTaskEntry, "OtaMaintenanceTask",
                                12288, this, 2, &maintenance_task_, 0);
  ok &= xTaskCreatePinnedToCore(serialCommandTaskEntry, "SerialCommandTask",
                                4096, this, 1, &serial_command_task_, 0);
  const bool created = ok == pdPASS;
  PM_LOG_INFO("TASK", "TASK_SET_CREATED",
              "result=%s count=8 sample_queue_capacity=8 action_queue_capacity=%u",
              created ? "success" : "failed",
              static_cast<unsigned>(build::ACTION_QUEUE_DEPTH));
  return created;
}

}  // namespace pm
