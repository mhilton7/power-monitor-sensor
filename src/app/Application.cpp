#include "app/Application.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <new>

#include <Arduino.h>
#include <ESP.h>
#include <ESPmDNS.h>
#include <WiFi.h>
#include <esp_chip_info.h>
#include <esp_heap_caps.h>
#include <esp_sleep.h>
#include <esp_system.h>
#include <esp_task_wdt.h>
#include <esp_timer.h>
#include <mbedtls/platform_util.h>

#include "app/TaskConfig.h"
#include "board_pins.h"
#include "build_config.h"
#include "core/MemoryPressurePolicy.h"
#include "diagnostics/DiagnosticCore.h"
#include "diagnostics/SerialLogger.h"
#include "meter/PzemMeter.h"
#include "meter/SimulatedMeter.h"
#include "version.h"

namespace pm {
namespace {

void registerWatchdog() { esp_task_wdt_add(nullptr); }

void feedWatchdog() { esp_task_wdt_reset(); }

bool takeSemaphoreWithWatchdog(const SemaphoreHandle_t semaphore,
                               const std::uint32_t timeout_ms) {
  const TickType_t timeout_ticks = pdMS_TO_TICKS(timeout_ms);
  const TickType_t maximum_slice = pdMS_TO_TICKS(500);
  TickType_t waited = 0;
  while (waited < timeout_ticks) {
    const TickType_t slice = std::min(
        maximum_slice, static_cast<TickType_t>(timeout_ticks - waited));
    if (xSemaphoreTake(semaphore, slice) == pdTRUE) {
      return true;
    }
    waited += slice;
    feedWatchdog();
  }
  return false;
}

void delayUntilWithWatchdog(TickType_t *const previous_wake,
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

void warnLowStack(const TaskHandle_t task, const char *name,
                  const std::uint32_t allocated_bytes) {
  if (task == nullptr)
    return;
  // ESP-IDF's FreeRTOS port reports this value in bytes, unlike vanilla
  // FreeRTOS. See freertos/task.h in the pinned framework.
  const std::uint32_t high_water_bytes =
      static_cast<std::uint32_t>(uxTaskGetStackHighWaterMark(task));
  const std::uint32_t margin_percent =
      allocated_bytes == 0U ? 0U
                            : static_cast<std::uint32_t>(
                                  (static_cast<std::uint64_t>(std::min(
                                       allocated_bytes, high_water_bytes)) *
                                   100U) /
                                  allocated_bytes);
  if (margin_percent >= task_config::kMinimumStackMarginPercent)
    return;
  char key[48]{};
  std::snprintf(key, sizeof(key), "low_stack_%s", name);
  if (diag::SerialLogger::instance().allow(key, 60'000U)) {
    PM_LOG_WARN(
        "TASK", "STACK_LOW",
        "error=PM-TASK-002 task=%s allocated_bytes=%lu "
        "high_water_bytes=%lu margin_percent=%lu threshold_percent=%lu",
        name, static_cast<unsigned long>(allocated_bytes),
        static_cast<unsigned long>(high_water_bytes),
        static_cast<unsigned long>(margin_percent),
        static_cast<unsigned long>(task_config::kMinimumStackMarginPercent));
  }
}

void wipeString(std::string &value) {
  if (!value.empty()) {
    mbedtls_platform_zeroize(value.data(), value.size());
  }
  value.clear();
}

#if PM_PHYSICAL_ADMIN_RECOVERY
std::uint64_t recoveryMonotonicMs() {
  return static_cast<std::uint64_t>(esp_timer_get_time()) / 1000U;
}
#endif

std::string httpsHost(const std::string &url) {
  if (url.rfind("https://", 0) != 0)
    return {};
  const std::size_t start = 8;
  const std::size_t end = url.find_first_of("/?#", start);
  const std::string authority = url.substr(start, end - start);
  if (authority.empty() || authority.find('@') != std::string::npos)
    return {};
  const std::size_t colon = authority.rfind(':');
  return colon == std::string::npos ? authority : authority.substr(0, colon);
}

Limits measurementLimits(const MeasurementRuntimeConfig &config) {
  Limits limits;
  limits.ct_rating_a = config.ct_rating_a;
  limits.ct_warning_fraction = config.ct_warning_fraction;
  limits.ct_critical_fraction = config.ct_critical_fraction;
  limits.ct_fault_fraction = config.ct_fault_fraction;
  limits.minimum_voltage_v = config.voltage_minimum_v;
  limits.maximum_voltage_v = config.voltage_maximum_v;
  limits.minimum_frequency_hz = config.frequency_minimum_hz;
  limits.maximum_frequency_hz = config.frequency_maximum_hz;
  return limits;
}

} // namespace

Application::Application()
    : network_(config_, clock_), storage_coordinator_(storage_, diagnostics_),
      ota_(config_, diagnostics_) {}

bool Application::begin() {
  Serial.begin(pins::SERIAL_BAUD);
  const std::uint64_t serial_wait_started = millis();
  while (!Serial && millis() - serial_wait_started < 1500U) {
    delay(10);
  }
  auto &logger = diag::SerialLogger::instance();
  if (!logger.begin()) {
    Serial.println(
        "[000000000][FATAL][LOGGER   ][LOGGER_INIT_FAILED] error=PM-TASK-001");
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
  std::snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                static_cast<unsigned>((efuse_mac >> 40U) & 0xffU),
                static_cast<unsigned>((efuse_mac >> 32U) & 0xffU),
                static_cast<unsigned>((efuse_mac >> 24U) & 0xffU),
                static_cast<unsigned>((efuse_mac >> 16U) & 0xffU),
                static_cast<unsigned>((efuse_mac >> 8U) & 0xffU),
                static_cast<unsigned>(efuse_mac & 0xffU));
  PM_LOG_INFO("BOOT", "BOOT_START",
              "product=%s firmware=%s protocol=%s build=%s build_timestamp=%s "
              "git_commit=%s boot_count=%lu",
              build::PRODUCT_NAME, version::FIRMWARE, version::PROTOCOL,
              PM_RELEASE_BUILD ? "release" : "diagnostic",
              version::BUILD_TIMESTAMP, version::GIT_COMMIT,
              static_cast<unsigned long>(logger.bootCount()));
  PM_LOG_INFO("BOOT", "RESET_CAUSE",
              "reason=%s numeric=%d abnormal_count=%lu previous_subsystem=%s "
              "previous_event=%s",
              diag::resetReasonName(reset_reason), reset_reason,
              static_cast<unsigned long>(logger.abnormalResetCount()),
              previous_subsystem.c_str(), previous_event.c_str());
  PM_LOG_INFO(
      "BOOT", "WAKEUP_CAUSE", "reason=%s numeric=%d",
      diag::wakeupReasonName(static_cast<int>(esp_sleep_get_wakeup_cause())),
      static_cast<int>(esp_sleep_get_wakeup_cause()));
  if (logger.abnormalResetCount() >= 3U) {
    PM_LOG_FATAL("BOOT", "REBOOT_LOOP_DETECTED",
                 "error=PM-BOOT-001 abnormal_resets=%lu "
                 "configuration_erased=false safe_mode=preserved",
                 static_cast<unsigned long>(logger.abnormalResetCount()));
  }
  PM_LOG_INFO("BOOT", "HARDWARE",
              "model=%s revision=%u cores=%u cpu_mhz=%u flash_bytes=%lu "
              "flash_mode=%u psram_detected=%s psram_bytes=%lu mac=%s",
              ESP.getChipModel(), static_cast<unsigned>(chip.revision),
              static_cast<unsigned>(chip.cores), ESP.getCpuFreqMHz(),
              static_cast<unsigned long>(ESP.getFlashChipSize()),
              static_cast<unsigned>(ESP.getFlashChipMode()),
              ESP.getPsramSize() > 0 ? "true" : "false",
              static_cast<unsigned long>(ESP.getPsramSize()),
              diag::maskMac(mac).c_str());
  PM_LOG_INFO("MEMORY", "BOOT_MEMORY",
              "heap_free=%lu heap_min=%lu heap_largest=%lu psram_free=%lu "
              "sketch_bytes=%lu sketch_free=%lu",
              static_cast<unsigned long>(ESP.getFreeHeap()),
              static_cast<unsigned long>(ESP.getMinFreeHeap()),
              static_cast<unsigned long>(
                  heap_caps_get_largest_free_block(MALLOC_CAP_8BIT)),
              static_cast<unsigned long>(ESP.getFreePsram()),
              static_cast<unsigned long>(ESP.getSketchSize()),
              static_cast<unsigned long>(ESP.getFreeSketchSpace()));
  PM_LOG_INFO("BOOT", "SAFETY_SCOPE",
              "monitoring_only=true switching=false billing=false");
#if PM_PHYSICAL_ADMIN_RECOVERY
  PM_LOG_WARN(
      "SECURITY", "PHYSICAL_ADMIN_RECOVERY_BUILD",
      "temporary_firmware=true transport=physical_usb "
      "restore_esp32_s3_release_after_success=true secrets_output=false");
#endif
  if (!config_.begin()) {
    PM_LOG_FATAL("CONFIG", "CONFIG_INIT_FAILED",
                 "error=PM-CONFIG-001 storage=nvs");
    return false;
  }
  if (!ota_.begin()) {
    PM_LOG_FATAL("OTA", "RECOVERY_INIT_FAILED",
                 "error=PM-OTA-011 configuration_erased=false");
    return false;
  }
  logger.setLevel(
      static_cast<diag::LogLevel>(config_.config().diagnostic_log_level));
  PM_LOG_INFO(
      "CONFIG", "CONFIG_LOADED",
      "version=%lu friendly_name=%s hostname=%s wifi_ssid=%s "
      "server_configured=%s mode=%s log_level=%s safe_mode=%s",
      static_cast<unsigned long>(config_.config().config_version),
      config_.config().friendly_name.c_str(), config_.config().hostname.c_str(),
      diag::maskSsid(config_.config().wifi_ssid).c_str(),
      config_.config().server_url.empty() ? "false" : "true",
      connectionModeName(config_.config().connection_mode),
      diag::levelName(logger.level()), config_.safeMode() ? "true" : "false");
  PM_LOG_INFO("CONFIG", "CATEGORY_SUMMARY",
              "wifi_ssid=%s wifi_psk_state=%s server_url=%s "
              "https_required=true ca_certificate=%s fingerprint_legacy=%s "
              "enrollment=%s device_id=%s enrollment_key_state=%s "
              "administrator=%s timezone=%s micro_sd=required pzem=valid",
              config_.config().wifi_ssid.empty() ? "missing" : "present",
              config_.hasWifiCredentials() ? "present" : "missing",
              config_.config().server_url.empty() ? "missing" : "present",
              config_.config().server_ca_pem.empty() ? "missing" : "present",
              config_.config().server_fingerprint.empty()
                  ? "not_configured"
                  : "configured_unusable",
              config_.identity().enrolled ? "completed" : "not_completed",
              config_.identity().device_id.empty() ? "missing" : "present",
              config_.identity().enrolled ? "present" : "missing",
              config_.hasAdminPassword() ? "configured" : "not_configured",
              config_.config().timezone.empty() ? "missing" : "configured");
#if PM_PHYSICAL_ADMIN_RECOVERY
  const bool recovery_task_started =
      xTaskCreatePinnedToCore(serialCommandTaskEntry, "AdminRecoveryTask", 8192,
                              this, 2, &serial_command_task_, 0) == pdPASS;
  if (!recovery_task_started) {
    PM_LOG_FATAL("SECURITY", "ADMIN_RECOVERY_TASK_FAILED",
                 "error=PM-TASK-001 configuration_erased=false");
    return false;
  }
  PM_LOG_WARN("SECURITY", "ADMIN_RECOVERY_OFFLINE_READY",
              "wifi=disabled http=disabled server_sync=disabled sd=disabled "
              "meter=disabled transport=physical_usb "
              "action=run_Set-SensorAdminPassword.ps1");
  logger.markBootHealthy();
  return true;
#endif
  config_.recordBootStarted();
  clock_.begin();
  clock_.update();
  const DeviceIdentity storage_identity = config_.identity();
  const std::uint64_t required_sequence_floor =
      std::max({config_.serverAckSequence(),
                config_.serverMaximumSeenSequence(),
                config_.preparedRemovalSequence()});
  bool storage_started = storage_.begin(
      config_.config().sd_spi_hz,
      storage_identity.device_id.empty() ? storage_identity.hardware_id
                                         : storage_identity.device_id,
      storage_identity.hardware_id, required_sequence_floor);
  if (!storage_started) {
    // A firmware upload or watchdog reset does not power-cycle the card. The
    // first complete recovery ladder can therefore encounter a card that is
    // still leaving an interrupted SPI transaction. Retry synchronously,
    // before watchdog-supervised runtime tasks exist, so the card cannot enter
    // a slow remount scan on the live measurement path.
    PM_LOG_WARN("STORAGE", "BOOT_MOUNT_RETRY",
                "reason=initial_recovery_failed delay_ms=500 "
                "format_attempted=false");
    delay(500U);
    storage_started = storage_.remountPreferred();
  }
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
  maintenance_queue_ =
      xQueueCreate(build::ACTION_QUEUE_DEPTH, sizeof(MaintenanceMessage));
  meter_mutex_ = xSemaphoreCreateMutex();
  if (sample_queue_ == nullptr || maintenance_queue_ == nullptr ||
      meter_mutex_ == nullptr) {
    PM_LOG_FATAL(
        "TASK", "RUNTIME_PRIMITIVE_FAILED",
        "error=PM-TASK-001 sample_queue=%s action_queue=%s meter_mutex=%s",
        sample_queue_ == nullptr ? "failed" : "ready",
        maintenance_queue_ == nullptr ? "failed" : "ready",
        meter_mutex_ == nullptr ? "failed" : "ready");
    return false;
  }
  sync_ = std::unique_ptr<ServerSync>(
      new (std::nothrow) ServerSync(config_, network_, clock_, storage_,
                                    storage_coordinator_, diagnostics_, *meter_,
                                    maintenance_queue_));
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
    PM_LOG_WARN("OTA", "PARTITION_STATE_UNAVAILABLE", "error=PM-OTA-007");
  }
  config_.recordBootHealthy();
  logger.markBootHealthy();
  storage_coordinator_.enqueueEvent("EVT_BOOT_COMPLETE", "info",
                                    config_.safeMode()
                                        ? "Booted into safe mode."
                                        : "Runtime services started.",
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

void Application::meterTaskEntry(void *context) {
  static_cast<Application *>(context)->meterTask();
}

void Application::aggregationTaskEntry(void *context) {
  static_cast<Application *>(context)->aggregationTask();
}

void Application::storageTaskEntry(void *context) {
  static_cast<Application *>(context)->storage_coordinator_.taskLoop();
}

void Application::networkTaskEntry(void *context) {
  static_cast<Application *>(context)->networkTask();
}

void Application::syncTaskEntry(void *context) {
  static_cast<Application *>(context)->syncTask();
}

void Application::healthTaskEntry(void *context) {
  static_cast<Application *>(context)->healthTask();
}

void Application::maintenanceTaskEntry(void *context) {
  static_cast<Application *>(context)->maintenanceTask();
}

void Application::serialCommandTaskEntry(void *context) {
  static_cast<Application *>(context)->serialCommandTask();
}

void Application::meterTask() {
  registerWatchdog();
  PM_LOG_INFO(
      "TASK", "TASK_STARTED",
      "name=MeterTask core=%d priority=%u stack_bytes=%lu watchdog=true",
      xPortGetCoreID(), static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
      static_cast<unsigned long>(task_config::kMeterStackBytes));
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
    const MeasurementRuntimeConfig measurement_config =
        config_.measurementRuntimeConfig();
    const Limits limits = measurementLimits(measurement_config);
    if (sample.error == MeterError::None) {
      validateMeasurement(sample, limits);
      sample.device_lifetime_energy_wh =
          config_.energyOffsetWh() + sample.raw_energy_wh;
    }
    diagnostics_.setLatest(sample);
    if (xQueueSend(sample_queue_, &sample, 0) != pdTRUE) {
      ++sample_dropped_;
      if (diag::SerialLogger::instance().allow("sample_queue_full", 30'000U)) {
        PM_LOG_WARN(
            "QUEUE", "SAMPLE_QUEUE_FULL",
            "error=PM-QUEUE-001 dropped=%llu depth=%u",
            static_cast<unsigned long long>(sample_dropped_),
            static_cast<unsigned>(uxQueueMessagesWaiting(sample_queue_)));
      }
    }
    ++meter_progress_;
    feedWatchdog();
    delayUntilWithWatchdog(
        &last_wake,
        pdMS_TO_TICKS(measurement_config.sample_interval_seconds * 1000U));
  }
}

void Application::aggregationTask() {
  registerWatchdog();
  PM_LOG_INFO(
      "TASK", "TASK_STARTED",
      "name=AggregationTask core=%d priority=%u stack_bytes=%lu watchdog=true",
      xPortGetCoreID(), static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
      static_cast<unsigned long>(task_config::kAggregationStackBytes));
  Limits limits = measurementLimits(config_.measurementRuntimeConfig());
  IntervalAggregator aggregator(limits);
  EnergyNormalizer energy(config_.energyOffsetWh());
  bool started = false;
  std::uint64_t interval_started_ms = 0;
  MeasurementSnapshot sample;
  for (;;) {
    if (xQueueReceive(sample_queue_, &sample, pdMS_TO_TICKS(1000)) == pdTRUE) {
      const MeasurementRuntimeConfig measurement_config =
          config_.measurementRuntimeConfig();
      limits = measurementLimits(measurement_config);
      aggregator.setLimits(limits);
      if (!started) {
        aggregator.reset(sample.utc_ms, sample.monotonic_ms);
        interval_started_ms = sample.monotonic_ms;
        started = true;
      }
      aggregator.add(sample);
      const std::uint64_t interval_ms =
          static_cast<std::uint64_t>(
              measurement_config.durable_log_interval_seconds) *
          1000U;
      if (sample.monotonic_ms - interval_started_ms >= interval_ms &&
          aggregator.hasSamples()) {
        IntervalRecord record = aggregator.finish(
            config_.identity().device_id.empty()
                ? config_.identity().local_instance_id
                : config_.identity().device_id,
            measurement_config.friendly_name, config_.identity().boot_id,
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
  PM_LOG_INFO(
      "TASK", "TASK_STARTED",
      "name=NetworkTask core=%d priority=%u stack_bytes=%lu watchdog=true",
      xPortGetCoreID(), static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
      static_cast<unsigned long>(task_config::kNetworkStackBytes));
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
      "name=ServerSyncTask core=%d priority=%u stack_bytes=%lu watchdog=false",
      xPortGetCoreID(), static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
      static_cast<unsigned long>(task_config::kServerSyncStackBytes));
  std::uint64_t next_ota_report_ms = 0U;
  for (;;) {
    sync_->tick();
    const std::uint64_t now = clock_.monotonicMs();
    if (ota_.hasPendingReport() && now >= next_ota_report_ms) {
      (void)ota_.flushPendingReport();
      next_ota_report_ms = now + 30'000U;
    }
    ++sync_progress_;
    vTaskDelay(pdMS_TO_TICKS(250));
  }
}

void Application::healthTask() {
  // Hourly retention can scan a large on-card history. It is bounded by the
  // stored files, but it is not a five-second operation.
  PM_LOG_INFO(
      "TASK", "TASK_STARTED",
      "name=HealthTask core=%d priority=%u stack_bytes=%lu watchdog=false",
      xPortGetCoreID(), static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
      static_cast<unsigned long>(task_config::kHealthStackBytes));
  // Mount/recovery already calculates pressure and validates the card. Do not
  // immediately replay a stale one-shot cleanup request or start the hourly
  // full-card retention scan during boot reconciliation. Capacity pressure
  // can still bypass this interval below.
  const MeasurementRuntimeConfig startup_measurement_config =
      config_.measurementRuntimeConfig();
  std::uint64_t last_retention_ms = clock_.monotonicMs();
  last_storage_cleanup_ack_sequence_ = config_.serverAckSequence();
  last_storage_cleanup_request_id_ =
      startup_measurement_config.storage_cleanup_request_id;
  last_storage_prepare_removal_request_id_ =
      startup_measurement_config.storage_prepare_removal_request_id;
  std::uint64_t last_health_ms = 0;
  for (;;) {
    diagnostics_.setQueueDepths(
        storage_coordinator_.depth(),
        uxQueueMessagesWaiting(maintenance_queue_),
        storage_coordinator_.dropped() + sample_dropped_, action_dropped_);
    const std::uint64_t now = clock_.monotonicMs();
    const MeasurementRuntimeConfig measurement_config =
        config_.measurementRuntimeConfig();
    const auto requested_level =
        static_cast<diag::LogLevel>(measurement_config.diagnostic_log_level);
    if (diag::SerialLogger::instance().level() != requested_level) {
      diag::SerialLogger::instance().setLevel(requested_level);
      PM_LOG_INFO("LOGGER", "LOG_LEVEL_APPLIED", "level=%s source=config",
                  diag::levelName(requested_level));
    }
    if (last_health_ms == 0 || now - last_health_ms >= 60'000U) {
      captureTaskDiagnostics();
      const NetworkStatus network = network_.status();
      const StorageHealth storage = storage_.health();
      const MeterMetrics meter = meter_->metrics();
      const QueueMetrics queues = diagnostics_.queueMetrics();
      PM_LOG_INFO(
          "HEALTH", "PERIODIC_SUMMARY",
          "uptime_s=%llu wifi=%s rssi_dbm=%ld time_trusted=%s storage=%s "
          "sd_free=%llu meter_error=%s meter_consecutive=%lu sync_reachable=%s "
          "storage_queue=%lu action_queue=%lu dropped_logs=%lu heap_free=%lu "
          "heap_min=%lu",
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
          static_cast<unsigned long>(diag::SerialLogger::instance().dropped()),
          static_cast<unsigned long>(ESP.getFreeHeap()),
          static_cast<unsigned long>(ESP.getMinFreeHeap()));
      warnLowStack(meter_task_, "MeterTask", task_config::kMeterStackBytes);
      warnLowStack(aggregation_task_, "AggregationTask",
                   task_config::kAggregationStackBytes);
      warnLowStack(storage_task_, "StorageTask",
                   task_config::kStorageStackBytes);
      warnLowStack(network_task_, "NetworkTask",
                   task_config::kNetworkStackBytes);
      warnLowStack(sync_task_, "ServerSyncTask",
                   task_config::kServerSyncStackBytes);
      warnLowStack(health_task_, "HealthTask", task_config::kHealthStackBytes);
      warnLowStack(maintenance_task_, "OtaMaintenanceTask",
                   task_config::kMaintenanceStackBytes);
      warnLowStack(serial_command_task_, "SerialCommandTask",
                   task_config::kSerialCommandStackBytes);
      last_health_ms = now;
    }
    const HeapSnapshot heap = heap_telemetry_.snapshot();
    const std::uint32_t free_internal = heap.free_internal_bytes;
    const std::uint32_t largest_internal =
        heap.largest_internal_block_bytes;
    const MemoryOperationContext operation_context =
        diagnostics_.memoryOperationContext();
    const MemoryPressureUpdate pressure = memory_pressure_.update(
        free_internal, largest_internal, now, operation_context,
        heap.integrity_ok, diagnostics_.lastMemoryOperationCompletedMs());
    diagnostics_.setMemoryPressureMetrics(memory_pressure_.metrics(now));
    if (pressure.changed) {
      const bool constrained =
          pressure.current != MemoryPressureState::Normal;
      PM_LOG_WARN(
          "MEMORY", "MEMORY_PRESSURE_STATE_CHANGED",
          "previous=%s current=%s transitions=%lu free_internal=%lu "
          "largest_internal=%lu operation_context=%s "
          "primary_measurement_preserved=true "
          "heavy_ui_deferred=%s",
          memoryPressureStateName(pressure.previous),
          memoryPressureStateName(pressure.current),
          static_cast<unsigned long>(memory_pressure_.transitions()),
          static_cast<unsigned long>(free_internal),
          static_cast<unsigned long>(largest_internal),
          memoryOperationContextName(operation_context),
          constrained ? "true" : "false");
      const MemoryPressureMetrics memory = memory_pressure_.metrics(now);
      char detail[384]{};
      std::snprintf(
          detail, sizeof(detail),
          "previous=%s current=%s entries=%lu recoveries=%lu "
          "free_internal=%lu largest_internal=%lu sync_in_progress=%s",
          memoryPressureStateName(pressure.previous),
          memoryPressureStateName(pressure.current),
          static_cast<unsigned long>(memory.entry_count),
          static_cast<unsigned long>(memory.recovery_count),
          static_cast<unsigned long>(free_internal),
          static_cast<unsigned long>(largest_internal),
          diagnostics_.syncMetrics().sync_in_progress ? "true" : "false");
      storage_coordinator_.enqueueEvent(
          pressure.current == MemoryPressureState::Normal
              ? "EVT_MEMORY_PRESSURE_RECOVERED"
              : "EVT_MEMORY_PRESSURE_CHANGED",
          pressure.current == MemoryPressureState::LowTotalMemory ||
                  pressure.current == MemoryPressureState::Fragmented
              ? "warning"
              : "info",
          detail, clock_.utcMs(), config_.identity().boot_id);
    }
    const WifiDisconnectSnapshot wifi_events =
        network_.wifiDisconnectEvents();
    for (std::size_t index = 0; index < wifi_events.count; ++index) {
      const WifiDisconnectEvent &event = wifi_events.events[index];
      if (event.transition_number <= last_persisted_wifi_transition_) {
        continue;
      }
      const diag::ReasonInfo reason = diag::wifiDisconnectReason(event.reason);
      const std::string bssid =
          diag::maskMac(std::string(event.bssid.data()));
      char detail[512]{};
      std::snprintf(
          detail, sizeof(detail),
          "event=%s transition=%llu reason=%s reason_code=%u bssid=%s "
          "channel=%d rssi_dbm=%ld ip=%s gateway=%s dns=%s dhcp_ms=%lu "
          "reconnect_attempt=%lu free_internal=%lu largest_internal=%lu",
          wifiEventKindName(event.kind),
          static_cast<unsigned long long>(event.transition_number),
          event.reason == 0U ? "none" : reason.name,
          static_cast<unsigned>(event.reason), bssid.c_str(),
          static_cast<int>(event.channel), static_cast<long>(event.rssi_dbm),
          event.ip_address.data(), event.gateway.data(), event.dns.data(),
          static_cast<unsigned long>(event.dhcp_duration_ms),
          static_cast<unsigned long>(event.reconnect_count),
          static_cast<unsigned long>(event.free_internal_heap_bytes),
          static_cast<unsigned long>(event.largest_internal_block_bytes));
      const bool persisted = storage_coordinator_.enqueueEvent(
          "EVT_WIFI_TRANSITION",
          event.kind == WifiDisconnectEvent::Kind::Disconnected ||
                  event.kind == WifiDisconnectEvent::Kind::IpLost
              ? "warning"
              : "info",
          detail, clock_.utcMs(), config_.identity().boot_id);
      if (!persisted) {
        break;
      }
      last_persisted_wifi_transition_ = event.transition_number;
    }
    if (ESP.getFreeHeap() < 32'768U &&
        diag::SerialLogger::instance().allow("low_heap", 30'000U)) {
      PM_LOG_WARN("MEMORY", "LOW_HEAP",
                  "error=PM-MEM-001 free_bytes=%lu minimum_bytes=%lu "
                  "largest_block=%lu threshold_bytes=32768",
                  static_cast<unsigned long>(ESP.getFreeHeap()),
                  static_cast<unsigned long>(ESP.getMinFreeHeap()),
                  static_cast<unsigned long>(
                      heap_caps_get_largest_free_block(MALLOC_CAP_8BIT)));
    }
    const StorageHealth retention_health = storage_.health();
    if (retention_health.pressure_state != last_storage_pressure_state_) {
      const std::string previous = last_storage_pressure_state_.empty()
                                       ? "unobserved"
                                       : last_storage_pressure_state_;
      const bool recovered = retention_health.pressure_state == "healthy";
      char detail[448]{};
      std::snprintf(
          detail, sizeof(detail),
          "previous=%s current=%s free_bytes=%llu capacity_bytes=%llu "
          "free_percent=%u server_ack_sequence=%llu newest_sequence=%llu "
          "reclaimable_bytes=%llu protected_unacknowledged_bytes=%llu",
          previous.c_str(), retention_health.pressure_state.c_str(),
          static_cast<unsigned long long>(retention_health.free_bytes),
          static_cast<unsigned long long>(retention_health.capacity_bytes),
          static_cast<unsigned>(retention_health.free_percent),
          static_cast<unsigned long long>(retention_health.server_ack_sequence),
          static_cast<unsigned long long>(retention_health.newest_sequence),
          static_cast<unsigned long long>(retention_health.reclaimable_bytes),
          static_cast<unsigned long long>(
              retention_health.protected_unacknowledged_bytes));
      PM_LOG_WARN("STORAGE", "storage.pressure_state_changed", "%s",
                  detail);
      storage_coordinator_.enqueueEvent(
          recovered ? "storage.pressure_recovered"
                    : "storage.pressure_changed",
          recovered ? "info"
                    : (retention_health.pressure_state == "notice"
                           ? "warning"
                           : "critical"),
          detail, clock_.utcMs(), config_.identity().boot_id);
      last_storage_pressure_state_ = retention_health.pressure_state;
    }
    if (retention_health.last_cleanup_utc_ms != 0U &&
        retention_health.last_cleanup_utc_ms !=
            last_storage_cleanup_observed_utc_ms_) {
      char detail[384]{};
      std::snprintf(
          detail, sizeof(detail),
          "result=%s reason=%s reclaimed_bytes=%llu free_bytes=%llu "
          "reclaimable_bytes=%llu protected_unacknowledged_bytes=%llu",
          retention_health.last_cleanup_result.c_str(),
          retention_health.last_cleanup_reason.c_str(),
          static_cast<unsigned long long>(
              retention_health.last_cleanup_reclaimed_bytes),
          static_cast<unsigned long long>(retention_health.free_bytes),
          static_cast<unsigned long long>(retention_health.reclaimable_bytes),
          static_cast<unsigned long long>(
              retention_health.protected_unacknowledged_bytes));
      storage_coordinator_.enqueueEvent(
          retention_health.last_cleanup_result == "completed"
              ? "storage.cleanup_completed"
              : "storage.cleanup_attention",
          retention_health.last_cleanup_result == "completed" ? "info"
                                                                : "warning",
          detail, clock_.utcMs(), config_.identity().boot_id);
      last_storage_cleanup_observed_utc_ms_ =
          retention_health.last_cleanup_utc_ms;
    }
    const bool pressure_cleanup =
        retention_health.pressure_state == "critical" ||
        retention_health.pressure_state == "emergency" ||
        retention_health.pressure_state == "full" ||
        retention_health.last_error.find("reserve_unavailable") !=
            std::string::npos;
    const std::uint64_t current_storage_ack = config_.serverAckSequence();
    const bool acknowledgement_advanced_materially =
        current_storage_ack > last_storage_cleanup_ack_sequence_ &&
        (last_storage_cleanup_ack_sequence_ == 0U ||
         current_storage_ack - last_storage_cleanup_ack_sequence_ >= 128U);
    if (!measurement_config.storage_cleanup_request_id.empty() &&
        measurement_config.storage_cleanup_request_id !=
            last_storage_cleanup_request_id_) {
      const std::uint64_t acknowledgement = config_.serverAckSequence();
      if (storage_coordinator_.queueRetention(
              acknowledgement, acknowledgement > 0U,
              config_.serverEventAckSequence(), clock_.utcMs(),
              measurement_config.storage_policy,
              measurement_config.storage_cleanup_reason.empty()
                  ? "operator_requested_cleanup"
                  : measurement_config.storage_cleanup_reason,
              true)) {
        last_storage_cleanup_request_id_ =
            measurement_config.storage_cleanup_request_id;
      }
    }
    if (!measurement_config.storage_prepare_removal_request_id.empty() &&
        measurement_config.storage_prepare_removal_request_id !=
            last_storage_prepare_removal_request_id_ &&
        config_.setPreparedRemovalSequence(storage_.health().newest_sequence) &&
        storage_coordinator_.queuePrepareRemoval()) {
      last_storage_prepare_removal_request_id_ =
          measurement_config.storage_prepare_removal_request_id;
    }
    if (!config_.safeMode() && measurement_config.storage_policy.mode !=
                                   RetentionMode::Disabled &&
        (clock_.synchronized() ||
         (pressure_cleanup && measurement_config.storage_policy.mode ==
                                  RetentionMode::ContinuousProtected)) &&
        (pressure_cleanup || last_retention_ms == 0 ||
         now - last_retention_ms >= 3'600'000U ||
         acknowledgement_advanced_materially)) {
      const std::uint64_t acknowledgement = config_.serverAckSequence();
      if (storage_coordinator_.queueRetention(
              acknowledgement, acknowledgement > 0U,
              config_.serverEventAckSequence(), clock_.utcMs(),
              measurement_config.storage_policy,
              pressure_cleanup
                  ? "automatic_capacity_pressure"
                  : (acknowledgement_advanced_materially
                         ? "server_acknowledgement_advanced"
                         : "automatic_scheduled_retention"),
              pressure_cleanup)) {
        last_retention_ms = now;
        last_storage_cleanup_ack_sequence_ = acknowledgement;
      }
    }
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}

void Application::maintenanceTask() {
  // Signed OTA downloads and explicit index rebuilds are bounded maintenance
  // operations that can run longer than the task watchdog interval.
  PM_LOG_INFO("TASK", "TASK_STARTED",
              "name=OtaMaintenanceTask core=%d priority=%u stack_bytes=%lu "
              "watchdog=false",
              xPortGetCoreID(),
              static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
              static_cast<unsigned long>(task_config::kMaintenanceStackBytes));
  MaintenanceMessage message;
  for (;;) {
    if (xQueueReceive(maintenance_queue_, &message, pdMS_TO_TICKS(1000)) ==
        pdTRUE) {
      executeMaintenance(message);
    }
  }
}

void Application::serialCommandTask() {
  constexpr std::uint32_t kSerialCommandStackBytes =
      PM_PHYSICAL_ADMIN_RECOVERY ? 8192U
                                 : task_config::kSerialCommandStackBytes;
  PM_LOG_INFO("TASK", "TASK_STARTED",
              "name=SerialCommandTask core=%d priority=%u stack_bytes=%lu "
              "watchdog=false",
              xPortGetCoreID(),
              static_cast<unsigned>(uxTaskPriorityGet(nullptr)),
              static_cast<unsigned long>(kSerialCommandStackBytes));
#if PM_PHYSICAL_ADMIN_RECOVERY
  PM_LOG_INFO("COMMAND", "CONSOLE_READY",
              "mode=physical_admin_recovery "
              "command=admin-recovery-begin line_limit=95");
#else
  PM_LOG_INFO("COMMAND", "CONSOLE_READY", "prompt=pm> type=help line_limit=95");
#endif
  std::string line;
  line.reserve(96);
  bool overflow = false;
  for (;;) {
    while (Serial.available() > 0) {
      const int next = Serial.read();
      if (next < 0)
        break;
      const char character = static_cast<char>(next);
      if (character == '\r' || character == '\n') {
        if (overflow) {
          PM_LOG_WARN("COMMAND", "COMMAND_TOO_LONG",
                      "error=PM-COMMAND-001 maximum_bytes=95");
        } else if (!line.empty()) {
          handleSerialCommand(line);
        }
        std::fill(line.begin(), line.end(), '\0');
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

void Application::handleSerialCommand(std::string &command) {
#if PM_PHYSICAL_ADMIN_RECOVERY
  constexpr std::uint32_t kAdminRecoveryWindowMs = 180'000U;
  constexpr char kAdminRecoveryBeginPrefix[] = "admin-recovery-begin ";
  if (command.rfind(kAdminRecoveryBeginPrefix, 0) == 0) {
    constexpr std::size_t kPrefixLength =
        sizeof(kAdminRecoveryBeginPrefix) - 1U;
    constexpr std::size_t kRequestIdLength = 16U;
    const std::string request_id = command.substr(kPrefixLength);
    const bool request_id_valid =
        request_id.size() == kRequestIdLength &&
        std::all_of(request_id.begin(), request_id.end(), [](const char value) {
          return (value >= '0' && value <= '9') ||
                 (value >= 'a' && value <= 'f');
        });
    if (!request_id_valid || admin_recovery_complete_) {
      PM_LOG_WARN("SECURITY", "ADMIN_PASSWORD_RECOVERY_ARM_REJECTED",
                  "error=PM-COMMAND-005 reason=%s secret_logged=false",
                  admin_recovery_complete_ ? "already_completed"
                                           : "invalid_request_id");
      return;
    }
    admin_recovery_request_id_ = request_id;
    admin_recovery_deadline_ms_ =
        recoveryMonotonicMs() + kAdminRecoveryWindowMs;
    const bool ready_written =
        diag::SerialLogger::instance().writeAdminPasswordRecoveryReady(
            request_id.c_str(), kAdminRecoveryWindowMs);
    PM_LOG_WARN("SECURITY", "ADMIN_PASSWORD_RECOVERY_ARMED",
                "request_id=%s window_ms=%lu ready_written=%s "
                "secret_logged=false",
                request_id.c_str(),
                static_cast<unsigned long>(kAdminRecoveryWindowMs),
                ready_written ? "true" : "false");
    return;
  }

  constexpr char kAdminRecoveryPrefix[] = "admin-password ";
  if (command.rfind(kAdminRecoveryPrefix, 0) == 0) {
    constexpr std::size_t kPrefixLength = sizeof(kAdminRecoveryPrefix) - 1U;
    constexpr std::size_t kRequestIdLength = 16U;
    const std::size_t separator = command.find(' ', kPrefixLength);
    const bool request_id_shape_valid =
        separator == kPrefixLength + kRequestIdLength &&
        std::all_of(command.begin() + kPrefixLength,
                    command.begin() + separator, [](const char value) {
                      return (value >= '0' && value <= '9') ||
                             (value >= 'a' && value <= 'f');
                    });
    if (!request_id_shape_valid) {
      wipeString(command);
      PM_LOG_WARN("SECURITY", "ADMIN_PASSWORD_RECOVERY_COMMAND_REJECTED",
                  "error=PM-COMMAND-005 reason=invalid_request_id "
                  "secret_logged=false");
      return;
    }
    const std::string request_id =
        command.substr(kPrefixLength, kRequestIdLength);
    const bool armed =
        !admin_recovery_complete_ &&
        recoveryMonotonicMs() <= admin_recovery_deadline_ms_ &&
        !admin_recovery_request_id_.empty() &&
        crypto::constantTimeEqual(request_id, admin_recovery_request_id_);
    if (!armed) {
      wipeString(command);
      diag::SerialLogger::instance().writeAdminPasswordRecoveryResult(
          request_id.c_str(), false, true);
      PM_LOG_WARN("SECURITY", "ADMIN_PASSWORD_RECOVERY_COMMAND_REJECTED",
                  "error=PM-COMMAND-005 reason=not_armed_or_expired "
                  "secret_logged=false");
      return;
    }
    wipeString(admin_recovery_request_id_);
    admin_recovery_deadline_ms_ = 0;
    PM_LOG_WARN("SECURITY", "ADMIN_PASSWORD_RECOVERY_REQUESTED",
                "request_id=%s transport=physical_usb "
                "temporary_firmware=true secret_logged=false",
                request_id.c_str());
    std::string password = command.substr(separator + 1U);
    wipeString(command);
    const AdminPasswordRecoveryResult recovery_result =
        config_.replaceAdminPasswordForPhysicalRecovery(password);
    wipeString(password);
    const bool persisted =
        recovery_result == AdminPasswordRecoveryResult::Applied;
    const bool configuration_preserved =
        recovery_result != AdminPasswordRecoveryResult::FailedUncertain;
    bool control_reply_written = false;
    for (std::uint8_t attempt = 0; attempt < 3U && !control_reply_written;
         ++attempt) {
      control_reply_written =
          diag::SerialLogger::instance().writeAdminPasswordRecoveryResult(
              request_id.c_str(), persisted, configuration_preserved);
      if (!control_reply_written) {
        vTaskDelay(pdMS_TO_TICKS(25));
      }
    }
    if (!persisted) {
      PM_LOG_ERROR("SECURITY", "ADMIN_PASSWORD_RECOVERY_FAILED",
                   "error=PM-CONFIG-032 persisted=false "
                   "configuration_preserved=%s control_reply_written=%s "
                   "secret_logged=false",
                   configuration_preserved ? "true" : "unverified",
                   control_reply_written ? "true" : "false");
      return;
    }
    admin_recovery_complete_ = true;
    PM_LOG_WARN("SECURITY", "ADMIN_PASSWORD_RECOVERY_COMPLETE",
                "request_id=%s persisted=true readback_verified=true "
                "configuration_preserved=true control_reply_written=%s "
                "one_shot_locked=true restore_esp32_s3_release=true "
                "secret_logged=false",
                request_id.c_str(), control_reply_written ? "true" : "false");
    return;
  }
  PM_LOG_WARN("SECURITY", "ADMIN_RECOVERY_COMMAND_REJECTED",
              "error=PM-COMMAND-005 mode=physical_admin_recovery "
              "permitted=admin_recovery_handshake secret_logged=false");
  return;
#endif

  constexpr char kSetupPasswordPrefix[] = "setup-password ";
  if (command.rfind(kSetupPasswordPrefix, 0) == 0) {
    constexpr std::size_t kPrefixLength = sizeof(kSetupPasswordPrefix) - 1U;
    constexpr std::size_t kRequestIdLength = 16U;
    const std::size_t separator = command.find(' ', kPrefixLength);
    const bool request_id_shape_valid =
        separator == kPrefixLength + kRequestIdLength &&
        std::all_of(command.begin() + kPrefixLength,
                    command.begin() + separator, [](const char value) {
                      return (value >= '0' && value <= '9') ||
                             (value >= 'a' && value <= 'f');
                    });
    if (!request_id_shape_valid) {
      wipeString(command);
      PM_LOG_WARN(
          "SECURITY", "SETUP_AP_PASSWORD_COMMAND_REJECTED",
          "error=PM-COMMAND-004 reason=invalid_request_id secret_logged=false");
      return;
    }
    const std::string request_id =
        command.substr(kPrefixLength, kRequestIdLength);
    PM_LOG_DEBUG("COMMAND", "COMMAND_RECEIVED",
                 "command=setup-password_<request_id>_<redacted> "
                 "request_id=%s secret_logged=false",
                 request_id.c_str());
    std::string password = command.substr(separator + 1U);
    wipeString(command);
    const bool persisted = config_.setSetupPassword(password);
    wipeString(password);
    if (persisted) {
      network_.requestSetupApRestart();
    }
    bool control_reply_written = false;
    for (std::uint8_t attempt = 0; attempt < 3U && !control_reply_written;
         ++attempt) {
      control_reply_written =
          diag::SerialLogger::instance().writeSetupPasswordResult(
              request_id.c_str(), persisted);
      if (!control_reply_written) {
        vTaskDelay(pdMS_TO_TICKS(25));
      }
    }
    if (!persisted) {
      PM_LOG_WARN(
          "SECURITY", "SETUP_AP_PASSWORD_COMMIT_REJECTED",
          "error=PM-CONFIG-030 requirement=12_to_63_printable_non_whitespace "
          "persisted=false control_reply_written=%s secret_logged=false",
          control_reply_written ? "true" : "false");
      return;
    }
    PM_LOG_INFO("SECURITY", "SETUP_AP_PASSWORD_COMMIT_COMPLETE",
                "request_id=%s persisted=true readback_verified=true "
                "ap_restart=scheduled control_reply_written=%s "
                "secret_logged=false",
                request_id.c_str(), control_reply_written ? "true" : "false");
    return;
  }

  std::string normalized = command;
  normalized.erase(normalized.begin(),
                   std::find_if(normalized.begin(), normalized.end(),
                                [](const unsigned char value) {
                                  return !std::isspace(value);
                                }));
  normalized.erase(std::find_if(normalized.rbegin(), normalized.rend(),
                                [](const unsigned char value) {
                                  return !std::isspace(value);
                                })
                       .base(),
                   normalized.end());
  std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                 [](const unsigned char value) {
                   return static_cast<char>(std::tolower(value));
                 });
  const bool recognized =
      normalized == "help" || normalized == "status" || normalized == "wifi" ||
      normalized == "network" || normalized == "time" || normalized == "tls" ||
      normalized == "server" || normalized == "tasks" ||
      normalized == "memory" || normalized == "sd" || normalized == "pzem" ||
      normalized == "errors" || normalized == "reconnect" ||
      normalized.rfind("loglevel ", 0) == 0;
  PM_LOG_DEBUG("COMMAND", "COMMAND_RECEIVED", "command=%s length=%u",
               recognized ? (normalized.rfind("loglevel ", 0) == 0
                                 ? "loglevel <value>"
                                 : normalized.c_str())
                          : "unrecognized",
               static_cast<unsigned>(normalized.size()));
  if (normalized == "help") {
    PM_LOG_INFO(
        "COMMAND", "HELP",
        "commands=help,status,wifi,network,time,tls,server,tasks,memory,sd,"
        "pzem,errors,loglevel_<trace|debug|info|warn|error|fatal>,reconnect,"
        "setup-password_<16_hex_request_id>_"
        "<12-63_printable_non-whitespace_chars>");
  } else if (normalized == "status") {
    reportStatus();
  } else if (normalized == "wifi" || normalized == "network") {
    if (normalized == "wifi")
      network_.requestScan();
    const NetworkStatus state = network_.status();
    PM_LOG_INFO(
        "COMMAND", normalized == "wifi" ? "WIFI_REPORT" : "NETWORK_REPORT",
        "station=%s setup_ap=%s ssid=%s rssi_dbm=%ld ip=%s subnet=%s "
        "gateway=%s dns=%s hostname=%s reconnects=%lu mdns=%s",
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
    PM_LOG_INFO("COMMAND", "TIME_REPORT",
                "trusted=%s utc=%s monotonic_ms=%llu last_trusted_utc_ms=%llu",
                clock_.synchronized() ? "true" : "false",
                clock_.synchronized() ? clock_.utcIso8601().c_str()
                                      : "unavailable",
                static_cast<unsigned long long>(clock_.monotonicMs()),
                static_cast<unsigned long long>(clock_.lastTrustedUtcMs()));
  } else if (normalized == "tls") {
    PM_LOG_INFO(
        "COMMAND", "TLS_REPORT",
        "server_configured=%s ca_configured=%s fingerprint_configured=%s "
        "time_trusted=%s validation=required insecure_mode=false",
        config_.config().server_url.empty() ? "false" : "true",
        config_.config().server_ca_pem.empty() ? "false" : "true",
        config_.config().server_fingerprint.empty() ? "false" : "true",
        clock_.synchronized() ? "true" : "false");
  } else if (normalized == "server") {
    const NetworkStatus state = network_.status();
    const SyncMetrics metrics = diagnostics_.syncMetrics();
    PM_LOG_INFO(
        "COMMAND", "SERVER_REPORT",
        "configured=%s reachable=%s authenticated=%s heartbeat_ok=%llu "
        "heartbeat_failed=%llu batch_ok=%llu batch_failed=%llu last_error=%s",
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
        "present=%s mounted=%s writable=%s prepared=%s filesystem=%s "
        "spi_hz=%lu capacity=%llu used=%llu free=%llu writes=%llu "
        "write_failures=%llu reads=%llu read_failures=%llu repairs=%lu "
        "last_error=%s",
        state.present ? "true" : "false", state.mounted ? "true" : "false",
        state.writable ? "true" : "false",
        state.prepared_for_removal ? "true" : "false", state.filesystem.c_str(),
        static_cast<unsigned long>(state.spi_hz),
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
    PM_LOG_INFO("COMMAND", "PZEM_REPORT",
                "method=%s requests=%llu successes=%llu timeouts=%llu "
                "crc_errors=%llu invalid_frames=%llu consecutive_errors=%lu "
                "last_error=%s last_latency_ms=%lu",
                meter_->methodName(),
                static_cast<unsigned long long>(state.requests),
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
      PM_LOG_WARN(
          "COMMAND", "LOG_LEVEL_REJECTED",
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
    PM_LOG_WARN(
        "COMMAND", "UNKNOWN_COMMAND",
        "error=PM-COMMAND-003 command=unrecognized length=%u hint=type_help",
        static_cast<unsigned>(normalized.size()));
  }
}

void Application::reportStatus() const {
  const NetworkStatus network = network_.status();
  const StorageHealth storage = storage_.health();
  const MeterMetrics meter = meter_->metrics();
  const QueueMetrics queues = diagnostics_.queueMetrics();
  PM_LOG_INFO("COMMAND", "STATUS_REPORT",
              "firmware=%s protocol=%s uptime_s=%llu safe_mode=%s enrolled=%s "
              "wifi=%s time_trusted=%s storage=%s meter=%s server=%s "
              "storage_queue=%lu action_queue=%lu",
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
  captureTaskDiagnostics();
  for (const auto &task : diagnostics_.taskMetrics()) {
    if (task.name.empty()) {
      continue;
    }
    PM_LOG_INFO("TASK", "TASK_REPORT",
                "name=%s running=%s priority=%lu core=%d stack_bytes=%lu "
                "high_water_bytes=%lu margin_percent=%lu watchdog=%s",
                task.name.c_str(), task.running ? "true" : "false",
                static_cast<unsigned long>(task.priority),
                static_cast<int>(task.core),
                static_cast<unsigned long>(task.configured_stack_bytes),
                static_cast<unsigned long>(task.high_water_bytes),
                static_cast<unsigned long>(task.margin_percent),
                task.watchdog ? "true" : "false");
  }
}

void Application::captureTaskDiagnostics() const {
  struct TaskReport {
    const char *name;
    TaskHandle_t handle;
    std::uint32_t configured_stack_bytes;
    std::int8_t core;
    bool watchdog;
  };
  const std::array<TaskReport, kTaskRuntimeMetricCapacity> tasks{{
      {"DiagLogTask", xTaskGetHandle("DiagLogTask"),
       task_config::kDiagnosticLoggerStackBytes, 0, false},
      {"MeterTask", meter_task_, task_config::kMeterStackBytes, 1, true},
      {"AggregationTask", aggregation_task_,
       task_config::kAggregationStackBytes, 1, true},
      {"StorageTask", storage_task_, task_config::kStorageStackBytes, 0,
       false},
      {"NetworkTask", network_task_, task_config::kNetworkStackBytes, 1,
       true},
      {"ServerSyncTask", sync_task_, task_config::kServerSyncStackBytes, 0,
       false},
      {"HealthTask", health_task_, task_config::kHealthStackBytes, 0, false},
      {"OtaMaintenanceTask", maintenance_task_,
       task_config::kMaintenanceStackBytes, 0, false},
      {"SerialCommandTask", serial_command_task_,
       task_config::kSerialCommandStackBytes, 0, false},
      {"PasswordJobTask", xTaskGetHandle("PasswordJobTask"),
       task_config::kPasswordJobStackBytes, 1, false},
  }};
  std::array<TaskRuntimeMetric, kTaskRuntimeMetricCapacity> snapshot{};
  for (std::size_t index = 0; index < tasks.size(); ++index) {
    const auto &task = tasks[index];
    const std::uint32_t high_water_bytes =
        task.handle == nullptr ? 0U
                               : static_cast<std::uint32_t>(
                                     uxTaskGetStackHighWaterMark(task.handle));
    const std::uint32_t margin_percent =
        task.configured_stack_bytes == 0U
            ? 0U
            : static_cast<std::uint32_t>(
                  (static_cast<std::uint64_t>(std::min(
                       task.configured_stack_bytes, high_water_bytes)) *
                   100U) /
                  task.configured_stack_bytes);
    snapshot[index] = {
        task.name,
        task.configured_stack_bytes,
        high_water_bytes,
        margin_percent,
        task.handle == nullptr
            ? 0U
            : static_cast<std::uint32_t>(uxTaskPriorityGet(task.handle)),
        task.core,
        task.handle != nullptr,
        task.watchdog,
    };
  }
  diagnostics_.setTaskMetrics(snapshot);
}

void Application::reportMemory() const {
  const std::uint32_t heap_free =
      heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  const std::uint32_t heap_largest =
      heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  const std::uint32_t fragmentation =
      heap_free == 0
          ? 0
          : 100U - static_cast<std::uint32_t>(
                       (static_cast<std::uint64_t>(heap_largest) * 100U) /
                       heap_free);
  PM_LOG_INFO("MEMORY", "MEMORY_REPORT",
              "heap_total=%lu heap_free=%lu heap_min=%lu heap_largest=%lu "
              "fragmentation_percent=%lu psram_total=%lu psram_free=%lu",
              static_cast<unsigned long>(
                  heap_caps_get_total_size(MALLOC_CAP_INTERNAL |
                                           MALLOC_CAP_8BIT)),
              static_cast<unsigned long>(heap_free),
              static_cast<unsigned long>(ESP.getMinFreeHeap()),
              static_cast<unsigned long>(heap_largest),
              static_cast<unsigned long>(fragmentation),
              static_cast<unsigned long>(ESP.getPsramSize()),
              static_cast<unsigned long>(ESP.getFreePsram()));
}

void Application::executeMaintenance(const MaintenanceMessage &message) {
  bool ok = false;
  const char *code = "EVT_MAINTENANCE_COMPLETE";
  const std::uint64_t started_ms = clock_.monotonicMs();
  PM_LOG_INFO("MAINTENANCE", "ACTION_BEGIN",
              "action=%u argument=redacted heap_free=%lu",
              static_cast<unsigned>(message.action),
              static_cast<unsigned long>(ESP.getFreeHeap()));
  switch (message.action) {
  case MaintenanceAction::TestPzem:
    if (xSemaphoreTake(meter_mutex_, pdMS_TO_TICKS(5000)) == pdTRUE) {
      ok = meter_
               ->poll(clock_.utcMs(), clock_.monotonicMs(),
                      clock_.synchronized())
               .error == MeterError::None;
      xSemaphoreGive(meter_mutex_);
    }
    break;
  case MaintenanceAction::TestSd:
    ok = storage_coordinator_.queueSelfTest();
    break;
  case MaintenanceAction::RemountSd:
    ok = storage_coordinator_.queueRemount();
    break;
  case MaintenanceAction::RebuildIndex:
    ok = storage_coordinator_.queueRebuildIndexes();
    break;
  case MaintenanceAction::PrepareCardRemoval:
    ok = config_.setPreparedRemovalSequence(storage_.health().newest_sequence) &&
         storage_coordinator_.queuePrepareRemoval();
    break;
  case MaintenanceAction::TestDns: {
    const std::string host = httpsHost(config_.config().server_url);
    IPAddress address;
    const std::uint64_t dns_started = clock_.monotonicMs();
    PM_LOG_INFO("DNS", "DIAGNOSTIC_LOOKUP_BEGIN",
                "host=%s method=dns_then_mdns",
                host.empty() ? "invalid" : host.c_str());
    const bool dns_resolved =
        !host.empty() && WiFi.hostByName(host.c_str(), address) == 1;
    bool mdns_resolved = false;
    if (!dns_resolved && host.size() > 6U &&
        host.compare(host.size() - 6U, 6U, ".local") == 0) {
      const std::string mdns_host = host.substr(0, host.size() - 6U);
      address = MDNS.queryHost(mdns_host.c_str(), 3000U);
      mdns_resolved = static_cast<std::uint32_t>(address) != 0U;
    }
    ok = dns_resolved || mdns_resolved;
    PM_LOG_INFO(
        "DNS", ok ? "DIAGNOSTIC_LOOKUP_COMPLETE" : "DIAGNOSTIC_LOOKUP_FAILED",
        "host=%s method=%s address=%s elapsed_ms=%llu",
        host.empty() ? "invalid" : host.c_str(),
        dns_resolved ? "dns" : (mdns_resolved ? "mdns" : "none"),
        ok ? address.toString().c_str() : "unresolved",
        static_cast<unsigned long long>(clock_.monotonicMs() - dns_started));
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
    storage_coordinator_.enqueueEvent(
        "EVT_REBOOT_REQUESTED", "warning", "Authorized local reboot requested.",
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
  ok &= xTaskCreatePinnedToCore(meterTaskEntry, "MeterTask",
                                task_config::kMeterStackBytes, this, 4,
                                &meter_task_, 1);
  ok &= xTaskCreatePinnedToCore(aggregationTaskEntry, "AggregationTask",
                                task_config::kAggregationStackBytes, this,
                                task_config::kAggregationPriority,
                                &aggregation_task_, 1);
  ok &= xTaskCreatePinnedToCore(storageTaskEntry, "StorageTask",
                                task_config::kStorageStackBytes, this,
                                task_config::kStoragePriority,
                                &storage_task_, 0);
  ok &= xTaskCreatePinnedToCore(networkTaskEntry, "NetworkTask",
                                task_config::kNetworkStackBytes, this, 2,
                                &network_task_, 1);
  ok &= xTaskCreatePinnedToCore(syncTaskEntry, "ServerSyncTask",
                                task_config::kServerSyncStackBytes, this, 2,
                                &sync_task_, 1);
  ok &= xTaskCreatePinnedToCore(healthTaskEntry, "HealthTask",
                                task_config::kHealthStackBytes, this, 1,
                                &health_task_, 0);
  ok &= xTaskCreatePinnedToCore(maintenanceTaskEntry, "OtaMaintenanceTask",
                                task_config::kMaintenanceStackBytes, this, 2,
                                &maintenance_task_, 0);
  ok &= xTaskCreatePinnedToCore(serialCommandTaskEntry, "SerialCommandTask",
                                task_config::kSerialCommandStackBytes, this, 1,
                                &serial_command_task_, 0);
  const bool created = ok == pdPASS;
  PM_LOG_INFO(
      "TASK", "TASK_SET_CREATED",
      "result=%s count=8 sample_queue_capacity=8 action_queue_capacity=%u",
      created ? "success" : "failed",
      static_cast<unsigned>(build::ACTION_QUEUE_DEPTH));
  return created;
}

} // namespace pm
