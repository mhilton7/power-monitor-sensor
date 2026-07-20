#include "app/Application.h"

#include <algorithm>
#include <cstring>
#include <new>

#include <Arduino.h>
#include <WiFi.h>
#include <esp_task_wdt.h>

#include "board_pins.h"
#include "build_config.h"
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
  Serial.printf("\n%s %s (%s)\n", build::PRODUCT_NAME, version::FIRMWARE,
                version::PROTOCOL);
  Serial.println("Monitoring only. No switching or bill calculation is present.");
  if (!config_.begin()) {
    Serial.println("Fatal: NVS configuration could not initialize.");
    return false;
  }
  config_.recordBootStarted();
  clock_.begin();
  clock_.update();
  storage_.begin(config_.config().sd_spi_hz);
  if (!storage_coordinator_.begin()) {
    Serial.println("Fatal: bounded storage queue could not initialize.");
    return false;
  }
#if PM_SIMULATED_METER
  meter_ = std::unique_ptr<IMeter>(new (std::nothrow) SimulatedMeter());
#else
  meter_ = std::unique_ptr<IMeter>(new (std::nothrow) PzemMeter(
      pzem_serial_, config_.config().pzem_timeout_ms, 2));
#endif
  if (meter_ == nullptr || !meter_->begin()) {
    Serial.println("Meter initialization degraded; recovery API remains available.");
  }
  if (!network_.begin()) {
    Serial.println("Network initialization degraded; local recovery continues.");
  }
  sample_queue_ = xQueueCreate(8, sizeof(MeasurementSnapshot));
  maintenance_queue_ = xQueueCreate(build::ACTION_QUEUE_DEPTH,
                                    sizeof(MaintenanceMessage));
  meter_mutex_ = xSemaphoreCreateMutex();
  if (sample_queue_ == nullptr || maintenance_queue_ == nullptr ||
      meter_mutex_ == nullptr) {
    Serial.println("Fatal: bounded runtime primitives could not initialize.");
    return false;
  }
  sync_ = std::unique_ptr<ServerSync>(new (std::nothrow) ServerSync(
      config_, network_, clock_, storage_, diagnostics_, *meter_));
  http_ = std::unique_ptr<HttpApi>(new (std::nothrow) HttpApi(
      config_, network_, clock_, storage_, storage_coordinator_, diagnostics_,
      *meter_, ota_, maintenance_queue_));
  if (sync_ == nullptr || http_ == nullptr || !createTasks()) {
    Serial.println("Fatal: runtime services could not start.");
    return false;
  }
  http_->begin();
  ota_.checkRunningImage();
  config_.recordBootHealthy();
  storage_coordinator_.enqueueEvent(
      "EVT_BOOT_COMPLETE", "info",
      config_.safeMode() ? "Booted into safe mode." : "Runtime services started.",
      clock_.utcMs(), config_.identity().boot_id);
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

void Application::meterTask() {
  registerWatchdog();
  TickType_t last_wake = xTaskGetTickCount();
  for (;;) {
    MeasurementSnapshot sample;
    if (xSemaphoreTake(meter_mutex_, pdMS_TO_TICKS(5000)) == pdTRUE) {
      sample = meter_->poll(clock_.utcMs(), clock_.monotonicMs(),
                            clock_.synchronized());
      xSemaphoreGive(meter_mutex_);
    } else {
      sample.monotonic_ms = clock_.monotonicMs();
      sample.error = MeterError::UartFailure;
      sample.quality_flags = MeterGap;
    }
    Limits limits;
    limits.ct_rating_a = config_.config().ct_rating_a;
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
    }
    ++meter_progress_;
    feedWatchdog();
    vTaskDelayUntil(&last_wake,
                    pdMS_TO_TICKS(config_.config().sample_interval_seconds * 1000U));
  }
}

void Application::aggregationTask() {
  registerWatchdog();
  Limits limits;
  limits.ct_rating_a = config_.config().ct_rating_a;
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
  for (;;) {
    network_.update();
    ++network_progress_;
    feedWatchdog();
    vTaskDelay(pdMS_TO_TICKS(250));
  }
}

void Application::syncTask() {
  registerWatchdog();
  for (;;) {
    sync_->tick();
    ++sync_progress_;
    feedWatchdog();
    vTaskDelay(pdMS_TO_TICKS(250));
  }
}

void Application::healthTask() {
  registerWatchdog();
  std::uint64_t previous_meter = 0;
  std::uint64_t previous_aggregation = 0;
  std::uint64_t previous_network = 0;
  std::uint64_t previous_sync = 0;
  std::uint64_t last_retention_ms = 0;
  for (;;) {
    diagnostics_.setQueueDepths(
        storage_coordinator_.depth(), uxQueueMessagesWaiting(maintenance_queue_),
        storage_coordinator_.dropped() + sample_dropped_, action_dropped_);
    const std::uint64_t meter = meter_progress_.load();
    const std::uint64_t aggregation = aggregation_progress_.load();
    const std::uint64_t network = network_progress_.load();
    const std::uint64_t sync = sync_progress_.load();
    const bool progress = meter != previous_meter &&
                          aggregation != previous_aggregation &&
                          network != previous_network && sync != previous_sync;
    previous_meter = meter;
    previous_aggregation = aggregation;
    previous_network = network;
    previous_sync = sync;
    if (progress) {
      feedWatchdog();
    }
    const std::uint64_t now = clock_.monotonicMs();
    if (config_.config().retention_enabled && clock_.synchronized() &&
        (last_retention_ms == 0 || now - last_retention_ms >= 3'600'000U)) {
      storage_.applyRetention(config_.serverAckSequence(), clock_.utcMs(),
                              config_.config().retention_days);
      last_retention_ms = now;
    }
    vTaskDelay(pdMS_TO_TICKS(5000));
  }
}

void Application::maintenanceTask() {
  registerWatchdog();
  MaintenanceMessage message;
  for (;;) {
    if (xQueueReceive(maintenance_queue_, &message, pdMS_TO_TICKS(1000)) == pdTRUE) {
      executeMaintenance(message);
    }
    feedWatchdog();
  }
}

void Application::executeMaintenance(const MaintenanceMessage& message) {
  bool ok = false;
  const char* code = "EVT_MAINTENANCE_COMPLETE";
  switch (message.action) {
    case MaintenanceAction::TestPzem:
      if (xSemaphoreTake(meter_mutex_, pdMS_TO_TICKS(5000)) == pdTRUE) {
        ok = meter_->poll(clock_.utcMs(), clock_.monotonicMs(),
                          clock_.synchronized()).error == MeterError::None;
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
      delay(250);
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
}

bool Application::createTasks() {
  BaseType_t ok = pdPASS;
  ok &= xTaskCreatePinnedToCore(meterTaskEntry, "MeterTask", 6144, this, 4,
                                nullptr, 1);
  ok &= xTaskCreatePinnedToCore(aggregationTaskEntry, "AggregationTask", 8192,
                                this, 3, nullptr, 1);
  ok &= xTaskCreatePinnedToCore(storageTaskEntry, "StorageTask", 8192, this, 3,
                                nullptr, 1);
  ok &= xTaskCreatePinnedToCore(networkTaskEntry, "NetworkTask", 6144, this, 2,
                                nullptr, 0);
  ok &= xTaskCreatePinnedToCore(syncTaskEntry, "ServerSyncTask", 12288, this, 2,
                                nullptr, 0);
  ok &= xTaskCreatePinnedToCore(healthTaskEntry, "HealthTask", 6144, this, 1,
                                nullptr, 0);
  ok &= xTaskCreatePinnedToCore(maintenanceTaskEntry, "OtaMaintenanceTask",
                                12288, this, 2, nullptr, 0);
  return ok == pdPASS;
}

}  // namespace pm
