#pragma once

#include <atomic>
#include <memory>
#include <string>

#include <HardwareSerial.h>

#include "api/HttpApi.h"
#include "app/Maintenance.h"
#include "build_config.h"
#include "config/ConfigService.h"
#include "core/Algorithms.h"
#include "core/MemoryPressurePolicy.h"
#include "diagnostics/Diagnostics.h"
#include "meter/IMeter.h"
#include "network/ClockService.h"
#include "network/NetworkService.h"
#include "network/ServerSync.h"
#include "ota/OtaService.h"
#include "storage/SdStorage.h"
#include "storage/StorageCoordinator.h"

namespace pm {

class Application {
public:
  Application();
  bool begin();

private:
  static void meterTaskEntry(void *context);
  static void aggregationTaskEntry(void *context);
  static void storageTaskEntry(void *context);
  static void networkTaskEntry(void *context);
  static void syncTaskEntry(void *context);
  static void healthTaskEntry(void *context);
  static void maintenanceTaskEntry(void *context);
  static void serialCommandTaskEntry(void *context);
  void meterTask();
  void aggregationTask();
  void networkTask();
  void syncTask();
  void healthTask();
  void maintenanceTask();
  void serialCommandTask();
  void handleSerialCommand(std::string &command);
  void reportStatus() const;
  void reportTasks() const;
  void captureTaskDiagnostics() const;
  void reportMemory() const;
  void executeMaintenance(const MaintenanceMessage &message);
  bool createTasks();

  ConfigService config_;
  ClockService clock_;
  NetworkService network_;
  SdStorage storage_;
  Diagnostics diagnostics_;
  StorageCoordinator storage_coordinator_;
  HardwareSerial pzem_serial_{1};
  std::unique_ptr<IMeter> meter_;
  OtaService ota_;
  std::unique_ptr<ServerSync> sync_;
  std::unique_ptr<HttpApi> http_;
  QueueHandle_t sample_queue_{nullptr};
  QueueHandle_t maintenance_queue_{nullptr};
  SemaphoreHandle_t meter_mutex_{nullptr};
  TaskHandle_t meter_task_{nullptr};
  TaskHandle_t aggregation_task_{nullptr};
  TaskHandle_t storage_task_{nullptr};
  TaskHandle_t network_task_{nullptr};
  TaskHandle_t sync_task_{nullptr};
  TaskHandle_t health_task_{nullptr};
  TaskHandle_t maintenance_task_{nullptr};
  TaskHandle_t serial_command_task_{nullptr};
  std::atomic<std::uint64_t> meter_progress_{0};
  std::atomic<std::uint64_t> aggregation_progress_{0};
  std::atomic<std::uint64_t> network_progress_{0};
  std::atomic<std::uint64_t> sync_progress_{0};
  MemoryPressurePolicy memory_pressure_;
  std::uint64_t sample_dropped_{0};
  std::uint64_t action_dropped_{0};
  std::uint64_t last_persisted_wifi_transition_{0};
  std::string last_storage_cleanup_request_id_;
  std::string last_storage_prepare_removal_request_id_;
  std::string last_storage_pressure_state_;
  std::uint64_t last_storage_cleanup_observed_utc_ms_{0};
  std::uint64_t last_storage_cleanup_ack_sequence_{0};
#if PM_PHYSICAL_ADMIN_RECOVERY
  std::string admin_recovery_request_id_;
  std::uint64_t admin_recovery_deadline_ms_{0};
  bool admin_recovery_complete_{false};
#endif
};

} // namespace pm
