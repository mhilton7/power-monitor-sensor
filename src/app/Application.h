#pragma once

#include <atomic>
#include <memory>

#include <HardwareSerial.h>

#include "api/HttpApi.h"
#include "app/Maintenance.h"
#include "config/ConfigService.h"
#include "core/Algorithms.h"
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
  static void meterTaskEntry(void* context);
  static void aggregationTaskEntry(void* context);
  static void storageTaskEntry(void* context);
  static void networkTaskEntry(void* context);
  static void syncTaskEntry(void* context);
  static void healthTaskEntry(void* context);
  static void maintenanceTaskEntry(void* context);
  void meterTask();
  void aggregationTask();
  void networkTask();
  void syncTask();
  void healthTask();
  void maintenanceTask();
  void executeMaintenance(const MaintenanceMessage& message);
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
  std::atomic<std::uint64_t> meter_progress_{0};
  std::atomic<std::uint64_t> aggregation_progress_{0};
  std::atomic<std::uint64_t> network_progress_{0};
  std::atomic<std::uint64_t> sync_progress_{0};
  std::uint64_t sample_dropped_{0};
  std::uint64_t action_dropped_{0};
};

}  // namespace pm

