#pragma once

#include <cstdint>
#include <string>

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include "config/ConfigService.h"
#include "diagnostics/Diagnostics.h"
#include "meter/IMeter.h"
#include "network/ClockService.h"
#include "ota/OtaService.h"
#include "reset/DataResetPolicy.h"
#include "reset/DataResetStore.h"
#include "storage/SdStorage.h"
#include "storage/StorageCoordinator.h"

namespace pm {

struct DataResetApiResult {
  int status{500};
  std::string code;
  std::string detail;
  std::string body;

  bool ok() const { return status >= 200 && status < 300; }
};

struct DataResetCancelRequest {
  std::string protocol;
  std::string operation_id;
  std::string device_id;
  std::uint64_t target_generation{0U};
  std::uint64_t plan_revision{0U};
  std::string plan_digest;
};

struct DataResetHeartbeatSnapshot {
  std::string state{"none"};
  std::string checkpoint{"none"};
  std::string operation_id;
  std::string failure_code;
  std::uint64_t target_generation{0U};
  std::uint64_t reset_boundary{0U};
  bool reset_required{false};
};

// Owns the durable device half of data-reset/1.0.0. HTTP callbacks only
// validate/enqueue commands; tick() runs the slow meter/storage checkpoints on
// OtaMaintenanceTask. All irreversible work is preceded by a read-back
// verified CommitAuthorized record.
class DataResetCoordinator {
public:
  DataResetCoordinator(ConfigService &config, ClockService &clock,
                       SdStorage &storage,
                       StorageCoordinator &storage_coordinator,
                       Diagnostics &diagnostics, IMeter &meter, OtaService &ota,
                       SemaphoreHandle_t meter_mutex);

  bool begin();
  void tick();

  DataResetApiResult requestPrepare(const data_reset::PrepareRequest &request);
  DataResetApiResult requestCommit(const data_reset::CommitRequest &request);
  DataResetApiResult requestCancel(const DataResetCancelRequest &request);
  DataResetApiResult status(const std::string &operation_id,
                            std::uint64_t target_generation) const;

  bool active() const;
  std::uint64_t requiredSequenceFloor() const;
  std::string heartbeatState() const;
  DataResetHeartbeatSnapshot heartbeatSnapshot() const;

private:
  enum class BarrierPurpose : std::uint8_t { None, PrepareDrain, Cleanup };

  bool lock(TickType_t timeout = pdMS_TO_TICKS(250)) const;
  void unlock() const;
  bool saveRecord(const data_reset::Record &proposed);
  bool applyGates(bool enabled);
  data_reset::GateSnapshot gateSnapshot() const;
  bool gatesReleased() const;
  bool completionVisible(const data_reset::Record &record) const;
  bool cancellationVisible(const data_reset::Record &record) const;
  bool terminalReleasePending(const data_reset::Record &record) const;
  void processPendingPrepare();
  void progressPreparing();
  void processPendingCommit();
  void progressCommit();
  bool captureMeterEnergy(std::uint64_t &raw_energy_wh);
  bool persistMeasurementPauseEvidence(data_reset::Record &record);
  bool prepareReceipt(data_reset::Record &record);
  std::string buildCommitReceipt(const data_reset::Record &record) const;
  std::string statusJson(const data_reset::Record &record) const;
  std::string receiptDigest(const std::string &canonical,
                            const std::string &device_id) const;
  void failBeforeCommit(const char *code);
  void requireAttention(const char *code);
  bool sameCard(const data_reset::Record &record,
                const StorageHealth &health) const;
  static DataResetApiResult problem(int status, const char *code,
                                    const char *detail);

  ConfigService &config_;
  ClockService &clock_;
  SdStorage &storage_;
  StorageCoordinator &storage_coordinator_;
  Diagnostics &diagnostics_;
  IMeter &meter_;
  OtaService &ota_;
  SemaphoreHandle_t meter_mutex_{nullptr};
  DataResetStore store_{};
  mutable SemaphoreHandle_t mutex_{nullptr};
  data_reset::Record record_{};
  bool has_record_{false};
  bool pending_prepare_{false};
  data_reset::PrepareRequest prepare_request_{};
  bool pending_commit_{false};
  data_reset::CommitRequest commit_request_{};
  BarrierPurpose barrier_purpose_{BarrierPurpose::None};
  std::uint32_t barrier_request_id_{0U};
};

} // namespace pm
