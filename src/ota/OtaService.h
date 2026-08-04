#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <esp_partition.h>

#include "config/ConfigService.h"
#include "diagnostics/Diagnostics.h"
#include "ota/CompactOtaStatus.h"
#include "ota/OtaManifestV2.h"
#include "ota/OtaRecoveryStore.h"
#include "ota/OtaUpdatePolicy.h"

namespace pm {

constexpr std::uint32_t kOtaPartitionSizeBytes = 0x600000U;
constexpr std::size_t kOtaReportMaximumBytes = 2048U;

struct OtaStatus {
  std::uint32_t protocol_version{ota_v2::kProtocolVersion};
  std::string authentication_mode{ota_v2::kAuthenticationMode};
  ota_v2::State state{ota_v2::State::Idle};
  std::string deployment_id;
  std::string release_id;
  std::uint32_t attempt{0U};
  bool in_progress{false};
  bool pending_reboot{false};
  bool rollback_supported{true};
  bool rollback_detected{false};
  bool restricted_recovery_mode{false};
  bool restricted_incident_durable{false};
  bool restricted_incident_report_pending{false};
  std::uint32_t bytes_received{0U};
  std::uint32_t image_size{0U};
  std::uint8_t progress_percent{0U};
  std::string target_version;
  std::string target_sha256;
  std::string target_build_hash;
  std::string running_partition;
  std::string target_partition;
  std::string last_result{"never"};
  std::string last_error;
  std::string restricted_failure_code;
  std::string restricted_rollback_result;
};

class OtaService {
public:
  OtaService(ConfigService &config, Diagnostics &diagnostics);
  bool begin();
  bool restrictedRecoveryMode() const;
  bool runningImagePendingVerification() const;
  ota_v2::RunningImageCheckResult
  checkRunningImage(ota_v2::PostBootHealthClass health);
  bool applyFromManifestUrl(const std::string &manifest_url);
  bool parseManifest(const std::string &json, ota_v2::Manifest &manifest,
                     std::string &error) const;
  bool verifyManifest(const ota_v2::Manifest &manifest,
                      std::string &error) const;
  std::string canonicalManifest(const ota_v2::Manifest &manifest) const;
  OtaStatus status() const;
  CompactOtaStatus compactStatus() const;
  ota_v2::RollbackResult rollbackAndReboot();
  bool pendingReport(std::string &body) const;
  bool hasPendingReport() const;
  bool flushPendingReport();
  void markPendingReportDelivered();
  static std::string runningBuildHash();
  static std::uint32_t updatePartitionSize();

private:
  bool fetchText(const std::string &url, std::string &body,
                 std::size_t maximum_bytes, std::string &error) const;
  bool downloadAndApply(const ota_v2::Manifest &manifest,
                        std::string &error);
  bool addDeviceAuthentication(HTTPClient &http, const char *method,
                               const std::string &target,
                               const char *body, std::size_t body_size,
                               std::string &error) const;
  bool postReport(const char *report_state, std::string &error);
  bool flushPendingReportWithLease();
  bool serverTarget(const RuntimeConfig &config, const std::string &url,
                    std::string &target) const;
  bool configureTls(WiFiClientSecure &client,
                    const std::string &ca_pem) const;
  OtaRecoveryStoreResult
  persistState(ota_v2::State state, const std::string &failure_code = {},
               bool pending_reboot = false);
  OtaRecoveryStoreResult setState(ota_v2::State state,
                                  const std::string &result,
                                  const std::string &error = {},
                                  bool persist = true, bool report = true);
  bool reportJson(const char *report_state,
                  std::array<char, kOtaReportMaximumBytes> &output,
                  std::size_t &size) const;
  bool verifySelectedBootPartition(const esp_partition_t *expected,
                                   const ota_v2::Manifest &manifest,
                                   std::string &error) const;
  bool verifyRecoveryBeforeReboot(std::string &error);
  bool restoreRunningBootPartition(const char *primary_failure,
                                   std::string &restore_error);
  bool failClosedAfterBootSelection(const char *failure_code,
                                    std::string &error);
  ota_v2::RunningImageCheckResult
  initiatePostBootRollback(const std::string &failure_code);
  OtaRecoveryStoreResult persistRestrictedIncident(
      const std::string &failure_code,
      ota_v2::RunningImageCheckResult rollback_result);
  void enterRestrictedRecovery(
      const std::string &failure_code,
      ota_v2::RunningImageCheckResult rollback_result,
      OtaRecoveryStoreResult incident_result);
  void initializePartitionStatus();

  ConfigService &config_;
  Diagnostics &diagnostics_;
  OtaRecoveryStore recovery_store_;
  ota_v2::RecoveryRecord recovery_;
  OtaRestrictedRecoveryRecord restricted_incident_;
  OtaRecoveryStoreResult recovery_load_result_{
      OtaRecoveryStoreResult::NotFound};
  std::atomic<bool> in_progress_{false};
  std::atomic<bool> report_pending_{false};
  std::atomic<bool> restricted_recovery_mode_{false};
  // Lock order is workflow_mutex_ -> mutex_ -> Diagnostics high-memory lease.
  // The workflow lock is recursive because an install deliberately flushes
  // persisted milestones through the same reporting path. It serializes all
  // access to recovery_ across ServerSyncTask and OtaMaintenanceTask; never
  // acquire it while already holding mutex_ or a Diagnostics lease.
  mutable SemaphoreHandle_t workflow_mutex_{nullptr};
  mutable SemaphoreHandle_t mutex_{nullptr};
  OtaStatus status_;
};

} // namespace pm
