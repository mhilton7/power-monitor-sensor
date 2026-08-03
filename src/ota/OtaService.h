#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

#include <HTTPClient.h>
#include <WiFiClientSecure.h>

#include "config/ConfigService.h"
#include "diagnostics/Diagnostics.h"
#include "ota/CompactOtaStatus.h"
#include "ota/OtaManifestV2.h"
#include "ota/OtaRecoveryStore.h"

namespace pm {

constexpr std::uint32_t kOtaPartitionSizeBytes = 0x600000U;

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
};

class OtaService {
public:
  OtaService(ConfigService &config, Diagnostics &diagnostics);
  bool begin();
  bool runningImagePendingVerification() const;
  bool checkRunningImage(bool health_checks_passed);
  bool applyFromManifestUrl(const std::string &manifest_url);
  bool parseManifest(const std::string &json, ota_v2::Manifest &manifest,
                     std::string &error) const;
  bool verifyManifest(const ota_v2::Manifest &manifest,
                      std::string &error) const;
  std::string canonicalManifest(const ota_v2::Manifest &manifest) const;
  OtaStatus status() const;
  CompactOtaStatus compactStatus() const;
  bool rollbackAndReboot();
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
                               const std::string &body,
                               std::string &error) const;
  bool postReport(const char *report_state, std::string &error);
  bool flushPendingReportWithLease();
  bool serverTarget(const RuntimeConfig &config, const std::string &url,
                    std::string &target) const;
  bool configureTls(WiFiClientSecure &client,
                    const std::string &ca_pem) const;
  bool persistState(ota_v2::State state, const std::string &failure_code = {},
                    bool pending_reboot = false);
  void setState(ota_v2::State state, const std::string &result,
                const std::string &error = {}, bool persist = true,
                bool report = true);
  std::string reportJson(const char *report_state) const;
  void initializePartitionStatus();

  ConfigService &config_;
  Diagnostics &diagnostics_;
  OtaRecoveryStore recovery_store_;
  ota_v2::RecoveryRecord recovery_;
  std::atomic<bool> in_progress_{false};
  std::atomic<bool> report_pending_{false};
  mutable SemaphoreHandle_t mutex_{nullptr};
  OtaStatus status_;
};

} // namespace pm
