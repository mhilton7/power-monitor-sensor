#include "ota/OtaService.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include <ArduinoJson.h>
#include <ESP.h>
#include <ESPmDNS.h>
#include <HTTPClient.h>
#include <Update.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <esp_app_format.h>
#include <esp_heap_caps.h>
#include <esp_ota_ops.h>
#include <mbedtls/sha256.h>

#include "diagnostics/SerialLogger.h"
#include "network/ResolvedTlsClient.h"
#include "ota/OtaFaultInjection.h"
#include "ota/OtaStageLedger.h"
#include "ota/OtaUpdatePolicy.h"
#include "security/Crypto.h"
#include "version.h"

namespace pm {
namespace {

constexpr std::size_t kManifestMaximumBytes = 16U * 1024U;
constexpr std::size_t kOtaStreamBufferBytes = 4096U;
constexpr std::size_t kImageMetadataBytes =
    sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) +
    sizeof(esp_app_desc_t);
constexpr std::uint16_t kEsp32S3ChipId = 9U;

// A physical 1.0.13 canary proved that reserving the stream buffer in the
// long-lived maintenance task stack pushed idle internal DRAM below the TLS
// admission floor. Keep the exact 4 KiB buffer in internal 8-bit memory (flash
// writes must not depend on PSRAM while its cache can be unavailable), but
// own it only for the active binary transaction. It is allocated after TLS
// admission and destroyed with the transport before Update.end().
class OtaStreamBuffer final {
public:
  OtaStreamBuffer()
      : data_(static_cast<std::uint8_t *>(heap_caps_malloc(
            kOtaStreamBufferBytes, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT))) {}
  ~OtaStreamBuffer() {
    if (data_ != nullptr)
      heap_caps_free(data_);
  }
  OtaStreamBuffer(const OtaStreamBuffer &) = delete;
  OtaStreamBuffer &operator=(const OtaStreamBuffer &) = delete;

  explicit operator bool() const { return data_ != nullptr; }
  std::uint8_t *data() { return data_; }
  constexpr std::size_t size() const { return kOtaStreamBufferBytes; }

private:
  std::uint8_t *data_{nullptr};
};

class OtaTransactionLease final {
public:
  OtaTransactionLease(Diagnostics &diagnostics,
                      const ota_stage::Stage preparing_stage)
      : diagnostics_(diagnostics),
        acquired_(diagnostics_.acquireHighMemoryOperation(
            MemoryOperationContext::TlsPreparing, pdMS_TO_TICKS(5000))) {
    if (acquired_) {
      ota_stage::record(ota_stage::Stage::TransportLeaseAcquired);
      ota_stage::record(preparing_stage);
    }
  }

  ~OtaTransactionLease() {
    if (acquired_) {
      diagnostics_.releaseHighMemoryOperation();
      static constexpr char kOtaOperation[] =
          "/api/v1/device-firmware/ota-operation";
      diagnostics_.recordTlsLifecycleCheckpoint(
          0U, kOtaOperation, sizeof(kOtaOperation) - 1U,
          TlsLifecycleStage::AfterHighMemoryLeaseRelease);
    }
  }

  explicit operator bool() const { return acquired_; }

  bool activate(const ota_stage::Stage active_stage,
                const std::uint32_t bytes_received = 0U,
                const std::uint32_t image_size = 0U) {
    if (!acquired_ || active_) {
      return acquired_ && active_;
    }
    active_ = diagnostics_.transitionHighMemoryOperation(
        MemoryOperationContext::TlsPreparing,
        MemoryOperationContext::TlsActive);
    if (active_) {
      ota_stage::record(active_stage, bytes_received, image_size);
    }
    return active_;
  }

private:
  Diagnostics &diagnostics_;
  bool acquired_{false};
  bool active_{false};
};

class OtaTransportLifecycle final {
public:
  OtaTransportLifecycle(Diagnostics &diagnostics, const std::string &endpoint)
      : diagnostics_(diagnostics), endpoint_(endpoint) {
    record(TlsLifecycleStage::BeforeClientConstruction);
  }

  ~OtaTransportLifecycle() {
    record(TlsLifecycleStage::AfterClientDestruction);
  }

  void record(const TlsLifecycleStage stage) const {
    diagnostics_.recordTlsLifecycleCheckpoint(
        0U, endpoint_.data(), endpoint_.size(), stage);
  }

private:
  Diagnostics &diagnostics_;
  const std::string &endpoint_;
};

class OtaHttpCleanup final {
public:
  OtaHttpCleanup(HTTPClient &http, OtaTransportLifecycle &lifecycle)
      : http_(http), lifecycle_(lifecycle) {}

  ~OtaHttpCleanup() { end(); }

  void end() {
    if (ended_) {
      return;
    }
    http_.end();
    ended_ = true;
    lifecycle_.record(TlsLifecycleStage::AfterHttpEnd);
  }

private:
  HTTPClient &http_;
  OtaTransportLifecycle &lifecycle_;
  bool ended_{false};
};

bool parseHttpsTarget(const std::string &url, std::string &host,
                      std::uint16_t &port) {
  if (url.rfind("https://", 0U) != 0U)
    return false;
  const std::size_t start = 8U;
  const std::size_t end = url.find_first_of("/?#", start);
  if (end != std::string::npos && url[end] == '#')
    return false;
  const std::string authority = url.substr(start, end - start);
  if (authority.empty() || authority.find('@') != std::string::npos ||
      authority.find('\\') != std::string::npos) {
    return false;
  }
  std::string encoded_port;
  if (authority.front() == '[') {
    const std::size_t close = authority.find(']');
    if (close == std::string::npos || close == 1U)
      return false;
    host = authority.substr(1U, close - 1U);
    if (close + 1U < authority.size()) {
      if (authority[close + 1U] != ':')
        return false;
      encoded_port = authority.substr(close + 2U);
    }
  } else {
    const std::size_t colon = authority.rfind(':');
    if (colon != std::string::npos) {
      if (authority.find(':') != colon)
        return false;
      host = authority.substr(0U, colon);
      encoded_port = authority.substr(colon + 1U);
    } else {
      host = authority;
    }
  }
  port = 443U;
  if (!encoded_port.empty()) {
    if (!std::all_of(encoded_port.begin(), encoded_port.end(),
                     [](const char byte) {
                       return byte >= '0' && byte <= '9';
                     })) {
      return false;
    }
    const unsigned long parsed =
        std::strtoul(encoded_port.c_str(), nullptr, 10);
    if (parsed == 0U || parsed > 65535U)
      return false;
    port = static_cast<std::uint16_t>(parsed);
  } else if (authority.back() == ':') {
    return false;
  }
  return !host.empty();
}

bool dotLocalHost(const std::string &host) {
  static constexpr char suffix[] = ".local";
  if (host.size() <= sizeof(suffix) - 1U)
    return false;
  const std::size_t offset = host.size() - (sizeof(suffix) - 1U);
  for (std::size_t index = 0U; index < sizeof(suffix) - 1U; ++index) {
    const char lowered = static_cast<char>(std::tolower(
        static_cast<unsigned char>(host[offset + index])));
    if (lowered != suffix[index])
      return false;
  }
  return true;
}

bool resolveHttpsTarget(const std::string &url, std::string &host,
                        std::uint16_t &port, IPAddress &address,
                        const char *&method) {
  if (!parseHttpsTarget(url, host, port))
    return false;
  const bool literal = address.fromString(host.c_str());
  method = literal ? "literal" : "dns";
  bool resolved = literal || (WiFi.hostByName(host.c_str(), address) == 1 &&
                              static_cast<std::uint32_t>(address) != 0U &&
                              address != INADDR_NONE);
  if (!resolved && dotLocalHost(host)) {
    const std::string query =
        host.substr(0U, host.size() - std::strlen(".local"));
    address = MDNS.queryHost(query.c_str(), 2000U);
    resolved =
        static_cast<std::uint32_t>(address) != 0U && address != INADDR_NONE;
    if (resolved)
      method = "mdns";
  }
  return resolved;
}

bool hostAllowed(const RuntimeConfig &config, const std::string &url) {
  std::string host;
  std::uint16_t port = 443U;
  if (!parseHttpsTarget(url, host, port))
    return false;
  bool constrained = false;
  for (const auto &allowed : config.allowed_server_addresses) {
    if (allowed.empty())
      continue;
    constrained = true;
    if (allowed == host)
      return true;
  }
  return !constrained;
}

bool withinUpdateWindow(const RuntimeConfig &config) {
  if (!config.ota_update_window_enabled)
    return true;
  const std::time_t now = std::time(nullptr);
  if (now < 1'600'000'000)
    return false;
  std::tm utc{};
  gmtime_r(&now, &utc);
  const int start = config.ota_update_window_start_hour;
  const int end = config.ota_update_window_end_hour;
  return start < end ? utc.tm_hour >= start && utc.tm_hour < end
                     : utc.tm_hour >= start || utc.tm_hour < end;
}

std::string partitionLabel(const esp_partition_t *partition) {
  return partition == nullptr || partition->label == nullptr
             ? std::string{}
             : std::string(partition->label);
}

std::string descriptorHash(const esp_app_desc_t &descriptor) {
  return crypto::hexEncode(descriptor.app_elf_sha256,
                           sizeof(descriptor.app_elf_sha256));
}

bool boundedDescriptorString(const char *value, const std::size_t capacity,
                             std::string &output) {
  const std::size_t length = strnlen(value, capacity);
  if (length == 0U || length == capacity)
    return false;
  output.assign(value, length);
  return true;
}

bool validateImageMetadata(
    const std::array<std::uint8_t, kImageMetadataBytes> &metadata,
    const ota_v2::Manifest &manifest, std::string &error) {
  esp_image_header_t image_header{};
  esp_image_segment_header_t segment_header{};
  esp_app_desc_t descriptor{};
  std::memcpy(&image_header, metadata.data(), sizeof(image_header));
  std::memcpy(&segment_header, metadata.data() + sizeof(image_header),
              sizeof(segment_header));
  std::memcpy(&descriptor,
              metadata.data() + sizeof(image_header) + sizeof(segment_header),
              sizeof(descriptor));
  if (image_header.magic != ESP_IMAGE_HEADER_MAGIC ||
      image_header.chip_id != kEsp32S3ChipId ||
      image_header.segment_count == 0U ||
      segment_header.data_len < sizeof(esp_app_desc_t) ||
      descriptor.magic_word != ESP_APP_DESC_MAGIC_WORD) {
    error = "ota_image_metadata_invalid";
    return false;
  }
  std::string project_name;
  std::string firmware_version;
  if (!boundedDescriptorString(descriptor.project_name,
                               sizeof(descriptor.project_name), project_name) ||
      !boundedDescriptorString(descriptor.version, sizeof(descriptor.version),
                               firmware_version)) {
    error = "ota_image_descriptor_invalid";
    return false;
  }
  if (project_name != manifest.project_name) {
    error = "ota_image_project_mismatch";
    return false;
  }
  if (firmware_version != manifest.version) {
    error = "ota_image_version_mismatch";
    return false;
  }
  if (!crypto::constantTimeEqual(descriptorHash(descriptor),
                                 manifest.build_hash)) {
    error = "ota_image_build_hash_mismatch";
    return false;
  }
  return true;
}

template <std::size_t Capacity>
bool copyCompact(std::array<char, Capacity> &target,
                 const std::string &source) {
  const int written =
      std::snprintf(target.data(), target.size(), "%s", source.c_str());
  return written >= 0 && static_cast<std::size_t>(written) < target.size();
}

template <std::size_t Capacity>
bool copyCompact(std::array<char, Capacity> &target, const char *source) {
  const int written = std::snprintf(target.data(), target.size(), "%s",
                                    source == nullptr ? "" : source);
  return written >= 0 && static_cast<std::size_t>(written) < target.size();
}

bool unavailableManifest(const std::string &json) {
  JsonDocument document;
  if (deserializeJson(document, json) || !document.is<JsonObject>() ||
      document.as<JsonObjectConst>().size() != 2U ||
      !document["available"].is<bool>() ||
      document["available"].as<bool>() ||
      !document["protocol_version"].is<const char *>()) {
    return false;
  }
  return std::string(document["protocol_version"].as<const char *>()) ==
         version::PROTOCOL;
}

} // namespace

OtaService::OtaService(ConfigService &config, Diagnostics &diagnostics)
    : config_(config), diagnostics_(diagnostics) {
  mutex_ = xSemaphoreCreateMutex();
  initializePartitionStatus();
}

bool OtaService::begin() {
  const auto &identity = config_.identity();
  ota_stage::beginBoot(
      identity.boot_id.c_str(), version::FIRMWARE, runningBuildHash().c_str(),
      diag::SerialLogger::instance().bootCount(),
      static_cast<std::uint32_t>(esp_reset_reason()));
  initializePartitionStatus();
  ota_v2::RecoveryRecord recovered;
  if (!recovery_store_.load(recovered))
    return true;
  recovery_ = recovered;
  if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(250)) != pdTRUE)
    return false;
  status_.deployment_id = recovered.deployment_id;
  status_.release_id = recovered.release_id;
  status_.attempt = recovered.attempt;
  status_.state = recovered.state;
  status_.target_version = recovered.target_version;
  status_.target_sha256 = recovered.target_sha256;
  status_.target_build_hash = recovered.target_build_hash;
  status_.image_size = recovered.image_size;
  status_.bytes_received = recovered.bytes_received;
  status_.progress_percent = recovered.progress_percent;
  status_.pending_reboot = recovered.pending_reboot;
  status_.last_error = recovered.failure_code;
  status_.last_result = ota_v2::stateName(recovered.state);
  xSemaphoreGive(mutex_);

  if (recovered.pending_reboot) {
    ota_stage::bindDeployment(recovered.deployment_id.c_str(),
                              recovered.attempt);
    ota_stage::record(ota_stage::Stage::PostBootImageDetected,
                      recovered.bytes_received, recovered.image_size, false,
                      recovered.pending_reboot);
    const bool running_pending = runningImagePendingVerification();
    const std::string running_build_hash = runningBuildHash();
    const ota_v2::PostBootAction action = ota_v2::classifyPostBoot(
        running_pending, true, version::FIRMWARE, running_build_hash,
        recovered.target_version, recovered.target_build_hash,
        recovered.previous_version, recovered.previous_build_hash, true);
    if (action == ota_v2::PostBootAction::Validate) {
      if (running_pending) {
        setState(ota_v2::State::PostBootValidation, "post_boot_validation", {},
                 true, false);
      } else {
        if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(250)) == pdTRUE) {
          status_.pending_reboot = false;
          status_.progress_percent = 100U;
          xSemaphoreGive(mutex_);
        }
        setState(ota_v2::State::Validated,
                 "installed_and_verified_recovered", {}, true);
      }
    } else if (action == ota_v2::PostBootAction::ReportRollback) {
      ota_stage::record(ota_stage::Stage::RollbackDetected,
                        recovered.bytes_received, recovered.image_size);
      if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(250)) == pdTRUE) {
        status_.rollback_detected = true;
        status_.pending_reboot = false;
        xSemaphoreGive(mutex_);
      }
      setState(ota_v2::State::RolledBack, "automatic_rollback",
               recovered.failure_code.empty() ? "ota_rollback_detected"
                                              : recovered.failure_code,
               true);
      report_pending_.store(true, std::memory_order_release);
    } else if (action == ota_v2::PostBootAction::Rollback) {
      setState(ota_v2::State::Failed, "post_boot_identity_rejected",
               version::FIRMWARE != recovered.target_version
                   ? "ota_post_boot_version_mismatch"
                   : "ota_post_boot_build_hash_mismatch",
               true, false);
    } else {
      setState(ota_v2::State::Failed, "failed",
               "ota_post_boot_version_unexpected", true);
      report_pending_.store(true, std::memory_order_release);
    }
  } else if (recovered.state != ota_v2::State::Idle) {
    report_pending_.store(true, std::memory_order_release);
  }
  return true;
}

bool OtaService::runningImagePendingVerification() const {
  const esp_partition_t *running = esp_ota_get_running_partition();
  esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
  return running != nullptr &&
         esp_ota_get_state_partition(running, &state) == ESP_OK &&
         state == ESP_OTA_IMG_PENDING_VERIFY;
}

bool OtaService::checkRunningImage(const bool health_checks_passed) {
  const esp_partition_t *running = esp_ota_get_running_partition();
  esp_ota_img_states_t image_state = ESP_OTA_IMG_UNDEFINED;
  if (running == nullptr ||
      esp_ota_get_state_partition(running, &image_state) != ESP_OK) {
    return false;
  }
  if (image_state != ESP_OTA_IMG_PENDING_VERIFY)
    return true;

  const std::string running_build_hash = runningBuildHash();
  const ota_v2::PostBootAction action = ota_v2::classifyPostBoot(
      true, health_checks_passed, version::FIRMWARE, running_build_hash,
      recovery_.target_version, recovery_.target_build_hash,
      recovery_.previous_version, recovery_.previous_build_hash,
      recovery_.pending_reboot);
  setState(ota_v2::State::PostBootValidation, "post_boot_validation", {},
           true, false);
  if (action == ota_v2::PostBootAction::Validate &&
      esp_ota_mark_app_valid_cancel_rollback() == ESP_OK) {
    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(250)) == pdTRUE) {
      status_.pending_reboot = false;
      status_.progress_percent = 100U;
      xSemaphoreGive(mutex_);
    }
    setState(ota_v2::State::Validated, "installed_and_verified", {}, true);
    report_pending_.store(true, std::memory_order_release);
    ota_stage::record(ota_stage::Stage::PostBootValidated,
                      recovery_.bytes_received, recovery_.image_size);
    PM_LOG_INFO("OTA", "POST_BOOT_VALIDATED",
                "version=%s build_hash=%s rollback_cancelled=true",
                version::FIRMWARE, runningBuildHash().c_str());
    return true;
  }

  std::string failure_code = "ota_post_boot_health_failed";
  if (!recovery_.pending_reboot) {
    failure_code = "ota_post_boot_recovery_missing";
  } else if (version::FIRMWARE != recovery_.target_version) {
    failure_code = "ota_post_boot_version_mismatch";
  } else if (running_build_hash != recovery_.target_build_hash) {
    failure_code = "ota_post_boot_build_hash_mismatch";
  } else if (action == ota_v2::PostBootAction::Validate) {
    failure_code = "ota_mark_valid_failed";
  }
  setState(ota_v2::State::Failed, "post_boot_failed",
           failure_code, true, false);
  PM_LOG_FATAL("OTA", "POST_BOOT_REJECTED",
               "error=PM-OTA-006 health_checks=%s rollback=automatic",
               health_checks_passed ? "passed" : "failed");
  return esp_ota_mark_app_invalid_rollback_and_reboot() == ESP_OK;
}

bool OtaService::applyFromManifestUrl(const std::string &manifest_url) {
  if (in_progress_.exchange(true, std::memory_order_acq_rel)) {
    PM_LOG_WARN("OTA", "UPDATE_REJECTED",
                "error=PM-OTA-002 reason=already_in_progress");
    return false;
  }
  struct ProgressRelease final {
    std::atomic<bool> &flag;
    ~ProgressRelease() { flag.store(false, std::memory_order_release); }
  } progress_release{in_progress_};
  ota_stage::record(ota_stage::Stage::WorkflowLockAcquired);

  const RuntimeConfig active_config = config_.config();
  if (config_.safeMode()) {
    setState(ota_v2::State::Failed, "rejected", "ota_disabled_in_safe_mode",
             false);
    return false;
  }

  bool install_ready = false;
  {
    setState(ota_v2::State::ManifestCheck, "manifest_check", {}, false);
    std::string manifest_json;
    std::string error;
    if (!fetchText(manifest_url, manifest_json, kManifestMaximumBytes, error)) {
      setState(ota_v2::State::Failed, "failed", error, false);
      return false;
    }
    ota_stage::record(ota_stage::Stage::ManifestResponseReceived);
    if (unavailableManifest(manifest_json)) {
      setState(ota_v2::State::ManifestUnavailable, "current", {}, false);
      return false;
    }
    ota_v2::Manifest manifest;
    if (!parseManifest(manifest_json, manifest, error)) {
      setState(ota_v2::State::ManifestRejected, "manifest_rejected", error,
               false);
      return false;
    }
    ota_stage::record(ota_stage::Stage::ManifestParsed);

    setState(ota_v2::State::ManifestReceived, "manifest_received", {}, false);
    if (!verifyManifest(manifest, error)) {
      setState(ota_v2::State::ManifestRejected, "manifest_rejected", error,
               false);
      return false;
    }

    const ota_v2::RecoveryRecord prior = recovery_;
    if (!prior.deployment_id.empty() &&
        prior.deployment_id == manifest.deployment_id) {
      const bool same_waiting_attempt =
          manifest.attempt == prior.attempt &&
          prior.state == ota_v2::State::WaitingForSchedule &&
          prior.release_id == manifest.release_id &&
          prior.target_version == manifest.version &&
          prior.target_sha256 == manifest.sha256 &&
          prior.target_build_hash == manifest.build_hash;
      if (prior.release_id != manifest.release_id ||
          manifest.attempt < prior.attempt ||
          (manifest.attempt == prior.attempt && !same_waiting_attempt)) {
        setState(ota_v2::State::ManifestRejected, "manifest_rejected",
                 prior.release_id != manifest.release_id
                     ? "ota_deployment_release_changed"
                     : "ota_attempt_replayed",
                 false);
        return false;
      }
    }

    const std::string last_report_state =
        prior.deployment_id == manifest.deployment_id &&
                prior.release_id == manifest.release_id &&
                manifest.attempt == prior.attempt
            ? prior.last_report_state
            : std::string{};
    recovery_ = {};
    recovery_.deployment_id = manifest.deployment_id;
    recovery_.release_id = manifest.release_id;
    recovery_.target_version = manifest.version;
    recovery_.target_sha256 = manifest.sha256;
    recovery_.target_build_hash = manifest.build_hash;
    recovery_.previous_version = version::FIRMWARE;
    recovery_.previous_build_hash = runningBuildHash();
    recovery_.image_size = manifest.size_bytes;
    recovery_.attempt = manifest.attempt;
    recovery_.last_report_state = last_report_state;
    ota_stage::bindDeployment(manifest.deployment_id.c_str(), manifest.attempt);
    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(250)) == pdTRUE) {
      status_.deployment_id = manifest.deployment_id;
      status_.release_id = manifest.release_id;
      status_.attempt = manifest.attempt;
      status_.target_version = manifest.version;
      status_.target_sha256 = manifest.sha256;
      status_.target_build_hash = manifest.build_hash;
      status_.image_size = manifest.size_bytes;
      status_.bytes_received = 0U;
      status_.progress_percent = 0U;
      status_.rollback_detected = false;
      status_.pending_reboot = false;
      xSemaphoreGive(mutex_);
    }
    setState(ota_v2::State::ManifestAuthenticated,
             "manifest_authenticated", {}, true);
    ota_stage::record(ota_stage::Stage::ManifestAuthenticated);
    if (flushPendingReportWithLease()) {
      ota_stage::record(ota_stage::Stage::ManifestMilestoneReported);
    }

    if (!withinUpdateWindow(active_config)) {
      setState(ota_v2::State::WaitingForSchedule, "waiting_for_schedule",
               "outside_ota_update_window", true);
      return false;
    }
    setState(ota_v2::State::DownloadStarting, "download_starting", {}, true);
    if (flushPendingReportWithLease()) {
      ota_stage::record(ota_stage::Stage::DownloadMilestoneReported, 0U,
                        manifest.size_bytes);
    }
    if (!downloadAndApply(manifest, error)) {
      setState(ota_v2::State::Failed, "failed", error, true);
      (void)flushPendingReportWithLease();
      return false;
    }
    // All stream/TLS/Update objects have been destroyed before durable state
    // and report catch-up touch Preferences or begin another TLS session.
    setState(ota_v2::State::PartitionWritten, "partition_written", {}, true);
    (void)flushPendingReportWithLease();
    ota_stage::record(ota_stage::Stage::RecoveryRecordPersisted,
                      status().bytes_received, status().image_size);
    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(250)) == pdTRUE) {
      status_.pending_reboot = true;
      status_.progress_percent = 100U;
      xSemaphoreGive(mutex_);
    }
    setState(ota_v2::State::RebootPending, "verified_pending_reboot", {},
             true);
    if (flushPendingReportWithLease()) {
      ota_stage::record(ota_stage::Stage::RebootMilestoneReported,
                        status().bytes_received, status().image_size, false,
                        true);
    }
    setState(ota_v2::State::Rebooting, "rebooting", {}, true);
    (void)flushPendingReportWithLease();
    ota_stage::record(ota_stage::Stage::RebootScheduled,
                      status().bytes_received, status().image_size, false,
                      true);
    if (ota_fault::configured(ota_fault::Point::BeforeReboot)) {
      setState(ota_v2::State::Failed, "fault_injected",
               ota_fault::failureCode(ota_fault::Point::BeforeReboot), true,
               false);
      return false;
    }
    install_ready = true;
  }

  if (install_ready) {
    PM_LOG_INFO("OTA", "REBOOTING_TO_PENDING_IMAGE",
                "target_version=%s deployment_id=%s",
                status().target_version.c_str(),
                status().deployment_id.c_str());
    delay(100U);
    ESP.restart();
  }
  return install_ready;
}

bool OtaService::parseManifest(const std::string &json,
                               ota_v2::Manifest &manifest,
                               std::string &error) const {
  return ota_v2::parseManifest(json, manifest, error);
}

bool OtaService::verifyManifest(const ota_v2::Manifest &manifest,
                                std::string &error) const {
  crypto::Key32 key{};
  if (!config_.otaManifestKey(key)) {
    error = "ota_manifest_key_unavailable";
    return false;
  }
  const std::string canonical = ota_v2::canonicalManifest(manifest);
  crypto::Key32 digest = crypto::hmacSha256(
      key.data(), key.size(),
      reinterpret_cast<const std::uint8_t *>(canonical.data()),
      canonical.size());
  const std::string expected =
      crypto::base64UrlEncode(digest.data(), digest.size());
  key.fill(0U);
  digest.fill(0U);
  if (canonical.empty() ||
      !crypto::constantTimeEqual(expected, manifest.manifest_hmac)) {
    error = "ota_manifest_hmac_invalid";
    PM_LOG_ERROR("OTA", "MANIFEST_AUTHENTICATION_FAILED",
                 "error=PM-OTA-005 algorithm=HMAC-SHA256");
    return false;
  }

  ota_v2::PolicyContext policy;
  policy.device_id = config_.identity().device_id;
  policy.current_version = version::FIRMWARE;
  policy.current_protocol = version::PROTOCOL;
  policy.hardware_target = version::HARDWARE_TARGET;
  policy.project_name = ota_v2::kProjectName;
  policy.now_unix_seconds = static_cast<std::int64_t>(std::time(nullptr));
  policy.partition_size_bytes = updatePartitionSize();
  return ota_v2::validatePolicy(manifest, policy, error);
}

std::string
OtaService::canonicalManifest(const ota_v2::Manifest &manifest) const {
  return ota_v2::canonicalManifest(manifest);
}

OtaStatus OtaService::status() const {
  if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(100)) != pdTRUE) {
    OtaStatus unavailable;
    unavailable.in_progress = in_progress_.load(std::memory_order_acquire);
    unavailable.last_result = "unavailable";
    unavailable.last_error = "ota_status_busy";
    return unavailable;
  }
  OtaStatus copy = status_;
  xSemaphoreGive(mutex_);
  copy.in_progress = in_progress_.load(std::memory_order_acquire);
  return copy;
}

CompactOtaStatus OtaService::compactStatus() const {
  const OtaStatus snapshot = status();
  const ota_stage::Snapshot lifecycle = ota_stage::current();
  const ota_stage::Snapshot previous = ota_stage::previousBoot();
  CompactOtaStatus compact;
  compact.protocol_version =
      static_cast<std::uint8_t>(snapshot.protocol_version);
  compact.bytes_received = snapshot.bytes_received;
  compact.image_size = snapshot.image_size;
  compact.progress_percent = snapshot.progress_percent;
  compact.in_progress = snapshot.in_progress;
  compact.pending_reboot = snapshot.pending_reboot;
  compact.rollback_supported = snapshot.rollback_supported;
  compact.rollback_detected = snapshot.rollback_detected;
  compact.lifecycle_stack_high_water_bytes =
      lifecycle.task_stack_high_water_bytes;
  compact.previous_boot_bytes_received = previous.bytes_received;
  compact.previous_boot_attempt = previous.attempt;
  compact.previous_boot_reset_reason_code = previous.reset_reason_code;
  compact.previous_boot_update_open = previous.update_open;
  compact.previous_boot_reboot_expected = previous.reboot_expected;
  compact.truncated =
      !copyCompact(compact.authentication_mode,
                   snapshot.authentication_mode) ||
      !copyCompact(compact.state, ota_v2::stateName(snapshot.state)) ||
      !copyCompact(compact.deployment_id, snapshot.deployment_id) ||
      !copyCompact(compact.target_version, snapshot.target_version) ||
      !copyCompact(compact.target_sha256, snapshot.target_sha256) ||
      !copyCompact(compact.running_partition, snapshot.running_partition) ||
      !copyCompact(compact.target_partition, snapshot.target_partition) ||
      !copyCompact(compact.last_result, snapshot.last_result) ||
      !copyCompact(compact.lifecycle_stage,
                   ota_stage::stageName(lifecycle.stage)) ||
      !copyCompact(compact.lifecycle_operation_context,
                   lifecycle.operation_context.data()) ||
      !copyCompact(compact.lifecycle_task, lifecycle.current_task.data()) ||
      !copyCompact(compact.previous_boot_stage,
                   ota_stage::stageName(previous.stage)) ||
      !copyCompact(compact.previous_boot_id, previous.boot_id.data()) ||
      !copyCompact(compact.previous_boot_firmware,
                   previous.firmware_version.data()) ||
      !copyCompact(compact.previous_boot_build_hash,
                   previous.build_hash.data()) ||
      !copyCompact(compact.previous_boot_deployment_id,
                   previous.deployment_id.data()) ||
      !copyCompact(compact.previous_boot_last_error,
                   previous.last_error.data());
  return compact;
}

bool OtaService::rollbackAndReboot() {
  const bool possible = esp_ota_check_rollback_is_possible();
  if (!possible)
    return false;
  setState(ota_v2::State::RolledBack, "manual_rollback", {}, true);
  report_pending_.store(true, std::memory_order_release);
  (void)flushPendingReportWithLease();
  return esp_ota_mark_app_invalid_rollback_and_reboot() == ESP_OK;
}

bool OtaService::pendingReport(std::string &body) const {
  if (!report_pending_.load(std::memory_order_acquire)) {
    body.clear();
    return false;
  }
  const char *desired = ota_v2::reportMilestoneForState(recovery_.state);
  const char *next =
      ota_v2::nextReportMilestone(recovery_.last_report_state, desired);
  body = next == nullptr ? std::string{} : reportJson(next);
  return !body.empty();
}

bool OtaService::hasPendingReport() const {
  return report_pending_.load(std::memory_order_acquire);
}

bool OtaService::flushPendingReport() {
  if (!hasPendingReport())
    return true;
  return flushPendingReportWithLease();
}

bool OtaService::flushPendingReportWithLease() {
  const char *desired = ota_v2::reportMilestoneForState(recovery_.state);
  const char *next =
      ota_v2::nextReportMilestone(recovery_.last_report_state, desired);
  if (next == nullptr) {
    report_pending_.store(false, std::memory_order_release);
    return true;
  }
  // One call performs exactly one HTTPS transaction. Catch-up is deliberately
  // spread across maintenance iterations (or explicit workflow checkpoints),
  // so no report burst overlaps the binary stream or retains TLS allocations.
  std::string error;
  return postReport(next, error);
}

void OtaService::markPendingReportDelivered() {
  report_pending_.store(false, std::memory_order_release);
}

std::string OtaService::runningBuildHash() {
  const esp_app_desc_t *descriptor = esp_ota_get_app_description();
  return descriptor == nullptr ? std::string{} : descriptorHash(*descriptor);
}

std::uint32_t OtaService::updatePartitionSize() {
  const esp_partition_t *partition = esp_ota_get_next_update_partition(nullptr);
  return partition == nullptr ? 0U
                              : static_cast<std::uint32_t>(partition->size);
}

bool OtaService::serverTarget(const RuntimeConfig &config,
                              const std::string &url,
                              std::string &target) const {
  target.clear();
  if (config.server_url.empty() ||
      url.compare(0U, config.server_url.size(), config.server_url) != 0 ||
      url.size() <= config.server_url.size() ||
      url[config.server_url.size()] != '/') {
    return false;
  }
  target = url.substr(config.server_url.size());
  std::string canonical;
  if (!crypto::canonicalTarget(target, canonical)) {
    target.clear();
    return false;
  }
  target = canonical;
  return true;
}

bool OtaService::addDeviceAuthentication(HTTPClient &http, const char *method,
                                         const std::string &target,
                                         const std::string &body,
                                         std::string &error) const {
  const std::time_t now = std::time(nullptr);
  if (now < 1'600'000'000) {
    error = "ota_time_not_trusted";
    return false;
  }
  const DeviceIdentity identity = config_.identity();
  crypto::Key32 outbound{};
  crypto::Key32 inbound{};
  if (!identity.enrolled || identity.device_id.empty() ||
      !config_.directionalKeys(outbound, inbound)) {
    error = "ota_device_credentials_unavailable";
    return false;
  }
  const std::string timestamp = std::to_string(now);
  const std::string nonce = crypto::randomHex(16U);
  const std::string body_hash = crypto::sha256Hex(
      reinterpret_cast<const std::uint8_t *>(body.data()), body.size());
  const std::string canonical = crypto::canonicalRequest(
      method, target, timestamp, nonce, body_hash);
  const std::string signature =
      crypto::hmacSha256Hex(outbound.data(), outbound.size(), canonical);
  http.addHeader("X-PM-Protocol", version::PROTOCOL);
  http.addHeader("X-PM-Device-ID", identity.device_id.c_str());
  http.addHeader("X-PM-Timestamp", timestamp.c_str());
  http.addHeader("X-PM-Nonce", nonce.c_str());
  http.addHeader("X-PM-Content-SHA256", body_hash.c_str());
  http.addHeader("X-PM-Signature", signature.c_str());
  outbound.fill(0U);
  inbound.fill(0U);
  return true;
}

bool OtaService::fetchText(const std::string &url, std::string &body,
                           const std::size_t maximum_bytes,
                           std::string &error) const {
  const RuntimeConfig active_config = config_.config();
  std::string target;
  if (!serverTarget(active_config, url, target) ||
      !hostAllowed(active_config, url)) {
    error = "ota_server_origin_required";
    return false;
  }
  std::string hostname;
  std::uint16_t port = 443U;
  IPAddress address;
  const char *method = "none";
  if (!resolveHttpsTarget(url, hostname, port, address, method)) {
    error = "ota_dns_resolution_failed";
    return false;
  }
  OtaTransactionLease lease(diagnostics_,
                            ota_stage::Stage::ManifestPreparing);
  if (!lease) {
    error = "ota_high_memory_lease_unavailable";
    return false;
  }
  OtaTransportLifecycle lifecycle(diagnostics_, target);
  ResolvedTlsClient client;
  if (!configureTls(client, active_config.server_ca_pem)) {
    error = "tls_ca_not_configured";
    return false;
  }
  lifecycle.record(TlsLifecycleStage::AfterTlsConfiguration);
  client.setResolvedEndpoint(address, hostname, port);
  HTTPClient http;
  OtaHttpCleanup cleanup(http, lifecycle);
  http.setConnectTimeout(5000);
  http.setTimeout(10000);
  if (!http.begin(client, url.c_str()) ||
      !addDeviceAuthentication(http, "GET", target, {}, error)) {
    return false;
  }
  lifecycle.record(TlsLifecycleStage::AfterHttpBegin);
  if (!lease.activate(ota_stage::Stage::ManifestRequest)) {
    error = "ota_tls_context_transition_failed";
    return false;
  }
  const int http_status = http.GET();
  lifecycle.record(TlsLifecycleStage::AfterRequest);
  const int content_length = http.getSize();
  if (http_status != 200 || content_length < 0 ||
      content_length > static_cast<int>(maximum_bytes)) {
    error = http_status == 200 ? "ota_manifest_length_invalid"
                               : "ota_manifest_download_failed";
    return false;
  }
  WiFiClient *stream = http.getStreamPtr();
  if (stream == nullptr) {
    error = "ota_manifest_stream_unavailable";
    return false;
  }
  body.clear();
  body.reserve(static_cast<std::size_t>(content_length));
  std::array<std::uint8_t, 1024U> buffer{};
  std::uint64_t last_progress_ms = millis();
  while (body.size() < static_cast<std::size_t>(content_length)) {
    const int available = stream->available();
    if (available <= 0) {
      if (!http.connected() || millis() - last_progress_ms > 10'000U) {
        error = "ota_manifest_stream_interrupted";
        return false;
      }
      vTaskDelay(pdMS_TO_TICKS(2));
      continue;
    }
    const std::size_t wanted = std::min<std::size_t>(
        buffer.size(), std::min<std::size_t>(
                           static_cast<std::size_t>(available),
                           static_cast<std::size_t>(content_length) -
                               body.size()));
    const int count = stream->readBytes(buffer.data(), wanted);
    if (count <= 0) {
      error = "ota_manifest_stream_interrupted";
      return false;
    }
    body.append(reinterpret_cast<const char *>(buffer.data()),
                static_cast<std::size_t>(count));
    last_progress_ms = millis();
  }
  cleanup.end();
  return body.size() == static_cast<std::size_t>(content_length);
}

bool OtaService::downloadAndApply(const ota_v2::Manifest &manifest,
                                  std::string &error) {
  const RuntimeConfig active_config = config_.config();
  const std::string image_url = active_config.server_url + manifest.download_path;
  std::string target;
  if (!serverTarget(active_config, image_url, target) ||
      !hostAllowed(active_config, image_url)) {
    error = "ota_image_origin_invalid";
    return false;
  }
  const esp_partition_t *update_partition =
      esp_ota_get_next_update_partition(nullptr);
  if (update_partition == nullptr || manifest.size_bytes > update_partition->size) {
    error = "ota_partition_too_small";
    return false;
  }
  if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(250)) == pdTRUE) {
    status_.target_partition = partitionLabel(update_partition);
    xSemaphoreGive(mutex_);
  }

  std::uint32_t received = 0U;
  bool update_open = false;
  bool extra_bytes = false;
  bool protocol_seen = false;
  std::size_t protocol_index = 0U;
  ota_v2::StreamTracker stream_tracker(manifest.size_bytes);
  crypto::Key32 digest{};
  const auto failUpdate = [&update_open]() {
    if (update_open) {
      Update.abort();
      update_open = false;
    }
  };
  const auto scanProtocol = [&protocol_index, &protocol_seen](
                                const std::uint8_t *data,
                                const std::size_t length) {
    static constexpr char marker[] = PM_PROTOCOL_VERSION;
    for (std::size_t index = 0U; index < length && !protocol_seen; ++index) {
      const char byte = static_cast<char>(data[index]);
      if (byte == marker[protocol_index]) {
        ++protocol_index;
        protocol_seen = protocol_index == sizeof(marker) - 1U;
      } else {
        protocol_index = byte == marker[0] ? 1U : 0U;
      }
    }
  };

  std::string hostname;
  std::uint16_t port = 443U;
  IPAddress address;
  const char *resolution_method = "none";
  if (!resolveHttpsTarget(image_url, hostname, port, address,
                          resolution_method)) {
    error = "ota_dns_resolution_failed";
    return false;
  }
  // The transport objects and their high-memory lease live only inside this
  // scope. Update.end() runs after the scope so flash finalization never
  // competes with a retained HTTP/TLS object graph.
  {
  OtaTransactionLease lease(diagnostics_,
                            ota_stage::Stage::DownloadPreparing);
  if (!lease) {
    error = "ota_high_memory_lease_unavailable";
    return false;
  }
  OtaTransportLifecycle lifecycle(diagnostics_, target);
  ResolvedTlsClient client;
  if (!configureTls(client, active_config.server_ca_pem)) {
    error = "tls_ca_not_configured";
    return false;
  }
  lifecycle.record(TlsLifecycleStage::AfterTlsConfiguration);
  client.setResolvedEndpoint(address, hostname, port);
  HTTPClient http;
  OtaHttpCleanup cleanup(http, lifecycle);
  http.setConnectTimeout(5000);
  http.setTimeout(15000);
  if (!http.begin(client, image_url.c_str()) ||
      !addDeviceAuthentication(http, "GET", target, {}, error)) {
    return false;
  }
  lifecycle.record(TlsLifecycleStage::AfterHttpBegin);
  if (!lease.activate(ota_stage::Stage::FirmwareRequest, 0U,
                      manifest.size_bytes)) {
    error = "ota_tls_context_transition_failed";
    return false;
  }
  const int http_status = http.GET();
  lifecycle.record(TlsLifecycleStage::AfterRequest);
  const int content_length = http.getSize();
  if (http_status != 200 ||
      content_length != static_cast<int>(manifest.size_bytes)) {
    error = "ota_image_size_or_status_invalid";
    return false;
  }
  ota_stage::record(ota_stage::Stage::FirmwareResponseHeaders, 0U,
                    manifest.size_bytes);
  WiFiClient *stream = http.getStreamPtr();
  if (stream == nullptr) {
    error = "ota_image_stream_unavailable";
    return false;
  }
  // DownloadStarting was persisted before this request. Avoid Preferences,
  // JSON and flash metadata churn while mbedTLS and Update own scarce DRAM;
  // the RTC ledger below is the crash-safe streaming evidence.
  setState(ota_v2::State::Downloading, "downloading", {}, false);
  ota_stage::record(ota_stage::Stage::ImageMetadataReceived, 0U,
                    manifest.size_bytes);

  std::array<std::uint8_t, kImageMetadataBytes> metadata{};
  std::size_t metadata_received = 0U;
  std::uint64_t last_progress_ms = millis();
  while (metadata_received < metadata.size()) {
    const int available = stream->available();
    if (available <= 0) {
      if (!http.connected() || millis() - last_progress_ms > 15'000U) {
        error = "ota_image_stream_interrupted";
        return false;
      }
      vTaskDelay(pdMS_TO_TICKS(2));
      continue;
    }
    const std::size_t wanted = std::min<std::size_t>(
        metadata.size() - metadata_received,
        static_cast<std::size_t>(available));
    const int count = stream->readBytes(metadata.data() + metadata_received,
                                        wanted);
    if (count <= 0) {
      error = "ota_image_stream_interrupted";
      return false;
    }
    metadata_received += static_cast<std::size_t>(count);
    last_progress_ms = millis();
  }
  if (!validateImageMetadata(metadata, manifest, error)) {
    return false;
  }
  ota_stage::record(ota_stage::Stage::ImageMetadataValidated, 0U,
                    manifest.size_bytes);
  if (ota_fault::configured(ota_fault::Point::AfterMetadata)) {
    error = ota_fault::failureCode(ota_fault::Point::AfterMetadata);
    return false;
  }
  OtaStreamBuffer stream_buffer;
  if (!stream_buffer) {
    error = "ota_internal_stream_buffer_unavailable";
    return false;
  }
  if (!Update.begin(manifest.size_bytes, U_FLASH)) {
    error = "ota_partition_unavailable";
    return false;
  }
  update_open = true;
  ota_stage::record(ota_stage::Stage::UpdateBeginCompleted,
                    static_cast<std::uint32_t>(metadata.size()),
                    manifest.size_bytes, true);
  if (ota_fault::configured(ota_fault::Point::AfterUpdateBegin)) {
    error = ota_fault::failureCode(ota_fault::Point::AfterUpdateBegin);
    Update.abort();
    update_open = false;
    return false;
  }

  mbedtls_sha256_context hash;
  mbedtls_sha256_init(&hash);
  mbedtls_sha256_starts_ret(&hash, 0);
  const bool metadata_written =
      !ota_fault::configured(ota_fault::Point::BeforeFirstByte) &&
      Update.write(metadata.data(), metadata.size()) == metadata.size();
  if (!stream_tracker.accept(metadata.size(), metadata_written)) {
    error = ota_v2::streamFailureCode(stream_tracker.failure());
    failUpdate();
    mbedtls_sha256_free(&hash);
    return false;
  }
  mbedtls_sha256_update_ret(&hash, metadata.data(), metadata.size());
  scanProtocol(metadata.data(), metadata.size());
  received = static_cast<std::uint32_t>(metadata.size());
  ota_stage::record(ota_stage::Stage::FirstBytesWritten, received,
                    manifest.size_bytes, true);
  bool halfway_fault_checked = false;
  while (received < manifest.size_bytes) {
    const int available = stream->available();
    if (available <= 0) {
      if (!http.connected() || millis() - last_progress_ms > 15'000U) {
        if (http.connected())
          stream_tracker.timeout();
        else
          stream_tracker.connectionReset();
        error = ota_v2::streamFailureCode(stream_tracker.failure());
        failUpdate();
        mbedtls_sha256_free(&hash);
        return false;
      }
      vTaskDelay(pdMS_TO_TICKS(2));
      continue;
    }
    const std::size_t wanted = std::min<std::size_t>(
        stream_buffer.size(), std::min<std::uint32_t>(
                           static_cast<std::uint32_t>(available),
                           manifest.size_bytes - received));
    const int count = stream->readBytes(stream_buffer.data(), wanted);
    const bool written =
        count > 0 &&
        Update.write(stream_buffer.data(), static_cast<std::size_t>(count)) ==
            static_cast<std::size_t>(count);
    if (count <= 0 ||
        !stream_tracker.accept(count > 0 ? static_cast<std::size_t>(count) : 0U,
                               written)) {
      error = count <= 0 ? "ota_image_connection_reset"
                         : ota_v2::streamFailureCode(stream_tracker.failure());
      failUpdate();
      mbedtls_sha256_free(&hash);
      return false;
    }
    mbedtls_sha256_update_ret(&hash, stream_buffer.data(),
                              static_cast<std::size_t>(count));
    scanProtocol(stream_buffer.data(), static_cast<std::size_t>(count));
    received += static_cast<std::uint32_t>(count);
    if (!halfway_fault_checked && received >= manifest.size_bytes / 2U) {
      halfway_fault_checked = true;
      if (ota_fault::configured(
              ota_fault::Point::HalfwayThroughDownload)) {
        error = ota_fault::failureCode(
            ota_fault::Point::HalfwayThroughDownload);
        failUpdate();
        mbedtls_sha256_free(&hash);
        return false;
      }
    }
    last_progress_ms = millis();
    if ((received & 0xFFFFU) < static_cast<std::uint32_t>(count) ||
        received == manifest.size_bytes) {
      ota_stage::record(ota_stage::Stage::Streaming, received,
                        manifest.size_bytes, true);
    }
    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(50)) == pdTRUE) {
      status_.bytes_received = received;
      status_.progress_percent = static_cast<std::uint8_t>(
          (static_cast<std::uint64_t>(received) * 100U) /
          manifest.size_bytes);
      xSemaphoreGive(mutex_);
    }
  }
  vTaskDelay(pdMS_TO_TICKS(2));
  extra_bytes = stream->available() > 0;
  mbedtls_sha256_finish_ret(&hash, digest.data());
  mbedtls_sha256_free(&hash);
  ota_stage::record(ota_stage::Stage::ShaFinalized, received,
                    manifest.size_bytes, true);
  ota_stage::record(ota_stage::Stage::StreamComplete, received,
                    manifest.size_bytes, true);
  if (ota_fault::configured(ota_fault::Point::AfterCompleteDownload)) {
    error = ota_fault::failureCode(ota_fault::Point::AfterCompleteDownload);
    failUpdate();
    return false;
  }
  cleanup.end();
  }
  ota_stage::record(ota_stage::Stage::HttpTransportDestroyed, received,
                    manifest.size_bytes, true, false, "ota_active");
  setState(ota_v2::State::BinaryVerifying, "binary_verifying", {}, false);
  const std::string received_hash =
      crypto::hexEncode(digest.data(), digest.size());
  digest.fill(0U);
  const bool hash_matches =
      crypto::constantTimeEqual(received_hash, manifest.sha256);
  if (!stream_tracker.finish(hash_matches, extra_bytes)) {
    error = ota_v2::streamFailureCode(stream_tracker.failure());
    failUpdate();
    return false;
  }
  if (!protocol_seen) {
    error = "ota_image_protocol_marker_missing";
    failUpdate();
    return false;
  }
  ota_stage::record(ota_stage::Stage::HashVerified, received,
                    manifest.size_bytes, true);
  ota_stage::record(ota_stage::Stage::ProtocolMarkerVerified, received,
                    manifest.size_bytes, true);
  setState(ota_v2::State::PartitionWriting, "partition_writing", {}, false);
  ota_stage::record(ota_stage::Stage::UpdateEndBeginning, received,
                    manifest.size_bytes, true);
  if (ota_fault::configured(ota_fault::Point::BeforeUpdateEnd)) {
    error = ota_fault::failureCode(ota_fault::Point::BeforeUpdateEnd);
    failUpdate();
    return false;
  }
  if (!Update.end(true) || !Update.isFinished()) {
    update_open = false;
    error = "ota_finalize_failed";
    return false;
  }
  update_open = false;
  ota_stage::record(ota_stage::Stage::UpdateEndCompleted, received,
                    manifest.size_bytes, false, true);
  ota_stage::record(ota_stage::Stage::BootPartitionSelected, received,
                    manifest.size_bytes, false, true);
  if (ota_fault::configured(ota_fault::Point::AfterUpdateEnd)) {
    (void)esp_ota_set_boot_partition(esp_ota_get_running_partition());
    error = ota_fault::failureCode(ota_fault::Point::AfterUpdateEnd);
    return false;
  }
  ota_stage::record(ota_stage::Stage::PartitionWritten, received,
                    manifest.size_bytes, false, true);
  setState(ota_v2::State::PartitionWritten, "partition_written", {}, false);
  return true;
}

bool OtaService::postReport(const char *report_state, std::string &error) {
  const std::string body = reportJson(report_state);
  if (body.empty()) {
    error = "ota_report_unavailable";
    return false;
  }
  report_pending_.store(true, std::memory_order_release);
  const RuntimeConfig active_config = config_.config();
  const std::string endpoint = "/api/v1/device-firmware/report";
  const std::string url = active_config.server_url + endpoint;
  if (!hostAllowed(active_config, url)) {
    error = "ota_report_origin_invalid";
    return false;
  }
  std::string hostname;
  std::uint16_t port = 443U;
  IPAddress address;
  const char *resolution_method = "none";
  if (!resolveHttpsTarget(url, hostname, port, address, resolution_method)) {
    error = "ota_report_dns_failed";
    return false;
  }
  OtaTransactionLease lease(diagnostics_, ota_stage::Stage::ReportPreparing);
  if (!lease) {
    error = "ota_high_memory_lease_unavailable";
    return false;
  }
  OtaTransportLifecycle lifecycle(diagnostics_, endpoint);
  ResolvedTlsClient client;
  if (!configureTls(client, active_config.server_ca_pem)) {
    error = "tls_ca_not_configured";
    return false;
  }
  lifecycle.record(TlsLifecycleStage::AfterTlsConfiguration);
  client.setResolvedEndpoint(address, hostname, port);
  HTTPClient http;
  OtaHttpCleanup cleanup(http, lifecycle);
  http.setConnectTimeout(5000);
  http.setTimeout(10000);
  if (!http.begin(client, url.c_str()) ||
      !addDeviceAuthentication(http, "POST", endpoint, body, error)) {
    return false;
  }
  lifecycle.record(TlsLifecycleStage::AfterHttpBegin);
  if (!lease.activate(ota_stage::Stage::ReportRequest,
                      status().bytes_received, status().image_size)) {
    error = "ota_tls_context_transition_failed";
    return false;
  }
  http.addHeader("Content-Type", "application/json");
  const int response = http.POST(
      reinterpret_cast<std::uint8_t *>(const_cast<char *>(body.data())),
      body.size());
  lifecycle.record(TlsLifecycleStage::AfterRequest);
  cleanup.end();
  if (response != 200 && response != 204) {
    error = "ota_report_rejected";
    return false;
  }
  recovery_.last_report_state = report_state;
  if (!recovery_store_.save(recovery_)) {
    error = "ota_report_checkpoint_save_failed";
    report_pending_.store(true, std::memory_order_release);
    return false;
  }
  report_pending_.store(false, std::memory_order_release);
  error.clear();
  return true;
}

bool OtaService::configureTls(WiFiClientSecure &client,
                              const std::string &ca_pem) const {
  client.setHandshakeTimeout(8);
  if (ca_pem.empty())
    return false;
  client.setCACert(ca_pem.c_str());
  return true;
}

bool OtaService::persistState(const ota_v2::State state,
                              const std::string &failure_code,
                              const bool pending_reboot) {
  if (recovery_.deployment_id.empty() || recovery_.release_id.empty())
    return false;
  recovery_.state = state;
  recovery_.failure_code = failure_code;
  recovery_.pending_reboot = pending_reboot;
  if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(250)) == pdTRUE) {
    recovery_.target_build_hash = status_.target_build_hash;
    recovery_.image_size = status_.image_size;
    recovery_.bytes_received = status_.bytes_received;
    recovery_.progress_percent = status_.progress_percent;
    xSemaphoreGive(mutex_);
  }
  const bool saved = recovery_store_.save(recovery_);
  if (!saved) {
    PM_LOG_ERROR("OTA", "RECOVERY_STATE_SAVE_FAILED",
                 "error=PM-OTA-011 state=%s", ota_v2::stateName(state));
  }
  return saved;
}

void OtaService::setState(const ota_v2::State state,
                          const std::string &result,
                          const std::string &error, const bool persist,
                          const bool report) {
  bool pending_reboot = false;
  if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(250)) == pdTRUE) {
    status_.state = state;
    status_.last_result = result;
    status_.last_error = error;
    status_.in_progress = in_progress_.load(std::memory_order_acquire);
    pending_reboot = status_.pending_reboot;
    xSemaphoreGive(mutex_);
  }
  bool persisted = false;
  if (persist) {
    persisted = persistState(state, error, pending_reboot);
    if (persisted) {
      const OtaStatus snapshot = status();
      ota_stage::record(ota_stage::Stage::RecoveryRecordPersisted,
                        snapshot.bytes_received, snapshot.image_size,
                        state == ota_v2::State::Downloading ||
                            state == ota_v2::State::BinaryVerifying ||
                            state == ota_v2::State::PartitionWriting,
                        pending_reboot);
    }
  }
  if (state == ota_v2::State::Failed ||
      state == ota_v2::State::ManifestRejected ||
      state == ota_v2::State::RolledBack) {
    const OtaStatus snapshot = status();
    ota_stage::recordFailure(error.empty() ? result.c_str() : error.c_str(),
                             snapshot.bytes_received, snapshot.image_size,
                             state == ota_v2::State::Downloading ||
                                 state == ota_v2::State::BinaryVerifying ||
                                 state == ota_v2::State::PartitionWriting);
  }
  if (report && persist && state != ota_v2::State::Idle &&
      state != ota_v2::State::ManifestUnavailable) {
    report_pending_.store(true, std::memory_order_release);
  }
  PM_LOG_INFO("OTA", "STATE_CHANGED", "state=%s result=%s error=%s",
              ota_v2::stateName(state), result.c_str(),
              error.empty() ? "none" : error.c_str());
}

std::string OtaService::reportJson(const char *report_state) const {
  const OtaStatus snapshot = status();
  if (snapshot.deployment_id.empty() || snapshot.release_id.empty() ||
      snapshot.attempt == 0U)
    return {};
  JsonDocument document;
  document["device_id"] = config_.identity().device_id;
  document["deployment_id"] = snapshot.deployment_id;
  document["release_id"] = snapshot.release_id;
  document["attempt"] = snapshot.attempt;
  document["state"] = report_state;
  document["current_firmware_version"] = version::FIRMWARE;
  document["current_build_hash"] = runningBuildHash();
  document["target_version"] = snapshot.target_version;
  document["target_sha256"] = snapshot.target_sha256;
  document["bytes_received"] = snapshot.bytes_received;
  document["image_size"] = snapshot.image_size;
  document["progress"] = snapshot.progress_percent;
  document["boot_id"] = config_.identity().boot_id;
  const std::string &failure_code = recovery_.failure_code;
  if (failure_code.empty() ||
      !ota_v2::reportStateAcceptsFailureEvidence(report_state)) {
    document["failure_code"] = nullptr;
    document["failure_summary"] = nullptr;
  } else {
    document["failure_code"] = failure_code;
    document["failure_summary"] = failure_code;
  }
  std::string body;
  serializeJson(document, body);
  return body;
}

void OtaService::initializePartitionStatus() {
  if (mutex_ == nullptr ||
      xSemaphoreTake(mutex_, pdMS_TO_TICKS(100)) != pdTRUE) {
    return;
  }
  status_.running_partition = partitionLabel(esp_ota_get_running_partition());
  status_.target_partition =
      partitionLabel(esp_ota_get_next_update_partition(nullptr));
  status_.rollback_supported = true;
  xSemaphoreGive(mutex_);
}

} // namespace pm
