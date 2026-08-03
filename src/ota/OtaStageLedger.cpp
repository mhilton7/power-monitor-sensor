#include "ota/OtaStageLedger.h"

#include <cstring>

#include <Arduino.h>
#include <esp_attr.h>
#include <esp_heap_caps.h>
#include <esp_ota_ops.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

namespace pm::ota_stage {
namespace {

constexpr std::uint32_t kMagic = 0x504D4F54U; // "PMOT"
constexpr std::uint16_t kVersion = 2U;

struct RetainedRecord {
  std::uint32_t magic{0U};
  std::uint16_t version{0U};
  std::uint16_t size{0U};
  std::uint32_t checksum{0U};
  Snapshot snapshot{};
};

RTC_NOINIT_ATTR RetainedRecord retained;
Snapshot prior{};

std::uint32_t checksum(const RetainedRecord &source) {
  RetainedRecord copy = source;
  copy.checksum = 0U;
  const auto *bytes = reinterpret_cast<const std::uint8_t *>(&copy);
  std::uint32_t value = 2166136261U;
  for (std::size_t index = 0U; index < sizeof(copy); ++index) {
    value ^= bytes[index];
    value *= 16777619U;
  }
  return value;
}

bool valid(const RetainedRecord &record) {
  return record.magic == kMagic && record.version == kVersion &&
         record.size == sizeof(RetainedRecord) &&
         record.checksum == checksum(record);
}

void copyPartition(std::array<char, 17U> &target,
                   const esp_partition_t *partition) {
  target.fill('\0');
  if (partition != nullptr) {
    std::strncpy(target.data(), partition->label, target.size() - 1U);
  }
}

template <std::size_t Capacity>
void copyText(std::array<char, Capacity> &target, const char *source) {
  target.fill('\0');
  if (source != nullptr) {
    std::strncpy(target.data(), source, target.size() - 1U);
  }
}

const char *defaultContext(const Stage stage) {
  switch (stage) {
  case Stage::ManifestPreparing:
  case Stage::ReportPreparing:
  case Stage::DownloadPreparing:
  case Stage::TransportLeaseAcquired: return "tls_preparing";
  case Stage::ManifestRequest:
  case Stage::ManifestResponseReceived:
  case Stage::ReportRequest:
  case Stage::FirmwareRequest:
  case Stage::FirmwareResponseHeaders:
  case Stage::ImageMetadataReceived:
  case Stage::ImageMetadataValidated:
  case Stage::UpdateBeginCompleted:
  case Stage::FirstBytesWritten:
  case Stage::Streaming:
  case Stage::StreamComplete:
  case Stage::ShaFinalized: return "tls_active";
  case Stage::Boot:
  case Stage::PostBootImageDetected:
  case Stage::PostBootValidated:
  case Stage::RollbackDetected: return "idle";
  default: return "ota_active";
  }
}

void commit() {
  retained.checksum = 0U;
  retained.checksum = checksum(retained);
}

} // namespace

void beginBoot(const char *boot_id, const char *firmware_version,
               const char *build_hash, const std::uint32_t boot_count,
               const std::uint32_t reset_reason_code) {
  prior = valid(retained) ? retained.snapshot : Snapshot{};
  retained = RetainedRecord{};
  retained.magic = kMagic;
  retained.version = kVersion;
  retained.size = sizeof(RetainedRecord);
  retained.snapshot.stage = Stage::Boot;
  retained.snapshot.sequence = prior.sequence + 1U;
  retained.snapshot.boot_count = boot_count;
  retained.snapshot.reset_reason_code = reset_reason_code;
  copyText(retained.snapshot.boot_id, boot_id);
  copyText(retained.snapshot.firmware_version, firmware_version);
  copyText(retained.snapshot.build_hash, build_hash);
  copyText(retained.snapshot.operation_context, "idle");
  copyText(retained.snapshot.current_task, pcTaskGetName(nullptr));
  copyPartition(retained.snapshot.running_partition,
                esp_ota_get_running_partition());
  copyPartition(retained.snapshot.target_partition,
                esp_ota_get_next_update_partition(nullptr));
  commit();
}

void bindDeployment(const char *deployment_id, const std::uint32_t attempt) {
  if (!valid(retained)) {
    return;
  }
  copyText(retained.snapshot.deployment_id, deployment_id);
  retained.snapshot.attempt = attempt;
  commit();
}

void record(const Stage stage, const std::uint32_t bytes_received,
            const std::uint32_t image_size, const bool update_open,
            const bool reboot_expected, const char *operation_context) {
  if (!valid(retained)) {
    return;
  }
  Snapshot &snapshot = retained.snapshot;
  snapshot.stage = stage;
  ++snapshot.sequence;
  snapshot.monotonic_ms = millis();
  snapshot.bytes_received = bytes_received;
  snapshot.image_size = image_size;
  snapshot.free_internal_bytes =
      heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  snapshot.largest_internal_block_bytes =
      heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  snapshot.free_psram_bytes = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
  snapshot.task_stack_high_water_bytes = uxTaskGetStackHighWaterMark(nullptr);
  snapshot.update_open = update_open;
  snapshot.reboot_expected = reboot_expected;
  copyText(snapshot.operation_context,
           operation_context == nullptr ? defaultContext(stage)
                                        : operation_context);
  copyText(snapshot.current_task, pcTaskGetName(nullptr));
  copyPartition(snapshot.running_partition, esp_ota_get_running_partition());
  copyPartition(snapshot.target_partition,
                esp_ota_get_next_update_partition(nullptr));
  commit();
}

void recordFailure(const char *failure_code,
                   const std::uint32_t bytes_received,
                   const std::uint32_t image_size, const bool update_open) {
  if (!valid(retained)) {
    return;
  }
  copyText(retained.snapshot.last_error, failure_code);
  record(Stage::FailurePersisted, bytes_received, image_size, update_open,
         false, "ota_active");
}

Snapshot current() { return valid(retained) ? retained.snapshot : Snapshot{}; }

Snapshot previousBoot() { return prior; }

const char *stageName(const Stage stage) {
  switch (stage) {
  case Stage::Boot: return "boot";
  case Stage::WorkflowLockAcquired: return "workflow_lock_acquired";
  case Stage::TransportLeaseAcquired: return "transport_lease_acquired";
  case Stage::ManifestPreparing: return "manifest_preparing";
  case Stage::ManifestRequest: return "manifest_request";
  case Stage::ManifestResponseReceived: return "manifest_response_received";
  case Stage::ManifestParsed: return "manifest_parsed";
  case Stage::ManifestAuthenticated: return "manifest_authenticated";
  case Stage::ManifestMilestoneReported: return "manifest_milestone_reported";
  case Stage::DownloadMilestoneReported: return "download_milestone_reported";
  case Stage::ReportPreparing: return "report_preparing";
  case Stage::ReportRequest: return "report_request";
  case Stage::DownloadPreparing: return "download_preparing";
  case Stage::FirmwareRequest: return "firmware_request";
  case Stage::FirmwareResponseHeaders: return "firmware_response_headers";
  case Stage::ImageMetadataReceived: return "image_metadata_received";
  case Stage::ImageMetadataValidated: return "image_metadata_validated";
  case Stage::UpdateBeginCompleted: return "update_begin_completed";
  case Stage::FirstBytesWritten: return "first_bytes_written";
  case Stage::Streaming: return "streaming";
  case Stage::StreamComplete: return "stream_complete";
  case Stage::ShaFinalized: return "sha_finalized";
  case Stage::HashVerified: return "hash_verified";
  case Stage::ProtocolMarkerVerified: return "protocol_marker_verified";
  case Stage::HttpTransportDestroyed: return "http_transport_destroyed";
  case Stage::UpdateEndBeginning: return "update_end_beginning";
  case Stage::UpdateEndCompleted: return "update_end_completed";
  case Stage::BootPartitionSelected: return "boot_partition_selected";
  case Stage::RecoveryRecordPersisted: return "recovery_record_persisted";
  case Stage::PartitionWritten: return "partition_written";
  case Stage::RebootMilestoneReported: return "reboot_milestone_reported";
  case Stage::RebootScheduled: return "reboot_scheduled";
  case Stage::PostBootImageDetected: return "post_boot_image_detected";
  case Stage::PostBootValidated: return "post_boot_validated";
  case Stage::RollbackDetected: return "rollback_detected";
  case Stage::FailurePersisted: return "failure_persisted";
  case Stage::Failed: return "failed";
  }
  return "unknown";
}

} // namespace pm::ota_stage
