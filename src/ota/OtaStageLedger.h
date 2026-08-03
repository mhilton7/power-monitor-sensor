#pragma once

#include <array>
#include <cstdint>

namespace pm::ota_stage {

enum class Stage : std::uint8_t {
  Boot,
  WorkflowLockAcquired,
  TransportLeaseAcquired,
  ManifestPreparing,
  ManifestRequest,
  ManifestResponseReceived,
  ManifestParsed,
  ManifestAuthenticated,
  ManifestMilestoneReported,
  DownloadMilestoneReported,
  ReportPreparing,
  ReportRequest,
  DownloadPreparing,
  FirmwareRequest,
  FirmwareResponseHeaders,
  ImageMetadataReceived,
  ImageMetadataValidated,
  UpdateBeginCompleted,
  FirstBytesWritten,
  Streaming,
  StreamComplete,
  ShaFinalized,
  HashVerified,
  ProtocolMarkerVerified,
  HttpTransportDestroyed,
  UpdateEndBeginning,
  UpdateEndCompleted,
  BootPartitionSelected,
  RecoveryRecordPersisted,
  PartitionWritten,
  RebootMilestoneReported,
  RebootScheduled,
  PostBootImageDetected,
  PostBootValidated,
  RollbackDetected,
  FailurePersisted,
  Failed,
};

struct Snapshot {
  Stage stage{Stage::Boot};
  std::uint32_t sequence{0U};
  std::uint64_t monotonic_ms{0U};
  std::uint32_t bytes_received{0U};
  std::uint32_t image_size{0U};
  std::uint32_t free_internal_bytes{0U};
  std::uint32_t largest_internal_block_bytes{0U};
  std::uint32_t free_psram_bytes{0U};
  std::uint32_t task_stack_high_water_bytes{0U};
  std::uint32_t boot_count{0U};
  std::uint32_t reset_reason_code{0U};
  std::uint32_t attempt{0U};
  bool update_open{false};
  bool reboot_expected{false};
  std::array<char, 65U> boot_id{};
  std::array<char, 32U> firmware_version{};
  std::array<char, 65U> build_hash{};
  std::array<char, 37U> deployment_id{};
  std::array<char, 24U> operation_context{};
  std::array<char, 17U> current_task{};
  std::array<char, 49U> last_error{};
  std::array<char, 17U> running_partition{};
  std::array<char, 17U> target_partition{};
};

// The ledger is allocation-free and retained in RTC slow memory. It is
// intentionally independent from Preferences/NVS so a panic during a TLS or
// flash-write operation leaves evidence that can be reported after reboot.
void beginBoot(const char *boot_id, const char *firmware_version,
               const char *build_hash, std::uint32_t boot_count,
               std::uint32_t reset_reason_code);
void bindDeployment(const char *deployment_id, std::uint32_t attempt);
void record(Stage stage, std::uint32_t bytes_received = 0U,
            std::uint32_t image_size = 0U, bool update_open = false,
            bool reboot_expected = false,
            const char *operation_context = nullptr);
void recordFailure(const char *failure_code, std::uint32_t bytes_received = 0U,
                   std::uint32_t image_size = 0U, bool update_open = false);
Snapshot current();
Snapshot previousBoot();
const char *stageName(Stage stage);

} // namespace pm::ota_stage
