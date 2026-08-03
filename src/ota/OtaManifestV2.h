#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace pm {
namespace ota_v2 {

constexpr char kSchemaVersion[] = "pm-ota-manifest/2";
constexpr char kAuthenticationMode[] = "existing_device_hmac";
constexpr char kHmacAlgorithm[] = "HMAC-SHA256";
constexpr char kHmacKeyContext[] =
    "pm-ota-manifest-v2/server-to-device";
constexpr char kProjectName[] = "power-monitor-sensor";
constexpr std::uint32_t kProtocolVersion = 2U;

enum class State : std::uint8_t {
  Idle,
  ManifestCheck,
  ManifestUnavailable,
  ManifestReceived,
  ManifestAuthenticated,
  ManifestRejected,
  WaitingForSchedule,
  WaitingForResources,
  DownloadStarting,
  Downloading,
  BinaryVerifying,
  PartitionWriting,
  PartitionWritten,
  RebootPending,
  Rebooting,
  PostBootValidation,
  Validated,
  Completed,
  Failed,
  RollbackDetected,
  RolledBack,
};

const char *stateName(State state);
bool parseState(const std::string &value, State &state);
bool terminalState(State state);

struct Manifest {
  bool available{false};
  std::string schema_version;
  std::string protocol_version;
  std::string deployment_id;
  std::string release_id;
  std::string device_id;
  std::string version;
  std::string project_name;
  std::string hardware_target;
  std::string protocol_min;
  std::string protocol_max;
  std::uint32_t size_bytes{0};
  std::string sha256;
  std::string build_hash;
  std::string not_before;
  std::string expires_at;
  bool allow_downgrade{false};
  std::uint32_t attempt{0};
  std::string hmac_algorithm;
  std::string hmac_key_context;
  std::string manifest_hmac;
  std::string download_path;
};

struct PolicyContext {
  std::string device_id;
  std::string current_version;
  std::string current_protocol;
  std::string hardware_target;
  std::string project_name{kProjectName};
  std::int64_t now_unix_seconds{0};
  std::uint32_t partition_size_bytes{0};
};

bool parseManifest(const std::string &json, Manifest &manifest,
                   std::string &error);
std::string canonicalManifest(const Manifest &manifest);
bool validatePolicy(const Manifest &manifest, const PolicyContext &context,
                    std::string &error);
bool parseUtcTimestamp(const std::string &value,
                       std::int64_t &unix_seconds);
bool validSemver(const std::string &value);
int compareSemver(const std::string &left, const std::string &right);

struct RecoveryRecord {
  std::string deployment_id;
  std::string release_id;
  std::string target_version;
  std::string target_sha256;
  std::string target_build_hash;
  std::string previous_version;
  std::string previous_build_hash;
  std::uint32_t image_size{0U};
  std::uint32_t bytes_received{0U};
  std::uint8_t progress_percent{0U};
  std::uint32_t attempt{0};
  State state{State::Idle};
  std::string last_report_state;
  std::string failure_code;
  bool pending_reboot{false};
};

std::string serializeRecovery(const RecoveryRecord &record);
bool parseRecovery(const std::string &json, RecoveryRecord &record);

} // namespace ota_v2
} // namespace pm
