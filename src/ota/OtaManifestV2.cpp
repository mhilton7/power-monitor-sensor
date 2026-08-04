#include "ota/OtaManifestV2.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <limits>
#include <vector>

#include <ArduinoJson.h>

namespace pm {
namespace ota_v2 {
namespace {

constexpr std::size_t kMaximumManifestBytes = 16U * 1024U;
constexpr std::size_t kMaximumRecoveryBytes = 2048U;

struct StateName {
  State state;
  const char *name;
};

constexpr std::array<StateName, 21U> kStateNames{{
    {State::Idle, "idle"},
    {State::ManifestCheck, "manifest_check"},
    {State::ManifestUnavailable, "manifest_unavailable"},
    {State::ManifestReceived, "manifest_received"},
    {State::ManifestAuthenticated, "manifest_authenticated"},
    {State::ManifestRejected, "manifest_rejected"},
    {State::WaitingForSchedule, "waiting_for_schedule"},
    {State::WaitingForResources, "waiting_for_resources"},
    {State::DownloadStarting, "download_starting"},
    {State::Downloading, "downloading"},
    {State::BinaryVerifying, "binary_verifying"},
    {State::PartitionWriting, "partition_writing"},
    {State::PartitionWritten, "partition_written"},
    {State::RebootPending, "reboot_pending"},
    {State::Rebooting, "rebooting"},
    {State::PostBootValidation, "post_boot_validation"},
    {State::Validated, "validated"},
    {State::Completed, "completed"},
    {State::Failed, "failed"},
    {State::RollbackDetected, "rollback_detected"},
    {State::RolledBack, "rolled_back"},
}};

bool printableAscii(const std::string &value, const std::size_t maximum,
                    const bool allow_empty = false) {
  return value.size() <= maximum && (allow_empty || !value.empty()) &&
         std::all_of(value.begin(), value.end(), [](const unsigned char byte) {
           return byte >= 0x20U && byte <= 0x7EU;
         });
}

std::string lowercase(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const unsigned char byte) {
                   return static_cast<char>(std::tolower(byte));
                 });
  return value;
}

bool compatibleHardware(const std::string &manifest_target,
                        const std::string &local_target) {
  const std::string offered = lowercase(manifest_target);
  const std::string local = lowercase(local_target);
  return offered == local ||
         (offered == "esp32-s3" && local.rfind("esp32-s3", 0U) == 0U);
}

bool lowercaseHex(const std::string &value, const std::size_t length) {
  return value.size() == length &&
         std::all_of(value.begin(), value.end(), [](const char byte) {
           return (byte >= '0' && byte <= '9') ||
                  (byte >= 'a' && byte <= 'f');
         });
}

bool lowercaseUuid(const std::string &value) {
  if (value.size() != 36U)
    return false;
  for (std::size_t index = 0; index < value.size(); ++index) {
    if (index == 8U || index == 13U || index == 18U || index == 23U) {
      if (value[index] != '-')
        return false;
    } else if (!((value[index] >= '0' && value[index] <= '9') ||
                 (value[index] >= 'a' && value[index] <= 'f'))) {
      return false;
    }
  }
  return true;
}

bool base64UrlSha256(const std::string &value) {
  return value.size() == 43U &&
         std::all_of(value.begin(), value.end(), [](const char byte) {
           return (byte >= '0' && byte <= '9') ||
                  (byte >= 'A' && byte <= 'Z') ||
                  (byte >= 'a' && byte <= 'z') || byte == '-' || byte == '_';
         });
}

bool boundedDownloadPath(const std::string &path,
                         const std::string &release_id,
                         const std::string &deployment_id) {
  const std::string expected = "/api/v1/device-firmware/" + release_id +
                               "/download?deployment_id=" + deployment_id;
  return printableAscii(path, 256U) && path == expected;
}

bool appendJsonString(std::string &output, const std::string &value) {
  if (!printableAscii(value, std::numeric_limits<std::size_t>::max(), true))
    return false;
  output.push_back('"');
  for (const char byte : value) {
    if (byte == '"' || byte == '\\')
      output.push_back('\\');
    output.push_back(byte);
  }
  output.push_back('"');
  return true;
}

bool appendStringField(std::string &output, const char *name,
                       const std::string &value, bool &first) {
  if (!first)
    output.push_back(',');
  first = false;
  output.push_back('"');
  output += name;
  output += "\":";
  return appendJsonString(output, value);
}

bool uniqueTopLevelKeys(const std::string &json) {
  std::vector<std::string> keys;
  std::size_t depth = 0U;
  for (std::size_t index = 0; index < json.size();) {
    const char byte = json[index];
    if (byte == '{' || byte == '[') {
      ++depth;
      ++index;
      continue;
    }
    if (byte == '}' || byte == ']') {
      if (depth == 0U)
        return false;
      --depth;
      ++index;
      continue;
    }
    if (byte != '"') {
      ++index;
      continue;
    }
    const std::size_t start = ++index;
    bool escaped = false;
    while (index < json.size()) {
      if (json[index] == '\\') {
        escaped = true;
        index += 2U;
        continue;
      }
      if (json[index] == '"')
        break;
      ++index;
    }
    if (index >= json.size())
      return false;
    const std::string token = json.substr(start, index - start);
    ++index;
    std::size_t cursor = index;
    while (cursor < json.size() &&
           std::isspace(static_cast<unsigned char>(json[cursor]))) {
      ++cursor;
    }
    if (depth == 1U && cursor < json.size() && json[cursor] == ':') {
      // Manifest field names are fixed printable ASCII. Reject escaped aliases
      // so duplicate-key detection cannot be bypassed with \u notation.
      if (escaped || std::find(keys.begin(), keys.end(), token) != keys.end())
        return false;
      keys.push_back(token);
    }
  }
  return depth == 0U;
}

bool expectedManifestKey(const std::string &key) {
  static const std::array<const char *, 21U> keys{{
      "allow_downgrade", "attempt",          "build_hash",
      "deployment_id",   "device_id",
      "download_path",   "expires_at",       "hardware_target",
      "hmac_algorithm",  "hmac_key_context", "manifest_hmac",
      "not_before",      "project_name",     "protocol_max",
      "protocol_min",    "protocol_version", "release_id",
      "schema_version",  "sha256",           "size_bytes",
      "version",
  }};
  return std::find_if(keys.begin(), keys.end(), [&key](const char *candidate) {
           return key == candidate;
         }) != keys.end();
}

bool exactManifestKeys(const JsonDocument &document) {
  std::size_t count = 0U;
  for (JsonPairConst pair : document.as<JsonObjectConst>()) {
    if (!expectedManifestKey(pair.key().c_str()))
      return false;
    ++count;
  }
  return count == 21U;
}

bool validReportState(const std::string &value) {
  static const std::array<const char *, 12U> states{{
      "manifest_authenticated", "waiting_for_schedule", "download_started",
      "downloading",            "binary_verified",      "partition_written",
      "rebooting",              "post_boot_validation", "validated",
      "failed",                 "rollback_detected",    "rolled_back",
  }};
  return value.empty() ||
         std::find_if(states.begin(), states.end(),
                      [&value](const char *state) { return value == state; }) !=
             states.end();
}

bool leapYear(const int year) {
  return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

std::int64_t daysFromCivil(int year, const unsigned month,
                           const unsigned day) {
  year -= month <= 2U;
  const int era = (year >= 0 ? year : year - 399) / 400;
  const unsigned year_of_era = static_cast<unsigned>(year - era * 400);
  const unsigned day_of_year =
      (153U * (month > 2U ? month - 3U : month + 9U) + 2U) / 5U + day - 1U;
  const unsigned day_of_era =
      year_of_era * 365U + year_of_era / 4U - year_of_era / 100U + day_of_year;
  return static_cast<std::int64_t>(era) * 146097LL +
         static_cast<std::int64_t>(day_of_era) - 719468LL;
}

bool parseUnsignedComponent(const std::string &component,
                            std::uint32_t &value) {
  if (component.empty() || component.size() > 10U ||
      (component.size() > 1U && component.front() == '0') ||
      !std::all_of(component.begin(), component.end(), [](const char byte) {
        return byte >= '0' && byte <= '9';
      })) {
    return false;
  }
  unsigned long long parsed = 0U;
  for (const char byte : component) {
    parsed = parsed * 10U + static_cast<unsigned>(byte - '0');
    if (parsed > std::numeric_limits<std::uint32_t>::max())
      return false;
  }
  value = static_cast<std::uint32_t>(parsed);
  return true;
}

struct Semver {
  std::array<std::uint32_t, 3U> core{};
  std::vector<std::string> prerelease;
};

bool validIdentifier(const std::string &identifier, const bool prerelease) {
  if (identifier.empty() ||
      !std::all_of(identifier.begin(), identifier.end(), [](const char byte) {
        return (byte >= '0' && byte <= '9') ||
               (byte >= 'A' && byte <= 'Z') ||
               (byte >= 'a' && byte <= 'z') || byte == '-';
      })) {
    return false;
  }
  const bool numeric = std::all_of(
      identifier.begin(), identifier.end(),
      [](const char byte) { return byte >= '0' && byte <= '9'; });
  return !prerelease || !numeric || identifier.size() == 1U ||
         identifier.front() != '0';
}

bool splitIdentifiers(const std::string &value, const bool prerelease,
                      std::vector<std::string> *output) {
  std::size_t cursor = 0U;
  while (cursor <= value.size()) {
    const std::size_t dot = value.find('.', cursor);
    const std::size_t end = dot == std::string::npos ? value.size() : dot;
    const std::string identifier = value.substr(cursor, end - cursor);
    if (!validIdentifier(identifier, prerelease))
      return false;
    if (output != nullptr)
      output->push_back(identifier);
    if (dot == std::string::npos)
      break;
    cursor = dot + 1U;
  }
  return true;
}

bool parseSemver(const std::string &value, Semver &semver) {
  semver = {};
  if (value.empty() || value.size() > 80U)
    return false;
  const std::size_t plus = value.find('+');
  if (plus != std::string::npos && value.find('+', plus + 1U) != std::string::npos)
    return false;
  const std::string precedence = value.substr(0U, plus);
  if (plus != std::string::npos &&
      !splitIdentifiers(value.substr(plus + 1U), false, nullptr)) {
    return false;
  }
  const std::size_t dash = precedence.find('-');
  const std::string core = precedence.substr(0U, dash);
  if (dash != std::string::npos &&
      !splitIdentifiers(precedence.substr(dash + 1U), true,
                        &semver.prerelease)) {
    return false;
  }
  std::size_t cursor = 0U;
  for (std::size_t index = 0U; index < semver.core.size(); ++index) {
    const std::size_t dot = core.find('.', cursor);
    if ((index < 2U && dot == std::string::npos) ||
        (index == 2U && dot != std::string::npos)) {
      return false;
    }
    const std::size_t end = dot == std::string::npos ? core.size() : dot;
    if (!parseUnsignedComponent(core.substr(cursor, end - cursor),
                                semver.core[index])) {
      return false;
    }
    cursor = end + 1U;
  }
  return true;
}

bool numericIdentifier(const std::string &value) {
  return std::all_of(value.begin(), value.end(), [](const char byte) {
    return byte >= '0' && byte <= '9';
  });
}

int compareNumericIdentifier(const std::string &left,
                             const std::string &right) {
  if (left.size() != right.size())
    return left.size() < right.size() ? -1 : 1;
  const int order = left.compare(right);
  return order < 0 ? -1 : (order > 0 ? 1 : 0);
}

} // namespace

const char *stateName(const State state) {
  if (state == State::RolledBack)
    return "rolled_back";
  for (const StateName &entry : kStateNames) {
    if (entry.state == state)
      return entry.name;
  }
  return "failed";
}

bool parseState(const std::string &value, State &state) {
  if (value == "rolled_back") {
    state = State::RolledBack;
    return true;
  }
  for (const StateName &entry : kStateNames) {
    if (value == entry.name) {
      state = entry.state;
      return true;
    }
  }
  return false;
}

bool terminalState(const State state) {
  return state == State::Completed || state == State::Failed ||
         state == State::RolledBack;
}

bool parseManifest(const std::string &json, Manifest &manifest,
                   std::string &error) {
  manifest = {};
  if (json.empty() || json.size() > kMaximumManifestBytes ||
      !uniqueTopLevelKeys(json)) {
    error = "ota_manifest_json_invalid";
    return false;
  }
  JsonDocument document;
  if (deserializeJson(document, json) || !document.is<JsonObject>() ||
      !exactManifestKeys(document)) {
    error = "ota_manifest_schema_invalid";
    return false;
  }
  if (!document["schema_version"].is<const char *>() ||
      !document["protocol_version"].is<const char *>() ||
      !document["deployment_id"].is<const char *>() ||
      !document["release_id"].is<const char *>() ||
      !document["device_id"].is<const char *>() ||
      !document["version"].is<const char *>() ||
      !document["project_name"].is<const char *>() ||
      !document["hardware_target"].is<const char *>() ||
      !document["protocol_min"].is<const char *>() ||
      !document["protocol_max"].is<const char *>() ||
      !document["size_bytes"].is<std::uint32_t>() ||
      !document["sha256"].is<const char *>() ||
      !document["build_hash"].is<const char *>() ||
      !document["not_before"].is<const char *>() ||
      !document["expires_at"].is<const char *>() ||
      !document["allow_downgrade"].is<bool>() ||
      !document["attempt"].is<std::uint32_t>() ||
      !document["hmac_algorithm"].is<const char *>() ||
      !document["hmac_key_context"].is<const char *>() ||
      !document["manifest_hmac"].is<const char *>() ||
      !document["download_path"].is<const char *>()) {
    error = "ota_manifest_required_field_missing";
    return false;
  }
  manifest.available = true;
  manifest.schema_version = document["schema_version"].as<const char *>();
  manifest.protocol_version = document["protocol_version"].as<const char *>();
  manifest.deployment_id = document["deployment_id"].as<const char *>();
  manifest.release_id = document["release_id"].as<const char *>();
  manifest.device_id = document["device_id"].as<const char *>();
  manifest.version = document["version"].as<const char *>();
  manifest.project_name = document["project_name"].as<const char *>();
  manifest.hardware_target = document["hardware_target"].as<const char *>();
  manifest.protocol_min = document["protocol_min"].as<const char *>();
  manifest.protocol_max = document["protocol_max"].as<const char *>();
  manifest.size_bytes = document["size_bytes"].as<std::uint32_t>();
  manifest.sha256 = document["sha256"].as<const char *>();
  manifest.build_hash = document["build_hash"].as<const char *>();
  manifest.not_before = document["not_before"].as<const char *>();
  manifest.expires_at = document["expires_at"].as<const char *>();
  manifest.allow_downgrade = document["allow_downgrade"].as<bool>();
  manifest.attempt = document["attempt"].as<std::uint32_t>();
  manifest.hmac_algorithm = document["hmac_algorithm"].as<const char *>();
  manifest.hmac_key_context =
      document["hmac_key_context"].as<const char *>();
  manifest.manifest_hmac = document["manifest_hmac"].as<const char *>();
  manifest.download_path = document["download_path"].as<const char *>();

  std::int64_t not_before = 0;
  std::int64_t expires_at = 0;
  if (manifest.schema_version != kSchemaVersion ||
      manifest.hmac_algorithm != kHmacAlgorithm ||
      manifest.hmac_key_context != kHmacKeyContext ||
      !lowercaseUuid(manifest.deployment_id) ||
      !lowercaseUuid(manifest.release_id) ||
      !lowercaseUuid(manifest.device_id) || !validSemver(manifest.version) ||
      !printableAscii(manifest.protocol_version, 64U) ||
      !printableAscii(manifest.project_name, 64U) ||
      !printableAscii(manifest.hardware_target, 64U) ||
      !printableAscii(manifest.protocol_min, 64U) ||
      !printableAscii(manifest.protocol_max, 64U) ||
      manifest.size_bytes == 0U || !lowercaseHex(manifest.sha256, 64U) ||
      !lowercaseHex(manifest.build_hash, 64U) ||
      !parseUtcTimestamp(manifest.not_before, not_before) ||
      !parseUtcTimestamp(manifest.expires_at, expires_at) ||
      expires_at <= not_before || manifest.attempt == 0U ||
      !base64UrlSha256(manifest.manifest_hmac) ||
      !boundedDownloadPath(manifest.download_path, manifest.release_id,
                           manifest.deployment_id)) {
    error = "ota_manifest_field_invalid";
    return false;
  }
  error.clear();
  return true;
}

std::string canonicalManifest(const Manifest &manifest) {
  std::string output{"{"};
  output.reserve(1024U);
  bool first = true;
  if (!first)
    output.push_back(',');
  first = false;
  output += "\"allow_downgrade\":";
  output += manifest.allow_downgrade ? "true" : "false";
  output += ",\"attempt\":" + std::to_string(manifest.attempt);
  if (!appendStringField(output, "build_hash", manifest.build_hash, first) ||
      !appendStringField(output, "deployment_id", manifest.deployment_id,
                         first) ||
      !appendStringField(output, "device_id", manifest.device_id, first) ||
      !appendStringField(output, "download_path", manifest.download_path,
                         first) ||
      !appendStringField(output, "expires_at", manifest.expires_at, first) ||
      !appendStringField(output, "hardware_target", manifest.hardware_target,
                         first) ||
      !appendStringField(output, "hmac_algorithm", manifest.hmac_algorithm,
                         first) ||
      !appendStringField(output, "hmac_key_context", manifest.hmac_key_context,
                         first) ||
      !appendStringField(output, "not_before", manifest.not_before, first) ||
      !appendStringField(output, "project_name", manifest.project_name,
                         first) ||
      !appendStringField(output, "protocol_max", manifest.protocol_max,
                         first) ||
      !appendStringField(output, "protocol_min", manifest.protocol_min,
                         first) ||
      !appendStringField(output, "protocol_version", manifest.protocol_version,
                         first) ||
      !appendStringField(output, "release_id", manifest.release_id, first) ||
      !appendStringField(output, "schema_version", manifest.schema_version,
                         first) ||
      !appendStringField(output, "sha256", manifest.sha256, first)) {
    return {};
  }
  output += ",\"size_bytes\":" + std::to_string(manifest.size_bytes);
  if (!appendStringField(output, "version", manifest.version, first))
    return {};
  output.push_back('}');
  return output;
}

bool validatePolicy(const Manifest &manifest, const PolicyContext &context,
                    std::string &error) {
  if (manifest.device_id != context.device_id) {
    error = "ota_manifest_device_mismatch";
    return false;
  }
  std::int64_t not_before = 0;
  std::int64_t expires_at = 0;
  if (!parseUtcTimestamp(manifest.not_before, not_before) ||
      !parseUtcTimestamp(manifest.expires_at, expires_at) ||
      context.now_unix_seconds < not_before) {
    error = "ota_manifest_not_yet_valid";
    return false;
  }
  if (context.now_unix_seconds >= expires_at) {
    error = "ota_manifest_expired";
    return false;
  }
  if (manifest.project_name != context.project_name) {
    error = "ota_project_incompatible";
    return false;
  }
  if (!compatibleHardware(manifest.hardware_target, context.hardware_target)) {
    error = "ota_hardware_incompatible";
    return false;
  }
  if (manifest.protocol_version != context.current_protocol ||
      manifest.protocol_min != context.current_protocol ||
      manifest.protocol_max != context.current_protocol) {
    error = "ota_protocol_incompatible";
    return false;
  }
  const int version_order = compareSemver(manifest.version, context.current_version);
  if (version_order == 0 || (version_order < 0 && !manifest.allow_downgrade)) {
    error = version_order == 0 ? "ota_same_version_rejected"
                               : "ota_downgrade_rejected";
    return false;
  }
  if (context.partition_size_bytes == 0U ||
      manifest.size_bytes > context.partition_size_bytes) {
    error = "ota_partition_too_small";
    return false;
  }
  error.clear();
  return true;
}

bool parseUtcTimestamp(const std::string &value, std::int64_t &unix_seconds) {
  unix_seconds = 0;
  if (value.size() != 20U || value[4] != '-' || value[7] != '-' ||
      value[10] != 'T' || value[13] != ':' || value[16] != ':' ||
      value[19] != 'Z') {
    return false;
  }
  for (const std::size_t index : {0U, 1U, 2U, 3U, 5U, 6U, 8U, 9U, 11U,
                                  12U, 14U, 15U, 17U, 18U}) {
    if (!std::isdigit(static_cast<unsigned char>(value[index])))
      return false;
  }
  const int year = std::stoi(value.substr(0U, 4U));
  const unsigned month = static_cast<unsigned>(std::stoi(value.substr(5U, 2U)));
  const unsigned day = static_cast<unsigned>(std::stoi(value.substr(8U, 2U)));
  const unsigned hour = static_cast<unsigned>(std::stoi(value.substr(11U, 2U)));
  const unsigned minute = static_cast<unsigned>(std::stoi(value.substr(14U, 2U)));
  const unsigned second = static_cast<unsigned>(std::stoi(value.substr(17U, 2U)));
  constexpr std::array<unsigned, 12U> days{{31U, 28U, 31U, 30U, 31U, 30U,
                                            31U, 31U, 30U, 31U, 30U, 31U}};
  if (year < 2020 || year > 2200 || month == 0U || month > 12U || day == 0U ||
      day > days[month - 1U] +
                static_cast<unsigned>(month == 2U && leapYear(year)) ||
      hour > 23U || minute > 59U || second > 59U) {
    return false;
  }
  unix_seconds = daysFromCivil(year, month, day) * 86400LL +
                 static_cast<std::int64_t>(hour * 3600U + minute * 60U + second);
  return true;
}

bool validSemver(const std::string &value) {
  Semver semver;
  return parseSemver(value, semver);
}

int compareSemver(const std::string &left, const std::string &right) {
  Semver left_semver;
  Semver right_semver;
  if (!parseSemver(left, left_semver) || !parseSemver(right, right_semver))
    return left.compare(right);
  for (std::size_t index = 0; index < left_semver.core.size(); ++index) {
    if (left_semver.core[index] < right_semver.core[index])
      return -1;
    if (left_semver.core[index] > right_semver.core[index])
      return 1;
  }
  if (left_semver.prerelease.empty() || right_semver.prerelease.empty()) {
    if (left_semver.prerelease.empty() == right_semver.prerelease.empty())
      return 0;
    return left_semver.prerelease.empty() ? 1 : -1;
  }
  const std::size_t shared =
      std::min(left_semver.prerelease.size(), right_semver.prerelease.size());
  for (std::size_t index = 0U; index < shared; ++index) {
    const std::string &left_identifier = left_semver.prerelease[index];
    const std::string &right_identifier = right_semver.prerelease[index];
    if (left_identifier == right_identifier)
      continue;
    const bool left_numeric = numericIdentifier(left_identifier);
    const bool right_numeric = numericIdentifier(right_identifier);
    if (left_numeric != right_numeric)
      return left_numeric ? -1 : 1;
    if (left_numeric)
      return compareNumericIdentifier(left_identifier, right_identifier);
    return left_identifier < right_identifier ? -1 : 1;
  }
  if (left_semver.prerelease.size() == right_semver.prerelease.size())
    return 0;
  return left_semver.prerelease.size() < right_semver.prerelease.size() ? -1
                                                                        : 1;
}

std::string serializeRecovery(const RecoveryRecord &record) {
  JsonDocument document;
  document["schema_version"] = 1;
  document["deployment_id"] = record.deployment_id;
  document["release_id"] = record.release_id;
  document["target_version"] = record.target_version;
  document["target_sha256"] = record.target_sha256;
  document["target_build_hash"] = record.target_build_hash;
  document["previous_version"] = record.previous_version;
  document["previous_build_hash"] = record.previous_build_hash;
  document["image_size"] = record.image_size;
  document["bytes_received"] = record.bytes_received;
  document["progress_percent"] = record.progress_percent;
  document["attempt"] = record.attempt;
  document["evidence_sequence"] = record.evidence_sequence;
  document["state"] = stateName(record.state);
  document["last_report_state"] = record.last_report_state;
  document["failure_code"] = record.failure_code;
  document["pending_reboot"] = record.pending_reboot;
  std::string output;
  serializeJson(document, output);
  return output.size() <= kMaximumRecoveryBytes ? output : std::string{};
}

bool parseRecovery(const std::string &json, RecoveryRecord &record) {
  record = {};
  if (json.empty() || json.size() > kMaximumRecoveryBytes ||
      !uniqueTopLevelKeys(json)) {
    return false;
  }
  JsonDocument document;
  if (deserializeJson(document, json) ||
      (document["schema_version"] | 0U) != 1U ||
      !document["deployment_id"].is<const char *>() ||
      !document["release_id"].is<const char *>() ||
      !document["target_version"].is<const char *>() ||
      !document["target_sha256"].is<const char *>() ||
      !document["target_build_hash"].is<const char *>() ||
      !document["previous_version"].is<const char *>() ||
      !document["previous_build_hash"].is<const char *>() ||
      !document["image_size"].is<std::uint32_t>() ||
      !document["bytes_received"].is<std::uint32_t>() ||
      !document["progress_percent"].is<std::uint32_t>() ||
      !document["attempt"].is<std::uint32_t>() ||
      !document["state"].is<const char *>() ||
      !document["last_report_state"].is<const char *>() ||
      !document["failure_code"].is<const char *>() ||
      !document["pending_reboot"].is<bool>()) {
    return false;
  }
  record.deployment_id = document["deployment_id"].as<const char *>();
  record.release_id = document["release_id"].as<const char *>();
  record.target_version = document["target_version"].as<const char *>();
  record.target_sha256 = document["target_sha256"].as<const char *>();
  record.target_build_hash =
      document["target_build_hash"].as<const char *>();
  record.previous_version = document["previous_version"].as<const char *>();
  record.previous_build_hash =
      document["previous_build_hash"].as<const char *>();
  record.image_size = document["image_size"].as<std::uint32_t>();
  record.bytes_received = document["bytes_received"].as<std::uint32_t>();
  const std::uint32_t progress_percent =
      document["progress_percent"].as<std::uint32_t>();
  if (progress_percent > 100U)
    return false;
  record.progress_percent = static_cast<std::uint8_t>(progress_percent);
  record.attempt = document["attempt"].as<std::uint32_t>();
  for (const JsonPairConst property : document.as<JsonObjectConst>()) {
    if (std::strcmp(property.key().c_str(), "evidence_sequence") != 0)
      continue;
    if (!property.value().is<std::uint64_t>())
      return false;
    record.evidence_sequence = property.value().as<std::uint64_t>();
    break;
  }
  record.last_report_state =
      document["last_report_state"].as<const char *>();
  record.failure_code = document["failure_code"].as<const char *>();
  record.pending_reboot = document["pending_reboot"].as<bool>();
  const std::string state = document["state"].as<const char *>();
  return lowercaseUuid(record.deployment_id) &&
         lowercaseUuid(record.release_id) && validSemver(record.target_version) &&
         lowercaseHex(record.target_sha256, 64U) &&
         lowercaseHex(record.target_build_hash, 64U) &&
         validSemver(record.previous_version) &&
         lowercaseHex(record.previous_build_hash, 64U) &&
         record.image_size != 0U && record.bytes_received <= record.image_size &&
         record.progress_percent <= 100U &&
         record.attempt != 0U && parseState(state, record.state) &&
         validReportState(record.last_report_state) &&
         printableAscii(record.failure_code, 96U, true);
}

bool recoveryRecordsEqual(const RecoveryRecord &left,
                          const RecoveryRecord &right) {
  return left.deployment_id == right.deployment_id &&
         left.release_id == right.release_id &&
         left.target_version == right.target_version &&
         left.target_sha256 == right.target_sha256 &&
         left.target_build_hash == right.target_build_hash &&
         left.previous_version == right.previous_version &&
         left.previous_build_hash == right.previous_build_hash &&
         left.image_size == right.image_size &&
         left.bytes_received == right.bytes_received &&
         left.progress_percent == right.progress_percent &&
         left.attempt == right.attempt &&
         left.evidence_sequence == right.evidence_sequence &&
         left.state == right.state &&
         left.last_report_state == right.last_report_state &&
         left.failure_code == right.failure_code &&
         left.pending_reboot == right.pending_reboot;
}

} // namespace ota_v2
} // namespace pm
