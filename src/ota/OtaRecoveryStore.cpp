#include "ota/OtaRecoveryStore.h"

#include <vector>

#include <ArduinoJson.h>
#include <Preferences.h>

#include "config/AtomicConfigStore.h"

namespace pm {
namespace {

constexpr char kPersistentPartition[] = "pmconfig";
constexpr char kPersistentNamespace[] = "pm-state";
constexpr persistence::SlotKeys kOtaRecoverySlots{"ota_a", "ota_b",
                                                   "ota_active"};
constexpr persistence::SlotKeys kOtaRestrictedIncidentSlots{
    "otai_a", "otai_b", "otai_active"};

bool validRestrictedIncident(const OtaRestrictedRecoveryRecord &record) {
  return record.schema_version == 1U && !record.failure_code.empty() &&
         record.failure_code.size() <= 96U &&
         !record.rollback_result.empty() &&
         record.rollback_result.size() <= 48U &&
         !record.running_version.empty() &&
         record.running_version.size() <= 32U &&
         !record.running_build_hash.empty() &&
         record.running_build_hash.size() <= 64U &&
         record.boot_id.size() <= 64U && record.boot_count != 0U &&
         record.pending_image && record.report_pending;
}

std::string serializeRestrictedIncident(
    const OtaRestrictedRecoveryRecord &record) {
  if (!validRestrictedIncident(record))
    return {};
  JsonDocument document;
  document["schema_version"] = record.schema_version;
  document["failure_code"] = record.failure_code;
  document["rollback_result"] = record.rollback_result;
  document["running_version"] = record.running_version;
  document["running_build_hash"] = record.running_build_hash;
  document["boot_id"] = record.boot_id;
  document["boot_count"] = record.boot_count;
  document["pending_image"] = record.pending_image;
  document["report_pending"] = record.report_pending;
  std::string output;
  serializeJson(document, output);
  return output;
}

bool parseRestrictedIncident(const std::string &json,
                             OtaRestrictedRecoveryRecord &record) {
  record = {};
  if (json.empty() || json.size() > 1024U)
    return false;
  JsonDocument document;
  if (deserializeJson(document, json) ||
      !document["schema_version"].is<std::uint32_t>() ||
      !document["failure_code"].is<const char *>() ||
      !document["rollback_result"].is<const char *>() ||
      !document["running_version"].is<const char *>() ||
      !document["running_build_hash"].is<const char *>() ||
      !document["boot_id"].is<const char *>() ||
      !document["boot_count"].is<std::uint32_t>() ||
      !document["pending_image"].is<bool>() ||
      !document["report_pending"].is<bool>()) {
    return false;
  }
  record.schema_version = document["schema_version"].as<std::uint32_t>();
  record.failure_code = document["failure_code"].as<const char *>();
  record.rollback_result = document["rollback_result"].as<const char *>();
  record.running_version = document["running_version"].as<const char *>();
  record.running_build_hash =
      document["running_build_hash"].as<const char *>();
  record.boot_id = document["boot_id"].as<const char *>();
  record.boot_count = document["boot_count"].as<std::uint32_t>();
  record.pending_image = document["pending_image"].as<bool>();
  record.report_pending = document["report_pending"].as<bool>();
  return validRestrictedIncident(record);
}

bool restrictedIncidentsEqual(const OtaRestrictedRecoveryRecord &left,
                              const OtaRestrictedRecoveryRecord &right) {
  return left.schema_version == right.schema_version &&
         left.failure_code == right.failure_code &&
         left.rollback_result == right.rollback_result &&
         left.running_version == right.running_version &&
         left.running_build_hash == right.running_build_hash &&
         left.boot_id == right.boot_id && left.boot_count == right.boot_count &&
         left.pending_image == right.pending_image &&
         left.report_pending == right.report_pending;
}

class PreferencesBlobStore final : public persistence::BlobStore {
public:
  bool read(const char *key, std::vector<std::uint8_t> &value) override {
    Preferences preferences;
    if (!preferences.begin(kPersistentNamespace, true, kPersistentPartition))
      return false;
    const std::size_t length = preferences.getBytesLength(key);
    value.resize(length);
    const bool read = length != 0U &&
                      preferences.getBytes(key, value.data(), length) == length;
    preferences.end();
    if (!read)
      value.clear();
    return read;
  }

  bool write(const char *key, const std::uint8_t *value,
             const std::size_t length) override {
    Preferences preferences;
    if (length == 0U ||
        !preferences.begin(kPersistentNamespace, false, kPersistentPartition)) {
      return false;
    }
    const bool written = preferences.putBytes(key, value, length) == length;
    preferences.end();
    return written;
  }

  bool erase(const char *key) override {
    Preferences preferences;
    if (!preferences.begin(kPersistentNamespace, false, kPersistentPartition))
      return false;
    const bool erased = !preferences.isKey(key) || preferences.remove(key);
    preferences.end();
    return erased;
  }

  bool exists(const char *key) override {
    Preferences preferences;
    if (!preferences.begin(kPersistentNamespace, true, kPersistentPartition))
      return false;
    const bool present = preferences.isKey(key);
    preferences.end();
    return present;
  }
};

} // namespace

const char *otaRecoveryStoreResultName(const OtaRecoveryStoreResult result) {
  switch (result) {
  case OtaRecoveryStoreResult::NotRequired: return "not_required";
  case OtaRecoveryStoreResult::Loaded: return "loaded";
  case OtaRecoveryStoreResult::SavedAndVerified: return "saved_and_verified";
  case OtaRecoveryStoreResult::Cleared: return "cleared";
  case OtaRecoveryStoreResult::NotFound: return "not_found";
  case OtaRecoveryStoreResult::LoadFailed: return "load_failed";
  case OtaRecoveryStoreResult::ParseFailed: return "parse_failed";
  case OtaRecoveryStoreResult::SerializeFailed: return "serialize_failed";
  case OtaRecoveryStoreResult::CommitFailed: return "commit_failed";
  case OtaRecoveryStoreResult::ReadbackFailed: return "readback_failed";
  case OtaRecoveryStoreResult::IdentityMismatch: return "identity_mismatch";
  case OtaRecoveryStoreResult::ClearFailed: return "clear_failed";
  case OtaRecoveryStoreResult::StateLockUnavailable:
    return "state_lock_unavailable";
  case OtaRecoveryStoreResult::EvidenceSequenceExhausted:
    return "evidence_sequence_exhausted";
  }
  return "unknown";
}

OtaRecoveryStoreResult
OtaRecoveryStore::load(ota_v2::RecoveryRecord &record) const {
  record = {};
  PreferencesBlobStore store;
  persistence::LoadResult loaded;
  if (!persistence::anyDataPresent(store, kOtaRecoverySlots))
    return OtaRecoveryStoreResult::NotFound;
  if (!persistence::loadActive(store, kOtaRecoverySlots, loaded))
    return OtaRecoveryStoreResult::LoadFailed;
  const std::string json(loaded.payload.begin(), loaded.payload.end());
  return ota_v2::parseRecovery(json, record)
             ? OtaRecoveryStoreResult::Loaded
             : OtaRecoveryStoreResult::ParseFailed;
}

OtaRecoveryStoreResult OtaRecoveryStore::saveAndVerify(
    const ota_v2::RecoveryRecord &record) const {
  const std::string json = ota_v2::serializeRecovery(record);
  if (json.empty())
    return OtaRecoveryStoreResult::SerializeFailed;
  const std::vector<std::uint8_t> payload(json.begin(), json.end());
  PreferencesBlobStore store;
  persistence::CommitResult committed;
  if (!persistence::commit(store, kOtaRecoverySlots, payload, committed) ||
      !committed.committed) {
    return OtaRecoveryStoreResult::CommitFailed;
  }
  persistence::LoadResult loaded;
  if (!persistence::loadActive(store, kOtaRecoverySlots, loaded))
    return OtaRecoveryStoreResult::ReadbackFailed;
  const std::string readback_json(loaded.payload.begin(), loaded.payload.end());
  ota_v2::RecoveryRecord readback;
  if (!ota_v2::parseRecovery(readback_json, readback))
    return OtaRecoveryStoreResult::ReadbackFailed;
  return ota_v2::recoveryRecordsEqual(record, readback)
             ? OtaRecoveryStoreResult::SavedAndVerified
             : OtaRecoveryStoreResult::IdentityMismatch;
}

OtaRecoveryStoreResult OtaRecoveryStore::clear() const {
  PreferencesBlobStore store;
  const bool cleared = store.erase(kOtaRecoverySlots.slot_a) &&
                       store.erase(kOtaRecoverySlots.slot_b) &&
                       store.erase(kOtaRecoverySlots.active);
  return cleared ? OtaRecoveryStoreResult::Cleared
                 : OtaRecoveryStoreResult::ClearFailed;
}

OtaRecoveryStoreResult OtaRecoveryStore::loadRestrictedIncident(
    OtaRestrictedRecoveryRecord &record) const {
  record = {};
  PreferencesBlobStore store;
  persistence::LoadResult loaded;
  if (!persistence::anyDataPresent(store, kOtaRestrictedIncidentSlots))
    return OtaRecoveryStoreResult::NotFound;
  if (!persistence::loadActive(store, kOtaRestrictedIncidentSlots, loaded))
    return OtaRecoveryStoreResult::LoadFailed;
  const std::string json(loaded.payload.begin(), loaded.payload.end());
  return parseRestrictedIncident(json, record)
             ? OtaRecoveryStoreResult::Loaded
             : OtaRecoveryStoreResult::ParseFailed;
}

OtaRecoveryStoreResult OtaRecoveryStore::saveRestrictedIncidentAndVerify(
    const OtaRestrictedRecoveryRecord &record) const {
  const std::string json = serializeRestrictedIncident(record);
  if (json.empty())
    return OtaRecoveryStoreResult::SerializeFailed;
  const std::vector<std::uint8_t> payload(json.begin(), json.end());
  PreferencesBlobStore store;
  persistence::CommitResult committed;
  if (!persistence::commit(store, kOtaRestrictedIncidentSlots, payload,
                           committed) ||
      !committed.committed) {
    return OtaRecoveryStoreResult::CommitFailed;
  }
  persistence::LoadResult loaded;
  if (!persistence::loadActive(store, kOtaRestrictedIncidentSlots, loaded))
    return OtaRecoveryStoreResult::ReadbackFailed;
  const std::string readback_json(loaded.payload.begin(), loaded.payload.end());
  OtaRestrictedRecoveryRecord readback;
  if (!parseRestrictedIncident(readback_json, readback))
    return OtaRecoveryStoreResult::ReadbackFailed;
  return restrictedIncidentsEqual(record, readback)
             ? OtaRecoveryStoreResult::SavedAndVerified
             : OtaRecoveryStoreResult::IdentityMismatch;
}

OtaRecoveryStoreResult OtaRecoveryStore::clearRestrictedIncident() const {
  PreferencesBlobStore store;
  const bool cleared = store.erase(kOtaRestrictedIncidentSlots.slot_a) &&
                       store.erase(kOtaRestrictedIncidentSlots.slot_b) &&
                       store.erase(kOtaRestrictedIncidentSlots.active);
  return cleared ? OtaRecoveryStoreResult::Cleared
                 : OtaRecoveryStoreResult::ClearFailed;
}

} // namespace pm
