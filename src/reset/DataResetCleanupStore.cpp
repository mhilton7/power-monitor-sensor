#include "reset/DataResetCleanupStore.h"

#include "reset/DataResetCapacityPolicy.h"

#include <limits>

#include <ArduinoJson.h>

#if !defined(PM_NATIVE_TEST)
#include <Preferences.h>
#endif

namespace pm {
namespace {

bool uuid(const std::string &value) {
  if (value.size() != 36U)
    return false;
  for (std::size_t index = 0U; index < value.size(); ++index) {
    const bool dash = index == 8U || index == 13U || index == 18U ||
                      index == 23U;
    if (dash ? value[index] != '-'
             : !((value[index] >= '0' && value[index] <= '9') ||
                 (value[index] >= 'a' && value[index] <= 'f'))) {
      return false;
    }
  }
  return true;
}

DataResetStoreResult loadFrom(persistence::BlobStore &store,
                              data_reset::CleanupRecord &record) {
  record = {};
  if (!persistence::anyDataPresent(store, kDataResetCleanupSlots))
    return DataResetStoreResult::NotFound;
  persistence::LoadResult loaded;
  if (!persistence::loadActive(store, kDataResetCleanupSlots, loaded))
    return DataResetStoreResult::LoadFailed;
  if (decodeDataResetCleanupRecord(loaded.payload, record))
    return DataResetStoreResult::Loaded;
  persistence::LoadResult previous;
  data_reset::CleanupRecord recovered;
  persistence::LoadResult rollback;
  if (persistence::loadPrevious(store, kDataResetCleanupSlots,
                                loaded.generation, previous) &&
      decodeDataResetCleanupRecord(previous.payload, recovered) &&
      persistence::rollbackToPrevious(store, kDataResetCleanupSlots,
                                      loaded.generation, rollback) &&
      rollback.payload == previous.payload) {
    record = std::move(recovered);
    return DataResetStoreResult::Loaded;
  }
  return DataResetStoreResult::ParseFailed;
}

DataResetStoreResult saveTo(persistence::BlobStore &store,
                            const data_reset::CleanupRecord &record) {
  if (!data_reset::validCleanupRecord(record))
    return DataResetStoreResult::InvalidRecord;
  const std::vector<std::uint8_t> payload =
      encodeDataResetCleanupRecord(record);
  if (payload.empty())
    return DataResetStoreResult::SerializeFailed;
  data_reset::CleanupRecord canonical;
  if (!decodeDataResetCleanupRecord(payload, canonical) ||
      !data_reset::cleanupRecordsEqual(canonical, record))
    return DataResetStoreResult::SerializeFailed;
  data_reset::CleanupRecord current;
  const DataResetStoreResult loaded = loadFrom(store, current);
  if (loaded == DataResetStoreResult::Loaded) {
    if (data_reset::cleanupRecordsEqual(current, record))
      return DataResetStoreResult::SavedAndVerified;
    if (!data_reset::validCleanupRecordUpdate(current, record))
      return DataResetStoreResult::InvalidTransition;
  } else if (loaded != DataResetStoreResult::NotFound) {
    return loaded;
  } else if (record.state != data_reset::CleanupState::Planned) {
    return DataResetStoreResult::InvalidTransition;
  }
  persistence::CommitResult committed;
  if (!persistence::commit(store, kDataResetCleanupSlots, payload, committed) ||
      !committed.committed)
    return DataResetStoreResult::CommitFailed;
  data_reset::CleanupRecord readback;
  if (loadFrom(store, readback) != DataResetStoreResult::Loaded)
    return DataResetStoreResult::ReadbackFailed;
  return data_reset::cleanupRecordsEqual(record, readback)
             ? DataResetStoreResult::SavedAndVerified
             : DataResetStoreResult::IdentityMismatch;
}

DataResetStoreResult scrubCompletedCopies(
    persistence::BlobStore &store,
    const data_reset::CleanupRecord &completed) {
  if (completed.state != data_reset::CleanupState::Completed ||
      !data_reset::validCleanupRecord(completed)) {
    return DataResetStoreResult::InvalidRecord;
  }
  persistence::LoadResult active;
  data_reset::CleanupRecord active_record;
  if (!persistence::loadActive(store, kDataResetCleanupSlots, active) ||
      !decodeDataResetCleanupRecord(active.payload, active_record) ||
      !data_reset::cleanupRecordsEqual(active_record, completed)) {
    return DataResetStoreResult::IdentityMismatch;
  }

  persistence::LoadResult previous;
  data_reset::CleanupRecord previous_record;
  if (persistence::loadPrevious(store, kDataResetCleanupSlots,
                                active.generation, previous) &&
      decodeDataResetCleanupRecord(previous.payload, previous_record) &&
      data_reset::cleanupRecordsEqual(previous_record, completed)) {
    return DataResetStoreResult::SavedAndVerified;
  }

  const std::vector<std::uint8_t> payload =
      encodeDataResetCleanupRecord(completed);
  persistence::CommitResult committed;
  if (payload.empty() ||
      !persistence::commit(store, kDataResetCleanupSlots, payload,
                           committed) ||
      !committed.committed) {
    return DataResetStoreResult::CommitFailed;
  }
  persistence::LoadResult verified_active;
  persistence::LoadResult verified_previous;
  data_reset::CleanupRecord verified_active_record;
  data_reset::CleanupRecord verified_previous_record;
  if (!persistence::loadActive(store, kDataResetCleanupSlots,
                               verified_active) ||
      !decodeDataResetCleanupRecord(verified_active.payload,
                                    verified_active_record) ||
      !data_reset::cleanupRecordsEqual(verified_active_record, completed) ||
      !persistence::loadPrevious(store, kDataResetCleanupSlots,
                                 verified_active.generation,
                                 verified_previous) ||
      !decodeDataResetCleanupRecord(verified_previous.payload,
                                    verified_previous_record) ||
      !data_reset::cleanupRecordsEqual(verified_previous_record, completed)) {
    return DataResetStoreResult::ReadbackFailed;
  }
  return DataResetStoreResult::SavedAndVerified;
}

#if !defined(PM_NATIVE_TEST)
constexpr char kPersistentPartition[] = "nvs";
constexpr char kPersistentNamespace[] = "pm-reset";
class PreferencesBlobStore final : public persistence::BlobStore {
public:
  PreferencesBlobStore()
      : ready_(preferences_.begin(kPersistentNamespace, false,
                                  kPersistentPartition)) {}
  ~PreferencesBlobStore() override {
    if (ready_)
      preferences_.end();
  }
  bool read(const char *key, std::vector<std::uint8_t> &value) override {
    if (!ready_)
      return false;
    const std::size_t length = preferences_.getBytesLength(key);
    value.resize(length);
    const bool ok = length != 0U &&
                    preferences_.getBytes(key, value.data(), length) == length;
    if (!ok)
      value.clear();
    return ok;
  }
  bool write(const char *key, const std::uint8_t *value,
             const std::size_t length) override {
    if (!ready_ || length == 0U)
      return false;
    return preferences_.putBytes(key, value, length) == length;
  }
  bool erase(const char *key) override {
    if (!ready_)
      return false;
    return !preferences_.isKey(key) || preferences_.remove(key);
  }
  bool exists(const char *key) override {
    return ready_ && preferences_.isKey(key);
  }
private:
  Preferences preferences_;
  bool ready_{false};
};
#endif

} // namespace

namespace data_reset {

bool validCleanupRecord(const CleanupRecord &record) {
  return (record.state == CleanupState::Planned ||
          record.state == CleanupState::Completed) &&
         record.schema_version == 1U && uuid(record.operation_id) &&
         uuid(record.device_id) &&
         record.source_generation <
             std::numeric_limits<std::uint64_t>::max() &&
         record.target_generation == record.source_generation + 1U &&
         record.card_generation > 0U;
}

bool cleanupRecordsEqual(const CleanupRecord &left,
                         const CleanupRecord &right) {
  return left.schema_version == right.schema_version &&
         left.state == right.state &&
         left.operation_id == right.operation_id &&
         left.device_id == right.device_id &&
         left.source_generation == right.source_generation &&
         left.target_generation == right.target_generation &&
         left.card_generation == right.card_generation &&
         left.reading_files == right.reading_files &&
         left.index_files == right.index_files &&
         left.export_files == right.export_files &&
         left.metadata_files == right.metadata_files &&
         left.bytes == right.bytes;
}

bool validCleanupRecordUpdate(const CleanupRecord &current,
                              const CleanupRecord &proposed) {
  if (!validCleanupRecord(current) || !validCleanupRecord(proposed))
    return false;
  if (current.operation_id != proposed.operation_id) {
    return current.state == CleanupState::Completed &&
           proposed.state == CleanupState::Planned &&
           (current.device_id != proposed.device_id ||
            proposed.target_generation > current.target_generation);
  }
  CleanupRecord expected = current;
  expected.state = CleanupState::Completed;
  return current.state == CleanupState::Planned &&
         cleanupRecordsEqual(expected, proposed);
}

} // namespace data_reset

std::vector<std::uint8_t>
encodeDataResetCleanupRecord(const data_reset::CleanupRecord &record) {
  if (!data_reset::validCleanupRecord(record))
    return {};
  JsonDocument document;
  document["schema_version"] = record.schema_version;
  document["state"] = static_cast<std::uint8_t>(record.state);
  document["operation_id"] = record.operation_id;
  document["device_id"] = record.device_id;
  document["source_generation"] = record.source_generation;
  document["target_generation"] = record.target_generation;
  document["card_generation"] = record.card_generation;
  document["reading_files"] = record.reading_files;
  document["index_files"] = record.index_files;
  document["export_files"] = record.export_files;
  document["metadata_files"] = record.metadata_files;
  document["bytes"] = record.bytes;
  std::string payload;
  serializeJson(document, payload);
  return payload.empty() ||
                 payload.size() > data_reset::kCleanupJournalMaximumBytes
             ? std::vector<std::uint8_t>{}
             : std::vector<std::uint8_t>(payload.begin(), payload.end());
}

bool decodeDataResetCleanupRecord(const std::vector<std::uint8_t> &encoded,
                                  data_reset::CleanupRecord &record) {
  record = {};
  if (encoded.empty() ||
      encoded.size() > data_reset::kCleanupJournalMaximumBytes)
    return false;
  JsonDocument document;
  if (deserializeJson(document, encoded.data(), encoded.size()) ||
      !document["schema_version"].is<std::uint32_t>() ||
      !document["state"].is<std::uint8_t>() ||
      !document["operation_id"].is<const char *>() ||
      !document["device_id"].is<const char *>() ||
      !document["source_generation"].is<std::uint64_t>() ||
      !document["target_generation"].is<std::uint64_t>() ||
      !document["card_generation"].is<std::uint64_t>() ||
      !document["reading_files"].is<std::uint64_t>() ||
      !document["index_files"].is<std::uint64_t>() ||
      !document["export_files"].is<std::uint64_t>() ||
      !document["metadata_files"].is<std::uint64_t>() ||
      !document["bytes"].is<std::uint64_t>())
    return false;
  record.schema_version = document["schema_version"].as<std::uint32_t>();
  record.state = static_cast<data_reset::CleanupState>(
      document["state"].as<std::uint8_t>());
  record.operation_id = document["operation_id"].as<const char *>();
  record.device_id = document["device_id"].as<const char *>();
  record.source_generation =
      document["source_generation"].as<std::uint64_t>();
  record.target_generation =
      document["target_generation"].as<std::uint64_t>();
  record.card_generation = document["card_generation"].as<std::uint64_t>();
  record.reading_files = document["reading_files"].as<std::uint64_t>();
  record.index_files = document["index_files"].as<std::uint64_t>();
  record.export_files = document["export_files"].as<std::uint64_t>();
  record.metadata_files = document["metadata_files"].as<std::uint64_t>();
  record.bytes = document["bytes"].as<std::uint64_t>();
  return data_reset::validCleanupRecord(record);
}

DataResetStoreResult
DataResetCleanupStore::load(data_reset::CleanupRecord &record) const {
  if (store_ != nullptr)
    return loadFrom(*store_, record);
#if !defined(PM_NATIVE_TEST)
  PreferencesBlobStore store;
  return loadFrom(store, record);
#else
  record = {};
  return DataResetStoreResult::BackendUnavailable;
#endif
}

DataResetStoreResult DataResetCleanupStore::saveAndVerify(
    const data_reset::CleanupRecord &record) const {
  if (store_ != nullptr)
    return saveTo(*store_, record);
#if !defined(PM_NATIVE_TEST)
  PreferencesBlobStore store;
  return saveTo(store, record);
#else
  return DataResetStoreResult::BackendUnavailable;
#endif
}

DataResetStoreResult DataResetCleanupStore::scrubCompletedPayloadCopies(
    const data_reset::CleanupRecord &completed) const {
  if (store_ != nullptr)
    return scrubCompletedCopies(*store_, completed);
#if !defined(PM_NATIVE_TEST)
  PreferencesBlobStore store;
  return scrubCompletedCopies(store, completed);
#else
  return DataResetStoreResult::BackendUnavailable;
#endif
}

} // namespace pm
