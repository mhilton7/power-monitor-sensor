#include "reset/DataResetEventStore.h"

#include "reset/DataResetCapacityPolicy.h"

#include <cstring>
#include <limits>

#if !defined(PM_NATIVE_TEST)
#include <Preferences.h>
#endif

namespace pm {
namespace {

constexpr std::uint32_t kEventJournalMagic = 0x454A4D50U; // PMJE
constexpr std::uint32_t kEventJournalFormatVersion = 1U;
constexpr std::size_t kMaximumEventJournalBytes =
    data_reset::kEventJournalMaximumBytes;

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

bool validEvent(const data_reset::PreservedEvent &event) {
  return !event.code.empty() && event.code.size() <= 64U &&
         !event.severity.empty() && event.severity.size() <= 16U &&
         event.detail.size() <= 512U && event.boot_id.size() <= 64U &&
         !event.boot_id.empty() && event.source_event_id > 0U &&
         event.required_occurrences == 1U;
}

bool eventEqual(const data_reset::PreservedEvent &left,
                const data_reset::PreservedEvent &right) {
  return left.code == right.code && left.severity == right.severity &&
         left.detail == right.detail && left.boot_id == right.boot_id &&
         left.utc_ms == right.utc_ms &&
         left.source_event_id == right.source_event_id &&
         left.required_occurrences == right.required_occurrences;
}

void appendU64(std::vector<std::uint8_t> &output, const std::uint64_t value) {
  for (std::uint8_t shift = 0U; shift < 64U; shift += 8U)
    output.push_back(static_cast<std::uint8_t>(value >> shift));
}

void appendU32(std::vector<std::uint8_t> &output, const std::uint32_t value) {
  for (std::uint8_t shift = 0U; shift < 32U; shift += 8U)
    output.push_back(static_cast<std::uint8_t>(value >> shift));
}

void appendText(std::vector<std::uint8_t> &output, const std::string &value) {
  appendU64(output, value.size());
  output.insert(output.end(), value.begin(), value.end());
}

bool readU32(const std::vector<std::uint8_t> &input, std::size_t &cursor,
             const std::size_t end, std::uint32_t &value) {
  if (cursor > end || end - cursor < 4U)
    return false;
  value = 0U;
  for (std::uint8_t shift = 0U; shift < 32U; shift += 8U)
    value |= static_cast<std::uint32_t>(input[cursor++]) << shift;
  return true;
}

bool readU64(const std::vector<std::uint8_t> &input, std::size_t &cursor,
             const std::size_t end, std::uint64_t &value) {
  if (cursor > end || end - cursor < 8U)
    return false;
  value = 0U;
  for (std::uint8_t shift = 0U; shift < 64U; shift += 8U)
    value |= static_cast<std::uint64_t>(input[cursor++]) << shift;
  return true;
}

bool readText(const std::vector<std::uint8_t> &input, std::size_t &cursor,
              const std::size_t end, const std::size_t maximum,
              std::string &value) {
  std::uint64_t length = 0U;
  if (!readU64(input, cursor, end, length) || length > maximum ||
      length > end - cursor)
    return false;
  value.assign(reinterpret_cast<const char *>(input.data() + cursor),
               static_cast<std::size_t>(length));
  cursor += static_cast<std::size_t>(length);
  return true;
}

DataResetStoreResult loadFrom(persistence::BlobStore &store,
                              data_reset::EventJournalRecord &record) {
  record = {};
  if (!persistence::anyDataPresent(store, kDataResetEventSlots))
    return DataResetStoreResult::NotFound;
  persistence::LoadResult loaded;
  if (!persistence::loadActive(store, kDataResetEventSlots, loaded))
    return DataResetStoreResult::LoadFailed;
  if (decodeDataResetEventJournal(loaded.payload, record))
    return DataResetStoreResult::Loaded;
  persistence::LoadResult previous;
  data_reset::EventJournalRecord recovered;
  persistence::LoadResult rollback;
  if (persistence::loadPrevious(store, kDataResetEventSlots,
                                loaded.generation, previous) &&
      decodeDataResetEventJournal(previous.payload, recovered) &&
      persistence::rollbackToPrevious(store, kDataResetEventSlots,
                                      loaded.generation, rollback) &&
      rollback.payload == previous.payload) {
    record = std::move(recovered);
    return DataResetStoreResult::Loaded;
  }
  return DataResetStoreResult::ParseFailed;
}

DataResetStoreResult saveTo(persistence::BlobStore &store,
                            const data_reset::EventJournalRecord &record) {
  if (!data_reset::validEventJournalRecord(record))
    return DataResetStoreResult::InvalidRecord;
  const std::vector<std::uint8_t> payload = encodeDataResetEventJournal(record);
  if (payload.empty())
    return DataResetStoreResult::SerializeFailed;
  data_reset::EventJournalRecord canonical;
  if (!decodeDataResetEventJournal(payload, canonical) ||
      !data_reset::eventJournalRecordsEqual(canonical, record))
    return DataResetStoreResult::SerializeFailed;
  data_reset::EventJournalRecord current;
  const DataResetStoreResult loaded = loadFrom(store, current);
  if (loaded == DataResetStoreResult::Loaded) {
    if (data_reset::eventJournalRecordsEqual(current, record))
      return DataResetStoreResult::SavedAndVerified;
    if (!data_reset::validEventJournalRecordUpdate(current, record))
      return DataResetStoreResult::InvalidTransition;
  } else if (loaded != DataResetStoreResult::NotFound) {
    return loaded;
  } else if (record.state != data_reset::EventJournalState::Staged) {
    return DataResetStoreResult::InvalidTransition;
  }
  persistence::CommitResult committed;
  if (!persistence::commit(store, kDataResetEventSlots, payload, committed) ||
      !committed.committed)
    return DataResetStoreResult::CommitFailed;
  data_reset::EventJournalRecord readback;
  if (loadFrom(store, readback) != DataResetStoreResult::Loaded)
    return DataResetStoreResult::ReadbackFailed;
  return data_reset::eventJournalRecordsEqual(record, readback)
             ? DataResetStoreResult::SavedAndVerified
             : DataResetStoreResult::IdentityMismatch;
}

DataResetStoreResult scrubCompletedCopies(
    persistence::BlobStore &store,
    const data_reset::EventJournalRecord &completed) {
  if (completed.state != data_reset::EventJournalState::Completed ||
      !data_reset::validEventJournalRecord(completed)) {
    return DataResetStoreResult::InvalidRecord;
  }
  persistence::LoadResult active;
  data_reset::EventJournalRecord active_record;
  if (!persistence::loadActive(store, kDataResetEventSlots, active) ||
      !decodeDataResetEventJournal(active.payload, active_record) ||
      !data_reset::eventJournalRecordsEqual(active_record, completed)) {
    return DataResetStoreResult::IdentityMismatch;
  }

  persistence::LoadResult previous;
  data_reset::EventJournalRecord previous_record;
  if (persistence::loadPrevious(store, kDataResetEventSlots,
                                active.generation, previous) &&
      decodeDataResetEventJournal(previous.payload, previous_record) &&
      data_reset::eventJournalRecordsEqual(previous_record, completed)) {
    return DataResetStoreResult::SavedAndVerified;
  }

  const std::vector<std::uint8_t> payload =
      encodeDataResetEventJournal(completed);
  persistence::CommitResult committed;
  if (payload.empty() ||
      !persistence::commit(store, kDataResetEventSlots, payload, committed) ||
      !committed.committed) {
    return DataResetStoreResult::CommitFailed;
  }
  persistence::LoadResult verified_active;
  persistence::LoadResult verified_previous;
  data_reset::EventJournalRecord verified_active_record;
  data_reset::EventJournalRecord verified_previous_record;
  if (!persistence::loadActive(store, kDataResetEventSlots,
                               verified_active) ||
      !decodeDataResetEventJournal(verified_active.payload,
                                   verified_active_record) ||
      !data_reset::eventJournalRecordsEqual(verified_active_record,
                                            completed) ||
      !persistence::loadPrevious(store, kDataResetEventSlots,
                                 verified_active.generation,
                                 verified_previous) ||
      !decodeDataResetEventJournal(verified_previous.payload,
                                   verified_previous_record) ||
      !data_reset::eventJournalRecordsEqual(verified_previous_record,
                                            completed)) {
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

std::uint32_t preservedEventCrc32(const PreservedEvent &event) {
  std::vector<std::uint8_t> material;
  material.reserve(event.code.size() + event.severity.size() +
                   event.detail.size() + event.boot_id.size() + 40U);
  appendText(material, event.code);
  appendText(material, event.severity);
  appendText(material, event.detail);
  appendText(material, event.boot_id);
  appendU64(material, event.utc_ms);
  appendU64(material, event.source_event_id);
  appendU64(material, event.required_occurrences);
  return persistence::crc32(material.data(), material.size());
}

bool validEventJournalRecord(const EventJournalRecord &record) {
  const bool known_state = record.state == EventJournalState::Staged ||
                           record.state == EventJournalState::Completed;
  bool payload_ok = record.event_count <= record.events.size();
  for (std::size_t index = 0U; index < record.events.size(); ++index) {
    const bool used = index < record.event_count;
    if (record.state == EventJournalState::Staged && used) {
      payload_ok = payload_ok && validEvent(record.events[index]) &&
                   record.event_crc32[index] != 0U &&
                   preservedEventCrc32(record.events[index]) ==
                       record.event_crc32[index];
    } else {
      payload_ok = payload_ok && eventEqual(record.events[index], {}) &&
                   (used ? record.event_crc32[index] != 0U
                         : record.event_crc32[index] == 0U);
    }
  }
  return known_state && record.schema_version == 1U &&
         uuid(record.operation_id) &&
         uuid(record.device_id) &&
         record.source_generation < std::numeric_limits<std::uint64_t>::max() &&
         record.target_generation == record.source_generation + 1U &&
         record.card_generation > 0U && payload_ok;
}

bool eventJournalRecordsEqual(const EventJournalRecord &left,
                              const EventJournalRecord &right) {
  if (left.schema_version != right.schema_version ||
      left.state != right.state || left.operation_id != right.operation_id ||
      left.device_id != right.device_id ||
      left.source_generation != right.source_generation ||
      left.target_generation != right.target_generation ||
      left.card_generation != right.card_generation ||
      left.event_count != right.event_count ||
      left.event_crc32 != right.event_crc32)
    return false;
  for (std::size_t index = 0U; index < left.events.size(); ++index) {
    if (!eventEqual(left.events[index], right.events[index]))
      return false;
  }
  return true;
}

bool validEventJournalRecordUpdate(const EventJournalRecord &current,
                                   const EventJournalRecord &proposed) {
  if (!validEventJournalRecord(current) ||
      !validEventJournalRecord(proposed))
    return false;
  if (current.operation_id != proposed.operation_id) {
    return current.state == EventJournalState::Completed &&
           proposed.state == EventJournalState::Staged &&
           (current.device_id != proposed.device_id ||
            proposed.target_generation > current.target_generation);
  }
  if (current.state == EventJournalState::Staged &&
      proposed.state == EventJournalState::Staged &&
      current.device_id == proposed.device_id &&
      current.source_generation == proposed.source_generation &&
      current.target_generation == proposed.target_generation &&
      current.card_generation == proposed.card_generation &&
      proposed.event_count >= current.event_count) {
    for (std::size_t index = 0U; index < current.event_count; ++index) {
      if (current.event_crc32[index] != proposed.event_crc32[index] ||
          !eventEqual(current.events[index], proposed.events[index]))
        return false;
    }
    return true;
  }
  if (current.state != EventJournalState::Staged ||
      proposed.state != EventJournalState::Completed ||
      current.device_id != proposed.device_id ||
      current.source_generation != proposed.source_generation ||
      current.target_generation != proposed.target_generation ||
      current.card_generation != proposed.card_generation ||
      current.event_count != proposed.event_count ||
      current.event_crc32 != proposed.event_crc32)
    return false;
  for (const auto &event : proposed.events) {
    if (!eventEqual(event, {}))
      return false;
  }
  return true;
}

} // namespace data_reset

std::vector<std::uint8_t>
encodeDataResetEventJournal(const data_reset::EventJournalRecord &record) {
  if (!data_reset::validEventJournalRecord(record))
    return {};
  std::vector<std::uint8_t> output;
  output.reserve(kMaximumEventJournalBytes);
  appendU32(output, kEventJournalMagic);
  appendU32(output, kEventJournalFormatVersion);
  appendU32(output, record.schema_version);
  appendU32(output, static_cast<std::uint8_t>(record.state));
  appendText(output, record.operation_id);
  appendText(output, record.device_id);
  appendU64(output, record.source_generation);
  appendU64(output, record.target_generation);
  appendU64(output, record.card_generation);
  appendU64(output, record.event_count);
  for (const std::uint32_t checksum : record.event_crc32)
    appendU32(output, checksum);
  if (record.state != data_reset::EventJournalState::Completed) {
    for (std::size_t index = 0U; index < record.event_count; ++index) {
      const auto &event = record.events[index];
      appendText(output, event.code);
      appendText(output, event.severity);
      appendText(output, event.detail);
      appendText(output, event.boot_id);
      appendU64(output, event.utc_ms);
      appendU64(output, event.source_event_id);
      appendU64(output, event.required_occurrences);
    }
  }
  if (output.size() + 4U > kMaximumEventJournalBytes)
    return {};
  appendU32(output, persistence::crc32(output.data(), output.size()));
  return output;
}

bool decodeDataResetEventJournal(const std::vector<std::uint8_t> &encoded,
                                 data_reset::EventJournalRecord &record) {
  record = {};
  constexpr std::size_t kMinimumEncodedBytes = 188U;
  if (encoded.size() < kMinimumEncodedBytes ||
      encoded.size() > kMaximumEventJournalBytes)
    return false;
  const std::size_t checksum_offset = encoded.size() - 4U;
  std::size_t checksum_cursor = checksum_offset;
  std::uint32_t expected_crc = 0U;
  if (!readU32(encoded, checksum_cursor, encoded.size(), expected_crc) ||
      checksum_cursor != encoded.size() ||
      persistence::crc32(encoded.data(), checksum_offset) != expected_crc)
    return false;
  std::size_t cursor = 0U;
  std::uint32_t magic = 0U;
  std::uint32_t format = 0U;
  std::uint32_t state = 0U;
  if (!readU32(encoded, cursor, checksum_offset, magic) ||
      !readU32(encoded, cursor, checksum_offset, format) ||
      !readU32(encoded, cursor, checksum_offset, record.schema_version) ||
      !readU32(encoded, cursor, checksum_offset, state) ||
      magic != kEventJournalMagic || format != kEventJournalFormatVersion ||
      state > std::numeric_limits<std::uint8_t>::max() ||
      !readText(encoded, cursor, checksum_offset, 36U, record.operation_id) ||
      !readText(encoded, cursor, checksum_offset, 36U, record.device_id) ||
      !readU64(encoded, cursor, checksum_offset, record.source_generation) ||
      !readU64(encoded, cursor, checksum_offset, record.target_generation) ||
      !readU64(encoded, cursor, checksum_offset, record.card_generation) ||
      !readU64(encoded, cursor, checksum_offset, record.event_count) ||
      record.event_count > record.events.size())
    return false;
  record.state = static_cast<data_reset::EventJournalState>(state);
  for (std::size_t index = 0U; index < record.event_crc32.size(); ++index) {
    if (!readU32(encoded, cursor, checksum_offset,
                 record.event_crc32[index]))
      return false;
  }
  if (record.state != data_reset::EventJournalState::Completed) {
    for (std::size_t index = 0U; index < record.event_count; ++index) {
      auto &event = record.events[index];
      if (!readText(encoded, cursor, checksum_offset, 64U, event.code) ||
          !readText(encoded, cursor, checksum_offset, 16U, event.severity) ||
          !readText(encoded, cursor, checksum_offset, 512U, event.detail) ||
          !readText(encoded, cursor, checksum_offset, 64U, event.boot_id) ||
          !readU64(encoded, cursor, checksum_offset, event.utc_ms) ||
          !readU64(encoded, cursor, checksum_offset,
                   event.source_event_id) ||
          !readU64(encoded, cursor, checksum_offset,
                   event.required_occurrences))
        return false;
    }
  }
  return cursor == checksum_offset &&
         data_reset::validEventJournalRecord(record);
}

DataResetStoreResult
DataResetEventStore::load(data_reset::EventJournalRecord &record) const {
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

DataResetStoreResult DataResetEventStore::saveAndVerify(
    const data_reset::EventJournalRecord &record) const {
  if (store_ != nullptr)
    return saveTo(*store_, record);
#if !defined(PM_NATIVE_TEST)
  PreferencesBlobStore store;
  return saveTo(store, record);
#else
  return DataResetStoreResult::BackendUnavailable;
#endif
}

DataResetStoreResult DataResetEventStore::scrubCompletedPayloadCopies(
    const data_reset::EventJournalRecord &completed) const {
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
