#include "reset/DataResetDrainStore.h"

#include "reset/DataResetCapacityPolicy.h"

#include <cmath>
#include <cstring>
#include <limits>

#include <ArduinoJson.h>

#if !defined(PM_NATIVE_TEST)
#include <Preferences.h>
#endif

namespace pm {
namespace {

constexpr std::size_t kMaximumDrainBytes =
    data_reset::kDrainJournalMaximumBytes;

bool bounded(const std::string &value, const std::size_t maximum,
             const bool allow_empty = false) {
  if ((!allow_empty && value.empty()) || value.size() > maximum)
    return false;
  for (const unsigned char character : value) {
    if (character < 0x20U || character > 0x7eU)
      return false;
  }
  return true;
}

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

bool localHardwareIdentity(const std::string &value) {
  static constexpr char kPrefix[] = "esp32s3-";
  static constexpr std::size_t kDigestLength = 20U;
  if (value.size() != sizeof(kPrefix) - 1U + kDigestLength ||
      value.compare(0U, sizeof(kPrefix) - 1U, kPrefix) != 0) {
    return false;
  }
  for (std::size_t index = sizeof(kPrefix) - 1U; index < value.size();
       ++index) {
    if (!((value[index] >= '0' && value[index] <= '9') ||
          (value[index] >= 'a' && value[index] <= 'f'))) {
      return false;
    }
  }
  return true;
}

bool authoritativeLocalIdentity(const std::string &value) {
  return uuid(value) || localHardwareIdentity(value);
}

bool intervalEqual(const IntervalRecord &left, const IntervalRecord &right) {
  return left.schema_version == right.schema_version &&
         left.data_generation == right.data_generation &&
         left.device_id == right.device_id &&
         left.friendly_name == right.friendly_name &&
         left.sequence == right.sequence && left.boot_id == right.boot_id &&
         left.start_utc_ms == right.start_utc_ms &&
         left.end_utc_ms == right.end_utc_ms &&
         left.start_monotonic_ms == right.start_monotonic_ms &&
         left.end_monotonic_ms == right.end_monotonic_ms &&
         left.time_trusted == right.time_trusted &&
         left.sample_count == right.sample_count &&
         left.valid_sample_count == right.valid_sample_count &&
         left.avg_voltage_v == right.avg_voltage_v &&
         left.min_voltage_v == right.min_voltage_v &&
         left.max_voltage_v == right.max_voltage_v &&
         left.avg_current_a == right.avg_current_a &&
         left.min_current_a == right.min_current_a &&
         left.max_current_a == right.max_current_a &&
         left.avg_active_power_w == right.avg_active_power_w &&
         left.min_active_power_w == right.min_active_power_w &&
         left.max_active_power_w == right.max_active_power_w &&
         left.avg_power_factor == right.avg_power_factor &&
         left.avg_frequency_hz == right.avg_frequency_hz &&
         left.raw_energy_start_wh == right.raw_energy_start_wh &&
         left.raw_energy_end_wh == right.raw_energy_end_wh &&
         left.device_lifetime_energy_wh == right.device_lifetime_energy_wh &&
         left.interval_energy_wh == right.interval_energy_wh &&
         left.energy_method == right.energy_method &&
         left.ct_rating_a == right.ct_rating_a &&
         left.quality_flags == right.quality_flags &&
         left.firmware_version == right.firmware_version;
}

std::uint32_t floatBits(const float value) {
  std::uint32_t bits = 0U;
  static_assert(sizeof(bits) == sizeof(value), "float size mismatch");
  std::memcpy(&bits, &value, sizeof(bits));
  return bits;
}

float floatFromBits(const std::uint32_t bits) {
  float value = 0.0F;
  std::memcpy(&value, &bits, sizeof(value));
  return value;
}

std::uint64_t doubleBits(const double value) {
  std::uint64_t bits = 0U;
  static_assert(sizeof(bits) == sizeof(value), "double size mismatch");
  std::memcpy(&bits, &value, sizeof(bits));
  return bits;
}

double doubleFromBits(const std::uint64_t bits) {
  double value = 0.0;
  std::memcpy(&value, &bits, sizeof(value));
  return value;
}

bool immutableDrainEvidenceEqual(const data_reset::DrainRecord &left,
                                 const data_reset::DrainRecord &right) {
  return left.operation_id == right.operation_id &&
         left.device_id == right.device_id &&
         left.source_generation == right.source_generation &&
         left.target_generation == right.target_generation &&
         left.card_generation == right.card_generation &&
         left.proposed_energy_offset_wh == right.proposed_energy_offset_wh &&
         left.interval_count == right.interval_count &&
         left.interval_crc32 == right.interval_crc32;
}

void writeInterval(JsonObject object, const IntervalRecord &record) {
  object["schema_version"] = record.schema_version;
  object["data_generation"] = record.data_generation;
  object["device_id"] = record.device_id;
  object["friendly_name"] = record.friendly_name;
  object["sequence"] = record.sequence;
  object["boot_id"] = record.boot_id;
  object["start_utc_ms"] = record.start_utc_ms;
  object["end_utc_ms"] = record.end_utc_ms;
  object["start_monotonic_ms"] = record.start_monotonic_ms;
  object["end_monotonic_ms"] = record.end_monotonic_ms;
  object["time_trusted"] = record.time_trusted;
  object["sample_count"] = record.sample_count;
  object["valid_sample_count"] = record.valid_sample_count;
  // Persist IEEE-754 bits as integers. ArduinoJson's textual float precision
  // is intentionally shorter than a bit-exact round trip; reset drain
  // readback must reproduce the exact interval that will be appended to SD.
  object["avg_voltage_v"] = floatBits(record.avg_voltage_v);
  object["min_voltage_v"] = floatBits(record.min_voltage_v);
  object["max_voltage_v"] = floatBits(record.max_voltage_v);
  object["avg_current_a"] = floatBits(record.avg_current_a);
  object["min_current_a"] = floatBits(record.min_current_a);
  object["max_current_a"] = floatBits(record.max_current_a);
  object["avg_active_power_w"] = floatBits(record.avg_active_power_w);
  object["min_active_power_w"] = floatBits(record.min_active_power_w);
  object["max_active_power_w"] = floatBits(record.max_active_power_w);
  object["avg_power_factor"] = floatBits(record.avg_power_factor);
  object["avg_frequency_hz"] = floatBits(record.avg_frequency_hz);
  object["raw_energy_start_wh"] = record.raw_energy_start_wh;
  object["raw_energy_end_wh"] = record.raw_energy_end_wh;
  object["device_lifetime_energy_wh"] = record.device_lifetime_energy_wh;
  object["interval_energy_wh"] = doubleBits(record.interval_energy_wh);
  object["energy_method"] = record.energy_method;
  object["ct_rating_a"] = floatBits(record.ct_rating_a);
  object["quality_flags"] = record.quality_flags;
  object["firmware_version"] = record.firmware_version;
}

std::uint32_t intervalCrc32(const IntervalRecord &record) {
  JsonDocument document;
  writeInterval(document.to<JsonObject>(), record);
  std::string payload;
  serializeJson(document, payload);
  return payload.empty()
             ? 0U
             : persistence::crc32(
                   reinterpret_cast<const std::uint8_t *>(payload.data()),
                   payload.size());
}

bool readInterval(const JsonObjectConst object, IntervalRecord &record) {
  if (object.isNull())
    return false;
#define PM_DRAIN_READ_INTEGER(name, type)                                     \
  if (!object[#name].is<type>())                                              \
    return false;                                                             \
  record.name = object[#name].as<type>()
#define PM_DRAIN_READ_FLOAT(name)                                             \
  if (!object[#name].is<std::uint32_t>())                                     \
    return false;                                                             \
  record.name = floatFromBits(object[#name].as<std::uint32_t>())
  PM_DRAIN_READ_INTEGER(schema_version, std::uint32_t);
  PM_DRAIN_READ_INTEGER(data_generation, std::uint64_t);
  PM_DRAIN_READ_INTEGER(sequence, std::uint64_t);
  PM_DRAIN_READ_INTEGER(start_utc_ms, std::uint64_t);
  PM_DRAIN_READ_INTEGER(end_utc_ms, std::uint64_t);
  PM_DRAIN_READ_INTEGER(start_monotonic_ms, std::uint64_t);
  PM_DRAIN_READ_INTEGER(end_monotonic_ms, std::uint64_t);
  PM_DRAIN_READ_INTEGER(sample_count, std::uint32_t);
  PM_DRAIN_READ_INTEGER(valid_sample_count, std::uint32_t);
  PM_DRAIN_READ_INTEGER(raw_energy_start_wh, std::uint64_t);
  PM_DRAIN_READ_INTEGER(raw_energy_end_wh, std::uint64_t);
  PM_DRAIN_READ_INTEGER(device_lifetime_energy_wh, std::uint64_t);
  PM_DRAIN_READ_INTEGER(quality_flags, std::uint32_t);
  PM_DRAIN_READ_FLOAT(avg_voltage_v);
  PM_DRAIN_READ_FLOAT(min_voltage_v);
  PM_DRAIN_READ_FLOAT(max_voltage_v);
  PM_DRAIN_READ_FLOAT(avg_current_a);
  PM_DRAIN_READ_FLOAT(min_current_a);
  PM_DRAIN_READ_FLOAT(max_current_a);
  PM_DRAIN_READ_FLOAT(avg_active_power_w);
  PM_DRAIN_READ_FLOAT(min_active_power_w);
  PM_DRAIN_READ_FLOAT(max_active_power_w);
  PM_DRAIN_READ_FLOAT(avg_power_factor);
  PM_DRAIN_READ_FLOAT(avg_frequency_hz);
  PM_DRAIN_READ_FLOAT(ct_rating_a);
#undef PM_DRAIN_READ_FLOAT
#undef PM_DRAIN_READ_INTEGER
  if (!object["time_trusted"].is<bool>() ||
      !object["interval_energy_wh"].is<std::uint64_t>() ||
      !object["device_id"].is<const char *>() ||
      !object["friendly_name"].is<const char *>() ||
      !object["boot_id"].is<const char *>() ||
      !object["energy_method"].is<const char *>() ||
      !object["firmware_version"].is<const char *>()) {
    return false;
  }
  record.time_trusted = object["time_trusted"].as<bool>();
  record.interval_energy_wh = doubleFromBits(
      object["interval_energy_wh"].as<std::uint64_t>());
  record.device_id = object["device_id"].as<const char *>();
  record.friendly_name = object["friendly_name"].as<const char *>();
  record.boot_id = object["boot_id"].as<const char *>();
  record.energy_method = object["energy_method"].as<const char *>();
  record.firmware_version = object["firmware_version"].as<const char *>();
  return true;
}

DataResetStoreResult loadFrom(persistence::BlobStore &store,
                              data_reset::DrainRecord &record) {
  record = {};
  if (!persistence::anyDataPresent(store, kDataResetDrainSlots))
    return DataResetStoreResult::NotFound;
  persistence::LoadResult loaded;
  if (!persistence::loadActive(store, kDataResetDrainSlots, loaded))
    return DataResetStoreResult::LoadFailed;
  if (decodeDataResetDrainRecord(loaded.payload, record))
    return DataResetStoreResult::Loaded;
  persistence::LoadResult previous;
  data_reset::DrainRecord recovered;
  persistence::LoadResult rollback;
  if (persistence::loadPrevious(store, kDataResetDrainSlots,
                                loaded.generation, previous) &&
      decodeDataResetDrainRecord(previous.payload, recovered) &&
      persistence::rollbackToPrevious(store, kDataResetDrainSlots,
                                      loaded.generation, rollback) &&
      rollback.payload == previous.payload) {
    record = std::move(recovered);
    return DataResetStoreResult::Loaded;
  }
  return DataResetStoreResult::ParseFailed;
}

DataResetStoreResult saveTo(persistence::BlobStore &store,
                            const data_reset::DrainRecord &record) {
  if (!data_reset::validDrainRecord(record))
    return DataResetStoreResult::InvalidRecord;
  const std::vector<std::uint8_t> payload = encodeDataResetDrainRecord(record);
  if (payload.empty())
    return DataResetStoreResult::SerializeFailed;
  data_reset::DrainRecord canonical;
  if (!decodeDataResetDrainRecord(payload, canonical) ||
      !data_reset::drainRecordsEqual(canonical, record))
    return DataResetStoreResult::SerializeFailed;
  data_reset::DrainRecord current;
  const DataResetStoreResult loaded = loadFrom(store, current);
  if (loaded == DataResetStoreResult::Loaded) {
    if (data_reset::drainRecordsEqual(current, record))
      return DataResetStoreResult::SavedAndVerified;
    if (!data_reset::validDrainRecordUpdate(current, record))
      return DataResetStoreResult::InvalidTransition;
  } else if (loaded != DataResetStoreResult::NotFound) {
    return loaded;
  } else if (record.state != data_reset::DrainState::Staged) {
    return DataResetStoreResult::InvalidTransition;
  }
  persistence::CommitResult committed;
  if (!persistence::commit(store, kDataResetDrainSlots, payload, committed) ||
      !committed.committed)
    return DataResetStoreResult::CommitFailed;
  data_reset::DrainRecord readback;
  if (loadFrom(store, readback) != DataResetStoreResult::Loaded)
    return DataResetStoreResult::ReadbackFailed;
  return data_reset::drainRecordsEqual(record, readback)
             ? DataResetStoreResult::SavedAndVerified
             : DataResetStoreResult::IdentityMismatch;
}

DataResetStoreResult scrubCompletedCopies(
    persistence::BlobStore &store,
    const data_reset::DrainRecord &completed) {
  if (completed.state != data_reset::DrainState::Completed ||
      !data_reset::validDrainRecord(completed))
    return DataResetStoreResult::InvalidRecord;
  persistence::LoadResult active;
  data_reset::DrainRecord active_record;
  if (!persistence::loadActive(store, kDataResetDrainSlots, active) ||
      !decodeDataResetDrainRecord(active.payload, active_record) ||
      !data_reset::drainRecordsEqual(active_record, completed))
    return DataResetStoreResult::IdentityMismatch;

  persistence::LoadResult previous;
  data_reset::DrainRecord previous_record;
  if (persistence::loadPrevious(store, kDataResetDrainSlots,
                                active.generation, previous) &&
      decodeDataResetDrainRecord(previous.payload, previous_record) &&
      data_reset::drainRecordsEqual(previous_record, completed)) {
    return DataResetStoreResult::SavedAndVerified;
  }

  const std::vector<std::uint8_t> payload =
      encodeDataResetDrainRecord(completed);
  persistence::CommitResult committed;
  if (payload.empty() ||
      !persistence::commit(store, kDataResetDrainSlots, payload, committed) ||
      !committed.committed)
    return DataResetStoreResult::CommitFailed;

  persistence::LoadResult verified_active;
  persistence::LoadResult verified_previous;
  data_reset::DrainRecord verified_active_record;
  data_reset::DrainRecord verified_previous_record;
  if (!persistence::loadActive(store, kDataResetDrainSlots,
                               verified_active) ||
      !decodeDataResetDrainRecord(verified_active.payload,
                                  verified_active_record) ||
      !data_reset::drainRecordsEqual(verified_active_record, completed) ||
      !persistence::loadPrevious(store, kDataResetDrainSlots,
                                 verified_active.generation,
                                 verified_previous) ||
      !decodeDataResetDrainRecord(verified_previous.payload,
                                  verified_previous_record) ||
      !data_reset::drainRecordsEqual(verified_previous_record, completed)) {
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

std::uint32_t drainIntervalCrc32(const IntervalRecord &record) {
  return intervalCrc32(record);
}

bool validDrainRecord(const DrainRecord &record) {
  const bool known_state = record.state == DrainState::Staged ||
                           record.state == DrainState::Assigned ||
                           record.state == DrainState::Completed;
  const bool assigned = record.state == DrainState::Assigned ||
                        record.state == DrainState::Completed;
  const bool payload_present = record.state != DrainState::Completed;
  const IntervalRecord empty_interval{};
  bool payload_valid = record.interval_count >= 1U &&
                       record.interval_count <= record.intervals.size();
  for (std::size_t index = 0U; index < record.intervals.size(); ++index) {
    const bool used = index < record.interval_count;
    const IntervalRecord &interval = record.intervals[index];
    if (used && payload_present) {
      payload_valid =
          payload_valid && interval.schema_version == 1U &&
          interval.data_generation == record.source_generation &&
          interval.device_id == record.device_id &&
          bounded(interval.friendly_name, 64U) && uuid(interval.boot_id) &&
          interval.sequence == 0U && interval.sample_count > 0U &&
          interval.valid_sample_count <= interval.sample_count &&
          interval.end_monotonic_ms >= interval.start_monotonic_ms &&
          bounded(interval.energy_method, 32U) &&
          bounded(interval.firmware_version, 32U) &&
          std::isfinite(interval.interval_energy_wh) &&
          std::isfinite(interval.avg_voltage_v) &&
          std::isfinite(interval.avg_current_a) &&
          std::isfinite(interval.avg_active_power_w) &&
          record.interval_crc32[index] != 0U &&
          intervalCrc32(interval) == record.interval_crc32[index];
    } else {
      payload_valid = payload_valid &&
                      intervalEqual(interval, empty_interval) &&
                      (!used || record.interval_crc32[index] != 0U) &&
                      (used || record.interval_crc32[index] == 0U);
    }
  }
  return known_state && record.schema_version == 1U &&
         uuid(record.operation_id) &&
         uuid(record.device_id) &&
         record.source_generation <
             std::numeric_limits<std::uint64_t>::max() &&
         record.target_generation == record.source_generation + 1U &&
         record.card_generation > 0U && payload_valid &&
         (assigned ? record.assigned_first_sequence > 0U
                   : record.assigned_first_sequence == 0U) &&
         (record.state == DrainState::Completed
              ? record.syncable_records_added <= record.interval_count
              : record.syncable_records_added == 0U);
}

bool drainRecordsEqual(const DrainRecord &left, const DrainRecord &right) {
  return left.schema_version == right.schema_version &&
         left.state == right.state &&
         immutableDrainEvidenceEqual(left, right) &&
         left.assigned_first_sequence == right.assigned_first_sequence &&
         left.syncable_records_added == right.syncable_records_added &&
         intervalEqual(left.intervals[0], right.intervals[0]) &&
         intervalEqual(left.intervals[1], right.intervals[1]);
}

bool validDrainRecordUpdate(const DrainRecord &current,
                            const DrainRecord &proposed) {
  if (!validDrainRecord(current) || !validDrainRecord(proposed))
    return false;
  if (current.operation_id != proposed.operation_id) {
    return current.state == DrainState::Completed &&
           proposed.state == DrainState::Staged &&
           (current.device_id != proposed.device_id ||
            proposed.target_generation >= current.target_generation);
  }
  if (!immutableDrainEvidenceEqual(current, proposed))
    return false;
  const auto current_state = static_cast<std::uint8_t>(current.state);
  const auto proposed_state = static_cast<std::uint8_t>(proposed.state);
  if (proposed_state != current_state + 1U)
    return false;
  if (current.state == DrainState::Staged) {
    return intervalEqual(current.intervals[0], proposed.intervals[0]) &&
           intervalEqual(current.intervals[1], proposed.intervals[1]) &&
           proposed.assigned_first_sequence > 0U &&
           proposed.syncable_records_added == 0U;
  }
  return current.state == DrainState::Assigned &&
         proposed.assigned_first_sequence ==
             current.assigned_first_sequence &&
         intervalEqual(proposed.intervals[0], IntervalRecord{}) &&
         intervalEqual(proposed.intervals[1], IntervalRecord{});
}

bool completedDrainFromDifferentDevice(
    const DrainRecord &record, const std::string &current_device_id) {
  return authoritativeLocalIdentity(current_device_id) &&
         validDrainRecord(record) &&
         record.state == DrainState::Completed &&
         record.device_id != current_device_id;
}

bool completedDrainMatchesCurrentGeneration(
    const DrainRecord &record, const std::string &current_device_id,
    const std::uint64_t current_generation) {
  return uuid(current_device_id) && validDrainRecord(record) &&
         record.state == DrainState::Completed &&
         record.device_id == current_device_id &&
         record.target_generation == current_generation;
}

} // namespace data_reset

std::vector<std::uint8_t>
encodeDataResetDrainRecord(const data_reset::DrainRecord &record) {
  if (!data_reset::validDrainRecord(record))
    return {};
  JsonDocument document;
  document["schema_version"] = record.schema_version;
  document["state"] = static_cast<std::uint8_t>(record.state);
  document["operation_id"] = record.operation_id;
  document["device_id"] = record.device_id;
  document["source_generation"] = record.source_generation;
  document["target_generation"] = record.target_generation;
  document["card_generation"] = record.card_generation;
  document["proposed_energy_offset_wh"] = record.proposed_energy_offset_wh;
  document["assigned_first_sequence"] = record.assigned_first_sequence;
  document["syncable_records_added"] = record.syncable_records_added;
  document["interval_count"] = record.interval_count;
  JsonArray checksums = document["interval_crc32"].to<JsonArray>();
  for (const std::uint32_t checksum : record.interval_crc32)
    checksums.add(checksum);
  if (record.state == data_reset::DrainState::Completed) {
    document["intervals"] = nullptr;
  } else {
    JsonArray intervals = document["intervals"].to<JsonArray>();
    for (std::size_t index = 0U; index < record.interval_count; ++index)
      writeInterval(intervals.add<JsonObject>(), record.intervals[index]);
  }
  std::string payload;
  serializeJson(document, payload);
  if (payload.empty() || payload.size() > kMaximumDrainBytes)
    return {};
  return {payload.begin(), payload.end()};
}

bool decodeDataResetDrainRecord(const std::vector<std::uint8_t> &encoded,
                                data_reset::DrainRecord &record) {
  record = {};
  if (encoded.empty() || encoded.size() > kMaximumDrainBytes)
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
      !document["proposed_energy_offset_wh"].is<std::uint64_t>() ||
      !document["assigned_first_sequence"].is<std::uint64_t>() ||
      !document["syncable_records_added"].is<std::uint64_t>() ||
      !document["interval_count"].is<std::uint64_t>() ||
      !document["interval_crc32"].is<JsonArrayConst>()) {
    return false;
  }
  record.schema_version = document["schema_version"].as<std::uint32_t>();
  record.state =
      static_cast<data_reset::DrainState>(document["state"].as<std::uint8_t>());
  record.operation_id = document["operation_id"].as<const char *>();
  record.device_id = document["device_id"].as<const char *>();
  record.source_generation =
      document["source_generation"].as<std::uint64_t>();
  record.target_generation =
      document["target_generation"].as<std::uint64_t>();
  record.card_generation = document["card_generation"].as<std::uint64_t>();
  record.proposed_energy_offset_wh =
      document["proposed_energy_offset_wh"].as<std::uint64_t>();
  record.assigned_first_sequence =
      document["assigned_first_sequence"].as<std::uint64_t>();
  record.syncable_records_added =
      document["syncable_records_added"].as<std::uint64_t>();
  record.interval_count = document["interval_count"].as<std::uint64_t>();
  const JsonArrayConst checksums =
      document["interval_crc32"].as<JsonArrayConst>();
  if (checksums.size() != record.interval_crc32.size())
    return false;
  for (std::size_t index = 0U; index < record.interval_crc32.size(); ++index) {
    if (!checksums[index].is<std::uint32_t>())
      return false;
    record.interval_crc32[index] = checksums[index].as<std::uint32_t>();
  }
  const bool completed = record.state == data_reset::DrainState::Completed;
  if (!completed) {
    const JsonArrayConst intervals = document["intervals"].as<JsonArrayConst>();
    if (intervals.size() != record.interval_count ||
        record.interval_count > record.intervals.size())
      return false;
    for (std::size_t index = 0U; index < record.interval_count; ++index) {
      if (!readInterval(intervals[index].as<JsonObjectConst>(),
                        record.intervals[index]))
        return false;
    }
  }
  return data_reset::validDrainRecord(record);
}

DataResetStoreResult
DataResetDrainStore::load(data_reset::DrainRecord &record) const {
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

DataResetStoreResult DataResetDrainStore::saveAndVerify(
    const data_reset::DrainRecord &record) const {
  if (store_ != nullptr)
    return saveTo(*store_, record);
#if !defined(PM_NATIVE_TEST)
  PreferencesBlobStore store;
  return saveTo(store, record);
#else
  return DataResetStoreResult::BackendUnavailable;
#endif
}

DataResetStoreResult DataResetDrainStore::scrubCompletedPayloadCopies(
    const data_reset::DrainRecord &completed) const {
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
