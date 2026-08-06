#include "reset/DataResetStore.h"

#include <cstddef>
#include <limits>
#include <string>

#if !defined(PM_NATIVE_TEST)
#include <Preferences.h>
#endif

namespace pm {
namespace {

constexpr std::uint32_t kMagic = 0x52444D50U; // PMDR
constexpr std::uint16_t kFormatVersion = 2U;
constexpr std::size_t kMaximumEncodedSize = 16U * 1024U;
constexpr std::uint8_t kExpectedBuildHashFlag = 1U << 0U;
constexpr std::uint8_t kExpectedCardGenerationFlag = 1U << 1U;
constexpr std::uint8_t kApprovedBoundaryFlag = 1U << 2U;
constexpr std::uint8_t kCommitEnergyBaselineFlag = 1U << 3U;
constexpr std::uint8_t kPrepareDrainSequenceRangeFlag = 1U << 4U;
constexpr std::uint8_t kMeasurementPauseEvidencedFlag = 1U << 6U;
constexpr std::uint8_t kKnownFlags =
    kExpectedBuildHashFlag | kExpectedCardGenerationFlag |
    kApprovedBoundaryFlag | kCommitEnergyBaselineFlag |
    kPrepareDrainSequenceRangeFlag |
    kMeasurementPauseEvidencedFlag;

void appendU16(std::vector<std::uint8_t> &output,
               const std::uint16_t value) {
  output.push_back(static_cast<std::uint8_t>(value));
  output.push_back(static_cast<std::uint8_t>(value >> 8U));
}

void appendU32(std::vector<std::uint8_t> &output,
               const std::uint32_t value) {
  for (std::uint8_t shift = 0U; shift < 32U; shift += 8U)
    output.push_back(static_cast<std::uint8_t>(value >> shift));
}

void appendU64(std::vector<std::uint8_t> &output,
               const std::uint64_t value) {
  for (std::uint8_t shift = 0U; shift < 64U; shift += 8U)
    output.push_back(static_cast<std::uint8_t>(value >> shift));
}

void appendString(std::vector<std::uint8_t> &output,
                  const std::string &value) {
  appendU16(output, static_cast<std::uint16_t>(value.size()));
  output.insert(output.end(), value.begin(), value.end());
}

bool readU8(const std::vector<std::uint8_t> &input, std::size_t &cursor,
            const std::size_t end, std::uint8_t &value) {
  if (cursor >= end)
    return false;
  value = input[cursor++];
  return true;
}

bool readU16(const std::vector<std::uint8_t> &input, std::size_t &cursor,
             const std::size_t end, std::uint16_t &value) {
  if (cursor + 2U > end)
    return false;
  value = static_cast<std::uint16_t>(input[cursor]) |
          static_cast<std::uint16_t>(input[cursor + 1U]) << 8U;
  cursor += 2U;
  return true;
}

bool readU32(const std::vector<std::uint8_t> &input, std::size_t &cursor,
             const std::size_t end, std::uint32_t &value) {
  if (cursor + 4U > end)
    return false;
  value = 0U;
  for (std::uint8_t shift = 0U; shift < 32U; shift += 8U)
    value |= static_cast<std::uint32_t>(input[cursor++]) << shift;
  return true;
}

bool readU64(const std::vector<std::uint8_t> &input, std::size_t &cursor,
             const std::size_t end, std::uint64_t &value) {
  if (cursor + 8U > end)
    return false;
  value = 0U;
  for (std::uint8_t shift = 0U; shift < 64U; shift += 8U)
    value |= static_cast<std::uint64_t>(input[cursor++]) << shift;
  return true;
}

bool readString(const std::vector<std::uint8_t> &input, std::size_t &cursor,
                const std::size_t end, const std::size_t maximum,
                std::string &value) {
  std::uint16_t length = 0U;
  if (!readU16(input, cursor, end, length) || length > maximum ||
      cursor + length > end) {
    return false;
  }
  value.assign(reinterpret_cast<const char *>(input.data() + cursor), length);
  cursor += length;
  return true;
}

bool readNumericFields(const std::vector<std::uint8_t> &encoded,
                       std::size_t &cursor, const std::size_t end,
                       data_reset::Record &record,
                       std::uint64_t &expected_card_generation) {
  return readU64(encoded, cursor, end, record.prepare.target_generation) &&
         readU64(encoded, cursor, end, record.prepare.plan_revision) &&
         readU64(encoded, cursor, end, record.prepare.expected_boundary) &&
         readU64(encoded, cursor, end,
                 record.prepare.server_highest_contiguous) &&
         readU64(encoded, cursor, end, record.prepare.server_maximum_seen) &&
         readU64(encoded, cursor, end, expected_card_generation) &&
         readU64(encoded, cursor, end, record.newest_stored_sequence) &&
         readU64(encoded, cursor, end, record.newest_syncable_sequence) &&
         readU64(encoded, cursor, end,
                 record.sensor_server_acknowledgement) &&
         readU64(encoded, cursor, end, record.sensor_maximum_seen) &&
         readU64(encoded, cursor, end, record.prepared_removal_floor) &&
         readU64(encoded, cursor, end, record.local_sequence_floor) &&
         readU64(encoded, cursor, end, record.next_sequence) &&
         readU64(encoded, cursor, end, record.local_record_count) &&
         readU64(encoded, cursor, end,
                 record.prepare_drain_records_added) &&
         readU64(encoded, cursor, end,
                 record.prepare_drain_first_sequence) &&
         readU64(encoded, cursor, end,
                 record.prepare_drain_last_sequence) &&
         readU64(encoded, cursor, end,
                 record.prepare_drain_syncable_records_added) &&
         readU64(encoded, cursor, end, record.card_generation) &&
         readU64(encoded, cursor, end, record.prepared_pzem_energy_wh) &&
         readU64(encoded, cursor, end,
                 record.software_energy_baseline_before_wh) &&
         readU64(encoded, cursor, end, record.approved_boundary) &&
         readU64(encoded, cursor, end, record.new_sequence_floor) &&
         readU64(encoded, cursor, end, record.new_next_sequence) &&
         readU64(encoded, cursor, end, record.commit_pzem_energy_wh) &&
         readU64(encoded, cursor, end,
                 record.application_energy_baseline_wh) &&
         readU64(encoded, cursor, end, record.verified_pzem_energy_wh) &&
         readU64(encoded, cursor, end, record.readings_deleted) &&
         readU64(encoded, cursor, end, record.indexes_deleted) &&
         readU64(encoded, cursor, end, record.exports_deleted) &&
         readU64(encoded, cursor, end, record.backlog_entries_deleted) &&
         readU64(encoded, cursor, end,
                 record.measurement_pause_started_utc_ms) &&
         readU64(encoded, cursor, end,
                 record.measurement_pause_ended_utc_ms);
}

void appendNumericFields(std::vector<std::uint8_t> &output,
                         const data_reset::Record &record) {
  appendU64(output, record.prepare.target_generation);
  appendU64(output, record.prepare.plan_revision);
  appendU64(output, record.prepare.expected_boundary);
  appendU64(output, record.prepare.server_highest_contiguous);
  appendU64(output, record.prepare.server_maximum_seen);
  appendU64(output, record.prepare.expected_card_generation_set
                        ? record.prepare.expected_card_generation
                        : 0U);
  appendU64(output, record.newest_stored_sequence);
  appendU64(output, record.newest_syncable_sequence);
  appendU64(output, record.sensor_server_acknowledgement);
  appendU64(output, record.sensor_maximum_seen);
  appendU64(output, record.prepared_removal_floor);
  appendU64(output, record.local_sequence_floor);
  appendU64(output, record.next_sequence);
  appendU64(output, record.local_record_count);
  appendU64(output, record.prepare_drain_records_added);
  appendU64(output, record.prepare_drain_first_sequence);
  appendU64(output, record.prepare_drain_last_sequence);
  appendU64(output, record.prepare_drain_syncable_records_added);
  appendU64(output, record.card_generation);
  appendU64(output, record.prepared_pzem_energy_wh);
  appendU64(output, record.software_energy_baseline_before_wh);
  appendU64(output, record.approved_boundary);
  appendU64(output, record.new_sequence_floor);
  appendU64(output, record.new_next_sequence);
  appendU64(output, record.commit_pzem_energy_wh);
  appendU64(output, record.application_energy_baseline_wh);
  appendU64(output, record.verified_pzem_energy_wh);
  appendU64(output, record.readings_deleted);
  appendU64(output, record.indexes_deleted);
  appendU64(output, record.exports_deleted);
  appendU64(output, record.backlog_entries_deleted);
  appendU64(output, record.measurement_pause_started_utc_ms);
  appendU64(output, record.measurement_pause_ended_utc_ms);
}

bool readStringFields(const std::vector<std::uint8_t> &encoded,
                      std::size_t &cursor, const std::size_t end,
                      const std::uint8_t flags,
                      data_reset::Record &record) {
  std::string category;
  std::string expected_build_hash;
  if (!readString(encoded, cursor, end, 32U, record.prepare.protocol) ||
      !readString(encoded, cursor, end, 36U, record.prepare.operation_id) ||
      !readString(encoded, cursor, end, 36U, record.prepare.device_id) ||
      !readString(encoded, cursor, end, 40U, record.prepare.reset_timestamp) ||
      !readString(encoded, cursor, end, 64U, record.prepare.plan_digest) ||
      !readString(encoded, cursor, end, 32U, category) ||
      !readString(encoded, cursor, end, 32U,
                  record.prepare.expected_firmware_version) ||
      !readString(encoded, cursor, end, 64U, expected_build_hash) ||
      !readString(encoded, cursor, end, 32U,
                  record.prepared_firmware_version) ||
      !readString(encoded, cursor, end, 64U, record.prepared_build_hash) ||
      !readString(encoded, cursor, end, 36U, record.prepared_boot_id) ||
      !readString(encoded, cursor, end, 32U, record.sd_status) ||
      !readString(encoded, cursor, end, 64U,
                  record.configuration_digest_before) ||
      !readString(encoded, cursor, end, 4096U, record.prepared_receipt) ||
      !readString(encoded, cursor, end, 64U,
                  record.prepared_receipt_digest) ||
      !readString(encoded, cursor, end, 64U,
                  record.configuration_digest_after) ||
      !readString(encoded, cursor, end, 40U, record.completion_timestamp) ||
      !readString(encoded, cursor, end, 4096U, record.completion_receipt) ||
      !readString(encoded, cursor, end, 80U, record.failure_code)) {
    return false;
  }
  record.prepare.categories = {category};
  if ((flags & kExpectedBuildHashFlag) != 0U) {
    record.prepare.expected_build_hash_set = true;
    record.prepare.expected_build_hash = expected_build_hash;
  } else if (!expected_build_hash.empty()) {
    return false;
  }
  return true;
}

void appendStringFields(std::vector<std::uint8_t> &output,
                        const data_reset::Record &record) {
  appendString(output, record.prepare.protocol);
  appendString(output, record.prepare.operation_id);
  appendString(output, record.prepare.device_id);
  appendString(output, record.prepare.reset_timestamp);
  appendString(output, record.prepare.plan_digest);
  appendString(output, record.prepare.categories.front());
  appendString(output, record.prepare.expected_firmware_version);
  appendString(output, record.prepare.expected_build_hash_set
                           ? record.prepare.expected_build_hash
                           : "");
  appendString(output, record.prepared_firmware_version);
  appendString(output, record.prepared_build_hash);
  appendString(output, record.prepared_boot_id);
  appendString(output, record.sd_status);
  appendString(output, record.configuration_digest_before);
  appendString(output, record.prepared_receipt);
  appendString(output, record.prepared_receipt_digest);
  appendString(output, record.configuration_digest_after);
  appendString(output, record.completion_timestamp);
  appendString(output, record.completion_receipt);
  appendString(output, record.failure_code);
}

DataResetStoreResult loadFrom(persistence::BlobStore &store,
                              data_reset::Record &record,
                              DataResetStoreMetadata *metadata) {
  record = {};
  if (metadata != nullptr)
    *metadata = {};
  if (!persistence::anyDataPresent(store, kDataResetSlots))
    return DataResetStoreResult::NotFound;
  persistence::LoadResult loaded;
  if (!persistence::loadActive(store, kDataResetSlots, loaded))
    return DataResetStoreResult::LoadFailed;
  if (!decodeDataResetRecord(loaded.payload, record)) {
    persistence::LoadResult previous;
    data_reset::Record recovered;
    persistence::LoadResult rollback;
    if (!persistence::loadPrevious(store, kDataResetSlots,
                                   loaded.generation, previous) ||
        !decodeDataResetRecord(previous.payload, recovered) ||
        !persistence::rollbackToPrevious(store, kDataResetSlots,
                                         loaded.generation, rollback) ||
        rollback.payload != previous.payload) {
      return DataResetStoreResult::ParseFailed;
    }
    record = std::move(recovered);
    loaded = std::move(rollback);
    loaded.recovered_fallback = true;
  }
  if (metadata != nullptr) {
    metadata->persistence_generation = loaded.generation;
    metadata->recovered_fallback = loaded.recovered_fallback;
  }
  return DataResetStoreResult::Loaded;
}

DataResetStoreResult saveTo(persistence::BlobStore &store,
                            const data_reset::Record &record,
                            DataResetStoreMetadata *metadata) {
  if (metadata != nullptr)
    *metadata = {};
  if (!data_reset::validRecord(record))
    return DataResetStoreResult::InvalidRecord;
  const std::vector<std::uint8_t> payload = encodeDataResetRecord(record);
  if (payload.empty())
    return DataResetStoreResult::SerializeFailed;
  data_reset::Record canonical;
  if (!decodeDataResetRecord(payload, canonical) ||
      !data_reset::recordsEqual(canonical, record))
    return DataResetStoreResult::SerializeFailed;

  if (persistence::anyDataPresent(store, kDataResetSlots)) {
    persistence::LoadResult current_payload;
    if (!persistence::loadActive(store, kDataResetSlots, current_payload))
      return DataResetStoreResult::LoadFailed;
    data_reset::Record current;
    if (!decodeDataResetRecord(current_payload.payload, current))
      return DataResetStoreResult::ParseFailed;
    if (data_reset::recordsEqual(current, record)) {
      if (metadata != nullptr) {
        metadata->persistence_generation = current_payload.generation;
        metadata->recovered_fallback = current_payload.recovered_fallback;
      }
      return DataResetStoreResult::SavedAndVerified;
    }
    if (!data_reset::validRecordUpdate(current, record))
      return DataResetStoreResult::InvalidTransition;
  } else if (record.state != data_reset::State::Preparing ||
             record.checkpoint != data_reset::Checkpoint::None) {
    return DataResetStoreResult::InvalidTransition;
  }

  persistence::CommitResult committed;
  if (!persistence::commit(store, kDataResetSlots, payload, committed) ||
      !committed.committed) {
    return DataResetStoreResult::CommitFailed;
  }
  persistence::LoadResult loaded;
  if (!persistence::loadActive(store, kDataResetSlots, loaded))
    return DataResetStoreResult::ReadbackFailed;
  data_reset::Record readback;
  if (!decodeDataResetRecord(loaded.payload, readback))
    return DataResetStoreResult::ReadbackFailed;
  if (!data_reset::recordsEqual(record, readback))
    return DataResetStoreResult::IdentityMismatch;
  if (metadata != nullptr) {
    metadata->persistence_generation = loaded.generation;
    metadata->recovered_fallback = loaded.recovered_fallback;
  }
  return DataResetStoreResult::SavedAndVerified;
}

#if !defined(PM_NATIVE_TEST)
constexpr char kPersistentPartition[] = "pmconfig";
constexpr char kPersistentNamespace[] = "pm-state";

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
    const bool read = length != 0U &&
                      preferences_.getBytes(key, value.data(), length) == length;
    if (!read)
      value.clear();
    return read;
  }

  bool write(const char *key, const std::uint8_t *value,
             const std::size_t length) override {
    if (!ready_ || length == 0U) {
      return false;
    }
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

const char *dataResetStoreResultName(const DataResetStoreResult result) {
  switch (result) {
  case DataResetStoreResult::Loaded: return "loaded";
  case DataResetStoreResult::SavedAndVerified: return "saved_and_verified";
  case DataResetStoreResult::NotFound: return "not_found";
  case DataResetStoreResult::InvalidRecord: return "invalid_record";
  case DataResetStoreResult::InvalidTransition: return "invalid_transition";
  case DataResetStoreResult::LoadFailed: return "load_failed";
  case DataResetStoreResult::ParseFailed: return "parse_failed";
  case DataResetStoreResult::SerializeFailed: return "serialize_failed";
  case DataResetStoreResult::CommitFailed: return "commit_failed";
  case DataResetStoreResult::ReadbackFailed: return "readback_failed";
  case DataResetStoreResult::IdentityMismatch: return "identity_mismatch";
  case DataResetStoreResult::BackendUnavailable:
    return "backend_unavailable";
  }
  return "unknown";
}

std::vector<std::uint8_t>
encodeDataResetRecord(const data_reset::Record &record) {
  if (!data_reset::validRecord(record))
    return {};
  std::vector<std::uint8_t> output;
  output.reserve(512U + record.prepared_receipt.size() +
                 record.completion_receipt.size());
  appendU32(output, kMagic);
  appendU16(output, kFormatVersion);
  appendU16(output, 0U);
  appendU32(output, record.schema_version);
  output.push_back(static_cast<std::uint8_t>(record.state));
  output.push_back(static_cast<std::uint8_t>(record.checkpoint));
  std::uint8_t flags = 0U;
  if (record.prepare.expected_build_hash_set)
    flags |= kExpectedBuildHashFlag;
  if (record.prepare.expected_card_generation_set)
    flags |= kExpectedCardGenerationFlag;
  if (record.approved_boundary_set)
    flags |= kApprovedBoundaryFlag;
  if (record.commit_energy_baseline_set)
    flags |= kCommitEnergyBaselineFlag;
  if (record.prepare_drain_sequence_range_set)
    flags |= kPrepareDrainSequenceRangeFlag;
  if (record.measurement_pause_evidenced)
    flags |= kMeasurementPauseEvidencedFlag;
  output.push_back(flags);
  output.push_back(0U);
  appendNumericFields(output, record);
  appendStringFields(output, record);
  if (output.size() + 4U > kMaximumEncodedSize)
    return {};
  appendU32(output, persistence::crc32(output.data(), output.size()));
  return output;
}

bool decodeDataResetRecord(const std::vector<std::uint8_t> &encoded,
                           data_reset::Record &record) {
  record = {};
  if (encoded.size() < 16U + 33U * 8U + 19U * 2U + 4U ||
      encoded.size() > kMaximumEncodedSize) {
    return false;
  }
  const std::size_t checksum_offset = encoded.size() - 4U;
  std::size_t checksum_cursor = checksum_offset;
  std::uint32_t expected_crc = 0U;
  if (!readU32(encoded, checksum_cursor, encoded.size(), expected_crc) ||
      persistence::crc32(encoded.data(), checksum_offset) != expected_crc) {
    return false;
  }

  std::size_t cursor = 0U;
  std::uint32_t magic = 0U;
  std::uint16_t format_version = 0U;
  std::uint16_t reserved = 0U;
  std::uint8_t state = 0U;
  std::uint8_t checkpoint = 0U;
  std::uint8_t flags = 0U;
  std::uint8_t byte_reserved = 0U;
  std::uint64_t expected_card_generation = 0U;
  if (!readU32(encoded, cursor, checksum_offset, magic) ||
      !readU16(encoded, cursor, checksum_offset, format_version) ||
      !readU16(encoded, cursor, checksum_offset, reserved) ||
      !readU32(encoded, cursor, checksum_offset, record.schema_version) ||
      !readU8(encoded, cursor, checksum_offset, state) ||
      !readU8(encoded, cursor, checksum_offset, checkpoint) ||
      !readU8(encoded, cursor, checksum_offset, flags) ||
      !readU8(encoded, cursor, checksum_offset, byte_reserved) ||
      magic != kMagic || format_version != kFormatVersion || reserved != 0U ||
      byte_reserved != 0U || (flags & ~kKnownFlags) != 0U ||
      !readNumericFields(encoded, cursor, checksum_offset, record,
                         expected_card_generation) ||
      !readStringFields(encoded, cursor, checksum_offset, flags, record) ||
      cursor != checksum_offset) {
    record = {};
    return false;
  }

  record.state = static_cast<data_reset::State>(state);
  record.checkpoint = static_cast<data_reset::Checkpoint>(checkpoint);
  record.approved_boundary_set = (flags & kApprovedBoundaryFlag) != 0U;
  record.commit_energy_baseline_set =
      (flags & kCommitEnergyBaselineFlag) != 0U;
  record.prepare_drain_sequence_range_set =
      (flags & kPrepareDrainSequenceRangeFlag) != 0U;
  record.measurement_pause_evidenced =
      (flags & kMeasurementPauseEvidencedFlag) != 0U;
  if ((flags & kExpectedCardGenerationFlag) != 0U) {
    record.prepare.expected_card_generation_set = true;
    record.prepare.expected_card_generation = expected_card_generation;
  } else if (expected_card_generation != 0U) {
    record = {};
    return false;
  }
  if (!data_reset::validRecord(record)) {
    record = {};
    return false;
  }
  return true;
}

DataResetStoreResult
DataResetStore::load(data_reset::Record &record,
                     DataResetStoreMetadata *metadata) const {
  if (store_ != nullptr)
    return loadFrom(*store_, record, metadata);
#if !defined(PM_NATIVE_TEST)
  PreferencesBlobStore store;
  return loadFrom(store, record, metadata);
#else
  record = {};
  if (metadata != nullptr)
    *metadata = {};
  return DataResetStoreResult::BackendUnavailable;
#endif
}

DataResetStoreResult
DataResetStore::saveAndVerify(const data_reset::Record &record,
                              DataResetStoreMetadata *metadata) const {
  if (store_ != nullptr)
    return saveTo(*store_, record, metadata);
#if !defined(PM_NATIVE_TEST)
  PreferencesBlobStore store;
  return saveTo(store, record, metadata);
#else
  if (metadata != nullptr)
    *metadata = {};
  return DataResetStoreResult::BackendUnavailable;
#endif
}

} // namespace pm
