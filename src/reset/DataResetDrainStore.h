#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "config/AtomicConfigStore.h"
#include "core/Models.h"
#include "reset/DataResetStore.h"

namespace pm {
namespace data_reset {

enum class DrainState : std::uint8_t { Staged = 1U, Assigned, Completed };

struct DrainRecord {
  std::uint32_t schema_version{1U};
  DrainState state{DrainState::Staged};
  std::string operation_id;
  std::string device_id;
  std::uint64_t source_generation{0U};
  std::uint64_t target_generation{0U};
  std::uint64_t card_generation{0U};
  std::uint64_t proposed_energy_offset_wh{0U};
  std::uint64_t assigned_first_sequence{0U};
  std::uint64_t syncable_records_added{0U};
  std::uint64_t interval_count{0U};
  std::array<std::uint32_t, 2U> interval_crc32{};
  std::array<IntervalRecord, 2U> intervals{};
};

std::uint32_t drainIntervalCrc32(const IntervalRecord &record);
bool validDrainRecord(const DrainRecord &record);
bool drainRecordsEqual(const DrainRecord &left, const DrainRecord &right);
bool validDrainRecordUpdate(const DrainRecord &current,
                            const DrainRecord &proposed);
bool completedDrainFromDifferentDevice(const DrainRecord &record,
                                       const std::string &current_device_id);
bool completedDrainMatchesCurrentGeneration(
    const DrainRecord &record, const std::string &current_device_id,
    std::uint64_t current_generation);

} // namespace data_reset

constexpr persistence::SlotKeys kDataResetDrainSlots{"dd_a", "dd_b",
                                                     "dd_active"};

std::vector<std::uint8_t>
encodeDataResetDrainRecord(const data_reset::DrainRecord &record);
bool decodeDataResetDrainRecord(const std::vector<std::uint8_t> &encoded,
                                data_reset::DrainRecord &record);

class DataResetDrainStore {
public:
  DataResetDrainStore() = default;
  explicit DataResetDrainStore(persistence::BlobStore &store) : store_(&store) {}

  DataResetStoreResult load(data_reset::DrainRecord &record) const;
  DataResetStoreResult
  saveAndVerify(const data_reset::DrainRecord &record) const;
  // A Completed tombstone must replace both alternating atomic slots. One
  // ordinary commit leaves the prior Staged/Assigned payload as fallback.
  DataResetStoreResult scrubCompletedPayloadCopies(
      const data_reset::DrainRecord &completed) const;

private:
  persistence::BlobStore *store_{nullptr};
};

} // namespace pm
