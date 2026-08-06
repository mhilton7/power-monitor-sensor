#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "config/AtomicConfigStore.h"
#include "reset/DataResetStore.h"

namespace pm {
namespace data_reset {

enum class CleanupState : std::uint8_t { Planned = 1U, Completed };

struct CleanupRecord {
  std::uint32_t schema_version{1U};
  CleanupState state{CleanupState::Planned};
  std::string operation_id;
  std::string device_id;
  std::uint64_t source_generation{0U};
  std::uint64_t target_generation{0U};
  std::uint64_t card_generation{0U};
  std::uint64_t reading_files{0U};
  std::uint64_t index_files{0U};
  std::uint64_t export_files{0U};
  std::uint64_t metadata_files{0U};
  std::uint64_t bytes{0U};
};

bool validCleanupRecord(const CleanupRecord &record);
bool cleanupRecordsEqual(const CleanupRecord &left,
                         const CleanupRecord &right);
bool validCleanupRecordUpdate(const CleanupRecord &current,
                              const CleanupRecord &proposed);

} // namespace data_reset

constexpr persistence::SlotKeys kDataResetCleanupSlots{"dc_a", "dc_b",
                                                       "dc_active"};

std::vector<std::uint8_t>
encodeDataResetCleanupRecord(const data_reset::CleanupRecord &record);
bool decodeDataResetCleanupRecord(const std::vector<std::uint8_t> &encoded,
                                  data_reset::CleanupRecord &record);

class DataResetCleanupStore {
public:
  DataResetCleanupStore() = default;
  explicit DataResetCleanupStore(persistence::BlobStore &store)
      : store_(&store) {}

  DataResetStoreResult load(data_reset::CleanupRecord &record) const;
  DataResetStoreResult
  saveAndVerify(const data_reset::CleanupRecord &record) const;
  DataResetStoreResult scrubCompletedPayloadCopies(
      const data_reset::CleanupRecord &completed) const;

private:
  persistence::BlobStore *store_{nullptr};
};

} // namespace pm
