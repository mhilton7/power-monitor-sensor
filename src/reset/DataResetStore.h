#pragma once

#include <cstdint>
#include <vector>

#include "config/AtomicConfigStore.h"
#include "reset/DataResetPolicy.h"

namespace pm {

enum class DataResetStoreResult : std::uint8_t {
  Loaded,
  SavedAndVerified,
  NotFound,
  InvalidRecord,
  InvalidTransition,
  LoadFailed,
  ParseFailed,
  SerializeFailed,
  CommitFailed,
  ReadbackFailed,
  IdentityMismatch,
  BackendUnavailable,
};

const char *dataResetStoreResultName(DataResetStoreResult result);

struct DataResetStoreMetadata {
  std::uint64_t persistence_generation{0U};
  bool recovered_fallback{false};
};

constexpr persistence::SlotKeys kDataResetSlots{"dr_a", "dr_b",
                                                "dr_active"};

std::vector<std::uint8_t>
encodeDataResetRecord(const data_reset::Record &record);
bool decodeDataResetRecord(const std::vector<std::uint8_t> &encoded,
                           data_reset::Record &record);

class DataResetStore {
public:
  DataResetStore() = default;
  explicit DataResetStore(persistence::BlobStore &store) : store_(&store) {}

  DataResetStoreResult
  load(data_reset::Record &record,
       DataResetStoreMetadata *metadata = nullptr) const;
  DataResetStoreResult
  saveAndVerify(const data_reset::Record &record,
                DataResetStoreMetadata *metadata = nullptr) const;

private:
  persistence::BlobStore *store_{nullptr};
};

} // namespace pm
