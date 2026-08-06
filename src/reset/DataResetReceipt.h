#pragma once

#include <cstdint>
#include <string>

#include "reset/DataResetPolicy.h"

namespace pm {
namespace data_reset {

struct CommitReceiptRuntime {
  std::uint64_t newest_syncable_sequence{0U};
  std::uint64_t local_record_count{0U};
  std::uint64_t next_sequence{0U};
  std::uint64_t sequence_floor{0U};
  std::uint64_t server_ack_sequence{0U};
  std::uint64_t server_maximum_seen{0U};
};

// These builders intentionally insert keys in lexicographic order. ArduinoJson
// preserves insertion order, producing the same compact canonical bytes that
// the server signs/verifies and that the shared vector exercises.
std::string buildPreparedReceiptCanonical(const Record &record);
std::string buildCommitReceiptCanonical(
    const Record &record, const CommitReceiptRuntime &runtime);

} // namespace data_reset
} // namespace pm
