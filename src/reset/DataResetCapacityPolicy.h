#pragma once

#include <cstddef>

namespace pm {
namespace data_reset {

// ESP-IDF NVS stores values in 32-byte entries. Variable-length blobs also
// consume one index entry and one chunk header per 4,000-byte page chunk.
// AtomicConfigStore adds a 24-byte envelope to each slot and stores a 20-byte
// active marker. These functions intentionally round up every component.
constexpr std::size_t kNvsEntryBytes = 32U;
constexpr std::size_t kNvsBlobChunkBytes = 4000U;
constexpr std::size_t kAtomicRecordEnvelopeBytes = 24U;
constexpr std::size_t kAtomicMarkerBytes = 20U;
constexpr std::size_t kNvsGarbageCollectionPageEntries = 126U;
// Covers the largest compact-tombstone slot plus its marker while preserving
// the full GC page below. This is deliberately larger than the 30-entry
// completed-drain rewrite bound.
constexpr std::size_t kNvsAdmissionMarginEntries = 32U;

constexpr std::size_t divideRoundUp(const std::size_t value,
                                    const std::size_t divisor) {
  return value == 0U ? 0U : 1U + (value - 1U) / divisor;
}

constexpr std::size_t nvsBlobEntries(const std::size_t bytes) {
  return 1U + divideRoundUp(bytes, kNvsEntryBytes) +
         divideRoundUp(bytes, kNvsBlobChunkBytes);
}

constexpr std::size_t atomicSlotEntries(const std::size_t payload_bytes) {
  return nvsBlobEntries(payload_bytes + kAtomicRecordEnvelopeBytes);
}

constexpr std::size_t kAtomicMarkerEntries =
    nvsBlobEntries(kAtomicMarkerBytes);

// DataResetStore's binary schema has a structural maximum of 9,326 bytes.
// A prepared slot (receipt, no completion receipt) and a completed slot can
// coexist, so reserve both plus the active marker and a full NVS GC page.
constexpr std::size_t kMainResetRecordMaximumBytes = 9326U;
constexpr std::size_t kPreparedResetRecordMaximumBytes = 5126U;
constexpr std::size_t kRequiredPmconfigFreeEntries =
    atomicSlotEntries(kMainResetRecordMaximumBytes) +
    atomicSlotEntries(kPreparedResetRecordMaximumBytes) +
    kAtomicMarkerEntries + kNvsGarbageCollectionPageEntries +
    kNvsAdmissionMarginEntries;

// The auxiliary pm-reset namespace lives on the default NVS partition. Its
// maximum live set is one full and one completed event journal, two full drain
// slots, two cleanup slots, three active markers, and one namespace entry.
constexpr std::size_t kEventJournalMaximumBytes = 11600U;
constexpr std::size_t kCompletedEventJournalMaximumBytes = 208U;
constexpr std::size_t kDrainJournalMaximumBytes = 3072U;
constexpr std::size_t kCompletedDrainJournalMaximumBytes = 768U;
constexpr std::size_t kCleanupJournalMaximumBytes = 448U;
constexpr std::size_t kRequiredDefaultNvsFreeEntries =
    atomicSlotEntries(kEventJournalMaximumBytes) +
    atomicSlotEntries(kCompletedEventJournalMaximumBytes) +
    2U * atomicSlotEntries(kDrainJournalMaximumBytes) +
    2U * atomicSlotEntries(kCleanupJournalMaximumBytes) +
    3U * kAtomicMarkerEntries + 1U +
    kNvsGarbageCollectionPageEntries + kNvsAdmissionMarginEntries;

static_assert(kNvsAdmissionMarginEntries >=
                  atomicSlotEntries(kCompletedEventJournalMaximumBytes) +
                      kAtomicMarkerEntries,
              "event tombstone rewrite must preserve the GC page");
static_assert(kNvsAdmissionMarginEntries >=
                  atomicSlotEntries(kCompletedDrainJournalMaximumBytes) +
                      kAtomicMarkerEntries,
              "drain tombstone rewrite must preserve the GC page");
static_assert(kNvsAdmissionMarginEntries >=
                  atomicSlotEntries(kCleanupJournalMaximumBytes) +
                      kAtomicMarkerEntries,
              "cleanup tombstone rewrite must preserve the GC page");

struct NvsCapacitySnapshot {
  bool query_succeeded{false};
  std::size_t free_entries{0U};
  std::size_t total_entries{0U};
};

struct DataResetCapacityReport {
  NvsCapacitySnapshot pmconfig;
  NvsCapacitySnapshot default_nvs;
  // A terminal atomic record already occupies part of the worst-case live set
  // reserved above. The next operation overwrites that record, so counting it
  // as both unavailable free space and a new allocation would permanently
  // reject otherwise safe repeated resets. Credit only semantically validated
  // terminal slots and their active markers.
  std::size_t pmconfig_terminal_entries{0U};
  std::size_t default_nvs_terminal_entries{0U};
};

constexpr std::size_t requiredFreeEntriesAfterTerminalCredit(
    const std::size_t worst_case_required,
    const std::size_t terminal_entries) {
  const std::size_t irreducible =
      kNvsGarbageCollectionPageEntries + kNvsAdmissionMarginEntries;
  const std::size_t maximum_credit =
      worst_case_required > irreducible
          ? worst_case_required - irreducible
          : 0U;
  const std::size_t credit =
      terminal_entries < maximum_credit ? terminal_entries : maximum_credit;
  return worst_case_required - credit;
}

constexpr std::size_t requiredPmconfigFreeEntries(
    const DataResetCapacityReport &report) {
  return requiredFreeEntriesAfterTerminalCredit(
      kRequiredPmconfigFreeEntries, report.pmconfig_terminal_entries);
}

constexpr std::size_t requiredDefaultNvsFreeEntries(
    const DataResetCapacityReport &report) {
  return requiredFreeEntriesAfterTerminalCredit(
      kRequiredDefaultNvsFreeEntries,
      report.default_nvs_terminal_entries);
}

constexpr bool capacitySnapshotSufficient(
    const NvsCapacitySnapshot &snapshot, const std::size_t required_entries) {
  return snapshot.query_succeeded && snapshot.total_entries > 0U &&
         required_entries <= snapshot.total_entries &&
         snapshot.free_entries >= required_entries;
}

constexpr bool dataResetCapacitySufficient(
    const DataResetCapacityReport &report) {
  return capacitySnapshotSufficient(report.pmconfig,
                                    requiredPmconfigFreeEntries(report)) &&
         capacitySnapshotSufficient(report.default_nvs,
                                    requiredDefaultNvsFreeEntries(report));
}

// Reads both physical partitions. Query failure is a hard rejection; prepare
// must never promise a reset whose remaining journals cannot be persisted.
bool queryDataResetCapacity(DataResetCapacityReport &report);

} // namespace data_reset
} // namespace pm
