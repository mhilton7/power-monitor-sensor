#include "reset/DataResetCapacityPolicy.h"

#include "reset/DataResetCleanupStore.h"
#include "reset/DataResetDrainStore.h"
#include "reset/DataResetEventStore.h"
#include "reset/DataResetStore.h"

#if !defined(PM_NATIVE_TEST)
#include <nvs.h>
#endif

namespace pm {
namespace data_reset {

bool queryDataResetCapacity(DataResetCapacityReport &report) {
  report = {};
#if !defined(PM_NATIVE_TEST)
  const auto read_partition = [](const char *partition,
                                 NvsCapacitySnapshot &snapshot) {
    nvs_stats_t stats{};
    if (nvs_get_stats(partition, &stats) != ESP_OK)
      return false;
    snapshot.query_succeeded = true;
    snapshot.free_entries = stats.free_entries;
    snapshot.total_entries = stats.total_entries;
    return true;
  };
  data_reset::Record reset_record;
  DataResetStore reset_store;
  if (reset_store.load(reset_record) == DataResetStoreResult::Loaded &&
      data_reset::terminalState(reset_record.state)) {
    const std::vector<std::uint8_t> encoded =
        encodeDataResetRecord(reset_record);
    if (!encoded.empty()) {
      report.pmconfig_terminal_entries =
          atomicSlotEntries(encoded.size());
    }
  }

  data_reset::EventJournalRecord event_record;
  DataResetEventStore event_store;
  if (event_store.load(event_record) == DataResetStoreResult::Loaded &&
      event_record.state == data_reset::EventJournalState::Completed) {
    const std::vector<std::uint8_t> encoded =
        encodeDataResetEventJournal(event_record);
    if (!encoded.empty()) {
      report.default_nvs_terminal_entries +=
          atomicSlotEntries(encoded.size());
    }
  }

  data_reset::DrainRecord drain_record;
  DataResetDrainStore drain_store;
  if (drain_store.load(drain_record) == DataResetStoreResult::Loaded &&
      drain_record.state == data_reset::DrainState::Completed) {
    const std::vector<std::uint8_t> encoded =
        encodeDataResetDrainRecord(drain_record);
    if (!encoded.empty()) {
      report.default_nvs_terminal_entries +=
          atomicSlotEntries(encoded.size());
    }
  }

  data_reset::CleanupRecord cleanup_record;
  DataResetCleanupStore cleanup_store;
  if (cleanup_store.load(cleanup_record) == DataResetStoreResult::Loaded &&
      cleanup_record.state == data_reset::CleanupState::Completed) {
    const std::vector<std::uint8_t> encoded =
        encodeDataResetCleanupRecord(cleanup_record);
    if (!encoded.empty()) {
      report.default_nvs_terminal_entries +=
          atomicSlotEntries(encoded.size());
    }
  }
  // Read the physical statistics after terminal inspection. Opening an empty
  // Preferences namespace can consume its namespace entry, and the snapshot
  // must include that allocation rather than overstate available capacity.
  return read_partition("pmconfig", report.pmconfig) &&
         read_partition("nvs", report.default_nvs);
#else
  return false;
#endif
}

} // namespace data_reset
} // namespace pm
