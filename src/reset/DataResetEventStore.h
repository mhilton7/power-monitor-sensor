#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "config/AtomicConfigStore.h"
#include "reset/DataResetStore.h"

namespace pm {
namespace data_reset {

constexpr std::size_t kMaximumPreservedResetEvents = 16U;

enum class EventJournalState : std::uint8_t { Staged = 1U, Completed };

struct PreservedEvent {
  std::string code;
  std::string severity;
  std::string detail;
  std::string boot_id;
  std::uint64_t utc_ms{0U};
  // Assigned before enqueue and unique within boot_id. It is carried into
  // the SD event envelope and is the durable retry identity.
  std::uint64_t source_event_id{0U};
  // A unique source identity must occur exactly once on the card.
  std::uint64_t required_occurrences{0U};
};

struct EventJournalRecord {
  std::uint32_t schema_version{1U};
  EventJournalState state{EventJournalState::Staged};
  std::string operation_id;
  std::string device_id;
  std::uint64_t source_generation{0U};
  std::uint64_t target_generation{0U};
  std::uint64_t card_generation{0U};
  std::uint64_t event_count{0U};
  std::array<std::uint32_t, kMaximumPreservedResetEvents> event_crc32{};
  std::array<PreservedEvent, kMaximumPreservedResetEvents> events{};
};

std::uint32_t preservedEventCrc32(const PreservedEvent &event);
bool validEventJournalRecord(const EventJournalRecord &record);
bool eventJournalRecordsEqual(const EventJournalRecord &left,
                              const EventJournalRecord &right);
bool validEventJournalRecordUpdate(const EventJournalRecord &current,
                                   const EventJournalRecord &proposed);

} // namespace data_reset

constexpr persistence::SlotKeys kDataResetEventSlots{"de_a", "de_b",
                                                     "de_active"};

std::vector<std::uint8_t>
encodeDataResetEventJournal(const data_reset::EventJournalRecord &record);
bool decodeDataResetEventJournal(const std::vector<std::uint8_t> &encoded,
                                 data_reset::EventJournalRecord &record);

class DataResetEventStore {
public:
  DataResetEventStore() = default;
  explicit DataResetEventStore(persistence::BlobStore &store) : store_(&store) {}

  DataResetStoreResult load(data_reset::EventJournalRecord &record) const;
  DataResetStoreResult
  saveAndVerify(const data_reset::EventJournalRecord &record) const;
  // Replace the inactive staged payload with the compact Completed tombstone
  // so a later reset does not permanently lose NVS admission capacity.
  DataResetStoreResult scrubCompletedPayloadCopies(
      const data_reset::EventJournalRecord &completed) const;

private:
  persistence::BlobStore *store_{nullptr};
};

} // namespace pm
