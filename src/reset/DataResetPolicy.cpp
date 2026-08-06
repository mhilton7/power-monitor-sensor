#include "reset/DataResetPolicy.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <limits>

namespace pm {
namespace data_reset {
namespace {

std::atomic<std::uint8_t> g_admission_owner{
    static_cast<std::uint8_t>(AdmissionOwner::Idle)};
std::atomic<std::uint32_t> g_reading_sync_in_flight{0U};

struct StateName {
  State state;
  const char *name;
};

constexpr std::array<StateName, 7U> kStateNames{{
    {State::Idle, "idle"},
    {State::Preparing, "preparing"},
    {State::Prepared, "prepared"},
    {State::Committing, "committing"},
    {State::Completed, "completed"},
    {State::Cancelled, "cancelled"},
    {State::AttentionRequired, "attention_required"},
}};

struct CheckpointName {
  Checkpoint checkpoint;
  const char *name;
};

constexpr std::array<CheckpointName, 8U> kCheckpointNames{{
    {Checkpoint::None, "none"},
    {Checkpoint::CommitAuthorized, "commit_authorized"},
    {Checkpoint::SequenceAdvanced, "sequence_advanced"},
    {Checkpoint::CursorsAdvanced, "cursors_advanced"},
    {Checkpoint::ReadingsCleared, "readings_cleared"},
    {Checkpoint::BaselineInstalled, "baseline_installed"},
    {Checkpoint::Verified, "verified"},
    {Checkpoint::Completed, "completed"},
}};

bool boundedPrintable(const std::string &value, const std::size_t maximum,
                      const bool allow_empty = false) {
  return value.size() <= maximum && (allow_empty || !value.empty()) &&
         std::all_of(value.begin(), value.end(), [](const unsigned char byte) {
           return byte >= 0x20U && byte <= 0x7EU;
         });
}

bool safeFailureCode(const std::string &value) {
  if (value.empty())
    return true;
  if (value.size() > 80U)
    return false;
  const auto lowercase_alphanumeric = [](const char byte) {
    return (byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9');
  };
  return lowercase_alphanumeric(value.front()) &&
         std::all_of(value.begin() + 1, value.end(),
                     [&lowercase_alphanumeric](const char byte) {
                       return lowercase_alphanumeric(byte) || byte == '_';
                     });
}

bool lowercaseHex(const std::string &value, const std::size_t length) {
  return value.size() == length &&
         std::all_of(value.begin(), value.end(), [](const char byte) {
           return (byte >= '0' && byte <= '9') ||
                  (byte >= 'a' && byte <= 'f');
         });
}

bool lowercaseUuid(const std::string &value) {
  if (value.size() != 36U)
    return false;
  for (std::size_t index = 0U; index < value.size(); ++index) {
    const bool separator =
        index == 8U || index == 13U || index == 18U || index == 23U;
    if (separator) {
      if (value[index] != '-')
        return false;
    } else if (!((value[index] >= '0' && value[index] <= '9') ||
                 (value[index] >= 'a' && value[index] <= 'f'))) {
      return false;
    }
  }
  return true;
}

bool validResetTimestamp(const std::string &value) {
  return value.size() >= 20U && value.size() <= 40U && value[4] == '-' &&
         value[7] == '-' && value[10] == 'T' && value.back() == 'Z' &&
         boundedPrintable(value, 40U);
}

int checkpointIndex(const Checkpoint checkpoint) {
  for (std::size_t index = 0U; index < kCheckpointNames.size(); ++index) {
    if (kCheckpointNames[index].checkpoint == checkpoint)
      return static_cast<int>(index);
  }
  return -1;
}

bool preparedEvidencePresent(const Record &record) {
  return !record.prepared_receipt.empty();
}

bool validPreparedEvidence(const Record &record) {
  if (!boundedPrintable(record.prepared_firmware_version, 32U) ||
      !lowercaseHex(record.prepared_build_hash, 64U) ||
      !lowercaseUuid(record.prepared_boot_id) || record.next_sequence == 0U ||
      record.local_sequence_floor >= record.next_sequence ||
      record.card_generation == 0U ||
      !boundedPrintable(record.sd_status, 32U) ||
      !lowercaseHex(record.configuration_digest_before, 64U) ||
      !boundedPrintable(record.prepared_receipt, 4096U) ||
      !lowercaseHex(record.prepared_receipt_digest, 64U)) {
    return false;
  }
  if (record.prepared_firmware_version !=
      record.prepare.expected_firmware_version) {
    return false;
  }
  if (record.prepare.expected_build_hash_set &&
      record.prepared_build_hash != record.prepare.expected_build_hash) {
    return false;
  }
  if (record.prepare.expected_card_generation_set &&
      record.card_generation != record.prepare.expected_card_generation) {
    return false;
  }
  if (record.prepare_drain_records_added > 2U ||
      record.prepare_drain_syncable_records_added >
          record.prepare_drain_records_added ||
      record.prepare_drain_sequence_range_set !=
          (record.prepare_drain_records_added > 0U) ||
      (record.prepare_drain_sequence_range_set
           ? (record.prepare_drain_first_sequence == 0U ||
              record.prepare_drain_last_sequence <
                  record.prepare_drain_first_sequence ||
              record.prepare_drain_last_sequence -
                          record.prepare_drain_first_sequence +
                      1U !=
                  record.prepare_drain_records_added ||
              record.prepare_drain_last_sequence !=
                  record.newest_stored_sequence ||
              record.next_sequence !=
                  record.prepare_drain_last_sequence + 1U ||
              record.local_record_count <
                  record.prepare_drain_records_added ||
              (record.prepare_drain_syncable_records_added > 0U &&
               (record.newest_syncable_sequence <
                    record.prepare_drain_first_sequence ||
                (record.prepare_drain_syncable_records_added ==
                     record.prepare_drain_records_added &&
                 record.newest_syncable_sequence !=
                     record.prepare_drain_last_sequence))))
           : (record.prepare_drain_first_sequence != 0U ||
              record.prepare_drain_last_sequence != 0U ||
              record.prepare_drain_syncable_records_added != 0U))) {
    return false;
  }
  return record.newest_syncable_sequence <= record.newest_stored_sequence &&
         record.sensor_server_acknowledgement <= record.sensor_maximum_seen;
}

bool preparedEvidenceEqual(const Record &left, const Record &right) {
  return left.prepared_firmware_version == right.prepared_firmware_version &&
         left.prepared_build_hash == right.prepared_build_hash &&
         left.prepared_boot_id == right.prepared_boot_id &&
         left.newest_stored_sequence == right.newest_stored_sequence &&
         left.newest_syncable_sequence == right.newest_syncable_sequence &&
         left.sensor_server_acknowledgement ==
             right.sensor_server_acknowledgement &&
         left.sensor_maximum_seen == right.sensor_maximum_seen &&
         left.prepared_removal_floor == right.prepared_removal_floor &&
         left.local_sequence_floor == right.local_sequence_floor &&
         left.next_sequence == right.next_sequence &&
         left.local_record_count == right.local_record_count &&
         left.prepare_drain_records_added ==
             right.prepare_drain_records_added &&
         left.prepare_drain_sequence_range_set ==
             right.prepare_drain_sequence_range_set &&
         left.prepare_drain_first_sequence ==
             right.prepare_drain_first_sequence &&
         left.prepare_drain_last_sequence ==
             right.prepare_drain_last_sequence &&
         left.prepare_drain_syncable_records_added ==
             right.prepare_drain_syncable_records_added &&
         left.card_generation == right.card_generation &&
         left.sd_status == right.sd_status &&
         left.prepared_pzem_energy_wh == right.prepared_pzem_energy_wh &&
         left.software_energy_baseline_before_wh ==
             right.software_energy_baseline_before_wh &&
         left.configuration_digest_before ==
             right.configuration_digest_before &&
         left.prepared_receipt == right.prepared_receipt &&
         left.prepared_receipt_digest == right.prepared_receipt_digest;
}

bool commitEvidenceEqual(const Record &left, const Record &right) {
  return left.approved_boundary_set == right.approved_boundary_set &&
         left.approved_boundary == right.approved_boundary &&
         left.new_sequence_floor == right.new_sequence_floor &&
         left.new_next_sequence == right.new_next_sequence &&
         left.commit_energy_baseline_set ==
             right.commit_energy_baseline_set &&
         left.commit_pzem_energy_wh == right.commit_pzem_energy_wh &&
         left.application_energy_baseline_wh ==
             right.application_energy_baseline_wh;
}

bool noPreparedEvidence(const Record &record) {
  return record.prepared_firmware_version.empty() &&
         record.prepared_build_hash.empty() && record.prepared_boot_id.empty() &&
         record.newest_stored_sequence == 0U &&
         record.newest_syncable_sequence == 0U &&
         record.sensor_server_acknowledgement == 0U &&
         record.sensor_maximum_seen == 0U &&
         record.prepared_removal_floor == 0U &&
         record.local_sequence_floor == 0U && record.next_sequence == 0U &&
         record.local_record_count == 0U &&
         record.prepare_drain_records_added == 0U &&
         !record.prepare_drain_sequence_range_set &&
         record.prepare_drain_first_sequence == 0U &&
         record.prepare_drain_last_sequence == 0U &&
         record.prepare_drain_syncable_records_added == 0U &&
         record.card_generation == 0U &&
         record.sd_status.empty() && record.prepared_pzem_energy_wh == 0U &&
         record.software_energy_baseline_before_wh == 0U &&
         record.configuration_digest_before.empty() &&
         record.prepared_receipt.empty() &&
         record.prepared_receipt_digest.empty();
}

bool noCommitEvidence(const Record &record) {
  return !record.approved_boundary_set && record.approved_boundary == 0U &&
         record.new_sequence_floor == 0U && record.new_next_sequence == 0U &&
         !record.commit_energy_baseline_set &&
         record.commit_pzem_energy_wh == 0U &&
         record.application_energy_baseline_wh == 0U &&
         record.verified_pzem_energy_wh == 0U &&
         record.readings_deleted == 0U && record.indexes_deleted == 0U &&
         record.exports_deleted == 0U &&
         record.backlog_entries_deleted == 0U &&
         record.configuration_digest_after.empty() &&
         record.completion_timestamp.empty() &&
         record.completion_receipt.empty();
}

bool validCommitEvidence(const Record &record) {
  if (!record.approved_boundary_set ||
      !record.commit_energy_baseline_set ||
      record.approved_boundary > kMaximumResetBoundary ||
      record.new_sequence_floor != record.approved_boundary ||
      record.new_next_sequence != record.approved_boundary + 1U) {
    return false;
  }
  const BoundaryResult required = highestTrustedBoundary(boundaryInputs(record));
  if (!required.valid || record.approved_boundary < required.boundary ||
      record.commit_pzem_energy_wh < record.prepared_pzem_energy_wh) {
    return false;
  }
  return record.checkpoint >= Checkpoint::Verified
             ? record.verified_pzem_energy_wh >=
                   record.commit_pzem_energy_wh
             : record.verified_pzem_energy_wh == 0U;
}

} // namespace

AdmissionOwner admissionOwner() {
  return static_cast<AdmissionOwner>(
      g_admission_owner.load(std::memory_order_seq_cst));
}

bool validPreauthorizationEvidence(const Record &record) {
  if (!record.approved_boundary_set)
    return noCommitEvidence(record);
  const BoundaryResult required = highestTrustedBoundary(boundaryInputs(record));
  return (record.state == State::Prepared ||
          record.state == State::AttentionRequired) &&
         record.checkpoint == Checkpoint::None && required.valid &&
         record.approved_boundary >= required.boundary &&
         record.approved_boundary <= kMaximumResetBoundary &&
         record.new_sequence_floor == record.approved_boundary &&
         record.new_next_sequence == record.approved_boundary + 1U &&
         !record.commit_energy_baseline_set &&
         record.commit_pzem_energy_wh == 0U &&
         record.application_energy_baseline_wh == 0U &&
         record.verified_pzem_energy_wh == 0U &&
         record.readings_deleted == 0U && record.indexes_deleted == 0U &&
         record.exports_deleted == 0U &&
         record.backlog_entries_deleted == 0U &&
         record.configuration_digest_after.empty() &&
         record.completion_timestamp.empty() &&
         record.completion_receipt.empty();
}

bool claimResetAdmission() {
  bool newly_acquired = false;
  return claimResetAdmission(newly_acquired);
}

bool claimResetAdmission(bool &newly_acquired) {
  newly_acquired = false;
  std::uint8_t expected = static_cast<std::uint8_t>(AdmissionOwner::Idle);
  if (g_admission_owner.compare_exchange_strong(
          expected, static_cast<std::uint8_t>(AdmissionOwner::Reset),
          std::memory_order_seq_cst)) {
    newly_acquired = true;
    return true;
  }
  return expected == static_cast<std::uint8_t>(AdmissionOwner::Reset);
}

void releaseResetAdmission() {
  std::uint8_t expected = static_cast<std::uint8_t>(AdmissionOwner::Reset);
  g_admission_owner.compare_exchange_strong(
      expected, static_cast<std::uint8_t>(AdmissionOwner::Idle),
      std::memory_order_seq_cst);
}

bool resetAdmissionActive() {
  return admissionOwner() == AdmissionOwner::Reset;
}

bool claimDisruptiveAdmission() {
  std::uint8_t expected = static_cast<std::uint8_t>(AdmissionOwner::Idle);
  return g_admission_owner.compare_exchange_strong(
      expected, static_cast<std::uint8_t>(AdmissionOwner::DisruptiveOperation),
      std::memory_order_seq_cst);
}

void releaseDisruptiveAdmission() {
  std::uint8_t expected =
      static_cast<std::uint8_t>(AdmissionOwner::DisruptiveOperation);
  g_admission_owner.compare_exchange_strong(
      expected, static_cast<std::uint8_t>(AdmissionOwner::Idle),
      std::memory_order_seq_cst);
}

bool tryBeginReadingSync() {
  if (resetAdmissionActive()) {
    return false;
  }
  g_reading_sync_in_flight.fetch_add(1U, std::memory_order_seq_cst);
  // Reset may have claimed admission between the first observation and the
  // counter increment. In that ordering the reset owns the race: publish no
  // work and release the provisional lease. If reset claims immediately after
  // this check, it observes the non-zero counter and waits for this lease.
  if (resetAdmissionActive()) {
    finishReadingSync();
    return false;
  }
  return true;
}

void finishReadingSync() {
  std::uint32_t current =
      g_reading_sync_in_flight.load(std::memory_order_seq_cst);
  while (current != 0U &&
         !g_reading_sync_in_flight.compare_exchange_weak(
             current, current - 1U, std::memory_order_seq_cst,
             std::memory_order_seq_cst)) {
  }
}

std::uint32_t readingSyncInFlight() {
  return g_reading_sync_in_flight.load(std::memory_order_seq_cst);
}

void PostBaselineFreshnessLatch::suspend() {
  publication_enabled_.store(false, std::memory_order_seq_cst);
}

void PostBaselineFreshnessLatch::markBaselineInstalled(
    const std::uint64_t generation) {
  publication_enabled_.store(false, std::memory_order_seq_cst);
  required_generation_.store(generation, std::memory_order_seq_cst);
}

void PostBaselineFreshnessLatch::resume(const std::uint64_t generation) {
  required_generation_.store(generation, std::memory_order_seq_cst);
  publication_enabled_.store(true, std::memory_order_seq_cst);
}

bool PostBaselineFreshnessLatch::eligible(
    const std::uint64_t sample_generation) const {
  return publication_enabled_.load(std::memory_order_seq_cst) &&
         sample_generation ==
             required_generation_.load(std::memory_order_seq_cst);
}

const char *stateName(const State state) {
  for (const StateName &entry : kStateNames) {
    if (entry.state == state)
      return entry.name;
  }
  return "unknown";
}

bool parseState(const std::string &value, State &state) {
  for (const StateName &entry : kStateNames) {
    if (value == entry.name) {
      state = entry.state;
      return true;
    }
  }
  return false;
}

const char *checkpointName(const Checkpoint checkpoint) {
  for (const CheckpointName &entry : kCheckpointNames) {
    if (entry.checkpoint == checkpoint)
      return entry.name;
  }
  return "unknown";
}

bool parseCheckpoint(const std::string &value, Checkpoint &checkpoint) {
  for (const CheckpointName &entry : kCheckpointNames) {
    if (value == entry.name) {
      checkpoint = entry.checkpoint;
      return true;
    }
  }
  return false;
}

const char *requestDispositionName(const RequestDisposition disposition) {
  switch (disposition) {
  case RequestDisposition::Accept: return "accept";
  case RequestDisposition::Replay: return "replay";
  case RequestDisposition::Invalid: return "data_reset_request_invalid";
  case RequestDisposition::StaleGeneration:
    return "data_generation_obsolete";
  case RequestDisposition::Conflict: return "reset_operation_conflict";
  case RequestDisposition::NotPrepared: return "data_reset_not_prepared";
  case RequestDisposition::BoundaryTooLow: return "reset_boundary_too_low";
  case RequestDisposition::SequenceExhausted: return "sequence_exhausted";
  }
  return "data_reset_request_invalid";
}

bool categoriesSupported(const std::vector<std::string> &categories) {
  return categories.size() == 1U &&
         categories.front() == kMeasurementHistoryCategory;
}

bool validPrepareRequest(const PrepareRequest &request) {
  return request.protocol == kProtocolVersion &&
         lowercaseUuid(request.operation_id) &&
         lowercaseUuid(request.device_id) && request.target_generation != 0U &&
         validResetTimestamp(request.reset_timestamp) &&
         request.plan_revision != 0U &&
         lowercaseHex(request.plan_digest, 64U) &&
         categoriesSupported(request.categories) &&
         request.expected_boundary <= kMaximumResetBoundary &&
         request.server_highest_contiguous <= kMaximumResetBoundary &&
         request.server_maximum_seen <= kMaximumResetBoundary &&
         request.server_highest_contiguous <= request.server_maximum_seen &&
         boundedPrintable(request.expected_firmware_version, 32U) &&
         (request.expected_build_hash_set
              ? lowercaseHex(request.expected_build_hash, 64U)
              : request.expected_build_hash.empty()) &&
         (request.expected_card_generation_set
              ? request.expected_card_generation != 0U
              : request.expected_card_generation == 0U);
}

bool validCommitRequest(const CommitRequest &request) {
  return request.protocol == kProtocolVersion &&
         lowercaseUuid(request.operation_id) &&
         lowercaseUuid(request.device_id) && request.target_generation != 0U &&
         request.plan_revision != 0U &&
         lowercaseHex(request.plan_digest, 64U) &&
         request.approved_boundary <= kMaximumResetBoundary &&
         lowercaseHex(request.prepared_receipt_digest, 64U);
}

bool prepareRequestsEqual(const PrepareRequest &left,
                          const PrepareRequest &right) {
  return left.protocol == right.protocol &&
         left.operation_id == right.operation_id &&
         left.device_id == right.device_id &&
         left.target_generation == right.target_generation &&
         left.reset_timestamp == right.reset_timestamp &&
         left.plan_revision == right.plan_revision &&
         left.plan_digest == right.plan_digest &&
         left.categories == right.categories &&
         left.expected_boundary == right.expected_boundary &&
         left.server_highest_contiguous == right.server_highest_contiguous &&
         left.server_maximum_seen == right.server_maximum_seen &&
         left.expected_firmware_version == right.expected_firmware_version &&
         left.expected_build_hash_set == right.expected_build_hash_set &&
         left.expected_build_hash == right.expected_build_hash &&
         left.expected_card_generation_set ==
             right.expected_card_generation_set &&
         left.expected_card_generation == right.expected_card_generation;
}

bool commitRequestsEqual(const CommitRequest &left,
                         const CommitRequest &right) {
  return left.protocol == right.protocol &&
         left.operation_id == right.operation_id &&
         left.device_id == right.device_id &&
         left.target_generation == right.target_generation &&
         left.plan_revision == right.plan_revision &&
         left.plan_digest == right.plan_digest &&
         left.approved_boundary == right.approved_boundary &&
         left.prepared_receipt_digest == right.prepared_receipt_digest;
}

BoundaryResult highestTrustedBoundary(const BoundaryInputs &inputs) {
  std::uint64_t boundary = inputs.expected_boundary;
  boundary = std::max(boundary, inputs.server_highest_contiguous);
  boundary = std::max(boundary, inputs.server_maximum_seen);
  boundary = std::max(boundary, inputs.local_sequence_floor);
  if (inputs.next_sequence != 0U)
    boundary = std::max(boundary, inputs.next_sequence - 1U);
  boundary = std::max(boundary, inputs.newest_stored_sequence);
  boundary = std::max(boundary, inputs.newest_syncable_sequence);
  boundary = std::max(boundary, inputs.sensor_server_acknowledgement);
  boundary = std::max(boundary, inputs.sensor_maximum_seen);
  boundary = std::max(boundary, inputs.prepared_removal_floor);
  if (boundary > kMaximumResetBoundary)
    return {};
  return {true, boundary, boundary + 1U};
}

BoundaryInputs boundaryInputs(const Record &record) {
  BoundaryInputs inputs;
  inputs.expected_boundary = record.prepare.expected_boundary;
  inputs.server_highest_contiguous =
      record.prepare.server_highest_contiguous;
  inputs.server_maximum_seen = record.prepare.server_maximum_seen;
  inputs.local_sequence_floor = record.local_sequence_floor;
  inputs.next_sequence = record.next_sequence;
  inputs.newest_stored_sequence = record.newest_stored_sequence;
  inputs.newest_syncable_sequence = record.newest_syncable_sequence;
  inputs.sensor_server_acknowledgement =
      record.sensor_server_acknowledgement;
  inputs.sensor_maximum_seen = record.sensor_maximum_seen;
  inputs.prepared_removal_floor = record.prepared_removal_floor;
  return inputs;
}

bool terminalState(const State state) {
  return state == State::Completed || state == State::Cancelled;
}

bool cancellableState(const State state) {
  return state == State::Preparing || state == State::Prepared ||
         state == State::AttentionRequired;
}

bool commitPointReached(const Checkpoint checkpoint) {
  const int index = checkpointIndex(checkpoint);
  return index >= checkpointIndex(Checkpoint::CommitAuthorized);
}

bool readingGateRequired(const State state, const Checkpoint checkpoint) {
  (void)checkpoint;
  return state == State::Preparing || state == State::Prepared ||
         state == State::Committing || state == State::AttentionRequired;
}

bool gatesReleased(const GateSnapshot &gates) {
  return !gates.configuration_frozen && gates.record_writes_enabled &&
         !gates.reset_admission_active;
}

bool completionExternallyVisible(const State state,
                                 const Checkpoint checkpoint,
                                 const GateSnapshot &gates) {
  return state == State::Completed && checkpoint == Checkpoint::Completed &&
         gatesReleased(gates);
}

bool cancellationExternallyVisible(const State state,
                                   const Checkpoint checkpoint,
                                   const GateSnapshot &gates) {
  return state == State::Cancelled && checkpoint == Checkpoint::None &&
         gatesReleased(gates);
}

State resumeStateForCheckpoint(const Checkpoint checkpoint) {
  if (checkpoint == Checkpoint::None)
    return State::Prepared;
  if (checkpoint == Checkpoint::Completed)
    return State::Completed;
  return State::Committing;
}

bool validStateCheckpoint(const State state, const Checkpoint checkpoint) {
  const int index = checkpointIndex(checkpoint);
  if (index < 0)
    return false;
  switch (state) {
  case State::Idle:
  case State::Preparing:
  case State::Prepared:
  case State::Cancelled: return checkpoint == Checkpoint::None;
  case State::Committing:
    return checkpoint >= Checkpoint::CommitAuthorized &&
           checkpoint <= Checkpoint::Verified;
  case State::Completed: return checkpoint == Checkpoint::Completed;
  case State::AttentionRequired:
    return checkpoint >= Checkpoint::None && checkpoint <= Checkpoint::Verified;
  }
  return false;
}

bool canTransition(const State from, const State to,
                   const Checkpoint checkpoint) {
  if (!validStateCheckpoint(to, checkpoint))
    return false;
  if (from == to)
    return !terminalState(from);
  switch (from) {
  case State::Idle: return to == State::Preparing;
  case State::Preparing:
    return to == State::Prepared || to == State::Cancelled;
  case State::Prepared:
    return (to == State::Committing &&
            checkpoint == Checkpoint::CommitAuthorized) ||
           to == State::Cancelled ||
           (to == State::AttentionRequired && checkpoint == Checkpoint::None);
  case State::Committing:
    return (to == State::Completed && checkpoint == Checkpoint::Completed) ||
           to == State::AttentionRequired;
  case State::AttentionRequired:
    return to == resumeStateForCheckpoint(checkpoint) ||
           (to == State::Cancelled && checkpoint == Checkpoint::None);
  case State::Completed:
  case State::Cancelled: return false;
  }
  return false;
}

bool canAdvanceCheckpoint(const Checkpoint current,
                          const Checkpoint proposed) {
  const int current_index = checkpointIndex(current);
  const int proposed_index = checkpointIndex(proposed);
  return current_index >= 0 && proposed_index >= 0 &&
         (proposed_index == current_index ||
          proposed_index == current_index + 1);
}

bool validRecord(const Record &record) {
  if (record.schema_version != kRecordSchemaVersion ||
      record.state == State::Idle || !validPrepareRequest(record.prepare) ||
      !validStateCheckpoint(record.state, record.checkpoint) ||
      !safeFailureCode(record.failure_code)) {
    return false;
  }

  const bool has_prepared = preparedEvidencePresent(record);
  if (has_prepared ? !validPreparedEvidence(record)
                   : !noPreparedEvidence(record)) {
    return false;
  }
  if ((record.state == State::Prepared || record.state == State::Committing ||
       record.state == State::Completed ||
       record.state == State::AttentionRequired) &&
      !has_prepared) {
    return false;
  }
  if (record.state == State::Preparing && has_prepared)
    return false;

  const bool at_commit_point = commitPointReached(record.checkpoint);
  if (at_commit_point ? !validCommitEvidence(record)
                      : !validPreauthorizationEvidence(record)) {
    return false;
  }
  const bool pause_complete = record.state == State::Cancelled ||
                              record.checkpoint >= Checkpoint::Verified;
  if (record.measurement_pause_started_utc_ms == 0U ||
      (pause_complete
          ? (!record.measurement_pause_evidenced ||
             record.measurement_pause_ended_utc_ms <
                 record.measurement_pause_started_utc_ms)
          : (record.measurement_pause_evidenced ||
             record.measurement_pause_ended_utc_ms != 0U))) {
    return false;
  }
  if (record.state == State::AttentionRequired && record.failure_code.empty())
    return false;

  if (record.checkpoint >= Checkpoint::Verified) {
    if (!lowercaseHex(record.configuration_digest_after, 64U) ||
        record.configuration_digest_after !=
            record.configuration_digest_before) {
      return false;
    }
  } else if (!record.configuration_digest_after.empty() &&
             !lowercaseHex(record.configuration_digest_after, 64U)) {
    return false;
  }

  if (record.state == State::Completed) {
    return boundedPrintable(record.completion_timestamp, 40U) &&
           boundedPrintable(record.completion_receipt, 4096U);
  }
  return record.completion_timestamp.empty() &&
         record.completion_receipt.empty();
}

bool recordsEqual(const Record &left, const Record &right) {
  return left.schema_version == right.schema_version &&
         left.state == right.state && left.checkpoint == right.checkpoint &&
         prepareRequestsEqual(left.prepare, right.prepare) &&
         preparedEvidenceEqual(left, right) &&
         commitEvidenceEqual(left, right) &&
         left.readings_deleted == right.readings_deleted &&
         left.indexes_deleted == right.indexes_deleted &&
         left.exports_deleted == right.exports_deleted &&
         left.backlog_entries_deleted == right.backlog_entries_deleted &&
         left.verified_pzem_energy_wh == right.verified_pzem_energy_wh &&
         left.configuration_digest_after ==
             right.configuration_digest_after &&
         left.completion_timestamp == right.completion_timestamp &&
         left.completion_receipt == right.completion_receipt &&
         left.measurement_pause_started_utc_ms ==
             right.measurement_pause_started_utc_ms &&
         left.measurement_pause_ended_utc_ms ==
             right.measurement_pause_ended_utc_ms &&
         left.measurement_pause_evidenced ==
             right.measurement_pause_evidenced &&
         left.failure_code == right.failure_code;
}

bool validRecordUpdate(const Record &current, const Record &proposed) {
  if (!validRecord(current) || !validRecord(proposed))
    return false;
  if (current.prepare.operation_id != proposed.prepare.operation_id) {
    if (!terminalState(current.state) || proposed.state != State::Preparing ||
        proposed.checkpoint != Checkpoint::None) {
      return false;
    }
    if (current.state == State::Completed) {
      return proposed.prepare.target_generation >
             current.prepare.target_generation;
    }
    return proposed.prepare.target_generation >=
           current.prepare.target_generation;
  }
  if (!prepareRequestsEqual(current.prepare, proposed.prepare) ||
      !canTransition(current.state, proposed.state, proposed.checkpoint) ||
      !canAdvanceCheckpoint(current.checkpoint, proposed.checkpoint)) {
    return false;
  }
  if (preparedEvidencePresent(current) &&
      !preparedEvidenceEqual(current, proposed)) {
    return false;
  }
  if (commitPointReached(current.checkpoint) &&
      !commitEvidenceEqual(current, proposed)) {
    return false;
  }
  if (current.approved_boundary_set &&
      (current.approved_boundary != proposed.approved_boundary ||
       current.new_sequence_floor != proposed.new_sequence_floor ||
       current.new_next_sequence != proposed.new_next_sequence ||
       !proposed.approved_boundary_set)) {
    return false;
  }
  if (current.checkpoint >= Checkpoint::Verified &&
      current.verified_pzem_energy_wh != proposed.verified_pzem_energy_wh) {
    return false;
  }
  if (proposed.readings_deleted < current.readings_deleted ||
      proposed.indexes_deleted < current.indexes_deleted ||
      proposed.exports_deleted < current.exports_deleted ||
      proposed.backlog_entries_deleted < current.backlog_entries_deleted) {
    return false;
  }
  if (!current.configuration_digest_after.empty() &&
      current.configuration_digest_after !=
          proposed.configuration_digest_after) {
    return false;
  }
  if (!current.completion_receipt.empty() &&
      (current.completion_receipt != proposed.completion_receipt ||
       current.completion_timestamp != proposed.completion_timestamp)) {
    return false;
  }
  if (current.measurement_pause_started_utc_ms !=
      proposed.measurement_pause_started_utc_ms) {
    return false;
  }
  if (current.measurement_pause_evidenced &&
      (current.measurement_pause_ended_utc_ms !=
           proposed.measurement_pause_ended_utc_ms ||
       !proposed.measurement_pause_evidenced)) {
    return false;
  }
  return true;
}

RequestDisposition classifyPrepareRequest(const Record *existing,
                                          const std::uint64_t active_generation,
                                          const PrepareRequest &request) {
  if (!validPrepareRequest(request))
    return RequestDisposition::Invalid;
  if (existing != nullptr) {
    if (request.operation_id == existing->prepare.operation_id) {
      return prepareRequestsEqual(request, existing->prepare)
                 ? RequestDisposition::Replay
                 : RequestDisposition::Conflict;
    }
    if (!terminalState(existing->state))
      return RequestDisposition::Conflict;
    if (request.target_generation <= active_generation ||
        (existing->state == State::Completed &&
         request.target_generation <= existing->prepare.target_generation)) {
      return RequestDisposition::StaleGeneration;
    }
    return RequestDisposition::Accept;
  }
  return request.target_generation > active_generation
             ? RequestDisposition::Accept
             : RequestDisposition::StaleGeneration;
}

RequestDisposition classifyCommitRequest(const Record &record,
                                         const CommitRequest &request) {
  if (!validCommitRequest(request))
    return RequestDisposition::Invalid;
  if (request.target_generation < record.prepare.target_generation)
    return RequestDisposition::StaleGeneration;
  if (request.operation_id != record.prepare.operation_id ||
      request.device_id != record.prepare.device_id ||
      request.target_generation != record.prepare.target_generation ||
      request.plan_revision != record.prepare.plan_revision ||
      request.plan_digest != record.prepare.plan_digest ||
      request.prepared_receipt_digest != record.prepared_receipt_digest) {
    return RequestDisposition::Conflict;
  }
  if (record.state == State::Preparing || record.state == State::Cancelled) {
    return RequestDisposition::NotPrepared;
  }
  const BoundaryResult required = highestTrustedBoundary(boundaryInputs(record));
  if (!required.valid)
    return RequestDisposition::SequenceExhausted;
  if (request.approved_boundary < required.boundary)
    return RequestDisposition::BoundaryTooLow;
  if (record.checkpoint == Checkpoint::None &&
      record.approved_boundary_set) {
    return request.approved_boundary == record.approved_boundary
               ? RequestDisposition::Replay
               : RequestDisposition::Conflict;
  }
  if (commitPointReached(record.checkpoint)) {
    return record.approved_boundary_set &&
                   request.approved_boundary == record.approved_boundary
               ? RequestDisposition::Replay
               : RequestDisposition::Conflict;
  }
  return record.state == State::Prepared ? RequestDisposition::Accept
                                         : RequestDisposition::NotPrepared;
}

} // namespace data_reset
} // namespace pm
