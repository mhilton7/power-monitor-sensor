#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

namespace pm {
namespace data_reset {

constexpr std::uint32_t kRecordSchemaVersion = 1U;
constexpr char kProtocolVersion[] = "data-reset/1.0.0";
constexpr char kMeasurementHistoryCategory[] = "measurement_history";
// Server sequence columns are signed BIGINT. Keeping the reset boundary two
// below INT64_MAX leaves a valid next-sequence value and at least one complete
// post-reset append without crossing the server's persistence range.
constexpr std::uint64_t kMaximumResetBoundary = 9'223'372'036'854'775'805ULL;

constexpr bool installedEnergyBaselineMatches(
    const std::uint64_t installed_baseline_wh,
    const std::uint64_t commit_authorized_baseline_wh) {
  return installed_baseline_wh == commit_authorized_baseline_wh;
}

enum class State : std::uint8_t {
  Idle = 0U,
  Preparing = 1U,
  Prepared = 2U,
  Committing = 3U,
  Completed = 4U,
  Cancelled = 5U,
  AttentionRequired = 6U,
};

enum class Checkpoint : std::uint8_t {
  None = 0U,
  CommitAuthorized = 10U,
  SequenceAdvanced = 20U,
  CursorsAdvanced = 30U,
  ReadingsCleared = 40U,
  BaselineInstalled = 50U,
  Verified = 60U,
  Completed = 70U,
};

struct GateSnapshot {
  bool configuration_frozen{false};
  bool record_writes_enabled{true};
  bool reset_admission_active{false};
};

enum class RequestDisposition : std::uint8_t {
  Accept,
  Replay,
  Invalid,
  StaleGeneration,
  Conflict,
  NotPrepared,
  BoundaryTooLow,
  SequenceExhausted,
};

// Cross-task admission is intentionally independent from the durable reset
// record. It closes the short interval between an HTTP prepare response and
// OtaMaintenanceTask persisting Preparing, while also letting an OTA/reboot
// that already claimed execution make prepare fail instead of racing it.
enum class AdmissionOwner : std::uint8_t {
  Idle = 0U,
  Reset = 1U,
  DisruptiveOperation = 2U,
};

bool claimResetAdmission();
bool claimResetAdmission(bool &newly_acquired);
void releaseResetAdmission();
bool resetAdmissionActive();
bool claimDisruptiveAdmission();
void releaseDisruptiveAdmission();
AdmissionOwner admissionOwner();

// Reading-batch synchronization uses a lease that spans page consumption,
// transport, response parsing, and durable acknowledgement persistence. Reset
// admission closes new leases atomically and waits for any lease that won just
// before the gate, so Prepared can never attest to cursors that are still
// changing on the sync task.
bool tryBeginReadingSync();
void finishReadingSync();
std::uint32_t readingSyncInFlight();

constexpr bool sampleForGenerationAllowed(
    const bool data_reset_frozen, const std::uint64_t sample_generation,
    const std::uint64_t active_generation) {
  return !data_reset_frozen && sample_generation == active_generation;
}

// Latest measurements remain closed from prepare admission through baseline
// installation. Reopening binds publication to the post-reset generation, so
// only a sample captured after the baseline checkpoint can become heartbeat
// evidence.
class PostBaselineFreshnessLatch {
public:
  void suspend();
  void markBaselineInstalled(std::uint64_t generation);
  void resume(std::uint64_t generation);
  bool eligible(std::uint64_t sample_generation) const;

private:
  std::atomic<std::uint64_t> required_generation_{0U};
  std::atomic<bool> publication_enabled_{true};
};

struct PrepareRequest {
  std::string protocol;
  std::string operation_id;
  std::string device_id;
  std::uint64_t target_generation{0U};
  std::string reset_timestamp;
  std::uint64_t plan_revision{0U};
  std::string plan_digest;
  std::vector<std::string> categories;
  std::uint64_t expected_boundary{0U};
  std::uint64_t server_highest_contiguous{0U};
  std::uint64_t server_maximum_seen{0U};
  std::string expected_firmware_version;
  bool expected_build_hash_set{false};
  std::string expected_build_hash;
  bool expected_card_generation_set{false};
  std::uint64_t expected_card_generation{0U};
};

struct CommitRequest {
  std::string protocol;
  std::string operation_id;
  std::string device_id;
  std::uint64_t target_generation{0U};
  std::uint64_t plan_revision{0U};
  std::string plan_digest;
  std::uint64_t approved_boundary{0U};
  std::string prepared_receipt_digest;
};

struct BoundaryInputs {
  std::uint64_t expected_boundary{0U};
  std::uint64_t server_highest_contiguous{0U};
  std::uint64_t server_maximum_seen{0U};
  std::uint64_t local_sequence_floor{0U};
  std::uint64_t next_sequence{0U};
  std::uint64_t newest_stored_sequence{0U};
  std::uint64_t newest_syncable_sequence{0U};
  std::uint64_t sensor_server_acknowledgement{0U};
  std::uint64_t sensor_maximum_seen{0U};
  std::uint64_t prepared_removal_floor{0U};
};

struct BoundaryResult {
  bool valid{false};
  std::uint64_t boundary{0U};
  std::uint64_t next_sequence{0U};
};

struct Record {
  std::uint32_t schema_version{kRecordSchemaVersion};
  State state{State::Idle};
  Checkpoint checkpoint{Checkpoint::None};
  PrepareRequest prepare;

  std::string prepared_firmware_version;
  std::string prepared_build_hash;
  std::string prepared_boot_id;
  std::uint64_t newest_stored_sequence{0U};
  std::uint64_t newest_syncable_sequence{0U};
  std::uint64_t sensor_server_acknowledgement{0U};
  std::uint64_t sensor_maximum_seen{0U};
  std::uint64_t prepared_removal_floor{0U};
  std::uint64_t local_sequence_floor{0U};
  std::uint64_t next_sequence{0U};
  std::uint64_t local_record_count{0U};
  // Exactly one partial interval can be closed by reset admission. These
  // fields describe only that reset-only FIFO handoff, after SdStorage has
  // durably assigned its sequence; ordinary queued records are excluded.
  std::uint64_t prepare_drain_records_added{0U};
  bool prepare_drain_sequence_range_set{false};
  std::uint64_t prepare_drain_first_sequence{0U};
  std::uint64_t prepare_drain_last_sequence{0U};
  std::uint64_t prepare_drain_syncable_records_added{0U};
  std::uint64_t card_generation{0U};
  std::string sd_status;
  std::uint64_t prepared_pzem_energy_wh{0U};
  std::uint64_t software_energy_baseline_before_wh{0U};
  std::string configuration_digest_before;
  std::string prepared_receipt;
  std::string prepared_receipt_digest;
  std::uint64_t measurement_pause_started_utc_ms{0U};
  std::uint64_t measurement_pause_ended_utc_ms{0U};
  bool measurement_pause_evidenced{false};

  bool approved_boundary_set{false};
  std::uint64_t approved_boundary{0U};
  std::uint64_t new_sequence_floor{0U};
  std::uint64_t new_next_sequence{0U};
  bool commit_energy_baseline_set{false};
  std::uint64_t commit_pzem_energy_wh{0U};
  std::uint64_t application_energy_baseline_wh{0U};
  std::uint64_t verified_pzem_energy_wh{0U};

  std::uint64_t readings_deleted{0U};
  std::uint64_t indexes_deleted{0U};
  std::uint64_t exports_deleted{0U};
  std::uint64_t backlog_entries_deleted{0U};
  std::string configuration_digest_after;
  std::string completion_timestamp;
  std::string completion_receipt;
  std::string failure_code;
};

const char *stateName(State state);
bool parseState(const std::string &value, State &state);
const char *checkpointName(Checkpoint checkpoint);
bool parseCheckpoint(const std::string &value, Checkpoint &checkpoint);
const char *requestDispositionName(RequestDisposition disposition);

bool categoriesSupported(const std::vector<std::string> &categories);
bool validPrepareRequest(const PrepareRequest &request);
bool validCommitRequest(const CommitRequest &request);
bool prepareRequestsEqual(const PrepareRequest &left,
                          const PrepareRequest &right);
bool commitRequestsEqual(const CommitRequest &left,
                         const CommitRequest &right);

BoundaryResult highestTrustedBoundary(const BoundaryInputs &inputs);
BoundaryInputs boundaryInputs(const Record &record);

bool terminalState(State state);
bool cancellableState(State state);
bool commitPointReached(Checkpoint checkpoint);
bool readingGateRequired(State state, Checkpoint checkpoint);
bool gatesReleased(const GateSnapshot &gates);
bool completionExternallyVisible(State state, Checkpoint checkpoint,
                                 const GateSnapshot &gates);
bool cancellationExternallyVisible(State state, Checkpoint checkpoint,
                                   const GateSnapshot &gates);
State resumeStateForCheckpoint(Checkpoint checkpoint);
bool validStateCheckpoint(State state, Checkpoint checkpoint);
bool canTransition(State from, State to, Checkpoint checkpoint);
bool canAdvanceCheckpoint(Checkpoint current, Checkpoint proposed);

bool validRecord(const Record &record);
bool recordsEqual(const Record &left, const Record &right);
bool validRecordUpdate(const Record &current, const Record &proposed);

RequestDisposition classifyPrepareRequest(const Record *existing,
                                          std::uint64_t active_generation,
                                          const PrepareRequest &request);
RequestDisposition classifyCommitRequest(const Record &record,
                                         const CommitRequest &request);

} // namespace data_reset
} // namespace pm
