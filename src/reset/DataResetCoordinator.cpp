#include "reset/DataResetCoordinator.h"

#include <algorithm>
#include <limits>

#include <ArduinoJson.h>

#include "diagnostics/SerialLogger.h"
#include "reset/DataResetCapacityPolicy.h"
#include "reset/DataResetReceipt.h"
#include "security/Crypto.h"
#include "version.h"

namespace pm {
namespace {

constexpr char kReceiptContext[] = "pm-data-reset-receipt-v1";

const char *wireState(const data_reset::Record &record) {
  if (record.state == data_reset::State::Committing) {
    return data_reset::checkpointName(record.checkpoint);
  }
  if (record.state == data_reset::State::AttentionRequired) {
    return "attention_required";
  }
  return data_reset::stateName(record.state);
}

std::string serializeCompact(JsonDocument &document) {
  std::string output;
  serializeJson(document, output);
  return output;
}

bool preparedFirmwareMatchesRunning(const data_reset::Record &record) {
  return record.prepared_firmware_version == version::FIRMWARE &&
         record.prepared_build_hash == OtaService::runningBuildHash();
}

} // namespace

DataResetCoordinator::DataResetCoordinator(
    ConfigService &config, ClockService &clock, SdStorage &storage,
    StorageCoordinator &storage_coordinator, Diagnostics &diagnostics,
    IMeter &meter, OtaService &ota, const SemaphoreHandle_t meter_mutex)
    : config_(config), clock_(clock), storage_(storage),
      storage_coordinator_(storage_coordinator), diagnostics_(diagnostics),
      meter_(meter), ota_(ota), meter_mutex_(meter_mutex) {}

bool DataResetCoordinator::begin() {
  mutex_ = xSemaphoreCreateMutex();
  if (mutex_ == nullptr) {
    return false;
  }
  data_reset::Record loaded;
  const DataResetStoreResult result = store_.load(loaded);
  if (result == DataResetStoreResult::Loaded) {
    record_ = std::move(loaded);
    has_record_ = true;
    if (record_.checkpoint == data_reset::Checkpoint::None &&
        record_.approved_boundary_set &&
        (record_.state == data_reset::State::Prepared ||
         record_.state == data_reset::State::AttentionRequired)) {
      commit_request_.protocol = record_.prepare.protocol;
      commit_request_.operation_id = record_.prepare.operation_id;
      commit_request_.device_id = record_.prepare.device_id;
      commit_request_.target_generation =
          record_.prepare.target_generation;
      commit_request_.plan_revision = record_.prepare.plan_revision;
      commit_request_.plan_digest = record_.prepare.plan_digest;
      commit_request_.approved_boundary = record_.approved_boundary;
      commit_request_.prepared_receipt_digest =
          record_.prepared_receipt_digest;
      pending_commit_ = true;
    }
  } else if (result != DataResetStoreResult::NotFound) {
    PM_LOG_FATAL("RESET", "RESET_STATE_LOAD_FAILED",
                 "error=%s fail_closed=true",
                 dataResetStoreResultName(result));
    applyGates(true);
    return false;
  }
  const bool completed_card_unverified =
      has_record_ && record_.state == data_reset::State::Completed &&
      !storage_.verifyDataResetCardBinding(record_.card_generation,
                                           record_.prepare.device_id);
  const bool gated =
      has_record_ &&
      (data_reset::readingGateRequired(record_.state, record_.checkpoint) ||
       completed_card_unverified);
  if (!applyGates(gated)) {
    PM_LOG_FATAL("RESET", "RESET_GATE_RESTORE_FAILED",
                 "active=%s fail_closed=true", gated ? "true" : "false");
    applyGates(true);
    return false;
  }
  if (gated) {
    storage_coordinator_.markDataResetPrepareDurable();
  }
  PM_LOG_INFO("RESET", "RESET_STATE_LOADED",
              "present=%s state=%s checkpoint=%s generation=%llu boundary=%llu",
              has_record_ ? "true" : "false",
              has_record_ ? data_reset::stateName(record_.state) : "none",
              has_record_ ? data_reset::checkpointName(record_.checkpoint)
                          : "none",
              static_cast<unsigned long long>(config_.dataGeneration()),
              static_cast<unsigned long long>(requiredSequenceFloor()));
  return true;
}

bool DataResetCoordinator::lock(const TickType_t timeout) const {
  return mutex_ != nullptr && xSemaphoreTake(mutex_, timeout) == pdTRUE;
}

void DataResetCoordinator::unlock() const { xSemaphoreGive(mutex_); }

data_reset::GateSnapshot DataResetCoordinator::gateSnapshot() const {
  return {config_.dataResetFrozen(),
          storage_coordinator_.recordWritesEnabled(),
          data_reset::resetAdmissionActive()};
}

bool DataResetCoordinator::gatesReleased() const {
  return data_reset::gatesReleased(gateSnapshot());
}

bool DataResetCoordinator::completionVisible(
    const data_reset::Record &record) const {
  return data_reset::completionExternallyVisible(
      record.state, record.checkpoint, gateSnapshot());
}

bool DataResetCoordinator::cancellationVisible(
    const data_reset::Record &record) const {
  return data_reset::cancellationExternallyVisible(
      record.state, record.checkpoint, gateSnapshot());
}

bool DataResetCoordinator::terminalReleasePending(
    const data_reset::Record &record) const {
  return (record.state == data_reset::State::Completed &&
          !completionVisible(record)) ||
         (record.state == data_reset::State::Cancelled &&
          !cancellationVisible(record));
}

bool DataResetCoordinator::applyGates(const bool enabled) {
  if (enabled) {
    bool admission_newly_acquired = false;
    if (!data_reset::claimResetAdmission(admission_newly_acquired)) {
      return false;
    }
    if (admission_newly_acquired) {
      const data_reset::PrepareRequest *const active_prepare =
          pending_prepare_ ? &prepare_request_
                           : (has_record_ ? &record_.prepare : nullptr);
      if (active_prepare != nullptr &&
          active_prepare->target_generation > 0U) {
        const StorageHealth health = storage_.health();
        const std::uint64_t bound_card_generation =
            active_prepare->expected_card_generation_set
                ? active_prepare->expected_card_generation
                : (has_record_ && record_.card_generation > 0U
                       ? record_.card_generation
                       : health.card_generation);
        storage_coordinator_.beginDataResetProducerBarrier(
            active_prepare->operation_id, active_prepare->device_id,
            active_prepare->target_generation - 1U,
            active_prepare->target_generation, bound_card_generation);
      }
    }
    if (!config_.setDataResetFreeze(true)) {
      // Reassertion is idempotent. A transient configuration-lock timeout
      // must not release admission that a durable reset already owned.
      if (admission_newly_acquired) {
        storage_coordinator_.endDataResetProducerBarrier();
        data_reset::releaseResetAdmission();
      }
      return false;
    }
    storage_coordinator_.setRecordWritesEnabled(false);
    // Latest measurement evidence is data, not health. Invalidate it at gate
    // admission so a heartbeat cannot retag a pre-reset/pre-baseline sample
    // with a later root generation.
    diagnostics_.suspendLatestForDataReset();
  } else {
    if (has_record_ && record_.state == data_reset::State::Completed &&
        !storage_.verifyDataResetCardBinding(record_.card_generation,
                                             record_.prepare.device_id)) {
      return false;
    }
    // The cache is cleared and the post-baseline generation latch is armed
    // before either producer gate is reopened.
    diagnostics_.resumeLatestForGeneration(config_.dataGeneration());
    storage_coordinator_.setRecordWritesEnabled(true);
    if (!config_.setDataResetFreeze(false)) {
      storage_coordinator_.setRecordWritesEnabled(false);
      return false;
    }
    data_reset::releaseResetAdmission();
    storage_coordinator_.endDataResetProducerBarrier();
    return gatesReleased();
  }
  return true;
}

DataResetApiResult DataResetCoordinator::problem(const int status,
                                                 const char *code,
                                                 const char *detail) {
  DataResetApiResult result;
  result.status = status;
  result.code = code;
  result.detail = detail;
  return result;
}

DataResetApiResult DataResetCoordinator::requestPrepare(
    const data_reset::PrepareRequest &request) {
  if (!data_reset::validPrepareRequest(request)) {
    return problem(422, "data_reset_request_invalid",
                   "The reset prepare document is invalid.");
  }
  const DeviceIdentity identity = config_.identity();
  if (!identity.enrolled || request.device_id != identity.device_id) {
    return problem(409, "data_reset_device_mismatch",
                   "The authenticated device does not match the reset target.");
  }

  // Exact operation replays are classified against the durable request before
  // comparing target_generation with the now-advanced active generation. This
  // keeps prepare idempotent after a completed reset while still rejecting a
  // changed document that reuses the operation ID.
  if (!lock()) {
    return problem(503, "data_reset_busy", "Reset state is temporarily busy.");
  }
  if (pending_prepare_ &&
      request.operation_id == prepare_request_.operation_id) {
    const bool replay =
        data_reset::prepareRequestsEqual(prepare_request_, request);
    JsonDocument response;
    response["protocol"] = data_reset::kProtocolVersion;
    response["operation_id"] = prepare_request_.operation_id;
    response["device_id"] = prepare_request_.device_id;
    response["target_generation"] = prepare_request_.target_generation;
    response["state"] = "preparing";
    response["checkpoint"] = "preparing";
    const std::string body = serializeCompact(response);
    unlock();
    return replay
               ? DataResetApiResult{202, {}, {}, body}
               : problem(409, "reset_operation_conflict",
                         "A changed request reused an active reset operation.");
  }
  if (has_record_ && request.operation_id == record_.prepare.operation_id) {
    const data_reset::RequestDisposition replay_disposition =
        data_reset::classifyPrepareRequest(&record_, config_.dataGeneration(),
                                           request);
    if (replay_disposition == data_reset::RequestDisposition::Replay) {
      const int status_code =
          record_.state == data_reset::State::Preparing ||
                  terminalReleasePending(record_)
              ? 202
              : 200;
      const std::string body = statusJson(record_);
      unlock();
      return {status_code, {}, {}, body};
    }
    unlock();
    return problem(409, "reset_operation_conflict",
                   "A changed request reused a durable reset operation.");
  }
  unlock();

  if (config_.dataGeneration() ==
          std::numeric_limits<std::uint64_t>::max() ||
      request.target_generation != config_.dataGeneration() + 1U) {
    return problem(409, "data_generation_conflict",
                   "The target generation is not the next generation.");
  }
  const std::string running_hash = OtaService::runningBuildHash();
  if (request.expected_firmware_version != version::FIRMWARE ||
      (request.expected_build_hash_set &&
       request.expected_build_hash != running_hash)) {
    return problem(409, "data_reset_firmware_mismatch",
                   "Firmware evidence changed after the reset plan was made.");
  }
  const StorageHealth health = storage_.health();
  if (!health.present || !health.mounted || !health.writable ||
      health.card_identity_status != "verified" ||
      (request.expected_card_generation_set &&
       request.expected_card_generation != health.card_generation)) {
    return problem(409, "data_reset_storage_mismatch",
                   "The planned microSD identity is not mounted and writable.");
  }
  data_reset::BoundaryInputs boundary_inputs;
  boundary_inputs.expected_boundary = request.expected_boundary;
  boundary_inputs.server_highest_contiguous =
      request.server_highest_contiguous;
  boundary_inputs.server_maximum_seen = request.server_maximum_seen;
  boundary_inputs.local_sequence_floor = health.sequence_floor;
  boundary_inputs.next_sequence = health.next_sequence;
  boundary_inputs.newest_stored_sequence = health.newest_sequence;
  boundary_inputs.newest_syncable_sequence = health.newest_syncable_sequence;
  boundary_inputs.sensor_server_acknowledgement = config_.serverAckSequence();
  boundary_inputs.sensor_maximum_seen = config_.serverMaximumSeenSequence();
  boundary_inputs.prepared_removal_floor = config_.preparedRemovalSequence();
  if (!data_reset::highestTrustedBoundary(boundary_inputs).valid) {
    return problem(409, "sequence_exhausted",
                   "No monotonic sequence remains above the reset boundary.");
  }
  const OtaStatus ota_status = ota_.status();
  if (ota_status.in_progress || ota_status.pending_reboot ||
      ota_status.restricted_recovery_mode) {
    return problem(409, "data_reset_ota_active",
                   "An OTA or restricted-recovery operation is active.");
  }
  if (!lock()) {
    return problem(503, "data_reset_busy", "Reset state is temporarily busy.");
  }
  if (pending_prepare_) {
    const bool replay =
        data_reset::prepareRequestsEqual(prepare_request_, request);
    JsonDocument response;
    response["protocol"] = data_reset::kProtocolVersion;
    response["operation_id"] = prepare_request_.operation_id;
    response["device_id"] = prepare_request_.device_id;
    response["target_generation"] = prepare_request_.target_generation;
    response["state"] = "preparing";
    response["checkpoint"] = "preparing";
    const std::string body = serializeCompact(response);
    unlock();
    return replay
               ? DataResetApiResult{202, {}, {}, body}
               : problem(409, "reset_operation_conflict",
                         "A changed request reused an active reset operation.");
  }
  const data_reset::RequestDisposition disposition =
      data_reset::classifyPrepareRequest(has_record_ ? &record_ : nullptr,
                                         config_.dataGeneration(), request);
  if (disposition == data_reset::RequestDisposition::Replay) {
    const int status_code =
        record_.state == data_reset::State::Preparing ||
                terminalReleasePending(record_)
            ? 202
            : 200;
    const std::string body = statusJson(record_);
    unlock();
    return {status_code, {}, {}, body};
  }
  if (disposition != data_reset::RequestDisposition::Accept) {
    const char *code = data_reset::requestDispositionName(disposition);
    unlock();
    return problem(disposition == data_reset::RequestDisposition::Invalid
                       ? 422
                       : 409,
                   code, "The reset prepare request conflicts with device state.");
  }
  prepare_request_ = request;
  pending_prepare_ = true;
  // Publish the shared atomic config/storage admission gate before returning
  // 202. An OTA, reboot, or maintenance item already queued on another task
  // therefore cannot start in the RAM-only pending-prepare window.
  if (!applyGates(true)) {
    pending_prepare_ = false;
    prepare_request_ = {};
    unlock();
    return problem(503, "data_reset_gate_failed",
                   "The reset admission gate could not be established.");
  }
  const OtaStatus gated_ota_status = ota_.status();
  if (gated_ota_status.in_progress || gated_ota_status.pending_reboot ||
      gated_ota_status.restricted_recovery_mode) {
    pending_prepare_ = false;
    prepare_request_ = {};
    applyGates(false);
    unlock();
    return problem(409, "data_reset_ota_active",
                   "An OTA operation won the reset admission race.");
  }
  data_reset::DataResetCapacityReport capacity;
  const bool capacity_queried = data_reset::queryDataResetCapacity(capacity);
  if (!capacity_queried || !data_reset::dataResetCapacitySufficient(capacity)) {
    pending_prepare_ = false;
    prepare_request_ = {};
    applyGates(false);
    PM_LOG_ERROR(
        "RESET", "RESET_PERSISTENCE_CAPACITY_REJECTED",
        "pmconfig_query=%s pmconfig_free_entries=%u pmconfig_required_entries=%u "
        "pmconfig_terminal_entries=%u "
        "default_nvs_query=%s default_nvs_free_entries=%u "
        "default_nvs_required_entries=%u default_nvs_terminal_entries=%u "
        "destructive_work_started=false",
        capacity.pmconfig.query_succeeded ? "true" : "false",
        static_cast<unsigned>(capacity.pmconfig.free_entries),
        static_cast<unsigned>(
            data_reset::requiredPmconfigFreeEntries(capacity)),
        static_cast<unsigned>(capacity.pmconfig_terminal_entries),
        capacity.default_nvs.query_succeeded ? "true" : "false",
        static_cast<unsigned>(capacity.default_nvs.free_entries),
        static_cast<unsigned>(
            data_reset::requiredDefaultNvsFreeEntries(capacity)),
        static_cast<unsigned>(capacity.default_nvs_terminal_entries));
    unlock();
    return problem(507, "data_reset_persistence_capacity_insufficient",
                   "Durable reset journal capacity is insufficient.");
  }
  unlock();
  JsonDocument accepted;
  accepted["protocol"] = data_reset::kProtocolVersion;
  accepted["operation_id"] = request.operation_id;
  accepted["device_id"] = request.device_id;
  accepted["target_generation"] = request.target_generation;
  accepted["state"] = "preparing";
  accepted["checkpoint"] = "preparing";
  return {202, {}, {}, serializeCompact(accepted)};
}

DataResetApiResult DataResetCoordinator::requestCommit(
    const data_reset::CommitRequest &request) {
  if (!data_reset::validCommitRequest(request)) {
    return problem(422, "data_reset_request_invalid",
                   "The reset commit document is invalid.");
  }
  if (!lock()) {
    return problem(503, "data_reset_busy", "Reset state is temporarily busy.");
  }
  if (!has_record_) {
    unlock();
    return problem(409, "data_reset_not_prepared",
                   "No prepared reset exists on this device.");
  }
  if (pending_commit_) {
    const bool replay =
        data_reset::commitRequestsEqual(commit_request_, request);
    const std::string body = has_record_ ? statusJson(record_) : std::string{};
    unlock();
    return replay
               ? DataResetApiResult{202, {}, {}, body}
               : problem(409, "reset_operation_conflict",
                         "A changed request reused an active reset operation.");
  }
  const data_reset::RequestDisposition disposition =
      data_reset::classifyCommitRequest(record_, request);
  const bool durable_commit_intent =
      disposition == data_reset::RequestDisposition::Replay &&
      record_.checkpoint == data_reset::Checkpoint::None &&
      record_.approved_boundary_set;
  if (disposition == data_reset::RequestDisposition::Replay &&
      record_.state != data_reset::State::AttentionRequired &&
      !durable_commit_intent) {
    const std::string body = statusJson(record_);
    const bool completed = completionVisible(record_);
    unlock();
    return {completed ? 200 : 202, {}, {}, body};
  }
  if (disposition != data_reset::RequestDisposition::Accept &&
      !(disposition == data_reset::RequestDisposition::Replay &&
        (record_.state == data_reset::State::AttentionRequired ||
         durable_commit_intent))) {
    const char *code = data_reset::requestDispositionName(disposition);
    unlock();
    return problem(disposition == data_reset::RequestDisposition::Invalid
                       ? 422
                       : 409,
                   code, "The reset commit request conflicts with prepared state.");
  }
  if (disposition == data_reset::RequestDisposition::Accept) {
    data_reset::Record latched = record_;
    latched.approved_boundary_set = true;
    latched.approved_boundary = request.approved_boundary;
    latched.new_sequence_floor = request.approved_boundary;
    latched.new_next_sequence = request.approved_boundary + 1U;
    latched.failure_code.clear();
    if (!saveRecord(latched)) {
      unlock();
      return problem(503, "data_reset_commit_intent_persistence_failed",
                     "Commit intent could not be durably latched.");
    }
  }
  commit_request_ = request;
  pending_commit_ = true;
  const std::string body = statusJson(record_);
  unlock();
  return {202, {}, {}, body};
}

DataResetApiResult DataResetCoordinator::requestCancel(
    const DataResetCancelRequest &request) {
  if (!lock()) {
    return problem(503, "data_reset_busy", "Reset state is temporarily busy.");
  }
  bool durable_match =
      has_record_ && request.protocol == record_.prepare.protocol &&
      request.operation_id == record_.prepare.operation_id &&
      request.device_id == record_.prepare.device_id &&
      request.target_generation == record_.prepare.target_generation &&
      request.plan_revision == record_.prepare.plan_revision &&
      request.plan_digest == record_.prepare.plan_digest;
  // The mutex linearizes commit-vs-cancel. Once commit has been accepted into
  // the RAM work queue, that request owns the operation even though the
  // irreversible durable checkpoint is written by a later tick.
  if (pending_commit_ && durable_match) {
    unlock();
    return problem(409, "data_reset_commit_already_authorized",
                   "Commit was accepted before cancellation.");
  }
  const bool pending_match =
      pending_prepare_ && request.protocol == prepare_request_.protocol &&
      request.operation_id == prepare_request_.operation_id &&
      request.device_id == prepare_request_.device_id &&
      request.target_generation == prepare_request_.target_generation &&
      request.plan_revision == prepare_request_.plan_revision &&
      request.plan_digest == prepare_request_.plan_digest;
  if (pending_match &&
      (!has_record_ || data_reset::terminalState(record_.state))) {
    if (!storage_coordinator_.dataResetProducerQuiesced()) {
      JsonDocument response;
      response["protocol"] = data_reset::kProtocolVersion;
      response["operation_id"] = request.operation_id;
      response["device_id"] = request.device_id;
      response["target_generation"] = request.target_generation;
      response["state"] = "preparing";
      response["checkpoint"] = "preparing";
      const std::string body = serializeCompact(response);
      unlock();
      return {202, {}, {}, body};
    }
    data_reset::Record preparing;
    preparing.state = data_reset::State::Preparing;
    preparing.checkpoint = data_reset::Checkpoint::None;
    preparing.prepare = prepare_request_;
    preparing.measurement_pause_started_utc_ms = clock_.utcMs();
    if (preparing.measurement_pause_started_utc_ms == 0U ||
        !saveRecord(preparing)) {
      unlock();
      return problem(503, "data_reset_persistence_failed",
                     "Cancellation tombstone admission could not be persisted.");
    }
    pending_prepare_ = false;
    prepare_request_ = {};
    storage_coordinator_.markDataResetPrepareDurable();
    durable_match = true;
  }
  if (!has_record_ && !pending_prepare_) {
    unlock();
    return problem(409, "data_reset_not_prepared",
                   "No accepted reset operation exists to cancel.");
  }
  if (!durable_match) {
    unlock();
    return problem(409, "reset_operation_conflict",
                   "Cancellation does not match the prepared reset.");
  }
  if (record_.state == data_reset::State::Cancelled) {
    // Cancellation is idempotent. Also retry the reversible gate release in
    // case the original response observed a transient configuration-lock
    // timeout after the cancelled record had already been read back.
    if (!applyGates(false)) {
      const std::string body = statusJson(record_);
      unlock();
      return {202, {}, {}, body};
    }
    const std::string body = statusJson(record_);
    unlock();
    return {200, {}, {}, body};
  }
  if (record_.approved_boundary_set) {
    unlock();
    return problem(409, "data_reset_commit_already_authorized",
                   "Cancellation is not allowed after commit acceptance.");
  }
  if ((record_.state == data_reset::State::Preparing ||
       (record_.state == data_reset::State::AttentionRequired &&
        record_.checkpoint == data_reset::Checkpoint::None)) &&
      !storage_coordinator_.dataResetDrainSafeToCancel(
          record_.prepare.operation_id, record_.prepare.device_id,
          record_.prepare.target_generation - 1U,
          record_.prepare.target_generation,
          record_.prepare.expected_card_generation_set
              ? record_.prepare.expected_card_generation
              : 0U,
          config_.energyOffsetWh())) {
    // A Staged/Assigned accumulator drain still owns measurement data. Let
    // the prepare barrier append and scrub it first. Persistent pre-commit
    // failures become cancellable once that handoff is Completed (or proved
    // absent after producer quiescence).
    const std::string body = statusJson(record_);
    unlock();
    return {202, {}, {}, body};
  }
  if (!data_reset::cancellableState(record_.state) ||
      data_reset::commitPointReached(record_.checkpoint)) {
    unlock();
    return problem(409, "data_reset_commit_already_authorized",
                   "Cancellation is not allowed after commit authorization.");
  }
  data_reset::Record cancelled = record_;
  cancelled.state = data_reset::State::Cancelled;
  cancelled.failure_code.clear();
  if (!persistMeasurementPauseEvidence(cancelled)) {
    unlock();
    return problem(503, "data_reset_pause_evidence_failed",
                   "Cancellation pause evidence could not be persisted.");
  }
  if (!saveRecord(cancelled)) {
    unlock();
    return problem(503, "data_reset_persistence_failed",
                   "Cancellation could not be durably verified.");
  }
  pending_prepare_ = false;
  pending_commit_ = false;
  barrier_purpose_ = BarrierPurpose::None;
  if (!applyGates(false)) {
    const std::string body = statusJson(record_);
    unlock();
    return {202, {}, {}, body};
  }
  const std::string body = statusJson(record_);
  unlock();
  return {200, {}, {}, body};
}

DataResetApiResult
DataResetCoordinator::status(const std::string &operation_id,
                             const std::uint64_t target_generation) const {
  if (!lock()) {
    return problem(503, "data_reset_busy", "Reset state is temporarily busy.");
  }
  if (!has_record_ || record_.prepare.operation_id != operation_id ||
      record_.prepare.target_generation != target_generation) {
    unlock();
    return problem(404, "data_reset_not_found",
                   "The reset operation is not present on this device.");
  }
  const std::string body = statusJson(record_);
  const int status_code = terminalReleasePending(record_) ? 202 : 200;
  unlock();
  return {status_code, {}, {}, body};
}

bool DataResetCoordinator::saveRecord(const data_reset::Record &proposed) {
  const DataResetStoreResult result = store_.saveAndVerify(proposed);
  if (result != DataResetStoreResult::SavedAndVerified) {
    PM_LOG_ERROR("RESET", "RESET_STATE_SAVE_FAILED",
                 "error=%s state=%s checkpoint=%s",
                 dataResetStoreResultName(result),
                 data_reset::stateName(proposed.state),
                 data_reset::checkpointName(proposed.checkpoint));
    return false;
  }
  record_ = proposed;
  has_record_ = true;
  return true;
}

void DataResetCoordinator::tick() {
  if (!lock(pdMS_TO_TICKS(25))) {
    return;
  }
  if (pending_prepare_) {
    // Persist Preparing before considering terminal/no-record gate repair.
    // This prevents the admission gate set before HTTP 202 from reopening for
    // one tick while the request still exists only in RAM.
    processPendingPrepare();
  }
  if (!pending_prepare_ &&
      (!has_record_ ||
       (has_record_ && (record_.state == data_reset::State::Completed ||
                        record_.state == data_reset::State::Cancelled))) &&
      !gatesReleased()) {
    // Completion/cancellation is the durable decision. Gate release is
    // reversible and may be retried until both producers agree that normal
    // work is enabled; a reboot performs the same reconciliation in begin().
    applyGates(false);
  }
  if (has_record_ && record_.state == data_reset::State::Preparing) {
    progressPreparing();
  }
  if (pending_commit_) {
    processPendingCommit();
  }
  if (has_record_ && record_.state == data_reset::State::Committing) {
    progressCommit();
  }
  unlock();
}

void DataResetCoordinator::processPendingPrepare() {
  data_reset::Record proposed;
  proposed.state = data_reset::State::Preparing;
  proposed.checkpoint = data_reset::Checkpoint::None;
  proposed.prepare = prepare_request_;
  proposed.measurement_pause_started_utc_ms = clock_.utcMs();
  if (proposed.measurement_pause_started_utc_ms == 0U) {
    // The authenticated reset timestamp is UTC, and pause evidence must be a
    // real comparable instant. Keep admission closed and retry once the local
    // trusted clock is available rather than persisting a fake epoch value.
    return;
  }
  if (!applyGates(true)) {
    return;
  }
  // Close and durably stage the accumulator before publishing Preparing.
  // If power fails after staging but before this main-state commit, boot
  // recognizes the orphan journal and appends it through the ordinary source
  // generation instead of losing the interval.
  if (!storage_coordinator_.dataResetProducerQuiesced()) {
    return;
  }
  if (!saveRecord(proposed)) {
    // Retain admission and retry. Reopening here would strand a successfully
    // staged pre-main drain journal.
    return;
  }
  storage_coordinator_.markDataResetPrepareDurable();
  pending_prepare_ = false;
  prepare_request_ = {};
  barrier_purpose_ = BarrierPurpose::None;
  PM_LOG_WARN("RESET", "RESET_PREPARE_STARTED",
              "operation=%s generation=%llu reading_gate=true",
              record_.prepare.operation_id.c_str(),
              static_cast<unsigned long long>(
                  record_.prepare.target_generation));
}

void DataResetCoordinator::progressPreparing() {
  applyGates(true);
  storage_coordinator_.markDataResetPrepareDurable();
  if (!storage_coordinator_.dataResetProducerQuiesced()) {
    if (diag::SerialLogger::instance().allow("data_reset_producer_drain",
                                             5000U)) {
      PM_LOG_INFO("RESET", "RESET_PRODUCER_DRAIN_WAIT",
                  "aggregation_quiesced=false prepared=false");
    }
    return;
  }
  if (data_reset::readingSyncInFlight() != 0U) {
    if (diag::SerialLogger::instance().allow("data_reset_sync_drain", 5000U)) {
      PM_LOG_INFO("RESET", "RESET_SYNC_DRAIN_WAIT",
                  "reading_sync_in_flight=%lu prepared=false",
                  static_cast<unsigned long>(
                      data_reset::readingSyncInFlight()));
    }
    return;
  }
  if (barrier_purpose_ == BarrierPurpose::None) {
    if (++barrier_request_id_ == 0U) {
      ++barrier_request_id_;
    }
    const std::uint64_t bound_card_generation =
        record_.prepare.expected_card_generation_set
            ? record_.prepare.expected_card_generation
            : (record_.card_generation > 0U
                   ? record_.card_generation
                   : storage_.health().card_generation);
    if (storage_coordinator_.queueDataResetBarrier(
            barrier_request_id_, false, bound_card_generation,
            record_.prepare.device_id, record_.prepare.operation_id,
            record_.prepare.target_generation - 1U,
            record_.prepare.target_generation)) {
      barrier_purpose_ = BarrierPurpose::PrepareDrain;
    }
    return;
  }
  if (barrier_purpose_ != BarrierPurpose::PrepareDrain) {
    return;
  }
  StorageCoordinator::DataResetStorageResult barrier;
  if (!storage_coordinator_.dataResetStorageResult(barrier_request_id_, barrier) ||
      !barrier.complete) {
    return;
  }
  barrier_purpose_ = BarrierPurpose::None;
  if (!barrier.ok) {
    failBeforeCommit(barrier.error.empty() ? "data_reset_storage_barrier_failed"
                                          : barrier.error.c_str());
    return;
  }
  if (barrier.prepare_drain_records_added > 2U ||
      barrier.prepare_drain_syncable_records_added >
          barrier.prepare_drain_records_added ||
      barrier.prepare_drain_sequence_range_set !=
          (barrier.prepare_drain_records_added > 0U) ||
      (barrier.prepare_drain_records_added > 0U &&
       (barrier.prepare_drain_first_sequence == 0U ||
        barrier.prepare_drain_last_sequence <
            barrier.prepare_drain_first_sequence ||
        barrier.prepare_drain_last_sequence -
                    barrier.prepare_drain_first_sequence +
                1U !=
            barrier.prepare_drain_records_added)) ||
      (barrier.prepare_drain_records_added > 0U &&
       (!config_.setEnergyOffsetWhForDataResetDrain(
            barrier.prepare_drain_energy_offset_wh) ||
        config_.energyOffsetWh() !=
            barrier.prepare_drain_energy_offset_wh))) {
    failBeforeCommit("data_reset_drain_evidence_invalid");
    return;
  }
  const StorageHealth health = storage_.health();
  if (!health.present || !health.mounted || !health.writable ||
      health.card_identity_status != "verified" || health.card_generation == 0U ||
      health.next_sequence == 0U || health.sequence_floor >= health.next_sequence ||
      (record_.prepare.expected_card_generation_set &&
       record_.prepare.expected_card_generation != health.card_generation)) {
    failBeforeCommit("data_reset_storage_evidence_invalid");
    return;
  }
  std::uint64_t raw_energy_wh = 0U;
  if (!captureMeterEnergy(raw_energy_wh)) {
    failBeforeCommit("data_reset_pzem_unavailable");
    return;
  }
  std::string config_digest;
  if (!config_.configurationPreservationDigest(config_digest)) {
    failBeforeCommit("data_reset_configuration_digest_failed");
    return;
  }
  data_reset::Record prepared = record_;
  prepared.state = data_reset::State::Prepared;
  prepared.prepared_firmware_version = version::FIRMWARE;
  prepared.prepared_build_hash = OtaService::runningBuildHash();
  prepared.prepared_boot_id = config_.identity().boot_id;
  prepared.newest_stored_sequence = health.newest_sequence;
  prepared.newest_syncable_sequence = health.newest_syncable_sequence;
  prepared.sensor_server_acknowledgement = config_.serverAckSequence();
  prepared.sensor_maximum_seen =
      std::max(config_.serverMaximumSeenSequence(),
               prepared.sensor_server_acknowledgement);
  prepared.prepared_removal_floor = config_.preparedRemovalSequence();
  prepared.local_sequence_floor = health.sequence_floor;
  prepared.next_sequence = health.next_sequence;
  prepared.local_record_count = health.local_record_count;
  prepared.prepare_drain_records_added =
      barrier.prepare_drain_records_added;
  prepared.prepare_drain_sequence_range_set =
      barrier.prepare_drain_sequence_range_set;
  prepared.prepare_drain_first_sequence =
      barrier.prepare_drain_first_sequence;
  prepared.prepare_drain_last_sequence =
      barrier.prepare_drain_last_sequence;
  prepared.prepare_drain_syncable_records_added =
      barrier.prepare_drain_syncable_records_added;
  prepared.card_generation = health.card_generation;
  prepared.sd_status = health.card_identity_status;
  prepared.prepared_pzem_energy_wh = raw_energy_wh;
  prepared.software_energy_baseline_before_wh =
      config_.energyBaselineAbsoluteWh();
  prepared.configuration_digest_before = std::move(config_digest);
  prepared.failure_code.clear();
  // Reset admission prevents a new lease after the earlier drain. Keep the
  // final assertion adjacent to the durable transition so future refactors
  // cannot move Prepared ahead of sync quiescence.
  if (!storage_coordinator_.dataResetProducerQuiesced() ||
      data_reset::readingSyncInFlight() != 0U ||
      !storage_.verifyDataResetCardBinding(health.card_generation,
                                           record_.prepare.device_id)) {
    return;
  }
  if (!prepareReceipt(prepared) || !saveRecord(prepared)) {
    failBeforeCommit("data_reset_prepare_persistence_failed");
    return;
  }
  if (!storage_.verifyDataResetCardBinding(record_.card_generation,
                                           record_.prepare.device_id)) {
    data_reset::Record attention = record_;
    attention.state = data_reset::State::AttentionRequired;
    attention.failure_code = "data_reset_storage_identity_changed";
    saveRecord(attention);
    return;
  }
  PM_LOG_WARN("RESET", "RESET_PREPARED",
              "operation=%s generation=%llu boundary_floor=%llu records=%llu",
              record_.prepare.operation_id.c_str(),
              static_cast<unsigned long long>(record_.prepare.target_generation),
              static_cast<unsigned long long>(record_.local_sequence_floor),
              static_cast<unsigned long long>(record_.local_record_count));
}

void DataResetCoordinator::processPendingCommit() {
  data_reset::RequestDisposition disposition =
      data_reset::classifyCommitRequest(record_, commit_request_);
  if (disposition == data_reset::RequestDisposition::Replay &&
      record_.state == data_reset::State::AttentionRequired) {
    const bool after_commit_point =
        data_reset::commitPointReached(record_.checkpoint);
    data_reset::Record resumed = record_;
    resumed.state = data_reset::resumeStateForCheckpoint(record_.checkpoint);
    resumed.failure_code.clear();
    if (!saveRecord(resumed)) {
      return;
    }
    if (after_commit_point) {
      pending_commit_ = false;
      return;
    }
    // Before authorization, an operator can restore changed evidence and
    // replay the exact signed commit. Reclassify the now-Prepared record and
    // capture fresh evidence below; no irreversible checkpoint was crossed.
    disposition =
        data_reset::classifyCommitRequest(record_, commit_request_);
  }
  if (disposition == data_reset::RequestDisposition::Replay &&
      record_.checkpoint == data_reset::Checkpoint::None &&
      record_.approved_boundary_set) {
    disposition = data_reset::RequestDisposition::Accept;
  }
  if (disposition == data_reset::RequestDisposition::Replay) {
    pending_commit_ = false;
    return;
  }
  if (disposition != data_reset::RequestDisposition::Accept) {
    pending_commit_ = false;
    return;
  }
  const StorageHealth health = storage_.health();
  std::string current_digest;
  if (!preparedFirmwareMatchesRunning(record_)) {
    data_reset::Record attention = record_;
    attention.state = data_reset::State::AttentionRequired;
    attention.failure_code = "data_reset_prepared_firmware_changed";
    saveRecord(attention);
    pending_commit_ = false;
    return;
  }
  if (!sameCard(record_, health) ||
      !storage_.verifyDataResetCardBinding(record_.card_generation,
                                           record_.prepare.device_id) ||
      !config_.configurationPreservationDigest(current_digest) ||
      current_digest != record_.configuration_digest_before) {
    data_reset::Record attention = record_;
    attention.state = data_reset::State::AttentionRequired;
    attention.failure_code = "data_reset_prepare_evidence_changed";
    saveRecord(attention);
    pending_commit_ = false;
    return;
  }
  std::uint64_t raw_energy_wh = 0U;
  if (!captureMeterEnergy(raw_energy_wh) ||
      raw_energy_wh > std::numeric_limits<std::uint64_t>::max() -
                          config_.energyOffsetWh()) {
    data_reset::Record waiting = record_;
    waiting.failure_code = "data_reset_pzem_commit_capture_failed";
    saveRecord(waiting);
    pending_commit_ = false;
    return;
  }
  if (raw_energy_wh < record_.prepared_pzem_energy_wh) {
    data_reset::Record attention = record_;
    attention.state = data_reset::State::AttentionRequired;
    attention.failure_code = "data_reset_pzem_counter_decreased";
    saveRecord(attention);
    pending_commit_ = false;
    return;
  }
  data_reset::Record authorized = record_;
  authorized.state = data_reset::State::Committing;
  authorized.checkpoint = data_reset::Checkpoint::CommitAuthorized;
  authorized.approved_boundary_set = true;
  authorized.approved_boundary = commit_request_.approved_boundary;
  authorized.new_sequence_floor = commit_request_.approved_boundary;
  authorized.new_next_sequence = commit_request_.approved_boundary + 1U;
  authorized.commit_energy_baseline_set = true;
  authorized.commit_pzem_energy_wh = raw_energy_wh;
  authorized.application_energy_baseline_wh =
      config_.energyOffsetWh() + raw_energy_wh;
  authorized.failure_code.clear();
  if (!saveRecord(authorized)) {
    return;
  }
  pending_commit_ = false;
  PM_LOG_WARN("RESET", "RESET_COMMIT_AUTHORIZED",
              "operation=%s boundary=%llu irreversible=true",
              record_.prepare.operation_id.c_str(),
              static_cast<unsigned long long>(record_.approved_boundary));
}

void DataResetCoordinator::progressCommit() {
  // A durable Prepared/Committing record can survive a boot-slot rollback or
  // other image change. Never continue or sign completion using stale stored
  // firmware evidence under different running bytes.
  if (!preparedFirmwareMatchesRunning(record_)) {
    requireAttention("data_reset_prepared_firmware_changed");
    return;
  }
  switch (record_.checkpoint) {
  case data_reset::Checkpoint::CommitAuthorized: {
    const StorageHealth health = storage_.health();
    if (health.sequence_floor < record_.approved_boundary ||
        health.next_sequence < record_.new_next_sequence) {
      storage_coordinator_.queueDataResetSequenceReconciliation(
          record_.approved_boundary, record_.card_generation,
          record_.prepare.device_id);
      return;
    }
    if (!storage_.verifyDataResetCardBinding(record_.card_generation,
                                             record_.prepare.device_id)) {
      requireAttention("data_reset_storage_identity_changed");
      return;
    }
    data_reset::Record advanced = record_;
    advanced.checkpoint = data_reset::Checkpoint::SequenceAdvanced;
    if (!saveRecord(advanced)) {
      requireAttention("data_reset_sequence_checkpoint_failed");
    }
    return;
  }
  case data_reset::Checkpoint::SequenceAdvanced: {
    if (config_.serverAckSequence() > record_.approved_boundary ||
        config_.serverMaximumSeenSequence() > record_.approved_boundary ||
        !config_.setServerAckSequence(record_.approved_boundary) ||
        !config_.setServerMaximumSeenSequence(record_.approved_boundary) ||
        !config_.setDataGeneration(record_.prepare.target_generation) ||
        !config_.setDataResetBoundary(record_.approved_boundary)) {
      requireAttention("data_reset_cursor_advance_failed");
      return;
    }
    data_reset::Record advanced = record_;
    advanced.checkpoint = data_reset::Checkpoint::CursorsAdvanced;
    if (!saveRecord(advanced)) {
      requireAttention("data_reset_cursor_checkpoint_failed");
    }
    return;
  }
  case data_reset::Checkpoint::CursorsAdvanced:
    if (barrier_purpose_ == BarrierPurpose::None) {
      if (++barrier_request_id_ == 0U) {
        ++barrier_request_id_;
      }
      if (storage_coordinator_.queueDataResetBarrier(
          barrier_request_id_, true, record_.card_generation,
          record_.prepare.device_id, record_.prepare.operation_id,
          record_.prepare.target_generation - 1U,
          record_.prepare.target_generation)) {
        barrier_purpose_ = BarrierPurpose::Cleanup;
      }
      return;
    }
    if (barrier_purpose_ == BarrierPurpose::Cleanup) {
      StorageCoordinator::DataResetStorageResult result;
      if (!storage_coordinator_.dataResetStorageResult(barrier_request_id_,
                                                       result) ||
          !result.complete) {
        return;
      }
      barrier_purpose_ = BarrierPurpose::None;
      data_reset::Record counted = record_;
      // The SD cleanup journal returns authoritative counts from the initial
      // pre-delete inventory for this operation. Replacing, rather than
      // adding, keeps retries and reboot recovery exactly idempotent.
      counted.indexes_deleted = result.cleanup.index_files_removed;
      counted.exports_deleted = result.cleanup.export_files_removed;
      counted.backlog_entries_deleted =
          result.cleanup.metadata_files_removed;
      if ((counted.indexes_deleted != record_.indexes_deleted ||
           counted.exports_deleted != record_.exports_deleted ||
           counted.backlog_entries_deleted !=
               record_.backlog_entries_deleted) &&
          !saveRecord(counted)) {
        requireAttention("data_reset_cleanup_count_persistence_failed");
        return;
      }
      if (!result.ok) {
        requireAttention(result.error.empty()
                             ? "data_reset_reading_cleanup_failed"
                             : result.error.c_str());
        return;
      }
      data_reset::Record advanced = record_;
      advanced.readings_deleted = record_.local_record_count;
      advanced.checkpoint = data_reset::Checkpoint::ReadingsCleared;
      if (!saveRecord(advanced)) {
        requireAttention("data_reset_cleanup_checkpoint_failed");
      }
    }
    return;
  case data_reset::Checkpoint::ReadingsCleared: {
    if (!config_.setEnergyBaselineAbsoluteWh(
            record_.application_energy_baseline_wh) ||
        config_.energyBaselineAbsoluteWh() !=
            record_.application_energy_baseline_wh) {
      requireAttention("data_reset_baseline_install_failed");
      return;
    }
    data_reset::Record advanced = record_;
    advanced.checkpoint = data_reset::Checkpoint::BaselineInstalled;
    diagnostics_.markLatestBaselineInstalled(
        record_.prepare.target_generation);
    if (!saveRecord(advanced)) {
      requireAttention("data_reset_baseline_checkpoint_failed");
    }
    return;
  }
  case data_reset::Checkpoint::BaselineInstalled: {
    // Re-establish the RAM freshness epoch when boot resumes directly at the
    // durable baseline checkpoint.
    diagnostics_.markLatestBaselineInstalled(
        record_.prepare.target_generation);
    const StorageHealth health = storage_.health();
    std::string digest;
    std::uint64_t raw_energy_wh = 0U;
    if (!sameCard(record_, health) ||
        !storage_.verifyDataResetCardBinding(record_.card_generation,
                                             record_.prepare.device_id) ||
        !health.index_healthy ||
        health.local_record_count != 0U ||
        health.newest_sequence != 0U ||
        health.newest_syncable_sequence != 0U ||
        health.sequence_floor < record_.approved_boundary ||
        health.next_sequence < record_.new_next_sequence ||
        config_.serverAckSequence() < record_.approved_boundary ||
        config_.serverMaximumSeenSequence() < record_.approved_boundary ||
        config_.dataGeneration() != record_.prepare.target_generation ||
        config_.dataResetBoundary() != record_.approved_boundary ||
        !data_reset::installedEnergyBaselineMatches(
            config_.energyBaselineAbsoluteWh(),
            record_.application_energy_baseline_wh) ||
        !preparedFirmwareMatchesRunning(record_) ||
        !captureMeterEnergy(raw_energy_wh) ||
        raw_energy_wh < record_.commit_pzem_energy_wh ||
        !config_.configurationPreservationDigest(digest) ||
        digest != record_.configuration_digest_before) {
      requireAttention("data_reset_verification_failed");
      return;
    }
    data_reset::Record advanced = record_;
    advanced.configuration_digest_after = std::move(digest);
    advanced.verified_pzem_energy_wh = raw_energy_wh;
    advanced.checkpoint = data_reset::Checkpoint::Verified;
    if (!persistMeasurementPauseEvidence(advanced)) {
      requireAttention("data_reset_pause_evidence_failed");
      return;
    }
    if (!storage_.verifyDataResetCardBinding(record_.card_generation,
                                             record_.prepare.device_id) ||
        !saveRecord(advanced)) {
      requireAttention("data_reset_verification_checkpoint_failed");
      return;
    }
    if (!storage_.verifyDataResetCardBinding(record_.card_generation,
                                             record_.prepare.device_id)) {
      requireAttention("data_reset_storage_identity_changed");
    }
    return;
  }
  case data_reset::Checkpoint::Verified: {
    if (!storage_.verifyDataResetCardBinding(record_.card_generation,
                                             record_.prepare.device_id)) {
      requireAttention("data_reset_storage_identity_changed");
      return;
    }
    data_reset::Record completed = record_;
    completed.state = data_reset::State::Completed;
    completed.checkpoint = data_reset::Checkpoint::Completed;
    completed.completion_timestamp = clock_.utcIso8601();
    if (completed.completion_timestamp.empty()) {
      completed.completion_timestamp = completed.prepare.reset_timestamp;
    }
    completed.completion_receipt = buildCommitReceipt(completed);
    if (completed.completion_receipt.empty() ||
        !storage_.verifyDataResetCardBinding(record_.card_generation,
                                             record_.prepare.device_id) ||
        !saveRecord(completed)) {
      requireAttention("data_reset_completion_failed");
      return;
    }
    if (!applyGates(false)) {
      // The completed decision and receipt are already durable. tick() keeps
      // retrying this reversible release; never rewrite a completed operation
      // into a different terminal state.
      PM_LOG_WARN("RESET", "RESET_GATE_RELEASE_DEFERRED",
                  "operation=%s retryable=true",
                  record_.prepare.operation_id.c_str());
      return;
    }
    PM_LOG_WARN("RESET", "RESET_COMPLETED",
                "operation=%s generation=%llu boundary=%llu records_deleted=%llu",
                record_.prepare.operation_id.c_str(),
                static_cast<unsigned long long>(
                    record_.prepare.target_generation),
                static_cast<unsigned long long>(record_.approved_boundary),
                static_cast<unsigned long long>(record_.readings_deleted));
    return;
  }
  case data_reset::Checkpoint::None:
  case data_reset::Checkpoint::Completed: return;
  }
}

bool DataResetCoordinator::captureMeterEnergy(std::uint64_t &raw_energy_wh) {
  if (meter_mutex_ == nullptr ||
      xSemaphoreTake(meter_mutex_, pdMS_TO_TICKS(5000)) != pdTRUE) {
    return false;
  }
  const MeasurementSnapshot sample =
      meter_.poll(clock_.utcMs(), clock_.monotonicMs(), clock_.synchronized());
  xSemaphoreGive(meter_mutex_);
  if (sample.error != MeterError::None || !sample.valid) {
    return false;
  }
  raw_energy_wh = sample.raw_energy_wh;
  return true;
}

bool DataResetCoordinator::persistMeasurementPauseEvidence(
    data_reset::Record &record) {
  if (record.measurement_pause_evidenced) {
    return true;
  }
  const std::uint64_t observed_end = clock_.utcMs();
  record.measurement_pause_ended_utc_ms =
      std::max(record.measurement_pause_started_utc_ms, observed_end);
  char detail[256]{};
  const int written = std::snprintf(
      detail, sizeof(detail),
      "operation=%s generation=%llu start_utc_ms=%llu end_utc_ms=%llu",
      record.prepare.operation_id.c_str(),
      static_cast<unsigned long long>(record.prepare.target_generation),
      static_cast<unsigned long long>(
          record.measurement_pause_started_utc_ms),
      static_cast<unsigned long long>(record.measurement_pause_ended_utc_ms));
  if (written < 0 || static_cast<std::size_t>(written) >= sizeof(detail)) {
    record.measurement_pause_ended_utc_ms = 0U;
    return false;
  }
  const std::uint64_t expected_card_generation =
      record.card_generation > 0U
          ? record.card_generation
          : (record.prepare.expected_card_generation_set
                 ? record.prepare.expected_card_generation
                 : 0U);
  if (!storage_.appendEvent(
          "DATA_RESET_MEASUREMENT_PAUSED", "info", detail,
          record.measurement_pause_ended_utc_ms, config_.identity().boot_id,
          expected_card_generation,
          expected_card_generation > 0U ? record.prepare.device_id
                                        : std::string{})) {
    PM_LOG_WARN("RESET", "RESET_PAUSE_EVENT_DEFERRED",
                "operation=%s evidence=durable_reset_record",
                record.prepare.operation_id.c_str());
  }
  // The atomic reset record itself is the authoritative durable evidence.
  // The preserved event is supplemental and must never make reversible
  // cancellation depend on free SD capacity.
  record.measurement_pause_evidenced = true;
  return true;
}

bool DataResetCoordinator::prepareReceipt(data_reset::Record &record) {
  const std::string canonical =
      data_reset::buildPreparedReceiptCanonical(record);
  record.prepared_receipt_digest =
      receiptDigest(canonical, record.prepare.device_id);
  if (record.prepared_receipt_digest.size() != 64U) {
    return false;
  }
  record.prepared_receipt = canonical;
  return !record.prepared_receipt.empty();
}

std::string DataResetCoordinator::buildCommitReceipt(
    const data_reset::Record &record) const {
  const StorageHealth health = storage_.health();
  data_reset::CommitReceiptRuntime runtime;
  runtime.newest_syncable_sequence = health.newest_syncable_sequence;
  runtime.local_record_count = health.local_record_count;
  runtime.next_sequence = health.next_sequence;
  runtime.sequence_floor = health.sequence_floor;
  runtime.server_ack_sequence = config_.serverAckSequence();
  runtime.server_maximum_seen = config_.serverMaximumSeenSequence();
  return data_reset::buildCommitReceiptCanonical(record, runtime);
}

std::string DataResetCoordinator::receiptDigest(
    const std::string &canonical, const std::string &device_id) const {
  crypto::Key32 device_to_server{};
  crypto::Key32 server_to_device{};
  if (canonical.empty() ||
      !config_.directionalKeys(device_to_server, server_to_device)) {
    return {};
  }
  const crypto::Key32 receipt_key = crypto::hkdfSha256(
      device_to_server.data(), device_to_server.size(),
      reinterpret_cast<const std::uint8_t *>(device_id.data()),
      device_id.size(), kReceiptContext);
  const std::string digest = crypto::hmacSha256Hex(
      receipt_key.data(), receipt_key.size(), canonical);
  device_to_server.fill(0U);
  server_to_device.fill(0U);
  return digest;
}

std::string
DataResetCoordinator::statusJson(const data_reset::Record &record) const {
  const bool completion_pending_release =
      record.state == data_reset::State::Completed &&
      !completionVisible(record);
  const bool cancellation_pending_release =
      record.state == data_reset::State::Cancelled &&
      !cancellationVisible(record);
  JsonDocument response;
  response["protocol"] = data_reset::kProtocolVersion;
  response["operation_id"] = record.prepare.operation_id;
  response["device_id"] = record.prepare.device_id;
  response["target_generation"] = record.prepare.target_generation;
  response["state"] = completion_pending_release
                          ? "verified"
                          : (cancellation_pending_release
                                 ? "attention_required"
                                 : wireState(record));
  response["checkpoint"] =
      completion_pending_release
          ? "verified"
          : cancellation_pending_release
          ? "attention_required"
          : record.state == data_reset::State::Preparing
          ? "preparing"
          : (record.state == data_reset::State::Prepared
                 ? "prepared"
                 : (record.state == data_reset::State::Cancelled
                        ? "cancelled"
                        : (record.state == data_reset::State::AttentionRequired
                               ? "attention_required"
                               : data_reset::checkpointName(record.checkpoint))));
  if (!record.failure_code.empty()) {
    response["failure_code"] = record.failure_code;
  } else if (completion_pending_release || cancellation_pending_release) {
    response["failure_code"] = "data_reset_gate_release_pending";
  } else {
    response["failure_code"] = nullptr;
  }
  if (!record.prepared_receipt.empty()) {
    response["prepared_receipt"] = record.prepared_receipt;
    response["prepared_receipt_digest"] = record.prepared_receipt_digest;
    response["configuration_preservation_digest_before"] =
        record.configuration_digest_before;
  }
  if (data_reset::commitPointReached(record.checkpoint) &&
      !completion_pending_release) {
    const std::string receipt =
        record.state == data_reset::State::Completed &&
                !record.completion_receipt.empty()
            ? record.completion_receipt
            : buildCommitReceipt(record);
    const std::string digest = receiptDigest(receipt, record.prepare.device_id);
    if (!receipt.empty() && !digest.empty()) {
      response["commit_receipt"] = receipt;
      response["commit_receipt_digest"] = digest;
    }
  }
  if (!record.configuration_digest_after.empty()) {
    response["configuration_preservation_digest_after"] =
        record.configuration_digest_after;
  }
  return serializeCompact(response);
}

void DataResetCoordinator::failBeforeCommit(const char *code) {
  if (!has_record_ || record_.state != data_reset::State::Preparing) {
    return;
  }
  if (record_.failure_code == code) {
    return;
  }
  data_reset::Record failed = record_;
  failed.failure_code = code;
  saveRecord(failed);
  PM_LOG_WARN("RESET", "RESET_PREPARE_WAITING", "reason=%s retryable=true",
              code);
}

void DataResetCoordinator::requireAttention(const char *code) {
  if (!has_record_ || !data_reset::commitPointReached(record_.checkpoint)) {
    return;
  }
  data_reset::Record failed = record_;
  failed.state = data_reset::State::AttentionRequired;
  failed.failure_code = code;
  saveRecord(failed);
  applyGates(true);
  PM_LOG_ERROR("RESET", "RESET_ATTENTION_REQUIRED",
               "checkpoint=%s reason=%s reading_gate=true",
               data_reset::checkpointName(record_.checkpoint), code);
}

bool DataResetCoordinator::sameCard(const data_reset::Record &record,
                                    const StorageHealth &health) const {
  return health.present && health.mounted && health.writable &&
         health.card_identity_status == record.sd_status &&
         resetCardBindingMatches(
             health.card_generation, health.card_device_id,
             record.card_generation, record.prepare.device_id);
}

bool DataResetCoordinator::active() const {
  // ConfigService exposes the cross-task atomic admission gate. It becomes
  // true before prepare returns 202, including before the durable record is
  // written by OtaMaintenanceTask.
  if (!gatesReleased()) {
    return true;
  }
  if (!lock(pdMS_TO_TICKS(25))) {
    return true;
  }
  const bool result = has_record_ && data_reset::readingGateRequired(
                                         record_.state, record_.checkpoint);
  unlock();
  return result;
}

std::uint64_t DataResetCoordinator::requiredSequenceFloor() const {
  std::uint64_t result = config_.dataResetBoundary();
  if (has_record_ && record_.approved_boundary_set) {
    result = std::max(result, record_.approved_boundary);
  }
  return result;
}

std::string DataResetCoordinator::heartbeatState() const {
  if (!lock(pdMS_TO_TICKS(25))) {
    return "attention_required";
  }
  const bool gate_release_pending = !gatesReleased();
  const std::string result =
      has_record_ ? (record_.state == data_reset::State::Completed &&
                             gate_release_pending
                         ? "verified"
                         : (record_.state == data_reset::State::Cancelled &&
                                    gate_release_pending
                                ? "attention_required"
                                : wireState(record_)))
                  : (gate_release_pending ? "attention_required" : "none");
  unlock();
  return result;
}

DataResetHeartbeatSnapshot DataResetCoordinator::heartbeatSnapshot() const {
  DataResetHeartbeatSnapshot result;
  result.reset_boundary = config_.dataResetBoundary();
  if (!lock(pdMS_TO_TICKS(25))) {
    result.state = "attention_required";
    result.checkpoint = "attention_required";
    result.failure_code = "data_reset_state_lock_timeout";
    result.reset_required = true;
    return result;
  }
  if (has_record_) {
    const bool completion_pending_release =
        record_.state == data_reset::State::Completed && !gatesReleased();
    const bool cancellation_pending_release =
        record_.state == data_reset::State::Cancelled && !gatesReleased();
    result.state = completion_pending_release
                       ? "verified"
                       : (cancellation_pending_release
                              ? "attention_required"
                              : wireState(record_));
    result.checkpoint =
        completion_pending_release
            ? "verified"
            : cancellation_pending_release
            ? "attention_required"
            : record_.state == data_reset::State::Preparing
            ? "preparing"
            : (record_.state == data_reset::State::Prepared
                   ? "prepared"
                   : (record_.state == data_reset::State::Cancelled
                          ? "cancelled"
                          : (record_.state ==
                                     data_reset::State::AttentionRequired
                                 ? "attention_required"
                                 : data_reset::checkpointName(
                                       record_.checkpoint))));
    result.operation_id = record_.prepare.operation_id;
    result.failure_code = !record_.failure_code.empty()
                              ? record_.failure_code
                              : (completion_pending_release ||
                                         cancellation_pending_release
                                     ? "data_reset_gate_release_pending"
                                     : "");
    result.target_generation = record_.prepare.target_generation;
    result.reset_boundary =
        record_.approved_boundary_set ? record_.approved_boundary
                                      : result.reset_boundary;
    result.reset_required = data_reset::readingGateRequired(
                                record_.state, record_.checkpoint) ||
                            !gatesReleased();
  } else if (!gatesReleased()) {
    result.state = "attention_required";
    result.checkpoint = "attention_required";
    result.failure_code = "data_reset_gate_state_invalid";
    result.reset_required = true;
  }
  unlock();
  return result;
}

} // namespace pm
