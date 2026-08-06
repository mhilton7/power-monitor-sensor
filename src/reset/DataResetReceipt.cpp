#include "reset/DataResetReceipt.h"

#include <ArduinoJson.h>

namespace pm {
namespace data_reset {
namespace {

std::uint64_t backlog(const std::uint64_t newest,
                      const std::uint64_t acknowledgement) {
  return newest > acknowledgement ? newest - acknowledgement : 0U;
}

bool checkpointAtLeast(const Checkpoint current, const Checkpoint expected) {
  return static_cast<std::uint8_t>(current) >=
         static_cast<std::uint8_t>(expected);
}

const char *wireState(const Record &record) {
  if (record.state == State::Committing) {
    return checkpointName(record.checkpoint);
  }
  if (record.state == State::AttentionRequired) {
    return "attention_required";
  }
  return stateName(record.state);
}

std::string compact(JsonDocument &document) {
  std::string output;
  serializeJson(document, output);
  return output;
}

} // namespace

std::string buildPreparedReceiptCanonical(const Record &record) {
  const BoundaryResult boundary = highestTrustedBoundary(boundaryInputs(record));
  if (!boundary.valid) {
    return {};
  }
  JsonDocument receipt;
  receipt["backlog_after"] = backlog(record.newest_syncable_sequence,
                                     record.sensor_server_acknowledgement);
  receipt["backlog_before"] = backlog(record.newest_syncable_sequence,
                                      record.sensor_server_acknowledgement);
  receipt["boot_id"] = record.prepared_boot_id;
  receipt["card_generation"] = std::to_string(record.card_generation);
  receipt["checkpoint"] = "prepared";
  receipt["configuration_preservation_digest_before"] =
      record.configuration_digest_before;
  receipt["configuration_preserved"] = true;
  receipt["device_id"] = record.prepare.device_id;
  receipt["firmware_build_hash"] = record.prepared_build_hash;
  receipt["firmware_version"] = record.prepared_firmware_version;
  receipt["local_records_after"] = record.local_record_count;
  receipt["local_records_before"] = record.local_record_count;
  receipt["measurement_pause_started_utc_ms"] =
      record.measurement_pause_started_utc_ms;
  receipt["newest_stored_sequence"] = record.newest_stored_sequence;
  receipt["newest_syncable_sequence"] = record.newest_syncable_sequence;
  receipt["next_sequence"] = record.next_sequence;
  receipt["operation_id"] = record.prepare.operation_id;
  receipt["plan_digest"] = record.prepare.plan_digest;
  receipt["plan_revision"] = record.prepare.plan_revision;
  if (record.prepare_drain_sequence_range_set) {
    receipt["prepare_drain_first_sequence"] =
        record.prepare_drain_first_sequence;
    receipt["prepare_drain_last_sequence"] =
        record.prepare_drain_last_sequence;
  } else {
    receipt["prepare_drain_first_sequence"] = nullptr;
    receipt["prepare_drain_last_sequence"] = nullptr;
  }
  receipt["prepare_drain_records_added"] =
      record.prepare_drain_records_added;
  receipt["prepare_drain_syncable_records_added"] =
      record.prepare_drain_syncable_records_added;
  receipt["prepared_pzem_energy_wh"] = record.prepared_pzem_energy_wh;
  receipt["protocol"] = kProtocolVersion;
  receipt["pzem_baseline_captured"] = true;
  receipt["reset_boundary"] = boundary.boundary;
  receipt["sd_status"] = record.sd_status;
  receipt["sequence_floor"] = record.local_sequence_floor;
  receipt["server_ack_sequence"] = record.sensor_server_acknowledgement;
  receipt["server_maximum_seen"] = record.sensor_maximum_seen;
  receipt["software_energy_baseline_before_wh"] =
      record.software_energy_baseline_before_wh;
  receipt["state"] = "prepared";
  receipt["target_generation"] = record.prepare.target_generation;
  return compact(receipt);
}

std::string buildCommitReceiptCanonical(
    const Record &record, const CommitReceiptRuntime &runtime) {
  const bool cleanup_checkpoint =
      checkpointAtLeast(record.checkpoint, Checkpoint::ReadingsCleared);
  const bool completion_verified =
      checkpointAtLeast(record.checkpoint, Checkpoint::Verified);
  JsonDocument receipt;
  receipt["backlog_after"] =
      completion_verified
          ? std::uint64_t{0U}
          : backlog(runtime.newest_syncable_sequence,
                    runtime.server_ack_sequence);
  receipt["backlog_before"] = backlog(record.newest_syncable_sequence,
                                      record.sensor_server_acknowledgement);
  receipt["boot_id"] = record.prepared_boot_id;
  receipt["card_generation"] = std::to_string(record.card_generation);
  receipt["checkpoint"] = checkpointName(record.checkpoint);
  receipt["commit_pzem_energy_wh"] = record.commit_pzem_energy_wh;
  if (!record.configuration_digest_after.empty()) {
    receipt["configuration_preservation_digest_after"] =
        record.configuration_digest_after;
  }
  receipt["configuration_preservation_digest_before"] =
      record.configuration_digest_before;
  receipt["configuration_preserved"] = completion_verified;
  receipt["device_id"] = record.prepare.device_id;
  receipt["exports_cleared"] = cleanup_checkpoint;
  receipt["firmware_build_hash"] = record.prepared_build_hash;
  receipt["firmware_version"] = record.prepared_firmware_version;
  receipt["indexes_rebuilt"] = completion_verified;
  receipt["local_records_after"] =
      completion_verified ? std::uint64_t{0U} : runtime.local_record_count;
  receipt["local_records_before"] = record.local_record_count;
  receipt["measurement_pause_ended_utc_ms"] =
      record.measurement_pause_ended_utc_ms;
  receipt["measurement_pause_evidenced"] =
      record.measurement_pause_evidenced;
  receipt["measurement_pause_started_utc_ms"] =
      record.measurement_pause_started_utc_ms;
  receipt["next_sequence"] = runtime.next_sequence;
  receipt["operation_id"] = record.prepare.operation_id;
  receipt["plan_digest"] = record.prepare.plan_digest;
  receipt["plan_revision"] = record.prepare.plan_revision;
  if (record.prepare_drain_sequence_range_set) {
    receipt["prepare_drain_first_sequence"] =
        record.prepare_drain_first_sequence;
    receipt["prepare_drain_last_sequence"] =
        record.prepare_drain_last_sequence;
  } else {
    receipt["prepare_drain_first_sequence"] = nullptr;
    receipt["prepare_drain_last_sequence"] = nullptr;
  }
  receipt["prepare_drain_records_added"] =
      record.prepare_drain_records_added;
  receipt["prepare_drain_syncable_records_added"] =
      record.prepare_drain_syncable_records_added;
  receipt["prepared_pzem_energy_wh"] = record.prepared_pzem_energy_wh;
  receipt["prepared_receipt_digest"] = record.prepared_receipt_digest;
  receipt["protocol"] = kProtocolVersion;
  receipt["pzem_baseline_captured"] = record.commit_energy_baseline_set;
  receipt["queues_cleared"] = cleanup_checkpoint;
  receipt["records_deleted"] = record.readings_deleted;
  receipt["reset_boundary"] = record.approved_boundary;
  receipt["sequence_floor"] = runtime.sequence_floor;
  receipt["server_ack_sequence"] = runtime.server_ack_sequence;
  receipt["server_maximum_seen"] = runtime.server_maximum_seen;
  receipt["state"] = wireState(record);
  receipt["target_generation"] = record.prepare.target_generation;
  if (completion_verified) {
    receipt["verified_pzem_energy_wh"] = record.verified_pzem_energy_wh;
  }
  return compact(receipt);
}

} // namespace data_reset
} // namespace pm
