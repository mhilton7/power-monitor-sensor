#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "api/CompactUiStatus.h"
#include "config/AtomicConfigStore.h"
#include "core/MemoryPressurePolicy.h"
#include "diagnostics/DiagnosticCore.h"
#include "network/ServerSyncPolicy.h"
#include "ota/OtaManifestV2.h"
#include "ota/OtaUpdatePolicy.h"
#include "storage/StoragePolicy.h"

namespace pm {
namespace randomized_reliability {

struct Result {
  bool passed{true};
  std::uint32_t sequences{0U};
  std::uint64_t events{0U};
  std::string failure;
};

// A small deterministic generator keeps this test reproducible on Windows and
// Linux without depending on a standard-library random implementation.
class Generator {
public:
  explicit Generator(const std::uint64_t seed) : state_(seed) {}

  std::uint32_t next() {
    state_ ^= state_ >> 12U;
    state_ ^= state_ << 25U;
    state_ ^= state_ >> 27U;
    return static_cast<std::uint32_t>((state_ * 0x2545F4914F6CDD1DULL) >> 32U);
  }

  std::uint32_t bounded(const std::uint32_t limit) {
    return limit == 0U ? 0U : next() % limit;
  }

  bool chance(const std::uint32_t numerator, const std::uint32_t denominator) {
    return bounded(denominator) < numerator;
  }

private:
  std::uint64_t state_;
};

class FaultBlobStore final : public persistence::BlobStore {
public:
  bool read(const char *key, std::vector<std::uint8_t> &value) override {
    const auto found = values_.find(key);
    if (found == values_.end()) {
      value.clear();
      return false;
    }
    value = found->second;
    return true;
  }

  bool write(const char *key, const std::uint8_t *value,
             const std::size_t length) override {
    if (writes_before_failure_ == 0) {
      writes_before_failure_ = kNoFailure;
      return false;
    }
    if (writes_before_failure_ != kNoFailure) {
      --writes_before_failure_;
    }
    values_[key] = std::vector<std::uint8_t>(value, value + length);
    return true;
  }

  bool erase(const char *key) override {
    values_.erase(key);
    return true;
  }

  bool exists(const char *key) override {
    return values_.find(key) != values_.end();
  }

  void failWriteAfter(const std::uint32_t successful_writes) {
    writes_before_failure_ = static_cast<std::int32_t>(successful_writes);
  }

private:
  static constexpr std::int32_t kNoFailure = -1;
  std::map<std::string, std::vector<std::uint8_t>> values_;
  std::int32_t writes_before_failure_{kNoFailure};
};

struct Coverage {
  std::uint32_t network_failures{0U};
  std::uint32_t persistence_failures{0U};
  std::uint32_t reboots{0U};
  std::uint32_t duplicate_or_stale_reports{0U};
  std::uint32_t heartbeats{0U};
  std::uint32_t reading_batches{0U};
  std::uint32_t rollbacks{0U};
  std::uint32_t config_changes{0U};
  std::uint32_t web_requests{0U};
  std::uint32_t cleanup_attempts{0U};
};

struct Reading {
  std::uint64_t sequence{0U};
  std::uint64_t measured_at{0U};
};

inline bool allowedCollapsedOtaTransition(const ota_v2::State current,
                                          const ota_v2::State next) {
  using ota_v2::State;
  switch (current) {
  case State::ManifestCheck:
    return next == State::ManifestAuthenticated ||
           next == State::ManifestRejected;
  case State::ManifestAuthenticated:
    return next == State::Downloading;
  case State::Downloading:
    return next == State::PartitionWritten || next == State::Failed;
  case State::PartitionWritten:
    return next == State::Rebooting;
  case State::Rebooting:
    return next == State::PostBootValidation;
  case State::PostBootValidation:
    return next == State::Completed || next == State::RolledBack;
  default:
    return false;
  }
}

class SequenceModel {
public:
  SequenceModel(Result &result, Coverage &coverage, Generator &random,
                const std::uint32_t sequence_index)
      : result_(result), coverage_(coverage), random_(random),
        sequence_index_(sequence_index) {}

  bool begin() {
    persistence::CommitResult committed;
    expected_config_ = bytes("home=single;poll=15;generation=0");
    return require(persistence::commit(config_store_, configKeys(),
                                       expected_config_, committed),
                   "initial atomic configuration commit failed") &&
           verifyConfiguration();
  }

  bool appendReading() {
    ++result_.events;
    readings_.push_back({next_sequence_, now_ms_});
    ++next_sequence_;
    now_ms_ += 15'000U;
    return require(next_sequence_ > readings_.back().sequence,
                   "sequence did not advance after durable reading");
  }

  bool duplicateReading() {
    ++result_.events;
    ++coverage_.duplicate_or_stale_reports;
    const std::size_t before = readings_.size();
    const std::uint64_t duplicate =
        readings_.empty() ? acknowledged_ : readings_.front().sequence;
    const bool already_present =
        duplicate <= acknowledged_ ||
        std::any_of(readings_.begin(), readings_.end(),
                    [duplicate](const Reading &value) {
                      return value.sequence == duplicate;
                    });
    if (!already_present) {
      readings_.push_back({duplicate, now_ms_});
    }
    return require(readings_.size() == before,
                   "duplicate reading was inserted a second time");
  }

  bool heartbeat(const int status) {
    ++result_.events;
    ++coverage_.heartbeats;
    if (status < 0 || status >= 500) {
      ++coverage_.network_failures;
    }
    const bool transaction_ok = transportTransaction(status);
    return require(transaction_ok, "heartbeat transaction leaked ownership");
  }

  bool readingBatch(const int status, const bool force_stale = false) {
    ++result_.events;
    ++coverage_.reading_batches;
    if (status < 0 || status >= 500) {
      ++coverage_.network_failures;
    }
    if (!transportTransaction(status)) {
      return require(false, "reading batch transaction leaked ownership");
    }
    if (sync_policy::classifyHttpStatus(status) !=
        sync_policy::HttpDisposition::Success) {
      return true;
    }

    const std::uint64_t newest = newestStoredSequence();
    std::uint64_t reported = acknowledged_;
    if (force_stale && acknowledged_ != 0U) {
      reported = acknowledged_ - 1U;
      ++coverage_.duplicate_or_stale_reports;
    } else {
      switch (random_.bounded(4U)) {
      case 0U:
        reported = acknowledged_;
        break;
      case 1U:
        reported =
            newest > acknowledged_
                ? acknowledged_ + random_.bounded(static_cast<std::uint32_t>(
                                      newest - acknowledged_ + 1U))
                : acknowledged_;
        break;
      case 2U:
        reported = newest;
        break;
      default:
        // Exercises replacement-card/server-cursor reconciliation.
        reported = newest + 1U + random_.bounded(3U);
        break;
      }
    }

    const auto disposition =
        sync_policy::classifyAcknowledgement(acknowledged_, newest, reported);
    if (force_stale && acknowledged_ != 0U) {
      return require(disposition ==
                         sync_policy::AcknowledgementDisposition::Invalid,
                     "stale acknowledgement was not rejected");
    }
    if (disposition == sync_policy::AcknowledgementDisposition::Invalid) {
      return true;
    }
    if (disposition != sync_policy::AcknowledgementDisposition::Current) {
      acknowledged_ = reported;
    }
    if (disposition ==
        sync_policy::AcknowledgementDisposition::AdvanceSequenceFloor) {
      const std::uint64_t floor = sync_policy::requiredSequenceFloor(
          newest, next_sequence_ == 0U ? 0U : next_sequence_ - 1U,
          acknowledged_, acknowledged_, acknowledged_);
      if (floor == std::numeric_limits<std::uint64_t>::max()) {
        return require(false, "sequence floor exhausted");
      }
      next_sequence_ = std::max(next_sequence_, floor + 1U);
    }
    return true;
  }

  bool cleanup() {
    ++result_.events;
    ++coverage_.cleanup_attempts;
    std::vector<std::uint64_t> protected_unacknowledged;
    std::vector<SegmentMetadata> segments;
    segments.reserve(readings_.size());
    for (const Reading &reading : readings_) {
      if (reading.sequence > acknowledged_) {
        protected_unacknowledged.push_back(reading.sequence);
      }
      SegmentMetadata segment;
      segment.record_path = "records/" + std::to_string(reading.sequence);
      segment.index_path = "index/" + std::to_string(reading.sequence);
      segment.first_sequence = reading.sequence;
      segment.last_sequence = reading.sequence;
      segment.first_utc_ms = reading.measured_at;
      segment.last_utc_ms = reading.measured_at;
      segment.payload_bytes = 512U;
      segment.index_bytes = 64U;
      segment.record_count = 1U;
      segment.all_times_trusted = true;
      segment.complete = true;
      segment.index_valid = true;
      segment.closed = true;
      segments.push_back(std::move(segment));
    }
    RetentionContext context;
    context.mode = RetentionMode::ContinuousProtected;
    context.emergency_pressure = true;
    context.acknowledgement_verified = true;
    context.server_ack_sequence = acknowledged_;
    context.retention_cutoff_utc_ms = now_ms_ + 1U;
    context.minimum_history_cutoff_utc_ms = now_ms_ + 1U;
    const CleanupPlan plan = buildCleanupPlan(segments, context, 1U, 4096U);
    std::vector<std::uint64_t> deletions;
    for (const std::size_t index : plan.candidate_indexes) {
      if (!require(index < segments.size(),
                   "cleanup selected an out-of-range segment")) {
        return false;
      }
      const std::uint64_t selected = segments[index].last_sequence;
      if (!require(selected <= acknowledged_,
                   "cleanup selected an unacknowledged reading")) {
        return false;
      }
      deletions.push_back(selected);
    }
    readings_.erase(
        std::remove_if(readings_.begin(), readings_.end(),
                       [&deletions](const Reading &reading) {
                         return std::find(deletions.begin(), deletions.end(),
                                          reading.sequence) != deletions.end();
                       }),
        readings_.end());
    return require(std::all_of(protected_unacknowledged.begin(),
                               protected_unacknowledged.end(),
                               [this](const std::uint64_t sequence) {
                                 return std::any_of(
                                     readings_.begin(), readings_.end(),
                                     [sequence](const Reading &reading) {
                                       return reading.sequence == sequence;
                                     });
                               }),
                   "cleanup deleted an unacknowledged reading");
  }

  bool changeConfiguration(const bool fail_persistence) {
    ++result_.events;
    ++coverage_.config_changes;
    const std::vector<std::uint8_t> candidate =
        bytes("home=single;poll=" + std::to_string(5U + random_.bounded(56U)) +
              ";generation=" + std::to_string(config_generation_ + 1U));
    if (fail_persistence) {
      ++coverage_.persistence_failures;
      config_store_.failWriteAfter(random_.bounded(2U));
    }
    persistence::CommitResult committed;
    const bool success =
        persistence::commit(config_store_, configKeys(), candidate, committed);
    if (success) {
      expected_config_ = candidate;
      ++config_generation_;
    } else if (!fail_persistence) {
      return require(false, "configuration commit failed without injection");
    }
    return verifyConfiguration();
  }

  bool reboot() {
    ++result_.events;
    ++coverage_.reboots;
    memory_context_ = MemoryOperationContext::Idle;
    sync_in_progress_ = false;
    if (single_flight_.active()) {
      single_flight_.finish();
    }
    while (single_flight_.pending()) {
      single_flight_.consumePending();
    }
    return verifyConfiguration() &&
           require(next_sequence_ > acknowledged_ ||
                       newestStoredSequence() >= acknowledged_,
                   "reboot regressed both durable and acknowledged cursors");
  }

  bool webRequest() {
    ++result_.events;
    ++coverage_.web_requests;
    static constexpr char kSecret[] = "state-machine-secret-7f9c";
    char redacted[160]{};
    diag::redactSensitiveAssignments(
        "status=ready password=state-machine-secret-7f9c token=private-token",
        redacted, sizeof(redacted));

    CompactUiStatusSnapshot snapshot;
    copyCompactText(snapshot.friendly_name, "Randomized sensor");
    copyCompactText(snapshot.ip_address, "192.168.0.26");
    copyCompactText(snapshot.server_now, "2026-08-03T20:00:00Z");
    copyCompactText(snapshot.last_safe_error, redacted);
    copyCompactText(snapshot.last_attempt_result, "success");
    snapshot.uptime_seconds = now_ms_ / 1000U;
    snapshot.current_monotonic_ms = now_ms_;
    snapshot.last_heartbeat_success_monotonic_ms =
        now_ms_ > 1000U ? now_ms_ - 1000U : 1U;
    snapshot.newest_sequence = newestStoredSequence();
    snapshot.acknowledged_sequence = acknowledged_;
    snapshot.backlog = backlog();
    snapshot.wifi_connected = true;
    snapshot.authenticated = true;
    snapshot.server_reachable = true;
    snapshot.storage_writable = true;
    snapshot.meter_healthy = true;
    snapshot.heap.free_internal_bytes = 80U * 1024U;
    snapshot.heap.largest_internal_block_bytes = 48U * 1024U;
    snapshot.heap.integrity_ok = true;
    snapshot.memory.state = MemoryPressureState::Normal;
    snapshot.server_state = ServerFreshnessState::Live;
    const CompactUiBuildMetadata metadata{
        "1.0.16",       "0123456789ab", "2026-08-03T20:00:00Z",
        "native-tests", "index",        "app",
        "style"};
    std::array<char, 8192U> output{};
    const auto serialized = serializeCompactUiStatus(
        snapshot, metadata, output.data(), output.size());
    const std::string body(output.data(), serialized.bytes);
    return require(serialized.success,
                   "bounded Web UI status serialization failed") &&
           require(body.find(kSecret) == std::string::npos &&
                       body.find("private-token") == std::string::npos,
                   "Web UI status exposed a secret") &&
           require(body.find("[REDACTED]") != std::string::npos,
                   "Web UI status omitted the redaction marker");
  }

  bool otaAttempt(const bool authenticated, const std::uint32_t outcome) {
    ++result_.events;
    const std::string source_version = "1.0.15";
    const std::string source_hash(64U, 'a');
    const std::string target_version = "1.0.16";
    const std::string target_hash(64U, 'b');
    const std::string target_sha(64U, 'c');

    ota_v2::Manifest manifest;
    manifest.available = true;
    manifest.schema_version = ota_v2::kSchemaVersion;
    manifest.protocol_version = "pm-protocol/1.0.0";
    manifest.deployment_id = "123e4567-e89b-12d3-a456-426614174000";
    manifest.release_id = "223e4567-e89b-12d3-a456-426614174000";
    manifest.device_id = deviceId();
    manifest.version = target_version;
    manifest.project_name = ota_v2::kProjectName;
    manifest.hardware_target = "esp32-s3-n16r8";
    manifest.protocol_min = "pm-protocol/1.0.0";
    manifest.protocol_max = "pm-protocol/1.0.0";
    manifest.size_bytes = 4096U;
    manifest.sha256 = target_sha;
    manifest.build_hash = target_hash;
    manifest.not_before = "2026-01-01T00:00:00Z";
    manifest.expires_at = "2030-01-01T00:00:00Z";
    manifest.attempt = 1U;
    manifest.hmac_algorithm = ota_v2::kHmacAlgorithm;
    manifest.hmac_key_context = ota_v2::kHmacKeyContext;
    manifest.manifest_hmac = "not-used-by-policy-test";
    manifest.download_path = "/api/v1/device-firmware/image";

    ota_v2::PolicyContext policy;
    policy.device_id = deviceId();
    policy.current_version = source_version;
    policy.current_protocol = "pm-protocol/1.0.0";
    policy.hardware_target = "esp32-s3-n16r8";
    policy.now_unix_seconds = 1'800'000'000LL;
    policy.partition_size_bytes = 6U * 1024U * 1024U;
    std::string error;
    const bool policy_valid = ota_v2::validatePolicy(manifest, policy, error);
    if (!require(policy_valid, "valid OTA policy fixture was rejected")) {
      return false;
    }

    bool image_accepted = false;
    ota_v2::State final_state = ota_v2::State::ManifestCheck;
    std::uint32_t transition_count = 0U;
    const auto advance = [this, &final_state,
                          &transition_count](const ota_v2::State next) {
      if (!require(allowedCollapsedOtaTransition(final_state, next),
                   "OTA entered an impossible transition")) {
        return false;
      }
      final_state = next;
      ++transition_count;
      return true;
    };
    if (authenticated) {
      if (!advance(ota_v2::State::ManifestAuthenticated) ||
          !advance(ota_v2::State::Downloading)) {
        return false;
      }
      ota_v2::StreamTracker stream(manifest.size_bytes);
      const bool first_chunk = stream.accept(1024U);
      bool stream_complete = false;
      switch (outcome % 7U) {
      case 0U:
      case 6U:
        stream_complete = first_chunk && stream.accept(1024U) &&
                          stream.accept(2048U) && stream.finish(true);
        break;
      case 1U:
        stream.timeout();
        break;
      case 2U:
        stream.connectionReset();
        break;
      case 3U:
        stream_complete = stream.finish(true);
        break;
      case 4U:
        stream_complete =
            first_chunk && stream.accept(3072U) && stream.finish(false);
        break;
      default:
        (void)first_chunk;
        (void)stream.accept(1024U, false);
        stream_complete = false;
        break;
      }
      if (stream_complete) {
        ota_v2::PartitionVerificationEvidence partition;
        partition.expected_present = true;
        partition.selected_present = true;
        partition.running_present = true;
        partition.expected_is_ota_app = true;
        partition.selected_not_running = true;
        partition.selected_state_available = true;
        partition.selected_state_new = true;
        partition.descriptor_available = true;
        partition.expected_type = 0U;
        partition.selected_type = 0U;
        partition.expected_subtype = 16U;
        partition.selected_subtype = 16U;
        partition.expected_address = 0x620000U;
        partition.selected_address = 0x620000U;
        partition.expected_size = 6U * 1024U * 1024U;
        partition.selected_size = partition.expected_size;
        partition.expected_label = "ota_1";
        partition.selected_label = "ota_1";
        partition.project_name = ota_v2::kProjectName;
        partition.version = target_version;
        partition.build_hash = target_hash;
        if (outcome == 6U) {
          partition.selected_label = "ota_corrupt";
        }
        image_accepted = ota_v2::validateSelectedPartition(
            partition, ota_v2::kProjectName, target_version, target_hash,
            manifest.size_bytes, error);
      }

      if (image_accepted) {
        if (!advance(ota_v2::State::PartitionWritten) ||
            !advance(ota_v2::State::Rebooting) ||
            !advance(ota_v2::State::PostBootValidation)) {
          return false;
        }
        ota_v2::PostBootHealthEvidence evidence;
        evidence.core_primitives_ready = true;
        evidence.heap_integrity_ok = true;
        evidence.meter_task_progressed = true;
        evidence.aggregation_task_progressed = true;
        evidence.network_task_progressed = true;
        evidence.sync_task_progressed = true;
        evidence.observation_window_expired = true;
        evidence.storage_available = true;
        evidence.meter_hardware_available = true;
        evidence.network_initialized = true;
        evidence.wifi_connected = true;
        evidence.time_trusted = true;
        evidence.server_reachable = true;
        if (outcome == 0U && sequence_index_ % 4U == 0U) {
          evidence.heap_integrity_ok = false;
        }
        const auto health = ota_v2::classifyPostBootHealth(evidence);
        const auto action = ota_v2::classifyPostBoot(
            true, health, target_version, target_hash, target_version,
            target_hash, source_version, source_hash, true);
        if (action == ota_v2::PostBootAction::Validate) {
          if (!advance(ota_v2::State::Completed)) {
            return false;
          }
        } else {
          if (!require(action == ota_v2::PostBootAction::Rollback,
                       "post-boot policy produced an impossible action")) {
            return false;
          }
          ++coverage_.rollbacks;
          if (!advance(ota_v2::State::RolledBack)) {
            return false;
          }
        }
      } else if (!advance(ota_v2::State::Failed)) {
        return false;
      }
    } else if (!advance(ota_v2::State::ManifestRejected)) {
      return false;
    }

    if (!require(authenticated || !image_accepted,
                 "unverified OTA image was accepted") ||
        !require(transition_count <= 8U,
                 "OTA attempt exceeded its bounded transition budget") ||
        !require(!authenticated || ota_v2::terminalState(final_state),
                 "authenticated OTA attempt did not terminalize")) {
      return false;
    }

    ota_v2::RecoveryRecord recovery;
    recovery.deployment_id = manifest.deployment_id;
    recovery.release_id = manifest.release_id;
    recovery.target_version = target_version;
    recovery.target_sha256 = target_sha;
    recovery.target_build_hash = target_hash;
    recovery.previous_version = source_version;
    recovery.previous_build_hash = source_hash;
    recovery.image_size = manifest.size_bytes;
    recovery.bytes_received = image_accepted ? manifest.size_bytes : 1024U;
    recovery.progress_percent = image_accepted ? 100U : 25U;
    recovery.attempt = 1U;
    recovery.state = final_state;
    recovery.last_report_state =
        final_state == ota_v2::State::Completed
            ? "validated"
            : (final_state == ota_v2::State::RolledBack ? "rolled_back"
                                                        : "failed");
    recovery.failure_code =
        final_state == ota_v2::State::Completed ? "" : "injected_failure";
    recovery.pending_reboot = false;
    ota_v2::RecoveryRecord restored;
    const std::string serialized = ota_v2::serializeRecovery(recovery);
    return require(!serialized.empty() &&
                       ota_v2::parseRecovery(serialized, restored) &&
                       ota_v2::recoveryRecordsEqual(recovery, restored),
                   "OTA recovery record did not survive persistence") &&
           require(restored.previous_version == source_version &&
                       restored.previous_build_hash == source_hash &&
                       restored.target_version == target_version &&
                       restored.target_build_hash == target_hash,
                   "OTA recovery changed source or target identity") &&
           verifyReportProgress(final_state);
  }

  bool checkInvariants() {
    return require(!single_flight_.active() && !single_flight_.pending(),
                   "single-flight transaction remained latched") &&
           require(!sync_in_progress_, "sync_in_progress remained latched") &&
           require(memory_context_ == MemoryOperationContext::Idle,
                   "high-memory owner was not released") &&
           verifyConfiguration() &&
           require(next_sequence_ > newestStoredSequence(),
                   "next sequence no longer exceeds durable history") &&
           require(std::all_of(readings_.begin(), readings_.end(),
                               [this](const Reading &reading) {
                                 return reading.sequence < next_sequence_;
                               }),
                   "durable history contains a future sequence");
  }

  bool finish() {
    // Force one successful final reconciliation. This proves backlog progress
    // is bounded even when the random body ended on transport failures.
    if (!readings_.empty()) {
      const std::uint64_t newest = newestStoredSequence();
      const auto disposition =
          sync_policy::classifyAcknowledgement(acknowledged_, newest, newest);
      if (disposition != sync_policy::AcknowledgementDisposition::Invalid &&
          disposition != sync_policy::AcknowledgementDisposition::Current) {
        acknowledged_ = newest;
      }
    }
    return cleanup() &&
           require(backlog() == 0U,
                   "backlog failed to synchronize by sequence end") &&
           checkInvariants();
  }

private:
  static const persistence::SlotKeys &configKeys() {
    static const persistence::SlotKeys keys{"random_cfg_a", "random_cfg_b",
                                            "random_cfg_active"};
    return keys;
  }

  static const char *deviceId() {
    return "323e4567-e89b-12d3-a456-426614174000";
  }

  static std::vector<std::uint8_t> bytes(const std::string &value) {
    return {value.begin(), value.end()};
  }

  bool require(const bool condition, const char *message) {
    if (!condition && result_.passed) {
      result_.passed = false;
      result_.failure =
          "sequence " + std::to_string(sequence_index_) + ": " + message;
    }
    return condition;
  }

  bool verifyConfiguration() {
    persistence::LoadResult loaded;
    return require(
        persistence::loadActive(config_store_, configKeys(), loaded) &&
            loaded.payload == expected_config_,
        "active configuration was not preserved");
  }

  bool transportTransaction(const int status) {
    if (single_flight_.queue() != sync_policy::QueueResult::Queued ||
        !single_flight_.consumePending() || !single_flight_.tryBegin()) {
      return false;
    }
    sync_in_progress_ = true;
    memory_context_ = MemoryOperationContext::TlsPreparing;
    if (!memoryOperationTransitionAllowed(memory_context_,
                                          MemoryOperationContext::TlsActive)) {
      return false;
    }
    memory_context_ = MemoryOperationContext::TlsActive;
    memory_policy_.update(24U * 1024U, 12U * 1024U, now_ms_, memory_context_);
    if (random_.chance(1U, 4U)) {
      if (single_flight_.queue() != sync_policy::QueueResult::Queued ||
          single_flight_.queue() != sync_policy::QueueResult::Coalesced) {
        return false;
      }
    }
    (void)sync_policy::classifyHttpStatus(status);
    memory_context_ = MemoryOperationContext::Idle;
    sync_in_progress_ = false;
    single_flight_.finish();
    while (single_flight_.pending()) {
      if (!single_flight_.consumePending() || !single_flight_.tryBegin()) {
        return false;
      }
      sync_in_progress_ = true;
      sync_in_progress_ = false;
      single_flight_.finish();
    }
    const std::uint64_t completed = now_ms_;
    memory_policy_.update(80U * 1024U, 48U * 1024U, now_ms_ + 1000U,
                          MemoryOperationContext::Idle, true, completed);
    now_ms_ += 1000U;
    return !single_flight_.active() && !single_flight_.pending() &&
           !sync_in_progress_ &&
           memory_context_ == MemoryOperationContext::Idle;
  }

  bool verifyReportProgress(const ota_v2::State terminal) {
    const std::string desired = ota_v2::reportMilestoneForState(terminal);
    std::string delivered;
    std::uint32_t steps = 0U;
    while (const char *next = ota_v2::nextReportMilestone(delivered, desired)) {
      delivered = next;
      if (++steps > 12U) {
        return require(false, "OTA report progression did not terminate");
      }
    }
    ++coverage_.duplicate_or_stale_reports;
    if (!require(ota_v2::nextReportMilestone(delivered, desired) == nullptr,
                 "duplicate OTA report was emitted")) {
      return false;
    }
    // Successful install milestones are monotonic. Failure/rollback markers
    // deliberately use a separate terminal-report path, while stale server
    // acknowledgements are exercised and rejected by readingBatch().
    return terminal != ota_v2::State::Completed ||
           require(ota_v2::nextReportMilestone(
                       delivered, "manifest_authenticated") == nullptr,
                   "completed OTA report regressed to a stale milestone");
  }

  std::uint64_t newestStoredSequence() const {
    return readings_.empty()
               ? (next_sequence_ == 0U ? 0U : next_sequence_ - 1U)
               : std::max_element(
                     readings_.begin(), readings_.end(),
                     [](const Reading &left, const Reading &right) {
                       return left.sequence < right.sequence;
                     })
                     ->sequence;
  }

  std::uint64_t backlog() const {
    return static_cast<std::uint64_t>(std::count_if(
        readings_.begin(), readings_.end(), [this](const Reading &reading) {
          return reading.sequence > acknowledged_;
        }));
  }

  Result &result_;
  Coverage &coverage_;
  Generator &random_;
  std::uint32_t sequence_index_{0U};
  FaultBlobStore config_store_;
  std::vector<std::uint8_t> expected_config_;
  std::uint64_t config_generation_{0U};
  sync_policy::SingleFlightGate single_flight_;
  MemoryPressurePolicy memory_policy_;
  MemoryOperationContext memory_context_{MemoryOperationContext::Idle};
  bool sync_in_progress_{false};
  std::vector<Reading> readings_;
  std::uint64_t acknowledged_{0U};
  std::uint64_t next_sequence_{1U};
  std::uint64_t now_ms_{1'000U};
};

inline Result run() {
  constexpr std::uint32_t kSequenceCount = 128U;
  constexpr std::uint32_t kRandomEventsPerSequence = 96U;
  Result result;
  Coverage coverage;
  Generator random(0xC0DEC0DE5EED1234ULL);

  for (std::uint32_t sequence = 0U; sequence < kSequenceCount; ++sequence) {
    SequenceModel model(result, coverage, random, sequence);
    if (!model.begin()) {
      return result;
    }

    // Mandatory prefix guarantees every sequence combines all failure domains
    // before the seeded randomized body permutes and repeats them.
    if (!model.appendReading() || !model.appendReading() ||
        !model.duplicateReading() || !model.heartbeat(-1) ||
        !model.readingBatch(200) || !model.readingBatch(200, true) ||
        !model.changeConfiguration(true) || !model.changeConfiguration(false) ||
        !model.reboot() || !model.webRequest() ||
        !model.otaAttempt(false, 0U) ||
        !model.otaAttempt(true, sequence % 7U) || !model.cleanup() ||
        !model.checkInvariants()) {
      return result;
    }

    for (std::uint32_t event = 0U; event < kRandomEventsPerSequence; ++event) {
      bool ok = true;
      switch (random.bounded(11U)) {
      case 0U:
        ok = model.appendReading();
        break;
      case 1U:
        ok = model.duplicateReading();
        break;
      case 2U:
        ok = model.heartbeat(random.chance(3U, 4U) ? 200 : -1);
        break;
      case 3U:
        ok = model.readingBatch(random.chance(2U, 3U) ? 200 : 503);
        break;
      case 4U:
        ok = model.changeConfiguration(random.chance(1U, 3U));
        break;
      case 5U:
        ok = model.reboot();
        break;
      case 6U:
        ok = model.webRequest();
        break;
      case 7U:
        ok = model.otaAttempt(random.chance(3U, 4U), random.bounded(7U));
        break;
      case 8U:
        ok = model.cleanup();
        break;
      case 9U:
        ok = model.readingBatch(200, true);
        break;
      default:
        ok = model.heartbeat(random.chance(1U, 2U) ? 429 : 204);
        break;
      }
      if (!ok || !model.checkInvariants()) {
        return result;
      }
    }
    if (!model.finish()) {
      return result;
    }
    ++result.sequences;
  }

  const bool covered = coverage.network_failures >= kSequenceCount &&
                       coverage.persistence_failures >= kSequenceCount &&
                       coverage.reboots >= kSequenceCount &&
                       coverage.duplicate_or_stale_reports >= kSequenceCount &&
                       coverage.heartbeats >= kSequenceCount &&
                       coverage.reading_batches >= kSequenceCount &&
                       coverage.rollbacks > 0U &&
                       coverage.config_changes >= kSequenceCount &&
                       coverage.web_requests >= kSequenceCount &&
                       coverage.cleanup_attempts >= kSequenceCount;
  if (!covered) {
    result.passed = false;
    result.failure = "randomized reliability coverage counter was not met";
  }
  return result;
}

} // namespace randomized_reliability
} // namespace pm
