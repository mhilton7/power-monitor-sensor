#include "storage/StoragePolicy.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <numeric>

namespace pm {
namespace {

std::uint64_t percentBytes(const std::uint64_t capacity,
                           const std::uint8_t percent) {
  return capacity / 100U * percent +
         (capacity % 100U * percent) / 100U;
}

std::uint64_t segmentBytes(const SegmentMetadata &segment) {
  return segment.payload_bytes + segment.index_bytes;
}

} // namespace

StoragePolicyValidation validateStoragePolicy(const StoragePolicy &policy) {
  if (policy.notice_percent > 50U || policy.emergency_percent < 1U ||
      !(policy.notice_percent > policy.warning_percent &&
        policy.warning_percent > policy.critical_percent &&
        policy.critical_percent > policy.emergency_percent)) {
    return {false, "storage_threshold_order_invalid"};
  }
  if (policy.retention_days < 1U || policy.retention_days > 3650U ||
      policy.minimum_local_history_days < 1U ||
      policy.minimum_local_history_days > policy.retention_days ||
      policy.event_retention_days < 1U ||
      policy.event_retention_days > 3650U) {
    return {false, "storage_retention_window_invalid"};
  }
  if (policy.emergency_reserve_bytes < 64ULL * 1024ULL * 1024ULL ||
      policy.cleanup_target_bytes < policy.emergency_reserve_bytes ||
      policy.cleanup_target_percent < policy.warning_percent ||
      policy.cleanup_target_percent > policy.notice_percent) {
    return {false, "storage_reserve_invalid"};
  }
  return {true, "ok"};
}

StoragePressureState classifyStoragePressure(
    const std::uint64_t capacity_bytes, const std::uint64_t free_bytes,
    const StoragePolicy &policy) {
  if (capacity_bytes == 0U) {
    return StoragePressureState::Failed;
  }
  if (free_bytes == 0U) {
    return StoragePressureState::Full;
  }
  const std::uint64_t emergency_threshold =
      std::max(percentBytes(capacity_bytes, policy.emergency_percent),
               std::min(policy.emergency_reserve_bytes, capacity_bytes / 2U));
  if (free_bytes <= emergency_threshold) {
    return StoragePressureState::Emergency;
  }
  if (free_bytes <= percentBytes(capacity_bytes, policy.critical_percent)) {
    return StoragePressureState::Critical;
  }
  if (free_bytes <= percentBytes(capacity_bytes, policy.warning_percent)) {
    return StoragePressureState::Warning;
  }
  if (free_bytes <= percentBytes(capacity_bytes, policy.notice_percent)) {
    return StoragePressureState::Notice;
  }
  return StoragePressureState::Healthy;
}

std::uint64_t cleanupTargetFreeBytes(const std::uint64_t capacity_bytes,
                                     const StoragePolicy &policy) {
  const std::uint64_t percentage =
      percentBytes(capacity_bytes, policy.cleanup_target_percent);
  // A configured absolute target that would consume more than half a small
  // card is not practical. In that case the percentage target remains the
  // safe bounded target.
  const std::uint64_t absolute =
      std::min(policy.cleanup_target_bytes, capacity_bytes / 2U);
  return std::max(percentage, absolute);
}

std::uint64_t conservativeWriteReserveBytes(const std::size_t record_bytes) {
  constexpr std::uint64_t kMaximumIndexEntry = 128U;
  constexpr std::uint64_t kSequenceJournalPair = 1024U;
  constexpr std::uint64_t kCleanupJournal = 4096U;
  constexpr std::uint64_t kFatAndDirectoryOverhead = 64U * 1024U;
  constexpr std::uint64_t kSafetyMargin = 256U * 1024U;
  return static_cast<std::uint64_t>(record_bytes) + kMaximumIndexEntry +
         kSequenceJournalPair + kCleanupJournal + kFatAndDirectoryOverhead +
         kSafetyMargin;
}

SegmentEligibility segmentEligibility(const SegmentMetadata &segment,
                                      const RetentionContext &context) {
  if (segment.active || !segment.closed) {
    return SegmentEligibility::Active;
  }
  if (segment.cleanup_active) {
    return SegmentEligibility::CleanupActive;
  }
  if (segment.minimum_window_protected) {
    return SegmentEligibility::MinimumWindow;
  }
  if (!segment.complete) {
    return SegmentEligibility::Incomplete;
  }
  if (!segment.index_valid) {
    return SegmentEligibility::CorruptOrMissingIndex;
  }
  if (segment.first_sequence == 0U ||
      segment.last_sequence < segment.first_sequence) {
    return SegmentEligibility::SequenceUnknown;
  }
  if (!context.acknowledgement_verified ||
      segment.last_sequence > context.server_ack_sequence) {
    return SegmentEligibility::Unacknowledged;
  }
  if (segment.all_times_trusted && segment.last_utc_ms != 0U &&
      context.retention_cutoff_utc_ms != 0U &&
      segment.last_utc_ms < context.retention_cutoff_utc_ms) {
    return SegmentEligibility::EligibleAge;
  }
  if (context.mode != RetentionMode::ContinuousProtected ||
      !context.emergency_pressure) {
    return segment.all_times_trusted ? SegmentEligibility::TooRecent
                                     : SegmentEligibility::TimeUntrusted;
  }
  if (segment.all_times_trusted) {
    return segment.last_utc_ms != 0U &&
                   context.minimum_history_cutoff_utc_ms != 0U &&
                   segment.last_utc_ms < context.minimum_history_cutoff_utc_ms
               ? SegmentEligibility::EligibleEmergency
               : SegmentEligibility::TooRecent;
  }
  // Untrusted-time emergency cleanup is allowed only because the caller has
  // explicitly selected ContinuousProtected, verified the persisted server
  // acknowledgement, and this is not the active/newest segment. A bounded
  // newest-file window is preserved by marking it active before this call.
  return SegmentEligibility::EligibleEmergency;
}

CleanupPlan buildCleanupPlan(const std::vector<SegmentMetadata> &segments,
                             const RetentionContext &context,
                             const std::uint64_t free_bytes,
                             const std::uint64_t target_free_bytes) {
  CleanupPlan plan;
  std::vector<std::size_t> eligible;
  for (std::size_t index = 0; index < segments.size(); ++index) {
    const SegmentEligibility eligibility =
        segmentEligibility(segments[index], context);
    const std::uint64_t bytes = segmentBytes(segments[index]);
    if (eligibility == SegmentEligibility::EligibleAge ||
        eligibility == SegmentEligibility::EligibleEmergency) {
      eligible.push_back(index);
      plan.eligible_bytes += bytes;
    } else if (eligibility == SegmentEligibility::Unacknowledged) {
      plan.protected_unacknowledged_bytes += bytes;
    } else if (eligibility == SegmentEligibility::TimeUntrusted) {
      plan.protected_untrusted_bytes += bytes;
    }
  }
  std::sort(eligible.begin(), eligible.end(),
            [&segments](const std::size_t left, const std::size_t right) {
              const SegmentMetadata &a = segments[left];
              const SegmentMetadata &b = segments[right];
              if (a.first_sequence != b.first_sequence) {
                return a.first_sequence < b.first_sequence;
              }
              return a.record_path < b.record_path;
            });
  const std::uint64_t needed =
      target_free_bytes > free_bytes ? target_free_bytes - free_bytes : 0U;
  // A non-zero target denotes pressure-driven cleanup. If an earlier record
  // cleanup already restored that target, a later artifact/event pass must
  // not interpret zero required bytes as permission to remove every otherwise
  // eligible segment. A zero target is reserved for ordinary age cleanup and
  // intentionally visits all age-eligible segments.
  if (target_free_bytes != 0U && needed == 0U) {
    return plan;
  }
  for (const std::size_t index : eligible) {
    if (needed != 0U && plan.expected_reclaimed_bytes >= needed) {
      break;
    }
    plan.candidate_indexes.push_back(index);
    plan.expected_reclaimed_bytes += segmentBytes(segments[index]);
  }
  return plan;
}

CleanupRecoveryAction
cleanupRecoveryAction(const CleanupRecoverySnapshot &snapshot) {
  const bool record_collision = snapshot.record_original_exists &&
                                snapshot.record_trash_exists;
  const bool record_missing = !snapshot.record_original_exists &&
                              !snapshot.record_trash_exists;
  const bool index_collision =
      snapshot.has_index && snapshot.index_original_exists &&
      snapshot.index_trash_exists;
  const bool index_missing = snapshot.has_index &&
                             !snapshot.index_original_exists &&
                             !snapshot.index_trash_exists;
  if (record_collision || index_collision) {
    return CleanupRecoveryAction::Block;
  }

  if (snapshot.stage == "planned") {
    if (record_missing || index_missing) {
      return CleanupRecoveryAction::Block;
    }
    if (snapshot.record_trash_exists ||
        (snapshot.has_index && snapshot.index_trash_exists)) {
      return CleanupRecoveryAction::ReverseMoves;
    }
    return CleanupRecoveryAction::ClearJournal;
  }

  if (snapshot.stage == "files_moved" ||
      snapshot.stage == "record_deleted" || snapshot.stage == "complete") {
    if (snapshot.record_original_exists ||
        (snapshot.has_index && snapshot.index_original_exists)) {
      return CleanupRecoveryAction::Block;
    }
    return snapshot.record_trash_exists ||
                   (snapshot.has_index && snapshot.index_trash_exists)
               ? CleanupRecoveryAction::ForwardDelete
               : CleanupRecoveryAction::ClearJournal;
  }
  return CleanupRecoveryAction::Block;
}

const char *retentionModeName(const RetentionMode mode) {
  switch (mode) {
  case RetentionMode::Disabled:
    return "disabled";
  case RetentionMode::StrictAge:
    return "strict_age";
  case RetentionMode::ContinuousProtected:
    return "continuous_protected";
  }
  return "disabled";
}

bool parseRetentionMode(const std::string &value, RetentionMode &mode) {
  if (value == "disabled") {
    mode = RetentionMode::Disabled;
    return true;
  }
  if (value == "strict_age") {
    mode = RetentionMode::StrictAge;
    return true;
  }
  if (value == "continuous_protected") {
    mode = RetentionMode::ContinuousProtected;
    return true;
  }
  return false;
}

const char *storagePressureStateName(const StoragePressureState state) {
  switch (state) {
  case StoragePressureState::Healthy: return "healthy";
  case StoragePressureState::Notice: return "notice";
  case StoragePressureState::Warning: return "warning";
  case StoragePressureState::Critical: return "critical";
  case StoragePressureState::Emergency: return "emergency";
  case StoragePressureState::CleanupQueued: return "cleanup_queued";
  case StoragePressureState::CleanupRunning: return "cleanup_running";
  case StoragePressureState::CleanupRecovering: return "cleanup_recovering";
  case StoragePressureState::CleanupBlockedUnacknowledged:
    return "cleanup_blocked_unacknowledged";
  case StoragePressureState::CleanupBlockedUntrusted:
    return "cleanup_blocked_untrusted";
  case StoragePressureState::ReadOnly: return "read_only";
  case StoragePressureState::Full: return "full";
  case StoragePressureState::Failed: return "failed";
  case StoragePressureState::PreparedForRemoval:
    return "prepared_for_removal";
  }
  return "failed";
}

void StorageGrowthEstimator::observe(const std::uint64_t used_bytes,
                                     const std::uint64_t monotonic_ms) {
  if (previous_monotonic_ms_ != 0U && monotonic_ms > previous_monotonic_ms_) {
    const std::uint64_t elapsed = monotonic_ms - previous_monotonic_ms_;
    const std::uint64_t adjusted_previous =
        previous_used_bytes_ > cleanup_bytes_
            ? previous_used_bytes_ - cleanup_bytes_
            : 0U;
    if (used_bytes >= adjusted_previous && elapsed >= 1000U) {
      const double sample =
          static_cast<double>(used_bytes - adjusted_previous) * 86'400'000.0 /
          static_cast<double>(elapsed);
      bytes_per_day_ = observations_ == 0U ? sample
                                          : bytes_per_day_ * 0.8 + sample * 0.2;
      if (observations_ < std::numeric_limits<std::uint8_t>::max()) {
        ++observations_;
      }
    }
  }
  previous_used_bytes_ = used_bytes;
  previous_monotonic_ms_ = monotonic_ms;
  cleanup_bytes_ = 0U;
}

void StorageGrowthEstimator::recordCleanup(const std::uint64_t reclaimed_bytes) {
  cleanup_bytes_ += reclaimed_bytes;
}

std::uint64_t StorageGrowthEstimator::bytesPerDay() const {
  return bytes_per_day_ > 0.0
             ? static_cast<std::uint64_t>(std::llround(bytes_per_day_))
             : 0U;
}

std::int64_t StorageGrowthEstimator::estimatedDaysRemaining(
    const std::uint64_t free_bytes, const std::uint64_t reserve_bytes) const {
  if (observations_ < 2U || bytes_per_day_ <= 0.0) {
    return -1;
  }
  if (free_bytes <= reserve_bytes) {
    return 0;
  }
  return static_cast<std::int64_t>(std::floor(
      static_cast<double>(free_bytes - reserve_bytes) / bytes_per_day_));
}

} // namespace pm
