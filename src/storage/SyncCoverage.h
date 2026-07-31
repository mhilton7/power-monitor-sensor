#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace pm {

struct SequenceRange {
  std::uint64_t start_sequence{0};
  std::uint64_t end_sequence{0};
};

struct SyncCoveragePlan {
  std::uint64_t end_sequence{0};
  std::vector<SequenceRange> unavailable_sequence_ranges;
};

// Build contiguous server coverage from the acknowledgement cursor through
// the last reading selected for this page. Any sequence that is not retained
// as a syncable record is explicitly declared unavailable. This includes
// holes in the local sequence history, not only retained records whose
// timestamps are unsuitable for server history.
inline SyncCoveragePlan deriveSyncCoverage(
    const std::uint64_t after_sequence,
    const std::uint64_t maximum_scanned_sequence,
    std::vector<std::uint64_t> selected_syncable_sequences,
    std::vector<std::uint64_t> observed_syncable_sequences,
    const std::size_t maximum_unavailable_sequences) {
  SyncCoveragePlan plan;
  if (maximum_scanned_sequence <= after_sequence ||
      maximum_unavailable_sequences == 0U ||
      after_sequence == std::numeric_limits<std::uint64_t>::max()) {
    return plan;
  }

  const auto sort_unique = [](std::vector<std::uint64_t> &values) {
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
  };
  sort_unique(selected_syncable_sequences);
  sort_unique(observed_syncable_sequences);

  const std::uint64_t desired_end =
      selected_syncable_sequences.empty()
          ? maximum_scanned_sequence
          : std::min(maximum_scanned_sequence,
                     selected_syncable_sequences.back());
  std::size_t unavailable_count = 0U;
  SequenceRange current;
  bool range_open = false;

  for (std::uint64_t sequence = after_sequence + 1U;
       sequence <= desired_end; ++sequence) {
    const bool selected =
        std::binary_search(selected_syncable_sequences.begin(),
                           selected_syncable_sequences.end(), sequence);
    const bool observed_syncable =
        std::binary_search(observed_syncable_sequences.begin(),
                           observed_syncable_sequences.end(), sequence);

    // A retained syncable record that was not selected cannot be skipped or
    // declared lost. End this page immediately before it.
    if (observed_syncable && !selected) {
      break;
    }
    if (!selected) {
      if (unavailable_count >= maximum_unavailable_sequences) {
        break;
      }
      ++unavailable_count;
      if (!range_open) {
        current = {sequence, sequence};
        range_open = true;
      } else if (sequence == current.end_sequence + 1U) {
        current.end_sequence = sequence;
      } else {
        plan.unavailable_sequence_ranges.push_back(current);
        current = {sequence, sequence};
      }
    } else if (range_open) {
      plan.unavailable_sequence_ranges.push_back(current);
      range_open = false;
    }
    plan.end_sequence = sequence;
    if (sequence == std::numeric_limits<std::uint64_t>::max()) {
      break;
    }
  }
  if (range_open) {
    plan.unavailable_sequence_ranges.push_back(current);
  }
  return plan;
}

} // namespace pm
