#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace pm {

enum class ReplayRememberResult : std::uint8_t {
  Accepted,
  Replayed,
  CapacityExceeded,
};

template <typename Digest, std::size_t Capacity> class AuthReplayWindow {
public:
  ReplayRememberResult remember(const Digest &digest,
                                const std::int64_t accepted_at,
                                const std::uint32_t window_seconds) {
    Entry *available = nullptr;
    for (auto &entry : entries_) {
      const std::uint64_t elapsed =
          accepted_at >= entry.accepted_at
              ? static_cast<std::uint64_t>(accepted_at) -
                    static_cast<std::uint64_t>(entry.accepted_at)
              : 0U;
      if (entry.used && elapsed > window_seconds) {
        entry = {};
      }
      if (entry.used && entry.digest == digest) {
        return ReplayRememberResult::Replayed;
      }
      if (!entry.used && available == nullptr) {
        available = &entry;
      }
    }
    // Never evict an entry that is still inside the authentication window.
    // This converts an excessive signed-request rate into a bounded rejection
    // instead of reopening a replay opportunity.
    if (available == nullptr) {
      return ReplayRememberResult::CapacityExceeded;
    }
    available->used = true;
    available->digest = digest;
    available->accepted_at = accepted_at;
    return ReplayRememberResult::Accepted;
  }

  static constexpr std::size_t capacity() { return Capacity; }

private:
  struct Entry {
    bool used{false};
    Digest digest{};
    std::int64_t accepted_at{0};
  };
  std::array<Entry, Capacity> entries_{};
};

} // namespace pm
