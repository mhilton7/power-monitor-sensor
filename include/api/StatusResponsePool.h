#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace pm {

template <std::size_t SlotCount, std::size_t SlotCapacity>
class StatusResponsePool {
public:
  static_assert(SlotCount > 0U, "status response pool needs at least one slot");
  static_assert(SlotCapacity > 1U,
                "status response slots need payload and terminator space");

  class Lease {
  public:
    Lease() = default;
    Lease(const Lease &) = delete;
    Lease &operator=(const Lease &) = delete;

    Lease(Lease &&other) noexcept { moveFrom(other); }
    Lease &operator=(Lease &&other) noexcept {
      if (this != &other) {
        release();
        moveFrom(other);
      }
      return *this;
    }

    ~Lease() { release(); }

    explicit operator bool() const { return pool_ != nullptr; }
    char *data() { return pool_ == nullptr ? nullptr : pool_->slots_[index_].body.data(); }
    const char *data() const {
      return pool_ == nullptr ? nullptr : pool_->slots_[index_].body.data();
    }
    constexpr std::size_t capacity() const { return SlotCapacity; }
    std::size_t size() const { return size_; }
    bool setSize(const std::size_t size) {
      if (pool_ == nullptr || size >= SlotCapacity) {
        return false;
      }
      size_ = size;
      pool_->slots_[index_].body[size_] = '\0';
      return true;
    }
    void release() {
      if (pool_ != nullptr) {
        pool_->release(index_, generation_);
        pool_ = nullptr;
        size_ = 0U;
      }
    }

  private:
    friend class StatusResponsePool;
    Lease(StatusResponsePool *pool, const std::size_t index,
          const std::uint32_t generation)
        : pool_(pool), index_(index), generation_(generation) {}

    void moveFrom(Lease &other) {
      pool_ = other.pool_;
      index_ = other.index_;
      generation_ = other.generation_;
      size_ = other.size_;
      other.pool_ = nullptr;
      other.size_ = 0U;
    }

    StatusResponsePool *pool_{nullptr};
    std::size_t index_{0U};
    std::uint32_t generation_{0U};
    std::size_t size_{0U};
  };

  Lease acquire() {
    for (std::size_t index = 0U; index < slots_.size(); ++index) {
      bool expected = false;
      if (!slots_[index].in_use.compare_exchange_strong(
              expected, true, std::memory_order_acq_rel)) {
        continue;
      }
      const std::uint32_t generation =
          slots_[index].generation.fetch_add(1U, std::memory_order_acq_rel) +
          1U;
      slots_[index].body[0] = '\0';
      active_.fetch_add(1U, std::memory_order_relaxed);
      return Lease(this, index, generation);
    }
    exhaustions_.fetch_add(1U, std::memory_order_relaxed);
    return {};
  }

  constexpr std::size_t capacity() const { return SlotCount; }
  constexpr std::size_t responseCapacity() const { return SlotCapacity; }
  std::uint32_t active() const {
    return active_.load(std::memory_order_relaxed);
  }
  std::uint64_t exhaustions() const {
    return exhaustions_.load(std::memory_order_relaxed);
  }

private:
  struct Slot {
    std::array<char, SlotCapacity> body{};
    std::atomic<bool> in_use{false};
    std::atomic<std::uint32_t> generation{0U};
  };

  void release(const std::size_t index, const std::uint32_t generation) {
    if (index >= slots_.size() ||
        slots_[index].generation.load(std::memory_order_acquire) != generation) {
      return;
    }
    bool expected = true;
    if (slots_[index].in_use.compare_exchange_strong(
            expected, false, std::memory_order_acq_rel)) {
      active_.fetch_sub(1U, std::memory_order_relaxed);
    }
  }

  std::array<Slot, SlotCount> slots_{};
  std::atomic<std::uint32_t> active_{0U};
  std::atomic<std::uint64_t> exhaustions_{0U};
};

} // namespace pm
