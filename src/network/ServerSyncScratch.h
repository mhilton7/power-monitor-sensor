#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#if defined(PM_NATIVE_TEST)
#include <cstdlib>
#else
#include <esp_heap_caps.h>
#endif

namespace pm {

// A fixed-capacity, PSRAM-backed byte buffer for the single-owner
// ServerSyncTask.  Keeping request/response payloads out of internal DRAM
// prevents recurring JSON and HTTP body allocations from splitting the
// contiguous block reserved for mbedTLS.  Capacity never grows at runtime.
class ServerSyncBuffer final {
public:
  ServerSyncBuffer() = default;
  ServerSyncBuffer(const ServerSyncBuffer &) = delete;
  ServerSyncBuffer &operator=(const ServerSyncBuffer &) = delete;

  ~ServerSyncBuffer() {
    if (data_ != nullptr) {
#if defined(PM_NATIVE_TEST)
      std::free(data_);
#else
      heap_caps_free(data_);
#endif
    }
  }

  bool begin(const std::size_t capacity) {
    if (data_ != nullptr) {
      return capacity_ == capacity;
    }
#if defined(PM_NATIVE_TEST)
    data_ = static_cast<char *>(std::malloc(capacity + 1U));
#else
    data_ = static_cast<char *>(
        heap_caps_malloc(capacity + 1U, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
#endif
    if (data_ == nullptr) {
      return false;
    }
    capacity_ = capacity;
    clear();
    return true;
  }

  void clear() {
    size_ = 0U;
    overflowed_ = false;
    if (data_ != nullptr) {
      data_[0] = '\0';
    }
  }

  bool prepare(const std::size_t size) {
    if (data_ == nullptr || size > capacity_) {
      overflowed_ = true;
      return false;
    }
    size_ = size;
    data_[size_] = '\0';
    return true;
  }

  std::size_t write(const std::uint8_t value) {
    return write(&value, 1U);
  }

  std::size_t write(const char *data, const std::size_t size) {
    return write(reinterpret_cast<const std::uint8_t *>(data), size);
  }

  bool writeText(const char *text) {
    return text != nullptr && write(text, std::strlen(text)) == std::strlen(text);
  }

  std::size_t write(const std::uint8_t *data, const std::size_t size) {
    if (data_ == nullptr || data == nullptr || size > capacity_ - size_) {
      overflowed_ = true;
      return 0U;
    }
    if (size != 0U) {
      std::memcpy(data_ + size_, data, size);
      size_ += size;
    }
    data_[size_] = '\0';
    return size;
  }

  char *data() { return data_; }
  const char *data() const { return data_; }
  std::size_t size() const { return size_; }
  std::size_t capacity() const { return capacity_; }
  bool overflowed() const { return overflowed_; }
  bool ready() const { return data_ != nullptr; }

private:
  char *data_{nullptr};
  std::size_t capacity_{0U};
  std::size_t size_{0U};
  bool overflowed_{false};
};

struct ServerSyncScratch final {
  // The largest configured request is the bounded event batch (20 KiB with
  // envelope allowance); responses are capped at 24 KiB by policy.
  static constexpr std::size_t kRequestCapacity = 20U * 1024U;
  static constexpr std::size_t kResponseCapacity = 24U * 1024U;
  static constexpr std::size_t kCanonicalCapacity = 2U * 1024U;
  static constexpr std::size_t kUrlCapacity = 1024U;
  static constexpr std::size_t kCanonicalTargetCapacity = 1024U;

  bool begin() {
    if (!request_body.begin(kRequestCapacity) ||
        !response_body.begin(kResponseCapacity) ||
        !canonical_request.begin(kCanonicalCapacity) ||
        !url.begin(kUrlCapacity)) {
      return false;
    }
    // canonicalTarget() requires std::string output. Reserving the bounded
    // endpoint maximum here means the recurring heartbeat path reuses one
    // allocation; requests with larger targets fail closed rather than grow.
    canonical_target.reserve(kCanonicalTargetCapacity);
    return canonical_target.capacity() >= kCanonicalTargetCapacity;
  }

  bool ready() const {
    return request_body.ready() && response_body.ready() &&
           canonical_request.ready() && url.ready() &&
           canonical_target.capacity() >= kCanonicalTargetCapacity;
  }

  ServerSyncBuffer request_body;
  ServerSyncBuffer response_body;
  ServerSyncBuffer canonical_request;
  ServerSyncBuffer url;
  std::string canonical_target;
  std::uint64_t request_reuses{0U};
  std::uint64_t response_reuses{0U};
  std::uint64_t canonical_reuses{0U};
  std::uint64_t url_reuses{0U};
  std::uint64_t unexpected_growths{0U};
};

} // namespace pm
