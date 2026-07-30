#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pm {
namespace persistence {

class BlobStore {
public:
  virtual ~BlobStore() = default;
  virtual bool read(const char *key, std::vector<std::uint8_t> &value) = 0;
  virtual bool write(const char *key, const std::uint8_t *value,
                     std::size_t length) = 0;
  virtual bool erase(const char *key) = 0;
  virtual bool exists(const char *key) = 0;
};

struct SlotKeys {
  const char *slot_a;
  const char *slot_b;
  const char *active;
};

struct LoadResult {
  bool found{false};
  bool recovered_fallback{false};
  char slot{'\0'};
  std::uint64_t generation{0};
  std::vector<std::uint8_t> payload;
};

struct CommitResult {
  bool committed{false};
  char slot{'\0'};
  std::uint64_t generation{0};
};

std::uint32_t crc32(const std::uint8_t *data, std::size_t length);

bool loadActive(BlobStore &store, const SlotKeys &keys, LoadResult &result);
bool loadPrevious(BlobStore &store, const SlotKeys &keys,
                  std::uint64_t expected_current_generation,
                  LoadResult &result);
bool commit(BlobStore &store, const SlotKeys &keys,
            const std::vector<std::uint8_t> &payload, CommitResult &result);
bool rollbackToPrevious(BlobStore &store, const SlotKeys &keys,
                        std::uint64_t expected_current_generation,
                        LoadResult &result);
bool anyDataPresent(BlobStore &store, const SlotKeys &keys);

} // namespace persistence
} // namespace pm
