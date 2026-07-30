#include "config/AtomicConfigStore.h"

#include <algorithm>
#include <array>
#include <limits>

namespace pm {
namespace persistence {
namespace {

constexpr std::uint32_t kRecordMagic = 0x504D4346U; // PMCF
constexpr std::uint32_t kMarkerMagic = 0x504D4143U; // PMAC
constexpr std::uint16_t kFormatVersion = 1U;
constexpr std::size_t kRecordHeaderSize = 24U;
constexpr std::size_t kMarkerSize = 20U;
constexpr std::size_t kMaximumPayloadSize = 24U * 1024U;

void appendU16(std::vector<std::uint8_t> &output, const std::uint16_t value) {
  output.push_back(static_cast<std::uint8_t>(value));
  output.push_back(static_cast<std::uint8_t>(value >> 8U));
}

void appendU32(std::vector<std::uint8_t> &output, const std::uint32_t value) {
  for (std::uint8_t shift = 0; shift < 32U; shift += 8U) {
    output.push_back(static_cast<std::uint8_t>(value >> shift));
  }
}

void appendU64(std::vector<std::uint8_t> &output, const std::uint64_t value) {
  for (std::uint8_t shift = 0; shift < 64U; shift += 8U) {
    output.push_back(static_cast<std::uint8_t>(value >> shift));
  }
}

bool readU16(const std::vector<std::uint8_t> &input, const std::size_t offset,
             std::uint16_t &value) {
  if (offset + 2U > input.size())
    return false;
  value = static_cast<std::uint16_t>(input[offset]) |
          static_cast<std::uint16_t>(input[offset + 1U]) << 8U;
  return true;
}

bool readU32(const std::vector<std::uint8_t> &input, const std::size_t offset,
             std::uint32_t &value) {
  if (offset + 4U > input.size())
    return false;
  value = 0;
  for (std::uint8_t shift = 0; shift < 32U; shift += 8U) {
    value |= static_cast<std::uint32_t>(input[offset + shift / 8U]) << shift;
  }
  return true;
}

bool readU64(const std::vector<std::uint8_t> &input, const std::size_t offset,
             std::uint64_t &value) {
  if (offset + 8U > input.size())
    return false;
  value = 0;
  for (std::uint8_t shift = 0; shift < 64U; shift += 8U) {
    value |= static_cast<std::uint64_t>(input[offset + shift / 8U]) << shift;
  }
  return true;
}

std::vector<std::uint8_t>
recordCrcMaterial(const std::uint64_t generation,
                  const std::vector<std::uint8_t> &payload) {
  std::vector<std::uint8_t> material;
  material.reserve(12U + payload.size());
  appendU64(material, generation);
  appendU32(material, static_cast<std::uint32_t>(payload.size()));
  material.insert(material.end(), payload.begin(), payload.end());
  return material;
}

std::vector<std::uint8_t>
encodeRecord(const std::uint64_t generation,
             const std::vector<std::uint8_t> &payload) {
  std::vector<std::uint8_t> output;
  output.reserve(kRecordHeaderSize + payload.size());
  appendU32(output, kRecordMagic);
  appendU16(output, kFormatVersion);
  appendU16(output, 0U);
  appendU64(output, generation);
  appendU32(output, static_cast<std::uint32_t>(payload.size()));
  const std::vector<std::uint8_t> material =
      recordCrcMaterial(generation, payload);
  appendU32(output, crc32(material.data(), material.size()));
  output.insert(output.end(), payload.begin(), payload.end());
  return output;
}

bool decodeRecord(const std::vector<std::uint8_t> &encoded,
                  std::uint64_t &generation,
                  std::vector<std::uint8_t> &payload) {
  if (encoded.size() < kRecordHeaderSize)
    return false;
  std::uint32_t magic = 0;
  std::uint16_t version = 0;
  std::uint32_t payload_length = 0;
  std::uint32_t expected_crc = 0;
  if (!readU32(encoded, 0, magic) || !readU16(encoded, 4, version) ||
      !readU64(encoded, 8, generation) ||
      !readU32(encoded, 16, payload_length) ||
      !readU32(encoded, 20, expected_crc) || magic != kRecordMagic ||
      version != kFormatVersion || generation == 0 ||
      payload_length > kMaximumPayloadSize ||
      encoded.size() != kRecordHeaderSize + payload_length) {
    return false;
  }
  payload.assign(encoded.begin() +
                     static_cast<std::ptrdiff_t>(kRecordHeaderSize),
                 encoded.end());
  const std::vector<std::uint8_t> material =
      recordCrcMaterial(generation, payload);
  return crc32(material.data(), material.size()) == expected_crc;
}

std::vector<std::uint8_t> markerCrcMaterial(const char slot,
                                            const std::uint64_t generation) {
  std::vector<std::uint8_t> material;
  material.reserve(9U);
  material.push_back(static_cast<std::uint8_t>(slot));
  appendU64(material, generation);
  return material;
}

std::vector<std::uint8_t> encodeMarker(const char slot,
                                       const std::uint64_t generation) {
  std::vector<std::uint8_t> output;
  output.reserve(kMarkerSize);
  appendU32(output, kMarkerMagic);
  appendU16(output, kFormatVersion);
  output.push_back(static_cast<std::uint8_t>(slot));
  output.push_back(0U);
  appendU64(output, generation);
  const std::vector<std::uint8_t> material =
      markerCrcMaterial(slot, generation);
  appendU32(output, crc32(material.data(), material.size()));
  return output;
}

bool decodeMarker(const std::vector<std::uint8_t> &encoded, char &slot,
                  std::uint64_t &generation) {
  if (encoded.size() != kMarkerSize)
    return false;
  std::uint32_t magic = 0;
  std::uint16_t version = 0;
  std::uint32_t expected_crc = 0;
  if (!readU32(encoded, 0, magic) || !readU16(encoded, 4, version) ||
      !readU64(encoded, 8, generation) || !readU32(encoded, 16, expected_crc) ||
      magic != kMarkerMagic || version != kFormatVersion || generation == 0) {
    return false;
  }
  slot = static_cast<char>(encoded[6]);
  if (slot != 'a' && slot != 'b')
    return false;
  const std::vector<std::uint8_t> material =
      markerCrcMaterial(slot, generation);
  return crc32(material.data(), material.size()) == expected_crc;
}

struct DecodedSlot {
  bool valid{false};
  char slot{'\0'};
  std::uint64_t generation{0};
  std::vector<std::uint8_t> payload;
};

DecodedSlot readSlot(BlobStore &store, const char *key, const char slot) {
  DecodedSlot decoded;
  decoded.slot = slot;
  std::vector<std::uint8_t> encoded;
  decoded.valid = store.read(key, encoded) &&
                  decodeRecord(encoded, decoded.generation, decoded.payload);
  return decoded;
}

const DecodedSlot *newestValid(const DecodedSlot &a, const DecodedSlot &b) {
  if (!a.valid)
    return b.valid ? &b : nullptr;
  if (!b.valid)
    return &a;
  return a.generation >= b.generation ? &a : &b;
}

const char *slotKey(const SlotKeys &keys, const char slot) {
  return slot == 'a' ? keys.slot_a : keys.slot_b;
}

bool writeVerified(BlobStore &store, const char *key,
                   const std::vector<std::uint8_t> &encoded) {
  if (!store.write(key, encoded.data(), encoded.size()))
    return false;
  std::vector<std::uint8_t> readback;
  return store.read(key, readback) && readback == encoded;
}

} // namespace

std::uint32_t crc32(const std::uint8_t *data, const std::size_t length) {
  std::uint32_t crc = 0xFFFFFFFFU;
  for (std::size_t index = 0; index < length; ++index) {
    crc ^= data[index];
    for (std::uint8_t bit = 0; bit < 8U; ++bit) {
      const std::uint32_t mask =
          static_cast<std::uint32_t>(-static_cast<std::int32_t>(crc & 1U));
      crc = (crc >> 1U) ^ (0xEDB88320U & mask);
    }
  }
  return ~crc;
}

bool loadActive(BlobStore &store, const SlotKeys &keys, LoadResult &result) {
  result = {};
  const DecodedSlot a = readSlot(store, keys.slot_a, 'a');
  const DecodedSlot b = readSlot(store, keys.slot_b, 'b');

  std::vector<std::uint8_t> encoded_marker;
  char marker_slot = '\0';
  std::uint64_t marker_generation = 0;
  const bool marker_valid =
      store.read(keys.active, encoded_marker) &&
      decodeMarker(encoded_marker, marker_slot, marker_generation);
  const DecodedSlot *selected = nullptr;
  if (marker_valid) {
    const DecodedSlot &marked = marker_slot == 'a' ? a : b;
    if (marked.valid && marked.generation == marker_generation) {
      selected = &marked;
    }
  }
  if (selected == nullptr) {
    selected = newestValid(a, b);
    result.recovered_fallback = selected != nullptr;
  }
  if (selected == nullptr)
    return false;

  result.found = true;
  result.slot = selected->slot;
  result.generation = selected->generation;
  result.payload = selected->payload;
  return true;
}

bool commit(BlobStore &store, const SlotKeys &keys,
            const std::vector<std::uint8_t> &payload, CommitResult &result) {
  result = {};
  if (payload.empty() || payload.size() > kMaximumPayloadSize)
    return false;

  LoadResult current;
  const bool has_current = loadActive(store, keys, current);
  const DecodedSlot a = readSlot(store, keys.slot_a, 'a');
  const DecodedSlot b = readSlot(store, keys.slot_b, 'b');
  const std::uint64_t largest_generation =
      std::max(a.valid ? a.generation : std::uint64_t{0},
               b.valid ? b.generation : std::uint64_t{0});
  if (largest_generation == std::numeric_limits<std::uint64_t>::max()) {
    return false;
  }
  const std::uint64_t generation = largest_generation + 1U;
  const char target = has_current ? (current.slot == 'a' ? 'b' : 'a') : 'a';
  const char *target_key = slotKey(keys, target);
  const std::vector<std::uint8_t> encoded = encodeRecord(generation, payload);
  if (!writeVerified(store, target_key, encoded)) {
    store.erase(target_key);
    return false;
  }

  std::uint64_t decoded_generation = 0;
  std::vector<std::uint8_t> decoded_payload;
  std::vector<std::uint8_t> slot_readback;
  if (!store.read(target_key, slot_readback) ||
      !decodeRecord(slot_readback, decoded_generation, decoded_payload) ||
      decoded_generation != generation || decoded_payload != payload) {
    store.erase(target_key);
    return false;
  }

  const std::vector<std::uint8_t> marker = encodeMarker(target, generation);
  if (!writeVerified(store, keys.active, marker)) {
    store.erase(target_key);
    return false;
  }
  LoadResult verified;
  if (!loadActive(store, keys, verified) || verified.slot != target ||
      verified.generation != generation || verified.payload != payload) {
    store.erase(target_key);
    if (has_current) {
      const std::vector<std::uint8_t> previous_marker =
          encodeMarker(current.slot, current.generation);
      writeVerified(store, keys.active, previous_marker);
    } else {
      store.erase(keys.active);
    }
    return false;
  }
  result.committed = true;
  result.slot = target;
  result.generation = generation;
  return true;
}

bool loadPrevious(BlobStore &store, const SlotKeys &keys,
                  const std::uint64_t expected_current_generation,
                  LoadResult &result) {
  result = {};
  LoadResult current;
  if (!loadActive(store, keys, current) ||
      current.generation != expected_current_generation) {
    return false;
  }
  const DecodedSlot other =
      readSlot(store, current.slot == 'a' ? keys.slot_b : keys.slot_a,
               current.slot == 'a' ? 'b' : 'a');
  // A newer valid inactive slot can exist after power is lost between its
  // verified write and the active-marker commit. It was never committed and
  // must not be promoted by a rollback request.
  if (!other.valid || other.generation >= current.generation)
    return false;
  result.found = true;
  result.slot = other.slot;
  result.generation = other.generation;
  result.payload = other.payload;
  return true;
}

bool rollbackToPrevious(BlobStore &store, const SlotKeys &keys,
                        const std::uint64_t expected_current_generation,
                        LoadResult &result) {
  LoadResult previous;
  if (!loadPrevious(store, keys, expected_current_generation, previous)) {
    return false;
  }
  const std::vector<std::uint8_t> marker =
      encodeMarker(previous.slot, previous.generation);
  if (!writeVerified(store, keys.active, marker) ||
      !loadActive(store, keys, result)) {
    return false;
  }
  return result.slot == previous.slot &&
         result.generation == previous.generation &&
         result.payload == previous.payload;
}

bool anyDataPresent(BlobStore &store, const SlotKeys &keys) {
  return store.exists(keys.slot_a) || store.exists(keys.slot_b) ||
         store.exists(keys.active);
}

} // namespace persistence
} // namespace pm
