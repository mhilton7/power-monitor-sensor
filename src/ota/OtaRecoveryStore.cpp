#include "ota/OtaRecoveryStore.h"

#include <vector>

#include <Preferences.h>

#include "config/AtomicConfigStore.h"

namespace pm {
namespace {

constexpr char kPersistentPartition[] = "pmconfig";
constexpr char kPersistentNamespace[] = "pm-state";
constexpr persistence::SlotKeys kOtaRecoverySlots{"ota_a", "ota_b",
                                                   "ota_active"};

class PreferencesBlobStore final : public persistence::BlobStore {
public:
  bool read(const char *key, std::vector<std::uint8_t> &value) override {
    Preferences preferences;
    if (!preferences.begin(kPersistentNamespace, true, kPersistentPartition))
      return false;
    const std::size_t length = preferences.getBytesLength(key);
    value.resize(length);
    const bool read = length != 0U &&
                      preferences.getBytes(key, value.data(), length) == length;
    preferences.end();
    if (!read)
      value.clear();
    return read;
  }

  bool write(const char *key, const std::uint8_t *value,
             const std::size_t length) override {
    Preferences preferences;
    if (length == 0U ||
        !preferences.begin(kPersistentNamespace, false, kPersistentPartition)) {
      return false;
    }
    const bool written = preferences.putBytes(key, value, length) == length;
    preferences.end();
    return written;
  }

  bool erase(const char *key) override {
    Preferences preferences;
    if (!preferences.begin(kPersistentNamespace, false, kPersistentPartition))
      return false;
    const bool erased = !preferences.isKey(key) || preferences.remove(key);
    preferences.end();
    return erased;
  }

  bool exists(const char *key) override {
    Preferences preferences;
    if (!preferences.begin(kPersistentNamespace, true, kPersistentPartition))
      return false;
    const bool present = preferences.isKey(key);
    preferences.end();
    return present;
  }
};

} // namespace

bool OtaRecoveryStore::load(ota_v2::RecoveryRecord &record) const {
  PreferencesBlobStore store;
  persistence::LoadResult loaded;
  if (!persistence::loadActive(store, kOtaRecoverySlots, loaded))
    return false;
  const std::string json(loaded.payload.begin(), loaded.payload.end());
  return ota_v2::parseRecovery(json, record);
}

bool OtaRecoveryStore::save(const ota_v2::RecoveryRecord &record) const {
  const std::string json = ota_v2::serializeRecovery(record);
  if (json.empty())
    return false;
  const std::vector<std::uint8_t> payload(json.begin(), json.end());
  PreferencesBlobStore store;
  persistence::CommitResult committed;
  return persistence::commit(store, kOtaRecoverySlots, payload, committed) &&
         committed.committed;
}

bool OtaRecoveryStore::clear() const {
  PreferencesBlobStore store;
  return store.erase(kOtaRecoverySlots.slot_a) &&
         store.erase(kOtaRecoverySlots.slot_b) &&
         store.erase(kOtaRecoverySlots.active);
}

} // namespace pm
