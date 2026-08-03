#pragma once

#include "ota/OtaManifestV2.h"

namespace pm {

class OtaRecoveryStore {
public:
  bool load(ota_v2::RecoveryRecord &record) const;
  bool save(const ota_v2::RecoveryRecord &record) const;
  bool clear() const;
};

} // namespace pm
