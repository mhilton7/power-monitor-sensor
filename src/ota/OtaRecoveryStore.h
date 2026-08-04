#pragma once

#include <string>

#include "ota/OtaManifestV2.h"

namespace pm {

enum class OtaRecoveryStoreResult : std::uint8_t {
  NotRequired,
  Loaded,
  SavedAndVerified,
  Cleared,
  NotFound,
  LoadFailed,
  ParseFailed,
  SerializeFailed,
  CommitFailed,
  ReadbackFailed,
  IdentityMismatch,
  ClearFailed,
  StateLockUnavailable,
  EvidenceSequenceExhausted,
};

const char *otaRecoveryStoreResultName(OtaRecoveryStoreResult result);

// Independent evidence for the one failure mode in which the normal OTA
// record is, by definition, unavailable or unauthenticated.  It deliberately
// contains no invented deployment/release identity.  The record is committed
// through its own atomic slots and read back before restricted recovery is
// advertised as durable.
struct OtaRestrictedRecoveryRecord {
  std::uint32_t schema_version{1U};
  std::string failure_code;
  std::string rollback_result;
  std::string running_version;
  std::string running_build_hash;
  std::string boot_id;
  std::uint32_t boot_count{0U};
  bool pending_image{true};
  bool report_pending{true};
};

class OtaRecoveryStore {
public:
  OtaRecoveryStoreResult load(ota_v2::RecoveryRecord &record) const;
  OtaRecoveryStoreResult
  saveAndVerify(const ota_v2::RecoveryRecord &record) const;
  OtaRecoveryStoreResult clear() const;
  OtaRecoveryStoreResult
  loadRestrictedIncident(OtaRestrictedRecoveryRecord &record) const;
  OtaRecoveryStoreResult saveRestrictedIncidentAndVerify(
      const OtaRestrictedRecoveryRecord &record) const;
  OtaRecoveryStoreResult clearRestrictedIncident() const;
};

} // namespace pm
