#pragma once

#include <cstddef>

namespace pm {

inline bool shouldRecoverPreviousConfig(const bool primary_loaded,
                                        const bool primary_wifi_configured,
                                        const bool wifi_password_present,
                                        const bool previous_loaded,
                                        const bool previous_wifi_configured) {
  static_cast<void>(previous_wifi_configured);
  if (!previous_loaded) {
    return false;
  }
  if (!primary_loaded) {
    // A valid previous record still carries useful non-network fields. The
    // caller quarantines an unusable Wi-Fi pair after selecting the record.
    return true;
  }
  // An orphaned password proves the primary's unconfigured Wi-Fi state was
  // not intentional. Recover the valid previous record for its non-network
  // fields regardless of whether that record had an SSID; the caller always
  // quarantines the orphaned password and any recovered Wi-Fi pair.
  return !primary_wifi_configured && wifi_password_present;
}

inline bool
legacyWifiPairNeedsQuarantine(const bool wifi_ssid_present,
                              const std::size_t wifi_password_length,
                              const bool password_was_orphaned = false) {
  if (password_was_orphaned) {
    return true;
  }
  if (!wifi_ssid_present) {
    return wifi_password_length != 0U;
  }
  return wifi_password_length < 8U || wifi_password_length > 63U;
}

inline bool reenrollmentPrerequisitesReady(const bool token_verified,
                                           const bool ack_cursor_verified,
                                           const bool config_cursor_verified) {
  return token_verified && ack_cursor_verified && config_cursor_verified;
}

} // namespace pm
