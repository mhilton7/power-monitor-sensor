#pragma once

#include <algorithm>
#include <cstdint>

namespace pm {
namespace network_policy {

constexpr std::uint32_t kReconnectInitialMs = 1'000U;
constexpr std::uint32_t kReconnectMaximumMs = 300'000U;
constexpr std::uint32_t kReconnectBaseMaximumMs = 240'000U;

inline bool elapsedAtLeast(const std::uint64_t now_ms,
                           const std::uint64_t started_ms,
                           const std::uint64_t interval_ms) {
  return started_ms != 0U && now_ms >= started_ms &&
         now_ms - started_ms >= interval_ms;
}

inline std::uint32_t reconnectBackoffMs(const std::uint32_t attempt,
                                        const std::uint16_t random_value) {
  const std::uint32_t exponent = std::min<std::uint32_t>(attempt, 8U);
  const std::uint32_t shifted = kReconnectInitialMs << exponent;
  const std::uint32_t base =
      std::min<std::uint32_t>(shifted, kReconnectBaseMaximumMs);
  const std::uint32_t jitter =
      static_cast<std::uint32_t>(random_value) % (base / 4U + 1U);
  return std::min<std::uint32_t>(base + jitter, kReconnectMaximumMs);
}

inline bool credentialsLikelyInvalid(const std::uint16_t disconnect_reason,
                                     const int station_status) {
  // Arduino WL_CONNECT_FAILED is 4. ESP-IDF authentication failures most
  // commonly surface as NOT_AUTHED, four-way handshake timeout, 802.1X
  // failure, AUTH_FAIL, or HANDSHAKE_TIMEOUT.
  return station_status == 4 || disconnect_reason == 6U ||
         disconnect_reason == 15U || disconnect_reason == 23U ||
         disconnect_reason == 202U || disconnect_reason == 204U;
}

inline bool shouldStartCredentialRecoveryAp(
    const bool has_credentials, const bool setup_ap_active,
    const std::uint64_t now_ms, const std::uint64_t attempt_started_ms,
    const std::uint64_t recovery_allowed_at_ms,
    const std::uint16_t disconnect_reason, const int station_status) {
  return has_credentials && !setup_ap_active &&
         now_ms >= recovery_allowed_at_ms &&
         elapsedAtLeast(now_ms, attempt_started_ms, 60'000U) &&
         credentialsLikelyInvalid(disconnect_reason, station_status);
}

} // namespace network_policy
} // namespace pm
