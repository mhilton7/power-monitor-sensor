#include "security/AuthService.h"

#include <algorithm>
#include <cstdlib>

#include "build_config.h"
#include "security/AuthPolicy.h"
#include "version.h"

namespace pm {

ReplayRememberResult
NonceCache::checkAndRemember(const std::string &nonce, const std::int64_t now,
                             const std::uint32_t window_seconds) {
  const crypto::Key32 digest = crypto::sha256(
      reinterpret_cast<const std::uint8_t *>(nonce.data()), nonce.size());
  return window_.remember(digest, now, window_seconds);
}

AuthResult RequestAuthenticator::verify(
    const std::string &method, const std::string &path,
    const std::vector<std::pair<std::string, std::string>> &query,
    const std::uint8_t *body, const std::size_t body_length,
    const AuthHeaders &headers, const std::string &expected_device_id,
    const crypto::Key32 &key, const std::int64_t now_seconds,
    const bool time_synchronized) {
  if (headers.protocol.empty() || headers.device_id.empty() ||
      headers.timestamp.empty() || headers.nonce.empty() ||
      headers.content_sha256.empty() || headers.signature.empty()) {
    return AuthResult::MissingHeader;
  }
  if (headers.protocol != version::PROTOCOL) {
    return AuthResult::ProtocolMismatch;
  }
  if (!crypto::constantTimeEqual(headers.device_id, expected_device_id)) {
    return AuthResult::DeviceMismatch;
  }
  std::int64_t parsed_timestamp = 0;
  if (!auth_policy::parseTimestamp(headers.timestamp, parsed_timestamp)) {
    return AuthResult::TimestampInvalid;
  }
  if (!time_synchronized ||
      !auth_policy::timestampWithinWindow(parsed_timestamp, now_seconds,
                                          build::SIGNATURE_WINDOW_SECONDS)) {
    return AuthResult::TimestampOutsideWindow;
  }
  if (headers.nonce.size() < 32U ||
      !std::all_of(headers.nonce.begin(), headers.nonce.end(),
                   [](const char value) {
                     return (value >= '0' && value <= '9') ||
                            (value >= 'a' && value <= 'f');
                   })) {
    return AuthResult::NonceInvalid;
  }
  const std::string actual_body_hash = crypto::sha256Hex(body, body_length);
  if (!crypto::constantTimeEqual(actual_body_hash, headers.content_sha256)) {
    return AuthResult::BodyHashMismatch;
  }
  const std::string canonical = crypto::canonicalRequest(
      method, crypto::canonicalPathQuery(path, query), headers.timestamp,
      headers.nonce, headers.content_sha256);
  const std::string expected_signature =
      crypto::hmacSha256Hex(key.data(), key.size(), canonical);
  if (!crypto::constantTimeEqual(expected_signature, headers.signature)) {
    return AuthResult::SignatureMismatch;
  }
  const ReplayRememberResult replay = nonce_cache_.checkAndRemember(
      headers.nonce, now_seconds, build::SIGNATURE_WINDOW_SECONDS);
  if (replay == ReplayRememberResult::Replayed) {
    return AuthResult::NonceReplayed;
  }
  if (replay == ReplayRememberResult::CapacityExceeded) {
    return AuthResult::NonceCapacityExceeded;
  }
  return AuthResult::Ok;
}

crypto::Key32 SessionManager::digest(const std::string &value) {
  return crypto::sha256(reinterpret_cast<const std::uint8_t *>(value.data()),
                        value.size());
}

bool SessionManager::digestEqual(const crypto::Key32 &left,
                                 const crypto::Key32 &right) {
  std::uint8_t difference = 0U;
  for (std::size_t index = 0; index < left.size(); ++index) {
    difference |= static_cast<std::uint8_t>(left[index] ^ right[index]);
  }
  return difference == 0U;
}

SessionManager::Entry *SessionManager::find(const crypto::Key32 &token_digest) {
  for (Entry &entry : entries_) {
    if (entry.used && digestEqual(entry.token_digest, token_digest)) {
      return &entry;
    }
  }
  return nullptr;
}

const SessionManager::Entry *
SessionManager::find(const crypto::Key32 &token_digest) const {
  for (const Entry &entry : entries_) {
    if (entry.used && digestEqual(entry.token_digest, token_digest)) {
      return &entry;
    }
  }
  return nullptr;
}

void SessionManager::purgeExpired(const std::uint64_t now_ms) {
  for (Entry &entry : entries_) {
    if (entry.used && now_ms >= entry.expires_ms) {
      entry = {};
      ++metrics_.expired;
    }
  }
}

void SessionManager::updatePeak() {
  std::uint32_t active = 0U;
  for (const Entry &entry : entries_) {
    active += entry.used ? 1U : 0U;
  }
  metrics_.active = active;
  metrics_.peak_active = std::max(metrics_.peak_active, active);
}

SessionManager::Session
SessionManager::open(const std::string &presented_token,
                     const std::uint64_t now_ms,
                     const std::uint32_t ttl_seconds) {
  std::lock_guard<std::mutex> lock(mutex_);
  const std::uint64_t expires_ms =
      now_ms + static_cast<std::uint64_t>(ttl_seconds) * 1000U;
  if (!presented_token.empty()) {
    Entry *existing = find(digest(presented_token));
    if (existing != nullptr && now_ms < existing->expires_ms) {
      Session session;
      session.token = presented_token;
      session.csrf = crypto::randomHex(24);
      session.expires_ms = expires_ms;
      session.elevated = now_ms < existing->elevated_until_ms;
      session.reused = true;
      session.refreshed = true;
      existing->csrf_digest = digest(session.csrf);
      existing->last_seen_ms = now_ms;
      existing->expires_ms = expires_ms;
      ++metrics_.reused;
      ++metrics_.refreshed;
      updatePeak();
      return session;
    }
  }

  purgeExpired(now_ms);
  Entry *available = nullptr;
  for (Entry &entry : entries_) {
    if (!entry.used) {
      available = &entry;
      break;
    }
  }
  if (available == nullptr) {
    ++metrics_.capacity_rejections;
    updatePeak();
    Session rejected;
    rejected.capacity_reached = true;
    return rejected;
  }

  Session session;
  session.token = crypto::randomHex(32);
  session.csrf = crypto::randomHex(24);
  session.expires_ms = expires_ms;
  *available = {};
  available->used = true;
  available->token_digest = digest(session.token);
  available->csrf_digest = digest(session.csrf);
  available->created_ms = now_ms;
  available->last_seen_ms = now_ms;
  available->expires_ms = expires_ms;
  available->generation = next_generation_++;
  ++metrics_.created;
  updatePeak();
  return session;
}

SessionManager::Session SessionManager::elevate(
    const std::string &presented_token, const std::uint64_t now_ms,
    const std::uint32_t ttl_seconds,
    const std::uint32_t elevation_ttl_seconds) {
  std::lock_guard<std::mutex> lock(mutex_);
  Session session;
  if (presented_token.empty()) {
    return session;
  }
  Entry *existing = find(digest(presented_token));
  if (existing == nullptr || now_ms >= existing->expires_ms) {
    ++metrics_.invalid;
    return session;
  }
  session.token = presented_token;
  session.csrf = crypto::randomHex(24);
  session.expires_ms =
      now_ms + static_cast<std::uint64_t>(ttl_seconds) * 1000U;
  session.elevated = true;
  session.reused = true;
  session.refreshed = true;
  existing->csrf_digest = digest(session.csrf);
  existing->last_seen_ms = now_ms;
  existing->expires_ms = session.expires_ms;
  existing->elevated_until_ms = std::min(
      session.expires_ms,
      now_ms + static_cast<std::uint64_t>(elevation_ttl_seconds) * 1000U);
  ++metrics_.reused;
  ++metrics_.refreshed;
  updatePeak();
  return session;
}

LocalSessionResult
SessionManager::validate(const std::string &token, const std::uint64_t now_ms,
                         const bool require_elevated) const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (token.empty()) {
    return LocalSessionResult::Missing;
  }
  Entry *entry = const_cast<SessionManager *>(this)->find(digest(token));
  if (entry == nullptr) {
    ++metrics_.invalid;
    return LocalSessionResult::Invalid;
  }
  if (now_ms >= entry->expires_ms) {
    ++metrics_.expired;
    *entry = {};
    return LocalSessionResult::Expired;
  }
  if (require_elevated && now_ms >= entry->elevated_until_ms) {
    return LocalSessionResult::ElevationRequired;
  }
  entry->last_seen_ms = now_ms;
  return LocalSessionResult::Ok;
}

LocalSessionResult SessionManager::validateMutation(
    const std::string &token, const std::string &csrf,
    const std::uint64_t now_ms, const bool require_elevated) const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (token.empty()) {
    return LocalSessionResult::Missing;
  }
  Entry *entry = const_cast<SessionManager *>(this)->find(digest(token));
  if (entry == nullptr) {
    ++metrics_.invalid;
    return LocalSessionResult::Invalid;
  }
  if (now_ms >= entry->expires_ms) {
    ++metrics_.expired;
    *entry = {};
    return LocalSessionResult::Expired;
  }
  if (require_elevated && now_ms >= entry->elevated_until_ms) {
    return LocalSessionResult::ElevationRequired;
  }
  if (csrf.empty() || !digestEqual(entry->csrf_digest, digest(csrf))) {
    return LocalSessionResult::CsrfRejected;
  }
  entry->last_seen_ms = now_ms;
  return LocalSessionResult::Ok;
}

bool SessionManager::invalidate(const std::string &token,
                                const std::uint64_t now_ms) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (token.empty()) {
    return false;
  }
  Entry *entry = find(digest(token));
  if (entry == nullptr || now_ms >= entry->expires_ms) {
    return false;
  }
  *entry = {};
  ++metrics_.revoked;
  updatePeak();
  return true;
}

void SessionManager::invalidateAll() {
  std::lock_guard<std::mutex> lock(mutex_);
  for (Entry &entry : entries_) {
    entry = {};
  }
  updatePeak();
}

SessionManager::Metrics SessionManager::metrics(const std::uint64_t now_ms) const {
  std::lock_guard<std::mutex> lock(mutex_);
  const_cast<SessionManager *>(this)->purgeExpired(now_ms);
  const_cast<SessionManager *>(this)->updatePeak();
  return metrics_;
}

const char *localSessionResultCode(const LocalSessionResult result) {
  switch (result) {
  case LocalSessionResult::Ok:
    return "ok";
  case LocalSessionResult::Missing:
    return "local_session_missing";
  case LocalSessionResult::Invalid:
    return "local_session_invalid";
  case LocalSessionResult::Expired:
    return "local_session_expired";
  case LocalSessionResult::CsrfRejected:
    return "local_csrf_invalid";
  case LocalSessionResult::ElevationRequired:
    return "elevated_session_required";
  }
  return "local_session_invalid";
}

const char *requestAuthModeName(const RequestAuthMode mode) {
  switch (mode) {
  case RequestAuthMode::LocalBrowserSession:
    return "local_browser_session";
  case RequestAuthMode::ServerToDeviceHmac:
    return "server_to_device_hmac";
  case RequestAuthMode::Unauthenticated:
    return "unauthenticated";
  case RequestAuthMode::MalformedMixedAuthentication:
    return "malformed_mixed_authentication";
  }
  return "unauthenticated";
}

const char *authResultCode(const AuthResult result) {
  switch (result) {
  case AuthResult::Ok:
    return "ok";
  case AuthResult::MissingHeader:
    return "signature_headers_missing";
  case AuthResult::ProtocolMismatch:
    return "protocol_mismatch";
  case AuthResult::DeviceMismatch:
    return "device_mismatch";
  case AuthResult::TimestampInvalid:
    return "timestamp_invalid";
  case AuthResult::TimestampOutsideWindow:
    return "timestamp_outside_window";
  case AuthResult::NonceInvalid:
    return "nonce_invalid";
  case AuthResult::NonceReplayed:
    return "nonce_replayed";
  case AuthResult::NonceCapacityExceeded:
    return "nonce_window_capacity_exceeded";
  case AuthResult::BodyHashMismatch:
    return "body_hash_mismatch";
  case AuthResult::SignatureMismatch:
    return "signature_invalid";
  }
  return "authentication_failed";
}

} // namespace pm
