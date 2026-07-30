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

SessionManager::Session SessionManager::create(const std::uint64_t now_ms,
                                               const std::uint32_t ttl_seconds,
                                               const bool elevated) {
  session_.token = crypto::randomHex(32);
  session_.csrf = crypto::randomHex(24);
  session_.expires_ms =
      now_ms + static_cast<std::uint64_t>(ttl_seconds) * 1000U;
  session_.elevated = elevated;
  return session_;
}

bool SessionManager::validate(const std::string &token,
                              const std::uint64_t now_ms) const {
  return now_ms < session_.expires_ms && !session_.token.empty() &&
         crypto::constantTimeEqual(token, session_.token);
}

bool SessionManager::validateMutation(const std::string &token,
                                      const std::string &csrf,
                                      const std::uint64_t now_ms) const {
  return validate(token, now_ms) && !session_.csrf.empty() &&
         crypto::constantTimeEqual(csrf, session_.csrf);
}

bool SessionManager::validateElevated(const std::string &token,
                                      const std::uint64_t now_ms) const {
  return session_.elevated && validate(token, now_ms);
}

bool SessionManager::validateElevatedMutation(
    const std::string &token, const std::string &csrf,
    const std::uint64_t now_ms) const {
  return session_.elevated && validateMutation(token, csrf, now_ms);
}

void SessionManager::invalidate() { session_ = {}; }

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
