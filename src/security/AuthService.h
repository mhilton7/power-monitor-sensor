#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "security/AuthReplayWindow.h"
#include "security/Crypto.h"

namespace pm {

struct AuthHeaders {
  std::string protocol;
  std::string device_id;
  std::string timestamp;
  std::string nonce;
  std::string content_sha256;
  std::string signature;
};

enum class AuthResult : std::uint8_t {
  Ok,
  MissingHeader,
  ProtocolMismatch,
  DeviceMismatch,
  TimestampInvalid,
  TimestampOutsideWindow,
  NonceInvalid,
  NonceReplayed,
  NonceCapacityExceeded,
  BodyHashMismatch,
  SignatureMismatch,
};

class NonceCache {
public:
  ReplayRememberResult checkAndRemember(const std::string &nonce,
                                        std::int64_t now,
                                        std::uint32_t window_seconds);

private:
  static constexpr std::size_t kCapacity = 256U;
  AuthReplayWindow<crypto::Key32, kCapacity> window_;
};

class RequestAuthenticator {
public:
  AuthResult
  verify(const std::string &method, const std::string &path,
         const std::vector<std::pair<std::string, std::string>> &query,
         const std::uint8_t *body, std::size_t body_length,
         const AuthHeaders &headers, const std::string &expected_device_id,
         const crypto::Key32 &key, std::int64_t now_seconds,
         bool time_synchronized);

private:
  NonceCache nonce_cache_;
};

class SessionManager {
public:
  struct Session {
    std::string token;
    std::string csrf;
    std::uint64_t expires_ms{0};
    bool elevated{false};
  };

  Session create(std::uint64_t now_ms, std::uint32_t ttl_seconds,
                 bool elevated = false);
  bool validate(const std::string &token, std::uint64_t now_ms) const;
  bool validateMutation(const std::string &token, const std::string &csrf,
                        std::uint64_t now_ms) const;
  bool validateElevated(const std::string &token, std::uint64_t now_ms) const;
  bool validateElevatedMutation(const std::string &token,
                                const std::string &csrf,
                                std::uint64_t now_ms) const;
  void invalidate();

private:
  Session session_;
};

const char *authResultCode(AuthResult result);

} // namespace pm
