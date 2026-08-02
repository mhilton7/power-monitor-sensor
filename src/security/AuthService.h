#pragma once

#include <array>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "core/StringView.h"

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

enum class RequestAuthMode : std::uint8_t {
  LocalBrowserSession,
  ServerToDeviceHmac,
  Unauthenticated,
  MalformedMixedAuthentication,
};

const char *requestAuthModeName(RequestAuthMode mode);

enum class LocalSessionResult : std::uint8_t {
  Ok,
  Missing,
  Invalid,
  Expired,
  CsrfRejected,
  ElevationRequired,
};

const char *localSessionResultCode(LocalSessionResult result);

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
  static constexpr std::size_t kCapacity = 6U;

  struct Session {
    std::string token;
    std::string csrf;
    std::uint64_t expires_ms{0};
    bool elevated{false};
    bool reused{false};
    bool refreshed{false};
    bool capacity_reached{false};
  };

  struct Metrics {
    std::uint32_t capacity{kCapacity};
    std::uint32_t active{0};
    std::uint32_t peak_active{0};
    std::uint64_t created{0};
    std::uint64_t reused{0};
    std::uint64_t refreshed{0};
    std::uint64_t expired{0};
    std::uint64_t invalid{0};
    std::uint64_t revoked{0};
    std::uint64_t capacity_rejections{0};
  };

  Session open(const std::string &presented_token, std::uint64_t now_ms,
               std::uint32_t ttl_seconds);
  Session elevate(const std::string &presented_token, std::uint64_t now_ms,
                  std::uint32_t ttl_seconds,
                  std::uint32_t elevation_ttl_seconds);
  LocalSessionResult validate(StringView token, std::uint64_t now_ms,
                              bool require_elevated = false) const;
  LocalSessionResult validateMutation(StringView token, StringView csrf,
                                      std::uint64_t now_ms,
                                      bool require_elevated = false) const;
  bool invalidate(const std::string &token, std::uint64_t now_ms);
  void invalidateAll();
  Metrics metrics(std::uint64_t now_ms) const;

private:
  struct Entry {
    bool used{false};
    crypto::Key32 token_digest{};
    crypto::Key32 csrf_digest{};
    std::uint64_t created_ms{0};
    std::uint64_t last_seen_ms{0};
    std::uint64_t expires_ms{0};
    std::uint64_t elevated_until_ms{0};
    std::uint32_t generation{0};
  };

  static crypto::Key32 digest(StringView value);
  static bool digestEqual(const crypto::Key32 &left,
                          const crypto::Key32 &right);
  Entry *find(const crypto::Key32 &token_digest);
  const Entry *find(const crypto::Key32 &token_digest) const;
  void purgeExpired(std::uint64_t now_ms);
  void updatePeak();

  mutable std::mutex mutex_;
  mutable std::array<Entry, kCapacity> entries_{};
  mutable Metrics metrics_{};
  std::uint32_t next_generation_{1};
};

const char *authResultCode(AuthResult result);

} // namespace pm
