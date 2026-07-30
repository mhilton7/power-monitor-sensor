#pragma once

#include <cstdint>
#include <string>

#include <IPAddress.h>
#include <WiFiClientSecure.h>

namespace pm {

// HTTPClient normally resolves its URL host a second time from inside
// WiFiClientSecure. That loses an address obtained through the explicit mDNS
// fallback. Pin the already-resolved address while still passing the original
// DNS name to mbedTLS for SNI and certificate hostname verification.
class ResolvedTlsClient final : public WiFiClientSecure {
public:
  void setResolvedEndpoint(const IPAddress &address,
                           const std::string &tls_hostname,
                           const std::uint16_t port) {
    resolved_address_ = address;
    tls_hostname_ = tls_hostname;
    port_ = port;
    configured_ = static_cast<std::uint32_t>(resolved_address_) != 0U &&
                  !tls_hostname_.empty() && port_ != 0U;
  }

  int connect(const char *host, const std::uint16_t port) override {
    return connect(host, port, _timeout);
  }

  int connect(const char *host, const std::uint16_t port,
              const int32_t timeout) override {
    _timeout = timeout;
    if (!configured_ || _CA_cert == nullptr || host == nullptr ||
        port != port_ || !sameHostname(host, tls_hostname_)) {
      return 0;
    }
    return WiFiClientSecure::connect(resolved_address_, port,
                                     tls_hostname_.c_str(), _CA_cert, _cert,
                                     _private_key);
  }

private:
  static bool sameHostname(const char *left, const std::string &right) {
    std::size_t index = 0;
    while (left[index] != '\0' && index < right.size()) {
      char left_character = left[index];
      char right_character = right[index];
      if (left_character >= 'A' && left_character <= 'Z') {
        left_character =
            static_cast<char>(left_character - static_cast<char>('A') + 'a');
      }
      if (right_character >= 'A' && right_character <= 'Z') {
        right_character =
            static_cast<char>(right_character - static_cast<char>('A') + 'a');
      }
      if (left_character != right_character) {
        return false;
      }
      ++index;
    }
    return left[index] == '\0' && index == right.size();
  }

  IPAddress resolved_address_;
  std::string tls_hostname_;
  std::uint16_t port_{0};
  bool configured_{false};
};

} // namespace pm
