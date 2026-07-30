#include "config/ConfigValidationHelpers.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace pm {
namespace config_validation {
namespace {

bool validPort(const std::string &port) {
  if (port.empty() ||
      !std::all_of(port.begin(), port.end(), [](const unsigned char value) {
        return std::isdigit(value) != 0;
      })) {
    return false;
  }
  std::uint32_t numeric = 0;
  for (const char digit : port) {
    numeric = numeric * 10U + static_cast<std::uint32_t>(digit - '0');
    if (numeric > 65535U)
      return false;
  }
  return numeric >= 1U;
}

bool validIpv4Host(const std::string &host) {
  std::size_t cursor = 0;
  int parts = 0;
  while (cursor < host.size()) {
    const std::size_t dot = host.find('.', cursor);
    const std::size_t end = dot == std::string::npos ? host.size() : dot;
    if (end == cursor || end - cursor > 3)
      return false;
    std::uint32_t value = 0;
    for (std::size_t index = cursor; index < end; ++index) {
      if (!std::isdigit(static_cast<unsigned char>(host[index]))) {
        return false;
      }
      value = value * 10U + static_cast<std::uint32_t>(host[index] - '0');
    }
    if (value > 255U)
      return false;
    ++parts;
    if (dot == std::string::npos)
      break;
    cursor = dot + 1U;
  }
  return parts == 4;
}

bool validDnsHost(const std::string &host) {
  if (host.empty() || host.size() > 253 || host.front() == '.' ||
      host.back() == '.') {
    return false;
  }
  bool all_numeric_or_dot = true;
  std::size_t cursor = 0;
  while (cursor < host.size()) {
    const std::size_t dot = host.find('.', cursor);
    const std::size_t end = dot == std::string::npos ? host.size() : dot;
    if (end == cursor || end - cursor > 63 || host[cursor] == '-' ||
        host[end - 1U] == '-') {
      return false;
    }
    for (std::size_t index = cursor; index < end; ++index) {
      const unsigned char value = static_cast<unsigned char>(host[index]);
      if (!std::isalnum(value) && value != '-')
        return false;
      if (!std::isdigit(value))
        all_numeric_or_dot = false;
    }
    if (dot == std::string::npos)
      break;
    cursor = dot + 1U;
  }
  return !all_numeric_or_dot || validIpv4Host(host);
}

int base64Value(const unsigned char value) {
  if (value >= 'A' && value <= 'Z')
    return value - 'A';
  if (value >= 'a' && value <= 'z')
    return value - 'a' + 26;
  if (value >= '0' && value <= '9')
    return value - '0' + 52;
  if (value == '+')
    return 62;
  if (value == '/')
    return 63;
  return -1;
}

bool decodeBase64Strict(const std::string &encoded,
                        std::vector<std::uint8_t> &decoded) {
  decoded.clear();
  if (encoded.empty() || encoded.size() % 4U != 0U)
    return false;
  decoded.reserve(encoded.size() / 4U * 3U);
  for (std::size_t index = 0; index < encoded.size(); index += 4U) {
    const bool final_group = index + 4U == encoded.size();
    const bool pad2 = encoded[index + 2U] == '=';
    const bool pad3 = encoded[index + 3U] == '=';
    if ((!final_group && (pad2 || pad3)) || (pad2 && !pad3))
      return false;
    const int a = base64Value(static_cast<unsigned char>(encoded[index]));
    const int b = base64Value(static_cast<unsigned char>(encoded[index + 1U]));
    const int c =
        pad2 ? 0 : base64Value(static_cast<unsigned char>(encoded[index + 2U]));
    const int d =
        pad3 ? 0 : base64Value(static_cast<unsigned char>(encoded[index + 3U]));
    if (a < 0 || b < 0 || c < 0 || d < 0)
      return false;
    decoded.push_back(static_cast<std::uint8_t>((a << 2U) | (b >> 4U)));
    if (!pad2) {
      decoded.push_back(static_cast<std::uint8_t>((b << 4U) | (c >> 2U)));
    }
    if (!pad3) {
      decoded.push_back(static_cast<std::uint8_t>((c << 6U) | d));
    }
  }
  return true;
}

} // namespace

std::string normalizePemLineEndings(const std::string &pem) {
  std::string normalized;
  normalized.reserve(pem.size() + 1U);
  for (std::size_t index = 0; index < pem.size(); ++index) {
    if (pem[index] == '\r') {
      normalized.push_back('\n');
      if (index + 1U < pem.size() && pem[index + 1U] == '\n') {
        ++index;
      }
    } else {
      normalized.push_back(pem[index]);
    }
  }
  if (!normalized.empty() && normalized.back() != '\n') {
    normalized.push_back('\n');
  }
  return normalized;
}

bool containsPrivateKeyPem(const std::string &pem) {
  return pem.find("-----BEGIN "
                  "PRIVATE KEY-----") != std::string::npos ||
         pem.find("-----BEGIN RSA "
                  "PRIVATE KEY-----") != std::string::npos ||
         pem.find("-----BEGIN EC "
                  "PRIVATE KEY-----") != std::string::npos ||
         pem.find("-----BEGIN ENCRYPTED "
                  "PRIVATE KEY-----") != std::string::npos;
}

bool decodeEd25519PublicKeyPem(const std::string &pem,
                               std::array<std::uint8_t, 32> &public_key) {
  public_key.fill(0U);
  static constexpr char begin[] = "-----BEGIN PUBLIC KEY-----\n";
  static constexpr char end[] = "-----END PUBLIC KEY-----\n";
  static constexpr std::array<std::uint8_t, 12> spki_prefix{
      0x30U, 0x2aU, 0x30U, 0x05U, 0x06U, 0x03U,
      0x2bU, 0x65U, 0x70U, 0x03U, 0x21U, 0x00U};
  const std::string normalized = normalizePemLineEndings(pem);
  if (normalized.size() <= sizeof(begin) + sizeof(end) - 2U ||
      normalized.compare(0, sizeof(begin) - 1U, begin) != 0 ||
      normalized.compare(normalized.size() - (sizeof(end) - 1U),
                         sizeof(end) - 1U, end) != 0) {
    return false;
  }
  const std::size_t body_start = sizeof(begin) - 1U;
  const std::size_t body_length =
      normalized.size() - body_start - (sizeof(end) - 1U);
  std::string encoded;
  encoded.reserve(body_length);
  for (std::size_t index = body_start; index < body_start + body_length;
       ++index) {
    const unsigned char value = static_cast<unsigned char>(normalized[index]);
    if (value == '\n')
      continue;
    if (std::isspace(value) || std::iscntrl(value))
      return false;
    encoded.push_back(static_cast<char>(value));
  }
  std::vector<std::uint8_t> decoded;
  if (!decodeBase64Strict(encoded, decoded) ||
      decoded.size() != spki_prefix.size() + public_key.size() ||
      !std::equal(spki_prefix.begin(), spki_prefix.end(), decoded.begin())) {
    public_key.fill(0U);
    return false;
  }
  std::copy(decoded.begin() + static_cast<std::ptrdiff_t>(spki_prefix.size()),
            decoded.end(), public_key.begin());
  std::fill(decoded.begin(), decoded.end(), std::uint8_t{0});
  return true;
}

bool validEd25519PublicKeyPem(const std::string &pem) {
  std::array<std::uint8_t, 32> public_key{};
  const bool valid = decodeEd25519PublicKeyPem(pem, public_key);
  public_key.fill(0U);
  return valid;
}

bool validHttpsBaseUrl(const std::string &url) {
  constexpr char prefix[] = "https://";
  if (url.compare(0, sizeof(prefix) - 1U, prefix) != 0 ||
      url.size() == sizeof(prefix) - 1U) {
    return false;
  }
  const std::string authority = url.substr(sizeof(prefix) - 1U);
  if (authority.find_first_of("/?#\\@") != std::string::npos ||
      std::any_of(authority.begin(), authority.end(),
                  [](const unsigned char value) {
                    return std::isspace(value) || std::iscntrl(value);
                  })) {
    return false;
  }

  std::string host;
  std::string port;
  bool explicit_port = false;
  if (authority.front() == '[') {
    // The pinned Arduino WiFiClientSecure and deterministic preconnect path
    // are IPv4-only. Reject IPv6 origins instead of accepting an unreachable
    // production configuration.
    return false;
  } else {
    const std::size_t colon = authority.rfind(':');
    if (colon != std::string::npos) {
      if (authority.find(':') != colon)
        return false;
      explicit_port = true;
      host = authority.substr(0, colon);
      port = authority.substr(colon + 1U);
    } else {
      host = authority;
    }
    if (!validDnsHost(host))
      return false;
  }
  return !explicit_port || validPort(port);
}

} // namespace config_validation
} // namespace pm
