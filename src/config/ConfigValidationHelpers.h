#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace pm {
namespace config_validation {

std::string normalizePemLineEndings(const std::string &pem);
bool containsPrivateKeyPem(const std::string &pem);
bool decodeEd25519PublicKeyPem(const std::string &pem,
                               std::array<std::uint8_t, 32> &public_key);
bool validEd25519PublicKeyPem(const std::string &pem);
bool validHttpsBaseUrl(const std::string &url);

} // namespace config_validation
} // namespace pm
