#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace pm::crypto {

using Key32 = std::array<std::uint8_t, 32>;

Key32 sha256(const std::uint8_t* data, std::size_t length);
std::string hexEncode(const std::uint8_t* data, std::size_t length);
bool hexDecode(const std::string& hex, std::vector<std::uint8_t>& output);
std::string sha256Hex(const std::uint8_t* data, std::size_t length);
Key32 hmacSha256(const std::uint8_t* key, std::size_t key_length,
                 const std::uint8_t* data, std::size_t data_length);
std::string hmacSha256Hex(const std::uint8_t* key, std::size_t key_length,
                          const std::string& data);
Key32 hkdfSha256(const std::uint8_t* secret, std::size_t secret_length,
                 const std::string& info);
bool constantTimeEqual(const std::string& left, const std::string& right);
void secureRandom(std::uint8_t* output, std::size_t length);
std::string randomHex(std::size_t bytes);
std::string uuidV4();
std::string percentEncode(const std::string& input);
std::string canonicalPathQuery(
    const std::string& path,
    const std::vector<std::pair<std::string, std::string>>& query);
std::string canonicalRequest(const std::string& method,
                             const std::string& path_query,
                             const std::string& timestamp,
                             const std::string& nonce,
                             const std::string& body_hash);
Key32 passwordHash(const std::string& password,
                   const std::array<std::uint8_t, 16>& salt,
                   std::uint32_t iterations);

}  // namespace pm::crypto

