#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace pm {
namespace record {

constexpr char PREFIX[] = "PMR1\t";
std::uint32_t crc32(const std::uint8_t *data, std::size_t length);
std::string encodeEnvelope(const std::string &canonical_json);
bool decodeEnvelope(const std::string &line, std::string &canonical_json,
                    std::uint32_t &stored_crc);

} // namespace record
} // namespace pm
