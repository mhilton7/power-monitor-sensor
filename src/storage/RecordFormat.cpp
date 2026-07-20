#include "storage/RecordFormat.h"

#include <cstdio>

namespace pm {
namespace record {

std::uint32_t crc32(const std::uint8_t* data, const std::size_t length) {
  std::uint32_t crc = 0xFFFFFFFFU;
  for (std::size_t i = 0; i < length; ++i) {
    crc ^= data[i];
    for (std::uint8_t bit = 0; bit < 8; ++bit) {
      const std::uint32_t mask = 0U - (crc & 1U);
      crc = (crc >> 1U) ^ (0xEDB88320U & mask);
    }
  }
  return ~crc;
}

std::string encodeEnvelope(const std::string& canonical_json) {
  const std::uint32_t checksum =
      crc32(reinterpret_cast<const std::uint8_t*>(canonical_json.data()),
            canonical_json.size());
  char suffix[12]{};
  std::snprintf(suffix, sizeof(suffix), "\t%08x\n", checksum);
  return std::string(PREFIX) + canonical_json + suffix;
}

bool decodeEnvelope(const std::string& line, std::string& canonical_json,
                    std::uint32_t& stored_crc) {
  if (line.rfind(PREFIX, 0) != 0 || line.empty() || line.back() != '\n') {
    return false;
  }
  const std::size_t separator = line.rfind('\t', line.size() - 2);
  if (separator == std::string::npos || line.size() - separator != 10) {
    return false;
  }
  unsigned int parsed = 0;
  if (std::sscanf(line.c_str() + separator + 1, "%8x", &parsed) != 1) {
    return false;
  }
  canonical_json = line.substr(sizeof(PREFIX) - 1, separator - (sizeof(PREFIX) - 1));
  stored_crc = static_cast<std::uint32_t>(parsed);
  return stored_crc ==
         crc32(reinterpret_cast<const std::uint8_t*>(canonical_json.data()),
               canonical_json.size());
}

}  // namespace record
}  // namespace pm
