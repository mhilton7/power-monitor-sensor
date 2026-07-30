#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/Models.h"

namespace pm {
namespace pzem {

constexpr std::uint8_t DEFAULT_ADDRESS = 0xF8;
constexpr std::size_t REQUEST_SIZE = 8;
constexpr std::size_t RESPONSE_SIZE = 25;

std::uint16_t modbusCrc16(const std::uint8_t *data, std::size_t length);
std::array<std::uint8_t, REQUEST_SIZE>
buildReadMeasurementRequest(std::uint8_t address = DEFAULT_ADDRESS);
MeterError parseMeasurementResponse(const std::uint8_t *data,
                                    std::size_t length,
                                    MeasurementSnapshot &result,
                                    std::uint8_t address = DEFAULT_ADDRESS);

} // namespace pzem
} // namespace pm
