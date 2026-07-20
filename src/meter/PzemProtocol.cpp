#include "meter/PzemProtocol.h"

namespace pm {
namespace pzem {
namespace {

std::uint16_t readU16Be(const std::uint8_t* data) {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[0]) << 8U) |
                                    data[1]);
}

std::uint32_t readRegisterPair(const std::uint8_t* low_register) {
  return static_cast<std::uint32_t>(readU16Be(low_register)) |
         (static_cast<std::uint32_t>(readU16Be(low_register + 2)) << 16U);
}

}  // namespace

std::uint16_t modbusCrc16(const std::uint8_t* data, const std::size_t length) {
  std::uint16_t crc = 0xFFFFU;
  for (std::size_t pos = 0; pos < length; ++pos) {
    crc ^= data[pos];
    for (std::uint8_t bit = 0; bit < 8; ++bit) {
      const bool least_bit = (crc & 0x0001U) != 0U;
      crc >>= 1U;
      if (least_bit) {
        crc ^= 0xA001U;
      }
    }
  }
  return crc;
}

std::array<std::uint8_t, REQUEST_SIZE> buildReadMeasurementRequest(
    const std::uint8_t address) {
  std::array<std::uint8_t, REQUEST_SIZE> request{
      address, 0x04, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00};
  const std::uint16_t crc = modbusCrc16(request.data(), request.size() - 2);
  request[6] = static_cast<std::uint8_t>(crc & 0xFFU);
  request[7] = static_cast<std::uint8_t>(crc >> 8U);
  return request;
}

MeterError parseMeasurementResponse(const std::uint8_t* data,
                                    const std::size_t length,
                                    MeasurementSnapshot& result,
                                    const std::uint8_t address) {
  result.valid = false;
  if (length < 5) {
    return MeterError::ShortFrame;
  }
  if (data[0] != address) {
    return MeterError::WrongAddress;
  }
  if ((data[1] & 0x80U) != 0U) {
    return MeterError::ExceptionResponse;
  }
  if (data[1] != 0x04U) {
    return MeterError::WrongFunction;
  }
  if (data[2] != 20U || length != RESPONSE_SIZE) {
    return MeterError::InvalidByteCount;
  }
  const std::uint16_t expected_crc = modbusCrc16(data, length - 2);
  const std::uint16_t actual_crc =
      static_cast<std::uint16_t>(data[length - 2]) |
      (static_cast<std::uint16_t>(data[length - 1]) << 8U);
  if (expected_crc != actual_crc) {
    return MeterError::CrcMismatch;
  }
  const std::uint8_t* registers = data + 3;
  result.voltage_v = static_cast<float>(readU16Be(registers)) * 0.1F;
  result.current_a = static_cast<float>(readRegisterPair(registers + 2)) * 0.001F;
  result.active_power_w =
      static_cast<float>(readRegisterPair(registers + 6)) * 0.1F;
  result.raw_energy_wh = readRegisterPair(registers + 10);
  result.frequency_hz = static_cast<float>(readU16Be(registers + 14)) * 0.1F;
  result.power_factor = static_cast<float>(readU16Be(registers + 16)) * 0.01F;
  result.error = MeterError::None;
  result.valid = true;
  return MeterError::None;
}

}  // namespace pzem
}  // namespace pm
