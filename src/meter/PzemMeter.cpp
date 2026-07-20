#include "meter/PzemMeter.h"

#include <array>

#include <Arduino.h>

#include "board_pins.h"
#include "meter/PzemProtocol.h"

namespace pm {

PzemMeter::PzemMeter(HardwareSerial& serial, const std::uint32_t timeout_ms,
                     const std::uint8_t retries)
    : serial_(serial), timeout_ms_(timeout_ms), retries_(retries) {}

bool PzemMeter::begin() {
  serial_.begin(pins::PZEM_BAUD, SERIAL_8N1, pins::PZEM_UART_RX,
                pins::PZEM_UART_TX);
  while (serial_.available() > 0) {
    serial_.read();
  }
  return true;
}

MeasurementSnapshot PzemMeter::poll(const std::uint64_t utc_ms,
                                    const std::uint64_t monotonic_ms,
                                    const bool time_trusted) {
  MeasurementSnapshot sample;
  sample.utc_ms = utc_ms;
  sample.monotonic_ms = monotonic_ms;
  sample.time_trusted = time_trusted;
  ++metrics_.requests;
  MeterError error = MeterError::Timeout;
  std::uint32_t latency = 0;
  for (std::uint8_t attempt = 0; attempt <= retries_; ++attempt) {
    error = transact(sample, latency);
    if (error == MeterError::None) {
      break;
    }
    if (attempt < retries_) {
      vTaskDelay(pdMS_TO_TICKS(20U << attempt));
    }
  }
  sample.latency_ms = latency;
  sample.error = error;
  sample.valid = error == MeterError::None;
  metrics_.last_latency_ms = latency;
  metrics_.last_error = error;
  if (error == MeterError::None) {
    ++metrics_.successes;
    metrics_.consecutive_errors = 0;
  } else {
    ++metrics_.consecutive_errors;
    sample.quality_flags |= MeterGap;
    if (error == MeterError::Timeout) {
      ++metrics_.timeouts;
    } else if (error == MeterError::CrcMismatch) {
      ++metrics_.crc_errors;
    } else {
      ++metrics_.invalid_frames;
    }
  }
  return sample;
}

MeterMetrics PzemMeter::metrics() const { return metrics_; }

const char* PzemMeter::methodName() const { return "pzem"; }

MeterError PzemMeter::transact(MeasurementSnapshot& result,
                               std::uint32_t& latency_ms) {
  while (serial_.available() > 0) {
    serial_.read();
  }
  const auto request = pzem::buildReadMeasurementRequest();
  const std::uint32_t started = millis();
  if (serial_.write(request.data(), request.size()) != request.size()) {
    return MeterError::UartFailure;
  }
  serial_.flush();
  std::array<std::uint8_t, pzem::RESPONSE_SIZE> response{};
  std::size_t received = 0;
  while (millis() - started < timeout_ms_ && received < response.size()) {
    while (serial_.available() > 0 && received < response.size()) {
      response[received++] = static_cast<std::uint8_t>(serial_.read());
    }
    if (received < response.size()) {
      vTaskDelay(pdMS_TO_TICKS(1));
    }
  }
  latency_ms = millis() - started;
  if (received == 0) {
    return MeterError::Timeout;
  }
  return pzem::parseMeasurementResponse(response.data(), received, result);
}

}  // namespace pm

