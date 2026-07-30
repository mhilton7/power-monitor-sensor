#include "meter/PzemMeter.h"

#include <array>
#include <cstdio>

#include <Arduino.h>

#include "board_pins.h"
#include "diagnostics/SerialLogger.h"
#include "meter/PzemProtocol.h"

namespace pm {

PzemMeter::PzemMeter(HardwareSerial &serial, const std::uint32_t timeout_ms,
                     const std::uint8_t retries)
    : serial_(serial), timeout_ms_(timeout_ms), retries_(retries) {}

bool PzemMeter::begin() {
  PM_LOG_INFO("PZEM", "UART_INIT_BEGIN",
              "uart=1 baud=%lu data_bits=8 parity=none stop_bits=1 rx_gpio=%d "
              "tx_gpio=%d timeout_ms=%lu retries=%u protocol=pzem-004t-v4",
              static_cast<unsigned long>(pins::PZEM_BAUD), pins::PZEM_UART_RX,
              pins::PZEM_UART_TX, static_cast<unsigned long>(timeout_ms_),
              static_cast<unsigned>(retries_));
  serial_.begin(pins::PZEM_BAUD, SERIAL_8N1, pins::PZEM_UART_RX,
                pins::PZEM_UART_TX);
  while (serial_.available() > 0) {
    serial_.read();
  }
  PM_LOG_INFO("PZEM", "UART_READY", "uart=1 protocol=modbus-rtu address=248");
  return true;
}

MeasurementSnapshot
PzemMeter::poll(const std::uint64_t utc_ms, const std::uint64_t monotonic_ms,
                const bool time_trusted,
                const MeterWatchdogCallback watchdog_callback) {
  MeasurementSnapshot sample;
  sample.utc_ms = utc_ms;
  sample.monotonic_ms = monotonic_ms;
  sample.time_trusted = time_trusted;
  ++metrics_.requests;
  MeterError error = MeterError::Timeout;
  std::uint32_t latency = 0;
  for (std::uint8_t attempt = 0; attempt <= retries_; ++attempt) {
    if (watchdog_callback != nullptr) {
      watchdog_callback();
    }
    error = transact(sample, latency, watchdog_callback);
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
  const std::uint32_t previous_errors = metrics_.consecutive_errors;
  if (error == MeterError::None) {
    ++metrics_.successes;
    metrics_.consecutive_errors = 0;
    if (previous_errors > 0) {
      PM_LOG_INFO("PZEM", "METER_RECOVERED",
                  "previous_consecutive_errors=%lu latency_ms=%lu",
                  static_cast<unsigned long>(previous_errors),
                  static_cast<unsigned long>(latency));
    }
    PM_LOG_TRACE(
        "PZEM", "READING",
        "voltage_v=%.1f current_a=%.3f active_power_w=%.1f energy_wh=%llu "
        "frequency_hz=%.1f power_factor=%.2f latency_ms=%lu",
        sample.voltage_v, sample.current_a, sample.active_power_w,
        static_cast<unsigned long long>(sample.raw_energy_wh),
        sample.frequency_hz, sample.power_factor,
        static_cast<unsigned long>(latency));
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
    char limiter_key[40]{};
    std::snprintf(limiter_key, sizeof(limiter_key), "pzem_error_%u",
                  static_cast<unsigned>(error));
    if (diag::SerialLogger::instance().allow(limiter_key, 10'000U)) {
      PM_LOG_WARN("PZEM", "READ_FAILED",
                  "error=%s numeric=%u consecutive=%lu latency_ms=%lu "
                  "retries=%u hint=%s",
                  meterErrorCode(error), static_cast<unsigned>(error),
                  static_cast<unsigned long>(metrics_.consecutive_errors),
                  static_cast<unsigned long>(latency),
                  static_cast<unsigned>(retries_),
                  error == MeterError::Timeout
                      ? "check_uart_wiring_meter_power_and_rx_tx_direction"
                      : (error == MeterError::CrcMismatch
                             ? "check_uart_noise_ground_and_baud"
                             : "inspect_modbus_frame_and_meter_address"));
    }
  }
  if (diag::SerialLogger::instance().allow("pzem_summary", 60'000U)) {
    PM_LOG_INFO("PZEM", "PERIODIC_SUMMARY",
                "requests=%llu successes=%llu timeouts=%llu crc_errors=%llu "
                "invalid_frames=%llu consecutive_errors=%lu last_error=%s "
                "last_latency_ms=%lu",
                static_cast<unsigned long long>(metrics_.requests),
                static_cast<unsigned long long>(metrics_.successes),
                static_cast<unsigned long long>(metrics_.timeouts),
                static_cast<unsigned long long>(metrics_.crc_errors),
                static_cast<unsigned long long>(metrics_.invalid_frames),
                static_cast<unsigned long>(metrics_.consecutive_errors),
                meterErrorCode(metrics_.last_error),
                static_cast<unsigned long>(metrics_.last_latency_ms));
  }
  publishMetrics();
  return sample;
}

MeterMetrics PzemMeter::metrics() const {
  portENTER_CRITICAL(&metrics_mux_);
  const MeterMetrics snapshot = published_metrics_;
  portEXIT_CRITICAL(&metrics_mux_);
  return snapshot;
}

void PzemMeter::publishMetrics() {
  portENTER_CRITICAL(&metrics_mux_);
  published_metrics_ = metrics_;
  portEXIT_CRITICAL(&metrics_mux_);
}

const char *PzemMeter::methodName() const { return "pzem"; }

MeterError PzemMeter::transact(MeasurementSnapshot &result,
                               std::uint32_t &latency_ms,
                               const MeterWatchdogCallback watchdog_callback) {
  while (serial_.available() > 0) {
    serial_.read();
  }
  const auto request = pzem::buildReadMeasurementRequest();
  PM_LOG_TRACE("PZEM", "UART_TX",
               "bytes=8 hex=%02X%02X%02X%02X%02X%02X%02X%02X", request[0],
               request[1], request[2], request[3], request[4], request[5],
               request[6], request[7]);
  const std::uint32_t started = millis();
  if (serial_.write(request.data(), request.size()) != request.size()) {
    return MeterError::UartFailure;
  }
  serial_.flush();
  std::array<std::uint8_t, pzem::RESPONSE_SIZE> response{};
  std::size_t received = 0;
  std::uint32_t last_watchdog_ms = started;
  while (millis() - started < timeout_ms_ && received < response.size()) {
    while (serial_.available() > 0 && received < response.size()) {
      response[received++] = static_cast<std::uint8_t>(serial_.read());
    }
    if (received < response.size()) {
      vTaskDelay(pdMS_TO_TICKS(1));
    }
    if (watchdog_callback != nullptr && millis() - last_watchdog_ms >= 250U) {
      watchdog_callback();
      last_watchdog_ms = millis();
    }
  }
  latency_ms = millis() - started;
  if (received > 0) {
    char frame[3 * pzem::RESPONSE_SIZE + 1]{};
    std::size_t cursor = 0;
    for (std::size_t index = 0; index < received && cursor + 3U < sizeof(frame);
         ++index) {
      cursor += static_cast<std::size_t>(std::snprintf(
          frame + cursor, sizeof(frame) - cursor, "%02X", response[index]));
    }
    PM_LOG_TRACE("PZEM", "UART_RX", "bytes=%u latency_ms=%lu hex=%s",
                 static_cast<unsigned>(received),
                 static_cast<unsigned long>(latency_ms), frame);
  }
  if (received == 0) {
    return MeterError::Timeout;
  }
  return pzem::parseMeasurementResponse(response.data(), received, result);
}

} // namespace pm
