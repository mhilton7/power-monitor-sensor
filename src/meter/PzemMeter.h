#pragma once

#include <HardwareSerial.h>

#include "meter/IMeter.h"

namespace pm {

class PzemMeter final : public IMeter {
 public:
  explicit PzemMeter(HardwareSerial& serial, std::uint32_t timeout_ms = 750,
                     std::uint8_t retries = 2);
  bool begin() override;
  MeasurementSnapshot poll(std::uint64_t utc_ms, std::uint64_t monotonic_ms,
                           bool time_trusted,
                           MeterWatchdogCallback watchdog_callback =
                               nullptr) override;
  MeterMetrics metrics() const override;
  const char* methodName() const override;

 private:
  MeterError transact(MeasurementSnapshot& result, std::uint32_t& latency_ms,
                      MeterWatchdogCallback watchdog_callback);

  HardwareSerial& serial_;
  std::uint32_t timeout_ms_;
  std::uint8_t retries_;
  MeterMetrics metrics_;
};

}  // namespace pm
