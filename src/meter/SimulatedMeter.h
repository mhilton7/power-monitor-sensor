#pragma once

#include "meter/IMeter.h"

namespace pm {

enum class SimulatedFault : std::uint8_t { None, Timeout, CrcError, EnergyReset };

class SimulatedMeter final : public IMeter {
 public:
  bool begin() override;
  MeasurementSnapshot poll(std::uint64_t utc_ms, std::uint64_t monotonic_ms,
                           bool time_trusted) override;
  MeterMetrics metrics() const override;
  const char* methodName() const override;
  void injectFault(SimulatedFault fault, std::uint32_t polls = 1);

 private:
  std::uint64_t poll_number_{0};
  double energy_wh_{1000.0};
  std::uint64_t previous_monotonic_ms_{0};
  SimulatedFault fault_{SimulatedFault::None};
  std::uint32_t fault_polls_remaining_{0};
  MeterMetrics metrics_;
};

}  // namespace pm

