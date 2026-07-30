#include "meter/SimulatedMeter.h"

#include <cmath>

namespace pm {

bool SimulatedMeter::begin() {
  poll_number_ = 0;
  previous_monotonic_ms_ = 0;
  metrics_ = {};
  publishMetrics();
  return true;
}

MeasurementSnapshot
SimulatedMeter::poll(const std::uint64_t utc_ms,
                     const std::uint64_t monotonic_ms, const bool time_trusted,
                     const MeterWatchdogCallback watchdog_callback) {
  if (watchdog_callback != nullptr) {
    watchdog_callback();
  }
  ++metrics_.requests;
  ++poll_number_;
  MeasurementSnapshot sample;
  sample.utc_ms = utc_ms;
  sample.monotonic_ms = monotonic_ms;
  sample.time_trusted = time_trusted;
  sample.latency_ms = 2;
  if (fault_polls_remaining_ > 0) {
    --fault_polls_remaining_;
    sample.error = fault_ == SimulatedFault::CrcError ? MeterError::CrcMismatch
                                                      : MeterError::Timeout;
    sample.quality_flags = MeterGap | (time_trusted ? 0U : TimeUntrusted);
    ++metrics_.consecutive_errors;
    metrics_.last_error = sample.error;
    if (sample.error == MeterError::CrcMismatch) {
      ++metrics_.crc_errors;
    } else {
      ++metrics_.timeouts;
    }
    if (fault_polls_remaining_ == 0) {
      fault_ = SimulatedFault::None;
    }
    publishMetrics();
    return sample;
  }
  const double phase = static_cast<double>(poll_number_ % 300U) * 0.020943951;
  sample.voltage_v = static_cast<float>(121.0 + 0.8 * std::sin(phase));
  sample.current_a = static_cast<float>(7.0 + 1.2 * std::sin(phase * 0.5));
  sample.power_factor =
      static_cast<float>(0.96 + 0.02 * std::sin(phase * 0.25));
  sample.active_power_w =
      sample.voltage_v * sample.current_a * sample.power_factor;
  sample.frequency_hz = static_cast<float>(60.0 + 0.02 * std::sin(phase * 0.1));
  if (previous_monotonic_ms_ != 0 && monotonic_ms > previous_monotonic_ms_) {
    energy_wh_ += static_cast<double>(sample.active_power_w) *
                  static_cast<double>(monotonic_ms - previous_monotonic_ms_) /
                  3'600'000.0;
  }
  previous_monotonic_ms_ = monotonic_ms;
  if (fault_ == SimulatedFault::EnergyReset) {
    energy_wh_ = 0.0;
    fault_ = SimulatedFault::None;
  }
  sample.raw_energy_wh = static_cast<std::uint64_t>(energy_wh_);
  sample.error = MeterError::None;
  sample.valid = true;
  sample.quality_flags = time_trusted ? QualityNone : TimeUntrusted;
  ++metrics_.successes;
  metrics_.consecutive_errors = 0;
  metrics_.last_error = MeterError::None;
  metrics_.last_latency_ms = sample.latency_ms;
  publishMetrics();
  return sample;
}

MeterMetrics SimulatedMeter::metrics() const {
  portENTER_CRITICAL(&metrics_mux_);
  const MeterMetrics snapshot = published_metrics_;
  portEXIT_CRITICAL(&metrics_mux_);
  return snapshot;
}

void SimulatedMeter::publishMetrics() {
  portENTER_CRITICAL(&metrics_mux_);
  published_metrics_ = metrics_;
  portEXIT_CRITICAL(&metrics_mux_);
}

const char *SimulatedMeter::methodName() const { return "simulated"; }

void SimulatedMeter::injectFault(const SimulatedFault fault,
                                 const std::uint32_t polls) {
  fault_ = fault;
  fault_polls_remaining_ = fault == SimulatedFault::EnergyReset ? 0 : polls;
}

} // namespace pm
