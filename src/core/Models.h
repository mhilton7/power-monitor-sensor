#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace pm {

enum class MeterError : std::uint8_t {
  None = 0,
  Timeout,
  ShortFrame,
  WrongAddress,
  WrongFunction,
  ExceptionResponse,
  InvalidByteCount,
  CrcMismatch,
  ImplausibleValue,
  UartFailure,
};

enum QualityFlag : std::uint32_t {
  QualityNone = 0,
  TimeUntrusted = 1U << 0U,
  MeterGap = 1U << 1U,
  EnergyIntegrated = 1U << 2U,
  EnergyIncomplete = 1U << 3U,
  CounterReset = 1U << 4U,
  CtWarning80 = 1U << 5U,
  CtWarning90 = 1U << 6U,
  CtOverRange = 1U << 7U,
  VoltageOutOfRange = 1U << 8U,
  FrequencyOutOfRange = 1U << 9U,
  CounterRollover = 1U << 10U,
};

struct MeasurementSnapshot {
  std::uint64_t utc_ms{0};
  std::uint64_t monotonic_ms{0};
  std::uint64_t raw_energy_wh{0};
  std::uint64_t device_lifetime_energy_wh{0};
  float voltage_v{0.0F};
  float current_a{0.0F};
  float active_power_w{0.0F};
  float frequency_hz{0.0F};
  float power_factor{0.0F};
  std::uint32_t latency_ms{0};
  std::uint32_t quality_flags{QualityNone};
  MeterError error{MeterError::None};
  bool valid{false};
  bool time_trusted{false};
};

struct Limits {
  float ct_rating_a{100.0F};
  float ct_warning_fraction{0.8F};
  float ct_critical_fraction{0.9F};
  float ct_fault_fraction{1.1F};
  float minimum_voltage_v{80.0F};
  float maximum_voltage_v{280.0F};
  float minimum_frequency_hz{45.0F};
  float maximum_frequency_hz{65.0F};
};

struct IntervalRecord {
  std::uint32_t schema_version{1};
  std::string device_id;
  std::string friendly_name;
  std::uint64_t sequence{0};
  std::string boot_id;
  std::uint64_t start_utc_ms{0};
  std::uint64_t end_utc_ms{0};
  std::uint64_t start_monotonic_ms{0};
  std::uint64_t end_monotonic_ms{0};
  bool time_trusted{false};
  std::uint32_t sample_count{0};
  std::uint32_t valid_sample_count{0};
  float avg_voltage_v{0.0F};
  float min_voltage_v{0.0F};
  float max_voltage_v{0.0F};
  float avg_current_a{0.0F};
  float min_current_a{0.0F};
  float max_current_a{0.0F};
  float avg_active_power_w{0.0F};
  float min_active_power_w{0.0F};
  float max_active_power_w{0.0F};
  float avg_power_factor{0.0F};
  float avg_frequency_hz{0.0F};
  std::uint64_t raw_energy_start_wh{0};
  std::uint64_t raw_energy_end_wh{0};
  std::uint64_t device_lifetime_energy_wh{0};
  double interval_energy_wh{0.0};
  std::string energy_method{"unavailable"};
  float ct_rating_a{100.0F};
  std::uint32_t quality_flags{QualityNone};
  std::string firmware_version;
};

const char* meterErrorCode(MeterError error);

}  // namespace pm
