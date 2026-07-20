#pragma once

#include <cstdint>

#include "core/Models.h"

namespace pm {

std::uint32_t validateMeasurement(MeasurementSnapshot& sample,
                                  const Limits& limits);
bool retentionEligible(bool complete_and_valid, bool time_trusted,
                       std::uint64_t newest_sequence,
                       std::uint64_t server_ack_sequence,
                       std::uint64_t newest_utc_ms,
                       std::uint64_t cutoff_utc_ms);

struct EnergyResult {
  double interval_wh{0.0};
  std::uint64_t lifetime_wh{0};
  std::uint64_t persisted_offset_wh{0};
  std::uint32_t quality_flags{QualityNone};
  const char* method{"unavailable"};
  bool offset_changed{false};
};

class EnergyNormalizer {
 public:
  explicit EnergyNormalizer(std::uint64_t persisted_offset_wh = 0);
  EnergyResult update(std::uint64_t raw_start_wh, std::uint64_t raw_end_wh,
                      bool raw_start_valid, bool raw_end_valid,
                      double integrated_power_wh, bool integration_complete);
  std::uint64_t offsetWh() const;

 private:
  std::uint64_t offset_wh_;
  std::uint64_t last_lifetime_wh_{0};
};

class IntervalAggregator {
 public:
  explicit IntervalAggregator(Limits limits);
  void reset(std::uint64_t start_utc_ms, std::uint64_t start_monotonic_ms);
  void add(const MeasurementSnapshot& sample);
  bool hasSamples() const;
  IntervalRecord finish(const std::string& device_id,
                        const std::string& friendly_name,
                        const std::string& boot_id,
                        const std::string& firmware_version,
                        std::uint64_t end_utc_ms,
                        std::uint64_t end_monotonic_ms,
                        EnergyNormalizer& energy);

 private:
  Limits limits_;
  std::uint64_t start_utc_ms_{0};
  std::uint64_t start_monotonic_ms_{0};
  std::uint32_t samples_{0};
  std::uint32_t valid_samples_{0};
  std::uint32_t quality_{QualityNone};
  double sum_voltage_{0.0};
  double sum_current_{0.0};
  double sum_power_{0.0};
  double sum_pf_{0.0};
  double sum_frequency_{0.0};
  double integrated_wh_{0.0};
  float min_voltage_{0.0F};
  float max_voltage_{0.0F};
  float min_current_{0.0F};
  float max_current_{0.0F};
  float min_power_{0.0F};
  float max_power_{0.0F};
  std::uint64_t raw_start_wh_{0};
  std::uint64_t raw_end_wh_{0};
  std::uint64_t previous_monotonic_ms_{0};
  float previous_power_w_{0.0F};
  bool raw_start_valid_{false};
  bool raw_end_valid_{false};
  bool previous_power_valid_{false};
  bool all_times_trusted_{true};
  bool last_sample_seen_{false};
  std::uint64_t last_sample_monotonic_ms_{0};
};

}  // namespace pm
