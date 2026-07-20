#include "core/Algorithms.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <utility>

namespace pm {

bool retentionEligible(const bool complete_and_valid, const bool time_trusted,
                       const std::uint64_t newest_sequence,
                       const std::uint64_t server_ack_sequence,
                       const std::uint64_t newest_utc_ms,
                       const std::uint64_t cutoff_utc_ms) {
  return complete_and_valid && time_trusted && newest_sequence != 0 &&
         newest_sequence <= server_ack_sequence && newest_utc_ms != 0 &&
         cutoff_utc_ms != 0 && newest_utc_ms < cutoff_utc_ms;
}

std::uint32_t validateMeasurement(MeasurementSnapshot& sample,
                                  const Limits& limits) {
  std::uint32_t flags = sample.time_trusted ? QualityNone : TimeUntrusted;
  const bool finite = std::isfinite(sample.voltage_v) &&
                      std::isfinite(sample.current_a) &&
                      std::isfinite(sample.active_power_w) &&
                      std::isfinite(sample.frequency_hz) &&
                      std::isfinite(sample.power_factor);
  if (!finite || sample.voltage_v < 0.0F || sample.current_a < 0.0F ||
      sample.active_power_w < 0.0F || sample.power_factor < 0.0F ||
      sample.power_factor > 1.01F) {
    sample.valid = false;
    sample.error = MeterError::ImplausibleValue;
    sample.quality_flags = flags | MeterGap;
    return sample.quality_flags;
  }
  if (sample.voltage_v < limits.minimum_voltage_v ||
      sample.voltage_v > limits.maximum_voltage_v) {
    flags |= VoltageOutOfRange;
  }
  if (sample.frequency_hz < limits.minimum_frequency_hz ||
      sample.frequency_hz > limits.maximum_frequency_hz) {
    flags |= FrequencyOutOfRange;
  }
  if (sample.current_a >= limits.ct_rating_a * 1.10F) {
    flags |= CtOverRange;
  } else if (sample.current_a >= limits.ct_rating_a * 0.90F) {
    flags |= CtWarning90;
  } else if (sample.current_a >= limits.ct_rating_a * 0.80F) {
    flags |= CtWarning80;
  }
  sample.valid = (flags & (VoltageOutOfRange | FrequencyOutOfRange |
                           CtOverRange)) == 0U;
  sample.error = sample.valid ? MeterError::None : MeterError::ImplausibleValue;
  sample.quality_flags = flags | (sample.valid ? 0U : MeterGap);
  return sample.quality_flags;
}

EnergyNormalizer::EnergyNormalizer(const std::uint64_t persisted_offset_wh)
    : offset_wh_(persisted_offset_wh), last_lifetime_wh_(persisted_offset_wh) {}

EnergyResult EnergyNormalizer::update(
    const std::uint64_t raw_start_wh, const std::uint64_t raw_end_wh,
    const bool raw_start_valid, const bool raw_end_valid,
    const double integrated_power_wh, const bool integration_complete) {
  EnergyResult result;
  result.persisted_offset_wh = offset_wh_;
  if (raw_start_valid && raw_end_valid && raw_end_wh >= raw_start_wh) {
    result.interval_wh = static_cast<double>(raw_end_wh - raw_start_wh);
    result.method = "pzem_delta";
  } else if (raw_start_valid && raw_end_valid &&
             raw_start_wh > 0xFFF00000ULL && raw_end_wh < 0x00100000ULL) {
    constexpr std::uint64_t counter_range = 0x1'0000'0000ULL;
    offset_wh_ += counter_range;
    result.persisted_offset_wh = offset_wh_;
    result.offset_changed = true;
    result.interval_wh = static_cast<double>(counter_range - raw_start_wh + raw_end_wh);
    result.method = "pzem_rollover";
    result.quality_flags |= CounterRollover;
  } else if (raw_start_valid && raw_end_valid) {
    // A decreasing counter is treated as a reset/replacement. Preserve the
    // lifetime total by adding the previous raw value to the durable offset.
    offset_wh_ += raw_start_wh;
    result.persisted_offset_wh = offset_wh_;
    result.offset_changed = true;
    result.interval_wh = static_cast<double>(raw_end_wh);
    result.method = "pzem_reset";
    result.quality_flags |= CounterReset;
  } else if (integration_complete && integrated_power_wh >= 0.0) {
    result.interval_wh = integrated_power_wh;
    result.method = "power_integration";
    result.quality_flags |= EnergyIntegrated;
  } else {
    result.interval_wh = std::max(0.0, integrated_power_wh);
    result.method = "incomplete";
    result.quality_flags |= EnergyIncomplete;
  }
  if (raw_end_valid) {
    result.lifetime_wh = offset_wh_ + raw_end_wh;
  } else {
    result.lifetime_wh = last_lifetime_wh_ +
                         static_cast<std::uint64_t>(std::llround(result.interval_wh));
  }
  result.lifetime_wh = std::max(result.lifetime_wh, last_lifetime_wh_);
  last_lifetime_wh_ = result.lifetime_wh;
  return result;
}

std::uint64_t EnergyNormalizer::offsetWh() const { return offset_wh_; }

IntervalAggregator::IntervalAggregator(Limits limits)
    : limits_(std::move(limits)) {}

void IntervalAggregator::reset(const std::uint64_t start_utc_ms,
                               const std::uint64_t start_monotonic_ms) {
  start_utc_ms_ = start_utc_ms;
  start_monotonic_ms_ = start_monotonic_ms;
  samples_ = valid_samples_ = quality_ = 0;
  sum_voltage_ = sum_current_ = sum_power_ = sum_pf_ = sum_frequency_ = 0.0;
  integrated_wh_ = 0.0;
  min_voltage_ = min_current_ = min_power_ = std::numeric_limits<float>::max();
  max_voltage_ = max_current_ = max_power_ = std::numeric_limits<float>::lowest();
  raw_start_wh_ = raw_end_wh_ = previous_monotonic_ms_ = 0;
  previous_power_w_ = 0.0F;
  raw_start_valid_ = raw_end_valid_ = previous_power_valid_ = false;
  last_sample_seen_ = false;
  last_sample_monotonic_ms_ = 0;
  all_times_trusted_ = true;
}

void IntervalAggregator::add(const MeasurementSnapshot& sample) {
  if (last_sample_seen_ && sample.monotonic_ms <= last_sample_monotonic_ms_) {
    if (sample.monotonic_ms < last_sample_monotonic_ms_) quality_ |= MeterGap;
    return;
  }
  last_sample_seen_ = true;
  last_sample_monotonic_ms_ = sample.monotonic_ms;
  ++samples_;
  quality_ |= sample.quality_flags;
  all_times_trusted_ = all_times_trusted_ && sample.time_trusted;
  if (!sample.valid) {
    quality_ |= MeterGap;
    previous_power_valid_ = false;
    return;
  }
  ++valid_samples_;
  sum_voltage_ += sample.voltage_v;
  sum_current_ += sample.current_a;
  sum_power_ += sample.active_power_w;
  sum_pf_ += sample.power_factor;
  sum_frequency_ += sample.frequency_hz;
  min_voltage_ = std::min(min_voltage_, sample.voltage_v);
  max_voltage_ = std::max(max_voltage_, sample.voltage_v);
  min_current_ = std::min(min_current_, sample.current_a);
  max_current_ = std::max(max_current_, sample.current_a);
  min_power_ = std::min(min_power_, sample.active_power_w);
  max_power_ = std::max(max_power_, sample.active_power_w);
  if (!raw_start_valid_) {
    raw_start_wh_ = sample.raw_energy_wh;
    raw_start_valid_ = true;
  }
  raw_end_wh_ = sample.raw_energy_wh;
  raw_end_valid_ = true;
  if (previous_power_valid_ && sample.monotonic_ms > previous_monotonic_ms_) {
    const double hours = static_cast<double>(sample.monotonic_ms - previous_monotonic_ms_) /
                         3'600'000.0;
    integrated_wh_ +=
        (static_cast<double>(previous_power_w_) + sample.active_power_w) * 0.5 * hours;
  }
  previous_monotonic_ms_ = sample.monotonic_ms;
  previous_power_w_ = sample.active_power_w;
  previous_power_valid_ = true;
}

bool IntervalAggregator::hasSamples() const { return samples_ != 0; }

IntervalRecord IntervalAggregator::finish(
    const std::string& device_id, const std::string& friendly_name,
    const std::string& boot_id, const std::string& firmware_version,
    const std::uint64_t end_utc_ms, const std::uint64_t end_monotonic_ms,
    EnergyNormalizer& energy) {
  IntervalRecord record;
  record.device_id = device_id;
  record.friendly_name = friendly_name;
  record.boot_id = boot_id;
  record.firmware_version = firmware_version;
  record.start_utc_ms = start_utc_ms_;
  record.end_utc_ms = end_utc_ms;
  record.start_monotonic_ms = start_monotonic_ms_;
  record.end_monotonic_ms = end_monotonic_ms;
  record.time_trusted = all_times_trusted_ && start_utc_ms_ != 0 && end_utc_ms != 0;
  record.sample_count = samples_;
  record.valid_sample_count = valid_samples_;
  record.ct_rating_a = limits_.ct_rating_a;
  record.quality_flags = quality_ | (record.time_trusted ? 0U : TimeUntrusted);
  if (valid_samples_ > 0) {
    const double divisor = static_cast<double>(valid_samples_);
    record.avg_voltage_v = static_cast<float>(sum_voltage_ / divisor);
    record.min_voltage_v = min_voltage_;
    record.max_voltage_v = max_voltage_;
    record.avg_current_a = static_cast<float>(sum_current_ / divisor);
    record.min_current_a = min_current_;
    record.max_current_a = max_current_;
    record.avg_active_power_w = static_cast<float>(sum_power_ / divisor);
    record.min_active_power_w = min_power_;
    record.max_active_power_w = max_power_;
    record.avg_power_factor = static_cast<float>(sum_pf_ / divisor);
    record.avg_frequency_hz = static_cast<float>(sum_frequency_ / divisor);
  }
  record.raw_energy_start_wh = raw_start_wh_;
  record.raw_energy_end_wh = raw_end_wh_;
  const bool integration_complete = samples_ > 1 && valid_samples_ == samples_;
  const EnergyResult result =
      energy.update(raw_start_wh_, raw_end_wh_, raw_start_valid_, raw_end_valid_,
                    integrated_wh_, integration_complete);
  record.interval_energy_wh = result.interval_wh;
  record.device_lifetime_energy_wh = result.lifetime_wh;
  record.energy_method = result.method;
  record.quality_flags |= result.quality_flags;
  return record;
}

}  // namespace pm
