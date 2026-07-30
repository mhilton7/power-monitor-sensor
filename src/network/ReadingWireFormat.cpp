#include "network/ReadingWireFormat.h"

#include <array>
#include <cmath>
#include <cstdint>
#include <limits>
#include <utility>

#include "core/Models.h"

namespace pm {
namespace reading_wire {
namespace {

void addQualityFlags(const std::uint32_t flags, JsonArray output) {
  const std::array<std::pair<std::uint32_t, const char *>, 11> names{{
      {TimeUntrusted, "time_untrusted"},
      {MeterGap, "meter_gap"},
      {EnergyIntegrated, "energy_integrated"},
      {EnergyIncomplete, "energy_incomplete"},
      {CounterReset, "counter_reset"},
      {CtWarning80, "ct_warning_80"},
      {CtWarning90, "ct_warning_90"},
      {CtOverRange, "ct_over_range"},
      {VoltageOutOfRange, "voltage_out_of_range"},
      {FrequencyOutOfRange, "frequency_out_of_range"},
      {CounterRollover, "counter_rollover"},
  }};
  for (const auto &item : names) {
    if ((flags & item.first) != 0U)
      output.add(item.second);
  }
}

void setUnavailableMeasurements(JsonObject record) {
  record["voltage_avg"] = nullptr;
  record["voltage_min"] = nullptr;
  record["voltage_max"] = nullptr;
  record["current_avg"] = nullptr;
  record["current_min"] = nullptr;
  record["current_max"] = nullptr;
  record["power_avg"] = nullptr;
  record["power_min"] = nullptr;
  record["power_max"] = nullptr;
  record["power_factor"] = nullptr;
  record["frequency_hz"] = nullptr;
  record["pzem_energy_start_wh"] = nullptr;
  record["pzem_energy_end_wh"] = nullptr;
  record["device_lifetime_energy_wh"] = nullptr;
  record["interval_energy_wh"] = nullptr;
}

bool boundedNumber(const JsonVariantConst value, const double minimum,
                   const double maximum) {
  if (!value.is<double>())
    return false;
  const double number = value.as<double>();
  return std::isfinite(number) && number >= minimum && number <= maximum;
}

std::uint32_t serverContractViolationFlags(const JsonDocument &source) {
  std::uint32_t flags = QualityNone;
  if (!boundedNumber(source["voltage_v"]["average"], 0.0, 400.0) ||
      !boundedNumber(source["voltage_v"]["minimum"], 0.0, 400.0) ||
      !boundedNumber(source["voltage_v"]["maximum"], 0.0, 400.0)) {
    flags |= MeterGap | VoltageOutOfRange;
  }
  if (!boundedNumber(source["average_frequency_hz"], 40.0, 70.0)) {
    flags |= MeterGap | FrequencyOutOfRange;
  }
  if (!boundedNumber(source["average_power_factor"], 0.0, 1.0) ||
      !boundedNumber(source["current_a"]["average"], 0.0, 5000.0) ||
      !boundedNumber(source["current_a"]["minimum"], 0.0, 5000.0) ||
      !boundedNumber(source["current_a"]["maximum"], 0.0, 5000.0) ||
      !boundedNumber(source["active_power_w"]["average"], 0.0, 10'000'000.0) ||
      !boundedNumber(source["active_power_w"]["minimum"], 0.0, 10'000'000.0) ||
      !boundedNumber(source["active_power_w"]["maximum"], 0.0, 10'000'000.0) ||
      !boundedNumber(source["raw_energy_start_wh"], 0.0,
                     std::numeric_limits<double>::max()) ||
      !boundedNumber(source["raw_energy_end_wh"], 0.0,
                     std::numeric_limits<double>::max()) ||
      !boundedNumber(source["device_lifetime_energy_wh"], 0.0,
                     std::numeric_limits<double>::max()) ||
      !boundedNumber(source["interval_energy_wh"], 0.0,
                     std::numeric_limits<double>::max())) {
    flags |= MeterGap;
  }
  return flags;
}

} // namespace

bool append(JsonArray output, const std::string &encoded_record) {
  JsonDocument source;
  if (deserializeJson(source, encoded_record) ||
      !source["sequence"].is<std::uint64_t>() ||
      !source["boot_id"].is<const char *>() ||
      !source["start_utc"].is<const char *>() ||
      !source["end_utc"].is<const char *>()) {
    return false;
  }

  JsonObject record = output.add<JsonObject>();
  record["sequence"] = source["sequence"];
  record["boot_id"] = source["boot_id"];
  record["interval_start"] = source["start_utc"];
  record["interval_end"] = source["end_utc"];
  record["time_trusted"] = source["time_trusted"] | false;
  const std::uint32_t valid_samples = source["valid_sample_count"] | 0U;
  const std::uint32_t contract_violation_flags =
      valid_samples == 0U ? MeterGap : serverContractViolationFlags(source);
  if (valid_samples == 0U || contract_violation_flags != QualityNone) {
    setUnavailableMeasurements(record);
  } else {
    record["voltage_avg"] = source["voltage_v"]["average"];
    record["voltage_min"] = source["voltage_v"]["minimum"];
    record["voltage_max"] = source["voltage_v"]["maximum"];
    record["current_avg"] = source["current_a"]["average"];
    record["current_min"] = source["current_a"]["minimum"];
    record["current_max"] = source["current_a"]["maximum"];
    record["power_avg"] = source["active_power_w"]["average"];
    record["power_min"] = source["active_power_w"]["minimum"];
    record["power_max"] = source["active_power_w"]["maximum"];
    record["power_factor"] = source["average_power_factor"];
    record["frequency_hz"] = source["average_frequency_hz"];
    record["pzem_energy_start_wh"] = source["raw_energy_start_wh"];
    record["pzem_energy_end_wh"] = source["raw_energy_end_wh"];
    record["device_lifetime_energy_wh"] = source["device_lifetime_energy_wh"];
    record["interval_energy_wh"] = source["interval_energy_wh"];
  }
  record["energy_method"] = source["energy_method"] | "incomplete";
  record["ct_rating_amps"] = source["ct_rating_a"];
  addQualityFlags((source["quality_flags"] | 0U) | contract_violation_flags,
                  record["quality_flags"].to<JsonArray>());
  record["firmware_version"] = source["firmware_version"];
  return true;
}

} // namespace reading_wire
} // namespace pm
