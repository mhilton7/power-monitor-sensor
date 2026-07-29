#include <array>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <string>

#include "core/Algorithms.h"
#include "diagnostics/DiagnosticCore.h"
#include "meter/PzemProtocol.h"
#include "storage/RecordFormat.h"

namespace {
int failures = 0;

void check(const bool condition, const char* message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
    ++failures;
  }
}

void testPzem() {
  const auto request = pm::pzem::buildReadMeasurementRequest();
  const std::array<std::uint8_t, 8> expected{0xF8, 0x04, 0x00, 0x00,
                                             0x00, 0x0A, 0x64, 0x64};
  check(request == expected, "PZEM read request and CRC");

  std::array<std::uint8_t, pm::pzem::RESPONSE_SIZE> response{
      0xF8, 0x04, 0x14, 0x04, 0xBD, 0x1C, 0xFC, 0x00, 0x00,
      0x22, 0x1D, 0x00, 0x00, 0x48, 0x28, 0x00, 0x3C, 0x02,
      0x58, 0x00, 0x61, 0x00, 0x00, 0x00, 0x00};
  const auto crc = pm::pzem::modbusCrc16(response.data(), response.size() - 2);
  response[23] = static_cast<std::uint8_t>(crc & 0xFFU);
  response[24] = static_cast<std::uint8_t>(crc >> 8U);
  pm::MeasurementSnapshot sample;
  check(pm::pzem::parseMeasurementResponse(response.data(), response.size(), sample) ==
            pm::MeterError::None,
        "PZEM response parses");
  check(std::fabs(sample.voltage_v - 121.3F) < 0.01F, "voltage scaling");
  check(std::fabs(sample.current_a - 7.42F) < 0.01F, "current scaling");
  check(std::fabs(sample.active_power_w - 873.3F) < 0.01F, "power scaling");
  check(sample.raw_energy_wh == 3'950'632U, "energy scaling");
  response[10] ^= 1U;
  check(pm::pzem::parseMeasurementResponse(response.data(), response.size(), sample) ==
            pm::MeterError::CrcMismatch,
        "bad CRC rejected");
  check(pm::pzem::parseMeasurementResponse(response.data(), 4, sample) ==
            pm::MeterError::ShortFrame,
        "short frame rejected");
  response[10] ^= 1U;
  response[0] = 1;
  check(pm::pzem::parseMeasurementResponse(response.data(), response.size(), sample) ==
            pm::MeterError::WrongAddress,
        "wrong meter address rejected");
  response[0] = 0xF8;
  response[1] = 0x84;
  check(pm::pzem::parseMeasurementResponse(response.data(), response.size(), sample) ==
            pm::MeterError::ExceptionResponse,
        "Modbus exception rejected");
}

void testEnergyAndRecord() {
  check(!pm::retentionEligible(true, true, 101, 100, 1000, 2000),
        "retention protects unacknowledged data");
  check(!pm::retentionEligible(true, false, 100, 100, 1000, 2000),
        "retention protects time-untrusted data");
  check(pm::retentionEligible(true, true, 100, 100, 1000, 2000),
        "retention permits acknowledged expired data");
  pm::EnergyNormalizer normalizer(1000);
  auto result = normalizer.update(500, 525, true, true, 0.0, false);
  check(result.interval_wh == 25.0 && result.lifetime_wh == 1525,
        "positive energy delta");
  result = normalizer.update(525, 3, true, true, 0.0, false);
  check(result.interval_wh == 3.0 && result.lifetime_wh == 1528 &&
            result.offset_changed,
        "counter reset offset");
  result = normalizer.update(0, 0, false, false, 2.5, true);
  check(result.method == std::string("power_integration"),
        "power integration fallback");
  pm::EnergyNormalizer rollover;
  result = rollover.update(0xFFFFFFF0ULL, 20, true, true, 0.0, false);
  check(result.method == std::string("pzem_rollover") &&
            result.interval_wh == 36.0 && result.lifetime_wh == 0x1'0000'0014ULL,
        "32-bit PZEM counter rollover");

  pm::MeasurementSnapshot invalid;
  invalid.time_trusted = true;
  invalid.valid = true;
  invalid.voltage_v = 121.0F;
  invalid.current_a = 111.0F;
  invalid.active_power_w = 1000.0F;
  invalid.frequency_hz = 60.0F;
  invalid.power_factor = 0.98F;
  check((pm::validateMeasurement(invalid, pm::Limits{}) & pm::CtOverRange) != 0 &&
            !invalid.valid,
        "measurement CT over-range validation");

  pm::IntervalAggregator aggregator(pm::Limits{});
  pm::EnergyNormalizer interval_energy;
  aggregator.reset(1'700'000'000'000ULL, 1000);
  pm::MeasurementSnapshot aggregate_sample;
  aggregate_sample.valid = true;
  aggregate_sample.time_trusted = true;
  aggregate_sample.utc_ms = 1'700'000'000'000ULL;
  aggregate_sample.monotonic_ms = 1000;
  aggregate_sample.voltage_v = 120.0F;
  aggregate_sample.current_a = 2.0F;
  aggregate_sample.active_power_w = 240.0F;
  aggregate_sample.frequency_hz = 60.0F;
  aggregate_sample.power_factor = 1.0F;
  aggregate_sample.raw_energy_wh = 100;
  aggregator.add(aggregate_sample);
  aggregator.add(aggregate_sample);
  aggregate_sample.monotonic_ms = 61'000;
  aggregate_sample.utc_ms += 60'000;
  aggregate_sample.raw_energy_wh = 104;
  aggregator.add(aggregate_sample);
  const pm::IntervalRecord aggregate_record = aggregator.finish(
      "device", "name", "boot", "1.0.0", aggregate_sample.utc_ms,
      aggregate_sample.monotonic_ms, interval_energy);
  check(aggregate_record.sample_count == 2 &&
            aggregate_record.valid_sample_count == 2 &&
            std::fabs(aggregate_record.interval_energy_wh - 4.0) < 0.001,
        "interval aggregation ignores duplicate monotonic samples");

  const std::string payload = R"({"schema_version":1,"sequence":42})";
  const std::string line = pm::record::encodeEnvelope(payload);
  std::string decoded;
  std::uint32_t crc = 0;
  check(pm::record::decodeEnvelope(line, decoded, crc) && decoded == payload,
        "record envelope roundtrip");
  std::string corrupt = line;
  corrupt[8] ^= 1;
  check(!pm::record::decodeEnvelope(corrupt, decoded, crc),
        "record corruption rejected");
}

void testDiagnostics() {
  using pm::diag::LogLevel;
  LogLevel level = LogLevel::Info;
  check(pm::diag::parseLogLevel("trace", level) && level == LogLevel::Trace,
        "diagnostic log-level parsing");
  check(pm::diag::parseLogLevel("ERROR", level) && level == LogLevel::Error,
        "diagnostic case-insensitive log-level parsing");
  check(!pm::diag::parseLogLevel("verbose", level),
        "unsupported diagnostic level rejected");
  check(pm::diag::shouldLog(LogLevel::Info, LogLevel::Info) &&
            pm::diag::shouldLog(LogLevel::Info, LogLevel::Error) &&
            !pm::diag::shouldLog(LogLevel::Info, LogLevel::Debug),
        "diagnostic threshold filtering");
  check(pm::diag::sensitiveKey("admin_password") &&
            pm::diag::sensitiveKey("X-PM-Signature") &&
            !pm::diag::sensitiveKey("friendly_name"),
        "sensitive-key detection");

  char redacted[160]{};
  pm::diag::redactSensitiveAssignments(
      "host=server.local password=hunter2 token=\"abc\" status=ready",
      redacted, sizeof(redacted));
  const std::string safe(redacted);
  check(safe.find("hunter2") == std::string::npos &&
            safe.find("abc") == std::string::npos &&
            safe.find("host=server.local") != std::string::npos,
        "central diagnostic redaction");
  check(pm::diag::maskSsid("HomeWiFi") == "Ho***Fi",
        "SSID masking");

  const pm::diag::ReasonInfo no_ap =
      pm::diag::wifiDisconnectReason(201);
  check(std::string(no_ap.name) == "NO_AP_FOUND" &&
            std::string(no_ap.error_code) == "PM-WIFI-002",
        "Wi-Fi disconnect reason translation");
  const pm::diag::ReasonInfo unknown =
      pm::diag::wifiDisconnectReason(65535);
  check(std::string(unknown.name) == "UNKNOWN",
        "unknown Wi-Fi reason preserves category");
  check(std::string(pm::diag::wifiStatusName(4)) ==
            "authentication_or_connection_failed",
        "Wi-Fi status translation");
  check(std::string(pm::diag::resetReasonName(6)) == "TASK_WATCHDOG",
        "reset-reason translation");
  check(std::string(pm::diag::wakeupReasonName(4)) == "TIMER",
        "wakeup-reason translation");
  check(std::string(pm::diag::tlsErrorCategory("certificate hostname mismatch")) ==
            "HOSTNAME_MISMATCH",
        "TLS error categorization");
  check(std::string(pm::diag::httpStatusCategory(429)) == "rate_limited",
        "HTTP status categorization");

  char line[256]{};
  pm::diag::formatLine(line, sizeof(line), 1284, LogLevel::Info, "BOOT",
                       "BOOT_START", "firmware=1.0.0");
  check(std::string(line).find("[000001284][INFO ][BOOT") == 0 &&
            std::string(line).find("[BOOT_START]") != std::string::npos,
        "structured diagnostic formatting");

  pm::diag::ErrorRing<2> ring;
  pm::diag::ErrorRecord first;
  first.numeric_code = 1;
  pm::diag::ErrorRecord second;
  second.numeric_code = 2;
  pm::diag::ErrorRecord third;
  third.numeric_code = 3;
  ring.push(first);
  ring.push(second);
  ring.push(third);
  check(ring.size() == 2 && ring.at(0).numeric_code == 2 &&
            ring.at(1).numeric_code == 3,
        "bounded diagnostic error ring");

  pm::diag::RateLimiter limiter;
  check(limiter.allow("offline", 1000, 5000) &&
            !limiter.allow("offline", 2000, 5000) &&
            limiter.allow("offline", 6000, 5000),
        "diagnostic rate limiting");
}
}  // namespace

int main() {
  testPzem();
  testEnergyAndRecord();
  testDiagnostics();
  if (failures == 0) {
    std::cout << "native C++ tests passed\n";
  }
  return failures == 0 ? 0 : 1;
}
