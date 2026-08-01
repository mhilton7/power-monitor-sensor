#include <array>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <limits>
#include <map>
#include <string>
#include <vector>

#include "config/AtomicConfigStore.h"
#include "config/ConfigRecovery.h"
#include "config/ConfigValidationHelpers.h"
#include "config/ProvisioningTransaction.h"
#include "core/Algorithms.h"
#include "core/MemoryPressurePolicy.h"
#include "diagnostics/DiagnosticCore.h"
#include "meter/PzemProtocol.h"
#include "network/ClockPolicy.h"
#include "network/NetworkPolicy.h"
#include "network/ReadingWireFormat.h"
#include "network/ServerSyncPolicy.h"
#include "security/AuthPolicy.h"
#include "security/AuthReplayWindow.h"
#include "security/Crypto.h"
#include "storage/RecordFormat.h"
#include "storage/StoragePolicy.h"
#include "storage/SyncCoverage.h"

namespace {
int failures = 0;

void check(const bool condition, const char *message) {
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
  check(pm::pzem::parseMeasurementResponse(response.data(), response.size(),
                                           sample) == pm::MeterError::None,
        "PZEM response parses");
  check(std::fabs(sample.voltage_v - 121.3F) < 0.01F, "voltage scaling");
  check(std::fabs(sample.current_a - 7.42F) < 0.01F, "current scaling");
  check(std::fabs(sample.active_power_w - 873.3F) < 0.01F, "power scaling");
  check(sample.raw_energy_wh == 3'950'632U, "energy scaling");
  response[10] ^= 1U;
  check(pm::pzem::parseMeasurementResponse(response.data(), response.size(),
                                           sample) ==
            pm::MeterError::CrcMismatch,
        "bad CRC rejected");
  check(pm::pzem::parseMeasurementResponse(response.data(), 4, sample) ==
            pm::MeterError::ShortFrame,
        "short frame rejected");
  response[10] ^= 1U;
  response[0] = 1;
  check(pm::pzem::parseMeasurementResponse(response.data(), response.size(),
                                           sample) ==
            pm::MeterError::WrongAddress,
        "wrong meter address rejected");
  response[0] = 0xF8;
  response[1] = 0x84;
  check(pm::pzem::parseMeasurementResponse(response.data(), response.size(),
                                           sample) ==
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
  pm::EnergyNormalizer low_power;
  result = low_power.update(100, 100, true, true, 1.0 / 720.0, true);
  check(result.method == std::string("power_integration") &&
            std::fabs(result.interval_wh - 0.0013888889) < 0.0000001,
        "unchanged whole-Wh counter preserves five-second one-watt energy");
  result = low_power.update(100, 101, true, true, 0.0013888889, true);
  check(result.method == std::string("power_integration") &&
            std::fabs(result.interval_wh - 0.0013888889) < 0.0000001,
        "later whole-Wh counter movement reconciles without a duplicate spike");
  using pm::sync_policy::AcknowledgementDisposition;
  check(pm::sync_policy::classifyAcknowledgement(5, 5, 8) ==
            AcknowledgementDisposition::AdvanceSequenceFloor,
        "authenticated server cursor can safely advance a regressed sequence floor");
  check(pm::sync_policy::classifyAcknowledgement(2207, 92, 2207) ==
            AcknowledgementDisposition::AdvanceSequenceFloor,
        "persisted acknowledgement ahead of reset storage still advances the sequence floor");
  check(pm::sync_policy::classifyAcknowledgement(5, 8, 5) ==
            AcknowledgementDisposition::Current,
        "matching acknowledgement remains current when retained history is not behind it");
  check(pm::sync_policy::classifyAcknowledgement(5, 8, 7) ==
            AcknowledgementDisposition::Advance,
        "acknowledgement advances within retained history");
  check(pm::sync_policy::classifyAcknowledgement(5, 8, 4) ==
            AcknowledgementDisposition::Invalid,
        "acknowledgement cannot regress");
  check(pm::sync_policy::requiredSequenceFloor(0, 0, 785, 790, 790) ==
            790,
        "blank replacement card resumes above the server maximum-seen cursor");
  check(pm::sync_policy::requiredSequenceFloor(812, 810, 785, 790, 790) ==
            812,
        "retained local records cannot be replaced by an older remote cursor");
  check(pm::sync_policy::sequenceCursorContractValid(785, 785, 790, 791),
        "server cursor accepts a maximum-seen value beyond contiguous ack");
  check(!pm::sync_policy::sequenceCursorContractValid(785, 785, 790, 790),
        "server cursor rejects a reused next sequence");
  pm::EnergyNormalizer rollover;
  result = rollover.update(0xFFFFFFF0ULL, 20, true, true, 0.0, false);
  check(result.method == std::string("pzem_rollover") &&
            result.interval_wh == 36.0 &&
            result.lifetime_wh == 0x1'0000'0014ULL,
        "32-bit PZEM counter rollover");

  pm::MeasurementSnapshot invalid;
  invalid.time_trusted = true;
  invalid.valid = true;
  invalid.voltage_v = 121.0F;
  invalid.current_a = 111.0F;
  invalid.active_power_w = 1000.0F;
  invalid.frequency_hz = 60.0F;
  invalid.power_factor = 0.98F;
  check((pm::validateMeasurement(invalid, pm::Limits{}) & pm::CtOverRange) !=
                0 &&
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

  pm::IntervalAggregator untrusted_aggregator(pm::Limits{});
  pm::EnergyNormalizer untrusted_energy;
  pm::MeasurementSnapshot untrusted_sample;
  untrusted_sample.monotonic_ms = 1'000;
  untrusted_sample.utc_ms = 0;
  untrusted_sample.time_trusted = false;
  untrusted_aggregator.reset(0, untrusted_sample.monotonic_ms);
  untrusted_aggregator.add(untrusted_sample);
  untrusted_sample.monotonic_ms = 61'000;
  untrusted_sample.utc_ms = 1'787'000'000'000ULL;
  untrusted_sample.time_trusted = true;
  untrusted_aggregator.add(untrusted_sample);
  const pm::IntervalRecord untrusted_record = untrusted_aggregator.finish(
      "device", "name", "boot", "1.0.0", untrusted_sample.utc_ms,
      untrusted_sample.monotonic_ms, untrusted_energy);
  check(!untrusted_record.time_trusted &&
            untrusted_record.end_utc_ms > untrusted_record.start_utc_ms &&
            untrusted_record.end_utc_ms - untrusted_record.start_utc_ms ==
                60'000,
        "mid-interval NTP step preserves bounded monotonic duration");

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

void testReadingWireFormat() {
  const std::string durable_record =
      R"json({"sequence":42,"boot_id":"boot-1","start_utc":"2026-07-29T00:00:00Z","end_utc":"2026-07-29T00:01:00Z","time_trusted":true,"valid_sample_count":60,"voltage_v":{"average":120.0,"minimum":118.0,"maximum":122.0},"current_a":{"average":2.0,"minimum":1.0,"maximum":3.0},"active_power_w":{"average":240.0,"minimum":120.0,"maximum":360.0},"average_power_factor":0.98,"average_frequency_hz":60.0,"raw_energy_start_wh":1000,"raw_energy_end_wh":1004,"device_lifetime_energy_wh":2004,"interval_energy_wh":4.0,"energy_method":"pzem_delta","ct_rating_a":100.0,"quality_flags":0,"firmware_version":"1.0.0"})json";
  JsonDocument valid_output;
  JsonArray valid_readings = valid_output["readings"].to<JsonArray>();
  check(pm::reading_wire::append(valid_readings, durable_record) &&
            valid_readings.size() == 1 &&
            !valid_readings[0]["voltage_avg"].isNull(),
        "wire translator retains measurements inside server numeric bounds");

  std::string invalid_record = durable_record;
  const std::string valid_power_factor = "\"average_power_factor\":0.98";
  const std::size_t power_factor_position =
      invalid_record.find(valid_power_factor);
  check(power_factor_position != std::string::npos,
        "wire test fixture contains power factor");
  if (power_factor_position != std::string::npos) {
    invalid_record.replace(power_factor_position, valid_power_factor.size(),
                           "\"average_power_factor\":1.01");
  }
  JsonDocument invalid_output;
  JsonArray invalid_readings = invalid_output["readings"].to<JsonArray>();
  check(pm::reading_wire::append(invalid_readings, invalid_record) &&
            invalid_readings.size() == 1 &&
            invalid_readings[0]["voltage_avg"].isNull() &&
            invalid_readings[0]["power_factor"].isNull(),
        "out-of-contract durable measurements become null instead of rejected");
  bool meter_gap = false;
  for (JsonVariantConst flag :
       invalid_readings[0]["quality_flags"].as<JsonArrayConst>()) {
    meter_gap =
        meter_gap || std::string(flag.as<const char *>()) == "meter_gap";
  }
  check(meter_gap, "null wire measurements carry a meter-gap quality flag");
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
      "host=server.local password=hunter2 token=\"abc\" status=ready", redacted,
      sizeof(redacted));
  const std::string safe(redacted);
  check(safe.find("hunter2") == std::string::npos &&
            safe.find("abc") == std::string::npos &&
            safe.find("host=server.local") != std::string::npos,
        "central diagnostic redaction");
  pm::diag::redactSensitiveAssignments(
      R"({"token": "json-secret","friendly_name":"Kitchen"})", redacted,
      sizeof(redacted));
  const std::string json_safe(redacted);
  check(json_safe.find("json-secret") == std::string::npos &&
            json_safe.find("Kitchen") != std::string::npos &&
            json_safe.find("[REDACTED]") != std::string::npos,
        "JSON diagnostic values are centrally redacted");
  pm::diag::redactSensitiveAssignments(
      "Authorization: Bearer top-secret next=value", redacted,
      sizeof(redacted));
  const std::string authorization_safe(redacted);
  check(authorization_safe.find("top-secret") == std::string::npos &&
            authorization_safe.find("next=value") != std::string::npos,
        "authorization metadata is redacted without hiding later fields");
  pm::diag::redactSensitiveAssignments(
      R"({"signature":"escaped-\"secret\"","status":"ready"})", redacted,
      sizeof(redacted));
  const std::string escaped_safe(redacted);
  check(escaped_safe.find("secret") == std::string::npos &&
            escaped_safe.find("status") != std::string::npos,
        "escaped quoted secrets are fully redacted");
  check(pm::diag::maskSsid("HomeWiFi") == "Ho***Fi", "SSID masking");

  const pm::diag::ReasonInfo no_ap = pm::diag::wifiDisconnectReason(201);
  check(std::string(no_ap.name) == "NO_AP_FOUND" &&
            std::string(no_ap.error_code) == "PM-WIFI-002",
        "Wi-Fi disconnect reason translation");
  const pm::diag::ReasonInfo unknown = pm::diag::wifiDisconnectReason(65535);
  check(std::string(unknown.name) == "UNKNOWN",
        "unknown Wi-Fi reason preserves category");
  check(std::string(pm::diag::wifiStatusName(4)) ==
            "authentication_or_connection_failed",
        "Wi-Fi status translation");
  check(std::string(pm::diag::resetReasonName(6)) == "TASK_WATCHDOG",
        "reset-reason translation");
  check(std::string(pm::diag::wakeupReasonName(4)) == "TIMER",
        "wakeup-reason translation");
  check(std::string(pm::diag::tlsErrorCategory(
            "certificate hostname mismatch")) == "HOSTNAME_MISMATCH",
        "TLS error categorization");
  check(std::string(pm::diag::tlsErrorCategory(
            "SSL - Memory allocation failed")) == "MEMORY_EXHAUSTED",
        "TLS allocation failures have a distinct diagnostic category");
  check(std::string(pm::diag::tlsErrorCategory("response connection closed")) ==
            "CONNECTION_CLOSED",
        "TLS response closure has a distinct diagnostic category");
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

void testNetworkPolicy() {
  using pm::network_policy::elapsedAtLeast;
  using pm::network_policy::reconnectBackoffMs;
  using pm::network_policy::shouldStartCredentialRecoveryAp;

  check(!elapsedAtLeast(1'000U, 2'000U, 500U),
        "future Wi-Fi timestamp cannot underflow into a timeout");
  check(!elapsedAtLeast(60'000U, 0U, 60'000U) &&
            elapsedAtLeast(61'000U, 1'000U, 60'000U),
        "Wi-Fi elapsed timeout is bounded and zero-safe");

  std::uint32_t previous_floor = 0;
  for (std::uint32_t attempt = 0; attempt < 32U; ++attempt) {
    const std::uint32_t minimum = reconnectBackoffMs(attempt, 0U);
    const std::uint32_t maximum = reconnectBackoffMs(attempt, 0xFFFFU);
    check(minimum >= previous_floor && maximum >= minimum &&
              maximum <= pm::network_policy::kReconnectMaximumMs,
          "Wi-Fi reconnect backoff is monotonic and capped at five minutes");
    previous_floor = minimum;
  }

  check(!shouldStartCredentialRecoveryAp(true, false, 61'000U, 1'000U, 0U, 201U,
                                         1),
        "missing SSID does not start provisioning or erase configuration");
  check(
      !shouldStartCredentialRecoveryAp(true, false, 61'000U, 1'000U, 0U, 0U, 0),
      "DHCP delay does not start provisioning");
  check(shouldStartCredentialRecoveryAp(true, false, 61'000U, 1'000U, 0U, 202U,
                                        4),
        "proven authentication failure permits local credential recovery");
  check(!shouldStartCredentialRecoveryAp(false, false, 61'000U, 1'000U, 0U,
                                         202U, 4) &&
            !shouldStartCredentialRecoveryAp(true, true, 61'000U, 1'000U, 0U,
                                             202U, 4),
        "credential recovery policy respects configuration and active AP");
}

void testClockPolicy() {
  using pm::clock_policy::CandidateDisposition;
  constexpr std::uint64_t build = 1'767'225'600'000ULL;
  check(pm::clock_policy::classifyCandidate(build + 1'000U, 0U, build) ==
            CandidateDisposition::Accept,
        "fresh plausible SNTP time is accepted");
  check(pm::clock_policy::classifyCandidate(
            pm::clock_policy::kMaximumUtcMs + 1U, 0U, build) ==
            CandidateDisposition::RejectImplausible,
        "absolute far-future SNTP time is rejected");
  check(pm::clock_policy::classifyCandidate(
            build + pm::clock_policy::kMaximumInitialBuildAdvanceMs + 1U, 0U,
            build) == CandidateDisposition::RequireConfirmation,
        "first-boot forward jump requires confirmation");
  check(pm::clock_policy::classifyCandidate(
            build + pm::clock_policy::kMaximumAnchoredForwardStepMs + 1U, build,
            build) == CandidateDisposition::RequireConfirmation,
        "anchored forward jump requires confirmation");
  check(pm::clock_policy::classifyCandidate(
            build - pm::clock_policy::kRollbackToleranceMs - 1U, build,
            build) == CandidateDisposition::RequireConfirmation,
        "clock rollback requires confirmation");
  check(pm::clock_policy::candidatesConsistent(build, 10'000U, build + 15'000U,
                                               25'000U),
        "consistent suspicious SNTP samples can recover boundedly");
  check(!pm::clock_policy::candidatesConsistent(build, 10'000U,
                                                build + 900'000U, 25'000U),
        "inconsistent suspicious SNTP samples reset confirmation");
}

void testServerSyncPolicy() {
  using pm::sync_policy::HttpDisposition;
  using pm::sync_policy::QueueResult;

  pm::sync_policy::SingleFlightGate gate;
  check(!gate.active() && !gate.pending(), "server sync gate starts idle");
  check(gate.queue() == QueueResult::Queued && gate.pending() &&
            gate.queue() == QueueResult::Coalesced,
        "server sync gate retains one coalesced pending request");
  check(gate.consumePending() && !gate.pending() && !gate.consumePending(),
        "server sync gate consumes pending work exactly once");
  check(gate.tryBegin() && gate.active() && !gate.tryBegin(),
        "server sync gate permits only one active transport");
  check(gate.queue() == QueueResult::Queued &&
            gate.queue() == QueueResult::Coalesced,
        "local actions coalesce while a transport is active");
  gate.finish();
  check(!gate.active() && gate.pending() && gate.consumePending(),
        "transport cleanup releases ownership without dropping queued work");

  check(pm::sync_policy::stackMarginPercent(16'384U, 4096U) == 25U &&
            pm::sync_policy::stackMarginPercent(16'384U, 20'000U) == 100U &&
            pm::sync_policy::stackMarginPercent(0U, 4096U) == 0U,
        "server sync stack margin uses ESP-IDF byte units and is bounded");
  check(pm::sync_policy::stackMarginHealthy(24'576U, 11'844U, 25U) &&
            !pm::sync_policy::stackMarginHealthy(24'576U, 6143U, 25U),
        "historical stack watermark is release health evidence, not a "
        "latching TLS request admission gate");
  check(pm::sync_policy::tlsMemoryReserveAvailable(
            pm::sync_policy::kMinimumInternalHeapBytes,
            pm::sync_policy::kMinimumLargestInternalBlockBytes) &&
              pm::sync_policy::tlsMemoryReserveAvailable(92'696U, 39'924U) &&
              pm::sync_policy::tlsMemoryReserveAvailable(88'424U, 33'780U) &&
              pm::sync_policy::tlsMemoryReserveAvailable(81'508U, 52'212U) &&
              pm::sync_policy::tlsMemoryReserveAvailable(72'348U, 58'356U) &&
              !pm::sync_policy::tlsMemoryReserveAvailable(
                 pm::sync_policy::kMinimumInternalHeapBytes - 1U,
                 pm::sync_policy::kMinimumLargestInternalBlockBytes) &&
            !pm::sync_policy::tlsMemoryReserveAvailable(
                pm::sync_policy::kMinimumInternalHeapBytes,
                pm::sync_policy::kMinimumLargestInternalBlockBytes - 1U),
        "TLS admission accepts measured post-catch-up, live-PZEM, and "
        "storage-boundary heap while enforcing both memory reserves");
  check(pm::sync_policy::responseLengthAllowed(
            static_cast<int>(pm::sync_policy::kMaximumResponseBytes), 200) &&
            !pm::sync_policy::responseLengthAllowed(
                static_cast<int>(pm::sync_policy::kMaximumResponseBytes + 1U),
                200) &&
            !pm::sync_policy::responseLengthAllowed(-1, 200) &&
            pm::sync_policy::responseLengthAllowed(-1, 204),
        "HTTP response allocation is bounded and rejects chunked JSON");
  check(pm::sync_policy::maximumResponseBytes(
            "/api/v1/device-heartbeats") == 8U * 1024U &&
            pm::sync_policy::maximumResponseBytes(
                "/api/v1/device-readings/batch") == 12U * 1024U &&
            pm::sync_policy::maximumRequestBytes(
                "/api/v1/device-events/batch") == 20U * 1024U &&
            !pm::sync_policy::responseLengthAllowed(
                "/api/v1/device-heartbeats", 8193, 200),
        "central endpoints enforce measured request and response caps");
  check(pm::sync_policy::responseAllocationAvailable(
            pm::sync_policy::kMinimumPostResponseInternalHeapBytes + 4096U,
            4096U, 4096) &&
            !pm::sync_policy::responseAllocationAvailable(
                pm::sync_policy::kMinimumPostResponseInternalHeapBytes + 4095U,
                4096U, 4096) &&
            !pm::sync_policy::responseAllocationAvailable(
                pm::sync_policy::kMinimumPostResponseInternalHeapBytes + 4096U,
                4095U, 4096) &&
            pm::sync_policy::responseAllocationAvailable(0U, 0U, 0),
        "response allocation preserves internal heap after the body");
  check(pm::sync_policy::classifyHttpStatus(200) == HttpDisposition::Success &&
            pm::sync_policy::classifyHttpStatus(401) ==
                HttpDisposition::AuthenticationRejected &&
            pm::sync_policy::classifyHttpStatus(429) ==
                HttpDisposition::RateLimited &&
            pm::sync_policy::classifyHttpStatus(503) ==
                HttpDisposition::Retryable &&
            pm::sync_policy::classifyHttpStatus(422) ==
                HttpDisposition::PermanentFailure &&
            pm::sync_policy::classifyHttpStatus(-1) ==
                HttpDisposition::TransportFailure,
        "server sync retry policy classifies HTTP and transport outcomes");
  check(pm::sync_policy::shouldReleaseReadingBackoff(
            true, 10U, 11U, false, 0U) &&
            !pm::sync_policy::shouldReleaseReadingBackoff(
                true, 10U, 11U, true, 10U) &&
            pm::sync_policy::shouldReleaseReadingBackoff(
                true, 11U, 12U, true, 10U) &&
            !pm::sync_policy::shouldReleaseReadingBackoff(
                false, 10U, 11U, false, 0U) &&
            !pm::sync_policy::shouldReleaseReadingBackoff(
                true, 11U, 11U, false, 0U) &&
            !pm::sync_policy::shouldReleaseReadingBackoff(
                true, 12U, 11U, false, 0U),
        "server synchronize-now releases reading backoff once per cursor");
  check(!pm::sync_policy::secondaryOperationsAllowed(true) &&
            pm::sync_policy::secondaryOperationsAllowed(false),
        "durable reading backlog blocks secondary TLS operations");
  check(!pm::sync_policy::shouldScheduleEventIdleDelay(true, true) &&
            pm::sync_policy::shouldScheduleEventIdleDelay(true, false) &&
            !pm::sync_policy::shouldScheduleEventIdleDelay(false, false),
        "event-page polling keeps its short deadline until the page is "
        "consumed");

  pm::sync_policy::EndpointAddressCache address_cache;
  std::uint32_t cached_address = 99U;
  check(!address_cache.lookup("power-monitor.home.arpa", 8443U,
                              cached_address) &&
            cached_address == 0U,
        "server endpoint cache begins empty");
  address_cache.update("power-monitor.home.arpa", 8443U, 0xAF00A8C0U);
  check(address_cache.configured() &&
            address_cache.lookup("power-monitor.home.arpa", 8443U,
                                 cached_address) &&
            cached_address == 0xAF00A8C0U &&
            !address_cache.lookup("power-monitor.home.arpa", 443U,
                                  cached_address),
        "server endpoint cache is scoped to host and port");
  check(!address_cache.recordTransportFailure() &&
            address_cache.configured() &&
            address_cache.recordTransportFailure() &&
            !address_cache.configured(),
        "two consecutive cached-address failures force fresh DNS");
  address_cache.update("power-monitor.home.arpa", 8443U, 0xAF00A8C0U);
  check(!address_cache.recordTransportFailure(),
        "first cached-address failure is retained");
  address_cache.recordTransportSuccess();
  check(!address_cache.recordTransportFailure() &&
            address_cache.configured(),
        "transport success resets cached-address failure count");
}

void testConfigRecovery() {
  check(!pm::shouldRecoverPreviousConfig(true, true, true, true, true),
        "valid primary config remains authoritative");
  check(pm::shouldRecoverPreviousConfig(false, false, true, true, true),
        "invalid primary config recovers previous config");
  check(pm::shouldRecoverPreviousConfig(false, false, false, true, true),
        "invalid primary preserves previous non-network configuration");
  check(pm::shouldRecoverPreviousConfig(true, false, true, true, true),
        "orphaned Wi-Fi state recovers previous non-network fields");
  check(!pm::shouldRecoverPreviousConfig(true, false, false, true, true),
        "intentional unconfigured state does not recover without password");
  check(pm::shouldRecoverPreviousConfig(true, false, true, true, false),
        "orphaned Wi-Fi state preserves a previous non-network-only record");
  check(!pm::shouldRecoverPreviousConfig(false, false, true, false, false),
        "missing previous config falls back to defaults");

  check(!pm::legacyWifiPairNeedsQuarantine(false, 0) &&
            pm::legacyWifiPairNeedsQuarantine(false, 16) &&
            pm::legacyWifiPairNeedsQuarantine(true, 0) &&
            pm::legacyWifiPairNeedsQuarantine(true, 7) &&
            !pm::legacyWifiPairNeedsQuarantine(true, 8) &&
            !pm::legacyWifiPairNeedsQuarantine(true, 63) &&
            pm::legacyWifiPairNeedsQuarantine(true, 64) &&
            pm::legacyWifiPairNeedsQuarantine(true, 16, true),
        "legacy Wi-Fi migration quarantines orphaned and malformed pairs");

  check(pm::reenrollmentPrerequisitesReady(true, true, true) &&
            !pm::reenrollmentPrerequisitesReady(false, true, true) &&
            !pm::reenrollmentPrerequisitesReady(true, false, true) &&
            !pm::reenrollmentPrerequisitesReady(true, true, false),
        "reenrollment tombstone requires verified token and both cursors");
}

void testConfigValidationHelpers() {
  using pm::config_validation::containsPrivateKeyPem;
  using pm::config_validation::normalizePemLineEndings;
  using pm::config_validation::validHttpsBaseUrl;

  check(normalizePemLineEndings("line1\r\nline2\rline3") ==
            "line1\nline2\nline3\n",
        "CA PEM CRLF and CR line endings normalize to LF");
  check(containsPrivateKeyPem("-----BEGIN "
                              "PRIVATE KEY-----\nsecret\n"
                              "-----END "
                              "PRIVATE KEY-----\n") &&
            containsPrivateKeyPem("-----BEGIN RSA "
                                  "PRIVATE KEY-----\nsecret\n") &&
            !containsPrivateKeyPem("-----BEGIN CERTIFICATE-----\npublic\n"),
        "private key PEM markers are rejected");

  check(validHttpsBaseUrl("https://server.example") &&
            validHttpsBaseUrl("https://server.example:8443") &&
            validHttpsBaseUrl("https://192.168.0.175:5000"),
        "strict HTTPS origins accept valid hosts and ports");
  check(!validHttpsBaseUrl("http://server.example") &&
            !validHttpsBaseUrl("https://user@server.example") &&
            !validHttpsBaseUrl("https://server.example/") &&
            !validHttpsBaseUrl("https://server.example/api") &&
            !validHttpsBaseUrl("https://server.example?query=1") &&
            !validHttpsBaseUrl("https://server.example#fragment") &&
            !validHttpsBaseUrl("https://server.example:") &&
            !validHttpsBaseUrl("https://server.example:0") &&
            !validHttpsBaseUrl("https://server.example:65536") &&
            !validHttpsBaseUrl("https://999.1.1.1") &&
            !validHttpsBaseUrl("https://[2001:db8::1]:443") &&
            !validHttpsBaseUrl("https://[2001:db8:1]:443"),
        "strict HTTPS origins reject ambiguous or unsafe base URLs");
}

class MemoryBlobStore final : public pm::persistence::BlobStore {
public:
  bool read(const char *key, std::vector<std::uint8_t> &value) override {
    const auto found = blobs.find(key);
    if (found == blobs.end()) {
      value.clear();
      return false;
    }
    value = found->second;
    return true;
  }

  bool write(const char *key, const std::uint8_t *value,
             const std::size_t length) override {
    ++write_count;
    if (fail_write != 0 && write_count == fail_write) {
      if (partial_failure && length > 1) {
        blobs[key] = std::vector<std::uint8_t>(value, value + length / 2);
      }
      return false;
    }
    blobs[key] = std::vector<std::uint8_t>(value, value + length);
    return true;
  }

  bool erase(const char *key) override {
    blobs.erase(key);
    return true;
  }

  bool exists(const char *key) override {
    return blobs.find(key) != blobs.end();
  }

  void failOnWrite(const std::size_t number, const bool partial) {
    write_count = 0;
    fail_write = number;
    partial_failure = partial;
  }

  void allowWrites() {
    write_count = 0;
    fail_write = 0;
    partial_failure = false;
  }

  std::map<std::string, std::vector<std::uint8_t>> blobs;

private:
  std::size_t write_count{0};
  std::size_t fail_write{0};
  bool partial_failure{false};
};

std::vector<std::uint8_t> bytes(const std::string &value) {
  return std::vector<std::uint8_t>(value.begin(), value.end());
}

std::string text(const std::vector<std::uint8_t> &value) {
  return std::string(value.begin(), value.end());
}

void testAtomicConfigStore() {
  constexpr pm::persistence::SlotKeys config_keys{"cfg_a", "cfg_b",
                                                  "cfg_active"};
  MemoryBlobStore store;
  pm::persistence::CommitResult committed;
  check(pm::persistence::commit(store, config_keys, bytes("config-0"),
                                committed) &&
            committed.committed && committed.generation == 1,
        "atomic config initial commit");

  pm::persistence::LoadResult loaded;
  check(pm::persistence::loadActive(store, config_keys, loaded) &&
            text(loaded.payload) == "config-0",
        "atomic config survives reopen");

  const std::string complete_bundle =
      R"({"wifi_ssid":"fixture-net","wifi_password":"fixture-only-123","server_url":"https://power-monitor.local:8443","server_ca_pem":"line1\nline2\n"})";
  check(pm::persistence::commit(store, config_keys, bytes(complete_bundle),
                                committed) &&
            pm::persistence::loadActive(store, config_keys, loaded) &&
            text(loaded.payload) == complete_bundle,
        "SSID, password, HTTPS port, and multiline CA persist as one bundle");

  for (int reboot = 1; reboot <= 25; ++reboot) {
    MemoryBlobStore reopened;
    reopened.blobs = store.blobs;
    const std::string expected = "config-" + std::to_string(reboot);
    check(pm::persistence::commit(reopened, config_keys, bytes(expected),
                                  committed),
          "atomic config commit across 25 reboot cycles");
    check(pm::persistence::loadActive(reopened, config_keys, loaded) &&
              text(loaded.payload) == expected,
          "atomic config readback across 25 reboot cycles");
    store.blobs = reopened.blobs;
  }

  const std::string stable = text(loaded.payload);
  const char active_slot = loaded.slot;
  const char *active_key = active_slot == 'a' ? "cfg_a" : "cfg_b";
  store.blobs[active_key].back() ^= 0x80U;
  check(pm::persistence::loadActive(store, config_keys, loaded) &&
            loaded.recovered_fallback && text(loaded.payload) != stable,
        "corrupt CRC falls back to prior slot");

  check(pm::persistence::commit(store, config_keys, bytes("known-good"),
                                committed),
        "atomic config recommit after corrupt CRC");
  store.blobs["cfg_active"][0] ^= 0x01U;
  check(pm::persistence::loadActive(store, config_keys, loaded) &&
            loaded.recovered_fallback && text(loaded.payload) == "known-good",
        "corrupt active marker falls back to newest valid slot");

  check(pm::persistence::commit(store, config_keys, bytes("stable-before-cut"),
                                committed),
        "atomic config stable baseline");
  check(pm::persistence::loadActive(store, config_keys, loaded) &&
            text(loaded.payload) == "stable-before-cut",
        "atomic config baseline readback before abrupt cuts");

  const std::vector<std::uint8_t> old_marker = store.blobs["cfg_active"];
  check(pm::persistence::commit(store, config_keys,
                                bytes("fully-staged-not-activated"), committed),
        "inactive slot can be fully staged");
  store.blobs["cfg_active"] = old_marker;
  check(pm::persistence::loadActive(store, config_keys, loaded) &&
            text(loaded.payload) == "stable-before-cut",
        "abrupt cut before marker update retains old active generation");

  const char *abrupt_inactive = loaded.slot == 'a' ? "cfg_b" : "cfg_a";
  store.blobs[abrupt_inactive] = {0x50U, 0x4dU, 0x43U};
  check(pm::persistence::loadActive(store, config_keys, loaded) &&
            text(loaded.payload) == "stable-before-cut",
        "abrupt partial slot write with no cleanup retains old config");

  store.failOnWrite(1, true);
  check(!pm::persistence::commit(store, config_keys,
                                 bytes("partial-slot-write"), committed),
        "partial inactive-slot write is rejected");
  store.allowWrites();
  check(pm::persistence::loadActive(store, config_keys, loaded) &&
            text(loaded.payload) == "stable-before-cut",
        "partial inactive-slot write does not erase active config");

  store.failOnWrite(2, true);
  check(!pm::persistence::commit(store, config_keys,
                                 bytes("power-cut-before-marker"), committed),
        "power cut during active-marker write is rejected");
  store.allowWrites();
  check(pm::persistence::loadActive(store, config_keys, loaded) &&
            text(loaded.payload) == "stable-before-cut",
        "power cut during marker write preserves old active config");

  for (int failure = 0; failure < 25; ++failure) {
    store.failOnWrite((failure % 2) + 1, true);
    check(!pm::persistence::commit(
              store, config_keys,
              bytes("failed-update-" + std::to_string(failure)), committed),
          "injected commit failure is reported");
    store.allowWrites();
    check(pm::persistence::loadActive(store, config_keys, loaded) &&
              text(loaded.payload) == "stable-before-cut",
          "25 injected power cuts never erase active config");
  }

  check(pm::persistence::commit(store, config_keys, bytes("new-active"),
                                committed),
        "atomic config second valid slot");
  check(pm::persistence::loadActive(store, config_keys, loaded),
        "atomic config current generation is available for rollback");
  const std::uint64_t rollback_generation = loaded.generation;
  const std::vector<std::uint8_t> marker_before_peek =
      store.blobs["cfg_active"];
  pm::persistence::LoadResult previous;
  check(pm::persistence::loadPrevious(store, config_keys, rollback_generation,
                                      previous) &&
            text(previous.payload) == "stable-before-cut" &&
            store.blobs["cfg_active"] == marker_before_peek,
        "previous-slot semantic inspection does not activate it");
  check(!pm::persistence::loadPrevious(store, config_keys,
                                       rollback_generation - 1U, previous) &&
            !pm::persistence::rollbackToPrevious(
                store, config_keys, rollback_generation - 1U, previous) &&
            store.blobs["cfg_active"] == marker_before_peek,
        "stale generation cannot inspect or roll back a newer config");
  check(pm::persistence::rollbackToPrevious(store, config_keys,
                                            rollback_generation, loaded) &&
            text(loaded.payload) == "stable-before-cut",
        "atomic config rollback selects verified previous slot");

  MemoryBlobStore interrupted_store;
  pm::persistence::CommitResult interrupted_commit;
  check(pm::persistence::commit(interrupted_store, config_keys,
                                bytes("generation-one"), interrupted_commit),
        "interrupted rollback fixture commits generation one");
  const std::uint64_t generation_one = interrupted_commit.generation;
  const std::vector<std::uint8_t> generation_one_marker =
      interrupted_store.blobs["cfg_active"];
  check(pm::persistence::commit(interrupted_store, config_keys,
                                bytes("uncommitted-generation-two"),
                                interrupted_commit),
        "interrupted rollback fixture stages generation two");
  interrupted_store.blobs["cfg_active"] = generation_one_marker;
  check(!pm::persistence::rollbackToPrevious(interrupted_store, config_keys,
                                             generation_one, loaded),
        "rollback refuses a newer inactive slot that lacks marker commit");
  check(pm::persistence::loadActive(interrupted_store, config_keys, loaded) &&
            text(loaded.payload) == "generation-one",
        "refused rollback keeps the committed generation active");

  constexpr pm::persistence::SlotKeys enrollment_keys{"enroll_a", "enroll_b",
                                                      "enroll_active"};
  MemoryBlobStore enrollment_store;
  check(pm::persistence::commit(enrollment_store, enrollment_keys,
                                bytes("enrolled:generation-0"), committed),
        "enrollment bundle commits as one atomic record");
  check(
      pm::persistence::loadActive(enrollment_store, enrollment_keys, loaded) &&
          text(loaded.payload) == "enrolled:generation-0",
      "enrollment bundle readback is complete");
  const std::vector<std::uint8_t> enrolled_marker =
      enrollment_store.blobs["enroll_active"];
  check(pm::persistence::commit(enrollment_store, enrollment_keys,
                                bytes("pending:token:generation-1"), committed),
        "reenrollment pending token and tombstone commit atomically");
  enrollment_store.blobs["enroll_active"] = enrolled_marker;
  check(
      pm::persistence::loadActive(enrollment_store, enrollment_keys, loaded) &&
          text(loaded.payload) == "enrolled:generation-0",
      "power cut before pending marker retains enrolled credentials");
  check(pm::persistence::commit(enrollment_store, enrollment_keys,
                                bytes("pending:token:generation-1"),
                                committed) &&
            pm::persistence::loadActive(enrollment_store, enrollment_keys,
                                        loaded) &&
            text(loaded.payload) == "pending:token:generation-1",
        "committed reenrollment state is resumable after reboot");
  check(pm::persistence::commit(enrollment_store, enrollment_keys,
                                bytes("enrolled:new-credentials:generation-1"),
                                committed) &&
            pm::persistence::loadActive(enrollment_store, enrollment_keys,
                                        loaded) &&
            text(loaded.payload) == "enrolled:new-credentials:generation-1",
        "new enrollment atomically replaces the pending token state");
  MemoryBlobStore reopened_enrollment;
  reopened_enrollment.blobs = enrollment_store.blobs;
  check(pm::persistence::loadActive(reopened_enrollment, enrollment_keys,
                                    loaded) &&
            text(loaded.payload) == "enrolled:new-credentials:generation-1",
        "completed reenrollment persists across reopen");

  enrollment_store.failOnWrite(2, true);
  check(!pm::persistence::commit(enrollment_store, enrollment_keys,
                                 bytes("partial-new-enrollment"), committed),
        "partial enrollment marker write is rejected");
  enrollment_store.allowWrites();
  check(
      pm::persistence::loadActive(enrollment_store, enrollment_keys, loaded) &&
          text(loaded.payload) == "enrolled:new-credentials:generation-1",
      "failed enrollment update preserves UUID, secret, and OTA key");
}

void testProtocolCanonicalization() {
  check(
      pm::crypto::constantTimeEqualPortable("same", "same") &&
          !pm::crypto::constantTimeEqualPortable("same", "different") &&
          !pm::crypto::constantTimeEqualPortable(std::string(1, '\0'),
                                                 std::string(257, '\0')),
      "constant-time comparison rejects content and large length differences");

  const std::string target =
      "/api/v1/device-readings/batch?z=last&a=hello%20world&a=&slash=%2F";
  std::string canonical;
  check(pm::crypto::canonicalTarget(target, canonical) &&
            canonical == "/api/v1/device-readings/"
                         "batch?a=&a=hello%20world&slash=%2F&z=last",
        "sibling server HMAC target canonicalization vector");
  check(
      pm::crypto::canonicalRequest(
          "POST", canonical, "1784558400", "0123456789abcdef0123456789abcdef",
          "2b6341f1d5ce79c205eaf40981d99053de417039df083fbc71315c5ac3ca7fc7") ==
          "PM-HMAC-SHA256-V1\nPOST\n/api/v1/device-readings/batch?a=&a="
          "hello%20world&slash=%2F&z=last\n1784558400\n"
          "0123456789abcdef0123456789abcdef\n"
          "2b6341f1d5ce79c205eaf40981d99053de417039df083fbc71315c5ac3ca7fc7",
      "sibling server full canonical request vector");

  check(pm::crypto::canonicalTarget("/resource?q=hello+world&q=%252F",
                                    canonical) &&
            canonical == "/resource?q=%252F&q=hello%20world",
        "query decoding occurs exactly once and plus means space");
  check(pm::crypto::canonicalTarget("/resource?duplicate=&duplicate",
                                    canonical) &&
            canonical == "/resource?duplicate=&duplicate=",
        "duplicate blank query values are retained");
  check(!pm::crypto::canonicalTarget("/resource?broken=%2", canonical),
        "malformed percent escape is rejected");
  check(!pm::crypto::canonicalTarget("resource?key=value", canonical),
        "non-origin-form request target is rejected");
}

void testSyncCoverage() {
  const pm::SyncCoveragePlan recovered = pm::deriveSyncCoverage(
      244U, 756U, {463U, 533U}, {463U, 533U}, 500U);
  check(
      recovered.end_sequence == 533U &&
          recovered.unavailable_sequence_ranges.size() == 2U &&
          recovered.unavailable_sequence_ranges[0].start_sequence == 245U &&
          recovered.unavailable_sequence_ranges[0].end_sequence == 462U &&
          recovered.unavailable_sequence_ranges[1].start_sequence == 464U &&
          recovered.unavailable_sequence_ranges[1].end_sequence == 532U,
      "sync coverage declares missing local sequence holes before selected "
      "readings");

  const pm::SyncCoveragePlan bounded =
      pm::deriveSyncCoverage(0U, 600U, {600U}, {600U}, 500U);
  check(bounded.end_sequence == 500U &&
            bounded.unavailable_sequence_ranges.size() == 1U &&
            bounded.unavailable_sequence_ranges[0].start_sequence == 1U &&
            bounded.unavailable_sequence_ranges[0].end_sequence == 500U,
        "sync coverage respects the protocol unavailable-sequence limit");

  const pm::SyncCoveragePlan unsent_syncable =
      pm::deriveSyncCoverage(0U, 5U, {5U}, {3U, 5U}, 500U);
  check(unsent_syncable.end_sequence == 2U &&
            unsent_syncable.unavailable_sequence_ranges.size() == 1U &&
            unsent_syncable.unavailable_sequence_ranges[0].start_sequence ==
                1U &&
            unsent_syncable.unavailable_sequence_ranges[0].end_sequence == 2U,
        "sync coverage never declares an unselected retained reading lost");
}

void testAuthenticationPolicy() {
  std::int64_t parsed = 0;
  check(pm::auth_policy::parseTimestamp("9223372036854775807", parsed) &&
            parsed == std::numeric_limits<std::int64_t>::max(),
        "maximum signed authentication timestamp parses");
  check(pm::auth_policy::parseTimestamp("-9223372036854775808", parsed) &&
            parsed == std::numeric_limits<std::int64_t>::min(),
        "minimum signed authentication timestamp parses");
  check(!pm::auth_policy::parseTimestamp("9223372036854775808", parsed) &&
            !pm::auth_policy::parseTimestamp("-9223372036854775809", parsed) &&
            !pm::auth_policy::parseTimestamp("12seconds", parsed),
        "overflowed and malformed authentication timestamps are rejected");
  check(pm::auth_policy::timestampWithinWindow(
            std::numeric_limits<std::int64_t>::max(),
            std::numeric_limits<std::int64_t>::max() - 10, 300) &&
            pm::auth_policy::timestampWithinWindow(
                std::numeric_limits<std::int64_t>::min(),
                std::numeric_limits<std::int64_t>::min() + 10, 300) &&
            !pm::auth_policy::timestampWithinWindow(
                std::numeric_limits<std::int64_t>::max(),
                std::numeric_limits<std::int64_t>::min(), 300),
        "timestamp window comparisons remain correct at integer extremes");

  using Digest = std::array<std::uint8_t, 2>;
  pm::AuthReplayWindow<Digest, 2> replay_window;
  const Digest first{{1, 2}};
  const Digest second{{3, 4}};
  const Digest third{{5, 6}};
  check(replay_window.remember(first, 1000, 300) ==
                pm::ReplayRememberResult::Accepted &&
            replay_window.remember(first, 1001, 300) ==
                pm::ReplayRememberResult::Replayed &&
            replay_window.remember(second, 1001, 300) ==
                pm::ReplayRememberResult::Accepted &&
            replay_window.remember(third, 1002, 300) ==
                pm::ReplayRememberResult::CapacityExceeded,
        "replay cache refuses capacity pressure without evicting live nonces");
  check(replay_window.remember(third, 1300, 300) ==
                pm::ReplayRememberResult::CapacityExceeded &&
            replay_window.remember(third, 1301, 300) ==
                pm::ReplayRememberResult::Accepted,
        "replay capacity becomes available only after the full window");
}

void testMemoryPressurePolicy() {
  pm::MemoryPressurePolicy policy;
  auto update = policy.update(96U * 1024U, 48U * 1024U, 0U);
  check(!update.changed &&
            update.current == pm::MemoryPressureState::Normal,
        "healthy heap begins in normal memory state");

  update = policy.update(79U * 1024U, 31U * 1024U, 1'000U);
  check(update.changed &&
            update.current == pm::MemoryPressureState::PressureWarning,
        "moderate pressure enters warning without low-memory mode");
  policy.update(70U * 1024U, 27U * 1024U, 2'000U);
  policy.update(70U * 1024U, 27U * 1024U, 3'000U);
  update = policy.update(70U * 1024U, 27U * 1024U, 4'000U);
  check(update.changed &&
            update.current == pm::MemoryPressureState::LowMemory,
        "three consecutive low samples enter low-memory mode");

  for (std::uint64_t second = 5U; second < 34U; ++second) {
    policy.update(96U * 1024U, 48U * 1024U, second * 1'000U);
  }
  update = policy.update(96U * 1024U, 48U * 1024U, 34'000U);
  check(update.changed &&
            update.current == pm::MemoryPressureState::Recovering,
        "low-memory mode requires sustained recovery and minimum dwell");
  update = policy.update(96U * 1024U, 48U * 1024U, 64'000U);
  check(update.changed &&
            update.current == pm::MemoryPressureState::Normal,
        "recovery dwell returns to normal without threshold oscillation");
  const pm::MemoryPressureMetrics metrics = policy.metrics(64'000U);
  check(metrics.entry_count == 1U && metrics.recovery_count == 1U &&
            metrics.transition_count == 4U &&
            metrics.cumulative_pressure_ms == 63'000U &&
            metrics.longest_pressure_episode_ms == 63'000U &&
            metrics.lowest_free_internal_bytes == 70U * 1024U &&
            metrics.lowest_largest_internal_block_bytes == 27U * 1024U,
        "memory pressure evidence retains bounded episode and minimum metrics");
}

void testProvisioningTransaction() {
  pm::provisioning_transaction::Journal journal;
  journal.previous_config_generation = 7;
  journal.enrollment_token = {1, 2, 3};
  journal.admin_salt = {4, 5};
  journal.admin_hash = {6, 7, 8};
  const std::vector<std::uint8_t> encoded =
      pm::provisioning_transaction::encode(journal);
  pm::provisioning_transaction::Journal decoded;
  check(!encoded.empty() &&
            pm::provisioning_transaction::decode(encoded, decoded) &&
            decoded.previous_config_generation == 7 &&
            decoded.enrollment_token == journal.enrollment_token &&
            decoded.admin_salt == journal.admin_salt &&
            decoded.admin_hash == journal.admin_hash,
        "provisioning rollback journal round trips with CRC");
  std::vector<std::uint8_t> corrupted = encoded;
  corrupted[corrupted.size() / 2] ^= 1U;
  check(!pm::provisioning_transaction::decode(corrupted, decoded),
        "corrupt provisioning rollback journal is rejected");
  check(pm::provisioning_transaction::recoveryAction(7, 7) ==
                pm::provisioning_transaction::RecoveryAction::
                    RestoreCredentials &&
            pm::provisioning_transaction::recoveryAction(7, 8) ==
                pm::provisioning_transaction::RecoveryAction::
                    RollbackConfigAndRestoreCredentials &&
            pm::provisioning_transaction::recoveryAction(7, 6) ==
                pm::provisioning_transaction::RecoveryAction::Conflict,
        "provisioning recovery distinguishes pre-commit, post-commit, and "
        "conflicting generations");
  pm::provisioning_transaction::scrub(journal);
  check(journal.enrollment_token.empty() && journal.admin_salt.empty() &&
            journal.admin_hash.empty(),
        "provisioning journal secrets are scrubbed after use");
}

void testStoragePolicy() {
  pm::StoragePolicy policy;
  check(pm::validateStoragePolicy(policy).valid,
        "recommended storage policy is valid");
  pm::StoragePolicy invalid = policy;
  invalid.warning_percent = invalid.notice_percent;
  check(!pm::validateStoragePolicy(invalid).valid,
        "unordered pressure thresholds are rejected");

  constexpr std::uint64_t gib = 1024ULL * 1024ULL * 1024ULL;
  check(pm::classifyStoragePressure(64U * gib, 30U * gib, policy) ==
            pm::StoragePressureState::Healthy,
        "healthy storage is classified above notice threshold");
  check(pm::classifyStoragePressure(64U * gib, 6U * gib, policy) ==
            pm::StoragePressureState::Warning,
        "ten-percent storage is warning");
  check(pm::classifyStoragePressure(64U * gib, 400U * 1024U * 1024U,
                                    policy) ==
            pm::StoragePressureState::Emergency,
        "absolute emergency reserve protects large cards");

  pm::SegmentMetadata acknowledged;
  acknowledged.record_path = "/POWERMON/records/2026/07/2026-07-01.pmr";
  acknowledged.index_path = "/POWERMON/indexes/2026/07/2026-07-01.idx";
  acknowledged.first_sequence = 1;
  acknowledged.last_sequence = 100;
  acknowledged.first_utc_ms = 1'700'000'000'000ULL;
  acknowledged.last_utc_ms = 1'700'086'400'000ULL;
  acknowledged.payload_bytes = 1000;
  acknowledged.index_bytes = 100;
  acknowledged.record_count = 100;
  acknowledged.all_times_trusted = true;
  acknowledged.complete = true;
  acknowledged.index_valid = true;
  acknowledged.closed = true;

  pm::RetentionContext context;
  context.mode = pm::RetentionMode::StrictAge;
  context.acknowledgement_verified = true;
  context.server_ack_sequence = 100;
  context.retention_cutoff_utc_ms = 1'701'000'000'000ULL;
  context.minimum_history_cutoff_utc_ms = 1'701'000'000'000ULL;
  check(pm::segmentEligibility(acknowledged, context) ==
            pm::SegmentEligibility::EligibleAge,
        "complete trusted acknowledged old segment is eligible");
  pm::SegmentMetadata unacknowledged = acknowledged;
  unacknowledged.last_sequence = 101;
  check(pm::segmentEligibility(unacknowledged, context) ==
            pm::SegmentEligibility::Unacknowledged,
        "one sequence beyond acknowledgement remains protected");
  pm::SegmentMetadata active = acknowledged;
  active.active = true;
  check(pm::segmentEligibility(active, context) ==
            pm::SegmentEligibility::Active,
        "active segment is never eligible");
  pm::SegmentMetadata missing_index = acknowledged;
  missing_index.index_valid = false;
  check(pm::segmentEligibility(missing_index, context) ==
            pm::SegmentEligibility::CorruptOrMissingIndex,
        "missing index triggers recovery instead of deletion");
  pm::SegmentMetadata untrusted = acknowledged;
  untrusted.all_times_trusted = false;
  check(pm::segmentEligibility(untrusted, context) ==
            pm::SegmentEligibility::TimeUntrusted,
        "strict age protects untrusted-time history");
  context.mode = pm::RetentionMode::ContinuousProtected;
  context.emergency_pressure = true;
  check(pm::segmentEligibility(untrusted, context) ==
            pm::SegmentEligibility::EligibleEmergency,
        "explicit continuous emergency mode can reclaim acknowledged untrusted segment");
  untrusted.minimum_window_protected = true;
  check(pm::segmentEligibility(untrusted, context) ==
            pm::SegmentEligibility::MinimumWindow,
        "emergency cleanup preserves the minimum sequence/file window");
  untrusted.minimum_window_protected = false;
  pm::SegmentMetadata recent = acknowledged;
  recent.last_utc_ms = context.minimum_history_cutoff_utc_ms + 1U;
  check(pm::segmentEligibility(recent, context) ==
            pm::SegmentEligibility::TooRecent,
        "minimum recent history is protected during emergency cleanup");

  std::vector<pm::SegmentMetadata> segments{acknowledged, unacknowledged};
  const pm::CleanupPlan plan =
      pm::buildCleanupPlan(segments, context, 100U, 1000U);
  check(plan.candidate_indexes.size() == 1U &&
            plan.expected_reclaimed_bytes == 1100U &&
            plan.protected_unacknowledged_bytes == 1100U,
        "cleanup selects only the oldest eligible bytes and reports protected backlog");
  const pm::CleanupPlan target_already_met =
      pm::buildCleanupPlan(segments, context, 1000U, 1000U);
  check(target_already_met.candidate_indexes.empty() &&
            target_already_met.eligible_bytes == 1100U,
        "pressure cleanup stops without deleting eligible evidence once the free-space target is met");
  const pm::CleanupPlan ordinary_age_cleanup =
      pm::buildCleanupPlan(segments, context, 1000U, 0U);
  check(ordinary_age_cleanup.candidate_indexes.size() == 1U,
        "ordinary age cleanup still selects all age-eligible segments without a pressure target");
  check(pm::conservativeWriteReserveBytes(4096U) > 300U * 1024U,
        "write reserve includes journals and filesystem overhead");

  pm::StorageGrowthEstimator growth;
  growth.observe(1'000U, 1'000U);
  growth.observe(2'000U, 86'401'000U);
  growth.observe(3'000U, 172'801'000U);
  check(growth.bytesPerDay() == 1000U &&
            growth.estimatedDaysRemaining(20'000U, 5'000U) == 15,
        "growth estimate uses bounded daily precision");
}

void testCleanupRecoveryPolicy() {
  using pm::CleanupRecoveryAction;
  using pm::CleanupRecoverySnapshot;
  using pm::cleanupRecoveryAction;

  CleanupRecoverySnapshot snapshot{"planned", true, true, false, true, false};
  check(cleanupRecoveryAction(snapshot) ==
            CleanupRecoveryAction::ClearJournal,
        "untouched planned cleanup only clears its journal");
  snapshot = {"planned", true, false, true, true, false};
  check(cleanupRecoveryAction(snapshot) ==
            CleanupRecoveryAction::ReverseMoves,
        "partial pre-commit move is rolled back");
  snapshot = {"planned", true, false, true, false, true};
  check(cleanupRecoveryAction(snapshot) ==
            CleanupRecoveryAction::ReverseMoves,
        "complete pre-commit move is rolled back");
  snapshot = {"planned", true, true, true, true, false};
  check(cleanupRecoveryAction(snapshot) == CleanupRecoveryAction::Block,
        "ambiguous duplicate record copies block cleanup recovery");
  snapshot = {"planned", true, false, false, true, false};
  check(cleanupRecoveryAction(snapshot) == CleanupRecoveryAction::Block,
        "missing record copies block cleanup recovery");
  snapshot = {"planned", true, true, false, false, false};
  check(cleanupRecoveryAction(snapshot) == CleanupRecoveryAction::Block,
        "missing index copies block cleanup recovery");
  snapshot = {"files_moved", true, false, true, false, true};
  check(cleanupRecoveryAction(snapshot) ==
            CleanupRecoveryAction::ForwardDelete,
        "committed moved files are deleted forward");
  snapshot = {"record_deleted", true, false, false, false, true};
  check(cleanupRecoveryAction(snapshot) ==
            CleanupRecoveryAction::ForwardDelete,
        "committed remaining index trash is deleted forward");
  snapshot = {"complete", true, false, false, false, false};
  check(cleanupRecoveryAction(snapshot) ==
            CleanupRecoveryAction::ClearJournal,
        "complete clean transaction clears its journal");
  snapshot = {"files_moved", true, true, false, false, true};
  check(cleanupRecoveryAction(snapshot) == CleanupRecoveryAction::Block,
        "an original reappearing after commit blocks cleanup recovery");
  snapshot = {"unknown", false, true, false, false, false};
  check(cleanupRecoveryAction(snapshot) == CleanupRecoveryAction::Block,
        "unknown cleanup stage is fail-safe");
}
} // namespace

int main() {
  testPzem();
  testEnergyAndRecord();
  testReadingWireFormat();
  testDiagnostics();
  testNetworkPolicy();
  testClockPolicy();
  testServerSyncPolicy();
  testConfigRecovery();
  testConfigValidationHelpers();
  testAtomicConfigStore();
  testSyncCoverage();
  testProtocolCanonicalization();
  testAuthenticationPolicy();
  testMemoryPressurePolicy();
  testStoragePolicy();
  testCleanupRecoveryPolicy();
  testProvisioningTransaction();
  if (failures == 0) {
    std::cout << "native C++ tests passed\n";
  }
  return failures == 0 ? 0 : 1;
}
