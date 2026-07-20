#pragma once

#include <cstdint>

#include "core/Models.h"

namespace pm {

struct MeterMetrics {
  std::uint64_t requests{0};
  std::uint64_t successes{0};
  std::uint64_t timeouts{0};
  std::uint64_t crc_errors{0};
  std::uint64_t invalid_frames{0};
  std::uint32_t last_latency_ms{0};
  std::uint32_t consecutive_errors{0};
  MeterError last_error{MeterError::None};
};

class IMeter {
 public:
  virtual ~IMeter() = default;
  virtual bool begin() = 0;
  virtual MeasurementSnapshot poll(std::uint64_t utc_ms,
                                   std::uint64_t monotonic_ms,
                                   bool time_trusted) = 0;
  virtual MeterMetrics metrics() const = 0;
  virtual const char* methodName() const = 0;
};

}  // namespace pm

