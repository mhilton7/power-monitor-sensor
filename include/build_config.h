#pragma once

#include <cstddef>
#include <cstdint>

#ifndef PM_SIMULATED_METER
#define PM_SIMULATED_METER 0
#endif

#ifndef PM_RELEASE_BUILD
#define PM_RELEASE_BUILD 0
#endif

#ifndef PM_PHYSICAL_ADMIN_RECOVERY
#define PM_PHYSICAL_ADMIN_RECOVERY 0
#endif

namespace pm::build {
inline constexpr char PRODUCT_NAME[] = "Power Monitor Sensor Agent";
inline constexpr char DEFAULT_FRIENDLY_NAME[] = "Unassigned Power Monitor";
inline constexpr char DEFAULT_TIMEZONE[] = "America/Los_Angeles";
inline constexpr char MDNS_SERVICE[] = "powermonitor";
inline constexpr char API_VERSION[] = "1.0";
inline constexpr std::uint32_t DEFAULT_SAMPLE_MS = 1000;
inline constexpr std::uint32_t DEFAULT_LOG_MS = 60000;
inline constexpr std::uint32_t DEFAULT_HEARTBEAT_MS = 15000;
inline constexpr std::uint32_t DEFAULT_SD_SPI_HZ = 4'000'000;
inline constexpr std::uint32_t MAX_SD_SPI_HZ = 20'000'000;
inline constexpr std::size_t MAX_HISTORY_PAGE = 500;
inline constexpr std::size_t MAX_JSON_BODY = 16384;
inline constexpr std::size_t STORAGE_QUEUE_DEPTH = 64;
inline constexpr std::size_t ACTION_QUEUE_DEPTH = 12;
inline constexpr std::size_t OFFLINE_RECORD_QUEUE_DEPTH = 120;
inline constexpr std::uint32_t SIGNATURE_WINDOW_SECONDS = 300;
inline constexpr std::uint32_t SESSION_TTL_SECONDS = 900;
inline constexpr std::uint32_t SETUP_AP_TTL_SECONDS = 900;
inline constexpr std::uint32_t PBKDF2_ITERATIONS = 120000;
static_assert(!PM_RELEASE_BUILD || !PM_SIMULATED_METER,
              "Simulated readings are forbidden in release firmware");
static_assert(
    !PM_RELEASE_BUILD || !PM_PHYSICAL_ADMIN_RECOVERY,
    "Physical administrator recovery is forbidden in release firmware");
} // namespace pm::build
