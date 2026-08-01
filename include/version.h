#pragma once

#include <cstdint>

#ifndef PM_FIRMWARE_VERSION
#define PM_FIRMWARE_VERSION "1.0.9"
#endif
#ifndef PM_PROTOCOL_VERSION
#define PM_PROTOCOL_VERSION "pm-protocol/1.0.0"
#endif
#ifndef PM_GIT_COMMIT
#define PM_GIT_COMMIT "unknown"
#endif
#ifndef PM_BUILD_TIMESTAMP
#define PM_BUILD_TIMESTAMP "reproducible-local"
#endif
#ifndef PM_BUILD_UNIX_SECONDS
#define PM_BUILD_UNIX_SECONDS 1704067200ULL
#endif
#ifndef PM_PLATFORMIO_ENVIRONMENT
#define PM_PLATFORMIO_ENVIRONMENT "unknown"
#endif

namespace pm::version {
inline constexpr char FIRMWARE[] = PM_FIRMWARE_VERSION;
inline constexpr char PROTOCOL[] = PM_PROTOCOL_VERSION;
inline constexpr char GIT_COMMIT[] = PM_GIT_COMMIT;
inline constexpr char BUILD_TIMESTAMP[] = PM_BUILD_TIMESTAMP;
inline constexpr std::uint64_t BUILD_UNIX_SECONDS = PM_BUILD_UNIX_SECONDS;
inline constexpr char PLATFORMIO_ENVIRONMENT[] = PM_PLATFORMIO_ENVIRONMENT;
inline constexpr char HARDWARE_TARGET[] = "esp32-s3-n16r8";
} // namespace pm::version
