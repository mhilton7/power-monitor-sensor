#include "diagnostics/DiagnosticCore.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace pm {
namespace diag {
namespace {

void copyText(char *output, const std::size_t size, const char *value) {
  if (output == nullptr || size == 0)
    return;
  std::snprintf(output, size, "%s", value == nullptr ? "" : value);
}

std::string lower(const char *value) {
  std::string result = value == nullptr ? "" : value;
  std::transform(result.begin(), result.end(), result.begin(),
                 [](const unsigned char character) {
                   return static_cast<char>(std::tolower(character));
                 });
  return result;
}

bool tokenDelimiter(const char value) {
  return value == ' ' || value == '\t' || value == '\r' || value == '\n' ||
         value == '&' || value == ',' || value == ';' || value == '{' ||
         value == '[' || value == '}' || value == ']';
}

bool findAssignment(const char *input, const std::size_t start,
                    std::size_t &key_start, std::size_t &key_length,
                    std::size_t &separator) {
  if (input == nullptr || input[start] == '\0' ||
      (start != 0 && !tokenDelimiter(input[start]) &&
       !tokenDelimiter(input[start - 1]))) {
    return false;
  }
  std::size_t cursor = start;
  while (input[cursor] == ' ' || input[cursor] == '\t')
    ++cursor;
  const char quote =
      input[cursor] == '"' || input[cursor] == '\'' ? input[cursor++] : '\0';
  key_start = cursor;
  while (input[cursor] != '\0' && input[cursor] != '=' &&
         input[cursor] != ':' && input[cursor] != ' ' &&
         input[cursor] != '\t' && (quote == '\0' || input[cursor] != quote) &&
         !tokenDelimiter(input[cursor])) {
    ++cursor;
  }
  key_length = cursor - key_start;
  if (quote != '\0') {
    if (input[cursor] != quote)
      return false;
    ++cursor;
  }
  while (input[cursor] == ' ' || input[cursor] == '\t')
    ++cursor;
  if (key_length == 0 || (input[cursor] != '=' && input[cursor] != ':')) {
    return false;
  }
  separator = cursor;
  return true;
}

bool assignmentStartsAfter(const char *input, const std::size_t cursor) {
  std::size_t key_start = 0;
  std::size_t key_length = 0;
  std::size_t separator = 0;
  return findAssignment(input, cursor, key_start, key_length, separator);
}

} // namespace

const char *levelName(const LogLevel level) {
  switch (level) {
  case LogLevel::Trace:
    return "TRACE";
  case LogLevel::Debug:
    return "DEBUG";
  case LogLevel::Info:
    return "INFO";
  case LogLevel::Warn:
    return "WARN";
  case LogLevel::Error:
    return "ERROR";
  case LogLevel::Fatal:
    return "FATAL";
  }
  return "INFO";
}

bool parseLogLevel(const char *value, LogLevel &level) {
  const std::string normalized = lower(value);
  if (normalized == "trace" || normalized == "0") {
    level = LogLevel::Trace;
  } else if (normalized == "debug" || normalized == "1") {
    level = LogLevel::Debug;
  } else if (normalized == "info" || normalized == "2") {
    level = LogLevel::Info;
  } else if (normalized == "warn" || normalized == "warning" ||
             normalized == "3") {
    level = LogLevel::Warn;
  } else if (normalized == "error" || normalized == "4") {
    level = LogLevel::Error;
  } else if (normalized == "fatal" || normalized == "5") {
    level = LogLevel::Fatal;
  } else {
    return false;
  }
  return true;
}

bool shouldLog(const LogLevel configured_level, const LogLevel message_level) {
  return static_cast<std::uint8_t>(message_level) >=
         static_cast<std::uint8_t>(configured_level);
}

bool sensitiveKey(const char *key) {
  const std::string normalized = lower(key);
  static constexpr const char *sensitive[] = {
      "password",      "passwd",  "secret",     "token",
      "authorization", "cookie",  "signature",  "private_key",
      "api_key",       "session", "credential", "csrf"};
  for (const char *item : sensitive) {
    if (normalized.find(item) != std::string::npos)
      return true;
  }
  return false;
}

void redactSensitiveAssignments(const char *input, char *output,
                                const std::size_t output_size) {
  if (output == nullptr || output_size == 0)
    return;
  output[0] = '\0';
  if (input == nullptr)
    return;
  std::size_t source = 0;
  std::size_t destination = 0;
  while (input[source] != '\0' && destination + 1U < output_size) {
    std::size_t key_start = 0;
    std::size_t key_length = 0;
    std::size_t separator = 0;
    if (findAssignment(input, source, key_start, key_length, separator)) {
      char key[64]{};
      const std::size_t bounded_key_length =
          std::min<std::size_t>(key_length, sizeof(key) - 1U);
      std::memcpy(key, input + key_start, bounded_key_length);
      if (sensitiveKey(key)) {
        while (source <= separator && destination + 1U < output_size) {
          output[destination++] = input[source++];
        }
        static constexpr char redacted[] = "[REDACTED]";
        for (const char character : redacted) {
          if (character == '\0' || destination + 1U >= output_size)
            break;
          output[destination++] = character;
        }
        while (input[source] == ' ' || input[source] == '\t')
          ++source;
        const bool quoted = input[source] == '"' || input[source] == '\'';
        const char quote = quoted ? input[source++] : '\0';
        bool escaped = false;
        while (input[source] != '\0') {
          if (quoted) {
            if (!escaped && input[source] == quote) {
              ++source;
              break;
            }
            if (!escaped && input[source] == '\\') {
              escaped = true;
            } else {
              escaped = false;
            }
            ++source;
            continue;
          }
          if (input[source] == '&' || input[source] == ',' ||
              input[source] == ';' || input[source] == '\r' ||
              input[source] == '\n' || input[source] == '}' ||
              input[source] == ']') {
            break;
          }
          if ((input[source] == ' ' || input[source] == '\t') &&
              assignmentStartsAfter(input, source)) {
            break;
          }
          ++source;
        }
        continue;
      }
    }
    output[destination++] = input[source++];
  }
  output[destination] = '\0';
}

std::string maskSsid(const std::string &value) {
  if (value.empty())
    return "<missing>";
  if (value.size() <= 2U)
    return "**";
  if (value.size() <= 4U)
    return value.substr(0, 1) + "**" + value.back();
  return value.substr(0, 2) + "***" + value.substr(value.size() - 2U);
}

std::string maskIdentifier(const std::string &value) {
  if (value.empty())
    return "<missing>";
  return value.substr(0, std::min<std::size_t>(8U, value.size())) +
         "-****-****-****-************";
}

std::string maskMac(const std::string &value) {
  if (value.size() < 8U)
    return "**:**:**:**:**:**";
  return value.substr(0, 8U) + ":**:**:**";
}

ReasonInfo wifiDisconnectReason(const std::uint16_t reason) {
  switch (reason) {
  case 1:
    return {"UNSPECIFIED", "The access point gave no specific reason.", "",
            "PM-WIFI-099"};
  case 2:
    return {"AUTH_EXPIRE", "Authentication expired.",
            "Check signal strength and access point stability.", "PM-WIFI-003"};
  case 3:
    return {"AUTH_LEAVE", "The station left authentication.", "",
            "PM-WIFI-099"};
  case 4:
    return {"ASSOC_EXPIRE", "Association expired.",
            "Check access point compatibility and signal strength.",
            "PM-WIFI-004"};
  case 5:
    return {"ASSOC_TOOMANY", "The access point rejected another station.",
            "Check the access point client limit.", "PM-WIFI-004"};
  case 6:
    return {"NOT_AUTHED", "The station is not authenticated.",
            "Verify the saved password and security mode.", "PM-WIFI-003"};
  case 7:
    return {"NOT_ASSOCED", "The station is not associated.", "", "PM-WIFI-004"};
  case 8:
    return {"ASSOC_LEAVE", "The station intentionally left association.", "",
            "PM-WIFI-099"};
  case 9:
    return {"ASSOC_NOT_AUTHED",
            "Association was rejected before authentication.",
            "Verify access point security compatibility.", "PM-WIFI-004"};
  case 10:
    return {"DISASSOC_PWRCAP_BAD",
            "The access point rejected station power capability.", "",
            "PM-WIFI-004"};
  case 11:
    return {"DISASSOC_SUPCHAN_BAD",
            "The access point rejected supported channels.",
            "Use a compatible 2.4 GHz channel.", "PM-WIFI-004"};
  case 13:
    return {"IE_INVALID", "A Wi-Fi information element was invalid.", "",
            "PM-WIFI-004"};
  case 14:
    return {"MIC_FAILURE", "Wi-Fi message integrity verification failed.",
            "Verify security mode and signal quality.", "PM-WIFI-003"};
  case 15:
    return {"FOUR_WAY_HANDSHAKE_TIMEOUT",
            "The WPA four-way handshake timed out.",
            "Verify the saved password and WPA2/WPA3 compatibility.",
            "PM-WIFI-003"};
  case 16:
    return {"GROUP_KEY_UPDATE_TIMEOUT", "Group-key update timed out.", "",
            "PM-WIFI-003"};
  case 17:
    return {"IE_IN_4WAY_DIFFERS",
            "Security parameters changed during the handshake.", "",
            "PM-WIFI-003"};
  case 18:
    return {"GROUP_CIPHER_INVALID", "The group cipher is unsupported.",
            "Use WPA2-AES or WPA2/WPA3 transition mode.", "PM-WIFI-003"};
  case 19:
    return {"PAIRWISE_CIPHER_INVALID", "The pairwise cipher is unsupported.",
            "Use WPA2-AES or WPA2/WPA3 transition mode.", "PM-WIFI-003"};
  case 20:
    return {"AKMP_INVALID",
            "The authentication key-management mode is unsupported.",
            "Use WPA2-Personal or WPA2/WPA3 transition mode.", "PM-WIFI-003"};
  case 21:
    return {"UNSUPPORTED_RSN_IE_VERSION",
            "The advertised RSN version is unsupported.", "", "PM-WIFI-003"};
  case 22:
    return {"INVALID_RSN_IE_CAP",
            "The advertised RSN capabilities are invalid.", "", "PM-WIFI-003"};
  case 23:
    return {"AUTH_8021X_FAILED", "802.1X authentication failed.",
            "This firmware expects a personal pre-shared-key network.",
            "PM-WIFI-003"};
  case 24:
    return {"CIPHER_SUITE_REJECTED", "The cipher suite was rejected.",
            "Use WPA2-AES or WPA2/WPA3 transition mode.", "PM-WIFI-003"};
  case 200:
    return {"BEACON_TIMEOUT", "Access point beacons were lost.",
            "Check signal strength and access point stability.", "PM-WIFI-005"};
  case 201:
    return {"NO_AP_FOUND", "The configured access point was not found.",
            "Verify the masked SSID and that 2.4 GHz is enabled.",
            "PM-WIFI-002"};
  case 202:
    return {"AUTH_FAIL", "The access point rejected authentication.",
            "Verify the saved Wi-Fi password and access point security mode.",
            "PM-WIFI-003"};
  case 203:
    return {"ASSOC_FAIL", "The access point rejected association.",
            "Check access point compatibility and client limits.",
            "PM-WIFI-004"};
  case 204:
    return {"HANDSHAKE_TIMEOUT", "The security handshake timed out.",
            "Verify the password, security mode, and signal strength.",
            "PM-WIFI-003"};
  case 205:
    return {"CONNECTION_FAIL", "The Wi-Fi connection could not complete.",
            "Check access point compatibility and signal strength.",
            "PM-WIFI-004"};
  case 206:
    return {"AP_TSF_RESET", "The access point reset its timing state.", "",
            "PM-WIFI-005"};
  case 207:
    return {"ROAMING", "The station is roaming between access points.", "",
            "PM-WIFI-005"};
  default:
    return {"UNKNOWN", "The Wi-Fi driver returned an unrecognized reason.",
            "Retain the numeric code when requesting support.", "PM-WIFI-099"};
  }
}

const char *wifiStatusName(const int status) {
  switch (status) {
  case 0:
    return "association_or_dhcp_pending";
  case 1:
    return "ssid_not_found";
  case 2:
    return "scan_completed";
  case 3:
    return "connected";
  case 4:
    return "authentication_or_connection_failed";
  case 5:
    return "connection_lost";
  case 6:
    return "disconnected";
  default:
    return "unknown";
  }
}

const char *resetReasonName(const int reason) {
  switch (reason) {
  case 1:
    return "POWER_ON";
  case 2:
    return "EXTERNAL_RESET";
  case 3:
    return "SOFTWARE_RESET";
  case 4:
    return "PANIC";
  case 5:
    return "INTERRUPT_WATCHDOG";
  case 6:
    return "TASK_WATCHDOG";
  case 7:
    return "WATCHDOG";
  case 8:
    return "DEEP_SLEEP";
  case 9:
    return "BROWNOUT";
  default:
    return "UNKNOWN";
  }
}

const char *wakeupReasonName(const int reason) {
  switch (reason) {
  case 0:
    return "UNDEFINED";
  case 2:
    return "EXT0";
  case 3:
    return "EXT1";
  case 4:
    return "TIMER";
  case 5:
    return "TOUCHPAD";
  case 6:
    return "ULP";
  case 7:
    return "GPIO";
  case 8:
    return "UART";
  default:
    return "UNKNOWN";
  }
}

const char *tlsErrorCategory(const char *error) {
  const std::string value = lower(error);
  if (value.empty() || value.find("empty") != std::string::npos)
    return "CA_EMPTY";
  if (value.find("missing") != std::string::npos ||
      value.find("not_configured") != std::string::npos)
    return "CA_MISSING";
  if (value.find("pem") != std::string::npos ||
      value.find("parse") != std::string::npos)
    return "CA_PEM_INVALID";
  if (value.find("hostname") != std::string::npos)
    return "HOSTNAME_MISMATCH";
  if (value.find("unknown_ca") != std::string::npos ||
      value.find("unknown ca") != std::string::npos ||
      value.find("not trusted") != std::string::npos)
    return "UNKNOWN_CA";
  if (value.find("not yet valid") != std::string::npos ||
      value.find("future") != std::string::npos)
    return "CERT_NOT_YET_VALID";
  if (value.find("expired") != std::string::npos)
    return "CERT_EXPIRED";
  if (value.find("memory") != std::string::npos ||
      value.find("allocation") != std::string::npos ||
      value.find("heap") != std::string::npos)
    return "MEMORY_EXHAUSTED";
  if (value.find("closed") != std::string::npos ||
      value.find("truncated") != std::string::npos)
    return "CONNECTION_CLOSED";
  if (value.find("refused") != std::string::npos)
    return "CONNECTION_REFUSED";
  if (value.find("timeout") != std::string::npos)
    return "TLS_HANDSHAKE_TIMEOUT";
  if (value.find("time") != std::string::npos)
    return "TIME_NOT_TRUSTED";
  if (value.find("verify") != std::string::npos ||
      value.find("certificate") != std::string::npos)
    return "CERT_CHAIN_INVALID";
  return "TLS_NEGOTIATION_FAILED";
}

const char *httpStatusCategory(const int status) {
  switch (status) {
  case 200:
    return "success";
  case 201:
    return "created";
  case 202:
    return "accepted";
  case 204:
    return "no_content";
  case 400:
    return "invalid_request";
  case 401:
    return "authentication_rejected";
  case 403:
    return "access_denied";
  case 404:
    return "endpoint_not_found";
  case 408:
    return "timeout";
  case 409:
    return "conflict";
  case 410:
    return "history_not_retained";
  case 413:
    return "payload_too_large";
  case 422:
    return "validation_failed";
  case 429:
    return "rate_limited";
  case 500:
    return "server_error";
  case 502:
    return "gateway_error";
  case 503:
    return "unavailable";
  case 504:
    return "gateway_timeout";
  default:
    return status > 0 ? "http_status" : "transport_error";
  }
}

std::size_t formatLine(char *output, const std::size_t output_size,
                       const std::uint64_t monotonic_ms, const LogLevel level,
                       const char *subsystem, const char *event,
                       const char *detail) {
  if (output == nullptr || output_size == 0)
    return 0;
  const int length = std::snprintf(
      output, output_size, "[%09llu][%-5s][%-9s][%s] %s",
      static_cast<unsigned long long>(monotonic_ms), levelName(level),
      subsystem == nullptr ? "SYSTEM" : subsystem,
      event == nullptr ? "UNSPECIFIED" : event,
      detail == nullptr ? "" : detail);
  if (length <= 0) {
    output[0] = '\0';
    return 0;
  }
  return std::min<std::size_t>(static_cast<std::size_t>(length),
                               output_size - 1U);
}

bool RateLimiter::allow(const char *key, const std::uint64_t now_ms,
                        const std::uint32_t interval_ms) {
  if (key == nullptr || key[0] == '\0')
    return true;
  Slot *empty = nullptr;
  for (auto &slot : slots_) {
    if (!slot.used && empty == nullptr)
      empty = &slot;
    if (slot.used && std::strncmp(slot.key.data(), key, slot.key.size()) == 0) {
      if (now_ms < slot.next_allowed_ms)
        return false;
      slot.next_allowed_ms = now_ms + interval_ms;
      return true;
    }
  }
  Slot &slot = empty == nullptr ? slots_[now_ms % slots_.size()] : *empty;
  slot.used = true;
  copyText(slot.key.data(), slot.key.size(), key);
  slot.next_allowed_ms = now_ms + interval_ms;
  return true;
}

} // namespace diag
} // namespace pm
