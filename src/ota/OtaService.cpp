#include "ota/OtaService.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <vector>

#include <ArduinoJson.h>
#include <ESP.h>
#include <ESPmDNS.h>
#include <HTTPClient.h>
#include <Update.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <esp_ota_ops.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha256.h>
#include <sodium.h>

#include "config/ConfigValidationHelpers.h"
#include "diagnostics/SerialLogger.h"
#include "network/ResolvedTlsClient.h"
#include "security/Crypto.h"
#include "version.h"

namespace pm {
namespace {

bool parseHttpsTarget(const std::string &url, std::string &host,
                      std::uint16_t &port) {
  if (url.rfind("https://", 0) != 0)
    return false;
  const std::size_t start = 8;
  const std::size_t end = url.find_first_of("/?#", start);
  if (end != std::string::npos && url[end] == '#')
    return false;
  const std::string authority = url.substr(start, end - start);
  if (authority.empty() || authority.find('@') != std::string::npos ||
      authority.find('\\') != std::string::npos) {
    return false;
  }

  std::string encoded_port;
  if (authority.front() == '[') {
    const std::size_t close = authority.find(']');
    if (close == std::string::npos || close == 1)
      return false;
    host = authority.substr(1, close - 1);
    if (close + 1 < authority.size()) {
      if (authority[close + 1] != ':')
        return false;
      encoded_port = authority.substr(close + 2);
    }
  } else {
    const std::size_t colon = authority.rfind(':');
    if (colon != std::string::npos) {
      if (authority.find(':') != colon)
        return false;
      host = authority.substr(0, colon);
      encoded_port = authority.substr(colon + 1);
    } else {
      host = authority;
    }
  }
  port = 443;
  if (!encoded_port.empty()) {
    if (!std::all_of(
            encoded_port.begin(), encoded_port.end(),
            [](const char value) { return value >= '0' && value <= '9'; })) {
      return false;
    }
    const unsigned long parsed =
        std::strtoul(encoded_port.c_str(), nullptr, 10);
    if (parsed == 0 || parsed > 65535U)
      return false;
    port = static_cast<std::uint16_t>(parsed);
  } else if (authority.back() == ':') {
    return false;
  }
  return !host.empty() && port != 0;
}

bool dotLocalHost(const std::string &host) {
  static constexpr char suffix[] = ".local";
  if (host.size() <= sizeof(suffix) - 1U)
    return false;
  const std::size_t offset = host.size() - (sizeof(suffix) - 1U);
  for (std::size_t index = 0; index < sizeof(suffix) - 1U; ++index) {
    if (static_cast<char>(std::tolower(static_cast<unsigned char>(
            host[offset + index]))) != suffix[index]) {
      return false;
    }
  }
  return true;
}

bool resolveHttpsTarget(const std::string &url, std::string &host,
                        std::uint16_t &port, IPAddress &address,
                        const char *&method) {
  if (!parseHttpsTarget(url, host, port))
    return false;
  const bool literal = address.fromString(host.c_str());
  method = literal ? "literal" : "dns";
  bool resolved = literal || (WiFi.hostByName(host.c_str(), address) == 1 &&
                              static_cast<std::uint32_t>(address) != 0U &&
                              address != INADDR_NONE);
  if (!resolved && dotLocalHost(host)) {
    const std::string query =
        host.substr(0, host.size() - std::strlen(".local"));
    address = MDNS.queryHost(query.c_str(), 2000U);
    resolved =
        static_cast<std::uint32_t>(address) != 0U && address != INADDR_NONE;
    if (resolved)
      method = "mdns";
  }
  return resolved;
}

bool parseSemver(const std::string &value, std::array<unsigned int, 3> &parts) {
  char trailing = '\0';
  return std::sscanf(value.c_str(), "%u.%u.%u%c", &parts[0], &parts[1],
                     &parts[2], &trailing) == 3;
}

bool validSemver(const std::string &value) {
  std::array<unsigned int, 3> parts{};
  return parseSemver(value, parts);
}

bool hostAllowed(const RuntimeConfig &config, const std::string &url) {
  std::string host;
  std::uint16_t port = 443;
  if (!parseHttpsTarget(url, host, port))
    return false;
  bool constrained = false;
  for (const auto &allowed : config.allowed_server_addresses) {
    if (allowed.empty())
      continue;
    constrained = true;
    if (allowed == host)
      return true;
  }
  return !constrained;
}

bool withinUpdateWindow(const RuntimeConfig &config) {
  if (!config.ota_update_window_enabled)
    return true;
  const std::time_t now = std::time(nullptr);
  if (now < 1'600'000'000)
    return false;
  std::tm utc{};
  gmtime_r(&now, &utc);
  const int start = config.ota_update_window_start_hour;
  const int end = config.ota_update_window_end_hour;
  return start < end ? utc.tm_hour >= start && utc.tm_hour < end
                     : utc.tm_hour >= start || utc.tm_hour < end;
}

bool strictBase64(const std::string &encoded) {
  if (encoded.empty() || encoded.size() % 4U != 0U)
    return false;
  bool padding = false;
  std::size_t padding_count = 0;
  for (const unsigned char value : encoded) {
    if (value == '=') {
      padding = true;
      ++padding_count;
      if (padding_count > 2U)
        return false;
      continue;
    }
    if (padding || !(std::isalnum(value) || value == '+' || value == '/')) {
      return false;
    }
  }
  return true;
}

void appendHexEscape(std::string &output, const std::uint32_t value) {
  static constexpr char digits[] = "0123456789abcdef";
  output += "\\u";
  output.push_back(digits[(value >> 12U) & 0x0FU]);
  output.push_back(digits[(value >> 8U) & 0x0FU]);
  output.push_back(digits[(value >> 4U) & 0x0FU]);
  output.push_back(digits[value & 0x0FU]);
}

bool appendPythonJsonString(std::string &output, const std::string &input) {
  output.push_back('"');
  std::size_t index = 0;
  while (index < input.size()) {
    const std::uint8_t first = static_cast<std::uint8_t>(input[index++]);
    std::uint32_t codepoint = first;
    if ((first & 0x80U) != 0U) {
      std::size_t continuation_count = 0;
      std::uint32_t minimum = 0;
      if ((first & 0xE0U) == 0xC0U) {
        continuation_count = 1;
        codepoint = first & 0x1FU;
        minimum = 0x80U;
      } else if ((first & 0xF0U) == 0xE0U) {
        continuation_count = 2;
        codepoint = first & 0x0FU;
        minimum = 0x800U;
      } else if ((first & 0xF8U) == 0xF0U) {
        continuation_count = 3;
        codepoint = first & 0x07U;
        minimum = 0x10000U;
      } else {
        return false;
      }
      if (index + continuation_count > input.size())
        return false;
      for (std::size_t count = 0; count < continuation_count; ++count) {
        const std::uint8_t next = static_cast<std::uint8_t>(input[index++]);
        if ((next & 0xC0U) != 0x80U)
          return false;
        codepoint = (codepoint << 6U) | (next & 0x3FU);
      }
      if (codepoint < minimum || codepoint > 0x10FFFFU ||
          (codepoint >= 0xD800U && codepoint <= 0xDFFFU)) {
        return false;
      }
    }
    switch (codepoint) {
    case '"':
      output += "\\\"";
      break;
    case '\\':
      output += "\\\\";
      break;
    case '\b':
      output += "\\b";
      break;
    case '\f':
      output += "\\f";
      break;
    case '\n':
      output += "\\n";
      break;
    case '\r':
      output += "\\r";
      break;
    case '\t':
      output += "\\t";
      break;
    default:
      if (codepoint < 0x20U) {
        appendHexEscape(output, codepoint);
      } else if (codepoint < 0x80U) {
        output.push_back(static_cast<char>(codepoint));
      } else if (codepoint <= 0xFFFFU) {
        appendHexEscape(output, codepoint);
      } else {
        const std::uint32_t adjusted = codepoint - 0x10000U;
        appendHexEscape(output, 0xD800U + (adjusted >> 10U));
        appendHexEscape(output, 0xDC00U + (adjusted & 0x3FFU));
      }
      break;
    }
  }
  output.push_back('"');
  return true;
}

bool channelAllowed(const std::string &configured,
                    const std::string &manifest_channel) {
  if (configured == "beta")
    return manifest_channel == "canary";
  return configured == manifest_channel;
}

} // namespace

OtaService::OtaService(ConfigService &config) : config_(config) {
  mutex_ = xSemaphoreCreateMutex();
}

bool OtaService::runningImagePendingVerification() const {
  const esp_partition_t *running = esp_ota_get_running_partition();
  esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
  return running != nullptr &&
         esp_ota_get_state_partition(running, &state) == ESP_OK &&
         state == ESP_OTA_IMG_PENDING_VERIFY;
}

bool OtaService::checkRunningImage(const bool health_checks_passed) {
  const esp_partition_t *running = esp_ota_get_running_partition();
  esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
  if (running == nullptr ||
      esp_ota_get_state_partition(running, &state) != ESP_OK) {
    return false;
  }
  if (state == ESP_OTA_IMG_PENDING_VERIFY) {
    const bool valid = health_checks_passed &&
                       esp_ota_mark_app_valid_cancel_rollback() == ESP_OK;
    PM_LOG_INFO("OTA", "RUNNING_IMAGE_VALIDATION",
                "health_checks=%s result=%s rollback_cancelled=%s",
                health_checks_passed ? "passed" : "failed",
                valid ? "success" : "failed", valid ? "true" : "false");
    return valid;
  }
  PM_LOG_DEBUG("OTA", "RUNNING_IMAGE_STATE",
               "state=%d pending_verification=false", static_cast<int>(state));
  return true;
}

bool OtaService::applyFromManifestUrl(const std::string &manifest_url) {
  const bool safe_mode = config_.safeMode();
  const RuntimeConfig active_config = config_.config();
  const bool update_window_open = withinUpdateWindow(active_config);
  PM_LOG_INFO("OTA", "UPDATE_REQUESTED",
              "safe_mode=%s update_window=%s heap_free=%lu psram_free=%lu",
              safe_mode ? "true" : "false",
              update_window_open ? "open" : "closed",
              static_cast<unsigned long>(ESP.getFreeHeap()),
              static_cast<unsigned long>(ESP.getFreePsram()));
  if (in_progress_.exchange(true, std::memory_order_acq_rel)) {
    PM_LOG_WARN("OTA", "UPDATE_REJECTED",
                "error=PM-OTA-002 reason=already_in_progress");
    return false;
  }
  if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(100)) != pdTRUE) {
    in_progress_.store(false, std::memory_order_release);
    PM_LOG_WARN("OTA", "STATUS_LOCK_BUSY", "error=PM-OTA-001");
    return false;
  }
  if (safe_mode || !update_window_open) {
    status_.last_result = "rejected";
    status_.last_error =
        safe_mode ? "ota_disabled_in_safe_mode" : "outside_ota_update_window";
    PM_LOG_WARN("OTA", "UPDATE_REJECTED", "error=PM-OTA-002 reason=%s",
                safe_mode ? "safe_mode" : "outside_update_window");
    xSemaphoreGive(mutex_);
    in_progress_.store(false, std::memory_order_release);
    return false;
  }
  status_.in_progress = true;
  status_.pending_reboot = false;
  status_.bytes_received = 0;
  status_.image_size = 0;
  status_.target_version.clear();
  status_.last_result = "in_progress";
  status_.last_error.clear();
  xSemaphoreGive(mutex_);

  std::string manifest_json;
  std::string error;
  OtaManifest manifest;
  bool ok = fetchText(manifest_url, manifest_json, 32 * 1024, error) &&
            parseManifest(manifest_json, manifest, error) &&
            verifyManifest(manifest, error) &&
            downloadAndApply(manifest, error);
  in_progress_.store(false, std::memory_order_release);
  if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(250)) == pdTRUE) {
    status_.in_progress = false;
    status_.last_result = ok ? "verified_pending_reboot" : "failed";
    status_.last_error = error;
    status_.pending_reboot = ok;
    xSemaphoreGive(mutex_);
  } else {
    PM_LOG_ERROR("OTA", "STATUS_LOCK_TIMEOUT",
                 "error=PM-OTA-010 phase=completion timeout_ms=250");
  }
  const OtaStatus completion = status();
  PM_LOG_INFO("OTA", "UPDATE_COMPLETE",
              "result=%s target_version=%s bytes_received=%lu image_size=%lu "
              "error=%s heap_free=%lu",
              ok ? "verified_pending_reboot" : "failed",
              manifest.version.empty() ? "unknown" : manifest.version.c_str(),
              static_cast<unsigned long>(completion.bytes_received),
              static_cast<unsigned long>(completion.image_size),
              error.empty() ? "none" : error.c_str(),
              static_cast<unsigned long>(ESP.getFreeHeap()));
  if (ok) {
    delay(100);
    ESP.restart();
  }
  return ok;
}

bool OtaService::parseManifest(const std::string &json, OtaManifest &manifest,
                               std::string &error) const {
  JsonDocument document;
  const DeserializationError parse_error = deserializeJson(document, json);
  if (parse_error) {
    error = "ota_manifest_json_invalid";
    PM_LOG_ERROR("OTA", "MANIFEST_PARSE_FAILED",
                 "error=PM-OTA-003 category=json_invalid");
    return false;
  }
  if (!document["available"].is<bool>()) {
    error = "ota_manifest_required_field_missing";
    PM_LOG_ERROR("OTA", "MANIFEST_REJECTED",
                 "error=PM-OTA-003 category=available_missing");
    return false;
  }
  manifest.available = document["available"].as<bool>();
  if (!manifest.available) {
    error = "ota_update_not_available";
    PM_LOG_INFO("OTA", "MANIFEST_CURRENT", "available=false");
    return false;
  }
  if (!document["version"].is<const char *>() ||
      !document["channel"].is<const char *>() ||
      !document["hardware_target"].is<const char *>() ||
      !document["protocol_min"].is<const char *>() ||
      !document["protocol_max"].is<const char *>() ||
      !document["size_bytes"].is<std::uint32_t>() ||
      !document["sha256"].is<const char *>() ||
      !document["signature"].is<const char *>() ||
      !document["signing_key_id"].is<const char *>() ||
      !document["release_notes"].is<const char *>() ||
      !document["download_path"].is<const char *>()) {
    error = "ota_manifest_required_field_missing";
    PM_LOG_ERROR("OTA", "MANIFEST_REJECTED",
                 "error=PM-OTA-003 category=signed_fields_missing "
                 "required=version,channel,hardware_target,protocol_min,"
                 "protocol_max,size_bytes,sha256,signature,signing_key_id,"
                 "release_notes,download_path");
    return false;
  }
  if (!document["protocol_version"].isNull() &&
      (!document["protocol_version"].is<const char *>() ||
       std::string(document["protocol_version"].as<const char *>()) !=
           version::PROTOCOL)) {
    error = "ota_protocol_incompatible";
    return false;
  }
  manifest.version = document["version"].as<const char *>();
  manifest.channel = document["channel"].as<const char *>();
  manifest.hardware_target = document["hardware_target"].as<const char *>();
  manifest.protocol_min = document["protocol_min"].as<const char *>();
  manifest.protocol_max = document["protocol_max"].as<const char *>();
  manifest.size_bytes = document["size_bytes"].as<std::uint32_t>();
  manifest.sha256 = document["sha256"].as<const char *>();
  manifest.signature_base64 = document["signature"].as<const char *>();
  manifest.signing_key_id = document["signing_key_id"].as<const char *>();
  manifest.release_notes = document["release_notes"].as<const char *>();
  manifest.download_path = document["download_path"].as<const char *>();
  if (manifest.version.empty() || manifest.version.size() > 80U ||
      !validSemver(manifest.version) ||
      (manifest.channel != "development" && manifest.channel != "canary" &&
       manifest.channel != "stable") ||
      manifest.hardware_target.empty() ||
      manifest.hardware_target.size() > 120U || manifest.protocol_min.empty() ||
      manifest.protocol_min.size() > 64U || manifest.protocol_max.empty() ||
      manifest.protocol_max.size() > 64U || manifest.size_bytes == 0U ||
      manifest.size_bytes > 0x600000U || manifest.sha256.size() != 64U ||
      manifest.signature_base64.size() > 128U ||
      manifest.signing_key_id.empty() ||
      manifest.signing_key_id.size() > 128U ||
      manifest.release_notes.size() > 20'000U ||
      manifest.download_path.size() > 256U ||
      manifest.download_path.rfind("/api/v1/device-firmware/", 0) != 0U ||
      manifest.download_path.find_first_of("?#") != std::string::npos ||
      manifest.download_path.size() < std::strlen("/download") ||
      manifest.download_path.compare(
          manifest.download_path.size() - std::strlen("/download"),
          std::strlen("/download"), "/download") != 0 ||
      !std::all_of(manifest.sha256.begin(), manifest.sha256.end(),
                   [](const char value) {
                     return (value >= '0' && value <= '9') ||
                            (value >= 'a' && value <= 'f');
                   }) ||
      !strictBase64(manifest.signature_base64)) {
    error = "ota_manifest_field_invalid";
    PM_LOG_ERROR("OTA", "MANIFEST_REJECTED",
                 "error=PM-OTA-003 category=field_invalid");
    return false;
  }
  PM_LOG_INFO("OTA", "MANIFEST_PARSED",
              "target_version=%s protocol_min=%s protocol_max=%s hardware=%s "
              "image_size=%lu algorithm=ed25519 key_id=%s",
              manifest.version.c_str(), manifest.protocol_min.c_str(),
              manifest.protocol_max.c_str(), manifest.hardware_target.c_str(),
              static_cast<unsigned long>(manifest.size_bytes),
              manifest.signing_key_id.c_str());
  return true;
}

bool OtaService::verifyManifest(const OtaManifest &manifest,
                                std::string &error) const {
  const std::string current_protocol = version::PROTOCOL;
  if (current_protocol < manifest.protocol_min ||
      current_protocol > manifest.protocol_max) {
    error = "ota_protocol_incompatible";
    PM_LOG_ERROR("OTA", "POLICY_REJECTED",
                 "error=PM-OTA-004 reason=protocol_incompatible");
    return false;
  }
  if (manifest.hardware_target != version::HARDWARE_TARGET) {
    error = "ota_hardware_incompatible";
    PM_LOG_ERROR("OTA", "POLICY_REJECTED",
                 "error=PM-OTA-004 reason=hardware_incompatible");
    return false;
  }
  const RuntimeConfig active_config = config_.config();
  if (!channelAllowed(active_config.ota_channel, manifest.channel)) {
    error = "ota_channel_incompatible";
    PM_LOG_ERROR("OTA", "POLICY_REJECTED",
                 "error=PM-OTA-004 reason=channel_incompatible");
    return false;
  }
  if (compareSemver(manifest.version, version::FIRMWARE) <= 0) {
    error = "ota_downgrade_or_same_version_rejected";
    return false;
  }
  if (!active_config.ota_signing_key_id.empty() &&
      manifest.signing_key_id != active_config.ota_signing_key_id) {
    error = "ota_signing_key_id_mismatch";
    PM_LOG_ERROR("OTA", "SIGNING_KEY_REJECTED",
                 "error=PM-OTA-005 reason=key_id_mismatch expected=%s "
                 "received=%s",
                 active_config.ota_signing_key_id.c_str(),
                 manifest.signing_key_id.c_str());
    return false;
  }
  const std::string public_key = config_.otaPublicKey();
  if (public_key.empty()) {
    error = "ota_public_key_unavailable";
    PM_LOG_ERROR("OTA", "SIGNING_KEY_REJECTED",
                 "error=PM-OTA-005 reason=public_key_unavailable "
                 "provisioning=local_only");
    return false;
  }
  std::array<std::uint8_t, crypto_sign_ed25519_BYTES> signature{};
  std::size_t signature_length = 0;
  if (mbedtls_base64_decode(signature.data(), signature.size(),
                            &signature_length,
                            reinterpret_cast<const std::uint8_t *>(
                                manifest.signature_base64.data()),
                            manifest.signature_base64.size()) != 0 ||
      signature_length != signature.size()) {
    error = "ota_signature_base64_invalid";
    return false;
  }
  const std::string canonical = canonicalManifest(manifest);
  std::array<std::uint8_t, crypto_sign_ed25519_PUBLICKEYBYTES> raw_key{};
  const bool valid =
      sodium_init() >= 0 && !canonical.empty() &&
      config_validation::decodeEd25519PublicKeyPem(public_key, raw_key) &&
      crypto_sign_ed25519_verify_detached(
          signature.data(),
          reinterpret_cast<const unsigned char *>(canonical.data()),
          static_cast<unsigned long long>(canonical.size()),
          raw_key.data()) == 0;
  raw_key.fill(0U);
  signature.fill(0U);
  if (!valid) {
    error = "ota_signature_invalid";
    PM_LOG_ERROR("OTA", "SIGNATURE_INVALID",
                 "error=PM-OTA-005 algorithm=ed25519 key_id=%s",
                 manifest.signing_key_id.c_str());
  } else {
    PM_LOG_INFO("OTA", "SIGNATURE_VERIFIED",
                "algorithm=ed25519 target_version=%s key_id=%s",
                manifest.version.c_str(), manifest.signing_key_id.c_str());
  }
  return valid;
}

std::string OtaService::canonicalManifest(const OtaManifest &manifest) const {
  std::string output{"{\"channel\":"};
  if (!appendPythonJsonString(output, manifest.channel))
    return {};
  output += ",\"hardware_target\":";
  if (!appendPythonJsonString(output, manifest.hardware_target))
    return {};
  output += ",\"protocol_max\":";
  if (!appendPythonJsonString(output, manifest.protocol_max))
    return {};
  output += ",\"protocol_min\":";
  if (!appendPythonJsonString(output, manifest.protocol_min))
    return {};
  output += ",\"release_notes\":";
  if (!appendPythonJsonString(output, manifest.release_notes))
    return {};
  output += ",\"sha256\":";
  if (!appendPythonJsonString(output, manifest.sha256))
    return {};
  output += ",\"signing_key_id\":";
  if (!appendPythonJsonString(output, manifest.signing_key_id))
    return {};
  output += ",\"version\":";
  if (!appendPythonJsonString(output, manifest.version))
    return {};
  output.push_back('}');
  return output;
}

OtaStatus OtaService::status() const {
  if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(100)) != pdTRUE) {
    OtaStatus unavailable;
    unavailable.in_progress = in_progress_.load(std::memory_order_acquire);
    unavailable.last_result = "unavailable";
    unavailable.last_error = "ota_status_busy";
    return unavailable;
  }
  const OtaStatus copy = status_;
  xSemaphoreGive(mutex_);
  OtaStatus result = copy;
  result.in_progress = in_progress_.load(std::memory_order_acquire);
  return result;
}

bool OtaService::rollbackAndReboot() {
  const bool possible = esp_ota_check_rollback_is_possible();
  PM_LOG_WARN("OTA", "ROLLBACK_REQUESTED", "possible=%s",
              possible ? "true" : "false");
  return possible && esp_ota_mark_app_invalid_rollback_and_reboot() == ESP_OK;
}

bool OtaService::serverTarget(const RuntimeConfig &config,
                              const std::string &url,
                              std::string &target) const {
  target.clear();
  if (config.server_url.empty() ||
      url.compare(0, config.server_url.size(), config.server_url) != 0 ||
      url.size() <= config.server_url.size() ||
      url[config.server_url.size()] != '/') {
    return false;
  }
  target = url.substr(config.server_url.size());
  std::string canonical;
  if (!crypto::canonicalTarget(target, canonical)) {
    target.clear();
    return false;
  }
  return true;
}

bool OtaService::addDeviceAuthentication(HTTPClient &http, const char *method,
                                         const std::string &target,
                                         std::string &error) const {
  const std::time_t now = std::time(nullptr);
  if (now < 1'600'000'000) {
    error = "ota_time_not_trusted";
    return false;
  }
  const DeviceIdentity identity = config_.identity();
  crypto::Key32 outbound{};
  crypto::Key32 inbound{};
  if (!identity.enrolled || identity.device_id.empty() ||
      !config_.directionalKeys(outbound, inbound)) {
    error = "ota_device_credentials_unavailable";
    return false;
  }
  std::string canonical_target;
  if (!crypto::canonicalTarget(target, canonical_target)) {
    std::fill(outbound.begin(), outbound.end(), 0U);
    std::fill(inbound.begin(), inbound.end(), 0U);
    error = "ota_request_target_invalid";
    return false;
  }
  const std::string timestamp = std::to_string(now);
  const std::string nonce = crypto::randomHex(16);
  static constexpr std::uint8_t empty_body = 0U;
  const std::string body_hash = crypto::sha256Hex(&empty_body, 0U);
  const std::string canonical = crypto::canonicalRequest(
      method, canonical_target, timestamp, nonce, body_hash);
  const std::string signature =
      crypto::hmacSha256Hex(outbound.data(), outbound.size(), canonical);
  http.addHeader("X-PM-Protocol", version::PROTOCOL);
  http.addHeader("X-PM-Device-ID", identity.device_id.c_str());
  http.addHeader("X-PM-Timestamp", timestamp.c_str());
  http.addHeader("X-PM-Nonce", nonce.c_str());
  http.addHeader("X-PM-Content-SHA256", body_hash.c_str());
  http.addHeader("X-PM-Signature", signature.c_str());
  std::fill(outbound.begin(), outbound.end(), 0U);
  std::fill(inbound.begin(), inbound.end(), 0U);
  return true;
}

bool OtaService::fetchText(const std::string &url, std::string &body,
                           const std::size_t maximum_bytes,
                           std::string &error) const {
  if (url.rfind("https://", 0) != 0) {
    error = "ota_url_insecure";
    return false;
  }
  // WiFiClientSecure retains the CA pointer for the life of the connection.
  // Keep one immutable configuration snapshot alive until HTTPClient is done.
  const RuntimeConfig active_config = config_.config();
  std::string target;
  if (!serverTarget(active_config, url, target)) {
    error = "ota_server_origin_required";
    return false;
  }
  if (!hostAllowed(active_config, url)) {
    error = "ota_host_not_allowed";
    return false;
  }
  std::string tls_hostname;
  std::uint16_t tls_port = 443;
  IPAddress resolved_address;
  const char *resolution_method = "none";
  const std::uint64_t dns_started_ms = millis();
  if (!resolveHttpsTarget(url, tls_hostname, tls_port, resolved_address,
                          resolution_method)) {
    error = "ota_dns_resolution_failed";
    PM_LOG_ERROR("DNS", "OTA_LOOKUP_FAILED",
                 "error=PM-DNS-001 host=%s methods=dns,mdns_if_local "
                 "elapsed_ms=%llu",
                 tls_hostname.empty() ? "invalid" : tls_hostname.c_str(),
                 static_cast<unsigned long long>(millis() - dns_started_ms));
    return false;
  }
  PM_LOG_INFO("DNS", "OTA_LOOKUP_COMPLETE",
              "host=%s address=%s method=%s elapsed_ms=%llu",
              tls_hostname.c_str(), resolved_address.toString().c_str(),
              resolution_method,
              static_cast<unsigned long long>(millis() - dns_started_ms));
  ResolvedTlsClient client;
  if (!configureTls(client, active_config.server_ca_pem)) {
    error = active_config.server_ca_pem.empty() ? "tls_ca_not_configured"
                                                : "tls_configuration_failed";
    PM_LOG_ERROR("TLS", "OTA_TLS_REJECTED",
                 "error=PM-TLS-001 category=CA_MISSING "
                 "fingerprint_configured=%s insecure_mode=false",
                 active_config.server_fingerprint.empty() ? "false" : "true");
    return false;
  }
  client.setResolvedEndpoint(resolved_address, tls_hostname, tls_port);
  HTTPClient http;
  http.setConnectTimeout(5000);
  http.setTimeout(10000);
  if (!http.begin(client, url.c_str())) {
    error = "ota_manifest_http_begin_failed";
    return false;
  }
  if (!addDeviceAuthentication(http, "GET", target, error)) {
    http.end();
    return false;
  }
  PM_LOG_INFO("OTA", "MANIFEST_DOWNLOAD_BEGIN",
              "maximum_bytes=%u host=%s address=%s port=%u "
              "tls_validation=ca_and_hostname",
              static_cast<unsigned>(maximum_bytes), tls_hostname.c_str(),
              resolved_address.toString().c_str(),
              static_cast<unsigned>(tls_port));
  const int status = http.GET();
  if (status != 200) {
    error = status <= 0 ? "ota_manifest_tls_or_transport_failed"
                        : "ota_manifest_download_failed";
    http.end();
    return false;
  }
  PM_LOG_INFO("TLS", "OTA_HANDSHAKE_VERIFIED",
              "host=%s address=%s port=%u ca_validation=true "
              "hostname_validation=true",
              tls_hostname.c_str(), resolved_address.toString().c_str(),
              static_cast<unsigned>(tls_port));
  const int content_length = http.getSize();
  if (content_length < 0 || content_length > static_cast<int>(maximum_bytes)) {
    error = content_length < 0 ? "ota_manifest_length_required"
                               : "ota_manifest_too_large";
    http.end();
    return false;
  }
  WiFiClient *stream = http.getStreamPtr();
  std::array<std::uint8_t, 1024> buffer{};
  body.clear();
  if (content_length > 0) {
    body.reserve(static_cast<std::size_t>(content_length));
  }
  std::uint64_t last_progress_ms = millis();
  while (body.size() < static_cast<std::size_t>(content_length)) {
    const int available = stream->available();
    if (available <= 0) {
      if (!http.connected() || millis() - last_progress_ms > 10'000U) {
        error = http.connected() ? "ota_manifest_stream_timeout"
                                 : "ota_manifest_stream_interrupted";
        http.end();
        return false;
      }
      vTaskDelay(pdMS_TO_TICKS(2));
      continue;
    }
    const std::size_t room = maximum_bytes + 1U - body.size();
    const std::size_t wanted = std::min<std::size_t>(
        buffer.size(), std::min<std::size_t>(available, room));
    if (wanted == 0) {
      error = "ota_manifest_too_large";
      http.end();
      return false;
    }
    const int count = stream->readBytes(buffer.data(), wanted);
    if (count <= 0) {
      error = "ota_manifest_stream_interrupted";
      http.end();
      return false;
    }
    body.append(reinterpret_cast<const char *>(buffer.data()),
                static_cast<std::size_t>(count));
    last_progress_ms = millis();
    if (body.size() > maximum_bytes) {
      error = "ota_manifest_too_large";
      http.end();
      return false;
    }
  }
  if (body.size() != static_cast<std::size_t>(content_length)) {
    error = "ota_manifest_stream_interrupted";
    http.end();
    return false;
  }
  http.end();
  PM_LOG_INFO("OTA", "MANIFEST_DOWNLOAD_COMPLETE", "status=200 bytes=%u",
              static_cast<unsigned>(body.size()));
  return true;
}

bool OtaService::downloadAndApply(const OtaManifest &manifest,
                                  std::string &error) {
  // Keep the CA backing storage stable for the complete TLS/download
  // operation; ConfigService returns thread-safe values by copy.
  const RuntimeConfig active_config = config_.config();
  const std::string image_url =
      active_config.server_url + manifest.download_path;
  std::string target;
  if (!serverTarget(active_config, image_url, target) ||
      !hostAllowed(active_config, image_url)) {
    error = "ota_host_not_allowed";
    return false;
  }
  std::string tls_hostname;
  std::uint16_t tls_port = 443;
  IPAddress resolved_address;
  const char *resolution_method = "none";
  const std::uint64_t dns_started_ms = millis();
  if (!resolveHttpsTarget(image_url, tls_hostname, tls_port, resolved_address,
                          resolution_method)) {
    error = "ota_dns_resolution_failed";
    PM_LOG_ERROR("DNS", "OTA_LOOKUP_FAILED",
                 "error=PM-DNS-001 host=%s methods=dns,mdns_if_local "
                 "elapsed_ms=%llu",
                 tls_hostname.empty() ? "invalid" : tls_hostname.c_str(),
                 static_cast<unsigned long long>(millis() - dns_started_ms));
    return false;
  }
  PM_LOG_INFO("DNS", "OTA_LOOKUP_COMPLETE",
              "host=%s address=%s method=%s elapsed_ms=%llu",
              tls_hostname.c_str(), resolved_address.toString().c_str(),
              resolution_method,
              static_cast<unsigned long long>(millis() - dns_started_ms));
  ResolvedTlsClient client;
  if (!configureTls(client, active_config.server_ca_pem)) {
    error = "tls_ca_not_configured";
    return false;
  }
  client.setResolvedEndpoint(resolved_address, tls_hostname, tls_port);
  HTTPClient http;
  http.setConnectTimeout(5000);
  http.setTimeout(15000);
  if (!http.begin(client, image_url.c_str())) {
    error = "ota_image_http_begin_failed";
    return false;
  }
  if (!addDeviceAuthentication(http, "GET", target, error)) {
    http.end();
    return false;
  }
  PM_LOG_INFO(
      "OTA", "IMAGE_DOWNLOAD_BEGIN",
      "target_version=%s expected_bytes=%lu heap_free=%lu "
      "host=%s address=%s port=%u tls_validation=ca_and_hostname",
      manifest.version.c_str(), static_cast<unsigned long>(manifest.size_bytes),
      static_cast<unsigned long>(ESP.getFreeHeap()), tls_hostname.c_str(),
      resolved_address.toString().c_str(), static_cast<unsigned>(tls_port));
  const int status = http.GET();
  const int content_length = http.getSize();
  if (status != 200 ||
      content_length != static_cast<int>(manifest.size_bytes)) {
    error = status <= 0 ? "ota_image_tls_or_transport_failed"
                        : "ota_image_size_or_status_invalid";
    http.end();
    return false;
  }
  PM_LOG_INFO("TLS", "OTA_HANDSHAKE_VERIFIED",
              "host=%s address=%s port=%u ca_validation=true "
              "hostname_validation=true",
              tls_hostname.c_str(), resolved_address.toString().c_str(),
              static_cast<unsigned>(tls_port));
  if (!Update.begin(manifest.size_bytes, U_FLASH)) {
    error = "ota_partition_unavailable";
    http.end();
    return false;
  }
  mbedtls_sha256_context hash;
  mbedtls_sha256_init(&hash);
  mbedtls_sha256_starts_ret(&hash, 0);
  WiFiClient *stream = http.getStreamPtr();
  std::array<std::uint8_t, 4096> buffer{};
  std::uint32_t received = 0;
  std::uint64_t last_progress_ms = millis();
  std::uint8_t last_progress_percent = 0;
  while (received < manifest.size_bytes) {
    const int available = stream->available();
    if (available <= 0) {
      if (!http.connected() || millis() - last_progress_ms > 15'000U) {
        error = "ota_image_stream_interrupted";
        Update.abort();
        mbedtls_sha256_free(&hash);
        http.end();
        return false;
      }
      vTaskDelay(pdMS_TO_TICKS(2));
      continue;
    }
    const std::size_t wanted = std::min<std::size_t>(
        buffer.size(),
        std::min<std::uint32_t>(available, manifest.size_bytes - received));
    const int count = stream->readBytes(buffer.data(), wanted);
    if (count <= 0 ||
        Update.write(buffer.data(), count) != static_cast<std::size_t>(count)) {
      error = "ota_partition_write_failed";
      Update.abort();
      mbedtls_sha256_free(&hash);
      http.end();
      return false;
    }
    mbedtls_sha256_update_ret(&hash, buffer.data(), count);
    received += static_cast<std::uint32_t>(count);
    last_progress_ms = millis();
    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(50)) == pdTRUE) {
      status_.bytes_received = received;
      status_.image_size = manifest.size_bytes;
      status_.target_version = manifest.version;
      xSemaphoreGive(mutex_);
    } else if (diag::SerialLogger::instance().allow("ota_progress_lock",
                                                    10'000U)) {
      PM_LOG_WARN("OTA", "STATUS_LOCK_TIMEOUT",
                  "error=PM-OTA-010 phase=progress timeout_ms=50");
    }
    const std::uint8_t progress = static_cast<std::uint8_t>(
        (static_cast<std::uint64_t>(received) * 100U) / manifest.size_bytes);
    if (progress >= last_progress_percent + 10U || progress == 100U) {
      last_progress_percent = static_cast<std::uint8_t>((progress / 10U) * 10U);
      PM_LOG_INFO("OTA", "DOWNLOAD_PROGRESS",
                  "percent=%u bytes_received=%lu image_size=%lu heap_free=%lu",
                  static_cast<unsigned>(progress),
                  static_cast<unsigned long>(received),
                  static_cast<unsigned long>(manifest.size_bytes),
                  static_cast<unsigned long>(ESP.getFreeHeap()));
    }
  }
  crypto::Key32 digest{};
  mbedtls_sha256_finish_ret(&hash, digest.data());
  mbedtls_sha256_free(&hash);
  http.end();
  if (!crypto::constantTimeEqual(
          crypto::hexEncode(digest.data(), digest.size()), manifest.sha256)) {
    error = "ota_image_sha256_mismatch";
    PM_LOG_ERROR("OTA", "IMAGE_HASH_MISMATCH", "error=PM-OTA-008 bytes=%lu",
                 static_cast<unsigned long>(received));
    Update.abort();
    return false;
  }
  if (!Update.end(true) || !Update.isFinished()) {
    error = "ota_finalize_failed";
    PM_LOG_ERROR("OTA", "PARTITION_FINALIZE_FAILED",
                 "error=PM-OTA-009 update_error=%u",
                 static_cast<unsigned>(Update.getError()));
    return false;
  }
  PM_LOG_INFO(
      "OTA", "IMAGE_VERIFIED",
      "sha256_match=true bytes=%lu target_version=%s pending_reboot=true",
      static_cast<unsigned long>(received), manifest.version.c_str());
  return true;
}

bool OtaService::configureTls(WiFiClientSecure &client,
                              const std::string &ca_pem) const {
  client.setHandshakeTimeout(8);
  if (!ca_pem.empty()) {
    client.setCACert(ca_pem.c_str());
    return true;
  }
  return false;
}

int OtaService::compareSemver(const std::string &left,
                              const std::string &right) {
  std::array<unsigned int, 3> left_parts{};
  std::array<unsigned int, 3> right_parts{};
  if (!parseSemver(left, left_parts) || !parseSemver(right, right_parts)) {
    return left.compare(right);
  }
  for (std::size_t index = 0; index < 3; ++index) {
    if (left_parts[index] < right_parts[index]) {
      return -1;
    }
    if (left_parts[index] > right_parts[index]) {
      return 1;
    }
  }
  return 0;
}

} // namespace pm
