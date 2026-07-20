#include "ota/OtaService.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <Update.h>
#include <WiFiClientSecure.h>
#include <esp_ota_ops.h>
#include <mbedtls/base64.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>

#include "security/Crypto.h"
#include "version.h"

namespace pm {
namespace {

bool parseHttpsTarget(const std::string& url, std::string& host,
                      std::uint16_t& port) {
  if (url.rfind("https://", 0) != 0) return false;
  const std::size_t start = 8;
  const std::size_t end = url.find('/', start);
  const std::string authority = url.substr(start, end - start);
  if (authority.empty() || authority.find('@') != std::string::npos) return false;
  const std::size_t colon = authority.rfind(':');
  host = colon == std::string::npos ? authority : authority.substr(0, colon);
  port = colon == std::string::npos
             ? 443
             : static_cast<std::uint16_t>(std::strtoul(
                   authority.substr(colon + 1).c_str(), nullptr, 10));
  return !host.empty() && port != 0;
}

bool verifyPinnedPeer(WiFiClientSecure& client, const std::string& url,
                      const std::string& fingerprint) {
  if (fingerprint.empty()) return true;
  std::string host;
  std::uint16_t port = 443;
  return parseHttpsTarget(url, host, port) &&
         client.connect(host.c_str(), port, 5000) &&
         client.verify(fingerprint.c_str(), host.c_str());
}

}  // namespace

OtaService::OtaService(ConfigService& config) : config_(config) {
  mutex_ = xSemaphoreCreateMutex();
}

bool OtaService::checkRunningImage() {
  const esp_partition_t* running = esp_ota_get_running_partition();
  esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
  if (running == nullptr || esp_ota_get_state_partition(running, &state) != ESP_OK) {
    return false;
  }
  if (state == ESP_OTA_IMG_PENDING_VERIFY) {
    // Application calls this only after storage, meter initialization, network
    // service startup, and task creation have succeeded.
    return esp_ota_mark_app_valid_cancel_rollback() == ESP_OK;
  }
  return true;
}

bool OtaService::applyFromManifestUrl(const std::string& manifest_url) {
  if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(100)) != pdTRUE) {
    return false;
  }
  if (status_.in_progress || config_.safeMode()) {
    xSemaphoreGive(mutex_);
    return false;
  }
  status_.in_progress = true;
  status_.pending_reboot = false;
  status_.bytes_received = 0;
  status_.last_error.clear();
  xSemaphoreGive(mutex_);

  std::string manifest_json;
  std::string error;
  OtaManifest manifest;
  bool ok = fetchText(manifest_url, manifest_json, 16 * 1024, error) &&
            parseManifest(manifest_json, manifest, error) &&
            verifyManifest(manifest, error) && downloadAndApply(manifest, error);
  xSemaphoreTake(mutex_, portMAX_DELAY);
  status_.in_progress = false;
  status_.last_result = ok ? "verified_pending_reboot" : "failed";
  status_.last_error = error;
  status_.pending_reboot = ok;
  xSemaphoreGive(mutex_);
  if (ok) {
    delay(100);
    ESP.restart();
  }
  return ok;
}

bool OtaService::parseManifest(const std::string& json, OtaManifest& manifest,
                               std::string& error) const {
  JsonDocument document;
  const DeserializationError parse_error = deserializeJson(document, json);
  if (parse_error) {
    error = "ota_manifest_json_invalid";
    return false;
  }
  manifest.schema_version = document["schema_version"] | 0;
  manifest.firmware_version = document["firmware_version"] | "";
  manifest.protocol = document["protocol"] | "";
  manifest.hardware_target = document["hardware_target"] | "";
  manifest.image_url = document["image_url"] | "";
  manifest.image_size = document["image_size"] | 0;
  manifest.image_sha256 = document["image_sha256"] | "";
  manifest.minimum_rollback_version = document["minimum_rollback_version"] | "";
  manifest.release_notes = document["release_notes"] | "";
  manifest.signature_algorithm = document["signature_algorithm"] | "";
  manifest.signature_base64 = document["signature"] | "";
  manifest.allow_downgrade = document["allow_downgrade"] | false;
  if (manifest.schema_version != 1 || manifest.firmware_version.empty() ||
      manifest.protocol.empty() || manifest.hardware_target.empty() ||
      manifest.image_url.empty() || manifest.image_size == 0 ||
      manifest.image_sha256.size() != 64 || manifest.signature_base64.empty()) {
    error = "ota_manifest_required_field_missing";
    return false;
  }
  return true;
}

bool OtaService::verifyManifest(const OtaManifest& manifest,
                                std::string& error) const {
  if (manifest.protocol != version::PROTOCOL) {
    error = "ota_protocol_incompatible";
    return false;
  }
  if (manifest.hardware_target != version::HARDWARE_TARGET) {
    error = "ota_hardware_incompatible";
    return false;
  }
  if (manifest.signature_algorithm != "ecdsa-p256-sha256") {
    error = "ota_signature_algorithm_unsupported";
    return false;
  }
  if (manifest.image_url.rfind("https://", 0) != 0 ||
      manifest.image_size > 0x600000U) {
    error = "ota_image_location_or_size_invalid";
    return false;
  }
  if (!manifest.allow_downgrade &&
      compareSemver(manifest.firmware_version, version::FIRMWARE) <= 0) {
    error = "ota_downgrade_or_same_version_rejected";
    return false;
  }
  if (compareSemver(version::FIRMWARE, manifest.minimum_rollback_version) < 0) {
    error = "ota_minimum_rollback_policy_incompatible";
    return false;
  }
  const std::string public_key = config_.otaPublicKey();
  if (public_key.empty()) {
    error = "ota_public_key_unavailable";
    return false;
  }
  std::array<std::uint8_t, 128> signature{};
  std::size_t signature_length = 0;
  if (mbedtls_base64_decode(
          signature.data(), signature.size(), &signature_length,
          reinterpret_cast<const std::uint8_t*>(manifest.signature_base64.data()),
          manifest.signature_base64.size()) != 0) {
    error = "ota_signature_base64_invalid";
    return false;
  }
  const std::string canonical = canonicalManifest(manifest);
  const crypto::Key32 digest = crypto::sha256(
      reinterpret_cast<const std::uint8_t*>(canonical.data()), canonical.size());
  mbedtls_pk_context key;
  mbedtls_pk_init(&key);
  const int parse_result = mbedtls_pk_parse_public_key(
      &key, reinterpret_cast<const std::uint8_t*>(public_key.c_str()),
      public_key.size() + 1);
  const bool valid = parse_result == 0 &&
                     mbedtls_pk_can_do(&key, MBEDTLS_PK_ECDSA) != 0 &&
                     mbedtls_pk_verify(&key, MBEDTLS_MD_SHA256, digest.data(),
                                       digest.size(), signature.data(),
                                       signature_length) == 0;
  mbedtls_pk_free(&key);
  if (!valid) {
    error = "ota_signature_invalid";
  }
  return valid;
}

std::string OtaService::canonicalManifest(const OtaManifest& manifest) const {
  const std::string notes_hash = crypto::sha256Hex(
      reinterpret_cast<const std::uint8_t*>(manifest.release_notes.data()),
      manifest.release_notes.size());
  return "PM-OTA-MANIFEST-V1\n" + std::to_string(manifest.schema_version) + "\n" +
         manifest.firmware_version + "\n" + manifest.protocol + "\n" +
         manifest.hardware_target + "\n" + manifest.image_url + "\n" +
         std::to_string(manifest.image_size) + "\n" + manifest.image_sha256 + "\n" +
         manifest.minimum_rollback_version + "\n" + notes_hash + "\n" +
         (manifest.allow_downgrade ? "true" : "false");
}

OtaStatus OtaService::status() const {
  if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(100)) != pdTRUE) {
    OtaStatus copy = status_;
    copy.last_error = "ota_status_busy";
    return copy;
  }
  const OtaStatus copy = status_;
  xSemaphoreGive(mutex_);
  return copy;
}

bool OtaService::rollbackAndReboot() {
  return esp_ota_check_rollback_is_possible() &&
         esp_ota_mark_app_invalid_rollback_and_reboot() == ESP_OK;
}

bool OtaService::fetchText(const std::string& url, std::string& body,
                           const std::size_t maximum_bytes,
                           std::string& error) const {
  if (url.rfind("https://", 0) != 0) {
    error = "ota_url_insecure";
    return false;
  }
  WiFiClientSecure client;
  if (!configureTls(client)) {
    error = "tls_trust_not_configured";
    return false;
  }
  HTTPClient http;
  http.setConnectTimeout(5000);
  http.setTimeout(10000);
  if (!http.begin(client, url.c_str())) {
    error = "ota_manifest_http_begin_failed";
    return false;
  }
  if (config_.config().server_ca_pem.empty() &&
      !verifyPinnedPeer(client, url, config_.config().server_fingerprint)) {
    client.stop();
    http.end();
    error = "tls_fingerprint_verification_failed";
    return false;
  }
  const int status = http.GET();
  if (status != 200) {
    error = "ota_manifest_download_failed";
    http.end();
    return false;
  }
  const String response = http.getString();
  if (response.length() > maximum_bytes) {
    error = "ota_manifest_too_large";
    http.end();
    return false;
  }
  body = response.c_str();
  http.end();
  return true;
}

bool OtaService::downloadAndApply(const OtaManifest& manifest,
                                  std::string& error) {
  WiFiClientSecure client;
  if (!configureTls(client)) {
    error = "tls_trust_not_configured";
    return false;
  }
  HTTPClient http;
  http.setConnectTimeout(5000);
  http.setTimeout(15000);
  if (!http.begin(client, manifest.image_url.c_str())) {
    error = "ota_image_http_begin_failed";
    return false;
  }
  if (config_.config().server_ca_pem.empty() &&
      !verifyPinnedPeer(client, manifest.image_url,
                        config_.config().server_fingerprint)) {
    client.stop();
    http.end();
    error = "tls_fingerprint_verification_failed";
    return false;
  }
  const int status = http.GET();
  const int content_length = http.getSize();
  if (status != 200 || content_length != static_cast<int>(manifest.image_size)) {
    error = "ota_image_size_or_status_invalid";
    http.end();
    return false;
  }
  if (!Update.begin(manifest.image_size, U_FLASH)) {
    error = "ota_partition_unavailable";
    http.end();
    return false;
  }
  mbedtls_sha256_context hash;
  mbedtls_sha256_init(&hash);
  mbedtls_sha256_starts_ret(&hash, 0);
  WiFiClient* stream = http.getStreamPtr();
  std::array<std::uint8_t, 4096> buffer{};
  std::uint32_t received = 0;
  std::uint64_t last_progress_ms = millis();
  while (received < manifest.image_size) {
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
    const std::size_t wanted = std::min<std::size_t>(buffer.size(),
        std::min<std::uint32_t>(available, manifest.image_size - received));
    const int count = stream->readBytes(buffer.data(), wanted);
    if (count <= 0 || Update.write(buffer.data(), count) != static_cast<std::size_t>(count)) {
      error = "ota_partition_write_failed";
      Update.abort();
      mbedtls_sha256_free(&hash);
      http.end();
      return false;
    }
    mbedtls_sha256_update_ret(&hash, buffer.data(), count);
    received += static_cast<std::uint32_t>(count);
    last_progress_ms = millis();
    xSemaphoreTake(mutex_, portMAX_DELAY);
    status_.bytes_received = received;
    status_.image_size = manifest.image_size;
    status_.target_version = manifest.firmware_version;
    xSemaphoreGive(mutex_);
  }
  crypto::Key32 digest{};
  mbedtls_sha256_finish_ret(&hash, digest.data());
  mbedtls_sha256_free(&hash);
  http.end();
  if (!crypto::constantTimeEqual(crypto::hexEncode(digest.data(), digest.size()),
                                 manifest.image_sha256)) {
    error = "ota_image_sha256_mismatch";
    Update.abort();
    return false;
  }
  if (!Update.end(true) || !Update.isFinished()) {
    error = "ota_finalize_failed";
    return false;
  }
  return true;
}

bool OtaService::configureTls(WiFiClientSecure& client) const {
  client.setHandshakeTimeout(8);
  if (!config_.config().server_ca_pem.empty()) {
    client.setCACert(config_.config().server_ca_pem.c_str());
    return true;
  }
  if (!config_.config().server_fingerprint.empty()) {
    client.setInsecure();
    return true;
  }
  return false;
}

int OtaService::compareSemver(const std::string& left, const std::string& right) {
  unsigned int left_parts[3]{};
  unsigned int right_parts[3]{};
  if (std::sscanf(left.c_str(), "%u.%u.%u", &left_parts[0], &left_parts[1],
                  &left_parts[2]) != 3 ||
      std::sscanf(right.c_str(), "%u.%u.%u", &right_parts[0], &right_parts[1],
                  &right_parts[2]) != 3) {
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

}  // namespace pm
