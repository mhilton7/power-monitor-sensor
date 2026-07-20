#pragma once

#include <cstdint>
#include <string>

#include <WiFiClientSecure.h>

#include "config/ConfigService.h"

namespace pm {

struct OtaManifest {
  std::uint32_t schema_version{0};
  std::string firmware_version;
  std::string protocol;
  std::string hardware_target;
  std::string image_url;
  std::uint32_t image_size{0};
  std::string image_sha256;
  std::string minimum_rollback_version;
  std::string release_notes;
  std::string signature_algorithm;
  std::string signature_base64;
  bool allow_downgrade{false};
};

struct OtaStatus {
  bool in_progress{false};
  bool pending_reboot{false};
  std::uint32_t bytes_received{0};
  std::uint32_t image_size{0};
  std::string target_version;
  std::string last_result{"never"};
  std::string last_error;
};

class OtaService {
 public:
  explicit OtaService(ConfigService& config);
  bool checkRunningImage();
  bool applyFromManifestUrl(const std::string& manifest_url);
  bool parseManifest(const std::string& json, OtaManifest& manifest,
                     std::string& error) const;
  bool verifyManifest(const OtaManifest& manifest, std::string& error) const;
  std::string canonicalManifest(const OtaManifest& manifest) const;
  OtaStatus status() const;
  bool rollbackAndReboot();

 private:
  bool fetchText(const std::string& url, std::string& body,
                 std::size_t maximum_bytes, std::string& error) const;
  bool downloadAndApply(const OtaManifest& manifest, std::string& error);
  bool configureTls(WiFiClientSecure& client) const;
  static int compareSemver(const std::string& left, const std::string& right);

  ConfigService& config_;
  mutable SemaphoreHandle_t mutex_{nullptr};
  OtaStatus status_;
};

}  // namespace pm
