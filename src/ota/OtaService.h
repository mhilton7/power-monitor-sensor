#pragma once

#include <atomic>
#include <cstdint>
#include <string>

#include <HTTPClient.h>
#include <WiFiClientSecure.h>

#include "config/ConfigService.h"

namespace pm {

struct OtaManifest {
  bool available{false};
  std::string version;
  std::string channel;
  std::string hardware_target;
  std::string protocol_min;
  std::string protocol_max;
  std::uint32_t size_bytes{0};
  std::string sha256;
  std::string signature_base64;
  std::string signing_key_id;
  std::string release_notes;
  std::string download_path;
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
  explicit OtaService(ConfigService &config);
  bool runningImagePendingVerification() const;
  bool checkRunningImage(bool health_checks_passed);
  bool applyFromManifestUrl(const std::string &manifest_url);
  bool parseManifest(const std::string &json, OtaManifest &manifest,
                     std::string &error) const;
  bool verifyManifest(const OtaManifest &manifest, std::string &error) const;
  std::string canonicalManifest(const OtaManifest &manifest) const;
  OtaStatus status() const;
  bool rollbackAndReboot();

private:
  bool fetchText(const std::string &url, std::string &body,
                 std::size_t maximum_bytes, std::string &error) const;
  bool downloadAndApply(const OtaManifest &manifest, std::string &error);
  bool addDeviceAuthentication(HTTPClient &http, const char *method,
                               const std::string &target,
                               std::string &error) const;
  bool serverTarget(const RuntimeConfig &config, const std::string &url,
                    std::string &target) const;
  bool configureTls(WiFiClientSecure &client, const std::string &ca_pem) const;
  static int compareSemver(const std::string &left, const std::string &right);

  ConfigService &config_;
  std::atomic<bool> in_progress_{false};
  mutable SemaphoreHandle_t mutex_{nullptr};
  OtaStatus status_;
};

} // namespace pm
