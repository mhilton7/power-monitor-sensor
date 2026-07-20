#pragma once

#include <string>

#include "config/ConfigService.h"

namespace pm {

struct ProvisioningResult {
  bool ok{false};
  std::string code;
  std::string detail;
};

class ProvisioningService {
 public:
  explicit ProvisioningService(ConfigService& config);
  ProvisioningResult apply(const std::string& json);

 private:
  ConfigService& config_;
};

}  // namespace pm

