#pragma once

#include <cstdint>

namespace pm {

enum class MaintenanceAction : std::uint8_t {
  TestPzem,
  TestSd,
  RemountSd,
  RebuildIndex,
  PrepareCardRemoval,
  TestDns,
  TestNtp,
  TestServerTls,
  TestHeartbeat,
  Reboot,
  EnrollmentActivationReboot,
  NetworkReset,
  FactoryReset,
  ApplyOta,
  RollbackOta,
};

struct MaintenanceMessage {
  MaintenanceAction action{MaintenanceAction::TestSd};
  char argument[384]{};
};

} // namespace pm
