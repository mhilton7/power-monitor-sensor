#pragma once

#include <cstdint>
#include <string>

#include <DNSServer.h>

#include "config/ConfigService.h"
#include "network/ClockService.h"

namespace pm {

struct NetworkStatus {
  bool station_connected{false};
  bool setup_ap_active{false};
  bool mdns_active{false};
  bool time_synchronized{false};
  bool server_reachable{false};
  bool server_authenticated{false};
  std::int32_t rssi_dbm{-127};
  std::uint32_t reconnect_count{0};
  std::string ip_address;
  std::string subnet;
  std::string gateway;
  std::string dns;
  std::string hostname;
  std::string last_ip_address;
};

class NetworkService {
 public:
  NetworkService(ConfigService& config, ClockService& clock);
  bool begin();
  void update();
  void applyConfiguration();
  void touchSetupActivity();
  NetworkStatus status() const;
  bool ipChangedSinceHeartbeat();
  void setServerStatus(bool reachable, bool authenticated);

 private:
  void startSetupAp();
  void connectStation();
  void onConnected();
  std::uint32_t nextBackoffMs();

  ConfigService& config_;
  ClockService& clock_;
  NetworkStatus status_;
  std::uint64_t next_reconnect_ms_{0};
  std::uint64_t setup_last_activity_ms_{0};
  std::uint64_t station_connect_started_ms_{0};
  std::uint64_t next_setup_recovery_ms_{0};
  std::uint32_t backoff_attempt_{0};
  bool ip_changed_{false};
  DNSServer dns_server_;
};

}  // namespace pm
