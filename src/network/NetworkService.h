#pragma once

#include <atomic>
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
  void requestConfigurationApply(std::uint32_t delay_ms = 1000);
  void requestScan();
  void touchSetupActivity();
  NetworkStatus status() const;
  bool ipChangedSinceHeartbeat();
  void setServerStatus(bool reachable, bool authenticated);

 private:
  enum class Phase : std::uint8_t {
    Unconfigured,
    Provisioning,
    Idle,
    Scanning,
    Connecting,
    WaitingForIp,
    Connected,
    ValidatingNetwork,
    Online,
    RetryWait,
    Failed,
  };

  void startSetupAp();
  void stopSetupAp();
  void connectStation();
  void onConnected();
  void updateScan();
  void transition(Phase next, const char* reason);
  static const char* phaseName(Phase phase);
  std::uint32_t nextBackoffMs();

  ConfigService& config_;
  ClockService& clock_;
  NetworkStatus status_;
  std::uint64_t next_reconnect_ms_{0};
  std::uint64_t setup_last_activity_ms_{0};
  std::uint64_t station_connect_started_ms_{0};
  std::uint64_t next_setup_recovery_ms_{0};
  std::uint64_t configuration_apply_at_ms_{0};
  std::uint64_t scan_started_ms_{0};
  std::uint32_t backoff_attempt_{0};
  std::uint32_t observed_configuration_generation_{0};
  std::atomic<std::uint32_t> configuration_apply_generation_{0};
  std::atomic<std::uint32_t> configuration_apply_delay_ms_{1000};
  std::atomic<bool> scan_requested_{false};
  std::atomic<std::uint16_t> last_disconnect_reason_{0};
  Phase phase_{Phase::Unconfigured};
  bool scan_running_{false};
  bool ip_changed_{false};
  DNSServer dns_server_;
};

}  // namespace pm
