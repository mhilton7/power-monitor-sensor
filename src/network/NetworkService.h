#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <string>

#include <DNSServer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

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
  NetworkService(ConfigService &config, ClockService &clock);
  bool begin();
  void update();
  void requestConfigurationApply(std::uint32_t delay_ms = 1000);
  void requestSetupApRestart();
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
    TimeSync,
    ServerValidation,
    Online,
    RetryWait,
    Degraded,
    Failed,
  };

  void applyConfiguration();
  bool startSetupAp();
  void stopSetupAp();
  void connectStation();
  void onConnected();
  void configureNtp(const std::array<std::string, 3> &servers);
  void updateScan();
  Phase connectedPhase() const;
  void transition(Phase next, const char *reason);
  static const char *phaseName(Phase phase);
  std::uint32_t nextBackoffMs();
  bool lockStatus(TickType_t timeout) const;
  void unlockStatus() const;

  ConfigService &config_;
  ClockService &clock_;
  NetworkStatus status_;
  mutable SemaphoreHandle_t status_mutex_{nullptr};
  std::uint64_t next_reconnect_ms_{0};
  std::uint64_t setup_last_activity_ms_{0};
  std::uint64_t next_setup_ap_start_ms_{0};
  std::uint64_t next_setup_ready_serial_ms_{0};
  std::uint64_t station_connect_started_ms_{0};
  std::uint64_t next_setup_recovery_ms_{0};
  std::uint64_t configuration_apply_at_ms_{0};
  std::uint64_t scan_started_ms_{0};
  std::uint64_t next_ntp_retry_ms_{0};
  std::uint32_t backoff_attempt_{0};
  std::uint32_t ntp_attempt_{0};
  std::uint32_t observed_configuration_generation_{0};
  std::uint32_t observed_server_status_generation_{0};
  // lwIP SNTP retains the pointers supplied by configTzTime instead of
  // copying the server names. Keep their storage alive for the SNTP client.
  std::array<std::string, 3> active_ntp_servers_;
  std::atomic<std::uint32_t> configuration_apply_generation_{0};
  std::atomic<std::uint32_t> configuration_apply_delay_ms_{1000};
  std::atomic<std::uint32_t> server_status_generation_{0};
  std::atomic<bool> pending_server_reachable_{false};
  std::atomic<bool> pending_server_authenticated_{false};
  std::atomic<bool> scan_requested_{false};
  std::atomic<bool> setup_activity_requested_{false};
  std::atomic<bool> setup_ap_restart_requested_{false};
  std::atomic<std::uint16_t> last_disconnect_reason_{0};
  Phase phase_{Phase::Unconfigured};
  bool scan_running_{false};
  bool setup_ap_restart_pending_{false};
  bool setup_ready_serial_pending_{false};
  std::atomic<bool> ip_changed_{false};
  DNSServer dns_server_;
};

} // namespace pm
