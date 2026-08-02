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

struct CompactNetworkStatus {
  bool station_connected{false};
  bool server_reachable{false};
  bool server_authenticated{false};
  std::int32_t rssi_dbm{-127};
  std::array<char, 16> ip_address{};
  std::array<char, 64> hostname{};
  bool truncated{false};
};

struct WifiDisconnectEvent {
  enum class Kind : std::uint8_t {
    StationStart,
    Connected,
    Disconnected,
    IpAcquired,
    IpLost,
    AuthModeChanged,
  };

  Kind kind{Kind::StationStart};
  std::uint64_t transition_number{0};
  std::uint64_t monotonic_ms{0};
  std::uint16_t reason{0};
  std::int32_t rssi_dbm{-127};
  std::uint32_t reconnect_count{0};
  std::uint32_t free_internal_heap_bytes{0};
  std::uint32_t largest_internal_block_bytes{0};
  std::uint32_t dhcp_duration_ms{0};
  std::int16_t channel{0};
  std::array<char, 18> bssid{};
  std::array<char, 16> ip_address{};
  std::array<char, 16> gateway{};
  std::array<char, 16> dns{};
};

// This small RAM tail is only the live excerpt. The Application persists each
// transition into the CRC-protected rotating microSD event archive, which is
// the authoritative cross-reboot flight recorder.
inline constexpr std::size_t kWifiDisconnectEventCapacity = 16U;

const char *wifiEventKindName(WifiDisconnectEvent::Kind kind);

struct WifiDisconnectSnapshot {
  std::array<WifiDisconnectEvent, kWifiDisconnectEventCapacity> events{};
  std::size_t count{0};
  std::uint64_t total{0};
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
  bool setupApActive() const;
  NetworkStatus status() const;
  CompactNetworkStatus compactStatus() const;
  bool ipChangedSinceHeartbeat();
  void setServerStatus(bool reachable, bool authenticated);
  WifiDisconnectSnapshot wifiDisconnectEvents() const;

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
  void recordWifiEvent(WifiDisconnectEvent::Kind kind,
                       std::uint16_t reason = 0U);
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
  // Wi-Fi driver callbacks execute outside the NetworkTask status mutex.
  // Keep callback-visible evidence in atomics rather than reading status_
  // or the task-owned connection timestamp concurrently.
  std::atomic<std::uint32_t> reconnect_count_snapshot_{0};
  std::atomic<std::uint64_t> station_connect_started_snapshot_ms_{0};
  mutable portMUX_TYPE disconnect_events_mux_ = portMUX_INITIALIZER_UNLOCKED;
  std::array<WifiDisconnectEvent, kWifiDisconnectEventCapacity>
      disconnect_events_{};
  std::size_t disconnect_event_next_{0};
  std::size_t disconnect_event_count_{0};
  std::uint64_t disconnect_event_total_{0};
  Phase phase_{Phase::Unconfigured};
  bool scan_running_{false};
  bool setup_ap_restart_pending_{false};
  bool setup_ready_serial_pending_{false};
  std::atomic<bool> ip_changed_{false};
  DNSServer dns_server_;
};

} // namespace pm
