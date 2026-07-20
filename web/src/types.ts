export interface Health {
  schema_version: number;
  protocol: string;
  device_id: string;
  friendly_name: string;
  status: "healthy" | "degraded" | "safe_mode";
  uptime_seconds: number;
  firmware_version: string;
  wifi: {
    connected: boolean;
    rssi_dbm: number;
    ip_address: string;
    hostname: string;
  };
  time: { synchronized: boolean; utc: string };
  meter: { connected: boolean; consecutive_errors: number; last_error: string };
  storage: {
    present: boolean;
    mounted: boolean;
    writable: boolean;
    free_bytes: number;
    oldest_sequence: number;
    newest_sequence: number;
    server_ack_sequence: number;
  };
  server: { configured: boolean; reachable: boolean; last_heartbeat_utc: number };
}

export interface LiveReading {
  timestamp_utc: string;
  timestamp_trusted: boolean;
  voltage_v: number;
  current_a: number;
  active_power_w: number;
  meter_energy_total_wh: number;
  device_lifetime_energy_wh: number;
  frequency_hz: number;
  power_factor: number;
  ct_rating_a: number;
  quality: { valid: boolean; method: string; error: string };
}

export interface EffectiveConfig {
  schema_version: 1;
  config_version: number;
  friendly_name: string;
  hostname: string;
  wifi_ssid: string;
  server_url: string;
  server_ca_configured: boolean;
  server_fingerprint_configured: boolean;
  connection_mode: "pull" | "push" | "hybrid";
  sample_interval_seconds: number;
  durable_log_interval_seconds: number;
  heartbeat_interval_seconds: number;
  ct_rating_a: number;
  timezone: string;
  sd_spi_hz: number;
}

export interface SetupPayload {
  friendly_name: string;
  wifi_ssid: string;
  wifi_password: string;
  server_url: string;
  server_ca_pem: string;
  server_fingerprint: string;
  enrollment_token: string;
  admin_password: string;
  connection_mode: "pull" | "push" | "hybrid";
  ct_rating_a: number;
}
