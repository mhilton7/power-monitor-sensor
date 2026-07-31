export type HealthState = "connected" | "offline" | "unauthenticated";

export interface UiStatus {
  schema_version: 1;
  server_now: string;
  device: {
    friendly_name: string;
    firmware: string;
    git_commit: string;
    build_timestamp: string;
    platformio_environment: string;
    web_assets: {
      index_html_sha256: string;
      app_js_sha256: string;
      style_css_sha256: string;
    };
    uptime_seconds: number;
  };
  reading: {
    measured_at_utc_ms: number | null;
    power_w: number | null;
    voltage_v: number | null;
    current_a: number | null;
    frequency_hz: number | null;
    power_factor: number | null;
  };
  health: {
    wifi: "connected" | "offline";
    rssi_dbm: number;
    ip_address: string;
    server: HealthState;
    storage: "writable" | "degraded";
    meter: "healthy" | "degraded";
    low_memory: boolean;
  };
  sync: {
    last_success_utc_ms: number | null;
    newest_sequence: number;
    acknowledged_sequence: number;
    backlog: number;
    last_safe_error: string;
  };
}

export interface TaskDiagnostic {
  name: string;
  core: number;
  priority: number;
  configured_stack_bytes: number;
  high_water_bytes: number;
  margin_percent: number;
  running: boolean;
  watchdog: boolean;
}

export interface UiDiagnostics {
  schema_version: 1;
  memory: {
    free_heap_bytes: number;
    minimum_free_heap_bytes: number;
    free_internal_heap_bytes: number;
    minimum_free_internal_heap_bytes: number;
    largest_internal_block_bytes: number;
    free_psram_bytes: number;
    largest_psram_block_bytes: number;
    heap_integrity_ok: boolean;
  };
  tasks: {
    server_sync_stack_bytes: number;
    server_sync_high_water_bytes: number;
    server_sync_margin_percent: number;
    network_margin_percent: number | null;
    table: TaskDiagnostic[];
  };
  sync: {
    heartbeat_successes: number;
    heartbeat_failures: number;
    batch_successes: number;
    batch_failures: number;
    local_resource_deferrals: number;
    tls_requests_admitted: number;
    tls_requests_rejected_heap: number;
    tls_requests_rejected_stack: number;
    acknowledged_sequence: number;
    newest_sequence: number;
    backlog: number;
    last_safe_error: string;
  };
  local_http: {
    ui_status_requests: number;
    ui_setup_requests: number;
    ui_diagnostics_requests: number;
    ui_heavy_requests_deferred: number;
    peak_requests: number;
    browser_session_rejections: number;
    malformed_auth_header_rejections: number;
    browser_rate_limited: number;
    server_hmac_rate_limited: number;
    browser_requests_accepted: number;
    browser_requests_session_expired: number;
    browser_requests_session_invalid: number;
    browser_requests_csrf_rejected: number;
    server_hmac_requests_accepted: number;
    server_hmac_headers_incomplete: number;
    server_hmac_protocol_mismatch: number;
    server_hmac_device_mismatch: number;
    server_hmac_timestamp_rejected: number;
    server_hmac_nonce_rejected: number;
    server_hmac_body_hash_rejected: number;
    server_hmac_signature_rejected: number;
  };
  local_sessions: {
    capacity: number;
    active: number;
    peak_active: number;
    created: number;
    reused: number;
    refreshed: number;
    expired: number;
    invalid: number;
    revoked: number;
    capacity_rejections: number;
  };
  wifi_disconnects: {
    total: number;
    events: Array<{
      monotonic_ms: number;
      reason: string;
      reason_code: number;
      rssi_dbm: number;
      disconnect_number: number;
      free_internal_heap_bytes: number;
      largest_internal_block_bytes: number;
    }>;
  };
}

export interface EffectiveConfig {
  schema_version: 1;
  config_version: number;
  friendly_name: string;
  hostname: string;
  wifi_ssid: string;
  static_network_enabled: boolean;
  static_ip: string;
  static_gateway: string;
  static_subnet: string;
  static_dns: string;
  server_url: string;
  server_ca_configured: boolean;
  server_fingerprint_configured: boolean;
  ota_signing_key_configured: boolean;
  ota_signing_key_id: string;
  connection_mode: "pull" | "push" | "hybrid";
  sample_interval_seconds: number;
  durable_log_interval_seconds: number;
  heartbeat_interval_seconds: number;
  ct_rating_a: number;
  ct_warning_fraction?: number;
  ct_critical_fraction?: number;
  ct_fault_fraction?: number;
  timezone: string;
  sd_spi_hz: number;
  diagnostic_log_level: number;
}

export interface NetworkSettingsPayload {
  wifi_ssid: string;
  wifi_password?: string;
  static_network_enabled: boolean;
  static_ip: string;
  static_gateway: string;
  static_subnet: string;
  static_dns: string;
  server_url: string;
  tls_trust_action: "keep" | "replace_ca";
  server_ca_pem?: string;
  server_fingerprint?: string;
  ota_trust_action: "keep" | "replace";
  ota_signing_public_key_pem?: string;
  ota_signing_key_id?: string;
  connection_mode: "push";
}

export interface SetupPayload {
  friendly_name: string;
  wifi_ssid: string;
  wifi_password: string;
  static_network_enabled: boolean;
  static_ip: string;
  static_gateway: string;
  static_subnet: string;
  static_dns: string;
  server_url: string;
  server_ca_pem: string;
  server_fingerprint: string;
  ota_signing_public_key_pem: string;
  ota_signing_key_id: string;
  enrollment_token: string;
  admin_password: string;
  connection_mode: "push";
  ct_rating_a: number;
}
