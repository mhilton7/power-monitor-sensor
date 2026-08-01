import { describe, expect, it, vi } from "vitest";
import * as api from "../src/api";
import { App } from "../src/main";
import {
  clearSecrets,
  readConfiguredSetupForm,
  renderDiagnostics,
  renderSetup,
  renderShell,
  renderStatus,
  updateDiagnostics,
  updateStatus,
} from "../src/ui";
import type { EffectiveConfig, UiDiagnostics, UiStatus } from "../src/types";

const status: UiStatus = {
  schema_version: 1,
  server_now: "2026-07-31T14:00:00Z",
  device: {
    friendly_name: "Outdoor-AC",
    firmware: "1.0.8",
    git_commit: "0123456789abcdef",
    build_timestamp: "2026-07-31T14:00:00Z",
    platformio_environment: "esp32-s3-release",
    web_assets: {
      index_html_sha256: "a".repeat(64),
      app_js_sha256: "b".repeat(64),
      style_css_sha256: "c".repeat(64),
    },
    uptime_seconds: 600,
  },
  reading: {
    measured_at_utc_ms: Date.parse("2026-07-31T13:59:59Z"),
    power_w: 0.8,
    voltage_v: 120.4,
    current_a: 0.01,
    frequency_hz: 60,
    power_factor: 0.83,
  },
  health: {
    wifi: "connected",
    rssi_dbm: -68,
    ip_address: "192.168.0.202",
    server: "connected",
    storage: "writable",
    meter: "healthy",
    low_memory: false,
  },
  sync: {
    last_success_utc_ms: Date.parse("2026-07-31T13:59:58Z"),
    newest_sequence: 19,
    acknowledged_sequence: 19,
    backlog: 0,
    last_safe_error: "",
  },
};

const config: EffectiveConfig = {
  schema_version: 1,
  config_version: 2,
  friendly_name: "Outdoor-AC",
  hostname: "power-monitor-abc123",
  wifi_ssid: "Home",
  static_network_enabled: false,
  static_ip: "",
  static_gateway: "",
  static_subnet: "",
  static_dns: "",
  server_url: "https://power-monitor.home.arpa:8443",
  server_ca_configured: true,
  server_fingerprint_configured: false,
  ota_signing_key_configured: true,
  ota_signing_key_id: "server",
  connection_mode: "push",
  sample_interval_seconds: 1,
  durable_log_interval_seconds: 60,
  heartbeat_interval_seconds: 15,
  ct_rating_a: 100,
  timezone: "America/Los_Angeles",
  sd_spi_hz: 4_000_000,
  diagnostic_log_level: 2,
};

const diagnostics: UiDiagnostics = {
  schema_version: 1,
  memory: {
    free_heap_bytes: 90_000,
    minimum_free_heap_bytes: 21_000,
    free_internal_heap_bytes: 94_000,
    minimum_free_internal_heap_bytes: 20_000,
    largest_internal_block_bytes: 40_000,
    free_psram_bytes: 8_000_000,
    largest_psram_block_bytes: 7_000_000,
    heap_integrity_ok: true,
  },
  tasks: {
    server_sync_stack_bytes: 24_576,
    server_sync_high_water_bytes: 11_844,
    server_sync_margin_percent: 48,
    network_margin_percent: 36,
    table: [],
  },
  sync: {
    heartbeat_successes: 75,
    heartbeat_failures: 11,
    batch_successes: 24,
    batch_failures: 1,
    local_resource_deferrals: 2,
    tls_requests_admitted: 100,
    tls_requests_rejected_heap: 2,
    tls_requests_rejected_stack: 0,
    acknowledged_sequence: 41,
    newest_sequence: 41,
    backlog: 0,
    last_safe_error: "",
  },
  local_http: {
    ui_status_requests: 10,
    ui_setup_requests: 1,
    ui_diagnostics_requests: 1,
    ui_heavy_requests_deferred: 0,
    peak_requests: 1,
    browser_session_rejections: 0,
    malformed_auth_header_rejections: 0,
    browser_rate_limited: 0,
    server_hmac_rate_limited: 0,
    browser_requests_accepted: 10,
    browser_requests_session_expired: 0,
    browser_requests_session_invalid: 0,
    browser_requests_csrf_rejected: 0,
    server_hmac_requests_accepted: 2,
    server_hmac_headers_incomplete: 0,
    server_hmac_protocol_mismatch: 0,
    server_hmac_device_mismatch: 0,
    server_hmac_timestamp_rejected: 0,
    server_hmac_nonce_rejected: 0,
    server_hmac_body_hash_rejected: 0,
    server_hmac_signature_rejected: 0,
  },
  local_sessions: {
    capacity: 6,
    active: 2,
    peak_active: 3,
    created: 3,
    reused: 4,
    refreshed: 4,
    expired: 1,
    invalid: 0,
    revoked: 0,
    capacity_rejections: 0,
  },
  wifi_disconnects: {
    total: 1,
    events: [
      {
        monotonic_ms: 1000,
        reason: "beacon_timeout",
        reason_code: 200,
        rssi_dbm: -68,
        disconnect_number: 1,
        free_internal_heap_bytes: 90_000,
        largest_internal_block_bytes: 40_000,
      },
    ],
  },
};

describe("minimal WebUI", () => {
  it("has exactly Status, Setup, and Diagnostics primary views", () => {
    document.body.innerHTML = renderShell();
    const labels = [...document.querySelectorAll("nav [data-view]")].map(
      (node) => node.textContent?.trim(),
    );
    expect(labels).toEqual(["Status", "Setup", "Diagnostics"]);
    expect(document.querySelector('nav [data-view="network"]')).toBeNull();
  });

  it("updates only status text nodes and distinguishes missing data from zero", () => {
    document.body.innerHTML = renderStatus();
    const main = document.body.firstElementChild;
    updateStatus(document, status);
    expect(document.querySelector("#power")?.textContent).toBe("0.8");
    expect(document.body.textContent).toContain("120.4 V");
    const zero = structuredClone(status);
    zero.reading.power_w = 0;
    updateStatus(document, zero);
    expect(document.querySelector("#power")?.textContent).toBe("0");
    const missing = structuredClone(status);
    missing.reading.power_w = null;
    missing.reading.measured_at_utc_ms = null;
    updateStatus(document, missing);
    expect(document.querySelector("#power")?.textContent).toBe("—");
    expect(document.body.textContent).toContain(
      "Waiting for the first reading",
    );
    expect(document.body.firstElementChild).toBe(main);
  });

  it("keeps advanced setup collapsed and secrets write-only", () => {
    document.body.innerHTML = renderSetup(config);
    const details = document.querySelector("details")!;
    expect(details.hasAttribute("open")).toBe(false);
    expect(
      (document.querySelector('[name="server_ca_pem"]') as HTMLTextAreaElement)
        .value,
    ).toBe("");
    expect(document.body.textContent).not.toContain("PRIVATE KEY");
  });

  it("preserves current trust when replacement fields are blank and clears secrets", () => {
    document.body.innerHTML = renderSetup(config);
    const form = document.querySelector("form")!;
    (form.elements.namedItem("wifi_password") as HTMLInputElement).value =
      "secret";
    const payload = readConfiguredSetupForm(form, config);
    expect(payload.network.tls_trust_action).toBe("keep");
    expect(payload.network.ota_trust_action).toBe("keep");
    clearSecrets(form);
    expect(
      (form.elements.namedItem("wifi_password") as HTMLInputElement).value,
    ).toBe("");
  });

  it("renders compact diagnostics only when data is explicitly supplied", () => {
    document.body.innerHTML = renderDiagnostics();
    expect(document.body.textContent).toContain("Not loaded");
    updateDiagnostics(document, diagnostics);
    expect(document.body.textContent).toContain("48%");
    expect(document.body.textContent).toContain("75 succeeded · 11 failed");
    expect(document.body.textContent).toContain("Test server TLS");
    expect(document.body.textContent).toContain("Prepare card for removal");
  });

  it("requires confirmation before preparing the microSD card for removal", async () => {
    vi.spyOn(api, "openSession").mockResolvedValue({
      expiresInSeconds: 900,
      setupRequired: false,
      elevated: false,
    });
    vi.spyOn(api, "getUiStatus").mockResolvedValue(status);
    vi.spyOn(api, "getUiDiagnostics").mockResolvedValue(diagnostics);
    const runAction = vi.spyOn(api, "runAction").mockResolvedValue({
      status: "queued",
    });
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    const root = document.querySelector<HTMLElement>("#app")!;

    new App(root).start();
    await Promise.resolve();
    await Promise.resolve();
    root.querySelector<HTMLButtonElement>('[data-view="diagnostics"]')!.click();
    await Promise.resolve();
    await Promise.resolve();

    const prepare = root.querySelector<HTMLButtonElement>(
      '[data-action="prepare-card-removal"]',
    )!;
    prepare.click();
    await Promise.resolve();
    expect(runAction).not.toHaveBeenCalled();

    confirm.mockReturnValue(true);
    prepare.click();
    await Promise.resolve();
    await Promise.resolve();
    expect(runAction).toHaveBeenCalledWith("prepare-card-removal", undefined);
    expect(root.querySelector("#action-result")?.textContent).toContain(
      "power off the sensor before removing the card",
    );
  });

  it("does not overlap Status polls and does not fetch config, metrics, OTA, or events", async () => {
    vi.useFakeTimers();
    vi.spyOn(api, "openSession").mockResolvedValue({
      expiresInSeconds: 900,
      setupRequired: false,
      elevated: false,
    });
    let resolveStatus!: (value: UiStatus) => void;
    const statusRequest = new Promise<UiStatus>((resolve) => {
      resolveStatus = resolve;
    });
    const getStatus = vi
      .spyOn(api, "getUiStatus")
      .mockReturnValue(statusRequest);
    const getConfig = vi.spyOn(api, "getConfig");
    const getDiagnostics = vi.spyOn(api, "getUiDiagnostics");
    const root = document.querySelector<HTMLElement>("#app")!;
    new App(root).start();
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(20_000);
    expect(getStatus).toHaveBeenCalledTimes(1);
    expect(getConfig).not.toHaveBeenCalled();
    expect(getDiagnostics).not.toHaveBeenCalled();
    resolveStatus(status);
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(4_999);
    expect(getStatus).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(getStatus).toHaveBeenCalledTimes(2);
  });

  it("loads Setup and Diagnostics only after their views are opened", async () => {
    vi.spyOn(api, "openSession").mockResolvedValue({
      expiresInSeconds: 900,
      setupRequired: false,
      elevated: false,
    });
    vi.spyOn(api, "getUiStatus").mockResolvedValue(status);
    const getConfig = vi.spyOn(api, "getConfig").mockResolvedValue(config);
    const getDiagnostics = vi
      .spyOn(api, "getUiDiagnostics")
      .mockResolvedValue(diagnostics);
    const root = document.querySelector<HTMLElement>("#app")!;
    new App(root).start();
    await Promise.resolve();
    await Promise.resolve();
    expect(getConfig).not.toHaveBeenCalled();
    expect(getDiagnostics).not.toHaveBeenCalled();
    root.querySelector<HTMLButtonElement>('[data-view="setup"]')!.click();
    await Promise.resolve();
    expect(getConfig).toHaveBeenCalledOnce();
    root.querySelector<HTMLButtonElement>('[data-view="diagnostics"]')!.click();
    await Promise.resolve();
    expect(getDiagnostics).toHaveBeenCalledOnce();
  });
});
