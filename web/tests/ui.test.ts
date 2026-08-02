import { describe, expect, it, vi } from "vitest";
import * as api from "../src/api";
import { App, STATUS_INTERVAL_MS } from "../src/main";
import {
  clearSecrets,
  readConfiguredSetupForm,
  renderDiagnostics,
  renderSetup,
  renderShell,
  renderStatus,
  resolveServerFreshness,
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

  it.each([
    [0, "live", "Connected"],
    [4, "live", "Connected"],
    [15, "live", "Connected"],
    [29, "delayed", "Heartbeat delayed"],
    [30, "stale", "Connection stale"],
    [31, "stale", "Connection stale"],
    [356, "stale", "Connection stale"],
  ] as const)(
    "maps a %s-second-old heartbeat to %s",
    (age, expectedState, expectedLabel) => {
      const aged = structuredClone(status);
      aged.server = {
        state: age >= 30 ? "stale" : age > 15 ? "delayed" : "live",
        last_success_utc_ms: status.sync.last_success_utc_ms,
        age_seconds: age,
        expected_heartbeat_seconds: 15,
        stale_after_seconds: 30,
        offline_after_seconds: 30,
        last_attempt_result: age >= 30 ? "local_resource_deferred" : "ok",
        last_safe_error: age >= 30 ? "internal_heap_fragmented" : "",
      };
      const freshness = resolveServerFreshness(aged);
      expect(freshness.state).toBe(expectedState);
      expect(freshness.serverLabel).toBe(expectedLabel);
      if (age === 356) {
        expect(freshness.heartbeatLabel).toBe("5 minutes 56 seconds ago");
        expect(freshness.headerLabel).not.toBe("Server connected");
        expect(freshness.reason).toContain("contiguous TLS memory block");
      }
    },
  );

  it("distinguishes never connected, unauthenticated, and Wi-Fi offline", () => {
    const never = structuredClone(status);
    never.sync.last_success_utc_ms = null;
    expect(resolveServerFreshness(never).state).toBe("never_connected");

    const unauthenticated = structuredClone(status);
    unauthenticated.health.server = "unauthenticated";
    expect(resolveServerFreshness(unauthenticated).state).toBe(
      "unauthenticated",
    );

    const offline = structuredClone(status);
    offline.health.wifi = "offline";
    expect(resolveServerFreshness(offline).state).toBe("offline");
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
    await vi.advanceTimersByTimeAsync(STATUS_INTERVAL_MS - 1);
    expect(getStatus).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(getStatus).toHaveBeenCalledTimes(2);
  });

  it("coalesces manual refresh with an in-flight automatic Status request", async () => {
    vi.useFakeTimers();
    vi.spyOn(api, "openSession").mockResolvedValue({
      expiresInSeconds: 900,
      setupRequired: false,
      elevated: false,
    });
    let resolveStatus!: (value: UiStatus) => void;
    const getStatus = vi.spyOn(api, "getUiStatus").mockReturnValue(
      new Promise<UiStatus>((resolve) => {
        resolveStatus = resolve;
      }),
    );
    const root = document.querySelector<HTMLElement>("#app")!;
    const app = new App(root);
    app.start();
    await Promise.resolve();
    root.querySelector<HTMLButtonElement>("#refresh-status")!.click();
    root.querySelector<HTMLButtonElement>("#refresh-status")!.click();
    expect(getStatus).toHaveBeenCalledOnce();
    expect(app.requestCounters()).toMatchObject({
      requestsStarted: 1,
      maximumSimultaneousRequests: 1,
    });
    resolveStatus(status);
    await Promise.resolve();
    await Promise.resolve();
    expect(app.requestCounters()).toMatchObject({
      requestsCompleted: 1,
      requestsAborted: 0,
    });
  });

  it("pauses while hidden and refreshes once immediately when visible", async () => {
    vi.useFakeTimers();
    let hidden = false;
    vi.spyOn(document, "hidden", "get").mockImplementation(() => hidden);
    vi.spyOn(api, "openSession").mockResolvedValue({
      expiresInSeconds: 900,
      setupRequired: false,
      elevated: false,
    });
    const getStatus = vi.spyOn(api, "getUiStatus").mockResolvedValue(status);
    const root = document.querySelector<HTMLElement>("#app")!;
    const app = new App(root);
    app.start();
    await Promise.resolve();
    await Promise.resolve();
    expect(getStatus).toHaveBeenCalledOnce();

    hidden = true;
    document.dispatchEvent(new Event("visibilitychange"));
    await vi.advanceTimersByTimeAsync(60_000);
    expect(getStatus).toHaveBeenCalledOnce();

    hidden = false;
    document.dispatchEvent(new Event("visibilitychange"));
    await Promise.resolve();
    await Promise.resolve();
    expect(getStatus).toHaveBeenCalledTimes(2);
    expect(app.requestCounters().maximumSimultaneousRequests).toBe(1);
  });

  it("pauses Status polling during session renewal and resumes once", async () => {
    vi.useFakeTimers();
    vi.spyOn(api, "openSession").mockResolvedValue({
      expiresInSeconds: 1,
      setupRequired: false,
      elevated: false,
    });
    let releaseRenewal!: (value: api.SessionResult) => void;
    const renewal = new Promise<api.SessionResult>((resolve) => {
      releaseRenewal = resolve;
    });
    const renewSession = vi
      .spyOn(api, "renewLocalSession")
      .mockReturnValue(renewal);
    let call = 0;
    const getStatus = vi
      .spyOn(api, "getUiStatus")
      .mockImplementation((signal?: AbortSignal) => {
        call += 1;
        if (call !== 2) return Promise.resolve(status);
        return new Promise<UiStatus>((_resolve, reject) => {
          signal?.addEventListener(
            "abort",
            () => reject(new DOMException("Aborted", "AbortError")),
            { once: true },
          );
        });
      });
    const root = document.querySelector<HTMLElement>("#app")!;
    const app = new App(root);
    app.start();
    await vi.advanceTimersByTimeAsync(30_000);
    expect(renewSession).toHaveBeenCalledOnce();
    expect(getStatus).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(getStatus).toHaveBeenCalledTimes(2);

    releaseRenewal({
      expiresInSeconds: 900,
      setupRequired: false,
      elevated: false,
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(getStatus).toHaveBeenCalledTimes(3);
    expect(app.requestCounters()).toMatchObject({
      requestsAborted: 1,
      maximumSimultaneousRequests: 1,
      sessionRenewals: 1,
    });
  });

  it("updates heartbeat age once per second without additional network requests", async () => {
    vi.useFakeTimers();
    vi.spyOn(api, "openSession").mockResolvedValue({
      expiresInSeconds: 900,
      setupRequired: false,
      elevated: false,
    });
    const fresh = structuredClone(status);
    fresh.server = {
      state: "live",
      last_success_utc_ms: status.sync.last_success_utc_ms,
      age_seconds: 4,
      expected_heartbeat_seconds: 15,
      stale_after_seconds: 30,
      offline_after_seconds: 30,
      last_attempt_result: "ok",
      last_safe_error: "",
    };
    const getStatus = vi.spyOn(api, "getUiStatus").mockResolvedValue(fresh);
    const root = document.querySelector<HTMLElement>("#app")!;
    new App(root).start();
    await Promise.resolve();
    await Promise.resolve();
    expect(root.querySelector("#heartbeat-at")?.textContent).toBe(
      "4 seconds ago",
    );
    await vi.advanceTimersByTimeAsync(9_000);
    expect(getStatus).toHaveBeenCalledOnce();
    expect(root.querySelector("#heartbeat-at")?.textContent).toBe(
      "13 seconds ago",
    );
  });

  it("honors a bounded Retry-After without a 503 request storm", async () => {
    vi.useFakeTimers();
    vi.spyOn(api, "openSession").mockResolvedValue({
      expiresInSeconds: 900,
      setupRequired: false,
      elevated: false,
    });
    const getStatus = vi
      .spyOn(api, "getUiStatus")
      .mockRejectedValueOnce(
        new api.ApiError(
          503,
          "local_resource_deferred",
          "TLS has priority.",
          25_000,
        ),
      )
      .mockResolvedValue(status);
    const root = document.querySelector<HTMLElement>("#app")!;
    const app = new App(root);
    app.start();
    await Promise.resolve();
    await Promise.resolve();
    expect(getStatus).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(24_999);
    expect(getStatus).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(1);
    expect(getStatus).toHaveBeenCalledTimes(2);
    expect(app.requestCounters().automaticRetries).toBe(1);
  });

  it("keeps a 35-minute visible session at the 10-second request budget", async () => {
    vi.useFakeTimers();
    vi.spyOn(api, "openSession").mockResolvedValue({
      expiresInSeconds: 10_000,
      setupRequired: false,
      elevated: false,
    });
    const getStatus = vi.spyOn(api, "getUiStatus").mockResolvedValue(status);
    const root = document.querySelector<HTMLElement>("#app")!;
    const app = new App(root);
    app.start();
    await vi.advanceTimersByTimeAsync(2_100_000);
    expect(getStatus).toHaveBeenCalledTimes(211);
    expect(app.requestCounters().maximumSimultaneousRequests).toBe(1);
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
    expect(getDiagnostics).not.toHaveBeenCalled();
    root.querySelector<HTMLButtonElement>("#refresh-diagnostics")!.click();
    await Promise.resolve();
    expect(getDiagnostics).toHaveBeenCalledOnce();
  });
});
