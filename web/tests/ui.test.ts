import { describe, expect, it, vi } from "vitest";
import * as api from "../src/api";
import { App } from "../src/main";
import {
  destructiveConfirmation,
  readConfigForm,
  readNetworkSettingsForm,
  renderBanners,
  renderSetup,
  renderShell,
  renderStatus,
} from "../src/ui";
import type { EffectiveConfig, Health, LiveReading } from "../src/types";

const health: Health = {
  schema_version: 1,
  protocol: "pm-protocol/1.0.0",
  device_id: "6db47e3d-b16c-4746-8f21-64310f9e9252",
  friendly_name: "Garage HVAC",
  status: "healthy",
  uptime_seconds: 120,
  firmware_version: "1.0.0",
  wifi: {
    connected: true,
    rssi_dbm: -57,
    ip_address: "192.168.1.41",
    hostname: "power-monitor-a1b2c3.local",
  },
  time: { synchronized: true, utc: "2026-07-20T18:42:15Z" },
  meter: { connected: true, consecutive_errors: 0, last_error: "none" },
  storage: {
    present: true,
    mounted: true,
    writable: true,
    free_bytes: 1_000_000,
    oldest_sequence: 1,
    newest_sequence: 20,
    server_ack_sequence: 18,
  },
  server: { configured: true, reachable: true, last_heartbeat_utc: 0 },
};
const live: LiveReading = {
  timestamp_utc: health.time.utc,
  timestamp_trusted: true,
  voltage_v: 121.3,
  current_a: 7.42,
  active_power_w: 873.5,
  meter_energy_total_wh: 3957128,
  device_lifetime_energy_wh: 3957128,
  frequency_hz: 59.98,
  power_factor: 0.97,
  ct_rating_a: 100,
  quality: { valid: true, method: "pzem", error: "none" },
};
const config: EffectiveConfig = {
  schema_version: 1,
  config_version: 1,
  friendly_name: "Garage HVAC",
  hostname: "power-monitor-a1b2c3",
  wifi_ssid: "Test",
  static_network_enabled: false,
  static_ip: "",
  static_gateway: "",
  static_subnet: "",
  static_dns: "",
  server_url: "https://server.local",
  server_ca_configured: true,
  server_fingerprint_configured: false,
  connection_mode: "hybrid",
  sample_interval_seconds: 1,
  durable_log_interval_seconds: 60,
  heartbeat_interval_seconds: 15,
  ct_rating_a: 100,
  timezone: "America/Los_Angeles",
  sd_spi_hz: 4_000_000,
  diagnostic_log_level: 2,
};

describe("local diagnostics UI", () => {
  it("polls a bounded background password job without blocking the request", async () => {
    vi.useFakeTimers();
    const responses = [
      { status: 202, body: { status: "queued", job_id: "a".repeat(32) } },
      { status: 202, body: { status: "pending" } },
      {
        status: 200,
        body: {
          csrf: "job-csrf",
          expires_in_seconds: 900,
          setup_required: false,
        },
      },
    ];
    const fetchMock = vi.fn(async (_input: RequestInfo | URL) => {
      const next = responses.shift()!;
      return new Response(JSON.stringify(next.body), {
        status: next.status,
        headers: { "Content-Type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    const login = api.login("not-logged");
    for (let index = 0; index < 10; index += 1) await Promise.resolve();
    await vi.advanceTimersByTimeAsync(250);
    const session = await login;
    expect(session).toEqual({
      expiresInSeconds: 900,
      setupRequired: false,
    });
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(String(fetchMock.mock.calls[1][0])).toContain(
      "/api/v1/auth/password-jobs?job_id=",
    );
    vi.useRealTimers();
  });

  it("renders local diagnostics without a login screen", () => {
    document.body.innerHTML = renderShell();
    expect(document.querySelector("#login-form")).toBeNull();
    const navigation = document.querySelector(
      'nav[aria-label="Diagnostics sections"]',
    );
    expect(navigation).not.toBeNull();
    const buttons = [
      ...navigation!.querySelectorAll<HTMLButtonElement>("[data-view]"),
    ];
    expect(buttons[1].dataset.view).toBe("setup");
    expect(buttons[1].textContent).toBe("Settings");
    expect(document.body.textContent).toContain("Power Monitor Sensor Agent");
  });

  it("renders live status with text status indicators", () => {
    document.body.innerHTML = renderStatus(health, live);
    expect(document.body.textContent).toContain("873.5 W");
    expect(document.body.textContent).toContain("Operational");
    expect(document.body.textContent).toContain("2 records");
  });

  it("keeps a persistent critical storage warning", () => {
    const degraded = structuredClone(health);
    degraded.storage.writable = false;
    document.body.innerHTML = renderBanners(degraded);
    expect(document.querySelector('[role="alert"]')?.textContent).toContain(
      "Durable history is not protected",
    );
    expect(document.body.textContent).toContain("will not survive reboot");
  });

  it("validates setup and requires CT acknowledgement", () => {
    document.body.innerHTML = `<form id="f"><input name="friendly_name" value="Garage"><input name="hostname" value="garage-meter"><input name="server_url" value="https://server.local"><select name="connection_mode"><option selected>hybrid</option></select><input name="ct_rating_a" value="32"><input name="ct_ack" type="checkbox" checked></form>`;
    const form = document.querySelector<HTMLFormElement>("#f")!;
    Object.defineProperty(form, "reportValidity", { value: () => true });
    const result = readConfigForm(form, config);
    expect(result.config.ct_rating_a).toBe(32);
    expect(result.ctAcknowledged).toBe(true);
    (form.elements.namedItem("ct_rating_a") as HTMLInputElement).value = "0";
    expect(() => readConfigForm(form, config)).toThrow(/1 through 1000/);
  });

  it("requires exact destructive-action confirmation", () => {
    vi.spyOn(window, "prompt").mockReturnValue("no");
    expect(
      destructiveConfirmation("factory-reset", "FACTORY RESET"),
    ).toBeNull();
    vi.spyOn(window, "prompt").mockReturnValue("FACTORY RESET");
    expect(destructiveConfirmation("factory-reset", "FACTORY RESET")).toBe(
      "FACTORY RESET",
    );
  });

  it("renders a write-only first-run provisioning form", () => {
    document.body.innerHTML = renderSetup(config, true);
    expect(
      document.querySelector<HTMLInputElement>('[name="enrollment_token"]')
        ?.type,
    ).toBe("password");
    expect(
      document.querySelector<HTMLInputElement>('[name="admin_password"]')
        ?.autocomplete,
    ).toBe("new-password");
    const wifiPassword = document.querySelector<HTMLInputElement>(
      '[name="wifi_password"]',
    );
    expect(wifiPassword?.required).toBe(true);
    expect(wifiPassword?.minLength).toBe(8);
    expect(document.body.textContent).toContain("Secrets are write-only");
  });

  it("renders post-enrollment Wi-Fi and server settings without secrets", () => {
    document.body.innerHTML = renderSetup(config);
    const form = document.querySelector<HTMLFormElement>(
      "#network-settings-form",
    );
    expect(form).not.toBeNull();
    expect(
      form?.querySelector<HTMLInputElement>('[name="wifi_ssid"]')?.value,
    ).toBe("Test");
    expect(
      form?.querySelector<HTMLInputElement>('[name="wifi_password"]')?.value,
    ).toBe("");
    expect(
      form?.querySelector<HTMLTextAreaElement>('[name="server_ca_pem"]')?.value,
    ).toBe("");
    expect(document.body.textContent).toContain(
      "A CA certificate is configured",
    );
  });

  it("builds a bounded network update and preserves omitted secrets", () => {
    document.body.innerHTML = renderSetup(config);
    const form = document.querySelector<HTMLFormElement>(
      "#network-settings-form",
    )!;
    Object.defineProperty(form, "reportValidity", { value: () => true });
    const payload = readNetworkSettingsForm(form, config);
    expect(payload.wifi_ssid).toBe("Test");
    expect(payload.tls_trust_action).toBe("keep");
    expect(payload).not.toHaveProperty("wifi_password");
    expect(payload).not.toHaveProperty("server_ca_pem");

    (form.elements.namedItem("wifi_ssid") as HTMLInputElement).value =
      "Replacement Wi-Fi";
    expect(() => readNetworkSettingsForm(form, config)).toThrow(
      /password when changing/,
    );
  });

  it("supports keyboard navigation and mobile viewport markup", () => {
    document.body.innerHTML = renderShell();
    Object.defineProperty(window, "innerWidth", {
      value: 390,
      configurable: true,
    });
    const nav = document.querySelector("nav");
    const status = nav?.querySelector<HTMLButtonElement>(
      '[data-view="status"]',
    );
    status?.focus();
    expect(document.activeElement).toBe(status);
    expect(
      document.querySelector('meta[name="viewport"]') ?? true,
    ).toBeTruthy();
  });

  it("opens a local session automatically and renders fetched state", async () => {
    const responses = [
      { csrf: "csrf", expires_in_seconds: 900, setup_required: false },
      health,
      live,
      config,
      { index_healthy: true },
      {},
      {},
      { records: [] },
    ];
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL) =>
        new Response(JSON.stringify(responses.shift()), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    document.body.innerHTML = '<div id="app"></div>';
    const root = document.querySelector<HTMLElement>("#app")!;
    new App(root).start();
    await vi.waitFor(() => expect(root.textContent).toContain("Garage HVAC"));
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/v1/auth/session");
    expect(root.querySelector("#login-form")).toBeNull();
  });

  it("renders available diagnostics when the first meter snapshot is unavailable", async () => {
    const responses = [
      {
        body: { csrf: "csrf", expires_in_seconds: 900, setup_required: false },
        status: 200,
      },
      { body: health, status: 200 },
      {
        body: {
          code: "live_unavailable",
          detail: "No meter snapshot has completed yet.",
        },
        status: 503,
      },
      { body: config, status: 200 },
      { body: { index_healthy: true }, status: 200 },
      { body: {}, status: 200 },
      { body: {}, status: 200 },
      { body: { records: [] }, status: 200 },
    ];
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        const response = responses.shift()!;
        return new Response(JSON.stringify(response.body), {
          status: response.status,
          headers: { "Content-Type": "application/json" },
        });
      }),
    );
    document.body.innerHTML = '<div id="app"></div>';
    const root = document.querySelector<HTMLElement>("#app")!;
    new App(root).start();
    await vi.waitFor(() =>
      expect(root.textContent).toContain("Current sensor status"),
    );
    expect(root.textContent).toContain("Unavailable");
    expect(root.textContent).toContain(
      "Waiting for the first valid meter reading",
    );
    root.querySelector<HTMLButtonElement>('[data-view="network"]')!.click();
    expect(root.textContent).toContain("Change Wi-Fi/server settings");
    root.querySelector<HTMLButtonElement>("[data-open-settings]")!.click();
    expect(root.querySelector("#network-settings-form")).not.toBeNull();
    expect(
      root.querySelector("#network-settings-form")?.previousElementSibling
        ?.textContent,
    ).toContain("Leave the new Wi-Fi password blank");
  });

  it("preserves an edited friendly name across background polling", async () => {
    vi.useFakeTimers();
    const responses = [
      { csrf: "csrf", expires_in_seconds: 900, setup_required: true },
      health,
      live,
      config,
      { index_healthy: true },
      {},
      {},
      { records: [] },
      health,
      live,
      { ...config, friendly_name: "Previously saved name" },
      { index_healthy: true },
      {},
      {},
      { records: [] },
    ];
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async (_input: RequestInfo | URL) =>
          new Response(JSON.stringify(responses.shift() ?? {}), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
      ),
    );
    document.body.innerHTML = '<div id="app"></div>';
    const root = document.querySelector<HTMLElement>("#app")!;
    new App(root).start();
    for (let index = 0; index < 20; index += 1) await Promise.resolve();
    const input = root.querySelector<HTMLInputElement>(
      '#first-run-form [name="friendly_name"]',
    )!;
    input.value = "Kitchen power";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await vi.advanceTimersByTimeAsync(5000);
    for (let index = 0; index < 20; index += 1) await Promise.resolve();
    expect(
      root.querySelector<HTMLInputElement>(
        '#first-run-form [name="friendly_name"]',
      ),
    ).toBe(input);
    expect(input.value).toBe("Kitchen power");
    vi.useRealTimers();
  });

  it("stops polling and shows network transition instructions after setup", async () => {
    vi.useFakeTimers();
    const responses = [
      { csrf: "csrf", expires_in_seconds: 900, setup_required: true },
      health,
      live,
      config,
      { index_healthy: true },
      {},
      {},
      { records: [] },
      { status: "setup_applied" },
    ];
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL) =>
        new Response(JSON.stringify(responses.shift() ?? {}), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    document.body.innerHTML = '<div id="app"></div>';
    const root = document.querySelector<HTMLElement>("#app")!;
    new App(root).start();
    for (let index = 0; index < 20; index += 1) await Promise.resolve();
    const form = root.querySelector<HTMLFormElement>("#first-run-form")!;
    const setValue = (name: string, value: string): void => {
      (form.elements.namedItem(name) as HTMLInputElement).value = value;
    };
    setValue("wifi_ssid", "Test Wi-Fi");
    setValue("wifi_password", "test-password");
    setValue("server_url", "https://192.168.1.10:8443");
    setValue(
      "server_ca_pem",
      "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----",
    );
    setValue("enrollment_token", "single-use-token");
    setValue("admin_password", "correct horse battery staple");
    setValue("admin_password_confirm", "correct horse battery staple");
    (form.elements.namedItem("ct_ack") as HTMLInputElement).checked = true;
    form.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    for (let index = 0; index < 30; index += 1) await Promise.resolve();
    expect(root.textContent).toContain("Setup saved");
    expect(root.textContent).toContain("Reconnect this phone or computer");
    const callsAfterSetup = fetchMock.mock.calls.length;
    await vi.advanceTimersByTimeAsync(10_000);
    expect(fetchMock).toHaveBeenCalledTimes(callsAfterSetup);
    vi.useRealTimers();
  });

  it("saves post-enrollment network settings and leaves a stable reconnect screen", async () => {
    vi.useFakeTimers();
    const responses = [
      { csrf: "csrf", expires_in_seconds: 900, setup_required: false },
      health,
      live,
      config,
      { index_healthy: true },
      {},
      {},
      { records: [] },
      {
        status: "network_settings_applied",
        config_version: 2,
        network_apply_queued: true,
        reboot_queued: false,
      },
    ];
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL) =>
        new Response(JSON.stringify(responses.shift() ?? {}), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    document.body.innerHTML = '<div id="app"></div>';
    const root = document.querySelector<HTMLElement>("#app")!;
    new App(root).start();
    for (let index = 0; index < 20; index += 1) await Promise.resolve();
    root.querySelector<HTMLButtonElement>('[data-view="setup"]')!.click();
    const form = root.querySelector<HTMLFormElement>("#network-settings-form")!;
    form.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    for (let index = 0; index < 30; index += 1) await Promise.resolve();
    expect(root.textContent).toContain("Network/server settings saved");
    expect(
      fetchMock.mock.calls.some(
        ([path]) => path === "/api/v1/network-settings",
      ),
    ).toBe(true);
    const callsAfterSave = fetchMock.mock.calls.length;
    await vi.advanceTimersByTimeAsync(10_000);
    expect(fetchMock).toHaveBeenCalledTimes(callsAfterSave);
    vi.useRealTimers();
  });

  it("renews the local session automatically before it expires", async () => {
    vi.useFakeTimers();
    const responses = [
      { csrf: "csrf", expires_in_seconds: 1, setup_required: false },
      health,
      live,
      config,
      { index_healthy: true },
      {},
      {},
      { records: [] },
      { csrf: "csrf-renewed", expires_in_seconds: 900, setup_required: false },
      health,
      live,
      config,
      { index_healthy: true },
      {},
      {},
      { records: [] },
    ];
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL) =>
        new Response(JSON.stringify(responses.shift() ?? {}), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    document.body.innerHTML = '<div id="app"></div>';
    const root = document.querySelector<HTMLElement>("#app")!;
    new App(root).start();
    for (let index = 0; index < 20; index += 1) await Promise.resolve();
    expect(root.textContent).toContain("Garage HVAC");
    await vi.advanceTimersByTimeAsync(1000);
    for (let index = 0; index < 20; index += 1) await Promise.resolve();
    expect(
      fetchMock.mock.calls.filter(([path]) => path === "/api/v1/auth/session"),
    ).toHaveLength(2);
    expect(root.querySelector("#login-form")).toBeNull();
    vi.useRealTimers();
  });
});
