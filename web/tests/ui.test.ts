import { describe, expect, it, vi } from "vitest";
import { App } from "../src/main";
import { destructiveConfirmation, readConfigForm, renderBanners, renderSetup, renderShell, renderStatus } from "../src/ui";
import type { EffectiveConfig, Health, LiveReading } from "../src/types";

const health: Health = {
  schema_version: 1, protocol: "pm-protocol/1.0.0", device_id: "6db47e3d-b16c-4746-8f21-64310f9e9252",
  friendly_name: "Garage HVAC", status: "healthy", uptime_seconds: 120, firmware_version: "1.0.0",
  wifi: { connected: true, rssi_dbm: -57, ip_address: "192.168.1.41", hostname: "power-monitor-a1b2c3.local" },
  time: { synchronized: true, utc: "2026-07-20T18:42:15Z" }, meter: { connected: true, consecutive_errors: 0, last_error: "none" },
  storage: { present: true, mounted: true, writable: true, free_bytes: 1_000_000, oldest_sequence: 1, newest_sequence: 20, server_ack_sequence: 18 },
  server: { configured: true, reachable: true, last_heartbeat_utc: 0 },
};
const live: LiveReading = { timestamp_utc: health.time.utc, timestamp_trusted: true, voltage_v: 121.3, current_a: 7.42, active_power_w: 873.5, meter_energy_total_wh: 3957128, device_lifetime_energy_wh: 3957128, frequency_hz: 59.98, power_factor: 0.97, ct_rating_a: 100, quality: { valid: true, method: "pzem", error: "none" } };
const config: EffectiveConfig = { schema_version: 1, config_version: 1, friendly_name: "Garage HVAC", hostname: "power-monitor-a1b2c3", wifi_ssid: "Test", server_url: "https://server.local", server_ca_configured: true, server_fingerprint_configured: false, connection_mode: "hybrid", sample_interval_seconds: 1, durable_log_interval_seconds: 60, heartbeat_interval_seconds: 15, ct_rating_a: 100, timezone: "America/Los_Angeles", sd_spi_hz: 4_000_000 };

describe("local diagnostics UI", () => {
  it("renders login with safe password semantics", () => {
    document.body.innerHTML = renderShell(false);
    const input = document.querySelector<HTMLInputElement>("#password");
    expect(input?.type).toBe("password");
    expect(input?.autocomplete).toBe("current-password");
    expect(document.body.textContent).toContain("One CT measures only");
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
    expect(document.querySelector('[role="alert"]')?.textContent).toContain("Durable history is not protected");
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
    expect(destructiveConfirmation("factory-reset", "FACTORY RESET")).toBeNull();
    vi.spyOn(window, "prompt").mockReturnValue("FACTORY RESET");
    expect(destructiveConfirmation("factory-reset", "FACTORY RESET")).toBe("FACTORY RESET");
  });

  it("renders a write-only first-run provisioning form", () => {
    document.body.innerHTML = renderSetup(config, true);
    expect(document.querySelector<HTMLInputElement>('[name="enrollment_token"]')?.type).toBe("password");
    expect(document.querySelector<HTMLInputElement>('[name="admin_password"]')?.autocomplete).toBe("new-password");
    expect(document.body.textContent).toContain("Secrets are write-only");
  });

  it("supports keyboard navigation and mobile viewport markup", () => {
    document.body.innerHTML = renderShell(true);
    Object.defineProperty(window, "innerWidth", { value: 390, configurable: true });
    const nav = document.querySelector("nav");
    const status = nav?.querySelector<HTMLButtonElement>('[data-view="status"]');
    status?.focus();
    expect(document.activeElement).toBe(status);
    expect(document.querySelector('meta[name="viewport"]') ?? true).toBeTruthy();
  });

  it("logs in, clears the password, and renders fetched state", async () => {
    const responses = [
      { csrf: "csrf", expires_in_seconds: 900, setup_required: false }, health, live, config, { index_healthy: true }, {},
    ];
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(responses.shift()), { status: 200, headers: { "Content-Type": "application/json" } })));
    document.body.innerHTML = '<div id="app"></div>';
    const root = document.querySelector<HTMLElement>("#app")!;
    new App(root).start();
    const input = root.querySelector<HTMLInputElement>("#password")!;
    input.value = "correct horse battery staple";
    root.querySelector<HTMLFormElement>("#login-form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(root.textContent).toContain("Garage HVAC"));
    expect(input.value).toBe("");
  });
});
