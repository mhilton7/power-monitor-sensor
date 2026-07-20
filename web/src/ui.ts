import type { EffectiveConfig, Health, LiveReading, SetupPayload } from "./types";

export type View = "status" | "storage" | "network" | "meter" | "maintenance" | "setup";

const escapeHtml = (value: unknown): string =>
  String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

const number = (value: number, digits = 1): string =>
  Number.isFinite(value) ? value.toFixed(digits) : "Unavailable";

const statusLabel = (value: boolean): string => (value ? "Operational" : "Attention required");

export function renderShell(authenticated: boolean): string {
  if (!authenticated) {
    return `<main id="main" class="login-shell"><section class="panel login-panel" aria-labelledby="login-title">
      <p class="eyebrow">Local diagnostics</p><h1 id="login-title">Power Monitor Sensor Agent</h1>
      <p>Sign in with this device's local administrator password. Credentials stay on this device.</p>
      <form id="login-form"><label for="password">Administrator password</label>
      <input id="password" name="password" type="password" minlength="12" maxlength="128" autocomplete="current-password" required />
      <button type="submit">Sign in</button><p id="login-error" class="error" role="alert" hidden></p></form>
      <p class="scope-note">Monitoring only. One CT measures only the single conductor passing through it. No utility bill is calculated here.</p>
    </section></main>`;
  }
  const views: Array<[View, string]> = [
    ["status", "Status"], ["storage", "Storage"], ["network", "Network & server"],
    ["meter", "Meter"], ["maintenance", "Maintenance"], ["setup", "Setup"],
  ];
  return `<header><div><p class="eyebrow">Local setup & diagnostics</p><h1>Power Monitor Sensor Agent</h1></div>
    <button id="theme-toggle" class="secondary" type="button" aria-label="Toggle color theme">Theme</button></header>
    <nav aria-label="Diagnostics sections">${views.map(([id, label]) => `<button type="button" data-view="${id}" aria-controls="main">${label}</button>`).join("")}</nav>
    <div id="banner-region" aria-live="polite"></div><main id="main" tabindex="-1"></main>
    <footer><p>Estimated sensor readings only. The central server owns rates, costs, reports, and alerts.</p>
    <button id="logout" type="button" class="link-button">Sign out</button></footer>`;
}

export function renderBanners(health: Health): string {
  const banners: string[] = [];
  if (!health.storage.present || !health.storage.writable) {
    banners.push(`<div class="banner critical" role="alert"><strong>Durable history is not protected.</strong> The required microSD card is missing, unmounted, read-only, full, or damaged. Live readings may continue; buffered RAM data will not survive reboot.</div>`);
  }
  if (!health.meter.connected) {
    banners.push(`<div class="banner warning" role="status"><strong>Meter communication degraded.</strong> Invalid readings are not replaced with zero. Check low-voltage UART wiring only after the installation is safely de-energized.</div>`);
  }
  if (!health.time.synchronized) {
    banners.push(`<div class="banner warning" role="status"><strong>UTC time is untrusted.</strong> Records retain monotonic time and an explicit quality flag until synchronization returns.</div>`);
  }
  if (health.status === "safe_mode") {
    banners.push(`<div class="banner critical" role="alert"><strong>Safe mode is active.</strong> Automatic OTA and destructive storage work are disabled.</div>`);
  }
  return banners.join("");
}

export function renderStatus(health: Health, live: LiveReading): string {
  const readings = [
    ["Voltage", `${number(live.voltage_v)} V`], ["Current", `${number(live.current_a, 2)} A`],
    ["Active power", `${number(live.active_power_w)} W`], ["Frequency", `${number(live.frequency_hz, 2)} Hz`],
    ["Power factor", number(live.power_factor, 2)], ["Meter energy", `${number(live.meter_energy_total_wh / 1000, 3)} kWh`],
  ];
  return `<section aria-labelledby="status-heading"><div class="section-heading"><div><p class="eyebrow">${escapeHtml(health.friendly_name)}</p><h2 id="status-heading">Current sensor status</h2></div><span class="status-pill ${health.status}">${escapeHtml(health.status)}</span></div>
    <div class="reading-grid">${readings.map(([label, value]) => `<article class="reading"><h3>${label}</h3><p>${value}</p></article>`).join("")}</div>
    <div class="panel-grid"><article class="panel"><h3>Device</h3><dl><dt>Firmware</dt><dd>${escapeHtml(health.firmware_version)}</dd><dt>Uptime</dt><dd>${Math.floor(health.uptime_seconds / 60)} min</dd><dt>Timestamp</dt><dd>${escapeHtml(live.timestamp_utc || "Untrusted")}</dd></dl></article>
    <article class="panel"><h3>Connectivity</h3><dl><dt>Wi-Fi</dt><dd>${statusLabel(health.wifi.connected)} (${health.wifi.rssi_dbm} dBm)</dd><dt>Server</dt><dd>${statusLabel(health.server.reachable)}</dd><dt>Backlog</dt><dd>${Math.max(0, health.storage.newest_sequence - health.storage.server_ack_sequence)} records</dd></dl></article>
    <article class="panel"><h3>Scope</h3><p>This sensor reports one consumption-only circuit or conductor. It is not revenue-grade and does not calculate an electric bill.</p></article></div></section>`;
}

export function renderStorage(health: Health, storage: Record<string, unknown>): string {
  const freeGb = Number(health.storage.free_bytes) / 1_000_000_000;
  return `<section aria-labelledby="storage-heading"><h2 id="storage-heading">microSD storage</h2><p>The removable FAT32 card is the authoritative history store.</p>
    <div class="panel-grid"><article class="panel"><h3>Card health</h3><dl><dt>Present</dt><dd>${statusLabel(health.storage.present)}</dd><dt>Writable</dt><dd>${statusLabel(health.storage.writable)}</dd><dt>Free</dt><dd>${number(freeGb, 2)} GB</dd><dt>Index</dt><dd>${escapeHtml(storage.index_healthy ?? "Unknown")}</dd></dl></article>
    <article class="panel"><h3>Stored range</h3><dl><dt>Oldest sequence</dt><dd>${health.storage.oldest_sequence}</dd><dt>Newest sequence</dt><dd>${health.storage.newest_sequence}</dd><dt>Server acknowledged</dt><dd>${health.storage.server_ack_sequence}</dd></dl></article></div>
    <div class="actions" aria-label="Storage maintenance"><button data-action="test-sd">Test card</button><button data-action="remount-sd">Remount</button><button data-action="rebuild-index">Rebuild index</button><button data-action="prepare-card-removal">Prepare removal</button></div>
    <p class="warning-text">Prepare removal before physically touching the card. This action does not make a mains enclosure safe to open.</p></section>`;
}

export function renderNetwork(health: Health, config: EffectiveConfig): string {
  return `<section aria-labelledby="network-heading"><h2 id="network-heading">Network and central server</h2><div class="panel-grid"><article class="panel"><h3>Local network</h3><dl><dt>SSID</dt><dd>${escapeHtml(config.wifi_ssid)}</dd><dt>IP address</dt><dd>${escapeHtml(health.wifi.ip_address)}</dd><dt>Hostname</dt><dd>${escapeHtml(health.wifi.hostname)}</dd><dt>Signal</dt><dd>${health.wifi.rssi_dbm} dBm</dd></dl></article>
  <article class="panel"><h3>Central server</h3><dl><dt>URL</dt><dd>${escapeHtml(config.server_url)}</dd><dt>Mode</dt><dd>${escapeHtml(config.connection_mode)}</dd><dt>TLS trust</dt><dd>${config.server_ca_configured || config.server_fingerprint_configured ? "Configured" : "Missing"}</dd><dt>Authenticated</dt><dd>${statusLabel(health.server.reachable)}</dd></dl></article></div>
  <div class="actions"><button data-action="test-dns">Test DNS</button><button data-action="test-ntp">Test NTP</button><button data-action="test-server-tls">Test server TLS</button><button data-action="test-heartbeat">Test heartbeat</button></div></section>`;
}

export function renderMeter(health: Health, live: LiveReading, config: EffectiveConfig): string {
  const ratio = live.current_a / config.ct_rating_a;
  const level = ratio >= 1.1 ? "Possible configuration or hardware fault" : ratio >= 0.9 ? "90% CT warning" : ratio >= 0.8 ? "80% CT warning" : "Within configured range";
  return `<section aria-labelledby="meter-heading"><h2 id="meter-heading">PZEM meter</h2><div class="panel-grid"><article class="panel"><h3>Communication</h3><dl><dt>Status</dt><dd>${statusLabel(health.meter.connected)}</dd><dt>Recent errors</dt><dd>${health.meter.consecutive_errors}</dd><dt>Last error</dt><dd>${escapeHtml(health.meter.last_error)}</dd></dl></article>
  <article class="panel"><h3>CT scope</h3><dl><dt>Configured rating</dt><dd>${config.ct_rating_a} A</dd><dt>Current loading</dt><dd>${number(ratio * 100)}%</dd><dt>Threshold status</dt><dd>${level}</dd></dl></article></div>
  <div class="banner warning"><strong>Electrical scope:</strong> the CT must surround exactly one current-carrying conductor, and the PZEM voltage input must reference the same monitored circuit and phase. Never move or clamp conductors while energized.</div><button data-action="test-pzem">Run communication test</button></section>`;
}

export function renderMaintenance(metrics: Record<string, unknown>): string {
  return `<section aria-labelledby="maintenance-heading"><h2 id="maintenance-heading">Maintenance and recovery</h2><p>Diagnostics are redacted. Signed OTA verifies target, protocol, signature, image hash, and downgrade policy before changing the inactive slot.</p>
  <details><summary>Machine counters</summary><pre>${escapeHtml(JSON.stringify(metrics, null, 2))}</pre></details>
  <div class="actions"><a class="button" href="/api/v1/diagnostics/bundle" download>Download diagnostics</a><button data-action="reboot" data-destructive="REBOOT">Reboot</button><button data-action="network-reset" data-destructive="RESET NETWORK">Reset network</button><button class="danger" data-action="factory-reset" data-destructive="FACTORY RESET">Factory reset</button></div></section>`;
}

export function renderSetup(config: EffectiveConfig, setupRequired = false): string {
  if (setupRequired) {
    return `<section aria-labelledby="setup-heading"><h2 id="setup-heading">Complete first-run setup</h2>
    <div class="banner warning" role="status"><strong>Local-only workflow:</strong> enter the one-time enrollment token and TLS trust material from your central server. Secrets are write-only and are cleared from the browser after submission.</div>
    <form id="first-run-form" class="form-grid"><label>Friendly name<input name="friendly_name" value="${escapeHtml(config.friendly_name)}" minlength="1" maxlength="64" required /></label>
    <label>Wi-Fi SSID<input name="wifi_ssid" maxlength="32" autocomplete="off" required /></label>
    <label>Wi-Fi password<input name="wifi_password" type="password" maxlength="63" autocomplete="new-password" /></label>
    <label>Central server URL<input name="server_url" type="url" pattern="https://.*" placeholder="https://monitor.example" required /></label>
    <label>Private CA certificate (PEM)<textarea name="server_ca_pem" rows="7" maxlength="8192" spellcheck="false"></textarea></label>
    <label>Or SHA-256 certificate fingerprint<input name="server_fingerprint" maxlength="128" spellcheck="false" /></label>
    <label>One-time enrollment token<input name="enrollment_token" type="password" maxlength="256" autocomplete="off" required /></label>
    <label>Local administrator password<input name="admin_password" type="password" minlength="12" maxlength="128" autocomplete="new-password" required /></label>
    <label>Confirm administrator password<input name="admin_password_confirm" type="password" minlength="12" maxlength="128" autocomplete="new-password" required /></label>
    <label>Connection mode<select name="connection_mode"><option>hybrid</option><option>push</option><option>pull</option></select></label>
    <label>Installed CT rating (A)<input name="ct_rating_a" type="number" min="1" max="1000" step="0.1" value="${config.ct_rating_a}" required /></label>
    <label class="check"><input name="ct_ack" type="checkbox" required /> I verified the CT rating matches the installed PZEM/CT set. Electrical work remains de-energized.</label>
    <button type="submit">Commit setup and reboot</button><p id="setup-result" role="status"></p></form></section>`;
  }
  return `<section aria-labelledby="setup-heading"><h2 id="setup-heading">Setup and provisioning</h2><p>Network-critical settings are validated and staged with rollback. Secret values are accepted by dedicated setup handlers and are never returned to this page.</p>
  <form id="config-form" class="form-grid"><label>Friendly name<input name="friendly_name" value="${escapeHtml(config.friendly_name)}" minlength="1" maxlength="64" required /></label>
  <label>Hostname<input name="hostname" value="${escapeHtml(config.hostname)}" pattern="[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?" required /></label>
  <label>Central server URL<input name="server_url" type="url" value="${escapeHtml(config.server_url)}" pattern="https://.*" required /></label>
  <label>Connection mode<select name="connection_mode">${["pull", "push", "hybrid"].map((mode) => `<option ${config.connection_mode === mode ? "selected" : ""}>${mode}</option>`).join("")}</select></label>
  <label>CT rating (A)<input name="ct_rating_a" type="number" min="1" max="1000" step="0.1" value="${config.ct_rating_a}" required /></label>
  <label class="check"><input name="ct_ack" type="checkbox" /> I verified the configured CT rating matches the installed PZEM/CT set.</label>
  <button type="submit">Validate and apply</button><p id="config-result" role="status"></p></form>
  <div class="scope-note"><strong>No rate settings:</strong> this device stores raw and normalized energy only. Utility rates and bill estimates belong on the central server.</div></section>`;
}

export function readSetupForm(form: HTMLFormElement): SetupPayload {
  if (!form.reportValidity()) throw new Error("Please correct the highlighted first-run fields.");
  const data = new FormData(form);
  const adminPassword = String(data.get("admin_password") ?? "");
  if (adminPassword !== String(data.get("admin_password_confirm") ?? "")) {
    throw new Error("Administrator password confirmation does not match.");
  }
  if (adminPassword.length < 12) throw new Error("Administrator password must contain at least 12 characters.");
  const ca = String(data.get("server_ca_pem") ?? "").trim();
  const fingerprint = String(data.get("server_fingerprint") ?? "").trim();
  if (!ca && !fingerprint) throw new Error("Provide a private CA PEM or a SHA-256 certificate fingerprint.");
  const ct = Number(data.get("ct_rating_a"));
  if (!Number.isFinite(ct) || ct < 1 || ct > 1000 || data.get("ct_ack") !== "on") {
    throw new Error("Verify and acknowledge the installed CT rating (1 through 1000 A).");
  }
  return {
    friendly_name: String(data.get("friendly_name") ?? "").trim(),
    wifi_ssid: String(data.get("wifi_ssid") ?? ""),
    wifi_password: String(data.get("wifi_password") ?? ""),
    server_url: String(data.get("server_url") ?? "").trim(),
    server_ca_pem: ca,
    server_fingerprint: fingerprint,
    enrollment_token: String(data.get("enrollment_token") ?? ""),
    admin_password: adminPassword,
    connection_mode: String(data.get("connection_mode")) as SetupPayload["connection_mode"],
    ct_rating_a: ct,
  };
}

export function readConfigForm(form: HTMLFormElement, current: EffectiveConfig): { config: EffectiveConfig; ctAcknowledged: boolean } {
  if (!form.reportValidity()) throw new Error("Please correct the highlighted setup fields.");
  const data = new FormData(form);
  const ct = Number(data.get("ct_rating_a"));
  if (!Number.isFinite(ct) || ct < 1 || ct > 1000) throw new Error("CT rating must be 1 through 1000 A.");
  return {
    config: {
      ...current,
      friendly_name: String(data.get("friendly_name") ?? "").trim(),
      hostname: String(data.get("hostname") ?? "").trim(),
      server_url: String(data.get("server_url") ?? "").trim(),
      connection_mode: String(data.get("connection_mode")) as EffectiveConfig["connection_mode"],
      ct_rating_a: ct,
    },
    ctAcknowledged: data.get("ct_ack") === "on",
  };
}

export function destructiveConfirmation(action: string, phrase: string): string | null {
  const value = window.prompt(`Type ${phrase} to authorize ${action}. This confirmation expires immediately.`);
  return value === phrase ? value : null;
}
