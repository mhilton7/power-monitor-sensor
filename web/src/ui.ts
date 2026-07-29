import type {
  EffectiveConfig,
  Health,
  LiveReading,
  NetworkSettingsPayload,
  SetupPayload,
} from "./types";

export type View =
  | "status"
  | "storage"
  | "network"
  | "meter"
  | "maintenance"
  | "setup";

const escapeHtml = (value: unknown): string =>
  String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

const number = (value: number, digits = 1): string =>
  Number.isFinite(value) ? value.toFixed(digits) : "Unavailable";

const statusLabel = (value: boolean): string =>
  value ? "Operational" : "Attention required";

export function renderShell(): string {
  const views: Array<[View, string]> = [
    ["status", "Status"],
    ["setup", "Settings"],
    ["network", "Network status"],
    ["storage", "Storage"],
    ["meter", "Meter"],
    ["maintenance", "Maintenance"],
  ];
  return `<header><div><p class="eyebrow">Local setup & diagnostics</p><h1>Power Monitor Sensor Agent</h1></div>
    <button id="theme-toggle" class="secondary" type="button" aria-label="Toggle color theme">Theme</button></header>
    <nav aria-label="Diagnostics sections">${views.map(([id, label]) => `<button type="button" data-view="${id}" aria-controls="main">${label}</button>`).join("")}</nav>
    <div id="banner-region" aria-live="polite"></div><main id="main" tabindex="-1"></main>
    <footer><p>Estimated sensor readings only. The central server owns rates, costs, reports, and alerts.</p></footer>`;
}

export function renderBanners(health: Health): string {
  const banners: string[] = [];
  if (!health.storage.present || !health.storage.writable) {
    banners.push(
      `<div class="banner critical" role="alert"><strong>Durable history is not protected.</strong> The required microSD card is missing, unmounted, read-only, full, or damaged. Live readings may continue; buffered RAM data will not survive reboot.</div>`,
    );
  }
  if (health.storage.low_space) {
    banners.push(
      `<div class="banner warning" role="alert"><strong>microSD free space is below the configured warning threshold.</strong> Review acknowledged retention or replace the card using the prepare-removal workflow.</div>`,
    );
  }
  if (!health.meter.connected) {
    banners.push(
      `<div class="banner warning" role="status"><strong>Meter communication degraded.</strong> Invalid readings are not replaced with zero. Check low-voltage UART wiring only after the installation is safely de-energized.</div>`,
    );
  }
  if (!health.time.synchronized) {
    banners.push(
      `<div class="banner warning" role="status"><strong>UTC time is untrusted.</strong> Records retain monotonic time and an explicit quality flag until synchronization returns.</div>`,
    );
  }
  if (health.status === "safe_mode") {
    banners.push(
      `<div class="banner critical" role="alert"><strong>Safe mode is active.</strong> Automatic OTA and destructive storage work are disabled.</div>`,
    );
  }
  return banners.join("");
}

export function renderStatus(health: Health, live?: LiveReading): string {
  const readings = live
    ? [
        ["Voltage", `${number(live.voltage_v)} V`],
        ["Current", `${number(live.current_a, 2)} A`],
        ["Active power", `${number(live.active_power_w)} W`],
        ["Frequency", `${number(live.frequency_hz, 2)} Hz`],
        ["Power factor", number(live.power_factor, 2)],
        ["Meter energy", `${number(live.meter_energy_total_wh / 1000, 3)} kWh`],
      ]
    : [
        ["Voltage", "Unavailable"],
        ["Current", "Unavailable"],
        ["Active power", "Unavailable"],
        ["Frequency", "Unavailable"],
        ["Power factor", "Unavailable"],
        ["Meter energy", "Unavailable"],
      ];
  return `<section aria-labelledby="status-heading"><div class="section-heading"><div><p class="eyebrow">${escapeHtml(health.friendly_name)}</p><h2 id="status-heading">Current sensor status</h2></div><span class="status-pill ${health.status}">${escapeHtml(health.status)}</span></div>
    <div class="reading-grid">${readings.map(([label, value]) => `<article class="reading"><h3>${label}</h3><p>${value}</p></article>`).join("")}</div>
    <div class="panel-grid"><article class="panel"><h3>Device</h3><dl><dt>Firmware</dt><dd>${escapeHtml(health.firmware_version)}</dd><dt>Uptime</dt><dd>${Math.floor(health.uptime_seconds / 60)} min</dd><dt>Timestamp</dt><dd>${escapeHtml(live?.timestamp_utc || health.time.utc || "Untrusted")}</dd></dl></article>
    <article class="panel"><h3>Connectivity</h3><dl><dt>Wi-Fi</dt><dd>${statusLabel(health.wifi.connected)} (${health.wifi.rssi_dbm} dBm)</dd><dt>Server</dt><dd>${statusLabel(health.server.reachable)}</dd><dt>Backlog</dt><dd>${Math.max(0, health.storage.newest_sequence - health.storage.server_ack_sequence)} records</dd></dl></article>
    <article class="panel"><h3>Scope</h3><p>This sensor reports one consumption-only circuit or conductor. It is not revenue-grade and does not calculate an electric bill.</p></article></div></section>`;
}

export function renderStorage(
  health: Health,
  storage: Record<string, unknown>,
): string {
  const freeGb = Number(health.storage.free_bytes) / 1_000_000_000;
  return `<section aria-labelledby="storage-heading"><h2 id="storage-heading">microSD storage</h2><p>The removable FAT32 card is the authoritative history store.</p>
    <div class="panel-grid"><article class="panel"><h3>Card health</h3><dl><dt>Present</dt><dd>${statusLabel(health.storage.present)}</dd><dt>Writable</dt><dd>${statusLabel(health.storage.writable)}</dd><dt>Free</dt><dd>${number(freeGb, 2)} GB</dd><dt>Index</dt><dd>${escapeHtml(storage.index_healthy ?? "Unknown")}</dd></dl></article>
    <article class="panel"><h3>Stored range</h3><dl><dt>Oldest sequence</dt><dd>${health.storage.oldest_sequence}</dd><dt>Newest sequence</dt><dd>${health.storage.newest_sequence}</dd><dt>Server acknowledged</dt><dd>${health.storage.server_ack_sequence}</dd></dl></article></div>
    <form id="export-form" class="form-grid"><label>After sequence<input name="after_sequence" type="number" min="0" step="1" value="0" /></label><label>From local date/time<input name="from_utc" type="datetime-local" /></label><label>To local date/time<input name="to_utc" type="datetime-local" /></label><button type="submit">Export bounded NDJSON page</button><p id="export-result" role="status"></p></form>
    <div class="actions" aria-label="Storage maintenance"><button data-action="test-sd">Test card</button><button data-action="remount-sd">Remount</button><button data-action="rebuild-index">Rebuild index</button><button data-action="prepare-card-removal">Prepare removal</button></div>
    <p class="warning-text">Prepare removal before physically touching the card. This action does not make a mains enclosure safe to open.</p></section>`;
}

export function renderNetwork(health: Health, config: EffectiveConfig): string {
  return `<section aria-labelledby="network-heading"><h2 id="network-heading">Network and central server</h2><div class="panel-grid"><article class="panel"><h3>Local network</h3><dl><dt>SSID</dt><dd>${escapeHtml(config.wifi_ssid)}</dd><dt>IP address</dt><dd>${escapeHtml(health.wifi.ip_address)}</dd><dt>Hostname</dt><dd>${escapeHtml(health.wifi.hostname)}</dd><dt>Signal</dt><dd>${health.wifi.rssi_dbm} dBm</dd></dl></article>
  <article class="panel"><h3>Central server</h3><dl><dt>URL</dt><dd>${escapeHtml(config.server_url)}</dd><dt>Mode</dt><dd>${escapeHtml(config.connection_mode)}</dd><dt>TLS trust</dt><dd>${config.server_ca_configured || config.server_fingerprint_configured ? "Configured" : "Missing"}</dd><dt>Authenticated</dt><dd>${statusLabel(health.server.reachable)}</dd></dl></article></div>
  <div class="actions"><button type="button" data-open-settings>Change Wi-Fi/server settings</button><button data-action="test-dns">Test DNS</button><button data-action="test-ntp">Test NTP</button><button data-action="test-server-tls">Test server TLS</button><button data-action="test-heartbeat">Test heartbeat</button></div></section>`;
}

export function renderMeter(
  health: Health,
  live: LiveReading | undefined,
  config: EffectiveConfig,
): string {
  const ratio = live ? live.current_a / config.ct_rating_a : Number.NaN;
  const warning = config.ct_warning_fraction ?? 0.8;
  const critical = config.ct_critical_fraction ?? 0.9;
  const fault = config.ct_fault_fraction ?? 1.1;
  const level = !live
    ? "Waiting for a valid meter snapshot"
    : ratio >= fault
      ? "Possible configuration or hardware fault"
      : ratio >= critical
        ? `${number(critical * 100, 0)}% CT warning`
        : ratio >= warning
          ? `${number(warning * 100, 0)}% CT warning`
          : "Within configured range";
  return `<section aria-labelledby="meter-heading"><h2 id="meter-heading">PZEM meter</h2><div class="panel-grid"><article class="panel"><h3>Communication</h3><dl><dt>Status</dt><dd>${statusLabel(health.meter.connected)}</dd><dt>Recent errors</dt><dd>${health.meter.consecutive_errors}</dd><dt>Last error</dt><dd>${escapeHtml(health.meter.last_error)}</dd></dl></article>
  <article class="panel"><h3>CT scope</h3><dl><dt>Configured rating</dt><dd>${config.ct_rating_a} A</dd><dt>Current loading</dt><dd>${number(ratio * 100)}%</dd><dt>Threshold status</dt><dd>${level}</dd></dl></article></div>
  <div class="banner warning"><strong>Electrical scope:</strong> the CT must surround exactly one current-carrying conductor, and the PZEM voltage input must reference the same monitored circuit and phase. Never move or clamp conductors while energized.</div><button data-action="test-pzem">Run communication test</button></section>`;
}

export function renderMaintenance(
  metrics: Record<string, unknown>,
  ota: Record<string, unknown>,
  events: Record<string, unknown>,
): string {
  return `<section aria-labelledby="maintenance-heading"><h2 id="maintenance-heading">Maintenance and recovery</h2><p>Diagnostics are redacted. Signed OTA verifies target, protocol, signature, image hash, and downgrade policy before changing the inactive slot.</p>
  <div class="panel-grid"><article class="panel"><h3>Signed OTA status</h3><pre>${escapeHtml(JSON.stringify(ota, null, 2))}</pre></article><article class="panel"><h3>Recent device events</h3><pre>${escapeHtml(JSON.stringify(events, null, 2))}</pre></article></div>
  <details><summary>Machine counters</summary><pre>${escapeHtml(JSON.stringify(metrics, null, 2))}</pre></details>
  <div class="actions"><a class="button" href="/api/v1/diagnostics/bundle" download>Download diagnostics</a><button data-action="reboot" data-destructive="REBOOT">Reboot</button><button data-action="network-reset" data-destructive="RESET NETWORK">Reset network</button><button class="danger" data-action="factory-reset" data-destructive="FACTORY RESET">Factory reset</button></div></section>`;
}

export function renderSetup(
  config: EffectiveConfig,
  setupRequired = false,
): string {
  if (setupRequired) {
    return `<section aria-labelledby="setup-heading"><h2 id="setup-heading">Complete first-run setup</h2>
    <div class="banner warning" role="status"><strong>Local-only workflow:</strong> enter the one-time enrollment token and TLS trust material from your central server. Secrets are write-only and are cleared from the browser after submission.</div>
    <form id="first-run-form" class="form-grid"><label>Friendly name<input name="friendly_name" value="${escapeHtml(config.friendly_name)}" minlength="1" maxlength="64" required /></label>
    <label>Wi-Fi SSID<input name="wifi_ssid" maxlength="32" autocomplete="off" required /></label>
    <label>Wi-Fi password<input name="wifi_password" type="password" minlength="8" maxlength="63" autocomplete="new-password" required /><span class="field-note">ESP32-S3 uses 2.4 GHz Wi-Fi. Enter the network password exactly.</span></label>
    <label class="check"><input name="static_network_enabled" type="checkbox" /> Use optional static IPv4 settings below (DHCP is the default).</label>
    <label>Static IPv4 address<input name="static_ip" inputmode="decimal" maxlength="15" /></label><label>Gateway<input name="static_gateway" inputmode="decimal" maxlength="15" /></label><label>Subnet mask<input name="static_subnet" inputmode="decimal" maxlength="15" /></label><label>DNS server<input name="static_dns" inputmode="decimal" maxlength="15" /></label>
    <label>Central server URL<input name="server_url" type="url" pattern="https://.*" placeholder="https://monitor.example" required /></label>
    <label>Server CA certificate (public PEM)<textarea name="server_ca_pem" rows="7" maxlength="8192" spellcheck="false" required></textarea><span class="field-note">For TrueNAS internal-CA deployments, paste the complete public <code>root.crt</code> from <code>/mnt/Apps/Power/power-monitor/caddy-data/caddy/pki/authorities/local/root.crt</code>. Never paste or export <code>root.key</code>. CA and hostname validation are mandatory.</span></label>
    <label>One-time enrollment token<input name="enrollment_token" type="password" maxlength="256" autocomplete="off" required /></label>
    <label>Local administrator password<input name="admin_password" type="password" minlength="12" maxlength="128" autocomplete="new-password" required /></label>
    <label>Confirm administrator password<input name="admin_password_confirm" type="password" minlength="12" maxlength="128" autocomplete="new-password" required /></label>
    <label>Connection mode<select name="connection_mode"><option>hybrid</option><option>push</option><option>pull</option></select></label>
    <label>Installed CT rating (A)<input name="ct_rating_a" type="number" min="1" max="1000" step="0.1" value="${config.ct_rating_a}" required /></label>
    <label class="check"><input name="ct_ack" type="checkbox" required /> I verified the CT rating matches the installed PZEM/CT set. Electrical work remains de-energized.</label>
    <button type="submit">Commit setup and connect</button><p id="setup-result" role="status"></p></form></section>`;
  }
  const trustSummary = config.server_ca_configured
    ? "A CA certificate is configured."
    : config.server_fingerprint_configured
      ? "A legacy fingerprint is configured but cannot be used safely; replace it with a CA certificate."
      : "No TLS trust material is configured.";
  return `<section aria-labelledby="setup-heading"><h2 id="setup-heading">Device settings</h2><p>Changes are validated and stored persistently. Passwords and TLS trust material are write-only and are never returned to this page.</p>
  <h3>Wi-Fi and central server</h3>
  <p>Leave the new Wi-Fi password blank to keep the saved password. Changing these settings restarts the Wi-Fi connection and may change its address.</p>
  <form id="network-settings-form" class="form-grid">
  <label>Wi-Fi SSID<input name="wifi_ssid" value="${escapeHtml(config.wifi_ssid)}" maxlength="32" autocomplete="off" required /></label>
  <label>New Wi-Fi password<input name="wifi_password" type="password" minlength="8" maxlength="63" autocomplete="new-password" placeholder="Leave blank to keep current password" /></label>
  <label class="check"><input name="static_network_enabled" type="checkbox" ${config.static_network_enabled ? "checked" : ""} /> Use static IPv4 settings instead of DHCP.</label>
  <label>Static IPv4 address<input name="static_ip" value="${escapeHtml(config.static_ip)}" inputmode="decimal" maxlength="15" /></label>
  <label>Gateway<input name="static_gateway" value="${escapeHtml(config.static_gateway)}" inputmode="decimal" maxlength="15" /></label>
  <label>Subnet mask<input name="static_subnet" value="${escapeHtml(config.static_subnet)}" inputmode="decimal" maxlength="15" /></label>
  <label>DNS server<input name="static_dns" value="${escapeHtml(config.static_dns)}" inputmode="decimal" maxlength="15" /></label>
  <label>Central server URL<input name="server_url" type="url" value="${escapeHtml(config.server_url)}" pattern="https://.*" maxlength="256" required /></label>
  <label>Connection mode<select name="connection_mode">${["pull", "push", "hybrid"].map((mode) => `<option ${config.connection_mode === mode ? "selected" : ""}>${mode}</option>`).join("")}</select></label>
  <label>TLS trust update<select name="tls_trust_action"><option value="keep" selected>Keep current CA</option><option value="replace_ca">Replace with CA certificate</option></select><span class="field-note">${escapeHtml(trustSummary)}</span></label>
  <label>Replacement server CA certificate (public PEM)<textarea name="server_ca_pem" rows="7" maxlength="8192" spellcheck="false" placeholder="Required only when replacing the CA"></textarea><span class="field-note">Use the public <code>root.crt</code>, never Caddy's private <code>root.key</code>.</span></label>
  <button type="submit">Save settings and reconnect</button><p id="network-settings-result" role="status"></p></form>
  <h3>Device identity and meter</h3>
  <form id="config-form" class="form-grid"><label>Friendly name<input name="friendly_name" value="${escapeHtml(config.friendly_name)}" minlength="1" maxlength="64" required /></label>
  <label>Hostname<input name="hostname" value="${escapeHtml(config.hostname)}" pattern="[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?" required /></label>
  <label>CT rating (A)<input name="ct_rating_a" type="number" min="1" max="1000" step="0.1" value="${config.ct_rating_a}" required /></label>
  <label>Serial diagnostic level<select name="diagnostic_log_level">${[
    ["0", "Trace (temporary deep diagnosis)"],
    ["1", "Debug"],
    ["2", "Info (production default)"],
    ["3", "Warning"],
    ["4", "Error"],
    ["5", "Fatal only"],
  ]
    .map(
      ([value, label]) =>
        `<option value="${value}" ${config.diagnostic_log_level === Number(value) ? "selected" : ""}>${label}</option>`,
    )
    .join(
      "",
    )}</select><span class="field-note">Changes persist. TRACE raw protocol logs are compiled only into diagnostic builds.</span></label>
  <label class="check"><input name="ct_ack" type="checkbox" /> I verified the configured CT rating matches the installed PZEM/CT set.</label>
  <button type="submit">Validate and apply</button><p id="config-result" role="status"></p></form>
  <h3>Enrollment</h3>
  <form id="reenrollment-form" class="form-grid"><label>New one-time enrollment token<input name="enrollment_token" type="password" maxlength="256" autocomplete="off" required /></label><button class="danger" type="submit">Revoke and reenroll</button><p id="reenrollment-result" role="status"></p></form>
  <div class="scope-note"><strong>No rate settings:</strong> this device stores raw and normalized energy only. Utility rates and bill estimates belong on the central server.</div></section>`;
}

export function readSetupForm(form: HTMLFormElement): SetupPayload {
  if (!form.reportValidity())
    throw new Error("Please correct the highlighted first-run fields.");
  const data = new FormData(form);
  const adminPassword = String(data.get("admin_password") ?? "");
  if (adminPassword !== String(data.get("admin_password_confirm") ?? "")) {
    throw new Error("Administrator password confirmation does not match.");
  }
  if (adminPassword.length < 12)
    throw new Error(
      "Administrator password must contain at least 12 characters.",
    );
  const wifiPassword = String(data.get("wifi_password") ?? "");
  if (wifiPassword.length < 8 || wifiPassword.length > 63)
    throw new Error("Wi-Fi password must contain 8 through 63 characters.");
  const ca = String(data.get("server_ca_pem") ?? "").trim();
  if (!ca)
    throw new Error("Provide the public server CA certificate in PEM format.");
  const ct = Number(data.get("ct_rating_a"));
  if (
    !Number.isFinite(ct) ||
    ct < 1 ||
    ct > 1000 ||
    data.get("ct_ack") !== "on"
  ) {
    throw new Error(
      "Verify and acknowledge the installed CT rating (1 through 1000 A).",
    );
  }
  const staticEnabled = data.get("static_network_enabled") === "on";
  const staticValues = [
    "static_ip",
    "static_gateway",
    "static_subnet",
    "static_dns",
  ].map((name) => String(data.get(name) ?? "").trim());
  if (
    staticEnabled &&
    staticValues.some((value) => !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value))
  ) {
    throw new Error(
      "Static networking requires an IPv4 address, gateway, subnet mask, and DNS server.",
    );
  }
  return {
    friendly_name: String(data.get("friendly_name") ?? "").trim(),
    wifi_ssid: String(data.get("wifi_ssid") ?? ""),
    wifi_password: wifiPassword,
    static_network_enabled: staticEnabled,
    static_ip: staticValues[0],
    static_gateway: staticValues[1],
    static_subnet: staticValues[2],
    static_dns: staticValues[3],
    server_url: String(data.get("server_url") ?? "").trim(),
    server_ca_pem: ca,
    server_fingerprint: "",
    enrollment_token: String(data.get("enrollment_token") ?? ""),
    admin_password: adminPassword,
    connection_mode: String(
      data.get("connection_mode"),
    ) as SetupPayload["connection_mode"],
    ct_rating_a: ct,
  };
}

export function readConfigForm(
  form: HTMLFormElement,
  current: EffectiveConfig,
): { config: EffectiveConfig; ctAcknowledged: boolean } {
  if (!form.reportValidity())
    throw new Error("Please correct the highlighted setup fields.");
  const data = new FormData(form);
  const ct = Number(data.get("ct_rating_a"));
  if (!Number.isFinite(ct) || ct < 1 || ct > 1000)
    throw new Error("CT rating must be 1 through 1000 A.");
  const diagnosticLogLevel = Number(data.get("diagnostic_log_level"));
  if (
    !Number.isInteger(diagnosticLogLevel) ||
    diagnosticLogLevel < 0 ||
    diagnosticLogLevel > 5
  )
    throw new Error("Select a supported serial diagnostic level.");
  return {
    config: {
      ...current,
      friendly_name: String(data.get("friendly_name") ?? "").trim(),
      hostname: String(data.get("hostname") ?? "").trim(),
      ct_rating_a: ct,
      diagnostic_log_level: diagnosticLogLevel,
    },
    ctAcknowledged: data.get("ct_ack") === "on",
  };
}

export function readNetworkSettingsForm(
  form: HTMLFormElement,
  current: EffectiveConfig,
): NetworkSettingsPayload {
  if (!form.reportValidity())
    throw new Error("Please correct the highlighted network fields.");
  const data = new FormData(form);
  const wifiSsid = String(data.get("wifi_ssid") ?? "").trim();
  const wifiPassword = String(data.get("wifi_password") ?? "");
  if (!wifiSsid || wifiSsid.length > 32)
    throw new Error("Wi-Fi SSID must contain 1 through 32 characters.");
  if (wifiSsid !== current.wifi_ssid && !wifiPassword)
    throw new Error("Enter the Wi-Fi password when changing the network name.");
  if (wifiPassword && (wifiPassword.length < 8 || wifiPassword.length > 63))
    throw new Error("Wi-Fi password must contain 8 through 63 characters.");

  const staticEnabled = data.get("static_network_enabled") === "on";
  const staticValues = [
    "static_ip",
    "static_gateway",
    "static_subnet",
    "static_dns",
  ].map((name) => String(data.get(name) ?? "").trim());
  if (
    staticEnabled &&
    staticValues.some((value) => !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value))
  ) {
    throw new Error(
      "Static networking requires an IPv4 address, gateway, subnet mask, and DNS server.",
    );
  }

  const serverUrl = String(data.get("server_url") ?? "").trim();
  if (!serverUrl.startsWith("https://"))
    throw new Error("The central server URL must use HTTPS.");
  const trustAction = String(
    data.get("tls_trust_action") ?? "keep",
  ) as NetworkSettingsPayload["tls_trust_action"];
  const ca = String(data.get("server_ca_pem") ?? "").trim();
  if (trustAction === "keep") {
    if (!current.server_ca_configured) {
      throw new Error(
        "No usable CA is configured; replace the legacy or missing trust with a CA certificate.",
      );
    }
  } else if (trustAction === "replace_ca") {
    if (!ca) throw new Error("Paste the replacement CA certificate.");
  } else {
    throw new Error("Select a supported TLS trust update.");
  }

  const payload: NetworkSettingsPayload = {
    wifi_ssid: wifiSsid,
    static_network_enabled: staticEnabled,
    static_ip: staticValues[0],
    static_gateway: staticValues[1],
    static_subnet: staticValues[2],
    static_dns: staticValues[3],
    server_url: serverUrl,
    tls_trust_action: trustAction,
    connection_mode: String(
      data.get("connection_mode") ?? "hybrid",
    ) as NetworkSettingsPayload["connection_mode"],
  };
  if (wifiPassword) payload.wifi_password = wifiPassword;
  if (trustAction === "replace_ca") payload.server_ca_pem = ca;
  return payload;
}

export function destructiveConfirmation(
  action: string,
  phrase: string,
): string | null {
  const value = window.prompt(
    `Type ${phrase} to authorize ${action}. This confirmation expires immediately.`,
  );
  return value === phrase ? value : null;
}
