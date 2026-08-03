import type {
  EffectiveConfig,
  MemoryState,
  NetworkSettingsPayload,
  ServerFreshnessState,
  SetupPayload,
  UiDiagnostics,
  UiStatus,
} from "./types";

export type View = "status" | "setup" | "diagnostics";

const escapeHtml = (value: string): string =>
  value.replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        character
      ] ?? character,
  );

const value = (form: HTMLFormElement, name: string): string =>
  String(new FormData(form).get(name) ?? "").trim();
const checked = (form: HTMLFormElement, name: string): boolean =>
  (form.elements.namedItem(name) as HTMLInputElement | null)?.checked === true;
const numberValue = (form: HTMLFormElement, name: string): number =>
  Number(value(form, name));

export const renderShell = (): string => `
  <a class="skip-link" href="#main">Skip to main content</a>
  <header class="app-header">
    <div><strong>Power Monitor</strong><span>Local sensor agent</span></div>
    <span id="header-state" class="state muted">Connecting</span>
  </header>
  <nav aria-label="Primary sensor views">
    <button type="button" data-view="status" aria-current="page">Status</button>
    <button type="button" data-view="setup">Setup</button>
    <button type="button" data-view="diagnostics">Diagnostics</button>
  </nav>
  <div id="notification-region" aria-live="polite"></div>
  <main id="main" tabindex="-1"></main>`;

export const renderStatus = (): string => `
  <section class="page-heading"><div><p class="eyebrow">Sensor status</p>
    <h1 id="sensor-name">Power Monitor</h1><p>Live measurements and essential health only.</p></div>
    <button type="button" id="refresh-status">Refresh status</button>
  </section>
  <section class="power-panel" aria-labelledby="power-title">
    <div><p class="eyebrow">Current power</p><h2 id="power-title"><span id="power">—</span> <small>W</small></h2>
      <p id="measured-at" class="muted">Waiting for the first reading</p></div>
    <dl class="measurement-grid">
      <div><dt>Voltage</dt><dd id="voltage">—</dd></div>
      <div><dt>Current</dt><dd id="current">—</dd></div>
      <div><dt>Frequency</dt><dd id="frequency">—</dd></div>
      <div><dt>Power factor</dt><dd id="power-factor">—</dd></div>
    </dl>
  </section>
  <section class="panel" aria-labelledby="health-title"><h2 id="health-title">Health</h2>
    <dl class="status-rows">
      <div><dt>Wi-Fi</dt><dd id="wifi-state">—</dd></div>
      <div><dt>IP address</dt><dd id="ip-address">—</dd></div>
      <div><dt>Signal strength</dt><dd id="signal">—</dd></div>
      <div><dt>Server</dt><dd id="server-state">—</dd></div>
      <div><dt>Last successful heartbeat</dt><dd id="heartbeat-at">—</dd></div>
      <div id="server-reason-row" hidden><dt>Reason</dt><dd id="server-reason">—</dd></div>
      <div><dt>microSD</dt><dd id="storage-state">—</dd></div>
      <div><dt>PZEM meter</dt><dd id="meter-state">—</dd></div>
      <div><dt>Memory</dt><dd id="memory-state">—</dd></div>
      <div><dt>TLS readiness</dt><dd id="tls-ready">—</dd></div>
      <div><dt>Durable backlog</dt><dd id="backlog">—</dd></div>
      <div><dt>OTA</dt><dd id="ota-status">—</dd></div>
      <div><dt>Firmware</dt><dd id="firmware">—</dd></div>
      <div><dt>Uptime</dt><dd id="uptime">—</dd></div>
    </dl>
  </section>`;

const setText = (root: ParentNode, selector: string, text: string): void => {
  const target = root.querySelector<HTMLElement>(selector);
  if (target && target.textContent !== text) target.textContent = text;
};

const finite = (input: number | null, digits: number): string =>
  input !== null && Number.isFinite(input)
    ? input.toFixed(digits).replace(/\.0+$/, "")
    : "—";

const time = (utcMs: number | null): string =>
  utcMs === null || !Number.isFinite(utcMs)
    ? "—"
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "medium",
      }).format(new Date(utcMs));

const duration = (seconds: number): string => {
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  return `${days ? `${days}d ` : ""}${hours ? `${hours}h ` : ""}${minutes}m`;
};

const safeSeconds = (value: number | null | undefined): number | null =>
  typeof value === "number" && Number.isFinite(value)
    ? Math.max(0, Math.floor(value))
    : null;

const statusAgeSeconds = (status: UiStatus): number | null => {
  const suppliedAge = safeSeconds(status.server?.age_seconds);
  if (suppliedAge !== null) return suppliedAge;

  const lastSuccess =
    status.server?.last_success_utc_ms ?? status.sync.last_success_utc_ms;
  if (lastSuccess === null || !Number.isFinite(lastSuccess)) return null;
  const serverNow = Date.parse(status.server_now);
  return Number.isFinite(serverNow)
    ? Math.max(0, Math.floor((serverNow - lastSuccess) / 1_000))
    : null;
};

export interface ServerFreshnessPresentation {
  state: ServerFreshnessState;
  ageSeconds: number | null;
  serverLabel: string;
  heartbeatLabel: string;
  reason: string;
  headerLabel: string;
}

export const memoryStateLabel = (state: MemoryState): string =>
  ({
    normal: "Memory normal",
    pressure_warning: "Reduced memory headroom",
    fragmented: "Memory fragmented · TLS waiting for a contiguous block",
    low_total_memory: "Low memory",
    recovering: "Memory recovering",
  })[state];

export const otaStatusLabel = (ota: UiStatus["ota"]): string => {
  if (!ota) return "Not reported";
  if (
    ota.rollback_detected ||
    ota.state === "rollback_detected" ||
    ota.state === "rolled_back"
  ) {
    return "Automatic rollback confirmed";
  }
  if (ota.in_progress) {
    const target = ota.target_version ? ` to ${ota.target_version}` : "";
    return `Installing${target} · ${ota.progress_percent}%`;
  }
  if (ota.pending_reboot || ota.state === "reboot_pending") {
    return "Firmware verified · reboot pending";
  }
  if (ota.state === "completed" || ota.state === "validated") {
    return "Installed and verified";
  }
  if (ota.state === "failed" || ota.last_result === "failed") {
    return "Update failed";
  }
  return ota.protocol_version >= 2 ? "Ready for server OTA" : "Legacy OTA only";
};

const ageLabel = (seconds: number | null): string => {
  if (seconds === null) return "Never";
  if (seconds === 0) return "Just now";
  if (seconds < 60) return `${seconds} second${seconds === 1 ? "" : "s"} ago`;
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  const minuteLabel = `${minutes} minute${minutes === 1 ? "" : "s"}`;
  return remainder
    ? `${minuteLabel} ${remainder} second${remainder === 1 ? "" : "s"} ago`
    : `${minuteLabel} ago`;
};

export function resolveServerFreshness(
  status: UiStatus,
  elapsedSeconds = 0,
): ServerFreshnessPresentation {
  const baseAge = statusAgeSeconds(status);
  const ageSeconds =
    baseAge === null
      ? null
      : Math.max(0, baseAge + Math.floor(Math.max(0, elapsedSeconds)));
  const expectedSeconds = Math.max(
    1,
    status.server?.expected_heartbeat_seconds ?? 15,
  );
  const staleAfterSeconds = Math.max(
    expectedSeconds + 1,
    status.server?.stale_after_seconds ?? 30,
  );
  const offlineAfterSeconds = Math.max(
    staleAfterSeconds,
    status.server?.offline_after_seconds ?? staleAfterSeconds,
  );

  let state: ServerFreshnessState;
  if (
    status.server?.state === "unauthenticated" ||
    status.health.server === "unauthenticated"
  ) {
    state = "unauthenticated";
  } else if (
    status.server?.state === "offline" ||
    status.health.wifi === "offline"
  ) {
    state = "offline";
  } else if (ageSeconds === null) {
    state = "never_connected";
  } else if (ageSeconds <= expectedSeconds) {
    state = "live";
  } else if (ageSeconds < staleAfterSeconds) {
    state = "delayed";
  } else if (
    offlineAfterSeconds > staleAfterSeconds &&
    ageSeconds >= offlineAfterSeconds
  ) {
    state = "offline";
  } else {
    // A connected sensor with an old heartbeat is stale. Never promote the
    // previous sticky `health.server` Boolean to a false Connected label.
    state = "stale";
  }

  const labels: Record<ServerFreshnessState, string> = {
    never_connected: "Never connected",
    live: "Connected",
    delayed: "Heartbeat delayed",
    stale: "Connection stale",
    offline: "Offline",
    unauthenticated: "Reachable · authentication required",
  };
  const headerLabels: Record<ServerFreshnessState, string> = {
    never_connected: "Waiting for server",
    live: "Server connected",
    delayed: "Heartbeat delayed",
    stale: "Connection stale",
    offline: "Server offline",
    unauthenticated: "Authentication required",
  };
  const localDeferral =
    status.server?.last_attempt_result === "local_resource_deferred" ||
    /internal_heap_(?:fragmented|reserve_low)/.test(
      status.server?.last_safe_error ?? status.sync.last_safe_error,
    );
  const reason =
    state === "stale" && localDeferral
      ? "Synchronization is waiting for a contiguous TLS memory block."
      : state === "stale"
        ? "No heartbeat has reached the server within the freshness window."
        : "";

  return {
    state,
    ageSeconds,
    serverLabel: labels[state],
    heartbeatLabel: ageLabel(ageSeconds),
    reason,
    headerLabel: headerLabels[state],
  };
}

export function updateStatusFreshness(
  root: ParentNode,
  status: UiStatus,
  elapsedSeconds = 0,
): ServerFreshnessPresentation {
  const freshness = resolveServerFreshness(status, elapsedSeconds);
  setText(root, "#server-state", freshness.serverLabel);
  setText(root, "#heartbeat-at", freshness.heartbeatLabel);
  setText(root, "#header-state", freshness.headerLabel);
  const reasonRow = root.querySelector<HTMLElement>("#server-reason-row");
  if (reasonRow) reasonRow.hidden = !freshness.reason;
  setText(root, "#server-reason", freshness.reason || "—");
  return freshness;
}

export function updateStatus(root: ParentNode, status: UiStatus): void {
  setText(root, "#sensor-name", status.device.friendly_name || "Power Monitor");
  setText(root, "#power", finite(status.reading.power_w, 1));
  setText(
    root,
    "#voltage",
    `${finite(status.reading.voltage_v, 1)}${status.reading.voltage_v === null ? "" : " V"}`,
  );
  setText(
    root,
    "#current",
    `${finite(status.reading.current_a, 2)}${status.reading.current_a === null ? "" : " A"}`,
  );
  setText(
    root,
    "#frequency",
    `${finite(status.reading.frequency_hz, 1)}${status.reading.frequency_hz === null ? "" : " Hz"}`,
  );
  setText(root, "#power-factor", finite(status.reading.power_factor, 2));
  setText(
    root,
    "#measured-at",
    status.reading.measured_at_utc_ms === null
      ? "Waiting for the first reading"
      : `Last data ${time(status.reading.measured_at_utc_ms)}`,
  );
  setText(
    root,
    "#wifi-state",
    status.health.wifi === "connected" ? "Connected" : "Offline",
  );
  setText(
    root,
    "#signal",
    status.health.wifi === "connected" ? `${status.health.rssi_dbm} dBm` : "—",
  );
  setText(root, "#ip-address", status.health.ip_address || "—");
  updateStatusFreshness(root, status);
  setText(
    root,
    "#storage-state",
    status.health.storage === "writable" ? "Writable" : "Degraded",
  );
  setText(
    root,
    "#meter-state",
    status.health.meter === "healthy" ? "Healthy" : "Degraded",
  );
  const memoryState =
    status.health.memory_state ??
    (status.health.low_memory ? "low_total_memory" : "normal");
  setText(root, "#memory-state", memoryStateLabel(memoryState));
  setText(
    root,
    "#tls-ready",
    status.health.tls_ready === false ? "Waiting" : "Ready",
  );
  setText(
    root,
    "#backlog",
    `${status.sync.backlog} reading${status.sync.backlog === 1 ? "" : "s"}`,
  );
  setText(root, "#ota-status", otaStatusLabel(status.ota));
  setText(root, "#firmware", status.device.firmware);
  setText(root, "#uptime", duration(status.device.uptime_seconds));
}

export function renderSetup(config: EffectiveConfig, firstRun = false): string {
  const caLabel =
    firstRun || !config.server_ca_configured
      ? "Public CA PEM"
      : "Replacement public CA PEM (leave blank to keep current)";
  return `<section class="page-heading"><p class="eyebrow">Configuration</p><h1>Setup</h1>
    <p>Secrets are write-only and cleared after submission.</p></section>
  <form id="setup-form" class="panel form-grid" data-first-run="${firstRun}">
    <label>Friendly name<input name="friendly_name" required maxlength="64" value="${escapeHtml(config.friendly_name)}"></label>
    <label>Installed CT rating (A)<input name="ct_rating_a" type="number" min="1" max="1000" step="0.1" required value="${config.ct_rating_a}"></label>
    <label>Wi-Fi SSID<input name="wifi_ssid" required maxlength="32" autocomplete="off" value="${escapeHtml(config.wifi_ssid)}"></label>
    <label>Wi-Fi password<input name="wifi_password" type="password" maxlength="64" autocomplete="new-password" ${firstRun ? "required" : ""}></label>
    <label class="wide">Server URL<input name="server_url" type="url" required value="${escapeHtml(config.server_url)}" placeholder="https://power-monitor.home.arpa:8443"></label>
    <label class="wide">${caLabel}<textarea name="server_ca_pem" rows="5" ${firstRun || !config.server_ca_configured ? "required" : ""} autocomplete="off"></textarea></label>
    ${
      firstRun
        ? `<label class="wide">One-time enrollment token<input name="enrollment_token" type="password" minlength="32" maxlength="256" required autocomplete="off"></label>
      <label>Local administrator password<input name="admin_password" type="password" minlength="12" maxlength="128" required autocomplete="new-password"></label>`
        : ""
    }
    <details class="wide"><summary>Advanced settings</summary><div class="form-grid advanced">
      <label class="checkbox"><input name="static_network_enabled" type="checkbox" ${config.static_network_enabled ? "checked" : ""}> Use static IPv4</label>
      <label>Static IP<input name="static_ip" inputmode="decimal" value="${escapeHtml(config.static_ip)}"></label>
      <label>Gateway<input name="static_gateway" inputmode="decimal" value="${escapeHtml(config.static_gateway)}"></label>
      <label>Subnet<input name="static_subnet" inputmode="decimal" value="${escapeHtml(config.static_subnet)}"></label>
      <label>Custom DNS<input name="static_dns" inputmode="decimal" value="${escapeHtml(config.static_dns)}"></label>
      <label>Sample interval (s)<input name="sample_interval_seconds" type="number" min="1" max="60" value="${config.sample_interval_seconds}"></label>
      <label>Durable log interval (s)<input name="durable_log_interval_seconds" type="number" min="10" max="3600" value="${config.durable_log_interval_seconds}"></label>
      <label>Heartbeat interval (s)<input name="heartbeat_interval_seconds" type="number" min="5" max="3600" value="${config.heartbeat_interval_seconds}"></label>
    </div></details>
    <p id="setup-result" class="wide" role="status"></p>
    <button class="primary wide" type="submit">Save and verify setup</button>
  </form>`;
}

export function readSetupForm(form: HTMLFormElement): SetupPayload {
  return {
    friendly_name: value(form, "friendly_name"),
    wifi_ssid: value(form, "wifi_ssid"),
    wifi_password: value(form, "wifi_password"),
    static_network_enabled: checked(form, "static_network_enabled"),
    static_ip: value(form, "static_ip"),
    static_gateway: value(form, "static_gateway"),
    static_subnet: value(form, "static_subnet"),
    static_dns: value(form, "static_dns"),
    server_url: value(form, "server_url"),
    server_ca_pem: value(form, "server_ca_pem"),
    server_fingerprint: "",
    enrollment_token: value(form, "enrollment_token"),
    admin_password: value(form, "admin_password"),
    connection_mode: "push",
    ct_rating_a: numberValue(form, "ct_rating_a"),
  };
}

export function readConfiguredSetupForm(
  form: HTMLFormElement,
  current: EffectiveConfig,
): { config: EffectiveConfig; network: NetworkSettingsPayload } {
  const ca = value(form, "server_ca_pem");
  return {
    config: {
      ...current,
      friendly_name: value(form, "friendly_name"),
      connection_mode: "push",
      ct_rating_a: numberValue(form, "ct_rating_a"),
      sample_interval_seconds: numberValue(form, "sample_interval_seconds"),
      durable_log_interval_seconds: numberValue(
        form,
        "durable_log_interval_seconds",
      ),
      heartbeat_interval_seconds: numberValue(
        form,
        "heartbeat_interval_seconds",
      ),
    },
    network: {
      wifi_ssid: value(form, "wifi_ssid"),
      wifi_password: value(form, "wifi_password") || undefined,
      static_network_enabled: checked(form, "static_network_enabled"),
      static_ip: value(form, "static_ip"),
      static_gateway: value(form, "static_gateway"),
      static_subnet: value(form, "static_subnet"),
      static_dns: value(form, "static_dns"),
      server_url: value(form, "server_url"),
      tls_trust_action: ca ? "replace_ca" : "keep",
      server_ca_pem: ca || undefined,
      ota_trust_action: "keep",
      connection_mode: "push",
    },
  };
}

export const clearSecrets = (form: HTMLFormElement): void => {
  for (const name of [
    "wifi_password",
    "server_ca_pem",
    "enrollment_token",
    "admin_password",
  ]) {
    const field = form.elements.namedItem(name) as
      | HTMLInputElement
      | HTMLTextAreaElement
      | null;
    if (field) field.value = "";
  }
};

export const renderDiagnostics =
  (): string => `<section class="page-heading"><p class="eyebrow">On-demand</p><h1>Diagnostics</h1>
  <p>Nothing on this page refreshes until you request it.</p></section>
  <section class="panel"><div class="panel-heading"><h2>Resource and sync window</h2><button type="button" id="refresh-diagnostics">Refresh diagnostics</button></div>
    <dl id="diagnostic-values" class="status-rows"><div><dt>Status</dt><dd>Not loaded</dd></div></dl>
  </section>
  <section class="panel"><h2>Tests and support</h2><div class="actions">
    <button type="button" data-action="test-dns">Test DNS</button><button type="button" data-action="test-ntp">Test NTP</button>
    <button type="button" data-action="test-server-tls">Test server TLS</button><button type="button" data-action="test-heartbeat">Test heartbeat</button>
    <button type="button" data-action="test-pzem">Test PZEM</button><button type="button" data-action="test-sd">Test microSD</button>
    <button type="button" data-action="prepare-card-removal" data-confirm-message="Stop microSD writes and safely unmount the card? Wait for storage to leave the Writable state, then power off the sensor before physically removing the card.">Prepare card for removal</button>
    <a class="button" href="/api/v1/diagnostics/bundle" download>Download redacted bundle</a><a class="button" href="/api/v1/diagnostics/disconnect-flight-recorder" download>Download disconnect record</a><button type="button" data-action="reboot" data-confirm="REBOOT">Reboot</button>
  </div><p class="muted">Preparing the card stops durable writes and unmounts it safely. Power off the sensor before physically removing the card.</p><p id="action-result" role="status"></p>
  <details class="recovery"><summary>Owner-only recovery</summary><p>These actions preserve typed confirmation and administrator elevation.</p>
    <div class="actions"><button type="button" data-action="network-reset" data-confirm="RESET NETWORK">Network reset</button>
    <button type="button" class="danger" data-action="factory-reset" data-confirm="FACTORY RESET">Factory reset</button></div>
    <form id="reenroll-form"><label>New one-time enrollment token<input name="enrollment_token" type="password" minlength="32" maxlength="256" autocomplete="off" required></label><button type="submit">Re-enroll</button></form>
  </details></section>`;

const row = (label: string, content: string): string =>
  `<div><dt>${label}</dt><dd>${content}</dd></div>`;
export function updateDiagnostics(root: ParentNode, data: UiDiagnostics): void {
  const list = root.querySelector<HTMLElement>("#diagnostic-values");
  if (!list) return;
  list.innerHTML = [
    row("Memory state", memoryStateLabel(data.memory.memory_state)),
    row("Memory severity", data.memory.severity),
    row("TLS readiness", data.memory.tls_ready ? "Ready" : "Waiting"),
    row("High-memory owner", data.memory.high_memory_owner),
    row(
      "TLS transient minimum",
      `${data.memory.tls_transient_minimum_free_internal_bytes.toLocaleString()} B`,
    ),
    row(
      "OTA transient minimum",
      `${data.memory.ota_transient_minimum_free_internal_bytes.toLocaleString()} B`,
    ),
    row("Fragmentation entries", String(data.memory.fragmentation_entries)),
    row("Low-total entries", String(data.memory.low_total_entries)),
    row("Recoveries", String(data.memory.recoveries)),
    row(
      "Free internal heap",
      `${data.memory.free_internal_heap_bytes.toLocaleString()} B`,
    ),
    row(
      "Largest internal block",
      `${data.memory.largest_internal_block_bytes.toLocaleString()} B`,
    ),
    row(
      "Minimum heap",
      `${data.memory.minimum_free_heap_bytes.toLocaleString()} B`,
    ),
    row("Free PSRAM", `${data.memory.free_psram_bytes.toLocaleString()} B`),
    row("Heap integrity", data.memory.heap_integrity_ok ? "Healthy" : "Failed"),
    row("ServerSyncTask margin", `${data.tasks.server_sync_margin_percent}%`),
    row(
      "NetworkTask margin",
      data.tasks.network_margin_percent === null
        ? "Collecting"
        : `${data.tasks.network_margin_percent}%`,
    ),
    row(
      "Heartbeats",
      `${data.sync.heartbeat_successes} succeeded · ${data.sync.heartbeat_failures} failed`,
    ),
    row(
      "Reading batches",
      `${data.sync.batch_successes} succeeded · ${data.sync.batch_failures} failed`,
    ),
    row("Server acknowledgement", String(data.sync.acknowledged_sequence)),
    row("Newest stored sequence", String(data.sync.newest_sequence)),
    row("Durable backlog", String(data.sync.backlog)),
    row("Local resource deferrals", String(data.sync.local_resource_deferrals)),
    row(
      "Local browser sessions",
      `${data.local_sessions.active} of ${data.local_sessions.capacity} active`,
    ),
    row(
      "Browser auth rejections",
      String(data.local_http.browser_session_rejections),
    ),
    row(
      "Server HMAC rate limits",
      String(data.local_http.server_hmac_rate_limited),
    ),
    row("Wi-Fi disconnects", String(data.wifi_disconnects.total)),
    row(
      "Last Wi-Fi disconnect",
      escapeHtml(
        data.wifi_disconnects.events.at(-1)?.reason ?? "None recorded",
      ),
    ),
    row("Last safe error", escapeHtml(data.sync.last_safe_error || "None")),
  ].join("");
}

export const destructiveConfirmation = (action: string): string | undefined =>
  ({
    reboot: "REBOOT",
    "network-reset": "RESET NETWORK",
    "factory-reset": "FACTORY RESET",
  })[action];
