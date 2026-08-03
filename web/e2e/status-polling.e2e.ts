import { expect, test, type Page, type Route } from "@playwright/test";

interface BrowserNetworkStats {
  paths: Record<string, number>;
  statusActive: number;
  statusMaximumActive: number;
  statusStartedAtMs: number[];
}

interface MockApiOptions {
  sessionExpiresInSeconds?: number;
  holdStatusRequest?: number;
}

interface MockApiControl {
  counts: Record<string, number>;
  releaseHeldStatus(): void;
}

const statusResponse = {
  schema_version: 1,
  server_now: "2026-08-01T22:52:13Z",
  server: {
    state: "stale",
    last_success_utc_ms: Date.parse("2026-08-01T22:46:17Z"),
    age_seconds: 356,
    expected_heartbeat_seconds: 15,
    stale_after_seconds: 30,
    offline_after_seconds: 30,
    last_attempt_result: "local_resource_deferred",
    last_safe_error: "internal_heap_fragmented",
  },
  device: {
    friendly_name: "Outdoor-AC",
    firmware: "1.0.9",
    git_commit: "0123456789abcdef",
    build_timestamp: "2026-08-01T22:00:00Z",
    platformio_environment: "esp32-s3-release",
    web_assets: {
      index_html_sha256: "a".repeat(64),
      app_js_sha256: "b".repeat(64),
      style_css_sha256: "c".repeat(64),
    },
    uptime_seconds: 2_118,
  },
  reading: {
    measured_at_utc_ms: Date.parse("2026-08-01T22:52:12Z"),
    power_w: 12.8,
    voltage_v: 245.6,
    current_a: 0.659,
    frequency_hz: 60,
    power_factor: 0.08,
  },
  health: {
    wifi: "connected",
    rssi_dbm: -54,
    ip_address: "192.168.0.202",
    server: "connected",
    storage: "writable",
    meter: "healthy",
    low_memory: false,
    memory_state: "fragmented",
    memory_severity: "warning",
    tls_ready: false,
    operation_context: "idle",
  },
  sync: {
    last_success_utc_ms: Date.parse("2026-08-01T22:46:17Z"),
    newest_sequence: 2_369,
    acknowledged_sequence: 2_364,
    backlog: 5,
    last_safe_error: "internal_heap_fragmented",
  },
  ota: {
    protocol_version: 2,
    authentication_mode: "existing_device_hmac",
    state: "idle",
    deployment_id: "",
    target_version: "",
    target_sha256: "",
    bytes_received: 0,
    image_size: 0,
    progress_percent: 0,
    running_partition: "ota_0",
    target_partition: "ota_1",
    in_progress: false,
    pending_reboot: false,
    rollback_supported: true,
    last_result: "never",
    rollback_detected: false,
  },
};

const diagnosticsResponse = {
  schema_version: 1,
  memory: {
    free_heap_bytes: 72_280,
    minimum_free_heap_bytes: 15_520,
    free_internal_heap_bytes: 72_280,
    minimum_free_internal_heap_bytes: 15_520,
    largest_internal_block_bytes: 24_564,
    free_psram_bytes: 8_000_000,
    largest_psram_block_bytes: 7_000_000,
    heap_integrity_ok: true,
    memory_state: "fragmented",
    severity: "warning",
    tls_ready: false,
    operation_context: "diagnostics_active",
    high_memory_owner: "diagnostics_active",
    tls_transient_minimum_free_internal_bytes: 35_840,
    ota_transient_minimum_free_internal_bytes: 0,
    fragmentation_entries: 1,
    low_total_entries: 0,
    recoveries: 0,
  },
  tasks: {
    server_sync_stack_bytes: 24_576,
    server_sync_high_water_bytes: 13_500,
    server_sync_margin_percent: 45,
    network_margin_percent: 59,
    table: [],
  },
  sync: {
    heartbeat_successes: 109,
    heartbeat_failures: 0,
    batch_successes: 28,
    batch_failures: 0,
    local_resource_deferrals: 117,
    tls_requests_admitted: 155,
    tls_requests_rejected_heap: 117,
    tls_requests_rejected_stack: 0,
    acknowledged_sequence: 2_364,
    newest_sequence: 2_369,
    backlog: 5,
    last_safe_error: "internal_heap_fragmented",
  },
  local_http: {
    ui_status_requests: 341,
    ui_setup_requests: 0,
    ui_diagnostics_requests: 1,
    ui_heavy_requests_deferred: 0,
    peak_requests: 1,
    browser_session_rejections: 0,
    malformed_auth_header_rejections: 0,
    browser_rate_limited: 0,
    server_hmac_rate_limited: 0,
    browser_requests_accepted: 344,
    browser_requests_session_expired: 0,
    browser_requests_session_invalid: 0,
    browser_requests_csrf_rejected: 0,
    server_hmac_requests_accepted: 0,
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
    reused: 341,
    refreshed: 1,
    expired: 0,
    invalid: 0,
    revoked: 0,
    capacity_rejections: 0,
  },
  wifi_disconnects: { total: 0, events: [] },
};

async function installBrowserInstrumentation(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const stats: BrowserNetworkStats = {
      paths: {},
      statusActive: 0,
      statusMaximumActive: 0,
      statusStartedAtMs: [],
    };
    const instrumentedWindow = window as typeof window & {
      __pmNetworkStats: BrowserNetworkStats;
      __setPmHidden(hidden: boolean): void;
    };
    instrumentedWindow.__pmNetworkStats = stats;

    let hidden = false;
    Object.defineProperty(document, "hidden", {
      configurable: true,
      get: () => hidden,
    });
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => (hidden ? "hidden" : "visible"),
    });
    instrumentedWindow.__setPmHidden = (nextHidden: boolean): void => {
      hidden = nextHidden;
      document.dispatchEvent(new Event("visibilitychange"));
    };

    const originalFetch = window.fetch.bind(window);
    window.fetch = async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      const rawUrl =
        typeof input === "string"
          ? input
          : input instanceof Request
            ? input.url
            : input.toString();
      const path = new URL(rawUrl, window.location.href).pathname;
      stats.paths[path] = (stats.paths[path] ?? 0) + 1;
      const isStatus = path === "/api/v1/ui/status";
      if (isStatus) {
        stats.statusActive += 1;
        stats.statusMaximumActive = Math.max(
          stats.statusMaximumActive,
          stats.statusActive,
        );
        stats.statusStartedAtMs.push(performance.now());
      }
      try {
        return await originalFetch(input, init);
      } finally {
        if (isStatus) stats.statusActive -= 1;
      }
    };
  });
}

const json = (route: Route, body: unknown, status = 200): Promise<void> =>
  route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });

async function mockSensorApi(
  page: Page,
  options: MockApiOptions = {},
): Promise<MockApiControl> {
  const counts: Record<string, number> = {};
  let releaseHeldStatus: (() => void) | undefined;
  const heldStatus = new Promise<void>((resolve) => {
    releaseHeldStatus = resolve;
  });

  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    counts[path] = (counts[path] ?? 0) + 1;
    if (path === "/api/v1/auth/session") {
      await json(route, {
        csrf: "browser-test-csrf",
        expires_in_seconds: options.sessionExpiresInSeconds ?? 3_600,
        setup_required: false,
        elevated: false,
      });
      return;
    }
    if (path === "/api/v1/ui/status") {
      if (counts[path] === options.holdStatusRequest) await heldStatus;
      await json(route, statusResponse);
      return;
    }
    if (path === "/api/v1/ui/diagnostics") {
      await json(route, diagnosticsResponse);
      return;
    }
    await json(
      route,
      { code: "unexpected_browser_request", detail: `Unexpected ${path}` },
      404,
    );
  });

  return {
    counts,
    releaseHeldStatus: () => releaseHeldStatus?.(),
  };
}

const readNetworkStats = (page: Page): Promise<BrowserNetworkStats> =>
  page.evaluate(
    () =>
      (window as typeof window & { __pmNetworkStats: BrowserNetworkStats })
        .__pmNetworkStats,
  );

const setHidden = (page: Page, hidden: boolean): Promise<void> =>
  page.evaluate(
    (nextHidden) =>
      (
        window as typeof window & {
          __setPmHidden(value: boolean): void;
        }
      ).__setPmHidden(nextHidden),
    hidden,
  );

const captureErrors = (page: Page): string[] => {
  const errors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  page.on("pageerror", (error) => errors.push(error.message));
  return errors;
};

test.beforeEach(async ({ page }) => {
  await page.clock.install({ time: new Date("2026-08-01T22:52:13Z") });
  await installBrowserInstrumentation(page);
});

test("polls once per 10 seconds for ten virtual minutes without fan-out", async ({
  page,
}) => {
  const errors = captureErrors(page);
  const api = await mockSensorApi(page);
  await page.goto("/");
  await expect(page.locator("#refresh-status")).toBeEnabled();

  for (let interval = 1; interval <= 60; interval += 1) {
    await page.clock.fastForward(10_000);
    await expect
      .poll(
        async () => (await readNetworkStats(page)).paths["/api/v1/ui/status"],
      )
      .toBe(interval + 1);
    // WebKit exposes the request one event-loop turn before fetch completes.
    // Settle the response before advancing the next exact interval.
    await expect(page.locator("#refresh-status")).toBeEnabled();
  }

  const stats = await readNetworkStats(page);
  expect(stats.paths["/api/v1/ui/status"]).toBe(61);
  expect(stats.statusMaximumActive).toBe(1);
  expect(api.counts["/api/v1/auth/session"]).toBe(1);
  expect(api.counts["/api/v1/config"] ?? 0).toBe(0);
  expect(api.counts["/api/v1/ui/diagnostics"] ?? 0).toBe(0);
  expect(api.counts["/api/v1/events"] ?? 0).toBe(0);
  expect(errors).toEqual([]);
});

test("bounds two visible clients while a second tab is hidden", async ({
  browser,
}) => {
  const desktopContext = await browser.newContext({
    viewport: { width: 1440, height: 900 },
  });
  const phoneContext = await browser.newContext({
    viewport: { width: 390, height: 844 },
  });
  const desktop = await desktopContext.newPage();
  const hiddenTab = await desktopContext.newPage();
  const phone = await phoneContext.newPage();
  const clients = [desktop, hiddenTab, phone];
  const clientErrors: string[][] = [];
  const controls: MockApiControl[] = [];

  try {
    for (const client of clients) {
      await client.clock.install({ time: new Date("2026-08-01T22:52:13Z") });
      await installBrowserInstrumentation(client);
      clientErrors.push(captureErrors(client));
      controls.push(await mockSensorApi(client));
      await client.goto("/");
      await expect(client.locator("#refresh-status")).toBeEnabled();
    }

    await setHidden(hiddenTab, true);
    for (let interval = 1; interval <= 60; interval += 1) {
      await Promise.all(
        clients.map((client) => client.clock.fastForward(10_000)),
      );
      await expect
        .poll(() => controls[0].counts["/api/v1/ui/status"])
        .toBe(interval + 1);
      await expect
        .poll(() => controls[2].counts["/api/v1/ui/status"])
        .toBe(interval + 1);
      await expect(desktop.locator("#refresh-status")).toBeEnabled();
      await expect(phone.locator("#refresh-status")).toBeEnabled();
    }

    expect(controls[0].counts["/api/v1/ui/status"]).toBe(61);
    expect(controls[1].counts["/api/v1/ui/status"]).toBe(1);
    expect(controls[2].counts["/api/v1/ui/status"]).toBe(61);
    for (const client of clients) {
      expect((await readNetworkStats(client)).statusMaximumActive).toBe(1);
    }
    expect(clientErrors.flat()).toEqual([]);
  } finally {
    await phoneContext.close();
    await desktopContext.close();
  }
});

test("hidden pages pause and manual refresh cannot overlap a held request", async ({
  page,
}) => {
  const errors = captureErrors(page);
  const api = await mockSensorApi(page, { holdStatusRequest: 3 });
  await page.goto("/");
  await expect(page.locator("#refresh-status")).toBeEnabled();
  expect(api.counts["/api/v1/ui/status"]).toBe(1);

  await setHidden(page, true);
  await page.clock.fastForward(60_000);
  expect(api.counts["/api/v1/ui/status"]).toBe(1);

  await setHidden(page, false);
  await expect.poll(() => api.counts["/api/v1/ui/status"]).toBe(2);
  await expect(page.locator("#refresh-status")).toBeEnabled();

  await page.locator("#refresh-status").click();
  await expect.poll(() => api.counts["/api/v1/ui/status"]).toBe(3);
  await page.evaluate(() => {
    document
      .querySelector<HTMLButtonElement>("#refresh-status")
      ?.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  });
  await page.clock.fastForward(60_000);
  expect(api.counts["/api/v1/ui/status"]).toBe(3);
  expect((await readNetworkStats(page)).statusMaximumActive).toBe(1);

  api.releaseHeldStatus();
  await expect(page.locator("#refresh-status")).toBeEnabled();
  await page.getByRole("button", { name: "Diagnostics" }).click();
  await page.clock.fastForward(60_000);
  expect(api.counts["/api/v1/ui/diagnostics"] ?? 0).toBe(0);
  await page.getByRole("button", { name: "Refresh diagnostics" }).click();
  await expect.poll(() => api.counts["/api/v1/ui/diagnostics"]).toBe(1);
  expect(api.counts["/api/v1/config"] ?? 0).toBe(0);
  expect(api.counts["/api/v1/events"] ?? 0).toBe(0);
  expect(errors).toEqual([]);
});

test("stale age advances locally and session renewal creates no burst", async ({
  page,
}) => {
  const errors = captureErrors(page);
  const api = await mockSensorApi(page, { sessionExpiresInSeconds: 1 });
  await page.goto("/");
  await expect(page.locator("#server-state")).toHaveText("Connection stale");
  await expect(page.locator("#heartbeat-at")).toHaveText(
    "5 minutes 56 seconds ago",
  );
  await expect(page.locator("#header-state")).not.toHaveText(
    "Server connected",
  );

  await page.clock.fastForward(4_000);
  await expect(page.locator("#heartbeat-at")).toHaveText("6 minutes ago");
  expect(api.counts["/api/v1/ui/status"]).toBe(1);

  for (const step of [6_000, 10_000, 10_000]) {
    await page.clock.fastForward(step);
    await page.waitForTimeout(0);
  }
  await expect.poll(() => api.counts["/api/v1/auth/session"]).toBe(2);
  if ((api.counts["/api/v1/ui/status"] ?? 0) < 4) {
    // WebKit can complete the single-flight renewal one event-loop turn after
    // the nominal poll boundary. Advance one bounded interval instead of
    // requiring a catch-up burst.
    await page.clock.fastForward(10_000);
    await page.waitForTimeout(0);
  }
  await expect
    .poll(() => (api.counts["/api/v1/ui/status"] ?? 0) >= 4)
    .toBe(true);
  expect(api.counts["/api/v1/ui/status"]).toBeLessThanOrEqual(5);
  const stats = await readNetworkStats(page);
  expect(stats.statusMaximumActive).toBe(1);
  expect(
    new Set(stats.statusStartedAtMs.map((value) => Math.round(value))).size,
  ).toBe(stats.statusStartedAtMs.length);
  expect(errors).toEqual([]);
});
