import { describe, expect, it, vi } from "vitest";
import * as api from "../src/api";
import type { NetworkSettingsPayload } from "../src/types";

const networkSettings: NetworkSettingsPayload = {
  wifi_ssid: "Test Network",
  static_network_enabled: false,
  static_ip: "",
  static_gateway: "",
  static_subnet: "",
  static_dns: "",
  server_url: "https://192.0.2.10:8443",
  tls_trust_action: "keep",
  ota_trust_action: "keep",
  connection_mode: "push",
};

describe("device API opt-in asynchronous jobs", () => {
  it("rejects short reenrollment tokens before making a request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(api.beginReenrollment("too-short")).rejects.toMatchObject({
      status: 422,
      code: "enrollment_token_invalid",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("uses PUT for network settings and polls the verified result", async () => {
    vi.useFakeTimers();
    const calls: Array<{ path: string; init?: RequestInit }> = [];
    const responses = [
      { status: 202, body: { status: "queued", job_id: "a".repeat(32) } },
      { status: 202, body: { status: "pending" } },
      {
        status: 200,
        body: {
          status: "network_settings_applied",
          saved: true,
          verified: true,
          network_apply_queued: true,
        },
      },
    ];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        calls.push({ path: String(input), init });
        const next = responses.shift()!;
        return new Response(JSON.stringify(next.body), {
          status: next.status,
          headers: { "Content-Type": "application/json" },
        });
      }),
    );

    const pending = api.updateNetworkSettings(networkSettings);
    for (let index = 0; index < 10; index += 1) await Promise.resolve();
    await vi.advanceTimersByTimeAsync(250);
    await expect(pending).resolves.toMatchObject({
      saved: true,
      verified: true,
    });

    expect(calls[0]).toMatchObject({
      path: "/api/v1/network-settings",
      init: { method: "PUT" },
    });
    expect(new Headers(calls[0]?.init?.headers).get("Prefer")).toBe(
      "respond-async",
    );
    expect(calls[1]?.path).toContain("/api/v1/auth/password-jobs?job_id=");
    expect(calls).toHaveLength(3);
  });

  it("accepts a direct final response without starting a result poll", async () => {
    const calls: Array<{ path: string; init?: RequestInit }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        calls.push({ path: String(input), init });
        return new Response(
          JSON.stringify({
            status: "network_settings_applied",
            saved: true,
            verified: true,
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        );
      }),
    );

    await expect(
      api.updateNetworkSettings(networkSettings),
    ).resolves.toMatchObject({
      saved: true,
      verified: true,
    });
    expect(calls).toHaveLength(1);
    expect(new Headers(calls[0]?.init?.headers).get("Prefer")).toBe(
      "respond-async",
    );
  });

  it("queues reenrollment with confirmation and polls verified revocation", async () => {
    vi.useFakeTimers();
    const calls: Array<{ path: string; init?: RequestInit }> = [];
    const responses = [
      { status: 202, body: { status: "queued", job_id: "d".repeat(32) } },
      { status: 202, body: { status: "pending" } },
      {
        status: 200,
        body: {
          status: "reenrollment_pending",
          saved: true,
          verified: true,
        },
      },
    ];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        calls.push({ path: String(input), init });
        const next = responses.shift()!;
        return new Response(JSON.stringify(next.body), {
          status: next.status,
          headers: { "Content-Type": "application/json" },
        });
      }),
    );

    const pending = api.beginReenrollment("t".repeat(32));
    for (let index = 0; index < 10; index += 1) await Promise.resolve();
    await vi.advanceTimersByTimeAsync(250);
    await expect(pending).resolves.toMatchObject({
      saved: true,
      verified: true,
    });

    const headers = new Headers(calls[0]?.init?.headers);
    expect(calls[0]).toMatchObject({
      path: "/api/v1/enrollment/reenroll",
      init: { method: "POST" },
    });
    expect(headers.get("X-PM-Action-Token")).toBe("REENROLL");
    expect(headers.get("Prefer")).toBe("respond-async");
    expect(calls[1]?.path).toContain("/api/v1/auth/password-jobs?job_id=");
    expect(calls).toHaveLength(3);
  });

  it("polls a queued event-history request without repeating the read", async () => {
    vi.useFakeTimers();
    const calls: Array<{ path: string; prefer: string | null }> = [];
    const responses = [
      { status: 202, body: { status: "queued", job_id: "b".repeat(16) } },
      { status: 202, body: { status: "pending" } },
      {
        status: 200,
        body: {
          schema_version: 1,
          records: [{ event_sequence: 7 }],
          has_more: false,
        },
      },
    ];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        calls.push({
          path: String(input),
          prefer: new Headers(init?.headers).get("Prefer"),
        });
        const next = responses.shift()!;
        return new Response(JSON.stringify(next.body), {
          status: next.status,
          headers: { "Content-Type": "application/json" },
        });
      }),
    );

    const pending = api.getEvents();
    for (let index = 0; index < 10; index += 1) await Promise.resolve();
    await vi.advanceTimersByTimeAsync(100);
    await expect(pending).resolves.toMatchObject({
      records: [{ event_sequence: 7 }],
    });

    expect(
      calls.filter(({ path }) => path.startsWith("/api/v1/events")),
    ).toEqual([
      {
        path: "/api/v1/events?limit=20",
        prefer: "respond-async",
      },
    ]);
    expect(
      calls.filter(({ path }) => path.startsWith("/api/v1/history-jobs")),
    ).toHaveLength(2);
  });

  it("keeps NDJSON content negotiation while polling an export", async () => {
    vi.useFakeTimers();
    const calls: Array<{
      path: string;
      accept: string | null;
      prefer: string | null;
    }> = [];
    const responses = [
      new Response(
        JSON.stringify({ status: "queued", job_id: "c".repeat(16) }),
        {
          status: 202,
          headers: { "Content-Type": "application/json" },
        },
      ),
      new Response(JSON.stringify({ status: "pending" }), {
        status: 202,
        headers: { "Content-Type": "application/json" },
      }),
      new Response('{"sequence":1}\n', {
        status: 200,
        headers: { "Content-Type": "application/x-ndjson" },
      }),
    ];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const headers = new Headers(init?.headers);
        calls.push({
          path: String(input),
          accept: headers.get("Accept"),
          prefer: headers.get("Prefer"),
        });
        return responses.shift()!;
      }),
    );

    const pending = api.exportHistory(0);
    for (let index = 0; index < 10; index += 1) await Promise.resolve();
    await vi.advanceTimersByTimeAsync(100);
    const blob = await pending;

    expect(await blob.text()).toBe('{"sequence":1}\n');
    expect(calls).toHaveLength(3);
    expect(calls.every(({ accept }) => accept === "application/x-ndjson")).toBe(
      true,
    );
    expect(calls[0]?.prefer).toBe("respond-async");
    expect(calls.slice(1).every(({ prefer }) => prefer === null)).toBe(true);
  });
});
