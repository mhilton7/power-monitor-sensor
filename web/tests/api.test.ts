import { describe, expect, it, vi } from "vitest";
import * as api from "../src/api";

const response = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });

describe("minimal local API client", () => {
  it("uses only the compact endpoint for Status and forwards cancellation", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        response({ schema_version: 1 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const controller = new AbortController();
    await api.getUiStatus(controller.signal);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0][0])).toBe("/api/v1/ui/status");
    expect((fetchMock.mock.calls[0][1] as RequestInit).signal).toBe(
      controller.signal,
    );
  });

  it("loads compact diagnostics from its on-demand endpoint", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        response({ schema_version: 1 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await api.getUiDiagnostics();
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(String(fetchMock.mock.calls[0][0])).toBe("/api/v1/ui/diagnostics");
  });

  it("polls a queued password job without resubmitting the mutation", async () => {
    vi.useFakeTimers();
    const replies = [
      response({ job_id: "a".repeat(32) }, 202),
      response({ status: "pending" }, 202),
      response({
        csrf: "csrf",
        expires_in_seconds: 900,
        setup_required: false,
        elevated: true,
      }),
    ];
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        replies.shift()!,
    );
    vi.stubGlobal("fetch", fetchMock);
    const login = api.login("correct horse battery staple");
    await vi.advanceTimersByTimeAsync(250);
    await expect(login).resolves.toMatchObject({ elevated: true });
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(String(fetchMock.mock.calls[0][0])).toBe("/api/v1/auth/login");
    expect(String(fetchMock.mock.calls[1][0])).toContain(
      "/api/v1/auth/password-jobs?job_id=",
    );
  });

  it("keeps CSRF and typed action confirmation on mutations", async () => {
    api.setCsrfForTest("csrf-value");
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        response({ queued: true }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await api.runAction("factory-reset", "FACTORY RESET");
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    const headers = new Headers(init.headers);
    expect(init.method).toBe("POST");
    expect(headers.get("X-PM-CSRF")).toBe("csrf-value");
    expect(headers.get("X-PM-Action-Token")).toBe("FACTORY RESET");
  });

  it("coalesces concurrent local-session renewal into one request", async () => {
    let release: ((value: Response) => void) | undefined;
    const pending = new Promise<Response>((resolve) => {
      release = resolve;
    });
    const fetchMock = vi.fn(async () => pending);
    vi.stubGlobal("fetch", fetchMock);
    const first = api.renewLocalSession();
    const second = api.renewLocalSession();
    expect(fetchMock).toHaveBeenCalledOnce();
    release?.(
      response({
        csrf: "renewed",
        expires_in_seconds: 900,
        setup_required: false,
        elevated: false,
      }),
    );
    await expect(Promise.all([first, second])).resolves.toHaveLength(2);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("renews and retries one safe GET after a local session expires", async () => {
    const replies = [
      response(
        {
          code: "local_session_expired",
          detail: "The local browser session expired.",
        },
        401,
      ),
      response({
        csrf: "renewed",
        expires_in_seconds: 900,
        setup_required: false,
        elevated: false,
      }),
      response({ schema_version: 1 }),
    ];
    const fetchMock = vi.fn(async () => replies.shift()!);
    vi.stubGlobal("fetch", fetchMock);
    await expect(api.getUiStatus()).resolves.toMatchObject({
      schema_version: 1,
    });
    expect(fetchMock).toHaveBeenCalledTimes(3);
    const calls = fetchMock.mock.calls as unknown as Array<[RequestInfo | URL]>;
    expect(String(calls[1][0])).toBe("/api/v1/auth/session");
    expect(String(calls[2][0])).toBe("/api/v1/ui/status");
  });

  it("does not retry a mutation after an authentication response", async () => {
    api.setCsrfForTest("csrf-value");
    const fetchMock = vi.fn(async () =>
      response(
        {
          code: "local_session_expired",
          detail: "The local browser session expired.",
        },
        401,
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    await expect(api.runAction("restart")).rejects.toMatchObject({
      code: "local_session_expired",
    });
    expect(fetchMock).toHaveBeenCalledOnce();
  });
});
