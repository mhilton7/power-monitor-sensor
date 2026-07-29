import type {
  EffectiveConfig,
  Health,
  LiveReading,
  NetworkSettingsPayload,
  SetupPayload,
} from "./types";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

let csrfToken = "";

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body) headers.set("Content-Type", "application/json");
  if (init.method && init.method !== "GET") headers.set("X-PM-CSRF", csrfToken);
  const response = await fetch(path, {
    ...init,
    headers,
    credentials: "same-origin",
    cache: "no-store",
  });
  if (!response.ok) {
    const problem = (await response.json().catch(() => ({}))) as {
      code?: string;
      detail?: string;
    };
    throw new ApiError(
      response.status,
      problem.code ?? "request_failed",
      problem.detail ?? "Request failed.",
    );
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export interface SessionResult {
  expiresInSeconds: number;
  setupRequired: boolean;
}

async function establishSession(
  path: string,
  body: string,
): Promise<SessionResult> {
  const queued = await request<{ job_id?: string }>(path, {
    method: "POST",
    body,
  });
  const result = queued.job_id
    ? await waitForPasswordJob<{
        csrf: string;
        expires_in_seconds: number;
        setup_required: boolean;
      }>(queued.job_id)
    : (queued as {
        csrf: string;
        expires_in_seconds: number;
        setup_required: boolean;
      });
  csrfToken = result.csrf;
  return {
    expiresInSeconds: result.expires_in_seconds,
    setupRequired: result.setup_required,
  };
}

async function waitForPasswordJob<T>(jobId: string): Promise<T> {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    const result = await request<T & { status?: string }>(
      `/api/v1/auth/password-jobs?job_id=${encodeURIComponent(jobId)}`,
    );
    if (result.status !== "pending") return result;
    await new Promise((resolve) => window.setTimeout(resolve, 250));
  }
  throw new ApiError(
    504,
    "password_job_timeout",
    "The device did not finish the password operation in time.",
  );
}

async function queuePasswordOperation<T>(
  path: string,
  body: string,
): Promise<T> {
  const queued = await request<{ job_id?: string }>(path, {
    method: "POST",
    body,
  });
  return queued.job_id ? waitForPasswordJob<T>(queued.job_id) : (queued as T);
}

export function openSession(): Promise<SessionResult> {
  return establishSession("/api/v1/auth/session", "{}");
}

export function login(password: string): Promise<SessionResult> {
  return establishSession("/api/v1/auth/login", JSON.stringify({ password }));
}

export async function logout(): Promise<void> {
  await request<void>("/api/v1/auth/logout", { method: "POST", body: "{}" });
  csrfToken = "";
}

export const getHealth = (): Promise<Health> => request("/api/v1/health");
export const getLive = (): Promise<LiveReading> => request("/api/v1/live");
export const getConfig = (): Promise<EffectiveConfig> =>
  request("/api/v1/config");
export const getStorage = (): Promise<Record<string, unknown>> =>
  request("/api/v1/storage");
export const getMetrics = (): Promise<Record<string, unknown>> =>
  request("/api/v1/metrics");
export const getOtaStatus = (): Promise<Record<string, unknown>> =>
  request("/api/v1/ota/status");
export const getEvents = (): Promise<Record<string, unknown>> =>
  request("/api/v1/events?limit=20");

export async function exportHistory(
  afterSequence: number,
  fromUtc?: string,
  toUtc?: string,
): Promise<Blob> {
  const parameters = new URLSearchParams({
    after_sequence: String(Math.max(0, Math.trunc(afterSequence))),
    limit: "500",
  });
  if (fromUtc) parameters.set("from_utc", fromUtc);
  if (toUtc) parameters.set("to_utc", toUtc);
  const response = await fetch(`/api/v1/readings?${parameters}`, {
    headers: { Accept: "application/x-ndjson" },
    credentials: "same-origin",
    cache: "no-store",
  });
  if (!response.ok) {
    const problem = (await response.json().catch(() => ({}))) as {
      code?: string;
      detail?: string;
    };
    throw new ApiError(
      response.status,
      problem.code ?? "export_failed",
      problem.detail ?? "History export failed.",
    );
  }
  return response.blob();
}

export function updateConfig(
  config: EffectiveConfig,
  ctAcknowledged: boolean,
): Promise<Record<string, unknown>> {
  return request("/api/v1/config", {
    method: "PUT",
    headers: {
      "X-PM-CT-Change-Acknowledged": ctAcknowledged ? "true" : "false",
    },
    body: JSON.stringify(config),
  });
}

export function applySetup(
  payload: SetupPayload,
): Promise<Record<string, unknown>> {
  return queuePasswordOperation("/api/v1/setup/apply", JSON.stringify(payload));
}

export function updateNetworkSettings(
  payload: NetworkSettingsPayload,
): Promise<Record<string, unknown>> {
  return request("/api/v1/network-settings", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function beginReenrollment(
  token: string,
): Promise<Record<string, unknown>> {
  return request("/api/v1/enrollment/reenroll", {
    method: "POST",
    headers: { "X-PM-Action-Token": "REENROLL" },
    body: JSON.stringify({ enrollment_token: token }),
  });
}

export function runAction(
  action: string,
  confirmation?: string,
): Promise<Record<string, unknown>> {
  const headers: Record<string, string> = {};
  if (confirmation) headers["X-PM-Action-Token"] = confirmation;
  return request(`/api/v1/actions/${encodeURIComponent(action)}`, {
    method: "POST",
    headers,
    body: "{}",
  });
}

export function setCsrfForTest(value: string): void {
  csrfToken = value;
}
