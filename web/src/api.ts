import type {
  EffectiveConfig,
  NetworkSettingsPayload,
  SetupPayload,
  UiDiagnostics,
  UiStatus,
} from "./types";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly retryAfterMs?: number,
  ) {
    super(message);
  }
}

const MIN_RETRY_AFTER_MS = 1_000;
const MAX_RETRY_AFTER_MS = 60_000;

function retryAfterMs(response: Response): number | undefined {
  const header = response.headers.get("Retry-After")?.trim();
  if (!header) return undefined;

  const seconds = Number(header);
  const requestedMs = Number.isFinite(seconds)
    ? seconds * 1_000
    : Date.parse(header) - Date.now();
  if (!Number.isFinite(requestedMs)) return undefined;
  return Math.min(
    MAX_RETRY_AFTER_MS,
    Math.max(MIN_RETRY_AFTER_MS, Math.ceil(requestedMs)),
  );
}

let csrfToken = "";
let sessionPromise: Promise<SessionResult> | undefined;

const renewalCodes = new Set([
  "authentication_required",
  "local_session_missing",
  "local_session_invalid",
  "local_session_expired",
]);

function cookieValue(name: string): string {
  if (typeof document === "undefined") return "";
  const prefix = `${name}=`;
  for (const part of document.cookie.split(";")) {
    const candidate = part.trim();
    if (candidate.startsWith(prefix)) {
      return decodeURIComponent(candidate.slice(prefix.length));
    }
  }
  return "";
}

const csrfForRequest = (): string => cookieValue("pm_csrf") || csrfToken;

async function rawRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body) headers.set("Content-Type", "application/json");
  if (init.method && init.method !== "GET" && init.method !== "HEAD") {
    headers.set("X-PM-CSRF", csrfForRequest());
  }
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
      retryAfterMs(response),
    );
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  try {
    return await rawRequest<T>(path, init);
  } catch (error) {
    const safeToRetry = method === "GET" || method === "HEAD";
    if (
      safeToRetry &&
      path !== "/api/v1/auth/session" &&
      error instanceof ApiError &&
      error.status === 401 &&
      renewalCodes.has(error.code)
    ) {
      await renewLocalSession();
      return rawRequest<T>(path, init);
    }
    throw error;
  }
}

export interface SessionResult {
  expiresInSeconds: number;
  setupRequired: boolean;
  elevated: boolean;
}

async function waitForPasswordJob<T>(jobId: string): Promise<T> {
  const deadline = Date.now() + 60_000;
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
    "The device did not finish the bounded password operation in time.",
  );
}

async function establishSession(
  path: string,
  body: string,
): Promise<SessionResult> {
  const queued = await rawRequest<{
    job_id?: string;
    csrf?: string;
    expires_in_seconds?: number;
    setup_required?: boolean;
    elevated?: boolean;
  }>(path, { method: "POST", body });
  const result = queued.job_id
    ? await waitForPasswordJob<{
        csrf: string;
        expires_in_seconds: number;
        setup_required: boolean;
        elevated: boolean;
      }>(queued.job_id)
    : queued;
  csrfToken = result.csrf ?? "";
  return {
    expiresInSeconds: result.expires_in_seconds ?? 900,
    setupRequired: result.setup_required === true,
    elevated: result.elevated === true,
  };
}

async function queuePasswordOperation<T>(
  path: string,
  body: string,
  method: "POST" | "PUT" = "POST",
  headers?: HeadersInit,
): Promise<T> {
  const operationHeaders = new Headers(headers);
  operationHeaders.set("Prefer", "respond-async");
  const queued = await request<T & { job_id?: string }>(path, {
    method,
    headers: operationHeaders,
    body,
  });
  return queued.job_id ? waitForPasswordJob<T>(queued.job_id) : queued;
}

export const openSession = (): Promise<SessionResult> => renewLocalSession();
export function renewLocalSession(): Promise<SessionResult> {
  if (!sessionPromise) {
    sessionPromise = establishSession("/api/v1/auth/session", "{}").finally(
      () => {
        sessionPromise = undefined;
      },
    );
  }
  return sessionPromise;
}
export const login = (password: string): Promise<SessionResult> =>
  establishSession("/api/v1/auth/login", JSON.stringify({ password }));
export const getUiStatus = (signal?: AbortSignal): Promise<UiStatus> =>
  request("/api/v1/ui/status", { signal });
export const getUiDiagnostics = (): Promise<UiDiagnostics> =>
  request("/api/v1/ui/diagnostics");
export const getConfig = (): Promise<EffectiveConfig> =>
  request("/api/v1/config");

export function updateConfig(
  config: EffectiveConfig,
  ctAcknowledged: boolean,
): Promise<Record<string, unknown>> {
  return queuePasswordOperation(
    "/api/v1/config",
    JSON.stringify(config),
    "PUT",
    { "X-PM-CT-Change-Acknowledged": ctAcknowledged ? "true" : "false" },
  );
}

export const applySetup = (
  payload: SetupPayload,
): Promise<Record<string, unknown>> =>
  queuePasswordOperation("/api/v1/setup/apply", JSON.stringify(payload));

export const updateNetworkSettings = (
  payload: NetworkSettingsPayload,
): Promise<Record<string, unknown>> =>
  queuePasswordOperation(
    "/api/v1/network-settings",
    JSON.stringify(payload),
    "PUT",
  );

export function beginReenrollment(
  token: string,
): Promise<Record<string, unknown>> {
  if (token.length < 32 || token.length > 256) {
    return Promise.reject(
      new ApiError(
        422,
        "enrollment_token_invalid",
        "Enrollment token must contain 32 through 256 characters.",
      ),
    );
  }
  return queuePasswordOperation(
    "/api/v1/enrollment/reenroll",
    JSON.stringify({ enrollment_token: token }),
    "POST",
    { "X-PM-Action-Token": "REENROLL" },
  );
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
