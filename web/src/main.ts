import "./style.css";
import * as api from "./api";
import {
  clearSecrets,
  destructiveConfirmation,
  readConfiguredSetupForm,
  readSetupForm,
  renderDiagnostics,
  renderSetup,
  renderShell,
  renderStatus,
  updateDiagnostics,
  updateStatus,
  updateStatusFreshness,
  type View,
} from "./ui";
import type { EffectiveConfig, UiStatus } from "./types";

export const STATUS_INTERVAL_MS = 10_000;
const FRESHNESS_TICK_MS = 1_000;

export interface BrowserRequestCounters {
  requestsStarted: number;
  requestsCompleted: number;
  requestsAborted: number;
  maximumSimultaneousRequests: number;
  sessionRenewals: number;
  automaticRetries: number;
}

let activeApp: App | undefined;

const blankConfig = (): EffectiveConfig => ({
  schema_version: 1,
  config_version: 1,
  friendly_name: "Power Monitor",
  hostname: "",
  wifi_ssid: "",
  static_network_enabled: false,
  static_ip: "",
  static_gateway: "",
  static_subnet: "",
  static_dns: "",
  server_url: "",
  server_ca_configured: false,
  server_fingerprint_configured: false,
  ota_signing_key_configured: false,
  ota_signing_key_id: "",
  connection_mode: "push",
  sample_interval_seconds: 1,
  durable_log_interval_seconds: 60,
  heartbeat_interval_seconds: 15,
  ct_rating_a: 100,
  timezone: "America/Los_Angeles",
  sd_spi_hz: 4_000_000,
  diagnostic_log_level: 2,
});

export class App {
  private started = false;
  private view: View = "status";
  private setupRequired = false;
  private pollTimer = 0;
  private freshnessTimer = 0;
  private sessionTimer = 0;
  private sessionExpiresAtMs = 0;
  private statusController?: AbortController;
  private statusRequest?: Promise<void>;
  private sessionRenewal?: Promise<boolean>;
  private privilegedOperationActive = false;
  private lastStatus?: UiStatus;
  private statusReceivedAtMonotonicMs = 0;
  private activeStatusRequests = 0;
  private readonly counters: BrowserRequestCounters = {
    requestsStarted: 0,
    requestsCompleted: 0,
    requestsAborted: 0,
    maximumSimultaneousRequests: 0,
    sessionRenewals: 0,
    automaticRetries: 0,
  };
  private readonly visibilityHandler = (): void => {
    if (document.hidden) this.stopPolling();
    else void this.resumeAfterVisibility();
  };

  constructor(private readonly root: HTMLElement) {}

  requestCounters(): Readonly<BrowserRequestCounters> {
    return { ...this.counters };
  }

  start(): void {
    if (this.started) return;
    activeApp?.destroy();
    activeApp = this;
    this.started = true;
    this.root.innerHTML = renderShell();
    this.root
      .querySelectorAll<HTMLButtonElement>("[data-view]")
      .forEach((button) =>
        button.addEventListener(
          "click",
          () => void this.openView(button.dataset.view as View),
        ),
      );
    document.addEventListener("visibilitychange", this.visibilityHandler);
    void this.connect();
  }

  destroy(): void {
    if (!this.started) return;
    this.started = false;
    document.removeEventListener("visibilitychange", this.visibilityHandler);
    this.stopPolling();
    window.clearTimeout(this.sessionTimer);
    this.sessionTimer = 0;
    if (activeApp === this) activeApp = undefined;
  }

  private async connect(): Promise<void> {
    this.notify("Connecting to the local sensor…", "pending");
    try {
      const session = await api.openSession();
      this.scheduleSessionRenewal(session.expiresInSeconds);
      this.setupRequired = session.setupRequired;
      await this.openView(session.setupRequired ? "setup" : "status");
      this.notify("", "info");
    } catch (error) {
      this.notify(
        this.message(error, "Unable to open a local session."),
        "error",
      );
    }
  }

  private scheduleSessionRenewal(expiresInSeconds: number): void {
    window.clearTimeout(this.sessionTimer);
    this.sessionExpiresAtMs = Date.now() + expiresInSeconds * 1_000;
    const delay = Math.max(30_000, Math.floor(expiresInSeconds * 800));
    this.sessionTimer = window.setTimeout(
      () => void this.renewSessionAndResume(),
      delay,
    );
  }

  private renewSession(): Promise<boolean> {
    if (this.sessionRenewal) return this.sessionRenewal;
    if (this.privilegedOperationActive) return Promise.resolve(false);
    const pendingStatus = this.statusRequest;
    this.stopPolling();
    this.counters.sessionRenewals += 1;
    this.notify("Local session expired. Reconnecting…", "pending");
    const operation = (async (): Promise<boolean> => {
      try {
        // Drain the aborted fetch before renewal completes. Otherwise a fast
        // renewal can coalesce its post-renewal refresh into the request that
        // is still unwinding, losing that refresh in slower browser engines.
        await pendingStatus?.catch(() => undefined);
        const session = await api.renewLocalSession();
        this.setupRequired = session.setupRequired;
        this.scheduleSessionRenewal(session.expiresInSeconds);
        this.notify("", "info");
        return true;
      } catch (error) {
        this.notify(
          this.message(
            error,
            "The local browser session could not be renewed.",
          ),
          "error",
        );
        return false;
      }
    })();
    this.sessionRenewal = operation.finally(() => {
      this.sessionRenewal = undefined;
    });
    return this.sessionRenewal;
  }

  private async renewSessionAndResume(): Promise<void> {
    const renewed = await this.renewSession();
    if (renewed && this.view === "status" && !document.hidden)
      await this.refreshStatus();
  }

  private async resumeAfterVisibility(): Promise<void> {
    if (this.privilegedOperationActive) return;
    this.refreshLocalFreshness();
    const renewalDue = Date.now() >= this.sessionExpiresAtMs - 30_000;
    if (renewalDue && !(await this.renewSession())) return;
    if (this.view === "status") await this.refreshStatus();
  }

  private main(): HTMLElement {
    const target = this.root.querySelector<HTMLElement>("#main");
    if (!target) throw new Error("The application shell is unavailable.");
    return target;
  }

  private setCurrentView(view: View): void {
    this.view = view;
    this.root
      .querySelectorAll<HTMLButtonElement>("[data-view]")
      .forEach((button) => {
        if (button.dataset.view === view)
          button.setAttribute("aria-current", "page");
        else button.removeAttribute("aria-current");
      });
  }

  private async openView(view: View): Promise<void> {
    this.stopPolling();
    this.setCurrentView(view);
    if (view === "status") {
      this.main().innerHTML = renderStatus();
      this.root
        .querySelector<HTMLButtonElement>("#refresh-status")
        ?.addEventListener("click", () => void this.refreshStatus());
      await this.refreshStatus();
      return;
    }
    if (view === "setup") {
      this.main().innerHTML = `<section class="panel"><p>Loading setup…</p></section>`;
      try {
        const config = await api.getConfig();
        this.main().innerHTML = renderSetup(config, this.setupRequired);
        this.bindSetup(config);
      } catch (error) {
        if (this.setupRequired) {
          const config = blankConfig();
          this.main().innerHTML = renderSetup(config, true);
          this.bindSetup(config);
        } else {
          this.showViewError(error, "Setup could not be loaded.");
        }
      }
      return;
    }
    this.main().innerHTML = renderDiagnostics();
    this.bindDiagnostics();
  }

  private refreshStatus(): Promise<void> {
    if (this.statusRequest) return this.statusRequest;
    if (
      this.view !== "status" ||
      document.hidden ||
      this.privilegedOperationActive
    ) {
      return Promise.resolve();
    }
    if (this.sessionRenewal) {
      return this.sessionRenewal.then((renewed) =>
        renewed ? this.refreshStatus() : undefined,
      );
    }

    window.clearTimeout(this.pollTimer);
    this.pollTimer = 0;
    const controller = new AbortController();
    this.statusController = controller;
    const button =
      this.root.querySelector<HTMLButtonElement>("#refresh-status");
    if (button) button.disabled = true;
    this.counters.requestsStarted += 1;
    this.activeStatusRequests += 1;
    this.counters.maximumSimultaneousRequests = Math.max(
      this.counters.maximumSimultaneousRequests,
      this.activeStatusRequests,
    );
    let nextDelayMs = STATUS_INTERVAL_MS;

    const request = (async (): Promise<void> => {
      try {
        const status = await api.getUiStatus(controller.signal);
        if (controller.signal.aborted) {
          this.counters.requestsAborted += 1;
          return;
        }
        this.counters.requestsCompleted += 1;
        this.lastStatus = status;
        this.statusReceivedAtMonotonicMs = performance.now();
        if (this.view === "status") {
          updateStatus(this.root, status);
          this.startFreshnessTicker();
          this.notify("", "info");
        }
      } catch (error) {
        if (this.isAbortError(error) || controller.signal.aborted) {
          this.counters.requestsAborted += 1;
          return;
        }
        this.counters.requestsCompleted += 1;
        if (error instanceof api.ApiError && error.status === 503) {
          nextDelayMs = error.retryAfterMs ?? STATUS_INTERVAL_MS;
          this.counters.automaticRetries += 1;
          this.notify(
            `Status is temporarily deferred. Retrying in ${Math.ceil(nextDelayMs / 1_000)} seconds.`,
            "pending",
          );
        } else {
          this.notify(this.message(error, "Status refresh failed."), "error");
        }
      } finally {
        this.activeStatusRequests -= 1;
        if (this.statusController === controller)
          this.statusController = undefined;
        if (button) button.disabled = false;
      }
    })();

    const tracked = request.finally(() => {
      if (this.statusRequest === tracked) this.statusRequest = undefined;
      if (
        !controller.signal.aborted &&
        this.view === "status" &&
        !document.hidden &&
        !this.privilegedOperationActive &&
        !this.sessionRenewal
      ) {
        this.pollTimer = window.setTimeout(
          () => void this.refreshStatus(),
          nextDelayMs,
        );
      }
    });
    this.statusRequest = tracked;
    return tracked;
  }

  private stopPolling(): void {
    window.clearTimeout(this.pollTimer);
    this.pollTimer = 0;
    window.clearInterval(this.freshnessTimer);
    this.freshnessTimer = 0;
    this.statusController?.abort();
    this.statusController = undefined;
  }

  private startFreshnessTicker(): void {
    window.clearInterval(this.freshnessTimer);
    if (document.hidden || this.view !== "status" || !this.lastStatus) return;
    this.freshnessTimer = window.setInterval(
      () => this.refreshLocalFreshness(),
      FRESHNESS_TICK_MS,
    );
  }

  private refreshLocalFreshness(): void {
    if (!this.lastStatus || this.view !== "status") return;
    const elapsedSeconds = Math.floor(
      Math.max(0, performance.now() - this.statusReceivedAtMonotonicMs) / 1_000,
    );
    updateStatusFreshness(this.root, this.lastStatus, elapsedSeconds);
    if (!document.hidden && this.freshnessTimer === 0)
      this.startFreshnessTicker();
  }

  private isAbortError(error: unknown): boolean {
    return (
      error instanceof DOMException &&
      (error.name === "AbortError" || error.code === DOMException.ABORT_ERR)
    );
  }

  private bindSetup(config: EffectiveConfig): void {
    const form = this.root.querySelector<HTMLFormElement>("#setup-form");
    if (!form) return;
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!form.reportValidity() || this.privilegedOperationActive) return;
      const button = form.querySelector<HTMLButtonElement>(
        'button[type="submit"]',
      );
      const result = form.querySelector<HTMLElement>("#setup-result");
      const firstRun = form.dataset.firstRun === "true";
      this.privilegedOperationActive = true;
      if (button) button.disabled = true;
      if (result) result.textContent = "Saving and verifying…";
      try {
        if (firstRun) {
          const payload = readSetupForm(form);
          const operation = api.applySetup(payload);
          clearSecrets(form);
          await operation;
          this.setupRequired = false;
        } else {
          if (!(await this.elevate("update sensor setup"))) return;
          const payload = readConfiguredSetupForm(form, config);
          const ctChanged = payload.config.ct_rating_a !== config.ct_rating_a;
          const configOperation = api.updateConfig(payload.config, ctChanged);
          clearSecrets(form);
          await configOperation;
          await api.updateNetworkSettings(payload.network);
        }
        if (result)
          result.textContent =
            "Setup saved and verified. The network connection may restart.";
        this.notify("Setup saved and verified.", "success");
      } catch (error) {
        if (result) result.textContent = this.message(error, "Setup failed.");
        this.notify(this.message(error, "Setup failed."), "error");
      } finally {
        clearSecrets(form);
        this.privilegedOperationActive = false;
        if (button) button.disabled = false;
      }
    });
  }

  private bindDiagnostics(): void {
    this.root
      .querySelector("#refresh-diagnostics")
      ?.addEventListener("click", () => void this.refreshDiagnostics());
    this.root
      .querySelectorAll<HTMLButtonElement>("[data-action]")
      .forEach((button) =>
        button.addEventListener(
          "click",
          () => void this.runDiagnosticAction(button),
        ),
      );
    this.root
      .querySelector<HTMLFormElement>("#reenroll-form")
      ?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const form = event.currentTarget as HTMLFormElement;
        const input = form.elements.namedItem(
          "enrollment_token",
        ) as HTMLInputElement;
        if (
          !form.reportValidity() ||
          !(await this.elevate("re-enroll this sensor"))
        )
          return;
        const token = input.value;
        input.value = "";
        try {
          await api.beginReenrollment(token);
          this.actionResult(
            "Re-enrollment was queued. Existing credentials are being replaced safely.",
          );
        } catch (error) {
          this.actionResult(this.message(error, "Re-enrollment failed."), true);
        }
      });
  }

  private async refreshDiagnostics(): Promise<void> {
    if (this.view !== "diagnostics" || this.privilegedOperationActive) return;
    const button = this.root.querySelector<HTMLButtonElement>(
      "#refresh-diagnostics",
    );
    if (button) button.disabled = true;
    try {
      updateDiagnostics(this.root, await api.getUiDiagnostics());
    } catch (error) {
      this.actionResult(
        this.message(error, "Diagnostics could not be loaded."),
        true,
      );
    } finally {
      if (button) button.disabled = false;
    }
  }

  private async runDiagnosticAction(button: HTMLButtonElement): Promise<void> {
    if (this.privilegedOperationActive) return;
    const action = button.dataset.action ?? "";
    const confirmationMessage = button.dataset.confirmMessage;
    if (confirmationMessage && !window.confirm(confirmationMessage)) return;
    const confirmation = destructiveConfirmation(action);
    if (confirmation) {
      const typed = window.prompt(`Type ${confirmation} to continue.`);
      if (typed !== confirmation || !(await this.elevate(action))) return;
    }
    this.privilegedOperationActive = true;
    this.stopPolling();
    button.disabled = true;
    try {
      await api.runAction(action, confirmation);
      this.actionResult(
        action === "prepare-card-removal"
          ? "Card preparation was queued. Wait for microSD on Status to leave the Writable state, then power off the sensor before removing the card."
          : `${button.textContent?.trim() || action} was queued.`,
      );
    } catch (error) {
      this.actionResult(this.message(error, `${action} failed.`), true);
    } finally {
      button.disabled = false;
      this.privilegedOperationActive = false;
    }
  }

  private async elevate(operation: string): Promise<boolean> {
    const password = window.prompt(
      `Enter the local administrator password to ${operation}.`,
    );
    if (!password) return false;
    try {
      const session = await api.login(password);
      if (!session.elevated) throw new Error("The session was not elevated.");
      this.scheduleSessionRenewal(session.expiresInSeconds);
      return true;
    } catch (error) {
      this.notify(
        this.message(error, "Administrator verification failed."),
        "error",
      );
      return false;
    }
  }

  private actionResult(message: string, error = false): void {
    const result = this.root.querySelector<HTMLElement>("#action-result");
    if (result) {
      result.textContent = message;
      result.classList.toggle("error", error);
    }
  }

  private notify(
    message: string,
    tone: "info" | "pending" | "success" | "error",
  ): void {
    const region = this.root.querySelector<HTMLElement>("#notification-region");
    if (!region) return;
    region.textContent = message;
    region.className = message ? `notification ${tone}` : "";
  }

  private showViewError(error: unknown, fallback: string): void {
    this.main().innerHTML = `<section class="panel"><h1>Something needs attention</h1><p id="view-error"></p></section>`;
    const target = this.root.querySelector<HTMLElement>("#view-error");
    if (target) target.textContent = this.message(error, fallback);
  }

  private message(error: unknown, fallback: string): string {
    return error instanceof Error ? error.message : fallback;
  }
}

const root = document.querySelector<HTMLElement>("#app");
if (root) new App(root).start();
