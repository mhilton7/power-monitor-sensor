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
  type View,
} from "./ui";
import type { EffectiveConfig } from "./types";

const STATUS_INTERVAL_MS = 5_000;

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
  private view: View = "status";
  private setupRequired = false;
  private pollTimer = 0;
  private sessionTimer = 0;
  private statusController?: AbortController;
  private statusRequestActive = false;
  private sessionRenewalActive = false;
  private privilegedOperationActive = false;

  constructor(private readonly root: HTMLElement) {}

  start(): void {
    this.root.innerHTML = renderShell();
    this.root
      .querySelectorAll<HTMLButtonElement>("[data-view]")
      .forEach((button) =>
        button.addEventListener(
          "click",
          () => void this.openView(button.dataset.view as View),
        ),
      );
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) this.stopPolling();
      else void this.resumeAfterVisibility();
    });
    void this.connect();
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
    const delay = Math.max(30_000, Math.floor(expiresInSeconds * 800));
    this.sessionTimer = window.setTimeout(
      () => void this.renewSession(),
      delay,
    );
  }

  private async renewSession(): Promise<boolean> {
    if (this.sessionRenewalActive || this.privilegedOperationActive)
      return false;
    this.sessionRenewalActive = true;
    this.stopPolling();
    this.notify("Local session expired. Reconnecting…", "pending");
    try {
      const session = await api.renewLocalSession();
      this.setupRequired = session.setupRequired;
      this.scheduleSessionRenewal(session.expiresInSeconds);
      this.notify("", "info");
      return true;
    } catch (error) {
      this.notify(
        this.message(error, "The local browser session could not be renewed."),
        "error",
      );
      return false;
    } finally {
      this.sessionRenewalActive = false;
    }
  }

  private async resumeAfterVisibility(): Promise<void> {
    if (this.privilegedOperationActive) return;
    const renewed = await this.renewSession();
    if (renewed && this.view === "status") await this.refreshStatus();
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
    await this.refreshDiagnostics();
  }

  private async refreshStatus(): Promise<void> {
    if (this.view !== "status" || document.hidden || this.statusRequestActive)
      return;
    this.statusRequestActive = true;
    this.statusController?.abort();
    this.statusController = new AbortController();
    try {
      const status = await api.getUiStatus(this.statusController.signal);
      if (this.view === "status") updateStatus(this.root, status);
    } catch (error) {
      if (!(error instanceof DOMException && error.name === "AbortError")) {
        this.notify(this.message(error, "Status refresh failed."), "error");
      }
    } finally {
      this.statusRequestActive = false;
      if (
        this.view === "status" &&
        !document.hidden &&
        !this.privilegedOperationActive
      ) {
        window.clearTimeout(this.pollTimer);
        this.pollTimer = window.setTimeout(
          () => void this.refreshStatus(),
          STATUS_INTERVAL_MS,
        );
      }
    }
  }

  private stopPolling(): void {
    window.clearTimeout(this.pollTimer);
    this.pollTimer = 0;
    this.statusController?.abort();
    this.statusController = undefined;
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
      this.actionResult(`${button.textContent?.trim() || action} was queued.`);
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
