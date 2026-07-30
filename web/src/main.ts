import "./style.css";
import * as api from "./api";
import {
  destructiveConfirmation,
  readConfigForm,
  readNetworkSettingsForm,
  readSetupForm,
  renderBanners,
  renderMaintenance,
  renderMeter,
  renderNetwork,
  renderSetup,
  renderShell,
  renderStatus,
  renderStorage,
  type View,
} from "./ui";
import type { EffectiveConfig, Health, LiveReading } from "./types";

type NotificationTone = "info" | "pending" | "success" | "error";

export class App {
  private sessionTimer = 0;
  private pollTimer = 0;
  private health?: Health;
  private live?: LiveReading;
  private config?: EffectiveConfig;
  private storage: Record<string, unknown> = {};
  private metrics: Record<string, unknown> = {};
  private otaStatus: Record<string, unknown> = {};
  private events: Record<string, unknown> = {};
  private view: View = "status";
  private setupRequired = false;
  private setupFormDirty = false;
  private provisioningComplete = false;
  private refreshInProgress = false;
  private eventsRefreshInProgress = false;
  private privilegedOperationInProgress = false;
  private reconnectAfterPrivilegedOperation = false;
  private refreshWarning = "";
  private bannerHtml = "";

  constructor(private readonly root: HTMLElement) {}

  private notify(tone: NotificationTone, message: string): void {
    const region = this.root.querySelector<HTMLElement>("#notification-region");
    if (!region) return;
    const notification = document.createElement("div");
    notification.className = `notification notification-${tone}`;
    notification.setAttribute("role", tone === "error" ? "alert" : "status");

    const content = document.createElement("div");
    const heading = document.createElement("strong");
    heading.textContent =
      tone === "pending"
        ? "Request in progress"
        : tone === "success"
          ? "Request accepted"
          : tone === "error"
            ? "Request failed"
            : "Notice";
    const detail = document.createElement("span");
    detail.textContent = message;
    content.append(heading, detail);

    const dismiss = document.createElement("button");
    dismiss.type = "button";
    dismiss.className = "notification-dismiss";
    dismiss.textContent = "Dismiss";
    dismiss.setAttribute("aria-label", "Dismiss notification");
    dismiss.addEventListener("click", () => region.replaceChildren());

    notification.append(content, dismiss);
    region.replaceChildren(notification);
  }

  private errorMessage(error: unknown, fallback: string): string {
    return error instanceof Error ? error.message : fallback;
  }

  private beginPrivilegedOperation(): boolean {
    if (this.privilegedOperationInProgress) return false;
    this.privilegedOperationInProgress = true;
    this.reconnectAfterPrivilegedOperation = false;
    this.stopPolling();
    return true;
  }

  private finishPrivilegedOperation(): void {
    if (!this.privilegedOperationInProgress) return;
    this.privilegedOperationInProgress = false;
    if (this.provisioningComplete) {
      this.reconnectAfterPrivilegedOperation = false;
      return;
    }
    if (this.reconnectAfterPrivilegedOperation) {
      this.reconnectAfterPrivilegedOperation = false;
      void this.connect();
      return;
    }
    this.startPolling();
  }

  private requestElevation(operation: string): Promise<boolean> {
    if (!this.beginPrivilegedOperation()) {
      this.notify(
        "info",
        "Finish the current administrator-authorized operation before starting another.",
      );
      return Promise.resolve(false);
    }
    this.root.querySelector("#elevation-dialog")?.remove();
    const dialog = document.createElement("dialog");
    dialog.id = "elevation-dialog";
    dialog.className = "elevation-dialog";
    dialog.setAttribute("aria-labelledby", "elevation-heading");

    const form = document.createElement("form");
    form.method = "dialog";
    const heading = document.createElement("h2");
    heading.id = "elevation-heading";
    heading.textContent = "Administrator verification required";
    const explanation = document.createElement("p");
    explanation.textContent = `Enter the local administrator password to continue ${operation}. The password is sent only for this verification and is not retained.`;
    const label = document.createElement("label");
    label.textContent = "Administrator password";
    const password = document.createElement("input");
    password.type = "password";
    password.autocomplete = "current-password";
    password.minLength = 12;
    password.maxLength = 128;
    password.required = true;
    label.append(password);
    const status = document.createElement("p");
    status.setAttribute("role", "status");
    const actions = document.createElement("div");
    actions.className = "actions";
    const verify = document.createElement("button");
    verify.type = "submit";
    verify.textContent = "Verify and continue";
    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.textContent = "Cancel";
    actions.append(verify, cancel);
    form.append(heading, explanation, label, status, actions);
    dialog.append(form);
    this.root.append(dialog);

    return new Promise((resolve) => {
      let finished = false;
      const finish = (accepted: boolean): void => {
        if (finished) return;
        finished = true;
        password.value = "";
        dialog.close?.();
        dialog.remove();
        if (!accepted) this.finishPrivilegedOperation();
        resolve(accepted);
      };
      cancel.addEventListener("click", () => finish(false));
      dialog.addEventListener("cancel", (event) => {
        event.preventDefault();
        finish(false);
      });
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (!form.reportValidity()) return;
        verify.disabled = true;
        cancel.disabled = true;
        password.disabled = true;
        status.textContent = "Verifying password\u2026";
        this.notify(
          "pending",
          `Verifying administrator credentials before ${operation}\u2026`,
        );
        let secret = password.value;
        password.value = "";
        const verification = api.login(secret);
        secret = "";
        try {
          const session = await verification;
          if (!session.elevated) {
            throw new api.ApiError(
              403,
              "elevated_session_required",
              "The device did not issue an elevated session.",
            );
          }
          window.clearTimeout(this.sessionTimer);
          const renewAfterSeconds = Math.max(1, session.expiresInSeconds - 5);
          this.sessionTimer = window.setTimeout(
            () => void this.connect(),
            renewAfterSeconds * 1000,
          );
          this.notify(
            "success",
            `Administrator verification succeeded. Continuing ${operation}.`,
          );
          finish(true);
        } catch (error) {
          status.textContent = this.errorMessage(
            error,
            "Administrator verification failed.",
          );
          this.notify(
            "error",
            `Administrator verification failed: ${status.textContent}`,
          );
          verify.disabled = false;
          cancel.disabled = false;
          password.disabled = false;
          password.focus();
        }
      });
      if (typeof dialog.showModal === "function") {
        dialog.showModal();
      } else {
        dialog.setAttribute("open", "");
      }
      password.focus();
    });
  }

  start(): void {
    this.showConnecting();
    void this.connect();
  }

  private showConnecting(message = "Connecting to this sensor\u2026"): void {
    if (this.provisioningComplete) return;
    this.root.innerHTML = renderShell();
    this.bannerHtml = "";
    this.bindShell();
    const main = this.root.querySelector<HTMLElement>("#main");
    if (main) {
      main.innerHTML = `<section class="panel"><h2>Local diagnostics</h2><p>${message}</p></section>`;
    }
  }

  private async connect(): Promise<void> {
    if (this.provisioningComplete) return;
    if (this.privilegedOperationInProgress) {
      this.reconnectAfterPrivilegedOperation = true;
      return;
    }
    this.stopPolling();
    window.clearTimeout(this.sessionTimer);
    try {
      const session = await api.openSession();
      this.setupRequired = session.setupRequired;
      this.view = session.setupRequired ? "setup" : "status";
      const renewAfterSeconds = Math.max(1, session.expiresInSeconds - 5);
      this.sessionTimer = window.setTimeout(
        () => void this.connect(),
        renewAfterSeconds * 1000,
      );
      await this.load();
    } catch {
      this.showConnecting(
        "The sensor is unavailable or reconnecting. Retrying automatically\u2026",
      );
      this.sessionTimer = window.setTimeout(() => void this.connect(), 2000);
    }
  }

  private async load(): Promise<void> {
    this.stopPolling();
    this.root.innerHTML = renderShell();
    this.bannerHtml = "";
    this.bindShell();
    await this.refresh();
    this.startPolling();
  }

  private startPolling(): void {
    if (this.provisioningComplete || this.privilegedOperationInProgress) return;
    this.stopPolling();
    this.pollTimer = window.setInterval(() => void this.refresh(), 5000);
  }

  private stopPolling(): void {
    window.clearInterval(this.pollTimer);
    this.pollTimer = 0;
  }

  private bindShell(): void {
    this.root
      .querySelectorAll<HTMLButtonElement>("[data-view]")
      .forEach((button) => {
        button.addEventListener("click", () => {
          const nextView = button.dataset.view as View;
          if (nextView !== this.view) {
            this.setupFormDirty = false;
            this.view = nextView;
          }
          this.renderView();
          this.root.querySelector<HTMLElement>("#main")?.focus();
        });
      });
    this.root.querySelector("#theme-toggle")?.addEventListener("click", () => {
      document.documentElement.dataset.theme =
        document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    });
  }

  private async refresh(): Promise<void> {
    if (this.provisioningComplete || this.refreshInProgress) return;
    this.refreshInProgress = true;
    try {
      const results = await Promise.allSettled([
        api.getHealth(),
        api.getLive(),
        api.getConfig(),
        api.getStorage(),
        api.getMetrics(),
        api.getOtaStatus(),
      ] as const);
      const unauthorized = results.some(
        (result) =>
          result.status === "rejected" &&
          result.reason instanceof api.ApiError &&
          result.reason.status === 401,
      );
      if (unauthorized) {
        this.refreshInProgress = false;
        await this.connect();
        return;
      }

      if (results[0].status === "fulfilled") this.health = results[0].value;
      this.live =
        results[1].status === "fulfilled" ? results[1].value : undefined;
      if (results[2].status === "fulfilled") this.config = results[2].value;
      if (results[3].status === "fulfilled") this.storage = results[3].value;
      if (results[4].status === "fulfilled") this.metrics = results[4].value;
      if (results[5].status === "fulfilled") this.otaStatus = results[5].value;

      const failures = results
        .map((result, index) => ({ result, index }))
        .filter(({ result }) => result.status === "rejected");
      const waitingForLive =
        failures.length === 1 &&
        failures[0].index === 1 &&
        failures[0].result.status === "rejected" &&
        failures[0].result.reason instanceof api.ApiError &&
        failures[0].result.reason.code === "live_unavailable";
      this.refreshWarning = waitingForLive
        ? `<div class="banner warning" role="status">Waiting for the first valid meter reading. Device settings and available diagnostics remain accessible.</div>`
        : failures.length
          ? `<div class="banner warning" role="alert">Some diagnostic panels could not be refreshed. Available device data is shown and retrying continues automatically.</div>`
          : "";
      this.renderView();
      this.refreshEvents();
    } finally {
      this.refreshInProgress = false;
    }
  }

  private refreshEvents(): void {
    if (this.eventsRefreshInProgress || this.provisioningComplete) return;
    this.eventsRefreshInProgress = true;
    void api
      .getEvents()
      .then((events) => {
        this.events = events;
        if (this.view === "maintenance") this.renderView();
      })
      .catch(() => {
        // Event history is optional and retries independently; essential
        // health/config rendering must not wait for microSD.
      })
      .finally(() => {
        this.eventsRefreshInProgress = false;
      });
  }

  private renderView(): void {
    if (!this.health || !this.config) {
      const main = this.root.querySelector<HTMLElement>("#main");
      if (main) {
        main.innerHTML = `<section class="panel"><h2>Device status is loading</h2><p>Essential health or configuration data is temporarily unavailable. Retrying automatically\u2026</p></section>`;
      }
      return;
    }
    const banners = this.root.querySelector<HTMLElement>("#banner-region");
    const nextBannerHtml = renderBanners(this.health) + this.refreshWarning;
    if (banners && this.bannerHtml !== nextBannerHtml) {
      banners.innerHTML = nextBannerHtml;
      this.bannerHtml = nextBannerHtml;
    }
    const main = this.root.querySelector<HTMLElement>("#main");
    if (!main) return;
    if (this.view === "setup" && this.setupFormDirty) return;
    switch (this.view) {
      case "status":
        main.innerHTML = renderStatus(this.health, this.live);
        break;
      case "storage":
        main.innerHTML = renderStorage(this.health, this.storage);
        break;
      case "network":
        main.innerHTML = renderNetwork(this.health, this.config);
        break;
      case "meter":
        main.innerHTML = renderMeter(this.health, this.live, this.config);
        break;
      case "maintenance":
        main.innerHTML = renderMaintenance(
          this.metrics,
          this.otaStatus,
          this.events,
        );
        break;
      case "setup":
        main.innerHTML = renderSetup(this.config, this.setupRequired);
        break;
    }
    this.bindViewActions();
  }

  private bindViewActions(): void {
    this.root
      .querySelector<HTMLButtonElement>("[data-open-settings]")
      ?.addEventListener("click", () => {
        this.setupFormDirty = false;
        this.view = "setup";
        this.renderView();
        this.root.querySelector<HTMLElement>("#main")?.focus();
      });
    this.root
      .querySelectorAll<HTMLButtonElement>("[data-action]")
      .forEach((button) => {
        button.addEventListener("click", async () => {
          const action = button.dataset.action ?? "";
          const label = button.textContent?.trim() || action;
          const phrase = button.dataset.destructive;
          const confirmation = phrase
            ? destructiveConfirmation(action, phrase)
            : undefined;
          if (phrase && !confirmation) {
            this.notify(
              "info",
              `${label} was cancelled. No request was sent to the device.`,
            );
            return;
          }
          const requiresElevation = [
            "network-reset",
            "factory-reset",
            "rollback-ota",
          ].includes(action);
          if (
            requiresElevation &&
            !(await this.requestElevation(`with ${label}`))
          ) {
            this.notify(
              "info",
              `${label} was cancelled. No elevated request was sent to the device.`,
            );
            return;
          }
          const originalText = button.textContent;
          button.disabled = true;
          button.setAttribute("aria-busy", "true");
          button.textContent = "Sending\u2026";
          this.notify("pending", `Sending ${label} to the device\u2026`);
          try {
            const response = await api.runAction(
              action,
              confirmation ?? undefined,
            );
            const queued = response.status === "queued";
            this.notify(
              "success",
              queued
                ? `${label} was queued by the device. Background results will appear in diagnostics and the next status refresh.`
                : `${label} was accepted by the device.`,
            );
          } catch (error) {
            this.notify(
              "error",
              `${label} failed: ${this.errorMessage(error, "The device rejected the request.")}`,
            );
          } finally {
            if (button.isConnected) {
              button.disabled = false;
              button.removeAttribute("aria-busy");
              button.textContent = originalText;
            }
            if (requiresElevation) this.finishPrivilegedOperation();
          }
        });
      });
    this.root
      .querySelector<HTMLAnchorElement>(
        'a[download][href="/api/v1/diagnostics/bundle"]',
      )
      ?.addEventListener("click", () => {
        this.notify(
          "info",
          "Diagnostics download requested. Your browser will save the bundle when the device responds.",
        );
      });
    const exportForm = this.root.querySelector<HTMLFormElement>("#export-form");
    exportForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const result = this.root.querySelector<HTMLElement>("#export-result");
      if (!result) return;
      const data = new FormData(exportForm);
      const sequence = Number(data.get("after_sequence") ?? 0);
      const toUtc = (value: FormDataEntryValue | null): string | undefined => {
        const text = String(value ?? "");
        return text ? new Date(text).toISOString() : undefined;
      };
      try {
        result.textContent = "Preparing a bounded NDJSON page\u2026";
        this.notify("pending", "Preparing the history export\u2026");
        const blob = await api.exportHistory(
          sequence,
          toUtc(data.get("from_utc")),
          toUtc(data.get("to_utc")),
        );
        const href = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = href;
        link.download = `power-monitor-readings-after-${Math.max(0, Math.trunc(sequence))}.ndjson`;
        link.click();
        URL.revokeObjectURL(href);
        result.textContent =
          "Export downloaded. Continue from the last sequence for another page.";
        this.notify(
          "success",
          "History export was generated and sent to your browser.",
        );
      } catch (error) {
        const message = this.errorMessage(error, "History export failed.");
        result.textContent = message;
        this.notify("error", `History export failed: ${message}`);
      }
    });
    const form = this.root.querySelector<HTMLFormElement>("#config-form");
    form?.addEventListener("input", () => {
      this.setupFormDirty = true;
    });
    form?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const result = this.root.querySelector<HTMLElement>("#config-result");
      if (!this.config || !result) return;
      const submit = form.querySelector<HTMLButtonElement>(
        'button[type="submit"]',
      );
      if (submit) submit.disabled = true;
      let elevated = false;
      try {
        const candidate = readConfigForm(form, this.config);
        elevated = await this.requestElevation("saving device configuration");
        if (!elevated) {
          if (submit) submit.disabled = false;
          result.textContent =
            "Administrator verification was cancelled; configuration was not changed.";
          return;
        }
        this.notify(
          "pending",
          "Validating and saving device configuration\u2026",
        );
        this.stopPolling();
        await api.updateConfig(candidate.config, candidate.ctAcknowledged);
        this.setupFormDirty = false;
        await this.refresh();
        this.startPolling();
        const refreshedResult =
          this.root.querySelector<HTMLElement>("#config-result");
        if (refreshedResult)
          refreshedResult.textContent = "Configuration validated and applied.";
        this.notify(
          "success",
          "Device configuration was validated, saved, and applied.",
        );
      } catch (error) {
        this.startPolling();
        if (submit) submit.disabled = false;
        const message = this.errorMessage(error, "Configuration failed.");
        result.textContent = message;
        this.notify("error", `Configuration failed: ${message}`);
      } finally {
        if (elevated) this.finishPrivilegedOperation();
      }
    });
    const networkSettingsForm = this.root.querySelector<HTMLFormElement>(
      "#network-settings-form",
    );
    networkSettingsForm?.addEventListener("input", () => {
      this.setupFormDirty = true;
    });
    networkSettingsForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const result = this.root.querySelector<HTMLElement>(
        "#network-settings-result",
      );
      if (!this.config || !result) return;
      const submit = networkSettingsForm.querySelector<HTMLButtonElement>(
        'button[type="submit"]',
      );
      if (submit) submit.disabled = true;
      let submitted = false;
      let elevated = false;
      try {
        const payload = readNetworkSettingsForm(
          networkSettingsForm,
          this.config,
        );
        elevated = await this.requestElevation("saving Wi-Fi/server settings");
        if (!elevated) {
          if (submit) submit.disabled = false;
          result.textContent =
            "Administrator verification was cancelled; network settings were not changed.";
          return;
        }
        this.notify(
          "pending",
          "Validating and saving Wi-Fi and server settings\u2026",
        );
        this.stopPolling();
        submitted = true;
        const response = await api.updateNetworkSettings(payload);
        networkSettingsForm
          .querySelectorAll<
            HTMLInputElement | HTMLTextAreaElement
          >('input[type="password"], textarea[name="server_ca_pem"], input[name="server_fingerprint"]')
          .forEach((input) => {
            input.value = "";
          });
        this.showNetworkTransition(
          true,
          false,
          response.reboot_queued !== false ||
            response.network_apply_queued === true,
        );
        this.notify(
          "success",
          "Wi-Fi and server settings were saved. The device is applying them now.",
        );
      } catch (error) {
        if (submitted && !(error instanceof api.ApiError)) {
          this.showNetworkTransition(false, false);
          this.notify(
            "info",
            "The connection closed after submission. The device may be applying the saved network settings.",
          );
          return;
        }
        this.startPolling();
        if (submit) submit.disabled = false;
        const message = this.errorMessage(
          error,
          "Network/server settings failed.",
        );
        result.textContent = message;
        this.notify("error", `Network/server settings failed: ${message}`);
      } finally {
        if (elevated) this.finishPrivilegedOperation();
      }
    });
    const setupForm =
      this.root.querySelector<HTMLFormElement>("#first-run-form");
    setupForm?.addEventListener("input", () => {
      this.setupFormDirty = true;
    });
    setupForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const result = this.root.querySelector<HTMLElement>("#setup-result");
      if (!result) return;
      const submit = setupForm.querySelector<HTMLButtonElement>(
        'button[type="submit"]',
      );
      if (submit) submit.disabled = true;
      this.notify("pending", "Validating and committing first-run setup\u2026");
      let submitted = false;
      try {
        const payload = readSetupForm(setupForm);
        this.stopPolling();
        submitted = true;
        const response = await api.applySetup(payload);
        setupForm
          .querySelectorAll<HTMLInputElement>(
            'input[type="password"], input[name="enrollment_token"], textarea[name="server_ca_pem"]',
          )
          .forEach((input) => {
            input.value = "";
          });
        this.showNetworkTransition(
          true,
          true,
          response.reboot_queued !== false ||
            response.network_apply_queued === true,
        );
        this.notify(
          "success",
          "First-run setup was saved. The device is applying its network settings.",
        );
      } catch (error) {
        if (submitted && !(error instanceof api.ApiError)) {
          this.showNetworkTransition(false, true);
          this.notify(
            "info",
            "The connection closed after setup submission. The device may be applying the saved settings.",
          );
          return;
        }
        this.startPolling();
        if (submit) submit.disabled = false;
        const message = this.errorMessage(error, "First-run setup failed.");
        result.textContent = message;
        this.notify("error", `First-run setup failed: ${message}`);
      }
    });
    const reenrollmentForm =
      this.root.querySelector<HTMLFormElement>("#reenrollment-form");
    reenrollmentForm?.addEventListener("input", () => {
      this.setupFormDirty = true;
    });
    reenrollmentForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const result = this.root.querySelector<HTMLElement>(
        "#reenrollment-result",
      );
      const input = reenrollmentForm.elements.namedItem(
        "enrollment_token",
      ) as HTMLInputElement;
      if (!result) return;
      const submit = reenrollmentForm.querySelector<HTMLButtonElement>(
        'button[type="submit"]',
      );
      if (!reenrollmentForm.reportValidity()) {
        this.notify(
          "error",
          "Reenrollment token must contain 32 through 256 characters.",
        );
        return;
      }
      if (
        destructiveConfirmation(
          "credential revocation and reenrollment",
          "REENROLL",
        ) === null
      ) {
        this.notify(
          "info",
          "Reenrollment was cancelled. Existing credentials were not changed.",
        );
        return;
      }
      const elevated = await this.requestElevation(
        "credential revocation and reenrollment",
      );
      if (!elevated) {
        this.notify(
          "info",
          "Reenrollment was cancelled. Existing credentials were not changed.",
        );
        return;
      }
      this.notify(
        "pending",
        "Revoking existing server credentials and queuing reenrollment\u2026",
      );
      this.setupFormDirty = true;
      this.stopPolling();
      if (submit) {
        submit.disabled = true;
        submit.setAttribute("aria-busy", "true");
      }
      try {
        await api.beginReenrollment(input.value);
        input.value = "";
        this.setupFormDirty = false;
        await this.refresh();
        this.startPolling();
        const refreshedResult = this.root.querySelector<HTMLElement>(
          "#reenrollment-result",
        );
        if (refreshedResult) {
          refreshedResult.textContent =
            "Existing server credentials were revoked. Enrollment is pending.";
        }
        this.notify(
          "success",
          "Existing credentials were revoked and reenrollment was queued.",
        );
      } catch (error) {
        this.startPolling();
        input.value = "";
        if (submit) {
          submit.disabled = false;
          submit.removeAttribute("aria-busy");
        }
        const message = this.errorMessage(error, "Reenrollment failed.");
        result.textContent = message;
        this.notify("error", `Reenrollment failed: ${message}`);
      } finally {
        this.finishPrivilegedOperation();
      }
    });
  }

  private showNetworkTransition(
    confirmed: boolean,
    firstRun: boolean,
    automaticTransition = true,
  ): void {
    this.provisioningComplete = true;
    this.stopPolling();
    window.clearTimeout(this.sessionTimer);
    this.root.innerHTML = renderShell();
    this.root.querySelector("nav")?.remove();
    this.root.querySelector("#banner-region")?.remove();
    this.bindShell();
    const main = this.root.querySelector<HTMLElement>("#main");
    if (!main) return;
    const hostname = this.config?.hostname
      ? `http://${this.config.hostname}.local/`
      : "the address assigned by your router";
    const heading = confirmed
      ? firstRun
        ? "Setup saved"
        : "Network/server settings saved"
      : "Connection closed after submission";
    const networkDescription = firstRun
      ? "Its temporary setup network will close."
      : "Its Wi-Fi connection and local address may change.";
    const transitionDescription = automaticTransition
      ? "The sensor is applying the network settings"
      : "The settings were saved, but automatic application could not be queued; power-cycle the sensor to apply them";
    main.innerHTML = `<section class="panel" aria-labelledby="setup-saved-title">
      <p class="eyebrow">${firstRun ? "First-run setup" : "Network settings"}</p><h2 id="setup-saved-title">${heading}</h2>
      <p>${confirmed ? transitionDescription : "The sensor may have saved the settings and started applying them"}. ${networkDescription}</p>
      <ol><li>Reconnect this phone or computer to your normal Wi-Fi network.</li>
      <li>Wait about 30 seconds.</li><li>Open <code id="configured-device-address"></code>, or find the sensor's DHCP address in your router.</li></ol>
      <p>If the <code>PowerMonitor-Setup-xxxxxx</code> network returns after about 60 seconds, the station connection failed. Rejoin it, reopen this page, and correct the SSID, password, or IP settings.</p>
      <p>This page will remain still while the sensor changes networks.</p></section>`;
    const address = this.root.querySelector<HTMLElement>(
      "#configured-device-address",
    );
    if (address) address.textContent = hostname;
  }
}

const root = document.querySelector<HTMLElement>("#app");
if (root) new App(root).start();
