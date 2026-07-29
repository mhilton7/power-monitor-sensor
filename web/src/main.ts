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
  private refreshWarning = "";
  private bannerHtml = "";

  constructor(private readonly root: HTMLElement) {}

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
    if (this.provisioningComplete) return;
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
        api.getEvents(),
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
      if (results[6].status === "fulfilled") this.events = results[6].value;

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
    } finally {
      this.refreshInProgress = false;
    }
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
          const phrase = button.dataset.destructive;
          const confirmation = phrase
            ? destructiveConfirmation(action, phrase)
            : undefined;
          if (phrase && !confirmation) return;
          button.disabled = true;
          try {
            await api.runAction(action, confirmation ?? undefined);
          } finally {
            button.disabled = false;
          }
        });
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
        result.textContent = "Preparing a bounded NDJSON page…";
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
      } catch (error) {
        result.textContent =
          error instanceof Error ? error.message : "History export failed.";
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
      try {
        const candidate = readConfigForm(form, this.config);
        this.stopPolling();
        await api.updateConfig(candidate.config, candidate.ctAcknowledged);
        this.setupFormDirty = false;
        await this.refresh();
        this.startPolling();
        const refreshedResult =
          this.root.querySelector<HTMLElement>("#config-result");
        if (refreshedResult)
          refreshedResult.textContent = "Configuration validated and applied.";
      } catch (error) {
        this.startPolling();
        if (submit) submit.disabled = false;
        result.textContent =
          error instanceof Error ? error.message : "Configuration failed.";
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
      try {
        const payload = readNetworkSettingsForm(
          networkSettingsForm,
          this.config,
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
      } catch (error) {
        if (submitted && !(error instanceof api.ApiError)) {
          this.showNetworkTransition(false, false);
          return;
        }
        this.startPolling();
        if (submit) submit.disabled = false;
        result.textContent =
          error instanceof Error
            ? error.message
            : "Network/server settings failed.";
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
      } catch (error) {
        if (submitted && !(error instanceof api.ApiError)) {
          this.showNetworkTransition(false, true);
          return;
        }
        this.startPolling();
        if (submit) submit.disabled = false;
        result.textContent =
          error instanceof Error ? error.message : "First-run setup failed.";
      }
    });
    const reenrollmentForm =
      this.root.querySelector<HTMLFormElement>("#reenrollment-form");
    reenrollmentForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const result = this.root.querySelector<HTMLElement>(
        "#reenrollment-result",
      );
      const input = reenrollmentForm.elements.namedItem(
        "enrollment_token",
      ) as HTMLInputElement;
      if (
        !result ||
        destructiveConfirmation(
          "credential revocation and reenrollment",
          "REENROLL",
        ) === null
      )
        return;
      try {
        await api.beginReenrollment(input.value);
        input.value = "";
        result.textContent =
          "Existing server credentials were revoked. Enrollment is pending.";
      } catch (error) {
        input.value = "";
        result.textContent =
          error instanceof Error ? error.message : "Reenrollment failed.";
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
