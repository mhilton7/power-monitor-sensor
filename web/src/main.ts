import "./style.css";
import * as api from "./api";
import {
  destructiveConfirmation,
  readConfigForm,
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
  private authenticated = false;
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

  constructor(private readonly root: HTMLElement) {}

  start(): void {
    this.root.innerHTML = renderShell(false);
    this.bindLogin();
  }

  private bindLogin(): void {
    const form = this.root.querySelector<HTMLFormElement>("#login-form");
    form?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const input = form.elements.namedItem("password") as HTMLInputElement;
      const error = this.root.querySelector<HTMLElement>("#login-error");
      try {
        const login = await api.login(input.value);
        input.value = "";
        this.authenticated = true;
        this.setupRequired = login.setupRequired;
        this.view = login.setupRequired ? "setup" : "status";
        this.sessionTimer = window.setTimeout(() => void this.signOut(), login.expiresInSeconds * 1000);
        await this.load();
      } catch (caught) {
        input.value = "";
        if (error) {
          error.hidden = false;
          error.textContent = caught instanceof Error ? caught.message : "Sign-in failed.";
        }
      }
    });
  }

  private async load(): Promise<void> {
    this.root.innerHTML = renderShell(true);
    this.bindShell();
    await this.refresh();
    this.pollTimer = window.setInterval(() => void this.refresh(), 5000);
  }

  private bindShell(): void {
    this.root.querySelectorAll<HTMLButtonElement>("[data-view]").forEach((button) => {
      button.addEventListener("click", () => {
        this.view = button.dataset.view as View;
        this.renderView();
        this.root.querySelector<HTMLElement>("#main")?.focus();
      });
    });
    this.root.querySelector("#logout")?.addEventListener("click", () => void this.signOut());
    this.root.querySelector("#theme-toggle")?.addEventListener("click", () => {
      document.documentElement.dataset.theme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    });
  }

  private async refresh(): Promise<void> {
    try {
      [this.health, this.live, this.config, this.storage, this.metrics, this.otaStatus, this.events] = await Promise.all([
        api.getHealth(), api.getLive(), api.getConfig(), api.getStorage(), api.getMetrics(),
        api.getOtaStatus(), api.getEvents(),
      ]);
      this.renderView();
    } catch (error) {
      if (error instanceof api.ApiError && error.status === 401) {
        await this.signOut();
      } else {
        const banner = this.root.querySelector<HTMLElement>("#banner-region");
        if (banner) banner.innerHTML = `<div class="banner warning" role="alert">Refresh failed. The device may be busy or reconnecting.</div>`;
      }
    }
  }

  private renderView(): void {
    if (!this.health || !this.live || !this.config) return;
    const banners = this.root.querySelector<HTMLElement>("#banner-region");
    if (banners) banners.innerHTML = renderBanners(this.health);
    const main = this.root.querySelector<HTMLElement>("#main");
    if (!main) return;
    switch (this.view) {
      case "status": main.innerHTML = renderStatus(this.health, this.live); break;
      case "storage": main.innerHTML = renderStorage(this.health, this.storage); break;
      case "network": main.innerHTML = renderNetwork(this.health, this.config); break;
      case "meter": main.innerHTML = renderMeter(this.health, this.live, this.config); break;
      case "maintenance": main.innerHTML = renderMaintenance(this.metrics, this.otaStatus, this.events); break;
      case "setup": main.innerHTML = renderSetup(this.config, this.setupRequired); break;
    }
    this.bindViewActions();
  }

  private bindViewActions(): void {
    this.root.querySelectorAll<HTMLButtonElement>("[data-action]").forEach((button) => {
      button.addEventListener("click", async () => {
        const action = button.dataset.action ?? "";
        const phrase = button.dataset.destructive;
        const confirmation = phrase ? destructiveConfirmation(action, phrase) : undefined;
        if (phrase && !confirmation) return;
        button.disabled = true;
        try { await api.runAction(action, confirmation ?? undefined); } finally { button.disabled = false; }
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
        const blob = await api.exportHistory(sequence, toUtc(data.get("from_utc")), toUtc(data.get("to_utc")));
        const href = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = href;
        link.download = `power-monitor-readings-after-${Math.max(0, Math.trunc(sequence))}.ndjson`;
        link.click();
        URL.revokeObjectURL(href);
        result.textContent = "Export downloaded. Continue from the last sequence for another page.";
      } catch (error) {
        result.textContent = error instanceof Error ? error.message : "History export failed.";
      }
    });
    const form = this.root.querySelector<HTMLFormElement>("#config-form");
    form?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const result = this.root.querySelector<HTMLElement>("#config-result");
      if (!this.config || !result) return;
      try {
        const candidate = readConfigForm(form, this.config);
        await api.updateConfig(candidate.config, candidate.ctAcknowledged);
        result.textContent = "Configuration validated and applied.";
        await this.refresh();
      } catch (error) {
        result.textContent = error instanceof Error ? error.message : "Configuration failed.";
      }
    });
    const setupForm = this.root.querySelector<HTMLFormElement>("#first-run-form");
    setupForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const result = this.root.querySelector<HTMLElement>("#setup-result");
      if (!result) return;
      try {
        await api.applySetup(readSetupForm(setupForm));
        setupForm.querySelectorAll<HTMLInputElement>('input[type="password"], input[name="enrollment_token"], textarea[name="server_ca_pem"]').forEach((input) => { input.value = ""; });
        result.textContent = "Setup committed. The sensor is rebooting to join Wi-Fi and enroll.";
      } catch (error) {
        result.textContent = error instanceof Error ? error.message : "First-run setup failed.";
      }
    });
    const reenrollmentForm = this.root.querySelector<HTMLFormElement>("#reenrollment-form");
    reenrollmentForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const result = this.root.querySelector<HTMLElement>("#reenrollment-result");
      const input = reenrollmentForm.elements.namedItem("enrollment_token") as HTMLInputElement;
      if (!result || destructiveConfirmation("credential revocation and reenrollment", "REENROLL") === null) return;
      try {
        await api.beginReenrollment(input.value);
        input.value = "";
        result.textContent = "Existing server credentials were revoked. Enrollment is pending.";
      } catch (error) {
        input.value = "";
        result.textContent = error instanceof Error ? error.message : "Reenrollment failed.";
      }
    });
  }

  private async signOut(): Promise<void> {
    window.clearInterval(this.pollTimer);
    window.clearTimeout(this.sessionTimer);
    if (this.authenticated) await api.logout().catch(() => undefined);
    this.authenticated = false;
    this.health = undefined;
    this.live = undefined;
    this.config = undefined;
    this.setupRequired = false;
    this.root.innerHTML = renderShell(false);
    this.bindLogin();
  }
}

const root = document.querySelector<HTMLElement>("#app");
if (root) new App(root).start();
