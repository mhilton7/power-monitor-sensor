import { afterEach, vi } from "vitest";

afterEach(() => {
  vi.clearAllTimers();
  vi.useRealTimers();
  document.body.innerHTML = '<div id="app"></div>';
  vi.unstubAllGlobals();
});
