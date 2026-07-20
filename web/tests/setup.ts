import { afterEach, vi } from "vitest";

afterEach(() => {
  document.body.innerHTML = '<div id="app"></div>';
  vi.unstubAllGlobals();
});

