import { defineConfig } from '@playwright/test';

/**
 * Single-project API-test config. No browser UI is driven — every spec uses
 * Playwright's APIRequestContext (the `request` fixture) to exercise the
 * Keycloak Admin REST API directly. The IGA capture is enforced at the model
 * layer, so raw REST exercises the exact production path a real admin tool hits.
 */
export default defineConfig({
  testDir: './tests',
  // IGA flows (realm create/delete, governed creates, authorize+commit) are
  // sequential by nature; keep it deterministic.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  timeout: 120_000,
  expect: { timeout: 15_000 },
  use: {
    baseURL: process.env.KC_BASE_URL || 'http://localhost:8080',
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: { Accept: 'application/json' },
  },
  projects: [{ name: 'iga-api' }],
});
