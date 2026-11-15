import { defineConfig, devices } from '@playwright/test';

/**
 * Browser-level checks for the console.
 *
 * The FastAPI backend is not required for these specs: every API call is stubbed
 * with `page.route` inside the tests, which is also what lets them run without a
 * database or nmap. The stubs live in `e2e/fixtures.ts` — production views never
 * contain fake data.
 */
export default defineConfig({
  testDir: './e2e',
  outputDir: './e2e/.artifacts',
  timeout: 30_000,
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  use: {
    // The SPA is mounted under /app/ in production; previewing with the same base
    // keeps the bundle at /app/assets/* and the API at /assets/*, so stubs can
    // intercept API calls without swallowing JavaScript.
    baseURL: 'http://127.0.0.1:4173/app/',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } } },
    { name: 'tablet', use: { ...devices['Desktop Chrome'], viewport: { width: 834, height: 1112 } } },
    { name: 'mobile', use: { ...devices['Pixel 7'] } },
  ],
  webServer: {
    command: 'npm run preview -- --port 4173 --strictPort --base=/app/',
    url: 'http://127.0.0.1:4173/app/',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
