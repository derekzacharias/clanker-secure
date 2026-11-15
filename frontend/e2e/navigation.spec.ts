import { expect, test } from '@playwright/test';
import { stubApi, user } from './fixtures';

/**
 * Navigation, theming and responsive shell.
 *
 * Auth is satisfied by stubbing /auth/me; the bearer token is set before the app
 * boots so the guard renders the console instead of the sign-in screen.
 */

/** Navigation lives in the sidebar at >=992px (Mantine's md breakpoint), else a drawer. */
function inDrawer(page: import('@playwright/test').Page) {
  return (page.viewportSize()?.width ?? 1440) < 992;
}

async function openNav(page: import('@playwright/test').Page) {
  if (!inDrawer(page)) return page.getByRole('navigation').first();
  await page.getByRole('button', { name: 'Open navigation' }).click();
  const drawer = page.getByRole('dialog');
  await expect(drawer).toBeVisible();
  return drawer;
}

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem('clanker_access_token', 'test-token');
    localStorage.setItem('clanker_refresh_token', 'test-refresh');
  });
  await stubApi(page);
});

test('loads the console with persistent navigation', async ({ page }) => {
  await page.goto('/app/');
  await expect(page.getByRole('heading', { level: 1, name: /Overview/i })).toBeVisible();
  const nav = await openNav(page);
  for (const label of ['Overview', 'Assets', 'Scans', 'Findings', 'Reports']) {
    await expect(nav.getByRole('link', { name: label })).toBeVisible();
  }
});

test('navigation updates the URL and the back button restores the previous view', async ({ page }) => {
  await page.goto('/app/');

  await (await openNav(page)).getByRole('link', { name: 'Findings' }).click();
  await expect(page).toHaveURL(/\/findings$/);
  await expect(page.getByRole('heading', { level: 1, name: /Findings/i })).toBeVisible();

  await (await openNav(page)).getByRole('link', { name: 'Assets' }).click();
  await expect(page).toHaveURL(/\/assets$/);

  await page.goBack();
  await expect(page).toHaveURL(/\/findings$/);
  await page.goForward();
  await expect(page).toHaveURL(/\/assets$/);
});

test('shows the operator identity and role', async ({ page }) => {
  await page.goto('/app/');
  if (inDrawer(page)) {
    const drawer = await openNav(page);
    await expect(drawer.getByText(new RegExp(user.email.replace('.', '\\.')))).toBeVisible();
    return;
  }
  await page.getByRole('button', { name: 'Account menu' }).click();
  await expect(page.getByText(user.email)).toBeVisible();
  await expect(page.getByText(/Administrator/i)).toBeVisible();
});

test('theme toggle switches the colour scheme and persists', async ({ page }) => {
  await page.goto('/app/');
  const html = page.locator('html');
  const initial = (await html.getAttribute('data-mantine-color-scheme')) ?? 'dark';
  const target = initial === 'dark' ? 'light' : 'dark';

  if (inDrawer(page)) {
    const drawer = await openNav(page);
    await drawer.getByText(new RegExp(`Use ${target} theme`, 'i')).click();
  } else {
    await page.getByRole('button', { name: 'Account menu' }).click();
    await page.getByRole('menuitem', { name: new RegExp(`Use ${target} theme`, 'i') }).click();
  }
  await expect(html).toHaveAttribute('data-mantine-color-scheme', initial === 'dark' ? 'light' : 'dark');

  await page.reload();
  await expect(html).toHaveAttribute('data-mantine-color-scheme', initial === 'dark' ? 'light' : 'dark');
});

test('mobile: navigation lives in a drawer', async ({ page }) => {
  test.skip(!inDrawer(page), 'narrow viewports only');
  await page.goto('/app/');
  // Narrow viewports get a burger instead of a persistent sidebar (the sidebar is
  // off-canvas rather than absent, so assert the control the operator uses).
  await expect(page.getByRole('button', { name: 'Open navigation' })).toBeVisible();
  const drawer = await openNav(page);
  await drawer.getByRole('link', { name: 'Findings' }).click();
  await expect(page).toHaveURL(/\/findings$/);
});

test('captures reference screenshots', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop' && testInfo.project.name !== 'mobile', 'desktop + mobile only');
  for (const scheme of ['dark', 'light'] as const) {
    await page.addInitScript((value) => localStorage.setItem('clanker-color-scheme', value), scheme);
    await page.goto('/app/');
    await expect(page.locator('html')).toHaveAttribute('data-mantine-color-scheme', scheme);
    await page.screenshot({ path: `e2e/.artifacts/${testInfo.project.name}-overview-${scheme}.png`, fullPage: true });

    await (await openNav(page)).getByRole('link', { name: 'Findings' }).click();
    await page.waitForURL(/\/findings$/);
    await page.screenshot({ path: `e2e/.artifacts/${testInfo.project.name}-findings-${scheme}.png`, fullPage: true });
  }
});
