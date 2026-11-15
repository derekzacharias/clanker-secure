import { expect, test } from '@playwright/test';
import { stubApi } from './fixtures';

/**
 * Surface hierarchy and code-block styling.
 *
 * These assertions are about contrast, not pixels: a content panel must differ from
 * the page background, a nested panel must differ from its parent, and any code
 * block must use the code surface from the theme — so "everything is one flat
 * surface" or "code looks like prose" regressions fail here.
 */
test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem('clanker_access_token', 'test-token');
    localStorage.setItem('clanker_refresh_token', 'test-refresh');
  });
  await stubApi(page);
});

async function parser(css: string) {
  // "rgb(11, 18, 32)" → [11,18,32]
  return css.match(/\d+/g)?.slice(0, 3).map(Number) ?? [0, 0, 0];
}

function distance(a: number[], b: number[]) {
  return Math.abs(a[0] - b[0]) + Math.abs(a[1] - b[1]) + Math.abs(a[2] - b[2]);
}

for (const scheme of ['dark', 'light'] as const) {
  test(`panels are distinct from the page background (${scheme})`, async ({ page, isMobile }) => {
    await page.addInitScript((value) => localStorage.setItem('clanker-color-scheme', value), scheme);
    await page.goto('/app/');
    await expect(page.locator('html')).toHaveAttribute('data-mantine-color-scheme', scheme);

    const colours = await page.evaluate(() => {
      const read = (el: Element | null) => (el ? getComputedStyle(el).backgroundColor : '');
      const cards = Array.from(document.querySelectorAll('.mantine-Card-root, .mantine-Paper-root'));
      return {
        body: read(document.body),
        firstCard: cards.length ? read(cards[0]) : '',
        cards: cards.length,
      };
    });
    expect(colours.cards).toBeGreaterThan(0);
    const bg = await parser(colours.body);
    const panel = await parser(colours.firstCard);
    // A content panel must be visibly a different surface than the page.
    expect(distance(bg, panel)).toBeGreaterThan(6);

    // Screenshot for visual review (desktop and mobile).
    await page.screenshot({ path: `e2e/.artifacts/surfaces-${scheme}-${isMobile ? 'mobile' : 'desktop'}.png`, fullPage: true });
  });
}

test('raw scanner output renders as a labelled, copyable code block', async ({ page }) => {
  await page.goto('/app/');
  // Navigation is a sidebar on wide viewports and a drawer below Mantine's md
  // breakpoint, so open the drawer first there.
  const narrow = (page.viewportSize()?.width ?? 1440) < 992;
  const nav = narrow ? page.getByRole('dialog') : page.getByRole('navigation').first();
  if (narrow) await page.getByRole('button', { name: 'Open navigation' }).click();
  await nav.getByRole('link', { name: 'Findings' }).click();
  await page.waitForURL(/\/findings$/);
  // The group is rendered per host; open the details of the first finding, whose
  // drawer repeats the raw output as a code block.
  // The host group renders one block per group; the drawer repeats it. Either is
  // fine — assert the first visible one.
  const code = page.locator('pre[aria-label="Nmap output"]').first();
  await expect(code).toBeVisible({ timeout: 10000 });

  const bg = await code.evaluate((el) => getComputedStyle(el).backgroundColor);
  const pageBg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  expect(distance(await parser(bg), await parser(pageBg))).toBeGreaterThan(6);

  // Copy button reports its own state. Grant the clipboard permission the way a
  // real browser does for a user-initiated copy; without it the component falls
  // back to selecting the text and says "Ctrl+C".
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.getByRole('button', { name: /Copy to clipboard/i }).first().click();
  await expect(page.getByText(/Copied/i).first()).toBeVisible();
  const clipboard = await page.evaluate(() => navigator.clipboard.readText());
  expect(clipboard).toContain('22/tcp open');
});
