import { expect, test } from '@playwright/test';
import { CATEGORIES, SIMS } from '../src/sims/registry';

// O hub: página inicial, categorias e a página de cada simulador (que incorpora a página legada por iframe).

test('a página inicial lista as categorias e os simuladores disponíveis', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto('./#/');
  await expect(page.getByRole('heading', { level: 1, name: 'Simul-Net' })).toBeVisible();
  for (const c of CATEGORIES) await expect(page.getByRole('heading', { level: 3, name: c.title })).toBeVisible();
  const available = SIMS.filter((s) => s.status === 'available');
  await expect(page.getByRole('link', { name: /Abrir simulador/ })).toHaveCount(available.length);
  expect(errors).toEqual([]);
});

for (const sim of SIMS.filter((s) => s.status === 'available')) {
  test(`o hub incorpora o simulador ${sim.id}`, async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(e.message));
    await page.route(/fonts\.(googleapis|gstatic)\.com/, (r) => r.abort());
    await page.goto(`./#/sim/${sim.id}`);
    const frame = page.frameLocator(`iframe[title="Simulador: ${sim.title}"]`);
    await expect(frame.locator('.stage-panel')).toBeVisible();
    await expect(frame.locator('#scenRow button.chip').first()).toBeVisible();
    // dentro do hub o simulador esconde o "Voltar" e o título, que o hub já mostra
    await expect(frame.locator('.back-link')).toBeHidden();
    expect(errors).toEqual([]);
  });
}

test('o endereço antigo do simulador de protocolos seguros leva à categoria', async ({ page }) => {
  await page.goto('./#/sim/protocolos-seguros');
  await expect(page).toHaveURL(/#\/categoria\/protocolos-seguros$/);
});
