import { expect, test } from '@playwright/test';
import { findSim } from '../src/sims/registry';

// Regressão do NC-22: a navegação direta de um simulador para outro mudava o endereço, mas a tela continuava no anterior.

async function abre(page: import('@playwright/test').Page, id: string) {
  await page.route(/fonts\.(googleapis|gstatic)\.com/, (r) => r.abort());
  await page.goto(`#/sim/${id}`);
  await page.waitForSelector('.simnet .scen-row button.chip');
}

test('trocar o endereço de um simulador para outro atualiza a tela', async ({ page }) => {
  await abre(page, 'tcp');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('TCP');
  await page.evaluate(() => {
    location.hash = '#/sim/udp';
  });
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('UDP', { timeout: 15_000 });
  await page.waitForSelector('.simnet .scen-row button.chip');
});

test('o link real da aba Referência do TCP abre o simulador de ataques', async ({ page }) => {
  await abre(page, 'tcp');
  await page.getByRole('tab', { name: 'Referência' }).click();
  await page.locator('a[href="#/sim/ataques-tcp-udp"]').first().click();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(findSim('ataques-tcp-udp')!.title, { timeout: 15_000 });
  await expect(page).toHaveURL(/#\/sim\/ataques-tcp-udp$/);
  await page.waitForSelector('.simnet .scen-row button.chip');
});

test('voltar no histórico retorna ao simulador anterior', async ({ page }) => {
  await abre(page, 'tcp');
  await page.evaluate(() => {
    location.hash = '#/sim/udp';
  });
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('UDP', { timeout: 15_000 });
  await page.goBack();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('TCP', { timeout: 15_000 });
});
