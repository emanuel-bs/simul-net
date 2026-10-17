import { createRequire } from 'node:module';
import { expect, test, type Page } from '@playwright/test';
import { SIMS } from '../src/sims/registry';

// Contraste de cores (WCAG AA) medido no Chrome real, que o axe não consegue medir no jsdom.
// Hub: páginas principais nos temas claro e escuro. Simuladores nativos: cada modo, uma amostra dos cenários, todas as abas.

const natives = SIMS.filter((s) => s.status === 'available' && s.engine === 'nativo');
const AXE = createRequire(import.meta.url).resolve('axe-core/axe.min.js');

async function contrast(page: Page): Promise<string[]> {
  await page.addScriptTag({ path: AXE });
  return page.evaluate(async () => {
    const r = await (window as any).axe.run(document, { runOnly: ['color-contrast'] });
    return r.violations.flatMap((v: any) => v.nodes.map((n: any) => `${n.target.join(' ')}: ${n.any[0]?.data ? n.any[0].data.fgColor + ' sobre ' + n.any[0].data.bgColor + ' = ' + n.any[0].data.contrastRatio : ''}`));
  });
}

for (const theme of ['dark', 'light']) {
  test(`o hub tem contraste suficiente no tema ${theme}`, async ({ page }) => {
    await page.route(/fonts\.(googleapis|gstatic)\.com/, (r) => r.abort());
    await page.addInitScript((t) => localStorage.setItem('simulnet-theme', t), theme);
    for (const path of ['#/', '#/categoria/camada-de-rede', '#/categoria/transporte', '#/categoria/protocolos-seguros']) {
      await page.goto(path);
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
      expect(await contrast(page), `contraste em ${path} (${theme})`).toEqual([]);
    }
  });
}

for (const sim of natives) {
  test(`${sim.id}: contraste suficiente em todos os modos e abas`, async ({ page }) => {
    test.setTimeout(240_000);
    await page.route(/fonts\.(googleapis|gstatic)\.com/, (r) => r.abort());
    await page.goto(`#/sim/${sim.id}`);
    await page.waitForSelector('.simnet .scen-row button.chip');
    const modes = page.locator('.simnet .topbar [aria-label="Modo de simulação"] button');
    const modeCount = (await modes.count()) || 1;
    const found = new Set<string>();
    for (let m = 0; m < modeCount; m++) {
      if ((await modes.count()) > 1) await modes.nth(m).click();
      const chips = page.locator('.simnet .scen-row button.chip');
      const n = await chips.count();
      // primeiro, último e um a cada três: cobre os estados de aviso, falha e sucesso sem rodar tudo
      for (let i = 0; i < n; i++) {
        if (i !== 0 && i !== n - 1 && i % 3 !== 0) continue;
        await chips.nth(i).click();
        for (let k = 0; k < 30; k++) await page.getByRole('button', { name: 'Passo' }).click();
        const tabs = page.getByRole('tab');
        const t = await tabs.count();
        for (let j = 0; j < t; j++) {
          await tabs.nth(j).click();
          (await contrast(page)).forEach((x) => found.add(x));
        }
      }
    }
    expect(Array.from(found), `contraste em ${sim.id}`).toEqual([]);
  });
}
