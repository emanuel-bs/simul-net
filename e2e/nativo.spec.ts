import { expect, test, type Page } from '@playwright/test';
import { SIMS } from '../src/sims/registry';

// Para cada simulador nativo do registro: percorre todos os modos e cenários prontos, executa a animação até o fim,
// abre todas as abas e falha se houver erro de JavaScript. Confere também o comportamento de layout da página.

const natives = SIMS.filter((s) => s.status === 'available' && s.engine === 'nativo');

function watchErrors(page: Page) {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() !== 'error') return;
    const t = m.text();
    if (/Failed to load resource|ERR_|fonts\.(googleapis|gstatic)/.test(t)) return;
    errors.push(`console.error: ${t}`);
  });
  return errors;
}

async function open(page: Page, id: string) {
  await page.route(/fonts\.(googleapis|gstatic)\.com/, (r) => r.abort());
  await page.goto(`#/sim/${id}`);
  await page.waitForSelector('.simnet .scen-row button.chip');
}

/** Roda a animação na velocidade máxima até o botão voltar a "Simular", e abre todas as abas. */
async function exercise(page: Page) {
  await page.getByLabel('Velocidade').selectOption({ label: 'Muito rápida' });
  await page.getByRole('button', { name: 'Voltar ao início' }).click();
  await page.getByRole('button', { name: /^(Simular|Continuar)$/ }).click();
  await expect(page.getByRole('button', { name: 'Simular', exact: true })).toBeVisible({ timeout: 30_000 });
  const tabs = page.getByRole('tab');
  const n = await tabs.count();
  for (let i = 0; i < n; i++) await tabs.nth(i).click();
}

// Os cenários são divididos em partes que rodam em paralelo (o de número i vai para a parte i % SHARDS).
const SHARDS = 3;

for (const sim of natives) {
  test.describe(sim.id, () => {
    for (let shard = 0; shard < SHARDS; shard++) {
      test(`todos os cenários rodam sem erro de JavaScript (parte ${shard + 1} de ${SHARDS})`, async ({ page }) => {
        test.setTimeout(240_000);
        const errors = watchErrors(page);
        await open(page, sim.id);
        const modes = page.locator('.simnet .topbar [aria-label="Modo de simulação"] button');
        const modeCount = (await modes.count()) || 1;
        let seen = 0;
        let ran = 0;
        for (let m = 0; m < modeCount; m++) {
          if ((await modes.count()) > 1) await modes.nth(m).click();
          const chips = page.locator('.simnet .scen-row button.chip');
          const n = await chips.count();
          for (let i = 0; i < n; i++) {
            if (seen++ % SHARDS !== shard) continue;
            await chips.nth(i).click();
            await exercise(page);
            ran++;
          }
        }
        if (shard === 0) expect(ran, 'o simulador precisa ter cenários prontos').toBeGreaterThan(0);
        expect(errors).toEqual([]);
      });
    }

    test('a página não rola e o diagrama rola por dentro', async ({ page }) => {
      const errors = watchErrors(page);
      for (const size of [{ width: 1366, height: 768 }, { width: 1600, height: 900 }]) {
        await page.setViewportSize(size);
        await open(page, sim.id);
        const overflow = await page.evaluate(() => ({
          h: document.documentElement.scrollHeight - window.innerHeight,
          w: document.documentElement.scrollWidth - window.innerWidth,
        }));
        expect(overflow.h, `rolagem vertical da página em ${size.width}x${size.height}`).toBeLessThanOrEqual(1);
        expect(overflow.w, `rolagem horizontal da página em ${size.width}x${size.height}`).toBeLessThanOrEqual(1);
      }
      expect(errors).toEqual([]);
    });

    test('os quadros destacam e encaixam na posição de origem, e Esc encaixa', async ({ page }) => {
      const errors = watchErrors(page);
      await page.setViewportSize({ width: 1600, height: 900 });
      await open(page, sim.id);
      for (const sel of ['.stage-panel', '.tabs-panel', '.side-col > .fpanel', '.simnet .cfg']) {
        const el = page.locator(sel).first();
        const before = await el.boundingBox();
        const toggle = el.getByRole('button', { name: /Destacar|Encaixar/ }).first();
        await toggle.click();
        await expect(el).toHaveClass(/is-floating/);
        await toggle.click();
        await expect(el).not.toHaveClass(/is-floating/);
        expect(await el.boundingBox(), `posição de ${sel} depois de encaixar`).toEqual(before);
      }
      // Esc encaixa o quadro flutuante
      const stage = page.locator('.stage-panel');
      await stage.getByRole('button', { name: 'Destacar' }).click();
      await expect(stage).toHaveClass(/is-floating/);
      await page.keyboard.press('Escape');
      await expect(stage).not.toHaveClass(/is-floating/);
      expect(errors).toEqual([]);
    });
  });
}

// Os endereços antigos (arquivos HTML dos simuladores que migraram para o motor nativo) redirecionam para a rota atual.
for (const id of ['ssh', 'https', 'ftp']) {
  test(`o endereço antigo sims/${id}-simulator.html leva ao simulador nativo`, async ({ page }) => {
    await page.route(/fonts\.(googleapis|gstatic)\.com/, (r) => r.abort());
    await page.goto(`sims/${id}-simulator.html`);
    await page.waitForSelector('.simnet .scen-row button.chip');
    expect(page.url()).toMatch(new RegExp(`#/sim/${id}$`));
  });
}
