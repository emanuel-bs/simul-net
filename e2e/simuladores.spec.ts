import { expect, test, type Locator, type Page } from '@playwright/test';
import { SIMS } from '../src/sims/registry';

// Para cada simulador disponível no registro (um simulador novo entra automaticamente):
//  1. percorre todos os modos e todos os cenários prontos, usando os botões de ação e abrindo todas as abas;
//  2. falha se houver erro de JavaScript;
//  3. confere o layout da bancada de trabalho e o ciclo destacar e encaixar dos quadros.

const available = SIMS.filter((s) => s.status === 'available' && s.file);

// Botões que reiniciam ou interrompem a simulação não entram na rodada de cliques.
const SKIP = /reset|restart|stop|pause|clear|reinici|parar|pausar|limpar/i;

function watchErrors(page: Page) {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() !== 'error') return;
    const t = m.text();
    if (/Failed to load resource|ERR_|fonts\.(googleapis|gstatic)/.test(t)) return; // fontes externas e recursos de rede
    errors.push(`console.error: ${t}`);
  });
  return errors;
}

async function open(page: Page, file: string) {
  // As fontes vêm do Google Fonts: bloqueadas, o teste não depende de rede externa.
  await page.route(/fonts\.(googleapis|gstatic)\.com/, (r) => r.abort());
  await page.goto(`sims/${file}`);
  await page.waitForSelector('#scenRow button.chip');
  // velocidade máxima: as simulações assíncronas (ICMP, ataques) terminam logo
  await page.evaluate(() => {
    const s = document.querySelector<HTMLSelectElement>('#speedSelect');
    if (s) {
      s.selectedIndex = s.options.length - 1;
      s.dispatchEvent(new Event('change', { bubbles: true }));
    }
  });
}

/** Clica nos botões de ação várias vezes (avançar fase, passo, executar...) e depois abre todas as abas. */
async function exercise(page: Page) {
  await page.evaluate((skip) => {
    const re = new RegExp(skip, 'i');
    const btns = [...document.querySelectorAll<HTMLButtonElement>('.play-bar button')].filter((b) => !re.test(`${b.id} ${b.textContent}`));
    for (let i = 0; i < 60; i++) for (const b of btns) if (!b.disabled) b.click();
  }, SKIP.source);
  await page.waitForTimeout(120);
  // enquanto uma execução assíncrona está em curso os chips ficam desabilitados: espera terminar
  await page.waitForFunction(() => !document.querySelector('#scenRow button.chip:disabled'), null, { timeout: 40_000 });
  await page.evaluate(() => {
    document.querySelectorAll<HTMLButtonElement>('.tab-btn').forEach((b) => {
      if (!b.classList.contains('hidden')) b.click();
    });
  });
}

/** Cada seletor de modo (protocolo e aplicação) é percorrido; depois, todos os chips de cenário de cada modo. */
async function forEachMode(page: Page, fn: () => Promise<void>) {
  const visible = async (l: Locator) => (await l.count()) > 0 && !(await l.first().evaluate((e) => e.classList.contains('hidden')));
  const proto = page.locator('#protoSeg button');
  const sub = page.locator('#subSeg button');
  const protoCount = (await visible(page.locator('#protoSeg'))) ? await proto.count() : 1;
  for (let p = 0; p < protoCount; p++) {
    if (protoCount > 1) await proto.nth(p).click();
    const subCount = (await visible(page.locator('#subSeg'))) ? await sub.count() : 1;
    for (let s = 0; s < subCount; s++) {
      if (subCount > 1) await sub.nth(s).click();
      await fn();
    }
  }
}

for (const sim of available) {
  test.describe(`${sim.id}`, () => {
    test('todos os cenários rodam sem erro de JavaScript', async ({ page }) => {
      test.setTimeout(300_000);
      const errors = watchErrors(page);
      await open(page, sim.file!);
      let scenarios = 0;
      await forEachMode(page, async () => {
        const chips = page.locator('#scenRow button.chip');
        const n = await chips.count();
        for (let i = 0; i < n; i++) {
          await chips.nth(i).click();
          await exercise(page);
          scenarios++;
        }
      });
      expect(scenarios, 'o simulador precisa ter cenários prontos').toBeGreaterThan(0);
      expect(errors).toEqual([]);
    });

    test('a bancada cabe na tela e os quadros destacam e encaixam', async ({ page }) => {
      const errors = watchErrors(page);
      for (const size of [{ width: 1366, height: 768 }, { width: 1600, height: 900 }]) {
        await page.setViewportSize(size);
        await open(page, sim.file!);
        const overflow = await page.evaluate(() => ({
          h: document.documentElement.scrollHeight - window.innerHeight,
          w: document.documentElement.scrollWidth - window.innerWidth,
        }));
        expect(overflow.h, `rolagem vertical da página em ${size.width}x${size.height}`).toBeLessThanOrEqual(1);
        expect(overflow.w, `rolagem horizontal da página em ${size.width}x${size.height}`).toBeLessThanOrEqual(1);
      }
      // destacar e encaixar: cada quadro volta exatamente à posição de origem
      const panels = ['.stage-panel', '.tabs-panel', '.side-col > .fpanel', 'details.cfg'];
      for (const sel of panels) {
        const el = page.locator(sel).first();
        if ((await el.count()) === 0) continue;
        const before = await el.boundingBox();
        const toggle = el.locator('.fbtn', { hasText: /Destacar|Encaixar/ }).first();
        await toggle.click();
        await expect(el).toHaveClass(/is-floating/);
        await toggle.click();
        await expect(el).not.toHaveClass(/is-floating/);
        expect(await el.boundingBox(), `posição de ${sel} depois de encaixar`).toEqual(before);
      }
      expect(errors).toEqual([]);
    });
  });
}
