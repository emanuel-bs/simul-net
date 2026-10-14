import { defineConfig } from '@playwright/test';

// Testes de ponta a ponta: abrem o site publicado localmente (vite preview sobre dist/) em um Chrome real.
// Uso local: npm run build && npm run test:e2e
// No GitHub Actions o build usa VITE_BASE=/Simul-Net/ e a variável E2E_BASE acompanha esse caminho.
const base = process.env.E2E_BASE || '/';
const port = 4173;

export default defineConfig({
  testDir: 'e2e',
  timeout: 120_000,
  expect: { timeout: 10_000 },
  fullyParallel: true,
  workers: process.env.CI ? 4 : undefined,
  maxFailures: process.env.CI ? 8 : 0,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: `http://localhost:${port}${base}`,
    // Usa o Chrome já instalado (no GitHub Actions e na máquina local), sem baixar navegadores.
    channel: 'chrome',
    viewport: { width: 1600, height: 900 },
    trace: 'retain-on-failure',
  },
  webServer: {
    command: `npm run preview -- --port ${port} --strictPort`,
    // o preview lê o caminho base da configuração do Vite, então precisa da mesma variável do build
    env: { VITE_BASE: base },
    url: `http://localhost:${port}${base}`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
