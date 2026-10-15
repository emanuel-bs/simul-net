// @vitest-environment jsdom
import axe from 'axe-core';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MotionConfig } from 'motion/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it } from 'vitest';
import { AppRoutes } from '../src/App';
import { NATIVE } from '../src/sims/native';
import { SIMS, findSim } from '../src/sims/registry';

afterEach(cleanup);

const natives = SIMS.filter((s) => s.engine === 'nativo');

function renderAt(path: string) {
  return render(
    <MotionConfig reducedMotion="always">
      <MemoryRouter initialEntries={[path]}>
        <AppRoutes />
      </MemoryRouter>
    </MotionConfig>,
  );
}

describe('simuladores nativos no registro', () => {
  it.each(natives.map((s) => [s.id]))('%s tem módulo carregável e não aponta para arquivo legado', async (id) => {
    expect(NATIVE[id], 'falta o módulo em src/sims/native.ts').toBeTypeOf('function');
    const mod = await NATIVE[id]();
    expect(mod.default.scenarios.length).toBeGreaterThan(0);
    expect(findSim(id)!.file).toBeUndefined();
  });

  it('todo módulo do mapa está registrado como nativo', () => {
    Object.keys(NATIVE).forEach((id) => expect(findSim(id)?.engine, id).toBe('nativo'));
  });
});

/** Abre a página de um simulador nativo e confere o título, a ausência de iframe e a acessibilidade em todos os modos. */
async function checkSim(id: string, heading: RegExp) {
  const { container } = renderAt(`/sim/${id}`);
  expect(screen.getByRole('heading', { level: 1, name: heading })).toBeTruthy();
  await screen.findByRole('tab', { name: 'Cenário' }, { timeout: 15000 });
  expect(screen.queryByTitle(/Simulador:/)).toBeNull(); // não é iframe
  expect(screen.queryByRole('link', { name: /Abrir em tela cheia/ })).toBeNull();
  const modes = Array.from(container.querySelectorAll<HTMLButtonElement>('.topbar [aria-label="Modo de simulação"] button'));
  expect(modes.length).toBeGreaterThan(1);
  for (const mode of modes) {
    fireEvent.click(mode);
    for (let i = 0; i < 25; i++) fireEvent.click(screen.getByRole('button', { name: 'Passo' }));
    for (const t of screen.getAllByRole('tab')) fireEvent.click(t);
    const r = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(r.violations.map((v) => `${mode.textContent}: ${v.id} ${v.nodes.map((n) => n.target.join(' ')).join(' | ')}`)).toEqual([]);
  }
}

describe('páginas dos simuladores nativos', () => {
  it('SSH: carrega, percorre os dois modos e não tem violações de acessibilidade', () => checkSim('ssh', /^SSH$/), 60000);
  it('HTTPS e TLS: carrega, percorre os quatro modos e não tem violações de acessibilidade', () => checkSim('https', /^HTTPS e TLS$/), 60000);
  it('FTP, FTPS e SFTP: carrega, percorre os quatro modos e não tem violações de acessibilidade', () => checkSim('ftp', /^FTP, FTPS e SFTP$/), 60000);

  it('o SSH percorre uma amostra de cenários dos dois modos sem quebrar', async () => {
    const { container } = renderAt('/sim/ssh');
    await screen.findByRole('tab', { name: 'Cenário' }, { timeout: 15000 });
    for (const mode of ['Sessão e autenticação', 'Túneis e encaminhamento']) {
      fireEvent.click(screen.getByRole('button', { name: mode }));
      const chips = Array.from(container.querySelectorAll<HTMLButtonElement>('.scen-row button.chip'));
      expect(chips.length).toBeGreaterThan(3);
      for (const chip of [chips[0], chips[chips.length - 1]]) {
        fireEvent.click(chip);
        for (let i = 0; i < 25; i++) fireEvent.click(screen.getByRole('button', { name: 'Passo' }));
        for (const t of screen.getAllByRole('tab')) fireEvent.click(t);
      }
    }
  }, 60000);

  it('o texto do cenário mostra a configuração e as abas próprias do SSH aparecem', async () => {
    renderAt('/sim/ssh');
    await screen.findByRole('tab', { name: 'Cenário' }, { timeout: 15000 });
    expect(screen.getByText(/Configuração do cenário:/)).toBeTruthy();
    fireEvent.click(screen.getByRole('tab', { name: 'Chaves e sessão' }));
    expect(screen.getByText('Da troca de chaves às chaves da sessão')).toBeTruthy();
    fireEvent.click(screen.getByRole('tab', { name: 'Configuração' }));
    expect(screen.getByText('Nota de hardening')).toBeTruthy();
  });

  it('o hub lista cada simulador de protocolos seguros uma única vez', () => {
    renderAt('/categoria/protocolos-seguros');
    ['SSH', 'HTTPS e TLS', 'FTP, FTPS e SFTP'].forEach((t) => expect(screen.getAllByRole('heading', { level: 2, name: t })).toHaveLength(1));
    expect(screen.queryByText(/versão nativa/)).toBeNull();
  });
});
