// @vitest-environment jsdom
// Regressão do NC-22: a navegação direta de um simulador nativo para outro (link da aba Referência, por exemplo)
// mudava o endereço, mas a tela continuava no simulador anterior.
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MotionConfig } from 'motion/react';
import { MemoryRouter, useNavigate } from 'react-router-dom';
import { afterEach, describe, expect, it } from 'vitest';
import { AppRoutes } from '../src/App';

afterEach(cleanup);

function Ir({ para }: { para: string }) {
  const navigate = useNavigate();
  return (
    <button type="button" onClick={() => navigate(para)}>
      ir para {para}
    </button>
  );
}

function abre(inicial: string, para: string) {
  return render(
    <MotionConfig reducedMotion="always">
      <MemoryRouter initialEntries={[inicial]}>
        <Ir para={para} />
        <AppRoutes />
      </MemoryRouter>
    </MotionConfig>,
  );
}

describe('navegação direta entre simuladores nativos', () => {
  it('TCP para UDP: a tela passa a mostrar o UDP', async () => {
    abre('/sim/tcp', '/sim/udp');
    await screen.findByRole('tab', { name: 'Cenário' }, { timeout: 15000 });
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('TCP');
    fireEvent.click(screen.getByRole('button', { name: 'ir para /sim/udp' }));
    await screen.findByRole('heading', { level: 1, name: 'UDP' }, { timeout: 15000 });
    await screen.findByRole('tab', { name: 'Cenário' }, { timeout: 15000 });
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('UDP');
  }, 60000);

  it('ida e volta: UDP para TCP e de novo para UDP reaproveita os módulos já carregados', async () => {
    abre('/sim/udp', '/sim/tcp');
    await screen.findByRole('tab', { name: 'Cenário' }, { timeout: 15000 });
    fireEvent.click(screen.getByRole('button', { name: 'ir para /sim/tcp' }));
    await screen.findByRole('heading', { level: 1, name: 'TCP' }, { timeout: 15000 });
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('TCP');
  }, 60000);
});
