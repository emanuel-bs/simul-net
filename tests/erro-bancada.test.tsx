// @vitest-environment jsdom
// Regressão do NC-05: uma exceção na bancada não pode derrubar a aplicação inteira.
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ErroBancada } from '../src/components/ErroBancada';

afterEach(cleanup);

let falha = true;
function Quebra() {
  if (falha) throw new Error('falha simulada');
  return <p>bancada funcionando</p>;
}

describe('ErroBancada', () => {
  it('mostra a mensagem em vez de derrubar a página e permite tentar de novo', () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    falha = true;
    render(
      <ErroBancada titulo="TCP">
        <Quebra />
      </ErroBancada>,
    );
    expect(screen.getByRole('alert').textContent).toContain('Não foi possível exibir este simulador');
    expect(screen.getByRole('alert').textContent).toContain('TCP');
    falha = false;
    fireEvent.click(screen.getByRole('button', { name: 'Tentar novamente' }));
    expect(screen.getByText('bancada funcionando')).toBeTruthy();
    log.mockRestore();
  });

  it('sem falha, apenas exibe o conteúdo', () => {
    falha = false;
    render(
      <ErroBancada titulo="TCP">
        <Quebra />
      </ErroBancada>,
    );
    expect(screen.queryByRole('alert')).toBeNull();
  });
});
