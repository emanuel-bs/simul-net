// @vitest-environment jsdom
import axe from 'axe-core';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { COLORS, newTrace } from '../../src/sim-core';
import { Workbench, type ProtocolDef } from '../../src/sim-core/ui';

afterEach(cleanup);

// Protocolo mínimo para exercitar a bancada: um pedido e uma resposta, com opção de perda.
const def: ProtocolDef = {
  id: 'demo',
  label: 'Demo',
  stateTitle: 'Estado da demonstração',
  rfcs: [[9293, 'TCP']],
  subs: [
    { key: 'a', label: 'Modo A', default: 'a-ok' },
    { key: 'b', label: 'Modo B', default: 'b-ok' },
  ],
  controls: [
    { id: 'rtt', label: 'RTT (ms)', type: 'select', num: true, opts: [[20, '20'], [100, '100']], def: 20, grp: 'Rede', help: { t: 'RTT', p: ['Tempo de <b>ida e volta</b>.'] } },
    { id: 'loss', label: 'Perder a resposta', type: 'check', def: false, grp: 'Rede' },
    { id: 'extra', label: 'Só no modo B', type: 'check', def: false, grp: 'Rede', subs: ['b'] },
    { id: 'adv', label: 'Ajuste avançado', type: 'check', def: false, grp: 'Rede', adv: true },
  ],
  scenarios: [
    { id: 'a-ok', g: 'Básicos', label: 'Normal', sub: 'a', what: '<p>Tudo certo.</p>' },
    { id: 'a-loss', g: 'Básicos', label: 'Com perda', sub: 'a', set: { loss: true, rtt: 100 }, what: '<p>A resposta se perde.</p>', openAdv: true },
    { id: 'b-ok', g: 'Outros', label: 'Normal B', sub: 'b', what: '<p>Modo B.</p>' },
  ],
  groupDoc: { Básicos: 'Cenários básicos.', Outros: 'Outros cenários.' },
  scenDoc: {
    'a-ok': { short: 'sem falhas', concept: 'Conceito A.', observe: ['olhe a ida'], msgs: [['Pedido', 'pergunta', 'cliente']], why: 'Porque sim.' },
    'a-loss': { short: 'perde a resposta', concept: 'Conceito perda.', observe: ['olhe o X'], msgs: [['Resposta', 'responde', 'servidor']], why: 'Perdas existem.' },
    'b-ok': { short: 'modo B', concept: 'Conceito B.', observe: ['nada'], msgs: [['Msg', 'f', 'x']], why: 'B.' },
  },
  tabs: [{ id: 'extra', label: 'Aba do modo B', subs: ['b'], render: (tr) => `<p>Mensagens: ${tr.msgs.length}</p>` }],
  build: (P, sub) => {
    const tr = newTrace([{ key: 'c', label: 'Cliente', addr: '10.0.0.1' }, { key: 's', label: 'Servidor', addr: '10.0.0.2' }], [{ key: 'estado', label: 'Estado' }], Number(P.rtt));
    tr.st(0, 'estado', 'início', 'warn');
    tr.mile(0, 'Início', sub);
    tr.add('c', 's', { label: 'Pedido', color: COLORS.enc, enc: true, info: 'Pedido cifrado', about: 'O cliente pergunta.', fields: [['campo', 'valor', 'significado']] });
    tr.add('s', 'c', { label: 'Resposta', lost: !!P.loss });
    tr.st(tr.t, 'estado', P.loss ? 'perdido' : 'concluído', P.loss ? 'bad' : 'est');
    tr.lg(tr.t, 'fim', 'sys');
    tr.mile(tr.t, 'Fim');
    return tr;
  },
  explain: (_tr, P, scen) => `<p>Execução com RTT ${P.rtt}${scen ? ' em ' + scen.label : ''}.</p>`,
  reference: '<h3>Referência</h3><p>Texto de referência.</p>',
};

const play = () => screen.getByRole('button', { name: /Simular|Continuar|Pausar/ });
const tab = (name: string) => screen.getByRole('tab', { name });
// Os chips do topo e os botões da lista lateral do Cenário têm os mesmos nomes: aqui só os chips.
const row = (container: HTMLElement) => within(container.querySelector('.scen-row') as HTMLElement);
const chip = (container: HTMLElement, name: string) => row(container).getByRole('button', { name });

describe('Workbench', () => {
  it('abre no primeiro cenário, com abas, chips e rodapé de crédito', () => {
    render(<Workbench def={def} />);
    expect(screen.getByRole('button', { name: 'Normal', pressed: true })).toBeTruthy();
    ['Cenário', 'Captura', 'Mensagem', 'Experimento', 'Referência', 'Log de eventos'].forEach((n) => expect(tab(n)).toBeTruthy());
    expect(screen.queryByRole('tab', { name: 'Aba do modo B' })).toBeNull();
    expect(screen.getByText('Conceito A.')).toBeTruthy();
    expect(screen.getByText(/Simulador desenvolvido pelo/)).toBeTruthy();
    expect(screen.getByText('Estado da demonstração')).toBeTruthy();
    expect(screen.getByRole('link', { name: /RFC 9293/ }).getAttribute('href')).toBe('https://www.rfc-editor.org/rfc/rfc9293');
  });

  it('Passo avança mensagem por mensagem e preenche a captura e o log', () => {
    render(<Workbench def={def} />);
    fireEvent.click(tab('Captura'));
    // em t = 0 só a primeira mensagem já saiu
    expect(screen.getAllByText('Pedido cifrado')).toHaveLength(1);
    expect(screen.queryByText('Resposta')).toBeNull();
    const step = screen.getByRole('button', { name: 'Passo' });
    for (let i = 0; i < 40; i++) fireEvent.click(step);
    expect(screen.getAllByText('Resposta').length).toBeGreaterThan(0);
    fireEvent.click(tab('Log de eventos'));
    expect(screen.getByText(/fim/)).toBeTruthy();
    // voltar ao início recolhe a captura
    fireEvent.click(screen.getByRole('button', { name: 'Voltar ao início' }));
    fireEvent.click(tab('Captura'));
    expect(screen.queryByText('Resposta')).toBeNull();
  });

  it('selecionar uma linha da captura abre a aba Mensagem com os campos e a análise', () => {
    render(<Workbench def={def} />);
    fireEvent.click(screen.getByRole('button', { name: 'Passo' }));
    fireEvent.click(screen.getByRole('button', { name: 'Passo' }));
    fireEvent.click(tab('Captura'));
    fireEvent.click(screen.getAllByText('Pedido cifrado')[0]);
    expect(tab('Mensagem').getAttribute('aria-selected')).toBe('true');
    expect(screen.getByText('campo')).toBeTruthy();
    expect(screen.getByText('sim: cifrada e autenticada')).toBeTruthy();
    expect(screen.getByText('O cliente pergunta.')).toBeTruthy();
  });

  it('alterar um campo marca o cenário como modificado, lista a diferença e restaura', () => {
    render(<Workbench def={def} />);
    fireEvent.change(screen.getByLabelText(/RTT/), { target: { value: '100' } });
    expect(screen.getByText('modificado')).toBeTruthy();
    expect(screen.getByText(/RTT \(ms\):/)).toBeTruthy();
    // desfazer a mudança reativa o cenário
    fireEvent.change(screen.getByLabelText(/RTT/), { target: { value: '20' } });
    expect(screen.queryByText('modificado')).toBeNull();
    fireEvent.click(screen.getByLabelText(/Perder a resposta/));
    fireEvent.click(screen.getByRole('button', { name: 'Restaurar o cenário' }));
    expect(screen.queryByText('modificado')).toBeNull();
    expect((screen.getByLabelText(/Perder a resposta/) as HTMLInputElement).checked).toBe(false);
  });

  it('cenário com perda aplica os parâmetros e abre os ajustes avançados', () => {
    const { container } = render(<Workbench def={def} />);
    fireEvent.click(chip(container, 'Com perda'));
    expect((screen.getByLabelText(/Perder a resposta/) as HTMLInputElement).checked).toBe(true);
    expect((screen.getByLabelText(/RTT/) as HTMLSelectElement).value).toBe('100');
    expect(container.querySelector('details.adv')?.hasAttribute('open')).toBe(true);
    fireEvent.click(tab('Experimento'));
    expect(screen.getByText('Execução com RTT 100 em Com perda.')).toBeTruthy();
  });

  it('trocar de modo mostra os campos e abas do modo e esconde os dos outros', () => {
    const { container } = render(<Workbench def={def} />);
    expect(screen.queryByLabelText(/Só no modo B/)).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Modo B' }));
    expect(screen.getByLabelText(/Só no modo B/)).toBeTruthy();
    expect(chip(container, 'Normal B')).toBeTruthy();
    expect(row(container).queryByRole('button', { name: 'Com perda' })).toBeNull();
    fireEvent.click(tab('Aba do modo B'));
    expect(screen.getByText('Mensagens: 2')).toBeTruthy();
  });

  it('a ajuda do campo aparece ao focar e some com Escape', () => {
    render(<Workbench def={def} />);
    const sel = screen.getByLabelText(/RTT/);
    fireEvent.focus(sel);
    const tip = screen.getByRole('tooltip');
    expect(within(tip).getByText('RTT')).toBeTruthy();
    expect(within(tip).getByText('ida e volta')).toBeTruthy();
    fireEvent.keyDown(sel, { key: 'Escape' });
    expect(screen.queryByRole('tooltip')).toBeNull();
  });

  it('Simular reproduz a animação até o fim', async () => {
    render(<Workbench def={def} />);
    fireEvent.change(screen.getByLabelText(/Velocidade/), { target: { value: '14' } });
    fireEvent.click(play());
    expect(screen.getByRole('button', { name: 'Pausar' })).toBeTruthy();
    // termina sozinho: o botão volta a "Simular" (espera condicional, sem depender do desempenho da máquina)
    await waitFor(() => expect(screen.getByRole('button', { name: 'Simular' })).toBeTruthy(), { timeout: 25000 });
    fireEvent.click(tab('Captura'));
    expect(screen.getAllByText('Resposta').length).toBeGreaterThan(1);
  }, 40000);

  it('o zoom do diagrama percorre os passos, desabilita nos extremos e volta a "Ajustada"', () => {
    const { container } = render(<Workbench def={def} />);
    const svg = container.querySelector('svg.ladder') as SVGElement;
    const out = screen.getByRole('button', { name: 'Zoom -' }) as HTMLButtonElement;
    const inn = screen.getByRole('button', { name: 'Zoom +' }) as HTMLButtonElement;
    expect(screen.getByRole('button', { name: 'Ajustada' })).toBeTruthy();
    fireEvent.click(out);
    expect(screen.getByRole('button', { name: 'Ajustar (80%)' })).toBeTruthy();
    expect(svg.style.width).toBe('80%');
    expect(svg.style.minWidth).toMatch(/^0(px)?$/);
    for (let i = 0; i < 5; i++) fireEvent.click(out);
    expect(out.disabled).toBe(true);
    expect(svg.style.width).toBe('50%');
    fireEvent.click(screen.getByRole('button', { name: /Ajustar \(50%\)/ }));
    expect(screen.getByRole('button', { name: 'Ajustada' })).toBeTruthy();
    expect(svg.style.width).toBe('');
    for (let i = 0; i < 5; i++) fireEvent.click(inn);
    expect(inn.disabled).toBe(true);
    expect(svg.style.width).toBe('200%');
  });

  it('quadros: destacar, maximizar, encaixar com o botão e com Esc; recolher e expandir', () => {
    const { container } = render(<Workbench def={def} />);
    const stage = container.querySelector('.stage-panel') as HTMLElement;
    const stageBtn = (name: RegExp | string) => within(stage).getByRole('button', { name });
    expect(stage.className).not.toMatch(/is-floating/);
    fireEvent.click(stageBtn('Destacar'));
    expect(stage.className).toMatch(/is-floating/);
    expect(stage.querySelectorAll('.frz, .fresize')).toHaveLength(8);
    expect(stageBtn('Encaixar').getAttribute('aria-pressed')).toBe('true');
    fireEvent.click(stageBtn('Maximizar'));
    expect(stageBtn('Restaurar')).toBeTruthy();
    fireEvent.click(stageBtn('Restaurar'));
    fireEvent.click(stageBtn('Encaixar'));
    expect(stage.className).not.toMatch(/is-floating/);
    expect(stage.querySelectorAll('.frz, .fresize')).toHaveLength(0);
    expect(stage.style.position).toBe('');

    // Esc encaixa o quadro mais recente
    fireEvent.click(stageBtn('Destacar'));
    const state = container.querySelector('.fpanel') as HTMLElement;
    fireEvent.click(within(state).getByRole('button', { name: 'Destacar' }));
    expect(state.className).toMatch(/is-floating/);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(state.className).not.toMatch(/is-floating/);
    expect(stage.className).toMatch(/is-floating/);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(stage.className).not.toMatch(/is-floating/);

    // recolher e expandir
    const cfg = container.querySelector('.cfg') as HTMLElement;
    fireEvent.click(within(cfg).getByRole('button', { name: 'Recolher painel' }));
    expect(cfg.className).toMatch(/body-collapsed/);
    expect(within(cfg).getByRole('button', { name: 'Configurações do simulador' }).getAttribute('aria-expanded')).toBe('false');
    fireEvent.click(within(cfg).getByRole('button', { name: 'Configurações do simulador' }));
    expect(cfg.className).not.toMatch(/body-collapsed/);
  });

  it('o painel de abas expande ao escolher uma aba e a alça muda a altura pelo teclado', () => {
    const { container } = render(<Workbench def={def} />);
    const tabs = container.querySelector('.tabs-panel') as HTMLElement;
    // em telas baixas (menos de 800 px) o painel de abas começa recolhido, como no legado
    expect(tabs.className).toMatch(/body-collapsed/);
    fireEvent.click(tab('Captura'));
    expect(tabs.className).not.toMatch(/body-collapsed/);
    fireEvent.click(within(tabs).getByRole('button', { name: 'Recolher painel' }));
    expect(tabs.className).toMatch(/body-collapsed/);
    fireEvent.click(within(tabs).getByRole('button', { name: 'Expandir painel' }));
    expect(tabs.className).not.toMatch(/body-collapsed/);
    const grip = screen.getByRole('separator');
    expect(grip.getAttribute('aria-valuenow')).toBeTruthy();
    fireEvent.keyDown(grip, { key: 'ArrowUp' });
    expect(tabs.style.getPropertyValue('--tabs-h')).toMatch(/px$/);
    expect(grip.getAttribute('aria-valuenow')).toBe(String(Math.round(parseFloat(tabs.style.getPropertyValue('--tabs-h')))));
  });

  it('não tem violações de acessibilidade em nenhuma aba', async () => {
    const { container } = render(<Workbench def={def} />);
    for (let i = 0; i < 40; i++) fireEvent.click(screen.getByRole('button', { name: 'Passo' }));
    for (const name of ['Cenário', 'Captura', 'Mensagem', 'Experimento', 'Referência', 'Log de eventos']) {
      fireEvent.click(tab(name));
      const r = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
      expect(r.violations.map((v) => `${name}: ${v.id} ${v.nodes.map((n) => n.target.join(' ')).join(' | ')}`)).toEqual([]);
    }
  });
});
