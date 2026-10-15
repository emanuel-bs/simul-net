import { describe, expect, it } from 'vitest';
import { COLORS, newTrace, prepare } from '../../src/sim-core';
import {
  changedControls,
  defaultParams,
  layoutLadder,
  messageProgress,
  milestoneIndex,
  nextStep,
  parseSelect,
  scenarioParams,
  stateAt,
  visibleControl,
  visibleLog,
  visibleMessages,
  wrapText,
  type ControlDef,
  type ScenarioDef,
} from '../../src/sim-core/ui';

const controls: ControlDef[] = [
  { id: 'rtt', label: 'RTT', type: 'select', num: true, opts: [[20, '20'], [50, '50']], def: 20, grp: 'Rede' },
  { id: 'enc', label: 'Cifrar', type: 'check', def: true, grp: 'Cliente' },
  { id: 'only', label: 'Só no modo b', type: 'check', def: false, grp: 'Cliente', subs: ['b'] },
];
const scen: ScenarioDef = { id: 's1', g: 'G', label: 'Um', sub: 'a', set: { rtt: 50 }, what: '' };

function sample() {
  const tr = newTrace([{ key: 'c', label: 'C', addr: '10.0.0.1' }, { key: 's', label: 'S' }], [{ key: 'k', label: 'K' }], 20);
  tr.phase('Fase 1', 'f1');
  tr.st(0, 'k', 'a', 'warn');
  tr.mile(0, 'Início');
  const a = tr.add('c', 's', { label: 'ida', color: COLORS.enc, enc: true });
  tr.ev(a.tArr, 's', 'recebeu a primeira mensagem, que é longa o bastante para quebrar em linhas', 'ok');
  tr.st(tr.t, 'k', 'b', 'est');
  tr.lg(tr.t, 'log', 'conn');
  const b = tr.add('s', 'c', { label: 'volta', lost: true });
  tr.mile(b.tSend, 'Fim');
  return { tr, endR: prepare(tr), a, b };
}

describe('cenários e parâmetros', () => {
  it('parâmetros padrão e sobreposição pelo cenário', () => {
    expect(defaultParams(controls)).toEqual({ rtt: 20, enc: true, only: false });
    expect(scenarioParams(controls, scen)).toEqual({ rtt: 50, enc: true, only: false });
  });

  it('controles ocultos fora do seu modo', () => {
    expect(visibleControl(controls[2], 'a')).toBe(false);
    expect(visibleControl(controls[2], 'b')).toBe(true);
    expect(visibleControl(controls[0], 'a')).toBe(true);
  });

  it('lista o que mudou em relação ao cenário, ignorando campos ocultos', () => {
    const cur = { rtt: 20, enc: false, only: true };
    const ch = changedControls(controls, 'a', cur, scen);
    expect(ch.map((c) => c.id)).toEqual(['rtt', 'enc']);
    expect(ch[0]).toMatchObject({ from: '50', to: '20' });
    expect(ch[1]).toMatchObject({ from: 'sim', to: 'não' });
    expect(changedControls(controls, 'a', scenarioParams(controls, scen), scen)).toEqual([]);
  });

  it('converte o valor do select conforme o tipo', () => {
    expect(parseSelect(controls[0], '50')).toBe(50);
    expect(parseSelect({ ...controls[0], num: false }, '50')).toBe('50');
  });
});

describe('reprodução', () => {
  it('avança de evento em evento e termina na linha final', () => {
    const { tr, endR } = sample();
    let c = 0;
    const seen: number[] = [];
    for (let i = 0; i < 50 && c < endR; i++) {
      c = nextStep(tr, c, endR);
      seen.push(c);
    }
    expect(seen[seen.length - 1]).toBe(endR);
    expect(seen).toEqual([...seen].sort((a, b) => a - b));
  });

  it('mostra só o que o relógio já alcançou', () => {
    const { tr, endR } = sample();
    expect(visibleMessages(tr, 0).map((m) => m.label)).toEqual(['ida']);
    expect(visibleMessages(tr, endR).map((m) => m.label)).toEqual(['ida', 'volta']);
    expect(visibleLog(tr, 0)).toEqual([]);
    expect(visibleLog(tr, endR)).toHaveLength(1);
    expect(stateAt(tr, 'k', 0)?.val).toBe('a');
    expect(stateAt(tr, 'k', endR)?.val).toBe('b');
    expect(stateAt(tr, 'inexistente', endR)).toBeNull();
  });

  it('marco ativo e fim do metrô', () => {
    const { tr, endR } = sample();
    expect(milestoneIndex(tr, 0, endR)).toBe(0);
    expect(milestoneIndex(tr, endR, endR)).toBe(tr.metro.length);
  });

  it('mensagem perdida para a 55% do caminho; antes do envio não aparece', () => {
    const { tr, endR, b } = sample();
    expect(messageProgress(b, 0).visible).toBe(false);
    const end = messageProgress(b, endR);
    expect(end.f).toBeCloseTo(0.55);
    expect(end.done).toBe(true);
    expect(messageProgress(tr.msgs[0], endR)).toMatchObject({ f: 1, done: true });
  });
});

describe('geometria do diagrama', () => {
  it('quebra o texto sem cortar palavras', () => {
    expect(wrapText('uma frase curta', 30)).toEqual(['uma frase curta']);
    expect(wrapText('aaa bbb ccc ddd', 7)).toEqual(['aaa bbb', 'ccc ddd']);
  });

  it('posiciona colunas, fases, mensagens e eventos sem sobreposição', () => {
    const { tr, endR } = sample();
    const L = layoutLadder(tr, endR);
    expect(L.columns.map((c) => c.x)).toEqual([230, 670]);
    expect(L.height).toBeGreaterThan(L.y(endR));
    expect(L.phases).toHaveLength(1);
    expect(L.messages).toHaveLength(2);
    expect(L.messages[0].y2).toBeGreaterThan(L.messages[0].y1);
    expect(L.events[0].lines.length).toBeGreaterThan(1);
    // com duas colunas, o texto do evento da coluna da direita começa à direita da linha de vida
    expect(L.events[0].anchor).toBe('start');
    expect(L.timeLabels.length).toBeGreaterThan(0);
  });
});
