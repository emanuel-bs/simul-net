// Regras do motor do spanning tree: eleição, custos, estados, falhas, RSTP, MSTP, laço e proteções.
import { describe, expect, it } from 'vitest';
import { scenarioParams, type Params } from '../../src/sim-core/ui';
import { controls } from '../../src/sims/stp/content/controls';
import { scenarios } from '../../src/sims/stp/content/scenarios';
import { compute, lastState, makeBridges, makeLinks, type PortEv } from '../../src/sims/stp/model';
import { stpProtocol } from '../../src/sims/stp/protocol';

const run = (id: string, over: Params = {}) => {
  const s = scenarios.find((x) => x.id === id)!;
  return stpProtocol.build({ ...scenarioParams(controls, s), ...over }, s.sub);
};
const port = (tr: ReturnType<typeof run>, br: number, link: string) => lastState(tr.raw.ports as PortEv[], br, link)!;

describe('eleição e papéis (modelo)', () => {
  it('a menor prioridade vence; no empate, o menor MAC', () => {
    expect(compute(makeBridges('mac'), makeLinks()).root).toBe(2);
    expect(compute(makeBridges('sw1'), makeLinks()).root).toBe(1);
    expect(compute(makeBridges('sw3'), makeLinks()).root).toBe(3);
  });

  it('o enlace lento não é o caminho até a raiz', () => {
    const t = compute(makeBridges('sw1'), makeLinks('100m'));
    expect(t.rootLink[3]).toBe('L23');
    expect(t.role(3, 'L13')).toBe('alternate');
    expect(t.cost[3]).toBe(40000);
  });

  it('cada enlace tem uma porta designada ou raiz do lado da raiz, e só um enlace fica com porta alternativa', () => {
    const brs = makeBridges('mac');
    const links = makeLinks();
    const t = compute(brs, links);
    const roles = links.map((l) => [l.a, l.b].map((n) => t.role(n, l.id)));
    roles.forEach((r) => expect(r.includes('designated')).toBe(true));
    expect(roles.flat().filter((r) => r === 'alternate')).toHaveLength(1);
  });
});

describe('STP clássico', () => {
  it('elege a raiz de menor MAC, bloqueia uma porta e converge em 30 s', () => {
    const tr = run('s-elect');
    expect(tr.raw.root0).toBe(2);
    expect(port(tr, 3, 'L13')).toMatchObject({ role: 'alternate', state: 'Bloqueio' });
    expect(port(tr, 1, 'L12').state).toBe('Encaminhamento');
    expect(tr.raw.conv).toBeGreaterThanOrEqual(30000);
    expect(tr.raw.conv).toBeLessThan(30100);
  });

  it('a prioridade muda a raiz e o lugar do bloqueio', () => {
    const tr = run('s-prio');
    expect(tr.raw.root0).toBe(3);
    expect(port(tr, 1, 'L12').role).toBe('alternate');
  });

  it('o custo escolhe a porta raiz', () => {
    const tr = run('s-cost');
    expect(tr.raw.root0).toBe(1);
    expect(port(tr, 3, 'L23').role).toBe('root');
    expect(port(tr, 3, 'L13').role).toBe('alternate');
  });

  it('a falha do enlace da porta raiz leva 30 s e promove a porta bloqueada', () => {
    const tr = run('s-fail-link');
    expect(tr.raw.changed).toBe(1);
    expect(tr.raw.reconv).toBeGreaterThanOrEqual(30000);
    expect(port(tr, 3, 'L13')).toMatchObject({ role: 'root', state: 'Encaminhamento' });
    expect(tr.msgs.filter((m) => m.label === 'TCN BPDU')).toHaveLength(2);
  });

  it('a falha da raiz elege a próxima ponte e também leva 30 s', () => {
    const tr = run('s-fail-root');
    expect(tr.raw.root1).toBe(1);
    expect(tr.raw.reconv).toBeGreaterThanOrEqual(30000);
  });

  it('a falha de um enlace bloqueado não muda nenhum papel', () => {
    const tr = run('s-fail-blocked');
    expect(tr.raw.changed).toBe(0);
    expect(tr.raw.reconv).toBe(0);
  });
});

describe('RSTP', () => {
  it('converge por proposta e acordo em milissegundos', () => {
    const tr = run('r-elect');
    expect(tr.raw.conv).toBeLessThan(100);
    expect(tr.msgs.some((m) => m.label === 'RST BPDU (proposta)')).toBe(true);
    expect(tr.msgs.some((m) => m.label === 'RST BPDU (acordo)')).toBe(true);
    expect(port(tr, 3, 'L13')).toMatchObject({ role: 'alternate', state: 'Descarte' });
  });

  it('a porta alternativa assume na hora quando a porta raiz falha', () => {
    const tr = run('r-fail-link');
    expect(tr.raw.reconv).toBeLessThan(100);
    expect(port(tr, 3, 'L13')).toMatchObject({ role: 'root', state: 'Encaminhamento' });
  });

  it('a falha da raiz também reconverge rápido', () => {
    const tr = run('r-fail-root');
    expect(tr.raw.root1).toBe(1);
    expect(tr.raw.reconv).toBeLessThan(100);
  });

  it('uma ponte STP faz os enlaces dela usar os temporizadores', () => {
    const tr = run('r-legacy');
    expect(tr.raw.conv).toBeGreaterThanOrEqual(30000);
    expect(tr.msgs.some((m) => m.label === 'Config BPDU')).toBe(true);
    expect(tr.msgs.some((m) => m.label === 'RST BPDU (proposta)')).toBe(true);
  });
});

describe('MSTP', () => {
  it('com duas instâncias, cada árvore bloqueia um enlace diferente', () => {
    const inst = run('m-two').raw.inst as { root: number; roles: { link: string; role: string }[] }[];
    expect(inst.map((i) => i.root)).toEqual([2, 1, 3]);
    const blocked = (i: number) => inst[i].roles.filter((r) => r.role === 'alternate').map((r) => r.link);
    expect(blocked(1)).toEqual(['L23']);
    expect(blocked(2)).toEqual(['L12']);
  });

  it('com uma só instância é o equivalente do RSTP', () => {
    expect((run('m-one').raw.inst as unknown[]).length).toBe(1);
  });
});

describe('laço e proteções', () => {
  it('sem STP o broadcast não termina; com STP, chega uma vez a cada host', () => {
    const a = run('l-nostp');
    expect(a.raw.storm).toBe(true);
    expect(a.raw.dupB).toBeGreaterThan(2);
    expect(a.raw.flaps).toBeGreaterThan(0);
    const b = run('l-stp');
    expect(b.raw.storm).toBe(false);
    expect(b.raw.dupB).toBe(1);
    expect(b.raw.lost).toBeGreaterThan(0);
  });

  it('o intruso sem proteção vira a raiz e deixa o SW3 30 s sem encaminhar', () => {
    const tr = run('p-none');
    expect(tr.raw.result).toBe('hijacked');
    expect(tr.raw.root1).toBe(4);
    expect(tr.raw.outage).toBeGreaterThanOrEqual(30000);
  });

  it('BPDU Guard e Root Guard mantêm a raiz', () => {
    const g = run('p-bpdu');
    expect(g.raw.result).toBe('isolated');
    expect(port(g, 1, 'LX').state).toContain('BPDU Guard');
    const r = run('p-root');
    expect(r.raw.result).toBe('contained');
    expect(r.raw.root1).toBe(2);
  });
});
