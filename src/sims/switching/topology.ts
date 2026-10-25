// Topologia do switching: hosts ligados às portas do switch; no modo de inundação, M ocupa a porta 3.
import type { Trace } from '../../sim-core';
import type { TopologyDef } from '../../sim-core/ui';
import { HOSTS, tableAt, who, type MacEv } from './model';

const notes = (tr: Trace, now: number): Record<string, string[]> => {
  const rows = tableAt((tr.raw.mac || []) as MacEv[], now).sort((a, b) => a.port - b.port);
  const lines = rows.map((r) => 'p' + r.port + ': ' + who(r.mac).replace('MAC forjado ', 'forjado '));
  return { sw: lines.length ? lines.slice(0, 7).concat(lines.length > 7 ? ['+ ' + (lines.length - 7) + ' entradas'] : []) : ['tabela vazia'] };
};

const lan = (moved: boolean): TopologyDef => ({
  width: 900,
  height: 262,
  nodes: [
    { key: 'a', label: 'Host A', sub: HOSTS.a.ip, x: 120, y: 50, kind: 'host' },
    { key: 'b', label: 'Host B', sub: HOSTS.b.ip, x: 120, y: 170, kind: 'host' },
    { key: 'sw', label: 'Switch', sub: 'camada 2', x: 400, y: 110, kind: 'switch' },
    { key: 'hub', label: 'Hub', sub: 'repetidor', x: 640, y: 110, kind: 'switch', w: 100 },
    { key: 'c', label: 'Host C', sub: HOSTS.c.ip, x: 800, y: 40, kind: 'host' },
    { key: 'd', label: 'Host D', sub: HOSTS.d.ip, x: 800, y: 180, kind: 'host' },
  ],
  links: [['a', 'sw', { label: 'p1' }], ['b', 'sw', { label: moved ? 'p4' : 'p2' }], ['sw', 'hub', { label: 'p3' }], ['hub', 'c'], ['hub', 'd']],
  route: (m) => {
    const viaHub = (k: string) => (k === 'c' || k === 'd' ? ['hub'] : []);
    if (m.from === 'sw') return ['sw', ...viaHub(m.to), m.to];
    if (m.to === 'sw') return [m.from, ...viaHub(m.from), 'sw'];
    return [m.from, 'hub', m.to];
  },
  notes,
});

const attack: TopologyDef = {
  width: 900,
  height: 262,
  nodes: [
    { key: 'a', label: 'Host A', sub: HOSTS.a.ip, x: 120, y: 50, kind: 'host' },
    { key: 'b', label: 'Host B', sub: HOSTS.b.ip, x: 120, y: 170, kind: 'host' },
    { key: 'sw', label: 'Switch', sub: 'camada 2', x: 450, y: 110, kind: 'switch' },
    { key: 'm', label: 'Host M', sub: HOSTS.m.ip, x: 780, y: 110, kind: 'attacker' },
  ],
  links: [['a', 'sw', { label: 'p1' }], ['b', 'sw', { label: 'p2' }], ['sw', 'm', { label: 'p3' }]],
  notes,
};

export const topology = (sub: string, tr: Trace): TopologyDef => {
  if (sub === 'inu') return attack;
  return lan(!!tr.raw.moved);
};
