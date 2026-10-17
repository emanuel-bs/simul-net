// Topologia do ARP: três hosts e um roteador ligados por um switch. O broadcast se espalha pelo switch.
import type { Trace } from '../../sim-core';
import type { TopologyDef } from '../../sim-core/ui';
import { HOSTS, type NeighEvent } from './engine';

const def: TopologyDef = {
  width: 900,
  height: 262,
  nodes: [
    { key: 'a', label: 'Host A', sub: HOSTS.a.ip, x: 140, y: 50, kind: 'host' },
    { key: 'sw', label: 'Switch', sub: 'camada 2', x: 450, y: 50, kind: 'switch' },
    { key: 'g', label: 'Gateway', sub: HOSTS.g.ip, x: 450, y: 150, kind: 'router' },
    { key: 'b', label: 'Host B', sub: HOSTS.b.ip, x: 760, y: 50, kind: 'host' },
    { key: 'net', label: 'Outras redes', sub: '192.0.2.0/24', x: 760, y: 150, kind: 'cloud' },
  ],
  links: [['a', 'sw'], ['sw', 'g'], ['sw', 'b'], ['g', 'net']],
  // todo quadro entre os hosts passa pelo switch
  route: (m) => [m.from, 'sw', m.to],
  notes: (tr: Trace, now: number) => {
    const ev = (tr.raw.neigh || []) as NeighEvent[];
    const out: Record<string, string[]> = {};
    (['a', 'b', 'g'] as const).forEach((k) => {
      const last = new Map<string, NeighEvent>();
      ev.filter((e) => e.host === k && e.t <= now).forEach((e) => last.set(e.ip, e));
      const lines = Array.from(last.values()).map((e) => e.ip + ' ' + e.state);
      out[k] = lines.length ? lines : ['tabela ARP vazia'];
    });
    return out;
  },
};

/** Os endereços mostrados em cada nó acompanham as colunas do cenário (no modo de conflito, o IP em disputa). */
export const topology = (_sub: string, tr: Trace): TopologyDef => ({
  ...def,
  nodes: def.nodes.map((n) => {
    const c = tr.cols.find((x) => x.key === n.key);
    return c && c.addr ? { ...n, sub: c.addr } : n;
  }),
});
