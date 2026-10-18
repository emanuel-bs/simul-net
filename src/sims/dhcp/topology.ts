// Topologia do DHCP: o cliente, o switch SW1, o PC-B (IP estático) e um ou dois servidores. Todo quadro passa pelo switch.
import type { Trace } from '../../sim-core';
import type { TopologyDef } from '../../sim-core/ui';
import { SERVERS, type DhcpParams, type LeaseEv } from './engine';

export const topology = (_sub: string, tr: Trace): TopologyDef => {
  const P = tr.raw.P as DhcpParams | undefined;
  const n = P ? P.servers : 1;
  const up = (v: boolean | undefined) => v !== false;
  const nodes: TopologyDef['nodes'] = [
    { key: 'pc', label: 'PC-A', sub: 'cliente DHCP', x: 110, y: 130, kind: 'host', w: 112 },
    { key: 'sw', label: 'SW1', sub: 'switch L2', x: 450, y: 130, kind: 'switch', w: 112 },
    { key: 'pcb', label: 'PC-B', sub: 'IP estático', x: 450, y: 232, kind: 'host', w: 112 },
    { key: 's1', label: 'DHCP-1', sub: SERVERS[0].ip, x: 790, y: n > 1 ? 50 : 100, kind: 'router', w: 112 },
  ];
  const links: TopologyDef['links'] = [
    ['pc', 'sw', { label: 'Fa0/1', down: P ? !P.l1up : false }],
    ['sw', 'pcb', { label: 'Fa0/2' }],
    ['sw', 's1', { label: 'Gi0/1', down: P ? !P.l2up || !P.s1up : false }],
  ];
  if (n > 1) {
    nodes.push({ key: 's2', label: 'DHCP-2', sub: SERVERS[1].ip, x: 790, y: 210, kind: 'router', w: 112 });
    links.push(['sw', 's2', { label: 'Gi0/2', down: P ? !P.l3up || !P.s2up : false }]);
  }
  return {
    width: 900,
    height: 318,
    nodes,
    links,
    route: (m) => [m.from, 'sw', m.to],
    notes: (t: Trace, now: number) => {
      const out: Record<string, string[]> = {};
      const ev = (t.raw.leaseEv || []) as LeaseEv[];
      SERVERS.slice(0, n).forEach((s) => {
        const last = new Map<string, LeaseEv>();
        ev.filter((e) => e.server === s.id && e.t <= now + 1e-9).forEach((e) => (e.state === 'FREE' ? last.delete(e.ip) : last.set(e.ip, e)));
        const lines = Array.from(last.values()).map((e) => e.ip + ' ' + e.state);
        out[s.key] = ['pool .' + s.start + ' a .' + s.end, ...lines];
        if (P && !up(s.key === 's1' ? P.s1up : P.s2up)) out[s.key].unshift('inativo');
      });
      return out;
    },
  };
};
