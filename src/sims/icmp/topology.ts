// Topologia do ICMP: PC-A, três roteadores, o switch da LAN do servidor, o SRV, um endereço sem host e uma rede sem rota.
import type { Trace } from '../../sim-core';
import type { TopologyDef } from '../../sim-core/ui';
import type { IcmpParams } from './engine';

const nodes: TopologyDef['nodes'] = [
  { key: 'pc', label: 'PC-A', sub: '10.0.1.10', x: 80, y: 118, kind: 'host', w: 96 },
  { key: 'r1', label: 'R1', sub: '10.0.1.1', x: 260, y: 118, kind: 'router', w: 96 },
  { key: 'r2', label: 'R2', sub: '10.0.12.2', x: 440, y: 118, kind: 'router', w: 96 },
  { key: 'r3', label: 'R3', sub: '10.0.23.2', x: 620, y: 118, kind: 'router', w: 96 },
  { key: 'sw2', label: 'SW2', sub: 'switch L2', x: 780, y: 118, kind: 'switch', w: 96 },
  { key: 'srv', label: 'SRV', sub: '10.0.4.20', x: 920, y: 72, kind: 'host', w: 96 },
  { key: 'ghost', label: '10.0.4.99', sub: 'sem host', x: 920, y: 168, kind: 'cloud', w: 150 },
  { key: 'net', label: '192.168.50.0/24', sub: 'sem rota em R2', x: 440, y: 38, kind: 'cloud', w: 150 },
];

const mtuLabel = (up: boolean, mtu: number) => (up ? 'MTU ' + mtu : 'caído');

export const topology = (_sub: string, tr: Trace): TopologyDef => {
  const P = tr.raw.P as IcmpParams | undefined;
  return {
    width: 1000,
    height: 222,
    nodes,
    links: [
      ['pc', 'r1', { label: P ? mtuLabel(P.l1up, P.l1mtu) : 'MTU 1500', down: P ? !P.l1up : false }],
      ['r1', 'r2', { label: P ? mtuLabel(P.l2up, P.l2mtu) : 'MTU 1500', down: P ? !P.l2up : false }],
      ['r2', 'r3', { label: P ? mtuLabel(P.l3up, P.l3mtu) : 'MTU 1500', down: P ? !P.l3up : false }],
      ['r3', 'sw2', { label: P ? mtuLabel(P.l4up, P.l4mtu) : 'MTU 1500', down: P ? !P.l4up : false }],
      ['sw2', 'srv', { down: P ? !P.l4up : false }],
      ['sw2', 'ghost', { dashed: true }],
      ['r2', 'net', { dashed: true }],
    ],
    route: (m) => (m.route as string[] | undefined) || [m.from, m.to],
    notes: (t: Trace, now: number) => {
      const p = (t.raw.P || {}) as Partial<IcmpParams>;
      const out: Record<string, string[]> = {};
      const pm = (t.raw.pmtuEv || []) as { t: number; dst: string; mtu: number }[];
      const learned = new Map<string, number>();
      pm.filter((e) => e.t <= now).forEach((e) => learned.set(e.dst, e.mtu));
      if (learned.size) out.pc = Array.from(learned).map(([d, m]) => 'PMTU ' + d + ' = ' + m);
      const r1: string[] = [];
      if (p.r1acl === 'deny-icmp') r1.push('ACL: nega todo ICMP');
      if (p.r1acl === 'deny-icmp-errors') r1.push('ACL: só echo-reply');
      if (p.unr1 === false) r1.push('no ip unreachables');
      if (r1.length) out.r1 = r1;
      const r2: string[] = [];
      if (p.r2lan === false) r2.push('sem rota 10.0.4.0/24');
      if (p.unr2 === false) r2.push('no ip unreachables');
      if (r2.length) out.r2 = r2;
      const r3: string[] = [];
      if (p.r3acl === 'deny-unreach') r3.push('ACL saída: nega (3/13)');
      if (p.r3acl === 'deny-silent') r3.push('ACL saída: nega em silêncio');
      if (p.unr3 === false) r3.push('no ip unreachables');
      if (r3.length) out.r3 = r3;
      const srv = ['UDP 53, 123 abertas'];
      if (p.srvEcho === false) srv.push('firewall: sem ping');
      out.srv = srv;
      return out;
    },
  };
};
