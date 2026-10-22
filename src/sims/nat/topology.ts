// Topologia do NAT: hosts internos, switch da LAN, roteador NAT (e o CGN, quando houver) e o servidor externo.
// No modo DNAT entram o servidor interno e, no retorno assimétrico, um segundo gateway.
import type { Trace } from '../../sim-core';
import type { TopologyDef } from '../../sim-core/ui';
import { IP, NAT_IN, NAT_OUT, SRV_IP, epText, type Entry, type NatParams, type TabEv } from './engine';

/** Entradas de um dispositivo no instante dado, reconstruídas a partir do diário de eventos da tabela. */
export function entriesAt(tr: Trace, dev: string, nowMs: number): Entry[] {
  const evs = ((tr.raw.tabEv || []) as TabEv[]).filter((e) => e.e.dev === dev && e.t <= nowMs + 1e-9);
  const sorted = evs.map((e, i) => ({ e, i })).sort((a, b) => a.e.t - b.e.t || a.i - b.i);
  const map = new Map<number, Entry>();
  sorted.forEach(({ e }) => (e.op === 'del' ? map.delete(e.e.id) : map.set(e.e.id, e.e)));
  return Array.from(map.values());
}

const line = (e: Entry): string => {
  const proto = e.proto === 'any' ? 'IP' : e.proto.toUpperCase();
  const int = e.kind === 'estatico' || e.kind === 'dinamico' ? e.intIp : epText({ ip: e.intIp, port: e.intPort });
  const ext = e.kind === 'estatico' || e.kind === 'dinamico' ? e.extIp : epText({ ip: e.extIp, port: e.extPort });
  return proto + ' ' + int + ' ↔ ' + ext;
};

export const topology = (sub: string, tr: Trace): TopologyDef => {
  const P = tr.raw.P as NatParams | undefined;
  const cgn = !!P?.cgnat;
  const dnat = sub === 'dnat';
  const acao = P?.acao ?? 'forward';
  const nodes: TopologyDef['nodes'] = [];
  const links: TopologyDef['links'] = [];

  if (!dnat) {
    const two = !(P && (P.dois || P.tardia));
    nodes.push({ key: 'pc1', label: 'PC1', sub: IP.pc1, x: 80, y: two ? 60 : 115, kind: 'host', w: 112 });
    if (two) nodes.push({ key: 'pc2', label: 'PC2', sub: IP.pc2, x: 80, y: 180, kind: 'host', w: 112 });
    nodes.push({ key: 'sw', label: 'SW LAN', sub: 'switch L2', x: 270, y: 120, kind: 'switch', w: 104 });
    nodes.push({ key: 'nat', label: cgn ? 'CPE' : 'R-NAT', sub: cgn ? NAT_IN + ' | 100.64.10.2' : NAT_IN + ' | ' + NAT_OUT, x: 480, y: 120, kind: 'router', w: 152 });
    if (cgn) nodes.push({ key: 'cgn', label: 'CGN', sub: '100.64.0.1 | ' + NAT_OUT, x: 700, y: 120, kind: 'router', w: 152 });
    nodes.push({ key: 'srv', label: 'SRV', sub: SRV_IP, x: cgn ? 920 : 820, y: 120, kind: 'host', w: 112 });
    links.push(['pc1', 'sw']);
    if (two) links.push(['pc2', 'sw']);
    links.push(['sw', 'nat', { label: 'interna' }]);
    if (cgn) links.push(['nat', 'cgn', { label: '100.64.0.0/10' }], ['cgn', 'srv', { label: 'externa' }]);
    else links.push(['nat', 'srv', { label: 'externa' }]);
  } else {
    nodes.push({ key: 'pc1', label: 'PC1', sub: IP.pc1, x: 80, y: 60, kind: 'host', w: 112 });
    nodes.push({ key: 'web', label: 'WEB', sub: acao === 'proxy' ? IP.web + ' (proxy)' : IP.web, x: 80, y: 190, kind: 'host', w: 128 });
    nodes.push({ key: 'sw', label: 'SW LAN', sub: 'switch L2', x: 270, y: 120, kind: 'switch', w: 104 });
    nodes.push({ key: 'nat', label: 'R-NAT', sub: NAT_IN + ' | ' + NAT_OUT, x: 480, y: 120, kind: 'router', w: 152 });
    nodes.push({ key: 'srv', label: acao === 'forward' ? 'CLI' : 'SRV', sub: SRV_IP, x: 820, y: 120, kind: 'host', w: 112 });
    links.push(['pc1', 'sw'], ['web', 'sw'], ['sw', 'nat', { label: 'interna' }], ['nat', 'srv', { label: 'externa' }]);
    if (P?.gwOutro && acao === 'forward') {
      nodes.push({ key: 'r2', label: 'R2', sub: 'outro gateway', x: 480, y: 215, kind: 'router', w: 112 });
      links.push(['sw', 'r2', { dashed: true }], ['r2', 'srv', { dashed: true }]);
    }
  }

  return {
    width: 940,
    height: 250,
    nodes,
    links,
    route: (m) => (m.route as string[] | undefined) || [m.from, m.to],
    notes: (t: Trace, now: number) => {
      const out: Record<string, string[]> = {};
      const devs = (t.raw.devs || []) as { key: string; rules: string[] }[];
      devs.forEach((d) => {
        const es = entriesAt(t, d.key, now);
        const lines = d.rules.map((r) => r);
        es.slice(0, 4).forEach((e) => lines.push(line(e)));
        if (es.length > 4) lines.push('+ ' + (es.length - 4) + ' entradas');
        if (!lines.length) lines.push('tabela vazia');
        out[d.key] = lines;
      });
      return out;
    },
  };
};
