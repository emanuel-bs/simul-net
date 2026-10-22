// Topologia do DNS: cliente, resolvedor e servidores da hierarquia; no ataque, o atacante; na privacidade, o observador.
import type { Trace } from '../../sim-core';
import type { TopologyDef } from '../../sim-core/ui';
import { IPS, type CacheEv, type DnsParams } from './engine';

/** Entradas do cache do resolvedor no instante dado, reconstruídas a partir do diário de eventos. */
export function cacheAt(tr: Trace, nowMs: number): CacheEv[] {
  const evs = ((tr.raw.cacheEv || []) as CacheEv[]).filter((e) => e.t <= nowMs + 1e-9);
  const map = new Map<string, CacheEv>();
  evs
    .map((e, i) => ({ e, i }))
    .sort((a, b) => a.e.t - b.e.t || a.i - b.i)
    .forEach(({ e }) => (e.op === 'del' ? map.delete(e.key) : map.set(e.key, e)));
  return Array.from(map.values());
}

export const topology = (sub: string, tr: Trace): TopologyDef => {
  const P = tr.raw.P as DnsParams | undefined;
  const nodes: TopologyDef['nodes'] = [];
  const links: TopologyDef['links'] = [];
  let route: TopologyDef['route'];

  if (sub === 'res' || sub === 'sec') {
    nodes.push({ key: 'cl', label: 'Cliente', sub: IPS.cl, x: 80, y: 125, kind: 'host', w: 120 });
    nodes.push({ key: 'rs', label: 'Resolvedor', sub: IPS.rs, x: 290, y: 125, kind: 'router', w: 140 });
    nodes.push({ key: 'rt', label: 'Raiz', sub: IPS.rt, x: 520, y: 40, kind: 'cloud', w: 120 });
    nodes.push({ key: 'tl', label: '.com', sub: IPS.tl, x: 520, y: 125, kind: 'cloud', w: 120 });
    nodes.push({ key: 'au', label: 'ns1', sub: IPS.au, x: 520, y: 210, kind: 'cloud', w: 120 });
    links.push(['cl', 'rs', { label: 'UDP 53' }], ['rs', 'rt'], ['rs', 'tl'], ['rs', 'au']);
    if (sub === 'res' && P && !P.ns1) {
      nodes.push({ key: 'a2', label: 'ns2', sub: IPS.a2, x: 700, y: 210, kind: 'cloud', w: 120 });
      links.push(['au', 'a2', { dashed: true }]);
      route = (m) => (m.to === 'a2' || m.from === 'a2' ? ['rs', 'au', 'a2'] : [m.from, m.to]);
    }
  } else if (sub === 'env') {
    nodes.push({ key: 'cl', label: 'Cliente', sub: IPS.cl, x: 80, y: 125, kind: 'host', w: 120 });
    nodes.push({ key: 'rs', label: 'Resolvedor', sub: IPS.rs, x: 290, y: 125, kind: 'router', w: 140 });
    nodes.push({ key: 'au', label: 'ns1', sub: IPS.au, x: 520, y: 60, kind: 'cloud', w: 120 });
    nodes.push({ key: 'at', label: 'Atacante', sub: IPS.at, x: 520, y: 190, kind: 'attacker', w: 120 });
    links.push(['cl', 'rs'], ['rs', 'au'], ['at', 'rs', { dashed: true, label: 'forjado' }]);
  } else if (sub === 'amp') {
    nodes.push({ key: 'at', label: 'Atacante', sub: IPS.at, x: 80, y: 125, kind: 'attacker', w: 120 });
    nodes.push({ key: 'rs', label: 'Resolvedor', sub: IPS.rs, x: 310, y: 125, kind: 'router', w: 140 });
    nodes.push({ key: 'vi', label: 'Vítima', sub: IPS.vi, x: 540, y: 125, kind: 'host', w: 120 });
    links.push(['at', 'rs', { label: 'origem forjada' }], ['rs', 'vi', { label: 'respostas' }]);
  } else {
    nodes.push({ key: 'cl', label: 'Cliente', sub: IPS.cl, x: 80, y: 125, kind: 'host', w: 120 });
    nodes.push({ key: 'ob', label: 'Rede', sub: 'observador', x: 310, y: 125, kind: 'switch', w: 120 });
    nodes.push({ key: 'rs', label: 'Resolvedor', sub: IPS.rs, x: 540, y: 125, kind: 'router', w: 140 });
    links.push(['cl', 'ob'], ['ob', 'rs']);
    route = (m) => (m.from === 'cl' && m.to === 'rs' ? ['cl', 'ob', 'rs'] : m.from === 'rs' && m.to === 'cl' ? ['rs', 'ob', 'cl'] : [m.from, m.to]);
  }

  return {
    width: sub === 'res' && P && !P.ns1 ? 780 : 620,
    height: 250,
    nodes,
    links,
    route,
    notes: (t: Trace, now: number) => {
      const out: Record<string, string[]> = {};
      if (sub === 'priv' || sub === 'amp') return out;
      const es = cacheAt(t, now);
      const lines = es.slice(0, 4).map((e) => (e.neg ? 'NXDOMAIN ' : e.ty + ' ') + e.n);
      if (es.length > 4) lines.push('+ ' + (es.length - 4) + ' entradas');
      out.rs = lines.length ? lines : ['cache vazio'];
      return out;
    },
  };
};
