// Topologia do spanning tree: três switches em triângulo; o enlace bloqueado (ao final) aparece tracejado.
import type { Trace } from '../../sim-core';
import type { TopoNode, TopologyDef } from '../../sim-core/ui';
import { compute, portNo, portsAt, portsOf, type Bridge, type Link, type PortEv } from './model';
import type { Inst } from './mstp';

const key = (n: number) => (n === 4 ? 'x' : 'sw' + n);
const LETTER: Record<string, string> = { root: 'R', designated: 'D', alternate: 'A', disabled: '-' };

export const topology = (sub: string, tr: Trace): TopologyDef => {
  const R = tr.raw;
  const brs = (R.brs || []) as Bridge[];
  const links = (R.links || []) as Link[];
  const final = compute(brs, links);
  const showAlt = !(sub === 'laco' && !R.stp);
  const inst = (R.inst || []) as Inst[];
  const hasX = brs.some((b) => b.n === 4);
  const hasHosts = sub === 'laco';
  const pos: Record<string, [number, number]> = hasX
    ? { sw1: [300, 190], sw2: [520, 45], sw3: [740, 190], x: [80, 190] }
    : hasHosts
      ? { sw1: [250, 190], sw2: [450, 45], sw3: [650, 190], a: [70, 110], b: [830, 110] }
      : { sw1: [170, 190], sw2: [450, 45], sw3: [730, 190] };
  const nodes: TopoNode[] = brs.map((b) => ({ key: key(b.n), label: b.name, sub: 'prioridade ' + b.prio, x: pos[key(b.n)][0], y: pos[key(b.n)][1], kind: b.n === 4 ? 'attacker' : 'switch' }));
  if (hasHosts) nodes.push({ key: 'a', label: 'Host A', sub: '192.168.1.10', x: pos.a[0], y: pos.a[1], kind: 'host' }, { key: 'b', label: 'Host B', sub: '192.168.1.20', x: pos.b[0], y: pos.b[1], kind: 'host' });
  const blocked = (l: Link) => showAlt && inst.length <= 1 && [l.a, l.b].some((n) => final.role(n, l.id) === 'alternate');
  const tl: TopologyDef['links'] = links.map((l) => [key(l.a), key(l.b), { label: l.speed, dashed: blocked(l), down: !l.up }]);
  if (hasHosts) tl.push(['a', 'sw1'], ['b', 'sw3']);
  return {
    width: 900,
    height: 262,
    nodes,
    links: tl,
    notes: (t: Trace, now: number) => {
      const out: Record<string, string[]> = {};
      if (inst.length) {
        brs.forEach((b) => {
          out[key(b.n)] = inst.map((i) => i.name.split(' ')[0] + ': ' + i.roles.filter((r) => r.br === b.n).map((r) => 'p' + portNo(links, b.n, links.find((l) => l.id === r.link)!) + ' ' + LETTER[r.role]).join(' '));
        });
        return out;
      }
      if (!showAlt) return out;
      const at = portsAt((t.raw.ports || []) as PortEv[], now);
      brs.forEach((b) => {
        out[key(b.n)] = portsOf(links, b.n).map((l) => {
          const e = at.get(b.n + ':' + l.id);
          return 'p' + portNo(links, b.n, l) + ' ' + (e ? e.state : '-');
        });
      });
      return out;
    },
  };
};
