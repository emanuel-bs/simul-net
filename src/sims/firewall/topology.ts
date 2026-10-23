// Topologia do Firewall: as zonas ligadas ao firewall. Os modos sem DMZ mostram duas zonas; os demais, três.
import type { Trace } from '../../sim-core';
import type { TopologyDef } from '../../sim-core/ui';
import { ADDR, COL, connText, connsAt } from './engine';

export const topology = (sub: string, tr: Trace): TopologyDef => {
  const three = sub === 'dmz' || sub === 'def';
  const col = (key: string) => tr.cols.find((c) => c.key === key);
  const ext = col('ext') ?? COL.srv;
  const int = col('int') ?? COL.int;
  const nodes: TopologyDef['nodes'] = [
    { key: 'fw', label: 'Firewall', sub: three ? 'três zonas' : 'duas zonas', x: 450, y: 150, kind: 'router', w: 136 },
    { key: 'ext', label: ext.label, sub: ext.addr, x: 800, y: 150, kind: 'cloud', w: 150 },
  ];
  const links: TopologyDef['links'] = [['fw', 'ext', { label: 'externa ' + ADDR.fwE }]];
  if (three) {
    nodes.push({ key: 'int', label: 'Host interno', sub: ADDR.int, x: 110, y: 50, kind: 'host', w: 128 });
    nodes.push({ key: 'db', label: 'Servidor interno', sub: ADDR.db, x: 110, y: 225, kind: 'host', w: 128 });
    nodes.push({ key: 'web', label: 'Servidor web', sub: ADDR.web, x: 450, y: 40, kind: 'host', w: 128 });
    links.push(['int', 'fw', { label: 'interna ' + ADDR.fwI }], ['db', 'fw'], ['web', 'fw', { label: 'DMZ ' + ADDR.fwD }]);
  } else {
    nodes.push({ key: 'int', label: int.label, sub: int.addr, x: 110, y: 150, kind: 'host', w: 128 });
    links.push(['int', 'fw', { label: 'interna ' + ADDR.fwI }]);
  }
  return {
    width: 920,
    height: 262,
    nodes,
    links,
    route: (m) => [m.from, m.to],
    notes: (t: Trace, now: number) => {
      const out: Record<string, string[]> = {};
      if (!t.raw.stateful) {
        out.fw = ['sem tabela de conexões'];
        return out;
      }
      const es = connsAt(t, now);
      const lines = es.slice(0, 3).map((c) => connText(c).replace(/^(\w+) /, '$1 ') + ' ' + c.state);
      if (es.length > 3) lines.push('+ ' + (es.length - 3) + ' entradas');
      out.fw = lines.length ? lines : ['tabela vazia'];
      return out;
    },
  };
};
