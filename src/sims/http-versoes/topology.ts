// Topologia do simulador das versões do HTTP: navegador, Internet e servidor.
import type { Trace } from '../../sim-core';
import type { TopologyDef } from '../../sim-core/ui';
import { HOST, VERSION_NAME, type HttpParams, type Job, type Version } from './engine';

export const topology = (_sub: string, tr: Trace): TopologyDef => {
  const P = tr.raw.P as HttpParams | undefined;
  const eff = (tr.raw.eff as Version | undefined) || 'h1';
  const jobs = (tr.raw.jobs || []) as Job[];
  const connEv = (tr.raw.connEv || []) as { t: number; n: number }[];
  return {
    width: 900,
    height: 210,
    nodes: [
      { key: 'cli', label: 'Navegador', sub: 'cliente', x: 110, y: 100, kind: 'host', w: 128 },
      { key: 'net', label: 'Internet', sub: P ? 'RTT de ' + P.rtt + ' ms' : '', x: 450, y: 100, kind: 'cloud', w: 128 },
      { key: 'srv', label: HOST, sub: VERSION_NAME[eff], x: 790, y: 100, kind: 'router', w: 150 },
    ],
    links: [['cli', 'net', { label: P && eff === 'h3' ? 'UDP 443' : 'TCP' }], ['net', 'srv', { label: P && eff === 'h3' ? 'QUIC' : tr.raw.eff === 'h1' && P && !P.tls ? 'porta 80' : 'porta 443' }]],
    route: (m) => [m.from, 'net', m.to],
    notes: (t: Trace, now: number) => {
      void t;
      const open = connEv.filter((c) => c.t <= now + 1e-9).length;
      const got = jobs.filter((j) => j.arr <= now + 1e-9).length;
      return { cli: ['conexões abertas: ' + open, 'recursos recebidos: ' + got + ' de ' + jobs.length] };
    },
  };
};
