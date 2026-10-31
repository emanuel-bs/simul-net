// Topologia do 802.1X: suplicante, autenticador (switch), servidor RADIUS e a rede protegida. Nos cenários de risco,
// o equipamento falso toma o lugar do autenticador e do servidor.
import type { Trace } from '../../sim-core';
import type { TopologyDef } from '../../sim-core/ui';
import { NODE } from './model';
import type { PortState } from './engine';

const PORT_NOTE: Record<PortState, string> = { unauth: 'porta fechada', authing: 'autenticando', auth: 'porta autorizada' };

export const topology = (sub: string, tr: Trace): TopologyDef => {
  const R = tr.raw;
  if (sub === 'seg') {
    return {
      width: 900,
      height: 220,
      nodes: [
        { key: 'sup', label: 'Notebook', sub: 'suplicante', x: 170, y: 110, kind: 'host' },
        { key: 'fake', label: 'Equipamento falso', sub: 'autenticador e servidor de terceiro', x: 700, y: 110, kind: 'attacker', w: 190 },
      ],
      links: [['sup', 'fake', { label: 'EAPOL' }]],
    };
  }
  const nosup = R.cause === 'nosup';
  const extra = R.pact === 'extra';
  const noRadius = nosup || extra;
  const nodes: TopologyDef['nodes'] = [
    { key: 'sup', label: nosup ? 'Impressora' : NODE.sup.name, sub: nosup ? 'sem suplicante 802.1X' : 'suplicante', x: 100, y: extra ? 80 : 130, kind: 'host' },
    { key: 'nas', label: NODE.nas.name, sub: 'autenticador, ' + NODE.nas.port, x: 400, y: 130, kind: 'switch', w: 150 },
    { key: 'lan', label: 'Rede', sub: 'rede corporativa', x: 760, y: noRadius ? 130 : 220, kind: 'cloud' },
  ];
  const links: TopologyDef['links'] = [
    ['sup', 'nas', { label: 'EAPOL' }],
    ['nas', 'lan', { label: 'dados, se autorizada' }],
  ];
  if (!noRadius) {
    nodes.push({ key: 'srv', label: 'RADIUS', sub: NODE.srv.ip, x: 760, y: 50, kind: 'router' });
    links.push(['nas', 'srv', { label: 'RADIUS UDP/1812', down: R.cause === 'noserver' }]);
  }
  if (extra) {
    nodes.push({ key: 'dev2', label: '2º dispositivo', sub: 'atrás da mesma porta', x: 100, y: 190, kind: 'host', w: 140 });
    links.push(['dev2', 'nas', { label: 'mesma porta' }]);
  }
  return {
    width: 900,
    height: 270,
    nodes,
    links,
    notes: (t: Trace, now: number) => {
      const log = (t.raw.port || []) as { t: number; state: PortState }[];
      const cur = log.filter((p) => p.t <= now + 1e-9).pop();
      return { nas: [cur ? 'Porta ' + PORT_NOTE[cur.state] : 'Porta fechada'] };
    },
  };
};
