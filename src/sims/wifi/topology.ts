// Topologia do Wi-Fi: o alcance do rádio de cada nó e os enlaces sem fio (tracejados). No acesso ao meio, o enlace caído entre os
// clientes mostra o nó oculto; em roaming, os dois APs aparecem ligados à mesma rede cabeada.
import type { Trace } from '../../sim-core';
import type { TopologyDef } from '../../sim-core/ui';
import { SSID } from './model';

const stateNote = (tr: Trace, now: number): string => {
  const log = (tr.raw.stlog || []) as { t: number; n: number }[];
  const cur = log.filter((p) => p.t <= now + 1e-9).pop();
  return cur ? 'estado ' + cur.n : 'estado 1';
};

export const topology = (sub: string, tr: Trace): TopologyDef => {
  const R = tr.raw;
  if (sub === 'meio') {
    const hidden = !!R.hidden;
    return {
      width: 900,
      height: 280,
      nodes: [
        { key: 'ap', label: 'AP-01', sub: 'ponto de acesso', x: 450, y: 70, kind: 'switch' },
        { key: 'a', label: 'Cliente A', sub: 'STA', x: 130, y: 210, kind: 'host' },
        { key: 'c', label: 'Cliente C', sub: hidden ? 'fora do alcance de A' : 'STA', x: 770, y: 210, kind: 'host' },
      ],
      links: [
        ['a', 'ap', { label: 'rádio', dashed: true }],
        ['c', 'ap', { label: 'rádio', dashed: true }],
        ['a', 'c', { label: hidden ? 'não se ouvem' : 'se ouvem', dashed: true, down: hidden }],
      ],
      notes: (t: Trace, now: number) => {
        const navs = ((t.raw.navs || []) as { who: string; t: number; until: number }[]).filter((n) => n.t <= now + 1e-9 && now < n.until);
        const out: Record<string, string[]> = {};
        for (const k of ['a', 'c']) if (navs.some((n) => n.who === k)) out[k] = ['NAV ativo: adia a transmissão'];
        return out;
      },
    };
  }
  if (sub === 'mov') {
    if (R.mov === 'ps') {
      return {
        width: 900,
        height: 262,
        nodes: [
          { key: 'sta', label: 'Notebook', sub: 'cliente (STA)', x: 130, y: 120, kind: 'host' },
          { key: 'ap1', label: 'AP-01', sub: 'ponto de acesso', x: 450, y: 120, kind: 'switch' },
          { key: 'lan', label: 'Rede cabeada', sub: 'origem do pacote', x: 770, y: 120, kind: 'cloud' },
        ],
        links: [['sta', 'ap1', { label: 'rádio', dashed: true }], ['ap1', 'lan', { label: 'cabo' }]],
        notes: (t: Trace, now: number) => {
          const ps = t.raw.ps as { arrival: number } | undefined;
          return { ap1: ps && now >= ps.arrival ? ['guarda 1 quadro do AID 1'] : ['beacon a cada 102,4 ms'] };
        },
      };
    }
    return {
      width: 900,
      height: 290,
      nodes: [
        { key: 'lan', label: 'Rede cabeada', sub: 'sistema de distribuição', x: 450, y: 50, kind: 'cloud' },
        { key: 'ap1', label: 'AP-01', sub: 'canal 1', x: 150, y: 140, kind: 'switch' },
        { key: 'ap2', label: 'AP-02', sub: 'canal 6', x: 750, y: 140, kind: 'switch' },
        { key: 'sta', label: 'Notebook', sub: 'cliente (STA)', x: 450, y: 240, kind: 'host' },
      ],
      links: [
        ['ap1', 'lan', { label: 'cabo' }],
        ['ap2', 'lan', { label: 'cabo' }],
        ['sta', 'ap1', { label: 'rádio', dashed: true }],
        ['sta', 'ap2', { label: 'rádio', dashed: true }],
      ],
      notes: (t: Trace, now: number) => {
        const r = ((t.raw.rssi || []) as { t: number; ap1: number; ap2: number }[]).filter((x) => x.t <= now + 1e-9).pop();
        const log = (t.raw.stlog || []) as { t: number; n: number }[];
        const cur = log.filter((p) => p.t <= now + 1e-9).pop();
        return { sta: [...(r ? ['AP-01: ' + r.ap1 + ' dBm; AP-02: ' + r.ap2 + ' dBm'] : []), ...(cur ? [stateNote(t, now)] : [])] };
      },
    };
  }
  if (sub === 'canal') {
    const rel = R.rel as string;
    return {
      width: 900,
      height: 262,
      nodes: [
        { key: 'sta1', label: 'Cliente 1', sub: 'rede 1', x: 120, y: 200, kind: 'host' },
        { key: 'ap1', label: 'AP-01', sub: 'canal 1, ' + R.larg + ' MHz', x: 330, y: 80, kind: 'switch' },
        { key: 'ap2', label: 'AP-02', sub: 'canal ' + R.ch2 + ', ' + R.larg + ' MHz', x: 570, y: 80, kind: 'switch' },
        { key: 'sta2', label: 'Cliente 2', sub: 'rede 2', x: 780, y: 200, kind: 'host' },
      ],
      links: [
        ['sta1', 'ap1', { label: 'rádio', dashed: true }],
        ['sta2', 'ap2', { label: 'rádio', dashed: true }],
        ['ap1', 'ap2', { label: rel === 'co' ? 'mesmo canal' : rel === 'adj' ? 'sobrepostos' : 'independentes', dashed: true, down: rel === 'indep' }],
      ],
    };
  }
  // descoberta e associação
  return {
    width: 900,
    height: 262,
    nodes: [
      { key: 'sta', label: 'Notebook', sub: 'cliente (STA)', x: 130, y: 120, kind: 'host' },
      { key: 'ap', label: 'AP-01', sub: R.hidden ? 'SSID oculto, canal ' + R.ch : SSID + ', canal ' + R.ch, x: 450, y: 120, kind: 'switch', w: 150 },
      { key: 'lan', label: 'Rede cabeada', sub: 'sistema de distribuição', x: 770, y: 120, kind: 'cloud' },
    ],
    links: [['sta', 'ap', { label: 'rádio', dashed: true }], ['ap', 'lan', { label: 'cabo' }]],
    notes: (t: Trace, now: number) => ({ sta: [stateNote(t, now)], ap: [stateNote(t, now) === 'estado 3' ? 'cliente com AID 1' : 'sem clientes associados'] }),
  };
};
