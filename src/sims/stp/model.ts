// Modelo do spanning tree (IEEE 802.1D e 802.1Q): identificador de ponte, vetor de prioridade, eleição da raiz,
// papéis das portas e quadros BPDU. Usado pelos cinco modos do simulador.
// Rede: três switches em triângulo (SW1, SW2, SW3). O custo dos enlaces segue a tabela longa do IEEE 802.1D-2004.
import { COLORS as C0, newTrace, type Column, type Field, type Message, type StateDef, type Trace } from '../../sim-core';

export type Role = 'root' | 'designated' | 'alternate' | 'disabled';
export type BpduKind = 'stp' | 'rstp' | 'mst' | 'tcn';

export interface Bridge {
  n: number;
  key: string;
  name: string;
  mac: string;
  prio: number;
  alive: boolean;
}
export interface Link {
  id: string;
  a: number;
  b: number;
  cost: number;
  up: boolean;
  speed: string;
}

/** Endereços de documentação (RFC 7042 e RFC 9542). O SW2 tem o menor MAC: é o "switch velho do armário" que vira raiz por acaso. */
const MACS: Record<number, string> = { 1: '00:00:5e:00:53:1e', 2: '00:00:5e:00:53:0a', 3: '00:00:5e:00:53:28', 4: '00:00:5e:00:53:42' };
export const BPDU_MAC = '01:80:c2:00:00:00';
export const DEF_PRIO = 32768;

/** Custo de porta pela velocidade (IEEE 802.1D-2004, valores longos de 32 bits). */
export const COST: Record<string, number> = { '10m': 2000000, '100m': 200000, '1g': 20000, '10g': 2000 };
export const SPEED: Record<string, string> = { '10m': '10 Mb/s', '100m': '100 Mb/s', '1g': '1 Gb/s', '10g': '10 Gb/s' };

export function makeBridges(root: 'mac' | 'sw1' | 'sw3' = 'mac', withX = false): Bridge[] {
  const b: Bridge[] = [1, 2, 3].map((n) => ({ n, key: 'sw' + n, name: 'SW' + n, mac: MACS[n], prio: DEF_PRIO, alive: true }));
  if (root === 'sw1') b[0].prio = 4096;
  if (root === 'sw3') b[2].prio = 4096;
  if (withX) b.push({ n: 4, key: 'x', name: 'Switch intruso', mac: MACS[4], prio: 0, alive: true });
  return b;
}

export function makeLinks(l13: '1g' | '100m' = '1g', withX = false): Link[] {
  const l: Link[] = [
    { id: 'L12', a: 1, b: 2, cost: COST['1g'], up: true, speed: SPEED['1g'] },
    { id: 'L23', a: 2, b: 3, cost: COST['1g'], up: true, speed: SPEED['1g'] },
    { id: 'L13', a: 1, b: 3, cost: COST[l13], up: true, speed: SPEED[l13] },
  ];
  if (withX) l.push({ id: 'LX', a: 1, b: 4, cost: COST['1g'], up: true, speed: SPEED['1g'] });
  return l;
}

export const cols = (brs: Bridge[]): Column[] => brs.map((b) => ({ key: b.key, label: b.name, sub: 'prioridade ' + b.prio, addr: b.mac }));

export const other = (l: Link, n: number): number => (l.a === n ? l.b : l.a);
export const portsOf = (links: Link[], n: number): Link[] => links.filter((l) => l.a === n || l.b === n);
/** Número da porta de uma ponte para o enlace (na ordem em que os enlaces aparecem). */
export const portNo = (links: Link[], n: number, l: Link): number => portsOf(links, n).findIndex((x) => x.id === l.id) + 1;
export const portId = (links: Link[], n: number, l: Link): string => '128.' + portNo(links, n, l);
export const bid = (b: Bridge): string => b.prio + ' / ' + b.mac;
/** Ponte de menor identificador (prioridade e depois MAC) é "melhor". */
export const less = (x: Bridge, y: Bridge): boolean => x.prio < y.prio || (x.prio === y.prio && x.mac < y.mac);

export interface Tree {
  root: number;
  cost: Record<number, number>;
  rootLink: Record<number, string | null>;
  role: (n: number, link: string) => Role;
}

/**
 * Resultado estável do protocolo: raiz de menor identificador; porta raiz de cada ponte pelo menor custo até a raiz
 * (desempate: menor identificador da ponte vizinha, depois menor porta); porta designada de cada enlace pelo melhor vetor.
 */
export function compute(brs: Bridge[], links: Link[]): Tree {
  const by = (n: number) => brs.find((b) => b.n === n)!;
  const live = brs.filter((b) => b.alive);
  const root = live.reduce((x, y) => (less(y, x) ? y : x)).n;
  const up = links.filter((l) => l.up && by(l.a).alive && by(l.b).alive);
  const cost: Record<number, number> = {};
  live.forEach((b) => (cost[b.n] = b.n === root ? 0 : Infinity));
  for (let i = 0; i < live.length; i++)
    up.forEach((l) =>
      ([[l.a, l.b], [l.b, l.a]] as [number, number][]).forEach(([u, v]) => {
        if (cost[u] + l.cost < cost[v]) cost[v] = cost[u] + l.cost;
      }),
    );
  const rootLink: Record<number, string | null> = {};
  live.forEach((b) => {
    if (b.n === root) return void (rootLink[b.n] = null);
    const c = up.filter((l) => (l.a === b.n || l.b === b.n) && cost[other(l, b.n)] + l.cost === cost[b.n]);
    c.sort((x, y) => {
      const ox = by(other(x, b.n));
      const oy = by(other(y, b.n));
      if (ox !== oy) return less(ox, oy) ? -1 : 1;
      const px = portNo(links, ox.n, x);
      const py = portNo(links, oy.n, y);
      return px !== py ? px - py : portNo(links, b.n, x) - portNo(links, b.n, y);
    });
    rootLink[b.n] = c[0] ? c[0].id : null;
  });
  const wins = (l: Link, n: number) => {
    const o = other(l, n);
    return cost[n] !== cost[o] ? cost[n] < cost[o] : less(by(n), by(o));
  };
  const role = (n: number, id: string): Role => {
    const l = links.find((x) => x.id === id)!;
    if (!by(n).alive || !up.includes(l)) return 'disabled';
    if (rootLink[n] === id) return 'root';
    return wins(l, n) ? 'designated' : 'alternate';
  };
  return { root, cost, rootLink, role };
}

// ---- estados das portas ao longo do tempo ----

export interface PortEv {
  t: number;
  br: number;
  link: string;
  role: Role;
  state: string;
}
export const ROLE_TXT: Record<Role, string> = { root: 'raiz', designated: 'designada', alternate: 'alternativa', disabled: 'desativada' };

export function portsAt(ev: PortEv[], now: number): Map<string, PortEv> {
  const m = new Map<string, PortEv>();
  [...ev].sort((x, y) => x.t - y.t).forEach((e) => e.t <= now && m.set(e.br + ':' + e.link, e));
  return m;
}
export const lastState = (ev: PortEv[], br: number, link: string): PortEv | undefined => [...ev].reverse().find((e) => e.br === br && e.link === link);

export const STATES: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'root', label: 'Ponte raiz' },
  { key: 'ports', label: 'Portas bloqueadas' },
  { key: 'conv', label: 'Convergência' },
];

export const blockedText = (tree: Tree, brs: Bridge[], links: Link[]): string => {
  const list: string[] = [];
  brs.filter((b) => b.alive).forEach((b) =>
    portsOf(links, b.n).forEach((l) => {
      if (tree.role(b.n, l.id) === 'alternate') list.push(b.name + ' no enlace ' + l.id.slice(1, 2) + '-' + l.id.slice(2) + ' (porta ' + portNo(links, b.n, l) + ')');
    }),
  );
  return list.length ? list.join(', ') : 'nenhuma';
};

export function newStpTrace(brs: Bridge[], rtt: number): Trace {
  return newTrace(cols(brs), STATES, rtt);
}

// ---- quadros BPDU ----

export interface BpduOpts {
  kind: BpduKind;
  root: Bridge;
  cost: number;
  port: string;
  flags?: string[];
  role?: string;
  /** Idade da mensagem, em segundos (0 na raiz, +1 a cada ponte). */
  age?: number;
  label?: string;
  info: string;
  about: string;
  at?: number;
  par?: boolean;
  lost?: boolean;
  color?: string;
  tags?: string[];
  extra?: Field[];
  msti?: number;
  phaseName?: string;
}

const VERSION: Record<BpduKind, string> = { stp: '0 (STP)', rstp: '2 (RSTP)', mst: '3 (MSTP)', tcn: '0 (STP)' };
const TYPE: Record<BpduKind, string> = { stp: '0x00 (Configuração)', rstp: '0x02 (RST BPDU)', mst: '0x02 (RST BPDU)', tcn: '0x80 (TCN)' };
const LABEL: Record<BpduKind, string> = { stp: 'Config BPDU', rstp: 'RST BPDU', mst: 'MST BPDU', tcn: 'TCN BPDU' };

export function bpdu(tr: Trace, from: Bridge, to: Bridge, o: BpduOpts): Message {
  const fields: Field[] = [
    { sec: 'Ethernet 802.3 e LLC' },
    ['Destino', BPDU_MAC, 'endereço de grupo reservado: a ponte não o encaminha'],
    ['Origem', from.mac, 'MAC da porta que envia'],
    ['DSAP/SSAP/Controle', '0x42 / 0x42 / 0x03', 'LLC do spanning tree'],
    { sec: 'BPDU (IEEE 802.1D e 802.1Q)' },
    ['Protocol ID', '0x0000', ''],
    ['Versão', VERSION[o.kind], o.kind === 'stp' || o.kind === 'tcn' ? 'STP clássico' : ''],
    ['Tipo', TYPE[o.kind], ''],
  ];
  if (o.kind !== 'tcn') {
    fields.push(
      ['Flags', o.flags && o.flags.length ? o.flags.join(', ') : 'nenhuma', o.kind === 'stp' ? 'só TC e TCA existem no STP' : 'no RSTP: proposta, acordo, papel e estados da porta'],
      ['ID da raiz', bid(o.root), 'prioridade / MAC da ponte que o remetente acredita ser a raiz'],
      ['Custo até a raiz', String(o.cost), 'soma dos custos de porta até a raiz'],
      ['ID da ponte', bid(from), 'prioridade / MAC do remetente'],
      ['ID da porta', o.port, 'prioridade da porta (128) e número da porta'],
      ['Idade da mensagem', (o.age ?? 0) + ' s', 'aumenta 1 s a cada ponte; descartada ao passar de Max Age'],
      ['Max Age', '20 s', 'validade da informação da raiz'],
      ['Hello Time', '2 s', 'intervalo entre BPDUs da raiz'],
      ['Forward Delay', '15 s', 'tempo em Escuta e em Aprendizado'],
    );
    if (o.role) fields.push(['Papel da porta (RSTP)', o.role, 'campo nos bits 2 e 3 das flags']);
    if (o.kind === 'rstp') fields.push(['Versão 1 Length', '0', 'sem campo de versão 1']);
  }
  if (o.extra) fields.push(...o.extra);
  const len = o.kind === 'tcn' ? 21 : o.kind === 'stp' ? 52 : o.kind === 'rstp' ? 53 : 151;
  return tr.add(from.key, to.key, {
    label: o.label || LABEL[o.kind], proto: o.kind === 'stp' || o.kind === 'tcn' ? 'STP' : o.kind === 'rstp' ? 'RSTP' : 'MSTP', color: o.lost ? C0.bad : o.color || C0.plain, len,
    info: o.info, about: o.about, fields, phaseName: o.phaseName || 'BPDU', lost: !!o.lost, par: !!o.par, at: o.at, tags: o.tags || [],
  });
}

// ---- eleição da raiz por troca de BPDUs ----

export interface ElectOpts {
  kind: BpduKind;
  /** Ponte que só fala STP (BPDUs de configuração nos enlaces dela). */
  legacy?: number;
  extra?: (b: Bridge) => Field[];
  /** Linhas do log e dos eventos em português para cada mudança. */
  quiet?: boolean;
}

/**
 * Cada ponte começa achando que é a raiz e anuncia isso em todas as portas; ao receber um vetor melhor, adota-o e o
 * repassa pelas portas que não são a sua porta raiz. Para quando nenhum anúncio traz informação nova.
 */
export function elect(tr: Trace, brs: Bridge[], links: Link[], o: ElectOpts): Tree {
  const by = (n: number) => brs.find((b) => b.n === n)!;
  const live = brs.filter((b) => b.alive);
  type Info = { root: number; cost: number; via: string | null; from: number };
  const info: Record<number, Info> = {};
  live.forEach((b) => (info[b.n] = { root: b.n, cost: 0, via: null, from: b.n }));
  const lastSent = new Map<string, string>();
  const better = (c: Info & { sport: number; lport: number }, cur: Info & { sport?: number; lport?: number }) => {
    const rc = by(c.root);
    const rr = by(cur.root);
    if (rc !== rr) return less(rc, rr);
    if (c.cost !== cur.cost) return c.cost < cur.cost;
    if (c.from !== cur.from) return less(by(c.from), by(cur.from));
    return c.sport < (cur.sport ?? 99);
  };
  const sportOf: Record<number, number> = {};
  for (let round = 0; round < 8; round++) {
    const sends: { b: Bridge; l: Link; to: Bridge; root: number; cost: number }[] = [];
    live.forEach((b) =>
      portsOf(links, b.n).forEach((l) => {
        const to = by(other(l, b.n));
        if (!l.up || !to.alive || l.id === info[b.n].via) return;
        const sig = info[b.n].root + ':' + info[b.n].cost;
        if (lastSent.get(b.n + l.id) === sig) return;
        lastSent.set(b.n + l.id, sig);
        sends.push({ b, l, to, root: info[b.n].root, cost: info[b.n].cost });
      }),
    );
    if (!sends.length) break;
    const t0 = tr.t;
    sends.forEach((s) => {
      const rb = by(s.root);
      const kind: BpduKind = o.legacy && (s.b.n === o.legacy || s.to.n === o.legacy) ? 'stp' : o.kind;
      bpdu(tr, s.b, s.to, {
        kind, root: rb, cost: s.cost, port: portId(links, s.b.n, s.l), at: t0, par: true, age: s.root === s.b.n ? 0 : 1, flags: kind === 'rstp' ? ['porta designada', 'em descarte'] : [], role: kind === 'rstp' ? 'designada' : undefined,
        info: s.root === s.b.n ? s.b.name + ' anuncia: "a raiz sou eu" (custo 0)' : s.b.name + ' anuncia a raiz ' + rb.name + ' (custo ' + s.cost + ')',
        about: s.root === s.b.n ? 'Toda ponte começa achando que é a raiz e anuncia isso em todas as portas.' : 'A ponte repassa, pelas portas que não levam à raiz, o que aprendeu: quem é a raiz e quanto custa chegar a ela.',
        extra: o.extra ? o.extra(s.b) : undefined, phaseName: 'Eleição',
      });
    });
    tr.t = t0 + tr.ow + 0.4;
    const arrive = tr.t - 0.4;
    sends.forEach((s) => {
      const r = s.to;
      const l = s.l;
      const cand = { root: s.root, cost: s.cost + l.cost, via: l.id, from: s.b.n, sport: portNo(links, s.b.n, l), lport: portNo(links, r.n, l) };
      if (better(cand, { ...info[r.n], sport: sportOf[r.n] })) {
        const prevRoot = info[r.n].root;
        info[r.n] = { root: cand.root, cost: cand.cost, via: cand.via, from: cand.from };
        sportOf[r.n] = cand.sport;
        if (!o.quiet) {
          const rn = by(cand.root);
          tr.ev(arrive + 0.4, r.key, prevRoot !== cand.root ? 'Vê uma raiz melhor: ' + rn.name + '. Adota (custo ' + cand.cost + ')' : 'Caminho melhor até ' + rn.name + ': custo ' + cand.cost, 'ok');
          tr.lg(arrive, r.name + ': raiz ' + rn.name + ' pela porta ' + portNo(links, r.n, l) + ', custo ' + cand.cost + '.', 'conn');
        }
      }
    });
  }
  return compute(brs, links);
}

/** BPDUs descem da raiz pelas portas designadas, onda a onda (o "hello" depois de uma mudança). */
export function propagate(tr: Trace, brs: Bridge[], links: Link[], tree: Tree, o: { kind: BpduKind; start: number[]; flags?: string[]; label?: string; about: string; phaseName?: string }): void {
  const by = (n: number) => brs.find((b) => b.n === n)!;
  const seen = new Set<number>(o.start);
  let wave = o.start;
  while (wave.length) {
    const t0 = tr.t;
    const next: number[] = [];
    let sent = 0;
    wave.forEach((n) => {
      const b = by(n);
      portsOf(links, n).forEach((l) => {
        const nb = by(other(l, n));
        if (tree.role(n, l.id) !== 'designated' || !nb.alive || !l.up) return;
        const child = tree.rootLink[nb.n] === l.id;
        bpdu(tr, b, nb, {
          kind: o.kind, root: by(tree.root), cost: tree.cost[n], port: portId(links, n, l), at: t0, par: true, age: n === tree.root ? 0 : 1, flags: o.flags, role: o.kind === 'rstp' ? 'designada' : undefined,
          info: b.name + ' → ' + nb.name + ': raiz ' + by(tree.root).name + ', custo ' + tree.cost[n], about: o.about, phaseName: o.phaseName || 'Hello',
        });
        sent++;
        if (child && !seen.has(nb.n)) {
          seen.add(nb.n);
          next.push(nb.n);
        }
      });
    });
    if (sent) tr.t = t0 + tr.ow + 0.4;
    wave = next;
  }
}
