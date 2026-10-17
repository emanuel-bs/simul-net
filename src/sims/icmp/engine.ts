// Motor do ICMP (RFC 792, RFC 1191, RFC 1812, RFC 2923): ping, traceroute, tracert e hping3 em uma rede de três roteadores.
// Porte do simulador legado (removido depois da conferência) para uma função pura: dados os parâmetros, devolve o Trace.
// O que era aleatório no legado (jitter dos enlaces, identificadores, atrasos de processamento) vem de um gerador com semente
// fixa, para o mesmo parâmetro produzir sempre o mesmo trace. Os valores são ilustrativos.
import { COLORS as C0, newTrace, type Column, type Field, type StateDef, type Trace } from '../../sim-core';

export interface IcmpParams {
  tool: 'traceroute' | 'traceroute-I' | 'tracert';
  dst: string;
  count: number;
  ttl: number;
  size: number;
  pmtu: 'want' | 'do' | 'dont';
  port: number;
  max: number;
  l1up: boolean;
  l2up: boolean;
  l3up: boolean;
  l4up: boolean;
  l1mtu: number;
  l2mtu: number;
  l3mtu: number;
  l4mtu: number;
  r1acl: 'permit' | 'deny-icmp' | 'deny-icmp-errors';
  r3acl: 'permit' | 'deny-unreach' | 'deny-silent';
  r2lan: boolean;
  srvEcho: boolean;
  unr1: boolean;
  unr2: boolean;
  unr3: boolean;
}

export type Tool = 'ping' | 'traceroute' | 'traceroute-I' | 'tracert' | 'hping3';

export const DEFAULT_NET = {
  l1up: true, l2up: true, l3up: true, l4up: true, l1mtu: 1500, l2mtu: 1500, l3mtu: 1500, l4mtu: 1500,
  r1acl: 'permit', r3acl: 'permit', r2lan: true, srvEcho: true, unr1: true, unr2: true, unr3: true,
} as const;

// ---------- constantes ----------
export const PURPLE = '#B48EF0';
const ERROR_TYPES = new Set([3, 4, 5, 11, 12]);
const TYPE_NAMES: Record<number, string> = { 0: 'Echo Reply', 3: 'Destination Unreachable', 8: 'Echo Request', 11: 'Time Exceeded' };
export const UNREACH_NAMES: Record<number, string> = { 0: 'Network unreachable', 1: 'Host unreachable', 2: 'Protocol unreachable', 3: 'Port unreachable', 4: 'Fragmentation needed', 13: 'Communication administratively filtered' };
const PING_TEXT: Record<string, string> = { '11/0': 'Time to live exceeded', '3/0': 'Destination Net Unreachable', '3/1': 'Destination Host Unreachable', '3/3': 'Destination Port Unreachable', '3/13': 'Packet filtered' };
const TRACE_ANN: Record<number, string> = { 0: '!N', 1: '!H', 2: '!P', 4: '!F', 13: '!X' };
const WIN_TEXT: Record<number, string> = { 0: 'Destination net unreachable.', 1: 'Destination host unreachable.', 3: 'Destination port unreachable.', 4: 'Packet needs to be fragmented but DF set.', 13: 'Communication administratively prohibited.' };
const NOW_SECONDS = 1760000000; // carimbo de tempo ilustrativo dos dados do ping

export const COLS: Column[] = [
  { key: 'pc', label: 'PC-A', sub: 'Linux, 64', addr: '10.0.1.10' },
  { key: 'r1', label: 'R1', sub: 'roteador, 255', addr: '10.0.1.1' },
  { key: 'r2', label: 'R2', sub: 'roteador, 255', addr: '10.0.12.2' },
  { key: 'r3', label: 'R3', sub: 'roteador, 255', addr: '10.0.23.2' },
  { key: 'srv', label: 'SRV', sub: 'Linux, 64', addr: '10.0.4.20' },
];
export const STATES: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'cmd', label: 'Comando' },
  { key: 'count', label: 'Sondas (enviadas, respondidas)' },
  { key: 'resp', label: 'Última resposta' },
  { key: 'pmtu', label: 'Cache de PMTU do PC-A' },
];

const COL_OF: Record<string, string> = { 'PC-A': 'pc', R1: 'r1', R2: 'r2', R3: 'r3', SRV: 'srv' };

interface Iface { name: string; ip: string; len: number; link: string }
interface Static { net: string; len: number; via: string; key?: string }
interface NodeDef { id: string; kind: 'host' | 'router' | 'switch' | 'ghost' | 'cloud'; ttl0?: number; ifaces?: Iface[]; statics?: Static[]; udpOpen?: number[] }
interface Link { id: string; name: string; net: string; defMtu: number; delay: number; up: boolean; mtu: number }
interface Frag { off: number; dataLen: number; mf: boolean }
interface FragInfo extends Frag { idx: number; count: number }
interface IcmpData { type: number; code: number; id?: number; seq?: number; mtu?: number; quote?: number[]; orig?: Pkt }
export interface Pkt {
  src: string; dst: string; ttl: number; proto: 1 | 17; tos: number; df: boolean; data: number[]; frags: Frag[] | null; frag: FragInfo | null;
  delay: number; ipid: number; pmtuMode: string; icmp?: IcmpData; udp?: { sport: number; dport: number };
}
export interface Route { type: string; net: string; len: number; iface: Iface | null; via: string | null; active: boolean; why: string }
export interface ProbeRec { kind: string; ttl0: number; src: string | null; type: number | null; code: number | null; mtu: number; rtt?: number; ttl?: number; msg?: string; lmtu?: number }
export interface CaptureRec { where: string; pkt: Pkt }

export const NODE_IDS = ['PC-A', 'R1', 'R2', 'R3', 'SRV'];

// ---------- utilidades IP ----------
const ip2int = (ip: string) => ip.split('.').reduce((a, o) => ((a << 8) >>> 0) + +o, 0) >>> 0;
const int2ip = (n: number) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
const maskOf = (len: number) => (len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0);
const netOf = (ip: string, len: number) => int2ip((ip2int(ip) & maskOf(len)) >>> 0);
const inNet = (ip: string, net: string, len: number) => ((ip2int(ip) & maskOf(len)) >>> 0) === ip2int(net);
const hx = (n: number, w: number) => n.toString(16).padStart(w, '0');
const ipBytes = (ip: string) => ip.split('.').map(Number);
export const plural = (n: number, s: string, p: string) => n + ' ' + (n === 1 ? s : p);

/** Gerador pseudoaleatório com semente fixa (mulberry32). */
function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function buildNodes(): Record<string, NodeDef> {
  return {
    'PC-A': { id: 'PC-A', kind: 'host', ttl0: 64, ifaces: [{ name: 'eth0', ip: '10.0.1.10', len: 24, link: 'L1' }], statics: [{ net: '0.0.0.0', len: 0, via: '10.0.1.1' }] },
    R1: { id: 'R1', kind: 'router', ttl0: 255, ifaces: [{ name: 'g0/0', ip: '10.0.1.1', len: 24, link: 'L1' }, { name: 'g0/1', ip: '10.0.12.1', len: 30, link: 'L2' }], statics: [{ net: '0.0.0.0', len: 0, via: '10.0.12.2' }] },
    R2: { id: 'R2', kind: 'router', ttl0: 255, ifaces: [{ name: 'g0/0', ip: '10.0.12.2', len: 30, link: 'L2' }, { name: 'g0/1', ip: '10.0.23.1', len: 30, link: 'L3' }], statics: [{ net: '10.0.1.0', len: 24, via: '10.0.12.1' }, { net: '10.0.4.0', len: 24, via: '10.0.23.2', key: 'r2lan' }] },
    R3: { id: 'R3', kind: 'router', ttl0: 255, ifaces: [{ name: 'g0/0', ip: '10.0.23.2', len: 30, link: 'L3' }, { name: 'g0/1', ip: '10.0.4.1', len: 24, link: 'L4' }], statics: [{ net: '0.0.0.0', len: 0, via: '10.0.23.1' }] },
    SW2: { id: 'SW2', kind: 'switch' },
    SRV: { id: 'SRV', kind: 'host', ttl0: 64, udpOpen: [53, 123], ifaces: [{ name: 'eth0', ip: '10.0.4.20', len: 24, link: 'L4' }], statics: [{ net: '0.0.0.0', len: 0, via: '10.0.4.1' }] },
  };
}

export function buildLinks(P: Pick<IcmpParams, 'l1up' | 'l2up' | 'l3up' | 'l4up' | 'l1mtu' | 'l2mtu' | 'l3mtu' | 'l4mtu'>): Record<string, Link> {
  const mk = (id: string, name: string, net: string, delay: number, up: boolean, mtu: number): Link => ({ id, name, net, defMtu: 1500, delay, up, mtu });
  return {
    L1: mk('L1', 'PC-A / R1', '10.0.1.0/24', 0.3, P.l1up, P.l1mtu),
    L2: mk('L2', 'R1 / R2 (WAN)', '10.0.12.0/30', 4.2, P.l2up, P.l2mtu),
    L3: mk('L3', 'R2 / R3 (WAN)', '10.0.23.0/30', 7.1, P.l3up, P.l3mtu),
    L4: mk('L4', 'LAN do servidor', '10.0.4.0/24', 0.2, P.l4up, P.l4mtu),
  };
}

/** Rotas de um nó no estado atual da rede (para a aba Rotas e para o encaminhamento). */
export function routesOf(node: NodeDef, links: Record<string, Link>, state: { r2lan: boolean }): Route[] {
  const out: Route[] = [];
  (node.ifaces || []).forEach((i) => {
    const l = links[i.link];
    out.push({ type: 'C', net: netOf(i.ip, i.len), len: i.len, iface: i, via: null, active: l.up, why: l.up ? '' : 'enlace ' + l.name + ' caído' });
  });
  (node.statics || []).forEach((s) => {
    const enabled = !s.key || (state as Record<string, boolean>)[s.key];
    const conn = out.find((c) => c.type === 'C' && c.active && inNet(s.via, c.net, c.len));
    out.push({ type: s.len === 0 ? 'S*' : 'S', net: s.net, len: s.len, iface: conn ? conn.iface : null, via: s.via, active: !!enabled && !!conn, why: !enabled ? 'rota removida' : !conn ? 'próximo salto inalcançável' : '' });
  });
  return out;
}

export const fmtRtt = (ms: number) => (ms < 1 ? ms.toFixed(3) : ms < 10 ? ms.toFixed(2) : ms < 100 ? ms.toFixed(1) : ms.toFixed(0));

/** Linha de comando equivalente aos parâmetros. */
export function commandLine(tool: Tool, P: IcmpParams): string {
  if (tool === 'ping') {
    let s = 'ping -c ' + P.count;
    if (P.ttl !== 64) s += ' -t ' + P.ttl;
    if (P.size !== 56) s += ' -s ' + P.size;
    if (P.pmtu !== 'want') s += ' -M ' + P.pmtu;
    return s + ' ' + P.dst;
  }
  if (tool === 'traceroute') return 'traceroute -n -m ' + P.max + ' ' + P.dst;
  if (tool === 'traceroute-I') return 'traceroute -n -I -m ' + P.max + ' ' + P.dst;
  if (tool === 'tracert') return 'tracert -d -h ' + P.max + ' ' + P.dst;
  return 'hping3 --udp -p ' + P.port + ' -c ' + P.count + (P.ttl !== 64 ? ' -t ' + P.ttl : '') + ' ' + P.dst;
}

export function toolOf(sub: string, P: IcmpParams): Tool {
  return sub === 'ping' ? 'ping' : sub === 'hping' ? 'hping3' : P.tool;
}

export interface TermLine { t: number; text: string; cls: string }

export function buildIcmp(P: IcmpParams, sub: string): Trace {
  const tool = toolOf(sub, P);
  const nodes = buildNodes();
  const links = buildLinks(P);
  const state = { r1Acl: P.r1acl, r3Acl: P.r3acl, r2lan: P.r2lan, srvEcho: P.srvEcho, unreach: { R1: P.unr1, R2: P.unr2, R3: P.unr3 } as Record<string, boolean> };
  const rand = rng(0x1c3d);
  const tr = newTrace(COLS, STATES, 20);
  const term: TermLine[] = [];
  const capture: CaptureRec[] = [];
  const probes: ProbeRec[] = [];
  const pmtuEv: { t: number; dst: string; mtu: number }[] = [];
  const R: Record<string, any> = { sub, tool, P, term, probes, capture, pmtuEv, line: commandLine(tool, P), t0: 0, sent: 0, recv: 0, pmtuCache: {} };
  tr.raw = R;
  const pmtuCache: Record<string, number> = {};
  let T0 = 0; // início da sonda em curso (ms)
  let quiet = false;
  const ipIdSeq: Record<string, number> = {};

  const col = (id: string) => COL_OF[id] || 'pc';
  const nodeOfIp = (ip: string) => Object.values(nodes).find((n) => n.ifaces && n.ifaces.some((i) => i.ip === ip));
  const nameOfIp = (ip: string) => {
    const n = nodeOfIp(ip);
    return n ? n.id : ip;
  };
  const lg = (p: { delay: number } | null, text: string, tag = 'sys') => {
    if (quiet) return;
    tr.lg(T0 + (p ? p.delay : 0), text, tag);
  };
  const ev = (p: { delay: number }, nodeId: string, text: string, kind = '') => {
    if (quiet || !COL_OF[nodeId]) return;
    tr.ev(T0 + p.delay + 0.05, col(nodeId), text, kind);
  };
  let lastT = 0;
  const tline = (t: number, text: string, cls = '') => {
    term.push({ t, text, cls });
    lastT = Math.max(lastT, t);
  };

  // ---------- rotas ----------
  const routes = (n: NodeDef) => routesOf(n, links, state);
  const lookup = (n: NodeDef, dst: string) => {
    let best: Route | null = null;
    routes(n).forEach((r) => {
      if (r.active && inNet(dst, r.net, r.len) && (!best || r.len > best.len)) best = r;
    });
    const b = best as Route | null;
    if (!b) return null;
    return { iface: b.iface as Iface, nextHop: b.via || dst, route: b };
  };
  const isLocal = (n: NodeDef, ip: string) => (n.ifaces || []).some((i) => i.ip === ip && links[i.link].up);
  const neighborOn = (linkId: string, ip: string, selfId: string) => {
    for (const n of Object.values(nodes)) {
      if (n.id === selfId || !n.ifaces) continue;
      const i = n.ifaces.find((f) => f.link === linkId && f.ip === ip);
      if (i) return { node: n, iface: i };
    }
    return null;
  };
  const pmtuFor = (dst: string) => Math.min(pmtuCache[dst] || Infinity, links.L1.mtu);

  // ---------- pacotes ----------
  const nextIpId = (nodeId: string) => {
    if (ipIdSeq[nodeId] === undefined) ipIdSeq[nodeId] = 0x1000 + Math.floor(rand() * 0xd000);
    ipIdSeq[nodeId] = (ipIdSeq[nodeId] + 1) & 0xffff;
    return ipIdSeq[nodeId];
  };
  const mkPkt = (o: Partial<Pkt> & { src: string; dst: string; ttl: number; proto: 1 | 17 }, from: string): Pkt =>
    Object.assign({ tos: 0, df: false, data: [] as number[], frags: null, frag: null, delay: 0, ipid: nextIpId(from), pmtuMode: 'dont' }, o) as Pkt;
  const l4Len = (p: Pkt) => 8 + (p.proto === 1 && p.icmp && ERROR_TYPES.has(p.icmp.type) ? (p.icmp.quote as number[]).length : p.data.length);
  const totalLen = (p: Pkt) => 20 + l4Len(p);
  const maxWireSize = (p: Pkt) => (p.frags ? Math.max(...p.frags.map((f) => 20 + f.dataLen)) : totalLen(p));
  const clonePkt = (p: Pkt): Pkt => Object.assign({}, p, { icmp: p.icmp ? Object.assign({}, p.icmp) : undefined, udp: p.udp ? Object.assign({}, p.udp) : undefined, frags: p.frags ? p.frags.map((f) => Object.assign({}, f)) : null, frag: p.frag ? Object.assign({}, p.frag) : null });
  const echoData = (n: number, style: string) => {
    const d: number[] = [];
    if (style === 'win') {
      const s = 'abcdefghijklmnopqrstuvw';
      for (let i = 0; i < n; i++) d.push(s.charCodeAt(i % s.length));
      return d;
    }
    if (style === 'trace') {
      for (let i = 0; i < n; i++) d.push(0x40 + (i % 64));
      return d;
    }
    for (let i = 0; i < n; i++) d.push(i & 255);
    if (n >= 16) {
      [24, 16, 8, 0].forEach((s, k) => (d[4 + k] = (NOW_SECONDS >>> s) & 255));
      for (let k = 0; k < 4; k++) d[k] = 0;
      for (let k = 8; k < 16; k++) d[k] = k === 13 ? 0x0b : 0;
    }
    return d;
  };
  const mkEcho = (o: { dst: string; ttl: number; id: number; seq: number; size: number; df: boolean; pmtuMode?: string; style?: string }) =>
    mkPkt({ src: '10.0.1.10', dst: o.dst, ttl: o.ttl, proto: 1, df: o.df, pmtuMode: o.pmtuMode || 'dont', icmp: { type: 8, code: 0, id: o.id, seq: o.seq }, data: echoData(o.size, o.style || '') }, 'PC-A');
  const mkUdp = (o: { dst: string; ttl: number; sport: number; dport: number; size: number }) =>
    mkPkt({ src: '10.0.1.10', dst: o.dst, ttl: o.ttl, proto: 17, udp: { sport: o.sport, dport: o.dport }, data: echoData(o.size, 'trace') }, 'PC-A');

  // ---------- bytes e checksum ----------
  const csum = (b: number[]) => {
    let s = 0;
    for (let i = 0; i < b.length; i += 2) s += (b[i] << 8) + (i + 1 < b.length ? b[i + 1] : 0);
    while (s >>> 16) s = (s & 0xffff) + (s >>> 16);
    return ~s & 0xffff;
  };
  const l4Bytes = (p: Pkt): number[] => {
    if (p.proto === 1) {
      const ic = p.icmp as IcmpData;
      const b = [ic.type, ic.code, 0, 0];
      if (ic.type === 0 || ic.type === 8) {
        const id = ic.id as number;
        const seq = ic.seq as number;
        b.push(id >> 8, id & 255, seq >> 8, seq & 255);
        b.push(...p.data);
      } else {
        const m = ic.type === 3 && ic.code === 4 ? (ic.mtu as number) : 0;
        b.push(0, 0, m >> 8, m & 255);
        b.push(...(ic.quote as number[]));
      }
      const c = csum(b);
      b[2] = c >> 8;
      b[3] = c & 255;
      return b;
    }
    const u = p.udp as { sport: number; dport: number };
    const len = 8 + p.data.length;
    const b = [u.sport >> 8, u.sport & 255, u.dport >> 8, u.dport & 255, len >> 8, len & 255, 0, 0].concat(p.data);
    const pseudo = ipBytes(p.src).concat(ipBytes(p.dst), [0, 17, len >> 8, len & 255]);
    let c = csum(pseudo.concat(b));
    if (c === 0) c = 0xffff;
    b[6] = c >> 8;
    b[7] = c & 255;
    return b;
  };
  const ipHeader = (p: Pkt, frag: Frag | null) => {
    const tl = frag ? 20 + frag.dataLen : totalLen(p);
    const fl = (p.df ? 0x4000 : 0) | (frag && frag.mf ? 0x2000 : 0) | ((frag ? frag.off : 0) >> 3);
    const b = [0x45, p.tos, tl >> 8, tl & 255, p.ipid >> 8, p.ipid & 255, fl >> 8, fl & 255, p.ttl, p.proto, 0, 0].concat(ipBytes(p.src), ipBytes(p.dst));
    const c = csum(b);
    b[10] = c >> 8;
    b[11] = c & 255;
    return b;
  };
  const wireBytes = (p: Pkt) => {
    const l4 = l4Bytes(p);
    if (p.frag) return ipHeader(p, p.frag).concat(l4.slice(p.frag.off, p.frag.off + p.frag.dataLen));
    return ipHeader(p, null).concat(l4);
  };

  // ---------- descrição ----------
  const protoName = (p: Pkt) => (p.proto === 1 ? 'ICMP' : 'UDP');
  const infoOf = (p: Pkt) => {
    if (p.frag && p.frag.off > 0) return 'Fragmented IP protocol (proto=' + protoName(p) + ' ' + p.proto + ', off=' + p.frag.off + ', ID=0x' + hx(p.ipid, 4) + ') [' + p.frag.idx + '/' + p.frag.count + ']';
    let s: string;
    if (p.proto === 17) s = (p.udp as { sport: number }).sport + ' → ' + (p.udp as { dport: number }).dport + ' Len=' + p.data.length;
    else {
      const ic = p.icmp as IcmpData;
      if (ic.type === 8 || ic.type === 0) s = 'Echo (ping) ' + (ic.type === 8 ? 'request' : 'reply') + '  id=0x' + hx(ic.id as number, 4) + ', seq=' + ic.seq + ', ttl=' + p.ttl;
      else if (ic.type === 11) s = 'Time-to-live exceeded (Time to live exceeded in transit)';
      else s = 'Destination unreachable (' + (UNREACH_NAMES[ic.code] || 'code ' + ic.code) + ')' + (ic.code === 4 ? ' MTU=' + ic.mtu : '');
    }
    if (p.frag) s += ' [fragmento ' + p.frag.idx + '/' + p.frag.count + ', MF=1]';
    return s;
  };
  const pktColor = (p: Pkt) => {
    if (p.proto === 17) return C0.data as string;
    const t = (p.icmp as IcmpData).type;
    return t === 8 ? C0.plain : t === 0 ? C0.enc : t === 11 ? PURPLE : C0.bad;
  };
  const pktShort = (p: Pkt) => {
    let s: string;
    if (p.proto === 17) s = 'UDP :' + (p.udp as { dport: number }).dport;
    else {
      const ic = p.icmp as IcmpData;
      s = ic.type === 8 ? 'ECHO REQ' : ic.type === 0 ? 'ECHO REP' : ic.type === 11 ? 'TIME EXCEEDED' : 'UNREACH 3/' + ic.code;
    }
    if (p.frags && p.frags.length > 1) s += ' x' + p.frags.length + ' frag';
    return s + ' ttl=' + p.ttl;
  };
  const fieldRow = (n: string, v: string | number, m = '', c = ''): Field => [n, String(v), m, c];
  const describe = (p: Pkt): Field[] => {
    const f: Field[] = [];
    const frag = p.frag;
    const tl = frag ? 20 + frag.dataLen : totalLen(p);
    const hdr = ipHeader(p, frag);
    const fl = (p.df ? 'DF ' : '') + (frag && frag.mf ? 'MF' : '');
    f.push({ sec: 'IPv4 (RFC 791)' });
    f.push(
      fieldRow('Versão / IHL', '4 / 5', 'cabeçalho de 20 bytes, sem opções'),
      fieldRow('DSCP / ToS', '0x' + hx(p.tos, 2), p.tos === 0xc0 ? 'precedência 6 (Internetwork Control): usada em erros ICMP' : 'serviço padrão'),
      fieldRow('Comprimento total', tl, frag ? 'tamanho deste fragmento' : 'cabeçalho IP + ' + (p.proto === 1 ? 'mensagem ICMP' : 'datagrama UDP')),
      fieldRow('Identificação', '0x' + hx(p.ipid, 4) + ' (' + p.ipid + ')', 'igual em todos os fragmentos de um mesmo datagrama'),
      fieldRow('Flags', fl.trim() || 'nenhuma', p.df ? 'DF: não fragmentar; um roteador com MTU menor deve descartar e gerar 3/4' : frag && frag.mf ? 'MF: mais fragmentos a seguir' : 'roteadores podem fragmentar se preciso'),
      fieldRow('Fragment offset', frag ? (frag.off >> 3) + ' (' + frag.off + ' bytes)' : '0', frag ? 'posição dos dados no datagrama original, em unidades de 8 bytes' : ''),
      fieldRow('TTL', p.ttl, 'valor neste salto; cada roteador decrementa e descarta ao chegar a 0'),
      fieldRow('Protocolo', p.proto === 1 ? '1 (ICMP)' : '17 (UDP)'),
      fieldRow('Checksum do cabeçalho', '0x' + hx((hdr[10] << 8) | hdr[11], 4), 'recalculado em cada salto porque o TTL muda'),
      fieldRow('Origem', p.src, nameOfIp(p.src) !== p.src ? nameOfIp(p.src) : ''),
      fieldRow('Destino', p.dst, nameOfIp(p.dst) !== p.dst ? nameOfIp(p.dst) : ''),
    );
    if (p.frags && p.frags.length > 1) {
      f.push({ sec: 'Fragmentos (este salto leva os ' + p.frags.length + ')' });
      p.frags.forEach((g, i) => f.push(fieldRow('Fragmento ' + (i + 1) + ' de ' + p.frags!.length, 20 + g.dataLen + ' bytes', 'offset ' + (g.off >> 3) + ' (' + g.off + ' bytes), ' + (g.mf ? 'MF=1' : 'MF=0'))));
    }
    if (frag && frag.off > 0) {
      f.push({ sec: 'Fragmento ' + frag.idx + '/' + frag.count });
      f.push(fieldRow('Carga', frag.dataLen + ' bytes', 'continuação do datagrama: não há cabeçalho ICMP/UDP neste fragmento'));
      return f;
    }
    const l4 = l4Bytes(p);
    if (p.proto === 17) {
      const u = p.udp as { sport: number; dport: number };
      const trc = u.dport >= 33434 && u.dport < 33534;
      f.push({ sec: 'UDP (RFC 768)' });
      f.push(
        fieldRow('Porta de origem', u.sport, 'escolhida pela ferramenta'),
        fieldRow('Porta de destino', u.dport, trc ? 'porta alta improvável de estar aberta: o destino responderá 3/3 (traceroute)' : u.dport === 53 ? 'DNS' : 'porta alvo'),
        fieldRow('Comprimento', 8 + p.data.length),
        fieldRow('Checksum', '0x' + hx((l4[6] << 8) | l4[7], 4), 'inclui pseudo-cabeçalho com IPs de origem e destino'),
      );
      return f;
    }
    const ic = p.icmp as IcmpData;
    f.push({ sec: 'ICMP (RFC 792)' });
    f.push(
      fieldRow('Tipo', ic.type + ' (' + (TYPE_NAMES[ic.type] || '?') + ')', ic.type === 8 || ic.type === 0 ? 'consulta' : 'mensagem de erro, enviada à origem do datagrama'),
      fieldRow('Código', ic.code + (ic.type === 3 ? ' (' + (UNREACH_NAMES[ic.code] || '?') + ')' : ic.type === 11 ? ' (TTL exceeded in transit)' : '')),
      fieldRow('Checksum', '0x' + hx((l4[2] << 8) | l4[3], 4), 'cobre toda a mensagem ICMP'),
    );
    if (ic.type === 8 || ic.type === 0) {
      f.push(fieldRow('Identificador', '0x' + hx(ic.id as number, 4), 'distingue processos ping simultâneos'), fieldRow('Sequência', ic.seq as number, 'incrementa a cada envio; casa request e reply'), fieldRow('Dados', p.data.length + ' bytes', 'ecoados sem alteração pelo destino'));
    } else {
      if (ic.type === 3 && ic.code === 4) f.push(fieldRow('Next-Hop MTU', ic.mtu as number, 'MTU do enlace que recusou o pacote (RFC 1191)'));
      else f.push(fieldRow('Não usado', '0x00000000', 'deve ser zero'));
      f.push(fieldRow('Dados citados', (ic.quote as number[]).length + ' bytes', 'cabeçalho IP original + início do payload'));
    }
    if (ic.orig) {
      const o = ic.orig;
      f.push({ sec: 'Datagrama original citado' });
      f.push(fieldRow('Origem / destino', o.src + ' → ' + o.dst, 'o erro volta para quem enviou o original'), fieldRow('TTL citado', o.ttl, ic.type === 11 ? 'chegou com 1: por isso expirou neste roteador' : 'TTL no momento do descarte'), fieldRow('Tamanho / DF', totalLen(o) + ' bytes' + (o.df ? ' / DF=1' : ' / DF=0')));
      if (o.proto === 1) f.push(fieldRow('ICMP citado', 'tipo ' + (o.icmp as IcmpData).type + ', id 0x' + hx((o.icmp as IcmpData).id as number, 4) + ', seq ' + (o.icmp as IcmpData).seq, 'o ping usa id e seq para associar o erro ao envio'));
      else f.push(fieldRow('UDP citado', (o.udp as { sport: number }).sport + ' → ' + (o.udp as { dport: number }).dport, 'o traceroute usa a porta de destino para saber qual sonda expirou'));
    }
    // hex dump (até 160 bytes), em linhas de 16: deslocamento, bytes e ASCII
    const b = wireBytes(p);
    const max = Math.min(b.length, 160);
    f.push({ sec: 'Hex dump (primeiros ' + max + ' bytes)' });
    for (let i = 0; i < max; i += 16) {
      const row = b.slice(i, Math.min(i + 16, max));
      f.push([hx(i, 4), row.map((x) => hx(x, 2)).join(' '), row.map((x) => (x >= 32 && x < 127 ? String.fromCharCode(x) : '.')).join(''), '']);
    }
    if (b.length > max) f.push(['...', 'mais ' + (b.length - max) + ' bytes', '', '']);
    return f;
  };

  // ---------- captura e mensagens ----------
  const addCapture = (p: Pkt, where: string) => {
    capture.push({ where, pkt: clonePkt(p) });
  };

  const fragmentPkt = (p: Pkt, mtu: number, where: string) => {
    const maxData = Math.floor((mtu - 20) / 8) * 8;
    const src: Frag[] = p.frags || [{ off: 0, dataLen: l4Len(p), mf: false }];
    const out: Frag[] = [];
    src.forEach((f) => {
      if (20 + f.dataLen <= mtu) {
        out.push(f);
        return;
      }
      let off = f.off;
      let left = f.dataLen;
      while (left > 0) {
        const n = left > maxData ? maxData : left;
        left -= n;
        out.push({ off, dataLen: n, mf: left > 0 ? true : f.mf });
        off += n;
      }
    });
    p.frags = out;
    out.forEach((f, i) => {
      const s = clonePkt(p);
      s.frag = Object.assign({ idx: i + 1, count: out.length }, f);
      s.frags = null;
      addCapture(s, where);
    });
    lg(p, where + ' fragmenta o datagrama (ID 0x' + hx(p.ipid, 4) + ', ' + totalLen(p) + ' bytes) em ' + out.length + ' fragmentos para caber na MTU ' + mtu + ': ' + out.map((f) => 20 + f.dataLen + ' B, offset ' + (f.off >> 3) + (f.mf ? ', MF=1' : ', MF=0')).join(' | ') + '.', 'frag');
    ev(p, where, 'Fragmenta (MTU ' + mtu + ')', 'warn');
  };

  /** Um salto: a mensagem sai de `from` e chega a `to` depois do atraso do enlace. */
  const hopMsg = (from: string, to: string, link: Link, p: Pkt, dur: number, extra: Record<string, unknown> = {}) => {
    if (quiet) return;
    const viaSwitch = link.id === 'L4';
    tr.add(col(from), col(to), {
      at: T0 + p.delay, dur, par: true, label: pktShort(p), proto: protoName(p), color: pktColor(p), len: p.frags ? p.frags.reduce((a, g) => a + 20 + g.dataLen, 0) : totalLen(p) + 14,
      info: infoOf(p), phaseName: 'Salto ' + link.name, fields: describe(p), tags: [], about: 'Pacote em trânsito no enlace ' + link.name + ' (atraso ' + link.delay + ' ms por sentido).',
      route: viaSwitch ? [col(from), 'sw2', col(to)] : undefined, ...extra,
    });
  };
  const dropMark = (p: Pkt, nodeId: string, text: string) => ev(p, nodeId, '✕ ' + text, 'warn');

  // ---------- motor de encaminhamento ----------
  const aclR1Blocks = (p: Pkt) => {
    if (state.r1Acl === 'permit' || p.proto !== 1) return false;
    if (state.r1Acl === 'deny-icmp') return true;
    return (p.icmp as IcmpData).type !== 0; // deny-icmp-errors: só echo-reply passa
  };

  interface Res { status: string; node?: string; iface?: Iface | null; reason?: string; error?: ErrRes | null; msg?: string; mtu?: number }
  interface ErrRes { pkt: Pkt; res: Res }

  const arpFail = (node: NodeDef, iface: Iface, target: string, p: Pkt) => {
    lg(p, node.id + ' precisa do MAC de ' + target + ' e envia ARP Request em broadcast por ' + iface.name + ' (3 tentativas, 1 s cada).', 'arp');
    for (let k = 0; k < 3; k++) {
      if (!quiet) {
        tr.add(col(node.id), 'srv', {
          at: T0 + p.delay + k * 1000, dur: 0.2, par: true, label: 'ARP who-has ' + target.split('.').pop(), proto: 'ARP', color: C0.plain as string, len: 42, lost: true, info: 'Who has ' + target + '? Tell ' + iface.ip, phaseName: 'ARP',
          fields: [{ sec: 'Ethernet II' }, ['Destino', 'ff:ff:ff:ff:ff:ff', 'broadcast: todos os hosts da LAN recebem'], { sec: 'ARP' }, ['Operação', '1 (request)', ''], ['IP do remetente', iface.ip, 'interface do roteador na rede conectada'], ['IP do alvo', target, 'ninguém responde: após 3 tentativas o roteador desiste e gera 3/1']],
          tags: ['sem resposta'], about: 'ARP Request sem resposta: o endereço ' + target + ' não pertence a nenhum host da rede.', route: [col(node.id), 'sw2', 'ghost'],
        });
      }
    }
    ev(p, node.id, 'ARP sem resposta (3 tentativas)', 'warn');
    p.delay += 3000;
  };

  const transmit = (p: Pkt, fromId: string): Res => {
    let cur = fromId;
    let inIf: Iface | null = null;
    let first = true;
    let hops = 0;
    for (;;) {
      const node = nodes[cur];
      if (!first) {
        if (isLocal(node, p.dst)) return { status: 'delivered', node: cur, iface: inIf };
        if (node.kind === 'host') {
          lg(p, cur + ' recebeu um datagrama para ' + p.dst + ', mas hosts não encaminham pacotes. Descartado.', 'sys');
          return { status: 'dropped', node: cur };
        }
        if (cur === 'R1' && inIf && inIf.name === 'g0/1' && aclR1Blocks(p)) {
          lg(p, 'ACL de entrada em R1 g0/1 descarta em silêncio: ' + infoOf(p) + '.', 'acl');
          dropMark(p, cur, 'ACL');
          return { status: 'dropped', node: cur, reason: 'acl' };
        }
        if (p.ttl <= 1) {
          lg(p, cur + ' recebeu o datagrama com TTL ' + p.ttl + '. Decrementar levaria a 0: descarta e gera Time Exceeded (11/0).', 'ttl');
          dropMark(p, cur, 'TTL');
          const e = icmpError(node, p, 11, 0);
          return { status: 'dropped', node: cur, reason: 'ttl', error: e };
        }
        p.ttl--;
      }
      const r = lookup(node, p.dst);
      if (!r) {
        if (first) return { status: 'local', msg: 'net' };
        lg(p, cur + ' não tem rota para ' + p.dst + ' (nem rota padrão). Descarta e gera Destination Unreachable, código 0 (Net Unreachable).', 'unreach');
        dropMark(p, cur, 'sem rota');
        const e = icmpError(node, p, 3, 0);
        return { status: 'dropped', node: cur, reason: 'noroute', error: e };
      }
      const L = links[r.iface.link];
      if (!first && cur === 'R3' && r.iface.name === 'g0/1' && state.r3Acl !== 'permit') {
        dropMark(p, cur, 'ACL');
        if (state.r3Acl === 'deny-unreach') {
          lg(p, 'ACL de saída em R3 g0/1 nega ' + infoOf(p) + ' e responde com 3/13 (Communication Administratively Prohibited).', 'acl');
          const e = icmpError(node, p, 3, 13);
          return { status: 'dropped', node: cur, reason: 'acl', error: e };
        }
        lg(p, 'ACL de saída em R3 g0/1 nega ' + infoOf(p) + ' em silêncio (deny sem ICMP). A origem só verá timeout.', 'acl');
        return { status: 'dropped', node: cur, reason: 'acl' };
      }
      if (maxWireSize(p) > L.mtu) {
        if (p.df) {
          if (first) return { status: 'local', msg: 'mtu', mtu: L.mtu };
          lg(p, cur + ': o datagrama tem ' + totalLen(p) + ' bytes, a MTU de ' + r.iface.name + ' é ' + L.mtu + ' e o bit DF está ligado. Descarta e gera 3/4 com Next-Hop MTU = ' + L.mtu + ' (RFC 1191).', 'unreach');
          dropMark(p, cur, 'MTU ' + L.mtu);
          const e = icmpError(node, p, 3, 4, { mtu: L.mtu });
          return { status: 'dropped', node: cur, reason: 'mtu', error: e };
        }
        fragmentPkt(p, L.mtu, cur);
      }
      const nb = neighborOn(L.id, r.nextHop, cur);
      if (!nb) {
        arpFail(node, r.iface, r.nextHop, p);
        if (first) return { status: 'local', msg: 'host' };
        lg(p, cur + ' não obteve resposta ARP para ' + r.nextHop + ' na rede conectada. Gera Destination Unreachable, código 1 (Host Unreachable).', 'unreach');
        const e = icmpError(node, p, 3, 1);
        return { status: 'dropped', node: cur, reason: 'arp', error: e };
      }
      hops++;
      if (hops === 7) lg(p, 'Mais de 6 saltos: repare no TTL caindo a cada volta.', 'sys');
      const dur = L.delay * (0.95 + rand() * 0.1);
      hopMsg(cur, nb.node.id, L, p, dur);
      p.delay += dur;
      cur = nb.node.id;
      inIf = nb.iface;
      first = false;
    }
  };

  const icmpError = (node: NodeDef, orig: Pkt, type: number, code: number, extra?: { mtu: number }): ErrRes | null => {
    if (type === 3 && node.kind === 'router' && !state.unreach[node.id]) {
      lg(orig, node.id + ' está com <b>no ip unreachables</b>: descarta sem gerar ICMP tipo 3. A origem verá timeout.', 'acl');
      ev(orig, node.id, 'no ip unreachables: sem erro', 'warn');
      return null;
    }
    if (orig.proto === 1 && ERROR_TYPES.has((orig.icmp as IcmpData).type)) {
      lg(orig, node.id + ' não gera erro ICMP sobre outra mensagem de erro ICMP (RFC 1122, seção 3.2.2). O erro original se perde.', 'sys');
      return null;
    }
    const back = lookup(node, orig.src);
    if (!back) {
      lg(orig, node.id + ' não tem rota de volta para ' + orig.src + '; o erro ICMP não pode ser enviado.', 'fail');
      return null;
    }
    const firstFrag = orig.frags ? Object.assign({}, orig.frags[0]) : null;
    const quoted = clonePkt(orig);
    quoted.frags = null;
    quoted.frag = firstFrag ? Object.assign({ idx: 1, count: (orig.frags as Frag[]).length }, firstFrag) : null;
    const qLen = node.kind === 'host' ? Math.min(firstFrag ? 20 + firstFrag.dataLen : totalLen(orig), 548) : 28;
    const e = mkPkt({ src: back.iface.ip, dst: orig.src, ttl: node.ttl0 as number, tos: 0xc0, proto: 1, icmp: { type, code, mtu: (extra && extra.mtu) || 0, quote: wireBytes(quoted).slice(0, qLen), orig: quoted } }, node.id);
    e.delay = orig.delay + (node.kind === 'router' ? 0.4 + rand() * 1.4 : 0.05);
    addCapture(e, node.id);
    ev(e, node.id, 'Gera ' + (type === 11 ? 'Time Exceeded' : 'Unreachable 3/' + code), 'ok');
    const res = transmit(e, node.id);
    return { pkt: e, res };
  };

  const deliver = (res: Res, p: Pkt): ErrRes | null => {
    const node = nodes[res.node as string];
    if (p.frags && p.frags.length > 1) lg(p, node.id + ' recebe os ' + p.frags.length + ' fragmentos (ID 0x' + hx(p.ipid, 4) + ') e remonta o datagrama de ' + totalLen(p) + ' bytes.', 'frag');
    if (p.proto === 1) {
      if ((p.icmp as IcmpData).type !== 8) return null;
      if (node.id === 'SRV' && !state.srvEcho) {
        lg(p, 'O firewall de SRV descarta Echo Request em silêncio (ping bloqueado no host).', 'acl');
        dropMark(p, 'SRV', 'firewall');
        return null;
      }
      const ic = p.icmp as IcmpData;
      const r = mkPkt({ src: p.dst, dst: p.src, ttl: node.ttl0 as number, tos: p.tos, proto: 1, df: p.df, icmp: { type: 0, code: 0, id: ic.id, seq: ic.seq }, data: p.data }, node.id);
      r.delay = p.delay + (node.kind === 'router' ? 0.3 + rand() * 0.6 : 0.04);
      lg(r, node.id + ' responde com Echo Reply (0/0), mesmo id e seq, TTL inicial ' + node.ttl0 + '.', 'rep');
      addCapture(r, node.id);
      return { pkt: r, res: transmit(r, node.id) };
    }
    const u = p.udp as { dport: number };
    if (node.udpOpen && node.udpOpen.indexOf(u.dport) >= 0) {
      lg(p, 'Porta UDP ' + u.dport + ' aberta em ' + node.id + ': a aplicação recebe o datagrama e nenhum ICMP é gerado. Para o scanner, aberta e filtrada parecem iguais.', 'udp');
      ev(p, node.id, 'Porta ' + u.dport + ' aberta: sem resposta', '');
      return null;
    }
    lg(p, node.id + ': nenhuma aplicação escuta a porta UDP ' + u.dport + '. Gera Destination Unreachable, código 3 (Port Unreachable).', 'unreach');
    return icmpError(node, p, 3, 3);
  };

  interface PR { kind: string; pkt?: Pkt | { src: string }; rtt?: number; ttl?: number; msg?: string; mtu?: number }
  const probeRaw = (p: Pkt): PR => {
    p.delay = 0;
    const me = nodes['PC-A'];
    if (isLocal(me, p.dst) || p.dst.indexOf('127.') === 0) return { kind: 'reply', rtt: 0.03 + rand() * 0.02, ttl: 64, pkt: { src: p.dst } };
    const pm = pmtuFor(p.dst);
    if (totalLen(p) > pm) {
      if (p.pmtuMode === 'do') return { kind: 'local', msg: 'mtu', mtu: pm };
      if (p.pmtuMode === 'want') {
        p.df = false;
        lg(p, 'PC-A conhece a PMTU ' + pm + ' para ' + p.dst + ' e fragmenta localmente.', 'frag');
        fragmentPkt(p, pm, 'PC-A');
      }
    }
    if (!p.frags) addCapture(p, 'PC-A');
    const r = transmit(p, 'PC-A');
    if (r.status === 'local') return { kind: 'local', msg: r.msg, mtu: r.mtu };
    const back = r.status === 'delivered' ? deliver(r, p) : r.error || null;
    if (back && back.res && back.res.status === 'delivered' && back.res.node === 'PC-A') {
      const resp = back.pkt;
      const ic = resp.icmp as IcmpData;
      if (ic.type === 3 && ic.code === 4) {
        pmtuCache[p.dst] = ic.mtu as number;
        pmtuEv.push({ t: T0 + resp.delay, dst: p.dst, mtu: ic.mtu as number });
        tr.st(T0 + resp.delay, 'pmtu', Object.keys(pmtuCache).map((k) => k + ' = ' + pmtuCache[k]).join(', '), 'warn');
        lg(resp, 'PC-A grava no cache de PMTU: ' + p.dst + ' = ' + ic.mtu + ' bytes.', 'frag');
      }
      return { kind: ic.type === 0 ? 'reply' : 'error', pkt: resp, rtt: resp.delay, ttl: resp.ttl };
    }
    if (back && back.res && back.res.status === 'dropped') lg(back.pkt, 'A resposta não chegou a PC-A (descartada em ' + back.res.node + ').', 'fail');
    return { kind: 'timeout' };
  };
  const probe = (p: Pkt): PR => {
    const ttl0 = p.ttl;
    const r = probeRaw(p);
    const ic = r.pkt && (r.pkt as Pkt).icmp;
    probes.push({ kind: r.kind, ttl0, src: r.pkt ? r.pkt.src : null, type: ic ? ic.type : null, code: ic ? ic.code : null, mtu: ic && ic.mtu ? ic.mtu : 0, rtt: r.rtt, ttl: r.ttl, msg: r.msg, lmtu: r.mtu });
    return r;
  };

  // ---------- comandos ----------
  const pr = (r: PR) => (r.pkt as Pkt).icmp as IcmpData;
  tr.st(0, 'cmd', R.line, 'est');
  tr.st(0, 'count', '0 enviadas, 0 respondidas', 'closed');
  tr.st(0, 'resp', '-', 'closed');
  tr.st(0, 'pmtu', 'vazio', 'closed');
  tr.mile(0, 'Comando', R.line);
  tline(0, '$ ' + R.line, 't-prompt');
  tr.lg(0, '<b>$ ' + R.line + '</b>', 'sys');
  const sendNote = (t: number, sent: number, recv: number, resp: string, cls: string) => {
    tr.st(t, 'count', sent + ' enviadas, ' + recv + ' respondidas', recv ? 'est' : 'warn');
    tr.st(t, 'resp', resp, cls);
  };
  const respText = (r: PR) => {
    if (r.kind === 'reply') return 'Echo Reply de ' + (r.pkt as Pkt).src + ', ttl=' + r.ttl + ', ' + fmtRtt(r.rtt as number) + ' ms';
    if (r.kind === 'error') return 'ICMP ' + pr(r).type + '/' + pr(r).code + ' de ' + (r.pkt as Pkt).src;
    if (r.kind === 'timeout') return 'sem resposta (timeout)';
    return 'erro local';
  };
  let tEnd = 0;

  if (tool === 'ping') {
    const c = P;
    tline(0, 'PING ' + c.dst + ' (' + c.dst + ') ' + c.size + '(' + (c.size + 28) + ') bytes of data.');
    const id = 0x1000 + Math.floor(rand() * 0xe000);
    let sent = 0;
    let recv = 0;
    let errors = 0;
    const rtts: number[] = [];
    let aborted = false;
    for (let seq = 1; seq <= c.count; seq++) {
      T0 = (seq - 1) * 1000;
      tr.t = T0;
      if (seq === 1) {
        tr.phase('Sondas (ping)', 'probe');
        tr.st(T0, 'phase', 'sondas', 'warn');
        tr.mile(T0, 'Sondas', c.count + ' Echo Request');
      }
      const p = mkEcho({ dst: c.dst, ttl: c.ttl, id, seq, size: c.size, df: c.pmtu !== 'dont', pmtuMode: c.pmtu });
      lg({ delay: 0 }, 'PC-A envia Echo Request (8/0) id=0x' + hx(id, 4) + ' seq=' + seq + ' TTL=' + c.ttl + ' (' + totalLen(p) + ' bytes' + (p.df ? ', DF=1' : '') + ').', 'req');
      const r = probe(p);
      sent++;
      const tResp = T0 + (r.rtt || 0);
      if (r.kind === 'reply') {
        recv++;
        rtts.push(r.rtt as number);
        tline(tResp, 8 + c.size + ' bytes from ' + (r.pkt as Pkt).src + ': icmp_seq=' + seq + ' ttl=' + r.ttl + ' time=' + fmtRtt(r.rtt as number) + ' ms');
      } else if (r.kind === 'error') {
        errors++;
        const k = pr(r).type + '/' + pr(r).code;
        const txt = k === '3/4' ? 'Frag needed and DF set (mtu = ' + pr(r).mtu + ')' : PING_TEXT[k] || 'ICMP type ' + pr(r).type + ' code ' + pr(r).code;
        tline(tResp, 'From ' + (r.pkt as Pkt).src + ' icmp_seq=' + seq + ' ' + txt, 't-err');
      } else if (r.kind === 'local') {
        if (r.msg === 'net') {
          tline(T0, 'ping: connect: Network is unreachable', 't-err');
          aborted = true;
          sent--;
          break;
        }
        errors++;
        if (r.msg === 'mtu') {
          tline(T0, 'ping: local error: message too long, mtu=' + r.mtu, 't-err');
          lg({ delay: 0 }, 'PC-A recusa enviar: ' + (c.size + 28) + ' bytes excedem a PMTU ' + r.mtu + ' e -M do proíbe fragmentar.', 'frag');
          ev({ delay: 0 }, 'PC-A', 'Recusa: message too long', 'warn');
        } else tline(T0 + 3000, 'From 10.0.1.10 icmp_seq=' + seq + ' Destination Host Unreachable', 't-err');
      } else lg({ delay: 1000 }, 'Sem resposta para seq=' + seq + ' (timeout). O ping não imprime nada nesse caso.', 'fail');
      sendNote(tResp, sent, recv, respText(r), r.kind === 'reply' ? 'est' : 'bad');
      tEnd = Math.max(tEnd, T0 + 1000);
    }
    if (sent && !aborted) {
      const tf = Math.max(sent * 1000, lastT);
      tline(tf, '');
      tline(tf, '--- ' + c.dst + ' ping statistics ---');
      const loss = Math.floor(((sent - recv) * 100) / sent);
      tline(tf, sent + ' packets transmitted, ' + recv + ' received, ' + (errors ? '+' + errors + ' errors, ' : '') + loss + '% packet loss, time ' + ((sent - 1) * 1000 + Math.floor(rand() * 4)) + 'ms');
      if (rtts.length) {
        const mn = Math.min(...rtts);
        const mx = Math.max(...rtts);
        const avg = rtts.reduce((a, b) => a + b, 0) / rtts.length;
        const md = Math.sqrt(rtts.reduce((a, b) => a + b * b, 0) / rtts.length - avg * avg) || 0;
        tline(tf, 'rtt min/avg/max/mdev = ' + [mn, avg, mx, md].map((v) => v.toFixed(3)).join('/') + ' ms');
      }
      tEnd = tf;
    }
    R.sent = sent;
    R.recv = recv;
  } else if (tool === 'hping3') {
    const c = P;
    tline(0, 'HPING ' + c.dst + ' (eth0 ' + c.dst + '): udp mode set, 28 headers + 0 data bytes');
    const sport = 1024 + Math.floor(rand() * 2000);
    let sent = 0;
    let recv = 0;
    const rtts: number[] = [];
    let aborted = false;
    for (let i = 0; i < c.count; i++) {
      T0 = i * 1000;
      tr.t = T0;
      if (i === 0) {
        tr.phase('Sondas (hping3 --udp)', 'probe');
        tr.st(T0, 'phase', 'sondas', 'warn');
        tr.mile(T0, 'Sondas', c.count + ' datagramas UDP');
      }
      const p = mkUdp({ dst: c.dst, ttl: c.ttl, sport: sport + i, dport: c.port, size: 0 });
      lg({ delay: 0 }, 'PC-A envia datagrama UDP ' + (sport + i) + ' → ' + c.port + ' para ' + c.dst + '.', 'udp');
      const r = probe(p);
      sent++;
      const tResp = T0 + (r.rtt || 0);
      if (r.kind === 'error') {
        recv++;
        rtts.push(r.rtt as number);
        const ic = pr(r);
        const name = ic.type === 11 ? 'Time to live exceeded in transit' : ic.code === 3 ? 'Port Unreachable' : ic.code === 13 ? 'Packet filtered' : ic.code === 1 ? 'Host Unreachable' : ic.code === 0 ? 'Network Unreachable' : 'Unreachable type=3 code=' + ic.code;
        tline(tResp, 'ICMP ' + name + ' from ip=' + (r.pkt as Pkt).src + ' name=UNKNOWN', ic.code === 3 ? '' : 't-err');
        tline(tResp, 'status=0 port=' + (sport + i) + ' seq=' + i, 't-dim');
      } else if (r.kind === 'local') {
        tline(T0, '[send_ip] sendto: Network is unreachable', 't-err');
        aborted = true;
        sent--;
        break;
      }
      sendNote(tResp, sent, recv, respText(r), r.kind === 'error' ? 'est' : 'warn');
      tEnd = Math.max(tEnd, T0 + 1000);
    }
    if (!aborted) {
      const tf = Math.max(sent * 1000, lastT);
      tline(tf, '');
      tline(tf, '--- ' + c.dst + ' hping statistic ---');
      tline(tf, sent + ' packets transmitted, ' + recv + ' packets received, ' + (sent ? Math.round(((sent - recv) * 100) / sent) : 0) + '% packet loss');
      if (rtts.length) {
        const mn = Math.min(...rtts);
        const mx = Math.max(...rtts);
        const avg = rtts.reduce((a, b) => a + b, 0) / rtts.length;
        tline(tf, 'round-trip min/avg/max = ' + mn.toFixed(1) + '/' + avg.toFixed(1) + '/' + mx.toFixed(1) + ' ms');
      } else tline(tf, '(nenhuma resposta: porta aberta ou filtrada em silêncio)', 't-dim');
      tEnd = tf;
    }
    R.sent = sent;
    R.recv = recv;
  } else {
    const win = tool === 'tracert';
    const useIcmp = tool !== 'traceroute';
    const c = P;
    const q = 3;
    let tclock = 0;
    if (win) {
      tline(0, '');
      tline(0, 'Tracing route to ' + c.dst + ' over a maximum of ' + c.max + ' hops');
      tline(0, '');
    } else tline(0, 'traceroute to ' + c.dst + ' (' + c.dst + '), ' + c.max + ' hops max, 60 byte packets');
    const id = win ? 1 : 0x2000 + Math.floor(rand() * 0xd000);
    const sport = 40000 + Math.floor(rand() * 20000);
    let seq = 1;
    let dport = 33434;
    let done = false;
    let aborted = false;
    tr.phase('Rastreamento (' + (win ? 'tracert' : useIcmp ? 'traceroute -I' : 'traceroute') + ')', 'probe');
    tr.st(0, 'phase', 'rastreando', 'warn');
    tr.mile(0, 'Rastreamento', 'TTL 1, 2, 3...');
    let sent = 0;
    let recv = 0;
    for (let ttl = 1; ttl <= c.max && !done; ttl++) {
      const res: PR[] = [];
      for (let k = 0; k < q; k++) {
        T0 = tclock;
        quiet = k > 0; // só a primeira sonda de cada salto é desenhada
        if (k === 0) lg({ delay: 0 }, 'Sondas com TTL=' + ttl + ' (' + (useIcmp ? 'Echo Request' : 'UDP porta ' + dport + ' em diante') + ').', useIcmp ? 'req' : 'udp');
        const p = useIcmp ? mkEcho({ dst: c.dst, ttl, id, seq: seq++, size: 32, df: false, style: win ? 'win' : 'trace' }) : mkUdp({ dst: c.dst, ttl, sport, dport: dport++, size: 32 });
        const r = probe(p);
        quiet = false;
        sent++;
        if (r.kind !== 'timeout' && r.kind !== 'local') recv++;
        if (r.kind === 'local') {
          tline(tclock, win ? 'Unable to contact IP driver.' : 'connect: Network is unreachable', 't-err');
          aborted = true;
          sent--;
          break;
        }
        res.push(r);
        tclock = T0 + (r.kind === 'timeout' ? (win ? 4000 : 5000) : (r.rtt as number) + 0.5);
        if (k === 0) sendNote(T0 + (r.rtt || 0), sent, recv, 'TTL ' + ttl + ': ' + respText(r), r.kind === 'timeout' ? 'bad' : 'est');
      }
      if (aborted || !res.length) break;
      const fin = res.find((r) => r.kind !== 'timeout');
      if (fin) {
        const t = (fin.pkt as Pkt).icmp ? pr(fin).type : 0;
        if (fin.kind === 'reply' || (t === 3 && pr(fin).code === 3 && (fin.pkt as Pkt).src === c.dst) || t === 3) done = true;
      }
      const tl = tclock;
      if (win) {
        let line = String(ttl).padStart(3, ' ');
        const err = res.find((r) => r.kind === 'error' && pr(r).type === 3);
        if (err) tline(tl, line + '  ' + (err.pkt as Pkt).src + '  reports: ' + (WIN_TEXT[pr(err).code] || 'Destination unreachable.'));
        else {
          res.forEach((r) => {
            line += r.kind === 'timeout' ? '     *   ' : ' ' + ((r.rtt as number) < 1 ? '<1' : String(Math.round(r.rtt as number))).padStart(5, ' ') + ' ms';
          });
          const any = res.find((r) => r.kind !== 'timeout');
          tline(tl, line + '  ' + (any ? (any.pkt as Pkt).src : 'Request timed out.'));
        }
      } else {
        let line = String(ttl).padStart(2, ' ');
        let last: string | null = null;
        let firstPiece = true;
        res.forEach((r) => {
          if (r.kind === 'timeout') line += (firstPiece ? '  ' : ' ') + '*';
          else {
            const src = (r.pkt as Pkt).src;
            if (src !== last) {
              line += '  ' + src;
              last = src;
            }
            let ann = '';
            if (r.kind === 'error' && pr(r).type === 3 && !(pr(r).code === 3 && src === c.dst)) ann = ' ' + (TRACE_ANN[pr(r).code] || '!<' + pr(r).code + '>');
            line += '  ' + (r.rtt as number).toFixed(3) + ' ms' + ann;
          }
          firstPiece = false;
        });
        tline(tl, line);
      }
    }
    if (win && !aborted) {
      tline(tclock, '');
      tline(tclock, 'Trace complete.');
    }
    tEnd = Math.max(tclock, lastT);
    R.sent = sent;
    R.recv = recv;
  }

  quiet = false;
  R.pmtuCache = Object.assign({}, pmtuCache);
  tr.t = tEnd;
  tr.phase('Resultado', 'result');
  tr.st(tEnd, 'phase', 'concluído', 'est');
  tr.mile(tEnd, 'Resultado', R.recv + ' de ' + R.sent + ' respondidas');
  tr.lg(tEnd, 'Comando concluído: ' + R.sent + ' sondas, ' + R.recv + ' com resposta.', 'sys');
  R.tEnd = tEnd;
  return tr;
}
