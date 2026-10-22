// Motor do NAT (RFC 2663, RFC 3022, RFC 4787, RFC 5382, RFC 5508, RFC 6598 e RFC 6888): Basic NAT estático e dinâmico, NAPT (PAT),
// SNAT e DNAT, hairpinning, expiração por inatividade, esgotamento de portas e de endereços, ESP com NAT-T e CGNAT.
// Função pura: dados os parâmetros, devolve o Trace. É um modelo didático: a primeira mensagem de cada sentido representa
// a conexão (SYN e SYN+ACK no TCP), sem handshake completo, sem estados do TCP e sem fragmentação.
import { COLORS as C0, newTrace, type Column, type Field, type Message, type StateDef, type Trace } from '../../sim-core';

export type Proto = 'tcp' | 'udp' | 'icmp' | 'esp';
export type Tipo = 'estatico' | 'dinamico' | 'napt';

export interface NatParams {
  tipo: Tipo;
  pool: number;
  proto: Proto;
  mapeamento: 'eim' | 'apdm';
  mesmaPorta: boolean;
  conex: number;
  dois: boolean;
  faixa: 'ampla' | 'pequena';
  timeout: number;
  tardia: boolean;
  entrada: boolean;
  cgnat: boolean;
  natt: boolean;
  acao: 'forward' | 'hairpin' | 'proxy';
  gwOutro: boolean;
  hairpin: 'nao' | 'dnat' | 'completo';
}

export const LAN = '192.168.1';
export const IP = { pc1: LAN + '.10', pc2: LAN + '.11', web: LAN + '.50' };
export const SRV_IP = '198.51.100.10';
export const PUB = '203.0.113';
export const NAT_IN = LAN + '.1';
export const NAT_OUT = PUB + '.1';
export const CPE_OUT = '100.64.10.2';
export const CGN_IN = '100.64.0.1';
export const OTHER_SUB = '100.64.77.5';
export const RANGE = { ampla: [1024, 65535], pequena: [50000, 50002] } as const;

const PROTO_NUM: Record<Proto, string> = { tcp: 'TCP (6)', udp: 'UDP (17)', icmp: 'ICMP (1)', esp: 'ESP (50)' };
export const PROTO_NAME: Record<Proto, string> = { tcp: 'TCP', udp: 'UDP', icmp: 'ICMP', esp: 'ESP' };

export const STATES: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'tab', label: 'Entradas na tabela' },
  { key: 'drop', label: 'Pacotes descartados' },
];

export interface Ep { ip: string; port?: number }
export interface Pkt { proto: Proto; src: Ep; dst: Ep; role: 'req' | 'rep'; inner?: 'esp' }
export type EntryKind = 'estatico' | 'dinamico' | 'napt' | 'dnat' | 'hairpin' | 'outro';
export interface Entry {
  id: number;
  dev: string;
  kind: EntryKind;
  proto: Proto | 'any';
  intIp: string;
  intPort?: number;
  extIp: string;
  extPort?: number;
  remIp?: string;
  remPort?: number;
  last: number;
  perm: boolean;
  obs?: string;
}
export interface TabEv { t: number; op: 'set' | 'del'; e: Entry }
export interface DevInfo { key: string; name: string; inIp: string; outIp: string; tipo: Tipo; min: number; max: number; timeout: number; pool: string[]; rules: string[] }
export interface JournalEntry { t: number; text: string }

interface Dev extends DevInfo {
  statics: Record<string, string>;
  apdm: boolean;
  entries: Entry[];
  expired: string[];
}

/** Tempo simulado em escala humana: de milissegundos a minutos. */
export function fmtTime(ms: number): string {
  const f = (v: number) => (Math.round(v * 10) / 10).toString().replace('.', ',');
  if (ms < 1000) return f(ms) + 'ms';
  const unit = ms >= 60000 ? 60000 : 1000;
  const base = Math.floor(ms / unit);
  const rem = ms - base * unit;
  return base + (unit === 60000 ? 'min' : 's') + (rem < 0.05 ? '' : '+' + fmtTime(rem));
}

export const epText = (e: Ep) => e.ip + (e.port !== undefined ? ':' + e.port : '');

/** Aplica ao conjunto de parâmetros o que não vale no modo escolhido (controles ocultos não interferem). */
export function normalize(P: NatParams, sub: string): NatParams {
  const o = { ...P };
  if (sub === 'snat') Object.assign(o, { faixa: 'ampla', tardia: false, entrada: false, cgnat: false, natt: false, timeout: 120 });
  if (sub === 'limites') Object.assign(o, { mapeamento: 'eim', dois: false });
  if (sub === 'dnat') Object.assign(o, { tipo: 'napt', pool: 2, proto: 'tcp', faixa: 'ampla', timeout: 120, tardia: false, entrada: false, cgnat: false, natt: false, dois: false, mapeamento: 'eim', conex: 1, mesmaPorta: false });
  else Object.assign(o, { acao: 'forward', gwOutro: false, hairpin: 'completo' });
  if (o.cgnat) o.tipo = 'napt';
  if (o.proto !== 'tcp' && o.proto !== 'udp') o.dois = false;
  if (o.dois || o.tardia) o.conex = 1;
  if (o.natt && o.proto !== 'esp') o.natt = false;
  return o;
}

export function columnsFor(P: NatParams, sub: string): Column[] {
  const nat: Column = { key: 'nat', label: P.cgnat ? 'CPE' : 'R-NAT', sub: 'roteador NAT', addr: NAT_IN };
  const srv: Column = { key: 'srv', label: 'SRV', sub: 'servidor externo', addr: SRV_IP };
  if (sub === 'dnat') {
    const web: Column = { key: 'web', label: 'WEB', sub: P.acao === 'proxy' ? 'proxy interno' : 'servidor interno', addr: IP.web };
    if (P.acao === 'forward') return [{ key: 'srv', label: 'CLI', sub: 'cliente externo', addr: SRV_IP }, nat, web];
    if (P.acao === 'hairpin') return [{ key: 'pc1', label: 'PC1', sub: 'cliente interno', addr: IP.pc1 }, nat, web];
    return [{ key: 'pc1', label: 'PC1', sub: 'cliente interno', addr: IP.pc1 }, nat, web, srv];
  }
  const cols: Column[] = [{ key: 'pc1', label: 'PC1', sub: 'cliente interno', addr: IP.pc1 }];
  if (!(P.dois || P.tardia)) cols.push({ key: 'pc2', label: 'PC2', sub: 'cliente interno', addr: IP.pc2 });
  cols.push(nat);
  if (P.cgnat) cols.push({ key: 'cgn', label: 'CGN', sub: 'NAT da operadora', addr: CGN_IN });
  cols.push(srv);
  return cols;
}

/** Observação sobre a natureza de um endereço, para ensinar a faixa de cada um. */
export function ipNote(ip: string): string {
  const [a, b] = ip.split('.').map(Number);
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'privado (RFC 1918)';
  if (a === 100 && b >= 64 && b <= 127) return 'espaço compartilhado do CGNAT (RFC 6598)';
  if (ip.startsWith(PUB + '.') || ip.startsWith('198.51.100.')) return 'documentação (RFC 5737), faz o papel de endereço público';
  return '';
}

const idOf = (p: Pkt) => p.src.port ?? p.dst.port;

export function describe(p: Pkt, prev: Pkt | null, by: string): Field[] {
  const f: Field[] = [];
  const chg = (a: unknown, b: unknown) => prev !== null && a !== b;
  const row = (name: string, val: string, meaning: string, changed: boolean, was: string): Field =>
    changed ? [name, val, 'reescrito por ' + by + ' (era ' + was + ')', 'chk-ok'] : [name, val, meaning];
  f.push({ sec: 'IPv4' });
  f.push(row('Origem', p.src.ip, ipNote(p.src.ip), chg(prev?.src.ip, p.src.ip), prev?.src.ip ?? ''));
  f.push(row('Destino', p.dst.ip, ipNote(p.dst.ip), chg(prev?.dst.ip, p.dst.ip), prev?.dst.ip ?? ''));
  f.push(['Protocolo', p.inner === 'esp' ? 'UDP (17)' : PROTO_NUM[p.proto], p.inner === 'esp' ? 'ESP encapsulado em UDP (RFC 3948)' : '']);
  const addrChanged = prev !== null && (prev.src.ip !== p.src.ip || prev.dst.ip !== p.dst.ip);
  const portChanged = prev !== null && (prev.src.port !== p.src.port || prev.dst.port !== p.dst.port);
  f.push(addrChanged ? ['Checksum do cabeçalho', 'recalculado', 'muda sempre que um endereço é reescrito', 'chk-ok'] : ['Checksum do cabeçalho', 'original', '']);
  if (p.proto === 'tcp' || p.proto === 'udp') {
    f.push({ sec: p.proto === 'tcp' ? 'TCP' : p.inner === 'esp' ? 'UDP (NAT-T)' : 'UDP' });
    f.push(row('Porta de origem', String(p.src.port), p.src.port === 4500 ? 'NAT-T (RFC 3948)' : '', chg(prev?.src.port, p.src.port), String(prev?.src.port)));
    f.push(row('Porta de destino', String(p.dst.port), p.dst.port === 4500 ? 'NAT-T (RFC 3948)' : '', chg(prev?.dst.port, p.dst.port), String(prev?.dst.port)));
    if (p.proto === 'tcp') f.push(['Flags', p.role === 'req' ? 'SYN' : 'SYN, ACK', 'primeira mensagem de cada sentido da conexão']);
    f.push(addrChanged || portChanged ? ['Checksum', 'recalculado', 'cobre o pseudo-cabeçalho: endereços e portas novos mudam o valor', 'chk-ok'] : ['Checksum', 'original', '']);
    if (p.inner === 'esp') f.push({ sec: 'ESP' }, ['SPI', '0x0000a1b2', 'identifica a associação de segurança'], ['Sequência', '1', '']);
  } else if (p.proto === 'icmp') {
    f.push({ sec: 'ICMP' });
    f.push(['Tipo', p.role === 'req' ? '8 (Echo Request)' : '0 (Echo Reply)', '']);
    f.push(['Código', '0', '']);
    f.push(row('Identifier', String(idOf(p)), 'o NAT usa o identificador no lugar da porta (RFC 5508)', chg(idOf(prev ?? p), idOf(p)), String(prev ? idOf(prev) : '')));
    f.push(['Sequência', '1', '']);
    f.push(prev !== null && (addrChanged || portChanged) ? ['Checksum', 'recalculado', 'o ICMP não usa pseudo-cabeçalho, mas cobre o identificador', 'chk-ok'] : ['Checksum', 'original', '']);
  } else {
    f.push({ sec: 'ESP' });
    f.push(['SPI', '0x0000a1b2', 'identifica a associação de segurança']);
    f.push(['Sequência', '1', '']);
    f.push(['Portas', 'nenhuma', 'o NAT só enxerga endereços: não há porta para traduzir', 'chk-bad']);
  }
  return f;
}

const labelOf = (p: Pkt): string => {
  if (p.inner === 'esp') return 'ESP em UDP';
  if (p.proto === 'tcp') return p.role === 'req' ? 'SYN' : 'SYN+ACK';
  if (p.proto === 'udp') return p.role === 'req' ? 'UDP' : 'UDP (resp.)';
  if (p.proto === 'icmp') return p.role === 'req' ? 'Echo Request' : 'Echo Reply';
  return 'ESP';
};
const lenOf = (p: Pkt) => (p.inner === 'esp' ? 120 : { tcp: 60, udp: 74, icmp: 98, esp: 120 }[p.proto]);

const INSIDE = ['pc1', 'pc2', 'web'];
export function routeOf(from: string, to: string, extra?: string[]): string[] {
  if (extra) return extra;
  if (INSIDE.includes(from) && INSIDE.includes(to)) return [from, 'sw', to];
  if (INSIDE.includes(from)) return [from, 'sw', to];
  if (INSIDE.includes(to)) return [from, 'sw', to];
  return [from, to];
}

export function buildNat(Pin: NatParams, sub: string): Trace {
  const P = normalize(Pin, sub);
  const tr = newTrace(columnsFor(P, sub), STATES, 20);
  const journal: JournalEntry[] = [];
  const tabEv: TabEv[] = [];
  const flags: string[] = [];
  const R: Record<string, any> = { sub, P, journal, tabEv, flags, devs: [] as DevInfo[], drops: 0, delivered: 0, result: '' };
  tr.raw = R;
  const timeoutMs = P.timeout * 1000;
  const [pmin, pmax] = RANGE[P.faixa];
  let entryId = 0;
  let drops = 0;

  const mkDev = (key: string, name: string, inIp: string, outIp: string): Dev => ({
    key, name, inIp, outIp, tipo: P.tipo, min: pmin, max: pmax, timeout: timeoutMs, pool: [], rules: [],
    statics: {}, apdm: P.mapeamento === 'apdm', entries: [], expired: [],
  });
  const chain: Dev[] = P.cgnat ? [mkDev('nat', 'CPE', NAT_IN, CPE_OUT), mkDev('cgn', 'CGN', CGN_IN, NAT_OUT)] : [mkDev('nat', 'R-NAT', NAT_IN, NAT_OUT)];
  const nat = chain[0];
  const outer = chain[chain.length - 1];
  if (sub !== 'dnat' && P.tipo === 'dinamico') nat.pool = [PUB + '.11', PUB + '.12', PUB + '.13'].slice(0, P.pool);
  if (sub !== 'dnat' && P.tipo === 'estatico') nat.statics = { [IP.pc1]: PUB + '.11', [IP.pc2]: PUB + '.12' };
  R.devs = chain.map((d): DevInfo => ({ key: d.key, name: d.name, inIp: d.inIp, outIp: d.outIp, tipo: d.tipo, min: d.min, max: d.max, timeout: d.timeout, pool: d.pool, rules: d.rules }));
  const devInfo = (d: Dev) => (R.devs as DevInfo[]).find((x) => x.key === d.key) as DevInfo;

  const jr = (t: number, text: string) => journal.push({ t, text });
  const flag = (k: string) => {
    if (!flags.includes(k)) flags.push(k);
  };
  const total = () => chain.map((d) => d.name + ': ' + d.entries.length).join('; ');
  const sync = (t: number) => {
    tr.st(t, 'tab', total(), chain.some((d) => d.entries.length) ? 'est' : 'closed');
    tr.st(t, 'drop', String(drops), drops ? 'warn' : 'closed');
  };
  const snap = (e: Entry): Entry => ({ ...e });
  const addEntry = (d: Dev, e: Omit<Entry, 'id' | 'dev' | 'last'>): Entry => {
    const en: Entry = { ...e, id: ++entryId, dev: d.key, last: tr.t };
    d.entries.push(en);
    tabEv.push({ t: tr.t, op: 'set', e: snap(en) });
    sync(tr.t);
    return en;
  };
  const touch = (en: Entry) => {
    en.last = tr.t;
    tabEv.push({ t: tr.t, op: 'set', e: snap(en) });
  };

  /** Remove as entradas que passaram do tempo de inatividade até o instante dado, no instante exato de cada expiração. */
  const sweep = (until: number) => {
    const due: { exp: number; d: Dev; e: Entry }[] = [];
    chain.forEach((d) => d.entries.filter((e) => !e.perm && e.last + d.timeout <= until).forEach((e) => due.push({ exp: e.last + d.timeout, d, e })));
    due.sort((a, b) => a.exp - b.exp || a.e.id - b.e.id);
    due.forEach(({ exp, d, e }) => {
      d.entries.splice(d.entries.indexOf(e), 1);
      d.expired.push([e.proto, e.extIp, e.extPort ?? ''].join('|'));
      tabEv.push({ t: exp, op: 'del', e: snap(e) });
      tr.lg(exp, d.name + ': a entrada ' + e.proto.toUpperCase() + ' ' + e.extIp + (e.extPort !== undefined ? ':' + e.extPort : '') + ' expirou após ' + P.timeout + ' s sem tráfego.', 'sys');
      jr(exp, d.name + ' removeu a entrada <b>' + e.extIp + (e.extPort !== undefined ? ':' + e.extPort : '') + '</b> (expirou após ' + P.timeout + ' s sem tráfego).');
      flag('expirou');
      sync(exp);
    });
  };
  const advance = (ms: number) => {
    sweep(tr.t + ms);
    tr.wait(ms);
  };

  const portUsed = (d: Dev, proto: Proto | 'any', ip: string, port: number) => d.entries.some((e) => e.proto === proto && e.extIp === ip && e.extPort === port);
  /** Porta externa: preserva a de origem se estiver na faixa e livre; senão, a próxima livre. Devolve também se houve colisão. */
  const allocPort = (d: Dev, proto: Proto, ip: string, pref: number): { port: number; collided: boolean } | null => {
    const inRange = pref >= d.min && pref <= d.max;
    if (inRange && !portUsed(d, proto, ip, pref)) return { port: pref, collided: false };
    const size = d.max - d.min + 1;
    const start = inRange ? pref - d.min + 1 : 0;
    for (let i = 0; i < size; i++) {
      const p = d.min + ((start + i) % size);
      if (!portUsed(d, proto, ip, p)) return { port: p, collided: inRange };
    }
    return null;
  };

  interface Res { ok: boolean; pkt: Pkt; entry?: Entry; reason?: string; note?: string }
  const fail = (p: Pkt, reason: string): Res => ({ ok: false, pkt: p, reason });
  const withSrc = (p: Pkt, ip: string, port: number | undefined = p.src.port): Pkt => ({ ...p, src: { ip, port: p.src.port === undefined ? undefined : port } });
  const withDst = (p: Pkt, ip: string, port: number | undefined = p.dst.port): Pkt => ({ ...p, dst: { ip, port: p.dst.port === undefined ? undefined : port } });

  /** Pacote que sai da rede interna: aplica Basic NAT ou NAPT (SNAT). */
  const snatOut = (d: Dev, p: Pkt): Res => {
    const key = p.src.port;
    const found = d.entries.find((e) => {
      if (e.kind === 'estatico' || e.kind === 'dinamico') return e.intIp === p.src.ip;
      if (e.kind !== 'napt') return false;
      if (e.proto !== p.proto || e.intIp !== p.src.ip) return false;
      if (p.proto === 'esp') return e.remIp === p.dst.ip;
      return e.intPort === key && e.remIp === p.dst.ip && e.remPort === p.dst.port;
    });
    if (found) {
      touch(found);
      return { ok: true, pkt: withSrc(p, found.extIp, found.extPort), entry: found, note: 'usou a entrada existente' };
    }
    // mapeamento independente do destino (EIM): o mesmo endereço e porta internos reaproveitam a porta externa
    const shared = d.tipo === 'napt' && p.proto !== 'esp' && !d.apdm ? d.entries.find((e) => e.kind === 'napt' && e.proto === p.proto && e.intIp === p.src.ip && e.intPort === key) : undefined;
    if (shared) {
      const en = addEntry(d, { kind: 'napt', proto: p.proto, intIp: p.src.ip, intPort: key, extIp: shared.extIp, extPort: shared.extPort, remIp: p.dst.ip, remPort: p.dst.port, perm: false, obs: 'mesmo mapeamento' });
      flag('eim-reuso');
      return { ok: true, pkt: withSrc(p, shared.extIp, shared.extPort), entry: en, note: 'reaproveitou a porta externa ' + shared.extPort + ' (mapeamento independente do destino)' };
    }
    if (d.tipo === 'estatico') return fail(p, 'não há mapeamento estático para ' + p.src.ip);
    if (d.tipo === 'dinamico') {
      const used = d.entries.filter((e) => e.kind === 'dinamico').map((e) => e.extIp);
      const free = d.pool.find((a) => !used.includes(a));
      if (!free) return fail(p, 'pool de endereços públicos esgotado (' + d.pool.length + ' de ' + d.pool.length + ' em uso)');
      const en = addEntry(d, { kind: 'dinamico', proto: 'any', intIp: p.src.ip, extIp: free, perm: false });
      return { ok: true, pkt: withSrc(p, free), entry: en, note: 'criou o vínculo ' + p.src.ip + ' ↔ ' + free };
    }
    if (p.proto === 'esp') {
      const clash = d.entries.find((e) => e.kind === 'napt' && e.proto === 'esp' && e.extIp === d.outIp && e.remIp === p.dst.ip && e.intIp !== p.src.ip);
      if (clash) return fail(p, 'o ESP não tem porta: o NAPT não tem como distinguir este host de ' + clash.intIp + ' no tráfego de volta');
      const en = addEntry(d, { kind: 'napt', proto: 'esp', intIp: p.src.ip, extIp: d.outIp, remIp: p.dst.ip, perm: false, obs: 'sem porta (só endereços)' });
      return { ok: true, pkt: withSrc(p, d.outIp), entry: en, note: 'criou entrada só com endereços' };
    }
    const a = allocPort(d, p.proto, d.outIp, key as number);
    if (!a) return fail(p, 'sem porta livre no intervalo ' + d.min + ' a ' + d.max + ' para ' + PROTO_NAME[p.proto] + ' em ' + d.outIp);
    const en = addEntry(d, { kind: 'napt', proto: p.proto, intIp: p.src.ip, intPort: key, extIp: d.outIp, extPort: a.port, remIp: p.dst.ip, remPort: p.dst.port, perm: false });
    return { ok: true, pkt: withSrc(p, d.outIp, a.port), entry: en, note: a.collided ? 'colisão: a porta ' + key + ' já estava em uso por outro mapeamento e a porta ' + a.port + ' foi escolhida' : a.port !== key ? 'a porta ' + key + ' está fora do intervalo do NAT: usou ' + a.port : 'preservou a porta ' + key };
  };

  /** Pacote que chega de fora destinado a um endereço do NAT: reverte a tradução pela tabela. */
  const snatIn = (d: Dev, p: Pkt): Res => {
    const key = p.dst.port;
    const found = d.entries.find((e) => {
      if (e.kind === 'estatico' || e.kind === 'dinamico') return e.extIp === p.dst.ip;
      if (e.kind !== 'napt') return false;
      if (e.proto !== p.proto || e.extIp !== p.dst.ip) return false;
      if (p.proto === 'esp') return e.remIp === p.src.ip;
      return e.extPort === key && e.remIp === p.src.ip && (e.remPort === undefined || e.remPort === p.src.port);
    });
    if (found) {
      touch(found);
      return { ok: true, pkt: withDst(p, found.intIp, found.intPort), entry: found };
    }
    const was = d.expired.includes([p.proto, p.dst.ip, key ?? ''].join('|'));
    if (was) return fail(p, 'a entrada de ' + p.dst.ip + (key !== undefined ? ':' + key : '') + ' expirou por inatividade (timeout de ' + P.timeout + ' s)');
    return fail(p, 'não há entrada na tabela para ' + p.dst.ip + (key !== undefined ? ':' + key : '') + ': ninguém de dentro iniciou esta conexão');
  };

  const mkReq = (proto: Proto, src: Ep, dst: Ep, inner?: 'esp'): Pkt => ({ proto, src, dst, role: 'req', inner });
  const mkRep = (q: Pkt): Pkt => ({ proto: q.proto, src: q.proto === 'icmp' ? { ip: q.dst.ip } : q.dst, dst: q.proto === 'icmp' ? { ip: q.src.ip, port: q.src.port } : q.src, role: 'rep', inner: q.inner });

  const colorOf = (from: string, to: string, lost: boolean): string => {
    if (lost) return C0.bad;
    const mid = (from === 'nat' && to === 'cgn') || (from === 'cgn' && to === 'nat');
    if (mid) return C0.enc;
    if (from === 'srv' || to === 'srv') return C0.data;
    return C0.plain;
  };
  const hop = (from: string, to: string, p: Pkt, prev: Pkt | null, o: { by?: string; lost?: boolean; tag?: string; route?: string[]; about?: string } = {}): Message => {
    const m = tr.add(from, to, {
      label: labelOf(p), proto: p.inner === 'esp' ? 'UDP' : PROTO_NAME[p.proto], color: colorOf(from, to, !!o.lost), len: lenOf(p),
      info: epText(p.src) + ' > ' + epText(p.dst), phaseName: labelOf(p), fields: describe(p, prev, o.by ?? 'o NAT'),
      about: o.about ?? '', lost: !!o.lost, tags: o.tag ? [o.tag] : [], route: routeOf(from, to, o.route),
    });
    return m;
  };
  const note = (m: Message, who: string, text: string, kind = '') => tr.ev(m.tArr + 0.4, who, text, kind);
  const drop = (m: Message, d: Dev, reason: string) => {
    drops++;
    R.drops = drops;
    m.lost = true;
    m.color = C0.bad;
    m.tags = ['descartado por ' + d.name + ': ' + reason];
    note(m, d.key, 'Descarta: ' + reason, 'warn');
    tr.lg(m.tArr, d.name + ' descartou o pacote: ' + reason + '.', 'err');
    jr(m.tArr, d.name + ' <b>descartou</b> o pacote de ' + epText(m_src(m)) + ': ' + reason + '.');
    sync(m.tArr);
  };
  const m_src = (m: Message): Ep => {
    const [a, b] = (m.info as string).split(' > ')[0].split(':');
    return { ip: a, port: b === undefined ? undefined : Number(b) };
  };

  // ---- estado inicial ----
  tr.st(0, 'phase', 'Tabela vazia', 'warn');
  tr.st(0, 'tab', chain.map((d) => d.name + ': 0').join('; '), 'closed');
  tr.st(0, 'drop', '0', 'closed');
  tr.lg(0, 'Simulação iniciada. As tabelas de tradução estão vazias.', 'sys');

  const setupRules = () => {
    if (sub !== 'dnat') return;
    if (P.acao === 'proxy') {
      nat.rules.push('DNAT (interna): TCP, destino qualquer:80 para ' + IP.web + ':3128');
    } else {
      nat.rules.push('DNAT (externa): TCP ' + NAT_OUT + ':443 para ' + IP.web + ':8443');
    }
    devInfo(nat).rules = nat.rules;
  };
  setupRules();

  // ---- Basic NAT estático: mapeamentos permanentes desde o início ----
  if (sub !== 'dnat' && P.tipo === 'estatico') {
    const hosts = columnsFor(P, sub).filter((c) => c.key === 'pc1' || c.key === 'pc2').map((c) => c.key);
    hosts.forEach((h) => {
      const ip = (IP as Record<string, string>)[h];
      addEntry(nat, { kind: 'estatico', proto: 'any', intIp: ip, extIp: nat.statics[ip], perm: true, obs: 'configurado' });
    });
    tr.lg(0, 'Mapeamentos estáticos configurados: ' + hosts.map((h) => (IP as Record<string, string>)[h] + ' ↔ ' + nat.statics[(IP as Record<string, string>)[h]]).join('; ') + '.', 'sys');
  }
  // ---- CGNAT: outros assinantes já ocupam portas do CGN ----
  if (sub !== 'dnat' && P.cgnat) {
    const protoUsed: Proto = P.proto === 'esp' ? 'udp' : P.proto;
    [50000, 50001].forEach((port) => addEntry(outer, { kind: 'outro', proto: protoUsed, intIp: OTHER_SUB, intPort: port, extIp: outer.outIp, extPort: port, perm: true, obs: 'outro assinante' }));
    tr.lg(0, 'O CGN já atende outros assinantes: as portas 50000 e 50001 de ' + outer.outIp + ' estão em uso.', 'sys');
  }

  // ================= modos snat e limites =================
  if (sub !== 'dnat') {
    interface Conn { host: string; ip: string; port?: number; dst: Ep; label: string }
    const natT = P.natt && P.proto === 'esp';
    const proto: Proto = natT ? 'udp' : P.proto;
    const dstPorts = proto === 'tcp' ? [443, 8443] : proto === 'udp' ? (natT ? [4500, 4500] : [53, 123]) : [undefined, undefined];
    const conns: Conn[] = [];
    const hosts = P.dois || P.tardia ? ['pc1'] : ['pc1', 'pc2'];
    const hostLabel: Record<string, string> = { pc1: 'PC1', pc2: 'PC2' };
    hosts.forEach((h) => {
      const ip = (IP as Record<string, string>)[h];
      for (let k = 0; k < (proto === 'esp' ? 1 : P.conex); k++) {
        const base = proto === 'icmp' ? (h === 'pc1' || P.mesmaPorta ? 4660 : 22136) : natT ? 4500 : h === 'pc1' || P.mesmaPorta ? 50000 : 40000;
        const port = proto === 'esp' ? undefined : natT ? 4500 : base + k;
        conns.push({ host: h, ip, port, dst: { ip: SRV_IP, port: dstPorts[0] }, label: hostLabel[h] });
      }
    });
    if (P.dois) conns.push({ host: 'pc1', ip: IP.pc1, port: conns[0].port, dst: { ip: SRV_IP, port: dstPorts[1] }, label: 'PC1' });

    const runConn = (c: Conn, i: number): boolean => {
      sweep(tr.t);
      tr.phase(i + 1 + '. ' + c.label + ' acessa o servidor (' + PROTO_NAME[proto] + (natT ? ' com ESP' : '') + ')', 'c' + i);
      tr.st(tr.t, 'phase', 'Conexão ' + (i + 1) + ' de ' + conns.length, 'est');
      let p = mkReq(proto, { ip: c.ip, port: c.port }, c.dst, natT ? 'esp' : undefined);
      let from = c.host;
      let prev: Pkt | null = null;
      let by = '';
      for (const d of chain) {
        const m = hop(from, d.key, p, prev, { by, about: from === c.host ? 'Pacote original, com o endereço privado do host.' : 'Pacote já traduzido pelo dispositivo anterior.' });
        const r = snatOut(d, p);
        if (!r.ok) {
          drop(m, d, r.reason as string);
          if (/pool/.test(r.reason as string)) flag('esgotamento-pool');
          else if (/ESP/.test(r.reason as string)) flag('esp-bloqueado');
          else flag('esgotamento-portas');
          return false;
        }
        const out = r.pkt;
        const what = d.tipo === 'napt' ? 'SNAT/NAPT' : 'Basic NAT';
        note(m, d.key, what + ': ' + epText(p.src) + ' vira ' + epText(out.src) + (r.note ? ' (' + r.note + ')' : ''));
        tr.lg(m.tArr, d.name + ' traduziu a origem ' + epText(p.src) + ' para ' + epText(out.src) + (r.note ? ': ' + r.note : '') + '.', 'sys');
        jr(m.tArr, d.name + ' traduziu a origem <b>' + epText(p.src) + '</b> para <b>' + epText(out.src) + '</b>' + (r.note ? ' (' + r.note + ')' : '') + '.');
        if (r.note && r.note.startsWith('colisão')) flag('colisao');
        prev = p;
        p = out;
        from = d.key;
        by = d.name;
      }
      hop(from, 'srv', p, prev, { by, about: 'Pacote no lado externo: o servidor vê só o endereço público.' });
      flag(chain.length > 1 ? 'cgnat' : P.tipo === 'napt' ? 'napt' : P.tipo === 'estatico' ? 'basic-estatico' : 'basic-dinamico');
      if (natT) flag('nat-t');
      if (proto === 'esp' && !natT) flag('esp-ok');
      if (proto === 'icmp') flag('icmp');
      tr.ev(tr.t, 'srv', 'Vê a origem ' + epText(p.src), '');

      // resposta, depois de um atraso opcional (resposta tardia)
      const first = i === 0;
      if (P.tardia && first) {
        advance((P.timeout + 30) * 1000);
        tr.lg(tr.t, 'O servidor responde ' + (P.timeout + 30) + ' s depois, mais que o timeout de ' + P.timeout + ' s.', 'sys');
      }
      let rp = mkRep(p);
      let rfrom = 'srv';
      let rprev: Pkt | null = null;
      let rby = '';
      for (let j = chain.length - 1; j >= 0; j--) {
        const d = chain[j];
        sweep(tr.t);
        const m = hop(rfrom, d.key, rp, rprev, { by: rby, about: rfrom === 'srv' ? 'Resposta do servidor ao endereço público.' : 'Resposta a caminho do cliente.' });
        const r = snatIn(d, rp);
        if (!r.ok) {
          drop(m, d, r.reason as string);
          flag(/expirou/.test(r.reason as string) ? 'expirou-resp' : 'entrada-descartada');
          return false;
        }
        const back = r.pkt;
        note(m, d.key, 'Reverte pela tabela: destino ' + epText(rp.dst) + ' vira ' + epText(back.dst));
        tr.lg(m.tArr, d.name + ' reverteu a tradução: o destino ' + epText(rp.dst) + ' volta a ser ' + epText(back.dst) + '.', 'sys');
        jr(m.tArr, d.name + ' reverteu o destino <b>' + epText(rp.dst) + '</b> para <b>' + epText(back.dst) + '</b> pela tabela.');
        rprev = rp;
        rp = back;
        rfrom = d.key;
        rby = d.name;
      }
      hop(rfrom, c.host, rp, rprev, { by: rby, about: 'Resposta entregue ao host, que não percebe a tradução.' });
      R.delivered++;
      return true;
    };

    conns.forEach((c, i) => runConn(c, i));

    // pacote não solicitado vindo de fora
    if (P.entrada) {
      sweep(tr.t);
      tr.phase('Pacote não solicitado de fora', 'entrada');
      tr.st(tr.t, 'phase', 'Entrada não solicitada', 'warn');
      const d = outer;
      const target: Ep =
        P.tipo === 'estatico' && !P.cgnat
          ? { ip: nat.statics[IP.pc1] }
          : P.tipo === 'dinamico' && !P.cgnat
            ? { ip: d.entries.find((e) => e.kind === 'dinamico')?.extIp ?? (d.pool[0] as string) }
            : { ip: d.outIp };
      const unPort = proto === 'tcp' || proto === 'udp' ? 8080 : proto === 'icmp' ? 9999 : undefined;
      const q: Pkt =
        proto === 'icmp'
          ? { proto: 'icmp', role: 'rep', src: { ip: SRV_IP }, dst: { ip: target.ip, port: unPort } }
          : mkReq(proto, { ip: SRV_IP, port: proto === 'esp' ? undefined : 33000 }, { ip: target.ip, port: unPort }, natT ? 'esp' : undefined);
      const m = hop('srv', d.key, q, null, { about: 'Pacote iniciado de fora, sem relação com nenhuma conexão de dentro.' });
      const r = snatIn(d, q);
      if (!r.ok) {
        drop(m, d, r.reason as string);
        flag('entrada-descartada');
      } else {
        note(m, d.key, 'Entrega: há entrada que casa com ' + epText(q.dst) + ' e o destino vira ' + epText(r.pkt.dst));
        tr.lg(m.tArr, d.name + ' entregou o pacote não solicitado a ' + epText(r.pkt.dst) + ' (o mapeamento existe, mesmo sem conexão iniciada de dentro).', 'err');
        jr(m.tArr, d.name + ' <b>entregou</b> o pacote não solicitado a <b>' + epText(r.pkt.dst) + '</b>: o mapeamento ' + (r.entry?.kind === 'estatico' ? 'estático é permanente e bidirecional' : 'existente vale nos dois sentidos') + '.');
        hop(d.key, 'pc1', r.pkt, q, { by: d.name, about: 'O NAT traduziu e entregou: ele não é um filtro de segurança.' });
        flag('entrada-entregue');
      }
    }
    tr.st(tr.t, 'phase', 'Concluído', 'est');
    R.result = drops ? 'com descartes' : 'sem descartes';
    return tr;
  }

  // ================= modo dnat =================
  const web = IP.web;
  const srcClient: Ep = { ip: SRV_IP, port: 41000 };

  if (P.acao === 'forward') {
    tr.phase('1. Cliente externo acessa o serviço publicado', 'fwd');
    tr.st(tr.t, 'phase', 'DNAT: pacote de entrada', 'est');
    const p0 = mkReq('tcp', srcClient, { ip: NAT_OUT, port: 443 });
    const m0 = hop('srv', 'nat', p0, null, { about: 'O cliente conhece só o endereço público e a porta 443.' });
    const p1 = withDst(p0, web, 8443);
    note(m0, 'nat', 'PREROUTING: DNAT ' + epText(p0.dst) + ' para ' + epText(p1.dst) + ', antes de decidir a rota');
    const en = addEntry(nat, { kind: 'dnat', proto: 'tcp', intIp: web, intPort: 8443, extIp: NAT_OUT, extPort: 443, remIp: srcClient.ip, remPort: srcClient.port, perm: false, obs: 'regra DNAT' });
    tr.lg(m0.tArr, 'R-NAT aplicou DNAT: destino ' + epText(p0.dst) + ' reescrito para ' + epText(p1.dst) + '.', 'sys');
    jr(m0.tArr, 'R-NAT aplicou <b>DNAT</b>: o destino <b>' + epText(p0.dst) + '</b> virou <b>' + epText(p1.dst) + '</b>. Só então o roteamento escolheu a interface interna.');
    flag('dnat');
    hop('nat', 'web', p1, p0, { about: 'Pacote entregue ao servidor interno com o destino reescrito.' });
    const p2 = mkRep(p1);
    if (P.gwOutro) {
      const m = hop('web', 'srv', p2, null, { lost: true, route: ['web', 'sw', 'r2', 'srv'], about: 'A resposta sai por outro gateway e não passa pelo R-NAT.' });
      m.tags = ['origem inesperada: o cliente esperava ' + epText({ ip: NAT_OUT, port: 443 }) + ' e recebeu ' + epText(p2.src) + ': descarta (em TCP, responde RST)'];
      drops++;
      R.drops = drops;
      note(m, 'srv', 'Descarta: não reconhece ' + epText(p2.src) + ' como o servidor com quem falou', 'warn');
      tr.lg(m.tArr, 'A resposta de ' + epText(p2.src) + ' foi para o cliente por outro gateway, com o endereço privado como origem. O cliente a descartou.', 'err');
      jr(m.tArr, 'O WEB respondeu por <b>outro gateway</b>, sem passar pelo R-NAT. A origem <b>' + epText(p2.src) + '</b> não é a que o cliente espera, e a conexão <b>falha</b>.');
      sync(m.tArr);
      flag('assimetrico');
    } else {
      const m = hop('web', 'nat', p2, p1, { about: 'A resposta volta ao gateway padrão, que é o R-NAT.' });
      const p3: Pkt = withSrc(p2, NAT_OUT, 443);
      touch(en);
      note(m, 'nat', 'Reverte: origem ' + epText(p2.src) + ' vira ' + epText(p3.src) + ' pela tabela');
      tr.lg(m.tArr, 'R-NAT reverteu a origem ' + epText(p2.src) + ' para ' + epText(p3.src) + '.', 'sys');
      jr(m.tArr, 'R-NAT reverteu a origem <b>' + epText(p2.src) + '</b> para <b>' + epText(p3.src) + '</b> pela entrada da tabela, sem regra extra.');
      hop('nat', 'srv', p3, p2, { by: 'R-NAT', about: 'O cliente vê a resposta vinda do endereço público que consultou.' });
      R.delivered++;
    }
  } else if (P.acao === 'hairpin') {
    tr.phase('1. Cliente interno acessa o endereço público do serviço', 'hp');
    tr.st(tr.t, 'phase', 'Hairpin: ' + (P.hairpin === 'nao' ? 'sem suporte' : P.hairpin === 'dnat' ? 'só DNAT' : 'DNAT e SNAT'), 'est');
    const c: Ep = { ip: IP.pc1, port: 50000 };
    const p0 = mkReq('tcp', c, { ip: NAT_OUT, port: 443 });
    const m0 = hop('pc1', 'nat', p0, null, { about: 'O cliente interno usa o nome público do serviço, que resolve para ' + NAT_OUT + '.' });
    if (P.hairpin === 'nao') {
      drop(m0, nat, 'sem hairpin: o pacote vem da rede interna para o endereço externo do próprio roteador, que não aplica o DNAT nesse caminho');
      flag('hairpin-nao');
    } else {
      const p1 = P.hairpin === 'completo' ? withSrc(withDst(p0, web, 8443), NAT_IN, 50000) : withDst(p0, web, 8443);
      note(m0, 'nat', 'PREROUTING: DNAT ' + epText(p0.dst) + ' para ' + epText(p1.dst) + (P.hairpin === 'completo' ? '; POSTROUTING: SNAT ' + epText(c) + ' para ' + epText(p1.src) : ''));
      addEntry(nat, { kind: P.hairpin === 'completo' ? 'hairpin' : 'dnat', proto: 'tcp', intIp: web, intPort: 8443, extIp: NAT_OUT, extPort: 443, remIp: c.ip, remPort: c.port, perm: false, obs: P.hairpin === 'completo' ? 'DNAT + SNAT para ' + NAT_IN + ':50000' : 'só DNAT' });
      jr(m0.tArr, 'R-NAT aplicou <b>DNAT</b>: o destino <b>' + epText(p0.dst) + '</b> virou <b>' + epText(p1.dst) + '</b>.' + (P.hairpin === 'completo' ? ' Aplicou também <b>SNAT</b>: a origem <b>' + epText(c) + '</b> virou <b>' + epText(p1.src) + '</b>, para forçar a resposta a passar pelo roteador.' : ''));
      tr.lg(m0.tArr, 'R-NAT traduziu o destino para ' + epText(p1.dst) + (P.hairpin === 'completo' ? ' e a origem para ' + epText(p1.src) : '') + '.', 'sys');
      hop('nat', 'web', p1, p0, { by: 'R-NAT', about: P.hairpin === 'completo' ? 'A origem foi reescrita: o servidor acha que o cliente é o roteador.' : 'A origem continua sendo o cliente interno, na mesma rede do servidor.' });
      const p2 = mkRep(p1);
      if (P.hairpin === 'dnat') {
        const m = hop('web', 'pc1', p2, null, { lost: true, route: ['web', 'sw', 'pc1'], about: 'O servidor e o cliente estão na mesma rede: a resposta vai direto, sem passar pelo roteador.' });
        m.tags = ['origem inesperada: o cliente esperava ' + epText({ ip: NAT_OUT, port: 443 }) + ' e recebeu ' + epText(p2.src) + ': descarta (em TCP, responde RST)'];
        drops++;
        R.drops = drops;
        note(m, 'pc1', 'Descarta: esperava resposta de ' + epText({ ip: NAT_OUT, port: 443 }), 'warn');
        tr.lg(m.tArr, 'A resposta chegou direto do WEB (' + epText(p2.src) + ') e o cliente a descartou: ele esperava ' + NAT_OUT + ':443.', 'err');
        jr(m.tArr, 'O WEB respondeu <b>direto</b> ao PC1, que está na mesma rede, sem passar pelo roteador. A origem <b>' + epText(p2.src) + '</b> não é a esperada (' + NAT_OUT + ':443) e a conexão <b>falha</b>.');
        sync(m.tArr);
        flag('hairpin-dnat');
      } else {
        const m = hop('web', 'nat', p2, p1, { about: 'Como o destino é o roteador, a resposta passa por ele.' });
        const p3: Pkt = { proto: 'tcp', role: 'rep', src: { ip: NAT_OUT, port: 443 }, dst: c };
        note(m, 'nat', 'Reverte: origem ' + epText(p2.src) + ' vira ' + epText(p3.src) + ' e destino ' + epText(p2.dst) + ' vira ' + epText(p3.dst));
        tr.lg(m.tArr, 'R-NAT reverteu a origem para ' + epText(p3.src) + ' e o destino para ' + epText(p3.dst) + '.', 'sys');
        jr(m.tArr, 'R-NAT reverteu os dois campos: a origem voltou a ser <b>' + epText(p3.src) + '</b> e o destino, <b>' + epText(p3.dst) + '</b>. O cliente aceita a resposta.');
        hop('nat', 'pc1', p3, p2, { by: 'R-NAT', about: 'O cliente vê a resposta vinda do endereço público, como esperava.' });
        R.delivered++;
        flag('hairpin-ok');
      }
    }
  } else {
    tr.phase('1. Redirecionamento transparente para o proxy', 'proxy');
    tr.st(tr.t, 'phase', 'DNAT na interface interna', 'est');
    const c: Ep = { ip: IP.pc1, port: 50000 };
    const p0 = mkReq('tcp', c, { ip: SRV_IP, port: 80 });
    const m0 = hop('pc1', 'nat', p0, null, { about: 'O cliente quer falar com o servidor externo na porta 80.' });
    const p1 = withDst(p0, web, 3128);
    note(m0, 'nat', 'PREROUTING (interna): DNAT ' + epText(p0.dst) + ' para ' + epText(p1.dst));
    const en = addEntry(nat, { kind: 'dnat', proto: 'tcp', intIp: web, intPort: 3128, extIp: SRV_IP, extPort: 80, remIp: c.ip, remPort: c.port, perm: false, obs: 'redirecionamento transparente' });
    tr.lg(m0.tArr, 'R-NAT redirecionou o destino ' + epText(p0.dst) + ' para o proxy ' + epText(p1.dst) + '.', 'sys');
    jr(m0.tArr, 'R-NAT desviou o destino <b>' + epText(p0.dst) + '</b> para o proxy <b>' + epText(p1.dst) + '</b>. A origem não muda e o cliente não é avisado.');
    flag('proxy');
    hop('nat', 'web', p1, p0, { by: 'R-NAT', about: 'O proxy recebe o pedido que era para o servidor externo.' });
    const p2 = mkRep(p1);
    const m = hop('web', 'nat', p2, p1, { about: 'A resposta do proxy volta pelo roteador.' });
    const p3: Pkt = withSrc(p2, SRV_IP, 80);
    touch(en);
    note(m, 'nat', 'Reverte: origem ' + epText(p2.src) + ' vira ' + epText(p3.src));
    tr.lg(m.tArr, 'R-NAT reverteu a origem para ' + epText(p3.src) + ', o servidor que o cliente acredita ter contatado.', 'sys');
    jr(m.tArr, 'R-NAT reverteu a origem <b>' + epText(p2.src) + '</b> para <b>' + epText(p3.src) + '</b>: o cliente acredita ter falado com o servidor externo.');
    hop('nat', 'pc1', p3, p2, { by: 'R-NAT', about: 'O cliente vê a resposta vinda do endereço que consultou.' });
    R.delivered++;
  }
  tr.st(tr.t, 'phase', 'Concluído', 'est');
  R.result = drops ? 'com descartes' : 'sem descartes';
  return tr;
}
