// Modelo do switch Ethernet (ponte MAC, IEEE 802.1D): aprendizado do endereço de origem, tabela de endereços com
// envelhecimento, encaminhamento por destino, inundação e filtragem. Usado pelos três modos do simulador.
// Simplificações: um único switch, sem VLANs e sem spanning tree (todas as portas encaminham).
import { COLORS as C0, type Field, type Message, type Trace } from '../../sim-core';

export type HostKey = 'a' | 'b' | 'c' | 'd' | 'm';

// Endereços de documentação (RFC 5737 para IPv4; RFC 7042 e RFC 9542 para MAC).
export const HOSTS: Record<HostKey, { ip: string; mac: string; name: string }> = {
  a: { ip: '192.168.1.10', mac: '00:00:5e:00:53:0a', name: 'Host A' },
  b: { ip: '192.168.1.20', mac: '00:00:5e:00:53:14', name: 'Host B' },
  c: { ip: '192.168.1.30', mac: '00:00:5e:00:53:1e', name: 'Host C' },
  d: { ip: '192.168.1.40', mac: '00:00:5e:00:53:28', name: 'Host D' },
  m: { ip: '192.168.1.66', mac: '00:00:5e:00:53:42', name: 'Host M' },
};
export const BCAST = 'ff:ff:ff:ff:ff:ff';
/** Endereço sem dono, usado como destino dos quadros de inundação. */
export const GHOST = '00:00:5e:00:53:ee';
export const isGroup = (mac: string): boolean => (parseInt(mac.slice(0, 2), 16) & 1) === 1;

/** Tempo de envelhecimento padrão da tabela de endereços (IEEE 802.1D): 300 s. */
export const AGING_S = 300;

export type MacType = 'dynamic' | 'secure';
export interface MacEv {
  t: number;
  op: 'add' | 'refresh' | 'move' | 'del';
  mac: string;
  port: number;
  ty: MacType;
  why: string;
}
export interface Row {
  mac: string;
  port: number;
  ty: MacType;
  seen: number;
}
export type Action = 'flood' | 'forward' | 'filter' | 'drop' | 'consume' | 'group';
export interface Decision {
  t: number;
  label: string;
  src: string;
  dst: string;
  inPort: number;
  action: Action;
  out: number[];
  why: string;
}

/** Tabela de endereços no instante dado, refeita a partir dos eventos (a aba e a topologia usam esta função). */
export function tableAt(ev: MacEv[], now: number): Row[] {
  const m = new Map<string, Row>();
  [...ev]
    .sort((x, y) => x.t - y.t)
    .forEach((e) => {
      if (e.t > now) return;
      if (e.op === 'del') m.delete(e.mac);
      else m.set(e.mac, { mac: e.mac, port: e.port, ty: e.ty, seen: e.t });
    });
  return Array.from(m.values());
}

export function who(mac: string): string {
  const k = (Object.keys(HOSTS) as HostKey[]).find((h) => HOSTS[h].mac === mac);
  if (k) return HOSTS[k].name;
  if (mac === GHOST) return 'destino inexistente';
  return 'MAC forjado ' + mac.slice(-5);
}

export const forged = (n: number): string => '0a:5f:00:00:00:' + n.toString(16).padStart(2, '0');

export class Switch {
  rows = new Map<string, Row>();
  ev: MacEv[] = [];
  constructor(
    public ports: Record<number, HostKey[]>,
    public cap = 1000,
    public agingMs = AGING_S * 1000,
  ) {}

  portOf(h: HostKey): number {
    return Number(Object.keys(this.ports).find((p) => this.ports[Number(p)].includes(h)));
  }

  /** Remove as entradas dinâmicas que passaram do tempo de envelhecimento, registrando o instante real da expiração. */
  expire(tr: Trace, now: number): void {
    Array.from(this.rows.values()).forEach((r) => {
      if (r.ty !== 'dynamic' || r.seen + this.agingMs > now) return;
      const t = r.seen + this.agingMs;
      this.rows.delete(r.mac);
      this.ev.push({ t, op: 'del', mac: r.mac, port: r.port, ty: r.ty, why: 'envelhecimento' });
      tr.ev(t, 'sw', who(r.mac) + ' expira da tabela (' + this.agingMs / 1000 + ' s sem tráfego)', 'warn');
      tr.lg(t, 'Entrada de ' + who(r.mac) + ' (' + r.mac + ', porta ' + r.port + ') removida por envelhecimento.', 'loss');
    });
  }

  /** Remove todas as entradas de uma porta (por exemplo, quando ela é desativada). */
  flushPort(tr: Trace, t: number, port: number): void {
    Array.from(this.rows.values())
      .filter((r) => r.port === port)
      .forEach((r) => {
        this.rows.delete(r.mac);
        this.ev.push({ t, op: 'del', mac: r.mac, port, ty: r.ty, why: 'porta desativada' });
      });
    tr.lg(t, 'Entradas da porta ' + port + ' removidas da tabela.', 'loss');
  }

  learn(t: number, mac: string, port: number, ty: MacType = 'dynamic', why = 'aprendido'): 'new' | 'refresh' | 'move' | 'full' {
    const r = this.rows.get(mac);
    if (r) {
      const moved = r.port !== port;
      r.port = port;
      r.seen = t;
      this.ev.push({ t, op: moved ? 'move' : 'refresh', mac, port, ty: r.ty, why: moved ? 'mudou de porta' : 'tempo renovado' });
      return moved ? 'move' : 'refresh';
    }
    if (this.rows.size >= this.cap) return 'full';
    this.rows.set(mac, { mac, port, ty, seen: t });
    this.ev.push({ t, op: 'add', mac, port, ty, why });
    return 'new';
  }

  /** Entrada que já existia antes do cenário (instante 0). */
  preload(...hs: HostKey[]): void {
    hs.forEach((h) => this.learn(0, HOSTS[h].mac, this.portOf(h), 'dynamic', 'já na tabela'));
  }

  stateText(): string {
    return (this.cap < 1000 ? this.rows.size + ' de ' + this.cap : String(this.rows.size)) + ' entradas';
  }
}

export const ethHeader = (dst: string, src: string, type: string): Field[] => [
  { sec: 'Ethernet II' },
  ['Destino', dst, dst === BCAST ? 'broadcast: todos os hosts da rede local recebem' : isGroup(dst) ? 'endereço de grupo (bit 0 do primeiro byte = 1)' : 'endereço físico do destino'],
  ['Origem', src, 'o switch aprende esta associação com a porta de entrada'],
  ['Tipo', type, ''],
];

export const ipFields = (src: string, dst: string, proto: string, extra: Field[] = []): Field[] => [
  { sec: 'IPv4 (RFC 791)' },
  ['Origem', src, ''],
  ['Destino', dst, ''],
  ['Protocolo', proto, ''],
  ...extra,
];

export interface Frame {
  label: string;
  proto: string;
  info: string;
  about: string;
  len: number;
  dst: string;
  src?: string;
  etype: string;
  body: Field[];
  color?: string;
  tags?: string[];
}

export interface GateResult {
  note: string;
  log: string;
}

export interface SendOpts {
  /** Controle de entrada (segurança de porta): devolve o motivo do descarte, ou null se o quadro é aceito. */
  gate?: (src: string) => GateResult | null;
  learnTy?: MacType;
  /** Portas com assinantes do grupo (IGMP snooping); sem o campo, o multicast é inundado. */
  group?: number[];
  /** Hosts que assinaram o grupo (a placa dos demais descarta o quadro). */
  members?: HostKey[];
  /** O quadro é endereçado à própria ponte e não é encaminhado (endereços reservados, relatórios IGMP lidos pelo snooping). */
  consume?: string;
  phaseName?: string;
  /** Host que deixou a porta de destino: o quadro enviado à porta antiga se perde. */
  ghost?: HostKey;
}

export interface Sent {
  action: Action;
  ports: number[];
  hosts: HostKey[];
  m: Message;
}

/**
 * Um quadro entra no switch por A, é processado (descarte, aprendizado e decisão) e sai pelas portas escolhidas.
 * O quadro que chega à ponte e as cópias que saem são mensagens separadas no diagrama.
 */
export function sendFrame(tr: Trace, sw: Switch, decs: Decision[], from: HostKey, f: Frame, o: SendOpts = {}): Sent {
  const src = f.src || HOSTS[from].mac;
  const inPort = sw.portOf(from);
  const fields = [...ethHeader(f.dst, src, f.etype), ...f.body];
  const base = { label: f.label, proto: f.proto, len: f.len, info: f.info, about: f.about, fields, phaseName: o.phaseName || 'Quadro' };
  const m = tr.add(from, 'sw', { ...base, color: f.color || C0.plain, tags: f.tags || [] });
  const tIn = m.tArr;
  sw.expire(tr, tIn);

  // quem está no mesmo segmento (atrás de um hub) ouve o quadro sem passar pelo switch
  (sw.ports[inPort] || [])
    .filter((h) => h !== from)
    .forEach((h) => {
      tr.add(from, h, { ...base, at: m.tSend, par: true, color: f.color || C0.plain, tags: ['via hub'] });
      tr.ev(m.tArr + 0.4, h, receive(h, f.dst, o.members), '');
    });

  const rec = (action: Action, out: number[], why: string) => decs.push({ t: tIn, label: f.label, src, dst: f.dst, inPort, action, out, why });
  const dec = (text: string, cls: string) => tr.st(tIn, 'dec', text, cls);

  const dropped = o.gate ? o.gate(src) : null;
  if (dropped) {
    m.lost = true;
    m.color = C0.bad;
    m.tags = [...m.tags, 'descartado'];
    tr.ev(tIn + 0.4, 'sw', dropped.note, 'warn');
    tr.lg(tIn, dropped.log, 'loss');
    rec('drop', [], dropped.note);
    dec('descartado', 'bad');
    return { action: 'drop', ports: [], hosts: [], m };
  }
  if (o.consume) {
    tr.ev(tIn + 0.4, 'sw', o.consume, 'ok');
    tr.lg(tIn, o.consume, 'conn');
    rec('consume', [], o.consume);
    dec('processado, não encaminhado', 'warn');
    return { action: 'consume', ports: [], hosts: [], m };
  }

  // 1. aprendizado: o endereço de origem fica associado à porta de entrada (grupos nunca são aprendidos)
  const parts: string[] = [];
  let kind = 'ok';
  if (!isGroup(src)) {
    const r = sw.learn(tIn, src, inPort, o.learnTy || 'dynamic');
    if (r === 'new') parts.push('Aprende ' + who(src) + ' na porta ' + inPort);
    else if (r === 'move') {
      parts.push(who(src) + ' mudou de porta: atualiza para ' + inPort);
      kind = 'warn';
    } else if (r === 'full') {
      parts.push('Tabela cheia: ' + who(src) + ' não é aprendido');
      kind = 'warn';
      tr.lg(tIn, 'Tabela de endereços cheia (' + sw.cap + ' entradas): ' + src + ' não foi aprendido.', 'loss');
    }
    tr.st(tIn, 'tab', sw.stateText(), r === 'full' || sw.rows.size >= sw.cap ? 'bad' : 'est');
  }

  // 2. decisão pelo destino
  let action: Action;
  let ports: number[];
  let why: string;
  const all = Object.keys(sw.ports).map(Number).filter((p) => p !== inPort);
  if (f.dst === BCAST) {
    action = 'flood';
    ports = all;
    why = 'broadcast: inunda todas as portas, menos a de entrada';
  } else if (isGroup(f.dst)) {
    if (o.group) {
      action = 'group';
      ports = o.group.filter((p) => p !== inPort);
      why = ports.length ? 'grupo conhecido (snooping): só as portas com assinantes' : 'nenhuma porta assinou o grupo: o quadro não sai';
    } else {
      action = 'flood';
      ports = all;
      why = 'multicast sem snooping: tratado como broadcast';
    }
  } else {
    const r = sw.rows.get(f.dst);
    if (!r) {
      action = 'flood';
      ports = all;
      why = 'destino desconhecido: inunda todas as portas, menos a de entrada';
    } else if (r.port === inPort) {
      action = 'filter';
      ports = [];
      why = 'destino na mesma porta de entrada: filtra';
    } else {
      action = 'forward';
      ports = [r.port];
      why = 'destino conhecido na porta ' + r.port + ': encaminha só para ela';
    }
  }
  parts.push(why.charAt(0).toUpperCase() + why.slice(1));
  tr.ev(tIn + 0.4, 'sw', parts.join('. '), kind);
  tr.lg(tIn, 'Switch: ' + f.label + ' ' + who(src) + ' → ' + (f.dst === BCAST ? 'broadcast' : isGroup(f.dst) ? f.dst : who(f.dst)) + ' (porta ' + inPort + '). ' + parts.join('. ') + '.', action === 'flood' ? 'loss' : 'conn');
  rec(action, ports, why);
  dec({ flood: 'inunda ' + ports.map((p) => 'p' + p).join(', '), forward: 'encaminha para p' + ports[0], filter: 'filtra', group: ports.length ? 'grupo: ' + ports.map((p) => 'p' + p).join(', ') : 'grupo sem assinantes' }[action as 'flood' | 'forward' | 'filter' | 'group'], action === 'flood' ? 'warn' : 'est');

  // 3. saída
  const hosts = ports.flatMap((p) => sw.ports[p] || []).filter((h) => h !== from);
  hosts.forEach((h) => {
    const isDst = f.dst === HOSTS[h].mac;
    tr.add('sw', h, { ...base, par: true, color: f.color || C0.plain, tags: [...(f.tags || []), ...(action === 'flood' && !isDst && !isGroup(f.dst) ? ['inundado'] : [])] });
    tr.ev(tr.t + tr.ow + 0.4, h, receive(h, f.dst, o.members), '');
  });
  if (action === 'forward' && !hosts.length && o.ghost) {
    tr.add('sw', o.ghost, { ...base, par: true, lost: true, color: C0.bad, tags: ['porta sem host'] });
    tr.ev(tr.t + tr.ow, 'sw', 'A porta ' + ports[0] + ' não tem mais ninguém: o quadro se perde', 'warn');
    hosts.length = 0;
    tr.wait(tr.ow + 0.4);
  } else if (hosts.length) tr.wait(tr.ow + 0.4);
  return { action, ports, hosts, m };
}

function receive(h: HostKey, dst: string, members?: HostKey[]): string {
  if (dst === HOSTS[h].mac) return 'Recebe o quadro (é o destino)';
  if (dst === BCAST) return 'Recebe o broadcast';
  if (isGroup(dst)) return members && members.includes(h) ? 'Recebe (assinante do grupo)' : 'A placa descarta: grupo não assinado';
  return 'Descarta: o destino é outro MAC';
}
