// Motor do DHCP (RFC 2131, RFC 2132 e RFC 5227): DORA, conflito detectado por ARP Probe, retransmissão com backoff,
// renovação (T1), rebinding (T2), expiração e liberação do lease. Porte do simulador legado (removido depois da conferência)
// para uma função pura: dados os parâmetros, devolve o Trace. Os identificadores de transação (xid) são determinísticos.
import { COLORS as C0, hex, newTrace, type Column, type Field, type StateDef, type Trace } from '../../sim-core';

export interface DhcpParams {
  servers: number;
  lease: number;
  conflict: boolean;
  s1up: boolean;
  s2up: boolean;
  l1up: boolean;
  l2up: boolean;
  l3up: boolean;
  action: 'renew' | 'release';
  srvFail: boolean;
}

export const NET = '192.168.10';
export const MASK = '255.255.255.0';
export const GATEWAY = NET + '.254';
export const DNS_LIST = ['8.8.8.8', '1.1.1.1'];
export const BCAST_MAC = 'ff:ff:ff:ff:ff:ff';
export const BCAST_IP = '255.255.255.255';
export const CLIENT_MAC = '00:1a:2b:3c:4d:5e';
export const PCB_MAC = '00:1a:2b:aa:bb:cc';
const PURPLE = '#B48EF0';
const GRAY = '#8FA9C7';
const WHITE = '#EAF2FB';
export const MSG_NAMES: Record<number, string> = { 1: 'DHCPDISCOVER', 2: 'DHCPOFFER', 3: 'DHCPREQUEST', 4: 'DHCPDECLINE', 5: 'DHCPACK', 6: 'DHCPNAK', 7: 'DHCPRELEASE' };
const TYPE_COLOR: Record<string, string> = { DISCOVER: C0.plain, OFFER: C0.data, REQUEST: PURPLE, ACK: C0.enc, DECLINE: C0.bad, RELEASE: GRAY, ARP: WHITE };
export const t1Secs = (h: number) => (h * 3600) / 2;
export const t2Secs = (h: number) => Math.round(h * 3600 * 0.875);

export const STATES: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'cs', label: 'Estado do cliente' },
  { key: 'cfg', label: 'Configuração do cliente' },
  { key: 'sv', label: 'Leases nos servidores' },
];

export interface ServerDef { key: string; id: string; ip: string; mac: string; start: number; end: number }
export const SERVERS: ServerDef[] = [
  { key: 's1', id: 'DHCP-1', ip: NET + '.1', mac: '00:50:56:00:00:01', start: 100, end: 150 },
  { key: 's2', id: 'DHCP-2', ip: NET + '.2', mac: '00:50:56:00:00:02', start: 200, end: 250 },
];

export function columnsFor(n: number): Column[] {
  const cols: Column[] = [{ key: 'pc', label: 'PC-A', sub: 'cliente DHCP', addr: '0.0.0.0' }, { key: 's1', label: 'DHCP-1', sub: 'servidor', addr: SERVERS[0].ip }];
  if (n > 1) cols.push({ key: 's2', label: 'DHCP-2', sub: 'servidor', addr: SERVERS[1].ip });
  cols.push({ key: 'pcb', label: 'PC-B', sub: 'IP estático', addr: '' });
  return cols;
}

export interface LeaseEv { t: number; server: string; ip: string; mac: string; state: 'OFFERED' | 'BOUND' | 'DECLINED' | 'FREE'; hours?: number }
export interface JournalEntry { type: string; t: number; [k: string]: any }

interface Opt extends Array<string | number> { 0: number; 1: string; 2: string }
interface DMsg {
  kind: 'dhcp' | 'arp';
  type: string;
  op?: number;
  srcIp?: string; srcPort?: number; dstIp?: string; dstPort?: number;
  srcMac: string; dstMac: string;
  ciaddr?: string; yiaddr?: string; siaddr?: string; giaddr?: string; flags?: string; secs?: number; xid?: string;
  options?: Opt[];
  arp?: { op: string; senderMac: string; senderIp: string; targetMac: string; targetIp: string };
  info: string;
}

export function describe(m: DMsg): Field[] {
  const f: Field[] = [{ sec: 'Ethernet II' }, ['Origem', m.srcMac, ''], ['Destino', m.dstMac, m.dstMac === BCAST_MAC ? 'broadcast L2: o switch envia por todas as portas' : 'unicast L2: apenas uma porta recebe']];
  if (m.kind === 'arp' && m.arp) {
    f.push({ sec: 'ARP' }, ['Operação', m.arp.op, ''], ['MAC do remetente', m.arp.senderMac, ''], ['IP do remetente', m.arp.senderIp, m.arp.senderIp === '0.0.0.0' ? '0.0.0.0 identifica um ARP Probe (RFC 5227)' : 'quem já usa o endereço responde'], ['MAC do alvo', m.arp.targetMac, ''], ['IP do alvo', m.arp.targetIp, 'endereço que o cliente quer verificar antes de usar']);
    return f;
  }
  f.push({ sec: 'IPv4' }, ['Origem', m.srcIp as string, m.srcIp === '0.0.0.0' ? 'cliente ainda sem endereço IP' : ''], ['Destino', m.dstIp as string, m.dstIp === BCAST_IP ? 'broadcast limitado' : 'unicast'], ['Protocolo', 'UDP (17)', '']);
  f.push({ sec: 'UDP' }, ['Porta de origem', String(m.srcPort), m.srcPort === 68 ? 'cliente DHCP' : 'servidor DHCP'], ['Porta de destino', String(m.dstPort), m.dstPort === 67 ? 'servidor DHCP' : 'cliente DHCP']);
  f.push(
    { sec: 'DHCP (RFC 2131, seção 2)' },
    ['op', m.op === 1 ? '1 (BOOTREQUEST)' : '2 (BOOTREPLY)', m.op === 1 ? 'mensagem do cliente' : 'mensagem do servidor'],
    ['htype / hlen', '1 (Ethernet) / 6', ''],
    ['hops', '0', 'incrementado por relay agents'],
    ['xid', m.xid as string, 'identifica a transação, igual em todo o DORA'],
    ['secs', String(m.secs), 'segundos desde o início da aquisição'],
    ['flags', m.flags as string, m.flags === '0x8000' ? 'bit B ligado: resposta em broadcast' : 'bit B desligado: resposta em unicast'],
    ['ciaddr', m.ciaddr as string, 'IP atual do cliente (só em RENEWING, REBINDING e RELEASE)'],
    ['yiaddr', m.yiaddr as string, '"your IP": endereço atribuído pelo servidor'],
    ['siaddr', m.siaddr as string, 'IP do servidor que respondeu'],
    ['giaddr', m.giaddr as string, '0.0.0.0 indica que não há relay agent'],
    ['chaddr', CLIENT_MAC, 'endereço de hardware do cliente'],
    ['magic cookie', '0x63825363', 'marca o início das opções DHCP'],
    { sec: 'Opções DHCP (RFC 2132)' },
  );
  (m.options || []).forEach((o) => f.push(['[' + o[0] + '] ' + o[1], o[2], '']));
  return f;
}

export function buildDhcp(P: DhcpParams, sub: string): Trace {
  const nServers = Math.max(1, Math.min(2, P.servers));
  const tr = newTrace(columnsFor(nServers), STATES, 2);
  const ow = tr.ow;
  const journal: JournalEntry[] = [];
  const leaseEv: LeaseEv[] = [];
  const R: Record<string, any> = { sub, P, journal, leaseEv, t0: 0, result: '', capture: [] as DMsg[], bound: null };
  tr.raw = R;
  const linkUp: Record<string, boolean> = { s1: P.l2up, s2: P.l3up };
  const up: Record<string, boolean> = { s1: P.s1up, s2: P.s2up };
  const active = SERVERS.slice(0, nServers);
  const leases: Record<string, Map<string, { mac: string; state: string; hours?: number }>> = { s1: new Map(), s2: new Map() };
  const reachable = (s: ServerDef) => up[s.key] && linkUp[s.key] && P.l1up;
  const why = (s: ServerDef) => (!up[s.key] ? 'servidor inativo' : 'enlace caído');
  let conflictUsed = false;
  let round = 0;
  let xid = '';
  let clientIp: string | null = null;

  const jr = (type: string, data: Record<string, unknown> = {}) => journal.push({ type, t: tr.t / 1000, ...data });
  const setLease = (s: ServerDef, ip: string, state: LeaseEv['state'], mac: string, hours?: number) => {
    if (state === 'FREE') leases[s.key].delete(ip);
    else leases[s.key].set(ip, { mac, state, hours });
    leaseEv.push({ t: tr.t, server: s.id, ip, mac, state, hours });
    const summary = active.map((x) => x.id + ': ' + Array.from(leases[x.key].values()).filter((l) => l.state === 'BOUND').length + ' em uso').join('; ');
    tr.st(tr.t, 'sv', summary, 'est');
  };
  const allocate = (s: ServerDef) => {
    for (const [ip, l] of leases[s.key]) if (l.mac === CLIENT_MAC && (l.state === 'BOUND' || l.state === 'OFFERED')) return ip;
    for (let n = s.start; n <= s.end; n++) {
      const ip = NET + '.' + n;
      if (!leases[s.key].has(ip)) return ip;
    }
    return null;
  };
  const optType = (n: number): Opt => [53, 'DHCP Message Type', n + ' (' + MSG_NAMES[n] + ')'];
  const optClient = (): Opt => [61, 'Client Identifier', '01:' + CLIENT_MAC];
  const optHost = (): Opt => [12, 'Host Name', 'PC-A'];
  const optParams = (): Opt => [55, 'Parameter Request List', '1 (Mask), 3 (Router), 6 (DNS), 51, 58, 59'];
  const optConfig = (h: number): Opt[] => [
    [51, 'IP Address Lease Time', h * 3600 + ' s (' + h + ' h)'],
    [58, 'Renewal Time Value (T1)', t1Secs(h) + ' s (50% do lease)'],
    [59, 'Rebinding Time Value (T2)', t2Secs(h) + ' s (87,5% do lease)'],
    [1, 'Subnet Mask', MASK],
    [3, 'Router', GATEWAY],
    [6, 'Domain Name Server', DNS_LIST.join(', ')],
  ];
  const base = (o: Partial<DMsg> & { type: string; srcMac: string; dstMac: string; info: string }): DMsg => ({ kind: 'dhcp', giaddr: '0.0.0.0', flags: '0x0000', secs: 0, xid, ...o });

  const mkDiscover = (secs = 0) => base({ type: 'DISCOVER', op: 1, srcIp: '0.0.0.0', srcPort: 68, dstIp: BCAST_IP, dstPort: 67, srcMac: CLIENT_MAC, dstMac: BCAST_MAC, ciaddr: '0.0.0.0', yiaddr: '0.0.0.0', siaddr: '0.0.0.0', secs, options: [optType(1), optClient(), optHost(), optParams()], info: 'DHCP Discover - Transaction ID ' + xid });
  const mkOffer = (s: ServerDef, ip: string) => base({ type: 'OFFER', op: 2, srcIp: s.ip, srcPort: 67, dstIp: ip, dstPort: 68, srcMac: s.mac, dstMac: CLIENT_MAC, ciaddr: '0.0.0.0', yiaddr: ip, siaddr: s.ip, options: [optType(2), [54, 'Server Identifier', s.ip] as Opt, ...optConfig(P.lease)], info: 'DHCP Offer (' + ip + ') de ' + s.id + ' - Transaction ID ' + xid });
  const mkRequest = (s: ServerDef, ip: string, secs = 0) => base({ type: 'REQUEST', op: 1, srcIp: '0.0.0.0', srcPort: 68, dstIp: BCAST_IP, dstPort: 67, srcMac: CLIENT_MAC, dstMac: BCAST_MAC, ciaddr: '0.0.0.0', yiaddr: '0.0.0.0', siaddr: '0.0.0.0', secs, options: [optType(3), optClient(), [50, 'Requested IP Address', ip] as Opt, [54, 'Server Identifier', s.ip] as Opt, optHost(), optParams()], info: 'DHCP Request (' + ip + ') escolhendo ' + s.id + ' - Transaction ID ' + xid });
  const mkAck = (s: ServerDef, ip: string, renew: boolean) => base({ type: 'ACK', op: 2, srcIp: s.ip, srcPort: 67, dstIp: ip, dstPort: 68, srcMac: s.mac, dstMac: CLIENT_MAC, ciaddr: renew ? ip : '0.0.0.0', yiaddr: ip, siaddr: s.ip, options: [optType(5), [54, 'Server Identifier', s.ip] as Opt, ...optConfig(P.lease)], info: 'DHCP ACK (' + ip + ') de ' + s.id + (renew ? ' (renovação)' : '') + ' - Transaction ID ' + xid });
  const mkRenew = (s: ServerDef, ip: string) => base({ type: 'REQUEST', op: 1, srcIp: ip, srcPort: 68, dstIp: s.ip, dstPort: 67, srcMac: CLIENT_MAC, dstMac: s.mac, ciaddr: ip, yiaddr: '0.0.0.0', siaddr: '0.0.0.0', options: [optType(3), optClient(), optParams()], info: 'DHCP Request (RENEWING, unicast para ' + s.id + ') - Transaction ID ' + xid });
  const mkRebind = (ip: string) => base({ type: 'REQUEST', op: 1, srcIp: ip, srcPort: 68, dstIp: BCAST_IP, dstPort: 67, srcMac: CLIENT_MAC, dstMac: BCAST_MAC, ciaddr: ip, yiaddr: '0.0.0.0', siaddr: '0.0.0.0', options: [optType(3), optClient(), optParams()], info: 'DHCP Request (REBINDING, broadcast) - Transaction ID ' + xid });
  const mkDecline = (s: ServerDef, ip: string) => base({ type: 'DECLINE', op: 1, srcIp: '0.0.0.0', srcPort: 68, dstIp: s.ip, dstPort: 67, srcMac: CLIENT_MAC, dstMac: s.mac, ciaddr: '0.0.0.0', yiaddr: '0.0.0.0', siaddr: '0.0.0.0', options: [optType(4), optClient(), [50, 'Requested IP Address', ip] as Opt, [54, 'Server Identifier', s.ip] as Opt], info: 'DHCP Decline (' + ip + ' em uso) enviado a ' + s.id + ' - Transaction ID ' + xid });
  const mkRelease = (s: ServerDef, ip: string) => base({ type: 'RELEASE', op: 1, srcIp: ip, srcPort: 68, dstIp: s.ip, dstPort: 67, srcMac: CLIENT_MAC, dstMac: s.mac, ciaddr: ip, yiaddr: '0.0.0.0', siaddr: '0.0.0.0', options: [optType(7), optClient(), [54, 'Server Identifier', s.ip] as Opt], info: 'DHCP Release (' + ip + ') enviado a ' + s.id + ' - Transaction ID ' + xid });
  const mkArpProbe = (ip: string): DMsg => ({ kind: 'arp', type: 'ARP', srcMac: CLIENT_MAC, dstMac: BCAST_MAC, arp: { op: '1 (request, ARP Probe)', senderMac: CLIENT_MAC, senderIp: '0.0.0.0', targetMac: '00:00:00:00:00:00', targetIp: ip }, info: 'Who has ' + ip + '? Tell 0.0.0.0 (ARP Probe)' });
  const mkArpReply = (ip: string): DMsg => ({ kind: 'arp', type: 'ARP', srcMac: PCB_MAC, dstMac: CLIENT_MAC, arp: { op: '2 (reply)', senderMac: PCB_MAC, senderIp: ip, targetMac: CLIENT_MAC, targetIp: '0.0.0.0' }, info: ip + ' is at ' + PCB_MAC + ' (conflito)' });

  const labelOf = (m: DMsg) => (m.kind === 'arp' ? (m.info.indexOf('Probe') >= 0 ? 'ARP Probe' : 'ARP Reply') : m.type);
  /** Uma mensagem entre dois nós da rede (sempre pelo switch SW1). */
  const send = (from: string, to: string, m: DMsg, o: { par?: boolean; lost?: boolean; about: string; tags?: string[] }) => {
    R.capture.push(m);
    return tr.add(from, to, {
      label: labelOf(m), proto: m.kind === 'arp' ? 'ARP' : 'DHCP', color: TYPE_COLOR[m.type] || C0.plain, len: m.kind === 'arp' ? 42 : 342, info: m.info, phaseName: m.type,
      fields: describe(m), about: o.about, par: !!o.par, lost: !!o.lost, tags: o.tags || [],
    });
  };
  /** Broadcast do cliente: todos os servidores e o PC-B recebem; só os alcançáveis processam. */
  const bcast = (m: DMsg, about: string) => {
    const targets = [...active.map((s) => ({ key: s.key, s })), { key: 'pcb', s: null as ServerDef | null }];
    let arr = 0;
    targets.forEach((tg, i) => {
      const lost = tg.s ? !reachable(tg.s) : !P.l1up;
      const msg = send('pc', tg.key, m, { par: i < targets.length - 1, lost, about, tags: lost && tg.s ? [why(tg.s)] : [] });
      arr = msg.tArr;
    });
    return arr;
  };
  const ev = (t: number, who: string, text: string, k = '') => tr.ev(t + 0.4, who, text, k);

  const setClient = (state: string, cls: string) => tr.st(tr.t, 'cs', state, cls);
  const setCfg = (ip: string | null, s?: ServerDef) =>
    tr.st(tr.t, 'cfg', ip ? ip + '/24, gateway ' + GATEWAY + ', DNS ' + DNS_LIST.join(', ') + (s ? ' (' + s.id + ')' : '') : '0.0.0.0 (sem configuração)', ip ? 'est' : 'closed');

  // ---- estado inicial ----
  tr.st(0, 'phase', 'INIT', 'warn');
  setClient('INIT', 'warn');
  setCfg(null);
  tr.st(0, 'sv', active.map((s) => s.id + ': 0 em uso').join('; '), 'closed');
  tr.mile(0, 'INIT', 'sem endereço IP');
  tr.lg(0, 'PC-A iniciou sem endereço IP (0.0.0.0). Estado: INIT.', 'sys');
  tr.ev(0, 'pc', 'Sem endereço IP (INIT)', '');

  let binding: { s: ServerDef; ip: string; hours: number } | null = null;

  /** Uma negociação DORA completa. Devolve true se o cliente ficou em BOUND. */
  const acquire = (): boolean => {
    round++;
    xid = '0x' + hex('xid' + round, 8);
    tr.phase('1. DISCOVER (broadcast)', 'discover');
    tr.st(tr.t, 'phase', 'DISCOVER', 'warn');
    if (round === 1) tr.mile(tr.t, 'DISCOVER', 'broadcast');
    setClient('SELECTING', 'warn');
    if (!P.l1up) {
      const m = send('pc', 's1', mkDiscover(), { lost: true, about: 'O enlace PC-A / SW1 está caído: o quadro não sai do cliente.', tags: ['enlace caído'] });
      ev(m.tArr, 'pc', 'Enlace caído: não transmite', 'warn');
      tr.lg(m.tSend, 'O enlace PC-A / SW1 está caído: o cliente não consegue transmitir.', 'fail');
      jr('linkdown');
      R.result = 'linkdown';
      return false;
    }
    const arr = bcast(mkDiscover(), 'O cliente ainda não tem endereço: sai de 0.0.0.0:68 para 255.255.255.255:67. O switch inunda o quadro por todas as portas.');
    tr.lg(tr.t, 'PC-A envia <b>DHCPDISCOVER</b> em broadcast (0.0.0.0:68 para 255.255.255.255:67), xid ' + xid + '. Estado: INIT para SELECTING.', 'discover');
    ev(arr, 'pcb', 'Descarta: não sou servidor DHCP', '');
    active.forEach((s) => {
      if (reachable(s)) tr.lg(tr.t, s.id + ' recebeu o DISCOVER.', 'discover');
      else {
        tr.lg(tr.t, s.id + ' não recebeu o DISCOVER (' + why(s) + ').', 'fail');
        ev(arr, s.key, 'Não recebeu (' + why(s) + ')', 'warn');
      }
    });
    jr('discover', { xid, reached: active.filter(reachable).map((s) => s.id), missed: active.filter((s) => !reachable(s)).map((s) => s.id + ' (' + why(s) + ')') });

    // OFFERs, com retransmissão e backoff quando ninguém responde
    let retry = 0;
    let offers: { s: ServerDef; ip: string }[] = [];
    for (;;) {
      offers = [];
      tr.phase('2. OFFER (servidores)', 'offer');
      tr.st(tr.t, 'phase', 'OFFER', 'warn');
      active.forEach((s) => {
        if (!reachable(s)) return;
        const ip = allocate(s);
        if (ip) {
          setLease(s, ip, 'OFFERED', CLIENT_MAC);
          offers.push({ s, ip });
        } else tr.lg(tr.t, s.id + ' não tem endereços livres no pool e não responde.', 'fail');
      });
      if (offers.length) break;
      const delay = Math.min(64, 4 * Math.pow(2, retry));
      jr('nooffer', { delay, why: active.map((s) => (!up[s.key] ? s.id + ' inativo' : !linkUp[s.key] || !P.l1up ? 'enlace de ' + s.id + ' caído' : s.id + ' sem endereços livres')) });
      tr.lg(tr.t, 'Nenhum OFFER recebido. O cliente espera ' + delay + ' s (backoff exponencial, RFC 2131 seção 4.1) e retransmite o DISCOVER.', 'fail');
      ev(tr.t, 'pc', 'Sem OFFER: espera ' + delay + ' s', 'warn');
      retry++;
      if (retry > 3) {
        tr.lg(tr.t, 'O cliente continuaria tentando, com espera de até 64 s entre as tentativas. O simulador mostra as três primeiras retransmissões.', 'fail');
        R.result = 'nooffer';
        setClient('SELECTING', 'bad');
        return false;
      }
      tr.wait(delay * 1000);
      tr.phase('Retransmissão do DISCOVER', 'retry');
      const rarr = bcast(mkDiscover(Math.round(tr.t / 1000)), 'Retransmissão do DISCOVER depois do backoff (o campo secs mostra há quanto tempo o cliente tenta).');
      ev(rarr, 'pcb', 'Descarta: não sou servidor DHCP', '');
    }
    offers.forEach((o) => {
      const m = send(o.s.key, 'pc', mkOffer(o.s, o.ip), { par: o !== offers[offers.length - 1], about: 'O servidor reserva ' + o.ip + ' e responde em unicast ao MAC do cliente (flag broadcast desligada).' });
      tr.lg(m.tSend, o.s.id + ' reserva ' + o.ip + ' e envia <b>DHCPOFFER</b> em unicast para ' + CLIENT_MAC + ' (flag broadcast desligada, então a resposta usa yiaddr como destino).', 'offer');
    });
    const chosen = offers[0];
    tr.lg(tr.t, 'Cliente recebeu ' + offers.length + ' OFFER(s) e escolhe a oferta de ' + chosen.s.id + ' (' + chosen.ip + ').' + (offers.length > 1 ? ' O RFC permite qualquer critério; aqui vale a primeira recebida.' : ''), 'offer');
    ev(tr.t - 0.4, 'pc', 'Escolhe a oferta de ' + chosen.s.id, 'ok');
    jr('offer', { offers: offers.map((o) => ({ s: o.s.id, ip: o.ip })), chosen: chosen.s.id });
    if (round === 1) tr.mile(tr.t, 'OFFER', offers.length + (offers.length > 1 ? ' ofertas' : ' oferta'));

    // REQUEST (broadcast, com a opção 54)
    tr.phase('3. REQUEST (broadcast)', 'request');
    tr.st(tr.t, 'phase', 'REQUEST', 'warn');
    setClient('REQUESTING', 'warn');
    const rq = bcast(mkRequest(chosen.s, chosen.ip), 'O REQUEST vai em broadcast e leva a opção 54 (Server Identifier): o servidor escolhido confirma e os demais devolvem a oferta.');
    tr.lg(tr.t, 'PC-A envia <b>DHCPREQUEST</b> em broadcast pedindo ' + chosen.ip + ' (opção 50) ao servidor ' + chosen.s.id + ' (opção 54). Estado: SELECTING para REQUESTING.', 'request');
    offers.forEach((o) => {
      if (o !== chosen) {
        setLease(o.s, o.ip, 'FREE', CLIENT_MAC);
        tr.lg(tr.t, o.s.id + ' vê que a opção 54 aponta para ' + chosen.s.id + ', cancela sua oferta e devolve ' + o.ip + ' ao pool.', 'request');
        ev(rq, o.s.key, 'Oferta cancelada: devolve ' + o.ip, '');
      }
    });
    jr('request', { ip: chosen.ip, s: chosen.s.id, cancelled: offers.filter((o) => o !== chosen).map((o) => o.s.id) });
    if (round === 1) tr.mile(tr.t, 'REQUEST', 'escolha');

    // ACK e verificação por ARP
    const s = chosen.s;
    const ip = chosen.ip;
    tr.phase('4. ACK e ARP Probe', 'ack');
    tr.st(tr.t, 'phase', 'ACK', 'warn');
    setLease(s, ip, 'BOUND', CLIENT_MAC, P.lease);
    const ack = send(s.key, 'pc', mkAck(s, ip, false), { about: 'O servidor grava o lease e confirma em unicast. A configuração (máscara, gateway, DNS, lease, T1 e T2) vem nas opções.' });
    tr.lg(ack.tSend, s.id + ' grava o lease de ' + ip + ' (' + P.lease + ' h) e envia <b>DHCPACK</b> em unicast.', 'ack');
    tr.lg(tr.t, 'Antes de usar ' + ip + ', o cliente executa um ARP Probe (RFC 2131 seção 3.1, passo 5) para detectar conflito.', 'arp');
    const probeArr = (() => {
      const targets = [...active.map((x) => x.key), 'pcb'];
      let a = 0;
      targets.forEach((k, i) => {
        a = send('pc', k, mkArpProbe(ip), { par: i < targets.length - 1, about: 'O ARP Probe pergunta se alguém usa ' + ip + ', com 0.0.0.0 como origem (RFC 5227).', tags: ['Probe'] }).tArr;
      });
      return a;
    })();
    if (P.conflict && !conflictUsed) {
      conflictUsed = true;
      const rp = send('pcb', 'pc', mkArpReply(ip), { about: 'O PC-B já usa ' + ip + ' (IP estático) e responde ao Probe: conflito de endereço.', tags: ['conflito'] });
      ev(probeArr, 'pcb', 'Já uso ' + ip + ': responde', 'warn');
      tr.lg(rp.tSend, 'PC-B responde ao ARP: ele já usa ' + ip + '. Conflito de endereço detectado.', 'fail');
      tr.st(tr.t, 'phase', 'conflito', 'bad');
      const dc = send('pc', s.key, mkDecline(s, ip), { about: 'O cliente recusa o endereço e avisa o servidor, que o tira do pool.', tags: ['conflito'] });
      tr.lg(dc.tSend, 'PC-A envia <b>DHCPDECLINE</b> para ' + s.id + ' e descarta ' + ip + '.', 'fail');
      ev(dc.tArr, 'pc', 'Conflito: DECLINE e recomeça', 'warn');
      setLease(s, ip, 'DECLINED', '-');
      tr.lg(tr.t, s.id + ' marca ' + ip + ' como indisponível e não o oferecerá novamente. O cliente espera 10 s e volta ao estado INIT.', 'fail');
      jr('conflict', { s: s.id, ip });
      setClient('INIT', 'warn');
      tr.wait(10000);
      return acquire();
    }
    binding = { s, ip, hours: P.lease };
    clientIp = ip;
    setClient('BOUND', 'est');
    setCfg(ip, s);
    tr.st(tr.t, 'phase', 'BOUND', 'est');
    ev(probeArr, 'pc', 'Sem resposta ao Probe: configura ' + ip, 'ok');
    tr.lg(tr.t, 'Nenhuma resposta ao ARP Probe. PC-A configura ' + ip + '/24, gateway ' + GATEWAY + ' e DNS ' + DNS_LIST.join(', ') + '. Estado: BOUND. T1 = ' + t1Secs(P.lease) + ' s, T2 = ' + t2Secs(P.lease) + ' s.', 'ack');
    jr('bound', { s: s.id, ip, hours: P.lease });
    tr.mile(tr.t, 'BOUND', ip);
    R.bound = { s: s.id, ip };
    R.result = 'bound';
    return true;
  };

  const ok = acquire();

  if (ok && sub === 'lease' && binding) {
    const b = binding as { s: ServerDef; ip: string; hours: number };
    if (P.action === 'release') {
      tr.wait(1000);
      tr.phase('5. RELEASE', 'release');
      tr.st(tr.t, 'phase', 'RELEASE', 'warn');
      const reach = P.srvFail ? false : reachable(b.s);
      if (P.srvFail) {
        up[b.s.key] = false;
        ev(tr.t, b.s.key, 'Fora do ar', 'warn');
        tr.lg(tr.t, b.s.id + ' ficou inativo e não responde a nenhuma mensagem.', 'fail');
      }
      const rel = send('pc', b.s.key, mkRelease(b.s, b.ip), { lost: !reach, about: 'O cliente devolve o endereço. O servidor não responde ao RELEASE.', tags: reach ? [] : [why(b.s)] });
      tr.lg(rel.tSend, 'PC-A envia <b>DHCPRELEASE</b> em unicast para ' + b.s.id + '. O servidor não responde a esta mensagem.', 'sys');
      if (reach) {
        setLease(b.s, b.ip, 'FREE', CLIENT_MAC);
        tr.lg(tr.t, b.s.id + ' libera ' + b.ip + ' e o devolve ao pool.', 'sys');
        ev(rel.tArr, b.s.key, 'Libera ' + b.ip, 'ok');
      } else {
        tr.lg(tr.t, b.s.id + ' não recebeu o RELEASE: o lease permanece registrado até expirar.', 'fail');
        ev(rel.tArr, 'pc', 'RELEASE sem efeito: o lease continua', 'warn');
      }
      jr('release', { s: b.s.id, ip: b.ip, ok: reach });
      setClient('INIT', 'warn');
      setCfg(null);
      tr.st(tr.t, 'phase', 'liberado', 'est');
      tr.lg(tr.t, 'PC-A remove a configuração IP. Estado: INIT.', 'sys');
      tr.mile(tr.t, 'RELEASE', reach ? 'endereço devolvido' : 'sem efeito');
      R.result = 'released';
    } else {
      // T1: renovação em unicast
      tr.wait(t1Secs(b.hours) * 1000);
      tr.phase('5. T1: renovação (RENEWING)', 'renew');
      tr.st(tr.t, 'phase', 'T1', 'warn');
      setClient('RENEWING', 'warn');
      if (P.srvFail) {
        up[b.s.key] = false;
        ev(tr.t, b.s.key, 'Fora do ar', 'warn');
        tr.lg(tr.t, b.s.id + ' ficou inativo e não responde a nenhuma mensagem.', 'fail');
      }
      const reach = reachable(b.s);
      tr.lg(tr.t, 'T1 expirou (' + t1Secs(b.hours) + ' s). Estado: BOUND para RENEWING. O cliente envia <b>DHCPREQUEST</b> em unicast para ' + b.s.id + '.', 'request');
      const rn = send('pc', b.s.key, mkRenew(b.s, b.ip), { lost: !reach, about: 'Renovação no T1: unicast direto ao servidor que concedeu o lease, já com o IP do cliente (ciaddr).', tags: reach ? [] : [why(b.s)] });
      if (reach) {
        setLease(b.s, b.ip, 'BOUND', CLIENT_MAC, b.hours);
        const ak = send(b.s.key, 'pc', mkAck(b.s, b.ip, true), { about: 'O servidor confirma e o lease recomeça.' });
        tr.lg(ak.tSend, b.s.id + ' confirma com <b>DHCPACK</b>. O lease é renovado por mais ' + b.hours + ' h. Estado: RENEWING para BOUND.', 'ack');
        ev(ak.tArr, 'pc', 'Lease renovado', 'ok');
        jr('renew', { s: b.s.id, ip: b.ip, hours: b.hours });
        setClient('BOUND', 'est');
        tr.st(tr.t, 'phase', 'renovado', 'est');
        tr.mile(tr.t, 'T1', 'lease renovado');
        R.result = 'renewed';
      } else {
        tr.lg(tr.t, 'Sem resposta de ' + b.s.id + ' (' + why(b.s) + '). O cliente continua usando ' + b.ip + ' e aguarda T2.', 'fail');
        ev(rn.tArr, 'pc', 'Sem resposta no T1: segue usando ' + b.ip, 'warn');
        tr.mile(tr.t, 'T1', 'sem resposta');
        tr.wait((t2Secs(b.hours) - t1Secs(b.hours)) * 1000);
        tr.phase('6. T2: rebinding (REBINDING)', 'rebind');
        tr.st(tr.t, 'phase', 'T2', 'warn');
        setClient('REBINDING', 'warn');
        tr.lg(tr.t, 'T2 expirou (' + t2Secs(b.hours) + ' s). Estado: RENEWING para REBINDING. O cliente envia o REQUEST em broadcast para qualquer servidor.', 'request');
        const rb = bcast(mkRebind(b.ip), 'No T2 o cliente tenta qualquer servidor, em broadcast.');
        active.forEach((s) => {
          if (s !== b.s && reachable(s)) ev(rb, s.key, 'Não conhece este lease: ignora', '');
        });
        tr.lg(tr.t, 'Nenhum servidor responde: somente ' + b.s.id + ' conhece este lease.', 'fail');
        tr.mile(tr.t, 'T2', 'ninguém responde');
        tr.wait((b.hours * 3600 - t2Secs(b.hours)) * 1000);
        tr.phase('7. Fim do lease', 'expire');
        tr.st(tr.t, 'phase', 'expirado', 'bad');
        tr.lg(tr.t, 'O lease expirou (T0). O cliente remove ' + b.ip + ' e volta ao estado INIT.', 'fail');
        ev(tr.t - 0.4, 'pc', 'Lease expirou: perde ' + b.ip, 'warn');
        jr('expire', { s: b.s.id, ip: b.ip, why: why(b.s) });
        setClient('INIT', 'bad');
        setCfg(null);
        tr.mile(tr.t, 'Expirou', 'volta a INIT');
        R.result = 'expired';
      }
    }
  }
  if (clientIp === null) R.ip = null;
  R.tEnd = tr.t;
  void ow;
  return tr;
}
