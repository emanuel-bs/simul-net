// Motor do modo Aprendizado e encaminhamento do switch Ethernet (IEEE 802.1D).
// Rede: A na porta 1, B na porta 2 e, na porta 3, um hub com C e D (um segmento compartilhado). A porta 4 está livre.
// A tabela de endereços aprende a origem de cada quadro, envelhece (300 s por padrão) e é consultada pelo destino.
import { COLORS as C0, newTrace, type Column, type StateDef, type Trace } from '../../sim-core';
import { BCAST, HOSTS, Switch, ipFields, sendFrame, type Decision, type Frame, type HostKey } from './model';

export interface AprParams {
  rtt: number;
  akind: 'first' | 'known' | 'bcast' | 'filter' | 'move' | 'aging';
  aging: number;
  areply: boolean;
}

export const COLS_APR: Column[] = [
  { key: 'a', label: 'Host A', sub: 'porta 1', addr: HOSTS.a.ip },
  { key: 'b', label: 'Host B', sub: 'porta 2', addr: HOSTS.b.ip },
  { key: 'sw', label: 'Switch', sub: 'camada 2' },
  { key: 'c', label: 'Host C', sub: 'porta 3 (hub)', addr: HOSTS.c.ip },
  { key: 'd', label: 'Host D', sub: 'porta 3 (hub)', addr: HOSTS.d.ip },
];

export const STATES_APR: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'tab', label: 'Tabela de endereços do switch' },
  { key: 'dec', label: 'Última decisão do switch' },
];

const echo = (from: HostKey, to: HostKey, reply: boolean): Frame => ({
  label: reply ? 'Echo Reply' : 'Echo Request',
  proto: 'ICMP',
  color: C0.tcp,
  len: 98,
  info: HOSTS[from].ip + ' → ' + HOSTS[to].ip + (reply ? ' (resposta de ping)' : ' (ping)'),
  about: (reply ? 'Resposta do ping. ' : 'Um ping de ' + HOSTS[from].name + ' para ' + HOSTS[to].name + ': ') + 'o endereço físico de destino já foi descoberto pelo ARP e o switch decide só pelo MAC de destino.',
  dst: HOSTS[to].mac,
  etype: '0x0800 (IPv4)',
  body: [...ipFields(HOSTS[from].ip, HOSTS[to].ip, '1 (ICMP)'), { sec: 'ICMP (RFC 792)' }, ['Tipo', reply ? '0 (Echo Reply)' : '8 (Echo Request)', '']],
});

const arpFrame = (reply: boolean): Frame => ({
  label: reply ? 'ARP Reply' : 'ARP Request',
  proto: 'ARP',
  len: 42,
  info: reply ? HOSTS.b.ip + ' is at ' + HOSTS.b.mac : 'Who has ' + HOSTS.b.ip + '? Tell ' + HOSTS.a.ip,
  about: reply ? 'Resposta em unicast: o switch já conhece A (aprendeu pela requisição) e a envia só pela porta 1.' : 'Pergunta em broadcast (ff:ff:ff:ff:ff:ff). O broadcast nunca consta da tabela, por isso o switch sempre o inunda.',
  dst: reply ? HOSTS.a.mac : BCAST,
  src: reply ? HOSTS.b.mac : HOSTS.a.mac,
  etype: '0x0806 (ARP)',
  body: [{ sec: 'ARP (RFC 826)' }, ['Operação', reply ? '2 (resposta)' : '1 (requisição)', ''], ['IP do remetente', reply ? HOSTS.b.ip : HOSTS.a.ip, ''], ['IP do alvo', reply ? HOSTS.a.ip : HOSTS.b.ip, '']],
  color: reply ? C0.data : C0.plain,
});

export function buildApr(P: AprParams): Trace {
  const tr = newTrace(COLS_APR, STATES_APR, P.rtt);
  const sw = new Switch({ 1: ['a'], 2: ['b'], 3: ['c', 'd'], 4: [] }, 1000, P.aging * 1000);
  const decs: Decision[] = [];
  tr.raw = { sub: 'apr', kind: P.akind, mac: sw.ev, dec: decs, aging: P.aging, reply: P.areply, moved: false };
  const send = (from: HostKey, f: Frame, phaseName: string, ghost?: HostKey) => sendFrame(tr, sw, decs, from, f, { phaseName, ghost });
  const phase = (label: string, st: string) => {
    tr.phase(label, st);
    tr.st(tr.t, 'phase', st, 'warn');
  };
  const rest = () => tr.wait(P.rtt / 2);

  const pre: HostKey[] = P.akind === 'first' || P.akind === 'bcast' ? [] : P.akind === 'known' || P.akind === 'filter' ? ['a', 'b', 'c', 'd'] : ['a', 'b'];
  sw.preload(...pre);
  tr.st(0, 'tab', sw.stateText(), pre.length ? 'est' : 'closed');
  tr.st(0, 'dec', '-', 'closed');
  tr.ev(0, 'sw', pre.length ? 'Tabela já tem ' + pre.map((h) => HOSTS[h].name).join(', ') : 'Tabela de endereços vazia', '');

  if (P.akind === 'first') {
    phase('1. Tabela vazia: destino desconhecido', 'inundação');
    tr.mile(tr.t, 'Tabela vazia', 'primeiro quadro');
    send('a', echo('a', 'b', false), 'Primeiro quadro');
    if (P.areply) {
      phase('2. A resposta de B revela a porta de B', 'aprendizado');
      send('b', echo('b', 'a', true), 'Resposta');
      phase('3. Os quadros seguintes vão só a B', 'encaminhamento');
    } else {
      tr.ev(tr.t, 'b', 'Sem resposta: o switch não aprende B', 'warn');
      phase('2. B não responde: continua desconhecido', 'inundação');
    }
    send('a', echo('a', 'b', false), 'Quadro seguinte');
  } else if (P.akind === 'known') {
    phase('1. Destino conhecido em outra porta', 'encaminhamento');
    send('a', echo('a', 'b', false), 'Encaminhamento');
    phase('2. Destino atrás do hub (porta 3)', 'encaminhamento');
    send('a', echo('a', 'c', false), 'Encaminhamento');
  } else if (P.akind === 'bcast') {
    phase('1. ARP Request em broadcast', 'inundação');
    tr.mile(tr.t, 'Broadcast', 'ARP Request');
    send('a', arpFrame(false), 'Requisição');
    if (P.areply) {
      phase('2. Resposta unicast: B é aprendido', 'aprendizado');
      send('b', arpFrame(true), 'Resposta');
    } else tr.ev(tr.t, 'b', 'Sem resposta ARP', 'warn');
  } else if (P.akind === 'filter') {
    phase('1. Origem e destino na mesma porta', 'filtragem');
    tr.mile(tr.t, 'Filtragem', 'C para D');
    send('c', echo('c', 'd', false), 'Filtragem');
    phase('2. Para comparar: destino em outra porta', 'encaminhamento');
    send('c', echo('c', 'a', false), 'Encaminhamento');
  } else if (P.akind === 'move') {
    phase('1. B está na porta 2', 'encaminhamento');
    send('a', echo('a', 'b', false), 'Encaminhamento');
    phase('2. B é mudado para a porta 4', 'tabela velha');
    tr.mile(tr.t, 'Mudança', 'B vai para a porta 4');
    sw.ports[2] = [];
    sw.ports[4] = ['b'];
    tr.raw.moved = true;
    tr.ev(tr.t, 'b', 'Cabo trocado: B passa da porta 2 para a porta 4', 'warn');
    tr.lg(tr.t, 'O cabo de B foi trocado da porta 2 para a porta 4. A tabela do switch ainda aponta para a porta 2.', 'conn');
    rest();
    send('a', echo('a', 'b', false), 'Tabela velha', 'b');
    phase('3. B transmite e a tabela se corrige', 'aprendizado');
    send('b', echo('b', 'a', true), 'Correção');
    phase('4. O tráfego volta a chegar a B', 'encaminhamento');
    send('a', echo('a', 'b', false), 'Encaminhamento');
  } else {
    phase('1. Tráfego recente', 'encaminhamento');
    send('a', echo('a', 'b', false), 'Encaminhamento');
    phase('2. Silêncio por ' + P.aging + ' s', 'envelhecimento');
    tr.mile(tr.t, 'Silêncio', P.aging + ' s');
    tr.ev(tr.t, 'sw', 'Sem tráfego: o relógio de envelhecimento corre', '');
    tr.wait(P.aging * 1000);
    phase('3. Entradas expiradas: o destino é desconhecido', 'inundação');
    send('a', echo('a', 'b', false), 'Depois do envelhecimento');
    if (P.areply) {
      phase('4. A resposta recria a entrada de B', 'aprendizado');
      send('b', echo('b', 'a', true), 'Resposta');
    }
  }
  tr.raw.tEnd = tr.t;
  tr.raw.flooded = decs.filter((d) => d.action === 'flood').length;
  return tr;
}
