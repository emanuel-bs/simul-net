// Motor do modo Broadcast, multicast e endereços reservados.
//  - broadcast (ff:ff:ff:ff:ff:ff): sempre inundado; nunca consta da tabela;
//  - multicast IP: o MAC de grupo vem do IP (RFC 1112, seção 6.4); sem IGMP snooping o switch o trata como broadcast, e com
//    snooping encaminha só às portas com assinantes (RFC 4541);
//  - endereços de grupo reservados (01-80-C2-00-00-00 a 0F): consumidos pela ponte, nunca encaminhados.
import { COLORS as C0, newTrace, type Column, type StateDef, type Trace } from '../../sim-core';
import { BCAST, HOSTS, Switch, ipFields, sendFrame, type Decision, type Frame, type HostKey } from './model';

export interface EspParams {
  rtt: number;
  ekind: 'bcast' | 'mcast' | 'reserved';
  esnoop: boolean;
  ejoin: boolean;
}

export const GROUP_IP = '239.1.1.1';
/** 239.1.1.1: os 23 bits de baixa ordem do IP (0x010101) entram em 01:00:5e:00:00:00. */
export const GROUP_MAC = '01:00:5e:01:01:01';
/** IGMPv3: os relatórios vão a 224.0.0.22, cujo MAC de grupo é este. */
export const IGMP_MAC = '01:00:5e:00:00:16';

export const COLS_ESP: Column[] = [
  { key: 'a', label: 'Host A', sub: 'porta 1', addr: HOSTS.a.ip },
  { key: 'b', label: 'Host B', sub: 'porta 2', addr: HOSTS.b.ip },
  { key: 'sw', label: 'Switch', sub: 'camada 2' },
  { key: 'c', label: 'Host C', sub: 'porta 3 (hub)', addr: HOSTS.c.ip },
  { key: 'd', label: 'Host D', sub: 'porta 3 (hub)', addr: HOSTS.d.ip },
];

export const STATES_ESP: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'tab', label: 'Tabela de endereços do switch' },
  { key: 'dec', label: 'Última decisão do switch' },
  { key: 'grp', label: 'Grupo ' + GROUP_IP + ' (snooping)' },
];

export function buildEsp(P: EspParams): Trace {
  const tr = newTrace(COLS_ESP, STATES_ESP, P.rtt);
  const sw = new Switch({ 1: ['a'], 2: ['b'], 3: ['c', 'd'] });
  const decs: Decision[] = [];
  const R = (tr.raw = { sub: 'esp', kind: P.ekind, snoop: P.esnoop, join: P.ejoin, mac: sw.ev, dec: decs, reached: [] as HostKey[], tEnd: 0 } as Record<string, any>);
  const phase = (label: string, st: string) => {
    tr.phase(label, st);
    tr.st(tr.t, 'phase', st, 'warn');
  };
  tr.st(0, 'tab', sw.stateText(), 'closed');
  tr.st(0, 'dec', '-', 'closed');
  tr.st(0, 'grp', P.ekind === 'mcast' && P.esnoop ? 'sem assinantes' : 'não usado', 'closed');
  tr.ev(0, 'sw', 'Tabela de endereços vazia', '');

  if (P.ekind === 'bcast') {
    phase('1. ARP Request em broadcast', 'broadcast');
    tr.mile(tr.t, 'Broadcast', 'inundado');
    const q: Frame = {
      label: 'ARP Request', proto: 'ARP', len: 42, color: C0.plain, dst: BCAST, etype: '0x0806 (ARP)',
      info: 'Who has ' + HOSTS.b.ip + '? Tell ' + HOSTS.a.ip,
      about: 'O destino ff:ff:ff:ff:ff:ff nunca consta da tabela: o switch sempre inunda o broadcast por todas as portas, menos a de entrada. Todos os hosts da rede local (o domínio de broadcast) o recebem.',
      body: [{ sec: 'ARP (RFC 826)' }, ['Operação', '1 (requisição)', ''], ['IP do remetente', HOSTS.a.ip, ''], ['IP do alvo', HOSTS.b.ip, '']],
    };
    const s = sendFrame(tr, sw, decs, 'a', q, { phaseName: 'Broadcast' });
    R.reached.push(...s.hosts);
    phase('2. Resposta unicast', 'unicast');
    const r: Frame = {
      label: 'ARP Reply', proto: 'ARP', len: 42, color: C0.data, dst: HOSTS.a.mac, etype: '0x0806 (ARP)',
      info: HOSTS.b.ip + ' is at ' + HOSTS.b.mac,
      about: 'Só o dono do IP responde, em unicast. O switch aprendeu A pela requisição e envia a resposta somente pela porta 1.',
      body: [{ sec: 'ARP (RFC 826)' }, ['Operação', '2 (resposta)', ''], ['IP do remetente', HOSTS.b.ip, ''], ['IP do alvo', HOSTS.a.ip, '']],
    };
    sendFrame(tr, sw, decs, 'b', r, { phaseName: 'Resposta' });
  } else if (P.ekind === 'mcast') {
    const members: HostKey[] = P.ejoin ? ['b'] : [];
    let group: number[] | undefined;
    phase('1. Assinatura do grupo (IGMP)', 'IGMP');
    if (P.ejoin) {
      const rep: Frame = {
        label: 'IGMP Membership Report', proto: 'IGMP', len: 64, color: C0.data, dst: IGMP_MAC, etype: '0x0800 (IPv4)',
        info: 'B entra no grupo ' + GROUP_IP,
        about: 'B avisa que quer receber o grupo ' + GROUP_IP + '. O relatório do IGMPv3 vai ao endereço 224.0.0.22 (MAC ' + IGMP_MAC + ').',
        body: [...ipFields(HOSTS.b.ip, '224.0.0.22', '2 (IGMP)'), { sec: 'IGMPv3 (RFC 9776)' }, ['Tipo', '0x22 (Membership Report)', ''], ['Grupo', GROUP_IP, 'registro do grupo que B quer receber']],
      };
      if (P.esnoop) {
        sendFrame(tr, sw, decs, 'b', rep, { phaseName: 'IGMP', consume: 'IGMP snooping: o switch lê o relatório e passa a enviar o grupo à porta 2' });
        group = [2];
        tr.st(tr.t, 'grp', 'porta 2', 'est');
        tr.lg(tr.t, 'Snooping: o grupo ' + GROUP_IP + ' (' + GROUP_MAC + ') tem assinante na porta 2.', 'conn');
      } else sendFrame(tr, sw, decs, 'b', rep, { phaseName: 'IGMP', members });
    } else {
      tr.ev(tr.t, 'b', 'Ninguém assinou o grupo ' + GROUP_IP, '');
      if (P.esnoop) group = [];
    }
    phase('2. Fluxo enviado ao grupo ' + GROUP_IP, 'multicast');
    tr.mile(tr.t, 'Multicast', GROUP_IP);
    for (let i = 1; i <= 2; i++) {
      const d: Frame = {
        label: 'Dados do grupo #' + i, proto: 'UDP', len: 1042, color: C0.data, dst: GROUP_MAC, etype: '0x0800 (IPv4)',
        info: HOSTS.a.ip + ' → ' + GROUP_IP + ' (UDP)',
        about: 'O MAC ' + GROUP_MAC + ' vem do IP ' + GROUP_IP + ' (RFC 1112, seção 6.4: os 23 bits de baixa ordem do IP entram em 01:00:5e:00:00:00). ' + (P.esnoop ? 'Com snooping, o switch consulta o grupo e só envia às portas com assinantes.' : 'Sem snooping, o switch não conhece o grupo e o trata como broadcast.'),
        body: ipFields(HOSTS.a.ip, GROUP_IP, '17 (UDP)'),
      };
      const s = sendFrame(tr, sw, decs, 'a', d, { phaseName: 'Multicast', group, members });
      R.reached.push(...s.hosts);
    }
  } else {
    phase('1. Quadros para endereços de grupo reservados', 'reservado');
    const bpdu: Frame = {
      label: 'BPDU', proto: 'STP', len: 60, color: C0.plain, dst: '01:80:c2:00:00:00', etype: '0x0026 (LLC)',
      info: 'BPDU do spanning tree, como o enviaria um switch vizinho',
      about: 'O destino 01-80-C2-00-00-00 é reservado para o spanning tree. A ponte que recebe o quadro o processa e não o encaminha, para que o protocolo funcione salto a salto.',
      body: [{ sec: 'LLC' }, ['DSAP/SSAP', '0x42/0x42', 'Spanning Tree']],
    };
    sendFrame(tr, sw, decs, 'a', bpdu, { phaseName: 'Reservado', consume: 'Endereço reservado 01-80-C2-00-00-00: a ponte processa e não encaminha' });
    const lldp: Frame = {
      label: 'LLDP', proto: 'LLDP', len: 60, color: C0.plain, dst: '01:80:c2:00:00:0e', etype: '0x88cc (LLDP)',
      info: 'anúncio de vizinho (LLDP)',
      about: 'O destino 01-80-C2-00-00-0E é o de grupo do LLDP, também reservado: descobre só o vizinho direto, e por isso a ponte não o repassa.',
      body: [{ sec: 'LLDP' }, ['Chassis ID', HOSTS.a.mac, '']],
    };
    sendFrame(tr, sw, decs, 'a', lldp, { phaseName: 'Reservado', consume: 'Endereço reservado 01-80-C2-00-00-0E: a ponte processa e não encaminha' });
    phase('2. Para comparar: unicast desconhecido', 'inundação');
    const e: Frame = {
      label: 'Echo Request', proto: 'ICMP', len: 98, color: C0.tcp, dst: HOSTS.b.mac, etype: '0x0800 (IPv4)',
      info: HOSTS.a.ip + ' → ' + HOSTS.b.ip,
      about: 'Um quadro comum para um destino desconhecido é inundado. Os reservados não: por isso A e B não receberam os dois quadros anteriores.',
      body: [...ipFields(HOSTS.a.ip, HOSTS.b.ip, '1 (ICMP)'), { sec: 'ICMP (RFC 792)' }, ['Tipo', '8 (Echo Request)', '']],
    };
    const s = sendFrame(tr, sw, decs, 'a', e, { phaseName: 'Comparação' });
    R.reached.push(...s.hosts);
  }
  R.tEnd = tr.t;
  return tr;
}
