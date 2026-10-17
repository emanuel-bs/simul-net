// Motor do ARP (RFC 826), com o proxy ARP (RFC 1027) e a revalidação de entradas antigas (RFC 1122, seção 2.3.2.1).
// Modo 'res' (resolução): como um host descobre o endereço físico (MAC) do próximo salto numa rede local Ethernet.
//   - destino na mesma sub-rede: o host pergunta pelo IP do destino;
//   - destino fora da sub-rede: o host pergunta pelo IP do gateway;
//   - sem gateway (máscara errada): o host pergunta pelo IP remoto e só o proxy ARP do roteador responde.
// Os tempos de retransmissão seguem os padrões do Linux (3 tentativas, 1 s entre elas); outros sistemas variam.
// Não há tráfego real: endereços físicos e IPs são valores de documentação (RFC 5737 e RFC 7042).
import { COLORS as C0, newTrace, type Column, type Field, type Message, type StateDef, type Trace } from '../../sim-core';

export interface ArpParams {
  rtt: number;
  dest: 'local' | 'gateway' | 'direto';
  cache: 'empty' | 'fresh' | 'stale';
  online: boolean;
  proxy: boolean;
  loss: boolean;
}

export const BCAST = 'ff:ff:ff:ff:ff:ff';
export const NO_MAC = '00:00:00:00:00:00';
export const HOSTS = {
  a: { ip: '192.168.1.10', mac: '00:00:5e:00:53:0a', name: 'Host A' },
  b: { ip: '192.168.1.20', mac: '00:00:5e:00:53:14', name: 'Host B' },
  g: { ip: '192.168.1.1', mac: '00:00:5e:00:53:01', name: 'Gateway' },
} as const;
export const REMOTE = '192.0.2.50';
export const TRIES = 3;
const RETRY_MS = 1000;

export const COLS: Column[] = [
  { key: 'a', label: 'Host A', sub: 'origem', addr: HOSTS.a.ip },
  { key: 'b', label: 'Host B', sub: 'vizinho', addr: HOSTS.b.ip },
  { key: 'g', label: 'Gateway', sub: 'roteador', addr: HOSTS.g.ip },
];

export const STATES: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'ta', label: 'Tabela ARP do Host A' },
  { key: 'tr', label: 'Tabela ARP de quem responde' },
  { key: 'pkt', label: 'Pacote IP' },
];

type X = Record<string, any>;
const fl = (...f: Field[]): Field[] => f;

/** Estados da entrada de vizinho, como o Linux os mostra em "ip neigh". */
export type NeighState = 'INCOMPLETE' | 'REACHABLE' | 'STALE' | 'FAILED';
export interface NeighEvent {
  host: 'a' | 'b' | 'g';
  ip: string;
  mac: string | null;
  state: NeighState;
  t: number;
}

export type HostKey = 'a' | 'b' | 'g';
export interface FrameOpts {
  sha: string;
  spa: string;
  tha: string;
  tpa: string;
  dmac: string;
  label: string;
  info: string;
  about: string;
  lost?: boolean;
  par?: boolean;
  bad?: boolean;
  tags?: string[];
}

/** Quadro ARP (requisição ou resposta) entre dois hosts do trace. */
export function arpFrame(tr: Trace, from: HostKey, to: HostKey, op: 1 | 2, o: FrameOpts): Message {
  return tr.add(from, to, {
    label: o.label, proto: 'ARP', color: o.bad ? C0.bad : op === 1 ? C0.plain : C0.data, len: 42, info: o.info, phaseName: op === 1 ? 'Requisição' : 'Resposta',
    fields: [...ethHeader(o.dmac, o.sha, '0x0806 (ARP)'), ...arpBody(op, o.sha, o.spa, o.tha, o.tpa)], about: o.about, lost: !!o.lost, par: !!o.par, tags: o.tags || [],
  });
}

export function ethHeader(dst: string, src: string, type: string): Field[] {
  return fl({ sec: 'Ethernet II' }, ['Destino', dst, dst === BCAST ? 'broadcast: todos os hosts da rede local recebem' : 'endereço físico do destino'], ['Origem', src, 'endereço físico de quem envia'], ['Tipo', type, type.startsWith('0x0806') ? 'ARP' : 'IPv4']);
}

export function arpBody(op: 1 | 2, sha: string, spa: string, tha: string, tpa: string): Field[] {
  return fl(
    { sec: 'ARP (RFC 826)' },
    ['Tipo de hardware', '1 (Ethernet)', ''],
    ['Tipo de protocolo', '0x0800 (IPv4)', ''],
    ['Tamanho do endereço físico', '6', 'bytes'],
    ['Tamanho do endereço de protocolo', '4', 'bytes'],
    ['Operação', op === 1 ? '1 (requisição)' : '2 (resposta)', op === 1 ? 'pergunta: quem tem este IP?' : 'resposta: este IP está neste endereço físico'],
    ['Endereço físico do remetente', sha, 'SHA'],
    ['IP do remetente', spa, 'SPA'],
    ['Endereço físico do alvo', tha, op === 1 ? 'TPA ainda não tem MAC: vai zerado' : 'THA: quem fez a pergunta'],
    ['IP do alvo', tpa, 'TPA'],
  );
}

export function buildArp(P: ArpParams, _sub: string): Trace {
  const tr = newTrace(COLS, STATES, P.rtt);
  const ow = tr.ow;
  const A = HOSTS.a;
  const nh = P.dest === 'local' ? HOSTS.b : HOSTS.g; // próximo salto físico
  const nhKey: 'b' | 'g' = P.dest === 'local' ? 'b' : 'g';
  const other: 'b' | 'g' = nhKey === 'b' ? 'g' : 'b';
  const dstIp = P.dest === 'local' ? HOSTS.b.ip : REMOTE; // destino final do pacote IP
  const askIp = P.dest === 'gateway' ? HOSTS.g.ip : dstIp; // IP por quem o ARP pergunta
  const proxyMode = P.dest === 'direto';
  // quem responde ao ARP: o próprio vizinho ou o gateway (como proxy). Sem proxy ARP, ninguém responde.
  const responder: 'b' | 'g' | null = proxyMode ? (P.proxy ? 'g' : null) : P.online ? nhKey : null;
  const neigh: NeighEvent[] = [];
  const R: X = { sub: 'res', t0: 0, askIp, dstIp, nhMac: nh.mac, nhKey, responder, tries: 0, result: 'ok', cacheHit: false, proxyMode, learned: false };
  tr.raw = R;
  R.neigh = neigh;
  const ne = (host: 'a' | 'b' | 'g', ip: string, mac: string | null, state: NeighState, t: number) => neigh.push({ host, ip, mac, state, t });

  const arpMsg = (from: HostKey, to: HostKey, op: 1 | 2, o: FrameOpts): Message => arpFrame(tr, from, to, op, o);

  // 0. A quer enviar um pacote IP
  tr.phase('1. Consulta à tabela ARP', 'look');
  tr.st(0, 'phase', 'consulta', 'warn');
  tr.st(0, 'ta', P.cache === 'empty' ? '(vazia)' : askIp + ' ' + (P.cache === 'fresh' ? 'REACHABLE' : 'STALE'), P.cache === 'empty' ? 'closed' : P.cache === 'fresh' ? 'est' : 'warn');
  tr.st(0, 'tr', '-', 'closed');
  tr.st(0, 'pkt', 'aguardando o MAC do próximo salto', 'warn');
  tr.mile(0, 'Consulta', 'tabela ARP');
  const how =
    P.dest === 'local'
      ? 'O destino ' + dstIp + ' está na mesma sub-rede: o próximo salto é o próprio destino.'
      : P.dest === 'gateway'
        ? 'O destino ' + dstIp + ' está fora da sub-rede: o próximo salto é o gateway ' + HOSTS.g.ip + ', e é por ele que o ARP pergunta.'
        : 'A máscara de A (255.0.0.0, configurada por engano) faz ' + dstIp + ' parecer local: A pergunta diretamente por ele, sem usar o gateway.';
  tr.ev(0, 'a', P.dest === 'local' ? 'Ping para ' + dstIp + ' (mesma sub-rede)' : P.dest === 'gateway' ? 'Ping para ' + dstIp + ': o próximo salto é o gateway' : 'Ping para ' + dstIp + ': a máscara errada o faz parecer local', '');
  tr.lg(0, 'Host A: ping para ' + dstIp + '. ' + how, 'conn');
  if (P.cache !== 'empty') ne('a', askIp, nh.mac, P.cache === 'fresh' ? 'REACHABLE' : 'STALE', 0);
  else ne('a', askIp, null, 'INCOMPLETE', 0);
  if (P.cache !== 'empty' && responder) {
    // o vizinho também conhece A (a cache costuma ser simétrica)
    ne(responder, A.ip, A.mac, 'REACHABLE', 0);
  }

  let resolved = false;
  if (P.cache === 'fresh') {
    R.cacheHit = true;
    resolved = true;
    tr.ev(ow / 4, 'a', 'Acerto na tabela: nenhum ARP necessário', 'ok');
    tr.lg(ow / 4, 'Acerto na tabela ARP: ' + askIp + ' → ' + nh.mac + '. Nenhum ARP enviado.', 'conn');
    tr.wait(ow / 4 + 0.4);
  } else if (P.cache === 'stale') {
    R.stale = true;
    tr.ev(ow / 4, 'a', 'Entrada STALE: confirma por unicast', 'warn');
    tr.wait(ow / 4 + 0.4);
    tr.phase('2. Revalidação da entrada (unicast)', 'probe');
    tr.st(tr.t, 'phase', 'revalidação', 'warn');
    for (let n = 1; n <= TRIES && !resolved; n++) {
      R.tries = n;
      const ok = !!responder && responder === nhKey;
      const q = arpMsg('a', nhKey, 1, {
        sha: A.mac, spa: A.ip, tha: NO_MAC, tpa: askIp, dmac: nh.mac, label: 'ARP Request (unicast)', info: 'Who has ' + askIp + '? Tell ' + A.ip + ' (unicast)',
        about: 'A confirma a entrada antiga perguntando diretamente ao dono do endereço, sem usar broadcast (RFC 1122). Se ele responder, a entrada volta a ser REACHABLE.',
        lost: !ok, bad: !ok, tags: ok ? [] : ['sem resposta'],
      });
      if (ok) {
        const ac = arpMsg(nhKey, 'a', 2, {
          sha: nh.mac, spa: askIp, tha: A.mac, tpa: A.ip, dmac: A.mac, label: 'ARP Reply', info: askIp + ' is at ' + nh.mac,
          about: 'O dono do endereço confirma. A entrada de A volta a ser REACHABLE.',
        });
        ne('a', askIp, nh.mac, 'REACHABLE', ac.tArr);
        tr.st(ac.tArr, 'ta', askIp + ' REACHABLE', 'est');
        tr.ev(ac.tArr, 'a', 'Entrada confirmada (REACHABLE)', 'ok');
        tr.lg(ac.tArr, 'Revalidação concluída: ' + askIp + ' → ' + nh.mac + ' (REACHABLE).', 'conn');
        resolved = true;
      } else {
        tr.lg(q.tSend, 'Revalidação sem resposta (tentativa ' + n + ' de ' + TRIES + ').', 'loss');
        tr.wait(RETRY_MS);
      }
    }
    if (!resolved) {
      ne('a', askIp, null, 'FAILED', tr.t);
      tr.st(tr.t, 'ta', askIp + ' FAILED', 'bad');
    }
  } else {
    tr.ev(ow / 4, 'a', 'Sem entrada: INCOMPLETE e broadcast', 'warn');
    tr.st(ow / 4, 'ta', askIp + ' INCOMPLETE', 'warn');
    tr.wait(ow / 4 + 0.4);
    tr.phase('2. Requisição em broadcast e resposta', 'arp');
    tr.st(tr.t, 'phase', 'ARP', 'warn');
    tr.mile(tr.t, 'ARP', 'requisição e resposta');
    for (let n = 1; n <= TRIES && !resolved; n++) {
      R.tries = n;
      const lostNow = P.loss && n === 1;
      const toTargetLost = lostNow || (!responder && !proxyMode); // alvo desligado: a cópia não chega a ninguém
      const common = { sha: A.mac, spa: A.ip, tha: NO_MAC, tpa: askIp, dmac: BCAST };
      // a mesma requisição chega a todos os hosts da rede local (broadcast)
      const q1 = arpMsg('a', other, 1, {
        ...common, label: 'ARP Request', info: 'Who has ' + askIp + '? Tell ' + A.ip + (n > 1 ? ' (tentativa ' + n + ')' : ''), par: true, lost: lostNow,
        about: 'O broadcast chega a todos os hosts da rede. Este host não é o alvo e descarta a pergunta.', bad: lostNow, tags: lostNow ? ['perdido'] : [],
      });
      const q2 = arpMsg('a', nhKey, 1, {
        ...common, label: 'ARP Request', info: 'Who has ' + askIp + '? Tell ' + A.ip + (n > 1 ? ' (tentativa ' + n + ')' : ''), lost: toTargetLost,
        about: 'A pergunta em broadcast: "quem tem ' + askIp + '?". O endereço físico do alvo ainda é desconhecido, por isso vai zerado.', bad: toTargetLost, tags: lostNow ? ['perdido'] : toTargetLost ? ['sem resposta'] : [],
      });
      if (n === 1) tr.lg(q1.tSend, 'Host A: ARP Request em broadcast: "quem tem ' + askIp + '?".', 'conn');
      if (!lostNow) tr.ev(q1.tArr + 0.4, other, 'Não é o alvo: descarta', '');
      if (lostNow) {
        tr.ev(q2.tArr, 'a', 'Requisição perdida: tenta de novo em 1 s', 'warn');
        tr.lg(q2.tArr, 'Requisição perdida (tentativa ' + n + ' de ' + TRIES + ').', 'loss');
        tr.wait(RETRY_MS);
        continue;
      }
      if (!responder) {
        const why = proxyMode ? 'Ninguém responde' : 'Alvo desligado: sem resposta';
        if (proxyMode) tr.ev(q2.tArr + 0.4, 'g', 'Sem proxy ARP: não responde', '');
        tr.ev(q2.tArr, 'a', why + ' (' + n + ' de ' + TRIES + ')', 'warn');
        tr.lg(q2.tArr, 'Sem resposta ARP (tentativa ' + n + ' de ' + TRIES + ').', 'loss');
        if (n < TRIES) tr.wait(RETRY_MS);
        continue;
      }
      // o alvo recebe, aprende o endereço de A (RFC 826) e responde por unicast
      const rb = responder;
      const rh = HOSTS[rb];
      const mac = rh.mac;
      ne(rb, A.ip, A.mac, 'REACHABLE', q2.tArr);
      tr.st(q2.tArr, 'tr', A.ip + ' REACHABLE', 'est');
      tr.ev(q2.tArr, rb, proxyMode ? 'Proxy ARP: responde com o próprio MAC' : 'É o alvo: guarda o MAC de A', 'ok');
      tr.lg(q2.tArr, HOSTS[rb].name + ' guarda ' + A.ip + ' → ' + A.mac + ' (aprendido da requisição).', 'conn');
      const ac = arpMsg(rb, 'a', 2, {
        sha: mac, spa: askIp, tha: A.mac, tpa: A.ip, dmac: A.mac, label: 'ARP Reply', info: askIp + ' is at ' + mac,
        about: proxyMode ? 'O roteador responde no lugar do destino remoto, entregando o próprio MAC: A enviará os quadros para ele (proxy ARP, RFC 1027).' : 'Resposta em unicast, só para A: "' + askIp + ' está em ' + mac + '".',
        tags: proxyMode ? ['proxy ARP'] : [],
      });
      ne('a', askIp, mac, 'REACHABLE', ac.tArr);
      tr.st(ac.tArr, 'ta', askIp + ' → ' + mac, 'est');
      tr.ev(ac.tArr, 'a', 'Tabela: ' + askIp + ' REACHABLE', 'ok');
      tr.lg(ac.tArr, 'ARP Reply: ' + askIp + ' está em ' + mac + (proxyMode ? ' (endereço do gateway, proxy ARP)' : '') + '.', 'conn');
      resolved = true;
      R.learned = true;
    }
    if (!resolved) {
      ne('a', askIp, null, 'FAILED', tr.t);
      tr.st(tr.t, 'ta', askIp + ' FAILED', 'bad');
    }
  }

  // 3. o pacote IP segue (ou é descartado)
  if (!resolved) {
    R.result = 'failed';
    tr.phase('3. Falha na resolução', 'fail');
    tr.st(tr.t, 'phase', 'falhou', 'bad');
    tr.st(tr.t, 'pkt', 'descartado (host inalcançável)', 'bad');
    tr.ev(tr.t, 'a', 'ARP falhou: Destination Host Unreachable', 'warn');
    tr.lg(tr.t, 'Resolução ARP falhou: o pacote IP foi descartado e o sistema de A gera o erro "Destination Host Unreachable" (localmente, sem ICMP na rede).', 'loss');
    tr.mile(tr.t, 'Falha', 'host inalcançável');
    R.tEnd = tr.t;
    return tr;
  }
  tr.phase('3. Envio do pacote IP', 'ip');
  tr.st(tr.t, 'phase', 'pacote IP', 'warn');
  tr.st(tr.t, 'pkt', 'enviando para ' + nh.mac, 'warn');
  tr.mile(tr.t, 'Pacote IP', 'ping');
  const dead = P.cache === 'fresh' && !P.online; // entrada recente, mas o host já não responde
  const echoField = (type: string, code: string, dmac: string, smac: string, src: string, dst: string): Field[] => [
    ...ethHeader(dmac, smac, '0x0800 (IPv4)'),
    ...fl({ sec: 'IPv4 (RFC 791)' }, ['Origem', src, ''], ['Destino', dst, P.dest === 'local' ? '' : 'o destino final; o quadro vai ao MAC do próximo salto'], ['Protocolo', '1 (ICMP)', '']),
    ...fl({ sec: 'ICMP (RFC 792)' }, ['Tipo', type, ''], ['Código', code, '']),
  ];
  const e1 = tr.add('a', nhKey, {
    label: 'Echo Request', proto: 'ICMP', color: dead ? C0.bad : C0.tcp, len: 98, info: 'Echo (ping) request ' + A.ip + ' → ' + dstIp, phaseName: 'Pacote IP', lost: dead,
    fields: echoField('8 (Echo Request)', '0', nh.mac, A.mac, A.ip, dstIp),
    about: 'Agora A sabe o endereço físico do próximo salto e monta o quadro: MAC de destino = ' + nh.mac + ', IP de destino = ' + dstIp + '.' + (dead ? ' O host está desligado, mas a entrada ainda estava na tabela: o ping não tem resposta.' : ''), tags: dead ? ['sem resposta'] : [],
  });
  if (dead) {
    R.result = 'noreply';
    tr.st(e1.tArr, 'pkt', 'sem resposta do destino', 'bad');
    tr.ev(e1.tArr, 'a', 'Ping sem resposta (a entrada ainda existe)', 'warn');
    tr.lg(e1.tArr, 'Echo Request sem resposta: a tabela ARP guardava o MAC de um host que já não responde.', 'loss');
    R.tEnd = tr.t;
    return tr;
  }
  const e2 = tr.add(nhKey, 'a', {
    label: 'Echo Reply', proto: 'ICMP', color: C0.tcp, len: 98, info: 'Echo (ping) reply ' + dstIp + ' → ' + A.ip, phaseName: 'Pacote IP',
    fields: echoField('0 (Echo Reply)', '0', A.mac, nh.mac, dstIp, A.ip),
    about: (P.dest === 'local' ? 'B responde sem precisar de uma consulta ARP: já aprendeu o MAC de A pela requisição.' : 'O gateway encaminha a resposta do destino remoto (simplificação do simulador) usando o MAC de A, que aprendeu pela requisição.'),
  });
  tr.st(e2.tArr, 'pkt', 'entregue', 'est');
  tr.st(e2.tArr, 'phase', 'concluído', 'est');
  tr.ev(e2.tArr, 'a', 'Ping respondido', 'ok');
  tr.lg(e2.tArr, 'Echo Reply recebido: o ping chegou ao destino e voltou.', 'conn');
  tr.mile(e2.tArr, 'Concluído', 'ping respondido');
  R.tEnd = tr.t;
  return tr;
}
