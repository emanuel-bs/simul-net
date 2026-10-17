// Motor do modo ARP gratuito e conflito de endereço (RFC 5227: ARP Probe, ARP Announce e defesa do endereço).
//   announce  um host configura um endereço novo: 3 Probes (verificação) e 2 Announces (anúncio);
//   inuse     o endereço já pertence a outro host: o dono responde ao Probe e o host desiste;
//   dispute   dois hosts com o mesmo endereço: o dono defende com um Announce (e o outro cede ou também defende);
//   failover  o reserva assume o IP do principal que caiu: com ou sem ARP gratuito para atualizar o gateway.
// Os tempos seguem a RFC 5227 (PROBE_WAIT 1 s, 3 Probes a cada 1 a 2 s, ANNOUNCE_WAIT 2 s, 2 Announces a cada 2 s); o simulador usa valores fixos.
import { COLORS as C0, newTrace, type Column, type Field, type StateDef, type Trace } from '../../sim-core';
import { arpFrame, BCAST, ethHeader, HOSTS, NO_MAC, type FrameOpts, type HostKey, type NeighEvent, type NeighState } from './engine';

export interface GraParams {
  rtt: number;
  gkind: 'announce' | 'inuse' | 'dispute' | 'failover';
  gold: boolean;
  yield: boolean;
  gsend: boolean;
}

export const ZERO_IP = '0.0.0.0';
export const CLAIM = '192.168.1.50';
export const OLD_MAC = '00:00:5e:00:53:99';
const PROBE_WAIT = 1000;
const PROBE_GAP = 1500;
const ANNOUNCE_WAIT = 2000;
const ANNOUNCE_GAP = 2000;
const RETRY_MS = 1000;
const fl = (...f: Field[]): Field[] => f;

export const GRA_STATES: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'addr', label: 'Situação do endereço' },
  { key: 'tg', label: 'Tabela ARP do gateway' },
];

/** Endereço em disputa em cada situação. */
export const claimedIp = (k: GraParams['gkind']): string => (k === 'inuse' || k === 'failover' ? HOSTS.b.ip : CLAIM);

export function graColumns(k: GraParams['gkind']): Column[] {
  const X = claimedIp(k);
  return [
    { key: 'a', label: 'Host A', sub: { announce: 'configura o endereço', inuse: 'quer o endereço', dispute: 'dono do endereço', failover: 'reserva' }[k], addr: k === 'dispute' || k === 'announce' ? X : k === 'inuse' ? X + ' (pretendido)' : X + ' (assume)' },
    { key: 'b', label: 'Host B', sub: { announce: 'vizinho', inuse: 'dono do endereço', dispute: 'configurou o mesmo endereço', failover: 'principal (caiu)' }[k], addr: k === 'announce' ? HOSTS.b.ip : X },
    { key: 'g', label: 'Gateway', sub: 'roteador', addr: HOSTS.g.ip },
  ];
}

const echoFields = (dmac: string, smac: string, src: string, dst: string, type: string): Field[] => [
  ...ethHeader(dmac, smac, '0x0800 (IPv4)'),
  ...fl({ sec: 'IPv4 (RFC 791)' }, ['Origem', src, ''], ['Destino', dst, ''], ['Protocolo', '1 (ICMP)', '']),
  ...fl({ sec: 'ICMP (RFC 792)' }, ['Tipo', type, ''], ['Código', '0', '']),
];

export function buildGratuito(P: GraParams): Trace {
  const kind = P.gkind;
  const X = claimedIp(kind);
  const A = HOSTS.a;
  const B = HOSTS.b;
  const G = HOSTS.g;
  const tr = newTrace(graColumns(kind), GRA_STATES, P.rtt);
  const ow = tr.ow;
  const neigh: NeighEvent[] = [];
  const R: Record<string, any> = { sub: 'gra', kind, X, t0: 0, result: '', neigh, probes: 0, announces: 0, learnedBy: [] as string[] };
  tr.raw = R;
  const ne = (host: HostKey, mac: string | null, state: NeighState, t: number, ip = X) => neigh.push({ host, ip, mac, state, t });
  const mac = (k: HostKey) => HOSTS[k].mac;
  const others = (k: HostKey): HostKey[] => (['a', 'b', 'g'] as const).filter((x) => x !== k);

  /** Envia o quadro em broadcast: todos os outros hosts o recebem. Devolve o instante de chegada. */
  const bcast = (from: HostKey, op: 1 | 2, o: Omit<FrameOpts, 'dmac'>, lostFor?: HostKey): number => {
    const to = others(from);
    let arr = 0;
    to.forEach((k, i) => {
      const m = arpFrame(tr, from, k, op, { ...o, dmac: BCAST, par: i < to.length - 1, lost: k === lostFor || o.lost, bad: k === lostFor || o.bad });
      arr = m.tArr;
    });
    return arr;
  };
  const ev = (t: number, who: HostKey, text: string, k = '') => tr.ev(t + 0.4, who, text, k);
  const probe = (from: HostKey, n: number) =>
    bcast(from, 1, {
      sha: mac(from), spa: ZERO_IP, tha: NO_MAC, tpa: X, label: 'ARP Probe', info: 'Who has ' + X + '? Tell ' + ZERO_IP + ' (Probe ' + n + ' de 3)',
      about: 'O Probe pergunta se alguém usa ' + X + ' sem revelar o endereço ainda: o IP do remetente vai zerado (0.0.0.0), para não contaminar as tabelas dos vizinhos.', tags: ['Probe'],
    });
  const announce = (from: HostKey, n: number, defend = false) =>
    bcast(from, 1, {
      sha: mac(from), spa: X, tha: NO_MAC, tpa: X, label: defend ? 'ARP Announce (defesa)' : 'ARP Announce', info: 'Gratuitous ARP for ' + X + ' (Request)' + (defend ? ' (defesa)' : n ? ' (Announce ' + n + ' de 2)' : ''),
      about: defend ? 'O dono do endereço o reafirma com um Announce: o IP do remetente e o do alvo são o mesmo, e os vizinhos atualizam a tabela.' : 'O Announce afirma que ' + X + ' agora pertence a este MAC. Remetente e alvo têm o mesmo IP, e os vizinhos que já tinham uma entrada para ele a atualizam.', tags: [defend ? 'defesa' : 'Announce'],
    });

  tr.mile(0, 'Início', kind === 'failover' ? 'o principal cai' : 'endereço novo');

  if (kind === 'announce' || kind === 'inuse') {
    if (P.gold && kind === 'announce') {
      ne('b', OLD_MAC, 'STALE', 0);
      ne('g', OLD_MAC, 'STALE', 0);
    }
    tr.phase('1. Verificação de conflito (ARP Probe)', 'probe');
    tr.st(0, 'phase', 'Probe', 'warn');
    tr.st(0, 'addr', 'testando ' + X, 'warn');
    tr.st(0, 'tg', P.gold && kind === 'announce' ? X + ' STALE (MAC antigo)' : '(sem entrada)', P.gold && kind === 'announce' ? 'warn' : 'closed');
    tr.mile(0, 'Probe', 'o endereço está livre?');
    tr.ev(0, 'a', 'Vai usar ' + X + ': antes, verifica se há conflito', '');
    tr.lg(0, 'Host A: vai configurar ' + X + ' e antes verifica se alguém já o usa (RFC 5227).', 'conn');
    tr.wait(PROBE_WAIT);
    for (let n = 1; n <= 3; n++) {
      R.probes = n;
      const arr = probe('a', n);
      if (n === 1) tr.lg(arr, 'ARP Probe 1 de 3: "quem tem ' + X + '?" (IP do remetente zerado).', 'conn');
      if (kind === 'inuse') {
        // o dono recebe o Probe e responde por unicast: é a prova do conflito
        ev(arr, 'g', 'Não é meu IP: ignora', '');
        ev(arr, 'b', 'É o meu IP: responde ao Probe', 'warn');
        const r = arpFrame(tr, 'b', 'a', 2, {
          sha: B.mac, spa: X, tha: A.mac, tpa: ZERO_IP, dmac: A.mac, label: 'ARP Reply', info: X + ' is at ' + B.mac,
          about: 'O dono do endereço responde ao Probe: ' + X + ' já está em uso por este MAC.', tags: ['conflito'],
        });
        tr.st(r.tArr, 'phase', 'conflito', 'bad');
        tr.st(r.tArr, 'addr', 'EM USO por ' + B.mac, 'bad');
        tr.ev(r.tArr, 'a', 'Conflito: endereço em uso. Desiste dele', 'warn');
        tr.lg(r.tArr, 'Conflito detectado no Probe: ' + X + ' já pertence a ' + B.mac + '. O host não usa o endereço (com DHCP, recusa a oferta com DHCPDECLINE, RFC 2131).', 'loss');
        tr.mile(r.tArr, 'Conflito', 'endereço em uso');
        R.result = 'conflict';
        R.tEnd = tr.t;
        return tr;
      }
      if (n === 1) {
        ev(arr, 'b', 'Não é meu IP: ignora o Probe', '');
        ev(arr, 'g', 'Não é meu IP: ignora o Probe', '');
      }
      if (n < 3) tr.wait(PROBE_GAP);
    }
    tr.ev(tr.t - 0.4, 'a', 'Ninguém respondeu: o endereço está livre', 'ok');
    tr.lg(tr.t, 'Nenhuma resposta aos 3 Probes: o endereço está livre.', 'conn');
    tr.wait(ANNOUNCE_WAIT);
    tr.phase('2. Anúncio (ARP Announce)', 'ann');
    tr.st(tr.t, 'phase', 'Announce', 'warn');
    tr.st(tr.t, 'addr', 'em uso por A', 'est');
    tr.mile(tr.t, 'Announce', 'o endereço é meu');
    for (let n = 1; n <= 2; n++) {
      R.announces = n;
      const arr = announce('a', n);
      (['b', 'g'] as const).forEach((k) => {
        if (P.gold) {
          ne(k, A.mac, 'REACHABLE', arr);
          if (n === 1) ev(arr, k, 'Atualiza ' + X + ': MAC novo', 'ok');
          if (!R.learnedBy.includes(k)) R.learnedBy.push(k);
        } else if (n === 1) ev(arr, k, 'Sem entrada: nada a atualizar', '');
      });
      if (P.gold) tr.st(arr, 'tg', X + ' → MAC de A', 'est');
      if (n === 1) tr.lg(arr, 'ARP Announce 1 de 2: ' + (P.gold ? 'vizinhos que guardavam o MAC antigo de ' + X + ' atualizam a tabela.' : 'ninguém tinha entrada para ' + X + ', então não há nada a atualizar.'), 'conn');
      if (n < 2) tr.wait(ANNOUNCE_GAP);
    }
    R.result = 'announced';
    tr.ev(tr.t - 0.4, 'a', 'Endereço configurado', 'ok');
    tr.lg(tr.t, 'Host A passa a usar ' + X + '.', 'conn');
    tr.mile(tr.t, 'Concluído', 'endereço em uso');
    R.tEnd = tr.t;
    return tr;
  }

  if (kind === 'dispute') {
    ne('g', A.mac, 'REACHABLE', 0);
    tr.phase('1. Um segundo host configura o mesmo endereço', 'dup');
    tr.st(0, 'phase', 'duplicado', 'warn');
    tr.st(0, 'addr', 'A usa ' + X, 'est');
    tr.st(0, 'tg', X + ' → MAC de A', 'est');
    tr.mile(0, 'Duplicado', 'dois hosts, um IP');
    tr.ev(0, 'b', 'Configurado com ' + X + ' sem verificar conflito', 'warn');
    tr.lg(0, 'Host B recebe ' + X + ' por configuração manual, sem executar a verificação de conflito, e anuncia o endereço.', 'loss');
    tr.wait(ow / 2);
    // B anuncia o endereço que já é de A
    const a1 = announce('b', 0);
    ev(a1, 'a', 'Conflito: outro MAC afirma ter o meu IP', 'warn');
    ne('g', B.mac, 'REACHABLE', a1);
    ev(a1, 'g', 'Troca ' + X + ' para o MAC de B', 'warn');
    tr.st(a1, 'tg', X + ' → MAC de B (errado)', 'bad');
    tr.st(a1, 'phase', 'conflito', 'bad');
    tr.lg(a1, 'O Announce de B chega com o IP de A e outro MAC: conflito. O gateway já trocou a entrada para o MAC de B.', 'loss');
    tr.phase('2. Defesa do endereço', 'def');
    tr.mile(tr.t, 'Defesa', 'A reafirma o endereço');
    const a2 = announce('a', 1, true);
    ne('g', A.mac, 'REACHABLE', a2);
    ev(a2, 'g', 'Volta ' + X + ' para o MAC de A', 'ok');
    tr.st(a2, 'tg', X + ' → MAC de A', 'est');
    tr.lg(a2, 'Host A defende o endereço com um ARP Announce: o gateway volta a apontar para A.', 'conn');
    if (P.yield) {
      ev(a2, 'b', 'Conflito: cede e abandona o endereço', 'ok');
      tr.st(a2, 'addr', 'A mantém ' + X, 'est');
      tr.st(a2, 'phase', 'resolvido', 'est');
      tr.lg(a2, 'Host B reconhece o conflito e abandona o endereço. A disputa termina com A.', 'conn');
      tr.mile(a2, 'Resolvido', 'A mantém o endereço');
      R.result = 'defended';
    } else {
      tr.wait(RETRY_MS);
      tr.phase('3. Os dois defendem o endereço', 'fight');
      const a3 = announce('b', 2, true);
      ev(a3, 'a', 'Segundo conflito em menos de 10 s: abandona', 'warn');
      ne('g', B.mac, 'REACHABLE', a3);
      ev(a3, 'g', 'Troca ' + X + ' para o MAC de B', 'warn');
      tr.st(a3, 'tg', X + ' → MAC de B', 'bad');
      tr.st(a3, 'addr', 'B ficou com ' + X, 'bad');
      tr.st(a3, 'phase', 'A desistiu', 'bad');
      tr.lg(a3, 'B também defende. A recebe um segundo conflito dentro do intervalo de defesa (10 s) e abandona o endereço (RFC 5227, seção 2.4).', 'loss');
      tr.mile(a3, 'A desiste', 'B ficou com o endereço');
      R.result = 'lost';
    }
    R.tEnd = tr.t;
    return tr;
  }

  // failover: o reserva A assume o IP do principal B, que caiu
  ne('g', B.mac, 'REACHABLE', 0);
  tr.phase('1. O principal cai e o reserva assume o IP', 'down');
  tr.st(0, 'phase', 'failover', 'warn');
  tr.st(0, 'addr', 'A assumiu ' + X, 'warn');
  tr.st(0, 'tg', X + ' → MAC de B (caiu)', 'warn');
  tr.mile(0, 'Failover', 'A assume o IP');
  tr.ev(0, 'b', 'Fora do ar', 'warn');
  tr.ev(0, 'a', 'Assume o IP ' + X, 'ok');
  tr.lg(0, 'O Host B (principal) saiu do ar e o Host A (reserva) assume o IP ' + X + '. O gateway ainda guarda o MAC de B para esse IP.', 'conn');
  tr.wait(ow / 2);
  const echo = (dst: HostKey, lost: boolean, label = 'Echo Request') => {
    const m = tr.add('g', dst, {
      label, proto: 'ICMP', color: lost ? C0.bad : C0.tcp, len: 98, lost, info: 'Echo (ping) request ' + G.ip + ' → ' + X, phaseName: 'Pacote IP', tags: lost ? ['sem resposta'] : [],
      fields: echoFields(mac(dst), G.mac, G.ip, X, '8 (Echo Request)'),
      about: lost ? 'O gateway envia ao MAC que tem na tabela (' + mac(dst) + '), que já não responde.' : 'O gateway envia ao MAC de A, o novo dono de ' + X + '.',
    });
    return m;
  };
  if (P.gsend) {
    tr.phase('2. ARP gratuito', 'grat');
    tr.st(tr.t, 'phase', 'ARP gratuito', 'warn');
    tr.mile(tr.t, 'ARP gratuito', 'atualiza os vizinhos');
    const arr = bcast('a', 2, {
      sha: A.mac, spa: X, tha: BCAST, tpa: X, label: 'Gratuitous ARP (Reply)', info: 'Gratuitous ARP for ' + X + ' (Reply)',
      about: 'O novo dono envia uma resposta ARP que ninguém pediu, em broadcast: remetente e alvo têm o mesmo IP. Os vizinhos que têm uma entrada para ' + X + ' a atualizam para o MAC de A. (O valor do endereço físico do alvo varia entre sistemas.)', tags: ['gratuito'],
    }, 'b');
    ne('g', A.mac, 'REACHABLE', arr);
    ev(arr, 'g', 'Atualiza ' + X + ': MAC de A', 'ok');
    tr.st(arr, 'tg', X + ' → MAC de A', 'est');
    tr.lg(arr, 'O gateway atualiza a entrada de ' + X + ' para o MAC de A. O host B está fora do ar e não recebe o quadro.', 'conn');
    tr.phase('3. O tráfego volta', 'back');
    echo('a', false);
    const rep = tr.add('a', 'g', {
      label: 'Echo Reply', proto: 'ICMP', color: C0.tcp, len: 98, info: 'Echo (ping) reply ' + X + ' → ' + G.ip, phaseName: 'Pacote IP',
      fields: echoFields(G.mac, A.mac, X, G.ip, '0 (Echo Reply)'), about: 'A responde pelo endereço que assumiu: o serviço continuou disponível.',
    });
    tr.ev(rep.tArr, 'g', 'Ping respondido: serviço recuperado', 'ok');
    tr.st(rep.tArr, 'phase', 'recuperado', 'est');
    tr.lg(rep.tArr, 'Echo Reply de A: o serviço voltou em cerca de um RTT, sem esperar a tabela expirar.', 'conn');
    tr.mile(rep.tArr, 'Recuperado', 'serviço no ar');
    R.result = 'fast';
  } else {
    tr.phase('2. Sem ARP gratuito', 'nograt');
    tr.st(tr.t, 'phase', 'sem aviso', 'warn');
    const e = echo('b', true);
    ev(e.tArr, 'g', 'Ping sem resposta: a tabela ainda aponta para B', 'warn');
    tr.st(e.tArr, 'phase', 'sem resposta', 'bad');
    tr.lg(e.tArr, 'O gateway continua enviando ao MAC de B, que caiu. Sem ARP gratuito, a tabela só se corrige quando a entrada expirar.', 'loss');
    tr.wait(RETRY_MS);
    tr.phase('3. A entrada expira e é revalidada', 'revalid');
    tr.ev(tr.t, 'g', 'Entrada STALE: confirma por unicast', 'warn');
    ne('g', B.mac, 'STALE', tr.t);
    tr.st(tr.t, 'tg', X + ' STALE', 'warn');
    for (let n = 1; n <= 3; n++) {
      const q = arpFrame(tr, 'g', 'b', 1, {
        sha: G.mac, spa: G.ip, tha: NO_MAC, tpa: X, dmac: B.mac, label: 'ARP Request (unicast)', info: 'Who has ' + X + '? Tell ' + G.ip + ' (unicast, ' + n + ' de 3)',
        about: 'O gateway confirma a entrada antiga perguntando ao MAC conhecido. B está fora do ar: sem resposta.', lost: true, bad: true, tags: ['sem resposta'],
      });
      if (n < 3) tr.wait(RETRY_MS);
      else tr.ev(q.tArr, 'g', 'Sem resposta: entrada FAILED, pergunta a todos', 'warn');
    }
    ne('g', null, 'FAILED', tr.t);
    tr.st(tr.t, 'tg', X + ' FAILED', 'bad');
    tr.lg(tr.t, 'Sem resposta às sondas unicast: a entrada vira FAILED e o gateway pergunta em broadcast.', 'loss');
    const arr = bcast('g', 1, {
      sha: G.mac, spa: G.ip, tha: NO_MAC, tpa: X, label: 'ARP Request', info: 'Who has ' + X + '? Tell ' + G.ip,
      about: 'Sem entrada válida, o gateway pergunta a todos quem tem ' + X + '.',
    }, 'b');
    const r = arpFrame(tr, 'a', 'g', 2, {
      sha: A.mac, spa: X, tha: G.mac, tpa: G.ip, dmac: G.mac, label: 'ARP Reply', info: X + ' is at ' + A.mac, about: 'A, o novo dono, responde.',
    });
    ne('g', A.mac, 'REACHABLE', r.tArr);
    tr.ev(arr, 'a', 'É o meu IP agora: responde', 'ok');
    tr.ev(r.tArr, 'g', 'Atualiza ' + X + ': MAC de A', 'ok');
    tr.st(r.tArr, 'tg', X + ' → MAC de A', 'est');
    echo('a', false);
    const rep = tr.add('a', 'g', {
      label: 'Echo Reply', proto: 'ICMP', color: C0.tcp, len: 98, info: 'Echo (ping) reply ' + X + ' → ' + G.ip, phaseName: 'Pacote IP',
      fields: echoFields(G.mac, A.mac, X, G.ip, '0 (Echo Reply)'), about: 'O serviço volta, mas só depois de a tabela se corrigir sozinha.',
    });
    tr.ev(rep.tArr, 'g', 'Ping respondido (depois da espera)', 'ok');
    tr.st(rep.tArr, 'phase', 'recuperado (lento)', 'est');
    tr.lg(rep.tArr, 'O serviço só voltou depois de a entrada expirar e ser revalidada. Neste exemplo o tempo é curto; na prática pode levar de dezenas de segundos a horas, conforme o equipamento.', 'conn');
    tr.mile(rep.tArr, 'Recuperado', 'depois da espera');
    R.result = 'slow';
  }
  R.tEnd = tr.t;
  return tr;
}
