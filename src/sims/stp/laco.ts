// Motor do modo Laço e tempestade de broadcast. Um broadcast de A entra no triângulo de switches.
//  - sem STP, as pontes inundam o quadro por todas as portas e ele dá voltas para sempre (o quadro Ethernet não tem TTL);
//  - com STP, uma porta bloqueada corta o laço e o quadro chega uma só vez a cada destino.
// O triângulo só tem duas cópias circulando; em malhas com mais enlaces o número de cópias cresce de forma exponencial.
import { COLORS as C0, newTrace, type Column, type Field, type StateDef, type Trace } from '../../sim-core';
import { compute, makeBridges, makeLinks, other, portsOf, type Link, type PortEv } from './model';
import { setRoles } from './stp';

export interface LacoParams {
  rtt: number;
  lmode: 'nostp' | 'stp';
  root: 'mac' | 'sw1' | 'sw3';
}

export const MAC_A = '00:00:5e:00:53:a0';
export const MAC_B = '00:00:5e:00:53:b0';
const ROUNDS = 6;

export const COLS_LACO: Column[] = [
  { key: 'a', label: 'Host A', sub: 'porta de acesso do SW1', addr: '192.168.1.10' },
  { key: 'sw1', label: 'SW1', sub: 'switch', addr: '00:00:5e:00:53:1e' },
  { key: 'sw2', label: 'SW2', sub: 'switch', addr: '00:00:5e:00:53:0a' },
  { key: 'sw3', label: 'SW3', sub: 'switch', addr: '00:00:5e:00:53:28' },
  { key: 'b', label: 'Host B', sub: 'porta de acesso do SW3', addr: '192.168.1.20' },
];

export const STATES_LACO: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'stp', label: 'Spanning tree' },
  { key: 'cop', label: 'Cópias do broadcast na rede' },
  { key: 'dup', label: 'Cópias recebidas por B' },
  { key: 'flap', label: 'Mudanças de porta do MAC de A no SW1' },
];

const arp: Field[] = [
  { sec: 'Ethernet II' },
  ['Destino', 'ff:ff:ff:ff:ff:ff', 'broadcast: toda ponte o inunda'],
  ['Origem', MAC_A, ''],
  ['Tipo', '0x0806 (ARP)', ''],
  { sec: 'ARP (RFC 826)' },
  ['Operação', '1 (requisição)', ''],
  ['IP do alvo', '192.168.1.99', 'ninguém responde: o quadro só circula'],
];

export function buildLaco(P: LacoParams): Trace {
  const brs = makeBridges(P.root);
  const links = makeLinks('1g');
  const tr = newTrace(COLS_LACO, STATES_LACO, P.rtt);
  const pe: PortEv[] = [];
  const stp = P.lmode === 'stp';
  const tree = compute(brs, links);
  const R = (tr.raw = { sub: 'laco', mode: 'laco', ports: pe, links, brs, stp, rounds: 0, copies: [] as number[], dupB: 0, dupA: 0, flaps: 0, lost: 0, tEnd: 0, storm: false } as Record<string, any>);
  if (stp) setRoles(pe, tree, brs, links, 0, (r) => (r === 'alternate' ? 'Bloqueio' : 'Encaminhamento'));

  tr.st(0, 'stp', stp ? 'ligado: raiz SW' + tree.root : 'desligado', stp ? 'est' : 'bad');
  tr.st(0, 'cop', '0', 'closed');
  tr.st(0, 'dup', '0', 'closed');
  tr.st(0, 'flap', '0', 'closed');
  tr.phase('1. Um broadcast entra na rede', 'broadcast');
  tr.st(0, 'phase', 'broadcast de A', 'warn');
  tr.ev(0, 'sw1', stp ? 'Spanning tree convergido: uma porta está bloqueada' : 'Spanning tree desligado: as três pontes formam um laço', stp ? 'ok' : 'warn');
  const first = tr.add('a', 'sw1', {
    label: 'ARP Request', proto: 'ARP', len: 42, color: C0.plain, info: 'Who has 192.168.1.99? Tell 192.168.1.10', phaseName: 'Broadcast', fields: arp,
    about: 'Um broadcast comum, como o de qualquer ARP. O quadro Ethernet não tem campo de TTL: nada o faz expirar.',
  });
  tr.ev(first.tArr + 0.4, 'sw1', 'Aprende A na porta de acesso e inunda o quadro', '');

  const by = (n: number) => brs.find((b) => b.n === n)!;
  type Arr = { at: number; via: string };
  let cur: Arr[] = [{ at: 1, via: 'host' }];
  const hostOf: Record<number, string | undefined> = { 1: 'a', 3: 'b' };
  const msg = (from: number | string, to: number | string, t0: number, lost: boolean, tags: string[], about: string) => {
    const f = typeof from === 'number' ? by(from).key : from;
    const t = typeof to === 'number' ? by(to).key : to;
    return tr.add(f, t, { label: 'ARP Request', proto: 'ARP', len: 42, color: lost ? C0.bad : C0.plain, info: 'cópia do broadcast', fields: arp, at: t0, par: true, lost, tags, about, phaseName: 'Cópia' });
  };

  for (let round = 1; round <= ROUNDS && cur.length; round++) {
    if (round === 2) tr.phase(stp ? '2. O quadro segue pela árvore' : '2. O quadro dá voltas no laço', stp ? 'árvore' : 'laço');
    const t0 = tr.t;
    const next: Arr[] = [];
    let sent = 0;
    cur.forEach((arr) => {
      portsOf(links, arr.at).forEach((l: Link) => {
        if (l.id === arr.via) return;
        const nb = other(l, arr.at);
        if (stp && tree.role(arr.at, l.id) === 'alternate') return;
        const blockedFar = stp && tree.role(nb, l.id) === 'alternate';
        msg(arr.at, nb, t0, blockedFar, blockedFar ? ['descartado: porta bloqueada'] : [], blockedFar ? 'O quadro chega a uma porta em Bloqueio e é descartado: o laço fica cortado aqui.' : 'A ponte repassa o broadcast por todas as portas, menos a de entrada.');
        sent++;
        if (blockedFar) {
          R.lost++;
          tr.ev(t0 + tr.ow + 0.4, by(nb).key, 'Porta em Bloqueio: descarta o quadro', 'ok');
        } else next.push({ at: nb, via: l.id });
      });
      const h = hostOf[arr.at];
      if (h && arr.via !== 'host') {
        msg(arr.at, h, t0, false, [], 'O broadcast também sai pela porta de acesso, e o host o recebe.');
        sent++;
        if (h === 'b') R.dupB++;
        else R.dupA++;
      }
    });
    // o switch que recebe o quadro de volta pelas portas entre pontes vê o MAC de A mudar de porta
    cur.forEach((arr) => {
      if (arr.at === 1 && arr.via !== 'host') {
        R.flaps++;
        tr.ev(t0 + tr.ow + 0.4, 'sw1', 'O MAC de A chega por outra porta: a tabela muda (flap)', 'warn');
      }
    });
    if (!sent) break;
    tr.t = t0 + tr.ow + 0.4;
    R.rounds = round;
    R.copies.push(next.length);
    tr.st(tr.t - 0.4, 'cop', next.length + ' em circulação', next.length ? (stp ? 'warn' : 'bad') : 'est');
    tr.st(tr.t - 0.4, 'dup', String(R.dupB), R.dupB > 1 ? 'bad' : R.dupB ? 'warn' : 'closed');
    tr.st(tr.t - 0.4, 'flap', String(R.flaps), R.flaps ? 'bad' : 'closed');
    cur = next;
  }
  if (cur.length) {
    R.storm = true;
    tr.phase('3. E continua indefinidamente', 'tempestade');
    tr.st(tr.t, 'phase', 'tempestade', 'bad');
    tr.ev(tr.t, 'sw2', 'As cópias seguem circulando sem parar: só desligar um enlace interrompe', 'warn');
    tr.lg(tr.t, 'Tempestade de broadcast: o quadro não expira. Cada volta entrega mais cópias a A e a B e faz o MAC de A mudar de porta.', 'loss');
  } else {
    tr.phase('3. O quadro acabou', 'fim');
    tr.st(tr.t, 'phase', 'sem laço', 'est');
    tr.ev(tr.t, 'b', 'Recebeu o broadcast uma única vez', 'ok');
    tr.lg(tr.t, 'Com a porta bloqueada, o broadcast chegou uma vez a cada host e não voltou.', 'conn');
  }
  tr.mile(tr.t, stp ? 'Sem laço' : 'Tempestade', stp ? 'uma cópia por host' : 'cópias sem fim');
  R.tEnd = tr.t;
  return tr;
}
