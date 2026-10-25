// Motor do modo RSTP (IEEE 802.1D-2004, antes 802.1w). Mesma rede do STP, mas a convergência usa o
// handshake de proposta e acordo entre pontes vizinhas, em vez de esperar os temporizadores. A porta alternativa vira porta
// raiz na hora quando a porta raiz falha. Uma ponte que só fala STP obriga os enlaces dela a usar os temporizadores.
import { COLORS as C0, type Trace } from '../../sim-core';
import {
  blockedText, bpdu, compute, elect, makeBridges, makeLinks, newStpTrace, other, portId, portNo, portsOf, propagate,
  type Bridge, type Link, type PortEv, type Tree,
} from './model';
import { FD, breakIt, diffRoles, roleSummary, sec, setRoles } from './stp';

export interface RstpParams {
  rtt: number;
  root: 'mac' | 'sw1' | 'sw3';
  l13: '1g' | '100m';
  fail: 'none' | 'link' | 'root';
  rlegacy: boolean;
}

const LEGACY = 3;

interface Ctx {
  tr: Trace;
  brs: Bridge[];
  links: Link[];
  tree: Tree;
  pe: PortEv[];
  legacy?: number;
}

const isLegacyLink = (c: Ctx, l: Link) => !!c.legacy && (l.a === c.legacy || l.b === c.legacy);

/** Portas em enlaces com ponte STP: seguem os temporizadores (Escuta e Aprendizado, 15 s cada). Devolve as pontes que ganharam porta raiz assim. */
function slowTimers(c: Ctx, ports: [number, string][], tStart: number): number[] {
  if (!ports.length) return [];
  const { tr, pe, brs, tree } = c;
  const rootOwners: number[] = [];
  const tL = tStart + FD;
  const tF = tStart + 2 * FD;
  ports.forEach(([n, id]) => {
    const role = tree.role(n, id);
    pe.push({ t: tStart, br: n, link: id, role, state: 'Escuta' });
    pe.push({ t: tL, br: n, link: id, role, state: 'Aprendizado' });
    pe.push({ t: tF, br: n, link: id, role, state: 'Encaminhamento' });
    if (role === 'root') rootOwners.push(n);
  });
  const names = Array.from(new Set(ports.map(([n]) => brs.find((b) => b.n === n)!.name))).join(', ');
  tr.ev(tStart, 'sw' + c.legacy, 'Ponte STP: não há proposta nem acordo, só os temporizadores', 'warn');
  tr.ev(tL, 'sw' + c.legacy, 'Aprendizado nas portas dos enlaces com a ponte STP (' + names + ')', '');
  tr.ev(tF, 'sw' + c.legacy, 'Encaminhamento (30 s depois)', 'ok');
  tr.lg(tStart, 'Enlaces com a ponte STP: ' + ports.length + ' portas dependem dos temporizadores (2 x Forward Delay = ' + sec(2 * FD) + ').', 'loss');
  if (tr.t < tF) tr.t = tF;
  return rootOwners;
}

/** Proposta e acordo, onda a onda, a partir das portas designadas dadas. Devolve as portas que precisam dos temporizadores. */
function handshake(c: Ctx, start: [number, string][]): [number, string][] {
  const { tr, brs, links, tree, pe } = c;
  const by = (n: number) => brs.find((b) => b.n === n)!;
  const linkOf = (id: string) => links.find((l) => l.id === id)!;
  const slow: [number, string][] = [];
  const seen = new Set<number>();
  let wave = start;
  while (wave.length) {
    const fast = wave.filter(([, id]) => !isLegacyLink(c, linkOf(id)));
    wave.filter((p) => !fast.includes(p)).forEach(([n, id]) => {
      slow.push([n, id]);
      slow.push([other(linkOf(id), n), id]);
    });
    if (!fast.length) break;
    const t0 = tr.t;
    fast.forEach(([n, id]) => {
      const l = linkOf(id);
      const b = by(n);
      const nb = by(other(l, n));
      bpdu(tr, b, nb, {
        kind: 'rstp', root: by(tree.root), cost: tree.cost[n], port: portId(links, n, l), at: t0, par: true, age: n === tree.root ? 0 : 1, flags: ['proposta', 'porta designada'], role: 'designada',
        label: 'RST BPDU (proposta)', info: b.name + ' propõe a ' + nb.name + ': "posso encaminhar?"', phaseName: 'Proposta',
        about: 'A porta designada ainda em descarte pergunta ao vizinho se pode passar a encaminhar já, sem esperar os temporizadores.',
      });
    });
    tr.t = t0 + tr.ow + 0.4;
    const t1 = tr.t;
    fast.forEach(([n, id]) => {
      const l = linkOf(id);
      const b = by(n);
      const nb = by(other(l, n));
      const rn = tree.role(nb.n, id);
      tr.ev(t1, nb.key, rn === 'root' ? 'Recebe a proposta na porta raiz: põe as outras portas em descarte (sincroniza) e concorda' : 'Recebe a proposta na porta alternativa, já em descarte: concorda', '');
      bpdu(tr, nb, b, {
        kind: 'rstp', root: by(tree.root), cost: tree.cost[nb.n], port: portId(links, nb.n, l), at: t1, par: true, age: 1, flags: rn === 'root' ? ['acordo', 'porta raiz', 'aprendizado', 'encaminhamento'] : ['acordo', 'porta alternativa'], role: rn === 'root' ? 'raiz' : 'alternativa',
        label: 'RST BPDU (acordo)', info: nb.name + ' concorda com ' + b.name, color: C0.data, phaseName: 'Acordo',
        about: 'O vizinho garante que não há laço pelas outras portas dele (sincronizadas). A porta do remetente do acordo, se for a porta raiz, já pode encaminhar.',
      });
      if (rn === 'root') pe.push({ t: t1, br: nb.n, link: id, role: 'root', state: 'Encaminhamento' });
    });
    tr.t = t1 + tr.ow + 0.4;
    const t2 = tr.t - 0.4;
    const next: [number, string][] = [];
    fast.forEach(([n, id]) => {
      const nb = by(other(linkOf(id), n));
      pe.push({ t: t2, br: n, link: id, role: 'designated', state: 'Encaminhamento' });
      tr.ev(t2 + 0.4, by(n).key, 'Acordo recebido: a porta ' + portNo(links, n, linkOf(id)) + ' passa a encaminhar', 'ok');
      if (tree.role(nb.n, id) === 'root' && !seen.has(nb.n)) {
        seen.add(nb.n);
        portsOf(links, nb.n).forEach((l2) => {
          const o2 = by(other(l2, nb.n));
          if (tree.role(nb.n, l2.id) === 'designated' && l2.up && o2.alive) next.push([nb.n, l2.id]);
        });
      }
    });
    wave = next;
  }
  return slow;
}

export function buildRstp(P: RstpParams): Trace {
  const brs = makeBridges(P.root);
  const links = makeLinks(P.l13);
  const tr = newStpTrace(brs, P.rtt);
  const pe: PortEv[] = [];
  const legacy = P.rlegacy ? LEGACY : undefined;
  const by = (n: number) => brs.find((b) => b.n === n)!;
  const R = (tr.raw = { sub: 'rstp', mode: 'rstp', ports: pe, links, brs, fail: P.fail, legacy: !!legacy, root0: 0, root1: 0, conv: 0, reconv: 0, changed: 0, slow: 0, tEnd: 0 } as Record<string, any>);

  setRoles(pe, compute(brs, links), brs, links, 0, () => 'Descarte');
  brs.forEach((b) => portsOf(links, b.n).forEach((l) => (pe.find((e) => e.br === b.n && e.link === l.id)!.role = 'designated')));
  tr.phase('1. Eleição da raiz', 'eleição');
  tr.st(0, 'phase', 'eleição da raiz', 'warn');
  tr.st(0, 'root', 'cada ponte acha que é a raiz', 'warn');
  tr.st(0, 'ports', '-', 'closed');
  tr.st(0, 'conv', '-', 'closed');
  tr.mile(0, 'Ligação', 'as pontes sobem');
  if (legacy) tr.ev(0, 'sw' + legacy, 'Só fala STP (802.1D de 1998)', 'warn');

  const tree = elect(tr, brs, links, { kind: 'rstp', legacy });
  const tE = tr.t;
  R.root0 = tree.root;
  const c: Ctx = { tr, brs, links, tree, pe, legacy };
  setRoles(pe, tree, brs, links, tE, () => 'Descarte');
  brs.forEach((b, i) => tr.ev(tE + 0.4 * i, b.key, roleSummary(tree, brs, links, b), b.n === tree.root ? 'ok' : ''));
  tr.wait(0.4 * brs.length);
  tr.st(tE, 'root', by(tree.root).name, 'est');
  tr.st(tE, 'ports', blockedText(tree, brs, links), blockedText(tree, brs, links) === 'nenhuma' ? 'closed' : 'warn');
  tr.mile(tE, 'Raiz eleita', by(tree.root).name);

  tr.phase('2. Proposta e acordo', 'sincronização');
  tr.st(tr.t, 'phase', 'proposta e acordo', 'warn');
  const startPorts = (n: number): [number, string][] => portsOf(links, n).filter((l) => tree.role(n, l.id) === 'designated').map((l) => [n, l.id]);
  let slow = handshake(c, startPorts(tree.root));
  // enlaces com a ponte STP: temporizadores; depois a cascata continua a partir das pontes que ganharam porta raiz
  let guard = 0;
  while (slow.length && guard++ < 3) {
    tr.phase('3. Enlaces com a ponte STP: temporizadores', 'temporizadores');
    tr.st(tr.t, 'phase', 'temporizadores do STP', 'warn');
    const owners = slowTimers(c, slow, guard === 1 ? tE : tr.t);
    slow = [];
    owners.forEach((n) => slow.push(...handshake(c, startPorts(n))));
  }
  R.conv = tr.t;
  tr.phase('4. Rede convergida', 'convergida');
  tr.st(tr.t, 'phase', 'convergida', 'est');
  tr.st(tr.t, 'conv', 'encaminhando após ' + (tr.t >= 1000 ? sec(R.conv) : Math.round(R.conv * 10) / 10 + ' ms'), 'est');
  tr.mile(tr.t, 'Convergida', tr.t >= 1000 ? sec(R.conv) : Math.round(R.conv) + ' ms');
  tr.lg(tr.t, 'Todas as portas ativas encaminham, exceto as alternativas, que ficam em descarte.', 'conn');

  if (P.fail !== 'none') {
    tr.wait(5000);
    const tF = tr.t;
    const old = tree;
    const wasAlive = brs.filter((b) => b.alive).map((b) => b.n);
    tr.phase(P.fail === 'link' ? '5. Falha de enlace' : '5. Falha da ponte raiz', 'falha');
    tr.st(tF, 'phase', 'falha', 'bad');
    const what = breakIt(tr, brs, links, P.fail, tF);
    brs.forEach((b) =>
      portsOf(links, b.n).forEach((l) => {
        if (!b.alive || !l.up || !by(other(l, b.n)).alive) pe.push({ t: tF, br: b.n, link: l.id, role: 'disabled', state: 'Desativada' });
      }),
    );
    tr.wait(tr.ow);
    const tree2 = P.fail === 'root' ? elect(tr, brs, links, { kind: 'rstp', legacy }) : compute(brs, links);
    R.root1 = tree2.root;
    c.tree = tree2;
    const ch = diffRoles(old, tree2, brs, links, pe, wasAlive);
    R.changed = ch.length;
    const tR = tr.t;
    tr.st(tR, 'root', by(tree2.root).name, 'est');
    tr.st(tR, 'ports', blockedText(tree2, brs, links), 'warn');
    const hs: [number, string][] = [];
    const slowP: [number, string][] = [];
    ch.forEach((cg) => {
      const pn = portNo(links, cg.b.n, cg.l);
      const txt = (r: string) => (r === 'alternate' ? 'alternativa' : r === 'root' ? 'raiz' : 'designada');
      const legacyLink = isLegacyLink(c, cg.l);
      if (cg.to === 'alternate') {
        pe.push({ t: tR, br: cg.b.n, link: cg.l.id, role: 'alternate', state: 'Descarte' });
        tr.ev(tR, cg.b.key, 'Porta ' + pn + ': ' + txt(cg.from) + ' passa a alternativa (descarte)', 'warn');
      } else if (legacyLink && cg.state0 === 'Descarte') {
        slowP.push([cg.b.n, cg.l.id]);
        pe.push({ t: tR, br: cg.b.n, link: cg.l.id, role: cg.to, state: 'Descarte' });
      } else if (cg.to === 'root') {
        const wasOff = cg.state0 === 'Descarte';
        pe.push({ t: tR + (wasOff ? 0.4 : 0), br: cg.b.n, link: cg.l.id, role: 'root', state: wasOff ? 'Encaminhamento' : cg.state0 });
        tr.ev(tR, cg.b.key, wasOff ? 'Porta ' + pn + ': a alternativa vira porta raiz e encaminha na hora, sem temporizador' : 'Porta ' + pn + ': ' + txt(cg.from) + ' passa a raiz (já encaminhava)', wasOff ? 'ok' : '');
      } else if (cg.state0 === 'Descarte') {
        pe.push({ t: tR, br: cg.b.n, link: cg.l.id, role: 'designated', state: 'Descarte' });
        hs.push([cg.b.n, cg.l.id]);
        tr.ev(tR, cg.b.key, 'Porta ' + pn + ': de alternativa a designada; propõe ao vizinho', 'warn');
      } else {
        pe.push({ t: tR, br: cg.b.n, link: cg.l.id, role: cg.to, state: cg.state0 });
      }
    });
    if (!ch.length) {
      tr.ev(tR, by(tree2.root).key, 'Nenhuma porta mudou de papel: o enlace perdido estava bloqueado', 'ok');
      tr.lg(tR, 'A falha de ' + what + ' não alterou nenhum papel de porta.', 'conn');
      tr.st(tR, 'conv', 'sem interrupção', 'est');
      tr.mile(tR, 'Sem efeito', 'enlace bloqueado');
    } else {
      tr.wait(tr.ow + 0.4);
      if (hs.length) {
        tr.phase('6. Proposta e acordo nas portas novas', 'sincronização');
        tr.st(tr.t, 'phase', 'proposta e acordo', 'warn');
        const sl = handshake(c, hs);
        slowP.push(...sl);
      }
      if (slowP.length) {
        tr.phase('7. Enlaces com a ponte STP: temporizadores', 'temporizadores');
        tr.st(tr.t, 'phase', 'temporizadores do STP', 'warn');
        slowTimers(c, slowP, tr.t);
      }
      R.slow = slowP.length;
      R.reconv = tr.t - tF;
      tr.ev(tr.t, by(tree2.root).key, 'Flag TC: as pontes limpam as tabelas MAC das outras portas, sem esperar o envelhecimento', '');
      if (P.fail === 'link' && !hs.length && !slowP.length) propagate(tr, brs, links, tree2, { kind: 'rstp', start: [tree2.root], about: 'A raiz segue enviando BPDUs; a informação chega pela porta nova.', phaseName: 'Hello' });
      tr.phase('8. Rede reconvergida', 'reconvergida');
      tr.st(tr.t, 'phase', 'reconvergida', 'est');
      const txt = tr.t - tF >= 1000 ? sec(tr.t - tF) : Math.round((tr.t - tF) * 10) / 10 + ' ms';
      R.reconvTxt = txt;
      tr.st(tr.t, 'conv', 'reconvergiu em ' + txt, 'est');
      tr.mile(tr.t, 'Reconvergida', txt);
      tr.lg(tr.t, 'Reconvergência após a falha de ' + what + ': ' + txt + '.', 'conn');
    }
  }
  R.tEnd = tr.t;
  return tr;
}
