// Motor do modo STP clássico (IEEE 802.1D). Três switches em triângulo: eleição da raiz por BPDUs, papéis das portas e os
// estados Bloqueio, Escuta (15 s), Aprendizado (15 s) e Encaminhamento. Depois, uma falha opcional e a reconvergência.
// Os tempos são os padrões: Hello 2 s, Max Age 20 s e Forward Delay 15 s.
import type { Trace } from '../../sim-core';
import {
  blockedText, bpdu, compute, elect, lastState, makeBridges, makeLinks, newStpTrace, other, portNo, portId, portsOf, propagate,
  type Bridge, type Link, type PortEv, type Role, type Tree,
} from './model';

export interface StpParams {
  rtt: number;
  root: 'mac' | 'sw1' | 'sw3';
  l13: '1g' | '100m';
  fail: 'none' | 'link' | 'root';
}

export const FD = 15000;
export const sec = (ms: number): string => Math.round(ms / 1000) + ' s';

/** Registra os papéis calculados e o estado inicial de cada porta em um instante. */
export function setRoles(pe: PortEv[], tree: Tree, brs: Bridge[], links: Link[], t: number, stateOf: (role: Role) => string): void {
  brs.filter((b) => b.alive).forEach((b) =>
    portsOf(links, b.n).forEach((l) => {
      const role = tree.role(b.n, l.id);
      pe.push({ t, br: b.n, link: l.id, role, state: role === 'disabled' ? 'Desativada' : stateOf(role) });
    }),
  );
}

/** Texto por ponte com a porta raiz e as portas bloqueadas, para o evento logo depois da eleição. */
export function roleSummary(tree: Tree, _brs: Bridge[], links: Link[], b: Bridge): string {
  if (b.n === tree.root) return 'É a raiz: todas as portas são designadas';
  const parts: string[] = [];
  const rl = links.find((l) => l.id === tree.rootLink[b.n]);
  if (rl) parts.push('Porta raiz: ' + portNo(links, b.n, rl) + ' (custo ' + tree.cost[b.n] + ')');
  portsOf(links, b.n).forEach((l) => {
    if (tree.role(b.n, l.id) === 'alternate') parts.push('Porta ' + portNo(links, b.n, l) + ' alternativa: bloqueada');
  });
  return parts.join('. ');
}

/** Aplica a falha escolhida e registra os eventos. Devolve o texto para o log. */
export function breakIt(tr: Trace, brs: Bridge[], links: Link[], fail: 'link' | 'root', t: number): string {
  if (fail === 'link') {
    links.find((l) => l.id === 'L23')!.up = false;
    tr.ev(t, 'sw2', 'Enlace com SW3 caiu', 'warn');
    tr.ev(t, 'sw3', 'Enlace com SW2 caiu', 'warn');
    tr.lg(t, 'O enlace entre SW2 e SW3 caiu.', 'loss');
    return 'enlace SW2-SW3';
  }
  const r = brs.find((b) => b.n === compute(brs, links).root)!;
  r.alive = false;
  tr.ev(t, r.key, 'Desligado', 'warn');
  brs.filter((b) => b.alive).forEach((b) => tr.ev(t, b.key, 'Enlace com ' + r.name + ' caiu', 'warn'));
  tr.lg(t, 'A ponte raiz ' + r.name + ' foi desligada.', 'loss');
  return 'ponte raiz ' + r.name;
}

export interface Change {
  b: Bridge;
  l: Link;
  from: Role;
  to: Role;
  state0: string;
}

/** Portas vivas cujo papel mudou entre a árvore antiga e a nova. */
export function diffRoles(old: Tree, neu: Tree, brs: Bridge[], links: Link[], pe: PortEv[], wasAlive: number[]): Change[] {
  const out: Change[] = [];
  brs.filter((b) => b.alive && wasAlive.includes(b.n)).forEach((b) =>
    portsOf(links, b.n).forEach((l) => {
      const to = neu.role(b.n, l.id);
      const from = old.role(b.n, l.id);
      if (to === 'disabled' || from === to) return;
      out.push({ b, l, from, to, state0: lastState(pe, b.n, l.id)?.state || 'Bloqueio' });
    }),
  );
  return out;
}

/** O TCN sobe pela porta raiz até a raiz, que avisa com a flag TC (a tabela MAC passa a envelhecer em 15 s). */
function tcnUp(tr: Trace, brs: Bridge[], links: Link[], tree: Tree, from: Bridge): void {
  const by = (n: number) => brs.find((b) => b.n === n)!;
  let cur = from;
  while (cur.n !== tree.root) {
    const l = links.find((x) => x.id === tree.rootLink[cur.n])!;
    const nb = by(other(l, cur.n));
    const m = bpdu(tr, cur, nb, {
      kind: 'tcn', root: by(tree.root), cost: 0, port: portId(links, cur.n, l), info: cur.name + ' avisa a mudança de topologia', phaseName: 'Mudança de topologia',
      about: 'Uma porta passou a encaminhar: as tabelas MAC podem estar erradas. O TCN sobe, ponte a ponte, pela porta raiz, e cada ponte o confirma.',
    });
    tr.ev(m.tArr + 0.4, nb.key, cur.n === from.n ? 'Recebe o TCN e o confirma' : 'Recebe o TCN, confirma e o repassa', '');
    cur = nb;
  }
  tr.ev(tr.t, by(tree.root).key, 'Sinaliza TC por Max Age + Forward Delay (35 s)', 'warn');
  const t0 = tr.t;
  portsOf(links, tree.root).forEach((l) => {
    const nb = by(other(l, tree.root));
    if (!nb.alive || !l.up || tree.role(tree.root, l.id) !== 'designated') return;
    bpdu(tr, by(tree.root), nb, {
      kind: 'stp', root: by(tree.root), cost: 0, port: portId(links, tree.root, l), at: t0, par: true, flags: ['TC'], info: 'A raiz anuncia a mudança de topologia (flag TC)', phaseName: 'Mudança de topologia',
      about: 'Com a flag TC, as pontes reduzem o tempo de envelhecimento da tabela MAC para o Forward Delay (15 s), para esquecerem endereços que ficaram em portas erradas.',
    });
  });
  tr.t = t0 + tr.ow + 0.4;
}

export function buildStp(P: StpParams): Trace {
  const brs = makeBridges(P.root);
  const links = makeLinks(P.l13);
  const tr = newStpTrace(brs, P.rtt);
  const pe: PortEv[] = [];
  const by = (n: number) => brs.find((b) => b.n === n)!;
  const R = (tr.raw = { sub: 'stp', mode: 'stp', ports: pe, links, brs, fail: P.fail, root0: 0, root1: 0, conv: 0, reconv: 0, changed: 0, slow: 0, tEnd: 0 } as Record<string, any>);

  setRoles(pe, compute(brs, links), brs, links, 0, () => 'Escuta');
  brs.forEach((b) => portsOf(links, b.n).forEach((l) => (pe.find((e) => e.br === b.n && e.link === l.id)!.role = 'designated')));
  tr.phase('1. Eleição da raiz', 'eleição');
  tr.st(0, 'phase', 'eleição da raiz', 'warn');
  tr.st(0, 'root', 'cada ponte acha que é a raiz', 'warn');
  tr.st(0, 'ports', '-', 'closed');
  tr.st(0, 'conv', '-', 'closed');
  tr.mile(0, 'Ligação', 'as pontes sobem');

  const tree = elect(tr, brs, links, { kind: 'stp' });
  const tE = tr.t;
  R.root0 = tree.root;
  setRoles(pe, tree, brs, links, tE, (r) => (r === 'alternate' ? 'Bloqueio' : 'Escuta'));
  brs.forEach((b) => tr.ev(tE, b.key, roleSummary(tree, brs, links, b), b.n === tree.root ? 'ok' : ''));
  tr.st(tE, 'root', by(tree.root).name, 'est');
  tr.st(tE, 'ports', blockedText(tree, brs, links), blockedText(tree, brs, links) === 'nenhuma' ? 'closed' : 'warn');
  tr.mile(tE, 'Raiz eleita', by(tree.root).name);
  tr.lg(tE, 'Eleição concluída: raiz ' + by(tree.root).name + '. Portas bloqueadas: ' + blockedText(tree, brs, links) + '.', 'conn');

  tr.phase('2. Escuta (15 s)', 'escuta');
  tr.st(tr.t, 'phase', 'escuta', 'warn');
  tr.wait(FD);
  setRoles(pe, tree, brs, links, tr.t, (r) => (r === 'alternate' ? 'Bloqueio' : 'Aprendizado'));
  tr.ev(tr.t, by(tree.root).key, 'Portas passam a Aprendizado: aprendem MACs, ainda não encaminham', '');
  tr.phase('3. Aprendizado (15 s)', 'aprendizado');
  tr.st(tr.t, 'phase', 'aprendizado', 'warn');
  tr.wait(FD);
  setRoles(pe, tree, brs, links, tr.t, (r) => (r === 'alternate' ? 'Bloqueio' : 'Encaminhamento'));
  R.conv = tr.t;
  tr.phase('4. Rede convergida', 'convergida');
  tr.st(tr.t, 'phase', 'convergida', 'est');
  tr.st(tr.t, 'conv', 'encaminhando após ' + sec(R.conv), 'est');
  tr.mile(tr.t, 'Convergida', sec(R.conv));
  tr.lg(tr.t, 'Todas as portas ativas estão em Encaminhamento, após ' + sec(R.conv) + ' (2 x Forward Delay).', 'conn');

  if (P.fail !== 'none') {
    tr.wait(5000);
    const tF = tr.t;
    const old = tree;
    const wasAlive = brs.filter((b) => b.alive).map((b) => b.n);
    tr.phase(P.fail === 'link' ? '5. Falha de enlace' : '5. Falha da ponte raiz', 'falha');
    tr.st(tF, 'phase', 'falha', 'bad');
    const what = breakIt(tr, brs, links, P.fail, tF);
    // portas que perderam o enlace
    brs.forEach((b) =>
      portsOf(links, b.n).forEach((l) => {
        if (!b.alive || !l.up || !by(other(l, b.n)).alive) pe.push({ t: tF, br: b.n, link: l.id, role: 'disabled', state: 'Desativada' });
      }),
    );
    tr.wait(tr.ow);
    const tree2 = P.fail === 'root' ? elect(tr, brs, links, { kind: 'stp' }) : compute(brs, links);
    R.root1 = tree2.root;
    const ch = diffRoles(old, tree2, brs, links, pe, wasAlive);
    R.changed = ch.length;
    const tR = tr.t;
    const slow = ch.filter((c) => (c.to === 'root' || c.to === 'designated') && c.state0 === 'Bloqueio');
    R.slow = slow.length;
    ch.forEach((c) => {
      const fast = c.to === 'alternate' || c.state0 !== 'Bloqueio';
      pe.push({ t: tR, br: c.b.n, link: c.l.id, role: c.to, state: c.to === 'alternate' ? 'Bloqueio' : fast ? c.state0 : 'Escuta' });
      tr.ev(tR, c.b.key, 'Porta ' + portNo(links, c.b.n, c.l) + ': ' + (c.from === 'alternate' ? 'alternativa' : c.from === 'root' ? 'raiz' : 'designada') + ' passa a ' + (c.to === 'root' ? 'raiz' : c.to === 'designated' ? 'designada' : 'alternativa') + (fast ? '' : ' (sai do Bloqueio: Escuta)'), fast ? '' : 'warn');
    });
    tr.st(tR, 'root', by(tree2.root).name, 'est');
    tr.st(tR, 'ports', blockedText(tree2, brs, links), 'warn');
    if (!ch.length) {
      tr.ev(tR, by(tree2.root).key, 'Nenhuma porta mudou de papel: o enlace perdido estava bloqueado', 'ok');
      tr.lg(tR, 'A falha de ' + what + ' não alterou nenhum papel de porta: o tráfego não foi interrompido.', 'conn');
      tr.st(tR, 'conv', 'sem interrupção', 'est');
      tr.mile(tR, 'Sem efeito', 'enlace bloqueado');
    } else {
      if (P.fail === 'link') propagate(tr, brs, links, tree2, { kind: 'stp', start: [tree2.root], about: 'A raiz continua enviando BPDUs. Pela porta nova, a informação chega à ponte que perdeu o caminho.', phaseName: 'Hello' });
      if (slow.length) {
        tr.phase('6. Escuta (15 s)', 'escuta');
        tr.st(tr.t, 'phase', 'escuta', 'warn');
        tr.st(tr.t, 'conv', 'portas sem encaminhar...', 'bad');
        tr.wait(FD);
        slow.forEach((c) => pe.push({ t: tr.t, br: c.b.n, link: c.l.id, role: c.to, state: 'Aprendizado' }));
        tr.phase('7. Aprendizado (15 s)', 'aprendizado');
        tr.st(tr.t, 'phase', 'aprendizado', 'warn');
        tr.wait(FD);
        slow.forEach((c) => pe.push({ t: tr.t, br: c.b.n, link: c.l.id, role: c.to, state: 'Encaminhamento' }));
        R.reconv = tr.t - tF;
        tr.phase('8. Rede reconvergida', 'reconvergida');
        tr.st(tr.t, 'phase', 'reconvergida', 'est');
        tr.st(tr.t, 'conv', 'reconvergiu em ' + sec(R.reconv), 'est');
        tr.mile(tr.t, 'Reconvergida', sec(R.reconv));
        tr.lg(tr.t, 'Reconvergência após a falha de ' + what + ': ' + sec(R.reconv) + ' sem encaminhar nas portas novas.', 'conn');
        const tcnFrom = Array.from(new Set(slow.map((c) => c.b.n))).filter((n) => n !== tree2.root);
        if (tcnFrom.length) {
          tr.phase('9. Mudança de topologia', 'tc');
          tcnUp(tr, brs, links, tree2, by(tcnFrom[0]));
        }
      } else {
        tr.st(tr.t, 'conv', 'sem interrupção', 'est');
      }
    }
  }
  R.tEnd = tr.t;
  R.final = { root: compute(brs, links).root };
  return tr;
}

