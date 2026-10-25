// Motor do modo Proteções do spanning tree (nível defensivo). Um switch não autorizado, de prioridade 0, é ligado a uma
// porta de acesso do SW1 e anuncia uma BPDU "superior". Sem proteção, ele vira a raiz e a rede reconverge ao redor dele.
// BPDU Guard e Root Guard são recursos de fabricantes (não são parte do IEEE 802.1D); os nomes seguem os de um fabricante comum.
import { newTrace, type StateDef, type Trace } from '../../sim-core';
import { bpdu, cols, compute, makeBridges, makeLinks, portId, portNo, propagate, blockedText, type PortEv } from './model';
import { FD, diffRoles, sec, setRoles } from './stp';

export interface ProtParams {
  rtt: number;
  pguard: 'none' | 'bpdu' | 'root';
}

export const STATES_PROT: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'root', label: 'Ponte raiz' },
  { key: 'acc', label: 'Porta de acesso do SW1 (p3)' },
  { key: 'conv', label: 'Efeito na rede' },
];

export function buildProt(P: ProtParams): Trace {
  const brs = makeBridges('mac', true);
  const links = makeLinks('1g', true);
  const x = brs.find((b) => b.n === 4)!;
  x.alive = false;
  const tr = newTrace(cols(brs), STATES_PROT, P.rtt);
  const pe: PortEv[] = [];
  const by = (n: number) => brs.find((b) => b.n === n)!;
  const sw1 = by(1);
  const lx = links.find((l) => l.id === 'LX')!;
  const R = (tr.raw = { sub: 'prot', mode: 'prot', ports: pe, links, brs, guard: P.pguard, root0: 0, root1: 0, reconv: 0, changed: 0, outage: 0, tEnd: 0 } as Record<string, any>);

  const base = compute(brs, links);
  R.root0 = base.root;
  setRoles(pe, base, brs, links, 0, (r) => (r === 'alternate' ? 'Bloqueio' : 'Encaminhamento'));
  tr.phase('1. Rede estável', 'estável');
  tr.st(0, 'phase', 'estável', 'est');
  tr.st(0, 'root', by(base.root).name, 'est');
  tr.st(0, 'acc', P.pguard === 'none' ? 'porta de acesso sem proteção' : P.pguard === 'bpdu' ? 'BPDU Guard' : 'Root Guard', P.pguard === 'none' ? 'warn' : 'est');
  tr.st(0, 'conv', 'tráfego normal', 'est');
  tr.ev(0, 'sw2', 'É a raiz (o switch de menor MAC)', 'ok');
  tr.ev(0, 'sw3', 'Porta bloqueada no enlace com SW1: sem laço', '');

  tr.wait(2000);
  tr.phase('2. Um switch não autorizado é ligado à porta de acesso do SW1', 'intruso');
  tr.st(tr.t, 'phase', 'intruso conectado', 'warn');
  x.alive = true;
  pe.push({ t: tr.t, br: 1, link: 'LX', role: 'disabled', state: 'Desativada' });
  tr.ev(tr.t, 'x', 'Ligado à porta 3 do SW1; anuncia prioridade 0', 'warn');
  const hello = bpdu(tr, x, sw1, {
    kind: 'stp', root: x, cost: 0, port: portId(links, 4, lx), info: 'o intruso se anuncia como raiz (prioridade 0)', phaseName: 'BPDU do intruso',
    about: 'Prioridade 0 é o melhor valor possível: qualquer ponte da rede aceitaria este anúncio como "superior" ao da raiz atual. Não é preciso nenhuma autenticação.',
  });
  const tH = hello.tArr + 0.4;

  if (P.pguard === 'bpdu') {
    tr.ev(tH, 'sw1', 'BPDU Guard: a porta de acesso recebeu uma BPDU, que ali não deveria existir. Desativa a porta (err-disable)', 'ok');
    tr.lg(tH, 'BPDU Guard: BPDU recebida na porta de borda 3 do SW1; porta colocada em err-disable. O intruso é isolado.', 'conn');
    pe.push({ t: tH, br: 1, link: 'LX', role: 'disabled', state: 'Desativada (BPDU Guard)' });
    tr.st(tH, 'acc', 'desativada (err-disable)', 'bad');
    tr.st(tH, 'conv', 'nenhum: o intruso foi isolado', 'est');
    tr.mile(tH, 'Isolado', 'BPDU Guard');
    R.root1 = base.root;
    R.result = 'isolated';
  } else if (P.pguard === 'root') {
    tr.ev(tH, 'sw1', 'Root Guard: a BPDU é superior à da raiz atual. A porta vai a root-inconsistente (bloqueio) e ignora o anúncio', 'ok');
    tr.lg(tH, 'Root Guard: BPDU superior recebida na porta 3 do SW1; porta em root-inconsistent. Volta ao normal quando o intruso parar de enviar BPDUs.', 'conn');
    pe.push({ t: tH, br: 1, link: 'LX', role: 'designated', state: 'Bloqueio (root-inconsistente)' });
    tr.st(tH, 'acc', 'root-inconsistente (bloqueada)', 'warn');
    tr.st(tH, 'conv', 'nenhum: a raiz não mudou', 'est');
    tr.mile(tH, 'Contido', 'Root Guard');
    R.root1 = base.root;
    R.result = 'contained';
  } else {
    const tree = compute(brs, links);
    R.root1 = tree.root;
    tr.ev(tH, 'sw1', 'Aceita: a BPDU é a melhor que já viu. O intruso passa a ser a raiz', 'warn');
    tr.lg(tH, 'SW1 adotou o switch intruso como raiz e passou a anunciá-lo aos vizinhos.', 'loss');
    tr.phase('3. A rede reconverge ao redor do intruso', 'reconvergência');
    tr.st(tr.t, 'phase', 'reconvergindo', 'bad');
    tr.st(tr.t, 'root', by(tree.root).name + ' (intruso)', 'bad');
    tr.st(tr.t, 'acc', 'sem proteção: aceitou o intruso', 'bad');
    propagate(tr, brs, links, tree, { kind: 'stp', start: [1], about: 'As pontes repassam o novo anúncio: todas passam a ter o intruso como raiz.', phaseName: 'Nova raiz' });
    const tR = tr.t;
    const ch = diffRoles(base, tree, brs, links, pe, [1, 2, 3]);
    R.changed = ch.length;
    const slow = ch.filter((c) => (c.to === 'root' || c.to === 'designated') && (c.state0 === 'Bloqueio' || c.state0 === 'Desativada'));
    ch.forEach((c) => {
      const isSlow = slow.includes(c);
      pe.push({ t: tR, br: c.b.n, link: c.l.id, role: c.to, state: c.to === 'alternate' ? 'Bloqueio' : isSlow ? 'Escuta' : c.state0 });
      const pn = portNo(links, c.b.n, c.l);
      tr.ev(tR, c.b.key, 'Porta ' + pn + (c.to === 'alternate' ? ' passa a alternativa (bloqueio)' : c.to === 'root' ? ' passa a porta raiz' + (isSlow ? ' (sai do bloqueio: Escuta)' : '') : ' passa a designada' + (isSlow ? ' (Escuta)' : '')), isSlow ? 'warn' : '');
    });
    tr.st(tR, 'ports', blockedText(tree, brs, links), 'warn');
    tr.phase('4. Escuta e aprendizado (30 s)', 'temporizadores');
    tr.st(tr.t, 'conv', 'portas novas sem encaminhar', 'bad');
    tr.wait(FD);
    slow.forEach((c) => pe.push({ t: tr.t, br: c.b.n, link: c.l.id, role: c.to, state: 'Aprendizado' }));
    tr.wait(FD);
    slow.forEach((c) => pe.push({ t: tr.t, br: c.b.n, link: c.l.id, role: c.to, state: 'Encaminhamento' }));
    R.reconv = tr.t - tR;
    R.outage = slow.some((c) => c.b.n === 3) ? R.reconv : 0;
    tr.phase('5. Rede reconvergida, com o intruso como raiz', 'reconvergida');
    tr.st(tr.t, 'phase', 'reconvergida', 'est');
    tr.st(tr.t, 'conv', 'tráfego desviado: SW3 ficou ' + sec(R.reconv) + ' sem encaminhar', 'bad');
    tr.mile(tr.t, 'Raiz trocada', 'o intruso');
    tr.lg(tr.t, 'O intruso é a raiz: o tráfego entre SW2 e SW3 passa a dar a volta pelo SW1 e pelo intruso, e a reconvergência custou ' + sec(R.reconv) + ' de interrupção.', 'loss');
    R.result = 'hijacked';
  }
  R.tEnd = tr.t;
  return tr;
}
