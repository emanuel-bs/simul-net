// Motor do modo MSTP (IEEE 802.1s, hoje no IEEE 802.1Q). Uma região com os três switches e uma única BPDU
// por enlace, que leva o CIST e as instâncias (MSTI). Cada instância tem a própria raiz e a própria árvore, e o mapa
// VLAN-instância decide qual árvore cada VLAN segue. Com duas instâncias, os dois enlaces ociosos são diferentes.
import type { Field, Trace } from '../../sim-core';
import { compute, elect, makeBridges, makeLinks, newStpTrace, portNo, portsOf, propagate, ROLE_TXT, type Bridge, type Link, type PortEv, type Role } from './model';
import { setRoles } from './stp';

export interface MstpParams {
  rtt: number;
  mmode: 'one' | 'two';
}

export interface Inst {
  id: number;
  name: string;
  vlans: string;
  root: number;
  roles: { br: number; link: string; role: Role }[];
}

const DIGEST_ONE = '0xac36177f50283cd4b83821d8ab26de62';
const DIGEST_TWO = '0x5d1e07b96ac2f3418e90b7cd22a4f651';

function instance(id: number, name: string, vlans: string, brs: Bridge[], links: Link[]): Inst {
  const tree = compute(brs, links);
  const roles: Inst['roles'] = [];
  brs.forEach((b) => portsOf(links, b.n).forEach((l) => roles.push({ br: b.n, link: l.id, role: tree.role(b.n, l.id) })));
  return { id, name, vlans, root: tree.root, roles };
}

export function buildMstp(P: MstpParams): Trace {
  const brs = makeBridges('mac');
  const links = makeLinks('1g');
  const two = P.mmode === 'two';
  const tr = newStpTrace(brs, P.rtt);
  const pe: PortEv[] = [];
  const by = (n: number) => brs.find((b) => b.n === n)!;
  const inst: Inst[] = [instance(0, 'CIST (instância 0)', two ? 'todas as outras VLANs' : 'VLANs 10 e 20 e as demais', brs, links)];
  if (two) {
    inst.push(instance(1, 'MSTI 1', 'VLAN 10', makeBridges('sw1'), links));
    inst.push(instance(2, 'MSTI 2', 'VLAN 20', makeBridges('sw3'), links));
  }
  const R = (tr.raw = { sub: 'mstp', mode: 'mstp', ports: pe, links, brs, inst, mmode: P.mmode, root0: 0, tEnd: 0 } as Record<string, any>);

  const extra = (_b: Bridge): Field[] => {
    const f: Field[] = [
      { sec: 'MSTP (IEEE 802.1Q)' },
      ['Nome da região', 'LAB', 'as pontes só formam uma região se nome, revisão e mapa forem iguais'],
      ['Revisão', '1', ''],
      ['Digest do mapa VLAN-instância', two ? DIGEST_TWO + ' (valor ilustrativo)' : DIGEST_ONE, two ? 'resume o mapa: VLAN 10 na MSTI 1, VLAN 20 na MSTI 2' : 'mapa padrão: todas as VLANs no CIST'],
      ['Raiz regional do CIST', 'SW2', 'a ponte de menor identificador da região'],
    ];
    if (two) {
      f.push(['Registro da MSTI 1', 'raiz SW1 (prioridade 4096)', '16 bytes por instância'], ['Registro da MSTI 2', 'raiz SW3 (prioridade 4096)', '16 bytes por instância']);
    }
    return f;
  };

  tr.phase('1. Eleição da raiz do CIST', 'eleição');
  tr.st(0, 'phase', 'eleição', 'warn');
  tr.st(0, 'root', 'CIST: cada ponte acha que é a raiz', 'warn');
  tr.st(0, 'ports', '-', 'closed');
  tr.st(0, 'conv', '-', 'closed');
  setRoles(pe, compute(brs, links), brs, links, 0, () => 'Descarte');
  const tree = elect(tr, brs, links, { kind: 'mst', extra });
  R.root0 = tree.root;
  const tE = tr.t;
  tr.st(tE, 'root', 'CIST: ' + by(tree.root).name + (two ? '; MSTI 1: SW1; MSTI 2: SW3' : ''), 'est');
  tr.mile(tE, 'Raiz do CIST', by(tree.root).name);
  brs.forEach((b, i) => {
    const parts = inst.map((i) => i.name.split(' ')[0] + ': ' + i.roles.filter((r) => r.br === b.n).map((r) => 'p' + portNo(links, b.n, links.find((l) => l.id === r.link)!) + ' ' + ROLE_TXT[r.role]).join(', '));
    tr.ev(tE + 0.4 * i, b.key, parts.join(' | '), '');
  });
  tr.wait(0.4 * brs.length);
  const blocked = inst.map((i) => i.name.split(' ')[0] + ': ' + (i.roles.filter((r) => r.role === 'alternate').map((r) => 'enlace ' + r.link.slice(1, 2) + '-' + r.link.slice(2)).join(', ') || 'nenhum'));
  tr.st(tE, 'ports', blocked.join('; '), 'warn');

  tr.phase('2. Sincronização rápida (proposta e acordo, como no RSTP)', 'sincronização');
  tr.st(tr.t, 'phase', 'sincronização', 'warn');
  propagate(tr, brs, links, tree, { kind: 'mst', start: [tree.root], flags: ['proposta', 'porta designada'], about: 'O MSTP usa o mesmo handshake de proposta e acordo do RSTP, por instância. O simulador mostra só o CIST; as instâncias seguem a mesma lógica.', phaseName: 'Sincronização' });
  setRoles(pe, tree, brs, links, tr.t, (r) => (r === 'alternate' ? 'Descarte' : 'Encaminhamento'));
  tr.phase('3. Regiões convergidas', 'convergida');
  tr.st(tr.t, 'phase', 'convergida', 'est');
  tr.st(tr.t, 'conv', 'poucos RTT', 'est');
  tr.mile(tr.t, 'Convergida', two ? '2 instâncias' : '1 instância');
  tr.lg(tr.t, two ? 'VLAN 10 segue a árvore da MSTI 1 e a VLAN 20, a da MSTI 2: os enlaces ociosos de cada VLAN são diferentes.' : 'Todas as VLANs seguem o CIST: o enlace SW1-SW3 fica ocioso para todas.', 'conn');
  R.tEnd = tr.t;
  return tr;
}
