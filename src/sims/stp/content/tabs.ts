// Abas próprias do simulador de spanning tree: portas das pontes no instante mostrado e instâncias do MSTP.
import { esc } from '../../../sim-core';
import type { TabDef } from '../../../sim-core/ui';
import { portNo, portsAt, portsOf, ROLE_TXT, other, type Bridge, type Link, type PortEv, type Role } from '../model';
import type { Inst } from '../mstp';

const portas: TabDef = {
  id: 'portas',
  label: 'Portas',
  render: (tr, ctx) => {
    const R = tr.raw;
    const brs = (R.brs || []) as Bridge[];
    const links = (R.links || []) as Link[];
    if (R.sub === 'laco' && !R.stp) return '<h3>Spanning tree desligado</h3><p>Sem o protocolo, todas as portas encaminham: não há papéis nem estados. É isso que permite o laço.</p>';
    const at = portsAt((R.ports || []) as PortEv[], ctx.timeAt(ctx.c));
    let h = '<h3>Papel e estado de cada porta (como um comando de status do spanning tree)</h3>';
    brs.filter((b) => b.key !== 'x').forEach((b) => {
      h += '<h3>' + esc(b.name) + ' (prioridade ' + b.prio + ', ' + b.mac + ')' + (b.alive ? '' : ' - desligada') + '</h3>';
      h += '<table class="sc-msgs"><thead><tr><th>Porta</th><th>Liga a</th><th>Custo</th><th>Papel</th><th>Estado</th></tr></thead><tbody>';
      portsOf(links, b.n).forEach((l) => {
        const e = at.get(b.n + ':' + l.id);
        const nb = brs.find((x) => x.n === other(l, b.n))!;
        h += '<tr><td>' + portNo(links, b.n, l) + '</td><td class="meaning">' + esc(nb.name) + (l.up ? '' : ' (enlace caído)') + '</td><td class="meaning">' + l.cost + '</td><td class="meaning">' + (e ? ROLE_TXT[e.role] : '-') + '</td><td class="meaning">' + (e ? esc(e.state) : '-') + '</td></tr>';
      });
      h += '</tbody></table>';
    });
    h += '<p><b>Papéis:</b> raiz (melhor caminho até a ponte raiz), designada (a que encaminha para o segmento) e alternativa (reserva, bloqueada). <b>Estados do STP:</b> Bloqueio, Escuta, Aprendizado e Encaminhamento. <b>Estados do RSTP:</b> Descarte, Aprendizado e Encaminhamento.</p>';
    return h;
  },
};

const instancias: TabDef = {
  id: 'instancias',
  label: 'Instâncias',
  subs: ['mstp'],
  render: (tr) => {
    const R = tr.raw;
    const inst = (R.inst || []) as Inst[];
    const links = (R.links || []) as Link[];
    const brs = (R.brs || []) as Bridge[];
    let h = '<h3>Mapa de VLANs e papéis por instância</h3>';
    inst.forEach((i) => {
      h += '<h3>' + esc(i.name) + ': ' + esc(i.vlans) + ' (raiz ' + esc(brs.find((b) => b.n === i.root)!.name) + ')</h3>';
      h += '<table class="sc-msgs"><thead><tr><th>Ponte</th><th>Porta</th><th>Liga a</th><th>Papel</th></tr></thead><tbody>';
      i.roles.forEach((r) => {
        const l = links.find((x) => x.id === r.link)!;
        const nb = brs.find((b) => b.n === other(l, r.br))!;
        h += '<tr><td>' + esc(brs.find((b) => b.n === r.br)!.name) + '</td><td>' + portNo(links, r.br, l) + '</td><td class="meaning">' + esc(nb.name) + '</td><td class="meaning">' + ROLE_TXT[r.role as Role] + '</td></tr>';
      });
      h += '</tbody></table>';
    });
    h += '<p>A porta alternativa bloqueia só as VLANs daquela instância. Um enlace bloqueado numa instância pode estar ativo na outra.</p>';
    return h;
  },
};

export const tabs: TabDef[] = [portas, instancias];
