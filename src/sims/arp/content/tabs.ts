// Aba própria do ARP: a tabela de vizinhos de cada host, no instante mostrado, no formato do "ip neigh" do Linux.
import { esc } from '../../../sim-core';
import type { TabDef } from '../../../sim-core/ui';
import { HOSTS, type NeighEvent } from '../engine';

const tabela: TabDef = {
  id: 'tabela',
  label: 'Tabela ARP',
  render: (tr, ctx) => {
    const R = tr.raw;
    const ev = (R.neigh || []) as NeighEvent[];
    const now = ctx.timeAt(ctx.c);
    let h = '<h3>Tabela de vizinhos de cada host (como o <code>ip neigh</code> do Linux a mostra)</h3>';
    (['a', 'b', 'g'] as const).forEach((k) => {
      const last = new Map<string, NeighEvent>();
      ev.filter((e) => e.host === k && e.t <= now).forEach((e) => last.set(e.ip, e));
      const lines = Array.from(last.values()).map((e) => e.ip + ' dev eth0 ' + (e.mac ? 'lladdr ' + e.mac + ' ' : ' ') + e.state);
      h += '<h3>' + esc(HOSTS[k].name) + ' (' + HOSTS[k].ip + ', ' + HOSTS[k].mac + ')</h3><pre class="conf">' + esc(lines.join('\n') || '(vazia)') + '</pre>';
    });
    h += '<p>Cada entrada associa um IP a um endereço físico. <b>INCOMPLETE</b>: pergunta enviada, sem resposta ainda. <b>REACHABLE</b>: confirmada há pouco. <b>STALE</b>: antiga, será confirmada. <b>FAILED</b>: ninguém respondeu.</p>';
    return h;
  },
};

export const tabs: TabDef[] = [tabela];
