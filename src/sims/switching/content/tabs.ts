// Abas próprias do simulador de switching: a tabela de endereços e as decisões do switch.
import { esc } from '../../../sim-core';
import type { TabDef } from '../../../sim-core/ui';
import { who, tableAt, type Decision, type MacEv } from '../model';

const ACTION: Record<Decision['action'], string> = { flood: 'inunda', forward: 'encaminha', filter: 'filtra', drop: 'descarta', consume: 'consome', group: 'grupo' };
const secs = (ms: number) => (ms / 1000).toFixed(1).replace('.', ',') + ' s';

const tabela: TabDef = {
  id: 'tabela',
  label: 'Tabela de endereços',
  render: (tr, ctx) => {
    const now = ctx.timeAt(ctx.c);
    const rows = tableAt((tr.raw.mac || []) as MacEv[], now).sort((a, b) => a.port - b.port || a.mac.localeCompare(b.mac));
    let h = '<h3>Tabela de endereços MAC do switch (como a mostraria um comando de listagem)</h3>';
    h += '<table class="sc-msgs"><thead><tr><th>Porta</th><th>Endereço MAC</th><th>Quem é</th><th>Tipo</th><th>Última vez visto</th></tr></thead><tbody>';
    h += rows.length
      ? rows.map((r) => '<tr><td>' + r.port + '</td><td>' + r.mac + '</td><td class="meaning">' + esc(who(r.mac)) + '</td><td class="meaning">' + (r.ty === 'secure' ? 'seguro (segurança de porta)' : 'dinâmico') + '</td><td class="meaning">há ' + secs(Math.max(0, now - r.seen)) + '</td></tr>').join('')
      : '<tr><td colspan="5" class="meaning">(tabela vazia)</td></tr>';
    h += '</tbody></table>';
    h += '<p>O switch associa cada endereço de <b>origem</b> à porta por onde o quadro chegou. A cada novo quadro do mesmo endereço, o tempo é renovado; sem tráfego, a entrada expira (padrão de 300 s). Endereços de broadcast e de grupo nunca entram na tabela.</p>';
    return h;
  },
};

const decisoes: TabDef = {
  id: 'decisoes',
  label: 'Decisões',
  render: (tr, ctx) => {
    const now = ctx.timeAt(ctx.c);
    const d = ((tr.raw.dec || []) as Decision[]).filter((x) => x.t <= now);
    let h = '<h3>O que o switch decidiu para cada quadro</h3>';
    h += '<table class="sc-msgs"><thead><tr><th>Quadro</th><th>Entrou na porta</th><th>Destino</th><th>Decisão</th><th>Saiu por</th></tr></thead><tbody>';
    h += d.length
      ? d.map((x) => '<tr><td>' + esc(x.label) + '</td><td>' + x.inPort + '</td><td class="meaning">' + esc(x.dst) + '</td><td class="meaning">' + ACTION[x.action] + '</td><td class="meaning">' + (x.out.length ? x.out.map((p) => 'porta ' + p).join(', ') : 'nenhuma') + '</td></tr>').join('')
      : '<tr><td colspan="5" class="meaning">(nenhum quadro ainda)</td></tr>';
    h += '</tbody></table>';
    h += '<p><b>Encaminha:</b> destino conhecido, uma só porta. <b>Inunda:</b> destino desconhecido, broadcast ou multicast sem snooping: todas as portas, menos a de entrada. <b>Filtra:</b> destino na própria porta de entrada. <b>Consome:</b> endereço reservado, processado e não repassado. <b>Descarta:</b> bloqueado pela segurança de porta.</p>';
    return h;
  },
};

export const tabs: TabDef[] = [tabela, decisoes];
