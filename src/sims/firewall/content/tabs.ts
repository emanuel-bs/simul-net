// Abas próprias do Firewall: a lista de regras (com os usos até o instante mostrado) e a tabela de conexões.
import { esc } from '../../../sim-core';
import type { TabDef } from '../../../sim-core/ui';
import { EXP, connsAt, ruleText, type Hit, type Rule } from '../engine';

const regras: TabDef = {
  id: 'regras',
  label: 'Regras',
  render: (tr, ctx) => {
    const rules = (tr.raw.rules || []) as Rule[];
    if (!tr.raw.P) return '';
    const now = ctx.timeAt(ctx.c);
    const hits = ((tr.raw.hits || []) as Hit[]).filter((h) => h.t <= now + 1e-9);
    const count = (f: (h: Hit) => boolean) => hits.filter(f).length;
    let h = '<h3>Lista de regras (avaliada de cima para baixo; a primeira que casa decide)</h3><table class="sc-msgs"><thead><tr><th>Nº</th><th>Regra</th><th>Permitidos</th><th>Negados</th></tr></thead><tbody>';
    for (const r of rules) {
      h += '<tr><td>' + r.n + '</td><td>' + esc(ruleText(r)) + '</td><td class="meaning">' + count((x) => x.via === 'regra' && x.n === r.n && x.ok) + '</td><td class="meaning">' + count((x) => x.via === 'regra' && x.n === r.n && !x.ok) + '</td></tr>';
    }
    const pol = tr.raw.policy === 'permit' ? 'permitir' : 'negar';
    h += '<tr><td>fim</td><td>política padrão: ' + pol + (pol === 'negar' ? ' (negação implícita)' : '') + '</td><td class="meaning">' + count((x) => x.via === 'politica' && x.ok) + '</td><td class="meaning">' + count((x) => x.via === 'politica' && !x.ok) + '</td></tr>';
    h += '</tbody></table>';
    if (tr.raw.stateful) {
      h += '<h3>Decisões que não passam pela lista</h3><table class="sc-msgs"><thead><tr><th>Mecanismo</th><th>Permitidos</th><th>Negados</th></tr></thead><tbody>';
      h += '<tr><td>Tabela de conexões (pacote de conexão registrada)</td><td class="meaning">' + count((x) => x.via === 'estado') + '</td><td class="meaning">0</td></tr>';
      h += '<tr><td>Fora de estado (não pertence a nenhuma conexão)</td><td class="meaning">0</td><td class="meaning">' + count((x) => x.via === 'invalido') + '</td></tr>';
      h += '<tr><td>Tabela cheia</td><td class="meaning">0</td><td class="meaning">' + count((x) => x.via === 'tabela') + '</td></tr>';
      h += '<tr><td>Limite de taxa</td><td class="meaning">0</td><td class="meaning">' + count((x) => x.via === 'taxa') + '</td></tr>';
      h += '<tr><td>Filtro de origem (BCP 38)</td><td class="meaning">0</td><td class="meaning">' + count((x) => x.via === 'antispoof') + '</td></tr>';
      h += '</tbody></table>';
    }
    h += '<p class="muted">A notação das regras é genérica: não segue a sintaxe de nenhum produto. Uma regra com "origem interna" casa com o endereço de origem do pacote, e uma com "pela interface" casa com o lado por onde ele chegou.</p>';
    return h;
  },
};

const conexoes: TabDef = {
  id: 'conexoes',
  label: 'Conexões',
  subs: ['est', 'dmz', 'def'],
  render: (tr, ctx) => {
    if (!tr.raw.P) return '';
    const es = connsAt(tr, ctx.timeAt(ctx.c));
    let h = '<h3>Tabela de conexões do firewall</h3>';
    if (!es.length) h += '<p class="muted">(vazia)</p>';
    else {
      h += '<table class="sc-msgs"><thead><tr><th>Protocolo</th><th>Origem</th><th>Destino</th><th>Estado</th><th>Prazo sem tráfego</th></tr></thead><tbody>';
      for (const c of es) {
        const prazo = c.proto === 'icmp' ? '10 s' : EXP[c.state] === Infinity ? 'conexão ativa' : EXP[c.state] / 1000 + ' s';
        const port = (p: number) => (c.proto === 'icmp' ? '' : ':' + p);
        h += '<tr><td>' + c.proto.toUpperCase() + '</td><td>' + esc(c.a.ip + port(c.a.port)) + '</td><td>' + esc(c.b.ip + port(c.b.port)) + '</td><td class="meaning">' + c.state + '</td><td class="meaning">' + prazo + '</td></tr>';
      }
      h += '</tbody></table>';
    }
    h += '<p><b>SYN_SENT</b>: viu o pedido de conexão. <b>SYN_RECV</b>: viu a resposta. <b>ESTABLISHED</b>: viu o ACK. <b>FIN_WAIT</b>: viu o primeiro FIN. <b>TIME_WAIT</b>: viu os dois FIN. <b>NEW</b> e <b>REPLIED</b>: UDP e ICMP, sem e com resposta.</p>';
    h += '<p class="muted">Os prazos são ilustrativos: cada produto usa os seus, e eles costumam ser configuráveis.</p>';
    return h;
  },
};

export const tabs: TabDef[] = [regras, conexoes];
