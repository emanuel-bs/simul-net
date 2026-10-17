// Abas próprias do ICMP: Terminal (a saída da ferramenta, no ritmo da simulação), Comando (o que cada parte faz) e Rotas.
import { esc } from '../../../sim-core';
import type { TabDef } from '../../../sim-core/ui';
import { buildLinks, buildNodes, NODE_IDS, routesOf, type IcmpParams, type TermLine, type Tool } from '../engine';
import { explainCommand } from './explain';

const terminal: TabDef = {
  id: 'term',
  label: 'Terminal',
  render: (tr, ctx) => {
    const lines = (tr.raw.term || []) as TermLine[];
    const now = ctx.timeAt(ctx.c);
    const shown = lines.filter((l) => l.t <= now + 1e-9);
    const body = shown.map((l) => '<div' + (l.cls ? ' class="' + l.cls + '"' : '') + '>' + (esc(l.text) || '&nbsp;') + '</div>').join('');
    return '<h3>Terminal do PC-A (10.0.1.10)</h3><pre class="term">' + (body || '<span class="t-dim">(aguardando)</span>') + '</pre><p class="muted">A saída aparece conforme as respostas chegam. Os tempos são simulados.</p>';
  },
};

const comando: TabDef = {
  id: 'cmd',
  label: 'Comando',
  render: (tr) => {
    const R = tr.raw;
    if (!R.P) return '';
    const items = explainCommand(R.tool as Tool, R.P as IcmpParams);
    return '<h3>O que este comando faz</h3><p><code>' + esc(R.line) + '</code></p><ul>' + items.map((x) => '<li><code>' + esc(x[0]) + '</code> ' + x[1] + '</li>').join('') + '</ul>';
  },
};

const rotas: TabDef = {
  id: 'routes',
  label: 'Rotas',
  render: (tr) => {
    const P = tr.raw.P as IcmpParams;
    if (!P) return '';
    const links = buildLinks(P);
    const nodes = buildNodes();
    let h = '<h3>Tabelas de rotas no estado atual da rede</h3><table class="sc-msgs"><thead><tr><th>Nó</th><th>Tipo</th><th>Rede</th><th>Próximo salto</th><th>Interface</th><th>Estado</th></tr></thead><tbody>';
    NODE_IDS.forEach((id) => {
      routesOf(nodes[id], links, { r2lan: P.r2lan }).forEach((r, i) => {
        h += '<tr><td>' + (i === 0 ? '<b>' + id + '</b>' : '') + '</td><td>' + r.type + '</td><td>' + r.net + '/' + r.len + '</td><td>' + (r.via || 'conectada') + '</td><td>' + (r.iface ? r.iface.name : '-') + '</td><td class="meaning">' + (r.active ? 'ativa' : 'inativa (' + esc(r.why) + ')') + '</td></tr>';
      });
    });
    return h + '</tbody></table><p>C: rede conectada. S: rota estática. S*: rota padrão. Uma rota fica inativa quando o enlace cai ou o próximo salto deixa de ser alcançável.</p>';
  },
};

export const tabs: TabDef[] = [terminal, comando, rotas];
