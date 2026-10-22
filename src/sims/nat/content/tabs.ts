// Abas próprias do NAT: a tabela de traduções e a ocupação de portas e endereços, no instante mostrado.
import { esc } from '../../../sim-core';
import type { TabDef } from '../../../sim-core/ui';
import { epText, fmtTime, PROTO_NAME, type DevInfo, type Entry, type NatParams } from '../engine';
import { entriesAt } from '../topology';

const KIND: Record<Entry['kind'], string> = {
  estatico: 'Basic NAT estático',
  dinamico: 'Basic NAT dinâmico',
  napt: 'NAPT',
  dnat: 'DNAT',
  hairpin: 'DNAT + SNAT',
  outro: 'Outro assinante',
};

const bar = (used: number, size: number) => {
  const n = Math.max(used > 0 ? 1 : 0, Math.round((10 * used) / Math.max(1, size)));
  return '<span aria-hidden="true">' + '█'.repeat(n) + '░'.repeat(10 - n) + '</span> ';
};

const tabela: TabDef = {
  id: 'tabela',
  label: 'Tabela NAT',
  render: (tr, ctx) => {
    const devs = (tr.raw.devs || []) as DevInfo[];
    if (!devs.length) return '';
    const now = ctx.timeAt(ctx.c);
    let h = '';
    devs.forEach((d) => {
      const es = entriesAt(tr, d.key, now);
      h += '<h3>Tabela de traduções de ' + esc(d.name) + '</h3>';
      if (d.rules.length) h += '<p>Regras configuradas: ' + d.rules.map(esc).join('; ') + '.</p>';
      h += '<table class="sc-msgs"><thead><tr><th>Tipo</th><th>Proto.</th><th>Interno</th><th>Externo</th><th>Remoto</th><th>Expira em</th><th>Observação</th></tr></thead><tbody>';
      if (!es.length) h += '<tr><td colspan="7" class="meaning">tabela vazia neste instante</td></tr>';
      es.forEach((e) => {
        const basic = e.kind === 'estatico' || e.kind === 'dinamico';
        const rem = e.remIp ? epText({ ip: e.remIp, port: e.remPort }) : '-';
        const left = e.perm ? 'permanente' : fmtTime(Math.max(0, e.last + d.timeout - now));
        h += '<tr><td>' + KIND[e.kind] + '</td><td>' + (e.proto === 'any' ? 'qualquer' : PROTO_NAME[e.proto]) + '</td><td>' + esc(basic ? e.intIp : epText({ ip: e.intIp, port: e.intPort })) + '</td><td>' + esc(basic ? e.extIp : epText({ ip: e.extIp, port: e.extPort })) + '</td><td>' + esc(rem) + '</td><td>' + left + '</td><td class="meaning">' + esc(e.obs || '') + '</td></tr>';
      });
      h += '</tbody></table>';
    });
    return h + '<p>Interno: endereço e porta (ou identificador ICMP) de quem iniciou. Externo: o que o servidor enxerga. Remoto: o outro extremo da conexão. A entrada some quando o tempo de inatividade termina.</p>';
  },
};

const portas: TabDef = {
  id: 'portas',
  label: 'Portas',
  subs: ['snat', 'limites'],
  render: (tr, ctx) => {
    const devs = (tr.raw.devs || []) as DevInfo[];
    const P = tr.raw.P as NatParams | undefined;
    if (!devs.length || !P) return '';
    const now = ctx.timeAt(ctx.c);
    let h = '<h3>Ocupação de endereços e portas</h3>';
    devs.forEach((d) => {
      const es = entriesAt(tr, d.key, now);
      h += '<h4>' + esc(d.name) + ' (' + d.inIp + ' interno, ' + d.outIp + ' externo)</h4>';
      if (d.tipo === 'estatico') {
        h += '<p>Basic NAT estático: nenhuma porta é consumida. Cada host usa um endereço público fixo, então o número de hosts é limitado pelo número de endereços (' + es.length + ' em uso neste instante).</p>';
        return;
      }
      if (d.tipo === 'dinamico') {
        const used = es.filter((e) => e.kind === 'dinamico').map((e) => e.extIp);
        h += '<p>' + bar(used.length, d.pool.length) + '<b>' + used.length + ' de ' + d.pool.length + '</b> endereços do pool em uso. O Basic NAT dinâmico não consome portas.</p><ul>';
        d.pool.forEach((a) => {
          const e = es.find((x) => x.kind === 'dinamico' && x.extIp === a);
          h += '<li>' + esc(a) + ': ' + (e ? 'em uso por ' + esc(e.intIp) : 'livre') + '</li>';
        });
        h += '</ul>';
        return;
      }
      const size = d.max - d.min + 1;
      const groups = new Map<string, Set<number>>();
      es.filter((e) => (e.kind === 'napt' || e.kind === 'outro') && e.extPort !== undefined).forEach((e) => {
        const k = e.proto === 'any' ? '' : PROTO_NAME[e.proto];
        if (!groups.has(k)) groups.set(k, new Set());
        groups.get(k)!.add(e.extPort as number);
      });
      const espOnly = es.filter((e) => e.proto === 'esp');
      if (!groups.size) h += '<p>' + (espOnly.length ? 'O ESP não usa portas: ' + espOnly.length + ' entrada(s) só com endereços.' : 'Nenhuma porta em uso neste instante.') + ' Intervalo disponível: ' + d.min + ' a ' + d.max + ' (' + size + ' portas por endereço e protocolo).</p>';
      groups.forEach((set, proto) => {
        const list = Array.from(set).sort((a, b) => a - b);
        h += '<p>' + bar(list.length, size) + '<b>' + proto + ' em ' + esc(d.outIp) + ':</b> ' + list.length + ' de ' + size + ' portas em uso (intervalo ' + d.min + ' a ' + d.max + '): ' + list.join(', ') + '.</p>';
      });
    });
    return h + '<p>Quando as portas acabam, novas conexões não conseguem entrada na tabela e são descartadas.</p>';
  },
};

export const tabs: TabDef[] = [tabela, portas];
