// Abas próprias do DNS: cache do resolvedor, registros das zonas e cadeia de confiança do DNSSEC.
import { esc } from '../../../sim-core';
import type { TabDef } from '../../../sim-core/ui';
import { dnskeyRR, dsRR, type ChainRow } from '../engine';
import { cacheAt } from '../topology';

const cache: TabDef = {
  id: 'cache',
  label: 'Cache',
  subs: ['res', 'sec', 'env'],
  render: (tr, ctx) => {
    const now = ctx.timeAt(ctx.c);
    const es = cacheAt(tr, now);
    let h = '<h3>Cache do resolvedor</h3>';
    if (!es.length) return h + '<p class="meaning">O cache está vazio neste instante. As entradas aparecem conforme as respostas chegam.</p>';
    h += '<table class="sc-msgs"><thead><tr><th>Nome</th><th>Tipo</th><th>Dados</th><th>TTL (s)</th><th>Origem</th></tr></thead><tbody>';
    es.forEach((e) => {
      const cls = e.bad ? 'chk-bad' : e.neg ? 'meaning' : '';
      h += '<tr class="' + cls + '"><td>' + esc(e.n) + '</td><td>' + esc(e.ty) + '</td><td>' + esc(e.d) + '</td><td>' + e.ttl + '</td><td>' + esc(e.src) + (e.bad ? ' (falsa)' : '') + '</td></tr>';
    });
    return h + '</tbody></table><p>O TTL mostrado é o prazo que a entrada tinha ao ser guardada. Entradas "consulta anterior" já estavam no cache antes da simulação; seu TTL é o que restava.</p>';
  },
};

const zonas: TabDef = {
  id: 'zonas',
  label: 'Zonas',
  subs: ['res', 'sec'],
  render: (tr) => {
    const sec = tr.raw.sub === 'sec';
    const rows: [string, string, string, string][] = [
      ['Raiz (.)', 'com', 'NS', 'a.gtld-servers.net (172800 s)'],
      ['.com', 'example.com', 'NS', 'ns1.example.com, ns2.example.com (172800 s)'],
      ['example.com', 'www.example.com', 'A / AAAA', '192.0.2.80 / 2001:db8::80 (300 s)'],
      ['example.com', 'blog.example.com', 'CNAME', 'www.example.com (300 s)'],
      ['example.com', 'example.com', 'MX', '10 mail.example.com (3600 s)'],
      ['example.com', 'example.com', 'TXT', '"v=spf1 ip4:192.0.2.0/24 -all" (3600 s)'],
      ['example.com', 'example.com', 'SOA', 'ns1.example.com, mínimo 3600 s (cache negativo)'],
    ];
    let h = '<h3>Dados de cada zona</h3><table class="sc-msgs"><thead><tr><th>Servidor da zona</th><th>Nome</th><th>Tipo</th><th>Dados</th></tr></thead><tbody>';
    rows.forEach((r) => (h += '<tr><td>' + esc(r[0]) + '</td><td>' + esc(r[1]) + '</td><td>' + esc(r[2]) + '</td><td>' + esc(r[3]) + '</td></tr>'));
    h += '</tbody></table>';
    if (sec) {
      h += '<h3>Registros DNSSEC (valores ilustrativos)</h3><table class="sc-msgs"><thead><tr><th>Zona</th><th>Registro</th><th>Dados</th></tr></thead><tbody>';
      [dsRR('com'), dsRR('example.com'), dnskeyRR('example.com', 'ksk'), dnskeyRR('example.com', 'zsk')].forEach((r) => (h += '<tr><td>' + esc(r.n) + '</td><td>' + r.t + '</td><td>' + esc(r.d) + '</td></tr>'));
      h += '</tbody></table><p>Os valores das chaves e dos resumos são ilustrativos: a simulação não faz criptografia real.</p>';
    }
    return h;
  },
};

const cadeia: TabDef = {
  id: 'cadeia',
  label: 'Cadeia',
  subs: ['sec'],
  render: (tr) => {
    const rows = (tr.raw.chain || []) as ChainRow[];
    const txt: Record<ChainRow['estado'], [string, string]> = { ok: ['chk-ok', 'válido'], falhou: ['chk-bad', 'falhou'], 'sem-ds': ['meaning', 'sem DS'], 'nao-verificado': ['meaning', 'não verificado'] };
    let h = '<h3>Cadeia de confiança</h3><table class="sc-msgs"><thead><tr><th>Elo</th><th>Verificação</th><th>Resultado</th></tr></thead><tbody>';
    rows.forEach((r) => (h += '<tr><td>' + esc(r.zona) + '</td><td>' + esc(r.passo) + '</td><td class="' + txt[r.estado][0] + '">' + txt[r.estado][1] + '</td></tr>'));
    return h + '</tbody></table><p>A validação parte da âncora de confiança (a KSK da raiz) e desce elo por elo. Basta um elo falhar para a resposta ser considerada bogus.</p>';
  },
};

export const tabs: TabDef[] = [cache, zonas, cadeia];
