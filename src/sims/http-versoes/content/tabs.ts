// Abas próprias das versões do HTTP: a cascata de recursos e a comparação entre as três versões.
import { esc } from '../../../sim-core';
import type { TabDef } from '../../../sim-core/ui';
import { buildHttp, VERSION_NAME, type HttpParams, type Job, type Metrics, type Version } from '../engine';

const int = (v: number) => Math.round(v).toString();
const dec = (v: number) => (Math.round(v * 10) / 10).toString().replace('.', ',');

function bar(segs: [number, number, string][], total: number, now: number): string {
  const pct = (t: number) => (Math.max(0, Math.min(t, total)) / total) * 100;
  let h = '<div aria-hidden="true" style="position:relative;height:12px;min-width:200px;background:var(--bg-deep);border-radius:2px">';
  segs.forEach(([a, b, color]) => {
    const end = Math.min(b, now);
    if (end <= a) return;
    h += '<span style="position:absolute;top:0;bottom:0;left:' + pct(a).toFixed(2) + '%;width:' + Math.max(0.6, pct(end) - pct(a)).toFixed(2) + '%;background:' + color + '"></span>';
  });
  return h + '</div>';
}

const cascata: TabDef = {
  id: 'cascata',
  label: 'Cascata',
  render: (tr, ctx) => {
    const R = tr.raw;
    const jobs = R.jobs as Job[] | undefined;
    const P = R.P as HttpParams | undefined;
    if (!jobs || !P) return '';
    const now = ctx.timeAt(ctx.c);
    const total = Math.max(R.tDone as number, 1);
    const eff = R.eff as Version;
    const ow = P.rtt / 2;
    let h = '<h3>Cascata de recursos</h3><table class="sc-msgs"><thead><tr><th>Recurso</th><th>Tamanho</th><th>' + (eff === 'h1' ? 'Conexão' : 'Fluxo') + '</th><th>Pedido</th><th>Recebido</th><th>Linha do tempo (0 a ' + int(total) + ' ms)</th></tr></thead><tbody>';
    jobs.slice().sort((a, b) => a.idx - b.idx).forEach((j) => {
      const first = j.start + ow;
      const segs: [number, number, string][] = [[j.reqSend, first, 'var(--muted)'], [first, j.rawArr, 'var(--blue)']];
      if (j.arr > j.rawArr) segs.push([j.rawArr, j.arr, 'var(--red)']);
      const held = j.hold !== 'none' && now >= j.rawArr;
      h += '<tr><td>' + esc(j.res.path) + '</td><td>' + j.res.kb + ' KB</td><td>' + (eff === 'h1' ? j.conn : j.stream) + '</td><td>' + (now >= j.reqSend ? int(j.reqSend) + ' ms' : '-') + '</td><td' + (held ? ' class="chk-bad"' : '') + '>' + (now >= j.arr ? int(j.arr) + ' ms' : '-') + '</td><td>' + bar(segs, total, now) + '</td></tr>';
    });
    return h + '</tbody></table><p>Cinza: pedido a caminho e espera do primeiro byte. Azul: transferência da resposta. Vermelho: bytes já recebidos, mas retidos até a retransmissão do trecho perdido.</p>';
  },
};

const cache = new Map<string, Record<Version, Metrics>>();
function metricsOf(P: HttpParams): Record<Version, Metrics> {
  const key = JSON.stringify(P);
  let m = cache.get(key);
  if (!m) {
    if (cache.size > 40) cache.clear();
    m = { h1: buildHttp(P, 'h1').raw.metrics, h2: buildHttp(P, 'h2').raw.metrics, h3: buildHttp(P, 'h3').raw.metrics };
    cache.set(key, m);
  }
  return m;
}

const comparacao: TabDef = {
  id: 'comparacao',
  label: 'Comparação',
  render: (tr) => {
    const P = tr.raw.P as HttpParams | undefined;
    if (!P) return '';
    const cur = tr.raw.sub as Version;
    const M = metricsOf(P);
    const slowest = Math.max(M.h1.tDone, M.h2.tDone, M.h3.tDone, 1);
    let h = '<h3>As três versões, com os mesmos parâmetros</h3><table class="sc-msgs"><thead><tr><th>Versão</th><th>RTT até o 1º pedido</th><th>HTML pronto</th><th>Página completa</th><th>Conexões</th><th>Bytes de cabeçalho</th><th>Recursos atrasados pela perda</th></tr></thead><tbody>';
    (['h1', 'h2', 'h3'] as Version[]).forEach((v) => {
      const m = M[v];
      const name = VERSION_NAME[v] + (v === 'h3' && P.udpBlocked ? ' (recorre ao HTTP/2)' : '');
      h += '<tr><td>' + (v === cur ? '<b>' + name + '</b> (modo atual)' : name) + '</td><td>' + dec(m.rttsBeforeRequest) + '</td><td>' + int(m.tHtml) + ' ms</td><td>' + int(m.tDone) + ' ms' + bar([[0, m.tDone, v === cur ? 'var(--amber)' : 'var(--blue)']], slowest, Infinity) + '</td><td>' + m.conns + '</td><td>' + m.hdrBytes + '</td><td>' + (P.loss ? m.delayed + (m.delayed ? ' (' + int(m.delayedMs) + ' ms)' : '') : '-') + '</td></tr>';
    });
    h += '</tbody></table>';
    h += '<p>O HTTP/1.1 usa ' + P.conns + (P.conns === 1 ? ' conexão' : ' conexões') + (P.tls ? ' com TLS' : ' sem TLS') + ', como configurado no painel do modo HTTP/1.1. O HTTP/3 ' + (P.resume ? 'retoma uma sessão (0-RTT)' : 'faz o handshake completo') + (P.udpBlocked ? ' e encontra o UDP 443 bloqueado' : '') + '.</p>';
    h += '<p class="muted">Modelo didático: banda dividida em partes iguais, sem slow start, cabeçalhos com tamanhos ilustrativos. Compare as diferenças entre as versões, não os valores absolutos.</p>';
    return h;
  },
};

export const tabs: TabDef[] = [cascata, comparacao];
