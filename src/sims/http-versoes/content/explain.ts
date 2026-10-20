// Texto da aba Experimento e do cabeçalho do cenário das versões do HTTP.
import type { Trace } from '../../../sim-core';
import { scenarioParams, type ScenarioDef } from '../../../sim-core/ui';
import { FALLBACK_MS, HOST, VERSION_NAME, VICTIM, type HttpParams, type JournalEntry, type Metrics, type Version } from '../engine';
import { controls } from './controls';

const plural = (n: number, s: string, p: string) => n + ' ' + (n === 1 ? s : p);
const b = (x: string) => '<b>' + x + '</b>';
const ms = (v: number) => (Math.round(v * 10) / 10).toString().replace('.', ',') + ' ms';

/** Texto "Configuração do cenário": o que o cenário define. */
export function setup(s: ScenarioDef): string {
  const P = scenarioParams(controls, s) as unknown as HttpParams;
  const p = ['RTT de ' + P.rtt + ' ms', plural(P.res, 'recurso', 'recursos') + (P.big ? ' e uma imagem grande' : '')];
  if (s.sub === 'h1') p.push(plural(P.conns, 'conexão', 'conexões'), P.tls ? 'com TLS' : 'sem TLS');
  if (s.sub === 'h3') {
    if (P.resume) p.push('retomada com 0-RTT');
    if (P.udpBlocked) p.push('UDP 443 bloqueado');
  }
  if (P.loss) p.push('um pacote de ' + VICTIM + ' se perde');
  return p.join('; ');
}

function step(e: JournalEntry): string {
  switch (e.type) {
    case 'fallback': return 'O QUIC Initial se perdeu (UDP 443 bloqueado). Depois de ' + FALLBACK_MS + ' ms, o navegador recorreu ao ' + b('HTTP/2 sobre TCP') + '.';
    case 'connect': {
      const r = e.rtts === 0 ? 'sem esperar nenhum RTT' : 'depois de ' + e.rtts + ' RTT';
      const how = e.via === 'h3' ? (e.resume ? 'QUIC com 0-RTT' : 'handshake QUIC') : e.tls ? 'TCP e TLS 1.3' : 'TCP';
      return 'A conexão (' + how + ') ficou pronta ' + r + '. O primeiro pedido saiu em ' + ms(e.t) + '.';
    }
    case 'html': return 'O ' + b('index.html') + ' chegou por inteiro. Primeiro byte ' + ms(e.ttfb) + ' depois do pedido.';
    case 'discover': return 'Com o HTML, o navegador descobriu ' + b(plural(e.n, 'subrecurso', 'subrecursos')) + (e.conns > 1 ? ' e abriu mais ' + (e.conns - 1) + ' conexão(ões) para pedi-los em paralelo.' : '.');
    case 'loss': {
      let s = 'Um pacote de ' + b(e.victim) + ' se perdeu. A retransmissão chegou em ' + ms(e.rec) + '. ';
      if (e.held.length) s += 'Como o TCP entrega em ordem, a entrega de ' + e.held.join(' e ') + ' ficou retida junto. ';
      s += e.delayed ? plural(e.delayed, 'recurso foi atrasado', 'recursos foram atrasados') + ' pela perda.' : 'Nenhum recurso foi atrasado: o trecho perdido foi reenviado antes de o recurso terminar.';
      return s;
    }
    case 'done': return b('Página completa') + ': todos os recursos recebidos.';
  }
  return '';
}

function concepts(P: HttpParams, v: Version, eff: Version, j: JournalEntry[]): string {
  const has = (t: string) => j.some((e) => e.type === t);
  const items: string[] = [];
  if (eff === 'h1') {
    items.push('O ' + b('HTTP/1.1') + ' atende um pedido por vez em cada conexão (sem pipelining): o próximo só sai depois da resposta anterior.');
    if (P.conns > 1) items.push('As ' + P.conns + ' conexões paralelas compensam a fila, mas cada uma paga o seu handshake e os cabeçalhos se repetem em texto a cada pedido.');
    if (!P.tls) items.push('Sem TLS, o tráfego é ' + b('texto claro') + ': pode ser lido e alterado por quem está no caminho.');
  }
  if (eff === 'h2') {
    items.push('O ' + b('HTTP/2') + ' usa uma conexão TCP com TLS (ALPN h2) e um ' + b('fluxo') + ' por pedido; as respostas voltam intercaladas em quadros.');
    items.push('O ' + b('HPACK') + ' comprime os cabeçalhos: o primeiro pedido é grande e os seguintes viram índices na tabela dinâmica.');
    items.push('Todos os fluxos compartilham a mesma sequência de bytes do TCP, e por isso uma perda atrasa todos (bloqueio de cabeça de fila do TCP).');
  }
  if (eff === 'h3') {
    items.push('O ' + b('HTTP/3') + ' usa o ' + b('QUIC') + ' sobre UDP: transporte e TLS 1.3 num só handshake (1 RTT), e fluxos com ordem de entrega independente.');
    items.push('O ' + b('QPACK') + ' faz o papel do HPACK sem depender da ordem de chegada dos fluxos.');
    if (P.resume) items.push('Com ' + b('0-RTT') + ', o pedido vai no primeiro pacote. Há risco de replay, então só pedidos que não alteram estado devem ser aceitos.');
  }
  if (v === 'h3' && P.udpBlocked) items.push('O ' + b('fallback') + ' garante que a página carregue mesmo quando a rede bloqueia o QUIC, ao custo da espera.');
  if (has('loss')) items.push(eff === 'h2' ? 'A perda mostra o ' + b('bloqueio de cabeça de fila no TCP') + ': o buraco na sequência de bytes retém todos os fluxos.' : eff === 'h3' ? 'No QUIC, a perda só retém o ' + b('fluxo') + ' cujos dados estavam no pacote perdido.' : 'No HTTP/1.1, a perda só retém a ' + b('conexão') + ' em que ocorreu.');
  return '<ul>' + items.map((t) => '<li>' + t + '</li>').join('') + '</ul>';
}

function next(P: HttpParams, v: Version): string {
  const out: string[] = [];
  if (v !== 'h1') out.push('Passe para o modo <b>HTTP/1.1</b> com os mesmos parâmetros e compare o tempo da página completa.');
  if (v === 'h1' && P.conns > 1) out.push('Escolha <b>1 conexão</b> e veja os pedidos em fila.');
  if (!P.loss) out.push('Marque <b>Perder um pacote de /app.js</b> com RTT de 200 ms e compare quantos fluxos são atrasados em cada versão.');
  if (!P.big) out.push('Marque <b>Incluir uma imagem grande</b>: no HTTP/1.1 ela bloqueia uma conexão; nas outras versões, não.');
  if (P.rtt < 200) out.push('Aumente o RTT para <b>200 ms</b> e observe quanto custa cada ida e volta de abertura.');
  if (v === 'h3' && !P.resume) out.push('Marque <b>Retomar sessão anterior</b> e veja o pedido sair no primeiro pacote.');
  if (v === 'h3' && !P.udpBlocked) out.push('Marque <b>UDP 443 bloqueado</b> e veja o fallback para o HTTP/2.');
  return '<ul>' + out.slice(0, 4).map((t) => '<li>' + t + '</li>').join('') + '</ul>';
}

export function explain(tr: Trace, P: HttpParams): string {
  const R = tr.raw;
  if (!R || !R.journal) return '';
  const j = R.journal as JournalEntry[];
  const v = R.sub as Version;
  const eff = R.eff as Version;
  const m = R.metrics as Metrics;
  const order = ['fallback', 'connect', 'html', 'discover', 'loss', 'done'];
  const steps = j.slice().sort((a, b) => order.indexOf(a.type) - order.indexOf(b.type));
  let h = '<h3>Experimento: carregamento de uma página em ' + VERSION_NAME[v] + '</h3>';
  h += '<p><b>Objetivo.</b> Medir quanto tempo o navegador gasta para carregar ' + b(HOST) + ' e entender o que muda entre o HTTP/1.1 (RFC 9112), o HTTP/2 (RFC 9113) e o HTTP/3 (RFC 9114): como cada versão usa conexões, pedidos em paralelo, compressão de cabeçalhos e recuperação de perdas.</p>';
  h += '<h3>Configuração</h3><p>RTT de <b>' + P.rtt + ' ms</b>, enlace de 10 Mbit/s, ' + plural(R.resources.length, 'recurso', 'recursos') + ' (' + Math.round(m.totalKB) + ' KB no total).' + (v === 'h1' ? ' ' + plural(P.conns, 'conexão paralela', 'conexões paralelas') + (P.tls ? ', com TLS 1.3.' : ', sem TLS.') : '') + '</p>';
  h += '<p>Perda de pacote: ' + (P.loss ? '<b>ativa</b> (um pacote de ' + VICTIM + ' se perde na metade da resposta).' : 'desativada.') + '</p>';
  h += '<h3>O que aconteceu</h3><ol>' + steps.map((e) => '<li>' + ms(e.t) + ': ' + step(e) + '</li>').join('') + '</ol>';
  h += '<h3>Resultados</h3><ul>';
  h += '<li>Viagens de ida e volta antes do primeiro pedido: <b>' + (Math.round(m.rttsBeforeRequest * 10) / 10).toString().replace('.', ',') + '</b>.</li>';
  h += '<li>HTML completo em <b>' + ms(m.tHtml) + '</b>; página completa em <b>' + ms(m.tDone) + '</b>.</li>';
  h += '<li>Conexões abertas: <b>' + m.conns + '</b>. Bytes de cabeçalho enviados e recebidos: <b>' + m.hdrBytes + '</b>' + (eff === 'h1' ? ' (sem compressão).' : ' (comprimidos).') + '</li>';
  if (P.loss) h += '<li>Recursos atrasados pela perda: <b>' + m.delayed + '</b>' + (m.delayed ? ' (atraso somado de ' + ms(m.delayedMs) + ')' : '') + '.</li>';
  h += '</ul>';
  h += '<p class="muted">Valores do modelo didático: largura de banda dividida em partes iguais, sem slow start e com tamanhos de cabeçalho ilustrativos. Servem para comparar as versões, não para prever uma rede real.</p>';
  h += '<h3>Conceitos observados</h3>' + concepts(P, v, eff, j);
  h += '<h3>Para explorar em seguida</h3>' + next(P, v);
  return h;
}
