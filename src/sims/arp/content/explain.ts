// Texto da aba Experimento e do cabeçalho do cenário.
import { esc, fmtMs, type Trace } from '../../../sim-core';
import type { ScenarioDef } from '../../../sim-core/ui';
import type { ArpParams } from '../engine';

/** Texto "Configuração do cenário": só o que o cenário define (o restante vem dos padrões). */
export function setup(s: ScenarioDef): string {
  const P = (s.set || {}) as Partial<ArpParams>;
  const p: string[] = [];
  p.push({ local: 'destino na mesma sub-rede', gateway: 'destino remoto via gateway', direto: 'destino remoto sem gateway (máscara errada)' }[P.dest || 'local']);
  p.push({ empty: 'tabela sem entrada', fresh: 'entrada recente (REACHABLE)', stale: 'entrada antiga (STALE)' }[P.cache || 'empty']);
  if (P.dest === 'direto') p.push('proxy ARP ' + (P.proxy ? 'ligado' : 'desligado'));
  if (P.online === false) p.push('próximo salto desligado');
  if (P.loss) p.push('a primeira requisição se perde');
  return p.join('; ');
}

export function explain(tr: Trace, _P: ArpParams): string {
  const R = tr.raw;
  if (!R || R.sub !== 'res') return '';
  let h = '<ul>';
  if (R.cacheHit) h += '<li>Acerto na tabela: o MAC de <b>' + esc(R.askIp) + '</b> já era conhecido, e nenhuma mensagem ARP foi enviada.</li>';
  else if (R.stale && R.result !== 'failed') h += '<li>A entrada antiga foi confirmada por uma requisição <b>unicast</b>, sem broadcast.</li>';
  else if (R.result !== 'failed') h += '<li>O ARP perguntou por <b>' + esc(R.askIp) + '</b>' + (R.askIp !== R.dstIp ? ' (o gateway), e não pelo destino ' + esc(R.dstIp) + ',' : '') + ' e recebeu o MAC <b>' + esc(R.nhMac) + '</b>' + (R.tries > 1 ? ' na tentativa ' + R.tries + ' de 3' : '') + '.</li>';
  if (R.proxyMode && R.result !== 'failed') h += '<li><b>Proxy ARP:</b> o roteador respondeu com o próprio MAC no lugar do destino remoto.</li>';
  if (R.result === 'failed') h += '<li><span class="chk-bad">A resolução falhou</span> depois de 3 tentativas: o pacote IP foi descartado e o próprio sistema de A informou "Destination Host Unreachable".</li>';
  else if (R.result === 'noreply') h += '<li><span class="chk-bad">O ping ficou sem resposta:</span> a tabela ARP ainda guardava o MAC de um host que já não responde.</li>';
  else h += '<li>O ping foi respondido em ' + fmtMs(R.tEnd - R.t0) + ' no total (incluindo a resolução).</li>';
  if (R.learned) h += '<li>Quem respondeu <b>aprendeu o MAC de A</b> pela própria requisição, e por isso não precisou perguntar de volta.</li>';
  h += '</ul>';
  return h;
}
