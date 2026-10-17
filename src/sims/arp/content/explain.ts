// Texto da aba Experimento e do cabeçalho do cenário.
import { esc, fmtMs, type Trace } from '../../../sim-core';
import type { ScenarioDef } from '../../../sim-core/ui';
import type { ArpParams } from '../engine';
import type { GraParams } from '../gratuito';

/** Texto "Configuração do cenário": só o que o cenário define (o restante vem dos padrões). */
export function setup(s: ScenarioDef): string {
  if (s.sub === 'gra') {
    const G = (s.set || {}) as Partial<GraParams>;
    const g: string[] = [{ announce: 'endereço novo', inuse: 'endereço já em uso por outro host', dispute: 'dois hosts com o mesmo endereço', failover: 'failover de IP' }[G.gkind || 'announce']];
    if (G.gkind === 'announce') g.push(G.gold === false ? 'vizinhos sem entrada antiga' : 'vizinhos com o MAC antigo do endereço');
    if (G.gkind === 'dispute') g.push(G.yield === false ? 'os dois hosts defendem o endereço' : 'o recém-chegado cede');
    if (G.gkind === 'failover') g.push(G.gsend === false ? 'sem ARP gratuito' : 'com ARP gratuito');
    return g.join('; ');
  }
  const P = (s.set || {}) as Partial<ArpParams>;
  const p: string[] = [];
  p.push({ local: 'destino na mesma sub-rede', gateway: 'destino remoto via gateway', direto: 'destino remoto sem gateway (máscara errada)' }[P.dest || 'local']);
  p.push({ empty: 'tabela sem entrada', fresh: 'entrada recente (REACHABLE)', stale: 'entrada antiga (STALE)' }[P.cache || 'empty']);
  if (P.dest === 'direto') p.push('proxy ARP ' + (P.proxy ? 'ligado' : 'desligado'));
  if (P.online === false) p.push('próximo salto desligado');
  if (P.loss) p.push('a primeira requisição se perde');
  return p.join('; ');
}

function explainGra(R: Record<string, any>): string {
  const X = esc(R.X);
  let h = '<ul>';
  if (R.kind === 'announce') {
    h += '<li>O host fez <b>3 ARP Probes</b> (com o IP do remetente zerado) e, sem resposta, <b>2 ARP Announces</b>.</li>';
    h += R.learnedBy.length
      ? '<li>Os vizinhos que guardavam um MAC antigo de <b>' + X + '</b> atualizaram a tabela: ' + R.learnedBy.map((k: string) => ({ b: 'Host B', g: 'Gateway' }[k as 'b' | 'g'])).join(' e ') + '.</li>'
      : '<li>Nenhum vizinho tinha entrada para o endereço, então o Announce <b>não alterou nenhuma tabela</b>.</li>';
  } else if (R.kind === 'inuse') {
    h += '<li><span class="chk-bad">Conflito:</span> o endereço <b>' + X + '</b> já pertence a outro host, que respondeu ao Probe. O host desistiu antes de usá-lo.</li>';
  } else if (R.kind === 'dispute') {
    h += R.result === 'defended'
      ? '<li>O dono defendeu <b>' + X + '</b> com um Announce e o outro host cedeu: o endereço continua com o dono.</li>'
      : '<li><span class="chk-bad">O dono perdeu o endereço:</span> os dois hosts defenderam, e no segundo conflito dentro de 10 s o dono desistiu.</li>';
    h += '<li>Enquanto a disputa durou, a tabela do gateway chegou a apontar para o MAC do host errado.</li>';
  } else {
    h += R.result === 'fast'
      ? '<li>O ARP gratuito atualizou o gateway na hora: o serviço em <b>' + X + '</b> voltou em cerca de um RTT.</li>'
      : '<li><span class="chk-bad">Sem ARP gratuito</span>, o gateway continuou enviando ao MAC do host que caiu, até a entrada expirar e ser revalidada.</li>';
  }
  h += '<li>Tempo total simulado: ' + fmtMs(R.tEnd - R.t0) + '.</li></ul>';
  return h;
}

export function explain(tr: Trace, _P: ArpParams): string {
  const R = tr.raw;
  if (R && R.sub === 'gra') return explainGra(R);
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
