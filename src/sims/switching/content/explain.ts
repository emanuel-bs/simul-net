// Texto da aba Experimento e do cabeçalho do cenário.
import { fmtMs, type Trace } from '../../../sim-core';
import type { ScenarioDef } from '../../../sim-core/ui';
import type { AprParams } from '../engine';
import type { EspParams } from '../especiais';
import type { InuParams } from '../inundacao';
import type { Decision } from '../model';

const n = (d: Decision[], a: Decision['action']) => d.filter((x) => x.action === a).length;

/** Texto "Configuração do cenário": só o que o cenário define (o restante vem dos padrões). */
export function setup(s: ScenarioDef): string {
  if (s.sub === 'inu') {
    const V = (s.set || {}) as Partial<InuParams>;
    if (V.iattack === false) return 'sem ataque; A e B fora da tabela';
    const p: string[] = ['M inunda a tabela (capacidade de ' + (V.icap || 4) + ')', V.ientries === 'present' ? 'A e B já na tabela' : 'A e B fora da tabela'];
    if (V.idefense && V.idefense !== 'none') p.push('segurança de porta: ' + V.idefense);
    return p.join('; ');
  }
  if (s.sub === 'esp') {
    const V = (s.set || {}) as Partial<EspParams>;
    if (V.ekind === 'reserved') return 'quadros para endereços de grupo reservados';
    if (V.ekind === 'mcast') return 'multicast IP; IGMP snooping ' + (V.esnoop ? 'ligado' : 'desligado') + '; ' + (V.ejoin === false ? 'ninguém assinou o grupo' : 'B assinou o grupo');
    return 'broadcast (ARP Request)';
  }
  const V = (s.set || {}) as Partial<AprParams>;
  const p: string[] = [{ first: 'tabela vazia', known: 'tabela com os quatro hosts', bcast: 'tabela vazia; broadcast', filter: 'tabela com os quatro hosts; C e D no mesmo segmento', move: 'B muda da porta 2 para a 4', aging: 'envelhecimento de ' + (V.aging || 300) + ' s' }[V.akind || 'first']];
  if (V.areply === false) p.push('B não responde');
  return p.join('; ');
}

function explainApr(R: Record<string, any>): string {
  const d = R.dec as Decision[];
  let h = '<ul>';
  h += '<li>Quadros recebidos: <b>' + d.length + '</b>; inundados: <b>' + n(d, 'flood') + '</b>; encaminhados por unicast: <b>' + n(d, 'forward') + '</b>; filtrados: <b>' + n(d, 'filter') + '</b>.</li>';
  if (R.kind === 'first') h += R.reply ? '<li>O primeiro quadro foi inundado porque B era desconhecido. Depois da resposta, o switch passou a encaminhar só pela porta 2.</li>' : '<li><span class="chk-bad">B nunca transmitiu</span>, então o switch nunca o aprendeu e inundou todos os quadros para ele.</li>';
  if (R.kind === 'bcast') h += '<li>O broadcast é sempre inundado: não existe entrada para ff:ff:ff:ff:ff:ff. O destino unicast foi aprendido pela resposta.</li>';
  if (R.kind === 'known') h += '<li>Com a tabela preenchida, nenhum quadro foi inundado. Atrás do hub, porém, D ouviu o quadro destinado a C.</li>';
  if (R.kind === 'filter') h += '<li>O quadro de C para D foi <b>filtrado</b>: D o recebeu direto pelo hub, e o switch não o repetiu para A e B.</li>';
  if (R.kind === 'move') h += '<li><span class="chk-bad">O quadro enviado à porta antiga se perdeu:</span> a tabela só foi corrigida quando B transmitiu da porta 4.</li>';
  if (R.kind === 'aging') h += '<li>Depois de ' + R.aging + ' s de silêncio, as entradas expiraram e o quadro seguinte voltou a ser inundado.</li>';
  h += '<li>Tempo total simulado: ' + fmtMs(R.tEnd) + '.</li></ul>';
  return h;
}

function explainInu(R: Record<string, any>): string {
  let h = '<ul>';
  if (!R.attack) h += '<li>Sem ataque, M recebeu <b>' + R.seen + '</b> quadro de A e B (o primeiro, inundado por B ser desconhecido).</li>';
  else {
    h += '<li>M enviou <b>' + R.forged + '</b> quadros forjados' + (R.defense === 'none' ? ', e a tabela terminou ' + (R.full ? '<b>cheia</b>' : 'com vagas') + '.' : '; <b>' + R.accepted + '</b> aceito' + (R.accepted === 1 ? '' : 's') + ' e ' + R.violations + ' violaç' + (R.violations === 1 ? 'ão' : 'ões') + ' de segurança de porta.') + '</li>';
    if (R.defense === 'shutdown') h += '<li><span class="chk-ok">A porta 3 foi desativada</span> na primeira violação, e M perdeu o enlace.</li>';
    if (R.result === 'leak') h += '<li><span class="chk-bad">Vazamento:</span> M recebeu ' + R.seen + ' dos 3 quadros legítimos, porque A e B não puderam ser aprendidos.</li>';
    else if (R.result === 'safe') h += '<li><span class="chk-ok">M não recebeu nenhum quadro legítimo.</span></li>';
    else h += '<li>M recebeu só o primeiro quadro, como aconteceria sem ataque.</li>';
    if (R.entries === 'present' && R.defense === 'none') h += '<li>As entradas de A e B já existiam e não foram apagadas. Se expirarem durante o ataque, o resultado passa a ser o do vazamento.</li>';
  }
  h += '<li>Lição: a tabela de endereços é um recurso finito, e a defesa é limitar quantos MACs cada porta pode ensinar ao switch.</li></ul>';
  return h;
}

function explainEsp(R: Record<string, any>): string {
  const d = R.dec as Decision[];
  let h = '<ul>';
  const names = Array.from(new Set(R.reached as string[])).map((k) => ({ a: 'A', b: 'B', c: 'C', d: 'D', m: 'M' }[k] || k));
  if (R.kind === 'bcast') h += '<li>O broadcast foi inundado e chegou a ' + names.join(', ') + '. A resposta foi unicast.</li>';
  else if (R.kind === 'reserved') h += '<li>Dos três quadros, <b>' + n(d, 'consume') + '</b> foram consumidos pelo switch (não encaminhados) e <b>' + n(d, 'flood') + '</b> foi inundado.</li>';
  else {
    const data = d.filter((x) => x.label.startsWith('Dados'));
    if (R.snoop) h += data.every((x) => x.out.length === 0) ? '<li>Com snooping e sem assinantes, o fluxo não saiu por nenhuma porta.</li>' : '<li>Com snooping, o fluxo foi enviado só às portas com assinantes (' + data[0].out.map((p) => 'porta ' + p).join(', ') + ').</li>';
    else h += '<li><span class="chk-bad">Sem snooping</span>, o fluxo foi inundado e chegou também a ' + names.filter((x) => x !== 'B' || !R.join).join(', ') + ', que não o pediram.</li>';
  }
  h += '<li>Tempo total simulado: ' + fmtMs(R.tEnd) + '.</li></ul>';
  return h;
}

export function explain(tr: Trace, _P: unknown): string {
  const R = tr.raw;
  if (R.sub === 'apr') return explainApr(R);
  if (R.sub === 'inu') return explainInu(R);
  if (R.sub === 'esp') return explainEsp(R);
  return '';
}
