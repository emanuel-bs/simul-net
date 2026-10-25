// Texto da aba Experimento e do cabeçalho do cenário.
import { fmtMs, type Trace } from '../../../sim-core';
import type { ScenarioDef } from '../../../sim-core/ui';
import { sec } from '../stp';

const NAME: Record<number, string> = { 1: 'SW1', 2: 'SW2', 3: 'SW3', 4: 'o switch intruso' };
const dur = (ms: number) => (ms >= 1000 ? sec(ms) : fmtMs(ms));

/** Texto "Configuração do cenário": só o que o cenário define (o restante vem dos padrões). */
export function setup(s: ScenarioDef): string {
  const V = (s.set || {}) as Record<string, any>;
  if (s.sub === 'mstp') return V.mmode === 'one' ? 'todas as VLANs no CIST' : 'VLAN 10 na MSTI 1 (raiz SW1) e VLAN 20 na MSTI 2 (raiz SW3)';
  if (s.sub === 'laco') return 'spanning tree ' + (V.lmode === 'stp' ? 'ligado' : 'desligado');
  if (s.sub === 'prot') return 'intruso de prioridade 0 na porta de acesso do SW1; ' + ({ none: 'sem proteção', bpdu: 'BPDU Guard', root: 'Root Guard' }[V.pguard as 'none'] || 'sem proteção');
  const p: string[] = [V.root === 'sw1' ? 'SW1 com prioridade 4096' : V.root === 'sw3' ? 'SW3 com prioridade 4096' : 'todas as pontes com a prioridade padrão'];
  if (V.l13 === '100m') p.push('enlace SW1-SW3 de 100 Mb/s');
  if (V.fail === 'link') p.push('o enlace SW2-SW3 cai');
  if (V.fail === 'root') p.push('a ponte raiz é desligada');
  if (V.rlegacy) p.push('SW3 só fala STP');
  return p.join('; ');
}

function explainTree(R: Record<string, any>): string {
  const rstp = R.sub === 'rstp';
  let h = '<ul>';
  h += '<li>Raiz eleita: <b>' + NAME[R.root0] + '</b>. A rede ' + (rstp ? 'passou a encaminhar' : 'só encaminhou') + ' depois de <b>' + dur(R.conv) + '</b>' + (rstp ? '' : ' (Escuta e Aprendizado de 15 s cada)') + '.</li>';
  if (R.fail === 'none') {
    h += rstp ? '<li>A convergência foi por proposta e acordo entre vizinhos, e não por temporizadores.</li>' : '<li>Durante esses 30 s, as portas não encaminharam dados: só BPDUs circularam.</li>';
    if (R.legacy) h += '<li><span class="chk-bad">Os enlaces com a ponte STP usaram os temporizadores</span> e levaram 30 s; os demais convergiram por proposta e acordo.</li>';
  } else if (!R.changed) {
    h += '<li><span class="chk-ok">A falha não mudou nenhum papel de porta:</span> o enlace perdido estava bloqueado, e o tráfego não foi interrompido.</li>';
  } else {
    if (R.fail === 'root') h += '<li>Com a raiz fora, as pontes elegeram <b>' + NAME[R.root1] + '</b>.</li>';
    h += R.reconv >= 1000 || !rstp ? '<li><span class="chk-bad">A reconvergência levou ' + dur(R.reconv) + '</span>, tempo em que ' + (R.slow === 1 ? 'uma porta' : R.slow + ' portas') + ' não encaminhou.</li>' : '<li><span class="chk-ok">Reconvergência em ' + (R.reconvTxt || dur(R.reconv)) + '</span>: a porta alternativa ou o acordo evitaram os temporizadores.</li>';
    if (rstp && R.reconv >= 1000) h += '<li>O tempo é o dos temporizadores do STP nos enlaces com a ponte que não fala RSTP.</li>';
  }
  h += '<li>Lição: ' + (rstp ? 'o RSTP troca os temporizadores por acordo entre vizinhos, mas depende de todas as pontes falarem.' : 'o STP é seguro, mas lento: toda porta que sai do bloqueio leva 30 s.') + '</li></ul>';
  return h;
}

function explainMstp(R: Record<string, any>): string {
  const inst = R.inst as { id: number; name: string; vlans: string; root: number; roles: { link: string; role: string; br: number }[] }[];
  let h = '<ul>';
  inst.forEach((i) => {
    const blocked = Array.from(new Set(i.roles.filter((r) => r.role === 'alternate').map((r) => 'SW1-SW2,SW2-SW3,SW1-SW3'.split(',')[['L12', 'L23', 'L13'].indexOf(r.link)])));
    h += '<li><b>' + i.name + '</b> (' + i.vlans + '): raiz ' + NAME[i.root] + '; enlace bloqueado: ' + (blocked.join(', ') || 'nenhum') + '.</li>';
  });
  h += R.mmode === 'two' ? '<li><span class="chk-ok">O tráfego se divide:</span> cada enlace é usado por pelo menos uma VLAN.</li>' : '<li>Uma só árvore: o enlace bloqueado fica ocioso para todas as VLANs, como no RSTP.</li>';
  h += '<li>Lição: o ganho do MSTP está no mapa de VLANs; sem mais de uma instância, ele equivale ao RSTP.</li></ul>';
  return h;
}

function explainLaco(R: Record<string, any>): string {
  let h = '<ul>';
  if (R.stp) {
    h += '<li><span class="chk-ok">O laço foi cortado:</span> uma cópia foi descartada em porta bloqueada, e B recebeu o broadcast <b>' + R.dupB + '</b> vez(es).</li>';
  } else {
    h += '<li><span class="chk-bad">Tempestade de broadcast:</span> em ' + R.rounds + ' rodadas, B recebeu <b>' + R.dupB + '</b> cópias, A recebeu <b>' + R.dupA + '</b> do próprio quadro, e <b>' + (R.copies[R.copies.length - 1] || 0) + '</b> cópias continuavam em circulação.</li>';
    h += '<li>O MAC de A mudou de porta no SW1 <b>' + R.flaps + '</b> vez(es): a tabela MAC fica instável.</li>';
  }
  h += '<li>Lição: sem TTL e sem spanning tree, um único quadro pode derrubar uma rede local.</li></ul>';
  return h;
}

function explainProt(R: Record<string, any>): string {
  let h = '<ul>';
  if (R.result === 'isolated') h += '<li><span class="chk-ok">O BPDU Guard isolou o intruso:</span> a porta foi desativada e a raiz continuou sendo ' + NAME[R.root0] + '.</li>';
  else if (R.result === 'contained') h += '<li><span class="chk-ok">O Root Guard conteve o anúncio:</span> a porta ficou em root-inconsistente e a raiz continuou sendo ' + NAME[R.root0] + '.</li>';
  else {
    h += '<li><span class="chk-bad">O intruso virou a raiz.</span> A raiz deixou de ser ' + NAME[R.root0] + ', e ' + R.changed + ' portas mudaram de papel.</li>';
    h += '<li>O SW3 ficou <b>' + sec(R.outage) + '</b> sem encaminhar enquanto reabria o enlace que estava bloqueado.</li>';
  }
  h += '<li>Lição: o spanning tree não autentica BPDUs, então a proteção vem das portas: BPDU Guard nas de acesso e Root Guard nas de borda.</li></ul>';
  return h;
}

export function explain(tr: Trace): string {
  const R = tr.raw;
  if (R.sub === 'stp' || R.sub === 'rstp') return explainTree(R);
  if (R.sub === 'mstp') return explainMstp(R);
  if (R.sub === 'laco') return explainLaco(R);
  if (R.sub === 'prot') return explainProt(R);
  return '';
}
