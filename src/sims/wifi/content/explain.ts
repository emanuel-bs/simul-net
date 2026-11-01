// Texto da aba Experimento e do cabeçalho do cenário.
import type { Trace } from '../../../sim-core';
import type { ScenarioDef } from '../../../sim-core/ui';
import { fmtTime } from '../model';

/** Texto "Configuração do cenário": só o que o cenário define (o restante vem dos padrões). */
export function setup(s: ScenarioDef): string {
  const V = (s.set || {}) as Record<string, any>;
  if (s.sub === 'desc') {
    const parts = [V.scan === 'ativo' ? 'varredura ativa' : 'varredura passiva', V.ssid === 'oculto' ? 'SSID oculto' : 'SSID divulgado', V.sec === 'rsn' ? 'rede protegida (RSN)' : 'rede aberta', 'AP no canal ' + V.ch];
    if (V.res === 'cheio') parts.push('AP lotado (status 17)');
    return parts.join('; ');
  }
  if (s.sub === 'meio') {
    const k = { basico: 'um cliente, transmissão normal', ack: 'ACK perdido', colisao: 'dois clientes sorteiam o mesmo slot', oculto: 'nó oculto (os clientes não se ouvem)' }[V.mkind as 'basico'];
    return k + '; ' + (V.rts ? 'com RTS/CTS' : 'sem RTS/CTS');
  }
  if (s.sub === 'mov') {
    if (V.mov === 'ps') return 'economia de energia; intervalo de escuta de ' + V.lis + (V.lis === 1 ? ' beacon' : ' beacons');
    if (V.mov === 'sticky') return 'cliente que não troca de AP';
    if (V.mov === 'btm') return 'o AP sugere a troca (802.11v)';
    return 'roaming ' + (V.ft ? 'com Fast BSS Transition (802.11r)' : 'comum, com handshake de quatro vias');
  }
  return 'redes nos canais 1 e ' + V.ch2 + ', com ' + V.larg + ' MHz';
}

export function explain(tr: Trace): string {
  const R = tr.raw;
  let h = '<ul>';
  if (R.sub === 'desc') {
    if (R.scan === 'passivo') h += '<li>A varredura foi <b>passiva</b>: o cliente só escutou, canal por canal, até ouvir o beacon do AP. Não transmitiu nada para descobrir a rede.</li>';
    else h += '<li>A varredura foi <b>ativa</b>: o cliente perguntou com um Probe Request em cada canal e recebeu a resposta no canal ' + R.ch + '. Descobriu a rede mais depressa, mas revelou a própria presença.</li>';
    if (R.hidden) h += '<li>O SSID estava oculto, mas bastou o cliente perguntar pelo nome para o AP revelá-lo, <b>em claro</b>. Ocultar o SSID não é segurança.</li>';
    if (R.res === 'cheio') {
      h += '<li><span class="chk-bad">O AP recusou a associação com o Status Code 17</span> (não consegue tratar mais estações). O cliente ficou no <b>estado 2</b>.</li>';
      h += '<li>Lição: um AP pode estar visível e, ainda assim, não aceitar o cliente. É preciso procurar outro AP.</li>';
    } else if (R.res === 'ok-rsn') {
      h += '<li>O cliente passou pelos três estados e <span class="chk-ok">chegou ao estado 3</span> (autenticado e associado, com AID ' + R.aid + ').</li>';
      h += '<li><span class="chk-bad">O primeiro frame de dados foi descartado:</span> numa rede protegida a porta de dados só abre depois do handshake de quatro vias.</li>';
      h += '<li>Lição: associar não é o mesmo que ser autorizado. A autenticação 802.11 de sistema aberto é um ritual, e a proteção real está nas chaves.</li>';
    } else {
      h += '<li>O cliente passou pelos três estados e <span class="chk-ok">chegou ao estado 3</span> (autenticado e associado, com AID ' + R.aid + ').</li>';
      h += '<li>O frame de dados foi aceito e o AP o <span class="chk-ok">encaminhou à rede cabeada</span> como Ethernet.</li>';
      h += '<li>Lição: numa rede aberta, associar é tudo o que se precisa. O tráfego também passa em claro, visível a quem escuta o ar.</li>';
    }
  } else if (R.sub === 'meio') {
    const w = Math.round(R.wasted * 1000);
    if (R.res === 'ok') {
      h += '<li>O cliente esperou o meio livre por um <b>DIFS</b>, fez o <b>backoff</b> de 5 slots e transmitiu. O AP confirmou com o <b>ACK</b> um SIFS depois.</li>';
      h += '<li>A troca inteira, a partir do instante em que o meio ficou livre, durou ' + fmtTime(R.total - 0.2) + ', dos quais só ' + fmtTime(0.25) + ' foram de dados.</li>';
      h += '<li>Lição: boa parte do tempo de ar é espera e confirmação. Por isso a vazão do Wi-Fi fica bem abaixo da taxa anunciada.</li>';
    } else if (R.res === 'ok-ack') {
      h += '<li><span class="chk-bad">O ACK se perdeu</span>, embora o frame tivesse chegado. O cliente esperou o ACKTimeout e <b>dobrou a janela de contenção</b> (15 para 31).</li>';
      h += '<li>A repetição levou o bit Retry e o mesmo número de sequência: o AP <span class="chk-ok">reconheceu a duplicata</span>, confirmou de novo e não entregou o frame duas vezes.</li>';
      h += '<li>Lição: a confiabilidade do Wi-Fi vem da camada de enlace. Cada frame unicast é confirmado e repetido se preciso.</li>';
    } else if (R.res === 'colisao' || R.res === 'colisao-rts') {
      h += '<li><span class="chk-bad">Os dois clientes sortearam o mesmo slot</span> e transmitiram juntos: ' + (R.rts ? 'os dois RTS' : 'os dois frames de dados') + ' se sobrepuseram, e nada foi decodificado.</li>';
      h += '<li>O tempo perdido na colisão foi de <b>' + w + ' µs</b>' + (R.rts ? ' (colidiram dois RTS curtos)' : ' (colidiram dois frames inteiros)') + '.</li>';
      h += '<li>Na segunda rodada, com a janela dobrada, os sorteios diferiram: quem tirou menos transmitiu e o outro <span class="chk-ok">congelou o contador</span> e esperou.</li>';
      h += '<li>Lição: ' + (R.rts ? 'com o RTS/CTS a colisão é barata, ao custo de dois frames a mais em cada transmissão.' : 'o backoff exponencial resolve a disputa, mas cada colisão custa um frame inteiro de ar.') + '</li>';
    } else {
      h += '<li>Os clientes <b>não se ouvem</b>: cada um viu o meio livre e transmitiu. Houve <span class="chk-bad">' + R.collisions + ' colisões</span>, com <b>' + w + ' µs</b> perdidos ' + (R.rts ? '(sempre entre RTS curtos)' : '(sempre entre frames inteiros de dados)') + '.</li>';
      if (R.rts) h += '<li>Depois que um RTS passou, o outro cliente <span class="chk-ok">ouviu o CTS do AP</span> e esperou pelo NAV: a reserva virtual resolveu o que a escuta de portadora não alcança.</li>';
      else h += '<li>Só na terceira rodada, com a janela de 63 slots, a diferença entre os sorteios foi maior que o frame, e a colisão deixou de se repetir.</li>';
      h += '<li>Lição: ' + (R.rts ? 'o RTS/CTS não elimina o nó oculto, mas reduz muito o custo.' : 'o nó oculto desperdiça tempo de ar em frames inteiros. O RTS/CTS, o posicionamento dos APs ou mais APs reduzem o problema.') + '</li>';
    }
  } else if (R.sub === 'mov') {
    const dt = (v: number) => fmtTime(v);
    if (R.res === 'sticky') {
      h += '<li><span class="chk-bad">O cliente não trocou de AP:</span> o AP-02 estava a -58 dBm, e ele seguiu no AP-01 a -80 dBm.</li>';
      h += '<li>A taxa caiu de 54 para 6 Mb/s, e o mesmo frame passou a ocupar o meio <b>' + R.ratio.toFixed(1).replace('.', ',') + ' vezes mais tempo</b>.</li>';
      h += '<li>Lição: o acesso ao meio dá a cada cliente a mesma chance de transmitir, não o mesmo tempo. Um cliente lento reduz a vazão de todos os que compartilham o AP.</li>';
    } else if (R.res === 'ps') {
      const p = R.ps;
      h += '<li>O pacote chegou em ' + dt(p.arrival) + ', com o cliente dormindo. O AP o <b>guardou</b> e marcou o AID 1 no TIM do beacon ' + p.kWake + '.</li>';
      h += '<li>O cliente, que acorda a cada ' + p.L + (p.L === 1 ? ' beacon' : ' beacons') + ', ouviu o beacon ' + p.kWake + ', pediu o frame com um <b>PS-Poll</b> e o recebeu. Latência: <b>' + dt(p.latency) + '</b>.</li>';
      h += '<li>Acordou ' + p.wakes + (p.wakes === 1 ? ' vez' : ' vezes') + ' até a entrega. A aba Energia compara os intervalos de escuta.</li>';
      h += '<li>Lição: dormir mais economiza bateria e aumenta a latência. A escolha depende do que o dispositivo faz.</li>';
    } else {
      const ft = R.res === 'roam-ft';
      h += '<li>O cliente decidiu trocar quando o sinal do AP-01 chegou a -78 dBm' + (R.res === 'roam-btm' ? ', depois que o AP-01 <b>sugeriu</b> a troca por um BTM Request (802.11v)' : '') + '.</li>';
      h += '<li>Procurou o AP-02, autenticou e <b>reassociou</b>, informando o endereço do AP anterior.' + (ft ? ' Com o <b>Fast BSS Transition</b>, as chaves foram derivadas nessa troca e <span class="chk-ok">o handshake de quatro vias não foi necessário</span>.' : ' Depois refez o <b>handshake de quatro vias</b> para ter as chaves do novo AP.') + '</li>';
      h += '<li>A conexão ficou parada por <b>' + dt(R.interrupt) + '</b> neste simulador (na prática a varredura e o handshake somam dezenas de milissegundos ou mais).</li>';
      h += '<li>O AP-02 anunciou o MAC do cliente à rede cabeada para o switch aprender a nova porta.</li>';
      h += '<li>Lição: ' + (ft ? 'o roaming rápido corta justamente o handshake, a parte mais cara da troca.' : 'cada troca de AP é uma pequena desconexão. Para voz e vídeo, usam-se o 802.11r e os APs bem posicionados.') + '</li>';
    }
  } else {
    if (R.res === 'indep') {
      h += '<li>Os canais 1 e ' + R.ch2 + ' <span class="chk-ok">não se sobrepõem</span> com ' + R.larg + ' MHz: as duas redes transmitiram ao mesmo tempo.</li>';
      h += '<li>O tempo total foi de ' + fmtTime(R.total) + ', o de uma só transmissão.</li>';
      h += '<li>Lição: canais independentes dobram a capacidade da região. Em 2,4 GHz, use 1, 6 e 11.</li>';
    } else if (R.res === 'co') {
      h += '<li>Mesmo canal: o Cliente 2 <b>ouviu</b> a outra rede e esperou a vez. Os frames foram em sequência, em ' + fmtTime(R.total) + '.</li>';
      h += '<li>Lição: duas redes no mesmo canal dividem a capacidade, mas continuam funcionando sem corromper uns aos outros.</li>';
    } else {
      h += '<li>Os canais 1 e ' + R.ch2 + ' (' + R.larg + ' MHz) <span class="chk-bad">se sobrepõem</span>: houve ' + R.collisions + ' rodadas de frames corrompidos antes de os sorteios separarem as transmissões.</li>';
      h += '<li>O tempo total foi de ' + fmtTime(R.total) + ', maior que o do mesmo canal.</li>';
      h += '<li>Lição: a sobreposição parcial interfere sem dividir o tempo. Escolha canais iguais ou independentes, nunca intermediários.</li>';
    }
  }
  return h + '</ul>';
}
