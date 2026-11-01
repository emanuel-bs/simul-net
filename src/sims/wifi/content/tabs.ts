// Abas próprias do simulador de Wi-Fi: estados do cliente, temporização do acesso ao meio, canais e energia.
import { esc } from '../../../sim-core';
import type { TabDef } from '../../../sim-core/ui';
import { psEstimate } from '../engine';
import { ACK_TIMEOUT, BEACON_INTERVAL, CW_MAX, CW_MIN, DIFS, fmtTime, SIFS, SLOT, T_ACK, T_CTS, T_DATA, T_RTS } from '../model';

const ESTADOS: [number, string, string, string][] = [
  [1, 'Não autenticado e não associado', 'classe 1: Beacon, Probe, Authentication, Deauthentication, ACK, RTS e CTS', 'descobrir redes e iniciar a autenticação'],
  [2, 'Autenticado e não associado', 'classes 1 e 2: acrescenta Association e Reassociation, Disassociation', 'pedir a associação a um AP'],
  [3, 'Autenticado e associado', 'classes 1, 2 e 3: acrescenta os quadros de dados e o PS-Poll', 'trocar dados pelo AP'],
];

const estados: TabDef = {
  id: 'estados',
  label: 'Estados',
  subs: ['desc', 'mov'],
  render: (tr, ctx) => {
    const now = ctx.timeAt(ctx.c);
    const log = ((tr.raw.stlog || []) as { t: number; n: number }[]).filter((p) => p.t <= now + 1e-9);
    const cur = log.length ? log[log.length - 1].n : 1;
    let h = '<h3>Os três estados do cliente em relação a um AP</h3>';
    h += '<table class="sc-msgs"><thead><tr><th>Estado</th><th>Nome</th><th>Quadros que o AP aceita</th><th>Serve para</th></tr></thead><tbody>';
    ESTADOS.forEach(([n, name, cls, use]) => {
      h += '<tr' + (n === cur ? ' class="cur"' : '') + '><td>' + n + (n === cur ? ' (agora)' : '') + '</td><td class="meaning">' + esc(name) + '</td><td class="meaning">' + esc(cls) + '</td><td class="meaning">' + esc(use) + '</td></tr>';
    });
    h += '</tbody></table>';
    h += '<p>O cliente tem um estado <b>por AP</b>: ao trocar de AP, ele continua associado ao antigo até o novo aceitar a reassociação. Um quadro que o AP não admite no estado atual do cliente é respondido com um Deauthentication ou um Disassociation.</p>';
    h += '<p>Em redes protegidas há ainda a <b>porta controlada</b>: mesmo no estado 3, os dados só passam depois do handshake de quatro vias, como a porta do 802.1X.</p>';
    if (log.length) {
      h += '<h3>Transições até agora</h3><ul>';
      log.forEach((p) => (h += '<li>' + esc(fmtTime(p.t)) + ': estado ' + p.n + '</li>'));
      h += '</ul>';
    }
    return h;
  },
};

const tempos: TabDef = {
  id: 'tempos',
  label: 'Temporização',
  subs: ['meio', 'canal'],
  render: (tr, ctx) => {
    const now = ctx.timeAt(ctx.c);
    const att = ((tr.raw.attempts || []) as { t: number; who: string; cw: number; bo: number; result: string }[]).filter((a) => a.t <= now + 1e-9);
    let h = '<h3>Intervalos do acesso ao meio (valores do simulador)</h3>';
    h += '<table class="sc-msgs"><thead><tr><th>Intervalo</th><th>Valor</th><th>Papel</th></tr></thead><tbody>';
    const rows: [string, string, string][] = [
      ['Slot', fmtTime(SLOT), 'unidade de contagem do backoff'],
      ['SIFS', fmtTime(SIFS), 'o menor: separa um quadro da resposta imediata (ACK, CTS) sem dar chance a quem disputa'],
      ['DIFS', fmtTime(DIFS), 'SIFS mais dois slots: quanto o meio precisa estar livre antes do backoff'],
      ['ACKTimeout', fmtTime(ACK_TIMEOUT), 'quanto o transmissor espera pelo ACK antes de presumir falha'],
      ['Janela de contenção (CW)', CW_MIN + ' a ' + CW_MAX, 'o backoff sai de 0 a CW; dobra a cada falha (15, 31, 63 até 1023) e volta ao mínimo no sucesso'],
      ['Quadro de dados', fmtTime(T_DATA), '1500 bytes a 54 Mb/s'],
      ['RTS, CTS e ACK', fmtTime(T_RTS) + ', ' + fmtTime(T_CTS) + ' e ' + fmtTime(T_ACK), 'quadros curtos a 6 Mb/s'],
    ];
    rows.forEach((r) => (h += '<tr><td>' + esc(r[0]) + '</td><td class="meaning">' + esc(r[1]) + '</td><td class="meaning">' + esc(r[2]) + '</td></tr>'));
    h += '</tbody></table>';
    h += '<h3>Tentativas de transmissão</h3>';
    if (!att.length) return h + '<p>Nenhuma tentativa até agora. Avance a simulação.</p>';
    h += '<table class="sc-msgs"><thead><tr><th>Instante</th><th>Cliente</th><th>Janela (CW)</th><th>Backoff sorteado</th><th>Resultado</th></tr></thead><tbody>';
    att.forEach((a) => {
      h += '<tr><td>' + esc(fmtTime(a.t)) + '</td><td class="meaning">' + esc(a.who) + '</td><td class="meaning">0 a ' + a.cw + '</td><td class="meaning">' + a.bo + (a.bo === 1 ? ' slot' : ' slots') + ' (' + esc(fmtTime(a.bo * SLOT)) + ')</td><td class="meaning">' + esc(a.result) + '</td></tr>';
    });
    h += '</tbody></table>';
    h += '<p>Os valores seguem o OFDM em 5 GHz (SIFS de 16 µs, slot de 9 µs) em todos os cenários, para manter as proporções. Em 2,4 GHz, o SIFS é de 10 µs e o slot pode ser de 9 ou 20 µs, conforme a compatibilidade com redes 802.11b.</p>';
    return h;
  },
};

const canais: TabDef = {
  id: 'canais',
  label: 'Canais',
  subs: ['desc', 'canal'],
  render: (tr) => {
    const R = tr.raw;
    const mine: number[] = R.sub === 'canal' ? [1, R.ch2] : [R.ch];
    const larg = R.sub === 'canal' ? (R.larg as number) : 20;
    let h = '<h3>Canais da faixa de 2,4 GHz</h3>';
    h += '<table class="sc-msgs"><thead><tr><th>Canal</th><th>Centro (MHz)</th><th>Faixa ocupada com ' + larg + ' MHz (MHz)</th><th>Independente de</th><th>' + (R.sub === 'canal' ? 'Neste cenário' : 'AP') + '</th></tr></thead><tbody>';
    for (let n = 1; n <= 13; n++) {
      const c = 2407 + 5 * n;
      const indep: number[] = [];
      for (let m = 1; m <= 13; m++) if (m !== n && Math.abs(m - n) * 5 >= larg + 5) indep.push(m);
      const tag = R.sub === 'canal' ? (n === 1 ? 'rede 1' : n === R.ch2 ? 'rede 2' : '') : n === R.ch ? 'o AP' : '';
      h += '<tr' + (mine.includes(n) ? ' class="cur"' : '') + '><td>' + n + '</td><td class="meaning">' + c + '</td><td class="meaning">' + (c - larg / 2) + ' a ' + (c + larg / 2) + '</td><td class="meaning">' + (indep.length ? (indep.length > 6 ? indep.slice(0, 3).join(', ') + ' e outros' : indep.join(', ')) : 'nenhum') + '</td><td class="meaning">' + tag + '</td></tr>';
    }
    h += '</tbody></table>';
    h += '<p>Os centros ficam a 5 MHz uns dos outros, mas cada canal ocupa pelo menos ' + larg + ' MHz. Por isso, com 20 MHz, só canais com 5 de distância (1, 6, 11) não se sobrepõem. O canal 14 existe só em alguns países e não consta da tabela. Os canais permitidos variam por país: confira a regulamentação local.</p>';
    return h;
  },
};

const energia: TabDef = {
  id: 'energia',
  label: 'Energia',
  subs: ['mov'],
  render: (tr) => {
    const R = tr.raw;
    if (R.mov !== 'ps') return '<h3>Energia e latência</h3><p>Esta aba compara os intervalos de escuta no modo <b>Economia de energia</b>. Escolha esse cenário para ver a comparação.</p>';
    const arrival = (R.ps as { arrival: number }).arrival;
    let h = '<h3>Intervalo de escuta: energia contra latência</h3>';
    h += '<table class="sc-msgs"><thead><tr><th>Intervalo de escuta</th><th>Acordou até a entrega</th><th>Tempo acordado (estimativa)</th><th>Latência do pacote</th></tr></thead><tbody>';
    [1, 3, 5].forEach((L) => {
      const e = psEstimate(L, arrival);
      h += '<tr' + (L === R.lis ? ' class="cur"' : '') + '><td>' + L + (L === 1 ? ' beacon' : ' beacons') + (L === R.lis ? ' (neste cenário)' : '') + '</td><td class="meaning">' + e.wakes + (e.wakes === 1 ? ' vez' : ' vezes') + '</td><td class="meaning">' + esc(fmtTime(e.awake)) + '</td><td class="meaning">' + esc(fmtTime(e.latency)) + '</td></tr>';
    });
    h += '</tbody></table>';
    h += '<p>O pacote chega em ' + esc(fmtTime(arrival)) + ', entre dois beacons (a cada ' + esc(fmtTime(BEACON_INTERVAL)) + '). O tempo acordado supõe cerca de 2 ms por beacon ouvido, mais o PS-Poll e a entrega: é uma estimativa ilustrativa, e o consumo real depende do aparelho.</p>';
    h += '<p>O <b>DTIM</b> (Delivery TIM) é um TIM especial, com período de vários beacons, depois do qual o AP envia os quadros multicast e broadcast guardados. Quem dorme precisa acordar para os DTIMs se quiser recebê-los. O simulador usa período 1.</p>';
    return h;
  },
};

export const tabs: TabDef[] = [estados, tempos, canais, energia];
