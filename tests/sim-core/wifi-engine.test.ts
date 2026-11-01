// Regras do motor de Wi-Fi (IEEE 802.11): os três estados do cliente, descoberta, CSMA/CA com backoff e ACK, colisões, nó oculto,
// RTS/CTS, roaming, economia de energia e canais.
import { describe, expect, it } from 'vitest';
import { scenarioParams, type Params } from '../../src/sim-core/ui';
import { controls } from '../../src/sims/wifi/content/controls';
import { scenarios } from '../../src/sims/wifi/content/scenarios';
import { canalRel, psEstimate, dataTime } from '../../src/sims/wifi/engine';
import { ACK_TIMEOUT, DIFS, SIFS, SLOT, T_DATA } from '../../src/sims/wifi/model';
import { wifiProtocol } from '../../src/sims/wifi/protocol';

const run = (id: string, over: Params = {}) => {
  const s = scenarios.find((x) => x.id === id)!;
  return wifiProtocol.build({ ...scenarioParams(controls, s), ...over }, s.sub);
};
type T = ReturnType<typeof run>;
const labels = (tr: T) => tr.msgs.map((m) => m.label as string);
const field = (m: T['msgs'][number], name: string) => (m.fields.find((f) => Array.isArray(f) && f[0] === name) as string[] | undefined)?.[1];
const states = (tr: T) => (tr.raw.stlog as { n: number }[]).map((p) => p.n);

describe('descoberta e associação', () => {
  it('varredura passiva: o cliente passa pelos estados 1, 2 e 3, e o beacon é o primeiro frame', () => {
    const tr = run('d-passivo');
    expect(states(tr)).toEqual([1, 2, 3]);
    expect(tr.msgs[0].label).toBe('Beacon');
    expect(tr.msgs[0].fields.some((f) => Array.isArray(f) && f[0] === 'Subtipo' && String(f[1]).startsWith('Beacon'))).toBe(true);
    expect(tr.raw.res).toBe('ok-aberta');
    expect(labels(tr)).toContain('DHCPDISCOVER (Ethernet)');
  });

  it('cada frame unicast de gerência e de dados é seguido de um ACK; o beacon e o Probe Request não', () => {
    const tr = run('d-ativo');
    const l = labels(tr);
    expect(l[0]).toBe('Probe Request');
    expect(l[1]).toBe('Probe Response');
    expect(l[2]).toBe('ACK');
    expect(l.indexOf('Authentication (1)') + 1).toBe(l.indexOf('ACK', l.indexOf('Authentication (1)')));
    expect(l.filter((x) => x === 'ACK').length).toBe(1 + 2 + 2 + 1);
  });

  it('SSID oculto: o beacon traz o nome vazio e o nome só aparece no Probe Request dirigido', () => {
    const tr = run('d-oculta');
    expect(field(tr.msgs[0], 'SSID (IE 0)')).toContain('comprimento 0');
    const directed = tr.msgs.find((m) => m.label === 'Probe Request (SSID LabRedes)')!;
    expect(field(directed, 'SSID (IE 0)')).toBe('LabRedes');
    expect(labels(tr)).toContain('Probe Response');
  });

  it('varredura ativa com SSID oculto: o pedido curinga fica sem resposta', () => {
    const tr = run('d-oculta', { scan: 'ativo' });
    const l = labels(tr);
    expect(l[0]).toBe('Probe Request');
    expect(l[1]).toBe('Probe Request (SSID LabRedes)');
  });

  it('a varredura percorre os canais até o do AP', () => {
    const t1 = run('d-passivo', { ch: 1 });
    const t11 = run('d-passivo', { ch: 11 });
    expect(t11.msgs[0].tSend).toBeGreaterThan(t1.msgs[0].tSend + 200);
  });

  it('rede protegida: o RSN é anunciado e o primeiro frame de dados é descartado', () => {
    const tr = run('d-rsn');
    expect(field(tr.msgs[0], 'RSN (IE 48)')).toBeDefined();
    expect(tr.raw.res).toBe('ok-rsn');
    expect(labels(tr)).not.toContain('DHCPDISCOVER (Ethernet)');
    expect(states(tr)).toEqual([1, 2, 3]);
  });

  it('AP lotado: o status é 17, sem AID, e o cliente fica no estado 2', () => {
    const tr = run('d-cheio');
    const resp = tr.msgs.find((m) => String(m.label).startsWith('Association Response'))!;
    expect(field(resp, 'Status Code')).toBe('17');
    expect(field(resp, 'Association ID (AID)')).toContain('não atribuído');
    expect(states(tr)).toEqual([1, 2]);
    expect(tr.raw.res).toBe('cheio');
  });
});

describe('acesso ao meio (CSMA/CA)', () => {
  it('transmissão normal: espera o DIFS, conta o backoff e recebe o ACK um SIFS depois', () => {
    const tr = run('m-basico');
    const data = tr.msgs.find((m) => m.label === 'Dados')!;
    expect(data.tSend).toBeCloseTo(0.2 + DIFS + 5 * SLOT, 9);
    const ack = tr.msgs.find((m) => m.label === 'ACK')!;
    expect(ack.tSend).toBeCloseTo(data.tArr + SIFS, 9);
    expect(ack.tSend - data.tArr).toBeLessThan(DIFS);
    expect(tr.raw.res).toBe('ok');
  });

  it('ACK perdido: espera o ACKTimeout, dobra a janela e repete com Retry=1 e o mesmo número de sequência', () => {
    const tr = run('m-ack');
    const datas = tr.msgs.filter((m) => String(m.label).startsWith('Dados'));
    expect(datas.length).toBe(2);
    expect(tr.msgs.find((m) => m.label === 'ACK' && m.lost)).toBeDefined();
    const seq = (m: T['msgs'][number]) => field(m, 'Sequence Control');
    expect(seq(datas[0])).toBe(seq(datas[1]));
    expect((datas[1].fields.find((f) => Array.isArray(f) && f[0] === 'Flags') as string[])[1]).toContain('Retry=1');
    expect(datas[1].tSend).toBeGreaterThanOrEqual(datas[0].tArr + ACK_TIMEOUT + DIFS);
    const att = tr.raw.attempts as { cw: number }[];
    expect(att.map((a) => a.cw)).toEqual([15, 31]);
  });

  it('mesmo slot: os dois frames colidem, a janela dobra e na rodada seguinte um passa na frente do outro', () => {
    const tr = run('m-colisao');
    const lost = tr.msgs.filter((m) => m.lost);
    expect(lost.length).toBe(2);
    expect(lost[0].tSend).toBe(lost[1].tSend);
    expect(tr.raw.collisions).toBe(1);
    const ok = tr.msgs.filter((m) => m.label === 'Dados');
    expect(ok.map((m) => m.from)).toEqual(['a', 'c']);
    expect(ok[1].tSend).toBeGreaterThan(ok[0].tArr);
  });

  it('o backoff do cliente congelado continua de onde parou: faltam (17 - 4) slots depois do DIFS', () => {
    const tr = run('m-colisao');
    const ack = tr.msgs.filter((m) => m.label === 'ACK')[0];
    const c = tr.msgs.filter((m) => m.label === 'Dados')[1];
    expect(c.tSend).toBeCloseTo(ack.tArr + DIFS + 13 * SLOT, 9);
  });

  it('com RTS/CTS a colisão é entre RTS e custa menos tempo de ar', () => {
    const sem = run('m-colisao');
    const com = run('m-colisao-rts');
    expect(com.msgs.filter((m) => m.lost).every((m) => String(m.label).startsWith('RTS'))).toBe(true);
    expect(com.raw.wasted).toBeLessThan(sem.raw.wasted);
    const l = labels(com);
    expect(l.indexOf('CTS')).toBeGreaterThan(l.indexOf('RTS'));
    expect(l.indexOf('Dados')).toBeGreaterThan(l.indexOf('CTS'));
  });

  it('nó oculto sem RTS/CTS: colisões repetidas de frames inteiros, e só depois um passa', () => {
    const tr = run('m-oculto');
    expect(tr.raw.collisions).toBe(2);
    expect(tr.raw.hidden).toBe(true);
    const att = tr.raw.attempts as { cw: number }[];
    expect(att.map((a) => a.cw)).toEqual([15, 15, 31, 31, 63, 63]);
    expect(tr.raw.wasted).toBeGreaterThan(2 * T_DATA);
  });

  it('nó oculto com RTS/CTS: o outro cliente ouve o CTS do AP e ajusta o NAV, e as colisões são só de RTS', () => {
    const sem = run('m-oculto');
    const com = run('m-oculto-rts');
    expect(com.msgs.filter((m) => m.lost).every((m) => String(m.label).startsWith('RTS'))).toBe(true);
    expect(com.raw.wasted).toBeLessThan(sem.raw.wasted);
    expect((com.raw.navs as { who: string }[]).some((n) => n.who === 'c')).toBe(true);
    expect(com.events.some((e) => e.who === 'c' && e.text.includes('CTS do AP'))).toBe(true);
  });

  it('o Duration/ID do RTS reserva a troca inteira', () => {
    const tr = run('m-colisao-rts');
    const rts = tr.msgs.find((m) => m.label === 'RTS')!;
    expect(Number(field(rts, 'Duration/ID'))).toBe(386);
    const cts = tr.msgs.find((m) => m.label === 'CTS')!;
    expect(Number(field(cts, 'Duration/ID'))).toBe(326);
  });
});

describe('roaming e economia de energia', () => {
  it('roaming: reassociação com o endereço do AP anterior, handshake de quatro vias e tráfego pelo novo AP', () => {
    const tr = run('r-roam');
    const re = tr.msgs.find((m) => m.label === 'Reassociation Request')!;
    expect(field(re, 'Current AP Address')).toBe('00:00:5e:00:53:a1');
    expect(tr.msgs.filter((m) => String(m.label).startsWith('EAPOL-Key')).length).toBe(4);
    expect(labels(tr)).toContain('Anúncio do MAC do cliente');
    const last = tr.msgs.filter((m) => String(m.label).startsWith('Dados'));
    expect(last[last.length - 1].to).toBe('ap2');
    expect(tr.raw.res).toBe('roam');
  });

  it('o Fast BSS Transition elimina o handshake e encurta a interrupção', () => {
    const std = run('r-roam');
    const ft = run('r-ft');
    expect(ft.msgs.filter((m) => String(m.label).startsWith('EAPOL-Key')).length).toBe(0);
    expect(ft.msgs.find((m) => String(m.label).startsWith('Authentication FT'))).toBeDefined();
    expect(ft.raw.interrupt).toBeLessThan(std.raw.interrupt);
  });

  it('cliente preso: a taxa cai e o frame ocupa o meio mais de oito vezes mais tempo', () => {
    const tr = run('r-sticky');
    const d = tr.msgs.filter((m) => String(m.label).startsWith('Dados (') && m.proto === 'IEEE 802.11').map((m) => m.tArr - m.tSend);
    expect(d.length).toBe(3);
    expect(d[0]).toBeLessThan(d[1]);
    expect(d[1]).toBeLessThan(d[2]);
    expect(tr.raw.ratio).toBeCloseTo(dataTime(6) / dataTime(54), 9);
    expect(tr.raw.ratio).toBeGreaterThan(8);
    expect(labels(tr)).not.toContain('Reassociation Request');
  });

  it('802.11v: o AP sugere a troca antes da reassociação', () => {
    const tr = run('r-btm');
    const l = labels(tr);
    expect(l.indexOf('BTM Request')).toBeLessThan(l.indexOf('BTM Response'));
    expect(l.indexOf('BTM Response')).toBeLessThan(l.indexOf('Reassociation Request'));
  });

  it('economia de energia: o AP guarda o pacote, o TIM do beacon marca o AID e o cliente busca com o PS-Poll', () => {
    const tr = run('r-ps');
    const l = labels(tr);
    expect(l[0]).toBe('Null Data (PM=1)');
    const ps = tr.raw.ps as { kWake: number; latency: number; arrival: number };
    expect(ps.kWake).toBe(2);
    const beacon = tr.msgs.find((m) => m.label === 'Beacon 2')!;
    expect(field(beacon, 'TIM (IE 5)')).toContain('AID 1 marcado');
    expect(l.indexOf('PS-Poll')).toBeGreaterThan(l.indexOf('Beacon 2'));
    expect(l.indexOf('Dados guardados')).toBeGreaterThan(l.indexOf('PS-Poll'));
    const arrive = tr.msgs.find((m) => m.label === 'Pacote IP para o cliente')!;
    expect(arrive.tSend).toBe(150);
  });

  it('o intervalo de escuta maior atrasa a entrega e reduz as vezes em que o cliente acorda', () => {
    const lat = [1, 3, 5].map((lis) => run('r-ps', { lis }).raw.ps.latency as number);
    expect(lat[0]).toBeLessThan(lat[1]);
    expect(lat[1]).toBeLessThan(lat[2]);
    const wakes = [1, 3, 5].map((lis) => psEstimate(lis).wakes);
    expect(wakes[0]).toBeGreaterThanOrEqual(wakes[1]);
    expect(wakes[2]).toBe(1);
    [1, 3, 5].forEach((lis) => expect(psEstimate(lis).latency).toBeCloseTo(run('r-ps', { lis }).raw.ps.latency, 6));
  });
});

describe('canais', () => {
  it('a relação entre os canais depende da distância e da largura', () => {
    expect(canalRel(1, 1, 20)).toBe('co');
    expect(canalRel(1, 3, 20)).toBe('adj');
    expect(canalRel(1, 6, 20)).toBe('indep');
    expect(canalRel(1, 11, 20)).toBe('indep');
    expect(canalRel(1, 6, 40)).toBe('adj');
    expect(canalRel(1, 11, 40)).toBe('indep');
  });

  it('independentes transmitem em paralelo; o mesmo canal, em sequência; sobrepostos, perdem rodadas', () => {
    const ind = run('c-ok');
    const co = run('c-co');
    const adj = run('c-adj');
    const dd = (tr: T) => tr.msgs.filter((m) => String(m.label).startsWith('Dados'));
    const [a, b] = dd(ind);
    expect(b.tSend).toBeLessThan(a.tArr);
    const [c1, c2] = dd(co);
    expect(c2.tSend).toBeGreaterThan(c1.tArr);
    expect(adj.msgs.some((m) => m.lost)).toBe(true);
    expect(ind.raw.total).toBeLessThan(co.raw.total);
    expect(co.raw.total).toBeLessThan(adj.raw.total);
  });

  it('com 40 MHz o canal 6 deixa de ser independente do canal 1', () => {
    expect(run('c-40').raw.rel).toBe('adj');
    expect(run('c-ok', { larg: 40, ch2: 11 }).raw.rel).toBe('indep');
  });
});
