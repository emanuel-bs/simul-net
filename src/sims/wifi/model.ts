// Modelo do Wi-Fi (IEEE 802.11, camada MAC): constantes de tempo, endereços e construtores dos campos dos quadros.
// Simplificações (detalhadas na aba Referência): um único BSS por vez, um só fluxo, um só par de antenas, taxas fixas por quadro
// (54 Mb/s nos dados e 6 Mb/s nos quadros de controle e de gerência), sem agregação, sem QoS (EDCA) e sem camada física detalhada.
import { hex, type Field } from '../../sim-core';

export const GREEN = '#7BD88F';

export const SSID = 'LabRedes';

/** Endereços MAC da faixa de documentação (RFC 9542) e IPs de documentação (RFC 5737). */
export const MAC: Record<string, string> = {
  sta: '00:00:5e:00:53:21',
  sta1: '00:00:5e:00:53:21',
  a: '00:00:5e:00:53:21',
  sta2: '00:00:5e:00:53:23',
  c: '00:00:5e:00:53:23',
  ap: '00:00:5e:00:53:a1',
  ap1: '00:00:5e:00:53:a1',
  ap2: '00:00:5e:00:53:a2',
};
export const BROADCAST = 'ff:ff:ff:ff:ff:ff';

// ---- temporização (valores típicos da camada física OFDM, em milissegundos) ----
/** Slot de 9 µs, SIFS de 16 µs e DIFS = SIFS + 2 slots = 34 µs (valores do OFDM em 5 GHz, usados em todo o simulador; em 2,4 GHz o SIFS é de 10 µs). */
export const SLOT = 0.009;
export const SIFS = 0.016;
export const DIFS = SIFS + 2 * SLOT;
/** Duração aproximada dos quadros no ar: dados de 1500 bytes a 54 Mb/s; RTS, CTS e ACK a 6 Mb/s; gerência a 6 Mb/s. */
export const T_DATA = 0.25;
export const T_RTS = 0.052;
export const T_CTS = 0.044;
export const T_ACK = 0.044;
export const T_MGMT = 0.12;
export const T_BEACON = 0.2;
/** Espera por um ACK ou CTS que não veio: SIFS + um slot + o início da recepção (aproximação). */
export const ACK_TIMEOUT = SIFS + T_ACK + SLOT;
export const CW_MIN = 15;
export const CW_MAX = 1023;
/** Beacon a cada 100 TU; 1 TU = 1024 µs. */
export const TU = 1.024;
export const BEACON_INTERVAL = 100 * TU;
/** Tempos de espera da varredura (valores típicos de implementação, não do padrão). */
export const MIN_CHANNEL_TIME = 20;
export const MAX_CHANNEL_TIME = 110;
/** Tempo típico acordado para ouvir um beacon, para a estimativa de energia (ilustrativo). */
export const WAKE_MS = 2;

const f1 = (v: number) => (Math.round(v * 10) / 10).toString().replace('.', ',');

/** Tempo simulado em escala humana, de microssegundos a segundos. */
export function fmtTime(ms: number): string {
  if (ms < 1) return f1(ms * 1000) + ' µs';
  if (ms < 1000) return f1(ms) + ' ms';
  return f1(ms / 1000) + ' s';
}

/** Duração em µs para os campos Duration/ID, arredondada para cima. */
export const us = (ms: number): number => Math.ceil(ms * 1000 - 1e-6);

// ---- quadros IEEE 802.11 ----

export type FrameType = 'mgmt' | 'ctrl' | 'data';

export interface Dot11 {
  type: FrameType;
  sub: string;
  subNum: number;
  ra: string;
  ta?: string;
  bssid?: string;
  /** Texto do campo Duration/ID. */
  dur: string;
  toDs?: boolean;
  fromDs?: boolean;
  retry?: boolean;
  pm?: boolean;
  more?: boolean;
  seq?: number;
  body?: Field[];
}

const TYPE_NAME: Record<FrameType, string> = { mgmt: 'Gerência (0)', ctrl: 'Controle (1)', data: 'Dados (2)' };

export function dot11Fields(o: Dot11): Field[] {
  const flags = [o.toDs ? 'To DS=1' : 'To DS=0', o.fromDs ? 'From DS=1' : 'From DS=0', 'Retry=' + (o.retry ? 1 : 0), 'PM=' + (o.pm ? 1 : 0), 'More Data=' + (o.more ? 1 : 0)].join('; ');
  const f: Field[] = [
    { sec: 'IEEE 802.11: cabeçalho MAC' },
    ['Tipo', TYPE_NAME[o.type], o.type === 'mgmt' ? 'gerencia a associação ao BSS' : o.type === 'ctrl' ? 'coordena o acesso ao meio' : 'carrega os dados do usuário'],
    ['Subtipo', o.sub + ' (' + o.subNum + ')', ''],
    ['Flags', flags, o.pm ? 'PM=1: o cliente avisa que vai dormir (economia de energia)' : o.retry ? 'Retry=1: este quadro é uma repetição' : ''],
    ['Duration/ID', o.dur, 'tempo que o meio ficará reservado (NAV), em µs; no PS-Poll, o AID'],
    ['Address 1 (RA)', o.ra, 'receptor do quadro'],
  ];
  if (o.ta) f.push(['Address 2 (TA)', o.ta, 'transmissor do quadro']);
  if (o.bssid) f.push(['Address 3', o.bssid, o.type === 'mgmt' ? 'BSSID: o endereço do AP' : 'BSSID ou destino final, conforme To DS e From DS']);
  if (o.seq !== undefined) f.push(['Sequence Control', 'número ' + o.seq + ', fragmento 0', 'o receptor descarta repetições com o mesmo número']);
  if (o.body && o.body.length) f.push(...o.body);
  f.push({ sec: 'Verificação' }, ['FCS', hex('fcs' + o.sub + (o.seq ?? 0) + o.ra, 4), 'CRC-32: sem FCS válido, o quadro é descartado e não é confirmado']);
  return f;
}

/** Tamanho aproximado em bytes de cada tipo de quadro (cabeçalho, corpo típico e FCS). */
export const LEN = { beacon: 130, probeReq: 60, probeResp: 130, auth: 30, assocReq: 140, assocResp: 90, ack: 14, cts: 14, rts: 20, psPoll: 16, data: 1528, nullData: 28, action: 40, eapol: 150 };

// ---- elementos de informação (IEs) usados nos corpos ----

export const ssidIe = (ssid: string): Field => ['SSID (IE 0)', ssid ? ssid : '(comprimento 0: SSID oculto)', ssid ? 'o nome da rede' : 'o AP não divulga o nome no beacon'];
export const ratesIe: Field = ['Supported Rates (IE 1)', '6(B), 9, 12(B), 18, 24(B), 36, 48, 54 Mb/s', '(B) marca as taxas básicas do BSS: o cliente precisa suportá-las'];
export const dsIe = (ch: number): Field => ['DS Parameter Set (IE 3)', 'canal ' + ch, 'o canal em que o AP opera'];
export const capField = (priv: boolean): Field => ['Capability Information', 'ESS=1; Privacy=' + (priv ? 1 : 0), priv ? 'Privacy=1: a rede exige proteção (WPA2 ou WPA3)' : 'rede aberta: sem proteção'];
export const rsnIe: Field = ['RSN (IE 48)', 'cifra CCMP; autenticação PSK ou SAE', 'anuncia a segurança; o handshake de quatro vias vem depois da associação'];
export const htIe: Field = ['HT/VHT/HE Capabilities', 'Wi-Fi 4, 5 e 6 (resumido)', 'o que o cliente e o AP sabem fazer: largura, fluxos e modulações'];

export const macOf = (k: string): string => MAC[k] ?? MAC.sta;
