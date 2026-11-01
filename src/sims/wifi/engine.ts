// Motor do Wi-Fi (IEEE 802.11, camada MAC). Quatro modos: descoberta e associação, acesso ao meio (CSMA/CA),
// roaming e economia de energia, e canais. Cada modo monta o trace de clientes (STA) e pontos de acesso (AP) e registra em
// tr.raw o estado de associação, as tentativas de acesso ao meio e as medidas usadas pelas abas e pelo Experimento.
import { COLORS as C0, hex, newTrace, type Column, type Field, type Message, type StateDef, type Trace } from '../../sim-core';
import {
  ACK_TIMEOUT,
  BEACON_INTERVAL,
  BROADCAST,
  capField,
  CW_MIN,
  DIFS,
  dot11Fields,
  dsIe,
  fmtTime,
  htIe,
  LEN,
  MAC,
  MAX_CHANNEL_TIME,
  MIN_CHANNEL_TIME,
  ratesIe,
  rsnIe,
  SIFS,
  SLOT,
  SSID,
  ssidIe,
  T_ACK,
  T_BEACON,
  T_CTS,
  T_DATA,
  T_MGMT,
  T_RTS,
  us,
  WAKE_MS,
  type Dot11,
  type FrameType,
} from './model';

// ---- base comum ----

const COL: Record<string, Omit<Column, 'key'>> = {
  sta: { label: 'Notebook', sub: 'cliente (STA)', addr: MAC.sta },
  a: { label: 'Cliente A', sub: 'STA', addr: MAC.a },
  c: { label: 'Cliente C', sub: 'STA', addr: MAC.c },
  sta1: { label: 'Cliente 1', sub: 'STA da rede 1', addr: MAC.sta1 },
  sta2: { label: 'Cliente 2', sub: 'STA da rede 2', addr: MAC.sta2 },
  ap: { label: 'AP-01', sub: 'ponto de acesso', addr: MAC.ap },
  ap1: { label: 'AP-01', sub: 'ponto de acesso', addr: MAC.ap1 },
  ap2: { label: 'AP-02', sub: 'ponto de acesso', addr: MAC.ap2 },
  lan: { label: 'Rede cabeada', sub: 'sistema de distribuição', addr: '' },
};

interface Ctx {
  tr: Trace;
  R: Record<string, any>;
  seq: number;
}

function ctx(sub: string, cols: string[], states: StateDef[], over: Record<string, Partial<Column>> = {}, extra: Record<string, unknown> = {}): Ctx {
  const columns: Column[] = cols.map((k) => ({ key: k, ...COL[k], ...(over[k] || {}) }));
  const tr = newTrace(columns, states, 1);
  tr.raw = { sub, mode: sub, res: '', stlog: [] as any[], tEnd: 0, ...extra } as Record<string, any>;
  return { tr, R: tr.raw, seq: 100 };
}

const colorOf = (t: FrameType): string => (t === 'mgmt' ? C0.plain : t === 'ctrl' ? C0.tcp : C0.data);

interface TxO {
  label: string;
  d: Dot11;
  len: number;
  dur: number;
  /** Espera antes de transmitir, a partir do cursor de tempo. */
  gap?: number;
  at?: number;
  par?: boolean;
  color?: string;
  info: string;
  about?: string;
  lost?: boolean;
  phaseName?: string;
  proto?: string;
}

/** Transmite um quadro no ar: o cursor de tempo avança até o fim da transmissão. */
function tx(c: Ctx, from: string, to: string, o: TxO): Message {
  const at = o.at ?? c.tr.t + (o.gap ?? 0);
  return c.tr.add(from, to, {
    at,
    dur: o.dur,
    proc: 0,
    par: o.par,
    label: o.label,
    proto: o.proto ?? 'IEEE 802.11',
    color: o.color ?? colorOf(o.d.type),
    len: o.len,
    fields: dot11Fields(o.d),
    info: o.info,
    about: o.about,
    lost: !!o.lost,
    phaseName: o.phaseName,
  });
}

const ACK_ABOUT = 'Todo quadro unicast é confirmado com um ACK, enviado um SIFS depois, sem disputar o meio. Sem o ACK, o transmissor presume falha e repete.';

function ack(c: Ctx, from: string, to: string, o: { gap?: number; lost?: boolean; phaseName?: string } = {}): Message {
  return tx(c, from, to, {
    label: 'ACK',
    d: { type: 'ctrl', sub: 'ACK', subNum: 13, ra: MAC[to], dur: '0' },
    len: LEN.ack,
    dur: T_ACK,
    gap: o.gap ?? SIFS,
    lost: o.lost,
    color: o.lost ? C0.bad : C0.tcp,
    info: o.lost ? 'o ACK se perde no ar' : 'confirmação de recepção',
    about: o.lost ? 'O quadro chegou, mas o ACK não voltou. Para o transmissor, é igual a um quadro perdido.' : ACK_ABOUT,
    phaseName: o.phaseName,
  });
}

/** Quadro de gerência unicast: o Duration/ID reserva o meio para o ACK. */
const mgmt = (c: Ctx, sub: string, subNum: number, from: string, to: string, body: Dot11['body'], bssid: string, retry = false): Dot11 => ({
  type: 'mgmt',
  sub,
  subNum,
  ra: MAC[to],
  ta: MAC[from],
  bssid,
  dur: String(us(SIFS + T_ACK)),
  seq: c.seq++,
  retry,
  body,
});

const setSta = (c: Ctx, n: 1 | 2 | 3, text?: string) => {
  const T = { 1: 'estado 1: não autenticado e não associado', 2: 'estado 2: autenticado, não associado', 3: 'estado 3: autenticado e associado' };
  const K = { 1: 'closed', 2: 'warn', 3: 'est' };
  c.tr.st(c.tr.t, 'sta', text ?? T[n], K[n]);
  (c.R.stlog as any[]).push({ t: c.tr.t, n });
};

function finish(c: Ctx, res: string, text: string, cls: string) {
  const { tr, R } = c;
  R.res = res;
  tr.phase('Resultado', 'resultado');
  tr.st(tr.t, 'phase', 'concluído', cls === 'bad' ? 'bad' : 'est');
  tr.st(tr.t, 'res', text, cls);
  tr.mile(tr.t, text.length > 30 ? text.slice(0, 28) + '...' : text, '');
  R.tEnd = tr.t;
}

const begin = (c: Ctx) => {
  c.tr.st(0, 'phase', 'início', 'warn');
  c.tr.st(0, 'res', 'em andamento', 'warn');
};

const beaconBody = (ch: number, hidden: boolean, priv: boolean, tim: string): Dot11['body'] => [
  { sec: 'Corpo do Beacon' },
  ['Timestamp', hex('ts' + ch, 8), 'relógio do AP, em µs: mantém os clientes sincronizados'],
  ['Beacon Interval', '100 TU (102,4 ms)', '1 TU = 1024 µs'],
  capField(priv),
  ssidIe(hidden ? '' : SSID),
  ratesIe,
  dsIe(ch),
  ['TIM (IE 5)', tim, 'quais clientes dormindo têm quadros guardados no AP'],
  ...(priv ? [rsnIe] : []),
];

const probeRespBody = (ch: number, priv: boolean): Dot11['body'] => [
  { sec: 'Corpo do Probe Response' },
  ['Timestamp', hex('ts' + ch, 8), ''],
  ['Beacon Interval', '100 TU (102,4 ms)', ''],
  capField(priv),
  ssidIe(SSID),
  ratesIe,
  dsIe(ch),
  ...(priv ? [rsnIe] : []),
];

// ---- 1. Descoberta e associação ----

export interface DescParams {
  scan: 'passivo' | 'ativo';
  ssid: 'visivel' | 'oculto';
  res: 'ok' | 'cheio';
  sec: 'aberta' | 'rsn';
  ch: number;
}

const STATES_DESC: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'sta', label: 'Estado do cliente (802.11)' },
  { key: 'res', label: 'Resultado' },
];

export function buildDesc(P: DescParams): Trace {
  const hidden = P.ssid === 'oculto';
  const priv = P.sec === 'rsn';
  const c = ctx('desc', ['sta', 'ap', 'lan'], STATES_DESC, { ap: { sub: 'ponto de acesso, canal ' + P.ch } }, { ch: P.ch, scan: P.scan, hidden, priv, aid: 0 });
  const { tr, R } = c;
  begin(c);
  setSta(c, 1);
  tr.ev(0, 'sta', 'Liga o rádio. Não conhece nenhuma rede: precisa descobrir quais APs estão por perto', '');
  tr.phase('1. Descobrir redes (varredura)', 'varredura');
  tr.st(tr.t, 'phase', 'varredura', 'warn');

  const chans = [1, 6, 11].filter((x) => x <= P.ch);
  let learned = false;
  for (const ch of chans) {
    const here = ch === P.ch;
    if (P.scan === 'passivo') {
      tr.ev(tr.t, 'sta', 'Varredura passiva: sintoniza o canal ' + ch + ' e só escuta, por ' + MAX_CHANNEL_TIME + ' ms (mais que um intervalo de beacon, de 102,4 ms)', '');
      if (!here) {
        tr.wait(MAX_CHANNEL_TIME);
        tr.ev(tr.t, 'sta', 'Nenhum beacon no canal ' + ch + ': passa ao próximo canal', 'warn');
        continue;
      }
      tr.wait(40);
      tx(c, 'ap', 'sta', {
        label: 'Beacon',
        d: { type: 'mgmt', sub: 'Beacon', subNum: 8, ra: BROADCAST, ta: MAC.ap, bssid: MAC.ap, dur: '0', seq: c.seq++, body: beaconBody(P.ch, hidden, priv, 'DTIM 0, período 1; nenhum cliente com dados guardados') },
        len: LEN.beacon,
        dur: T_BEACON,
        info: hidden ? 'SSID com comprimento 0 (oculto)' : 'SSID ' + SSID + ', canal ' + P.ch,
        about: 'O AP anuncia a rede a cada 102,4 ms, em broadcast e sem ACK. O beacon traz o SSID, as taxas, o canal, a segurança e a capacidade do AP.',
        phaseName: 'Varredura',
      });
      learned = !hidden;
      tr.ev(tr.t, 'sta', hidden ? 'Ouve o beacon, mas o SSID vem vazio: não sabe o nome da rede' : 'Ouve o beacon: aprendeu o SSID ' + SSID + ', o canal, as taxas e a segurança, sem transmitir nada', hidden ? 'warn' : 'ok');
    } else {
      tr.ev(tr.t, 'sta', 'Varredura ativa: no canal ' + ch + ', envia um Probe Request e espera ' + MIN_CHANNEL_TIME + ' ms por respostas', '');
      if (!here) {
        tr.wait(MIN_CHANNEL_TIME);
        tr.ev(tr.t, 'sta', 'Nenhuma resposta no canal ' + ch + ': passa ao próximo canal', 'warn');
        continue;
      }
      tx(c, 'sta', 'ap', {
        label: 'Probe Request',
        gap: DIFS + 3 * SLOT,
        d: { type: 'mgmt', sub: 'Probe Request', subNum: 4, ra: BROADCAST, ta: MAC.sta, bssid: BROADCAST, dur: '0', seq: c.seq++, body: [{ sec: 'Corpo do Probe Request' }, ['SSID (IE 0)', '(curinga, comprimento 0)', 'pergunta "que redes existem aqui?"'], ratesIe, htIe] },
        len: LEN.probeReq,
        dur: T_MGMT,
        info: 'SSID curinga, em broadcast',
        about: 'O cliente pergunta ativamente quem está por perto. É broadcast, e por isso não tem ACK.',
        phaseName: 'Varredura',
      });
      if (hidden) {
        tr.ev(tr.t, 'ap', 'O SSID está oculto: o AP não responde a Probe Request com SSID curinga', 'warn');
        tr.wait(MIN_CHANNEL_TIME);
        tr.ev(tr.t, 'sta', 'Sem resposta ao pedido curinga. Como tem o perfil salvo de ' + SSID + ', pergunta pelo nome', '');
        tx(c, 'sta', 'ap', {
          label: 'Probe Request (SSID ' + SSID + ')',
          gap: DIFS + 2 * SLOT,
          d: { type: 'mgmt', sub: 'Probe Request', subNum: 4, ra: BROADCAST, ta: MAC.sta, bssid: BROADCAST, dur: '0', seq: c.seq++, body: [{ sec: 'Corpo do Probe Request' }, ssidIe(SSID), ratesIe, htIe] },
          len: LEN.probeReq + 8,
          dur: T_MGMT,
          info: 'SSID ' + SSID + ' em claro',
          about: 'O nome da rede passa em claro no pedido. Ocultar o SSID não protege nada: quem escuta o ar vê o nome assim que um cliente legítimo pergunta por ele.',
          phaseName: 'Varredura',
        });
      }
      tx(c, 'ap', 'sta', {
        label: 'Probe Response',
        gap: DIFS + 2 * SLOT,
        d: mgmt(c, 'Probe Response', 5, 'ap', 'sta', probeRespBody(P.ch, priv), MAC.ap),
        len: LEN.probeResp,
        dur: T_MGMT + 0.05,
        info: 'SSID ' + SSID + ', canal ' + P.ch,
        about: 'O AP responde por unicast, disputando o meio como qualquer outro quadro. A resposta traz o mesmo conteúdo do beacon.',
        phaseName: 'Varredura',
      });
      ack(c, 'sta', 'ap');
      learned = true;
      tr.ev(tr.t, 'sta', 'Recebeu a resposta: aprendeu o SSID ' + SSID + ' sem esperar o próximo beacon', 'ok');
    }
    break;
  }

  if (P.scan === 'passivo' && hidden && !learned) {
    tr.ev(tr.t, 'sta', 'Tem o perfil salvo de ' + SSID + ': envia um Probe Request dirigido, com o nome da rede', '');
    tx(c, 'sta', 'ap', {
      label: 'Probe Request (SSID ' + SSID + ')',
      gap: DIFS + 2 * SLOT,
      d: { type: 'mgmt', sub: 'Probe Request', subNum: 4, ra: BROADCAST, ta: MAC.sta, bssid: BROADCAST, dur: '0', seq: c.seq++, body: [{ sec: 'Corpo do Probe Request' }, ssidIe(SSID), ratesIe, htIe] },
      len: LEN.probeReq + 8,
      dur: T_MGMT,
      info: 'SSID ' + SSID + ' em claro',
      about: 'O nome da rede passa em claro no pedido. Ocultar o SSID não protege nada: quem escuta o ar vê o nome assim que um cliente legítimo pergunta por ele.',
      phaseName: 'Varredura',
    });
    tx(c, 'ap', 'sta', {
      label: 'Probe Response',
      gap: DIFS + 2 * SLOT,
      d: mgmt(c, 'Probe Response', 5, 'ap', 'sta', probeRespBody(P.ch, priv), MAC.ap),
      len: LEN.probeResp,
      dur: T_MGMT + 0.05,
      info: 'SSID ' + SSID + ', canal ' + P.ch,
      about: 'O AP revela o nome da rede ao cliente que perguntou por ele.',
      phaseName: 'Varredura',
    });
    ack(c, 'sta', 'ap');
    tr.ev(tr.t, 'sta', 'Descobriu o AP oculto', 'ok');
  }
  tr.mile(tr.t, 'rede ' + SSID + ' encontrada', 'canal ' + P.ch);

  // ---- autenticação (sistema aberto) ----
  tr.wait(0.2);
  tr.phase('2. Autenticação (sistema aberto)', 'auth');
  tr.st(tr.t, 'phase', 'autenticação', 'warn');
  const authBody = (seqNo: number): Dot11['body'] => [
    { sec: 'Corpo da Authentication' },
    ['Authentication Algorithm', '0 (Open System)', 'sistema aberto: não prova identidade nenhuma'],
    ['Transaction Sequence', String(seqNo), seqNo === 1 ? 'primeiro quadro da troca' : 'resposta do AP'],
    ['Status Code', '0 (sucesso)', seqNo === 1 ? 'no pedido, o campo não tem significado' : 'o AP aceita a autenticação'],
  ];
  tx(c, 'sta', 'ap', { label: 'Authentication (1)', gap: DIFS + 4 * SLOT, d: mgmt(c, 'Authentication', 11, 'sta', 'ap', authBody(1), MAC.ap), len: LEN.auth, dur: T_MGMT, info: 'algoritmo 0 (sistema aberto), sequência 1', about: 'Este passo é um legado do padrão: no sistema aberto ele só cumpre o ritual, sem verificar quem é o cliente. A proteção de verdade vem depois (WPA2 e WPA3).', phaseName: 'Autenticação' });
  ack(c, 'ap', 'sta');
  tx(c, 'ap', 'sta', { label: 'Authentication (2)', gap: DIFS + 2 * SLOT, d: mgmt(c, 'Authentication', 11, 'ap', 'sta', authBody(2), MAC.ap), len: LEN.auth, dur: T_MGMT, info: 'status 0 (sucesso)', about: 'O AP aceita. O cliente passa ao estado 2: autenticado, mas ainda não associado.', phaseName: 'Autenticação' });
  ack(c, 'sta', 'ap');
  setSta(c, 2);

  // ---- associação ----
  tr.wait(0.2);
  tr.phase('3. Associação', 'assoc');
  tr.st(tr.t, 'phase', 'associação', 'warn');
  tx(c, 'sta', 'ap', {
    label: 'Association Request',
    gap: DIFS + 5 * SLOT,
    d: mgmt(c, 'Association Request', 0, 'sta', 'ap', [{ sec: 'Corpo da Association Request' }, capField(priv), ['Listen Interval', '10', 'de quantos em quantos beacons o cliente acorda, se usar economia de energia'], ssidIe(SSID), ratesIe, htIe, ...(priv ? [rsnIe] : [])], MAC.ap),
    len: LEN.assocReq,
    dur: T_MGMT + 0.06,
    info: 'SSID ' + SSID + ', capacidades do cliente',
    about: 'O cliente pede para entrar no BSS e informa o que sabe fazer (taxas, largura de canal, segurança). Associar é o que dá ao cliente um lugar no AP.',
    phaseName: 'Associação',
  });
  ack(c, 'ap', 'sta');
  const full = P.res === 'cheio';
  tr.ev(tr.t, 'ap', full ? 'A tabela de clientes do AP está cheia: não pode aceitar mais um' : 'Tem espaço: cria o registro do cliente e atribui o AID 1', full ? 'warn' : 'ok');
  tx(c, 'ap', 'sta', {
    label: full ? 'Association Response (recusada)' : 'Association Response',
    gap: DIFS + 2 * SLOT,
    color: full ? C0.bad : undefined,
    d: mgmt(c, 'Association Response', 1, 'ap', 'sta', [{ sec: 'Corpo da Association Response' }, capField(priv), ['Status Code', full ? '17' : '0 (sucesso)', full ? 'AP incapaz de tratar mais estações associadas' : 'associação aceita'], ['Association ID (AID)', full ? '(não atribuído)' : '1', full ? '' : 'identifica o cliente nos TIMs e no PS-Poll'], ratesIe, htIe], MAC.ap),
    len: LEN.assocResp,
    dur: T_MGMT,
    info: full ? 'status 17: AP lotado' : 'status 0, AID 1',
    about: full ? 'O AP recusa e diz o motivo no Status Code. O cliente continua no estado 2 e deve procurar outro AP ou tentar mais tarde.' : 'O AP aceita e atribui um AID. O cliente passa ao estado 3: autenticado e associado, o único em que quadros de dados são aceitos.',
    phaseName: 'Associação',
  });
  ack(c, 'sta', 'ap');
  if (full) {
    tr.ev(tr.t, 'sta', 'Associação recusada (código 17): continua no estado 2. Procura outro AP ou tenta depois', 'bad');
    finish(c, 'cheio', 'associação recusada: AP lotado', 'bad');
    return tr;
  }
  R.aid = 1;
  setSta(c, 3);

  // ---- primeiro tráfego ----
  tr.wait(0.3);
  tr.phase('4. Primeiro tráfego', 'dados');
  tr.st(tr.t, 'phase', 'dados', priv ? 'warn' : 'est');
  const dhcp = (): Dot11 => ({ type: 'data', sub: 'Data', subNum: 0, ra: MAC.ap, ta: MAC.sta, bssid: BROADCAST, dur: String(us(SIFS + T_ACK)), toDs: true, seq: c.seq++, body: [{ sec: 'Corpo' }, ['LLC/SNAP e IP', 'DHCPDISCOVER', 'primeira mensagem para obter um endereço IP']] });
  tx(c, 'sta', 'ap', { label: 'DHCPDISCOVER', gap: DIFS + 3 * SLOT, d: dhcp(), len: 400, dur: 0.15, info: 'dados do cliente para o AP (To DS=1)', about: 'Um quadro de dados comum, com To DS=1: vai do cliente ao AP, que o encaminhará à rede cabeada.', phaseName: 'Dados' });
  ack(c, 'ap', 'sta');
  if (priv) {
    tr.ev(tr.t, 'ap', 'Descarta o quadro: a porta controlada ainda está fechada. Em redes WPA2 e WPA3 os dados só passam depois do handshake de quatro vias', 'bad');
    R.dataOk = false;
    finish(c, 'ok-rsn', 'associado; aguardando o handshake', 'warn');
    return tr;
  }
  tr.add('ap', 'lan', { at: tr.t + 0.02, dur: 0.05, proc: 0, label: 'DHCPDISCOVER (Ethernet)', proto: 'Ethernet', color: C0.data, len: 342, fields: [{ sec: 'Ethernet II' }, ['Destino', BROADCAST, 'broadcast'], ['Origem', MAC.sta, 'o MAC do cliente'], ['EtherType', '0x0800', 'IPv4']], info: 'o AP converte o quadro 802.11 em Ethernet', about: 'O AP traduz o quadro 802.11 para Ethernet e o entrega à rede cabeada: ele faz a ponte entre o ar e o fio.' });
  R.dataOk = true;
  finish(c, 'ok-aberta', 'associado; rede aberta', 'est');
  return tr;
}

// ---- 2. Acesso ao meio ----

export interface MeioParams {
  mkind: 'basico' | 'ack' | 'colisao' | 'oculto';
  rts: boolean;
}

const STATES_MEIO: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'midia', label: 'Meio visto pelo AP' },
  { key: 'res', label: 'Resultado' },
];

interface Round {
  cw: number;
  a: number;
  c: number;
}

export function buildMeio(P: MeioParams): Trace {
  const hidden = P.mkind === 'oculto';
  const c = ctx('meio', ['a', 'ap', 'c'], STATES_MEIO, hidden ? { c: { label: 'Cliente C', sub: 'fora do alcance de A' } } : {}, { mkind: P.mkind, rts: P.rts, hidden, attempts: [] as any[], navs: [] as any[], collisions: 0, wasted: 0, retries: 0 });
  const { tr, R } = c;
  begin(c);
  const unit = P.rts ? T_RTS : T_DATA;
  const NAV_TOTAL = SIFS + T_CTS + SIFS + T_DATA + SIFS + T_ACK;
  const who = (k: string) => (k === 'a' ? 'Cliente A' : 'Cliente C');
  const other = (k: string) => (k === 'a' ? 'c' : 'a');
  const log = (t: number, k: string, cw: number, bo: number, result: string) => (R.attempts as any[]).push({ t, who: who(k), cw, bo, result });

  const dataD = (k: string, seq: number, retry: boolean): Dot11 => ({ type: 'data', sub: 'Data', subNum: 0, ra: MAC.ap, ta: MAC[k], bssid: '00:00:5e:00:53:01', dur: String(us(SIFS + T_ACK)), toDs: true, retry, seq, body: [{ sec: 'Corpo' }, ['Payload', '1500 bytes (IP)', 'quadro de dados do usuário']] });

  /** Troca completa de um cliente com o AP, a partir do instante dado. Devolve o fim dos dados e o fim da troca. */
  function exchange(k: string, start: number, o: { seq: number; retry?: boolean; ackLost?: boolean; nav?: boolean }): { dataEnd: number; end: number } {
    tr.t = start;
    tr.st(start, 'midia', 'ocupado', 'warn');
    let navStart: number | undefined;
    if (P.rts) {
      tx(c, k, 'ap', { label: 'RTS', d: { type: 'ctrl', sub: 'RTS', subNum: 11, ra: MAC.ap, ta: MAC[k], dur: String(us(NAV_TOTAL)) }, len: LEN.rts, dur: T_RTS, info: 'pede a reserva do meio', about: 'Request to Send: um quadro curto que pede ao AP permissão para transmitir. O campo Duration/ID reserva o meio por toda a troca (RTS, CTS, dados e ACK).' });
      const cts = tx(c, 'ap', k, { label: 'CTS', gap: SIFS, d: { type: 'ctrl', sub: 'CTS', subNum: 12, ra: MAC[k], dur: String(us(NAV_TOTAL - SIFS - T_CTS)) }, len: LEN.cts, dur: T_CTS, info: 'o AP libera e reserva o meio', about: 'Clear to Send: o AP autoriza e repete a reserva. Quem ouve o AP, mesmo sem ouvir o cliente, adia a transmissão (NAV).' });
      if (o.nav !== false) {
        navStart = hidden ? cts.tSend : start;
        tr.ev(hidden ? cts.tArr : start + T_RTS, other(k), hidden ? 'Não ouve ' + who(k) + ', mas ouve o CTS do AP: ajusta o NAV e adia a transmissão' : 'Ouve o RTS de ' + who(k) + ': ajusta o NAV (reserva virtual) e adia a transmissão', 'ok');
      }
    }
    const dm = tx(c, k, 'ap', { label: 'Dados' + (o.retry ? ' (repetição)' : ''), gap: P.rts ? SIFS : 0, d: dataD(k, o.seq, !!o.retry), len: LEN.data, dur: T_DATA, info: '1500 bytes' + (o.retry ? ', Retry=1' : ''), about: o.retry ? 'O mesmo quadro, com o mesmo número de sequência e o bit Retry ligado.' : 'O quadro de dados do usuário, enviado a 54 Mb/s no exemplo.' });
    const dataEnd = dm.tArr;
    const am = ack(c, 'ap', k, { lost: o.ackLost });
    tr.st(am.tArr, 'midia', 'livre', 'est');
    if (navStart !== undefined) (R.navs as any[]).push({ who: other(k), t: navStart, until: am.tArr });
    return { dataEnd, end: am.tArr };
  }

  /** Dois quadros simultâneos (ou sobrepostos): nenhum é decodificado. */
  function collide(ta: number, tc: number, round: Round, label: string): number {
    const msgs: Message[] = [];
    [['a', ta], ['c', tc]].forEach(([k, t]) => {
      const m = tx(c, k as string, 'ap', {
        label: label + ' (colisão)',
        at: t as number,
        par: true,
        color: C0.bad,
        lost: true,
        d: P.rts ? { type: 'ctrl', sub: 'RTS', subNum: 11, ra: MAC.ap, ta: MAC[k as string], dur: String(us(NAV_TOTAL)) } : dataD(k as string, 1, false),
        len: P.rts ? LEN.rts : LEN.data,
        dur: unit,
        info: 'sobreposto a outro quadro',
        about: 'Os dois sinais se somam no AP e nenhum quadro é decodificado. Os transmissores só descobrem a falha pela falta do ' + (P.rts ? 'CTS' : 'ACK') + '.',
      });
      msgs.push(m);
      log(t as number, k as string, round.cw, k === 'a' ? round.a : round.c, 'colisão');
    });
    const end = Math.max(...msgs.map((m) => m.tArr));
    tr.st(Math.min(ta, tc), 'midia', 'colisão', 'bad');
    tr.ev(end, 'ap', 'Dois sinais ao mesmo tempo: nenhum quadro é decodificado (colisão)', 'bad');
    tr.st(end, 'midia', 'livre', 'est');
    R.collisions++;
    const resp = end + ACK_TIMEOUT;
    R.wasted += end + ACK_TIMEOUT - Math.min(ta, tc);
    tr.ev(resp, 'a', 'Sem ' + (P.rts ? 'CTS' : 'ACK') + ' no prazo: presume falha e dobra a janela de contenção', 'warn');
    tr.ev(resp, 'c', 'Sem ' + (P.rts ? 'CTS' : 'ACK') + ' no prazo: presume falha e dobra a janela de contenção', 'warn');
    return resp;
  }

  // ---- cenários ----
  const t0 = 0.2;
  tr.st(0, 'midia', 'ocupado (outra transmissão)', 'warn');
  tr.st(0, 'phase', 'esperando o meio', 'warn');
  tr.st(0, 'res', 'em andamento', 'warn');
  tr.phase('1. Esperar o meio livre', 'espera');
  const first = P.mkind === 'basico' || P.mkind === 'ack';
  tr.ev(0, 'a', first ? 'Tem um quadro de 1500 bytes para enviar, mas o meio está ocupado por outra transmissão: espera' : 'Cliente A e Cliente C têm quadros para enviar e o meio está ocupado: os dois esperam', '');
  if (!first) tr.ev(0, 'c', hidden ? 'Está fora do alcance do Cliente A: não ouve as transmissões dele' : 'Também quer enviar e espera o meio ficar livre', '');
  tr.st(t0, 'midia', 'livre', 'est');
  tr.ev(t0, 'ap', 'O meio ficou livre', 'ok');

  if (first) {
    const bo = 5;
    const tS = t0 + DIFS + bo * SLOT;
    tr.ev(t0 + DIFS, 'a', 'Meio livre por um DIFS (34 µs). Sorteia o backoff em [0, ' + CW_MIN + ']: ' + bo + ' slots de 9 µs, contados só enquanto o meio está livre', '');
    tr.t = tS;
    tr.phase('2. Transmitir', 'tx');
    tr.st(tS, 'phase', 'transmitindo', 'warn');
    if (P.mkind === 'basico') {
      const x = exchange('a', tS, { seq: 200 });
      log(tS, 'a', CW_MIN, bo, 'sucesso');
      tr.ev(x.end, 'a', 'Recebeu o ACK: transmissão confirmada. A janela de contenção volta ao mínimo (' + CW_MIN + ')', 'ok');
      tr.ev(x.dataEnd, 'ap', 'Recebeu o quadro com FCS válido: entrega à rede cabeada e envia o ACK um SIFS depois', 'ok');
      tr.t = x.end;
      finish(c, 'ok', 'entregue na primeira tentativa', 'est');
      R.total = x.end;
      return tr;
    }
    const x1 = exchange('a', tS, { seq: 200, ackLost: true });
    log(tS, 'a', CW_MIN, bo, 'ACK perdido');
    tr.ev(x1.dataEnd, 'ap', 'Recebeu o quadro com FCS válido e envia o ACK, que se perde no ar', 'warn');
    const tOut = x1.dataEnd + ACK_TIMEOUT;
    tr.ev(tOut, 'a', 'ACKTimeout: o ACK não chegou. Presume falha, dobra a janela (' + CW_MIN + ' para ' + (2 * (CW_MIN + 1) - 1) + ') e conta uma repetição', 'warn');
    R.retries++;
    const bo2 = 12;
    tr.ev(tOut + DIFS, 'a', 'Meio livre por um DIFS. Novo backoff em [0, ' + (2 * (CW_MIN + 1) - 1) + ']: ' + bo2 + ' slots', '');
    tr.phase('3. Repetição', 'retry');
    tr.st(tOut, 'phase', 'repetição', 'warn');
    const tS2 = tOut + DIFS + bo2 * SLOT;
    const x2 = exchange('a', tS2, { seq: 200, retry: true });
    log(tS2, 'a', 2 * (CW_MIN + 1) - 1, bo2, 'sucesso');
    tr.ev(x2.dataEnd, 'ap', 'Recebe o quadro de novo (Retry=1, mesmo número de sequência): reconhece a repetição, confirma e não entrega duas vezes', 'ok');
    tr.ev(x2.end, 'a', 'Recebeu o ACK. A janela de contenção volta ao mínimo', 'ok');
    tr.t = x2.end;
    finish(c, 'ok-ack', 'entregue na 2ª tentativa', 'est');
    R.total = x2.end;
    return tr;
  }

  // dois clientes disputando o meio
  const rounds: Round[] = hidden
    ? [
        { cw: 15, a: 3, c: 6 },
        { cw: 31, a: 10, c: 11 },
        { cw: 63, a: 2, c: 40 },
      ]
    : [
        { cw: 15, a: 3, c: 3 },
        { cw: 31, a: 4, c: 17 },
      ];
  let idle = t0;
  tr.ev(t0 + DIFS, 'a', 'Meio livre por um DIFS (34 µs). Sorteia o backoff e conta os slots', '');
  let seq = 300;
  for (let i = 0; i < rounds.length; i++) {
    const r = rounds[i];
    tr.t = idle;
    const tA = idle + DIFS + r.a * SLOT;
    const tCplan = idle + DIFS + r.c * SLOT;
    tr.phase('Rodada ' + (i + 1) + ': janela de contenção até ' + r.cw, 'r' + (i + 1));
    tr.st(idle, 'phase', 'rodada ' + (i + 1), 'warn');
    tr.ev(idle + DIFS, 'a', 'Sorteou ' + r.a + ' slots em [0, ' + r.cw + ']', '');
    tr.ev(idle + DIFS, 'c', 'Sorteou ' + r.c + ' slots em [0, ' + r.cw + ']', '');
    const overlap = hidden ? Math.abs(tA - tCplan) < unit : r.a === r.c;
    if (overlap) {
      if (hidden) tr.ev(Math.min(tA, tCplan), tA <= tCplan ? 'c' : 'a', 'O meio parece livre: não ouve o outro cliente e transmite no seu slot', 'warn');
      idle = collide(tA, hidden ? tCplan : tA, r, P.rts ? 'RTS' : 'Dados');
      continue;
    }
    // o primeiro a transmitir (a) conclui
    const xa = exchange('a', tA, { seq: seq++ });
    log(tA, 'a', r.cw, r.a, 'sucesso');
    tr.ev(xa.end, 'a', 'Recebeu o ACK: transmissão confirmada', 'ok');
    // o outro cliente retoma
    const tC = hidden ? Math.max(tCplan, xa.end + DIFS) : xa.end + DIFS + (r.c - r.a) * SLOT;
    if (!hidden && !P.rts) tr.ev(tA, 'c', 'Ouve ' + (P.rts ? 'o RTS' : 'a transmissão') + ' de A e congela o contador em ' + (r.c - r.a) + ' slots', 'ok');
    else if (!P.rts) tr.ev(xa.dataEnd + SIFS, 'c', 'Ouve o ACK do AP: o meio está ocupado. Congela o contador e espera', 'ok');
    tr.ev(xa.end + DIFS, 'c', 'Meio livre por um DIFS: retoma a contagem' + (hidden ? '' : ' (faltam ' + (r.c - r.a) + ' slots)'), '');
    const xc = exchange('c', tC, { seq: seq++, nav: false });
    log(tC, 'c', r.cw, r.c, 'sucesso');
    tr.ev(xc.end, 'c', 'Recebeu o ACK: transmissão confirmada', 'ok');
    tr.t = xc.end;
    R.total = xc.end;
    break;
  }
  const lost = Math.round(R.wasted * 1000);
  finish(c, hidden ? (P.rts ? 'oculto-rts' : 'oculto') : P.rts ? 'colisao-rts' : 'colisao', R.collisions + (R.collisions === 1 ? ' colisão' : ' colisões') + ', ' + lost + ' µs perdidos', 'est');
  return tr;
}

// ---- 3. Roaming e economia de energia ----

export interface MovParams {
  mov: 'roam' | 'sticky' | 'btm' | 'ps';
  ft: boolean;
  lis: number;
}

const STATES_MOV: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'sta', label: 'Cliente' },
  { key: 'res', label: 'Resultado' },
];

/** Duração de um quadro de dados de 1500 bytes na taxa dada (Mb/s), com 20 µs de preâmbulo. */
export const dataTime = (mbps: number): number => 0.02 + (1528 * 8) / (mbps * 1000);

export function buildMov(P: MovParams): Trace {
  if (P.mov === 'ps') return buildPs(P);
  const c = ctx('mov', ['sta', 'ap1', 'ap2', 'lan'], STATES_MOV, { ap1: { sub: 'canal 1' }, ap2: { sub: 'canal 6' } }, { mov: P.mov, ft: P.ft, rssi: [] as any[], rates: [] as any[] });
  const { tr, R } = c;
  begin(c);
  const rssi = (t: number, a: number, b: number) => (R.rssi as any[]).push({ t, ap1: a, ap2: b });
  const dataVia = (ap: string, mbps: number, ph: string) => {
    const d = dataTime(mbps);
    tx(c, 'sta', ap, { label: 'Dados (' + mbps + ' Mb/s)', gap: DIFS + 3 * SLOT, d: { type: 'data', sub: 'Data', subNum: 0, ra: MAC[ap], ta: MAC.sta, bssid: BROADCAST, dur: String(us(SIFS + T_ACK)), toDs: true, seq: c.seq++, body: [{ sec: 'Corpo' }, ['Payload', '1500 bytes (IP)', 'a ' + mbps + ' Mb/s o quadro ocupa o meio por ' + fmtTime(d)]] }, len: LEN.data, dur: d, info: 'ocupa o meio por ' + fmtTime(d), about: 'Quanto pior o sinal, menor a taxa que o cliente consegue usar, e o mesmo quadro passa a ocupar o meio por mais tempo.', phaseName: ph });
    ack(c, ap, 'sta');
  };
  setSta(c, 3, 'associado ao AP-01');
  tr.phase('1. Conectado ao AP-01', 'ap1');
  tr.st(tr.t, 'phase', 'conectado', 'est');
  tr.st(tr.t, 'res', 'em andamento', 'warn');
  rssi(0, -55, -80);
  tr.ev(0, 'sta', 'Sinal do AP-01: -55 dBm. Taxa alta (54 Mb/s no exemplo)', 'ok');
  dataVia('ap1', 54, 'AP-01');
  R.rates.push({ t: tr.t, rssi: -55, mbps: 54, ms: dataTime(54) });
  tr.add('ap1', 'lan', { at: tr.t + 0.02, dur: 0.05, proc: 0, label: 'Dados (Ethernet)', proto: 'Ethernet', color: C0.data, len: 1514, fields: [{ sec: 'Ethernet II' }, ['Origem', MAC.sta, 'o MAC do cliente'], ['EtherType', '0x0800', 'IPv4']], info: 'o AP entrega à rede cabeada', about: 'O AP converte o quadro 802.11 em Ethernet e o entrega à rede cabeada.' });
  const tLast = tr.t;

  if (P.mov === 'sticky') {
    tr.wait(3000);
    rssi(tr.t, -70, -62);
    tr.ev(tr.t, 'sta', 'O cliente se afasta: sinal do AP-01 em -70 dBm. A taxa cai para 24 Mb/s', 'warn');
    dataVia('ap1', 24, 'AP-01');
    R.rates.push({ t: tr.t, rssi: -70, mbps: 24, ms: dataTime(24) });
    tr.wait(3000);
    rssi(tr.t, -80, -58);
    tr.ev(tr.t, 'sta', 'Sinal do AP-01 em -80 dBm, enquanto o AP-02 já está a -58 dBm. O cliente não troca de AP: o driver só procura outro quando perde a conexão', 'bad');
    tr.phase('2. Preso ao AP distante', 'sticky');
    tr.st(tr.t, 'phase', 'preso ao AP-01', 'bad');
    dataVia('ap1', 6, 'AP-01');
    R.rates.push({ t: tr.t, rssi: -80, mbps: 6, ms: dataTime(6) });
    tr.ev(tr.t, 'ap1', 'O quadro lento a 6 Mb/s ocupou o meio ' + (dataTime(6) / dataTime(54)).toFixed(1).replace('.', ',') + ' vezes mais que o de 54 Mb/s: todos os outros clientes do AP esperam por ele', 'bad');
    R.ratio = dataTime(6) / dataTime(54);
    finish(c, 'sticky', 'cliente preso, vazão baixa', 'bad');
    return tr;
  }

  tr.wait(2000);
  rssi(tr.t, -72, -60);
  tr.ev(tr.t, 'sta', 'O cliente se afasta: sinal do AP-01 em -72 dBm', 'warn');
  tr.wait(2000);
  rssi(tr.t, -78, -58);
  const tDecide = tr.t;
  R.tDecide = tDecide;

  if (P.mov === 'btm') {
    tr.ev(tr.t, 'ap1', 'Vê o cliente com sinal fraco (-78 dBm) e sabe que o AP-02 está mais perto (relatório de vizinhança). Sugere a troca', 'warn');
    tr.phase('2. O AP-01 sugere a troca (802.11v)', 'btm');
    tr.st(tr.t, 'phase', 'sugestão de troca', 'warn');
    tx(c, 'ap1', 'sta', { label: 'BTM Request', gap: DIFS + 2 * SLOT, d: mgmt(c, 'Action (BSS Transition Management Request)', 13, 'ap1', 'sta', [{ sec: 'Corpo do Action' }, ['Category / Action', 'WNM (10) / BSS Transition Management Request (7)', 'gerência de rede sem fio (802.11v)'], ['Candidate List', 'AP-02 ' + MAC.ap2 + ', canal 6', 'lista de APs sugeridos, no formato do Neighbor Report (802.11k)'], ['Disassociation Imminent', '1', 'o AP avisa que vai desassociar o cliente em breve']], MAC.ap1), len: LEN.action + 30, dur: T_MGMT, info: 'sugere o AP-02, canal 6', about: 'O AP pede ao cliente que troque de AP e entrega a lista de candidatos. É um pedido, não uma ordem: o cliente decide.', phaseName: 'Sugestão' });
    ack(c, 'sta', 'ap1');
    tx(c, 'sta', 'ap1', { label: 'BTM Response', gap: DIFS + 3 * SLOT, d: mgmt(c, 'Action (BSS Transition Management Response)', 13, 'sta', 'ap1', [{ sec: 'Corpo do Action' }, ['Category / Action', 'WNM (10) / BSS Transition Management Response (8)', ''], ['Status Code', '0 (aceita)', 'o cliente concorda em trocar'], ['Target BSSID', MAC.ap2, 'o AP escolhido']], MAC.ap1), len: LEN.action, dur: T_MGMT, info: 'aceita a troca para o AP-02', about: 'O cliente aceita e informa o BSSID de destino. Sem o BTM, um cliente teimoso ficaria preso ao AP fraco.', phaseName: 'Sugestão' });
    ack(c, 'ap1', 'sta');
  } else {
    tr.ev(tr.t, 'sta', 'O sinal do AP-01 (-78 dBm) caiu abaixo do limiar de roaming do driver (-75 dBm, valor típico de implementação). Decide procurar outro AP', 'warn');
  }

  roamTo(c, P.ft);
  const tFirst = R.tFirstNew as number;
  R.interrupt = tFirst - tDecide;
  R.gapLast = tFirst - tLast;
  finish(c, P.ft ? 'roam-ft' : P.mov === 'btm' ? 'roam-btm' : 'roam', 'AP-02, interrupção de ' + fmtTime(R.interrupt), 'est');
  return tr;
}

/** Troca de AP: varredura direcionada, autenticação, reassociação, handshake (se não houver FT) e primeiro tráfego. */
function roamTo(c: Ctx, ft: boolean) {
  const { tr, R } = c;
  tr.phase('Procurar o AP-02 (canal 6)', 'scan');
  tr.st(tr.t, 'phase', 'procurando', 'warn');
  tx(c, 'sta', 'ap2', { label: 'Probe Request (SSID ' + SSID + ')', gap: DIFS + 3 * SLOT, d: { type: 'mgmt', sub: 'Probe Request', subNum: 4, ra: BROADCAST, ta: MAC.sta, bssid: BROADCAST, dur: '0', seq: c.seq++, body: [{ sec: 'Corpo do Probe Request' }, ssidIe(SSID), ratesIe, htIe] }, len: LEN.probeReq + 8, dur: T_MGMT, info: 'procura o AP-02 no canal 6', about: 'O cliente sintoniza o canal do candidato e pergunta pelo nome da rede. Durante a varredura ele não está no canal do AP-01.', phaseName: 'Busca' });
  tx(c, 'ap2', 'sta', { label: 'Probe Response', gap: DIFS + 2 * SLOT, d: mgmt(c, 'Probe Response', 5, 'ap2', 'sta', probeRespBody(6, true), MAC.ap2), len: LEN.probeResp, dur: T_MGMT + 0.05, info: 'AP-02, canal 6, sinal -58 dBm', about: 'O AP-02 responde com o mesmo SSID e o BSSID dele.', phaseName: 'Busca' });
  ack(c, 'sta', 'ap2');
  setSta(c, 1, 'saindo do AP-01 (estado 1 no AP-02)');
  tr.phase('Autenticar e reassociar no AP-02', 'reassoc');
  tr.st(tr.t, 'phase', 'reassociação', 'warn');
  const auth = (n: number): Dot11['body'] => [
    { sec: 'Corpo da Authentication' },
    ['Authentication Algorithm', ft ? '2 (Fast BSS Transition)' : '0 (Open System)', ft ? 'FT: o cliente já leva a chave derivada para o AP-02 (802.11r)' : 'sistema aberto: só cumpre o ritual'],
    ['Transaction Sequence', String(n), ''],
    ['Status Code', '0 (sucesso)', ''],
    ...(ft ? [['FT IEs', 'MDE, FTE (SNonce, ANonce, R0KH-ID, R1KH-ID)', 'informações para derivar a chave do AP-02 sem o handshake completo'] as Field] : []),
  ];
  tx(c, 'sta', 'ap2', { label: ft ? 'Authentication FT (1)' : 'Authentication (1)', gap: DIFS + 4 * SLOT, d: mgmt(c, 'Authentication', 11, 'sta', 'ap2', auth(1), MAC.ap2), len: LEN.auth + (ft ? 120 : 0), dur: T_MGMT, info: ft ? 'algoritmo 2 (FT)' : 'algoritmo 0 (aberto)', about: 'Para o AP-02 o cliente ainda está no estado 1: precisa autenticar e associar de novo.', phaseName: 'Reassociação' });
  ack(c, 'ap2', 'sta');
  tx(c, 'ap2', 'sta', { label: ft ? 'Authentication FT (2)' : 'Authentication (2)', gap: DIFS + 2 * SLOT, d: mgmt(c, 'Authentication', 11, 'ap2', 'sta', auth(2), MAC.ap2), len: LEN.auth + (ft ? 120 : 0), dur: T_MGMT, info: 'status 0', about: 'O AP-02 aceita a autenticação.', phaseName: 'Reassociação' });
  ack(c, 'sta', 'ap2');
  tx(c, 'sta', 'ap2', { label: 'Reassociation Request', gap: DIFS + 5 * SLOT, d: mgmt(c, 'Reassociation Request', 2, 'sta', 'ap2', [{ sec: 'Corpo da Reassociation Request' }, capField(true), ['Listen Interval', '10', ''], ['Current AP Address', MAC.ap1, 'o AP de onde o cliente vem: o AP-02 usa isto para avisar o AP-01'], ssidIe(SSID), ratesIe, htIe, rsnIe], MAC.ap2), len: LEN.assocReq + 6, dur: T_MGMT + 0.06, info: 'vem do AP-01 (' + MAC.ap1 + ')', about: 'Igual à Association Request, mas com o endereço do AP anterior. Isso diz ao AP-02 que é uma troca de AP dentro do mesmo ESS, e não uma entrada nova.', phaseName: 'Reassociação' });
  ack(c, 'ap2', 'sta');
  tr.ev(tr.t, 'ap2', 'Avisa o AP-01, pela rede cabeada, que o cliente se reassociou (o mecanismo depende do fabricante: o IEEE 802.11F foi retirado)', '');
  tx(c, 'ap2', 'sta', { label: 'Reassociation Response', gap: DIFS + 2 * SLOT, d: mgmt(c, 'Reassociation Response', 3, 'ap2', 'sta', [{ sec: 'Corpo da Reassociation Response' }, capField(true), ['Status Code', '0 (sucesso)', ''], ['Association ID (AID)', '1', ''], ratesIe, htIe], MAC.ap2), len: LEN.assocResp, dur: T_MGMT, info: 'status 0, AID 1', about: 'O AP-02 aceita. O cliente passa a estar associado ao AP-02, e o AP-01 libera o registro dele.', phaseName: 'Reassociação' });
  ack(c, 'sta', 'ap2');
  setSta(c, 3, 'associado ao AP-02');
  tr.ev(tr.t, 'ap1', 'Libera o registro do cliente e encaminha ao AP-02 os quadros que tinha guardado', '');
  if (!ft) {
    tr.phase('Handshake de quatro vias (resumido)', 'hs');
    tr.st(tr.t, 'phase', 'handshake', 'warn');
    const eapol = (n: number, up: boolean): void => {
      tr.add(up ? 'sta' : 'ap2', up ? 'ap2' : 'sta', { at: tr.t + (n === 1 ? DIFS : SIFS), dur: 0.3, proc: 1, label: 'EAPOL-Key ' + n + '/4', proto: 'EAPOL (802.1X)', color: C0.enc, len: LEN.eapol, fields: [{ sec: 'EAPOL-Key (IEEE 802.1X e 802.11)' }, ['Mensagem', n + ' de 4', ['o AP envia o ANonce', 'o cliente envia o SNonce e o MIC', 'o AP instala a chave e envia a GTK', 'o cliente confirma'][n - 1]], ['Valor ilustrativo', hex('eapol' + n, 8), 'sem criptografia real no simulador']], info: 'mensagem ' + n + ' de 4', about: 'Resumo do handshake que deriva as chaves do novo AP. Os detalhes estão no simulador Wi-Fi: segurança.', phaseName: 'Handshake' });
    };
    [1, 2, 3, 4].forEach((n) => eapol(n, n % 2 === 0));
    tr.ev(tr.t, 'ap2', 'A porta controlada do AP-02 abre: os dados do cliente passam a ser aceitos', 'ok');
  } else {
    tr.ev(tr.t, 'ap2', 'Com o Fast BSS Transition, as chaves já foram derivadas na troca de Authentication e Reassociation: não há handshake de quatro vias', 'ok');
  }
  tr.phase('Tráfego pelo AP-02', 'ap2');
  tr.st(tr.t, 'phase', 'conectado ao AP-02', 'est');
  tr.add('ap2', 'lan', { at: tr.t + 0.02, dur: 0.05, proc: 0, label: 'Anúncio do MAC do cliente', proto: 'Ethernet', color: C0.data, len: 64, fields: [{ sec: 'Ethernet II' }, ['Origem', MAC.sta, 'o MAC do cliente, agora atrás do AP-02'], ['EtherType', '0x0800', '(quadro de anúncio, conteúdo ilustrativo)']], info: 'atualiza a tabela MAC do switch', about: 'O AP-02 envia um quadro com o MAC do cliente à rede cabeada. Sem isso, o switch continuaria enviando o tráfego de volta pelo AP-01 até aprender a nova porta.' });
  R.tFirstNew = tr.t + DIFS + 3 * SLOT;
  const dm = tx(c, 'sta', 'ap2', { label: 'Dados (54 Mb/s)', gap: DIFS + 3 * SLOT, d: { type: 'data', sub: 'Data', subNum: 0, ra: MAC.ap2, ta: MAC.sta, bssid: BROADCAST, dur: String(us(SIFS + T_ACK)), toDs: true, seq: c.seq++, body: [{ sec: 'Corpo' }, ['Payload', '1500 bytes (IP)', 'primeiro quadro pelo AP-02']] }, len: LEN.data, dur: T_DATA, info: 'volta a trafegar, a 54 Mb/s', about: 'O tráfego volta pelo novo AP, com sinal forte e taxa alta.', phaseName: 'AP-02' });
  R.tFirstNew = dm.tSend;
  ack(c, 'ap2', 'sta');
  R.rssi.push({ t: tr.t, ap1: -78, ap2: -58 });
}

// economia de energia

function buildPs(P: MovParams): Trace {
  const L = P.lis;
  const c = ctx('mov', ['sta', 'ap1', 'lan'], STATES_MOV, { ap1: { sub: 'ponto de acesso' } }, { mov: 'ps', lis: L, ps: {} });
  const { tr, R } = c;
  begin(c);
  setSta(c, 3, 'acordado');
  tr.phase('1. Avisar o AP que vai dormir', 'dormir');
  tr.st(0, 'phase', 'avisando o AP', 'warn');
  tx(c, 'sta', 'ap1', { label: 'Null Data (PM=1)', gap: 1, d: { type: 'data', sub: 'Null function (sem dados)', subNum: 4, ra: MAC.ap1, ta: MAC.sta, bssid: MAC.ap1, dur: String(us(SIFS + T_ACK)), toDs: true, pm: true, seq: c.seq++, body: [{ sec: 'Corpo' }, ['Payload', '(vazio)', 'um quadro sem dados serve só para carregar o bit PM']] }, len: LEN.nullData, dur: 0.06, info: 'bit Power Management = 1', about: 'O cliente avisa que vai entrar em economia de energia (PM=1). Daqui em diante o AP guarda os quadros destinados a ele, em vez de transmiti-los.', phaseName: 'Dormir' });
  ack(c, 'ap1', 'sta');
  tr.st(tr.t, 'sta', 'dormindo (PM=1)', 'closed');
  tr.ev(tr.t, 'sta', 'Desliga o rádio entre os beacons. Só acorda a cada ' + L + (L === 1 ? ' beacon' : ' beacons') + ' (o Listen Interval informado na associação)', '');
  tr.ev(tr.t, 'ap1', 'Passa a guardar os quadros do cliente (AID 1) e a marcar o bit dele no TIM dos beacons', '');

  const arrival = 150;
  const k0 = Math.floor(arrival / BEACON_INTERVAL) + 1;
  let kWake = k0;
  while (kWake % L !== 0) kWake++;
  const heard: number[] = [];
  const beaconTim = (k: number) => (k >= k0 ? 'AID 1 marcado: há quadros guardados' : 'bitmap vazio');
  tr.phase('2. Os beacons passam e chega um pacote', 'beacons');
  tr.st(tr.t, 'phase', 'dormindo', 'warn');
  let arrived = false;
  for (let k = 1; k <= kWake; k++) {
    const tb = k * BEACON_INTERVAL;
    if (!arrived && arrival < tb) {
      tr.t = arrival;
      tr.add('lan', 'ap1', { at: arrival, dur: 0.05, proc: 0, label: 'Pacote IP para o cliente', proto: 'Ethernet', color: C0.data, len: 1514, fields: [{ sec: 'Ethernet II' }, ['Destino', MAC.sta, 'o cliente que está dormindo'], ['EtherType', '0x0800', 'IPv4']], info: 'chega quando o cliente dorme', about: 'Um pacote chega da rede cabeada para um cliente em economia de energia.' });
      tr.ev(arrival + 0.05, 'ap1', 'Guarda o quadro: o cliente está dormindo. Marcará o AID 1 no TIM do próximo beacon', 'warn');
      arrived = true;
    }
    const m = k % L === 0;
    if (m) {
      tr.st(tb - 1, 'sta', 'acordado para o beacon ' + k, 'warn');
      tx(c, 'ap1', 'sta', { label: 'Beacon ' + k, at: tb, d: { type: 'mgmt', sub: 'Beacon', subNum: 8, ra: BROADCAST, ta: MAC.ap1, bssid: MAC.ap1, dur: '0', seq: c.seq++, body: beaconBody(1, false, true, 'DTIM 0, período 1; ' + beaconTim(k)) }, len: LEN.beacon, dur: T_BEACON, info: 'TIM: ' + beaconTim(k), about: 'O TIM (Traffic Indication Map) diz a cada cliente dormindo se há quadros guardados. O cliente acorda para ouvir o beacon e confere o bit do seu AID.', phaseName: 'Beacon ' + k });
      heard.push(k);
      if (k < kWake) {
        tr.ev(tb + T_BEACON, 'sta', 'Acordou, ouviu o beacon ' + k + ' e viu que não há nada para ele: volta a dormir', '');
        tr.st(tb + T_BEACON, 'sta', 'dormindo (PM=1)', 'closed');
      }
    } else {
      tr.ev(tb, 'ap1', 'Envia o beacon ' + k + (k >= k0 ? ' (TIM com o AID 1 marcado)' : '') + ', mas o cliente dorme e não o ouve', k >= k0 ? 'warn' : '');
    }
  }
  tr.t = kWake * BEACON_INTERVAL + T_BEACON;
  tr.ev(tr.t, 'sta', 'Vê o AID 1 marcado no TIM: há um quadro guardado para ele. Pede a entrega', 'ok');
  tr.phase('3. Buscar o quadro guardado', 'psPoll');
  tr.st(tr.t, 'phase', 'buscando o quadro', 'warn');
  tr.st(tr.t, 'sta', 'acordado: buscando o quadro', 'warn');
  tx(c, 'sta', 'ap1', { label: 'PS-Poll', gap: DIFS + 2 * SLOT, d: { type: 'ctrl', sub: 'PS-Poll', subNum: 10, ra: MAC.ap1, ta: MAC.sta, dur: 'AID 1 (bits 14 e 15 ligados: 0xC001)' }, len: LEN.psPoll, dur: T_ACK, info: 'pede o quadro guardado', about: 'O cliente pede ao AP, por controle, que entregue o quadro guardado. O campo Duration/ID leva o AID, e não uma duração.', phaseName: 'PS-Poll' });
  const delivery = tx(c, 'ap1', 'sta', { label: 'Dados guardados', gap: SIFS, d: { type: 'data', sub: 'Data', subNum: 0, ra: MAC.sta, ta: MAC.ap1, bssid: MAC.ap1, dur: String(us(SIFS + T_ACK)), fromDs: true, more: false, seq: c.seq++, body: [{ sec: 'Corpo' }, ['Payload', '1500 bytes (IP)', 'o pacote que chegou durante o sono']] }, len: LEN.data, dur: T_DATA, info: 'More Data=0: era o último', about: 'O AP entrega o quadro guardado. Com More Data=0 o cliente sabe que não há mais nada e pode voltar a dormir. O quadro de dados serve também de confirmação do PS-Poll.', phaseName: 'Entrega' });
  ack(c, 'sta', 'ap1');
  tr.ev(tr.t, 'sta', 'Recebeu o quadro e viu More Data=0: volta a dormir, ainda em economia de energia', 'ok');
  tr.st(tr.t, 'sta', 'dormindo (PM=1)', 'closed');
  const latency = delivery.tArr - arrival;
  R.ps = { L, arrival, k0, kWake, heard, delivered: delivery.tArr, latency, wakes: heard.length };
  finish(c, 'ps', 'entregue com ' + fmtTime(latency) + ' de atraso', 'est');
  return tr;
}

/** Estimativa para qualquer Listen Interval, com a mesma chegada, usada pela aba Energia. */
export function psEstimate(L: number, arrival = 150): { latency: number; wakes: number; awake: number } {
  const k0 = Math.floor(arrival / BEACON_INTERVAL) + 1;
  let k = k0;
  while (k % L !== 0) k++;
  const wakes = Math.floor(k / L);
  const delivered = k * BEACON_INTERVAL + T_BEACON + DIFS + 2 * SLOT + T_ACK + SIFS + T_DATA;
  return { latency: delivered - arrival, wakes, awake: wakes * WAKE_MS + (T_ACK + T_DATA + T_ACK) };
}

// ---- 4. Canais ----

export interface CanalParams {
  ch2: number;
  larg: number;
}

const STATES_CANAL: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'rel', label: 'Relação entre as duas redes' },
  { key: 'res', label: 'Resultado' },
];

export type CanalRel = 'indep' | 'co' | 'adj';

/** Dois canais de 20 MHz precisam de pelo menos 25 MHz entre os centros; para 40 MHz, de 45 MHz (centros a cada 5 MHz). */
export function canalRel(ch1: number, ch2: number, larg: number): CanalRel {
  const d = Math.abs(ch1 - ch2);
  if (d === 0) return 'co';
  return d * 5 >= larg + 5 ? 'indep' : 'adj';
}

export function buildCanal(P: CanalParams): Trace {
  const rel = canalRel(1, P.ch2, P.larg);
  const c = ctx('canal', ['sta1', 'ap1', 'sta2', 'ap2'], STATES_CANAL, { ap1: { sub: 'canal 1, ' + P.larg + ' MHz' }, ap2: { sub: 'canal ' + P.ch2 + ', ' + P.larg + ' MHz' } }, { ch2: P.ch2, larg: P.larg, rel, attempts: [] as any[], collisions: 0 });
  const { tr, R } = c;
  begin(c);
  const REL_TXT: Record<CanalRel, [string, string]> = { indep: ['independentes', 'est'], co: ['mesmo canal: dividem o tempo', 'warn'], adj: ['canais sobrepostos: interferem', 'bad'] };
  tr.st(0, 'rel', REL_TXT[rel][0], REL_TXT[rel][1]);
  tr.st(0, 'phase', 'esperando o meio', 'warn');
  const dataD = (k: string, ap: string, seq: number, retry: boolean): Dot11 => ({ type: 'data', sub: 'Data', subNum: 0, ra: MAC[ap], ta: MAC[k], bssid: MAC[ap], dur: String(us(SIFS + T_ACK)), toDs: true, retry, seq, body: [{ sec: 'Corpo' }, ['Payload', '1500 bytes (IP)', '']] });
  const ex = (k: string, ap: string, start: number, seq: number, retry = false): number => {
    tr.t = start;
    tx(c, k, ap, { label: 'Dados' + (retry ? ' (repetição)' : ''), d: dataD(k, ap, seq, retry), len: LEN.data, dur: T_DATA, info: 'rede de ' + (k === 'sta1' ? 'canal 1' : 'canal ' + P.ch2), about: 'Um quadro de dados de 1500 bytes na rede ' + (k === 'sta1' ? '1' : '2') + '.' });
    const am = ack(c, ap, k);
    return am.tArr;
  };
  const t0 = 0.2;
  tr.ev(0, 'sta1', 'Os dois clientes têm um quadro para enviar ao mesmo tempo', '');
  tr.ev(t0, 'sta1', 'Meio livre por um DIFS. Sorteia 3 slots', '');
  tr.ev(t0, 'sta2', 'Meio livre por um DIFS. Sorteia 5 slots', '');
  tr.phase('Transmissão das duas redes', 'tx');
  tr.st(t0, 'phase', 'transmitindo', 'warn');
  const t1 = t0 + DIFS + 3 * SLOT;
  const t2 = t0 + DIFS + 5 * SLOT;
  const log = (t: number, who: string, cw: number, bo: number, result: string) => (R.attempts as any[]).push({ t, who, cw, bo, result });

  if (rel === 'indep') {
    tr.ev(t1, 'ap2', 'Canal ' + P.ch2 + ' é independente do canal 1: o sinal da outra rede não chega a ocupar este canal', 'ok');
    const e1 = ex('sta1', 'ap1', t1, 400);
    const e2 = ex('sta2', 'ap2', t2, 500);
    log(t1, 'Cliente 1', 15, 3, 'sucesso');
    log(t2, 'Cliente 2', 15, 5, 'sucesso');
    tr.ev(Math.max(e1, e2), 'ap1', 'As duas redes transmitiram ao mesmo tempo, sem se atrapalhar', 'ok');
    R.total = Math.max(e1, e2) - t0;
    tr.t = Math.max(e1, e2);
    finish(c, 'indep', 'as duas entregues em paralelo', 'est');
    return tr;
  }
  if (rel === 'co') {
    tr.ev(t1, 'sta2', 'Ouve a transmissão do Cliente 1 no mesmo canal: o meio está ocupado. Congela o contador em 2 slots', 'warn');
    const e1 = ex('sta1', 'ap1', t1, 400);
    log(t1, 'Cliente 1', 15, 3, 'sucesso');
    tr.ev(e1 + DIFS, 'sta2', 'Meio livre por um DIFS: retoma a contagem (2 slots)', '');
    const e2 = ex('sta2', 'ap2', e1 + DIFS + 2 * SLOT, 500);
    log(e1 + DIFS + 2 * SLOT, 'Cliente 2', 15, 5, 'sucesso');
    tr.ev(e2, 'ap2', 'Mesmo canal: as duas redes dividiram o tempo de ar, uma de cada vez', 'warn');
    R.total = e2 - t0;
    tr.t = e2;
    finish(c, 'co', 'entregues em sequência', 'est');
    return tr;
  }
  // canais sobrepostos: as transmissões se atrapalham e as duas se perdem até a sorte do backoff separá-las
  const rounds: Round2[] = [
    { cw: 15, a: 3, b: 5 },
    { cw: 31, a: 4, b: 20 },
    { cw: 63, a: 2, b: 40 },
  ];
  let idle = t0;
  for (let i = 0; i < rounds.length; i++) {
    const r = rounds[i];
    const tA = idle + DIFS + r.a * SLOT;
    const tB = idle + DIFS + r.b * SLOT;
    const overlap = Math.abs(tA - tB) < T_DATA;
    if (i > 0) {
      tr.phase('Rodada ' + (i + 1) + ': janela até ' + r.cw, 'r' + (i + 1));
      tr.ev(idle, 'sta1', 'Sorteou ' + r.a + ' slots em [0, ' + r.cw + ']', '');
      tr.ev(idle, 'sta2', 'Sorteou ' + r.b + ' slots em [0, ' + r.cw + ']', '');
    }
    if (overlap) {
      const mk = (k: string, ap: string, t: number) => tx(c, k, ap, { label: 'Dados (corrompido)', at: t, par: true, lost: true, color: C0.bad, d: dataD(k, ap, 400, i > 0), len: LEN.data, dur: T_DATA, info: 'sobreposto ao sinal da outra rede', about: 'Os canais se sobrepõem em frequência: o sinal de uma rede entra na faixa da outra e corrompe o quadro, mas o outro cliente não o reconhece como "mesma rede" para esperar a vez.' });
      const m1 = mk('sta1', 'ap1', tA);
      const m2 = mk('sta2', 'ap2', tB);
      log(tA, 'Cliente 1', r.cw, r.a, 'corrompido');
      log(tB, 'Cliente 2', r.cw, r.b, 'corrompido');
      R.collisions++;
      const end = Math.max(m1.tArr, m2.tArr);
      tr.ev(end, 'ap1', 'Os dois quadros chegaram corrompidos pela interferência do canal vizinho (FCS inválido)', 'bad');
      idle = end + ACK_TIMEOUT;
      tr.ev(idle, 'sta1', 'Sem ACK: dobra a janela e repete', 'warn');
      tr.ev(idle, 'sta2', 'Sem ACK: dobra a janela e repete', 'warn');
      tr.st(end, 'phase', 'repetindo', 'warn');
      continue;
    }
    const e1 = ex('sta1', 'ap1', tA, 400, i > 0);
    const e2 = ex('sta2', 'ap2', Math.max(tB, e1 + DIFS), 500, i > 0);
    log(tA, 'Cliente 1', r.cw, r.a, 'sucesso');
    log(Math.max(tB, e1 + DIFS), 'Cliente 2', r.cw, r.b, 'sucesso');
    tr.ev(e2, 'ap2', 'Só depois de ' + R.collisions + ' rodadas corrompidas os quadros ficaram separados no tempo', 'ok');
    R.total = e2 - t0;
    tr.t = e2;
    break;
  }
  finish(c, 'adj', R.collisions + ' rodadas perdidas, depois entregues', 'est');
  return tr;
}

interface Round2 {
  cw: number;
  a: number;
  b: number;
}

