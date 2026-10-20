// Motor do simulador das versões do HTTP (RFC 9110, 9112, 9113 e 9114): o carregamento de uma página com vários
// recursos em HTTP/1.1, HTTP/2 e HTTP/3. Função pura: dados os parâmetros, devolve o Trace. O modelo é didático:
// a largura de banda do enlace é dividida em partes iguais entre as respostas em andamento (sem slow start), e os
// tamanhos de cabeçalho são ilustrativos.
import { COLORS as C, newTrace, type Column, type Field, type StateDef, type Trace } from '../../sim-core';

export type Version = 'h1' | 'h2' | 'h3';

export interface HttpParams {
  rtt: number;
  res: number;
  big: boolean;
  loss: boolean;
  tls: boolean;
  conns: number;
  resume: boolean;
  udpBlocked: boolean;
}

export const HOST = 'www.example.com';
export const CLIENT_IP = '198.51.100.10';
export const SERVER_IP = '203.0.113.80';
/** Capacidade do enlace em KB por ms (10 Mbit/s). */
export const BW = 1.25;
/** Tempo de processamento do servidor antes do primeiro byte da resposta (ms). */
export const SRV_MS = 10;
/** Espera do navegador por uma resposta QUIC antes de recorrer ao TCP (valor ilustrativo, ms). */
export const FALLBACK_MS = 300;
/** Fração da resposta já enviada quando o pacote é perdido. */
export const LOSS_AT = 0.5;
/** Recurso cuja resposta sofre a perda de pacote. */
export const VICTIM = '/app.js';

export const VERSION_NAME: Record<Version, string> = { h1: 'HTTP/1.1', h2: 'HTTP/2', h3: 'HTTP/3' };

export interface Res {
  path: string;
  type: string;
  kb: number;
}

const BASE: Res[] = [
  { path: '/index.html', type: 'text/html; charset=utf-8', kb: 20 },
  { path: '/style.css', type: 'text/css', kb: 40 },
  { path: VICTIM, type: 'text/javascript', kb: 120 },
  { path: '/logo.png', type: 'image/png', kb: 12 },
  { path: '/foto1.jpg', type: 'image/jpeg', kb: 60 },
  { path: '/foto2.jpg', type: 'image/jpeg', kb: 60 },
  { path: '/fonte.woff2', type: 'font/woff2', kb: 30 },
  { path: '/icones.svg', type: 'image/svg+xml', kb: 8 },
];
const EXTRA: Res[] = [
  ...[1, 2, 3, 4, 5, 6].map((n) => ({ path: `/img/p${n}.jpg`, type: 'image/jpeg', kb: 25 })),
  { path: '/api/dados.json', type: 'application/json', kb: 6 },
  { path: '/analytics.js', type: 'text/javascript', kb: 35 },
];
const HERO: Res = { path: '/hero.jpg', type: 'image/jpeg', kb: 400 };

/** Recursos da página, em ordem de aparição no HTML: o primeiro é sempre o documento. */
export function catalog(P: Pick<HttpParams, 'res' | 'big'>): Res[] {
  const n = P.res >= 16 ? 16 : P.res >= 8 ? 8 : 4;
  const all = [...BASE, ...EXTRA].slice(0, n);
  if (P.big) all.splice(1, 0, HERO);
  return all;
}

/** Bytes de cabeçalho por mensagem: [primeira da conexão, seguintes]. Valores ilustrativos (HPACK e QPACK). */
const HDR: Record<Version, { req: [number, number]; res: [number, number] }> = {
  h1: { req: [620, 620], res: [380, 380] },
  h2: { req: [330, 52], res: [280, 48] },
  h3: { req: [340, 56], res: [285, 50] },
};

export const STATES: StateDef[] = [
  { key: 'proto', label: 'Protocolo' },
  { key: 'conn', label: 'Conexões' },
  { key: 'prog', label: 'Recursos recebidos' },
  { key: 'net', label: 'Rede' },
];

export const COLUMNS: Column[] = [
  { key: 'cli', label: 'Navegador', sub: 'cliente', addr: CLIENT_IP },
  { key: 'srv', label: HOST, sub: 'servidor', addr: SERVER_IP },
];

export interface Job {
  idx: number;
  res: Res;
  conn: number;
  /** Identificador do fluxo (HTTP/2: ímpar; HTTP/3: múltiplo de 4); 0 no HTTP/1.1. */
  stream: number;
  reqSend: number;
  reqArr: number;
  start: number;
  kb: number;
  rem: number;
  end: number;
  rawArr: number;
  arr: number;
  hold: 'none' | 'victim' | 'hol';
  done: boolean;
  reqBytes: number;
  resBytes: number;
}

export interface Metrics {
  ready: number;
  rttsBeforeRequest: number;
  ttfb: number;
  tHtml: number;
  tDone: number;
  conns: number;
  hdrBytes: number;
  totalKB: number;
  delayed: number;
  delayedMs: number;
}

export interface JournalEntry { type: string; t: number; [k: string]: any }

interface Conn { id: number; openAt: number; readyAt: number; freeAt: number; busy: boolean }

interface Sched {
  jobs: Job[];
  conns: Conn[];
  lossT: number;
  recT: number;
  tHtml: number;
}

const r1 = (x: number) => Math.round(x * 10) / 10;
const EPS = 1e-9;

/** Instante (ms) em que o primeiro pedido pode ser enviado, contado a partir de t0. */
function readyAfter(P: HttpParams, eff: Version, t0: number): number {
  if (eff === 'h1') return t0 + (P.tls ? 2 : 1) * P.rtt;
  if (eff === 'h2') return t0 + 2 * P.rtt;
  return t0 + (P.resume ? 0 : P.rtt);
}

/** Núcleo temporal: pedidos, divisão da banda entre as respostas e efeito da perda de pacote. */
function schedule(P: HttpParams, eff: Version, ready: number): Sched {
  const rtt = P.rtt;
  const ow = rtt / 2;
  const list = catalog(P);
  const hdr = HDR[eff];
  const tlsOn = eff !== 'h1' || P.tls;
  let sent = 0;
  const mk = (idx: number, conn: number, reqSend: number): Job => {
    const first = eff === 'h1' ? false : idx === 0;
    const reqBytes = hdr.req[first || eff === 'h1' ? 0 : 1];
    const resHdr = hdr.res[first || eff === 'h1' ? 0 : 1];
    const kb = list[idx].kb + resHdr / 1024;
    const stream = eff === 'h2' ? 1 + 2 * sent : eff === 'h3' ? 4 * sent : 0;
    sent++;
    const reqArr = reqSend + ow;
    const start = reqArr + SRV_MS;
    return { idx, res: list[idx], conn, stream, reqSend, reqArr, start, kb, rem: kb, end: 0, rawArr: 0, arr: 0, hold: 'none', done: false, reqBytes, resBytes: Math.round(list[idx].kb * 1024 + resHdr) };
  };

  const html = mk(0, 1, ready);
  html.end = html.start + html.kb / BW;
  html.rawArr = html.end + ow;
  html.arr = html.rawArr;
  html.done = true;
  html.rem = 0;
  const tHtml = html.arr;

  const jobs: Job[] = [html];
  const conns: Conn[] = [{ id: 1, openAt: 0, readyAt: ready, freeAt: tHtml, busy: false }];
  let queue: number[] = [];
  const subs = list.length - 1;
  if (eff === 'h1') {
    for (let k = 2; k <= Math.min(P.conns, subs); k++) {
      const readyAt = tHtml + (tlsOn ? 2 : 1) * rtt;
      conns.push({ id: k, openAt: tHtml, readyAt, freeAt: readyAt, busy: false });
    }
    queue = list.slice(1).map((_, i) => i + 1);
  } else {
    for (let i = 1; i < list.length; i++) jobs.push(mk(i, 1, tHtml));
  }

  let t = tHtml;
  let lossT = -1;
  let lossFired = false;
  const recOf = () => lossT + rtt + ow;

  for (let guard = 0; guard < 100000; guard++) {
    if (eff === 'h1') {
      for (const c of conns) {
        if (!queue.length) break;
        if (!c.busy && c.freeAt <= t + EPS) {
          c.busy = true;
          jobs.push(mk(queue.shift()!, c.id, c.freeAt));
        }
      }
    }
    const active = jobs.filter((j) => !j.done && j.start <= t + EPS);
    let dt = Infinity;
    jobs.forEach((j) => {
      if (!j.done && j.start > t + EPS) dt = Math.min(dt, j.start - t);
    });
    if (eff === 'h1' && queue.length) conns.forEach((c) => { if (!c.busy && c.freeAt > t + EPS) dt = Math.min(dt, c.freeAt - t); });
    const rate = active.length ? BW / active.length : 0;
    const victim = active.find((j) => j.res.path === VICTIM);
    const thr = victim ? victim.kb * (1 - LOSS_AT) : 0;
    if (active.length) {
      active.forEach((j) => { dt = Math.min(dt, j.rem / rate); });
      if (P.loss && !lossFired && victim && victim.rem > thr + EPS) dt = Math.min(dt, (victim.rem - thr) / rate);
    }
    if (!isFinite(dt)) break;
    active.forEach((j) => { j.rem -= rate * dt; });
    t += dt;
    if (P.loss && !lossFired && victim && victim.rem <= thr + EPS) {
      lossFired = true;
      lossT = t;
    }
    for (const j of active) {
      if (j.rem > EPS) continue;
      j.rem = 0;
      j.done = true;
      j.end = t;
      j.rawArr = t + ow;
      j.arr = j.rawArr;
      if (lossFired) {
        const rec = recOf();
        if (j.res.path === VICTIM) {
          if (j.arr < rec - EPS) { j.arr = rec; j.hold = 'victim'; }
        } else if (eff === 'h2' && j.rawArr > lossT + ow + EPS && j.rawArr < rec - EPS) {
          // TCP entrega os bytes em ordem: tudo o que chegou depois do buraco espera a retransmissão
          j.arr = rec;
          j.hold = 'hol';
        }
      }
      if (eff === 'h1') {
        const c = conns.find((x) => x.id === j.conn)!;
        c.busy = false;
        c.freeAt = j.arr;
      }
    }
  }
  return { jobs, conns, lossT: lossFired ? lossT : -1, recT: lossFired ? recOf() : -1, tHtml };
}

function tcpFields(kind: string, port: number, from: 'c' | 's', detail: string, dstPort: number): Field[] {
  const c = from === 'c';
  return [
    { sec: 'IPv4' }, ['Origem', c ? CLIENT_IP : SERVER_IP, ''], ['Destino', c ? SERVER_IP : CLIENT_IP, ''], ['Protocolo', 'TCP (6)', ''],
    { sec: 'TCP' }, ['Porta de origem', String(c ? 50000 + port : dstPort), c ? 'porta efêmera do navegador' : ''], ['Porta de destino', String(c ? dstPort : 50000 + port), ''],
    ['Flags', kind, detail],
  ];
}
const UA = 'Navegador-Exemplo/1.0';

/** Constrói o trace de uma carga de página na versão pedida. */
export function buildHttp(P: HttpParams, sub: string): Trace {
  const version: Version = sub === 'h2' || sub === 'h3' ? sub : 'h1';
  const rtt = P.rtt;
  const ow = rtt / 2;
  const fallback = version === 'h3' && P.udpBlocked;
  const eff: Version = fallback ? 'h2' : version;
  const t0 = fallback ? FALLBACK_MS : 0;
  const tlsOn = eff !== 'h1' || P.tls;
  const srvPort = tlsOn ? 443 : 80;
  const ready = readyAfter(P, eff, t0);
  const S = schedule(P, eff, ready);
  const list = catalog(P);
  const N = list.length;

  const tr = newTrace(COLUMNS, STATES, rtt);
  const journal: JournalEntry[] = [];
  const ev = (t: number, who: string, text: string, k = '') => tr.ev(r1(t), who, text, k);
  const lg = (t: number, text: string, tag = 'sys') => tr.lg(r1(t), text, tag);
  const st = (t: number, key: string, val: string, cls = '') => tr.st(r1(t), key, val, cls);
  const mile = (t: number, label: string, sub = '') => tr.mile(r1(t), label, sub);
  const phase = (t: number, label: string, key: string) => { tr.t = r1(t); tr.phase(label, key); };
  tr.raw = { sub: version, eff, P, journal, jobs: S.jobs, conns: S.conns, resources: list, tHtml: S.tHtml, lossT: S.lossT, recT: S.recT, t0, ready };

  type Intent = { from: string; to: string; ts: number; ta: number; o: Record<string, unknown> };
  const out: Intent[] = [];
  const put = (from: string, to: string, ts: number, ta: number, o: Record<string, unknown>) => out.push({ from, to, ts: r1(ts), ta: r1(ta), o });
  const proto = VERSION_NAME[eff];
  let pn = 0;

  // ---- abertura da conexão ----
  const hello = (alpnOffer: string, alpnPick: string, quic: boolean): Field[] => [
    { sec: quic ? 'QUIC Initial (CRYPTO)' : 'TLS 1.3: ClientHello' },
    ['Versões (supported_versions)', 'TLS 1.3', 'o TLS 1.3 completa a troca de chaves em 1 RTT'],
    ['SNI (server_name)', HOST, 'nome do servidor, em claro no ClientHello'],
    ['ALPN', alpnOffer, 'protocolos de aplicação oferecidos pelo cliente'],
    ['key_share', 'X25519', 'o cliente já envia sua parte da troca de chaves'],
    ['Resposta esperada (ALPN)', alpnPick, 'o servidor escolhe um protocolo da lista'],
  ];
  const alpnOffer = eff === 'h3' ? 'h3' : 'h2, http/1.1';
  const alpnPick = eff === 'h1' ? 'http/1.1' : eff;
  const connectNote = (id: number) => (eff === 'h1' && P.conns > 1 ? ['conexão ' + id] : []);

  const openTcp = (id: number, at: number, withTls: boolean) => {
    // 3-way handshake (e TLS 1.3) de uma conexão que começa em 'at'. Devolve o instante em que ela está pronta.
    put('cli', 'srv', at, at + ow, { label: 'SYN', proto: 'TCP', color: C.tcp, len: 60, tags: connectNote(id), fields: tcpFields('SYN', id, 'c', 'abre a conexão; opções: MSS 1460, SACK, escala de janela', srvPort), about: 'O cliente pede a abertura da conexão TCP (três vias).', phaseName: 'TCP' });
    put('srv', 'cli', at + ow, at + rtt, { label: 'SYN/ACK', proto: 'TCP', color: C.tcp, len: 60, tags: connectNote(id), fields: tcpFields('SYN, ACK', id, 's', 'o servidor aceita e confirma', srvPort), about: 'O servidor aceita a conexão.', phaseName: 'TCP' });
    // o terceiro segmento do handshake já leva dados (ACK ligado): ClientHello ou o primeiro GET
    if (!withTls) return at + rtt;
    put('cli', 'srv', at + rtt, at + rtt + ow, { label: 'ACK + ClientHello', proto: 'TLS 1.3', color: C.enc, len: 517, tags: connectNote(id), fields: [{ sec: 'TCP' }, ['Flags', 'ACK, PSH', 'conclui o handshake TCP (1 RTT) e já leva o ClientHello'], ...hello(alpnOffer, alpnPick, false)], about: 'O ACK que conclui o handshake TCP já leva o ClientHello: começa o TLS com versões, SNI, ALPN e a parte do cliente da troca de chaves.', phaseName: 'TLS' });
    put('srv', 'cli', at + rtt + ow, at + 2 * rtt, {
      label: 'ServerHello + Finished', proto: 'TLS 1.3', color: C.enc, enc: true, len: 2800, tags: connectNote(id),
      fields: [{ sec: 'TLS 1.3: resposta do servidor' }, ['ServerHello', 'TLS_AES_128_GCM_SHA256, X25519', 'a partir daqui o handshake é cifrado'], ['EncryptedExtensions', 'ALPN: ' + alpnPick, 'protocolo de aplicação escolhido'], ['Certificate', HOST + ' (cadeia X.509)', 'o navegador valida a cadeia e o nome'], ['CertificateVerify', 'assinatura do handshake', ''], ['Finished', 'verify_data', 'o servidor já pode enviar dados da aplicação']],
      about: 'O servidor escolhe os parâmetros, prova sua identidade e termina o handshake.', phaseName: 'TLS',
    });
    return at + 2 * rtt;
  };

  const reqLabel = (j: Job) => 'GET ' + j.res.path;
  const connTag = (j: Job) => (eff === 'h1' ? (S.conns.length > 1 ? ['conexão ' + j.conn] : []) : [(eff === 'h2' ? 'fluxo ' : 'fluxo QUIC ') + j.stream]);

  const reqFields = (j: Job): Field[] => {
    const first = eff !== 'h1' && j.idx === 0;
    const accept = j.res.type.split(';')[0];
    if (eff === 'h1') {
      return [
        ...(tlsOn ? ([{ sec: 'TLS 1.3' }, ['Registro', 'Application Data (cifrado)', 'quem captura vê apenas tamanhos e tempos']] as Field[]) : ([{ sec: 'Transporte' }, ['Cifragem', 'nenhuma', 'o HTTP sem TLS viaja em texto claro']] as Field[])),
        { sec: 'HTTP/1.1 (RFC 9112)' },
        ['Linha de requisição', 'GET ' + j.res.path + ' HTTP/1.1', 'método, alvo e versão, em texto'],
        ['Host', HOST, 'obrigatório no HTTP/1.1'],
        ['User-Agent', UA, 'repetido em todo pedido'],
        ['Accept', accept + ',*/*;q=0.1', 'repetido em todo pedido'],
        ['Accept-Encoding', 'gzip, br', 'repetido em todo pedido'],
        ['Connection', 'keep-alive', 'mantém a conexão para o próximo pedido'],
        ['Cookie', 'sid=7f3a91c2', 'repetido em todo pedido'],
        ['Tamanho do cabeçalho', j.reqBytes + ' bytes', 'sem compressão, em todo pedido'],
      ];
    }
    if (eff === 'h2') {
      return [
        { sec: 'TLS 1.3' }, ['Registro', 'Application Data (cifrado)', ''],
        { sec: 'HTTP/2 (RFC 9113)' },
        ['Quadro', 'HEADERS', 'abre o fluxo e leva os cabeçalhos'],
        ['Fluxo (stream id)', String(j.stream), 'ímpar: iniciado pelo cliente'],
        ['Flags', 'END_STREAM, END_HEADERS', 'o pedido não tem corpo'],
        [':method', 'GET', first ? 'literal; entra na tabela dinâmica' : 'índice da tabela estática (1 byte)'],
        [':scheme', 'https', first ? 'literal' : 'índice da tabela estática'],
        [':authority', HOST, first ? 'literal; entra na tabela dinâmica' : 'índice da tabela dinâmica'],
        [':path', j.res.path, 'valor novo: literal'],
        ['user-agent / accept-encoding / cookie', first ? 'literais' : 'índices', first ? 'indexados para os próximos pedidos (HPACK, RFC 7541)' : 'já na tabela dinâmica do HPACK'],
        ['Tamanho do bloco de cabeçalhos', j.reqBytes + ' bytes', first ? 'primeiro pedido da conexão' : 'comprimido pelo HPACK'],
      ];
    }
    return [
      { sec: 'UDP e QUIC (RFC 9000)' }, ['Porta de destino', '443 (UDP)', ''], ['Pacote', '1-RTT, número ' + ++pn, 'cifrado com as chaves do handshake QUIC'],
      ['Quadro QUIC', 'STREAM (id ' + j.stream + ', FIN)', 'fluxo bidirecional iniciado pelo cliente: 0, 4, 8...'],
      { sec: 'HTTP/3 (RFC 9114)' },
      ['Quadro HTTP/3', 'HEADERS', 'um pedido por fluxo QUIC'],
      [':method / :scheme / :authority', 'GET / https / ' + HOST, first ? 'literais; entram na tabela dinâmica' : 'índices (QPACK, RFC 9204)'],
      [':path', j.res.path, 'valor novo: literal'],
      ['Tamanho do bloco de cabeçalhos', j.reqBytes + ' bytes', first ? 'primeiro pedido' : 'comprimido pelo QPACK'],
    ];
  };

  const resFields = (j: Job): Field[] => {
    const ct = j.res.type;
    const size = String(Math.round(j.res.kb * 1024));
    if (eff === 'h1') {
      return [
        { sec: 'HTTP/1.1 (RFC 9112)' }, ['Linha de status', 'HTTP/1.1 200 OK', ''], ['Content-Type', ct, ''], ['Content-Length', size, 'bytes do corpo'],
        ['Cache-Control', 'max-age=3600', ''], ['Connection', 'keep-alive', 'a conexão fica livre para o próximo pedido'], ['Corpo', j.res.kb + ' KB', 'a resposta ocupa a conexão até o último byte'],
      ];
    }
    const frames = Math.max(1, Math.ceil(j.res.kb * 1024 / 16384));
    if (eff === 'h2') {
      return [
        { sec: 'HTTP/2 (RFC 9113)' }, ['Fluxo (stream id)', String(j.stream), 'a resposta volta no mesmo fluxo do pedido'],
        ['Quadro HEADERS', ':status 200, content-type, content-length', 'comprimidos pelo HPACK'], ['Content-Length', size, 'bytes do corpo'],
        ['Quadros DATA', String(frames), 'até 16 KB cada (tamanho padrão); intercalados com os de outros fluxos'], ['Último quadro', 'DATA com END_STREAM', 'encerra o fluxo; a conexão continua aberta'],
      ];
    }
    return [
      { sec: 'UDP e QUIC (RFC 9000)' }, ['Quadros STREAM', 'fluxo ' + j.stream, 'cada fluxo tem controle de ordem e de perda próprio'],
      { sec: 'HTTP/3 (RFC 9114)' }, ['Quadro HEADERS', ':status 200, content-type, content-length', 'comprimidos pelo QPACK'], ['Content-Length', size, 'bytes do corpo'],
      ['Quadros DATA', String(frames), 'um byte perdido atrasa só este fluxo'],
    ];
  };

  // Abertura conforme a versão efetiva.
  phase(0, fallback ? '1. Tentativa de QUIC (UDP 443)' : eff === 'h3' ? (P.resume ? '1. QUIC com 0-RTT' : '1. Handshake QUIC (1 RTT)') : tlsOn ? '1. Conexão TCP e TLS' : '1. Conexão TCP', 'connect');
  st(0, 'proto', fallback ? 'tentando HTTP/3' : proto, 'warn');
  st(0, 'conn', '0 abertas', 'closed');
  st(0, 'prog', '0 de ' + N, 'closed');
  st(0, 'net', P.loss ? 'um pacote de ' + VICTIM + ' será perdido' : 'sem perdas', P.loss ? 'warn' : 'est');
  mile(0, 'Início', 'sem conexão');
  lg(0, 'O navegador vai carregar <b>' + HOST + '</b> em ' + proto + ': ' + N + ' recursos, RTT de ' + rtt + ' ms.', 'sys');
  ev(0, 'cli', 'Quer carregar a página', '');

  if (fallback) {
    put('cli', 'srv', 0, ow, { label: 'QUIC Initial', proto: 'QUIC', color: C.bad, lost: true, len: 1200, tags: ['UDP 443 bloqueado'], fields: [{ sec: 'UDP e QUIC' }, ['Porta de destino', '443 (UDP)', 'o firewall descarta o datagrama'], ['Tamanho do datagrama', '1200 bytes', 'o Initial tem no mínimo 1200 bytes (RFC 9000)'], ['Quadro', 'CRYPTO (ClientHello, ALPN h3)', '']], about: 'O Initial do QUIC nunca chega: nenhuma resposta volta.', phaseName: 'QUIC' });
    ev(ow, 'cli', 'Sem resposta em UDP 443', 'warn');
    lg(ow, 'O QUIC Initial se perde (UDP 443 bloqueado na rede). O navegador espera ' + FALLBACK_MS + ' ms e recorre ao TCP.', 'fail');
    phase(FALLBACK_MS, '2. Fallback: TCP e TLS (HTTP/2)', 'fallback');
    ev(FALLBACK_MS, 'cli', 'Tempo esgotado: usa HTTP/2 sobre TCP', 'warn');
    st(FALLBACK_MS, 'proto', 'HTTP/2 (fallback)', 'warn');
    journal.push({ type: 'fallback', t: FALLBACK_MS });
  }

  if (eff === 'h3') {
    if (P.resume) {
      put('cli', 'srv', 0, ow, { label: 'Initial + 0-RTT', proto: 'QUIC', color: C.enc, len: 1200, fields: hello('h3', 'h3', true), about: 'Com um ticket de sessão anterior, o cliente envia o pedido junto do primeiro pacote (dados 0-RTT).', phaseName: 'QUIC', tags: ['0-RTT'] });
      put('srv', 'cli', ow, rtt, { label: 'Initial + Handshake', proto: 'QUIC', color: C.enc, enc: true, len: 1350, fields: [{ sec: 'QUIC: resposta do servidor' }, ['Initial', 'ServerHello', ''], ['Handshake', 'EncryptedExtensions, Certificate, Finished', 'cifrados'], ['0-RTT', 'aceito', 'o servidor processa o pedido sem esperar o fim do handshake']], about: 'O servidor completa o handshake e já atende o pedido 0-RTT.', phaseName: 'QUIC' });
      put('cli', 'srv', rtt, rtt + ow, { label: 'Handshake (Finished)', proto: 'QUIC', color: C.enc, enc: true, len: 100, fields: [{ sec: 'QUIC' }, ['Quadro', 'CRYPTO (Finished)', 'o cliente conclui o handshake']], about: 'O cliente confirma o handshake; o pedido já estava a caminho.', phaseName: 'QUIC' });
    } else {
      put('cli', 'srv', 0, ow, { label: 'Initial (ClientHello)', proto: 'QUIC', color: C.enc, len: 1200, fields: hello('h3', 'h3', true), about: 'O QUIC une transporte e TLS 1.3: um só voo inicial, em UDP.', phaseName: 'QUIC' });
      put('srv', 'cli', ow, rtt, { label: 'Initial + Handshake', proto: 'QUIC', color: C.enc, enc: true, len: 1350, fields: [{ sec: 'QUIC: resposta do servidor' }, ['Initial', 'ServerHello', ''], ['Handshake', 'EncryptedExtensions (ALPN h3), Certificate, Finished', 'cifrados']], about: 'O servidor responde com a parte do TLS e já pode enviar dados.', phaseName: 'QUIC' });
      put('cli', 'srv', rtt, rtt + ow, { label: 'Handshake (Finished)', proto: 'QUIC', color: C.enc, enc: true, len: 100, fields: [{ sec: 'QUIC' }, ['Quadro', 'CRYPTO (Finished)', 'o cliente conclui o handshake']], about: 'O cliente conclui o handshake com 1 RTT e já envia o primeiro pedido.', phaseName: 'QUIC' });
    }
  } else {
    openTcp(1, t0, tlsOn);
    if (eff === 'h2') {
      put('cli', 'srv', ready, ready + ow, { label: 'SETTINGS (preface)', proto: 'HTTP/2', color: C.tcp, enc: true, len: 60, fields: [{ sec: 'HTTP/2 (RFC 9113)' }, ['Preface', 'PRI * HTTP/2.0 ... SM', 'sequência fixa que abre a conexão'], ['Quadro', 'SETTINGS', 'parâmetros do cliente: tabela HPACK, janela de controle de fluxo'], ['Fluxo', '0', 'quadros da conexão usam o fluxo 0']], about: 'O cliente abre a conexão HTTP/2 com o preface e seus parâmetros.', phaseName: 'HTTP/2', tags: ['conexão'] });
      put('srv', 'cli', ready + ow, ready + rtt, { label: 'SETTINGS', proto: 'HTTP/2', color: C.tcp, enc: true, len: 60, fields: [{ sec: 'HTTP/2 (RFC 9113)' }, ['Quadro', 'SETTINGS', 'MAX_CONCURRENT_STREAMS = 100 (valor típico)'], ['Fluxo', '0', '']], about: 'O servidor informa seus limites, como o máximo de fluxos simultâneos.', phaseName: 'HTTP/2', tags: ['conexão'] });
    }
  }

  const connReadyMsg = eff === 'h3' ? (P.resume ? 'o pedido já vai no primeiro voo (0-RTT)' : 'conexão pronta depois de 1 RTT') : tlsOn ? 'TCP e TLS prontos depois de 2 RTT' : 'TCP pronto depois de 1 RTT';
  ev(ready, 'cli', connReadyMsg[0].toUpperCase() + connReadyMsg.slice(1), 'ok');
  lg(ready, connReadyMsg[0].toUpperCase() + connReadyMsg.slice(1) + '. Primeiro pedido: <b>GET /index.html</b>.', 'sys');
  st(ready, 'conn', '1 aberta', 'est');
  mile(ready, 'Conexão pronta', Math.round((ready - t0) / rtt) + ' RTT');
  journal.push({ type: 'connect', t: ready, rtts: (ready - t0) / rtt, via: eff, tls: tlsOn, resume: eff === 'h3' && P.resume });

  // ---- pedidos e respostas ----
  const html = S.jobs[0];
  phase(html.reqSend, 'Documento HTML', 'html');
  const respMsg = (j: Job) => {
    put('srv', 'cli', j.start, j.arr, { label: '200 ' + j.res.path, proto, color: j.hold === 'none' ? C.data : C.bad, enc: tlsOn, len: j.resBytes, tags: [...connTag(j), ...(j.hold === 'victim' ? ['aguarda retransmissão'] : j.hold === 'hol' ? ['retida pelo TCP'] : [])], info: '200 OK ' + j.res.path + ' (' + j.res.kb + ' KB)', fields: resFields(j), about: 'O servidor responde com o recurso ' + j.res.path + '.', phaseName: '200' });
  };
  const reqMsg = (j: Job) => {
    const piggy = !tlsOn && eff === 'h1' && S.jobs.filter((x) => x.conn === j.conn).sort((a, b) => a.reqSend - b.reqSend)[0] === j;
    put('cli', 'srv', j.reqSend, j.reqArr, { label: (piggy ? 'ACK + ' : '') + reqLabel(j), proto, color: C.plain, enc: tlsOn, len: j.reqBytes + 60, tags: connTag(j), info: 'GET ' + j.res.path, fields: reqFields(j), about: 'O navegador pede ' + j.res.path + (eff === 'h1' ? ' na conexão ' + j.conn + '.' : ' no fluxo ' + j.stream + '.'), phaseName: 'GET' });
  };
  reqMsg(html);
  respMsg(html);
  ev(html.reqArr + SRV_MS, 'srv', 'Atende ' + html.res.path, '');
  lg(html.reqSend, 'GET <b>/index.html</b> enviado.', 'req');
  lg(html.start, 'Servidor começa a responder (' + html.res.kb + ' KB).', 'resp');
  const ttfb = html.start + ow - html.reqSend;
  mile(html.start + ow, 'Primeiro byte', 'TTFB ' + Math.round(ttfb) + ' ms');
  journal.push({ type: 'html', t: html.arr, ttfb });

  const tH = S.tHtml;
  ev(tH, 'cli', 'HTML recebido: descobre ' + (N - 1) + ' subrecursos', 'ok');
  lg(tH, 'HTML completo. O navegador encontra <b>' + (N - 1) + '</b> subrecursos (CSS, JavaScript, imagens, fonte).', 'sys');
  mile(tH, 'HTML pronto', '');
  phase(tH, eff === 'h1' ? '3. Subrecursos (' + S.conns.length + (S.conns.length === 1 ? ' conexão)' : ' conexões)') : '3. Subrecursos multiplexados', 'subs');
  if (eff === 'h1') {
    S.conns.slice(1).forEach((c) => {
      openTcp(c.id, c.openAt, tlsOn);
      ev(c.readyAt, 'cli', 'Conexão ' + c.id + ' pronta', 'ok');
    });
    if (S.conns.length > 1) {
      lg(tH, 'O navegador abre mais <b>' + (S.conns.length - 1) + '</b> conexão(ões) para pedir em paralelo (limite típico de 6 por servidor).', 'sys');
      st(tH, 'conn', S.conns.length + ' abertas (' + (tlsOn ? 'TCP+TLS' : 'TCP') + ')', 'est');
    }
  }
  const subJobs = S.jobs.slice(1).sort((a, b) => a.reqSend - b.reqSend || a.idx - b.idx);
  subJobs.forEach((j) => { reqMsg(j); respMsg(j); });
  journal.push({ type: 'discover', t: tH, n: N - 1, conns: S.conns.length });

  // progresso de recursos recebidos
  const arrivals = S.jobs.slice().sort((a, b) => a.arr - b.arr || a.idx - b.idx);
  arrivals.forEach((j, k) => {
    st(j.arr, 'prog', k + 1 + ' de ' + N, k + 1 === N ? 'est' : 'warn');
    lg(j.arr, '<b>' + j.res.path + '</b> recebido' + (eff === 'h1' ? ' (conexão ' + j.conn + ')' : '') + (j.hold === 'hol' ? ', entrega retida pelo TCP até a retransmissão' : j.hold === 'victim' ? ', depois da retransmissão' : '') + '.', 'resp');
  });
  const tDone = Math.max(...S.jobs.map((j) => j.arr));
  mile(tDone, 'Página completa', Math.round(tDone) + ' ms');
  ev(tDone, 'cli', 'Todos os recursos recebidos', 'ok');
  journal.push({ type: 'done', t: tDone });

  // ---- perda de pacote ----
  if (S.lossT >= 0) {
    const tL = S.lossT;
    const victim = S.jobs.find((j) => j.res.path === VICTIM)!;
    const quic = eff === 'h3';
    const where = eff === 'h1' ? ['conexão ' + victim.conn] : [quic ? 'fluxo QUIC ' + victim.stream : 'fluxo ' + victim.stream];
    put('srv', 'cli', tL, tL + ow, { label: quic ? 'pacote QUIC perdido' : 'segmento perdido', proto: quic ? 'QUIC' : 'TCP', color: C.bad, lost: true, len: 1400, tags: [...where, 'perda'], fields: [{ sec: quic ? 'UDP e QUIC' : 'TCP' }, ['Conteúdo', 'dados de ' + VICTIM, 'o pacote não chega ao cliente'], ['Número', quic ? 'pacote QUIC ' + ++pn : 'seq ' + (Math.round(victim.kb * 1024 * LOSS_AT)), '']], about: 'Um pacote com dados de ' + VICTIM + ' se perde na rede.', phaseName: 'perda' });
    put('cli', 'srv', tL + ow, tL + rtt, { label: quic ? 'ACK com intervalo' : 'ACK duplicado (SACK)', proto: quic ? 'QUIC' : 'TCP', color: C.tcp, len: 60, tags: where, fields: [{ sec: quic ? 'QUIC' : 'TCP' }, [quic ? 'Quadro ACK' : 'Opção SACK', quic ? 'faixas recebidas com um buraco' : 'bloco recebido depois do buraco', 'o cliente avisa que faltou um trecho'], ['Detecção', quic ? 'limite de 3 pacotes (RFC 9002)' : 'três ACKs duplicados (fast retransmit)', 'a perda é percebida cerca de 1 RTT depois']], about: 'O cliente percebe o buraco e avisa o servidor.', phaseName: 'perda' });
    put('srv', 'cli', tL + rtt, S.recT, { label: quic ? 'retransmissão (novo pacote)' : 'retransmissão', proto: quic ? 'QUIC' : 'TCP', color: C.data, len: 1400, tags: where, fields: [{ sec: quic ? 'UDP e QUIC' : 'TCP' }, ['Conteúdo', 'os mesmos dados de ' + VICTIM, quic ? 'o QUIC reenvia o conteúdo num pacote novo, com número novo' : 'o TCP reenvia o mesmo segmento']], about: 'O servidor reenvia o trecho perdido.', phaseName: 'perda' });
    st(tL, 'net', 'pacote perdido em ' + VICTIM, 'bad');
    st(S.recT, 'net', 'retransmissão recebida', 'est');
    lg(tL, 'Um pacote de <b>' + VICTIM + '</b> se perde na rede.', 'fail');
    ev(tL + ow, 'cli', eff === 'h2' ? 'Buraco no fluxo TCP: nada é entregue à aplicação' : eff === 'h3' ? 'Só o fluxo de ' + VICTIM + ' espera' : 'Só a conexão ' + victim.conn + ' espera', 'warn');
    ev(S.recT, 'cli', 'Retransmissão recebida', 'ok');
    const held = S.jobs.filter((j) => j.hold === 'hol');
    held.forEach((j) => ev(r1(j.rawArr), 'cli', 'Entrega de ' + j.res.path + ' retida pelo TCP', 'warn'));
    const delayed = S.jobs.filter((j) => j.hold !== 'none');
    journal.push({ type: 'loss', t: tL, rec: S.recT, victim: victim.res.path, victimHeld: victim.hold === 'victim', held: held.map((j) => j.res.path), delayed: delayed.length, conn: victim.conn });
  }

  // ---- métricas ----
  const hdrBytes = S.jobs.reduce((s, j) => s + j.reqBytes + (j.resBytes - Math.round(j.res.kb * 1024)), 0);
  const delayed = S.jobs.filter((j) => j.hold !== 'none');
  const metrics: Metrics = {
    ready,
    rttsBeforeRequest: (ready - t0) / rtt,
    ttfb,
    tHtml: tH,
    tDone,
    conns: S.conns.length,
    hdrBytes,
    totalKB: list.reduce((s, r) => s + r.kb, 0),
    delayed: delayed.length,
    delayedMs: delayed.reduce((s, j) => s + (j.arr - j.rawArr), 0),
  };
  tr.raw.metrics = metrics;
  tr.raw.tDone = tDone;
  tr.raw.connEv = S.conns.map((c) => ({ t: c.readyAt, n: c.id }));

  // ---- emissão ordenada das mensagens ----
  out.sort((a, b) => a.ts - b.ts || a.ta - b.ta);
  out.forEach((m) => {
    const msg = tr.add(m.from, m.to, { ...m.o, at: m.ts, dur: m.ta - m.ts, par: true });
    msg.tSend = m.ts;
    msg.tArr = m.ta;
  });
  tr.t = r1(tDone);
  return tr;
}
