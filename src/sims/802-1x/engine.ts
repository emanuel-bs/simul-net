// Motor do 802.1X (IEEE 802.1X, EAP na RFC 3748 e RADIUS nas RFC 2865 e 3579). Quatro modos: autenticação, falhas,
// estado da porta e sessão, e riscos com defesas. Cada um monta o trace de um suplicante, de um autenticador (switch)
// e de um servidor RADIUS, e registra em tr.raw o estado da porta, os quadros de dados e os pacotes RADIUS.
import { COLORS as C0, hex, newTrace, type Column, type Field, type StateDef, type Trace } from '../../sim-core';
import {
  eapolFields,
  eapolLen,
  EAP_MAX_REQ,
  EAP_TX_PERIOD,
  GREEN,
  IDENTITY,
  LEG,
  METHODS,
  NODE,
  PAE_GROUP,
  RADIUS_TIMEOUT,
  RADIUS_TRIES,
  radiusFields,
  radiusLen,
  nasAttrs,
  SESSION_TIMEOUT,
  type EapHdr,
  type Method,
  type MethodKey,
  type Round,
} from './model';

const STATES: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'port', label: 'Porta controlada do switch' },
  { key: 'res', label: 'Resultado' },
];

export type PortState = 'unauth' | 'authing' | 'auth';
const PORT_TXT: Record<PortState, string> = {
  unauth: 'não autorizada: só o EAPOL passa',
  authing: 'em autenticação: só o EAPOL passa',
  auth: 'autorizada: todo o tráfego passa',
};
const PORT_CLS: Record<PortState, string> = { unauth: 'closed', authing: 'warn', auth: 'est' };

const COL: Record<string, Omit<Column, 'key'>> = {
  sup: { label: 'Notebook', sub: 'suplicante', addr: NODE.sup.mac },
  dev2: { label: '2º dispositivo', sub: 'atrás da mesma porta', addr: NODE.dev2.mac },
  nas: { label: 'SW1', sub: 'autenticador, porta Gi1/0/5', addr: NODE.nas.ip },
  srv: { label: 'RADIUS', sub: 'servidor de autenticação', addr: NODE.srv.ip },
  lan: { label: 'Rede', sub: 'rede corporativa', addr: '' },
  fake: { label: 'Equipamento falso', sub: 'autenticador e servidor de terceiro', addr: '' },
};

interface Ctx {
  tr: Trace;
  R: Record<string, any>;
  eapId: number;
  radId: number;
  /** Coluna do autenticador (o equipamento falso nos cenários de risco). */
  nas: string;
}

function base(sub: string, cols: string[], rtt: number, over: Record<string, Partial<Column>> = {}, extra: Record<string, unknown> = {}): Ctx {
  const columns: Column[] = cols.map((k) => ({ key: k, ...COL[k], ...(over[k] || {}) }));
  const tr = newTrace(columns, STATES, rtt);
  tr.raw = { sub, mode: sub, cols, res: '', port: [] as any[], frames: [] as any[], rad: [] as any[], tEnd: 0, ...extra } as Record<string, any>;
  return { tr, R: tr.raw, eapId: 1, radId: 0, nas: cols.includes('fake') ? 'fake' : 'nas' };
}

function setPort(c: Ctx, state: PortState, why: string) {
  c.tr.st(c.tr.t, 'port', PORT_TXT[state], PORT_CLS[state]);
  c.R.port.push({ t: c.tr.t, state, why });
}

function finish(c: Ctx, res: string, text: string, cls: string) {
  const { tr, R } = c;
  R.res = res;
  tr.phase('Resultado', 'resultado');
  tr.st(tr.t, 'phase', 'concluído', cls === 'bad' ? 'bad' : 'est');
  tr.st(tr.t, 'res', text, cls);
  tr.mile(tr.t, text.length > 28 ? text.slice(0, 26) + '...' : text, '');
  R.tEnd = tr.t;
}

function begin(c: Ctx) {
  c.tr.st(0, 'phase', 'início', 'warn');
  c.tr.st(0, 'res', 'em andamento', 'warn');
}

// ---- mensagens ----

interface EapolSend {
  dir: 'up' | 'down';
  pkt: 'eap' | 'start' | 'logoff';
  eap?: EapHdr;
  label: string;
  color?: string;
  enc?: boolean;
  info: string;
  about?: string;
  /** Endereço de destino: padrão é o grupo do PAE (para cima) ou o MAC do suplicante (para baixo). */
  group?: boolean;
  phaseName?: string;
}

function eapol(c: Ctx, o: EapolSend) {
  const from = o.dir === 'up' ? 'sup' : c.nas;
  const to = o.dir === 'up' ? c.nas : 'sup';
  const src = o.dir === 'up' ? NODE.sup.mac : NODE.nas.mac;
  const dst = o.dir === 'up' || o.group ? PAE_GROUP : NODE.sup.mac;
  return c.tr.add(from, to, {
    label: o.label,
    proto: 'EAPOL',
    color: o.color ?? C0.plain,
    enc: !!o.enc,
    len: eapolLen(o.eap),
    fields: eapolFields({ pkt: o.pkt, from: src, to: dst, eap: o.eap }),
    info: o.info,
    about: o.about,
    phaseName: o.phaseName,
    dur: LEG,
  });
}

const eapAttr = (text: string): [string, string, string] => ['EAP-Message (79)', text, 'o pacote EAP inteiro, sem interpretação do autenticador (RFC 3579, seção 3.1)'];
const maAttr = (seed: string): [string, string, string] => ['Message-Authenticator (80)', hex('ma' + seed, 16), 'HMAC-MD5 do pacote com o segredo compartilhado (RFC 3579, seção 3.2)'];
const stateAttr = (n: number): [string, string, string] => ['State (24)', hex('state' + n, 8), 'o servidor devolve o mesmo valor para continuar a mesma conversa (RFC 2865, seção 5.24)'];

interface RadSend {
  toSrv: boolean;
  code: 1 | 2 | 3 | 11;
  id: number;
  attrs: [string, string, string?][];
  label: string;
  color?: string;
  info: string;
  about?: string;
  lost?: boolean;
  enc?: boolean;
  phaseName?: string;
}

function radius(c: Ctx, o: RadSend) {
  const name = { 1: 'Access-Request', 2: 'Access-Accept', 3: 'Access-Reject', 11: 'Access-Challenge' }[o.code];
  const m = c.tr.add(o.toSrv ? 'nas' : 'srv', o.toSrv ? 'srv' : 'nas', {
    label: o.label,
    proto: 'RADIUS',
    color: o.color ?? C0.data,
    enc: !!o.enc,
    len: radiusLen(o.attrs),
    fields: radiusFields({ code: o.code, id: o.id, toSrv: o.toSrv, attrs: o.attrs }),
    info: o.info,
    about: o.about,
    lost: !!o.lost,
    phaseName: o.phaseName,
  });
  c.R.rad.push({ t: m.tSend, code: name, id: o.id, label: o.label, from: o.toSrv ? 'SW1' : 'RADIUS', to: o.toSrv ? 'RADIUS' : 'SW1', lost: !!o.lost, attrs: o.attrs.map((a) => a[0] + ' = ' + a[1]) });
  return m;
}

/** Quadro de dados do suplicante: passa só se a porta (ou o endereço) está autorizada. */
function frame(c: Ctx, who: 'sup' | 'dev2', ok: boolean, label: string, why: string) {
  const { tr, R } = c;
  const src = NODE[who].mac;
  const fields: Field[] = [{ sec: 'Ethernet II' }, ['Destino', 'ff:ff:ff:ff:ff:ff', 'broadcast'], ['Origem', src, ''], ['EtherType', '0x0800', 'IPv4 (dados)'], { sec: 'Decisão do switch' }, ['Porta controlada', ok ? 'autorizada' : 'não autorizada', why]];
  const m = tr.add(who, c.nas, { label, proto: 'dados', color: ok ? C0.data : C0.bad, len: 342, fields, info: ok ? 'a porta está autorizada' : 'a porta não está autorizada', about: 'Um quadro de dados comum. O switch decide pelo estado da porta, e não pelo protocolo que o quadro carrega.', dur: LEG });
  if (ok) {
    tr.ev(m.tArr, c.nas, 'Encaminha o quadro: ' + why, 'ok');
    tr.add(c.nas, 'lan', { label: label + ' (encaminhado)', proto: 'dados', color: C0.data, len: 342, fields, info: 'tráfego liberado', about: 'O quadro segue para a rede corporativa.', dur: LEG });
  } else {
    tr.ev(m.tArr, c.nas, 'Descarta o quadro: ' + why, 'bad');
  }
  R.frames.push({ t: m.tSend, who, ok, label, why });
}

// ---- a troca de autenticação (suplicante, autenticador e servidor) ----

interface AuthOpts {
  m: Method;
  reject: boolean;
  /** O suplicante abre com EAPOL-Start. Sem ele, o autenticador pede a identidade por conta própria. */
  start: boolean;
  /** Reautenticação: a porta continua autorizada durante o processo. */
  reauth: boolean;
  /** Executado depois do primeiro Access-Request (por exemplo, um quadro para provar que a porta segue aberta). */
  during?: () => void;
  /** Texto do motivo da recusa, mostrado no servidor. */
  reason?: string;
}

const SRV_OK: Record<MethodKey, string> = {
  md5: 'Confere a resposta MD5 com a senha guardada: confere. Decide Access-Accept',
  peap: 'Confere a prova MSCHAPv2 com o hash da senha do usuário: confere. Decide Access-Accept',
  tls: 'Valida o certificado do cliente (cadeia, validade) e a prova de posse da chave: válido. Decide Access-Accept',
};

function authenticate(c: Ctx, o: AuthOpts): boolean {
  const { tr, R } = c;
  const m = o.m;
  c.eapId = 1;
  tr.phase('1. Identidade (EAPOL)', 'identidade');
  tr.st(tr.t, 'phase', 'identidade', 'warn');
  if (!o.reauth) setPort(c, 'authing', 'a autenticação começou; a porta continua fechada para dados');
  if (o.start) {
    eapol(c, { dir: 'up', pkt: 'start', label: 'EAPOL-Start', info: 'o suplicante pede a autenticação', about: 'O suplicante avisa ao autenticador que quer se autenticar. Sem ele, o autenticador também começa sozinho ao detectar o link.', group: true, phaseName: 'Identidade' });
  }
  const idReq: EapHdr = { code: 1, id: c.eapId++, type: 1, bytes: 0 };
  eapol(c, { dir: 'down', pkt: 'eap', eap: idReq, label: 'EAP-Request/Identity', info: 'o autenticador pede a identidade', about: 'O autenticador pede quem é o suplicante. Esta mensagem é do próprio autenticador: o servidor ainda não participou.', group: !o.start && !o.reauth, phaseName: 'Identidade' });
  const idRes: EapHdr = { code: 2, id: idReq.id, type: 1, data: m.identity, bytes: m.identity.length };
  eapol(c, { dir: 'up', pkt: 'eap', eap: idRes, label: 'EAP-Response/Identity', info: 'identidade: ' + m.identity, about: m.key === 'md5' || m.key === 'tls' ? 'A identidade vai em claro, pois ainda não há túnel.' : 'No PEAP a identidade externa pode ser anônima: a verdadeira vai dentro do túnel TLS.', phaseName: 'Identidade' });
  tr.ev(tr.t, c.nas, 'Não interpreta o EAP: coloca o pacote dentro de um Access-Request e o encaminha ao servidor RADIUS', '');

  tr.phase('2. Método ' + m.name + ' (EAP sobre RADIUS)', 'metodo');
  tr.st(tr.t, 'phase', m.name, 'warn');
  const user = m.identity;
  let lastId = idRes.id;
  const idUser = (n: number): [string, string, string?][] => [...nasAttrs(user, NODE.sup.mac), eapAttr('EAP-Response/Identity'), ...(n > 0 ? [stateAttr(n)] : []), maAttr('req' + n)];
  const first = ++c.radId;
  radius(c, { toSrv: true, code: 1, id: first, label: 'Access-Request (Identity)', attrs: idUser(0), info: 'EAP-Message: Response/Identity', about: 'O autenticador repassa a identidade ao servidor RADIUS (RFC 3579). O servidor identifica o método a usar.', phaseName: 'Identidade' });
  if (o.during) o.during();

  for (let i = 0; i < m.rounds.length; i++) {
    const rd: Round = m.rounds[i];
    const rid = c.eapId++;
    const req: EapHdr = { code: 1, id: rid, type: m.type, data: rd.reqData, bytes: rd.reqBytes };
    const challenge = ++c.radId;
    radius(c, { toSrv: false, code: 11, id: challenge, label: 'Access-Challenge (' + rd.req + ')', color: rd.enc ? C0.enc : C0.data, enc: rd.enc, attrs: [eapAttr('Request/' + m.typeName + ': ' + rd.req), stateAttr(i + 1), maAttr('chal' + i)], info: 'EAP-Message: Request/' + m.typeName, about: 'O servidor pede o próximo passo do método e devolve um State. ' + rd.reqAbout, phaseName: 'Método' });
    eapol(c, { dir: 'down', pkt: 'eap', eap: req, label: 'EAP-Request/' + rd.req, color: rd.enc ? C0.enc : C0.plain, enc: rd.enc, info: rd.reqData, about: rd.reqAbout, phaseName: 'Método' });
    const res: EapHdr = { code: 2, id: rid, type: m.type, data: rd.resData, bytes: rd.resBytes };
    eapol(c, { dir: 'up', pkt: 'eap', eap: res, label: 'EAP-Response/' + rd.res, color: rd.enc ? C0.enc : C0.plain, enc: rd.enc, info: rd.resData, about: rd.resAbout, phaseName: 'Método' });
    lastId = rid;
    const ar = ++c.radId;
    radius(c, { toSrv: true, code: 1, id: ar, label: 'Access-Request (' + rd.res + ')', color: rd.enc ? C0.enc : C0.data, enc: rd.enc, attrs: [...nasAttrs(user, NODE.sup.mac), eapAttr('Response/' + m.typeName + ': ' + rd.res), stateAttr(i + 1), maAttr('ar' + i)], info: 'EAP-Message: Response/' + m.typeName, about: 'O autenticador repassa a resposta, com o State recebido, para o servidor reconhecer a conversa.', phaseName: 'Método' });
    if (i === m.decisive && o.reject) {
      tr.phase('3. Decisão do servidor', 'decisao');
      tr.st(tr.t, 'phase', 'decisão: recusa', 'bad');
      tr.ev(tr.t, 'srv', (o.reason || 'A credencial não confere') + '. Decide Access-Reject', 'bad');
      const rej = ++c.radId;
      radius(c, { toSrv: false, code: 3, id: rej, label: 'Access-Reject', color: C0.bad, attrs: [eapAttr('Failure'), maAttr('rej')], info: 'EAP-Message: Failure', about: 'O servidor nega o acesso. No Access-Reject não se permitem outros atributos além do Proxy-State e das mensagens EAP (RFC 5080, seção 2.6.1).', phaseName: 'Decisão' });
      eapol(c, { dir: 'down', pkt: 'eap', eap: { code: 4, id: lastId }, label: 'EAP-Failure', color: C0.bad, info: 'acesso negado', about: 'O autenticador informa o fracasso ao suplicante. O EAP-Failure não é confirmado (RFC 3748, seção 4.2).', phaseName: 'Decisão' });
      tr.phase('4. Porta', 'porta');
      setPort(c, 'unauth', 'o servidor recusou: a porta permanece fechada para dados');
      return false;
    }
  }
  tr.phase('3. Decisão do servidor', 'decisao');
  tr.st(tr.t, 'phase', 'decisão: aceita', 'est');
  tr.ev(tr.t, 'srv', SRV_OK[m.key], 'ok');
  const acc = ++c.radId;
  const accAttrs: [string, string, string?][] = [eapAttr('Success'), ...(o.reauth || R.sessionTimeout ? [['Session-Timeout (27)', String(SESSION_TIMEOUT), 'a sessão vale por esta duração, em segundos (RFC 2865, seção 5.27)'] as [string, string, string]] : []), maAttr('acc')];
  radius(c, { toSrv: false, code: 2, id: acc, label: 'Access-Accept', color: GREEN, attrs: accAttrs, info: 'EAP-Message: Success', about: 'O servidor aceita o suplicante.' + (R.sessionTimeout || o.reauth ? ' O Session-Timeout diz por quanto tempo a sessão vale antes de uma nova autenticação.' : ''), phaseName: 'Decisão' });
  eapol(c, { dir: 'down', pkt: 'eap', eap: { code: 3, id: lastId }, label: 'EAP-Success', color: GREEN, info: 'acesso concedido', about: 'O autenticador informa o sucesso ao suplicante. É o Access-Accept que faz o autenticador abrir a porta.', phaseName: 'Decisão' });
  tr.phase('4. Porta', 'porta');
  setPort(c, 'auth', o.reauth ? 'reautenticação concluída: a sessão foi renovada' : 'Access-Accept recebido: a porta passa a encaminhar todo o tráfego');
  return true;
}

// ---- 1. Autenticação ----

export interface AuthParams {
  rtt: number;
  method: MethodKey;
}

export function buildAuth(P: AuthParams): Trace {
  const c = base('auth', ['sup', 'nas', 'srv', 'lan'], P.rtt, {}, { method: P.method });
  const { tr, R } = c;
  begin(c);
  setPort(c, 'unauth', 'o link subiu e a porta começa fechada');
  tr.ev(0, 'nas', 'O link da porta Gi1/0/5 subiu. A porta controlada começa não autorizada: só o EAPOL passa pela porta não controlada', '');
  frame(c, 'sup', false, 'DHCPDISCOVER', 'a porta ainda não foi autorizada, e só o EAPOL é aceito');
  tr.wait(0.4);
  authenticate(c, { m: METHODS[P.method], reject: false, start: true, reauth: false });
  tr.wait(0.4);
  frame(c, 'sup', true, 'DHCPDISCOVER', 'a porta está autorizada');
  R.accepted = true;
  finish(c, 'ok', 'porta autorizada', 'est');
  return tr;
}

// ---- 2. Falhas ----

export interface FalhaParams {
  rtt: number;
  cause: 'cred' | 'cert' | 'noserver' | 'secret' | 'nosup';
}

export function buildFalha(P: FalhaParams): Trace {
  const nosup = P.cause === 'nosup';
  const cols = nosup ? ['sup', 'nas', 'lan'] : ['sup', 'nas', 'srv', 'lan'];
  const c = base('falha', cols, P.rtt, nosup ? { sup: { label: 'Impressora', sub: 'sem suplicante 802.1X' } } : {}, { cause: P.cause });
  const { tr, R } = c;
  begin(c);
  setPort(c, 'unauth', 'o link subiu e a porta começa fechada');
  tr.ev(0, 'nas', 'O link da porta Gi1/0/5 subiu. A porta começa não autorizada', '');
  if (P.cause === 'cred' || P.cause === 'cert') {
    const m = METHODS[P.cause === 'cred' ? 'peap' : 'tls'];
    R.method = m.key;
    authenticate(c, { m, reject: true, start: true, reauth: false, reason: P.cause === 'cred' ? 'Dentro do túnel, a prova MSCHAPv2 não confere com o hash da senha do usuário (senha incorreta)' : 'O certificado do cliente está expirado (alerta TLS certificate_expired, 45)' });
    tr.wait(0.4);
    frame(c, 'sup', false, 'DHCPDISCOVER', 'a autenticação falhou e a porta continua fechada');
    finish(c, P.cause, P.cause === 'cred' ? 'acesso negado: senha incorreta' : 'acesso negado: certificado expirado', 'bad');
    return tr;
  }
  if (nosup) {
    tr.phase('1. O autenticador pede a identidade', 'identidade');
    tr.st(tr.t, 'phase', 'sem resposta', 'warn');
    setPort(c, 'authing', 'o autenticador está tentando iniciar a autenticação');
    const tries = 1 + EAP_MAX_REQ;
    for (let k = 0; k < tries; k++) {
      eapol(c, { dir: 'down', pkt: 'eap', eap: { code: 1, id: k + 1, type: 1, bytes: 0 }, label: 'EAP-Request/Identity' + (k ? ' (repetição ' + k + ')' : ''), info: 'ninguém responde', about: 'O autenticador repete o pedido a cada período de transmissão (aqui, 30 s). A Impressora não tem suplicante e ignora o EAPOL.', group: true, phaseName: 'Identidade' });
      tr.ev(tr.t, 'sup', 'Ignora o EAPOL: o dispositivo não tem suplicante 802.1X', 'warn');
      if (k < tries - 1) tr.wait(EAP_TX_PERIOD);
    }
    tr.wait(EAP_TX_PERIOD);
    tr.phase('2. Sem suplicante', 'sem-suplicante');
    tr.ev(tr.t, 'nas', 'Esgotou o número de repetições (' + EAP_MAX_REQ + '): nenhum suplicante respondeu', 'bad');
    setPort(c, 'unauth', 'sem suplicante: a porta permanece fechada para dados');
    tr.wait(0.4);
    frame(c, 'sup', false, 'DHCPDISCOVER', 'a porta continua fechada para quem não se autentica');
    finish(c, 'nosup', 'porta fechada: sem suplicante', 'bad');
    return tr;
  }
  // noserver e secret: o suplicante responde, mas o servidor não devolve nada
  tr.phase('1. Identidade (EAPOL)', 'identidade');
  setPort(c, 'authing', 'a autenticação começou; a porta continua fechada para dados');
  eapol(c, { dir: 'up', pkt: 'start', label: 'EAPOL-Start', info: 'o suplicante pede a autenticação', about: 'O suplicante pede que a autenticação comece.', group: true, phaseName: 'Identidade' });
  const idReq: EapHdr = { code: 1, id: 1, type: 1, bytes: 0 };
  eapol(c, { dir: 'down', pkt: 'eap', eap: idReq, label: 'EAP-Request/Identity', info: 'o autenticador pede a identidade', about: 'O autenticador pede a identidade do suplicante.', phaseName: 'Identidade' });
  eapol(c, { dir: 'up', pkt: 'eap', eap: { code: 2, id: 1, type: 1, data: IDENTITY, bytes: IDENTITY.length }, label: 'EAP-Response/Identity', info: 'identidade: ' + IDENTITY, about: 'O suplicante informa a identidade.', phaseName: 'Identidade' });
  tr.phase(P.cause === 'secret' ? '2. O servidor descarta o pedido' : '2. O servidor não responde', 'sem-resposta');
  tr.st(tr.t, 'phase', 'sem resposta do servidor', 'warn');
  const id = ++c.radId;
  const attrs: [string, string, string?][] = [...nasAttrs(IDENTITY, NODE.sup.mac), eapAttr('EAP-Response/Identity'), maAttr('req0')];
  for (let k = 0; k < RADIUS_TRIES; k++) {
    const lost = P.cause === 'noserver';
    const m = radius(c, { toSrv: true, code: 1, id, label: 'Access-Request' + (k ? ' (retransmissão ' + k + ')' : ''), attrs, lost, info: lost ? 'perdido: o servidor não responde' : 'chegou, mas o servidor o descarta', about: 'O autenticador retransmite com o mesmo Identifier e os mesmos atributos (RFC 5080, seção 2.2.1). O intervalo e o número de tentativas são ajustes do equipamento: aqui, 5 s e 3 tentativas.', phaseName: 'Sem resposta' });
    if (!lost) tr.ev(m.tArr, 'srv', 'Descarta em silêncio: o Message-Authenticator não confere com o segredo que ele tem (RFC 3579, seção 3.2). Nenhuma resposta é enviada', 'bad');
    if (k < RADIUS_TRIES - 1) tr.wait(RADIUS_TIMEOUT);
  }
  tr.wait(RADIUS_TIMEOUT);
  tr.phase('3. Tempo esgotado', 'timeout');
  tr.st(tr.t, 'phase', 'tempo esgotado', 'bad');
  tr.ev(tr.t, 'nas', 'Esgotou as ' + RADIUS_TRIES + ' tentativas sem resposta. A autenticação falha, e a porta permanece fechada', 'bad');
  eapol(c, { dir: 'down', pkt: 'eap', eap: { code: 4, id: 1 }, label: 'EAP-Failure', color: C0.bad, info: 'sem resposta do servidor', about: 'Sem resposta, o autenticador encerra a tentativa com falha. Não houve Access-Reject: o servidor não disse nada.', phaseName: 'Tempo esgotado' });
  setPort(c, 'unauth', 'sem resposta do servidor: a porta permanece fechada para dados');
  tr.wait(0.4);
  frame(c, 'sup', false, 'DHCPDISCOVER', 'o servidor não autorizou, e a porta continua fechada');
  finish(c, P.cause, P.cause === 'secret' ? 'tempo esgotado: segredo diferente' : 'tempo esgotado: servidor inalcançável', 'bad');
  return tr;
}

// ---- 3. Estado da porta e sessão ----

export interface PortaParams {
  rtt: number;
  method: MethodKey;
  pact: 'reauth' | 'logoff' | 'extra';
  pdef: 'none' | 'permac';
}

export function buildPorta(P: PortaParams): Trace {
  const cols = P.pact === 'extra' ? ['sup', 'dev2', 'nas', 'lan'] : ['sup', 'nas', 'srv', 'lan'];
  const c = base('porta', cols, P.rtt, {}, { pact: P.pact, pdef: P.pdef, method: P.method, sessionTimeout: P.pact === 'reauth' });
  const { tr, R } = c;
  begin(c);
  tr.st(0, 'phase', 'sessão ativa', 'est');
  setPort(c, 'auth', 'a sessão do Notebook já foi autenticada antes do cenário');
  tr.ev(0, 'nas', 'A sessão do Notebook já foi autenticada antes deste cenário' + (P.pact === 'reauth' ? ' (o Access-Accept trouxe Session-Timeout de ' + SESSION_TIMEOUT + ' s)' : ''), 'ok');
  frame(c, 'sup', true, 'DHCPDISCOVER', 'a porta está autorizada');
  tr.wait(0.4);
  if (P.pact === 'reauth') {
    tr.wait(SESSION_TIMEOUT * 1000);
    tr.phase('Fim da sessão', 'timeout');
    tr.st(tr.t, 'phase', 'reautenticação', 'warn');
    tr.ev(tr.t, 'nas', 'O Session-Timeout de ' + SESSION_TIMEOUT + ' s expirou. O autenticador inicia uma nova autenticação, mas mantém a porta autorizada enquanto ela corre', 'warn');
    const m = METHODS[P.method];
    authenticate(c, {
      m,
      reject: false,
      start: false,
      reauth: true,
      during: () => {
        tr.wait(0.4);
        frame(c, 'sup', true, 'Dados durante a reautenticação', 'a porta continua autorizada enquanto a reautenticação corre');
      },
    });
    R.reauthOk = true;
    finish(c, 'reauth', 'sessão renovada sem interrupção', 'est');
    return tr;
  }
  if (P.pact === 'logoff') {
    tr.wait(60000);
    tr.phase('Fim da sessão', 'logoff');
    tr.st(tr.t, 'phase', 'logoff', 'warn');
    tr.ev(tr.t, 'sup', 'O usuário encerra a sessão (ou o dispositivo é desligado)', '');
    eapol(c, { dir: 'up', pkt: 'logoff', label: 'EAPOL-Logoff', info: 'o suplicante encerra a sessão', about: 'O suplicante avisa que a sessão terminou. Não há resposta. Nas implementações sem MACsec, este pacote não é autenticado.', group: true, phaseName: 'Fim da sessão' });
    setPort(c, 'unauth', 'EAPOL-Logoff recebido: a porta volta a ficar fechada');
    tr.ev(tr.t, 'nas', 'Fecha a porta imediatamente, sem esperar um temporizador', 'warn');
    tr.wait(0.4);
    frame(c, 'sup', false, 'DHCPDISCOVER', 'a sessão terminou e a porta voltou a ficar fechada');
    finish(c, 'logoff', 'porta fechada pelo logoff', 'est');
    return tr;
  }
  // extra: um segundo dispositivo atrás da mesma porta
  tr.phase('Segundo dispositivo', 'extra');
  tr.st(tr.t, 'phase', 'segundo dispositivo', 'warn');
  tr.ev(tr.t, 'dev2', 'Um segundo dispositivo, ligado à mesma porta por um hub ou um mini-switch, nunca se autenticou e envia um quadro', 'warn');
  if (P.pdef === 'permac') {
    frame(c, 'dev2', false, 'DHCPDISCOVER', 'a autorização é por endereço MAC, e este MAC não se autenticou');
    R.leak = false;
    finish(c, 'extra-def', 'segundo dispositivo barrado', 'est');
  } else {
    frame(c, 'dev2', true, 'DHCPDISCOVER', 'a autorização vale para a porta inteira, e não só para o dispositivo que se autenticou');
    R.leak = true;
    finish(c, 'extra-leak', 'o segundo dispositivo usou a porta', 'bad');
  }
  return tr;
}

// ---- 4. Riscos e defesas ----

export interface SegParams {
  rtt: number;
  risk: 'md5' | 'peap';
  sdef: 'none' | 'def';
}

export function buildSeg(P: SegParams): Trace {
  const c = base('seg', ['sup', 'fake'], P.rtt, {}, { risk: P.risk, sdef: P.sdef });
  const { tr, R } = c;
  const def = P.sdef === 'def';
  begin(c);
  tr.st(0, 'port', 'sob controle do equipamento falso', 'bad');
  tr.ev(0, 'fake', 'Um equipamento de terceiro faz o papel de autenticador e de servidor para o Notebook', 'warn');
  tr.phase('1. Identidade (EAPOL)', 'identidade');
  const idReq: EapHdr = { code: 1, id: c.eapId++, type: 1, bytes: 0 };
  const m: Method = def && P.risk === 'md5' ? METHODS.tls : P.risk === 'md5' ? METHODS.md5 : METHODS.peap;
  R.method = m.key;
  eapol(c, { dir: 'down', pkt: 'eap', eap: idReq, label: 'EAP-Request/Identity', info: 'pede a identidade', about: 'O equipamento falso se comporta como um autenticador comum.', group: true, phaseName: 'Identidade' });
  eapol(c, { dir: 'up', pkt: 'eap', eap: { code: 2, id: idReq.id, type: 1, data: m.identity, bytes: m.identity.length }, label: 'EAP-Response/Identity', info: 'identidade: ' + m.identity, about: 'O suplicante responde.', phaseName: 'Identidade' });
  tr.phase('2. Método ' + m.name, 'metodo');
  tr.st(tr.t, 'phase', m.name, 'warn');
  const round = (i: number, alert?: string) => {
    const rd = m.rounds[i];
    const req: EapHdr = { code: 1, id: c.eapId++, type: m.type, data: rd.reqData, bytes: rd.reqBytes };
    eapol(c, { dir: 'down', pkt: 'eap', eap: req, label: 'EAP-Request/' + rd.req, color: rd.enc ? C0.enc : C0.plain, enc: rd.enc, info: rd.reqData, about: rd.reqAbout, phaseName: 'Método' });
    if (alert) {
      tr.ev(tr.t, 'sup', alert, 'ok');
      return req;
    }
    eapol(c, { dir: 'up', pkt: 'eap', eap: { code: 2, id: req.id, type: m.type, data: rd.resData, bytes: rd.resBytes }, label: 'EAP-Response/' + rd.res, color: rd.enc ? C0.enc : C0.plain, enc: rd.enc, info: rd.resData, about: rd.resAbout, phaseName: 'Método' });
    return req;
  };
  if (P.risk === 'md5' && !def) {
    const req = round(0);
    eapol(c, { dir: 'down', pkt: 'eap', eap: { code: 3, id: req.id }, label: 'EAP-Success', color: GREEN, info: 'acesso concedido', about: 'Quem está do outro lado diz Success. O EAP-MD5 não dá ao suplicante nenhuma forma de conferir se esse alguém é legítimo.', phaseName: 'Decisão' });
    tr.ev(tr.t, 'sup', 'Aceita o Success: o EAP-MD5 não autentica o servidor (RFC 3748, seção 5.4, sem autenticação mútua)', 'bad');
    tr.ev(tr.t, 'fake', 'Obteve o desafio e a resposta MD5 do usuário, que podem ser submetidos a tentativas de adivinhar a senha (sem proteção contra ataque de dicionário)', 'bad');
    finish(c, 'md5-exposed', 'o suplicante aceitou um autenticador falso', 'bad');
    return tr;
  }
  if (P.risk === 'md5') {
    round(0);
    const req = round(1, 'Valida o certificado do servidor: a cadeia termina numa CA desconhecida. Recusa continuar o handshake');
    eapol(c, { dir: 'up', pkt: 'eap', eap: { code: 2, id: req.id, type: m.type, data: 'TLS: alerta fatal unknown_ca (48)', bytes: 8 }, label: 'EAP-Response/EAP-TLS (alerta unknown_ca)', color: C0.bad, info: 'TLS: alerta fatal unknown_ca (48)', about: 'O suplicante aborta o handshake com um alerta TLS. Nenhuma credencial foi enviada.', phaseName: 'Método' });
    eapol(c, { dir: 'down', pkt: 'eap', eap: { code: 4, id: req.id }, label: 'EAP-Failure', color: C0.bad, info: 'o equipamento falso encerra', about: 'O equipamento falso encerra a tentativa. O suplicante não se conectou a ele.', phaseName: 'Decisão' });
    finish(c, 'tls-reject', 'servidor falso rejeitado', 'est');
    return tr;
  }
  // PEAP
  round(0);
  if (def) {
    const req = round(1, 'Valida o certificado do servidor: o nome não corresponde ao servidor RADIUS da organização e a CA não é a configurada. Recusa continuar o túnel');
    eapol(c, { dir: 'up', pkt: 'eap', eap: { code: 2, id: req.id, type: m.type, data: 'TLS: alerta fatal bad_certificate (42)', bytes: 8 }, label: 'EAP-Response/PEAP (alerta bad_certificate)', color: C0.bad, info: 'TLS: alerta fatal bad_certificate (42)', about: 'O suplicante aborta o túnel com um alerta TLS, antes de enviar usuário ou senha.', phaseName: 'Método' });
    eapol(c, { dir: 'down', pkt: 'eap', eap: { code: 4, id: req.id }, label: 'EAP-Failure', color: C0.bad, info: 'o equipamento falso encerra', about: 'O equipamento falso encerra a tentativa. A credencial não foi exposta.', phaseName: 'Decisão' });
    finish(c, 'peap-reject', 'servidor falso rejeitado', 'est');
    return tr;
  }
  round(1);
  tr.ev(tr.t, 'sup', 'Não valida o certificado do servidor (a verificação está desligada) e segue com o túnel', 'bad');
  round(2);
  tr.ev(tr.t, 'fake', 'Recebeu a prova MSCHAPv2 da senha, que pode ser submetida a tentativas de adivinhar a senha fora do túnel', 'bad');
  finish(c, 'peap-exposed', 'credencial exposta ao servidor falso', 'bad');
  return tr;
}
