// Motor do FTP, FTPS e SFTP (RFC 959, RFC 2228, RFC 2428, RFC 4217; SSH: RFC 4251 a 4254).
// Três famílias de transferência de arquivos:
//   ftp   FTP clássico: canal de controle (porta 21) e um canal de dados por transferência (modos passivo e ativo);
//   ftps  FTP sobre TLS: explícito (AUTH TLS) ou implícito (porta 990), com PROT P ou PROT C;
//   sftp  SFTP, subsistema do SSH: uma única conexão (porta 22);
//   cmp   a mesma ação nos três, com um observador na rede.
// Não há criptografia real: chaves, hashes e conteúdos são valores ilustrativos.
import { COLORS as C0, b64, fmtMs, hex, newTrace, type Column, type Field, type Message, type StateDef, type Trace } from '../../sim-core';

export interface FtpParams {
  rtt: number;
  op: 'get' | 'put' | 'list';
  cred: 'ok' | 'anon' | 'bad';
  mode: 'passive' | 'active';
  cfw: 'none' | 'nat' | 'helper';
  sfw: boolean;
  tlsMode: 'explicit' | 'implicit';
  prot: 'P' | 'C';
  certOk: boolean;
  sauth: 'password' | 'key';
}

export const SRV = '203.0.113.21';
export const CLI = '192.168.1.20';
export const PUB = '198.51.100.7';
export const HOST = 'ftp.example.org';
export const FILE = 'relatorio.pdf';
export const USR = 'aluno';
export const PWD = 'S3nh@123';
export const PASV_PORT = 50000;
const ACT_PORT = 50001;
const SPORT = 49152;
const pStr = (ip: string, port: number) => ip.replace(/\./g, ',') + ',' + (port >> 8) + ',' + (port & 255);
const MAGIC = '%PDF-1.7 ... Relatório de notas do aluno ...';
const sp = (h: string) => h.replace(/(..)/g, '$1 ').trim();
const fl = (...f: Field[]): Field[] => f;

export const STATES: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'ctrl', label: 'Canal de controle' },
  { key: 'cred', label: 'Usuário e senha' },
  { key: 'data', label: 'Canal de dados' },
  { key: 'file', label: 'Arquivo' },
];
export const CSTATES: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'ftp', label: 'FTP: o observador lê' },
  { key: 'ftps', label: 'FTPS: o observador lê' },
  { key: 'sftp', label: 'SFTP: o observador lê' },
];

type X = Record<string, any>;

// ---------- mensagens genéricas ----------
function tcp3(tr: Trace, init: string, pInit: number, pResp: number, what: string, x?: X): Message {
  const resp = init === 'c' ? 's' : 'c';
  const seg = (from: string, to: string, flags: string) =>
    tr.add(
      from,
      to,
      Object.assign(
        {
          label: flags, proto: 'TCP', color: C0.tcp as string, len: flags === 'SYN' ? 60 : 52,
          info: (from === init ? pInit + ' → ' + pResp : pResp + ' → ' + pInit) + ' [' + flags + ']', phaseName: what,
          fields: fl({ sec: 'TCP (RFC 9293)' }, ['Porta de origem', String(from === init ? pInit : pResp), ''], ['Porta de destino', String(from === init ? pResp : pInit), ''], ['Flags', flags, '']),
          about: 'Segmento do handshake de três vias da ' + what + '. Quem inicia a conexão é o ' + (init === 'c' ? 'cliente' : 'servidor') + '.',
          dump: { text: 'TCP  ' + (from === init ? pInit + ' → ' + pResp : pResp + ' → ' + pInit) + '  [' + flags + ']', hot: false },
        },
        x || {},
      ),
    );
  seg(init, resp, 'SYN');
  seg(resp, init, 'SYN, ACK');
  return seg(init, resp, 'ACK');
}

function tcpFin(tr: Trace, init: string, pInit: number, pResp: number, what: string, x?: X): void {
  const resp = init === 'c' ? 's' : 'c';
  const seg = (from: string, to: string) =>
    tr.add(
      from,
      to,
      Object.assign(
        {
          label: 'FIN, ACK', proto: 'TCP', color: C0.tcp as string, len: 52, info: (from === init ? pInit + ' → ' + pResp : pResp + ' → ' + pInit) + ' [FIN, ACK]', phaseName: what,
          fields: fl({ sec: 'TCP (RFC 9293)' }, ['Flags', 'FIN, ACK', 'encerra a conexão']), about: 'Encerramento da ' + what + '.',
          dump: { text: 'TCP  ' + (from === init ? pInit + ' → ' + pResp : pResp + ' → ' + pInit) + '  [FIN, ACK]', hot: false },
        },
        x || {},
      ),
    );
  seg(init, resp);
  seg(resp, init);
}

/** SYN sem resposta (filtrado): tenta duas vezes e desiste. */
function synLost(tr: Trace, from: string, to: string, pFrom: number, pTo: number, what: string): Message {
  const m = tr.add(from, to, {
    label: 'SYN (sem resposta)', proto: 'TCP', color: C0.bad, len: 60, lost: true, info: pFrom + ' → ' + pTo + ' [SYN]', phaseName: what,
    fields: fl({ sec: 'TCP (RFC 9293)' }, ['Flags', 'SYN', ''], ['Resultado', 'descartado no caminho', 'nenhum SYN, ACK volta', 'expert']), tags: ['SYN sem resposta (filtrado)'],
    about: 'O SYN foi descartado: o firewall ou o NAT não tem regra para esta conexão.', dump: { text: 'TCP  ' + pFrom + ' → ' + pTo + '  [SYN]   (sem resposta)', hot: true },
  });
  tr.wait(1000);
  tr.add(from, to, {
    label: 'SYN (retransmissão)', proto: 'TCP', color: C0.bad, len: 60, lost: true, info: pFrom + ' → ' + pTo + ' [SYN] retransmissão', phaseName: what,
    fields: fl({ sec: 'TCP (RFC 9293)' }, ['Flags', 'SYN', ''], ['Resultado', 'descartado de novo', '', 'expert']), tags: ['retransmissão de SYN'],
    about: 'Segunda tentativa, depois de 1 s, e outra vez sem resposta.', dump: { text: 'TCP  ' + pFrom + ' → ' + pTo + '  [SYN] retransmissão', hot: true },
  });
  tr.wait(2000);
  return m;
}

function tlsHello(tr: Trace, what: string) {
  const a = tr.add('c', 's', {
    label: 'Client Hello', proto: 'TLS', color: C0.plain, len: 310, info: 'Client Hello', phaseName: what,
    fields: fl({ sec: 'TLS 1.3 (RFC 9846)' }, ['Tipo', 'Client Hello (1)', ''], ['Versões', 'TLS 1.3 e 1.2', ''], ['SNI', HOST, 'o nome do servidor vai em claro', 'expert'], ['Suites', 'TLS_AES_256_GCM_SHA384, ...', '']),
    about: 'O cliente propõe versões e cifras. O nome do servidor (SNI) é visível a quem captura.', dump: { text: 'TLS  Client Hello   SNI=' + HOST + '   (em claro)', hot: false },
  });
  const b = tr.add('s', 'c', {
    label: 'Server Hello', proto: 'TLS', color: C0.plain, len: 130, info: 'Server Hello', phaseName: what,
    fields: fl({ sec: 'TLS 1.3 (RFC 9846)' }, ['Tipo', 'Server Hello (2)', ''], ['Versão', 'TLS 1.3', ''], ['Suite', 'TLS_AES_256_GCM_SHA384', '']),
    about: 'O servidor escolhe a versão e a cifra e envia sua parte da troca de chaves. Daqui em diante tudo vai cifrado.', dump: { text: 'TLS  Server Hello   TLS 1.3, TLS_AES_256_GCM_SHA384', hot: false },
  });
  const c = tr.add('s', 'c', {
    label: 'Certificate, Finished', proto: 'TLS', color: C0.enc, enc: true, len: 1180, info: 'Encrypted Extensions, Certificate, Finished', phaseName: what, par: true, at: b.tSend + 0.2,
    fields: fl({ sec: 'TLS 1.3 (RFC 9846)' }, ['Mensagens', 'EncryptedExtensions, Certificate, CertificateVerify, Finished', 'o certificado também vai cifrado no TLS 1.3'], ['Certificado', HOST + ' (emitido por uma CA pública)', '']),
    about: 'O servidor prova quem é: certificado, assinatura e Finished, já cifrados.', dump: { text: 'TLS  17 03 03  ' + sp(hex('cert' + tr.msgs.length, 10)) + ' ...  (1180 B, cifrado)', hot: false },
  });
  return { hello: a, flight: b, cert: c };
}

function tlsFinish(tr: Trace, what: string): Message {
  return tr.add('c', 's', {
    label: 'Finished', proto: 'TLS', color: C0.enc, enc: true, len: 80, info: 'Finished', phaseName: what,
    fields: fl({ sec: 'TLS 1.3 (RFC 9846)' }, ['Mensagem', 'Finished', 'confirma a troca de chaves']), about: 'O cliente confirma. A partir daqui o canal está protegido nos dois sentidos.',
    dump: { text: 'TLS  17 03 03  ' + sp(hex('fin' + tr.msgs.length, 10)) + ' ...  (80 B, cifrado)', hot: false },
  });
}

export interface RunFtpOptions {
  tls: 'explicit' | 'implicit' | null;
  prot?: 'P' | 'C';
  certOk?: boolean;
  mode: 'passive' | 'active';
  cfw: 'none' | 'nat' | 'helper';
  sfw: boolean;
  cred: 'ok' | 'anon' | 'bad';
  op: 'get' | 'put' | 'list';
  f?: string;
  quiet?: boolean;
  noMile?: boolean;
}

// ---------- FTP e FTPS ----------
export function runFtp(tr: Trace, o: RunFtpOptions): X {
  const ow = tr.ow;
  const tls = o.tls;
  const E = { on: false };
  const f = o.f || null;
  const R: X = { fail: null, conns: 1, ctrlEnc: false, credSeen: true, dataEnc: false, tls, t0: tr.t, i0: tr.msgs.length, helper: false, dataOk: null, ports: [] as string[] };
  const st = (t: number, k: string, v: string, c: string) => {
    if (!o.quiet) tr.st(t, k, v, c);
  };
  const fev = (t: number, text: string, kind?: string) => {
    if (f) tr.ev(t, f, text, kind);
  };
  const ctl = (from: string, to: string, text: string, mean: string, about?: string, x?: X) => {
    const xx = x || {};
    const enc = E.on;
    const sens = !!xx.sens;
    return tr.add(from, to, {
      label: xx.label || text, proto: enc ? 'FTP/TLS' : 'FTP', color: enc ? C0.enc : xx.bad ? C0.bad : C0.plain, enc, len: 70 + text.length, info: text, phaseName: xx.phase || 'Controle', about: about || '',
      fields: enc
        ? fl({ sec: 'TLS: dados do aplicativo (canal de controle cifrado)' }, ['Registro', 'Application Data (cifrado)', 'a captura não mostra o conteúdo do comando'], [from === 'c' ? 'Comando (após decifrar)' : 'Resposta (após decifrar)', text, mean])
        : fl({ sec: 'FTP (RFC 959): canal de controle' }, [from === 'c' ? 'Comando' : 'Resposta', text, mean], ...(sens ? ([['Exposição', 'texto puro', 'qualquer observador no caminho lê o usuário e a senha', 'expert']] as Field[]) : [])),
      tags: !enc && sens ? ['credencial em texto puro'] : [],
      dump: enc ? { text: 'TLS  17 03 03  ' + sp(hex('c' + tr.msgs.length, 9)) + ' ...  (' + (text.length + 29) + ' B, cifrado)', hot: false } : { text: (from === 'c' ? 'C> ' : 'S> ') + text, hot: sens },
    });
  };
  const cport = tls === 'implicit' ? 990 : 21;
  R.ports.push(String(cport) + ' (controle)');

  // 1. conexão de controle
  tr.phase('1. Conexão de controle (TCP ' + cport + ')', 'ctrl');
  st(tr.t, 'phase', 'controle', 'warn');
  st(tr.t, 'ctrl', 'conectando', 'warn');
  st(tr.t, 'cred', '-', 'closed');
  st(tr.t, 'data', '-', 'closed');
  st(tr.t, 'file', '-', 'closed');
  if (!o.noMile) tr.mile(tr.t, 'Controle', 'porta ' + cport);
  const tc = tcp3(tr, 'c', SPORT, cport, 'conexão de controle');
  tr.lg(tc.tArr, 'FTP: conexão de controle estabelecida na porta ' + cport + '.', 'conn');

  const rejectCert = () => {
    tr.add('c', 's', {
      label: 'Alert: unknown_ca', proto: 'TLS', color: C0.bad, enc: true, len: 60, info: 'Alert: unknown_ca', phaseName: 'TLS',
      fields: fl({ sec: 'TLS 1.3 (RFC 9846)' }, ['Alerta', 'unknown_ca (48)', 'a CA do certificado não é conhecida']),
      about: 'O cliente não confia no certificado e encerra a conexão antes de enviar qualquer senha.', tags: ['certificado rejeitado'], dump: { text: 'TLS  Alert  unknown_ca', hot: false },
    });
    st(tr.t, 'ctrl', 'TLS recusado', 'bad');
    st(tr.t, 'cred', 'nada foi enviado', 'est');
    tr.lg(tr.t, 'TLS: o cliente rejeitou o certificado e encerrou. Nenhuma credencial saiu.', 'conn');
    R.fail = { stage: 'cert' };
    if (!o.noMile) tr.mile(tr.t, 'Certificado recusado', 'sem credenciais enviadas');
  };

  if (tls === 'implicit') {
    tr.phase('2. TLS desde o primeiro byte (FTPS implícito)', 'tls');
    const h = tlsHello(tr, 'TLS');
    tr.wait(0);
    R.cert = h;
    fev(h.hello.tSend + ow / 2, 'Encaminha o TLS sem entender o conteúdo', '');
    tr.ev(h.cert.tArr, 'c', o.certOk === false ? 'O certificado não é confiável: o cliente interrompe' : 'Valida o certificado do servidor (cadeia, nome e validade)', o.certOk === false ? 'warn' : 'ok');
    if (o.certOk === false) {
      rejectCert();
      return R;
    }
    tlsFinish(tr, 'TLS');
    E.on = true;
    R.ctrlEnc = true;
    st(tr.t, 'ctrl', 'TLS (cifrado)', 'est');
    if (!o.noMile) tr.mile(tr.t, 'TLS', 'porta 990');
  }
  st(tr.t, 'ctrl', E.on ? 'TLS (cifrado)' : 'em claro', E.on ? 'est' : 'bad');
  tr.phase('Saudação e login', 'login');
  ctl('s', 'c', '220 FTP server ready', 'código 220: o servidor está pronto', 'Saudação do servidor FTP.');
  if (tls === 'explicit') {
    ctl('c', 's', 'AUTH TLS', 'pede para proteger o canal de controle com TLS (RFC 4217)', 'O cliente pede TLS no mesmo canal da porta 21. Até aqui tudo foi em claro.');
    ctl('s', 'c', '234 AUTH TLS successful', 'código 234: o servidor aceita o TLS', 'O servidor aceita. O handshake TLS começa agora.');
    tr.phase('TLS no canal de controle (FTPS explícito)', 'tls');
    const h = tlsHello(tr, 'TLS');
    R.cert = h;
    tr.ev(h.cert.tArr, 'c', o.certOk === false ? 'O certificado não é confiável: o cliente interrompe' : 'Valida o certificado do servidor (cadeia, nome e validade)', o.certOk === false ? 'warn' : 'ok');
    if (o.certOk === false) {
      rejectCert();
      return R;
    }
    tlsFinish(tr, 'TLS');
    E.on = true;
    R.ctrlEnc = true;
    st(tr.t, 'ctrl', 'TLS (cifrado)', 'est');
    if (!o.noMile) tr.mile(tr.t, 'TLS', 'AUTH TLS');
  }
  // 2. autenticação
  const anon = o.cred === 'anon';
  const bad = o.cred === 'bad';
  const user = anon ? 'anonymous' : USR;
  const pass = anon ? 'aluno@exemplo.org' : bad ? 'senha-errada' : PWD;
  ctl('c', 's', 'USER ' + user, 'identifica o usuário', 'O cliente informa o nome do usuário.', { phase: 'Login' });
  ctl('s', 'c', '331 Password required', 'código 331: falta a senha', 'O servidor pede a senha.', { phase: 'Login' });
  const pm = ctl('c', 's', 'PASS ' + pass, 'a senha', 'A senha vai no comando PASS.' + (E.on ? ' Neste caso, dentro do túnel TLS.' : ' Em texto puro: quem captura o tráfego a lê.'), { sens: true, phase: 'Login' });
  if (!E.on) {
    tr.ev(pm.tSend + ow / 2, 'c', 'A senha sai em texto puro no canal de controle', 'warn');
    st(pm.tSend + ow / 2, 'cred', 'EXPOSTOS (texto puro)', 'bad');
    R.credSeen = true;
  } else {
    st(pm.tSend + ow / 2, 'cred', 'protegidos (TLS)', 'est');
    R.credSeen = false;
  }
  if (bad) {
    ctl('s', 'c', '530 Login incorrect', 'código 530: não autenticado', 'O servidor recusa o login.', { bad: true, phase: 'Login' });
    tr.ev(tr.t - 0.4, 's', 'Registra a falha de login', 'warn');
    tr.lg(tr.t, 'FTP: login recusado (530).', 'loss');
    st(tr.t, 'ctrl', 'sem sessão', 'bad');
    ctl('c', 's', 'QUIT', 'encerra a sessão', 'O cliente encerra.', { phase: 'Fim' });
    ctl('s', 'c', '221 Goodbye', 'código 221: sessão encerrada', '', { phase: 'Fim' });
    tcpFin(tr, 'c', SPORT, cport, 'conexão de controle');
    st(tr.t, 'phase', 'falhou', 'bad');
    st(tr.t, 'ctrl', 'encerrado', 'closed');
    R.fail = { stage: 'auth' };
    if (!o.noMile) tr.mile(tr.t, 'Login recusado', '530');
    return R;
  }
  const lg = ctl('s', 'c', anon ? '230 Anonymous access granted' : '230 User ' + USR + ' logged in', 'código 230: autenticado', 'Login aceito.', { phase: 'Login' });
  tr.lg(lg.tArr, 'FTP: login aceito' + (E.on ? ' (credenciais protegidas pelo TLS).' : '; a senha trafegou em texto puro.'), E.on ? 'conn' : 'loss');
  if (!o.noMile) tr.mile(tr.t, 'Login', E.on ? 'dentro do TLS' : 'em claro');
  if (tls) {
    ctl('c', 's', 'PBSZ 0', 'tamanho do buffer de proteção (sempre 0 em TLS)', 'Comando exigido pelas extensões de segurança (RFC 2228).', { phase: 'Proteção' });
    ctl('s', 'c', '200 PBSZ=0', '', '', { phase: 'Proteção' });
    ctl('c', 's', 'PROT ' + o.prot, o.prot === 'P' ? 'P (Private): os dados também serão cifrados' : 'C (Clear): os dados continuarão em claro', 'Define o nível de proteção do canal de DADOS.', { phase: 'Proteção' });
    ctl('s', 'c', '200 Protection level set to ' + o.prot, '', '', { phase: 'Proteção' });
    R.dataEnc = o.prot === 'P';
  }
  ctl('c', 's', 'TYPE I', 'modo binário', 'Transferência binária (imagem).', { phase: 'Login' });
  ctl('s', 'c', '200 Type set to I', '', '', { phase: 'Login' });

  // 3. canal de dados
  const op = o.op;
  const opCmd = op === 'get' ? 'RETR ' + FILE : op === 'put' ? 'STOR ' + FILE : 'LIST';
  const opName = op === 'get' ? 'download' : op === 'put' ? 'upload' : 'listagem';
  const active = o.mode === 'active';
  const dataEnc = !!tls && o.prot === 'P';
  const dataPhase = active ? '3. Canal de dados (modo ativo: o servidor conecta ao cliente)' : '3. Canal de dados (modo passivo: o cliente conecta ao servidor)';
  tr.phase(dataPhase, 'data');
  st(tr.t, 'phase', 'dados', 'warn');
  const dataFail = (why: string) => {
    st(tr.t, 'data', 'BLOQUEADO', 'bad');
    st(tr.t, 'file', 'não transferido', 'bad');
    R.dataOk = false;
    R.fail = { stage: 'data', why };
  };
  let ok = true;
  const dport = active ? 20 : PASV_PORT;
  const cdp = active ? ACT_PORT : SPORT + 1;
  if (!active) {
    ctl('c', 's', 'PASV', 'pede um endereço e uma porta para a conexão de dados', 'No modo passivo o servidor abre uma porta e o cliente conecta nela.', { phase: 'Dados' });
    const r = ctl('s', 'c', '227 Entering Passive Mode (' + pStr(SRV, PASV_PORT) + ')', 'servidor ' + SRV + ', porta ' + PASV_PORT + ' (195×256+80)', 'O servidor informa onde o cliente deve conectar. Cada transferência usa uma porta nova da faixa passiva.', { phase: 'Dados' });
    R.ports.push(PASV_PORT + ' (dados, faixa passiva)');
    fev(r.tSend + ow / 2, 'Conexão de dentro para fora: o estado do NAT a permite', 'ok');
    if (o.sfw === false) {
      tr.ev(r.tArr, 'c', 'Tenta conectar na porta ' + PASV_PORT + '…', '');
      synLost(tr, 'c', 's', cdp, dport, 'conexão de dados');
      tr.ev(tr.t, 's', 'O firewall do servidor não libera a faixa de portas passivas', 'warn');
      tr.ev(tr.t, 'c', 'Tempo esgotado: o cliente desiste do canal de dados', 'warn');
      ok = false;
      R.why = 'a faixa passiva não está liberada no firewall do servidor';
      tr.lg(tr.t, 'FTP: SYN para a porta passiva ' + PASV_PORT + ' sem resposta. O firewall do servidor bloqueia a faixa passiva.', 'loss');
      dataFail('faixa passiva bloqueada');
    } else {
      tcp3(tr, 'c', cdp, dport, 'conexão de dados');
      R.conns = 2;
      st(tr.t, 'data', 'conectado', 'est');
    }
  } else {
    const portCmd = 'PORT ' + pStr(CLI, ACT_PORT);
    let seen = CLI;
    const helper = o.cfw === 'helper' && !E.on;
    ctl('c', 's', portCmd, 'o cliente anuncia o endereço ' + CLI + ' e a porta ' + ACT_PORT + ' (195×256+81)', 'No modo ativo o cliente escuta e o SERVIDOR conecta. O endereço no comando é o endereço privado do cliente.', { phase: 'Dados' });
    R.ports.push(ACT_PORT + ' (cliente) e 20 (servidor)');
    if (helper) {
      fev(tr.t - 0.4, 'Inspeciona o PORT: troca ' + CLI + ' por ' + PUB + ' e abre a porta ' + ACT_PORT + ' para o servidor', 'ok');
      seen = PUB;
      R.helper = true;
    } else if (o.cfw !== 'none') {
      fev(tr.t - 0.4, E.on && o.cfw === 'helper' ? 'O comando está cifrado: o helper de FTP não consegue lê-lo' : 'Repassa o PORT sem alterar o endereço privado', E.on && o.cfw === 'helper' ? 'warn' : '');
    }
    ctl('s', 'c', '200 PORT command successful', 'código 200: o servidor guardou ' + seen + ':' + ACT_PORT, 'O servidor aceita o comando. A conexão só acontece quando houver uma transferência.', { phase: 'Dados' });
    R.activeSeen = seen;
  }
  // comando da operação
  ctl('c', 's', opCmd, op === 'get' ? 'baixar o arquivo' : op === 'put' ? 'enviar o arquivo' : 'listar o diretório', 'O cliente pede a operação. Os dados irão pelo canal de dados.', { phase: 'Dados' });
  if (active) {
    ctl('s', 'c', '150 Opening BINARY mode data connection', 'código 150: vou abrir o canal de dados', 'O servidor vai conectar de volta ao cliente.', { phase: 'Dados' });
    const reach = o.cfw === 'none' || (o.cfw === 'helper' && !E.on);
    if (!reach) {
      tr.ev(tr.t, 's', 'Conecta em ' + CLI + ':' + ACT_PORT + ' (endereço privado)', '');
      synLost(tr, 's', 'c', 20, ACT_PORT, 'conexão de dados');
      fev(tr.t, o.cfw === 'helper' && E.on ? 'Sem o PORT legível, não há regra: descarta o SYN de entrada' : 'O NAT não traduz ' + CLI + ' e o firewall de estado descarta o SYN de entrada', 'warn');
      ctl('s', 'c', "425 Can't build data connection: Connection timed out", 'código 425: o servidor não conseguiu abrir o canal de dados', 'Falha clássica do modo ativo atrás de NAT.', { bad: true, phase: 'Dados' });
      tr.lg(tr.t, 'FTP: o servidor não alcançou ' + CLI + ':' + ACT_PORT + '. ' + (o.cfw === 'helper' && E.on ? 'O helper não lê comandos cifrados.' : 'Endereço privado atrás de NAT.'), 'loss');
      ok = false;
      R.why = o.cfw === 'helper' && E.on ? 'o FTPS cifra o comando PORT e o helper do NAT não consegue lê-lo' : 'o servidor tentou conectar a um endereço privado atrás de NAT';
      dataFail(R.why);
    } else {
      tcp3(tr, 's', 20, ACT_PORT, 'conexão de dados');
      R.conns = 2;
      st(tr.t, 'data', 'conectado', 'est');
      if (o.cfw === 'none') fev(tr.t - 0.4, 'Sem NAT nem filtro: o SYN de entrada passa', '');
    }
  } else if (ok) {
    ctl('s', 'c', '150 Opening BINARY mode data connection', 'código 150: canal de dados aberto', 'O servidor confirma e começa a transferência.', { phase: 'Dados' });
  }
  if (!ok) {
    tr.phase('Encerramento', 'end');
    ctl('c', 's', 'QUIT', 'encerra a sessão', 'O cliente desiste e encerra.', { phase: 'Fim' });
    ctl('s', 'c', '221 Goodbye', 'código 221: sessão encerrada', '', { phase: 'Fim' });
    tcpFin(tr, 'c', SPORT, cport, 'conexão de controle');
    st(tr.t, 'phase', 'falhou', 'bad');
    st(tr.t, 'ctrl', 'encerrado', 'closed');
    if (!o.noMile) tr.mile(tr.t, 'Dados bloqueados', R.why ? 'falha' : '');
    return R;
  }
  // TLS no canal de dados
  if (dataEnc) {
    tr.add('c', 's', {
      label: 'Client Hello (retoma a sessão)', proto: 'TLS', color: C0.plain, len: 260, info: 'Client Hello com ticket de sessão', phaseName: 'TLS dos dados',
      fields: fl({ sec: 'TLS 1.3 (RFC 9846)' }, ['Tipo', 'Client Hello (1)', 'reaproveita a sessão do canal de controle'], ['pre_shared_key', 'ticket da sessão do controle', 'muitos servidores exigem o reuso da sessão']),
      about: 'O canal de dados também é protegido por TLS (PROT P). O cliente reaproveita a sessão do controle, o que prova que as duas conexões são da mesma pessoa.',
      dump: { text: 'TLS  Client Hello (retomada)   SNI=' + HOST, hot: false },
    });
    tr.add('s', 'c', {
      label: 'Server Hello, Finished', proto: 'TLS', color: C0.enc, enc: true, len: 200, info: 'Server Hello, Finished', phaseName: 'TLS dos dados',
      fields: fl({ sec: 'TLS 1.3 (RFC 9846)' }, ['Mensagens', 'Server Hello, Finished', 'sessão retomada']), about: 'O servidor aceita a retomada.',
      dump: { text: 'TLS  17 03 03  ' + sp(hex('dh' + tr.msgs.length, 10)) + ' ...  (200 B, cifrado)', hot: false },
    });
    tr.add('c', 's', {
      label: 'Finished', proto: 'TLS', color: C0.enc, enc: true, len: 80, info: 'Finished', phaseName: 'TLS dos dados', fields: fl({ sec: 'TLS 1.3 (RFC 9846)' }, ['Mensagem', 'Finished', '']), about: 'Canal de dados protegido.',
      dump: { text: 'TLS  17 03 03  ' + sp(hex('df' + tr.msgs.length, 10)) + ' ...  (80 B, cifrado)', hot: false },
    });
    st(tr.t, 'data', 'TLS (cifrado)', 'est');
  } else st(tr.t, 'data', 'em claro', tls ? 'warn' : 'bad');
  // transferência
  tr.lg(tr.t, 'FTP: canal de dados ' + (dataEnc ? 'protegido por TLS (PROT P).' : tls ? 'sem proteção (PROT C).' : 'em texto puro.'), dataEnc ? 'conn' : 'loss');
  tr.phase('4. Transferência pelo canal de dados', 'xfer');
  st(tr.t, 'phase', 'transferência', 'warn');
  st(tr.t, 'file', 'em curso', 'warn');
  if (!o.noMile) tr.mile(tr.t, 'Dados', active ? 'ativo' : 'passivo');
  const from = op === 'put' ? 'c' : 's';
  const to = op === 'put' ? 's' : 'c';
  const parts = op === 'list' ? 1 : 3;
  const dm = (i: number) => {
    const label = op === 'list' ? 'Listagem do diretório' : 'Dados do arquivo (' + (i + 1) + '/' + parts + ')';
    const body = op === 'list' ? '-rw-r--r-- 1 aluno aluno 1245184 out 13 relatorio.pdf' : MAGIC;
    return tr.add(from, to, {
      label, proto: dataEnc ? 'FTP-DATA/TLS' : 'FTP-DATA', color: dataEnc ? C0.enc : C0.data, enc: dataEnc, len: op === 'list' ? 220 : 1514, info: label, phaseName: 'Dados',
      fields: dataEnc
        ? fl({ sec: 'TLS: dados do aplicativo (canal de dados cifrado)' }, ['Registro', 'Application Data (cifrado)', 'o conteúdo do arquivo não aparece na captura'])
        : fl({ sec: 'FTP-DATA (RFC 959): canal de dados' }, ['Conteúdo', body, 'o arquivo trafega em claro', 'expert'], ['Cifrado?', 'não', 'quem captura reconstrói o arquivo', 'expert']),
      tags: dataEnc ? [] : ['conteúdo do arquivo em claro'],
      about: dataEnc ? 'Parte do ' + (op === 'list' ? 'resultado' : 'arquivo') + ', cifrada pelo TLS dos dados.' : 'Parte do ' + (op === 'list' ? 'resultado' : 'arquivo') + ' em texto puro: quem captura o tráfego a lê.',
      dump: dataEnc ? { text: 'TLS  17 03 03  ' + sp(hex('d' + tr.msgs.length, 9)) + ' ...  (1500 B, cifrado)', hot: false } : { text: 'DADOS  ' + body, hot: true },
    });
  };
  let last: Message | null = null;
  for (let i = 0; i < parts; i++) {
    last = dm(i);
    if (i === 0 && !dataEnc) tr.ev(last.tArr, op === 'put' ? 's' : 'c', 'Recebe o conteúdo em claro: ' + (op === 'list' ? 'a listagem' : 'o arquivo'), 'warn');
  }
  tr.ev(last!.tArr, op === 'put' ? 's' : 'c', op === 'list' ? 'Recebe a listagem' : 'Arquivo completo (' + FILE + ')', 'ok');
  tcpFin(tr, from === 'c' ? 'c' : 's', from === 'c' ? cdp : dport, from === 'c' ? dport : cdp, 'conexão de dados');
  ctl('s', 'c', '226 Transfer complete', 'código 226: transferência concluída', 'O servidor confirma pelo canal de CONTROLE que o canal de dados foi encerrado com sucesso.', { phase: 'Dados' });
  st(tr.t, 'file', op === 'list' ? 'listagem recebida' : 'transferido', 'est');
  st(tr.t, 'data', 'encerrado', 'closed');
  R.dataOk = true;
  R.tXfer = tr.t;
  if (!o.noMile) tr.mile(tr.t, 'Transferido', opName);
  // 5. fim
  tr.phase('5. Encerramento', 'end');
  ctl('c', 's', 'QUIT', 'encerra a sessão', 'O cliente encerra a sessão.', { phase: 'Fim' });
  ctl('s', 'c', '221 Goodbye', 'código 221: sessão encerrada', '', { phase: 'Fim' });
  tcpFin(tr, 'c', SPORT, cport, 'conexão de controle');
  st(tr.t, 'ctrl', 'encerrado', 'closed');
  st(tr.t, 'phase', 'concluído', 'est');
  R.tEnd = tr.t;
  R.i1 = tr.msgs.length;
  tr.lg(tr.t, 'FTP' + (tls ? 'S' : '') + ': ' + opName + ' concluído com ' + R.conns + ' conexões TCP' + (R.credSeen ? ' e a senha exposta.' : '.'), R.credSeen ? 'loss' : 'conn');
  return R;
}

export interface RunSftpOptions {
  op: 'get' | 'put' | 'list';
  sauth: 'password' | 'key';
  f?: string;
  quiet?: boolean;
  noMile?: boolean;
}

// ---------- SFTP ----------
export function runSftp(tr: Trace, o: RunSftpOptions): X {
  const ow = tr.ow;
  const R: X = { fail: null, conns: 1, ctrlEnc: true, credSeen: false, dataEnc: true, t0: tr.t, i0: tr.msgs.length, ports: ['22 (tudo)'] };
  const st = (t: number, k: string, v: string, c: string) => {
    if (!o.quiet) tr.st(t, k, v, c);
  };
  const op = o.op;
  const auth = o.sauth || 'password';
  const enc = (from: string, to: string, label: string, info: string, fields?: Field[], x?: X) =>
    tr.add(
      from,
      to,
      Object.assign(
        {
          label, proto: 'SSHv2', color: C0.enc as string, enc: true, len: 96, info: info || label, phaseName: 'SFTP',
          fields: fl({ sec: 'SSH Binary Packet (RFC 4253, seção 6)' }, ['Registro', 'pacote cifrado e autenticado', 'a captura não mostra o tipo da mensagem'], ...(fields || [])),
          dump: { text: 'SSH  ' + sp(hex('s' + tr.msgs.length, 9)) + ' ...  (cifrado)', hot: false },
        },
        x || {},
      ),
    );
  const clr = (from: string, to: string, label: string, fields: Field[], about?: string, dump?: string) =>
    tr.add(from, to, { label, proto: 'SSHv2', color: C0.plain, len: 140, info: label, phaseName: 'SSH', fields: fl({ sec: 'SSH (RFC 4253): em claro' }, ...(fields || [])), about: about || '', dump: { text: 'SSH  ' + (dump || label), hot: false } });
  tr.phase('1. Conexão TCP e SSH (porta 22)', 'ctrl');
  st(tr.t, 'phase', 'SSH', 'warn');
  st(tr.t, 'ctrl', 'conectando', 'warn');
  st(tr.t, 'cred', '-', 'closed');
  st(tr.t, 'data', '-', 'closed');
  st(tr.t, 'file', '-', 'closed');
  if (!o.noMile) tr.mile(tr.t, 'SSH', 'porta 22');
  tcp3(tr, 'c', SPORT, 22, 'conexão SSH');
  clr('c', 's', 'SSH-2.0-OpenSSH_9.6', [['Banner', 'SSH-2.0-OpenSSH_9.6', 'versão do protocolo e do software']], 'Cada lado anuncia sua versão, em texto.', 'SSH-2.0-OpenSSH_9.6  (banner do cliente)');
  clr('s', 'c', 'SSH-2.0-OpenSSH_9.6', [['Banner', 'SSH-2.0-OpenSSH_9.6', '']], 'O servidor responde com seu banner.', 'SSH-2.0-OpenSSH_9.6  (banner do servidor)');
  clr('c', 's', 'KEXINIT', [['Algoritmos', 'curve25519-sha256, ssh-ed25519, chacha20-poly1305@openssh.com, ...', 'lista de preferência']], 'O cliente lista algoritmos de troca de chaves, assinatura e cifra.', 'KEXINIT  (algoritmos do cliente)');
  clr('s', 'c', 'KEXINIT', [['Algoritmos', 'curve25519-sha256, ssh-ed25519, chacha20-poly1305@openssh.com, ...', '']], 'O servidor lista os dele; vale o primeiro da lista do cliente que o servidor também suporta.', 'KEXINIT  (algoritmos do servidor)');
  clr('c', 's', 'KEX_ECDH_INIT', [['Valor público do cliente (Q_C)', hex('qc', 16) + '...', 'curve25519']], 'O cliente envia o valor público da troca de chaves.', 'KEX_ECDH_INIT  Q_C=' + hex('qc', 8) + '...');
  const kr = clr(
    's', 'c', 'KEX_ECDH_REPLY',
    [['Chave do host', 'ssh-ed25519 SHA256:' + b64('hk', 43), 'identifica o servidor'], ['Valor público do servidor (Q_S)', hex('qs', 16) + '...', ''], ['Assinatura', 'ssh-ed25519', 'prova a posse da chave do host']],
    'O servidor envia a chave do host e a assinatura. O cliente confere a chave em known_hosts.', 'KEX_ECDH_REPLY  chave do host SHA256:' + b64('hk', 12) + '...',
  );
  tr.ev(kr.tArr, 'c', 'Confere a chave do servidor em known_hosts: conhecida', 'ok');
  clr('c', 's', 'NEWKEYS', [['Mensagem', 'NEWKEYS', 'a partir daqui os pacotes são cifrados']], 'Ativa as chaves negociadas.', 'NEWKEYS');
  const nk = clr('s', 'c', 'NEWKEYS', [['Mensagem', 'NEWKEYS', '']], 'O servidor também ativa as chaves. Tudo o que vem depois é cifrado.', 'NEWKEYS');
  st(nk.tArr, 'ctrl', 'SSH (cifrado)', 'est');
  tr.lg(nk.tArr, 'SSH: chaves negociadas; a partir daqui tudo é cifrado.', 'conn');
  if (!o.noMile) tr.mile(nk.tArr, 'Chaves', 'cifrado');
  tr.phase('2. Autenticação (já dentro do túnel cifrado)', 'login');
  const ua = enc('c', 's', auth === 'key' ? 'USERAUTH publickey (assinatura)' : 'USERAUTH password', 'USERAUTH_REQUEST', [['Método', auth === 'key' ? 'publickey (assinatura com a chave privada)' : 'password', '']], {
    len: auth === 'key' ? 200 : 110, about: auth === 'key' ? 'O cliente prova a posse da chave privada sem enviá-la.' : 'A senha vai dentro do túnel cifrado: um observador não a lê.',
  });
  st(ua.tSend + ow / 2, 'cred', auth === 'key' ? 'sem senha (chave pública)' : 'protegidos (SSH)', 'est');
  const us = enc('s', 'c', 'USERAUTH success', 'USERAUTH_SUCCESS', [['Resultado', 'sucesso', '']], { len: 80, about: 'Autenticado.' });
  tr.lg(us.tArr, 'SSH: usuário autenticado por ' + (auth === 'key' ? 'chave pública' : 'senha') + ', dentro do túnel cifrado.', 'conn');
  tr.phase('3. Canal e subsistema SFTP', 'chan');
  enc('c', 's', 'CHANNEL_OPEN session', 'CHANNEL_OPEN', [['Tipo', 'session', '']], { about: 'Abre um canal dentro da mesma conexão TCP.' });
  enc('s', 'c', 'CHANNEL_OPEN_CONFIRMATION', 'CHANNEL_OPEN_CONFIRMATION', [], { len: 80 });
  enc('c', 's', 'CHANNEL_REQUEST subsystem sftp', 'CHANNEL_REQUEST', [['Subsistema', 'sftp', 'pede o servidor de arquivos do SSH']], { about: 'O cliente pede o subsistema SFTP. Não existe uma segunda porta: tudo segue na porta 22.' });
  enc('s', 'c', 'CHANNEL_SUCCESS', 'CHANNEL_SUCCESS', [], { len: 60 });
  enc('c', 's', 'SSH_FXP_INIT v3', 'SFTP: INIT', [['Mensagem', 'SSH_FXP_INIT', 'versão 3 do protocolo']], { len: 70 });
  enc('s', 'c', 'SSH_FXP_VERSION 3', 'SFTP: VERSION', [['Mensagem', 'SSH_FXP_VERSION', '']], { len: 70 });
  if (!o.noMile) tr.mile(tr.t, 'SFTP', 'subsistema');
  st(tr.t, 'phase', 'transferência', 'warn');
  st(tr.t, 'data', 'mesmo canal (cifrado)', 'est');
  st(tr.t, 'file', 'em curso', 'warn');
  tr.phase('4. Operação no mesmo canal', 'xfer');
  let lastX: Message;
  if (op === 'get') {
    enc('c', 's', 'SSH_FXP_OPEN ' + FILE, 'SFTP: OPEN', [['Arquivo', FILE, '']], { len: 130 });
    enc('s', 'c', 'SSH_FXP_HANDLE', 'SFTP: HANDLE', [], { len: 80 });
    enc('c', 's', 'SSH_FXP_READ', 'SFTP: READ', [['Tamanho', '32768 B por pedido', '']], { len: 90 });
    for (let i = 0; i < 3; i++) lastX = enc('s', 'c', 'SSH_FXP_DATA (' + (i + 1) + '/3)', 'SFTP: DATA', [['Conteúdo', 'cifrado', 'o arquivo viaja dentro do túnel']], { color: C0.enc, len: 1514, about: 'Parte do arquivo, cifrada e com verificação de integridade.' });
  } else if (op === 'put') {
    enc('c', 's', 'SSH_FXP_OPEN ' + FILE + ' (escrita)', 'SFTP: OPEN', [['Arquivo', FILE, '']], { len: 130 });
    enc('s', 'c', 'SSH_FXP_HANDLE', 'SFTP: HANDLE', [], { len: 80 });
    for (let i = 0; i < 3; i++) lastX = enc('c', 's', 'SSH_FXP_WRITE (' + (i + 1) + '/3)', 'SFTP: WRITE', [['Conteúdo', 'cifrado', '']], { len: 1514, about: 'Parte do arquivo enviada pelo túnel cifrado.' });
    enc('s', 'c', 'SSH_FXP_STATUS ok', 'SFTP: STATUS', [['Resultado', 'SSH_FX_OK', '']], { len: 70 });
  } else {
    enc('c', 's', 'SSH_FXP_OPENDIR', 'SFTP: OPENDIR', [['Diretório', '.', '']], { len: 90 });
    enc('s', 'c', 'SSH_FXP_HANDLE', 'SFTP: HANDLE', [], { len: 80 });
    enc('c', 's', 'SSH_FXP_READDIR', 'SFTP: READDIR', [], { len: 70 });
    lastX = enc('s', 'c', 'SSH_FXP_NAME (' + FILE + ')', 'SFTP: NAME', [['Entradas', '1', '']], { len: 260 });
  }
  tr.ev(lastX!.tArr, op === 'put' ? 's' : 'c', op === 'list' ? 'Recebe a listagem' : op === 'put' ? 'Arquivo gravado' : 'Arquivo completo (' + FILE + ')', 'ok');
  enc('c', 's', 'SSH_FXP_CLOSE', 'SFTP: CLOSE', [], { len: 70 });
  enc('s', 'c', 'SSH_FXP_STATUS ok', 'SFTP: STATUS', [['Resultado', 'SSH_FX_OK', '']], { len: 70 });
  st(tr.t, 'file', op === 'list' ? 'listagem recebida' : 'transferido', 'est');
  R.dataOk = true;
  R.tXfer = tr.t;
  if (!o.noMile) tr.mile(tr.t, 'Transferido', op === 'get' ? 'download' : op === 'put' ? 'upload' : 'listagem');
  tr.phase('5. Encerramento', 'end');
  enc('c', 's', 'CHANNEL_CLOSE', 'CHANNEL_CLOSE', [], { len: 60 });
  enc('c', 's', 'DISCONNECT', 'DISCONNECT', [], { len: 60, par: true, at: tr.t - 0.4 + 0.1 });
  tcpFin(tr, 'c', SPORT, 22, 'conexão SSH');
  st(tr.t, 'ctrl', 'encerrado', 'closed');
  st(tr.t, 'phase', 'concluído', 'est');
  R.tEnd = tr.t;
  R.i1 = tr.msgs.length;
  tr.lg(tr.t, 'SFTP: ' + (op === 'get' ? 'download' : op === 'put' ? 'upload' : 'listagem') + ' concluído em 1 conexão TCP, tudo cifrado.', 'conn');
  return R;
}

// ---------- simulações por modo ----------
function simFtp(P: FtpParams, sub: string): Trace {
  const cols: Column[] = [
    { key: 'c', label: 'Cliente', sub: CLI, addr: CLI },
    { key: 'f', label: 'Firewall / NAT', sub: 'do cliente (' + PUB + ')', addr: PUB },
    { key: 's', label: 'Servidor', sub: SRV + (sub === 'ftps' ? ':' + (P.tlsMode === 'implicit' ? '990' : '21') : ':21'), addr: SRV },
  ];
  const tr = newTrace(cols, STATES, P.rtt);
  tr.raw.sub = sub;
  const fwTxt = { none: 'sem NAT nem filtro', nat: 'NAT com firewall de estado', helper: 'NAT com inspeção de FTP' }[P.cfw];
  tr.ev(0, 'f', 'Firewall do cliente: ' + fwTxt, '');
  const R = runFtp(tr, { tls: sub === 'ftps' ? P.tlsMode : null, prot: P.prot, certOk: P.certOk, mode: P.mode, cfw: P.cfw, sfw: P.sfw, cred: P.cred, op: P.op, f: 'f' });
  tr.raw.R = R;
  tr.raw.P = P;
  return tr;
}

function simSftp(P: FtpParams): Trace {
  const cols: Column[] = [
    { key: 'c', label: 'Cliente', sub: CLI, addr: CLI },
    { key: 'f', label: 'Firewall / NAT', sub: 'do cliente (' + PUB + ')', addr: PUB },
    { key: 's', label: 'Servidor SFTP', sub: SRV + ':22', addr: SRV },
  ];
  const tr = newTrace(cols, STATES, P.rtt);
  tr.raw.sub = 'sftp';
  tr.ev(0, 'f', 'Basta liberar a saída para a porta 22 (uma única conexão)', '');
  const R = runSftp(tr, { op: P.op, sauth: P.sauth, f: 'f' });
  tr.raw.R = R;
  tr.raw.P = P;
  return tr;
}

function simCompare(P: FtpParams): Trace {
  const cols: Column[] = [
    { key: 'c', label: 'Cliente', sub: CLI, addr: CLI },
    { key: 'o', label: 'Observador na rede', sub: 'Wi-Fi público ou provedor', addr: '192.168.1.1' },
    { key: 's', label: 'Servidor', sub: SRV, addr: SRV },
  ];
  const tr = newTrace(cols, CSTATES, P.rtt);
  const ow = tr.ow;
  const raw = tr.raw;
  raw.sub = 'cmp';
  raw.P = P;
  const op = P.op;
  const opName = op === 'get' ? 'baixar o arquivo' : op === 'put' ? 'enviar o arquivo' : 'listar o diretório';
  tr.st(0, 'phase', 'início', 'warn');
  tr.st(0, 'ftp', '-', 'closed');
  tr.st(0, 'ftps', '-', 'closed');
  tr.st(0, 'sftp', '-', 'closed');
  tr.mile(0, 'A. FTP', 'portas 21 e dados');
  const watch = (R: X, names: string) => {
    // anotações do observador a partir das mensagens de cada execução
    const ms = tr.msgs.slice(R.i0, R.i1 === undefined ? tr.msgs.length : R.i1);
    let seenPass = false;
    let seenData = false;
    let seenTlsCtl = false;
    let seenEnc = false;
    ms.forEach((m) => {
      const t = m.tSend + ow / 2;
      const label = m.label as string;
      if (names === 'ftp') {
        if (/^PASS /.test(label) && !seenPass) {
          seenPass = true;
          tr.ev(t, 'o', 'Lê o usuário e a senha: ' + USR + ' / ' + PWD, 'warn');
        }
        if (m.proto === 'FTP-DATA' && !seenData) {
          seenData = true;
          tr.ev(t, 'o', 'Lê o conteúdo: "' + (op === 'list' ? 'relatorio.pdf' : '%PDF-1.7 ...') + '" e reconstrói o arquivo', 'warn');
        }
      } else if (names === 'ftps') {
        if (label === 'AUTH TLS' && !seenTlsCtl) {
          seenTlsCtl = true;
          tr.ev(t, 'o', 'Vê o AUTH TLS e o Client Hello (nome do servidor): nada além disso', 'ok');
        }
        if (m.enc && /^PASS /.test(label) && !seenPass) {
          seenPass = true;
          tr.ev(t, 'o', 'Vê só bytes cifrados: o usuário e a senha ficam ocultos', 'ok');
        }
        if (m.proto === 'FTP-DATA/TLS' && !seenData) {
          seenData = true;
          tr.ev(t, 'o', 'Vê a segunda conexão (porta ' + PASV_PORT + ') e bytes cifrados', 'ok');
        }
      } else if (m.enc && !seenEnc) {
        seenEnc = true;
        tr.ev(t, 'o', 'Vê só pacotes cifrados na porta 22: nem o comando, nem o arquivo', 'ok');
      }
    });
  };
  // ---------- A. FTP ----------
  tr.phase('A. FTP (sem proteção)', 'a');
  const a = runFtp(tr, { tls: null, mode: 'passive', cfw: 'none', sfw: true, cred: 'ok', op, quiet: true, noMile: true });
  tr.st(a.i0 === undefined ? 0 : tr.msgs[a.i0 + 0].tSend, 'phase', 'A. FTP', 'warn');
  tr.st(a.tEnd, 'ftp', 'usuário, senha e arquivo', 'bad');
  tr.mile(a.tEnd, 'FTP concluído', fmtMs(a.tEnd - a.t0));
  watch(a, 'ftp');
  tr.wait(ow);
  // ---------- B. FTPS ----------
  tr.phase('B. FTPS explícito (AUTH TLS, PROT P)', 'b');
  tr.st(tr.t, 'phase', 'B. FTPS', 'warn');
  tr.mile(tr.t, 'B. FTPS', 'AUTH TLS');
  const b = runFtp(tr, { tls: 'explicit', prot: 'P', certOk: true, mode: 'passive', cfw: 'none', sfw: true, cred: 'ok', op, quiet: true, noMile: true });
  tr.st(b.tEnd, 'ftps', 'só metadados (cifrado)', 'est');
  tr.mile(b.tEnd, 'FTPS concluído', fmtMs(b.tEnd - b.t0));
  watch(b, 'ftps');
  tr.wait(ow);
  // ---------- C. SFTP ----------
  tr.phase('C. SFTP (SSH, porta 22)', 'c');
  tr.st(tr.t, 'phase', 'C. SFTP', 'warn');
  tr.mile(tr.t, 'C. SFTP', 'porta 22');
  const c = runSftp(tr, { op, sauth: 'password', quiet: true, noMile: true });
  tr.st(c.tEnd, 'sftp', 'só metadados (cifrado)', 'est');
  tr.st(c.tEnd, 'phase', 'concluído', 'est');
  tr.mile(c.tEnd, 'SFTP concluído', fmtMs(c.tEnd - c.t0));
  watch(c, 'sftp');
  raw.A = a;
  raw.B = b;
  raw.C = c;
  // texto do que o observador captura (usa as linhas "dump" de cada mensagem)
  const lines = (R: X) => tr.msgs.slice(R.i0, R.i1).filter((m) => m.dump).map((m) => ({ t: m.tArr, text: (m.dump as X).text, hot: !!(m.dump as X).hot }));
  raw.dump = { ftp: lines(a), ftps: lines(b), sftp: lines(c) };
  raw.opName = opName;
  return tr;
}

/** Motor do FTP: modos ftp, ftps, sftp e cmp (comparação dos três com um observador na rede). */
export function buildFtp(P: FtpParams, sub: string): Trace {
  return sub === 'cmp' ? simCompare(P) : sub === 'sftp' ? simSftp(P) : simFtp(P, sub);
}
