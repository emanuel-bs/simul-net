// Comparação HTTP x HTTPS: a mesma ação do usuário feita em HTTP (porta 80) e em HTTPS (porta 443),
// com um observador na rede, para comparar confidencialidade, integridade, autenticação e custo.
import { COLORS as C0, fmtMs, hex, newTrace, type Field, type MessageOptions, type StateDef, type Trace } from '../../../sim-core';
import { closeSession, runTls, tcp3 } from './handshake';
import { SNI, type TlsParams } from './profiles';

export const CSTATES: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'chan', label: 'Canal' },
  { key: 'conf', label: 'Observador lê o conteúdo?' },
  { key: 'integ', label: 'Alteração é detectada?' },
  { key: 'host', label: 'Servidor autenticado' },
];
const COOKIE = 'sessionid=7f3a9c2e41d8b6';

interface Action {
  name: string;
  reqLabel: string;
  reqLines: string[];
  hot: number[];
  reqFields: Field[];
  leak: string;
  leakItems: string[];
  respLines: string[];
  respHot: number[];
  respFields: Field[];
  data: string;
  resp: string;
  respShort: string;
}

export const ACTIONS: Record<string, Action> = {
  login: {
    name: 'login com usuário e senha', reqLabel: 'POST /login',
    reqLines: ['POST /login HTTP/1.1', 'Host: ' + SNI, 'Content-Type: application/x-www-form-urlencoded', 'Content-Length: 29', '', 'usuario=aluno&senha=S3nh@123'], hot: [5],
    reqFields: [['Request line', 'POST /login HTTP/1.1', ''], ['Host', SNI, ''], ['Content-Type', 'application/x-www-form-urlencoded', ''], ['Corpo', 'usuario=aluno&senha=S3nh@123', 'usuário e senha em texto puro', 'expert']],
    leak: 'Lê o usuário e a senha: aluno / S3nh@123', leakItems: ['usuário e senha', 'cookie de sessão (na resposta)', 'todo o conteúdo da página'],
    respLines: ['HTTP/1.1 200 OK', 'Content-Type: text/html', 'Set-Cookie: ' + COOKIE + '; Path=/', '', '<html>... Bem-vindo, aluno ...</html>'], respHot: [2],
    respFields: [['Status', '200 OK', ''], ['Set-Cookie', COOKIE + '; Path=/', 'cookie de sessão em claro: quem o copiar assume a sessão', 'expert']],
    data: 'POST /login (usuário e senha no corpo)', resp: '200 OK com Set-Cookie: sessionid (Secure; HttpOnly)', respShort: '200 OK + Set-Cookie',
  },
  search: {
    name: 'busca (GET com termo)', reqLabel: 'GET /busca?q=resultado+do+exame',
    reqLines: ['GET /busca?q=resultado+do+exame HTTP/1.1', 'Host: ' + SNI, 'User-Agent: Mozilla/5.0'], hot: [0],
    reqFields: [['Request line', 'GET /busca?q=resultado+do+exame HTTP/1.1', 'o termo pesquisado vai na URL, em claro', 'expert'], ['Host', SNI, '']],
    leak: 'Lê a URL: o que o usuário está pesquisando', leakItems: ['o termo pesquisado e a URL', 'as páginas visitadas', 'todo o conteúdo da resposta'],
    respLines: ['HTTP/1.1 200 OK', 'Content-Type: text/html', '', '<html>... 3 resultados ...</html>'], respHot: [3],
    respFields: [['Status', '200 OK', ''], ['Content-Type', 'text/html', '']],
    data: 'GET /busca?q=resultado+do+exame', resp: '200 OK com os resultados da busca', respShort: '200 OK (resultados)',
  },
  page: {
    name: 'página com sessão (cookie)', reqLabel: 'GET /notas',
    reqLines: ['GET /notas HTTP/1.1', 'Host: ' + SNI, 'Cookie: ' + COOKIE], hot: [2],
    reqFields: [['Request line', 'GET /notas HTTP/1.1', ''], ['Host', SNI, ''], ['Cookie', COOKIE, 'o cookie identifica a sessão: quem o ler pode usá-lo', 'expert']],
    leak: 'Lê o cookie de sessão e a página', leakItems: ['o cookie de sessão', 'a página e as notas do aluno', 'as páginas visitadas'],
    respLines: ['HTTP/1.1 200 OK', 'Content-Type: text/html', '', '<html>... Notas do aluno ...</html>'], respHot: [3],
    respFields: [['Status', '200 OK', ''], ['Content-Type', 'text/html', 'conteúdo pessoal em claro', 'expert']],
    data: 'GET /notas com Cookie: sessionid', resp: '200 OK com as notas do aluno', respShort: '200 OK (notas)',
  },
};

interface DumpLine {
  t: number;
  text: string;
  hot: boolean;
  bad?: boolean;
}

export function simCompare(P: TlsParams): Trace {
  const tr = newTrace(
    [
      { key: 'c', label: 'Navegador', sub: '192.168.1.20', addr: '192.168.1.20' },
      { key: 'o', label: 'Observador na rede', sub: 'Wi-Fi público ou provedor', addr: '192.168.1.1' },
      { key: 's', label: 'Servidor', sub: '203.0.113.80', addr: '203.0.113.80' },
    ],
    CSTATES,
    P.rtt,
  );
  const raw = tr.raw;
  const ow = tr.ow;
  const A = ACTIONS[P.action] || ACTIONS.login;
  raw.sub = 'cmp';
  raw.action = P.action;
  raw.tamper = !!P.tamper;
  const tcp80 = (from: string, to: string, label: string, flags: string) =>
    tr.add(from, to, {
      label, proto: 'TCP', color: C0.tcp, len: 40, info: (from === 'c' ? '50121 → 80' : '80 → 50121') + ' [' + flags + ']', phaseName: 'HTTP',
      fields: [{ sec: 'TCP (RFC 9293)' }, ['Flags', flags, ''], ['Porta', '80 (HTTP)', 'porta sem proteção']],
      about: 'Segmento TCP da conexão HTTP, na porta 80.',
    });
  const http = (from: string, to: string, label: string, fields: Field[], o: MessageOptions) =>
    tr.add(
      from,
      to,
      Object.assign(
        {
          label, proto: 'HTTP', color: C0.plain as string, len: 260, info: label, phaseName: 'HTTP', about: '',
          fields: ([{ sec: 'HTTP (texto puro, porta 80)' }] as Field[]).concat(fields, [['Cifrado?', 'não', 'qualquer observador no caminho lê e pode alterar', 'expert']] as Field[]),
        },
        o,
      ),
    );
  tr.st(0, 'phase', 'início', 'warn');
  tr.st(0, 'chan', '-', 'closed');
  tr.st(0, 'conf', '-', 'closed');
  tr.st(0, 'integ', '-', 'closed');
  tr.st(0, 'host', '-', 'closed');
  tr.mile(0, 'A. HTTP', 'porta 80');

  // ---------- A. HTTP ----------
  tr.phase('A. HTTP (porta 80, sem proteção)', 'http');
  const tH0 = tr.t;
  const iH0 = tr.msgs.length;
  tr.st(tr.t, 'phase', 'HTTP', 'warn');
  tcp80('c', 's', 'SYN', 'SYN');
  tcp80('s', 'c', 'SYN, ACK', 'SYN, ACK');
  const ack = tcp80('c', 's', 'ACK', 'ACK');
  tr.st(tr.t, 'chan', 'em claro', 'bad');
  const req = http('c', 's', A.reqLabel, A.reqFields, { info: A.reqLines[0], about: 'A requisição vai em texto puro. O observador na rede lê tudo o que o navegador envia.' });
  tr.ev(req.tSend + ow / 2, 'o', A.leak, 'warn');
  tr.st(req.tSend + ow / 2, 'conf', 'SIM: tudo legível', 'bad');
  const rsp = http('s', 'c', P.tamper ? A.respShort + ' (+ conteúdo injetado)' : A.respShort, A.respFields, {
    len: 1200, info: 'HTTP/1.1 200 OK', color: P.tamper ? C0.bad : C0.plain,
    about: P.tamper ? 'A resposta foi alterada no caminho: um banner foi injetado na página. O navegador não tem como perceber.' : 'A resposta, também em texto puro.',
  });
  if (P.tamper) {
    rsp.tags.push('alterada no caminho (conteúdo injetado)');
    tr.ev(rsp.tSend + ow / 2, 'o', 'Um equipamento no caminho (proxy ou Wi-Fi público) injeta um banner na página', 'warn');
    tr.ev(rsp.tArr, 'c', 'Exibe a página alterada: o HTTP não permite detectar a adulteração', 'warn');
    tr.st(rsp.tArr, 'integ', 'NÃO: página alterada sem aviso', 'bad');
  } else tr.st(rsp.tArr, 'integ', 'não há como saber', 'warn');
  tr.st(rsp.tArr, 'host', 'NÃO (qualquer um pode se passar)', 'bad');
  tr.lg(req.tSend, 'HTTP: a requisição (' + A.name + ') trafega em texto puro e o observador na rede a lê.', 'loss');
  tr.lg(rsp.tArr, 'HTTP: a resposta chega em ' + fmtMs(rsp.tArr - tH0) + ' desde o SYN' + (P.tamper ? ', mas foi alterada no caminho sem que ninguém perceba' : '') + '.', 'data');
  tcp80('c', 's', 'FIN, ACK', 'FIN, ACK');
  tcp80('s', 'c', 'FIN, ACK', 'FIN, ACK');
  const iH1 = tr.msgs.length;
  raw.http = { t0: tH0, tResp: rsp.tArr, bytes: tr.msgs.slice(iH0, iH1).reduce((a, m) => a + m.len, 0), msgs: iH1 - iH0, leak: A.leakItems, rtts: 1 };
  tr.mile(rsp.tArr, 'HTTP concluído', fmtMs(rsp.tArr - tH0));

  // ---------- B. HTTPS ----------
  tr.wait(ow);
  tr.phase('B. HTTPS (porta 443, TLS)', 'https');
  const tS0 = tr.t;
  const iS0 = tr.msgs.length;
  tr.st(tr.t, 'phase', 'HTTPS', 'warn');
  tr.st(tr.t, 'integ', '-', 'closed');
  tr.st(tr.t, 'conf', '-', 'closed');
  tr.mile(tr.t, 'B. HTTPS', 'porta 443');
  tcp3(tr, true);
  tr.st(tr.t, 'chan', 'TLS (cifrado)', 'est');
  const R = runTls(tr, P, { sub: 'cmp', mode: 'full', cert: true, hsts: false, tamper: P.tamper, req: { label: A.reqLabel, data: A.data }, resp: A.resp });
  raw.R = R;
  const ms = tr.msgs;
  // o observador vê o ClientHello e depois só registros cifrados
  let seenReq = false;
  let seenFlight = false;
  for (let i = iS0; i < ms.length; i++) {
    const m = ms[i];
    const label = m.label as string;
    if (label === 'Client Hello') {
      tr.ev(m.tSend + ow / 2, 'o', 'Vê o ClientHello: o IP e o nome do site (SNI ' + SNI + '), não o conteúdo', '');
    } else if (!seenFlight && m.from === 's' && m.to === 'c' && /Certificate/.test(label)) {
      seenFlight = true;
      tr.ev(m.tSend + ow / 2, 'o', m.enc ? 'Vê um registro cifrado: nem o certificado fica visível (TLS 1.3)' : 'Vê o certificado do servidor em claro (TLS 1.2)', m.enc ? 'ok' : '');
    } else if (!seenReq && m.enc && m.from === 'c' && /^(HTTP\/2 )?(GET|POST)/.test(label)) {
      seenReq = true;
      tr.ev(m.tSend + ow / 2, 'o', 'Vê só bytes cifrados (' + m.len + ' B): senha, cookie e URL ficam ocultos', 'ok');
      tr.st(m.tSend + ow / 2, 'conf', 'NÃO: só bytes cifrados', 'est');
    }
  }
  const respM = ms
    .slice(iS0)
    .filter((m) => m.from === 's' && m.to === 'c' && /^(HTTP\/2 |HTTP\/1\.1 )200/.test(m.label as string))
    .pop();
  const tResp = respM ? respM.tArr : tr.t;
  const tamperDet = R.fail && R.fail.stage === 'tamper';
  if (R.ver && !R.fail) {
    tr.st(tResp, 'integ', 'SIM: AEAD detecta alteração', 'est');
    tr.st(tResp, 'host', 'SIM (certificado)', 'est');
    closeSession(tr, R);
  } else if (tamperDet) {
    tr.st(tResp, 'integ', 'SIM: bad_record_mac', 'est');
    tr.st(tResp, 'host', 'SIM (certificado)', 'est');
  }
  const iS1 = tr.msgs.length;
  raw.https = {
    t0: tS0, tResp, bytes: tr.msgs.slice(iS0, iS1).reduce((a, m) => a + m.len, 0), msgs: iS1 - iS0, ver: R.ver, suite: R.suite, fs: R.fs,
    tampered: !!tamperDet, failed: !!(R.fail && !tamperDet), fail: R.fail, rtts: R.ver === 'TLS 1.3' ? 2 : R.ver ? 3 : 0,
  };
  if (!R.fail) tr.mile(tResp, 'HTTPS concluído', fmtMs(tResp - tS0));

  // ---------- o que o observador captura ----------
  const hot = (arr: string[], idx: number[]): DumpLine[] => arr.map((t, i) => ({ t: 0, text: t, hot: idx.indexOf(i) >= 0 }));
  const hl: DumpLine[] = [{ t: ack.tArr, text: 'TCP  SYN, SYN-ACK, ACK  (porta 80)', hot: false }];
  hot(A.reqLines, A.hot).forEach((l) => {
    l.t = req.tArr;
    hl.push(l);
  });
  hl.push({ t: req.tArr, text: '', hot: false });
  hot(A.respLines, A.respHot).forEach((l) => {
    l.t = rsp.tArr;
    hl.push(l);
  });
  if (P.tamper) hl.splice(hl.length, 0, { t: rsp.tArr, text: '<div class="oferta">Clique aqui e ganhe um prêmio</div>   <- injetado no caminho', hot: true });
  const sl: DumpLine[] = [];
  const tcpAck = ms[iS0 + 2];
  sl.push({ t: tcpAck ? tcpAck.tArr : tS0, text: 'TCP  SYN, SYN-ACK, ACK  (porta 443)', hot: false });
  for (let i = iS0 + 3; i < ms.length; i++) {
    const m = ms[i];
    const label = m.label as string;
    if (m.proto === 'TCP') continue;
    if (label === 'Client Hello') sl.push({ t: m.tArr, text: 'TLS Client Hello   SNI=' + SNI + '   (em claro: o nome do site)', hot: false });
    else if (label === 'Server Hello') sl.push({ t: m.tArr, text: 'TLS Server Hello   ' + (R.ver || '') + ', ' + (R.suite || ''), hot: false });
    else if (!m.enc && /Certificate/.test(label)) sl.push({ t: m.tArr, text: 'TLS Certificate (em claro: ' + SNI + ')', hot: false });
    else if (m.enc) {
      const sz = m.len - 40;
      const hx = hex('rec' + i + P.action, 12).replace(/(..)/g, '$1 ').trim();
      const tag =
        /^(HTTP\/2 |HTTP\/1\.1 )?(GET|POST)/.test(label) || /^HTTP\/2 (GET|POST)/.test(label)
          ? '   <- pedido (ilegível)'
          : /^(HTTP\/2 |HTTP\/1\.1 )200/.test(label)
            ? '   <- resposta (ilegível)' + (/alterada/.test(label) ? ', ALTERADA: a tag não confere' : '')
            : /Alert/.test(label)
              ? '   <- alerta'
              : '';
      sl.push({
        t: m.tArr,
        text: '17 03 03 ' + (sz >> 8).toString(16).padStart(2, '0') + ' ' + (sz & 255).toString(16).padStart(2, '0') + '  ' + hx + ' ...  (' + sz + ' B, cifrado)' + tag,
        hot: false,
        bad: /alterada/.test(label),
      });
    }
  }
  raw.dump = { http: hl, https: sl };
  return tr;
}
