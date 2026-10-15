import { COLORS as C0, type Field, type MessageOptions, type Trace } from '../../../sim-core';
import { WSTATES, closeSession, mkTrace, runTls, tcp3 } from './handshake';
import type { TlsParams } from './profiles';

// ---------- HTTP, HTTPS e HSTS ----------
export function simWeb(P: TlsParams): Trace {
  const tr = mkTrace(P, false, WSTATES);
  const raw = tr.raw;
  raw.sub = 'web';
  raw.W = { path: '', exposed: false, hstsStored: false, upgraded: false, httpsOnly: false };
  const W = raw.W;
  const tcp80 = (from: string, to: string, label: string, flags: string) =>
    tr.add(from, to, {
      label, proto: 'TCP', color: C0.tcp, len: 40, info: (from === 'c' ? '50121 → 80' : '80 → 50121') + ' [' + flags + ']', phaseName: 'HTTP',
      fields: [{ sec: 'TCP (RFC 9293)' }, ['Flags', flags, ''], ['Porta', '80 (HTTP)', 'porta sem proteção']],
      about: 'Segmento TCP da conexão HTTP na porta 80.',
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
  const tcpAt = (a: string, b: string) => {
    tcp80(a, b, 'SYN', 'SYN');
    tcp80(b, a, 'SYN, ACK', 'SYN, ACK');
    tcp80(a, b, 'ACK', 'ACK');
  };
  tr.st(0, 'phase', 'início', 'warn');
  tr.st(0, 'hsts', P.hsts === 'none' ? 'desconhecido' : P.hsts === 'cached' ? 'em cache' : 'preload', P.hsts === 'none' ? 'closed' : 'est');
  tr.st(0, 'chan', '-', 'closed');
  tr.st(0, 'host', '-', 'closed');
  tr.mile(0, 'Usuário digita', 'example.org');
  const httpsFlow = () => {
    tr.phase('2. Conexão HTTPS (porta 443)', 'https');
    tr.st(tr.t, 'phase', 'HTTPS', 'warn');
    tr.mile(tr.t, 'HTTPS', 'TCP 443 + TLS');
    tcp3(tr, true);
    tr.st(tr.t, 'chan', 'TLS (cifrado)', 'est');
    const R = runTls(tr, P, { sub: 'web', mode: 'full', cert: true, hsts: P.sendHsts, ocsp: false });
    raw.R = R;
    if (R.ver && !R.fail) {
      tr.st(tr.t, 'host', 'verificado', 'est');
      if (P.sendHsts) {
        W.hstsStored = true;
        tr.ev(tr.t, 'c', 'Recebe Strict-Transport-Security: max-age=31536000; includeSubDomains; preload e passa a lembrar', 'ok');
        tr.st(tr.t, 'hsts', 'registrado (1 ano)', 'est');
        tr.lg(tr.t, 'Cabeçalho HSTS recebido: o navegador só usará HTTPS neste site por 1 ano.', 'conn');
      } else tr.ev(tr.t, 's', 'Sem cabeçalho HSTS: o navegador não aprende a exigir HTTPS', 'warn');
      closeSession(tr, R);
    }
  };
  if (!P.serverHttps) {
    W.path = 'http-only';
    W.exposed = true;
    tr.phase('1. Somente HTTP (porta 80)', 'http');
    tr.st(tr.t, 'phase', 'HTTP', 'warn');
    tr.mile(tr.t, 'HTTP', 'sem TLS');
    tcpAt('c', 's');
    tr.st(tr.t, 'chan', 'em claro', 'bad');
    http('c', 's', 'GET / HTTP/1.1', [['Request line', 'GET / HTTP/1.1', ''], ['Host', 'example.org', ''], ['Cookie', 'sessionid=ab12…', 'o cookie de sessão viaja em claro', 'expert']], {
      info: 'GET / HTTP/1.1', about: 'A requisição e o cookie de sessão trafegam em texto puro.',
    });
    http('s', 'c', 'HTTP/1.1 200 OK', [['Status', '200 OK', ''], ['Content-Type', 'text/html', '']], { len: 900, info: 'HTTP/1.1 200 OK', about: 'A resposta, também em claro.' });
    tr.ev(tr.t, 'c', 'Tudo em claro: conteúdo, cookies e senhas podem ser lidos e alterados por quem estiver no caminho', 'warn');
    tr.ev(tr.t, 's', 'O servidor não tem HTTPS: não há autenticação do servidor nem sigilo', 'warn');
    tr.lg(tr.t, 'Site somente HTTP: sem cifragem, sem integridade e sem autenticação do servidor.', 'loss');
    tr.st(tr.t, 'phase', 'Encerrada', 'bad');
    tr.mile(tr.t, 'Exposto', 'conteúdo em claro');
    return tr;
  }
  if (P.hsts !== 'none') {
    W.path = P.hsts;
    W.upgraded = true;
    tr.phase('1. O navegador aplica o HSTS', 'hsts');
    tr.st(tr.t, 'phase', 'HSTS', 'warn');
    tr.mile(tr.t, 'HSTS', 'sem HTTP');
    tr.ev(
      tr.t,
      'c',
      P.hsts === 'cached'
        ? 'HSTS em cache: converte http:// em https:// internamente (307 Internal Redirect), antes de enviar qualquer pacote'
        : 'Domínio na lista de preload: HTTPS exigido desde a primeira visita, sem enviar nenhum pacote HTTP',
      'ok',
    );
    tr.lg(
      tr.t,
      P.hsts === 'cached'
        ? 'HSTS em cache: nenhuma requisição HTTP é enviada, a conexão já começa em HTTPS.'
        : 'Domínio na lista de preload do navegador: HTTPS obrigatório mesmo na primeira visita.',
      'conn',
    );
    tr.wait(0.5);
    httpsFlow();
    return tr;
  }
  if (!P.redirect) {
    W.path = 'no-redirect';
    W.exposed = true;
    tr.phase('1. Requisição HTTP (porta 80)', 'http');
    tr.st(tr.t, 'phase', 'HTTP', 'warn');
    tr.mile(tr.t, 'HTTP', 'sem redirecionamento');
    tcpAt('c', 's');
    tr.st(tr.t, 'chan', 'em claro', 'bad');
    http('c', 's', 'GET / HTTP/1.1', [['Request line', 'GET / HTTP/1.1', ''], ['Host', 'example.org', '']], { info: 'GET / HTTP/1.1', about: 'O usuário digitou o endereço sem https.' });
    http('s', 'c', 'HTTP/1.1 200 OK', [['Status', '200 OK', 'o servidor responde o conteúdo em HTTP, sem redirecionar'], ['Content-Type', 'text/html', '']], {
      len: 900, info: 'HTTP/1.1 200 OK', about: 'Sem redirecionamento, o usuário permanece em HTTP.',
    });
    tr.ev(tr.t, 's', 'Sem redirecionamento para HTTPS: o usuário continua em HTTP, em claro', 'warn');
    tr.ev(tr.t, 'c', 'Sem HSTS e sem redirecionamento: nada leva o navegador ao HTTPS', 'warn');
    tr.lg(tr.t, 'O servidor atende HTTP sem redirecionar: o usuário fica exposto mesmo existindo HTTPS.', 'loss');
    tr.st(tr.t, 'phase', 'Encerrada', 'bad');
    tr.mile(tr.t, 'Exposto', 'HTTP mantido');
    return tr;
  }
  W.path = 'redirect';
  W.exposed = true;
  tr.phase('1. Primeira requisição em HTTP (porta 80)', 'http');
  tr.st(tr.t, 'phase', 'HTTP', 'warn');
  tr.mile(tr.t, 'HTTP', 'porta 80');
  tcpAt('c', 's');
  tr.st(tr.t, 'chan', 'em claro', 'warn');
  const g = http('c', 's', 'GET / HTTP/1.1', [['Request line', 'GET / HTTP/1.1', ''], ['Host', 'example.org', '']], {
    info: 'GET / HTTP/1.1',
    about: 'Sem HSTS, o navegador começa em HTTP quando o usuário digita só o nome do site. Esta primeira requisição é a janela de exposição.',
  });
  tr.ev(g.tSend, 'c', 'Sem HSTS: a primeira requisição sai em HTTP puro', 'warn');
  const rd = http('s', 'c', 'HTTP/1.1 301 Moved Permanently', [['Status', '301 Moved Permanently', ''], ['Location', 'https://example.org/', 'manda o navegador para a versão cifrada']], {
    len: 300, info: 'HTTP/1.1 301 Moved Permanently',
    about: 'O servidor redireciona para HTTPS. Este redirecionamento vai em claro: um atacante no caminho poderia alterá-lo ou impedi-lo (por isso o HSTS).',
  });
  tr.ev(rd.tArr, 'c', 'O 301 também vai em claro: quem estiver no caminho poderia impedir o upgrade', 'warn');
  tr.lg(rd.tArr, 'Redirecionamento 301 para HTTPS. A primeira requisição e a resposta trafegaram em claro: janela de exposição que o HSTS fecha.', 'loss');
  tcp80('c', 's', 'FIN, ACK', 'FIN, ACK');
  tcp80('s', 'c', 'FIN, ACK', 'FIN, ACK');
  httpsFlow();
  return tr;
}
