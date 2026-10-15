// Nota de hardening, configuração do nginx e tabela da cadeia de certificados.
import { esc } from '../../../sim-core';
import { SPROF, hasFS, isWeakSuite, weakVer, type TlsParams } from '../engine';

export interface Grade {
  items: [string, boolean][];
  ok: number;
  total: number;
  pct: number;
  letter: 'A' | 'B' | 'C' | 'D';
}

export function grade(P: TlsParams): Grade {
  const S = SPROF[P.sProf];
  const suites = S.s13.concat(S.s12);
  const items: [string, boolean][] = [
    ['TLS 1.3 habilitado', S.vers.indexOf('TLS 1.3') >= 0],
    ['Sem TLS 1.0 e 1.1', !S.vers.some(weakVer)],
    ['Só suítes com sigilo futuro (ECDHE ou TLS 1.3)', suites.every(hasFS)],
    ['Só cifras modernas (sem CBC e 3DES)', !suites.some(isWeakSuite)],
    ['Certificado válido, com cadeia completa e nome correto', P.certState === 'valid'],
    ['OCSP stapling ligado', !!P.stapling],
    ['HSTS enviado e redirecionamento 301', !!(P.sendHsts && P.redirect)],
    ['0-RTT desligado ou restrito', P.mode !== 'zero'],
    ['HTTPS ativo (porta 443)', !!P.serverHttps],
  ];
  const ok = items.filter((x) => x[1]).length;
  const pct = Math.round((ok / items.length) * 100);
  return { items, ok, total: items.length, pct, letter: pct >= 85 ? 'A' : pct >= 65 ? 'B' : pct >= 45 ? 'C' : 'D' };
}

export function nginx(P: TlsParams): string {
  const S = SPROF[P.sProf];
  const vers = S.vers.map((v) => 'TLSv' + v.slice(4)).join(' ');
  let s = '# nginx (servidor: ' + S.nome + ')\nserver {\n  listen 443 ssl http2;\n  server_name www.example.org;\n  ssl_protocols ' + vers + ';\n';
  if (S.s12.length) s += "  ssl_ciphers '" + S.s12.join(':') + "';\n";
  if (S.s13.length) s += '  # TLS 1.3 (suítes fixas): ' + S.s13.join(', ') + '\n';
  s +=
    '  ssl_certificate     /etc/ssl/www.example.org.' + (P.certState === 'chain' ? 'crt' : 'fullchain.pem') + ';\n  ssl_certificate_key /etc/ssl/www.example.org.key;   # ' +
    (P.keyType === 'ecdsa' ? 'ECDSA P-256' : 'RSA 2048') + '\n  ssl_stapling ' + (P.stapling ? 'on' : 'off') + ';\n  ssl_stapling_verify ' + (P.stapling ? 'on' : 'off') + ';\n  ssl_early_data ' +
    (P.mode === 'zero' ? 'on' : 'off') + ';\n' + (P.mtls ? '  ssl_verify_client on;\n' : '') +
    (P.sendHsts ? '  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\n' : '') + '}\n';
  s += P.redirect ? 'server {\n  listen 80;\n  server_name www.example.org;\n  return 301 https://$host$request_uri;\n}' : '# sem server na porta 80 redirecionando para HTTPS';
  return s;
}

export function chainTable(P: TlsParams): string {
  const exp = P.certState === 'expired';
  const st = P.certState;
  const kt = P.keyType === 'ecdsa' ? 'ECDSA P-256' : 'RSA 2048';
  const leafSubj = st === 'selfsigned' ? 'CN=www.example.org (autoassinado)' : 'CN=www.example.org';
  const san = st === 'name' ? 'shop.example.net' : 'www.example.org, example.org';
  const rows: string[][] = [
    [
      'Leaf (servidor)', leafSubj, st === 'selfsigned' ? 'CN=www.example.org' : 'CN=Example CA R3',
      exp ? '12/03/2024 a 12/03/2025 (VENCIDO)' : '01/09/2026 a 01/12/2026', san + ' | ' + kt + (st === 'revoked' ? ' | REVOGADO' : ''),
    ],
  ];
  if (st !== 'selfsigned') {
    rows.push(['Intermediário' + (st === 'chain' ? ' (NÃO enviado)' : ''), 'CN=Example CA R3', 'CN=Example Root CA X1', '2024 a 2030', 'CA:TRUE, pathlen:0']);
    rows.push(['Raiz (no repositório de confiança)', 'CN=Example Root CA X1', 'CN=Example Root CA X1 (autoassinada)', '2020 a 2040', 'CA:TRUE']);
  }
  return (
    '<table><thead><tr><th>Certificado</th><th>Assunto</th><th>Emissor</th><th>Validade</th><th>SAN, chave e estado</th></tr></thead><tbody>' +
    rows.map((r) => '<tr>' + r.map((c) => '<td>' + esc(c) + '</td>').join('') + '</tr>').join('') +
    '</tbody></table>'
  );
}
