// Motor HTTPS (TLS 1.3, TLS 1.2, certificados X.509 e HSTS).
// RFC 9846 (TLS 1.3), RFC 5246 (TLS 1.2, atualizada pela RFC 9846, apêndice D), RFC 6066 (SNI e OCSP stapling), RFC 6797 (HSTS), RFC 5280 (X.509).
// Não há criptografia real: valores de chaves, hashes e assinaturas são determinísticos e ilustrativos.

export type TlsVersion = 'TLS 1.3' | 'TLS 1.2' | 'TLS 1.1' | 'TLS 1.0';
export type ClientProfile = 'moderno' | 'intermediario' | 'legado';
export type ServerProfile = ClientProfile | 'endurecido';
export type CertState = 'valid' | 'expired' | 'name' | 'selfsigned' | 'chain' | 'revoked';

/** Parâmetros dos controles do painel (ids iguais aos do simulador legado). */
export interface TlsParams {
  rtt: number;
  cProf: ClientProfile;
  hsts: 'none' | 'cached' | 'preload';
  mode: 'full' | 'resume' | 'zero';
  mtls: boolean;
  certState: CertState;
  stapling: boolean;
  sProf: ServerProfile;
  redirect: boolean;
  sendHsts: boolean;
  serverHttps: boolean;
  action: 'login' | 'search' | 'page';
  tamper: boolean;
  keyType: 'ecdsa' | 'rsa';
  downgrade: boolean;
}

export interface TlsProfile {
  nome: string;
  vers: TlsVersion[];
  s13: string[];
  s12: string[];
}
export interface ClientTls extends TlsProfile {
  ua: string;
}
export interface ServerTls extends TlsProfile {
  sw: string;
}

export const ORDER: TlsVersion[] = ['TLS 1.3', 'TLS 1.2', 'TLS 1.1', 'TLS 1.0'];
const S13_ALL = ['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256', 'TLS_AES_128_GCM_SHA256'];

export const CPROF: Record<ClientProfile, ClientTls> = {
  moderno: {
    nome: 'Moderno (TLS 1.3 e 1.2)', vers: ['TLS 1.3', 'TLS 1.2'], s13: S13_ALL,
    s12: ['ECDHE-ECDSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-ECDSA-CHACHA20-POLY1305', 'ECDHE-RSA-AES256-GCM-SHA384'],
    ua: 'Mozilla/5.0 (Chrome 124)',
  },
  intermediario: {
    nome: 'Intermediário (só TLS 1.2)', vers: ['TLS 1.2'], s13: [],
    s12: ['ECDHE-ECDSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-SHA256', 'TLS_RSA_WITH_AES_128_CBC_SHA'],
    ua: 'Android 7 (TLS 1.2)',
  },
  legado: {
    nome: 'Legado (TLS 1.0 e 1.1)', vers: ['TLS 1.1', 'TLS 1.0'], s13: [],
    s12: ['TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'],
    ua: 'Internet Explorer 8 (Windows XP)',
  },
};
export const SPROF: Record<ServerProfile, ServerTls> = {
  moderno: {
    nome: 'Moderno (TLS 1.3 e 1.2)', vers: ['TLS 1.3', 'TLS 1.2'], s13: S13_ALL,
    s12: ['ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-ECDSA-CHACHA20-POLY1305', 'ECDHE-RSA-AES128-GCM-SHA256'],
    sw: 'nginx/1.25.3',
  },
  intermediario: {
    nome: 'Intermediário (só TLS 1.2)', vers: ['TLS 1.2'], s13: [],
    s12: ['ECDHE-ECDSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-SHA256'],
    sw: 'Apache/2.4.29',
  },
  legado: {
    nome: 'Legado (TLS 1.0 a 1.2, RSA sem sigilo futuro)', vers: ['TLS 1.2', 'TLS 1.1', 'TLS 1.0'], s13: [],
    s12: ['TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'],
    sw: 'Apache/2.2.15',
  },
  endurecido: {
    nome: 'Endurecido (só TLS 1.3)', vers: ['TLS 1.3'], s13: ['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256'], s12: [],
    sw: 'nginx/1.25.3',
  },
};

export const compat = (suite: string, kt: string): boolean => (/ECDSA/.test(suite) ? kt === 'ecdsa' : /RSA/.test(suite) ? kt === 'rsa' : true);
export const hasFS = (suite: string): boolean => /^TLS_(AES|CHACHA)/.test(suite) || /ECDHE|DHE/.test(suite);
export const isWeakSuite = (suite: string): boolean => /CBC|3DES|RC4|_SHA$/.test(suite) && !/SHA256|SHA384/.test(suite);
export const weakVer = (v: string): boolean => v === 'TLS 1.0' || v === 'TLS 1.1';

export const ALERT: Record<string, [number, string]> = {
  protocol_version: [70, 'protocol_version'],
  handshake_failure: [40, 'handshake_failure'],
  bad_certificate: [42, 'bad_certificate'],
  certificate_revoked: [44, 'certificate_revoked'],
  certificate_expired: [45, 'certificate_expired'],
  unknown_ca: [48, 'unknown_ca'],
  illegal_parameter: [47, 'illegal_parameter'],
  close_notify: [0, 'close_notify'],
};
export const BROWSER_ERR: Record<string, string> = {
  expired: 'ERR_CERT_DATE_INVALID',
  name: 'ERR_CERT_COMMON_NAME_INVALID',
  selfsigned: 'ERR_CERT_AUTHORITY_INVALID',
  chain: 'ERR_CERT_AUTHORITY_INVALID',
  revoked: 'ERR_CERT_REVOKED',
};
export const SNI = 'www.example.org';

export interface CertCheckResult {
  checks: [string, boolean, string][];
  failed: string | null;
  ok: boolean;
}

/** Verificação do certificado do servidor (RFC 5280 e 6125): devolve a lista de testes e o primeiro que falha. */
export function certChecks(P: Pick<TlsParams, 'certState'>): CertCheckResult {
  const st = P.certState;
  const checks: [string, boolean, string][] = [
    [
      'Cadeia: leaf → intermediário → raiz confiável',
      st !== 'selfsigned' && st !== 'chain',
      'selfsigned' === st
        ? 'o certificado é autoassinado: nenhuma CA do repositório de confiança o assinou'
        : st === 'chain'
          ? 'o servidor não enviou o certificado intermediário: o cliente não consegue ligar o leaf a uma raiz confiável'
          : 'cada certificado é assinado pelo seguinte e a raiz está no repositório de confiança',
    ],
    ['Assinaturas da cadeia verificadas', st !== 'selfsigned' && st !== 'chain', 'cada assinatura confere com a chave pública do emissor'],
    ['Período de validade (notBefore e notAfter)', st !== 'expired', st === 'expired' ? 'o certificado venceu em 12/03/2025' : 'a data atual está dentro da validade'],
    ['Nome do site na lista SAN', st !== 'name', st === 'name' ? 'o certificado vale para shop.example.net, e o site acessado é ' + SNI : 'o SAN inclui ' + SNI + ' (o campo CN é ignorado)'],
    ['Uso permitido (EKU serverAuth e CA:FALSE)', true, 'o certificado pode autenticar servidores TLS'],
    ['Revogação (OCSP ou CRL)', st !== 'revoked', st === 'revoked' ? 'a CA marcou o certificado como revogado (chave comprometida)' : 'a CA informa que o certificado está "good"'],
    ['Certificate Transparency (SCT)', true, 'o certificado traz prova de registro em logs públicos'],
  ];
  const first = checks.find((c) => !c[1]);
  return { checks, failed: first ? first[0] : null, ok: !first };
}

const CERT_ALERTS: Record<string, string> = {
  expired: 'certificate_expired',
  name: 'bad_certificate',
  selfsigned: 'unknown_ca',
  chain: 'unknown_ca',
  revoked: 'certificate_revoked',
};
export const certAlert = (st: string): string => CERT_ALERTS[st];
