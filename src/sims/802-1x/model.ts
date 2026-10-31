// Modelo do 802.1X com EAP e RADIUS: papéis, métodos EAP e construtores de campos das mensagens (EAPOL, EAP e RADIUS).
// Simplificações (detalhadas na aba Referência): sem fragmentação do EAP-TLS, mensagens de um mesmo voo do handshake TLS
// agrupadas numa única mensagem EAP, valores de chaves e desafios ilustrativos (determinísticos) e temporizadores típicos.
import { hex, type Field } from '../../sim-core';

export const GREEN = '#7BD88F';

/** Endereços MAC da faixa de documentação (RFC 9542) e IPs de documentação (RFC 5737). */
export const NODE = {
  sup: { name: 'Notebook', mac: '00:00:5e:00:53:11' },
  dev2: { name: 'Segundo dispositivo', mac: '00:00:5e:00:53:12' },
  nas: { name: 'SW1', mac: '00:00:5e:00:53:01', ip: '192.0.2.2', port: 'Gi1/0/5' },
  srv: { name: 'RADIUS', ip: '192.0.2.10' },
};
/** Endereço de grupo reservado do PAE (Port Access Entity), usado em EAPOL pelo autenticador e pelo suplicante. */
export const PAE_GROUP = '01:80:c2:00:00:03';
export const RADIUS_PORT = 1812;
export const IDENTITY = 'ana@example.org';
export const ANON = 'anonymous@example.org';
/** Temporizadores típicos (valores de implementação, não do padrão): atraso do EAPOL local e esperas em ms. */
export const LEG = 0.2;
export const RADIUS_TIMEOUT = 5000;
export const RADIUS_TRIES = 3;
export const EAP_TX_PERIOD = 30000;
export const EAP_MAX_REQ = 2;
export const SESSION_TIMEOUT = 3600;

/** Tempo simulado em escala humana (de milissegundos a horas), em formato compacto. */
export function fmtTime(ms: number): string {
  const f = (v: number) => (Math.round(v * 10) / 10).toString().replace('.', ',');
  if (ms < 1000) return f(ms) + 'ms';
  const unit = ms >= 3600000 ? 3600000 : ms >= 60000 ? 60000 : 1000;
  const name = unit === 3600000 ? 'h' : unit === 60000 ? 'min' : 's';
  const base = Math.floor(ms / unit);
  const rem = ms - base * unit;
  return base + name + (rem < 0.05 ? '' : '+' + fmtTime(rem));
}

// ---- métodos EAP ----

export type MethodKey = 'tls' | 'peap' | 'md5';

export interface Round {
  /** Mensagem do servidor (EAP-Request) e a resposta do suplicante (EAP-Response). */
  req: string;
  res: string;
  reqData: string;
  resData: string;
  reqAbout: string;
  resAbout: string;
  /** A rodada já vai dentro de um túnel TLS (protegida). */
  enc: boolean;
  reqBytes: number;
  resBytes: number;
}

export interface Method {
  key: MethodKey;
  name: string;
  /** Tipo do método no campo Type do EAP (IANA). */
  type: number;
  typeName: string;
  identity: string;
  rounds: Round[];
  /** Rodada (0 a n-1) depois de cuja resposta o servidor decide entre Accept e Reject. */
  decisive: number;
}

export const METHODS: Record<MethodKey, Method> = {
  md5: {
    key: 'md5',
    name: 'EAP-MD5',
    type: 4,
    typeName: 'MD5-Challenge',
    identity: IDENTITY,
    decisive: 0,
    rounds: [
      {
        req: 'MD5-Challenge',
        res: 'MD5-Challenge',
        reqData: 'Value-Size 16; Value: ' + hex('md5chal', 16),
        resData: 'Value-Size 16; Value: MD5(Identifier + senha + desafio) = ' + hex('md5resp', 16),
        reqAbout: 'O servidor envia 16 bytes aleatórios como desafio (RFC 3748, seção 5.4).',
        resAbout: 'O suplicante calcula o MD5 do identificador, da senha e do desafio, como no CHAP, e devolve o resultado. A senha não trafega, mas o desafio e a resposta sim.',
        enc: false,
        reqBytes: 22,
        resBytes: 22,
      },
    ],
  },
  peap: {
    key: 'peap',
    name: 'PEAP com MSCHAPv2',
    type: 25,
    typeName: 'PEAP',
    identity: ANON,
    decisive: 2,
    rounds: [
      { req: 'PEAP (Start)', res: 'PEAP (ClientHello)', reqData: 'Flags: Start; sem dados TLS', resData: 'TLS: ClientHello', reqAbout: 'O servidor inicia o túnel TLS: o bit Start indica que o suplicante deve começar o handshake.', resAbout: 'O suplicante abre o handshake TLS com o ClientHello.', enc: false, reqBytes: 6, resBytes: 120 },
      { req: 'PEAP (ServerHello, Certificate)', res: 'PEAP (troca de chaves, Finished)', reqData: 'TLS: ServerHello, Certificate (cadeia do servidor), ServerHelloDone', resData: 'TLS: troca de chaves, ChangeCipherSpec, Finished', reqAbout: 'O servidor se autentica ao suplicante com o certificado. O suplicante deve validar a cadeia e o nome.', resAbout: 'O suplicante conclui o handshake. A partir daqui o túnel está de pé.', enc: false, reqBytes: 1000, resBytes: 150 },
      { req: 'PEAP (Finished + desafio MSCHAPv2)', res: 'PEAP (resposta MSCHAPv2)', reqData: 'TLS: Finished; dentro do túnel: MSCHAPv2 Challenge', resData: 'Dentro do túnel: MSCHAPv2 Response (usuário e prova da senha)', reqAbout: 'O servidor fecha o handshake e já envia, protegido pelo túnel, o desafio da autenticação interna.', resAbout: 'O suplicante prova que conhece a senha, protegido pelo túnel. O servidor decide depois desta resposta.', enc: true, reqBytes: 90, resBytes: 100 },
      { req: 'PEAP (MSCHAPv2 Success)', res: 'PEAP (confirmação)', reqData: 'Dentro do túnel: MSCHAPv2 Success (o servidor também prova que conhece a senha)', resData: 'Dentro do túnel: confirmação sem dados', reqAbout: 'O servidor confirma a autenticação interna.', resAbout: 'O suplicante confirma, e o servidor pode encerrar com Success.', enc: true, reqBytes: 60, resBytes: 40 },
    ],
  },
  tls: {
    key: 'tls',
    name: 'EAP-TLS',
    type: 13,
    typeName: 'EAP-TLS',
    identity: IDENTITY,
    decisive: 1,
    rounds: [
      { req: 'EAP-TLS (Start)', res: 'EAP-TLS (ClientHello)', reqData: 'Flags: Start; sem dados TLS', resData: 'TLS: ClientHello', reqAbout: 'O servidor pede o início do handshake TLS (RFC 5216, seção 2.1.1).', resAbout: 'O suplicante abre o handshake TLS.', enc: false, reqBytes: 6, resBytes: 120 },
      { req: 'EAP-TLS (ServerHello, Certificate, CertificateRequest)', res: 'EAP-TLS (Certificate, CertificateVerify, Finished)', reqData: 'TLS: ServerHello, Certificate do servidor, CertificateRequest', resData: 'TLS: Certificate do cliente, prova de posse da chave, Finished', reqAbout: 'O servidor se autentica com o certificado e exige o certificado do cliente.', resAbout: 'O suplicante apresenta o próprio certificado e prova que possui a chave privada. O servidor decide depois desta resposta.', enc: false, reqBytes: 1000, resBytes: 900 },
      { req: 'EAP-TLS (Finished)', res: 'EAP-TLS (confirmação)', reqData: 'TLS: Finished do servidor', resData: 'Sem dados: confirmação', reqAbout: 'O servidor conclui o handshake. Os dois lados já podem derivar as chaves.', resAbout: 'O suplicante confirma com uma resposta vazia, e o servidor encerra com Success.', enc: true, reqBytes: 50, resBytes: 6 },
    ],
  },
};

// ---- campos das mensagens ----

const EAP_CODE: Record<number, string> = { 1: 'Request', 2: 'Response', 3: 'Success', 4: 'Failure' };
const EAP_TYPE: Record<number, string> = { 1: 'Identity', 4: 'MD5-Challenge', 13: 'EAP-TLS', 25: 'PEAP' };

export interface EapHdr {
  code: 1 | 2 | 3 | 4;
  id: number;
  type?: number;
  /** Rótulo do dado do tipo. */
  data?: string;
  /** Tamanho do EAP, em bytes. */
  bytes?: number;
}

export const eapLen = (e: EapHdr): number => (e.code === 3 || e.code === 4 ? 4 : 5 + (e.bytes ?? 0));

export function eapFields(e: EapHdr): Field[] {
  const f: Field[] = [{ sec: 'EAP (RFC 3748, seção 4)' }, ['Code', e.code + ' (' + EAP_CODE[e.code] + ')', e.code === 3 || e.code === 4 ? 'o resultado final, enviado pelo autenticador; não há confirmação (seção 4.2)' : e.code === 1 ? 'pedido do servidor' : 'resposta do suplicante'], ['Identifier', String(e.id), 'liga a resposta ao pedido'], ['Length', String(eapLen(e)), 'em bytes']];
  if (e.type !== undefined) {
    f.push(['Type', e.type + ' (' + (EAP_TYPE[e.type] ?? 'método') + ')', e.type === 1 ? 'pede ou informa a identidade (seção 5.1)' : 'identifica o método EAP']);
    if (e.data) f.push(['Type-Data', e.data, '']);
  }
  return f;
}

export interface EapolOpts {
  /** Tipo do pacote EAPOL: EAP-Packet, Start ou Logoff. */
  pkt: 'eap' | 'start' | 'logoff';
  from: string;
  /** Destino Ethernet. */
  to: string;
  eap?: EapHdr;
}

const PKT: Record<string, [number, string]> = { eap: [0, 'EAP-Packet'], start: [1, 'EAPOL-Start'], logoff: [2, 'EAPOL-Logoff'] };

export function eapolFields(o: EapolOpts): Field[] {
  const body = o.eap ? eapLen(o.eap) : 0;
  const f: Field[] = [
    { sec: 'Ethernet II' },
    ['Destino', o.to, o.to === PAE_GROUP ? 'endereço de grupo do PAE: não é encaminhado pelo switch' : 'unicast'],
    ['Origem', o.from, ''],
    ['EtherType', '0x888E', 'EAPOL (EAP sobre LAN)'],
    { sec: 'EAPOL (IEEE 802.1X)' },
    ['Versão do protocolo', '2 ou 3', 'conforme a edição do IEEE 802.1X implementada'],
    ['Tipo do pacote', PKT[o.pkt][0] + ' (' + PKT[o.pkt][1] + ')', o.pkt === 'eap' ? 'carrega um pacote EAP' : o.pkt === 'start' ? 'o suplicante pede que a autenticação comece' : 'o suplicante encerra a sessão'],
    ['Comprimento do corpo', String(body), o.pkt === 'eap' ? 'tamanho do pacote EAP' : 'sem corpo'],
  ];
  if (o.eap) f.push(...eapFields(o.eap));
  return f;
}

export const eapolLen = (e?: EapHdr): number => 18 + (e ? eapLen(e) : 0);

export interface RadiusOpts {
  code: 1 | 2 | 3 | 11;
  id: number;
  /** Sentido: do switch ao servidor (true) ou do servidor ao switch (false). */
  toSrv: boolean;
  attrs: [string, string, string?][];
}

const RAD_CODE: Record<number, string> = { 1: 'Access-Request', 2: 'Access-Accept', 3: 'Access-Reject', 11: 'Access-Challenge' };

export function radiusFields(o: RadiusOpts): Field[] {
  const src = o.toSrv ? NODE.nas.ip : NODE.srv.ip;
  const dst = o.toSrv ? NODE.srv.ip : NODE.nas.ip;
  const attrBytes = o.attrs.reduce((s, a) => s + 2 + a[1].length, 0);
  return [
    { sec: 'IPv4' },
    ['Origem', src, o.toSrv ? 'o switch (NAS, o cliente RADIUS)' : 'o servidor RADIUS'],
    ['Destino', dst, ''],
    ['Protocolo', 'UDP (17)', ''],
    { sec: 'UDP' },
    ['Porta de origem', o.toSrv ? '49152' : String(RADIUS_PORT), o.toSrv ? 'porta efêmera do cliente RADIUS' : ''],
    ['Porta de destino', o.toSrv ? String(RADIUS_PORT) : '49152', o.toSrv ? 'autenticação RADIUS (RFC 2865, seção 3)' : ''],
    { sec: 'RADIUS (RFC 2865, seção 3)' },
    ['Code', o.code + ' (' + RAD_CODE[o.code] + ')', ''],
    ['Identifier', String(o.id), 'liga a resposta ao pedido; não é o Identifier do EAP'],
    ['Length', String(20 + attrBytes), 'em bytes'],
    [o.toSrv ? 'Request Authenticator' : 'Response Authenticator', hex('rad' + o.code + '-' + o.id, 16), o.toSrv ? '16 bytes aleatórios' : 'calculado com MD5 e o segredo compartilhado'],
    { sec: 'Atributos' },
    ...o.attrs.map((a) => [a[0], a[1], a[2] ?? ''] as Field),
  ];
}

export const radiusLen = (attrs: [string, string, string?][]): number => 48 + attrs.reduce((s, a) => s + 2 + a[1].length, 0);

/** Atributos comuns de todo Access-Request do autenticador. */
export function nasAttrs(user: string, supMac: string): [string, string, string?][] {
  return [
    ['User-Name (1)', user, 'a identidade vinda do EAP-Response/Identity (RFC 2865, seção 5.1)'],
    ['NAS-IP-Address (4)', NODE.nas.ip, 'o switch que pede a autenticação (seção 5.4)'],
    ['NAS-Port (5)', '5', 'a porta física (seção 5.5)'],
    ['NAS-Port-Type (61)', 'Ethernet (15)', 'o tipo de acesso (seção 5.41)'],
    ['Calling-Station-Id (31)', supMac.toUpperCase().replace(/:/g, '-'), 'o MAC do suplicante (seção 5.31)'],
  ];
}

export const mac = (k: 'sup' | 'dev2' | 'nas'): string => NODE[k].mac;
