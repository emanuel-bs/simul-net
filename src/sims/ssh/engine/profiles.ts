// Motor SSH-2 (RFC 4251, 4252, 4253, 4254). Não há criptografia real: chaves, fingerprints e hashes
// são valores determinísticos e ilustrativos.
import { b64, type Field } from '../../../sim-core';

export type ProfileName = 'moderno' | 'intermediario' | 'legado' | 'endurecido';

export interface Profile {
  nome: string;
  banner: string;
  kex: string[];
  hostkey: string[];
  enc: string[];
  mac: string[];
}

/** Parâmetros dos controles do painel (ids iguais aos do simulador legado). */
export interface SshParams {
  rtt: number;
  cProf: ProfileName;
  known: 'known' | 'new' | 'changed';
  cMethod: 'publickey' | 'password' | 'kbd';
  credOk: boolean;
  user: 'aluno' | 'root';
  use: 'shell' | 'exec' | 'sftp';
  tunKind: 'local' | 'remote' | 'dynamic' | 'jump';
  sProf: ProfileName;
  sPass: boolean;
  sMfa: boolean;
  allowFwd: boolean;
  permitRoot: 'prohibit-password' | 'no' | 'yes';
  maxTries: number;
  hkCheck: 'ask' | 'accept-new' | 'yes' | 'no';
  fwdAgent: boolean;
  gateway: boolean;
}

export const PROF: Record<ProfileName, Profile> = {
  moderno: {
    nome: 'Moderno (OpenSSH 9.x)',
    banner: 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13',
    kex: ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'diffie-hellman-group16-sha512', 'diffie-hellman-group14-sha256'],
    hostkey: ['ssh-ed25519', 'rsa-sha2-512', 'rsa-sha2-256', 'ecdsa-sha2-nistp256'],
    enc: ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes128-ctr'],
    mac: ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com'],
  },
  intermediario: {
    nome: 'Intermediário (OpenSSH 7.x)',
    banner: 'SSH-2.0-OpenSSH_7.4',
    kex: ['curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'diffie-hellman-group-exchange-sha256', 'diffie-hellman-group14-sha256', 'diffie-hellman-group14-sha1'],
    hostkey: ['rsa-sha2-512', 'rsa-sha2-256', 'ecdsa-sha2-nistp256', 'ssh-ed25519', 'ssh-rsa'],
    enc: ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr', 'aes256-cbc', 'aes128-cbc'],
    mac: ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1'],
  },
  legado: {
    nome: 'Legado (OpenSSH 5.x)',
    banner: 'SSH-2.0-OpenSSH_5.3',
    kex: ['diffie-hellman-group-exchange-sha1', 'diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1'],
    hostkey: ['ssh-rsa', 'ssh-dss'],
    enc: ['aes128-ctr', 'aes128-cbc', '3des-cbc'],
    mac: ['hmac-sha1', 'hmac-md5'],
  },
  endurecido: {
    nome: 'Endurecido (somente algoritmos modernos)',
    banner: 'SSH-2.0-OpenSSH_9.6',
    kex: ['curve25519-sha256', 'curve25519-sha256@libssh.org'],
    hostkey: ['ssh-ed25519'],
    enc: ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com'],
    mac: ['hmac-sha2-512-etm@openssh.com'],
  },
};

export const WEAK = [
  'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1', 'ssh-dss', 'ssh-rsa',
  '3des-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'hmac-md5', 'hmac-sha1',
];
export const isWeak = (a: string): boolean => WEAK.indexOf(a) >= 0;
export const isAead = (e: string): boolean => /chacha20-poly1305|gcm@openssh/.test(e);
export const weakIn = (list: string[]): string[] => list.filter(isWeak);
/** Primeiro algoritmo da lista do cliente que o servidor também oferece. */
export const pick = (cl: string[], sl: string[]): string | null => cl.find((a) => sl.indexOf(a) >= 0) || null;

const KEYTYPES: Record<string, string> = {
  'ssh-ed25519': 'ED25519',
  'rsa-sha2-512': 'RSA 3072',
  'rsa-sha2-256': 'RSA 3072',
  'ssh-rsa': 'RSA 3072',
  'ecdsa-sha2-nistp256': 'ECDSA P-256',
  'ssh-dss': 'DSA 1024',
};
export const KEYTYPE = (a: string): string => KEYTYPES[a] || a;
export const KEYBITS = (e: string): number => (/chacha/.test(e) ? 64 : /aes256/.test(e) ? 32 : /3des/.test(e) ? 24 : 16);
export const fpOf = (P: { sProf: string }, alg: string, variant: string): string =>
  'SHA256:' + b64('fp|' + P.sProf + '|' + KEYTYPE(alg) + '|' + variant, 43);
export const list = (a: string[]): string => a.join(',');

// ---------- Campos de mensagem ----------
const SEC_BIN: Field = { sec: 'SSH Binary Packet (RFC 4253, seção 6)' };

export function plainFields(num: number | string, name: string, extra?: Field[]): Field[] {
  return ([SEC_BIN, ['Tipo da mensagem', num + ' (' + name + ')', 'primeiro byte do payload'], ['Cifrado?', 'não', 'esta mensagem ainda trafega em claro']] as Field[]).concat(extra || []);
}

export function encFields(len: number, num: number | string, name: string, extra?: Field[]): Field[] {
  return ([
    { sec: 'No fio (o que um observador vê)' },
    ['packet_length', 'cifrado (' + (len - 20) + ' bytes)', 'o próprio comprimento vai cifrado (ETM/AEAD)'],
    ['payload', 'cifrado', 'ilegível sem as chaves da sessão'],
    ['MAC ou tag de autenticação', '16 bytes', 'detecta qualquer alteração do pacote'],
    { sec: 'Nas pontas (depois de decifrar)' },
    ['Tipo da mensagem', num + ' (' + name + ')', 'só cliente e servidor enxergam isto'],
  ] as Field[]).concat(extra || []);
}

export const lst = (name: string, arr: string[], mean?: string): Field => [
  name,
  arr.join(','),
  mean || 'ordem de preferência: vale o primeiro da lista do cliente que o servidor também tiver',
  arr.some(isWeak) ? 'expert' : '',
];
