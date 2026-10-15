// Nota de hardening e arquivos de configuração exibidos na aba Configuração.
import { b64, type Trace } from '../../../sim-core';
import { PROF, isWeak, list, type SshParams } from '../engine';

export interface Grade {
  items: [string, boolean][];
  ok: number;
  total: number;
  pct: number;
  letter: 'A' | 'B' | 'C' | 'D';
}

export function grade(P: SshParams): Grade {
  const S = PROF[P.sProf];
  const items: [string, boolean][] = [
    ['Troca de chaves moderna (sem SHA-1 nem grupos antigos)', !S.kex.some(isWeak)],
    ['Chave de host ed25519 e sem DSA ou RSA com SHA-1', !S.hostkey.some(isWeak) && S.hostkey.indexOf('ssh-ed25519') >= 0],
    ['Cifras sem CBC e sem 3DES', !S.enc.some(isWeak)],
    ['MACs sem MD5 e sem SHA-1', !S.mac.some(isWeak)],
    ['Senha desativada (PasswordAuthentication no)', !P.sPass],
    ['Root sem senha (PermitRootLogin no ou prohibit-password)', P.permitRoot !== 'yes'],
    ['MaxAuthTries baixo (3)', P.maxTries <= 3],
    ['Segundo fator exigido (chave + TOTP)', !!P.sMfa],
    ['Encaminhamento de portas restrito (AllowTcpForwarding no)', !P.allowFwd],
    ['Cliente verifica a chave do servidor (StrictHostKeyChecking diferente de no)', P.hkCheck !== 'no'],
    ['Agente não encaminhado (ForwardAgent no)', !P.fwdAgent],
  ];
  const ok = items.filter((x) => x[1]).length;
  const pct = Math.round((ok / items.length) * 100);
  return { items, ok, total: items.length, pct, letter: pct >= 85 ? 'A' : pct >= 65 ? 'B' : pct >= 45 ? 'C' : 'D' };
}

export function sshdConf(P: SshParams): string {
  const S = PROF[P.sProf];
  return (
    '# /etc/ssh/sshd_config  (servidor: ' + S.nome + ')\nPort 22\nKexAlgorithms ' + list(S.kex) + '\nHostKeyAlgorithms ' + list(S.hostkey) + '\nCiphers ' + list(S.enc) + '\nMACs ' + list(S.mac) +
    '\nPubkeyAuthentication yes\nPasswordAuthentication ' + (P.sPass ? 'yes' : 'no') + '\nKbdInteractiveAuthentication ' + (P.sMfa || P.sPass ? 'yes' : 'no') +
    '\nPermitRootLogin ' + P.permitRoot + '\nMaxAuthTries ' + P.maxTries +
    (P.sMfa ? '\nAuthenticationMethods publickey,keyboard-interactive' : '') +
    '\nAllowTcpForwarding ' + (P.allowFwd ? 'yes' : 'no') + '\nGatewayPorts ' + (P.gateway ? 'yes' : 'no') + '\nX11Forwarding no'
  );
}

export function sshConf(P: SshParams): string {
  const C = PROF[P.cProf];
  let s =
    '# ~/.ssh/config  (cliente: ' + C.nome + ')\nHost srv\n  HostName 203.0.113.22\n  User ' + P.user + '\n  IdentityFile ~/.ssh/id_ed25519\n  KexAlgorithms ' + list(C.kex) +
    '\n  HostKeyAlgorithms ' + list(C.hostkey) + '\n  Ciphers ' + list(C.enc) + '\n  StrictHostKeyChecking ' + P.hkCheck + '\n  ForwardAgent ' + (P.fwdAgent ? 'yes' : 'no');
  const k = P.tunKind;
  if (k === 'local') s += '\n  LocalForward 5433 db.interno:5432';
  else if (k === 'remote') s += '\n  RemoteForward 9000 localhost:3000';
  else if (k === 'dynamic') s += '\n  DynamicForward 1080';
  else if (k === 'jump') s += '\n  ProxyJump aluno@bastion';
  return s;
}

/** Linhas que o sshd registraria no auth.log para a execução. */
export function authLog(P: SshParams, raw: Trace['raw']): string[] {
  const L: string[] = [];
  const ip = '192.168.1.20';
  const pt = 'port 50122 ssh2';
  if (raw.fail) {
    if (raw.fail.stage === 'neg') L.push('sshd[812]: Unable to negotiate with ' + ip + ' port 50122: ' + raw.fail.msg.slice(0, 90) + '... [preauth]');
    else L.push('sshd[812]: Connection closed by ' + ip + ' port 50122 [preauth]');
    return L;
  }
  if (raw.sub === 'tunnel') {
    if (raw.blocked) L.push('sshd[812]: error: channel 0: open failed: administratively prohibited: open failed');
    else L.push('sshd[812]: Accepted publickey for aluno from ' + ip + ' ' + pt + ': ED25519 SHA256:' + b64('lg', 20));
    return L;
  }
  const A = raw.auth;
  for (let i = 0; i < A.tries; i++) {
    if (A.denied === 'root') L.push('sshd[812]: ROOT LOGIN REFUSED FROM ' + ip + ' port 50122');
    else if (A.denied === 'key') L.push('sshd[812]: Failed publickey for ' + P.user + ' from ' + ip + ' ' + pt + ': ED25519 SHA256:' + b64('lg', 20));
    else L.push('sshd[812]: Failed password for ' + P.user + ' from ' + ip + ' ' + pt);
  }
  if (A.serverDisconnect) L.push('sshd[812]: error: maximum authentication attempts exceeded for ' + P.user + ' from ' + ip + ' ' + pt + ' [preauth]');
  if (A.ok) {
    L.push('sshd[812]: Accepted ' + (A.via || 'password') + ' for ' + P.user + ' from ' + ip + ' ' + pt + (A.via === 'chave pública' || A.via === 'chave + TOTP' ? ': ED25519 SHA256:' + b64('lg', 20) : ''));
  }
  if (A.ok && raw.use) L.push('sshd[812]: pam_unix(sshd:session): session opened for user ' + P.user);
  if (!A.ok && !A.tries) L.push('sshd[812]: Connection closed by authenticating user ' + P.user + ' ' + ip + ' port 50122 [preauth]');
  return L;
}
