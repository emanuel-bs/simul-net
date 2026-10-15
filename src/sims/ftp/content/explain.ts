// Texto da aba Experimento e do cabeçalho do cenário.
import { esc, fmtMs, type Trace } from '../../../sim-core';
import type { ScenarioDef } from '../../../sim-core/ui';
import type { FtpParams } from '../engine';

/** Texto "Configuração do cenário": só o que o cenário define (o restante vem dos padrões). */
export function setup(s: ScenarioDef): string {
  const P = (s.set || {}) as Partial<FtpParams>;
  const p: string[] = [];
  if (s.sub === 'ftp' || s.sub === 'ftps') {
    if (s.sub === 'ftps') p.push('FTPS ' + (P.tlsMode === 'implicit' ? 'implícito (990)' : 'explícito (AUTH TLS)'), 'PROT ' + P.prot);
    p.push(
      'modo ' + (P.mode === 'active' ? 'ativo' : 'passivo'),
      'firewall: ' + { none: 'sem NAT nem filtro', nat: 'NAT de estado', helper: 'NAT com inspeção de FTP' }[P.cfw as 'none' | 'nat' | 'helper'],
      'faixa passiva ' + (P.sfw === false ? 'bloqueada' : 'liberada'),
    );
    if (P.cred && P.cred !== 'ok') p.push(P.cred === 'bad' ? 'senha incorreta' : 'login anônimo');
  } else if (s.sub === 'sftp') p.push('autenticação por ' + (P.sauth === 'key' ? 'chave pública' : 'senha'));
  p.push({ get: 'download', put: 'upload', list: 'listagem' }[P.op as 'get' | 'put' | 'list']);
  return p.join('; ');
}

export function explain(tr: Trace, P: FtpParams): string {
  const r = tr.raw;
  const R = r.R;
  if (r.sub === 'cmp') {
    const A = r.A;
    const B = r.B;
    const C = r.C;
    return (
      '<p>Mesma ação (' + esc(r.opName) + ') em três protocolos.</p><ul><li><b>FTP:</b> ' + fmtMs(A.tEnd - A.t0) + ', ' + A.conns + ' conexões e senha e arquivo legíveis.</li><li><b>FTPS:</b> ' +
      fmtMs(B.tEnd - B.t0) + ', ' + B.conns + ' conexões, tudo cifrado.</li><li><b>SFTP:</b> ' + fmtMs(C.tEnd - C.t0) +
      ', 1 conexão, tudo cifrado.</li></ul><p>O custo do TLS e do SSH é de poucos RTT; a diferença maior está no que o observador consegue ler e em quantas portas o firewall precisa tratar.</p>'
    );
  }
  if (!R) return '';
  let h = '<ul>';
  if (r.sub === 'sftp') {
    h += '<li>Uma conexão TCP na porta 22; o SFTP funciona como subsistema do SSH.</li><li>Tudo depois do NEWKEYS está cifrado e autenticado.</li>';
  } else {
    h += '<li>Controle na porta ' + (R.tls === 'implicit' ? '990' : '21') + (R.ctrlEnc ? ', protegido por TLS' : ', em texto puro') + '.</li>';
    if (R.fail && R.fail.stage === 'cert') h += '<li><b>O cliente rejeitou o certificado</b> e nenhuma credencial foi enviada.</li>';
    else if (R.fail && R.fail.stage === 'auth') h += '<li>O login foi recusado (530). ' + (R.credSeen ? 'A senha digitada já havia sido exposta.' : 'A senha trafegou cifrada.') + '</li>';
    else if (R.fail && R.fail.stage === 'data') h += '<li><b>O canal de dados falhou:</b> ' + esc(R.why || '') + '.</li>';
    else h += '<li>O canal de dados foi aberto em modo ' + (P.mode === 'active' ? 'ativo' : 'passivo') + ' e a operação terminou em ' + fmtMs(R.tEnd - R.t0) + '.</li>';
    if (R.credSeen && !(R.fail && R.fail.stage === 'cert')) h += '<li><span class="chk-bad">Usuário e senha</span> trafegam em texto puro.</li>';
    if (R.tls && !(R.fail && R.fail.stage === 'cert')) h += '<li>O canal de dados ' + (R.dataEnc ? 'é cifrado (PROT P).' : '<span class="chk-bad">está em claro (PROT C)</span>: só o controle foi protegido.') + '</li>';
    if (!R.tls && !R.fail) h += '<li><span class="chk-bad">O arquivo</span> também trafega em texto puro.</li>';
  }
  h += '</ul>';
  return h;
}
