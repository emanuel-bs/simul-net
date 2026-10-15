// Abas próprias do FTP: Conexões e portas, O que o observador vê e Comparação.
import { esc, fmtMs } from '../../../sim-core';
import type { TabContext, TabDef } from '../../../sim-core/ui';
import type { FtpParams } from '../engine';

const nowMs = (ctx: TabContext): number => ctx.timeAt(ctx.c);

interface DumpLine {
  t: number;
  text: string;
  hot?: boolean;
}

function dumpBlock(lines: DumpLine[], now: number): string {
  const v = lines.filter((l) => l.t <= now);
  if (!v.length) return '(aguardando)';
  return v.map((l) => (l.hot ? '<span class="chk-bad">' + esc(l.text) + '</span>' : esc(l.text))).join('\n');
}

function singleDump(tr: Parameters<TabDef['render']>[0], R: Record<string, any>): DumpLine[] {
  const ms = tr.msgs.slice(R.i0, R.i1 === undefined ? tr.msgs.length : R.i1);
  return ms.filter((m) => m.dump).map((m) => ({ t: m.tArr, text: (m.dump as DumpLine).text, hot: !!(m.dump as DumpLine).hot }));
}

const portas: TabDef = {
  id: 'portas',
  label: 'Conexões e portas',
  subs: ['ftp', 'ftps', 'sftp'],
  render: (tr) => {
    const r = tr.raw;
    const R = r.R;
    if (!R) return '';
    const P = (r.P || {}) as Partial<FtpParams>;
    let h = '<h3>Quantas conexões e quais portas este cenário usa</h3>';
    h += '<table class="sc-msgs"><thead><tr><th>Item</th><th>Valor</th><th>Observação</th></tr></thead><tbody>';
    h += '<tr><td>Conexões TCP</td><td>' + R.conns + '</td><td class="meaning">' + (r.sub === 'sftp' ? 'uma só: comandos e arquivos viajam no mesmo canal' : 'controle + uma conexão de dados por transferência') + '</td></tr>';
    h += '<tr><td>Portas</td><td>' + esc((R.ports as string[]).join('; ')) + '</td><td class="meaning">' + (r.sub === 'sftp' ? 'só a 22 precisa estar liberada' : 'o firewall precisa tratar a conexão de dados') + '</td></tr>';
    if (r.sub !== 'sftp') {
      h += '<tr><td>Modo de dados</td><td>' + (P.mode === 'active' ? 'ativo (PORT)' : 'passivo (PASV)') + '</td><td class="meaning">' + (P.mode === 'active' ? 'o servidor conecta ao cliente, a partir da porta 20' : 'o cliente conecta a uma porta alta do servidor') + '</td></tr>';
      h +=
        '<tr><td>Firewall do cliente</td><td>' + ({ none: 'sem NAT nem filtro', nat: 'NAT com firewall de estado', helper: 'NAT com inspeção de FTP' } as Record<string, string>)[P.cfw as string] + '</td><td class="meaning">' +
        (R.helper ? 'o helper leu o PORT e abriu a porta' : '') + '</td></tr>';
      h += '<tr><td>Faixa passiva no servidor</td><td>' + (P.sfw === false ? 'bloqueada' : 'liberada') + '</td><td class="meaning">' + (P.mode === 'passive' ? 'precisa estar liberada para o modo passivo' : 'não é usada no modo ativo') + '</td></tr>';
      h +=
        '<tr><td>Resultado da conexão de dados</td><td>' + (R.dataOk === true ? '<span class="chk-ok">estabelecida</span>' : R.dataOk === false ? '<span class="chk-bad">falhou</span>' : '-') +
        '</td><td class="meaning">' + esc(R.why || '') + '</td></tr>';
    }
    h += '</tbody></table>';
    return h;
  },
};

const obs: TabDef = {
  id: 'obs',
  label: 'O que o observador vê',
  render: (tr, ctx) => {
    const r = tr.raw;
    const now = nowMs(ctx);
    let h = '<h3>Captura de quem está no meio do caminho (Wi-Fi público, provedor, outro equipamento da rede)</h3>';
    if (r.sub === 'cmp' && r.dump) {
      h += '<div class="cfg-two"><div><h3>FTP</h3><pre class="conf">' + dumpBlock(r.dump.ftp, now) + '</pre></div><div><h3>FTPS (explícito, PROT P)</h3><pre class="conf">' + dumpBlock(r.dump.ftps, now) + '</pre></div></div>';
      h += '<h3>SFTP (SSH)</h3><pre class="conf">' + dumpBlock(r.dump.sftp, now) + '</pre>';
    } else if (r.R) {
      h += '<pre class="conf">' + dumpBlock(singleDump(tr, r.R), now) + '</pre>';
      h += '<p>As linhas em vermelho são o que um observador lê sem esforço. Em linhas cifradas ele vê apenas o tamanho e o momento dos pacotes.</p>';
    }
    return h;
  },
};

const cmpx: TabDef = {
  id: 'cmpx',
  label: 'Comparação',
  subs: ['cmp'],
  render: (tr, ctx) => {
    const r = tr.raw;
    const now = nowMs(ctx);
    if (!r.A) return '';
    if (now < r.C.tEnd - 0.001) return '<h3>FTP, FTPS e SFTP lado a lado</h3><p class="muted">A tabela é preenchida quando as três execuções terminam. Clique em Simular ou avance com Passo.</p>';
    const A = r.A;
    const B = r.B;
    const C = r.C;
    const row = (k: string, a: string, b: string, c: string) => '<tr><td>' + k + '</td><td>' + a + '</td><td>' + b + '</td><td>' + c + '</td></tr>';
    const no = (t: string) => '<span class="chk-bad">' + t + '</span>';
    const ok = (t: string) => '<span class="chk-ok">' + t + '</span>';
    let h = '<h3>FTP, FTPS e SFTP na mesma rede e com a mesma ação (' + esc(r.opName) + ')</h3>';
    h += '<table class="sc-msgs"><thead><tr><th>Critério</th><th>FTP</th><th>FTPS (explícito, PROT P)</th><th>SFTP</th></tr></thead><tbody>';
    h += row('Conexões TCP', String(A.conns), String(B.conns), String(C.conns));
    h += row('Portas', '21 e uma de dados', '21 e uma de dados', '22');
    h += row('Usuário e senha', no('em claro'), ok('cifrados'), ok('cifrados'));
    h += row('Comandos', no('em claro'), ok('cifrados'), ok('cifrados'));
    h += row('Conteúdo do arquivo', no('em claro'), ok('cifrado'), ok('cifrado'));
    h += row('Detecta alteração no caminho', no('não'), ok('sim (TLS)'), ok('sim (MAC do SSH)'));
    h += row('Autentica o servidor', no('não'), ok('sim (certificado)'), ok('sim (chave do host)'));
    h += row('Firewall e NAT', no('difícil (dados em outra porta)'), no('difícil e o helper não lê comandos cifrados'), ok('simples: só a porta 22'));
    h += row('Tempo até concluir', fmtMs(A.tEnd - A.t0), fmtMs(B.tEnd - B.t0), fmtMs(C.tEnd - C.t0));
    h += '</tbody></table>';
    h += '<p>O FTP mostra tudo a quem está no caminho. O FTPS protege o conteúdo, mas herda a complexidade das duas conexões. O SFTP protege tudo e usa só a porta 22.</p>';
    return h;
  },
};

/** Mesma ordem do legado. */
export const tabs: TabDef[] = [portas, obs, cmpx];
