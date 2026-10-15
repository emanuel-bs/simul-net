// Abas próprias do HTTPS: O que o observador vê, Comparação, Chaves e sessão, Certificado e Configuração.
import { esc, fmtMs } from '../../../sim-core';
import type { TabContext, TabDef } from '../../../sim-core/ui';
import type { TlsParams } from '../engine';
import { chainTable, grade, nginx } from './config';

const KEYTAB =
  '<h3>O que cada elemento protege</h3><table><thead><tr><th>Elemento</th><th>Para que serve</th></tr></thead><tbody>' +
  '<tr><td>Certificado e CertificateVerify</td><td>autenticar o servidor (e o cliente, no mTLS)</td></tr>' +
  '<tr><td>Par ECDHE efêmero</td><td>obter o segredo sem enviá-lo e dar sigilo futuro</td></tr>' +
  '<tr><td>Chaves de handshake</td><td>cifrar o resto do handshake (certificado inclusive, no TLS 1.3)</td></tr>' +
  '<tr><td>Chaves de aplicação</td><td>cifrar e autenticar os dados HTTP (AEAD)</td></tr>' +
  '<tr><td>Finished</td><td>garantir que ninguém alterou o handshake (anti-downgrade)</td></tr></tbody></table>';

const nowMs = (ctx: TabContext): number => ctx.timeAt(ctx.c);

interface DumpLine {
  t: number;
  text: string;
  hot?: boolean;
  bad?: boolean;
}

const obs: TabDef = {
  id: 'obs',
  label: 'O que o observador vê',
  subs: ['cmp'],
  render: (tr, ctx) => {
    const r = tr.raw;
    const now = nowMs(ctx);
    if (!r.dump) return '';
    const view = (lines: DumpLine[]) =>
      lines
        .filter((l) => l.t <= now)
        .map((l) => (l.hot || l.bad ? '<span class="chk-bad">' + esc(l.text) + '</span>' : esc(l.text)))
        .join('\n') || '(aguardando)';
    let h = '<h3>Captura de quem está no meio do caminho (Wi-Fi público, provedor, proxy)</h3>';
    h += '<div class="cfg-two"><div><h3>HTTP (porta 80)</h3><pre class="conf">' + view(r.dump.http) + '</pre></div><div><h3>HTTPS (porta 443)</h3><pre class="conf">' + view(r.dump.https) + '</pre></div></div>';
    h +=
      '<h3>O que o observador consegue concluir</h3><div class="cfg-two"><div><ul>' + (r.http.leak as string[]).map((x) => '<li><span class="chk-bad">LÊ</span> ' + esc(x) + '</li>').join('') +
      '<li><span class="chk-bad">ALTERA</span> o conteúdo da resposta sem ser notado</li><li><span class="chk-bad">SE PASSA</span> pelo servidor: não há autenticação</li></ul></div>' +
      '<div><ul><li><span class="chk-ok">VÊ</span> o IP do servidor e o nome do site (SNI)</li><li><span class="chk-ok">VÊ</span> a quantidade e o tamanho dos registros e quando ocorrem</li><li><span class="chk-ok">NÃO LÊ</span> senha, cookie, URL completa nem a página</li><li><span class="chk-ok">NÃO ALTERA</span> sem ser detectado (AEAD)</li><li><span class="chk-ok">NÃO SE PASSA</span> pelo servidor sem um certificado válido</li></ul></div></div>';
    h += '<p>Em HTTPS o observador ainda aprende <b>quem fala com quem e quanto</b> (metadados). O conteúdo, os cookies e a senha ficam protegidos.</p>';
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
    if (!r.http) return '';
    const H = r.http;
    const S = r.https;
    let h = '<h3>HTTP x HTTPS na mesma rede e com a mesma ação</h3>';
    if (now < S.tResp - 0.001) return h + '<p class="muted">A tabela é preenchida quando as duas execuções terminam. Clique em Simular ou avance com Passo.</p>';
    const dH = H.tResp - H.t0;
    const dS = S.tResp - S.t0;
    const extra = dS - dH;
    const rtt = Number(ctx.P.rtt);
    const row = (a: string | number, b: string | number, c: string | number) => '<tr><td>' + a + '</td><td>' + b + '</td><td>' + c + '</td></tr>';
    h += '<table><thead><tr><th>Aspecto</th><th>HTTP (porta 80)</th><th>HTTPS (porta 443)</th></tr></thead><tbody>';
    h += row('Idas e voltas até o pedido', '1 RTT (só o TCP)', S.ver ? (S.ver === 'TLS 1.3' ? '2 RTT (TCP + TLS 1.3)' : '3 RTT (TCP + ' + esc(S.ver) + ')') : '(handshake não concluído)');
    h += row('Tempo até a resposta chegar', fmtMs(dH), S.tampered ? fmtMs(dS) + ' (resposta descartada)' : fmtMs(dS) + ' (<b>+' + fmtMs(extra) + '</b>, cerca de +' + (Math.round((extra / rtt) * 10) / 10).toString().replace('.', ',') + ' RTT)');
    h += row('Bytes na rede (aprox.)', H.bytes + ' B', S.bytes + ' B (+' + Math.round((S.bytes / H.bytes - 1) * 100) + '%, handshake e registros)');
    h += row('Mensagens trocadas', H.msgs, S.msgs);
    h += row('Confidencialidade', '<span class="chk-bad">nenhuma</span>: qualquer um no caminho lê', '<span class="chk-ok">cifrada</span> (' + esc(S.suite || '-') + ')');
    h += row('Integridade', '<span class="chk-bad">nenhuma</span>: o conteúdo pode ser alterado', '<span class="chk-ok">AEAD</span>: qualquer alteração é detectada');
    h += row('Autenticação do servidor', '<span class="chk-bad">nenhuma</span>: qualquer um pode se passar pelo site', '<span class="chk-ok">certificado X.509</span> validado pelo navegador');
    h += row('Sigilo futuro', 'não se aplica', S.fs ? '<span class="chk-ok">sim</span> (ECDHE)' : '<span class="chk-bad">não</span> (troca RSA)');
    h += row('O observador lê', (H.leak as string[]).map(esc).join('; '), 'só IP, SNI, tamanhos e tempos');
    h += row(
      'Com adulteração no caminho',
      r.tamper ? '<span class="chk-bad">página alterada e exibida sem aviso</span>' : '(ative "Equipamento no caminho altera a página")',
      r.tamper ? '<span class="chk-ok">detectada</span>: conexão encerrada (bad_record_mac)' : '(ative a adulteração para ver)',
    );
    h += '</tbody></table>';
    h +=
      '<p><b>Resumo:</b> o HTTPS custa ' + (S.tampered ? 'um handshake' : '<b>' + fmtMs(extra) + '</b> a mais na primeira resposta') +
      ' (em conexões reutilizadas, na retomada ou no TLS 1.3 esse custo é pequeno) e, em troca, entrega confidencialidade, integridade e autenticação do servidor. O HTTP não entrega nenhuma das três.</p>';
    return h;
  },
};

const keys: TabDef = {
  id: 'keys',
  label: 'Chaves e sessão',
  render: (tr, ctx) => {
    const R = tr.raw.R || tr.raw.tls;
    const now = ctx.timeAt(ctx.c);
    let h = '<h3>Do ECDHE às chaves de tráfego</h3>';
    if (!R || !R.keys) {
      return h + '<p>Esta execução terminou antes da derivação das chaves' + (R && R.fail ? ' (' + ({ neg: 'negociação de versão ou cifra', cert: 'validação do certificado', downgrade: 'detecção de downgrade' } as Record<string, string>)[R.fail.stage] + ')' : '') + '. Sem chaves, nenhum dado da aplicação foi enviado.</p>' + KEYTAB;
    }
    const k = R.keys;
    const box = (l: string, v: string) => '<div class="key-box">' + esc(l) + ': ' + v + '</div>';
    if (k.kind === '1.3') {
      h += '<p>No <b>TLS 1.3</b>, o segredo <b>ECDHE (' + esc(k.kex) + ')</b> alimenta a cascata <b>HKDF</b>: Early Secret → Handshake Secret → Master Secret. Dela saem as chaves de cada fase.</p>';
      if (now < k.tHs) return h + '<p class="muted">Aguardando o ServerHello (key_share do servidor)...</p>' + KEYTAB;
      h += box('Segredo ECDHE (calculado nas pontas, nunca enviado)', k.ecdhe) + box('Chave de handshake do cliente', k.hsC) + box('Chave de handshake do servidor', k.hsS);
      if (now < k.tApp) return h + '<p class="muted">As chaves de aplicação saem depois do Finished.</p>' + KEYTAB;
      h += box('Chave de aplicação do cliente', k.apC) + box('Chave de aplicação do servidor', k.apS) + '<p>Cifra: <b>' + esc(R.suite) + '</b> (AEAD). Valores ilustrativos: o simulador não faz criptografia real.</p>';
    } else {
      h +=
        '<p>No <b>TLS 1.2</b> (' + esc(R.ver) + '), o <b>pre-master secret</b> (' + esc(k.kex === 'RSA' ? 'cifrado com a chave RSA do servidor' : k.kex === 'ticket' ? 'recuperado do ticket' : 'calculado por ECDHE') +
        ') e os randoms geram o <b>master secret</b>, e dele o <b>key block</b> (chaves de cifra, integridade e IVs).</p>';
      if (now < k.tMs) return h + '<p class="muted">Aguardando o ClientKeyExchange e o ChangeCipherSpec...</p>' + KEYTAB;
      h +=
        box('Pre-master secret', k.pms) + box('Master secret (PRF com os randoms)', k.ms) + box('Key block (chaves e IVs)', k.block) +
        (R.fs ? '' : '<p><b>Sem sigilo futuro:</b> o pre-master secret viajou cifrado pela chave RSA do servidor. Quem gravar o tráfego e obtiver essa chave um dia decifra a conexão.</p>');
    }
    return h + KEYTAB;
  },
};

const cert: TabDef = {
  id: 'cert',
  label: 'Certificado',
  render: (tr, ctx) => {
    const P = ctx.P as unknown as TlsParams;
    const R = tr.raw.R || tr.raw.tls;
    const now = ctx.timeAt(ctx.c);
    let h = '<h3>Cadeia de certificados do servidor</h3>' + chainTable(P);
    h += '<p>A cadeia vai de um certificado de entidade final (o do site) até uma <b>raiz</b> que o navegador já tem no seu repositório de confiança. O servidor envia o leaf e os intermediários.</p>';
    if (tr.raw.sub === 'web' && !(R && R.cert)) return h + '<p class="muted">Nenhum certificado é apresentado nesta execução (sem TLS).</p>';
    if (!R || !R.cert) return h + '<p class="muted">O certificado ainda não foi apresentado nesta execução.</p>';
    if (now < (R.tCert || 0)) return h + '<p class="muted">Aguardando o certificado do servidor...</p>';
    const cc = R.cert;
    h +=
      '<h3>Testes do navegador</h3><table><thead><tr><th>Teste</th><th>Resultado</th><th>Detalhe</th></tr></thead><tbody>' +
      (cc.checks as [string, boolean, string][]).map((c) => '<tr><td>' + esc(c[0]) + '</td><td><span class="' + (c[1] ? 'chk-ok' : 'chk-bad') + '">' + (c[1] ? 'OK' : 'FALHA') + '</span></td><td class="meaning">' + esc(c[2]) + '</td></tr>').join('') +
      '</tbody></table>';
    if (R.fail && R.fail.stage === 'cert') h += '<p><b>Resultado:</b> conexão recusada. Alerta TLS <b>' + esc(R.fail.alert) + '</b>; o navegador mostra <b>' + esc(R.fail.browser) + '</b>.</p>';
    else if (cc.ok) h += '<p><b>Resultado:</b> todos os testes passaram. O servidor é quem diz ser.</p>';
    return h;
  },
};

const cfg: TabDef = {
  id: 'cfg',
  label: 'Configuração',
  render: (_tr, ctx) => {
    const P = ctx.P as unknown as TlsParams;
    const g = grade(P);
    let h =
      '<h3>Nota de hardening</h3><p><span class="grade ' + g.letter + '">' + g.letter + '</span><b>' + g.ok + ' de ' + g.total + ' boas práticas (' + g.pct + '%)</b></p><ul>' +
      g.items.map((x) => '<li><span class="' + (x[1] ? 'chk-ok' : 'chk-bad') + '">' + (x[1] ? 'OK' : 'FALTA') + '</span> ' + esc(x[0]) + '</li>').join('') + '</ul>' +
      '<p>A nota é didática: mede o que a configuração do painel faz ou deixa de fazer. Em produção, use o <b>SSL Labs</b>, o <b>testssl.sh</b> e o gerador de configuração da Mozilla.</p>';
    h += '<h3>Configuração do servidor (nginx)</h3><pre class="conf">' + esc(nginx(P)) + '</pre>';
    return h;
  },
};

/** Mesma ordem do legado: as abas da comparação vêm antes das demais. */
export const tabs: TabDef[] = [obs, cmpx, keys, cert, cfg];
