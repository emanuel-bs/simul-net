// Abas próprias do SSH: "Chaves e sessão" e "Configuração".
import { esc } from '../../../sim-core';
import type { TabDef } from '../../../sim-core/ui';
import { isAead, type SshParams } from '../engine';
import { authLog, grade, sshConf, sshdConf } from './config';

function keyTable(): string {
  return (
    '<h3>O que cada elemento protege</h3><table><thead><tr><th>Elemento</th><th>Para que serve</th></tr></thead><tbody>' +
    '<tr><td>Chave de host do servidor</td><td>autenticar o servidor (assina H); conferida no known_hosts</td></tr>' +
    '<tr><td>Par Diffie-Hellman efêmero</td><td>obter o segredo K sem enviá-lo; dá sigilo futuro (forward secrecy)</td></tr>' +
    '<tr><td>session_id (H)</td><td>amarrar a autenticação do usuário a esta sessão</td></tr>' +
    '<tr><td>Chaves de cifra e integridade (A a F)</td><td>cifrar e autenticar cada pacote nos dois sentidos</td></tr>' +
    '<tr><td>Chave do usuário (authorized_keys)</td><td>autenticar o cliente sem enviar segredo reutilizável</td></tr></tbody></table>'
  );
}

export const tabs: TabDef[] = [
  {
    id: 'keys',
    label: 'Chaves e sessão',
    render: (tr, ctx) => {
      const r = tr.raw;
      const now = ctx.timeAt(ctx.c);
      let h = '<h3>Da troca de chaves às chaves da sessão</h3>';
      if (r.sub === 'tunnel') {
        return h + '<p>Os túneis usam a sessão SSH já estabelecida, então esta aba mostra as chaves da sessão (modo Sessão). Aqui o que muda é o <b>canal</b>: cada conexão encaminhada abre um canal dentro da mesma conexão cifrada.</p>' + keyTable();
      }
      if (!r.keys) {
        return h + '<p>Esta execução terminou antes da derivação das chaves (' + (r.fail ? 'falha na ' + (r.fail.stage === 'neg' ? 'negociação de algoritmos' : 'verificação da chave do servidor') : 'sem sessão') + '). Sem chaves de sessão, nada foi cifrado e nenhuma credencial foi enviada.</p>' + keyTable();
      }
      const k = r.keys;
      h += '<p>Algoritmo de troca de chaves: <b>' + esc(k.kex) + '</b>. Cada lado gera um par efêmero; os valores públicos viajam (em claro) e o segredo <b>K</b> é calculado nas pontas, sem nunca ser enviado.</p>';
      if (now < k.tK) return h + '<p class="muted">Aguardando a resposta do servidor (KEX_ECDH_REPLY)...</p>' + keyTable();
      h +=
        '<h3>Segredo e hash da troca</h3><div class="key-box">K (segredo compartilhado): ' + k.K + '</div><div class="key-box">H (hash da troca) = session_id: ' + k.H + '</div>' +
        '<p>O servidor assinou <b>H</b> com a chave de host (' + esc(k.hk) + ', ' + esc(k.fp) + '). Quem verifica a assinatura confirma que fala com o dono da chave. O <b>session_id</b> (o primeiro H) identifica esta sessão e é incluído nas assinaturas de autenticação.</p>';
      if (now < k.tNew) return h + '<p class="muted">As chaves da sessão são derivadas quando as duas pontas trocam NEWKEYS.</p>' + keyTable();
      h +=
        '<h3>Chaves derivadas (RFC 4253, seção 7.2)</h3><table><thead><tr><th>Letra</th><th>Finalidade</th><th>Valor (ilustrativo)</th></tr></thead><tbody>' +
        (k.derived as string[][]).map((d) => '<tr><td>' + d[0] + '</td><td>' + d[1] + '</td><td style="font-family:\'IBM Plex Mono\',monospace;word-break:break-all">' + esc(d[2]) + '</td></tr>').join('') +
        '</tbody></table>' +
        '<p>Cada chave vem de <code>HASH(K || H || letra || session_id)</code>. Cifra: <b>' + esc(k.enc) + '</b>' + (isAead(k.enc) ? ' (AEAD: a própria cifra autentica, as chaves E e F não são usadas)' : '') +
        '. Os valores são ilustrativos: o simulador não faz criptografia real.</p>';
      return h + keyTable();
    },
  },
  {
    id: 'cfg',
    label: 'Configuração',
    render: (tr, ctx) => {
      const P = ctx.P as unknown as SshParams;
      const g = grade(P);
      let h =
        '<h3>Nota de hardening</h3><p><span class="grade ' + g.letter + '">' + g.letter + '</span><b>' + g.ok + ' de ' + g.total + ' boas práticas (' + g.pct + '%)</b></p><ul>' +
        g.items.map((x) => '<li><span class="' + (x[1] ? 'chk-ok' : 'chk-bad') + '">' + (x[1] ? 'OK' : 'FALTA') + '</span> ' + esc(x[0]) + '</li>').join('') + '</ul>' +
        '<p>A nota é didática: mede o que a configuração escolhida no painel faz ou deixa de fazer. Em produção, use o <b>ssh-audit</b> e revise a política de acesso.</p>';
      h += '<div class="cfg-two"><div><h3>Servidor (sshd_config)</h3><pre class="conf">' + esc(sshdConf(P)) + '</pre></div><div><h3>Cliente (ssh_config)</h3><pre class="conf">' + esc(sshConf(P)) + '</pre></div></div>';
      const log = authLog(P, tr.raw);
      h += '<h3>O que o servidor registra (auth.log)</h3><pre class="conf">' + esc(log.join('\n') || '(sem registros)') + '</pre><p>Esses registros alimentam a detecção de ataques e o bloqueio automático de origens.</p>';
      return h;
    },
  },
];
