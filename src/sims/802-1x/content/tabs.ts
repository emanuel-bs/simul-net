// Abas próprias do simulador de 802.1X: estado da porta, pacotes RADIUS e comparação dos métodos EAP.
import { esc, fmtMs } from '../../../sim-core';
import type { TabDef } from '../../../sim-core/ui';
import { fmtTime, METHODS, type MethodKey } from '../model';

const PORT_NAME: Record<string, string> = { unauth: 'não autorizada', authing: 'em autenticação', auth: 'autorizada' };
const PORT_TRAFFIC: Record<string, string> = { unauth: 'só EAPOL', authing: 'só EAPOL', auth: 'todo o tráfego' };

const porta: TabDef = {
  id: 'porta',
  label: 'Porta',
  render: (tr, ctx) => {
    const R = tr.raw;
    const now = ctx.timeAt(ctx.c);
    const log = ((R.port || []) as { t: number; state: string; why: string }[]).filter((p) => p.t <= now + 1e-9);
    const frames = ((R.frames || []) as { t: number; who: string; ok: boolean; label: string; why: string }[]).filter((f) => f.t <= now + 1e-9);
    let h = '<h3>Estado da porta controlada (Gi1/0/5)</h3>';
    h += '<table class="sc-msgs"><thead><tr><th>Instante</th><th>Estado</th><th>Passa pela porta</th><th>Motivo</th></tr></thead><tbody>';
    log.forEach((p) => {
      h += '<tr><td>' + esc(fmtTime(p.t)) + '</td><td class="meaning">' + PORT_NAME[p.state] + '</td><td class="meaning">' + PORT_TRAFFIC[p.state] + '</td><td class="meaning">' + esc(p.why) + '</td></tr>';
    });
    h += '</tbody></table>';
    h += '<h3>Quadros de dados na porta</h3>';
    if (!frames.length) h += '<p>Nenhum quadro de dados enviado até agora.</p>';
    else {
      h += '<table class="sc-msgs"><thead><tr><th>Instante</th><th>Origem</th><th>Quadro</th><th>Resultado</th><th>Motivo</th></tr></thead><tbody>';
      frames.forEach((f) => {
        h += '<tr><td>' + esc(fmtTime(f.t)) + '</td><td class="meaning">' + (f.who === 'dev2' ? '2º dispositivo' : 'Notebook') + '</td><td class="meaning">' + esc(f.label) + '</td><td class="meaning">' + (f.ok ? 'encaminhado' : 'descartado') + '</td><td class="meaning">' + esc(f.why) + '</td></tr>';
      });
      h += '</tbody></table>';
    }
    h += '<p>A <b>porta não controlada</b> aceita sempre o EAPOL. A <b>porta controlada</b> só encaminha dados depois do Access-Accept. O estado de cada porta é decidido pelo switch (o autenticador), nunca pelo suplicante.</p>';
    return h;
  },
};

const radius: TabDef = {
  id: 'radius',
  label: 'RADIUS',
  subs: ['auth', 'falha', 'porta'],
  render: (tr, ctx) => {
    const now = ctx.timeAt(ctx.c);
    const rad = ((tr.raw.rad || []) as { t: number; code: string; id: number; label: string; from: string; to: string; lost: boolean; attrs: string[] }[]).filter((r) => r.t <= now + 1e-9);
    let h = '<h3>Pacotes RADIUS trocados entre o switch e o servidor</h3>';
    if (!rad.length) return h + '<p>Nenhum pacote RADIUS até agora. Avance a simulação.</p>';
    h += '<table class="sc-msgs"><thead><tr><th>Instante</th><th>Pacote</th><th>Id</th><th>De para</th><th>Atributos principais</th></tr></thead><tbody>';
    rad.forEach((r) => {
      h += '<tr><td>' + esc(fmtTime(r.t)) + '</td><td class="meaning">' + esc(r.code) + (r.lost ? ' (sem resposta)' : '') + '</td><td class="meaning">' + r.id + '</td><td class="meaning">' + esc(r.from + ' para ' + r.to) + '</td><td class="meaning">' + esc(r.attrs.filter((a) => /^(EAP-Message|State|Session-Timeout|User-Name)/.test(a)).join('; ')) + '</td></tr>';
    });
    h += '</tbody></table>';
    h += '<p>O <b>Identifier</b> do RADIUS pareia pedido e resposta e é independente do Identifier do EAP. O <b>State</b> faz o servidor reconhecer a conversa a cada Access-Request. O Message-Authenticator, nos pacotes com EAP-Message, é obrigatório (RFC 3579, seções 3.1 e 3.2). Tempo de ida e volta até o servidor: ' + fmtMs(tr.rtt) + '.</p>';
    return h;
  },
};

const CMP: Record<MethodKey, string[]> = {
  md5: ['senha (MD5 de desafio e resposta)', 'não', 'não', 'não', 'só para estudo'],
  peap: ['certificado do servidor e senha do usuário', 'sim (o servidor por certificado, o cliente por senha dentro do túnel)', 'sim', 'sim', 'redes sem certificados de cliente'],
  tls: ['certificados do servidor e do cliente', 'sim', 'sim', 'sim', 'redes com infraestrutura de certificados'],
};

const metodos: TabDef = {
  id: 'metodos',
  label: 'Métodos EAP',
  subs: ['auth', 'seg'],
  render: (tr) => {
    const cur = tr.raw.method as MethodKey | undefined;
    let h = '<h3>Comparação dos métodos EAP do simulador</h3>';
    h += '<table class="sc-msgs"><thead><tr><th>Método</th><th>Tipo EAP</th><th>Credencial</th><th>Autenticação mútua</th><th>Túnel TLS</th><th>Deriva chaves</th><th>Uso típico</th></tr></thead><tbody>';
    (['md5', 'peap', 'tls'] as MethodKey[]).forEach((k) => {
      const m = METHODS[k];
      const c = CMP[k];
      h += '<tr' + (k === cur ? ' class="cur"' : '') + '><td>' + esc(m.name) + (k === cur ? ' (neste cenário)' : '') + '</td><td class="meaning">' + m.type + '</td><td class="meaning">' + esc(c[0]) + '</td><td class="meaning">' + esc(c[1]) + '</td><td class="meaning">' + (k === 'md5' ? 'não' : 'sim') + '</td><td class="meaning">' + esc(c[3]) + '</td><td class="meaning">' + esc(c[4]) + '</td></tr>';
    });
    h += '</tbody></table>';
    h += '<p>Para o EAP-MD5, as alegações de segurança estão na RFC 3748, seção 5.4. Para o EAP-TLS, na RFC 5216, atualizada pela RFC 9190 (TLS 1.3). O PEAP não é um padrão da IETF. A derivação de chaves só é usada quando algo precisa delas, como o Wi-Fi ou o MACsec; no Ethernet comum sem MACsec, o resultado do EAP é só abrir a porta.</p>';
    return h;
  },
};

export const tabs: TabDef[] = [porta, radius, metodos];
