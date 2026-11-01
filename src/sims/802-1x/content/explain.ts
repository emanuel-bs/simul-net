// Texto da aba Experimento e do cabeçalho do cenário.
import type { Trace } from '../../../sim-core';
import type { ScenarioDef } from '../../../sim-core/ui';
import { METHODS, SESSION_TIMEOUT, type MethodKey } from '../model';

/** Texto "Configuração do cenário": só o que o cenário define (o restante vem dos padrões). */
export function setup(s: ScenarioDef): string {
  const V = (s.set || {}) as Record<string, any>;
  if (s.sub === 'auth') return 'método: ' + METHODS[V.method as MethodKey].name;
  if (s.sub === 'falha') {
    return { cred: 'PEAP com senha incorreta', cert: 'EAP-TLS com certificado do cliente expirado', noserver: 'servidor RADIUS inalcançável', secret: 'segredo compartilhado diferente no servidor', nosup: 'dispositivo sem suplicante 802.1X' }[V.cause as 'cred'] || '';
  }
  if (s.sub === 'porta') {
    if (V.pact === 'reauth') return 'sessão com Session-Timeout de ' + SESSION_TIMEOUT + ' s; método: ' + METHODS[V.method as MethodKey].name;
    if (V.pact === 'logoff') return 'sessão autorizada; o suplicante envia EAPOL-Logoff';
    return 'segundo dispositivo atrás da mesma porta; autorização ' + (V.pdef === 'permac' ? 'por endereço MAC' : 'por porta');
  }
  const r = V.risk === 'peap' ? 'PEAP sem validar o certificado do servidor' : 'EAP-MD5 diante de um autenticador falso';
  return r + '; ' + (V.sdef === 'def' ? 'com a defesa' : 'sem defesa');
}

export function explain(tr: Trace): string {
  const R = tr.raw;
  let h = '<ul>';
  if (R.sub === 'auth') {
    const m = METHODS[R.method as MethodKey];
    h += '<li>O primeiro frame de dados foi <span class="chk-bad">descartado</span>: a porta controlada estava fechada, e só o EAPOL passa pela porta não controlada.</li>';
    h += '<li>O EAP foi conduzido de ponta a ponta pelo <b>' + m.name + '</b>. O switch só repassou os pacotes, entre EAPOL (do lado do suplicante) e RADIUS (do lado do servidor).</li>';
    h += '<li>O servidor decidiu e respondeu <b>Access-Accept</b>. <span class="chk-ok">O switch abriu a porta</span>, e o mesmo frame de dados passou a ser encaminhado.</li>';
    if (m.key === 'md5') h += '<li>Atenção: com o EAP-MD5 o suplicante <b>não autenticou o servidor</b>. O cenário de risco mostra a consequência.</li>';
    else h += '<li>O suplicante também conferiu o servidor pelo certificado dele. Na prática, essa verificação precisa estar configurada no suplicante.</li>';
    h += '<li>Lição: o 802.1X troca a pergunta "o cabo está ligado?" por "quem é você?" antes de liberar qualquer dado.</li>';
  } else if (R.sub === 'falha') {
    if (R.res === 'cred' || R.res === 'cert') {
      h += '<li><span class="chk-bad">O servidor respondeu Access-Reject:</span> ' + (R.res === 'cred' ? 'a prova da senha dentro do túnel não conferiu com o hash guardado.' : 'o certificado do cliente está fora da validade.') + '</li>';
      h += '<li>O switch repassou um EAP-Failure ao suplicante. O frame de dados seguinte foi descartado: a porta continua fechada.</li>';
      h += '<li>Lição: a recusa explícita é a mais fácil de diagnosticar. O motivo exato fica no log do servidor, e o suplicante só vê "falha".</li>';
    } else if (R.res === 'noserver') {
      h += '<li><span class="chk-bad">Nenhum Access-Request teve resposta:</span> o switch tentou três vezes, a cada 5 s, e desistiu.</li>';
      h += '<li>O switch enviou o EAP-Failure por conta própria. A porta continua fechada: o acesso falha de modo seguro.</li>';
      h += '<li>Lição: se o servidor RADIUS cai, ninguém novo entra. Convém ter servidores redundantes e monitorados.</li>';
    } else if (R.res === 'secret') {
      h += '<li><span class="chk-bad">Os pedidos chegaram, mas o servidor os descartou em silêncio:</span> o Message-Authenticator não confere porque o segredo compartilhado é outro.</li>';
      h += '<li>Do lado do switch o sintoma é idêntico ao de um servidor fora do ar. Só o log do servidor mostra a causa.</li>';
      h += '<li>Lição: um segredo diferente não produz erro visível. Confira o segredo nos dois lados antes de suspeitar da rede.</li>';
    } else {
      h += '<li><span class="chk-bad">Ninguém respondeu ao EAP-Request/Identity:</span> o dispositivo não tem suplicante 802.1X.</li>';
      h += '<li>O servidor RADIUS nem foi consultado. A porta continua fechada.</li>';
      h += '<li>Lição: dispositivos sem suplicante exigem outra política de acesso, que não faz parte do modelo básico.</li>';
    }
  } else if (R.sub === 'porta') {
    if (R.res === 'reauth') {
      h += '<li>O Session-Timeout de ' + SESSION_TIMEOUT + ' s expirou e o switch iniciou uma nova autenticação.</li>';
      h += '<li><span class="chk-ok">A porta permaneceu autorizada durante o processo:</span> o frame enviado no meio da troca passou.</li>';
      h += '<li>O novo Access-Accept renovou a sessão com outro Session-Timeout.</li>';
      h += '<li>Lição: a reautenticação periódica limita a validade de uma credencial sem interromper o usuário.</li>';
    } else if (R.res === 'logoff') {
      h += '<li>O <b>EAPOL-Logoff</b> chegou e o switch <span class="chk-ok">fechou a porta imediatamente</span>, sem esperar o Session-Timeout.</li>';
      h += '<li>O frame seguinte foi descartado.</li>';
      h += '<li>Lição: encerrar a sessão fecha a porta. O Logoff não é autenticado nas implementações sem MACsec.</li>';
    } else if (R.res === 'extra-leak') {
      h += '<li><span class="chk-bad">O segundo dispositivo usou a rede sem se autenticar:</span> a autorização valeu para a porta inteira.</li>';
      h += '<li>O switch não tem como distinguir os dois dispositivos no modelo básico do 802.1X.</li>';
      h += '<li>Lição: o 802.1X autoriza a porta, e não o dispositivo. Uma porta deve ligar um só equipamento, ou o switch deve autorizar por endereço MAC.</li>';
    } else {
      h += '<li><span class="chk-ok">O frame do segundo dispositivo foi descartado:</span> o endereço MAC dele não passou pela autenticação.</li>';
      h += '<li>O Notebook continua com acesso.</li>';
      h += '<li>Lição: a autorização por endereço MAC permite vários equipamentos por porta sem abrir a porta a todos.</li>';
    }
  } else {
    if (R.res === 'md5-exposed') {
      h += '<li><span class="chk-bad">O Notebook aceitou o Success de um equipamento falso:</span> o EAP-MD5 não autentica o servidor.</li>';
      h += '<li>A resposta ao desafio, que contém uma prova da senha, ficou nas mãos de quem controla o equipamento.</li>';
      h += '<li>Lição: o EAP-MD5 não oferece autenticação mútua (RFC 3748, seção 5.4). Em redes reais, use um método com túnel e validação do servidor.</li>';
    } else if (R.res === 'tls-reject') {
      h += '<li><span class="chk-ok">O Notebook recusou o equipamento falso:</span> a cadeia do certificado terminava numa CA desconhecida.</li>';
      h += '<li>Nenhuma credencial foi enviada.</li>';
      h += '<li>Lição: a autenticação mútua do EAP-TLS faz o suplicante desconfiar antes de falar.</li>';
    } else if (R.res === 'peap-exposed') {
      h += '<li><span class="chk-bad">A credencial chegou ao equipamento falso:</span> o suplicante abriu o túnel sem validar o certificado do servidor.</li>';
      h += '<li>O túnel protegeu o caminho, e não o destino.</li>';
      h += '<li>Lição: no PEAP, a validação do certificado do servidor é parte da segurança, e não um detalhe.</li>';
    } else {
      h += '<li><span class="chk-ok">O Notebook interrompeu o túnel:</span> o certificado não pertence à CA configurada, e o nome não corresponde ao servidor da organização.</li>';
      h += '<li>Nenhum usuário nem senha saíram do Notebook.</li>';
      h += '<li>Lição: configure o suplicante para validar a CA e o nome do servidor, e bloqueie a aceitação manual de certificados.</li>';
    }
  }
  return h + '</ul>';
}
