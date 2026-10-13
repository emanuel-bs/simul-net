(function(){
'use strict';
/* ==========================================================================
   MÓDULO HTTPS (TLS 1.3, TLS 1.2, certificados X.509 e HSTS)
   RFC 8446 (TLS 1.3), RFC 5246 (TLS 1.2), RFC 6066 (SNI e OCSP stapling), RFC 6797 (HSTS), RFC 5280 (X.509).
   Não há criptografia real: valores de chaves, hashes e assinaturas são determinísticos e ilustrativos.
   ========================================================================== */
const SS=window.SecureSim, hex=SS.hex, b64=SS.b64;
const ORDER=['TLS 1.3','TLS 1.2','TLS 1.1','TLS 1.0'];
const S13_ALL=['TLS_AES_256_GCM_SHA384','TLS_CHACHA20_POLY1305_SHA256','TLS_AES_128_GCM_SHA256'];

const CPROF={
  moderno:{nome:'Moderno (TLS 1.3 e 1.2)',vers:['TLS 1.3','TLS 1.2'],s13:S13_ALL,s12:['ECDHE-ECDSA-AES128-GCM-SHA256','ECDHE-RSA-AES128-GCM-SHA256','ECDHE-ECDSA-CHACHA20-POLY1305','ECDHE-RSA-AES256-GCM-SHA384'],ua:'Mozilla/5.0 (Chrome 124)'},
  intermediario:{nome:'Intermediário (só TLS 1.2)',vers:['TLS 1.2'],s13:[],s12:['ECDHE-ECDSA-AES128-GCM-SHA256','ECDHE-RSA-AES128-GCM-SHA256','ECDHE-RSA-AES128-SHA256','TLS_RSA_WITH_AES_128_CBC_SHA'],ua:'Android 7 (TLS 1.2)'},
  legado:{nome:'Legado (TLS 1.0 e 1.1)',vers:['TLS 1.1','TLS 1.0'],s13:[],s12:['TLS_RSA_WITH_AES_128_CBC_SHA','TLS_RSA_WITH_3DES_EDE_CBC_SHA'],ua:'Internet Explorer 8 (Windows XP)'}
};
const SPROF={
  moderno:{nome:'Moderno (TLS 1.3 e 1.2)',vers:['TLS 1.3','TLS 1.2'],s13:S13_ALL,s12:['ECDHE-ECDSA-AES256-GCM-SHA384','ECDHE-RSA-AES256-GCM-SHA384','ECDHE-ECDSA-CHACHA20-POLY1305','ECDHE-RSA-AES128-GCM-SHA256'],sw:'nginx/1.25.3'},
  intermediario:{nome:'Intermediário (só TLS 1.2)',vers:['TLS 1.2'],s13:[],s12:['ECDHE-ECDSA-AES128-GCM-SHA256','ECDHE-RSA-AES128-GCM-SHA256','ECDHE-RSA-AES128-SHA256'],sw:'Apache/2.4.29'},
  legado:{nome:'Legado (TLS 1.0 a 1.2, RSA sem sigilo futuro)',vers:['TLS 1.2','TLS 1.1','TLS 1.0'],s13:[],s12:['TLS_RSA_WITH_AES_128_CBC_SHA','TLS_RSA_WITH_AES_256_CBC_SHA','TLS_RSA_WITH_3DES_EDE_CBC_SHA'],sw:'Apache/2.2.15'},
  endurecido:{nome:'Endurecido (só TLS 1.3)',vers:['TLS 1.3'],s13:['TLS_AES_256_GCM_SHA384','TLS_CHACHA20_POLY1305_SHA256'],s12:[],sw:'nginx/1.25.3'}
};
const compat=(suite,kt)=>/ECDSA/.test(suite)?kt==='ecdsa':(/RSA/.test(suite)?kt==='rsa':true);
const hasFS=suite=>/^TLS_(AES|CHACHA)/.test(suite)||/ECDHE|DHE/.test(suite);
const isWeakSuite=suite=>/CBC|3DES|RC4|_SHA$/.test(suite)&&!/SHA256|SHA384/.test(suite);
const weakVer=v=>v==='TLS 1.0'||v==='TLS 1.1';
const ALERT={protocol_version:[70,'protocol_version'],handshake_failure:[40,'handshake_failure'],bad_certificate:[42,'bad_certificate'],certificate_revoked:[44,'certificate_revoked'],certificate_expired:[45,'certificate_expired'],unknown_ca:[48,'unknown_ca'],illegal_parameter:[47,'illegal_parameter'],close_notify:[0,'close_notify']};
const BROWSER_ERR={expired:'ERR_CERT_DATE_INVALID',name:'ERR_CERT_COMMON_NAME_INVALID',selfsigned:'ERR_CERT_AUTHORITY_INVALID',chain:'ERR_CERT_AUTHORITY_INVALID',revoked:'ERR_CERT_REVOKED'};
const SNI='www.example.org';

// Verificação do certificado do servidor (RFC 5280 e 6125): devolve a lista de testes e o primeiro que falha.
function certChecks(P){
  const st=P.certState;
  const checks=[
    ['Cadeia: leaf → intermediário → raiz confiável',st!=='selfsigned'&&st!=='chain','selfsigned'===st?'o certificado é autoassinado: nenhuma CA do repositório de confiança o assinou':(st==='chain'?'o servidor não enviou o certificado intermediário: o cliente não consegue ligar o leaf a uma raiz confiável':'cada certificado é assinado pelo seguinte e a raiz está no repositório de confiança')],
    ['Assinaturas da cadeia verificadas',st!=='selfsigned'&&st!=='chain','cada assinatura confere com a chave pública do emissor'],
    ['Período de validade (notBefore e notAfter)',st!=='expired',st==='expired'?'o certificado venceu em 12/03/2025':'a data atual está dentro da validade'],
    ['Nome do site na lista SAN',st!=='name',st==='name'?'o certificado vale para shop.example.net, e o site acessado é '+SNI:'o SAN inclui '+SNI+' (o campo CN é ignorado)'],
    ['Uso permitido (EKU serverAuth e CA:FALSE)',true,'o certificado pode autenticar servidores TLS'],
    ['Revogação (OCSP ou CRL)',st!=='revoked',st==='revoked'?'a CA marcou o certificado como revogado (chave comprometida)':'a CA informa que o certificado está "good"'],
    ['Certificate Transparency (SCT)',true,'o certificado traz prova de registro em logs públicos']
  ];
  const first=checks.find(c=>!c[1]);
  return {checks:checks,failed:first?first[0]:null,ok:!first};
}
function certAlert(st){ return ({expired:'certificate_expired',name:'bad_certificate',selfsigned:'unknown_ca',chain:'unknown_ca',revoked:'certificate_revoked'})[st]; }

const controls=[
  {id:'rtt',num:true,grp:'Rede',label:'RTT (ms)',type:'select',opts:[[5,'5'],[20,'20'],[50,'50'],[100,'100'],[200,'200']],def:50,help:{t:'RTT',p:['Tempo de ida e volta entre navegador e servidor.','O TLS 1.3 completo custa 1 RTT além do TCP; o TLS 1.2, 2 RTT. A retomada e o 0-RTT reduzem esse custo.']}},
  {id:'cProf',grp:'Navegador',label:'Perfil do navegador',type:'select',wide:true,opts:[['moderno','Moderno (TLS 1.3 e 1.2)'],['intermediario','Intermediário (só TLS 1.2)'],['legado','Legado (TLS 1.0 e 1.1)']],def:'moderno',help:{t:'Perfil do navegador',s:'Versões e cifras que o cliente oferece.',p:['<b>Moderno:</b> TLS 1.3 e 1.2, só com cifras AEAD e sigilo futuro.','<b>Intermediário:</b> só TLS 1.2, com algumas cifras CBC.','<b>Legado:</b> TLS 1.0 e 1.1, com RSA sem sigilo futuro, CBC e 3DES. Navegadores atuais já recusam estes protocolos.']}},
  {id:'hsts',subs:['web'],grp:'Navegador',label:'HSTS no navegador',type:'select',wide:true,opts:[['none','Nunca visitou (sem HSTS)'],['cached','Em cache (visita anterior)'],['preload','Na lista de preload']],def:'none',help:{t:'HSTS no navegador',s:'Se o navegador já sabe que o site só usa HTTPS.',p:['<b>Sem HSTS:</b> a primeira requisição pode sair em HTTP puro.','<b>Em cache:</b> o navegador lembra do cabeçalho Strict-Transport-Security de uma visita anterior e troca http por https internamente.','<b>Preload:</b> o domínio já vem na lista embutida do navegador, protegendo até a primeira visita.']}},
  {id:'mode',subs:['handshake'],grp:'Handshake',label:'Tipo de conexão',type:'select',wide:true,opts:[['full','Completa (primeira visita)'],['resume','Retomada de sessão (ticket)'],['zero','Retomada com 0-RTT (dados antecipados)']],def:'full',help:{t:'Tipo de conexão',s:'Handshake completo ou retomado.',p:['<b>Completa:</b> há troca de chaves e o servidor envia o certificado.','<b>Retomada:</b> usa um ticket da conexão anterior (PSK) e dispensa o certificado.','<b>0-RTT:</b> no TLS 1.3, o cliente já envia a requisição junto com o primeiro pacote. É mais rápido, mas esses dados podem ser repetidos por um atacante (replay).']}},
  {id:'mtls',subs:['handshake'],grp:'Handshake',label:'Certificado de cliente (mTLS)',type:'check',def:false,help:{t:'mTLS',s:'O servidor também autentica o cliente.',p:['Com mTLS, o servidor envia CertificateRequest e o cliente apresenta o próprio certificado. É comum em APIs internas e redes de confiança zero.']}},
  {id:'certState',subs:['cert'],grp:'Certificado',label:'Situação do certificado',type:'select',wide:true,opts:[['valid','Válido'],['expired','Expirado'],['name','Nome não confere (SAN)'],['selfsigned','Autoassinado (CA desconhecida)'],['chain','Cadeia incompleta (sem intermediário)'],['revoked','Revogado']],def:'valid',help:{t:'Situação do certificado',s:'O que o navegador encontra ao validar.',p:['Cada defeito leva a um teste que falha e a um alerta TLS diferente.','O usuário vê um erro do navegador (por exemplo ERR_CERT_DATE_INVALID).']}},
  {id:'stapling',subs:['cert'],grp:'Certificado',label:'OCSP stapling no servidor',type:'check',def:true,help:{t:'OCSP stapling',s:'O servidor anexa a resposta de revogação.',p:['Com stapling, o servidor entrega a resposta OCSP da CA junto ao certificado. O navegador não consulta a CA, o que é mais rápido e preserva a privacidade.','Sem stapling, o navegador pergunta à CA, gastando 1 RTT e revelando a ela qual site você visita.']}},
  {id:'sProf',grp:'Servidor',label:'Perfil do servidor',type:'select',wide:true,opts:[['moderno','Moderno (TLS 1.3 e 1.2)'],['intermediario','Intermediário (só TLS 1.2)'],['legado','Legado (TLS 1.0 a 1.2, RSA)'],['endurecido','Endurecido (só TLS 1.3)']],def:'moderno',help:{t:'Perfil do servidor',s:'Versões e cifras que o servidor aceita.',p:['Sem versão ou cifra em comum, o servidor responde com alerta fatal (protocol_version ou handshake_failure).','<b>Legado:</b> aceita TLS 1.0 e RSA sem sigilo futuro.','<b>Endurecido:</b> só TLS 1.3.']}},
  {id:'redirect',subs:['web'],grp:'Servidor',label:'Redireciona HTTP para HTTPS',type:'check',def:true,help:{t:'Redirecionamento',s:'O servidor responde 301 na porta 80.',p:['Sem o redirecionamento, quem digita o endereço sem https continua em HTTP.']}},
  {id:'sendHsts',subs:['web'],grp:'Servidor',label:'Envia o cabeçalho HSTS',type:'check',def:true,help:{t:'Strict-Transport-Security',s:'Cabeçalho que ativa o HSTS.',p:['O servidor manda <code>Strict-Transport-Security: max-age=31536000; includeSubDomains; preload</code> nas respostas HTTPS. O navegador passa a usar só HTTPS neste site pelo prazo indicado.']}},
  {id:'serverHttps',subs:['web'],grp:'Servidor',label:'Atende HTTPS (porta 443)',type:'check',def:true,help:{t:'HTTPS no servidor',s:'Se a porta 443 está ativa.',p:['Desmarcado, o site só existe em HTTP: nada é cifrado nem autenticado.']}},
  {id:'action',subs:['cmp'],grp:'Comparação',label:'O que o usuário faz',type:'select',wide:true,opts:[['login','Login com usuário e senha'],['search','Busca (GET com termo)'],['page','Página com sessão (cookie)']],def:'login',help:{t:'Ação do usuário',s:'A mesma ação é feita em HTTP e em HTTPS.',p:['<b>Login:</b> envia usuário e senha no corpo de um POST e recebe um cookie de sessão.','<b>Busca:</b> envia o termo pesquisado na URL.','<b>Página com sessão:</b> pede uma página enviando o cookie de sessão.','Compare o que um observador na rede consegue ler em cada caso.']}},
  {id:'tamper',subs:['cmp'],grp:'Comparação',label:'Equipamento no caminho altera a página',type:'check',def:false,help:{t:'Alteração no caminho',s:'Um proxy ou rede Wi-Fi pública injeta conteúdo na resposta.',p:['Em HTTP, a página é alterada e o navegador a exibe sem perceber.','Em HTTPS, o registro alterado falha na verificação de autenticidade (AEAD) e a conexão é encerrada.','É a diferença entre confidencialidade e integridade: o HTTPS protege as duas.']}},
  {id:'keyType',adv:true,subs:['handshake','cert'],grp:'Servidor',label:'Chave do certificado',type:'select',opts:[['ecdsa','ECDSA P-256'],['rsa','RSA 2048']],def:'ecdsa',help:{t:'Chave do certificado',s:'Tipo de chave do servidor.',p:['ECDSA gera assinaturas e certificados menores e mais rápidos. As cifras RSA do TLS 1.2 exigem chave RSA.']}},
  {id:'downgrade',adv:true,subs:['handshake'],grp:'Rede',label:'Equipamento no caminho força TLS 1.2',type:'check',def:false,help:{t:'Tentativa de downgrade',s:'Um equipamento remove o TLS 1.3 do ClientHello.',p:['O servidor vê só TLS 1.2 e responde com a versão menor. Mas, se ele suporta TLS 1.3, coloca um valor sentinela no final do campo random do ServerHello, e o cliente que suporta 1.3 percebe e aborta.']}}
];
window.__TLS={CPROF:CPROF,SPROF:SPROF,ORDER:ORDER,compat:compat,hasFS:hasFS,isWeakSuite:isWeakSuite,weakVer:weakVer,ALERT:ALERT,BROWSER_ERR:BROWSER_ERR,SNI:SNI,certChecks:certChecks,certAlert:certAlert,controls:controls};
})();
