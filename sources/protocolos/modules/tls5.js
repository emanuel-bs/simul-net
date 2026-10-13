(function(){
'use strict';
const SS=window.SecureSim, T=window.__TLS, esc=SS.esc, plural=SS.plural;
const {CPROF,SPROF,controls,grade,hasFS,isWeakSuite,weakVer,SNI}=T;
const concepts=a=>'<h3>Conceitos observados</h3><ul>'+a.map(x=>'<li>'+x+'</li>').join('')+'</ul>';

function setup(s){
  const P={}; controls.forEach(c=>{ P[c.id]=c.def; }); Object.keys(s.set||{}).forEach(k=>{ P[k]=s.set[k]; });
  const p=['navegador '+CPROF[P.cProf].nome,'servidor '+SPROF[P.sProf].nome,'RTT de '+P.rtt+' ms'];
  if(s.sub==='handshake'){ p.push('conexão: '+({full:'completa',resume:'retomada',zero:'0-RTT'})[P.mode]); if(P.mtls) p.push('mTLS'); if(P.downgrade) p.push('downgrade forçado'); if(P.keyType!=='ecdsa') p.push('certificado RSA'); }
  else if(s.sub==='cert'){ p.push('certificado: '+({valid:'válido',expired:'expirado',name:'nome diferente',selfsigned:'autoassinado',chain:'cadeia incompleta',revoked:'revogado'})[P.certState],'OCSP stapling '+(P.stapling?'ligado':'desligado')); }
  else if(s.sub==='cmp'){ p.push('ação: '+({login:'login com usuário e senha',search:'busca (GET com termo)',page:'página com sessão (cookie)'})[P.action],P.tamper?'equipamento no caminho altera a página':'sem adulteração'); }
  else { p.push('HSTS no navegador: '+({none:'ausente',cached:'em cache',preload:'preload'})[P.hsts],'redirecionamento '+(P.redirect?'sim':'não'),'cabeçalho HSTS '+(P.sendHsts?'sim':'não'),'HTTPS '+(P.serverHttps?'ativo':'inativo')); }
  return 'Configuração do cenário: <code>'+esc(p.join('; '))+'</code>';
}


function explainCompare(tr,P){
  const r=tr.raw, H=r.http, S=r.https, R=r.R, fmtMs=SS.fmtMs;
  const A={login:'login com usuário e senha',search:'busca (GET com termo)',page:'página com sessão (cookie)'}[P.action];
  const dH=H.tResp-H.t0, dS=S.tResp-S.t0, extra=dS-dH;
  let h='<h3>Configuração</h3><p>O mesmo usuário faz a mesma ação (<b>'+A+'</b>) duas vezes, na mesma rede (RTT de '+P.rtt+' ms) e com um <b>observador na rede</b> (por exemplo, um Wi-Fi público): primeiro por <b>HTTP</b> (porta 80) e depois por <b>HTTPS</b> (porta 443, '+esc(CPROF[P.cProf].nome)+' contra '+esc(SPROF[P.sProf].nome)+')'+(P.tamper?', com um equipamento no caminho que tenta <b>alterar a página</b>':'')+'.</p><h3>O que aconteceu</h3>';
  h+='<p><b>HTTP.</b> Depois do TCP (1 RTT), a requisição saiu em <b>texto puro</b>. O observador leu: '+H.leak.map(esc).join('; ')+'. A resposta chegou em <b>'+fmtMs(dH)+'</b>'+(P.tamper?' e foi <b>alterada no caminho</b>: o navegador exibiu a página com o conteúdo injetado sem perceber, porque o HTTP não tem como detectar a alteração.':', também em claro.')+' O HTTP também não autentica o servidor: nada garante que quem respondeu é o site verdadeiro.</p>';
  if(R.fail&&R.fail.stage!=='tamper'){
    h+='<p><b>HTTPS.</b> O handshake TLS falhou ('+esc(R.fail.alert||R.fail.stage)+'): nenhuma requisição foi enviada. Ajuste os perfis do navegador e do servidor para haver versão e cifra em comum.</p>';
    return h+concepts(['<b>Negociação TLS</b> e alerta de falha'])+next(tr,P);
  }
  h+='<p><b>HTTPS.</b> O TCP, o handshake TLS ('+esc(R.ver)+', '+esc(R.suite)+') e, só então, a requisição, agora <b>cifrada</b>. O observador viu o IP e o nome do site (SNI), os tamanhos e os tempos dos registros, mas <b>não</b> a senha, o cookie, a URL nem a página. '+
    (S.tampered?'Quando o equipamento no caminho alterou a resposta, a <b>tag de autenticação (AEAD)</b> não conferiu: o navegador descartou o registro, enviou o alerta <code>bad_record_mac</code> e encerrou a conexão. A alteração foi <b>detectada</b>.':'A resposta chegou em <b>'+fmtMs(dS)+'</b>, '+fmtMs(extra)+' a mais que no HTTP (cerca de +'+(Math.round(extra/P.rtt*10)/10).toString().replace('.',',')+' RTT), o custo do handshake.')+'</p>';
  h+='<p><b>Em números.</b> HTTP: '+H.msgs+' mensagens e cerca de '+H.bytes+' B. HTTPS: '+S.msgs+' mensagens e cerca de '+S.bytes+' B (o handshake e o certificado respondem pela diferença). Veja a aba Comparação.</p>';
  const cs=['<b>Confidencialidade</b>: o observador lê o HTTP e não lê o HTTPS','<b>Integridade</b>: o HTTP não detecta alteração; o HTTPS (AEAD) detecta','<b>Autenticação do servidor</b>: ausente no HTTP, por certificado no HTTPS','<b>Metadados</b> que sobram no HTTPS: IP, SNI, tamanhos e tempos','<b>Custo do handshake</b> do HTTPS em RTTs e em bytes'];
  if(!R.fs) cs.push('<b>Sigilo futuro ausente</b> na troca RSA');
  return h+concepts(cs)+next(tr,P);
}

function explainTls(tr,P){
  const R=tr.raw.R, C=CPROF[P.cProf], S=SPROF[P.sProf], sub=tr.raw.sub;
  let h='<h3>Configuração</h3><p>O navegador ('+esc(C.nome)+') acessa <code>https://'+SNI+'</code> em um servidor ('+esc(S.nome)+', certificado '+(P.keyType==='ecdsa'?'ECDSA P-256':'RSA 2048')+') com <b>RTT de '+P.rtt+' ms</b>. '+
    (sub==='handshake'?'Conexão <b>'+({full:'completa (primeira visita)',resume:'retomada com ticket',zero:'retomada com 0-RTT'})[P.mode]+'</b>'+(P.mtls?', com certificado de cliente (mTLS)':'')+(P.downgrade?', com um equipamento no caminho forçando TLS 1.2':'')+'.':
     'Situação do certificado: <b>'+({valid:'válido',expired:'expirado',name:'emitido para outro nome',selfsigned:'autoassinado',chain:'com a cadeia incompleta',revoked:'revogado'})[P.certState]+'</b>; OCSP stapling '+(P.stapling?'ligado':'desligado')+'.')+'</p>';
  h+='<h3>O que aconteceu</h3>';
  h+='<p><b>TCP.</b> A conexão TCP (1 RTT) veio primeiro: o TLS roda sobre ela, na porta 443.</p>';
  if(R.fail&&R.fail.stage==='neg'){
    h+='<p><b>Negociação.</b> O ClientHello ofereceu '+esc(C.vers.join(', '))+'. O servidor aceita '+esc(S.vers.join(', '))+'. '+(R.fail.what==='version'?'<b>Não há versão em comum</b>, então o servidor respondeu com o alerta fatal <code>protocol_version</code>.':'Há versão em comum, mas <b>nenhuma cifra compatível</b> com o certificado do servidor ('+(P.keyType==='ecdsa'?'ECDSA':'RSA')+'): as cifras RSA exigem chave RSA e as ECDHE-ECDSA exigem ECDSA. O servidor respondeu com <code>handshake_failure</code>.')+' Nada foi cifrado e nenhum dado da aplicação foi enviado.</p>';
    return h+concepts(['<b>ClientHello</b> e negociação de versão e cifra','<b>Alerta fatal</b> ('+R.fail.alert+')'])+next(tr,P);
  }
  h+='<p><b>ClientHello.</b> O navegador anunciou versões, cifras e extensões. O <b>SNI</b> ('+SNI+') vai <b>em claro</b>: quem observa a rede sabe qual site é acessado, mesmo com o conteúdo cifrado (o ECH resolveria isso).'+(R.mode!=='full'?' Nesta conexão ele apresentou também um ticket da visita anterior.':'')+'</p>';
  if(R.fail&&R.fail.stage==='downgrade'){
    h+='<p><b>Downgrade.</b> O equipamento no caminho removeu o TLS 1.3 do ClientHello. O servidor, que suporta 1.3, respondeu em 1.2, mas pôs o sentinela <code>DOWNGRD</code> no final do random do ServerHello. O navegador, que suporta 1.3, reconheceu o sentinela e <b>abortou</b> com <code>illegal_parameter</code>. Sem esse mecanismo, o atacante empurraria a conexão para uma versão e cifras mais fracas.</p>';
    return h+concepts(['<b>Proteção contra downgrade</b> do TLS 1.3 (sentinela DOWNGRD)','<b>supported_versions</b> e o random do ServerHello'])+next(tr,P);
  }
  h+='<p><b>Negociação.</b> Versão <b>'+esc(R.ver)+'</b> com a suíte <b>'+esc(R.suite)+'</b>'+(R.fs?', com <b>sigilo futuro</b> (ECDHE).':', por <b>troca RSA</b>: <b>sem sigilo futuro</b>.')+((weakVer(R.ver)||isWeakSuite(R.suite))?' Esta combinação é considerada obsoleta (versão antiga, CBC ou 3DES).':'')+'</p>';
  if(R.ver==='TLS 1.3'){
    h+='<p><b>Chaves.</b> O ServerHello trouxe a metade do ECDHE do servidor. Com ela, as duas pontas calcularam o segredo e derivaram as chaves de handshake (HKDF). A partir daí tudo vai <b>cifrado</b>, inclusive o certificado: um observador vê só registros "Application Data".</p>';
  } else {
    h+='<p><b>Certificado em claro.</b> No '+esc(R.ver)+' o servidor envia o certificado <b>sem cifrar</b>, junto aos parâmetros da troca de chaves. Quem captura a rede lê a identidade do servidor e o nome do certificado.</p>';
  }
  if(R.cert){
    if(R.fail&&R.fail.stage==='cert') h+='<p><b>Validação do certificado.</b> O navegador falhou no teste "'+esc(R.fail.check)+'". Enviou o alerta <code>'+esc(R.fail.alert)+'</code>, fechou a conexão e mostrou <b>'+esc(R.fail.browser)+'</b> ao usuário. <b>Nenhum dado da aplicação foi enviado.</b></p>';
    else h+='<p><b>Validação do certificado.</b> O navegador verificou a cadeia até uma raiz de confiança, as assinaturas, a validade, o nome (SAN), o uso permitido, a revogação'+(tr.raw.ocsp?' (consultando a CA diretamente: 1 RTT a mais e a CA ficou sabendo qual site foi visitado)':(P.stapling?' (pela resposta OCSP grampeada, sem consultar a CA)':''))+' e a transparência. Todos passaram.</p>';
  } else if(R.mode!=='full') h+='<p><b>Autenticação.</b> Na retomada não há certificado: o ticket (PSK) autentica a sessão. Ele foi emitido em um handshake completo anterior.</p>';
  if(R.fail&&R.fail.stage==='cert') return h+concepts(['<b>Validação de certificado</b> (cadeia, validade, nome, revogação)','<b>Alerta TLS</b> '+R.fail.alert+' e erro do navegador'])+next(tr,P);
  if(P.mtls) h+='<p><b>mTLS.</b> O servidor pediu o certificado do cliente (CertificateRequest) e o cliente enviou Certificate e CertificateVerify. As duas pontas se autenticaram.</p>';
  if(R.mode==='zero'&&R.early) h+='<p><b>0-RTT.</b> A requisição saiu junto com o ClientHello, antes da resposta. Economizou 1 RTT, mas o servidor não distingue um pedido novo de uma <b>repetição</b> por um atacante, e esses dados não têm sigilo futuro. Só deve ser usado em requisições idempotentes.</p>';
  if(R.zeroUnavailable) h+='<p><b>0-RTT indisponível.</b> Só existe no TLS 1.3; esta conexão usou uma retomada comum.</p>';
  h+='<p><b>Dados.</b> '+(R.ver==='TLS 1.3'?'O handshake custou <b>1 RTT</b>: o cliente enviou o Finished e a requisição HTTP juntos.':'O handshake custou <b>2 RTT</b> (1 RTT na retomada), e só depois a requisição HTTP foi enviada.')+' O protocolo HTTP negociado por ALPN foi <b>'+esc(R.alpn)+'</b>. O servidor ainda enviou um NewSessionTicket para futuras retomadas.</p>';
  const cs=['<b>ClientHello</b>, <b>ServerHello</b> e extensões (SNI, supported_versions, key_share)','<b>Negociação</b> de versão e cifra'];
  cs.push(R.fs?'<b>ECDHE</b> e <b>sigilo futuro</b>':'<b>Troca RSA</b> e a falta de sigilo futuro');
  if(R.ver==='TLS 1.3') cs.push('<b>HKDF</b>: chaves de handshake e de aplicação','<b>Certificado cifrado</b> e CertificateVerify'); else cs.push('<b>Certificado em claro</b> no TLS 1.2');
  if(R.cert) cs.push('<b>Validação de certificado</b> (cadeia, validade, nome, revogação)'); if(R.mode!=='full') cs.push('<b>Retomada</b> com ticket (PSK)'); if(R.early) cs.push('<b>0-RTT</b> e replay'); if(P.mtls) cs.push('<b>mTLS</b>');
  return h+concepts(cs)+next(tr,P);
}
function explainWeb(tr,P){
  const W=tr.raw.W, R=tr.raw.R;
  let h='<h3>Configuração</h3><p>O usuário digita <code>example.org</code> (sem https). HSTS no navegador: <b>'+({none:'ausente',cached:'em cache',preload:'na lista de preload'})[P.hsts]+'</b>. O servidor '+(P.serverHttps?'atende HTTPS':'<b>não</b> atende HTTPS')+', '+(P.redirect?'redireciona HTTP para HTTPS':'não redireciona')+' e '+(P.sendHsts?'envia':'não envia')+' o cabeçalho Strict-Transport-Security. RTT de '+P.rtt+' ms.</p><h3>O que aconteceu</h3>';
  if(W.path==='http-only') h+='<p>O site só existe em HTTP. A requisição, o <b>cookie de sessão</b> e a resposta trafegaram em <b>texto puro</b>: sem sigilo, sem integridade e sem autenticação do servidor. Quem estiver no caminho lê e altera tudo.</p>';
  else if(W.path==='no-redirect') h+='<p>O site tem HTTPS, mas o navegador começou em HTTP e o servidor <b>respondeu o conteúdo em HTTP</b>, sem redirecionar. Sem HSTS, nada levou o usuário ao HTTPS: ele permaneceu em claro mesmo havendo certificado.</p>';
  else if(W.upgraded) h+='<p>'+(W.path==='cached'?'O navegador tinha o HSTS em cache e <b>converteu http:// em https:// internamente</b> (307 Internal Redirect). Nenhum pacote HTTP foi enviado.':'O domínio está na <b>lista de preload</b> do navegador: o HTTPS é exigido desde a primeira visita, sem nenhum pacote HTTP.')+' A conexão começou direto no TLS.</p>';
  else h+='<p>Sem HSTS, a <b>primeira requisição saiu em HTTP</b> (porta 80), e o servidor respondeu <b>301</b> para HTTPS. Essa troca inicial vai em claro: um atacante no caminho poderia alterar a resposta ou impedir o upgrade (SSL stripping). Só depois o navegador abriu a conexão HTTPS (porta 443).</p>';
  if(R&&R.ver&&!R.fail){
    h+='<p><b>TLS.</b> O handshake foi em <b>'+esc(R.ver)+'</b> ('+esc(R.suite)+'). '+(W.hstsStored?'Na resposta HTTPS, o servidor enviou <code>Strict-Transport-Security: max-age=31536000; includeSubDomains; preload</code>, e o navegador passou a exigir HTTPS neste site por 1 ano.':'O servidor <b>não enviou</b> o cabeçalho HSTS, então o navegador não aprendeu a exigir HTTPS.')+'</p>';
  } else if(R&&R.fail) h+='<p><b>TLS.</b> O handshake falhou ('+esc(R.fail.stage)+').</p>';
  const cs=['<b>HTTP</b> (porta 80) contra <b>HTTPS</b> (porta 443)'];
  if(W.path==='redirect') cs.push('<b>Redirecionamento 301</b> e a janela de exposição','<b>SSL stripping</b>'); if(W.upgraded) cs.push('<b>HSTS</b> e o upgrade interno do navegador'); if(W.path==='preload') cs.push('<b>Lista de preload</b>'); if(W.hstsStored) cs.push('<b>Strict-Transport-Security</b>');
  return h+concepts(cs)+next(tr,P);
}
function next(tr,P){
  const s=[], g=grade(P), sub=tr.raw.sub, R=tr.raw.R||{};
  if(sub==='handshake'){
    if(P.mode==='full') s.push('Escolha <b>Retomada de sessão</b> e veja o servidor dispensar o certificado.');
    if(P.mode!=='zero') s.push('Escolha <b>0-RTT</b> e observe o pedido sair antes da resposta do servidor.');
    if(P.cProf==='moderno'&&P.sProf==='moderno') s.push('Troque os dois perfis para <b>Intermediário</b> (só TLS 1.2): o handshake passa a custar 2 RTT e o certificado vai em claro.');
    s.push('Marque <b>Equipamento no caminho força TLS 1.2</b> (Ajustes avançados) e veja o downgrade ser detectado.');
  } else if(sub==='cmp'){
    s.push('Troque a ação (login, busca, página com cookie) e compare o que o observador captura em cada uma.');
    if(!P.tamper) s.push('Marque <b>Equipamento no caminho altera a página</b>: o HTTP exibe a página alterada, e o HTTPS detecta a alteração.');
    s.push('Troque os perfis para <b>Intermediário</b> (TLS 1.2) e aumente o RTT: veja o custo do handshake crescer.','Volte ao modo <b>Handshake TLS</b> e escolha a retomada de sessão: o custo do HTTPS diminui.');
  } else if(sub==='cert'){
    s.push('Troque a situação do certificado e compare os alertas e os erros do navegador.');
    if(P.stapling) s.push('Desligue o <b>OCSP stapling</b> e observe a consulta à CA, o 1 RTT extra e a exposição do site visitado.');
    s.push('Veja a aba <b>Certificado</b>: quais testes falham em cada situação?');
  } else {
    if(P.hsts==='none') s.push('Mude o HSTS do navegador para <b>Em cache</b> e veja a primeira requisição HTTP desaparecer.');
    if(P.redirect) s.push('Desmarque o redirecionamento: o usuário fica em HTTP.');
    s.push('Desmarque <b>Envia o cabeçalho HSTS</b> e veja que o navegador não aprende a exigir HTTPS.');
  }
  s.push('Abra a aba <b>Configuração</b>: a nota é '+g.letter+' ('+g.pct+'%). O que falta para chegar a A?');
  return '<h3>Para explorar em seguida</h3><ul>'+s.slice(0,4).map(x=>'<li>'+x+'</li>').join('')+'</ul>';
}
function explain(tr,P){
  const sub=tr.raw.sub;
  const obj={cmp:'Comparar a mesma ação do usuário em HTTP e em HTTPS: o que um observador na rede lê, se a alteração é detectada, quem autentica o servidor e o que cada um custa.',handshake:'Observar como o TLS abre uma conexão segura: negociação, troca de chaves, certificado, retomada e as proteções contra downgrade.',cert:'Observar o que o navegador valida em um certificado e o que acontece quando um teste falha.',web:'Observar como o navegador chega ao HTTPS e como o HSTS fecha a janela de exposição do HTTP.'}[sub];
  return '<p><b>Objetivo.</b> '+obj+'</p>'+(sub==='cmp'?explainCompare(tr,P):(sub==='web'?explainWeb(tr,P):explainTls(tr,P)));
}

const REFERENCE=''+
'<h3>HTTPS = HTTP sobre TLS</h3>'+
'<p>O <b>HTTPS</b> é o HTTP dentro de uma conexão <b>TLS</b>, normalmente na porta 443. O TLS oferece <b>confidencialidade</b> (cifragem), <b>integridade</b> (detecção de alteração) e <b>autenticação do servidor</b> (por certificado X.509) e, opcionalmente, do cliente (mTLS). Ele roda sobre o TCP; o QUIC (HTTP/3) integra o TLS 1.3 sobre UDP.</p>'+
'<h3>TLS 1.3 contra TLS 1.2</h3>'+
'<table><thead><tr><th>Aspecto</th><th>TLS 1.3 (RFC 8446)</th><th>TLS 1.2 (RFC 5246)</th></tr></thead><tbody>'+
'<tr><td>Handshake</td><td>1 RTT (0-RTT na retomada)</td><td>2 RTT (1 RTT na retomada)</td></tr>'+
'<tr><td>Certificado</td><td>cifrado</td><td>em claro</td></tr>'+
'<tr><td>Sigilo futuro</td><td>sempre (só ECDHE e DHE)</td><td>só nas suítes ECDHE/DHE; não na troca RSA</td></tr>'+
'<tr><td>Cifras</td><td>só AEAD (AES-GCM, ChaCha20-Poly1305)</td><td>AEAD e também CBC, 3DES, RC4 (legado)</td></tr>'+
'<tr><td>Troca de chaves</td><td>x25519, secp256r1</td><td>ECDHE, DHE ou RSA</td></tr>'+
'<tr><td>Derivação</td><td>HKDF</td><td>PRF</td></tr>'+
'<tr><td>Downgrade</td><td>sentinela DOWNGRD no random</td><td>sem proteção própria</td></tr></tbody></table>'+
'<h3>O handshake do TLS 1.3</h3>'+
'<ul><li><b>ClientHello:</b> versões (supported_versions), cifras, <b>key_share</b> (metade do ECDHE), <b>SNI</b> (nome do site, em claro), ALPN e outras extensões.</li>'+
'<li><b>ServerHello:</b> versão, cifra e key_share. A partir daqui, as chaves de handshake saem do HKDF e tudo é cifrado.</li>'+
'<li><b>EncryptedExtensions, Certificate, CertificateVerify, Finished:</b> identidade do servidor, assinatura do hash da conversa e confirmação.</li>'+
'<li><b>Finished do cliente:</b> o cliente já pode enviar dados. Depois, o servidor entrega o <b>NewSessionTicket</b>.</li></ul>'+
'<h3>Certificados e validação</h3>'+
'<ul><li>O navegador valida: <b>cadeia</b> até uma raiz confiável, <b>assinaturas</b>, <b>validade</b>, <b>nome no SAN</b>, <b>uso permitido</b> (EKU), <b>revogação</b> e <b>Certificate Transparency</b> (SCT).</li>'+
'<li>A identidade vem do <b>SAN</b>; o campo CN é ignorado.</li>'+
'<li><b>Revogação:</b> OCSP (consulta à CA) ou <b>OCSP stapling</b> (o servidor anexa a resposta assinada). O stapling é mais rápido e preserva a privacidade.</li>'+
'<li>Os prazos são curtos (até 398 dias hoje), e a renovação deve ser automática (ACME, Let\'s Encrypt).</li>'+
'<li>O servidor deve enviar o <b>fullchain</b> (leaf e intermediários).</li></ul>'+
'<h3>Retomada, 0-RTT e privacidade</h3>'+
'<ul><li><b>Ticket (PSK):</b> evita novo certificado e assinatura. Em modo psk_dhe_ke mantém o sigilo futuro.</li>'+
'<li><b>0-RTT:</b> envia dados no primeiro voo. Sem proteção contra <b>replay</b> e sem sigilo futuro para esses dados: só para requisições idempotentes.</li>'+
'<li><b>SNI</b> em claro revela o site visitado; o <b>ECH</b> (Encrypted Client Hello) o esconde.</li>'+
'<li><b>ALPN</b> negocia o protocolo de aplicação (h2 ou http/1.1).</li></ul>'+
'<h3>HTTP x HTTPS: o que muda</h3>'+
'<table><thead><tr><th>Aspecto</th><th>HTTP</th><th>HTTPS</th></tr></thead><tbody>'+
'<tr><td>Porta</td><td>80</td><td>443</td></tr>'+
'<tr><td>Confidencialidade</td><td>nenhuma: o conteúdo, a URL, os cookies e as senhas são legíveis</td><td>cifrada (AEAD); o observador vê só IP, SNI, tamanhos e tempos</td></tr>'+
'<tr><td>Integridade</td><td>nenhuma: um intermediário pode alterar a resposta</td><td>cada registro tem uma tag de autenticação: a alteração é detectada</td></tr>'+
'<tr><td>Autenticação do servidor</td><td>nenhuma</td><td>certificado X.509 validado pelo navegador</td></tr>'+
'<tr><td>Custo inicial</td><td>1 RTT (TCP)</td><td>2 RTT com TLS 1.3 e 3 RTT com TLS 1.2, além de bytes de handshake e certificado</td></tr>'+
'<tr><td>Recursos modernos</td><td>HTTP/1.1</td><td>HTTP/2 e HTTP/3 (exigem TLS na prática), cookies Secure, service workers e APIs sensíveis do navegador</td></tr></tbody></table>'+
'<p>O custo do HTTPS é pago uma vez por conexão e diminui com TLS 1.3, retomada de sessão, conexões persistentes e HTTP/2 ou HTTP/3. Por isso, hoje o HTTPS é o padrão mínimo, inclusive para conteúdo público.</p>'+
'<h3>HSTS e a primeira requisição</h3>'+
'<ul><li>Sem HSTS, a primeira requisição pode sair em <b>HTTP</b> e o redirecionamento 301 também: um intermediário pode alterá-lo ou impedir o upgrade (<i>SSL stripping</i>).</li>'+
'<li>O cabeçalho <code>Strict-Transport-Security: max-age=31536000; includeSubDomains; preload</code> (RFC 6797) faz o navegador usar só HTTPS, trocando http por https internamente.</li>'+
'<li>A <b>lista de preload</b> protege até a primeira visita, mas exige HTTPS em todo o domínio e é difícil de desfazer.</li></ul>'+
'<h3>Boas práticas de hardening</h3>'+
'<ul><li>Habilitar TLS 1.3 e 1.2; desativar TLS 1.0, 1.1 e SSL.</li>'+
'<li>Só suítes com sigilo futuro e AEAD; sem CBC, 3DES e RC4.</li>'+
'<li>Certificado ECDSA (ou RSA 2048 no mínimo), cadeia completa e renovação automática.</li>'+
'<li>OCSP stapling, HSTS com preload e redirecionamento 301.</li>'+
'<li>0-RTT só quando o servidor tem proteção contra replay.</li>'+
'<li>Testar com SSL Labs ou testssl.sh e acompanhar os logs de Certificate Transparency do próprio domínio.</li></ul>'+
'<h3>O que este simulador simplifica</h3>'+
'<p>Não há criptografia real: chaves, assinaturas e hashes são valores ilustrativos. Não são simulados o HelloRetryRequest, o pós-handshake (KeyUpdate), a compressão, o DTLS, o QUIC, o ECH, o certificate pinning e o Must-Staple. Os tamanhos de registro são aproximados.</p>'+
'<h3>Segurança</h3>'+
'<ul><li>O TLS protege o <b>canal</b>: não protege contra um servidor malicioso nem contra vulnerabilidades da aplicação.</li>'+
'<li>Aceitar exceções de certificado por hábito remove a proteção contra interceptação.</li>'+
'<li>Proxies de inspeção TLS corporativos reencerram a conexão com uma CA privada: a confiança passa a ser neles.</li>'+
'<li>Para praticar a defesa de serviços sobre TCP, use o <a href="tcp-udp-security-simulator.html">Simulador de Ataques e Defesas TCP/UDP</a>. Para o acesso remoto seguro, veja o SSH neste simulador.</li></ul>'+
'<h3>Roteiro de exercícios</h3>'+
'<ol><li><b>TLS 1.3 completo:</b> a partir de qual mensagem as setas ficam cifradas? O que continua visível a quem observa a rede (SNI, tamanhos, tempos)?</li>'+
'<li><b>TLS 1.2 completo:</b> compare o número de RTTs e a visibilidade do certificado com o TLS 1.3.</li>'+
'<li><b>Retomada</b> e <b>0-RTT:</b> o que cada uma economiza? Qual o risco do 0-RTT e quando é aceitável?</li>'+
'<li><b>TLS legado sem sigilo futuro:</b> explique por que a troca RSA permite decifrar o tráfego gravado se a chave vazar no futuro.</li>'+
'<li><b>Downgrade detectado:</b> como o sentinela permite ao cliente perceber o ataque?</li>'+
'<li><b>Validação:</b> para cada defeito (expirado, nome, autoassinado, cadeia, revogado), qual teste falha e que alerta o navegador envia?</li>'+
'<li><b>Sem stapling:</b> o que muda na latência e na privacidade?</li>'+
'<li><b>HSTS:</b> compare o primeiro acesso, o acesso com HSTS em cache e o preload. Em qual deles há uma requisição em claro?</li>'+
'<li><b>Comparação HTTP x HTTPS:</b> para cada ação (login, busca, página com cookie), liste o que o observador lê em HTTP e o que ainda consegue ver em HTTPS. Que informação sobra mesmo com HTTPS?</li>'+
'<li><b>Conteúdo alterado no caminho:</b> o que acontece com a página em HTTP e em HTTPS? Que mecanismo do TLS detecta a alteração?</li></ol>';

SS.register({
  id:'https',label:'HTTPS',stateTitle:'Estado da conexão HTTPS',
  rfcs:[[8446,'TLS 1.3'],[5246,'TLS 1.2'],[5280,'X.509'],[6797,'HSTS']],
  subs:[{key:'handshake',label:'Handshake TLS',default:'h13'},{key:'cert',label:'Certificados',default:'c-ok'},{key:'web',label:'HTTP, HTTPS e HSTS',default:'w-none'},{key:'cmp',label:'Comparação HTTP x HTTPS',default:'k-login'}],
  controls:controls,scenarios:T.SCENARIOS,groupDoc:T.GROUP_DOC,scenDoc:T.SCEN_DOC,tabs:T.TABS,
  stageTitle:sub=>({handshake:'Diagrama de sequência: handshake TLS (do TCP aos dados HTTP)',cert:'Diagrama de sequência: validação do certificado do servidor',web:'Diagrama de sequência: do HTTP ao HTTPS (HSTS)',cmp:'Diagrama de sequência: a mesma ação em HTTP (A) e em HTTPS (B), com um observador na rede'})[sub],
  build:(P,sub)=>sub==='web'?T.simWeb(P):(sub==='cmp'?T.simCompare(P):T.simHandshake(P,sub)),
  explain:explain,reference:REFERENCE,setup:setup
});
})();
