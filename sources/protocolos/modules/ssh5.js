(function(){
'use strict';
const SS=window.SecureSim, X=window.__SSH, esc=SS.esc, fmtMs=SS.fmtMs, plural=SS.plural;
const {PROF,isAead,list,controls,grade}=X;
const f1=v=>(Math.round(v*10)/10).toString().replace('.',',');
const yn=v=>v?'sim':'não';

// ---------- Texto do cenário ----------
function setup(s){
  const P={}; controls.forEach(c=>{ P[c.id]=c.def; }); Object.keys(s.set||{}).forEach(k=>{ P[k]=s.set[k]; });
  const p=[];
  if(s.sub==='tunnel'){
    p.push('Túnel '+({local:'local (-L)',remote:'remoto (-R)',dynamic:'dinâmico (-D)',jump:'ProxyJump (-J)'})[P.tunKind],'RTT de '+P.rtt+' ms','AllowTcpForwarding '+(P.allowFwd?'yes':'no'));
    if(P.tunKind==='remote') p.push('GatewayPorts '+(P.gateway?'yes':'no'));
  } else {
    p.push('cliente '+PROF[P.cProf].nome,'servidor '+PROF[P.sProf].nome,'RTT de '+P.rtt+' ms','known_hosts: '+({known:'conhecida',new:'primeira conexão',changed:'chave diferente'})[P.known],'método: '+({publickey:'chave pública',password:'senha',kbd:'senha + TOTP'})[P.cMethod]+(P.credOk?'':' (credencial errada)'),'usuário '+P.user);
    p.push('PasswordAuthentication '+(P.sPass?'yes':'no'),'MaxAuthTries '+P.maxTries);
    if(P.sMfa) p.push('2º fator exigido'); if(P.fwdAgent) p.push('ForwardAgent');
  }
  return 'Configuração do cenário: <code>'+esc(p.join('; '))+'</code>';
}

// ---------- Experimento ----------
function explainSession(tr,P){
  const r=tr.raw, C=PROF[P.cProf], S=PROF[P.sProf], n=r.neg;
  let h='<h3>Configuração</h3><p>O cliente ('+esc(C.nome)+') conecta a um servidor SSH ('+esc(S.nome)+') com <b>RTT de '+P.rtt+' ms</b>. O known_hosts do cliente indica: <b>'+({known:'chave conhecida (confere)',new:'primeira conexão (a chave não consta)',changed:'chave registrada diferente da apresentada'})[P.known]+'</b>, com StrictHostKeyChecking = '+esc(P.hkCheck)+'. '+
    'O usuário <b>'+esc(P.user)+'</b> tenta entrar por <b>'+({publickey:'chave pública',password:'senha',kbd:'senha + código TOTP'})[P.cMethod]+'</b>'+(P.credOk?'':' (com credencial incorreta)')+'. No servidor: PasswordAuthentication '+(P.sPass?'yes':'no')+', PermitRootLogin '+esc(P.permitRoot)+', MaxAuthTries '+P.maxTries+(P.sMfa?', segundo fator exigido':'')+'.</p>';
  h+='<h3>O que aconteceu</h3>';
  h+='<p><b>Conexão e versões.</b> Depois do handshake TCP (1 RTT), os dois lados trocaram as linhas de versão em texto puro: <code>'+esc(C.banner)+'</code> e <code>'+esc(S.banner)+'</code>. Já aqui o servidor revela o software e a versão a qualquer observador.</p>';
  if(r.fail&&r.fail.stage==='neg'){
    h+='<p><b>Negociação.</b> Cada lado enviou o KEXINIT com suas listas. Para <b>'+({kex:'a troca de chaves',hostkey:'a chave de host',enc:'a cifra',mac:'o MAC'})[r.fail.what]+'</b> não existe nenhum algoritmo em comum, então a negociação falhou ('+esc(r.fail.msg.slice(0,110))+'...). O cliente enviou DISCONNECT 3 e encerrou o TCP. <b>Nada foi cifrado e nenhuma credencial foi enviada.</b> Servidores endurecidos deixam de atender clientes antigos: esse é o custo de recusar algoritmos fracos.</p>';
    return h+concepts(['<b>Banner</b> e <b>KEXINIT</b> em claro','<b>Negociação de algoritmos</b>: vale o primeiro da lista do cliente que o servidor aceita','<b>Falha de negociação</b> (KEY_EXCHANGE_FAILED)'])+next(tr,P);
  }
  h+='<p><b>Negociação.</b> Pela regra do SSH, vale o primeiro algoritmo da lista do cliente que o servidor também tem: troca de chaves <b>'+esc(n.kex)+'</b>, chave de host <b>'+esc(n.hostkey)+'</b>, cifra <b>'+esc(n.enc)+'</b>'+(isAead(n.enc)?' (AEAD, sem MAC separado)':', MAC <b>'+esc(n.mac)+'</b>')+'.'+
    (r.weakChosen&&r.weakChosen.length?' <b>Atenção:</b> foram negociados algoritmos fracos ('+esc(r.weakChosen.join(', '))+'). A conexão funciona, mas a proteção é menor e o cliente não avisa.':' Todos os algoritmos escolhidos são considerados fortes.')+'</p>';
  h+='<p><b>Troca de chaves.</b> O cliente enviou a metade pública de um segredo Diffie-Hellman efêmero e o servidor respondeu com a sua, a chave pública de host ('+esc(r.hk.type)+') e a assinatura do hash H. O segredo K foi calculado nas duas pontas, <b>sem nunca trafegar</b>. Como o par é descartado depois, uma chave comprometida no futuro não decifra esta sessão (<i>forward secrecy</i>).</p>';
  const hk={known:'O fingerprint recebido ('+esc((r.hk.recv||'').slice(0,26))+'…) conferiu com o known_hosts: o servidor é o que o cliente esperava.',
    new:'O servidor era desconhecido. '+({'aceita após pergunta':'O ssh mostrou o fingerprint e o usuário digitou "yes": a chave foi gravada (confiança no primeiro uso, TOFU). Só é seguro se o fingerprint for conferido por outro canal.','gravada sem perguntar':'Com accept-new, a chave foi gravada sem pergunta: protege contra mudanças futuras, mas não contra um intermediário já na primeira conexão.','aceita sem verificar':'Com StrictHostKeyChecking = no, o cliente aceitou sem verificar nada: não há proteção contra interceptação.'})[r.hk.action]||'O cliente exigia que o servidor já constasse no known_hosts (StrictHostKeyChecking = yes) e abortou.',
    changed:'A chave apresentada ('+esc((r.hk.recv||'').slice(0,26))+'…) é <b>diferente</b> da registrada ('+esc((r.hk.reg||'').slice(0,26))+'…).'}[P.known];
  h+='<p><b>Verificação do servidor.</b> '+hk+'</p>';
  if(r.fail&&r.fail.stage==='hostkey'){
    h+='<p>O cliente <b>abortou antes do NEWKEYS e de qualquer credencial</b>. É exatamente a proteção do SSH contra interceptação: um intermediário não tem a chave privada do servidor verdadeiro e não consegue assinar H com ela. A resposta correta é confirmar com o administrador, por outro canal, se a chave mudou de propósito.</p>';
    return h+concepts(['<b>known_hosts</b> e fingerprint da chave de host','<b>Assinatura de H</b>: prova de posse da chave de host','<b>MITM</b> detectado pela chave diferente'])+next(tr,P);
  }
  h+='<p><b>Cifragem.</b> Depois do NEWKEYS, seis chaves foram derivadas de K, H e do session_id (veja a aba Chaves e sessão). Tudo daqui em diante vai <b>cifrado e autenticado</b>: um observador vê só pacotes "Encrypted packet" com tamanho e tempo.</p>';
  const A=r.auth;
  if(A.ok){
    h+='<p><b>Autenticação.</b> O método "none" consultou o que o servidor aceita ('+esc(A.methods.join(', '))+'). O usuário entrou por <b>'+esc(A.via)+'</b>'+(A.partial?', em duas etapas: a chave terminou em sucesso parcial e o servidor pediu o código TOTP':'')+(A.tries?', depois de '+plural(A.tries,'falha','falhas'):'')+'. '+
      ({'chave pública':'A chave privada assinou o session_id: nenhum segredo reutilizável trafegou.','senha':'A senha viajou cifrada, mas o servidor a recebeu em claro.','senha + TOTP':'A senha e o código TOTP foram enviados em respostas cifradas.','chave + TOTP':'Mesmo que a chave seja roubada, sem o código TOTP o acesso não é concedido.'})[A.via]+'</p>';
    const use={shell:'abriu um canal de sessão, pediu um pseudoterminal e um shell, e o usuário digitou comandos',exec:'abriu um canal de sessão e executou um único comando (exec), recebendo a saída e o código de saída',sftp:'abriu um canal de sessão e pediu o subsistema SFTP, trocando pacotes SFTP (INIT, OPEN, READ, DATA) em CHANNEL_DATA'}[P.use];
    h+='<p><b>Canal.</b> O cliente '+use+'. Vários canais podem coexistir na mesma conexão cifrada, cada um com a sua janela de controle de fluxo.'+(P.fwdAgent?' Com <b>ForwardAgent</b>, o servidor ganhou acesso ao agente do cliente durante a sessão: quem tem privilégio nele pode usar suas chaves.':'')+'</p>';
  } else {
    const why={root:'o usuário <b>root</b> foi recusado por PermitRootLogin ('+esc(P.permitRoot)+') mesmo com a credencial correta',key:'a chave não consta em authorized_keys',pw:'a senha estava incorreta',nopass:'o servidor <b>não oferece senha</b> (PasswordAuthentication no), então o cliente nem chegou a tentar',nokbd:'o servidor não aceita keyboard-interactive como primeiro método',kbd:'a senha ou o código TOTP estavam incorretos',totp:'o código TOTP estava incorreto',restricted:'o cliente desativa a senha quando a chave do servidor mudou'}[A.denied]||'as credenciais não foram aceitas';
    h+='<p><b>Autenticação.</b> O acesso foi <b>negado</b>: '+why+'. '+(A.tries?'O servidor contou '+plural(A.tries,'falha','falhas')+' (MaxAuthTries = '+P.maxTries+')':'')+(A.serverDisconnect?' e <b>derrubou a conexão</b> ao atingir o limite ("Too many authentication failures"). Limitar as tentativas por conexão atrasa a adivinhação de senhas, mas o atacante pode reconectar; a defesa de fato é desativar a senha, usar chaves e bloquear origens (fail2ban).':'.')+' Cada falha vai para o auth.log (veja a aba Configuração).</p>';
  }
  const cs=['<b>Banner</b> e <b>KEXINIT</b> em claro','<b>Negociação</b>: o primeiro algoritmo do cliente que o servidor aceita','<b>Diffie-Hellman efêmero</b> e <b>forward secrecy</b>','<b>Chave de host</b>, <b>known_hosts</b> e assinatura de H','<b>NEWKEYS</b> e derivação das chaves (A a F)'];
  if(r.hk.action==='aceita após pergunta') cs.push('<b>TOFU</b>: confiança no primeiro uso');
  cs.push(A.ok?'<b>Autenticação</b> por '+esc(A.via):'<b>Autenticação recusada</b> e contagem de falhas');
  if(A.ok) cs.push('<b>Canais</b> e janela de controle de fluxo');
  if(r.weakChosen&&r.weakChosen.length) cs.push('<b>Algoritmos fracos</b> negociados');
  return h+concepts(cs)+next(tr,P);
}
function explainTunnel(tr,P){
  const r=tr.raw, k=r.kind;
  const nm={local:'o túnel local (-L)',remote:'o túnel remoto (-R)',dynamic:'o proxy dinâmico (-D)',jump:'o ProxyJump (-J)'}[k];
  let h='<h3>Configuração</h3><p>Sessão SSH já autenticada, com <b>RTT de '+P.rtt+' ms</b>. Cenário: <b>'+nm+'</b>, com <b>AllowTcpForwarding '+(P.allowFwd?'yes':'no')+'</b>'+(k==='remote'?' e <b>GatewayPorts '+(P.gateway?'yes':'no')+'</b>':'')+'. O foco aqui é o que acontece depois do login: os canais abertos dentro da conexão cifrada.</p><h3>O que aconteceu</h3>';
  if(r.blocked){
    h+='<p>O cliente pediu '+({local:'um canal direct-tcpip',remote:'o encaminhamento tcpip-forward',dynamic:'um canal direct-tcpip para o destino do SOCKS',jump:'um canal direct-tcpip até o alvo'})[k]+' e o servidor <b>recusou</b> ('+(k==='remote'?'REQUEST_FAILURE':'CHANNEL_OPEN_FAILURE, código 1, administratively prohibited')+') porque <b>AllowTcpForwarding</b> está desativado. A sessão SSH continua de pé; só o encaminhamento é negado. Essa política evita que o servidor sirva de pivô para alcançar a rede interna.</p>';
    return h+concepts(['<b>AllowTcpForwarding</b>','<b>Canais</b> e o código de falha (administratively prohibited)'])+next(tr,P);
  }
  if(k==='local') h+='<p>O cliente escuta na porta 5433 do loopback. Cada conexão da aplicação virou um canal <b>direct-tcpip</b> até <code>db.interno:5432</code>: o servidor abriu uma conexão TCP nova até o banco e repassou os bytes. O trecho <b>cliente ↔ servidor</b> foi cifrado e autenticado pelo SSH. O trecho <b>servidor ↔ banco</b> não faz parte do SSH e segue <b>em claro</b>, a menos que o banco use TLS. Para o banco, a conexão vem do servidor SSH, não do cliente.</p>';
  else if(k==='remote') h+=(r.refused?'<p>O cliente pediu ao servidor que escutasse na porta 9000 (<b>tcpip-forward</b>). Sem <b>GatewayPorts</b>, o sshd abriu a porta só no <b>loopback</b>. Quando o usuário externo tentou conectar, recebeu <b>RST</b>: só quem já está no servidor alcança a porta. É o padrão seguro contra exposição acidental.</p>':'<p>O cliente pediu ao servidor que escutasse na porta 9000 (<b>tcpip-forward</b>). Com <b>GatewayPorts</b> ligado, a porta ficou aberta em 0.0.0.0. Um usuário externo conectou, o servidor abriu um canal <b>forwarded-tcpip</b> de volta ao cliente, e o cliente chegou ao serviço local. O trecho do usuário externo até o servidor está <b>fora do SSH</b> e o serviço local ficou <b>exposto na internet</b>: protegido só pela autenticação e pelo TLS que o próprio serviço tiver.</p>');
  else if(k==='dynamic') h+='<p>O navegador falou SOCKS5 com o cliente SSH e pediu <code>example.org:443</code> pelo <b>nome</b>. Cada destino virou um canal <b>direct-tcpip</b>; o servidor SSH resolveu o DNS e conectou ao site. O HTTPS seguiu de ponta a ponta (TLS entre o navegador e o site): o servidor SSH repassa bytes e <b>vê os destinos</b> (nomes e IPs), mas não o conteúdo cifrado pelo TLS. Quem usa o proxy passa a confiar no servidor SSH quanto a metadados.</p>';
  else h+=(r.refused?'<p>O cliente abriu um canal até o alvo e iniciou uma sessão SSH interna. A chave de host do <b>alvo</b> não conferiu com a registrada, e o cliente <b>abortou</b>: o bastion não consegue encobrir a troca de chave do alvo porque não tem a chave privada dele.</p>':'<p>O cliente pediu ao bastion um canal <b>direct-tcpip</b> até a porta 22 do alvo e, dentro dele, rodou uma <b>segunda sessão SSH completa</b> (banner, KEXINIT, troca de chaves, NEWKEYS, autenticação). A chave de host verificada é a do <b>alvo</b>, e a autenticação ocorre direto nele. Os pacotes internos vão <b>cifrados duas vezes</b>; o bastion só repassa bytes e não consegue lê-los nem alterá-los. É por isso que o ProxyJump é preferível ao ForwardAgent.</p>');
  const cs={local:['<b>direct-tcpip</b> (canal para um destino)','<b>Trechos</b> do túnel: o que é cifrado e o que não é','<b>Origem vista pelo destino</b>: o servidor SSH'],remote:['<b>tcpip-forward</b> e <b>forwarded-tcpip</b>','<b>GatewayPorts</b> e exposição do serviço local','<b>Túnel reverso</b> para alcançar serviços atrás de NAT'],dynamic:['<b>SOCKS5</b> sobre SSH','<b>direct-tcpip</b> por destino','<b>TLS de ponta a ponta</b> dentro do túnel'],jump:['<b>ProxyJump</b> e sessão SSH aninhada','<b>Cifragem em duas camadas</b>','<b>Chave de host do alvo</b> verificada de ponta a ponta']}[k];
  return h+concepts(cs)+next(tr,P);
}
function concepts(a){ return '<h3>Conceitos observados</h3><ul>'+a.map(x=>'<li>'+x+'</li>').join('')+'</ul>'; }
function next(tr,P){
  const s=[], r=tr.raw, g=grade(P);
  if(r.sub==='session'){
    if(P.known==='known') s.push('Mude "Chave do servidor no known_hosts" para <b>Diferente</b> e veja o cliente abortar antes da autenticação.');
    if(P.cProf!=='legado') s.push('Troque o cliente para <b>Legado</b> e o servidor para <b>Endurecido</b>: a negociação falha no KEXINIT.');
    if(P.sPass&&P.cMethod==='publickey') s.push('Desmarque PasswordAuthentication e mude o método para <b>Senha</b>: o servidor não oferece a opção.');
    if(!P.sMfa) s.push('Marque <b>Exigir 2º fator</b> e veja o sucesso parcial depois da chave.');
    if(P.cMethod!=='password'||P.credOk) s.push('Use método <b>Senha</b> com "Credencial correta" desmarcada e MaxAuthTries = 3 (Ajustes avançados): o servidor derruba a conexão na 3ª falha.');
  }
  s.push('Abra a aba <b>Configuração</b>: a nota é '+g.letter+' ('+g.pct+'%). Quais itens faltam para chegar a A?');
  if(r.sub==='tunnel') s.push('Desmarque <b>AllowTcpForwarding</b> e compare a recusa do servidor.','Veja o <b>ProxyJump</b>: a sessão interna é cifrada de ponta a ponta, e o bastion só repassa bytes.');
  return '<h3>Para explorar em seguida</h3><ul>'+s.slice(0,4).map(x=>'<li>'+x+'</li>').join('')+'</ul>';
}
function explain(tr,P,scen){
  const obj=tr.raw.sub==='tunnel'?'Observar como o SSH encaminha portas e protocolos dentro do canal cifrado, e o que continua sem proteção em cada trecho.':'Observar como o SSH estabelece uma sessão segura: negociação, troca de chaves, verificação do servidor, autenticação e canais.';
  return '<p><b>Objetivo.</b> '+obj+'</p>'+(tr.raw.sub==='tunnel'?explainTunnel(tr,P):explainSession(tr,P));
}

// ---------- Referência ----------
const REFERENCE=''+
'<h3>O SSH em três camadas</h3>'+
'<p>O <b>SSH-2</b> (RFC 4251) protege o acesso remoto a sistemas com três camadas sobre uma conexão TCP, normalmente na porta 22. A <b>camada de transporte</b> (RFC 4253) negocia algoritmos, troca chaves, autentica o servidor e cifra os pacotes. A <b>camada de autenticação</b> (RFC 4252) identifica o usuário. A <b>camada de conexão</b> (RFC 4254) multiplexa canais (sessões, SFTP, túneis) sobre a mesma conexão cifrada.</p>'+
'<h3>Fases e o que cada uma protege</h3>'+
'<table><thead><tr><th>Fase</th><th>Mensagens</th><th>Em claro?</th><th>Objetivo</th></tr></thead><tbody>'+
'<tr><td>Versões</td><td>SSH-2.0-software</td><td>sim</td><td>combinar a versão do protocolo</td></tr>'+
'<tr><td>Negociação</td><td>KEXINIT (20)</td><td>sim</td><td>listas de algoritmos; vale o primeiro do cliente que o servidor aceita</td></tr>'+
'<tr><td>Troca de chaves</td><td>KEX_ECDH_INIT (30), REPLY (31), NEWKEYS (21)</td><td>sim</td><td>segredo K efêmero, assinatura de H pela chave de host, chaves da sessão</td></tr>'+
'<tr><td>Autenticação</td><td>SERVICE_REQUEST (5), USERAUTH_* (50 a 61)</td><td>não</td><td>identificar o usuário (chave, senha, 2 fatores)</td></tr>'+
'<tr><td>Canais</td><td>CHANNEL_* (90 a 100)</td><td>não</td><td>shell, comando, SFTP, túneis, com janela de fluxo por canal</td></tr></tbody></table>'+
'<h3>Troca de chaves e sigilo futuro</h3>'+
'<ul><li>Cada lado gera um par <b>efêmero</b> e envia só a parte pública. O segredo <b>K</b> é calculado nas pontas e nunca trafega.</li>'+
'<li>O servidor assina o hash <b>H</b> da troca com a chave de host. Isso prova que ele possui a chave e amarra a troca à identidade: um intermediário não consegue forjar.</li>'+
'<li>Como o par é descartado, o comprometimento futuro da chave de host não decifra sessões antigas (<b>forward secrecy</b>).</li>'+
'<li>As seis chaves da sessão (IVs, cifra e integridade nos dois sentidos) saem de <code>HASH(K || H || letra || session_id)</code> (RFC 4253, seção 7.2).</li></ul>'+
'<h3>Algoritmos recomendados e legados</h3>'+
'<table><thead><tr><th>Categoria</th><th>Preferir</th><th>Evitar</th></tr></thead><tbody>'+
'<tr><td>Troca de chaves</td><td>curve25519-sha256, ecdh-sha2-nistp256, DH group 16</td><td>diffie-hellman-group1-sha1, group14-sha1, group-exchange-sha1</td></tr>'+
'<tr><td>Chave de host</td><td>ssh-ed25519 (RFC 8709), rsa-sha2-256/512</td><td>ssh-dss, ssh-rsa (RSA com SHA-1)</td></tr>'+
'<tr><td>Cifra</td><td>chacha20-poly1305, aes256-gcm, aes-ctr</td><td>3des-cbc, aes-cbc</td></tr>'+
'<tr><td>MAC</td><td>hmac-sha2-512-etm, hmac-sha2-256-etm (ou AEAD)</td><td>hmac-md5, hmac-sha1</td></tr></tbody></table>'+
'<h3>known_hosts e confiança no primeiro uso (TOFU)</h3>'+
'<ul><li>O cliente guarda o <b>fingerprint</b> de cada servidor em ~/.ssh/known_hosts e compara nas conexões seguintes.</li>'+
'<li>Na primeira conexão não há o que comparar: o usuário decide (<b>TOFU</b>). Conferir o fingerprint por outro canal fecha essa janela.</li>'+
'<li>Chave diferente gera <b>WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED</b>. Pode ser reinstalação ou interceptação (MITM).</li>'+
'<li>Alternativas: certificados de host (CA SSH) e registros SSHFP no DNS (com DNSSEC).</li></ul>'+
'<h3>Autenticação do usuário</h3>'+
'<ul><li><b>Chave pública:</b> o cliente assina o session_id com a chave privada. Não trafega segredo reutilizável.</li>'+
'<li><b>Senha:</b> viaja dentro do canal cifrado, mas o servidor a recebe. Vulnerável a adivinhação e a reutilização de credenciais vazadas.</li>'+
'<li><b>keyboard-interactive:</b> o servidor define os prompts; é a base do segundo fator (TOTP, PAM).</li>'+
'<li><b>AuthenticationMethods publickey,keyboard-interactive:</b> exige as duas etapas. A primeira termina em sucesso parcial.</li>'+
'<li><b>MaxAuthTries</b> limita falhas por conexão; <b>fail2ban</b> e firewall limitam por origem.</li></ul>'+
'<h3>Canais, SFTP e túneis</h3>'+
'<ul><li>Cada canal tem número e janela de fluxo (WINDOW_ADJUST). Sessão, SFTP e túneis compartilham a mesma conexão cifrada.</li>'+
'<li><b>SFTP</b> é um subsistema do SSH, não é FTP sobre SSL.</li>'+
'<li><b>-L</b> (direct-tcpip): porta local até um destino alcançado pelo servidor. <b>-R</b> (tcpip-forward e forwarded-tcpip): porta no servidor até o cliente. <b>-D</b>: proxy SOCKS5. <b>-J</b>: salto por bastion com SSH de ponta a ponta.</li>'+
'<li>O trecho entre o servidor SSH e o destino final <b>não é protegido pelo SSH</b>.</li>'+
'<li><b>ForwardAgent</b> expõe o agente a quem tem privilégio no servidor; prefira ProxyJump.</li></ul>'+
'<h3>Boas práticas de hardening</h3>'+
'<ul><li>Desativar a senha e usar chaves (com passphrase) ou, melhor, certificados de usuário.</li>'+
'<li>PermitRootLogin no ou prohibit-password; contas nominais com sudo.</li>'+
'<li>Exigir segundo fator em acessos privilegiados.</li>'+
'<li>Restringir algoritmos a conjuntos modernos e revisar com o ssh-audit.</li>'+
'<li>MaxAuthTries baixo, fail2ban e restrição de origem no firewall.</li>'+
'<li>AllowTcpForwarding no (ou restrito com PermitOpen) nos servidores que não precisam de túneis.</li>'+
'<li>Manter o OpenSSH atualizado e monitorar o auth.log.</li></ul>'+
'<h3>O que este simulador simplifica</h3>'+
'<p>Não há criptografia real: chaves, fingerprints e hashes são valores determinísticos e ilustrativos. O SSH-1, o group-exchange, a compressão, o rekeying, o X11 forwarding e os certificados SSH não são simulados. As sequências seguem o OpenSSH, mas os tamanhos de pacote são aproximados.</p>'+
'<h3>Segurança</h3>'+
'<ul><li>Um canal cifrado não protege contra um servidor <b>malicioso</b> nem contra o uso de algoritmos fracos negociados.</li>'+
'<li>Banners e versões expostos facilitam o inventário por atacantes: mantenha o software atualizado em vez de depender de esconder a versão.</li>'+
'<li>Para praticar a defesa dos serviços que usam TCP, use o <a href="tcp-udp-security-simulator.html">Simulador de Ataques e Defesas TCP/UDP</a>.</li></ul>'+
'<h3>Roteiro de exercícios</h3>'+
'<ol><li><b>Conexão moderna com chave:</b> identifique na aba Captura quais mensagens estão em claro e a partir de qual aparecem só "Encrypted packet". O que o NEWKEYS faz?</li>'+
'<li><b>Primeira conexão (TOFU):</b> o que o usuário precisa conferir antes de digitar "yes"? Por que isso é uma fraqueza?</li>'+
'<li><b>Chave do servidor mudou:</b> por que o cliente aborta antes de enviar credenciais? Como um intermediário falharia?</li>'+
'<li><b>Sem algoritmo em comum</b> e <b>Algoritmos fracos aceitos:</b> compare as notas de hardening e explique o custo de compatibilidade.</li>'+
'<li><b>Muitas tentativas de senha:</b> o que o MaxAuthTries resolve e o que não resolve? Que defesas completam?</li>'+
'<li><b>Chave + TOTP:</b> explique o sucesso parcial e por que o segundo fator protege de uma chave roubada.</li>'+
'<li><b>Túnel local</b> e <b>Túnel remoto:</b> quais trechos estão cifrados? O que o destino enxerga como origem? Qual o risco do GatewayPorts?</li>'+
'<li><b>ProxyJump:</b> por que é melhor que o ForwardAgent? Quem verifica a chave de host do alvo?</li></ol>';

SS.register({
  id:'ssh',label:'SSH',stateTitle:'Estado da sessão SSH',
  rfcs:[[4253,'transporte'],[4252,'autenticação'],[4254,'conexão'],[8709,'Ed25519']],
  subs:[{key:'session',label:'Sessão e autenticação',default:'ok'},{key:'tunnel',label:'Túneis e encaminhamento',default:'t-local'}],
  controls:controls,scenarios:X.SCENARIOS,groupDoc:X.GROUP_DOC,scenDoc:X.SCEN_DOC,tabs:X.TABS,
  stageTitle:sub=>sub==='tunnel'?'Diagrama de sequência: SSH com túnel (canais dentro da conexão cifrada)':'Diagrama de sequência: sessão SSH-2 (do TCP ao encerramento)',
  build:(P,sub)=>sub==='tunnel'?X.simTunnel(P):X.simSession(P),
  explain:explain,reference:REFERENCE,setup:setup
});
})();
