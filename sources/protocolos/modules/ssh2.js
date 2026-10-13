(function(){
'use strict';
const SS=window.SecureSim, X=window.__SSH, C0=SS.COLORS, hex=SS.hex, b64=SS.b64;
const {PROF,isAead,pick,KEYTYPE,KEYBITS,fpOf,plainFields,encFields,lst,list,weakIn}=X;
const STATES=[{key:'phase',label:'Fase'},{key:'crypto',label:'Cifragem'},{key:'host',label:'Servidor autenticado'},{key:'user',label:'Usuário autenticado'},{key:'tries',label:'Falhas de login'}];

// ---------- Sessão SSH completa ----------
function simSession(P){
  const C=PROF[P.cProf], S=PROF[P.sProf];
  const tr=SS.newTrace([{key:'c',label:'Cliente SSH',sub:'192.168.1.20',addr:'192.168.1.20'},{key:'s',label:'Servidor SSH',sub:'203.0.113.22:22',addr:'203.0.113.22'}],STATES,P.rtt);
  const ow=tr.ow, who=f=>f==='c'?'Client':'Server';
  const raw=tr.raw={sub:'session',neg:null,fail:null,hk:{state:P.known,action:'',insecure:false,recv:'',reg:'',type:''},auth:{method:P.cMethod,tries:0,ok:false,via:'',denied:'',serverDisconnect:false,methods:[],partial:false},use:P.use,agent:P.fwdAgent,keys:null,enc:0};
  let curPhase='TCP';
  const phase=(label,key,short)=>{ curPhase=short; tr.phase(label,key); };
  const plain=(from,to,num,name,o)=>tr.add(from,to,Object.assign({label:name,type:num,color:C0.plain,proto:'SSHv2',len:60,info:who(from)+': '+name,phaseName:curPhase},o,{fields:(o&&o.f)?plainFields(num,name,o.f):plainFields(num,name,[])}));
  const encm=(from,to,num,name,o)=>{ o=o||{}; const len=o.len||(60+(o.n||0)); raw.enc++;
    return tr.add(from,to,Object.assign({label:name,type:num,color:o.bad?C0.bad:(o.data?C0.data:C0.enc),enc:true,proto:'SSHv2',len:len,info:who(from)+': Encrypted packet (len='+(len-20)+')',phaseName:curPhase},o,{fields:encFields(len,num,name,o.f||[])})); };
  const tcp=(from,to,label,flags,o)=>tr.add(from,to,Object.assign({label:label,proto:'TCP',color:C0.tcp,len:40,info:(from==='c'?'50122 → 22':'22 → 50122')+' ['+flags+']',phaseName:'TCP',
    fields:[{sec:'TCP (RFC 9293)'},['Flags',flags,'abertura e encerramento da conexão sobre a qual o SSH trafega']],about:'Segmento TCP. O SSH roda sobre uma conexão TCP comum, normalmente na porta 22.'},o));
  const closeTcp=by=>{ const o=by==='c'?'s':'c'; tcp(by,o,'FIN, ACK','FIN, ACK',{}); tcp(o,by,'FIN, ACK','FIN, ACK',{}); tcp(by,o,'ACK','ACK',{}); };
  const end=(phaseLabel,cls)=>{ tr.st(tr.t,'phase',phaseLabel,cls||'closed'); };

  // 0. TCP
  phase('0. Conexão TCP (porta 22)','tcp','TCP');
  tr.st(tr.t,'phase','TCP','warn'); tr.st(tr.t,'crypto','em claro','closed'); tr.st(tr.t,'host','não verificado','closed'); tr.st(tr.t,'user','não autenticado','closed'); tr.st(tr.t,'tries','0','closed');
  tr.mile(tr.t,'TCP','handshake');
  tcp('c','s','SYN','SYN',{}); tcp('s','c','SYN, ACK','SYN, ACK',{}); tcp('c','s','ACK','ACK',{});

  // 1. Versões
  phase('1. Troca de versões (em claro)','ver','Versões');
  tr.st(tr.t,'phase','Versões','warn'); tr.mile(tr.t,'Versões','banner');
  const a=plain('c','s','-','Banner do cliente',{par:true,label:C.banner.slice(0,26)+'…',info:'Client: Protocol ('+C.banner+')',len:C.banner.length+2,f:[['Linha de versão',C.banner,'protocolo 2.0, software e comentário'],['Protocolo','SSH-2.0','a versão 2 substituiu a 1, insegura']],
    about:'O cliente anuncia a versão do protocolo e do software. Vai em texto puro, terminada em CRLF. Revela a versão do software, o que ajuda inventário e também ataques.'});
  const b=plain('s','c','-','Banner do servidor',{par:true,at:a.tSend,label:S.banner.slice(0,26)+'…',info:'Server: Protocol ('+S.banner+')',len:S.banner.length+2,f:[['Linha de versão',S.banner,'protocolo 2.0, software e comentário'],['Protocolo','SSH-2.0','']],
    about:'O servidor responde com a própria linha de versão. Esconder ou reduzir o banner dificulta o inventário passivo, mas não substitui a atualização do software.'});
  tr.t=Math.max(a.tArr,b.tArr)+0.4;
  tr.lg(a.tSend,'Cliente e servidor trocam as linhas de versão ('+C.banner+' e '+S.banner+'), ainda em texto puro.','conn');

  // 2. Negociação
  phase('2. Negociação de algoritmos (KEXINIT, em claro)','neg','Negociação');
  tr.st(tr.t,'phase','Negociação','warn'); tr.mile(tr.t,'Algoritmos','KEXINIT');
  const kc=plain('c','s',20,'KEXINIT',{par:true,len:420,info:'Client: Key Exchange Init',f:[['cookie',hex('ck',16),'16 bytes aleatórios, entram no hash da troca de chaves'],
    lst('kex_algorithms',C.kex),lst('server_host_key_algorithms',C.hostkey),lst('encryption_algorithms_client_to_server',C.enc),lst('encryption_algorithms_server_to_client',C.enc),lst('mac_algorithms_client_to_server',C.mac),lst('mac_algorithms_server_to_client',C.mac),['compression_algorithms','none,zlib@openssh.com','compressão desligada por padrão'],['first_kex_packet_follows','falso','']],
    about:'Cada lado lista, em ordem de preferência, os algoritmos que aceita para troca de chaves, chave de host, cifra, MAC e compressão. Vale o primeiro da lista do cliente que o servidor também suporta.'});
  const ks=plain('s','c',20,'KEXINIT',{par:true,at:kc.tSend,len:480,info:'Server: Key Exchange Init',f:[['cookie',hex('sk',16),'16 bytes aleatórios do servidor'],
    lst('kex_algorithms',S.kex,'o que o servidor aceita'),lst('server_host_key_algorithms',S.hostkey,'tipos de chave de host que o servidor possui'),lst('encryption_algorithms_client_to_server',S.enc,'o que o servidor aceita'),lst('encryption_algorithms_server_to_client',S.enc,'o que o servidor aceita'),lst('mac_algorithms_client_to_server',S.mac,'o que o servidor aceita'),lst('mac_algorithms_server_to_client',S.mac,'o que o servidor aceita'),['compression_algorithms','none,zlib@openssh.com','']],
    about:'A lista do servidor. Se não houver nenhum algoritmo em comum em alguma categoria, a conexão é encerrada.'});
  [kc,ks].forEach(m=>{ const w=m===kc?weakIn(C.kex.concat(C.hostkey,C.enc,C.mac)):weakIn(S.kex.concat(S.hostkey,S.enc,S.mac)); if(w.length) m.tags.push('algoritmos fracos oferecidos: '+Array.from(new Set(w)).join(', ')); });
  tr.t=Math.max(kc.tArr,ks.tArr)+0.4;
  const neg={kex:pick(C.kex,S.kex),hostkey:pick(C.hostkey,S.hostkey),enc:pick(C.enc,S.enc),mac:pick(C.mac,S.mac)};
  raw.neg=neg;
  const miss=['kex','hostkey','enc','mac'].find(k=>!neg[k]);
  if(miss){
    const nm={kex:'key exchange method',hostkey:'host key type',enc:'cipher',mac:'MAC'}[miss], their=({kex:S.kex,hostkey:S.hostkey,enc:S.enc,mac:S.mac})[miss];
    raw.fail={stage:'neg',what:miss,msg:'no matching '+nm+' found. Their offer: '+list(their)};
    tr.ev(tr.t,'c','Unable to negotiate: no matching '+nm+' found. Their offer: '+list(their).slice(0,60)+'…','warn');
    tr.ev(tr.t,'s','Nenhum algoritmo em comum: a negociação falha','warn');
    tr.lg(tr.t,'Sem '+nm+' em comum. Cliente oferece '+list(({kex:C.kex,hostkey:C.hostkey,enc:C.enc,mac:C.mac})[miss])+'; servidor oferece '+list(their)+'.','loss');
    tr.st(tr.t,'phase','Falhou','bad');
    plain('c','s',1,'DISCONNECT (3) KEY_EXCHANGE_FAILED',{color:C0.bad,len:80,info:'Client: Disconnect Message (key exchange failed)',f:[['reason code','3 (SSH_DISCONNECT_KEY_EXCHANGE_FAILED)',''],['description','no matching '+nm,'']],about:'Sem algoritmo em comum, a conexão é encerrada com o código 3. Nada foi cifrado ainda, e nenhuma credencial foi enviada.'});
    closeTcp('c'); tr.mile(tr.t,'Falhou','sem algoritmo comum'); tr.st(tr.t,'phase','Encerrada','bad');
    return tr;
  }
  tr.ev(tr.t,'c','Negociado: '+neg.kex+', '+neg.hostkey+', '+neg.enc+(isAead(neg.enc)?'':', '+neg.mac),'ok');
  tr.ev(tr.t,'s','Mesma escolha: o primeiro da lista do cliente que o servidor tem','ok');
  tr.lg(tr.t,'Algoritmos negociados: troca de chaves '+neg.kex+'; chave de host '+neg.hostkey+'; cifra '+neg.enc+'; MAC '+(isAead(neg.enc)?'implícito (AEAD)':neg.mac)+'.','cc');
  const weakChosen=[neg.kex,neg.hostkey,neg.enc,neg.mac].filter(x=>X.isWeak(x)&&!(isAead(neg.enc)&&x===neg.mac));
  raw.weakChosen=weakChosen;
  if(weakChosen.length){ tr.ev(tr.t,'c','Atenção: algoritmo fraco escolhido: '+weakChosen.join(', '),'warn'); tr.lg(tr.t,'Algoritmo fraco negociado: '+weakChosen.join(', ')+'. A conexão funciona, mas a proteção é menor.','loss'); }

  // 3. Troca de chaves
  phase('3. Troca de chaves e verificação do servidor','kex','Troca de chaves');
  tr.st(tr.t,'phase','Troca de chaves','warn'); tr.mile(tr.t,'Chaves','Diffie-Hellman');
  const ecdh=/^(curve25519|ecdh)/.test(neg.kex), kt=KEYTYPE(neg.hostkey);
  const fpReal=fpOf(P,neg.hostkey,'real'), fpOther=fpOf(P,neg.hostkey,'imp'), fpRecv=P.known==='changed'?fpOther:fpReal;
  raw.hk.recv=fpRecv; raw.hk.reg=P.known==='new'?'':fpReal; raw.hk.type=kt;
  const qc=hex('qc'+P.sProf+neg.kex,32), qs=hex('qs'+P.sProf+neg.kex,32);
  const ki=plain('c','s',30,ecdh?'KEX_ECDH_INIT':'KEXDH_INIT',{len:84,info:'Client: '+(ecdh?'Elliptic Curve Diffie-Hellman Key Exchange Init':'Diffie-Hellman Key Exchange Init'),
    f:[['método',neg.kex,'algoritmo de troca de chaves negociado'],[ecdh?'Q_C (chave pública efêmera)':'e (valor DH público)',qc.slice(0,32)+'…','gerado para esta conexão e descartado depois: dá sigilo futuro (forward secrecy)']],
    about:'O cliente envia a metade pública de um segredo Diffie-Hellman gerado só para esta conexão. O segredo compartilhado K nunca viaja pela rede.'});
  const kr=plain('s','c',31,ecdh?'KEX_ECDH_REPLY':'KEXDH_REPLY',{len:340,info:'Server: '+(ecdh?'Elliptic Curve Diffie-Hellman Key Exchange Reply':'Diffie-Hellman Key Exchange Reply'),
    f:[['K_S (chave pública de host)',kt+' '+fpRecv,'a identidade do servidor'],[ecdh?'Q_S (chave pública efêmera)':'f (valor DH público)',qs.slice(0,32)+'…','metade pública do servidor'],['assinatura de H',neg.hostkey+' ('+hex('sg',16)+'…)','assina o hash H da troca com a chave privada de host: prova que este é o dono da chave'],['fingerprint',fpRecv,'o que o cliente compara com o known_hosts']],
    about:'O servidor devolve a sua chave pública de host, a metade pública do DH e a assinatura do hash H. Quem assina H com a chave de host prova ser o dono dela, e a assinatura amarra a troca à identidade: um intermediário não consegue forjá-la sem a chave privada.'});
  const K=hex('K|'+P.sProf+neg.kex,32), H=hex('H|'+P.sProf+neg.kex+fpRecv,32);
  tr.ev(kr.tArr,'c','Calcula K e H e verifica a assinatura de H com a chave de host','');
  tr.ev(ki.tArr,'s','Calcula K e H com o segredo DH','');
  tr.lg(kr.tArr,'Troca de chaves '+neg.kex+' concluída: ambos obtêm o mesmo segredo K sem enviá-lo. O servidor assinou H com a chave de host ('+kt+').','cc');
  // verificação da chave do servidor
  let abort=null;
  if(P.known==='known'){ tr.ev(tr.t,'c','Chave do servidor conhecida: o fingerprint confere com o known_hosts','ok'); raw.hk.action='confere'; }
  else if(P.known==='new'){
    if(P.hkCheck==='yes'){ abort='strict'; }
    else if(P.hkCheck==='ask'){ tr.ev(tr.t,'c','The authenticity of host can\'t be established. '+kt+' key fingerprint is '+fpRecv.slice(0,22)+'… Continue connecting (yes/no)?','warn'); tr.wait(1500); tr.ev(tr.t,'c','Usuário digita "yes": a chave é gravada em known_hosts (confiança no primeiro uso)',''); raw.hk.action='aceita após pergunta'; tr.lg(tr.t,'Primeira conexão: o usuário confirmou o fingerprint e a chave foi gravada em known_hosts (TOFU).','conn'); }
    else if(P.hkCheck==='accept-new'){ tr.ev(tr.t,'c','accept-new: a chave nova é gravada sem perguntar','warn'); raw.hk.action='gravada sem perguntar'; tr.lg(tr.t,'StrictHostKeyChecking=accept-new: chave nova gravada sem confirmação do usuário.','conn'); }
    else { tr.ev(tr.t,'c','StrictHostKeyChecking=no: aceita sem verificar','warn'); raw.hk.action='aceita sem verificar'; raw.hk.insecure=true; tr.lg(tr.t,'StrictHostKeyChecking=no: servidor aceito sem nenhuma verificação. A proteção contra interceptação está desligada.','loss'); }
  } else {
    if(P.hkCheck==='no'){ tr.ev(tr.t,'c','Chave mudou, mas StrictHostKeyChecking=no segue assim mesmo; a senha fica desativada','warn'); raw.hk.action='ignorada (chave mudou)'; raw.hk.insecure=true; tr.lg(tr.t,'A chave do servidor mudou e o cliente seguiu mesmo assim (StrictHostKeyChecking=no). O OpenSSH desativa a senha nesse caso.','loss'); }
    else abort='changed';
  }
  if(abort){
    raw.fail={stage:'hostkey',what:abort};
    tr.ev(tr.t,'c',abort==='changed'?'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! Possível interceptação. Host key verification failed.':'Host key verification failed: servidor ausente do known_hosts (StrictHostKeyChecking=yes)','warn');
    tr.st(tr.t,'host','RECUSADO','bad'); tr.st(tr.t,'phase','Falhou','bad');
    tr.lg(tr.t,abort==='changed'?'A chave apresentada ('+fpRecv.slice(0,24)+'…) difere da registrada ('+fpReal.slice(0,24)+'…). O cliente aborta antes de enviar qualquer credencial.':'O servidor não consta no known_hosts e a política exige que conste. O cliente aborta.','loss');
    closeTcp('c'); tr.mile(tr.t,'Recusado','chave do servidor'); tr.st(tr.t,'phase','Encerrada','bad');
    return tr;
  }
  tr.st(tr.t,'host',P.known==='known'?'verificado':(raw.hk.insecure?'não verificado':'aceito (1º uso)'),raw.hk.insecure?'warn':'est');
  // NEWKEYS
  const ns=plain('s','c',21,'NEWKEYS',{par:true,len:20,info:'Server: New Keys',f:[],about:'Sinaliza que, a partir do próximo pacote, o servidor usa as chaves recém-derivadas.'});
  const nc=plain('c','s',21,'NEWKEYS',{par:true,at:ns.tSend,len:20,info:'Client: New Keys',f:[],about:'O cliente também passa a cifrar. Este é o último pacote em claro.'});
  tr.t=Math.max(ns.tArr,nc.tArr)+0.4;
  const keyLen=KEYBITS(neg.enc);
  raw.keys={kex:neg.kex,K:K,H:H,sid:H,enc:neg.enc,mac:neg.mac,hk:neg.hostkey,fp:fpRecv,tK:kr.tArr,tNew:tr.t,
    derived:[['A','IV cliente → servidor',hex('A'+H,12)],['B','IV servidor → cliente',hex('B'+H,12)],['C','Chave de cifra cliente → servidor',hex('C'+H,keyLen)],['D','Chave de cifra servidor → cliente',hex('D'+H,keyLen)],['E','Chave de integridade cliente → servidor',isAead(neg.enc)?'(não usada: cifra AEAD)':hex('E'+H,32)],['F','Chave de integridade servidor → cliente',isAead(neg.enc)?'(não usada: cifra AEAD)':hex('F'+H,32)]]};
  tr.st(tr.t,'crypto','cifrado: '+neg.enc.replace('@openssh.com',''),'est');
  tr.ev(tr.t,'c','A partir daqui tudo vai cifrado e autenticado: '+neg.enc.replace('@openssh.com',''),'ok');
  tr.ev(tr.t,'s','Chaves derivadas de K, H e do session_id','ok');
  tr.lg(tr.t,'NEWKEYS: seis chaves derivadas de K e H (IVs, cifra e integridade nos dois sentidos). Tudo o que segue é cifrado.','cc');

  // 4. Autenticação
  phase('4. Autenticação do usuário (cifrada)','auth','Autenticação');
  tr.st(tr.t,'phase','Autenticação','warn'); tr.mile(tr.t,'Autenticação',P.cMethod==='publickey'?'chave pública':(P.cMethod==='password'?'senha':'senha + TOTP'));
  const methods=P.sMfa?['publickey']:(P.sPass?['publickey','password','keyboard-interactive']:['publickey']);
  const restricted=raw.hk.insecure&&P.known==='changed';
  raw.auth.methods=methods;
  const A=raw.auth; let tries=0, authed=false, serverDrop=false;
  const setTries=()=>{ tr.st(tr.t,'tries',tries+' de '+P.maxTries,tries?'warn':'closed'); };
  const rootBlocked=m=>P.user==='root'&&(m==='publickey'?P.permitRoot==='no':P.permitRoot!=='yes');
  const sreq=encm('c','s',5,'SERVICE_REQUEST ssh-userauth',{len:76,f:[['service name','ssh-userauth','pede o serviço de autenticação do usuário (RFC 4252)']],about:'Primeira mensagem cifrada. O cliente pede o serviço de autenticação.'});
  encm('s','c',6,'SERVICE_ACCEPT',{len:76,f:[['service name','ssh-userauth','']],about:'O servidor aceita o serviço.'});
  encm('c','s',50,'USERAUTH_REQUEST none',{len:112,f:[['user name',P.user,''],['service','ssh-connection',''],['method','none','consulta quais métodos o servidor aceita']],about:'O método "none" é só uma consulta: pergunta quais métodos de autenticação estão disponíveis para este usuário.'});
  encm('s','c',51,'USERAUTH_FAILURE',{bad:true,len:100,f:[['authentications that can continue',methods.join(','),'métodos que o servidor aceita'],['partial success','falso','']],about:'O "failure" aqui é esperado: devolve a lista de métodos aceitos.'});
  tr.ev(tr.t,'s','Métodos oferecidos: '+methods.join(', '),'');
  const fail=(why,logLine)=>{ tries++; A.tries=tries; setTries(); if(logLine) tr.lg(tr.t,logLine,'loss'); };
  const sendFail=(partial,txt,m)=>encm('s','c',51,'USERAUTH_FAILURE',{bad:true,len:100,f:[['authentications that can continue',(partial?'keyboard-interactive':methods.join(',')),''],['partial success',partial?'verdadeiro':'falso',partial?'a 1ª etapa foi aceita, falta a 2ª':'']],about:txt||'A tentativa foi recusada.'});
  const success=(m)=>{ authed=true; A.ok=true; A.via=m; encm('s','c',52,'USERAUTH_SUCCESS',{len:60,f:[],about:'Autenticação concluída: o usuário passa a ter acesso ao serviço ssh-connection.'}); tr.st(tr.t,'user',P.user+' ('+m+')','est'); tr.ev(tr.t,'s','Login aceito para '+P.user,'ok'); tr.lg(tr.t,'Usuário '+P.user+' autenticado por '+m+'.','conn'); };
  const disconnectMax=()=>{ serverDrop=true; A.serverDisconnect=true; encm('s','c',1,'DISCONNECT (2) Too many authentication failures',{bad:true,len:100,f:[['reason code','2 (PROTOCOL_ERROR)',''],['description','Too many authentication failures','']],about:'Ao atingir MaxAuthTries, o servidor derruba a conexão. Limita a velocidade de tentativas por conexão.'}); tr.ev(tr.t,'c','Disconnecting: Too many authentication failures','warn'); tr.st(tr.t,'phase','Encerrada','bad'); tr.lg(tr.t,'MaxAuthTries ('+P.maxTries+') atingido: o servidor encerra a conexão.','loss'); };
  const totp=()=>{
    encm('s','c',60,'USERAUTH_INFO_REQUEST "Verification code:"',{len:96,f:[['name',"",''],['prompt','Verification code: (echo off)','pede o código TOTP de 6 dígitos']],about:'No keyboard-interactive, o servidor envia os prompts que quiser (senha, código TOTP...).'});
    tr.wait(1200); tr.ev(tr.t,'c','Usuário digita o código do aplicativo autenticador','');
    encm('c','s',61,'USERAUTH_INFO_RESPONSE',{len:84,f:[['responses','1 resposta: ******','o código TOTP, válido por cerca de 30 s']],about:'O cliente devolve a resposta ao prompt. O código muda a cada 30 s.'});
    return P.credOk;
  };
  if(P.cMethod==='publickey'){
    const probe=encm('c','s',50,'USERAUTH_REQUEST publickey (consulta)',{len:180,f:[['method','publickey',''],['has signature','falso','primeiro só pergunta se a chave serve'],['public key algorithm','ssh-ed25519',''],['public key blob',hex('uk',16)+'…','chave pública do usuário']],about:'O cliente oferece a chave pública sem assinar. Evita fazer o usuário assinar à toa se a chave não consta em authorized_keys.'});
    if(P.credOk){
      encm('s','c',60,'USERAUTH_PK_OK',{len:150,f:[['public key algorithm','ssh-ed25519','']],about:'A chave consta em ~/.ssh/authorized_keys do usuário. Falta provar que o cliente tem a chave privada.'});
      encm('c','s',50,'USERAUTH_REQUEST publickey (assinado)',{len:260,f:[['has signature','verdadeiro',''],['signature','assinatura sobre session_id + dados do pedido','amarra a prova à sessão atual: não pode ser reaproveitada em outra']],about:'O cliente assina o session_id e os dados do pedido com a chave privada. A chave privada nunca sai da máquina e nenhum segredo reutilizável viaja.'});
      if(rootBlocked('publickey')){ sendFail(false,'O servidor recusa o login do root (PermitRootLogin no).'); fail('root','sshd registra: ROOT LOGIN REFUSED'); A.denied='root'; tr.ev(tr.t,'s','PermitRootLogin '+P.permitRoot+': root recusado','warn'); }
      else if(P.sMfa){ A.partial=true; sendFail(true,'A chave foi aceita, mas o servidor exige um segundo método: sucesso parcial.'); tr.ev(tr.t,'s','Sucesso parcial: falta o 2º fator','ok'); tr.lg(tr.t,'Chave aceita (sucesso parcial). O servidor exige keyboard-interactive como segundo método.','conn');
        encm('c','s',50,'USERAUTH_REQUEST keyboard-interactive',{len:140,f:[['method','keyboard-interactive','2º método exigido por AuthenticationMethods']],about:'O cliente passa ao segundo método.'});
        if(totp()) success('chave + TOTP'); else { sendFail(false,'Código incorreto.'); fail('totp','Falha no 2º fator (código TOTP incorreto).'); A.denied='totp'; }
      } else success('chave pública');
    } else { sendFail(false,'A chave não está em authorized_keys.'); fail('key','Falha de chave pública: a chave não consta em authorized_keys.'); A.denied='key'; tr.ev(tr.t,'c','Permission denied (publickey).','warn'); }
  } else if(P.cMethod==='password'){
    if(methods.indexOf('password')<0||restricted){
      A.denied=restricted?'restricted':'nopass';
      tr.ev(tr.t,'c','Permission denied (publickey). '+(restricted?'Senha desativada pelo cliente porque a chave do servidor mudou.':'O servidor não oferece autenticação por senha.'),'warn');
      tr.lg(tr.t,restricted?'Senha desativada: a chave do servidor mudou.':'O servidor não oferece senha (PasswordAuthentication no): o cliente não tem como seguir.','loss');
    } else {
      for(let k=0;k<3&&!authed&&!serverDrop;k++){
        tr.wait(1200); tr.ev(tr.t,'c',k?'Usuário digita a senha de novo':'Usuário digita a senha','');
        encm('c','s',50,'USERAUTH_REQUEST password',{len:140,f:[['method','password',''],['change password','falso',''],['password','******** (cifrada no canal)','a senha viaja dentro do canal cifrado, mas continua sendo um segredo reutilizável']],about:'A senha vai cifrada, mas o servidor a vê. Se o servidor for falso ou estiver comprometido, a senha é revelada.'});
        const ok=P.credOk&&!rootBlocked('password');
        if(ok){ success('senha'); break; }
        fail('pw','sshd registra: Failed password for '+P.user+' from 192.168.1.20 port 50122 ssh2'); if(rootBlocked('password')&&P.credOk) A.denied='root'; else A.denied='pw';
        if(tries>=P.maxTries){ disconnectMax(); break; }
        sendFail(false,'Senha incorreta ou usuário não autorizado.');
      }
      if(!authed&&!serverDrop) tr.ev(tr.t,'c','Permission denied (publickey,password).','warn');
    }
  } else { // kbd: senha + TOTP
    if(methods.indexOf('keyboard-interactive')<0||restricted){
      A.denied=restricted?'restricted':'nokbd';
      tr.ev(tr.t,'c','Permission denied (publickey). O servidor não aceita keyboard-interactive como 1º método.','warn');
      tr.lg(tr.t,'keyboard-interactive indisponível como 1º método neste servidor.','loss');
    } else {
      encm('c','s',50,'USERAUTH_REQUEST keyboard-interactive',{len:140,f:[['method','keyboard-interactive','o servidor define os prompts']],about:'O cliente pede o método interativo: o servidor envia os prompts (senha e código).'});
      encm('s','c',60,'USERAUTH_INFO_REQUEST "Password:"',{len:96,f:[['prompt','Password: (echo off)','']],about:'Primeiro prompt: a senha.'});
      tr.wait(1200); tr.ev(tr.t,'c','Usuário digita a senha','');
      encm('c','s',61,'USERAUTH_INFO_RESPONSE',{len:84,f:[['responses','1 resposta: ********','']],about:'A senha vai cifrada no canal.'});
      const ok2=totp();
      if(ok2&&!rootBlocked('kbd')) success('senha + TOTP');
      else { fail('kbd','sshd registra: Failed keyboard-interactive/pam for '+P.user+' from 192.168.1.20 port 50122 ssh2'); A.denied=rootBlocked('kbd')&&ok2?'root':'kbd'; if(tries>=P.maxTries) disconnectMax(); else sendFail(false,'Credencial ou código incorreto.'); }
    }
  }
  raw.authed=authed;
  if(!authed){
    if(!serverDrop){ encm('c','s',1,'DISCONNECT (11) By application',{len:84,f:[['reason code','11 (SSH_DISCONNECT_BY_APPLICATION)','']],about:'Sem mais métodos para tentar, o cliente encerra a conexão.'}); tr.st(tr.t,'phase','Encerrada','bad'); }
    closeTcp(serverDrop?'s':'c'); tr.mile(tr.t,'Acesso negado',A.denied||''); return tr;
  }

  // 5. Canal
  phase('5. Canal de sessão (cifrado)','chan','Canal');
  tr.st(tr.t,'phase','Sessão','est'); tr.mile(tr.t,'Sessão',P.use==='shell'?'shell':(P.use==='exec'?'comando':'SFTP'));
  const chOpen=encm('c','s',90,'CHANNEL_OPEN session',{len:100,f:[['channel type','session',''],['sender channel','0',''],['initial window size','2097152 (2 MiB)','controle de fluxo por canal: quantos bytes podem ser enviados antes de esperar WINDOW_ADJUST'],['maximum packet size','32768','']],about:'O cliente abre um canal lógico dentro da conexão SSH. Vários canais (sessões, túneis) compartilham a mesma conexão cifrada.'});
  encm('s','c',91,'CHANNEL_OPEN_CONFIRMATION',{len:100,f:[['recipient channel','0',''],['sender channel','0',''],['initial window size','2097152','']],about:'O servidor confirma o canal.'});
  if(P.fwdAgent){
    encm('c','s',98,'CHANNEL_REQUEST auth-agent-req',{len:90,f:[['request type','auth-agent-req@openssh.com','pede encaminhamento do agente SSH']],about:'Com ForwardAgent, o servidor recebe um socket que fala com o seu agente local. Útil, mas quem controlar o servidor (root) pode usar suas chaves enquanto a sessão durar.'});
    encm('s','c',99,'CHANNEL_SUCCESS',{len:60,f:[]});
    tr.ev(tr.t,'s','Agente encaminhado: um socket no servidor dá acesso às suas chaves','warn'); tr.lg(tr.t,'ForwardAgent ativo: o servidor pode pedir assinaturas ao seu agente enquanto durar a sessão.','loss');
  }
  const D=(f,t,txt,n,extra)=>encm(f,t,94,'CHANNEL_DATA '+txt,Object.assign({data:true,len:60+(n||0),f:[['data',txt,'dados do canal (aqui o conteúdo é só ilustrativo)']],about:'Dados da aplicação dentro do canal, também cifrados. O Wireshark só vê pacotes cifrados.'},extra||{}));
  if(P.use==='shell'){
    encm('c','s',98,'CHANNEL_REQUEST pty-req',{len:130,f:[['request type','pty-req','pede um pseudoterminal'],['term','xterm-256color','']],about:'Pede um pseudoterminal para o shell interativo.'});
    encm('s','c',99,'CHANNEL_SUCCESS',{len:60,f:[]});
    encm('c','s',98,'CHANNEL_REQUEST shell',{len:80,f:[['request type','shell','inicia o shell do usuário']],about:'Inicia o shell de login.'});
    encm('s','c',99,'CHANNEL_SUCCESS',{len:60,f:[]});
    D('s','c','"Welcome… '+P.user+'@srv:~$ "',60); tr.wait(800); D('c','s','"ls -l"',10); D('s','c','"total 8 ... relatorio.pdf"',90); D('c','s','"exit"',8);
    encm('s','c',98,'CHANNEL_REQUEST exit-status',{len:80,f:[['request type','exit-status',''],['exit status','0','']]});
  } else if(P.use==='exec'){
    encm('c','s',98,'CHANNEL_REQUEST exec',{len:120,f:[['request type','exec',''],['command','uname -a','comando executado no servidor, sem shell interativo']],about:'Executa um único comando. É o modo usado por scripts, rsync e git sobre SSH.'});
    encm('s','c',99,'CHANNEL_SUCCESS',{len:60,f:[]});
    D('s','c','"Linux srv 6.5.0 x86_64"',60);
    encm('s','c',98,'CHANNEL_REQUEST exit-status',{len:80,f:[['request type','exit-status',''],['exit status','0','']]});
  } else {
    encm('c','s',98,'CHANNEL_REQUEST subsystem sftp',{len:100,f:[['request type','subsystem',''],['subsystem name','sftp','transferência de arquivos sobre o canal SSH']],about:'O SFTP é um subsistema do SSH, não o FTP sobre SSL. Usa o mesmo canal cifrado e autenticado.'});
    encm('s','c',99,'CHANNEL_SUCCESS',{len:60,f:[]});
    D('c','s','SFTP INIT (v3)',10); D('s','c','SFTP VERSION (v3)',10); D('c','s','SFTP OPEN relatorio.pdf',30); D('s','c','SFTP HANDLE',12);
    D('c','s','SFTP READ 0..32768',16); D('s','c','SFTP DATA 32 kB',32768,{len:32800});
    D('c','s','SFTP READ 32768..65536',16); D('s','c','SFTP DATA 32 kB',32768,{len:32800});
    encm('c','s',93,'CHANNEL_WINDOW_ADJUST',{len:70,f:[['bytes to add','2097152','repõe a janela do canal para o servidor continuar enviando']],about:'Controle de fluxo do canal: o receptor libera mais espaço na janela.'});
    D('c','s','SFTP CLOSE',8); D('s','c','SFTP STATUS OK',12);
  }
  // 6. Encerramento
  phase('6. Encerramento','end','Encerramento');
  tr.st(tr.t,'phase','Encerrando','warn');
  encm('s','c',96,'CHANNEL_EOF',{len:60,f:[]}); encm('s','c',97,'CHANNEL_CLOSE',{len:60,f:[]}); encm('c','s',97,'CHANNEL_CLOSE',{len:60,f:[]});
  encm('c','s',1,'DISCONNECT (11) By application',{len:84,f:[['reason code','11 (SSH_DISCONNECT_BY_APPLICATION)','']],about:'Encerramento normal pelo cliente.'});
  closeTcp('c'); tr.st(tr.t,'phase','Encerrada','closed'); tr.mile(tr.t,'Encerrada','TCP fechado');
  return tr;
}
window.__SSH.simSession=simSession; window.__SSH.STATES=STATES;
})();
