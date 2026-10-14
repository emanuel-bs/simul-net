(function(){
'use strict';
/* ==========================================================================
   MÓDULO FTP, FTPS E SFTP (RFC 959, RFC 2228, RFC 2428, RFC 4217; SSH: RFC 4251 a 4254)
   Três famílias de transferência de arquivos:
     ftp   FTP clássico: canal de controle (porta 21) e um canal de dados por transferência (modos passivo e ativo);
     ftps  FTP sobre TLS: explícito (AUTH TLS) ou implícito (porta 990), com PROT P ou PROT C;
     sftp  SFTP, subsistema do SSH: uma única conexão (porta 22);
     cmp   a mesma ação nos três, com um observador na rede.
   Não há criptografia real: chaves, hashes e conteúdos são valores ilustrativos.
   ========================================================================== */
const SS=window.SecureSim, C0=SS.COLORS, hex=SS.hex, b64=SS.b64, esc=SS.esc, fmtMs=SS.fmtMs, plural=SS.plural;
const SRV='203.0.113.21', CLI='192.168.1.20', PUB='198.51.100.7', HOST='ftp.example.org', FILE='relatorio.pdf', USR='aluno', PWD='S3nh@123';
const PASV_PORT=50000, ACT_PORT=50001, SPORT=49152;
const pStr=(ip,port)=>ip.replace(/\./g,',')+','+(port>>8)+','+(port&255);
const MAGIC='%PDF-1.7 ... Relatório de notas do aluno ...';
const sp=h=>h.replace(/(..)/g,'$1 ').trim();

const STATES=[{key:'phase',label:'Fase'},{key:'ctrl',label:'Canal de controle'},{key:'cred',label:'Usuário e senha'},{key:'data',label:'Canal de dados'},{key:'file',label:'Arquivo'}];
const CSTATES=[{key:'phase',label:'Fase'},{key:'ftp',label:'FTP: o observador lê'},{key:'ftps',label:'FTPS: o observador lê'},{key:'sftp',label:'SFTP: o observador lê'}];

// ---------- mensagens genéricas ----------
function tcp3(tr,init,pInit,pResp,what,x){
  const resp=init==='c'?'s':'c';
  const seg=(from,to,flags)=>tr.add(from,to,Object.assign({label:flags,proto:'TCP',color:C0.tcp,len:flags==='SYN'?60:52,
    info:(from===init?pInit+' → '+pResp:pResp+' → '+pInit)+' ['+flags+']',phaseName:what,
    fields:[{sec:'TCP (RFC 9293)'},['Porta de origem',String(from===init?pInit:pResp),''],['Porta de destino',String(from===init?pResp:pInit),''],['Flags',flags,'']],
    about:'Segmento do handshake de três vias da '+what+'. Quem inicia a conexão é o '+(init==='c'?'cliente':'servidor')+'.',
    dump:{text:'TCP  '+(from===init?pInit+' → '+pResp:pResp+' → '+pInit)+'  ['+flags+']',hot:false}},x||{}));
  seg(init,resp,'SYN'); seg(resp,init,'SYN, ACK'); return seg(init,resp,'ACK');
}
function tcpFin(tr,init,pInit,pResp,what,x){
  const resp=init==='c'?'s':'c';
  const seg=(from,to)=>tr.add(from,to,Object.assign({label:'FIN, ACK',proto:'TCP',color:C0.tcp,len:52,info:(from===init?pInit+' → '+pResp:pResp+' → '+pInit)+' [FIN, ACK]',phaseName:what,
    fields:[{sec:'TCP (RFC 9293)'},['Flags','FIN, ACK','encerra a conexão']],about:'Encerramento da '+what+'.',dump:{text:'TCP  '+(from===init?pInit+' → '+pResp:pResp+' → '+pInit)+'  [FIN, ACK]',hot:false}},x||{}));
  seg(init,resp); seg(resp,init);
}
// SYN sem resposta (filtrado): tenta duas vezes e desiste
function synLost(tr,from,to,pFrom,pTo,what){
  const m=tr.add(from,to,{label:'SYN (sem resposta)',proto:'TCP',color:C0.bad,len:60,lost:true,info:pFrom+' → '+pTo+' [SYN]',phaseName:what,
    fields:[{sec:'TCP (RFC 9293)'},['Flags','SYN',''],['Resultado','descartado no caminho','nenhum SYN, ACK volta','expert']],tags:['SYN sem resposta (filtrado)'],
    about:'O SYN foi descartado: o firewall ou o NAT não tem regra para esta conexão.',dump:{text:'TCP  '+pFrom+' → '+pTo+'  [SYN]   (sem resposta)',hot:true}});
  tr.wait(1000);
  tr.add(from,to,{label:'SYN (retransmissão)',proto:'TCP',color:C0.bad,len:60,lost:true,info:pFrom+' → '+pTo+' [SYN] retransmissão',phaseName:what,
    fields:[{sec:'TCP (RFC 9293)'},['Flags','SYN',''],['Resultado','descartado de novo','','expert']],tags:['retransmissão de SYN'],
    about:'Segunda tentativa, depois de 1 s, e outra vez sem resposta.',dump:{text:'TCP  '+pFrom+' → '+pTo+'  [SYN] retransmissão',hot:true}});
  tr.wait(2000);
  return m;
}
function tlsHello(tr,what){
  const a=tr.add('c','s',{label:'Client Hello',proto:'TLS',color:C0.plain,len:310,info:'Client Hello',phaseName:what,
    fields:[{sec:'TLS 1.3 (RFC 8446)'},['Tipo','Client Hello (1)',''],['Versões','TLS 1.3 e 1.2',''],['SNI',HOST,'o nome do servidor vai em claro','expert'],['Suites','TLS_AES_256_GCM_SHA384, ...','']],
    about:'O cliente propõe versões e cifras. O nome do servidor (SNI) é visível a quem captura.',dump:{text:'TLS  Client Hello   SNI='+HOST+'   (em claro)',hot:false}});
  const b=tr.add('s','c',{label:'Server Hello',proto:'TLS',color:C0.plain,len:130,info:'Server Hello',phaseName:what,
    fields:[{sec:'TLS 1.3 (RFC 8446)'},['Tipo','Server Hello (2)',''],['Versão','TLS 1.3',''],['Suite','TLS_AES_256_GCM_SHA384','']],
    about:'O servidor escolhe a versão e a cifra e envia sua parte da troca de chaves. Daqui em diante tudo vai cifrado.',dump:{text:'TLS  Server Hello   TLS 1.3, TLS_AES_256_GCM_SHA384',hot:false}});
  const c=tr.add('s','c',{label:'Certificate, Finished',proto:'TLS',color:C0.enc,enc:true,len:1180,info:'Encrypted Extensions, Certificate, Finished',phaseName:what,par:true,at:b.tSend+0.2,
    fields:[{sec:'TLS 1.3 (RFC 8446)'},['Mensagens','EncryptedExtensions, Certificate, CertificateVerify, Finished','o certificado também vai cifrado no TLS 1.3'],['Certificado',HOST+' (emitido por uma CA pública)','']],
    about:'O servidor prova quem é: certificado, assinatura e Finished, já cifrados.',dump:{text:'TLS  17 03 03  '+sp(hex('cert'+tr.msgs.length,10))+' ...  (1180 B, cifrado)',hot:false}});
  return {hello:a,flight:b,cert:c};
}
function tlsFinish(tr,what){
  return tr.add('c','s',{label:'Finished',proto:'TLS',color:C0.enc,enc:true,len:80,info:'Finished',phaseName:what,
    fields:[{sec:'TLS 1.3 (RFC 8446)'},['Mensagem','Finished','confirma a troca de chaves']],about:'O cliente confirma. A partir daqui o canal está protegido nos dois sentidos.',
    dump:{text:'TLS  17 03 03  '+sp(hex('fin'+tr.msgs.length,10))+' ...  (80 B, cifrado)',hot:false}});
}

// ---------- FTP e FTPS ----------
function runFtp(tr,P,o){
  const ow=tr.ow, tls=o.tls, E={on:false}, f=o.f||null;
  const R={fail:null,conns:1,ctrlEnc:false,credSeen:true,dataEnc:false,tls:tls,t0:tr.t,i0:tr.msgs.length,helper:false,dataOk:null,ports:[]};
  const st=(t,k,v,c)=>{ if(!o.quiet) tr.st(t,k,v,c); };
  const fev=(t,text,kind)=>{ if(f) tr.ev(t,f,text,kind); };
  const ctl=(from,to,text,mean,about,x)=>{
    x=x||{}; const enc=E.on, sens=!!x.sens;
    return tr.add(from,to,{label:x.label||text,proto:enc?'FTP/TLS':'FTP',color:enc?C0.enc:(x.bad?C0.bad:C0.plain),enc:enc,len:70+text.length,info:text,phaseName:x.phase||'Controle',about:about||'',
      fields:enc?[{sec:'TLS: dados do aplicativo (canal de controle cifrado)'},['Registro','Application Data (cifrado)','a captura não mostra o conteúdo do comando'],[from==='c'?'Comando (após decifrar)':'Resposta (após decifrar)',text,mean]]
        :[{sec:'FTP (RFC 959): canal de controle'},[from==='c'?'Comando':'Resposta',text,mean]].concat(sens?[['Exposição','texto puro','qualquer observador no caminho lê o usuário e a senha','expert']]:[]),
      tags:(!enc&&sens)?['credencial em texto puro']:[],
      dump:enc?{text:'TLS  17 03 03  '+sp(hex('c'+tr.msgs.length,9))+' ...  ('+(text.length+29)+' B, cifrado)',hot:false}:{text:(from==='c'?'C> ':'S> ')+text,hot:sens}});
  };
  const cport=tls==='implicit'?990:21;
  R.ports.push(String(cport)+' (controle)');

  // 1. conexão de controle
  tr.phase('1. Conexão de controle (TCP '+cport+')','ctrl');
  st(tr.t,'phase','controle','warn'); st(tr.t,'ctrl','conectando','warn'); st(tr.t,'cred','-','closed'); st(tr.t,'data','-','closed'); st(tr.t,'file','-','closed');
  if(!o.noMile) tr.mile(tr.t,'Controle','porta '+cport);
  const tc=tcp3(tr,'c',SPORT,cport,'conexão de controle');
  tr.lg(tc.tArr,'FTP: conexão de controle estabelecida na porta '+cport+'.','conn');
  if(tls==='implicit'){
    tr.phase('2. TLS desde o primeiro byte (FTPS implícito)','tls');
    const h=tlsHello(tr,'TLS'); tr.wait(0);
    R.cert=h;
    fev(h.hello.tSend+ow/2,'Encaminha o TLS sem entender o conteúdo','');
    tr.ev(h.cert.tArr,'c',o.certOk===false?'O certificado não é confiável: o cliente interrompe':'Valida o certificado do servidor (cadeia, nome e validade)',o.certOk===false?'warn':'ok');
    if(o.certOk===false){
      tr.add('c','s',{label:'Alert: unknown_ca',proto:'TLS',color:C0.bad,enc:true,len:60,info:'Alert: unknown_ca',phaseName:'TLS',fields:[{sec:'TLS 1.3 (RFC 8446)'},['Alerta','unknown_ca (48)','a CA do certificado não é conhecida']],about:'O cliente não confia no certificado e encerra a conexão antes de enviar qualquer senha.',tags:['certificado rejeitado'],dump:{text:'TLS  Alert  unknown_ca',hot:false}});
      st(tr.t,'ctrl','TLS recusado','bad'); st(tr.t,'cred','nada foi enviado','est');
      tr.lg(tr.t,'TLS: o cliente rejeitou o certificado e encerrou. Nenhuma credencial saiu.','conn');
      R.fail={stage:'cert'}; if(!o.noMile) tr.mile(tr.t,'Certificado recusado','sem credenciais enviadas');
      return R;
    }
    tlsFinish(tr,'TLS'); E.on=true; R.ctrlEnc=true; st(tr.t,'ctrl','TLS (cifrado)','est');
    if(!o.noMile) tr.mile(tr.t,'TLS','porta 990');
  }
  st(tr.t,'ctrl',E.on?'TLS (cifrado)':'em claro',E.on?'est':'bad');
  tr.phase('Saudação e login','login');
  const g=ctl('s','c','220 FTP server ready','código 220: o servidor está pronto','Saudação do servidor FTP.');
  if(tls==='explicit'){
    ctl('c','s','AUTH TLS','pede para proteger o canal de controle com TLS (RFC 4217)','O cliente pede TLS no mesmo canal da porta 21. Até aqui tudo foi em claro.');
    ctl('s','c','234 AUTH TLS successful','código 234: o servidor aceita o TLS','O servidor aceita. O handshake TLS começa agora.');
    tr.phase('TLS no canal de controle (FTPS explícito)','tls');
    const h=tlsHello(tr,'TLS'); R.cert=h;
    tr.ev(h.cert.tArr,'c',o.certOk===false?'O certificado não é confiável: o cliente interrompe':'Valida o certificado do servidor (cadeia, nome e validade)',o.certOk===false?'warn':'ok');
    if(o.certOk===false){
      tr.add('c','s',{label:'Alert: unknown_ca',proto:'TLS',color:C0.bad,enc:true,len:60,info:'Alert: unknown_ca',phaseName:'TLS',fields:[{sec:'TLS 1.3 (RFC 8446)'},['Alerta','unknown_ca (48)','a CA do certificado não é conhecida']],about:'O cliente não confia no certificado e encerra a conexão antes de enviar qualquer senha.',tags:['certificado rejeitado'],dump:{text:'TLS  Alert  unknown_ca',hot:false}});
      st(tr.t,'ctrl','TLS recusado','bad'); st(tr.t,'cred','nada foi enviado','est');
      tr.lg(tr.t,'TLS: o cliente rejeitou o certificado e encerrou. Nenhuma credencial saiu.','conn');
      R.fail={stage:'cert'}; if(!o.noMile) tr.mile(tr.t,'Certificado recusado','sem credenciais enviadas');
      return R;
    }
    tlsFinish(tr,'TLS'); E.on=true; R.ctrlEnc=true; st(tr.t,'ctrl','TLS (cifrado)','est');
    if(!o.noMile) tr.mile(tr.t,'TLS','AUTH TLS');
  }
  // 2. autenticação
  const anon=o.cred==='anon', bad=o.cred==='bad';
  const user=anon?'anonymous':USR, pass=anon?'aluno@exemplo.org':(bad?'senha-errada':PWD);
  ctl('c','s','USER '+user,'identifica o usuário','O cliente informa o nome do usuário.',{phase:'Login'});
  ctl('s','c','331 Password required','código 331: falta a senha','O servidor pede a senha.',{phase:'Login'});
  const pm=ctl('c','s','PASS '+pass,'a senha','A senha vai no comando PASS.'+(E.on?' Neste caso, dentro do túnel TLS.':' Em texto puro: quem captura o tráfego a lê.'),{sens:true,phase:'Login'});
  if(!E.on){ tr.ev(pm.tSend+ow/2,'c','A senha sai em texto puro no canal de controle','warn'); st(pm.tSend+ow/2,'cred','EXPOSTOS (texto puro)','bad'); R.credSeen=true; }
  else { st(pm.tSend+ow/2,'cred','protegidos (TLS)','est'); R.credSeen=false; }
  if(bad){
    ctl('s','c','530 Login incorrect','código 530: não autenticado','O servidor recusa o login.',{bad:true,phase:'Login'});
    tr.ev(tr.t-0.4,'s','Registra a falha de login','warn'); tr.lg(tr.t,'FTP: login recusado (530).','loss');
    st(tr.t,'ctrl','sem sessão','bad');
    ctl('c','s','QUIT','encerra a sessão','O cliente encerra.',{phase:'Fim'}); ctl('s','c','221 Goodbye','código 221: sessão encerrada','',{phase:'Fim'});
    tcpFin(tr,'c',SPORT,cport,'conexão de controle');
    st(tr.t,'phase','falhou','bad'); st(tr.t,'ctrl','encerrado','closed');
    R.fail={stage:'auth'}; if(!o.noMile) tr.mile(tr.t,'Login recusado','530');
    return R;
  }
  const lg=ctl('s','c',anon?'230 Anonymous access granted':'230 User '+USR+' logged in','código 230: autenticado','Login aceito.',{phase:'Login'});
  tr.lg(lg.tArr,'FTP: login aceito'+(E.on?' (credenciais protegidas pelo TLS).':'; a senha trafegou em texto puro.'),E.on?'conn':'loss');
  if(!o.noMile) tr.mile(tr.t,'Login',E.on?'dentro do TLS':'em claro');
  if(tls){
    ctl('c','s','PBSZ 0','tamanho do buffer de proteção (sempre 0 em TLS)','Comando exigido pelas extensões de segurança (RFC 2228).',{phase:'Proteção'});
    ctl('s','c','200 PBSZ=0','','',{phase:'Proteção'});
    ctl('c','s','PROT '+o.prot,o.prot==='P'?'P (Private): os dados também serão cifrados':'C (Clear): os dados continuarão em claro','Define o nível de proteção do canal de DADOS.',{phase:'Proteção'});
    ctl('s','c','200 Protection level set to '+o.prot,'','',{phase:'Proteção'});
    R.dataEnc=o.prot==='P';
  }
  ctl('c','s','TYPE I','modo binário','Transferência binária (imagem).',{phase:'Login'}); ctl('s','c','200 Type set to I','','',{phase:'Login'});

  // 3. canal de dados
  const op=o.op, opCmd=op==='get'?'RETR '+FILE:(op==='put'?'STOR '+FILE:'LIST'), opName=op==='get'?'download':(op==='put'?'upload':'listagem');
  const active=o.mode==='active';
  const dataEnc=!!tls&&o.prot==='P';
  const dataPhase=(active?'3. Canal de dados (modo ativo: o servidor conecta ao cliente)':'3. Canal de dados (modo passivo: o cliente conecta ao servidor)');
  tr.phase(dataPhase,'data');
  st(tr.t,'phase','dados','warn');
  const dataFail=(why)=>{
    st(tr.t,'data','BLOQUEADO','bad'); st(tr.t,'file','não transferido','bad');
    R.dataOk=false; R.fail={stage:'data',why:why};
  };
  let ok=true;
  const dport=active?20:PASV_PORT, cdp=active?ACT_PORT:SPORT+1;
  if(!active){
    ctl('c','s','PASV','pede um endereço e uma porta para a conexão de dados','No modo passivo o servidor abre uma porta e o cliente conecta nela.',{phase:'Dados'});
    const r=ctl('s','c','227 Entering Passive Mode ('+pStr(SRV,PASV_PORT)+')','servidor '+SRV+', porta '+PASV_PORT+' (195×256+80)','O servidor informa onde o cliente deve conectar. Cada transferência usa uma porta nova da faixa passiva.',{phase:'Dados'});
    R.ports.push(PASV_PORT+' (dados, faixa passiva)');
    fev(r.tSend+ow/2,'Conexão de dentro para fora: o estado do NAT a permite','ok');
    if(o.sfw===false){
      tr.ev(r.tArr,'c','Tenta conectar na porta '+PASV_PORT+'…','');
      synLost(tr,'c','s',cdp,dport,'conexão de dados');
      tr.ev(tr.t,'s','O firewall do servidor não libera a faixa de portas passivas','warn');
      tr.ev(tr.t,'c','Tempo esgotado: o cliente desiste do canal de dados','warn');
      ok=false; R.why='a faixa passiva não está liberada no firewall do servidor';
      tr.lg(tr.t,'FTP: SYN para a porta passiva '+PASV_PORT+' sem resposta. O firewall do servidor bloqueia a faixa passiva.','loss');
      dataFail('faixa passiva bloqueada');
    } else {
      tcp3(tr,'c',cdp,dport,'conexão de dados');
      R.conns=2; st(tr.t,'data','conectado','est');
    }
  } else {
    let portCmd='PORT '+pStr(CLI,ACT_PORT), seen=CLI;
    const helper=o.cfw==='helper'&&!E.on;
    ctl('c','s',portCmd,'o cliente anuncia o endereço '+CLI+' e a porta '+ACT_PORT+' (195×256+81)','No modo ativo o cliente escuta e o SERVIDOR conecta. O endereço no comando é o endereço privado do cliente.',{phase:'Dados'});
    R.ports.push(ACT_PORT+' (cliente) e 20 (servidor)');
    if(helper){
      fev(tr.t-0.4,'Inspeciona o PORT: troca '+CLI+' por '+PUB+' e abre a porta '+ACT_PORT+' para o servidor','ok'); seen=PUB; R.helper=true;
    } else if(o.cfw!=='none'){
      fev(tr.t-0.4,E.on&&o.cfw==='helper'?'O comando está cifrado: o helper de FTP não consegue lê-lo':'Repassa o PORT sem alterar o endereço privado',E.on&&o.cfw==='helper'?'warn':'');
    }
    ctl('s','c','200 PORT command successful','código 200: o servidor guardou '+seen+':'+ACT_PORT,'O servidor aceita o comando. A conexão só acontece quando houver uma transferência.',{phase:'Dados'});
    R.activeSeen=seen;
  }
  // comando da operação
  const oc=ctl('c','s',opCmd,op==='get'?'baixar o arquivo':(op==='put'?'enviar o arquivo':'listar o diretório'),'O cliente pede a operação. Os dados irão pelo canal de dados.',{phase:'Dados'});
  if(active){
    ctl('s','c','150 Opening BINARY mode data connection','código 150: vou abrir o canal de dados','O servidor vai conectar de volta ao cliente.',{phase:'Dados'});
    const reach=o.cfw==='none'||(o.cfw==='helper'&&!E.on);
    if(!reach){
      tr.ev(tr.t,'s','Conecta em '+CLI+':'+ACT_PORT+' (endereço privado)','');
      synLost(tr,'s','c',20,ACT_PORT,'conexão de dados');
      fev(tr.t,o.cfw==='helper'&&E.on?'Sem o PORT legível, não há regra: descarta o SYN de entrada':'O NAT não traduz '+CLI+' e o firewall de estado descarta o SYN de entrada','warn');
      ctl('s','c','425 Can\'t build data connection: Connection timed out','código 425: o servidor não conseguiu abrir o canal de dados','Falha clássica do modo ativo atrás de NAT.',{bad:true,phase:'Dados'});
      tr.lg(tr.t,'FTP: o servidor não alcançou '+CLI+':'+ACT_PORT+'. '+(o.cfw==='helper'&&E.on?'O helper não lê comandos cifrados.':'Endereço privado atrás de NAT.'),'loss');
      ok=false; R.why=o.cfw==='helper'&&E.on?'o FTPS cifra o comando PORT e o helper do NAT não consegue lê-lo':'o servidor tentou conectar a um endereço privado atrás de NAT';
      dataFail(R.why);
    } else {
      tcp3(tr,'s',20,ACT_PORT,'conexão de dados');
      R.conns=2; st(tr.t,'data','conectado','est');
      if(o.cfw==='none') fev(tr.t-0.4,'Sem NAT nem filtro: o SYN de entrada passa','');
    }
  } else if(ok){
    ctl('s','c','150 Opening BINARY mode data connection','código 150: canal de dados aberto','O servidor confirma e começa a transferência.',{phase:'Dados'});
  }
  if(!ok){
    tr.phase('Encerramento','end');
    ctl('c','s','QUIT','encerra a sessão','O cliente desiste e encerra.',{phase:'Fim'});
    ctl('s','c','221 Goodbye','código 221: sessão encerrada','',{phase:'Fim'});
    tcpFin(tr,'c',SPORT,cport,'conexão de controle');
    st(tr.t,'phase','falhou','bad'); st(tr.t,'ctrl','encerrado','closed');
    if(!o.noMile) tr.mile(tr.t,'Dados bloqueados',R.why?'falha':'');
    return R;
  }
  // TLS no canal de dados
  if(dataEnc){
    const a=tr.add('c','s',{label:'Client Hello (retoma a sessão)',proto:'TLS',color:C0.plain,len:260,info:'Client Hello com ticket de sessão',phaseName:'TLS dos dados',
      fields:[{sec:'TLS 1.3 (RFC 8446)'},['Tipo','Client Hello (1)','reaproveita a sessão do canal de controle'],['pre_shared_key','ticket da sessão do controle','muitos servidores exigem o reuso da sessão']],about:'O canal de dados também é protegido por TLS (PROT P). O cliente reaproveita a sessão do controle, o que prova que as duas conexões são da mesma pessoa.',
      dump:{text:'TLS  Client Hello (retomada)   SNI='+HOST,hot:false}});
    tr.add('s','c',{label:'Server Hello, Finished',proto:'TLS',color:C0.enc,enc:true,len:200,info:'Server Hello, Finished',phaseName:'TLS dos dados',fields:[{sec:'TLS 1.3 (RFC 8446)'},['Mensagens','Server Hello, Finished','sessão retomada']],about:'O servidor aceita a retomada.',dump:{text:'TLS  17 03 03  '+sp(hex('dh'+tr.msgs.length,10))+' ...  (200 B, cifrado)',hot:false}});
    tr.add('c','s',{label:'Finished',proto:'TLS',color:C0.enc,enc:true,len:80,info:'Finished',phaseName:'TLS dos dados',fields:[{sec:'TLS 1.3 (RFC 8446)'},['Mensagem','Finished','']],about:'Canal de dados protegido.',dump:{text:'TLS  17 03 03  '+sp(hex('df'+tr.msgs.length,10))+' ...  (80 B, cifrado)',hot:false}});
    st(tr.t,'data','TLS (cifrado)','est');
  } else st(tr.t,'data','em claro',tls?'warn':'bad');
  // transferência
  tr.lg(tr.t,'FTP: canal de dados '+(dataEnc?'protegido por TLS (PROT P).':(tls?'sem proteção (PROT C).':'em texto puro.')),dataEnc?'conn':'loss');
  tr.phase('4. Transferência pelo canal de dados','xfer');
  st(tr.t,'phase','transferência','warn'); st(tr.t,'file','em curso','warn');
  if(!o.noMile) tr.mile(tr.t,'Dados',active?'ativo':'passivo');
  const from=op==='put'?'c':'s', to=op==='put'?'s':'c';
  const parts=op==='list'?1:3;
  const dm=(i)=>{
    const label=op==='list'?'Listagem do diretório':'Dados do arquivo ('+(i+1)+'/'+parts+')';
    const body=op==='list'?'-rw-r--r-- 1 aluno aluno 1245184 out 13 relatorio.pdf':MAGIC;
    return tr.add(from,to,{label:label,proto:dataEnc?'FTP-DATA/TLS':'FTP-DATA',color:dataEnc?C0.enc:C0.data,enc:dataEnc,len:op==='list'?220:1514,info:label,phaseName:'Dados',
      fields:dataEnc?[{sec:'TLS: dados do aplicativo (canal de dados cifrado)'},['Registro','Application Data (cifrado)','o conteúdo do arquivo não aparece na captura']]
        :[{sec:'FTP-DATA (RFC 959): canal de dados'},['Conteúdo',body,'o arquivo trafega em claro','expert'],['Cifrado?','não','quem captura reconstrói o arquivo','expert']],
      tags:dataEnc?[]:['conteúdo do arquivo em claro'],
      about:dataEnc?'Parte do '+(op==='list'?'resultado':'arquivo')+', cifrada pelo TLS dos dados.':'Parte do '+(op==='list'?'resultado':'arquivo')+' em texto puro: quem captura o tráfego a lê.',
      dump:dataEnc?{text:'TLS  17 03 03  '+sp(hex('d'+tr.msgs.length,9))+' ...  (1500 B, cifrado)',hot:false}:{text:'DADOS  '+body,hot:true}});
  };
  let last=null;
  for(let i=0;i<parts;i++){ last=dm(i); if(i===0&&!dataEnc) tr.ev(last.tArr,op==='put'?'s':'c','Recebe o conteúdo em claro: '+(op==='list'?'a listagem':'o arquivo'),'warn'); }
  tr.ev(last.tArr,op==='put'?'s':'c',op==='list'?'Recebe a listagem':'Arquivo completo ('+FILE+')','ok');
  tcpFin(tr,from==='c'?'c':'s',from==='c'?cdp:dport,from==='c'?dport:cdp,'conexão de dados');
  ctl('s','c','226 Transfer complete','código 226: transferência concluída','O servidor confirma pelo canal de CONTROLE que o canal de dados foi encerrado com sucesso.',{phase:'Dados'});
  st(tr.t,'file',op==='list'?'listagem recebida':'transferido','est'); st(tr.t,'data','encerrado','closed');
  R.dataOk=true; R.tXfer=tr.t;
  if(!o.noMile) tr.mile(tr.t,'Transferido',opName);
  // 5. fim
  tr.phase('5. Encerramento','end');
  ctl('c','s','QUIT','encerra a sessão','O cliente encerra a sessão.',{phase:'Fim'});
  ctl('s','c','221 Goodbye','código 221: sessão encerrada','',{phase:'Fim'});
  tcpFin(tr,'c',SPORT,cport,'conexão de controle');
  st(tr.t,'ctrl','encerrado','closed'); st(tr.t,'phase','concluído','est');
  R.tEnd=tr.t; R.i1=tr.msgs.length;
  tr.lg(tr.t,'FTP'+(tls?'S':'')+': '+opName+' concluído com '+R.conns+' conexões TCP'+(R.credSeen?' e a senha exposta.':'.'),R.credSeen?'loss':'conn');
  return R;
}

// ---------- SFTP ----------
function runSftp(tr,P,o){
  const ow=tr.ow, R={fail:null,conns:1,ctrlEnc:true,credSeen:false,dataEnc:true,t0:tr.t,i0:tr.msgs.length,ports:['22 (tudo)']};
  const st=(t,k,v,c)=>{ if(!o.quiet) tr.st(t,k,v,c); };
  const f=o.f||null;
  const op=o.op, auth=o.sauth||'password';
  const enc=(from,to,label,info,fields,x)=>tr.add(from,to,Object.assign({label:label,proto:'SSHv2',color:C0.enc,enc:true,len:96,info:info||label,phaseName:'SFTP',
    fields:[{sec:'SSH Binary Packet (RFC 4253, seção 6)'},['Registro','pacote cifrado e autenticado','a captura não mostra o tipo da mensagem']].concat(fields||[]),
    dump:{text:'SSH  '+sp(hex('s'+tr.msgs.length,9))+' ...  (cifrado)',hot:false}},x||{}));
  const clr=(from,to,label,fields,about,dump)=>tr.add(from,to,{label:label,proto:'SSHv2',color:C0.plain,len:140,info:label,phaseName:'SSH',fields:[{sec:'SSH (RFC 4253): em claro'}].concat(fields||[]),about:about||'',dump:{text:'SSH  '+(dump||label),hot:false}});
  tr.phase('1. Conexão TCP e SSH (porta 22)','ctrl');
  st(tr.t,'phase','SSH','warn'); st(tr.t,'ctrl','conectando','warn'); st(tr.t,'cred','-','closed'); st(tr.t,'data','-','closed'); st(tr.t,'file','-','closed');
  if(!o.noMile) tr.mile(tr.t,'SSH','porta 22');
  tcp3(tr,'c',SPORT,22,'conexão SSH');
  clr('c','s','SSH-2.0-OpenSSH_9.6',[['Banner','SSH-2.0-OpenSSH_9.6','versão do protocolo e do software']],'Cada lado anuncia sua versão, em texto.','SSH-2.0-OpenSSH_9.6  (banner do cliente)');
  clr('s','c','SSH-2.0-OpenSSH_9.6',[['Banner','SSH-2.0-OpenSSH_9.6','']],'O servidor responde com seu banner.','SSH-2.0-OpenSSH_9.6  (banner do servidor)');
  clr('c','s','KEXINIT',[['Algoritmos','curve25519-sha256, ssh-ed25519, chacha20-poly1305@openssh.com, ...','lista de preferência']],'O cliente lista algoritmos de troca de chaves, assinatura e cifra.','KEXINIT  (algoritmos do cliente)');
  clr('s','c','KEXINIT',[['Algoritmos','curve25519-sha256, ssh-ed25519, chacha20-poly1305@openssh.com, ...','']],'O servidor lista os dele; vale o primeiro da lista do cliente que o servidor também suporta.','KEXINIT  (algoritmos do servidor)');
  clr('c','s','KEX_ECDH_INIT',[['Valor público do cliente (Q_C)',hex('qc',16)+'...','curve25519']],'O cliente envia o valor público da troca de chaves.','KEX_ECDH_INIT  Q_C='+hex('qc',8)+'...');
  const kr=clr('s','c','KEX_ECDH_REPLY',[['Chave do host','ssh-ed25519 SHA256:'+b64('hk',43),'identifica o servidor'],['Valor público do servidor (Q_S)',hex('qs',16)+'...',''],['Assinatura','ssh-ed25519','prova a posse da chave do host']],'O servidor envia a chave do host e a assinatura. O cliente confere a chave em known_hosts.','KEX_ECDH_REPLY  chave do host SHA256:'+b64('hk',12)+'...');
  tr.ev(kr.tArr,'c','Confere a chave do servidor em known_hosts: conhecida','ok');
  clr('c','s','NEWKEYS',[['Mensagem','NEWKEYS','a partir daqui os pacotes são cifrados']],'Ativa as chaves negociadas.','NEWKEYS');
  const nk=clr('s','c','NEWKEYS',[['Mensagem','NEWKEYS','']],'O servidor também ativa as chaves. Tudo o que vem depois é cifrado.','NEWKEYS');
  st(nk.tArr,'ctrl','SSH (cifrado)','est'); tr.lg(nk.tArr,'SSH: chaves negociadas; a partir daqui tudo é cifrado.','conn');
  if(!o.noMile) tr.mile(nk.tArr,'Chaves','cifrado');
  tr.phase('2. Autenticação (já dentro do túnel cifrado)','login');
  const ua=enc('c','s',auth==='key'?'USERAUTH publickey (assinatura)':'USERAUTH password','USERAUTH_REQUEST',[['Método',auth==='key'?'publickey (assinatura com a chave privada)':'password','']],{len:auth==='key'?200:110,about:auth==='key'?'O cliente prova a posse da chave privada sem enviá-la.':'A senha vai dentro do túnel cifrado: um observador não a lê.'});
  st(ua.tSend+ow/2,'cred',auth==='key'?'sem senha (chave pública)':'protegidos (SSH)','est');
  const us=enc('s','c','USERAUTH success','USERAUTH_SUCCESS',[['Resultado','sucesso','']],{len:80,about:'Autenticado.'});
  tr.lg(us.tArr,'SSH: usuário autenticado por '+(auth==='key'?'chave pública':'senha')+', dentro do túnel cifrado.','conn');
  tr.phase('3. Canal e subsistema SFTP','chan');
  enc('c','s','CHANNEL_OPEN session','CHANNEL_OPEN',[['Tipo','session','']],{about:'Abre um canal dentro da mesma conexão TCP.'});
  enc('s','c','CHANNEL_OPEN_CONFIRMATION','CHANNEL_OPEN_CONFIRMATION',[],{len:80});
  enc('c','s','CHANNEL_REQUEST subsystem sftp','CHANNEL_REQUEST',[['Subsistema','sftp','pede o servidor de arquivos do SSH']],{about:'O cliente pede o subsistema SFTP. Não existe uma segunda porta: tudo segue na porta 22.'});
  enc('s','c','CHANNEL_SUCCESS','CHANNEL_SUCCESS',[],{len:60});
  enc('c','s','SSH_FXP_INIT v3','SFTP: INIT',[['Mensagem','SSH_FXP_INIT','versão 3 do protocolo']],{len:70});
  enc('s','c','SSH_FXP_VERSION 3','SFTP: VERSION',[['Mensagem','SSH_FXP_VERSION','']],{len:70});
  if(!o.noMile) tr.mile(tr.t,'SFTP','subsistema');
  st(tr.t,'phase','transferência','warn'); st(tr.t,'data','mesmo canal (cifrado)','est'); st(tr.t,'file','em curso','warn');
  tr.phase('4. Operação no mesmo canal','xfer');
  let lastX;
  if(op==='get'){
    enc('c','s','SSH_FXP_OPEN '+FILE,'SFTP: OPEN',[['Arquivo',FILE,'']],{len:130});
    enc('s','c','SSH_FXP_HANDLE','SFTP: HANDLE',[],{len:80});
    enc('c','s','SSH_FXP_READ','SFTP: READ',[['Tamanho','32768 B por pedido','']],{len:90});
    for(let i=0;i<3;i++) lastX=enc('s','c','SSH_FXP_DATA ('+(i+1)+'/3)','SFTP: DATA',[['Conteúdo','cifrado','o arquivo viaja dentro do túnel']],{color:C0.enc,len:1514,about:'Parte do arquivo, cifrada e com verificação de integridade.'});
  } else if(op==='put'){
    enc('c','s','SSH_FXP_OPEN '+FILE+' (escrita)','SFTP: OPEN',[['Arquivo',FILE,'']],{len:130});
    enc('s','c','SSH_FXP_HANDLE','SFTP: HANDLE',[],{len:80});
    for(let i=0;i<3;i++) lastX=enc('c','s','SSH_FXP_WRITE ('+(i+1)+'/3)','SFTP: WRITE',[['Conteúdo','cifrado','']],{len:1514,about:'Parte do arquivo enviada pelo túnel cifrado.'});
    enc('s','c','SSH_FXP_STATUS ok','SFTP: STATUS',[['Resultado','SSH_FX_OK','']],{len:70});
  } else {
    enc('c','s','SSH_FXP_OPENDIR','SFTP: OPENDIR',[['Diretório','.','']],{len:90});
    enc('s','c','SSH_FXP_HANDLE','SFTP: HANDLE',[],{len:80});
    enc('c','s','SSH_FXP_READDIR','SFTP: READDIR',[],{len:70});
    lastX=enc('s','c','SSH_FXP_NAME ('+FILE+')','SFTP: NAME',[['Entradas','1','']],{len:260});
  }
  tr.ev(lastX.tArr,op==='put'?'s':'c',op==='list'?'Recebe a listagem':(op==='put'?'Arquivo gravado':'Arquivo completo ('+FILE+')'),'ok');
  enc('c','s','SSH_FXP_CLOSE','SFTP: CLOSE',[],{len:70});
  enc('s','c','SSH_FXP_STATUS ok','SFTP: STATUS',[['Resultado','SSH_FX_OK','']],{len:70});
  st(tr.t,'file',op==='list'?'listagem recebida':'transferido','est');
  R.dataOk=true; R.tXfer=tr.t;
  if(!o.noMile) tr.mile(tr.t,'Transferido',op==='get'?'download':(op==='put'?'upload':'listagem'));
  tr.phase('5. Encerramento','end');
  enc('c','s','CHANNEL_CLOSE','CHANNEL_CLOSE',[],{len:60}); enc('c','s','DISCONNECT','DISCONNECT',[],{len:60,par:true,at:tr.t-0.4+0.1});
  tcpFin(tr,'c',SPORT,22,'conexão SSH');
  st(tr.t,'ctrl','encerrado','closed'); st(tr.t,'phase','concluído','est');
  R.tEnd=tr.t; R.i1=tr.msgs.length;
  tr.lg(tr.t,'SFTP: '+(op==='get'?'download':(op==='put'?'upload':'listagem'))+' concluído em 1 conexão TCP, tudo cifrado.','conn');
  return R;
}

// ---------- simulações por modo ----------
function simFtp(P,sub){
  const cols=[{key:'c',label:'Cliente',sub:CLI,addr:CLI},{key:'f',label:'Firewall / NAT',sub:'do cliente ('+PUB+')',addr:PUB},{key:'s',label:'Servidor',sub:SRV+(sub==='ftps'?':'+(P.tlsMode==='implicit'?'990':'21'):':21'),addr:SRV}];
  const tr=SS.newTrace(cols,STATES,P.rtt); tr.raw.sub=sub;
  const fwTxt={none:'sem NAT nem filtro',nat:'NAT com firewall de estado',helper:'NAT com inspeção de FTP'}[P.cfw];
  tr.ev(0,'f','Firewall do cliente: '+fwTxt,'');
  const R=runFtp(tr,P,{tls:sub==='ftps'?P.tlsMode:null,prot:P.prot,certOk:P.certOk,mode:P.mode,cfw:P.cfw,sfw:P.sfw,cred:P.cred,op:P.op,f:'f'});
  tr.raw.R=R; tr.raw.P=P;
  return tr;
}
function simSftp(P){
  const cols=[{key:'c',label:'Cliente',sub:CLI,addr:CLI},{key:'f',label:'Firewall / NAT',sub:'do cliente ('+PUB+')',addr:PUB},{key:'s',label:'Servidor SFTP',sub:SRV+':22',addr:SRV}];
  const tr=SS.newTrace(cols,STATES,P.rtt); tr.raw.sub='sftp';
  tr.ev(0,'f','Basta liberar a saída para a porta 22 (uma única conexão)','');
  const R=runSftp(tr,P,{op:P.op,sauth:P.sauth,f:'f'});
  tr.raw.R=R; tr.raw.P=P;
  return tr;
}
function simCompare(P){
  const cols=[{key:'c',label:'Cliente',sub:CLI,addr:CLI},{key:'o',label:'Observador na rede',sub:'Wi-Fi público ou provedor',addr:'192.168.1.1'},{key:'s',label:'Servidor',sub:SRV,addr:SRV}];
  const tr=SS.newTrace(cols,CSTATES,P.rtt), ow=tr.ow, raw=tr.raw; raw.sub='cmp'; raw.P=P;
  const op=P.op, opName=op==='get'?'baixar o arquivo':(op==='put'?'enviar o arquivo':'listar o diretório');
  tr.st(0,'phase','início','warn'); tr.st(0,'ftp','-','closed'); tr.st(0,'ftps','-','closed'); tr.st(0,'sftp','-','closed');
  tr.mile(0,'A. FTP','portas 21 e dados');
  const watch=(R,names)=>{
    // anotações do observador a partir das mensagens de cada execução
    const ms=tr.msgs.slice(R.i0,R.i1===undefined?tr.msgs.length:R.i1);
    let seenPass=false, seenData=false, seenTlsCtl=false, seenEnc=false;
    ms.forEach(m=>{
      const t=m.tSend+ow/2;
      if(names==='ftp'){
        if(/^PASS /.test(m.label)&&!seenPass){ seenPass=true; tr.ev(t,'o','Lê o usuário e a senha: '+USR+' / '+PWD,'warn'); }
        if(m.proto==='FTP-DATA'&&!seenData){ seenData=true; tr.ev(t,'o','Lê o conteúdo: "'+(op==='list'?'relatorio.pdf':'%PDF-1.7 ...')+'" e reconstrói o arquivo','warn'); }
      } else if(names==='ftps'){
        if(m.label==='AUTH TLS'&&!seenTlsCtl){ seenTlsCtl=true; tr.ev(t,'o','Vê o AUTH TLS e o Client Hello (nome do servidor): nada além disso','ok'); }
        if(m.enc&&/^PASS /.test(m.label)&&!seenPass){ seenPass=true; tr.ev(t,'o','Vê só bytes cifrados: o usuário e a senha ficam ocultos','ok'); }
        if(m.proto==='FTP-DATA/TLS'&&!seenData){ seenData=true; tr.ev(t,'o','Vê a segunda conexão (porta '+PASV_PORT+') e bytes cifrados','ok'); }
      } else {
        if(m.enc&&!seenEnc){ seenEnc=true; tr.ev(t,'o','Vê só pacotes cifrados na porta 22: nem o comando, nem o arquivo','ok'); }
      }
    });
  };
  // ---------- A. FTP ----------
  tr.phase('A. FTP (sem proteção)','a');
  const a=runFtp(tr,P,{tls:null,mode:'passive',cfw:'none',sfw:true,cred:'ok',op:op,quiet:true,noMile:true});
  tr.st(a.i0===undefined?0:tr.msgs[a.i0+0].tSend,'phase','A. FTP','warn');
  tr.st(a.tEnd,'ftp','usuário, senha e arquivo','bad');
  tr.mile(a.tEnd,'FTP concluído',fmtMs(a.tEnd-a.t0));
  watch(a,'ftp');
  tr.wait(ow);
  // ---------- B. FTPS ----------
  tr.phase('B. FTPS explícito (AUTH TLS, PROT P)','b');
  tr.st(tr.t,'phase','B. FTPS','warn'); tr.mile(tr.t,'B. FTPS','AUTH TLS');
  const b=runFtp(tr,P,{tls:'explicit',prot:'P',certOk:true,mode:'passive',cfw:'none',sfw:true,cred:'ok',op:op,quiet:true,noMile:true});
  tr.st(b.tEnd,'ftps','só metadados (cifrado)','est');
  tr.mile(b.tEnd,'FTPS concluído',fmtMs(b.tEnd-b.t0));
  watch(b,'ftps');
  tr.wait(ow);
  // ---------- C. SFTP ----------
  tr.phase('C. SFTP (SSH, porta 22)','c');
  tr.st(tr.t,'phase','C. SFTP','warn'); tr.mile(tr.t,'C. SFTP','porta 22');
  const c=runSftp(tr,P,{op:op,sauth:'password',quiet:true,noMile:true});
  tr.st(c.tEnd,'sftp','só metadados (cifrado)','est'); tr.st(c.tEnd,'phase','concluído','est');
  tr.mile(c.tEnd,'SFTP concluído',fmtMs(c.tEnd-c.t0));
  watch(c,'sftp');
  raw.A=a; raw.B=b; raw.C=c;
  // texto do que o observador captura (usa as linhas "dump" de cada mensagem)
  const lines=(R)=>tr.msgs.slice(R.i0,R.i1).filter(m=>m.dump).map(m=>({t:m.tArr,text:m.dump.text,hot:!!m.dump.hot}));
  raw.dump={ftp:lines(a),ftps:lines(b),sftp:lines(c)};
  raw.opName=opName;
  return tr;
}

// ---------- abas ----------
const nowMs=ctx=>ctx.timeAt(ctx.c);
function dumpBlock(lines,now){
  const v=lines.filter(l=>l.t<=now);
  if(!v.length) return '(aguardando)';
  return v.map(l=>l.hot?'<span class="chk-bad">'+esc(l.text)+'</span>':esc(l.text)).join('\n');
}
function singleDump(tr,R){
  const ms=tr.msgs.slice(R.i0,R.i1===undefined?tr.msgs.length:R.i1);
  return ms.filter(m=>m.dump).map(m=>({t:m.tArr,text:m.dump.text,hot:!!m.dump.hot}));
}
const TAB_OBS={id:'obs',label:'O que o observador vê',render:(tr,ctx)=>{
  const r=tr.raw, now=nowMs(ctx);
  let h='<h3>Captura de quem está no meio do caminho (Wi-Fi público, provedor, outro equipamento da rede)</h3>';
  if(r.sub==='cmp'&&r.dump){
    h+='<div class="cfg-two"><div><h3>FTP</h3><pre class="conf">'+dumpBlock(r.dump.ftp,now)+'</pre></div><div><h3>FTPS (explícito, PROT P)</h3><pre class="conf">'+dumpBlock(r.dump.ftps,now)+'</pre></div></div>';
    h+='<h3>SFTP (SSH)</h3><pre class="conf">'+dumpBlock(r.dump.sftp,now)+'</pre>';
  } else if(r.R){
    h+='<pre class="conf">'+dumpBlock(singleDump(tr,r.R),now)+'</pre>';
    h+='<p>As linhas em vermelho são o que um observador lê sem esforço. Em linhas cifradas ele vê apenas o tamanho e o momento dos pacotes.</p>';
  }
  return h;
}};
const TAB_PORTS={id:'portas',label:'Conexões e portas',subs:['ftp','ftps','sftp'],render:(tr,ctx)=>{
  const r=tr.raw, R=r.R; if(!R) return '';
  const P=r.P||{};
  let h='<h3>Quantas conexões e quais portas este cenário usa</h3>';
  h+='<table class="sc-msgs"><thead><tr><th>Item</th><th>Valor</th><th>Observação</th></tr></thead><tbody>';
  h+='<tr><td>Conexões TCP</td><td>'+R.conns+'</td><td class="meaning">'+(r.sub==='sftp'?'uma só: comandos e arquivos viajam no mesmo canal':'controle + uma conexão de dados por transferência')+'</td></tr>';
  h+='<tr><td>Portas</td><td>'+esc(R.ports.join('; '))+'</td><td class="meaning">'+(r.sub==='sftp'?'só a 22 precisa estar liberada':'o firewall precisa tratar a conexão de dados')+'</td></tr>';
  if(r.sub!=='sftp'){
    h+='<tr><td>Modo de dados</td><td>'+(P.mode==='active'?'ativo (PORT)':'passivo (PASV)')+'</td><td class="meaning">'+(P.mode==='active'?'o servidor conecta ao cliente, a partir da porta 20':'o cliente conecta a uma porta alta do servidor')+'</td></tr>';
    h+='<tr><td>Firewall do cliente</td><td>'+({none:'sem NAT nem filtro',nat:'NAT com firewall de estado',helper:'NAT com inspeção de FTP'}[P.cfw]||'-')+'</td><td class="meaning">'+(R.helper?'o helper leu o PORT e abriu a porta':'')+'</td></tr>';
    h+='<tr><td>Faixa passiva no servidor</td><td>'+(P.sfw===false?'bloqueada':'liberada')+'</td><td class="meaning">'+(P.mode==='passive'?'precisa estar liberada para o modo passivo':'não é usada no modo ativo')+'</td></tr>';
    h+='<tr><td>Resultado da conexão de dados</td><td>'+(R.dataOk===true?'<span class="chk-ok">estabelecida</span>':(R.dataOk===false?'<span class="chk-bad">falhou</span>':'-'))+'</td><td class="meaning">'+esc(R.why||'')+'</td></tr>';
  }
  h+='</tbody></table>';
  return h;
}};
const TAB_CMP={id:'cmpx',label:'Comparação',subs:['cmp'],render:(tr,ctx)=>{
  const r=tr.raw, now=nowMs(ctx);
  if(!r.A) return '';
  if(now<r.C.tEnd-0.001) return '<h3>FTP, FTPS e SFTP lado a lado</h3><p class="muted">A tabela é preenchida quando as três execuções terminam. Clique em Simular ou avance com Passo.</p>';
  const A=r.A, B=r.B, C=r.C;
  const row=(k,a,b,c)=>'<tr><td>'+k+'</td><td>'+a+'</td><td>'+b+'</td><td>'+c+'</td></tr>';
  const no=t=>'<span class="chk-bad">'+t+'</span>', ok=t=>'<span class="chk-ok">'+t+'</span>';
  let h='<h3>FTP, FTPS e SFTP na mesma rede e com a mesma ação ('+esc(r.opName)+')</h3>';
  h+='<table class="sc-msgs"><thead><tr><th>Critério</th><th>FTP</th><th>FTPS (explícito, PROT P)</th><th>SFTP</th></tr></thead><tbody>';
  h+=row('Conexões TCP',String(A.conns),String(B.conns),String(C.conns));
  h+=row('Portas','21 e uma de dados','21 e uma de dados','22');
  h+=row('Usuário e senha',no('em claro'),ok('cifrados'),ok('cifrados'));
  h+=row('Comandos',no('em claro'),ok('cifrados'),ok('cifrados'));
  h+=row('Conteúdo do arquivo',no('em claro'),ok('cifrado'),ok('cifrado'));
  h+=row('Detecta alteração no caminho',no('não'),ok('sim (TLS)'),ok('sim (MAC do SSH)'));
  h+=row('Autentica o servidor',no('não'),ok('sim (certificado)'),ok('sim (chave do host)'));
  h+=row('Firewall e NAT',no('difícil (dados em outra porta)'),no('difícil e o helper não lê comandos cifrados'),ok('simples: só a porta 22'));
  h+=row('Tempo até concluir',fmtMs(A.tEnd-A.t0),fmtMs(B.tEnd-B.t0),fmtMs(C.tEnd-C.t0));
  h+='</tbody></table>';
  h+='<p>O FTP mostra tudo a quem está no caminho. O FTPS protege o conteúdo, mas herda a complexidade das duas conexões. O SFTP protege tudo e usa só a porta 22.</p>';
  return h;
}};

// ---------- cenários ----------
const SCENARIOS=[
  {id:'f-pasv',g:'Modos de dados',sub:'ftp',label:'Passivo atrás de NAT',set:{mode:'passive',cfw:'nat',sfw:true,op:'get',cred:'ok'},what:'<p>Download em <b>modo passivo</b> com o cliente atrás de NAT. O cliente conecta a uma porta alta do servidor, e o NAT de estado deixa passar: é o modo que funciona na maioria das redes.</p>'},
  {id:'f-act-ok',g:'Modos de dados',sub:'ftp',label:'Ativo sem NAT',set:{mode:'active',cfw:'none',sfw:true,op:'get',cred:'ok'},what:'<p>Download em <b>modo ativo</b>, com o cliente em um endereço alcançável e sem filtros. O servidor conecta de volta ao cliente, a partir da porta 20, e funciona.</p>'},
  {id:'f-act-nat',g:'Modos de dados',sub:'ftp',label:'Ativo atrás de NAT (falha)',set:{mode:'active',cfw:'nat',sfw:true,op:'get',cred:'ok'},what:'<p>Modo ativo atrás de NAT: o cliente anuncia o endereço <b>privado</b> no PORT. O servidor tenta conectar a ele, não consegue e responde <b>425</b>. É a falha clássica do FTP.</p>'},
  {id:'f-act-alg',g:'Modos de dados',sub:'ftp',label:'Ativo com helper de FTP',set:{mode:'active',cfw:'helper',sfw:true,op:'get',cred:'ok'},what:'<p>O NAT com <b>inspeção de FTP</b> lê o comando PORT, troca o endereço privado pelo público e abre a porta. Funciona, mas só porque o comando está em claro.</p>'},
  {id:'f-pasv-fw',g:'Modos de dados',sub:'ftp',label:'Passivo com faixa bloqueada',set:{mode:'passive',cfw:'nat',sfw:false,op:'get',cred:'ok'},what:'<p>O servidor anuncia a porta passiva <b>50000</b>, mas o firewall dele não libera a faixa. O SYN do cliente fica sem resposta e a transferência não acontece.</p>'},
  {id:'f-list',g:'Operações e login',sub:'ftp',label:'Listar diretório (LIST)',set:{mode:'passive',cfw:'nat',sfw:true,op:'list',cred:'ok'},what:'<p>Até uma <b>listagem</b> usa um canal de dados novo: o resultado do LIST não vem pelo canal de controle.</p>'},
  {id:'f-stor',g:'Operações e login',sub:'ftp',label:'Enviar arquivo (STOR)',set:{mode:'passive',cfw:'nat',sfw:true,op:'put',cred:'ok'},what:'<p><b>Upload</b> com STOR: o arquivo vai do cliente ao servidor pelo canal de dados.</p>'},
  {id:'f-bad',g:'Operações e login',sub:'ftp',label:'Senha incorreta (530)',set:{mode:'passive',cfw:'nat',sfw:true,op:'get',cred:'bad'},what:'<p>Senha errada: o servidor responde <b>530</b>. Repare que a senha, certa ou errada, já trafegou em texto puro.</p>'},
  {id:'f-anon',g:'Operações e login',sub:'ftp',label:'Acesso anônimo',set:{mode:'passive',cfw:'nat',sfw:true,op:'get',cred:'anon'},what:'<p>Login <b>anonymous</b>, com o e-mail como senha: comum em repositórios públicos. Sem segredo para proteger, o texto puro é menos grave, mas o conteúdo continua sem integridade.</p>'},
  {id:'s-exp',g:'FTP sobre TLS',sub:'ftps',label:'FTPS explícito (AUTH TLS)',set:{tlsMode:'explicit',prot:'P',certOk:true,mode:'passive',cfw:'nat',sfw:true,op:'get',cred:'ok'},what:'<p>O cliente conecta na porta 21 em claro, envia <b>AUTH TLS</b> e só então autentica. Com <b>PROT P</b>, o canal de dados também é cifrado.</p>'},
  {id:'s-imp',g:'FTP sobre TLS',sub:'ftps',label:'FTPS implícito (porta 990)',set:{tlsMode:'implicit',prot:'P',certOk:true,mode:'passive',cfw:'nat',sfw:true,op:'get',cred:'ok'},what:'<p>No modo <b>implícito</b> o TLS começa no primeiro byte da conexão, na porta 990, sem AUTH TLS. É o modo legado, mas ainda comum.</p>'},
  {id:'s-protc',g:'FTP sobre TLS',sub:'ftps',label:'PROT C: dados em claro',set:{tlsMode:'explicit',prot:'C',certOk:true,mode:'passive',cfw:'nat',sfw:true,op:'get',cred:'ok'},what:'<p>Com <b>PROT C</b>, só o controle é cifrado: a senha fica protegida, mas o <b>arquivo trafega em claro</b>. É uma configuração insegura que parece segura.</p>'},
  {id:'s-act',g:'FTP sobre TLS',sub:'ftps',label:'Ativo com helper (falha)',set:{tlsMode:'explicit',prot:'P',certOk:true,mode:'active',cfw:'helper',sfw:true,op:'get',cred:'ok'},what:'<p>Com o controle cifrado, o <b>helper de FTP do NAT não consegue ler o PORT</b>. O servidor tenta conectar ao endereço privado e falha: por isso o FTPS costuma exigir modo passivo.</p>'},
  {id:'s-cert',g:'FTP sobre TLS',sub:'ftps',label:'Certificado inválido',set:{tlsMode:'explicit',prot:'P',certOk:false,mode:'passive',cfw:'nat',sfw:true,op:'get',cred:'ok'},what:'<p>O certificado não é confiável. O cliente envia o alerta <b>unknown_ca</b> e encerra <b>antes</b> de mandar a senha.</p>'},
  {id:'p-get',g:'SFTP',sub:'sftp',label:'Download (get)',set:{sauth:'password',op:'get'},what:'<p>Download por SFTP: TCP na porta 22, troca de chaves, autenticação e o subsistema <b>sftp</b>, tudo na mesma conexão.</p>'},
  {id:'p-key',g:'SFTP',sub:'sftp',label:'Chave pública',set:{sauth:'key',op:'get'},what:'<p>A autenticação por <b>chave pública</b> não envia segredo algum: o cliente assina um desafio com a chave privada.</p>'},
  {id:'p-put',g:'SFTP',sub:'sftp',label:'Upload (put)',set:{sauth:'password',op:'put'},what:'<p>Upload por SFTP: pedidos <b>WRITE</b> dentro do túnel cifrado, na mesma conexão do login.</p>'},
  {id:'p-ls',g:'SFTP',sub:'sftp',label:'Listar (ls)',set:{sauth:'password',op:'list'},what:'<p>Listagem por SFTP: <b>OPENDIR</b>, <b>READDIR</b> e <b>NAME</b>, sem canal de dados separado.</p>'},
  {id:'k-get',g:'FTP, FTPS e SFTP',sub:'cmp',label:'Download nos três',set:{op:'get'},what:'<p>O mesmo download feito em <b>FTP</b>, <b>FTPS</b> e <b>SFTP</b>, com um observador na rede, para comparar o que cada protocolo expõe.</p>'},
  {id:'k-put',g:'FTP, FTPS e SFTP',sub:'cmp',label:'Upload nos três',set:{op:'put'},what:'<p>O mesmo upload nos três protocolos, com o observador na rede.</p>'},
  {id:'k-list',g:'FTP, FTPS e SFTP',sub:'cmp',label:'Listagem nos três',set:{op:'list'},what:'<p>A mesma listagem de diretório nos três protocolos.</p>'}
];
const GROUP_DOC={
  'Modos de dados':'O FTP usa um canal de controle e um canal de dados separado. Quem abre o canal de dados (cliente ou servidor) decide se o NAT e o firewall deixam passar.',
  'Operações e login':'Cada operação (LIST, RETR, STOR) abre um canal de dados novo. O login mostra o que acontece com as credenciais.',
  'FTP sobre TLS':'O FTPS põe o TLS sobre o FTP. Protege controle e dados, mas mantém as duas conexões e seus problemas de firewall.',
  'SFTP':'O SFTP é um subsistema do SSH: uma conexão, uma porta, tudo cifrado e autenticado.',
  'FTP, FTPS e SFTP':'A mesma ação nos três protocolos, com um observador na rede, para comparar exposição, conexões e custo.'
};
const doc=(short,concept,observe,msgs,why)=>({short:short,concept:concept,observe:observe,msgs:msgs,why:why});
const SCEN_DOC={
  'f-pasv':doc('O cliente conecta a uma porta alta do servidor: passa pelo NAT.','No modo passivo o cliente envia PASV e o servidor responde com um endereço e uma porta. O cliente abre a conexão de dados para lá, de dentro para fora, e o NAT de estado a permite.',['No 227, a porta vem em dois bytes: 195×256+80 = 50000.','O SYN dos dados parte do cliente.','A senha trafega em claro no canal de controle.'],[['PASV / 227','o servidor informa onde conectar','cliente / servidor'],['SYN, SYN-ACK, ACK','conexão de dados, iniciada pelo cliente','cliente'],['RETR / 150 / 226','pedido, início e fim da transferência','cliente / servidor']],'É por isso que o modo passivo é o padrão na internet: quase todo cliente está atrás de NAT.'),
  'f-act-ok':doc('O servidor conecta ao cliente a partir da porta 20.','No modo ativo o cliente envia PORT com seu endereço e uma porta. O servidor abre a conexão de dados do seu lado (porta 20) para o cliente.',['O SYN dos dados parte do servidor.','O PORT carrega 192,168,1,20 e a porta 195,81 (50001).','Sem NAT nem filtro, o SYN de entrada passa.'],[['PORT / 200','o cliente anuncia seu endereço e porta','cliente / servidor'],['SYN, SYN-ACK, ACK','conexão de dados, iniciada pelo servidor','servidor'],['RETR / 150 / 226','a operação','cliente / servidor']],'O modo ativo inverte quem inicia a conexão. Em redes modernas, com NAT e firewalls, isso quase sempre quebra.'),
  'f-act-nat':doc('O servidor tenta um endereço privado e falha com 425.','O cliente atrás de NAT informa seu endereço privado no PORT. O servidor, na internet, tenta conectar a 192.168.1.20, que não é roteável.',['O SYN do servidor aparece com ✕ duas vezes (retransmissão).','O 425 chega pelo canal de controle.','A senha já foi exposta mesmo sem transferir nada.'],[['PORT / 200','anúncio do endereço privado','cliente / servidor'],['SYN (sem resposta)','o servidor tenta o endereço privado','servidor'],['425','falha ao abrir o canal de dados','servidor']],'É a causa mais comum de "o FTP conecta mas não lista nem baixa".'),
  'f-act-alg':doc('O helper do NAT lê o PORT e abre a porta.','Alguns firewalls inspecionam o canal de controle do FTP, reescrevem o endereço no PORT e criam uma regra temporária para a conexão de dados.',['O firewall reescreve 192.168.1.20 para 198.51.100.7.','A conexão de dados é aceita.','Isso só funciona com o controle em claro.'],[['PORT','reescrito pelo helper','firewall'],['SYN, SYN-ACK, ACK','agora alcança o cliente','servidor']],'O helper resolve o NAT, mas obriga o controle a ficar em claro, e por isso não combina com FTPS.'),
  'f-pasv-fw':doc('A porta passiva está bloqueada no servidor.','No modo passivo o servidor escolhe uma porta de uma faixa. Se o firewall do servidor não liberar a faixa, o cliente não chega a ela.',['O 227 informa a porta 50000.','O SYN do cliente é retransmitido sem resposta.','O cliente desiste do canal de dados.'],[['227','anuncia a porta 50000','servidor'],['SYN (sem resposta)','bloqueado no firewall do servidor','cliente']],'Todo servidor FTP passivo precisa de uma faixa de portas fixa e liberada no firewall.'),
  'f-list':doc('Até a listagem abre uma conexão de dados.','LIST não devolve o diretório no canal de controle: o servidor o envia por um canal de dados aberto só para isso.',['O 150 antecede os dados.','O 226 fecha a operação.'],[['PASV / 227','prepara o canal','cliente / servidor'],['LIST / 150','pede e confirma','cliente / servidor'],['listagem','texto do diretório','servidor'],['226','concluído','servidor']],'Entender isso explica por que o FTP "trava" ao listar quando o canal de dados está bloqueado.'),
  'f-stor':doc('O arquivo segue do cliente para o servidor.','STOR envia um arquivo: o cliente transmite os dados pelo canal de dados e o servidor confirma com 226.',['Os segmentos de dados partem do cliente.','O conteúdo está em claro.'],[['STOR / 150','pede e confirma','cliente / servidor'],['dados','o arquivo','cliente'],['226','concluído','servidor']],'O upload em FTP deixa o conteúdo legível para quem captura o tráfego.'),
  'f-bad':doc('A senha errada também foi exposta.','O servidor recusa o login com 530. Para um observador, o erro é irrelevante: ele já leu a senha digitada, e pode ser a de outro serviço.',['O PASS aparece em vermelho na captura.','Nenhum canal de dados chega a abrir.'],[['USER / 331','usuário e pedido de senha','cliente / servidor'],['PASS / 530','senha recusada','cliente / servidor']],'Senhas digitadas erradas costumam ser variações da correta: expô-las também é grave.'),
  'f-anon':doc('Login anônimo: o e-mail faz o papel de senha.','Servidores públicos aceitam "anonymous" e pedem um e-mail como senha, por convenção. Não há segredo para proteger.',['O PASS leva um e-mail.','O restante é igual ao FTP comum.'],[['USER anonymous / 331','login anônimo','cliente / servidor'],['PASS e-mail / 230','acesso concedido','cliente / servidor']],'Mesmo sem segredo, o conteúdo sem integridade pode ser alterado por quem estiver no caminho.'),
  's-exp':doc('AUTH TLS no canal de controle, depois login cifrado.','No FTPS explícito o cliente conecta em claro, pede AUTH TLS e faz o handshake. Com PBSZ 0 e PROT P, o canal de dados também usa TLS.',['O AUTH TLS e o Client Hello ainda estão em claro.','USER e PASS passam cifrados.','O canal de dados abre outro TLS, reaproveitando a sessão.'],[['AUTH TLS / 234','pede e aceita o TLS','cliente / servidor'],['Client Hello ... Finished','handshake TLS','cliente / servidor'],['PBSZ / PROT P','protege também os dados','cliente / servidor']],'É a forma recomendada de FTPS: padronizada na RFC 4217 e compatível com clientes e servidores comuns.'),
  's-imp':doc('TLS começa antes de qualquer comando FTP.','No modo implícito o servidor espera TLS desde o primeiro byte, na porta 990. Não há AUTH TLS.',['O Client Hello é o primeiro pacote depois do TCP.','O 220 já chega cifrado.'],[['Client Hello ... Finished','handshake TLS','cliente / servidor'],['220','saudação, já cifrada','servidor']],'É o modo legado, não padronizado na RFC 4217, mas ainda comum em ambientes corporativos.'),
  's-protc':doc('A senha é protegida, o arquivo não.','Com PROT C o canal de dados não usa TLS. O controle (login e comandos) segue cifrado, mas o arquivo trafega em claro.',['O DADOS aparece em vermelho na captura.','O PROT C vai dentro do TLS e passa despercebido.'],[['PROT C / 200','dados sem proteção','cliente / servidor'],['dados','arquivo em claro','servidor']],'É uma falsa sensação de segurança: sempre confira se PROT P está ativo.'),
  's-act':doc('O helper do NAT não lê comandos cifrados.','Com o controle cifrado, o firewall não consegue reescrever o PORT. O servidor tenta conectar ao endereço privado e falha com 425.',['O PORT segue cifrado.','O SYN do servidor é descartado.'],[['PORT','cifrado','cliente'],['SYN (sem resposta)','o servidor tenta o endereço privado','servidor'],['425','falha','servidor']],'É por isso que o FTPS costuma exigir modo passivo e uma faixa de portas liberada.'),
  's-cert':doc('O cliente rejeita o certificado antes de autenticar.','No TLS, o cliente valida o certificado do servidor (cadeia, nome e validade). Se falhar, envia um alerta e encerra, sem enviar nenhuma credencial.',['O alerta unknown_ca é o último pacote.','Nenhum USER ou PASS foi enviado.'],[['Certificate','certificado do servidor','servidor'],['Alert unknown_ca','cliente recusa','cliente']],'É a diferença para o FTP comum: aqui o cliente consegue evitar entregar a senha a um servidor falso.'),
  'p-get':doc('Uma conexão TCP, uma porta, tudo cifrado.','O SFTP roda como subsistema do SSH. Depois da troca de chaves e da autenticação, o cliente abre um canal e pede o subsistema sftp. Os pedidos e os dados dos arquivos usam o mesmo canal.',['Só os banners e o KEXINIT estão em claro.','A chave do host é conferida em known_hosts.','Não há canal de dados separado.'],[['KEXINIT ... NEWKEYS','negocia e ativa as chaves','cliente / servidor'],['USERAUTH','autentica dentro do túnel','cliente / servidor'],['SSH_FXP_OPEN / READ / DATA','lê o arquivo','cliente / servidor']],'Uma porta só e criptografia de ponta a ponta tornam o SFTP a opção mais simples de operar com firewalls.'),
  'p-key':doc('A chave privada nunca sai do cliente.','O cliente assina um desafio com a chave privada e o servidor verifica a assinatura com a chave pública cadastrada.',['Não há senha para capturar.','O restante é igual ao SFTP comum.'],[['USERAUTH publickey','assinatura','cliente'],['USERAUTH success','aceito','servidor']],'Chaves eliminam o risco de senhas fracas ou reutilizadas e permitem automação.'),
  'p-put':doc('Upload por pedidos WRITE.','O cliente grava o arquivo em blocos com SSH_FXP_WRITE e o servidor confirma cada gravação.',['Os blocos partem do cliente.','O STATUS confirma o fim.'],[['SSH_FXP_OPEN','abre para escrita','cliente'],['SSH_FXP_WRITE','grava os blocos','cliente'],['SSH_FXP_STATUS','confirma','servidor']],'O upload usa a mesma conexão e as mesmas proteções do login.'),
  'p-ls':doc('Listagem por OPENDIR e READDIR.','O cliente abre o diretório e lê as entradas, tudo pelo canal do SFTP.',['Nenhuma conexão extra.'],[['SSH_FXP_OPENDIR','abre o diretório','cliente'],['SSH_FXP_READDIR','lê as entradas','cliente'],['SSH_FXP_NAME','devolve a lista','servidor']],'Sem conexão extra, listar não falha por causa de firewall.'),
  'k-get':doc('O mesmo download nos três protocolos.','Três execuções em sequência, na mesma rede e com o mesmo observador: FTP em claro, FTPS com TLS e SFTP sobre SSH.',['No FTP o observador lê a senha e o arquivo.','No FTPS vê só o nome do servidor e o tamanho dos registros.','No SFTP vê só pacotes cifrados na porta 22.'],[['A. FTP','tudo em claro','-'],['B. FTPS','AUTH TLS e PROT P','-'],['C. SFTP','subsistema do SSH','-']],'A tabela da aba Comparação mostra também conexões, portas, integridade e tempo.'),
  'k-put':doc('O mesmo upload nos três protocolos.','O arquivo sai do cliente. No FTP, o observador o reconstrói; nos outros dois, vê só bytes cifrados.',['No FTP o conteúdo também é legível.','O custo do TLS é de cerca de 1 RTT extra.'],[['A. FTP','upload em claro','-'],['B. FTPS','upload cifrado','-'],['C. SFTP','upload cifrado','-']],'O mesmo vale para quem envia arquivos sensíveis: o FTP simples não deve ser usado em redes não confiáveis.'),
  'k-list':doc('A mesma listagem nos três protocolos.','Até a listagem expõe nomes de arquivos. No FTP o observador lê o diretório; nos outros dois, não.',['No FTP a listagem aparece em vermelho.'],[['A. FTP','listagem em claro','-'],['B. FTPS','listagem cifrada','-'],['C. SFTP','listagem cifrada','-']],'Nomes de arquivos também podem ser informação sensível.')
};

function setup(s){
  const P=s.set||{}, p=[];
  if(s.sub==='ftp'||s.sub==='ftps'){
    if(s.sub==='ftps') p.push('FTPS '+(P.tlsMode==='implicit'?'implícito (990)':'explícito (AUTH TLS)'),'PROT '+P.prot);
    p.push('modo '+(P.mode==='active'?'ativo':'passivo'),'firewall: '+({none:'sem NAT nem filtro',nat:'NAT de estado',helper:'NAT com inspeção de FTP'}[P.cfw]),'faixa passiva '+(P.sfw===false?'bloqueada':'liberada'));
    if(P.cred&&P.cred!=='ok') p.push(P.cred==='bad'?'senha incorreta':'login anônimo');
  } else if(s.sub==='sftp') p.push('autenticação por '+(P.sauth==='key'?'chave pública':'senha'));
  p.push({get:'download',put:'upload',list:'listagem'}[P.op]);
  return p.join('; ');
}
function explain(tr,P,scen){
  const r=tr.raw, R=r.R;
  if(r.sub==='cmp'){
    const A=r.A,B=r.B,C=r.C;
    return '<p>Mesma ação ('+esc(r.opName)+') em três protocolos.</p><ul><li><b>FTP:</b> '+fmtMs(A.tEnd-A.t0)+', '+A.conns+' conexões e senha e arquivo legíveis.</li><li><b>FTPS:</b> '+fmtMs(B.tEnd-B.t0)+', '+B.conns+' conexões, tudo cifrado.</li><li><b>SFTP:</b> '+fmtMs(C.tEnd-C.t0)+', 1 conexão, tudo cifrado.</li></ul><p>O custo do TLS e do SSH é de poucos RTT; a diferença maior está no que o observador consegue ler e em quantas portas o firewall precisa tratar.</p>';
  }
  if(!R) return '';
  let h='<ul>';
  if(r.sub==='sftp') h+='<li>Uma conexão TCP na porta 22; o SFTP funciona como subsistema do SSH.</li><li>Tudo depois do NEWKEYS está cifrado e autenticado.</li>';
  else {
    h+='<li>Controle na porta '+(R.tls==='implicit'?'990':'21')+(R.ctrlEnc?', protegido por TLS':', em texto puro')+'.</li>';
    if(R.fail&&R.fail.stage==='cert') h+='<li><b>O cliente rejeitou o certificado</b> e nenhuma credencial foi enviada.</li>';
    else if(R.fail&&R.fail.stage==='auth') h+='<li>O login foi recusado (530). '+(R.credSeen?'A senha digitada já havia sido exposta.':'A senha trafegou cifrada.')+'</li>';
    else if(R.fail&&R.fail.stage==='data') h+='<li><b>O canal de dados falhou:</b> '+esc(R.why||'')+'.</li>';
    else h+='<li>O canal de dados foi aberto em modo '+(P.mode==='active'?'ativo':'passivo')+' e a operação terminou em '+fmtMs(R.tEnd-R.t0)+'.</li>';
    if(R.credSeen&&!(R.fail&&R.fail.stage==='cert')) h+='<li><span class="chk-bad">Usuário e senha</span> trafegam em texto puro.</li>';
    if(R.tls&&!(R.fail&&R.fail.stage==='cert')) h+='<li>O canal de dados '+(R.dataEnc?'é cifrado (PROT P).':'<span class="chk-bad">está em claro (PROT C)</span>: só o controle foi protegido.')+'</li>';
    if(!R.tls&&!R.fail) h+='<li><span class="chk-bad">O arquivo</span> também trafega em texto puro.</li>';
  }
  h+='</ul>';
  return h;
}
const REFERENCE=`<h3>Os três protocolos</h3>
<ul>
<li><b>FTP (RFC 959):</b> canal de controle na porta 21 e um canal de dados por transferência. Usuário, senha, comandos e arquivos viajam em texto puro.</li>
<li><b>FTPS (RFC 4217, com RFC 2228):</b> o FTP com TLS. No modo <b>explícito</b>, o cliente envia <code>AUTH TLS</code> na porta 21. No modo <b>implícito</b>, o TLS começa no primeiro byte, por convenção na porta 990 (não padronizado na RFC 4217). Os comandos <code>PBSZ 0</code> e <code>PROT P</code> ou <code>PROT C</code> escolhem se os dados também são cifrados.</li>
<li><b>SFTP:</b> não é "FTP sobre SSH". É um protocolo próprio de acesso a arquivos, que roda como subsistema do SSH (RFC 4251 a 4254) em uma única conexão na porta 22. A especificação é o rascunho do IETF <i>SSH File Transfer Protocol</i>; a versão 3 é a mais usada.</li>
</ul>
<h3>Modos de dados do FTP</h3>
<ul>
<li><b>Passivo (<code>PASV</code> ou <code>EPSV</code>, RFC 2428):</b> o servidor abre uma porta de uma faixa e o cliente conecta nela. É o modo que atravessa NAT e firewalls de estado, desde que a faixa de portas esteja liberada no servidor.</li>
<li><b>Ativo (<code>PORT</code> ou <code>EPRT</code>):</b> o cliente anuncia seu endereço e uma porta, e o <b>servidor</b> conecta, a partir da porta 20. Atrás de NAT, o endereço anunciado é privado e a conexão falha, a menos que um helper do firewall reescreva o comando.</li>
<li>O helper de FTP precisa ler o canal de controle. Com FTPS o canal é cifrado e o helper não consegue fazer isso.</li>
</ul>
<h3>Códigos de resposta</h3>
<table class="sc-msgs"><thead><tr><th>Código</th><th>Significado</th></tr></thead><tbody>
<tr><td>150</td><td class="meaning">arquivo OK, abrindo o canal de dados</td></tr>
<tr><td>200</td><td class="meaning">comando aceito</td></tr>
<tr><td>220</td><td class="meaning">servidor pronto</td></tr>
<tr><td>226</td><td class="meaning">transferência concluída</td></tr>
<tr><td>227 e 229</td><td class="meaning">modo passivo (PASV e EPSV)</td></tr>
<tr><td>230 e 530</td><td class="meaning">login aceito e login recusado</td></tr>
<tr><td>234</td><td class="meaning">AUTH TLS aceito</td></tr>
<tr><td>331</td><td class="meaning">usuário aceito, falta a senha</td></tr>
<tr><td>425</td><td class="meaning">não foi possível abrir o canal de dados</td></tr>
</tbody></table>
<h3>Hardening</h3>
<ul>
<li>Prefira SFTP. Se precisar de FTP, use FTPS explícito com TLS 1.2 ou superior e <b>PROT P</b>.</li>
<li>Em FTPS, use modo passivo com uma faixa de portas fixa, pequena e liberada no firewall.</li>
<li>Exija a validação do certificado no cliente e desative contas anônimas que não forem necessárias.</li>
<li>No SFTP, desative a senha e use chaves; considere restringir os usuários ao seu diretório (chroot) e desativar o shell.</li>
<li>Registre e limite tentativas de login (por exemplo, com fail2ban).</li>
</ul>
<h3>Limitações do simulador</h3>
<p>As chaves, os hashes e os conteúdos são ilustrativos. Os tempos são didáticos, o certificado e o TLS são simplificados e não há criptografia real.</p>`;

SS.register({
  id:'ftp',label:'FTP, FTPS e SFTP',stateTitle:'Estado da transferência',
  rfcs:[[959,'FTP'],[4217,'FTP sobre TLS'],[2428,'EPSV e EPRT'],[4253,'SSH (SFTP)']],
  subs:[{key:'ftp',label:'FTP',default:'f-pasv'},{key:'ftps',label:'FTPS',default:'s-exp'},{key:'sftp',label:'SFTP',default:'p-get'},{key:'cmp',label:'Comparação',default:'k-get'}],
  controls:[
    {id:'rtt',num:true,grp:'Rede',label:'RTT (ms)',type:'select',opts:[[5,'5'],[20,'20'],[50,'50'],[100,'100'],[200,'200']],def:20,help:{t:'RTT',s:'Tempo de ida e volta entre cliente e servidor.',p:['Cada comando FTP espera uma resposta, então o RTT pesa mais no FTP e no FTPS do que no SFTP, que agrupa pedidos.','O TLS acrescenta cerca de 1 RTT por conexão.']}},
    {id:'op',grp:'Operação',label:'Operação',type:'select',wide:true,opts:[['get','Baixar um arquivo (RETR / get)'],['put','Enviar um arquivo (STOR / put)'],['list','Listar o diretório (LIST / ls)']],def:'get',help:{t:'Operação',s:'O que o cliente faz depois do login.',p:['<b>Baixar</b> e <b>enviar</b> abrem um canal de dados no FTP e no FTPS.','<b>Listar</b> também usa o canal de dados: o diretório não vem pelo controle.']}},
    {id:'cred',subs:['ftp','ftps'],grp:'Autenticação',label:'Login',type:'select',wide:true,opts:[['ok','Usuário e senha válidos'],['anon','Acesso anônimo (anonymous)'],['bad','Senha incorreta']],def:'ok',help:{t:'Login',s:'Resultado da autenticação no servidor.',p:['<b>Válidos:</b> o login funciona (230).','<b>Anônimo:</b> usuário anonymous e e-mail como senha.','<b>Incorreta:</b> o servidor responde 530. A senha, mesmo errada, pode já ter sido exposta.']}},
    {id:'mode',subs:['ftp','ftps'],grp:'Canal de dados',label:'Modo de dados',type:'select',wide:true,opts:[['passive','Passivo (PASV): o cliente conecta'],['active','Ativo (PORT): o servidor conecta']],def:'passive',help:{t:'Modo de dados',s:'Quem abre a conexão de dados.',p:['<b>Passivo:</b> o cliente conecta a uma porta alta do servidor; atravessa NAT de estado.','<b>Ativo:</b> o servidor conecta ao cliente, a partir da porta 20; costuma falhar atrás de NAT.']}},
    {id:'cfw',subs:['ftp','ftps'],grp:'Canal de dados',label:'Firewall/NAT do cliente',type:'select',wide:true,opts:[['none','Sem NAT nem filtro'],['nat','NAT com firewall de estado'],['helper','NAT com inspeção de FTP (helper)']],def:'nat',help:{t:'Firewall/NAT do cliente',s:'O que existe entre o cliente e a internet.',p:['<b>Sem NAT nem filtro:</b> conexões de entrada passam.','<b>NAT de estado:</b> só aceita respostas de conexões iniciadas de dentro.','<b>Helper de FTP:</b> lê o PORT e abre a porta, mas só se o controle estiver em claro.']}},
    {id:'sfw',subs:['ftp','ftps'],grp:'Canal de dados',label:'Faixa passiva liberada no servidor',type:'check',def:true,help:{t:'Faixa passiva',s:'Firewall do servidor.',p:['No modo passivo o servidor escolhe uma porta de uma faixa. Se o firewall dele não a liberar, o SYN do cliente fica sem resposta.']}},
    {id:'tlsMode',subs:['ftps'],grp:'TLS',label:'Modo FTPS',type:'select',wide:true,opts:[['explicit','Explícito (AUTH TLS, porta 21)'],['implicit','Implícito (porta 990)']],def:'explicit',help:{t:'Modo FTPS',s:'Como o TLS é iniciado.',p:['<b>Explícito:</b> começa em claro na porta 21 e passa a TLS com AUTH TLS.','<b>Implícito:</b> TLS desde o primeiro byte, na porta 990 (modo legado).']}},
    {id:'prot',subs:['ftps'],grp:'TLS',label:'Proteção dos dados (PROT)',type:'select',wide:true,opts:[['P','P: dados cifrados'],['C','C: dados em claro']],def:'P',help:{t:'PROT',s:'Nível de proteção do canal de dados.',p:['<b>P (Private):</b> o canal de dados usa TLS.','<b>C (Clear):</b> só o controle é cifrado e o arquivo trafega em claro.']}},
    {id:'certOk',subs:['ftps'],grp:'TLS',label:'Certificado do servidor válido',type:'check',def:true,help:{t:'Certificado',s:'Validação pelo cliente.',p:['Desmarcado, o cliente rejeita o certificado e encerra antes de enviar usuário e senha.']}},
    {id:'sauth',subs:['sftp'],grp:'SSH',label:'Autenticação',type:'select',wide:true,opts:[['password','Senha'],['key','Chave pública']],def:'password',help:{t:'Autenticação SSH',s:'Como o cliente se autentica.',p:['<b>Senha:</b> vai dentro do túnel cifrado.','<b>Chave pública:</b> o cliente assina um desafio, sem enviar segredo.']}}
  ],
  scenarios:SCENARIOS,groupDoc:GROUP_DOC,scenDoc:SCEN_DOC,tabs:[TAB_PORTS,TAB_OBS,TAB_CMP],
  stageTitle:sub=>({ftp:'Diagrama de sequência: sessão FTP (controle e dados)',ftps:'Diagrama de sequência: sessão FTP sobre TLS',sftp:'Diagrama de sequência: sessão SFTP (SSH, porta 22)',cmp:'Diagrama de sequência: a mesma ação em FTP (A), FTPS (B) e SFTP (C), com um observador na rede'})[sub],
  build:(P,sub)=>sub==='cmp'?simCompare(P):(sub==='sftp'?simSftp(P):simFtp(P,sub)),
  explain:explain,reference:REFERENCE,setup:setup
});
})();
