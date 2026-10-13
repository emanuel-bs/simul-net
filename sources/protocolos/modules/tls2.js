(function(){
'use strict';
const SS=window.SecureSim, T=window.__TLS, C0=SS.COLORS, hex=SS.hex, b64=SS.b64;
const {CPROF,SPROF,ORDER,compat,hasFS,isWeakSuite,weakVer,ALERT,SNI,certChecks,certAlert,BROWSER_ERR}=T;
const STATES=[{key:'phase',label:'Fase'},{key:'proto',label:'Versão e cifra'},{key:'host',label:'Servidor autenticado'},{key:'fs',label:'Sigilo futuro'},{key:'client',label:'Cliente autenticado'}];
const WSTATES=[{key:'phase',label:'Fase'},{key:'hsts',label:'HSTS'},{key:'chan',label:'Canal'},{key:'host',label:'Servidor autenticado'}];

function mkTrace(P,ocsp,states){
  const cols=[{key:'c',label:'Navegador',sub:'192.168.1.20',addr:'192.168.1.20'},{key:'s',label:'Servidor HTTPS',sub:'203.0.113.80:443',addr:'203.0.113.80'}];
  if(ocsp) cols.push({key:'o',label:'CA (responder OCSP)',sub:'ocsp.exampleca.org',addr:'198.51.100.9'});
  return SS.newTrace(cols,states||STATES,P.rtt);
}
const lines=a=>a.join(', ');

// ---------- Ferramentas de mensagem ----------
function toolkit(tr,P){
  const state={phase:'TCP',ver:'TLSv1.3'};
  const who=f=>f==='c'?'Client':'Server';
  const recSec=(type,tname,ver,len)=>[{sec:'TLS Record Layer'},['Content type',type+' ('+tname+')',''],['Version',ver,'campo de compatibilidade; a versão real vai na extensão supported_versions (TLS 1.3)'],['Length',len+' bytes','']];
  const plain=(from,to,label,hsNum,fields,o)=>{ o=o||{}; const len=o.len||200;
    return tr.add(from,to,Object.assign({label:label,color:C0.plain,proto:o.proto||state.ver,len:len,info:o.info||who(from)+': '+label,phaseName:state.phase,about:''},o,{fields:recSec(o.ctype||22,o.cname||'Handshake',o.rver||'0x0303 (TLS 1.2)',len-40).concat(hsNum?[{sec:'Handshake: '+label+' (tipo '+hsNum+')'}]:[],fields||[]).concat([['Cifrado?','não','trafega em claro: qualquer observador lê','']]).filter(x=>true)})); };
  const enc=(from,to,label,fields,o)=>{ o=o||{}; const len=o.len||200, t13=state.ver==='TLSv1.3';
    return tr.add(from,to,Object.assign({label:label,color:o.data?C0.data:(o.bad?C0.bad:C0.enc),enc:true,proto:o.proto||state.ver,len:len,info:o.info||(t13?'Application Data':who(from)+': Encrypted Handshake Message'),phaseName:state.phase,about:''},o,
      {fields:[{sec:'TLS Record Layer (o que aparece no fio)'},['Content type',t13?'23 (Application Data)':'22 (Handshake, cifrado)',t13?'no TLS 1.3 todo registro protegido aparece como Application Data; o tipo real vai cifrado':'conteúdo cifrado depois do ChangeCipherSpec'],['Length',(len-40)+' bytes',''],['Encrypted Application Data','cifrado','ilegível sem as chaves de tráfego'],{sec:'Nas pontas (depois de decifrar)'}].concat(fields||[])})); };
  const tcp=(from,to,label,flags,o)=>tr.add(from,to,Object.assign({label:label,proto:'TCP',color:C0.tcp,len:40,info:(from==='c'?'50122 → 443':'443 → 50122')+' ['+flags+']',phaseName:'TCP',fields:[{sec:'TCP (RFC 9293)'},['Flags',flags,'']],about:'Segmento TCP: o TLS roda sobre uma conexão TCP comum, na porta 443.'},o));
  const closeTcp=by=>{ const o=by==='c'?'s':'c'; tcp(by,o,'FIN, ACK','FIN, ACK',{}); tcp(o,by,'FIN, ACK','FIN, ACK',{}); tcp(by,o,'ACK','ACK',{}); };
  return {state:state,plain:plain,enc:enc,tcp:tcp,closeTcp:closeTcp,who:who};
}

// ---------- Handshake TLS completo (RFC 8446 e RFC 5246) ----------
function runTls(tr,P,o){
  const K=toolkit(tr,P), C=CPROF[P.cProf], S=SPROF[P.sProf], raw=tr.raw, kt=P.keyType, sub=o.sub;
  const {plain,enc,tcp,closeTcp,state}=K;
  const phase=(label,key,short)=>{ state.phase=short; tr.phase(label,key); };
  const ow=tr.ow, ocsp=!!o.ocsp;
  raw.tls={ver:null,suite:null,fs:false,alpn:'http/1.1',downgrade:false,mode:o.mode||'full',fail:null,cert:null,keys:null,early:false};
  const R=raw.tls;
  let mode=o.mode||'full';
  // versão e cifra
  let ver=ORDER.find(v=>C.vers.includes(v)&&S.vers.includes(v));
  if(P.downgrade&&sub==='handshake'&&C.vers.includes('TLS 1.3')&&S.vers.includes('TLS 1.3')){ ver='TLS 1.2'; R.downgrade=true; }
  let suite=null;
  if(ver==='TLS 1.3') suite=C.s13.find(x=>S.s13.includes(x)); else if(ver) suite=C.s12.find(x=>S.s12.includes(x)&&compat(x,kt));
  if(mode==='zero'&&ver!=='TLS 1.3'){ mode='resume'; R.zeroUnavailable=true; }
  R.mode=mode;
  const is13=ver==='TLS 1.3';
  state.ver=ver?'TLSv'+ver.slice(4):'TLSv'+C.vers[0].slice(4);
  const alpn=(P.sProf!=='legado'&&C.vers.indexOf('TLS 1.2')>=0)?'h2':'http/1.1'; R.alpn=alpn;
  const RQ=o.req||null;
  const reqLabel=(RQ?(alpn==='h2'?'HTTP/2 ':'')+RQ.label:(alpn==='h2'?'HTTP/2 GET /':'GET / HTTP/1.1'));
  const reqData=RQ?RQ.data:(alpn==='h2'?'HEADERS: :method GET, :path /, :authority '+SNI:'GET / HTTP/1.1, Host: '+SNI);
  const respData=(o.resp||'resposta com HTML')+(o.hsts?', Strict-Transport-Security':'');
  // Um equipamento no caminho altera a resposta: o registro falha na verificação de autenticidade (AEAD).
  const tamperEnd=resp=>{
    resp.color=C0.bad; resp.label+=' (alterada no caminho)'; resp.tags.push('adulterada: a tag de autenticação AEAD não confere');
    R.fail={stage:'tamper',what:'integrity',alert:'bad_record_mac'};
    tr.ev(resp.tArr,'c','Tag de autenticação inválida: o registro é descartado','warn');
    tr.lg(resp.tArr,'O registro foi alterado no caminho: a verificação de autenticidade (AEAD) falha e o navegador não exibe a página.','loss');
    tr.st(tr.t,'phase','Falhou','bad');
    enc('c','s','Alert: bad_record_mac (fatal)',[['Alert description','20 (bad_record_mac)','o registro recebido não confere com a sua tag de autenticação']],{bad:true,len:80,info:'Application Data',about:'O navegador descarta o registro adulterado e encerra a conexão. A alteração é detectada, ao contrário do HTTP.'});
    closeTcp('c'); tr.mile(tr.t,'Adulteração detectada','bad_record_mac'); tr.st(tr.t,'phase','Encerrada','bad');
    return R;
  };
  const clientRandom=hex('cr'+P.cProf,32), serverRandom=hex('sr'+P.sProf+ver,32);
  const keyShare=hex('ks'+P.cProf,32), serverShare=hex('ss'+P.sProf,32);
  const chFields=[['legacy_version','0x0303 (TLS 1.2)','valor legado; o TLS 1.3 usa a extensão supported_versions'],['random',clientRandom,'32 bytes aleatórios'],['cipher_suites',lines(C.s13.concat(C.s12)),'lista do cliente, em ordem de preferência',C.s12.concat(C.s13).some(isWeakSuite)?'expert':''],['compression_methods','null (0)',''],
    ['Extensão: server_name (SNI)',SNI,'o nome do site vai em claro: quem observa a rede vê QUAL site é acessado (ECH esconderia)','expert'],['Extensão: supported_versions',lines(C.vers),weakVer(C.vers[0])?'só versões obsoletas':'versões que o cliente aceita'],
    ['Extensão: supported_groups','x25519, secp256r1',''],['Extensão: signature_algorithms','ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256','assinaturas aceitas para o certificado'],['Extensão: ALPN',(C.vers.indexOf('TLS 1.2')>=0?'h2, ':'')+'http/1.1','protocolo de aplicação'],['Extensão: status_request','OCSP','pede a resposta de revogação grampeada']];
  if(C.vers.indexOf('TLS 1.3')>=0) chFields.splice(7,0,['Extensão: key_share','x25519: '+keyShare.slice(0,32)+'…','metade pública do ECDHE já no primeiro pacote: por isso o TLS 1.3 gasta 1 RTT']);
  if(mode!=='full'&&C.vers.indexOf('TLS 1.3')>=0) chFields.push(['Extensão: pre_shared_key','identidade = ticket da conexão anterior','chave pré-compartilhada vinda do NewSessionTicket'],['Extensão: psk_key_exchange_modes','psk_dhe_ke','mantém o sigilo futuro na retomada']);
  if(mode==='zero') chFields.push(['Extensão: early_data','presente','o cliente enviará dados antes de terminar o handshake','expert']);
  if(mode!=='full'&&!is13) chFields.push(['Extensão: session_ticket','ticket da sessão anterior','retomada da sessão sem novo handshake completo']);
  const clientHelloAbout='O primeiro pacote do TLS: versões, cifras, extensões e (no TLS 1.3) a metade pública do ECDHE. O nome do site (SNI) vai em claro, mesmo no TLS 1.3, a menos que o ECH seja usado.';
  phase('1. Handshake TLS: ClientHello','hello','ClientHello');
  tr.st(tr.t,'phase','ClientHello','warn'); tr.st(tr.t,'proto','em negociação','closed'); tr.st(tr.t,'host','não verificado','closed'); tr.st(tr.t,'fs','-','closed'); tr.st(tr.t,'client','não','closed');
  tr.mile(tr.t,'Handshake','ClientHello');
  const ch=plain('c','s','Client Hello',1,chFields,{len:517,info:'Client: Client Hello (SNI='+SNI+')',about:clientHelloAbout});
  if(!ver||!suite){
    const al=!ver?'protocol_version':'handshake_failure';
    R.fail={stage:'neg',what:!ver?'version':'suite',alert:al};
    tr.ev(tr.t,'s',!ver?'Nenhuma versão de TLS em comum: '+lines(C.vers)+' contra '+lines(S.vers):'Nenhuma cifra em comum compatível com o certificado '+(kt==='ecdsa'?'ECDSA':'RSA'),'warn');
    tr.st(tr.t,'phase','Falhou','bad');
    plain('s','c','Alert: '+al+' (fatal)',null,[['Alert level','2 (fatal)',''],['Alert description',ALERT[al][0]+' ('+al+')','o servidor recusa a negociação']],{ctype:21,cname:'Alert',color:C0.bad,len:70,info:'Server: Alert ('+al+')',about:'O servidor encerra a conexão com um alerta fatal. Em alertas antes do ServerHello, nada está cifrado.'});
    tr.lg(tr.t,(!ver?'Sem versão em comum':'Sem cifra em comum')+': o servidor envia o alerta '+al+' e fecha a conexão.','loss');
    closeTcp('s'); tr.mile(tr.t,'Falhou','alerta '+al); tr.st(tr.t,'phase','Encerrada','bad');
    return R;
  }
  R.ver=ver; R.suite=suite; R.fs=hasFS(suite);
  const tName=ver; const verNum=({'TLS 1.3':'0x0304','TLS 1.2':'0x0303','TLS 1.1':'0x0302','TLS 1.0':'0x0301'})[ver];
  tr.lg(ch.tSend,'ClientHello: '+lines(C.vers)+'; SNI '+SNI+(mode==='full'?'':'; retomada com ticket')+'.','conn');
  let early=null;
  if(mode==='zero'){ R.early=true;
    early=enc('c','s','GET / (0-RTT, dados antecipados)',[['Dados',alpn==='h2'?'HEADERS: GET /':'GET / HTTP/1.1','requisição enviada antes de o handshake terminar'],['Chave','early traffic secret (do ticket)','derivada do PSK, não do ECDHE novo: sem sigilo futuro para estes dados']],{data:true,at:ch.tSend+0.2,len:260,info:'Application Data (0-RTT)',about:'Os dados 0-RTT saem junto com o ClientHello, protegidos pela chave do ticket. O custo: o servidor não consegue distinguir um envio novo de uma repetição feita por um atacante (replay), e esses dados não têm sigilo futuro.'});
    early.tags.push('0-RTT: sujeito a replay; use só em requisições idempotentes');
    tr.ev(early.tSend,'c','Envia a requisição no primeiro voo, sem esperar o servidor','warn');
  }
  // ----- TLS 1.3 -----
  if(is13){
    phase('2. ServerHello e chaves de handshake','sh','ServerHello');
    tr.st(tr.t,'phase','ServerHello','warn'); tr.mile(tr.t,'ServerHello','chaves de handshake');
    const shFields=[['legacy_version','0x0303 (TLS 1.2)',''],['random',serverRandom,'32 bytes aleatórios do servidor'],['cipher_suite',suite,'escolhida entre as do cliente'],['Extensão: supported_versions',verNum+' (TLS 1.3)','a versão real negociada'],['Extensão: key_share','x25519: '+serverShare.slice(0,32)+'…','metade pública do servidor: com ela os dois calculam o segredo ECDHE']];
    if(mode!=='full') shFields.push(['Extensão: pre_shared_key','identidade 0','o servidor aceitou o ticket']);
    const sh=plain('s','c','Server Hello',2,shFields,{len:127,info:'Server: Server Hello, Change Cipher Spec',about:'O servidor escolhe versão e cifra e envia sua metade do ECDHE. A partir daqui, as duas pontas derivam as chaves de handshake (HKDF) e tudo o que segue vai cifrado, inclusive o certificado.'});
    const ecdhe=hex('ecdhe'+P.cProf+P.sProf,32), hsC=hex('chs'+ecdhe,32), hsS=hex('shs'+ecdhe,32), apC=hex('cap'+ecdhe,32), apS=hex('sap'+ecdhe,32);
    tr.ev(sh.tSend,'s','Calcula o segredo ECDHE e as chaves de handshake (HKDF)','');
    tr.ev(sh.tArr,'c','Chaves de handshake derivadas: o resto do handshake vai cifrado','ok');
    tr.lg(sh.tArr,'ServerHello: '+ver+', '+suite+'. Chaves de handshake derivadas do segredo ECDHE (x25519).','cc');
    tr.st(tr.t,'proto',ver+' / '+suite.replace('TLS_',''),'est'); tr.st(tr.t,'fs','sim (ECDHE)','est');
    R.keys={kind:'1.3',kex:'x25519',ecdhe:ecdhe,tHs:sh.tArr,hsC:hsC,hsS:hsS,apC:apC,apS:apS,tApp:0};
    // voo cifrado do servidor
    const certMsg=mode==='full';
    const flFields=[['EncryptedExtensions','ALPN: '+alpn+(mode==='zero'?', early_data aceito':''),'extensões que não precisam ir em claro']];
    if(P.mtls) flFields.push(['CertificateRequest','certificado de cliente solicitado','mTLS: o servidor quer autenticar o cliente']);
    if(certMsg) flFields.push(['Certificate','cadeia de 3 certificados: '+SNI+' (leaf), Example CA R3 (intermediário), Example Root CA X1 (raiz)','a identidade do servidor, agora cifrada (no TLS 1.2 ia em claro)'],['CertificateVerify','assinatura '+(kt==='ecdsa'?'ecdsa_secp256r1_sha256':'rsa_pss_rsae_sha256')+' do hash da conversa','prova que o servidor tem a chave privada do certificado'],);
    flFields.push(['Finished','HMAC de toda a conversa','confirma que nada foi alterado no handshake']);
    const fl=enc('s','c',certMsg?'EncryptedExtensions, Certificate, CertificateVerify, Finished':'EncryptedExtensions, Finished',flFields,{at:sh.tSend+0.2,len:certMsg?(kt==='ecdsa'?2600:3700):160,info:'Application Data, Application Data, Application Data',about:certMsg?'O servidor prova quem é: envia o certificado e assina o hash da conversa (CertificateVerify). O Finished confirma a integridade do handshake.':'Na retomada não há certificado nem assinatura: o ticket (PSK) já autentica a sessão.'});
    R.tCert=fl.tArr;
    let respEarly=null;
    if(mode==='zero'){ respEarly=enc('s','c','HTTP/2 200 OK (0,5-RTT)',[['Dados','resposta ao pedido 0-RTT','o servidor já pode responder antes do Finished do cliente']],{data:true,at:fl.tSend+0.3,len:900,info:'Application Data',about:'O servidor responde ao pedido 0-RTT antes de receber o Finished do cliente.'}); tr.ev(fl.tSend,'s','0-RTT aceito: pode ser um replay, o servidor não tem como saber','warn'); }
    tr.t=Math.max(fl.tArr,respEarly?respEarly.tArr:0)+0.4;
    // validação do certificado
    if(certMsg&&o.cert){
      const cc=certChecks(P); R.cert=cc;
      tr.ev(fl.tArr,'c','Valida o certificado do servidor: cadeia, validade, nome, revogação','');
      let failed=false;
      const needOcsp=ocsp&&cc.ok||ocsp&&P.certState==='revoked';
      if(!cc.ok&&P.certState!=='revoked'){ failed=true; }
      if(P.certState==='revoked'&&P.stapling&&!ocsp) failed=true;
      if(!failed&&ocsp){ // consulta OCSP direta à CA
        const rq=plain('c','o','OCSP request',null,[['serial do certificado',hex('serial',10),'identifica o certificado; a CA aprende qual site você visita','expert'],['Protocolo','HTTP na porta 80 (em claro)','o pedido não vai pelo canal TLS']],{proto:'OCSP',ctype:0,cname:'-',len:220,info:'OCSP Request',phaseName:'OCSP',at:tr.t,about:'Sem stapling, o navegador pergunta à CA se o certificado foi revogado. Isso custa 1 RTT e revela à CA o site visitado.'});
        tr.t=rq.tArr+0.4;
        const rs=plain('o','c','OCSP response: '+(P.certState==='revoked'?'revoked':'good'),null,[['certStatus',P.certState==='revoked'?'revoked':'good',''],['thisUpdate / nextUpdate','válida por 7 dias','']],{proto:'OCSP',ctype:0,cname:'-',len:480,color:P.certState==='revoked'?C0.bad:C0.plain,info:'OCSP Response ('+(P.certState==='revoked'?'revoked':'good')+')',about:'A resposta da CA, assinada. Se vier "revoked", o navegador recusa o certificado.',at:tr.t});
        tr.t=rs.tArr+0.4;
        if(P.certState==='revoked') failed=true;
      }
      if(P.stapling&&!ocsp&&cc.ok) tr.ev(tr.t,'c','OCSP stapling: a resposta "good" veio junto com o certificado','ok');
      if(failed){
        const al=certAlert(P.certState); R.fail={stage:'cert',what:P.certState,alert:al,browser:BROWSER_ERR[P.certState],check:cc.failed||'Revogação (OCSP ou CRL)'};
        tr.ev(tr.t,'c','Falha: '+R.fail.check+'. O navegador mostra '+R.fail.browser,'warn');
        tr.st(tr.t,'host','RECUSADO','bad'); tr.st(tr.t,'phase','Falhou','bad');
        tr.lg(tr.t,'Validação do certificado falhou ('+R.fail.check+'). O cliente envia o alerta '+al+' e fecha a conexão.','loss');
        enc('c','s','Alert: '+al+' (fatal)',[['Alert level','2 (fatal)',''],['Alert description',ALERT[al][0]+' ('+al+')','o cliente recusa o certificado']],{bad:true,len:80,info:'Application Data',about:'O cliente aborta o handshake. Aqui o alerta ainda vai cifrado com as chaves de handshake. Nenhum dado da aplicação foi enviado.'});
        closeTcp('c'); tr.mile(tr.t,'Recusado','certificado'); tr.st(tr.t,'phase','Encerrada','bad');
        return R;
      }
      tr.ev(tr.t,'c','Certificado válido: o servidor é quem diz ser ('+SNI+')','ok');
      tr.st(tr.t,'host','verificado (certificado)','est');
    } else if(!certMsg) tr.st(tr.t,'host','verificado (ticket)','est');
    else tr.st(tr.t,'host','verificado','est');
    phase('3. Finished e dados da aplicação','fin','Dados');
    tr.st(tr.t,'phase','Estabelecida','est'); tr.mile(tr.t,'Estabelecida','Finished');
    const cf=enc('c','s',P.mtls?'Certificate, CertificateVerify, Finished':(mode==='zero'?'EndOfEarlyData, Finished':'Finished'),
      (P.mtls?[['Certificate','certificado do cliente (CN=aluno01)','o cliente se identifica'],['CertificateVerify','assinatura do hash da conversa','prova a posse da chave do certificado de cliente']]:[]).concat(mode==='zero'?[['EndOfEarlyData','fim dos dados 0-RTT','']]:[],[['Finished','HMAC da conversa','confirma o handshake do lado do cliente']]),{len:P.mtls?1800:100,info:'Change Cipher Spec, Application Data',about:'O cliente confirma o handshake. No TLS 1.3 já pode enviar dados junto: o handshake custa 1 RTT.'});
    if(P.mtls){ tr.ev(cf.tArr,'s','Valida o certificado do cliente contra a CA de clientes','ok'); tr.st(tr.t,'client','autenticado (mTLS)','est'); }
    R.keys.tApp=cf.tSend; tr.ev(cf.tSend,'c','Chaves de aplicação derivadas: dados protegidos com chaves novas','ok');
    let req=null;
    if(mode!=='zero'){ req=enc('c','s',reqLabel,[['Dados',reqData,'requisição HTTP dentro do TLS'],['Cookie','sessionid=…','só trafega depois do handshake, cifrado']],{data:true,at:cf.tSend+0.2,len:240,info:'Application Data',about:'A requisição HTTP vai cifrada. Cabeçalhos e cookies ficam protegidos de quem observa a rede.'}); }
    tr.t=Math.max(cf.tArr,req?req.tArr:0)+0.4;
    const resp=mode==='zero'?null:enc('s','c',(alpn==='h2'?'HTTP/2 200 OK':'HTTP/1.1 200 OK'),[['Dados',respData,'']],{data:true,len:1400,info:'Application Data',about:'A resposta HTTP, cifrada.'});
    if(o.tamper&&resp) return tamperEnd(resp);
    const tk=enc('s','c','NewSessionTicket',[['ticket','válido por 7200 s','permite retomar sem novo certificado (PSK)'],['max_early_data_size','16384','0-RTT permitido nos próximos acessos']],{at:(resp||cf).tSend+0.2,len:260,info:'Application Data',about:'Depois do handshake, o servidor entrega um ticket para as próximas conexões. É o que viabiliza a retomada e o 0-RTT.'});
    tr.t=Math.max(tk.tArr,resp?resp.tArr:0)+0.4;
    tr.lg(cf.tSend,'Handshake concluído em 1 RTT (TLS 1.3). Dados protegidos pelas chaves de aplicação.','conn');
  } else {
    // ----- TLS 1.2 e anteriores -----
    const rsaKt=/^TLS_RSA/.test(suite), pv=state.ver;
    phase('2. ServerHello, certificado e troca de chaves (em claro)','sh','ServerHello');
    tr.st(tr.t,'phase','ServerHello','warn'); tr.mile(tr.t,'ServerHello',ver);
    const sentinel=R.downgrade?serverRandom.slice(0,48)+'444f574e47524401':serverRandom;
    const sh=plain('s','c','Server Hello',2,[['version',verNum+' ('+ver+')',''],['random',sentinel,R.downgrade?'termina em 44 4F 57 4E 47 52 44 01 ("DOWNGRD"): o servidor suporta TLS 1.3 mas foi forçado ao 1.2':'32 bytes aleatórios do servidor',R.downgrade?'expert':''],['cipher_suite',suite,isWeakSuite(suite)?'cifra fraca':'escolhida entre as do cliente',isWeakSuite(suite)?'expert':''],['Extensão: ALPN',alpn,'']],{len:112,info:'Server: Server Hello',about:'O servidor escolhe a versão e a cifra. No TLS 1.2 e anteriores, tudo o que vem a seguir (inclusive o certificado) trafega em claro.'});
    if(R.downgrade){
      R.fail={stage:'downgrade',what:'sentinel',alert:'illegal_parameter'};
      tr.ev(sh.tArr,'c','O ServerHello (TLS 1.2) traz o sentinela DOWNGRD: o cliente suporta 1.3 e conclui que houve downgrade','warn');
      tr.st(tr.t,'phase','Falhou','bad'); tr.lg(tr.t,'Downgrade detectado: o random do ServerHello termina em "DOWNGRD". O cliente aborta com illegal_parameter.','loss');
      plain('c','s','Alert: illegal_parameter (fatal)',null,[['Alert level','2 (fatal)',''],['Alert description','47 (illegal_parameter)','o cliente detectou a tentativa de rebaixar a versão']],{ctype:21,cname:'Alert',bad:true,color:C0.bad,len:70,info:'Client: Alert (illegal_parameter)',about:'A proteção contra downgrade do TLS 1.3 (RFC 8446, seção 4.1.3): o cliente que suporta 1.3 recusa um ServerHello 1.2 com o sentinela.'});
      closeTcp('c'); tr.mile(tr.t,'Downgrade detectado','alerta illegal_parameter'); tr.st(tr.t,'phase','Encerrada','bad');
      return R;
    }
    tr.st(tr.t,'proto',ver+' / '+suite,isWeakSuite(suite)||weakVer(ver)?'warn':'est'); tr.st(tr.t,'fs',R.fs?'sim (ECDHE)':'NÃO (RSA)',R.fs?'est':'bad');
    let fl;
    if(mode==='full'){
      const fields=[['Certificate','cadeia de 3 certificados: '+SNI+', Example CA R3, Example Root CA X1','o certificado vai EM CLARO: quem observa a rede o lê','expert']];
      if(!rsaKt) fields.push(['Server Key Exchange','ECDHE '+(kt==='ecdsa'?'x25519':'secp256r1')+' + assinatura','parâmetros efêmeros assinados com a chave do certificado']);
      if(P.mtls) fields.push(['Certificate Request','certificado de cliente solicitado','mTLS']);
      fields.push(['Server Hello Done','','fim do voo do servidor']);
      fl=plain('s','c','Certificate'+(rsaKt?'':', Server Key Exchange')+(P.mtls?', Certificate Request':'')+', Server Hello Done',11,fields,{at:sh.tSend+0.2,len:kt==='ecdsa'?2200:3300,info:'Server: Certificate, '+(rsaKt?'':'Server Key Exchange, ')+'Server Hello Done',about:'O servidor envia o certificado em claro e, em suítes ECDHE, os parâmetros efêmeros assinados.'});
      tr.t=fl.tArr+0.4; R.tCert=fl.tArr;
      const cc=certChecks(P); R.cert=cc;
      if(o.cert){
        tr.ev(fl.tArr,'c','Valida o certificado do servidor: cadeia, validade, nome, revogação','');
        let failed=!cc.ok&&P.certState!=='revoked';
        if(P.certState==='revoked'&&P.stapling&&!ocsp) failed=true;
        if(!failed&&ocsp){
          const rq=plain('c','o','OCSP request',null,[['serial do certificado',hex('serial',10),'a CA aprende qual site você visita','expert']],{proto:'OCSP',len:220,info:'OCSP Request',phaseName:'OCSP',about:'Consulta de revogação à CA.'}); tr.t=rq.tArr+0.4;
          const rs=plain('o','c','OCSP response: '+(P.certState==='revoked'?'revoked':'good'),null,[['certStatus',P.certState==='revoked'?'revoked':'good','']],{proto:'OCSP',len:480,color:P.certState==='revoked'?C0.bad:C0.plain,info:'OCSP Response',about:'Resposta da CA.'}); tr.t=rs.tArr+0.4;
          if(P.certState==='revoked') failed=true;
        }
        if(failed){
          const al=certAlert(P.certState); R.fail={stage:'cert',what:P.certState,alert:al,browser:BROWSER_ERR[P.certState],check:cc.failed||'Revogação (OCSP ou CRL)'};
          tr.ev(tr.t,'c','Falha: '+R.fail.check+'. O navegador mostra '+R.fail.browser,'warn'); tr.st(tr.t,'host','RECUSADO','bad'); tr.st(tr.t,'phase','Falhou','bad');
          tr.lg(tr.t,'Validação do certificado falhou ('+R.fail.check+'). Alerta '+al+'.','loss');
          plain('c','s','Alert: '+al+' (fatal)',null,[['Alert level','2 (fatal)',''],['Alert description',ALERT[al][0]+' ('+al+')','']],{ctype:21,cname:'Alert',bad:true,color:C0.bad,len:70,info:'Client: Alert ('+al+')',about:'No TLS 1.2 o alerta antes do ChangeCipherSpec vai em claro.'});
          closeTcp('c'); tr.mile(tr.t,'Recusado','certificado'); tr.st(tr.t,'phase','Encerrada','bad'); return R;
        }
        tr.ev(tr.t,'c','Certificado válido: o servidor é quem diz ser ('+SNI+')','ok'); tr.st(tr.t,'host','verificado (certificado)','est');
      }
      phase('3. Troca de chaves do cliente e Finished','cke','Troca de chaves');
      tr.st(tr.t,'phase','Troca de chaves','warn'); tr.mile(tr.t,'Troca de chaves',rsaKt?'RSA':'ECDHE');
      const cke=plain('c','s','Client Key Exchange',16,rsaKt?[['EncryptedPreMasterSecret',hex('pms',24)+'…','o segredo é cifrado com a chave pública RSA do servidor: SEM sigilo futuro','expert']]:[['Pubkey (ponto EC)',hex('cke'+P.cProf,32)+'…','metade pública do ECDHE']],{len:150,info:'Client: Client Key Exchange',about:rsaKt?'Na troca de chaves por RSA, o cliente envia o pre-master secret cifrado com a chave pública do servidor. Quem gravar o tráfego hoje e obtiver a chave privada um dia decifra tudo (sem sigilo futuro).':'O cliente envia sua metade do ECDHE. O segredo é calculado nas pontas e nunca trafega.'});
      if(rsaKt) cke.tags.push('sem sigilo futuro: o segredo viaja cifrado pela chave do servidor');
      const cfin=plain('c','s','Change Cipher Spec, Finished',20,[['Change Cipher Spec','1','a partir daqui o cliente cifra'],['Finished (cifrado)','verify_data','confirma o handshake']],{at:cke.tSend+0.2,len:100,info:'Client: Change Cipher Spec, Encrypted Handshake Message',ctype:20,cname:'Change Cipher Spec',about:'O cliente liga a cifragem e confirma o handshake.'});
      cfin.color=C0.enc; cfin.enc=true;
      R.keys={kind:'1.2',kex:rsaKt?'RSA':'ECDHE',pms:hex('pms'+P.cProf,32),ms:hex('ms'+P.cProf+P.sProf,48),tMs:cfin.tSend,block:hex('kb'+P.cProf+P.sProf,40)};
      tr.t=cfin.tArr+0.4;
      const sfin=enc('s','c','New Session Ticket, Change Cipher Spec, Finished',[['NewSessionTicket','ticket de sessão','permite retomar a sessão'],['Finished','verify_data','confirma o handshake do lado do servidor']],{len:360,info:'Server: New Session Ticket, Change Cipher Spec, Encrypted Handshake Message',about:'O servidor também liga a cifragem e confirma.'});
      tr.t=sfin.tArr+0.4;
    } else {
      fl=enc('s','c','Change Cipher Spec, Finished',[['Change Cipher Spec','1','a sessão é retomada com o ticket'],['Finished','verify_data','']],{at:sh.tSend+0.2,len:120,info:'Server: Change Cipher Spec, Encrypted Handshake Message',about:'Na retomada, o servidor aceita o ticket e vai direto ao Finished: sem certificado nem troca de chaves.'});
      tr.t=fl.tArr+0.4; tr.st(tr.t,'host','verificado (ticket)','est');
      const cfin=enc('c','s','Change Cipher Spec, Finished',[['Finished','verify_data','']],{len:100,info:'Client: Change Cipher Spec, Encrypted Handshake Message',about:'O cliente confirma.'});
      R.keys={kind:'1.2',kex:'ticket',pms:hex('pms'+P.cProf,32),ms:hex('ms'+P.cProf+P.sProf,48),tMs:cfin.tSend,block:hex('kb'+P.cProf+P.sProf,40)};
      tr.t=cfin.tArr+0.4;
    }
    phase('4. Dados da aplicação','data','Dados');
    tr.st(tr.t,'phase','Estabelecida','est'); tr.mile(tr.t,'Estabelecida','2 RTT'); if(P.mtls) tr.st(tr.t,'client','autenticado (mTLS)','est');
    const req=enc('c','s',reqLabel,[['Dados',reqData,'']],{data:true,len:240,info:'Application Data',about:'Requisição HTTP cifrada.'});
    const resp=enc('s','c',(alpn==='h2'?'HTTP/2 200 OK':'HTTP/1.1 200 OK'),[['Dados',respData,'']],{data:true,len:1400,info:'Application Data',about:'Resposta cifrada.'});
    if(o.tamper) return tamperEnd(resp);
    tr.lg(req.tSend,'Handshake concluído em 2 RTT ('+ver+'). '+(R.fs?'Sigilo futuro garantido pelo ECDHE.':'Troca por RSA: sem sigilo futuro.'),'conn');
  }
  R.hsDone=tr.t;
  return R;
}
function closeSession(tr,P,R){
  const K=toolkit(tr,P), is13=R.ver==='TLS 1.3';
  K.state.ver='TLSv'+R.ver.slice(4); K.state.phase='Encerramento';
  tr.phase('Encerramento','end');
  K.enc('c','s','Alert: close_notify',[['Alert description','0 (close_notify)','fim normal: evita o ataque de truncamento']],{len:70,info:'Application Data',about:'close_notify avisa que o cliente terminou de enviar. Sem ele, um atacante poderia truncar a conexão sem ser notado.'});
  K.enc('s','c','Alert: close_notify',[['Alert description','0 (close_notify)','']],{len:70,info:'Application Data'});
  K.closeTcp('c'); tr.st(tr.t,'phase','Encerrada','closed'); tr.mile(tr.t,'Encerrada','TCP fechado');
}

// ---------- Modos ----------
function tcp3(tr,P,quiet){
  const K=toolkit(tr,P);
  if(!quiet){ tr.st(tr.t,'phase','TCP','warn'); tr.mile(tr.t,'TCP','handshake'); }
  K.tcp('c','s','SYN','SYN',{}); K.tcp('s','c','SYN, ACK','SYN, ACK',{}); K.tcp('c','s','ACK','ACK',{});
}
function simHandshake(P,sub){
  const ocsp=sub==='cert'&&!P.stapling&&['valid','revoked'].indexOf(P.certState)>=0;
  const tr=mkTrace(P,ocsp,STATES);
  tr.raw.sub=sub; tr.raw.ocsp=ocsp; tcp3(tr,P);
  const R=runTls(tr,P,{sub:sub,mode:sub==='handshake'?P.mode:'full',cert:true,ocsp:ocsp});
  if(R.ver&&!R.fail) closeSession(tr,P,R);
  tr.raw.R=R; return tr;
}
window.__TLS.simHandshake=simHandshake; window.__TLS.STATES=STATES; window.__TLS.WSTATES=WSTATES; window.__TLS.mkTrace=mkTrace; window.__TLS.toolkit=toolkit; window.__TLS.runTls=runTls; window.__TLS.closeSession=closeSession; window.__TLS.tcp3=tcp3;
})();
