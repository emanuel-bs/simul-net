(function(){
'use strict';
const SS=window.SecureSim, X=window.__SSH, C0=SS.COLORS, hex=SS.hex;
const {PROF,KEYTYPE,fpOf,encFields}=X;
const TSTATES=[{key:'phase',label:'Túnel'},{key:'seg1',label:'Trecho 1'},{key:'seg2',label:'Trecho 2'},{key:'seg3',label:'Trecho 3'}];

// ---------- Túneis (-L, -R, -D e ProxyJump) ----------
function simTunnel(P){
  const tr=simTunnelCore(P);
  tr.events.forEach(e=>tr.lg(e.t,e.text,e.kind==='warn'?'loss':(e.kind==='ok'?'conn':'sys')));
  return tr;
}
function simTunnelCore(P){
  const kind=P.tunKind, rtt=P.rtt;
  const colsBy={
    local:[{key:'a',label:'Aplicação (psql)',sub:'127.0.0.1:50122',addr:'127.0.0.1'},{key:'c',label:'Cliente SSH',sub:'127.0.0.1:5433',addr:'127.0.0.1'},{key:'s',label:'Servidor SSH',sub:'203.0.113.22:22',addr:'203.0.113.22'},{key:'d',label:'Banco interno',sub:'10.0.0.50:5432',addr:'10.0.0.50'}],
    remote:[{key:'x',label:'Usuário externo',sub:'198.51.100.7',addr:'198.51.100.7'},{key:'s',label:'Servidor SSH',sub:'203.0.113.22:22',addr:'203.0.113.22'},{key:'c',label:'Cliente SSH',sub:'192.168.1.20',addr:'192.168.1.20'},{key:'a',label:'Serviço local',sub:'127.0.0.1:3000',addr:'127.0.0.1'}],
    dynamic:[{key:'b',label:'Navegador',sub:'127.0.0.1:50300',addr:'127.0.0.1'},{key:'c',label:'Cliente SSH (SOCKS5)',sub:'127.0.0.1:1080',addr:'127.0.0.1'},{key:'s',label:'Servidor SSH',sub:'203.0.113.22:22',addr:'203.0.113.22'},{key:'d',label:'Site de destino',sub:'93.184.216.34:443',addr:'93.184.216.34'}],
    jump:[{key:'c',label:'Cliente',sub:'192.168.1.20',addr:'192.168.1.20'},{key:'j',label:'Bastion (ProxyJump)',sub:'203.0.113.22:22',addr:'203.0.113.22'},{key:'t',label:'Alvo interno',sub:'10.0.0.50:22',addr:'10.0.0.50'}]
  };
  const tr=SS.newTrace(colsBy[kind],TSTATES,rtt);
  const ow=tr.ow, raw=tr.raw={sub:'tunnel',kind:kind,allow:P.allowFwd,gateway:P.gateway,blocked:false,known:P.known,hkCheck:P.hkCheck,refused:false};
  const nameOf=k=>tr.cols.find(c=>c.key===k).label;
  let curPhase='Túnel';
  // k: 'tcp' (segmento TCP), 'app' (dados em claro), 'ssh' (controle cifrado), 'data' (CHANNEL_DATA cifrado)
  const m=(from,to,label,k,o)=>{
    o=o||{}; const lan=k==='tcp'||k==='app'; const dur=o.dur!==undefined?o.dur:((o.local)?0.3:ow);
    const enc=k==='ssh'||k==='data';
    const color=k==='tcp'?C0.tcp:(k==='app'?C0.plain:(k==='data'?C0.data:C0.enc));
    const proto=o.proto||(k==='tcp'?'TCP':(enc?'SSHv2':'App'));
    const f=enc?encFields(o.len||100,o.num||'-',label,o.f||[]):[{sec:o.sec||(k==='tcp'?'TCP':'Dados da aplicação')}].concat(o.f||[['Conteúdo',label,'']]);
    return tr.add(from,to,Object.assign({label:label,color:o.bad?C0.bad:color,enc:enc,proto:proto,len:o.len||(enc?100:60),dur:dur,info:o.info||label,fields:f,phaseName:curPhase,about:o.about||''},o,{fields:f}));
  };
  const seg=(key,val,cls)=>tr.st(tr.t,key,val,cls);
  const ph=(label,short)=>{ curPhase=short; tr.phase(label,short); };
  tr.st(0,'phase','sessão pronta','est'); tr.st(0,'seg1','-','closed'); tr.st(0,'seg2','-','closed'); tr.st(0,'seg3','-','closed');
  tr.mile(0,'Sessão SSH','já autenticada');
  const chkTarget=()=>{ // verificação da chave do alvo (ProxyJump): mesma regra do modo Sessão
    return P.known==='changed'&&P.hkCheck!=='no';
  };

  if(kind==='local'){
    ph('Túnel local: ssh -L 5433:db.interno:5432 aluno@servidor','Túnel -L');
    tr.ev(0,'c','Sessão SSH já autenticada (fases 1 a 4 do modo Sessão). O cliente abre a porta 5433 no loopback.','ok');
    tr.mile(0,'Túnel -L','porta 5433');
    m('a','c','SYN 127.0.0.1:5433','tcp',{local:true,info:'50122 → 5433 [SYN]',about:'A aplicação local conecta na porta 5433 do próprio cliente. O cliente SSH está escutando nela.'});
    m('c','s','CHANNEL_OPEN direct-tcpip db.interno:5432','ssh',{num:90,len:150,f:[['channel type','direct-tcpip',''],['host to connect','db.interno','destino final, resolvido pelo servidor'],['port to connect','5432',''],['originator','127.0.0.1:50122','']],about:'O cliente pede ao servidor que abra uma conexão TCP até db.interno:5432 em nome dele. Para o destino, a origem será o servidor SSH.'});
    if(!P.allowFwd){
      raw.blocked=true;
      m('s','c','CHANNEL_OPEN_FAILURE (1) administratively prohibited','ssh',{num:92,bad:true,len:120,f:[['reason code','1 (ADMINISTRATIVELY_PROHIBITED)','AllowTcpForwarding no']],about:'O servidor recusa o encaminhamento por política (AllowTcpForwarding no).'});
      tr.ev(tr.t,'s','AllowTcpForwarding no: o servidor recusa o túnel','warn');
      m('c','a','RST','tcp',{local:true,bad:true,info:'5433 → 50122 [RST]',about:'O cliente SSH fecha a conexão local, pois o túnel não foi aberto.'});
      tr.lg(tr.t,'Túnel recusado pela política do servidor (AllowTcpForwarding no).','loss'); tr.st(tr.t,'phase','recusado','bad'); tr.mile(tr.t,'Recusado','política do servidor');
      return tr;
    }
    m('s','d','SYN db.interno:5432','tcp',{dur:1,info:'41234 → 5432 [SYN]',about:'O servidor SSH abre uma conexão TCP nova até o banco, a partir da rede interna.'});
    m('d','s','SYN, ACK','tcp',{dur:1,info:'5432 → 41234 [SYN, ACK]'});
    m('s','c','CHANNEL_OPEN_CONFIRMATION','ssh',{num:91,len:100,f:[['recipient channel','0',''],['sender channel','0','']],about:'O servidor confirma: o banco respondeu e o canal está aberto.'});
    m('c','a','SYN, ACK','tcp',{local:true,info:'5433 → 50122 [SYN, ACK]'});
    tr.mile(tr.t,'Túnel aberto','canal 0');
    tr.st(tr.t,'phase','aberto','est'); tr.st(tr.t,'seg1','loopback (mesmo host)','warn'); tr.st(tr.t,'seg2','cifrado pelo SSH','est'); tr.st(tr.t,'seg3','em claro (rede interna)','warn');
    tr.ev(tr.t,'c','Trecho 1: aplicação e cliente no mesmo host (em claro, mas local)','');
    tr.ev(tr.t,'s','Trecho 2: pela internet, cifrado e autenticado pelo SSH','ok');
    ph('Dados pelo túnel','Dados');
    m('a','c','SELECT * FROM notas','app',{local:true,proto:'PostgreSQL',info:'Query: SELECT * FROM notas',about:'A aplicação fala o protocolo do banco com o cliente SSH, como se fosse o banco.'});
    m('c','s','CHANNEL_DATA (consulta)','data',{num:94,len:160,f:[['data','consulta SQL','']],about:'O cliente SSH empacota os bytes recebidos em CHANNEL_DATA e os envia cifrados.'});
    m('s','d','SELECT * FROM notas','app',{dur:1,proto:'PostgreSQL',info:'Query: SELECT * FROM notas',about:'O servidor SSH entrega os bytes ao banco, já decifrados.'});
    tr.ev(tr.t,'d','Trecho 3: do servidor ao banco o tráfego segue em claro, a menos que o próprio banco use TLS','warn');
    m('d','s','resultado (linhas)','app',{dur:1,proto:'PostgreSQL',info:'Result: 12 rows'});
    m('s','c','CHANNEL_DATA (resultado)','data',{num:94,len:900,f:[['data','linhas do resultado','']]});
    m('c','a','resultado (linhas)','app',{local:true,proto:'PostgreSQL',info:'Result: 12 rows'});
    ph('Encerramento do túnel','Fim');
    m('a','c','FIN','tcp',{local:true,info:'50122 → 5433 [FIN, ACK]'});
    m('c','s','CHANNEL_EOF + CHANNEL_CLOSE','ssh',{num:97,len:100,f:[]});
    m('s','d','FIN','tcp',{dur:1,info:'41234 → 5432 [FIN, ACK]'});
    tr.st(tr.t,'phase','fechado','closed'); tr.mile(tr.t,'Canal fechado','sessão continua');
  } else if(kind==='remote'){
    ph('Túnel remoto: ssh -R 9000:localhost:3000 aluno@servidor','Túnel -R');
    tr.ev(0,'c','Sessão SSH já autenticada. O cliente pede ao servidor que escute na porta 9000.','ok');
    tr.mile(0,'Túnel -R','porta 9000 no servidor');
    m('c','s','GLOBAL_REQUEST tcpip-forward '+(P.gateway?'0.0.0.0:9000':'127.0.0.1:9000'),'ssh',{num:80,len:130,f:[['request name','tcpip-forward',''],['address to bind',P.gateway?'0.0.0.0':'127.0.0.1','com GatewayPorts yes escuta em todas as interfaces'],['port to bind','9000','']],about:'O cliente pede que o servidor escute numa porta e encaminhe as conexões de volta pelo túnel.'});
    if(!P.allowFwd){
      raw.blocked=true;
      m('s','c','REQUEST_FAILURE','ssh',{num:82,bad:true,len:80,f:[],about:'O servidor recusa por política (AllowTcpForwarding no).'});
      tr.ev(tr.t,'s','AllowTcpForwarding no: o servidor recusa o túnel reverso','warn'); tr.lg(tr.t,'Túnel reverso recusado (AllowTcpForwarding no).','loss'); tr.st(tr.t,'phase','recusado','bad'); tr.mile(tr.t,'Recusado','política do servidor');
      return tr;
    }
    m('s','c','REQUEST_SUCCESS','ssh',{num:81,len:80,f:[],about:'O servidor passou a escutar na porta 9000.'});
    tr.ev(tr.t,'s',P.gateway?'Porta 9000 aberta em 0.0.0.0 (GatewayPorts): visível para a rede':'Porta 9000 aberta só em 127.0.0.1 (padrão)',P.gateway?'warn':'ok');
    tr.st(tr.t,'phase','escutando','est');
    ph('Conexão de um usuário externo','Conexão externa');
    m('x','s','SYN :9000','tcp',{info:'51000 → 9000 [SYN]',about:'Um host externo tenta usar a porta que o túnel abriu no servidor.'});
    if(!P.gateway){
      raw.refused=true;
      m('s','x','RST (porta fechada)','tcp',{bad:true,info:'9000 → 51000 [RST, ACK]',about:'Sem GatewayPorts, a porta só existe no loopback do servidor. Quem vem de fora recebe RST. Só quem já está no servidor (ou outro túnel) alcança a porta.'});
      tr.ev(tr.t,'x','Recusado: a porta 9000 só aceita conexões do próprio servidor','warn');
      tr.lg(tr.t,'Sem GatewayPorts, a porta remota fica restrita ao loopback do servidor e o usuário externo é recusado.','loss'); tr.st(tr.t,'phase','só loopback','warn'); tr.mile(tr.t,'Externo recusado','sem GatewayPorts');
      return tr;
    }
    m('s','x','SYN, ACK','tcp',{info:'9000 → 51000 [SYN, ACK]'});
    m('s','c','CHANNEL_OPEN forwarded-tcpip 0.0.0.0:9000','ssh',{num:90,len:160,f:[['channel type','forwarded-tcpip',''],['connected address','0.0.0.0',''],['connected port','9000',''],['originator','198.51.100.7:51000','quem conectou na porta remota']],about:'O servidor avisa o cliente que chegou uma conexão na porta encaminhada e abre um canal de volta.'});
    m('c','a','SYN 127.0.0.1:3000','tcp',{local:true,info:'40100 → 3000 [SYN]',about:'O cliente SSH conecta ao serviço local indicado em -R.'});
    m('a','c','SYN, ACK','tcp',{local:true,info:'3000 → 40100 [SYN, ACK]'});
    m('c','s','CHANNEL_OPEN_CONFIRMATION','ssh',{num:91,len:100,f:[]});
    tr.mile(tr.t,'Túnel em uso','externo → local');
    tr.st(tr.t,'phase','em uso','est'); tr.st(tr.t,'seg1','internet (em claro)','warn'); tr.st(tr.t,'seg2','cifrado pelo SSH','est'); tr.st(tr.t,'seg3','loopback (local)','warn');
    tr.ev(tr.t,'x','Trecho 1: usuário externo ao servidor, pela internet, fora do SSH','warn');
    tr.ev(tr.t,'s','O serviço local agora está exposto na internet por este túnel','warn');
    ph('Dados pelo túnel','Dados');
    m('x','s','GET / HTTP/1.1','app',{proto:'HTTP',info:'GET / HTTP/1.1',about:'A requisição chega ao servidor pela porta 9000, em claro se o serviço não usar TLS.'});
    m('s','c','CHANNEL_DATA (GET /)','data',{num:94,len:200,f:[['data','GET / HTTP/1.1','']]});
    m('c','a','GET / HTTP/1.1','app',{local:true,proto:'HTTP',info:'GET / HTTP/1.1'});
    m('a','c','HTTP/1.1 200 OK','app',{local:true,proto:'HTTP',info:'HTTP/1.1 200 OK'});
    m('c','s','CHANNEL_DATA (200 OK)','data',{num:94,len:600,f:[['data','HTTP/1.1 200 OK','']]});
    m('s','x','HTTP/1.1 200 OK','app',{proto:'HTTP',info:'HTTP/1.1 200 OK'});
    tr.st(tr.t,'phase','fechado','closed'); tr.mile(tr.t,'Resposta entregue','canal fechado depois');
  } else if(kind==='dynamic'){
    ph('Proxy dinâmico: ssh -D 1080 aluno@servidor','Proxy -D');
    tr.ev(0,'c','Sessão SSH já autenticada. O cliente vira um proxy SOCKS5 na porta 1080.','ok');
    tr.mile(0,'Proxy -D','SOCKS5 :1080');
    m('b','c','SOCKS5 saudação (sem autenticação)','app',{local:true,proto:'SOCKS5',info:'SOCKS5 Version: 5, Method: no auth',about:'O navegador usa o proxy SOCKS5 do cliente SSH.'});
    m('c','b','SOCKS5 método escolhido','app',{local:true,proto:'SOCKS5',info:'SOCKS5 Method: no auth'});
    m('b','c','SOCKS5 CONNECT example.org:443','app',{local:true,proto:'SOCKS5',info:'SOCKS5 Request: CONNECT example.org:443',about:'O navegador pede conexão ao destino, enviando o NOME, não o IP: o servidor SSH é quem faz a resolução DNS (socks5h).'});
    m('c','s','CHANNEL_OPEN direct-tcpip example.org:443','ssh',{num:90,len:150,f:[['channel type','direct-tcpip',''],['host to connect','example.org','nome resolvido no servidor'],['port to connect','443','']],about:'Cada destino pedido pelo navegador vira um canal direct-tcpip.'});
    if(!P.allowFwd){
      raw.blocked=true;
      m('s','c','CHANNEL_OPEN_FAILURE (1) administratively prohibited','ssh',{num:92,bad:true,len:120,f:[['reason code','1 (ADMINISTRATIVELY_PROHIBITED)','']]});
      m('c','b','SOCKS5 resposta: falha geral','app',{local:true,bad:true,proto:'SOCKS5',info:'SOCKS5 Reply: general failure'});
      tr.ev(tr.t,'s','AllowTcpForwarding no: o servidor recusa o canal','warn'); tr.lg(tr.t,'Proxy recusado pela política do servidor.','loss'); tr.st(tr.t,'phase','recusado','bad'); tr.mile(tr.t,'Recusado','política do servidor');
      return tr;
    }
    tr.ev(tr.t,'s','O servidor resolve example.org e conecta ao destino','');
    m('s','d','SYN example.org:443','tcp',{dur:2,info:'41300 → 443 [SYN]'});
    m('d','s','SYN, ACK','tcp',{dur:2,info:'443 → 41300 [SYN, ACK]'});
    m('s','c','CHANNEL_OPEN_CONFIRMATION','ssh',{num:91,len:100,f:[]});
    m('c','b','SOCKS5 resposta: sucesso','app',{local:true,proto:'SOCKS5',info:'SOCKS5 Reply: succeeded'});
    tr.mile(tr.t,'Proxy pronto','canal para o site');
    tr.st(tr.t,'phase','em uso','est'); tr.st(tr.t,'seg1','loopback (mesmo host)','warn'); tr.st(tr.t,'seg2','cifrado pelo SSH','est'); tr.st(tr.t,'seg3','TLS de ponta a ponta','est');
    ph('Dados pelo proxy','Dados');
    m('b','c','TLS ClientHello','app',{local:true,proto:'TLS',info:'TLS Client Hello (SNI example.org)',about:'O navegador negocia TLS direto com o site. O túnel só transporta os bytes.'});
    m('c','s','CHANNEL_DATA (ClientHello)','data',{num:94,len:260,f:[['data','TLS ClientHello','']]});
    m('s','d','TLS ClientHello','app',{dur:2,proto:'TLS',info:'TLS Client Hello (SNI example.org)'});
    tr.ev(tr.t,'d','O HTTPS vai de ponta a ponta: o servidor SSH repassa bytes e não vê o conteúdo','ok');
    m('d','s','TLS ServerHello, Certificate','app',{dur:2,proto:'TLS',info:'TLS Server Hello, Certificate'});
    m('s','c','CHANNEL_DATA (ServerHello)','data',{num:94,len:1400,f:[['data','TLS ServerHello + certificado','']]});
    m('c','b','TLS ServerHello, Certificate','app',{local:true,proto:'TLS',info:'TLS Server Hello, Certificate'});
    tr.mile(tr.t,'TLS fim a fim','pelo proxy');
  } else {
    ph('ProxyJump: ssh -J aluno@bastion aluno@alvo','Bastion');
    tr.ev(0,'c','Sessão SSH #1 com o bastion já autenticada. O cliente pede um canal até o alvo.','ok');
    tr.mile(0,'Sessão externa','cliente ↔ bastion');
    m('c','j','CHANNEL_OPEN direct-tcpip 10.0.0.50:22','ssh',{num:90,len:150,f:[['channel type','direct-tcpip',''],['host to connect','10.0.0.50',''],['port to connect','22','porta SSH do alvo']],about:'O cliente pede ao bastion um canal TCP até a porta 22 do alvo interno. É o que o ProxyJump (-J) faz.'});
    if(!P.allowFwd){
      raw.blocked=true;
      m('j','c','CHANNEL_OPEN_FAILURE (1) administratively prohibited','ssh',{num:92,bad:true,len:120,f:[['reason code','1 (ADMINISTRATIVELY_PROHIBITED)','']],about:'O bastion não permite encaminhamento, então o ProxyJump não funciona.'});
      tr.ev(tr.t,'j','AllowTcpForwarding no: o bastion recusa o salto','warn'); tr.lg(tr.t,'ProxyJump recusado (AllowTcpForwarding no no bastion).','loss'); tr.st(tr.t,'phase','recusado','bad'); tr.mile(tr.t,'Recusado','política do bastion');
      return tr;
    }
    m('j','t','SYN :22','tcp',{dur:1,info:'42000 → 22 [SYN]'});
    m('t','j','SYN, ACK','tcp',{dur:1,info:'22 → 42000 [SYN, ACK]'});
    m('j','c','CHANNEL_OPEN_CONFIRMATION','ssh',{num:91,len:100,f:[]});
    tr.mile(tr.t,'Canal até o alvo','dentro da sessão #1');
    ph('Sessão SSH interna (cliente ↔ alvo), dentro do canal','SSH interno');
    const inner=(from,to,label,num,f,about,enc)=>{ const o=m(from,to,label,enc?'ssh':'app',{dur:ow+0.5,proto:'SSHv2',num:num,len:enc?140:80,info:(from==='c'?'Client: ':'Server: ')+label,f:f||[],about:about||''}); return o; };
    inner('c','t','SSH-2.0 (banner interno)','-',[['Linha de versão','SSH-2.0-OpenSSH_9.6p1','em claro dentro do canal externo, mas o bastion só enxerga bytes do canal']],'O banner interno vai dentro do canal do bastion. Para o bastion é só CHANNEL_DATA cifrado pela sessão #1.',false);
    inner('t','c','SSH-2.0 (banner do alvo)','-',[['Linha de versão','SSH-2.0-OpenSSH_9.2p1','']],'',false);
    inner('c','t','KEXINIT + KEX_ECDH_INIT',20,[['kex','curve25519-sha256','']],'A negociação interna acontece entre cliente e alvo, atravessando o bastion.',false);
    const fpRecv=P.known==='changed'?fpOf({sProf:'moderno'},'ssh-ed25519','imp'):fpOf({sProf:'moderno'},'ssh-ed25519','real');
    inner('t','c','KEX_ECDH_REPLY (chave de host do ALVO)',31,[['K_S','ED25519 '+fpRecv,'a chave do ALVO, não a do bastion'],['assinatura de H','ssh-ed25519 ('+hex('jg',16)+'…)','']],'A chave de host que o cliente confere é a do alvo. O bastion não consegue se passar por ele sem a chave privada do alvo.',false);
    if(chkTarget()){
      raw.refused=true;
      tr.ev(tr.t,'c','Chave do ALVO diferente da registrada: o cliente aborta, mesmo passando pelo bastion','warn');
      tr.lg(tr.t,'A chave de host do alvo mudou: o cliente recusa a conexão interna. O bastion não consegue encobrir isso.','loss');
      tr.st(tr.t,'phase','recusado','bad'); tr.mile(tr.t,'Alvo recusado','chave do alvo mudou');
      return tr;
    }
    inner('c','t','NEWKEYS',21,[],'A partir daqui a sessão interna é cifrada de ponta a ponta.',false);
    tr.ev(tr.t,'c','Camada 1: SSH interno (cliente ↔ alvo). Camada 2: SSH externo (cliente ↔ bastion).','ok');
    tr.st(tr.t,'phase','em uso','est'); tr.st(tr.t,'seg1','cifrado (sessão #1)','est'); tr.st(tr.t,'seg2','cifrado (sessão interna)','est'); tr.st(tr.t,'seg3','repasse no bastion','warn');
    inner('c','t','USERAUTH publickey (assinado)',50,[['method','publickey','autenticação feita diretamente no alvo']],'A chave privada do usuário assina o desafio da sessão interna. O bastion não participa.',true);
    inner('t','c','USERAUTH_SUCCESS',52,[],'',true);
    inner('c','t','CHANNEL_DATA (shell)',94,[['data','comandos do usuário','']],'Os comandos viajam cifrados duas vezes: pela sessão interna e pela externa.',true);
    tr.ev(tr.t,'j','O bastion repassa bytes cifrados: não consegue ler nem alterar a sessão interna','ok');
    tr.mile(tr.t,'Sessão no alvo','fim a fim');
  }
  return tr;
}
window.__SSH.simTunnel=simTunnel;
})();
