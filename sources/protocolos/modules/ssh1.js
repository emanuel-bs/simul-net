(function(){
'use strict';
/* ==========================================================================
   MÓDULO SSH (SSH-2: RFC 4251, 4252, 4253, 4254)
   Não há criptografia real: chaves, fingerprints e hashes são valores determinísticos e ilustrativos.
   ========================================================================== */
const SS=window.SecureSim, C0=SS.COLORS, esc=SS.esc, hex=SS.hex, b64=SS.b64, fmtMs=SS.fmtMs, plural=SS.plural;

// ---------- Perfis de algoritmos ----------
const PROF={
  moderno:{nome:'Moderno (OpenSSH 9.x)',banner:'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13',
    kex:['curve25519-sha256','curve25519-sha256@libssh.org','ecdh-sha2-nistp256','diffie-hellman-group16-sha512','diffie-hellman-group14-sha256'],
    hostkey:['ssh-ed25519','rsa-sha2-512','rsa-sha2-256','ecdsa-sha2-nistp256'],
    enc:['chacha20-poly1305@openssh.com','aes256-gcm@openssh.com','aes128-gcm@openssh.com','aes256-ctr','aes128-ctr'],
    mac:['hmac-sha2-256-etm@openssh.com','hmac-sha2-512-etm@openssh.com']},
  intermediario:{nome:'Intermediário (OpenSSH 7.x)',banner:'SSH-2.0-OpenSSH_7.4',
    kex:['curve25519-sha256@libssh.org','ecdh-sha2-nistp256','ecdh-sha2-nistp384','diffie-hellman-group-exchange-sha256','diffie-hellman-group14-sha256','diffie-hellman-group14-sha1'],
    hostkey:['rsa-sha2-512','rsa-sha2-256','ecdsa-sha2-nistp256','ssh-ed25519','ssh-rsa'],
    enc:['chacha20-poly1305@openssh.com','aes256-gcm@openssh.com','aes128-gcm@openssh.com','aes256-ctr','aes192-ctr','aes128-ctr','aes256-cbc','aes128-cbc'],
    mac:['hmac-sha2-256-etm@openssh.com','hmac-sha2-512-etm@openssh.com','hmac-sha2-256','hmac-sha2-512','hmac-sha1']},
  legado:{nome:'Legado (OpenSSH 5.x)',banner:'SSH-2.0-OpenSSH_5.3',
    kex:['diffie-hellman-group-exchange-sha1','diffie-hellman-group14-sha1','diffie-hellman-group1-sha1'],
    hostkey:['ssh-rsa','ssh-dss'],
    enc:['aes128-ctr','aes128-cbc','3des-cbc'],
    mac:['hmac-sha1','hmac-md5']},
  endurecido:{nome:'Endurecido (somente algoritmos modernos)',banner:'SSH-2.0-OpenSSH_9.6',
    kex:['curve25519-sha256','curve25519-sha256@libssh.org'],
    hostkey:['ssh-ed25519'],
    enc:['chacha20-poly1305@openssh.com','aes256-gcm@openssh.com'],
    mac:['hmac-sha2-512-etm@openssh.com']}
};
const WEAK=['diffie-hellman-group1-sha1','diffie-hellman-group14-sha1','diffie-hellman-group-exchange-sha1','ssh-dss','ssh-rsa','3des-cbc','aes128-cbc','aes192-cbc','aes256-cbc','hmac-md5','hmac-sha1'];
const isWeak=a=>WEAK.indexOf(a)>=0;
const isAead=e=>/chacha20-poly1305|gcm@openssh/.test(e);
const weakIn=list=>list.filter(isWeak);
const pick=(cl,sl)=>cl.find(a=>sl.indexOf(a)>=0)||null;
const KEYTYPE=a=>({'ssh-ed25519':'ED25519','rsa-sha2-512':'RSA 3072','rsa-sha2-256':'RSA 3072','ssh-rsa':'RSA 3072','ecdsa-sha2-nistp256':'ECDSA P-256','ssh-dss':'DSA 1024'})[a]||a;
const KEYBITS=e=>/chacha/.test(e)?64:(/aes256/.test(e)?32:(/3des/.test(e)?24:16));
const fpOf=(P,alg,variant)=>'SHA256:'+b64('fp|'+P.sProf+'|'+KEYTYPE(alg)+'|'+variant,43);
const list=a=>a.join(',');

// ---------- Campos de mensagem ----------
const SEC_BIN={sec:'SSH Binary Packet (RFC 4253, seção 6)'};
function plainFields(num,name,extra){ return [SEC_BIN,['Tipo da mensagem',num+' ('+name+')','primeiro byte do payload'],['Cifrado?','não','esta mensagem ainda trafega em claro']].concat(extra||[]); }
function encFields(len,num,name,extra){
  return [{sec:'No fio (o que um observador vê)'},['packet_length','cifrado ('+(len-20)+' bytes)','o próprio comprimento vai cifrado (ETM/AEAD)'],['payload','cifrado','ilegível sem as chaves da sessão'],['MAC ou tag de autenticação','16 bytes','detecta qualquer alteração do pacote'],
    {sec:'Nas pontas (depois de decifrar)'},['Tipo da mensagem',num+' ('+name+')','só cliente e servidor enxergam isto']].concat(extra||[]);
}
const lst=(name,arr,mean)=>[name,arr.join(','),mean||'ordem de preferência: vale o primeiro da lista do cliente que o servidor também tiver',arr.some(isWeak)?'expert':''];

// ---------- Controles ----------
const OPT_CPROF=[['moderno','Moderno (OpenSSH 9.x)'],['intermediario','Intermediário (OpenSSH 7.x)'],['legado','Legado (OpenSSH 5.x)']];
const OPT_SPROF=OPT_CPROF.concat([['endurecido','Endurecido (só algoritmos modernos)']]);
const controls=[
  {id:'rtt',num:true,grp:'Rede',label:'RTT (ms)',type:'select',opts:[[5,'5'],[20,'20'],[50,'50'],[100,'100'],[200,'200']],def:20,help:{t:'RTT',p:['Tempo de ida e volta entre cliente e servidor.','Cada mensagem do SSH que espera resposta custa meia ida e volta. O handshake do SSH leva vários RTTs antes do primeiro comando.']}},
  {id:'cProf',grp:'Cliente',label:'Perfil do cliente',type:'select',wide:true,opts:OPT_CPROF,def:'moderno',help:{t:'Perfil do cliente',s:'Conjunto de algoritmos que o cliente oferece.',p:['<b>Moderno:</b> curve25519, ed25519, chacha20 e AES-GCM.','<b>Intermediário:</b> OpenSSH 7.x, ainda aceita RSA com SHA-1, CBC e MACs antigos.','<b>Legado:</b> OpenSSH 5.x, só DH com SHA-1, DSA, 3DES e CBC. Vários servidores atuais recusam.']}},
  {id:'known',grp:'Cliente',label:'Chave do servidor no known_hosts',type:'select',wide:true,opts:[['known','Conhecida (confere)'],['new','Primeira conexão (não consta)'],['changed','Diferente da registrada']],def:'known',help:{t:'known_hosts',s:'O que o cliente já sabe sobre a chave deste servidor.',p:['<b>Conhecida:</b> o fingerprint recebido é igual ao guardado em ~/.ssh/known_hosts.','<b>Primeira conexão:</b> o cliente nunca viu este servidor. É o momento de confiar no primeiro uso (TOFU) e conferir o fingerprint por outro canal.','<b>Diferente:</b> o servidor apresenta outra chave. Pode ser reinstalação ou interceptação (MITM).']}},
  {id:'cMethod',subs:['session'],grp:'Cliente',label:'Método de autenticação',type:'select',wide:true,opts:[['publickey','Chave pública (ed25519)'],['password','Senha'],['kbd','Senha + código TOTP (keyboard-interactive)']],def:'publickey',help:{t:'Método de autenticação',s:'Como o cliente prova quem é.',p:['<b>Chave pública:</b> o cliente assina um desafio com a chave privada. A senha nunca viaja.','<b>Senha:</b> viaja dentro do canal cifrado, mas pode ser adivinhada por tentativas repetidas.','<b>Senha + TOTP:</b> o servidor pergunta a senha e depois um código temporário (keyboard-interactive).']}},
  {id:'credOk',subs:['session'],grp:'Cliente',label:'Credencial correta',type:'check',def:true,help:{t:'Credencial correta',s:'Se a chave, a senha ou o código estão certos.',p:['Desmarcado, a chave não consta em authorized_keys, ou a senha e o código estão errados. Serve para ver a falha e as tentativas.']}},
  {id:'user',subs:['session'],grp:'Cliente',label:'Usuário',type:'select',opts:[['aluno','aluno'],['root','root']],def:'aluno',help:{t:'Usuário',s:'Conta usada no login.',p:['<b>root</b> costuma ser recusado pela configuração PermitRootLogin, mesmo com a credencial certa.']}},
  {id:'use',subs:['session'],grp:'Sessão',label:'Uso da sessão',type:'select',opts:[['shell','Shell interativo'],['exec','Comando remoto'],['sftp','Transferência SFTP']],def:'shell',help:{t:'Uso da sessão',s:'O que o cliente pede depois de autenticado.',p:['<b>Shell:</b> terminal interativo (pty + shell).','<b>Comando:</b> executa um comando e encerra.','<b>SFTP:</b> subsistema de transferência de arquivos sobre o mesmo canal SSH.']}},
  {id:'tunKind',subs:['tunnel'],grp:'Túnel',label:'Tipo de túnel',type:'select',wide:true,opts:[['local','Local (-L): acessar um serviço interno'],['remote','Remoto (-R): expor um serviço local'],['dynamic','Dinâmico (-D): proxy SOCKS'],['jump','ProxyJump (-J): salto por bastion']],def:'local',help:{t:'Tipo de túnel',s:'Direção do encaminhamento de porta.',p:['<b>-L:</b> uma porta local leva ao serviço interno, passando pelo servidor SSH.','<b>-R:</b> uma porta do servidor leva a um serviço da máquina do cliente.','<b>-D:</b> o cliente vira um proxy SOCKS5 e cada destino abre um canal.','<b>-J:</b> o cliente chega a um alvo interno passando por um bastion, com SSH de ponta a ponta.']}},
  {id:'sProf',grp:'Servidor',label:'Perfil do servidor',type:'select',wide:true,opts:OPT_SPROF,def:'moderno',help:{t:'Perfil do servidor',s:'Algoritmos que o sshd aceita.',p:['Se não houver algoritmo em comum com o cliente, a conexão falha antes da troca de chaves.','<b>Endurecido:</b> só curve25519, ed25519, chacha20/AES-GCM e HMAC-SHA2-512-ETM.']}},
  {id:'sPass',subs:['session'],grp:'Servidor',label:'PasswordAuthentication',type:'check',def:true,help:{t:'PasswordAuthentication',s:'Aceitar login por senha.',p:['Desligar a senha e exigir chave pública elimina a adivinhação de senhas.']}},
  {id:'sMfa',subs:['session'],grp:'Servidor',label:'Exigir 2º fator (chave + TOTP)',type:'check',def:false,help:{t:'Segundo fator',s:'AuthenticationMethods publickey,keyboard-interactive.',p:['O servidor só libera o acesso depois de duas etapas: chave pública e um código TOTP.','A primeira etapa termina com "sucesso parcial" (partial success).']}},
  {id:'allowFwd',subs:['tunnel'],grp:'Servidor',label:'AllowTcpForwarding',type:'check',def:true,help:{t:'AllowTcpForwarding',s:'Permitir túneis pelo servidor.',p:['Desligado, o servidor recusa os canais direct-tcpip e o tcpip-forward (administratively prohibited).','Em bastions, restringir o encaminhamento reduz o risco de pivoteamento.']}},
  {id:'permitRoot',adv:true,subs:['session'],grp:'Servidor',label:'PermitRootLogin',type:'select',opts:[['prohibit-password','prohibit-password (só chave)'],['no','no'],['yes','yes']],def:'prohibit-password',help:{t:'PermitRootLogin',s:'Se o root pode entrar por SSH.',p:['<b>no:</b> nunca. <b>prohibit-password:</b> só por chave. <b>yes:</b> também por senha (arriscado).']}},
  {id:'maxTries',adv:true,num:true,subs:['session'],grp:'Servidor',label:'MaxAuthTries',type:'select',opts:[[3,'3'],[6,'6 (padrão)']],def:6,help:{t:'MaxAuthTries',s:'Falhas de autenticação antes de o servidor desconectar.',p:['O cliente OpenSSH tenta no máximo 3 senhas por conexão. Com MaxAuthTries = 3 é o servidor que encerra a conexão.']}},
  {id:'hkCheck',adv:true,grp:'Cliente',label:'StrictHostKeyChecking',type:'select',wide:true,opts:[['ask','ask (pergunta ao usuário)'],['accept-new','accept-new'],['yes','yes (só hosts conhecidos)'],['no','no (não verifica, inseguro)']],def:'ask',help:{t:'StrictHostKeyChecking',s:'Política do cliente para chaves de servidor.',p:['<b>ask:</b> pergunta na primeira conexão e recusa chave alterada.','<b>accept-new:</b> grava chaves novas sem perguntar e recusa as alteradas.','<b>yes:</b> recusa qualquer servidor ausente do known_hosts.','<b>no:</b> aceita tudo. Desliga a proteção contra interceptação.']}},
  {id:'fwdAgent',adv:true,subs:['session'],grp:'Cliente',label:'ForwardAgent',type:'check',def:false,help:{t:'ForwardAgent',s:'Encaminhar o agente SSH ao servidor.',p:['Permite usar suas chaves a partir do servidor, sem copiá-las. Quem tiver privilégio no servidor pode usar o agente enquanto a sessão durar. Prefira ProxyJump.']}},
  {id:'gateway',adv:true,subs:['tunnel'],grp:'Servidor',label:'GatewayPorts',type:'check',def:false,help:{t:'GatewayPorts',s:'Porta remota aberta para toda a rede.',p:['Em túneis -R, o padrão é abrir a porta só no loopback do servidor. Com GatewayPorts ligado, qualquer host que alcance o servidor usa o túnel.']}}
];
window.__SSH={PROF:PROF,WEAK:WEAK,isWeak:isWeak,isAead:isAead,pick:pick,KEYTYPE:KEYTYPE,KEYBITS:KEYBITS,fpOf:fpOf,plainFields:plainFields,encFields:encFields,lst:lst,list:list,weakIn:weakIn,controls:controls};
})();
