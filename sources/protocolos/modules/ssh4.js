(function(){
'use strict';
const SS=window.SecureSim, X=window.__SSH, esc=SS.esc, fmtMs=SS.fmtMs, plural=SS.plural;
const {PROF,isWeak,isAead,list,controls}=X;

// ---------- Cenários ----------
const SCENARIOS=[
  {id:'ok',sub:'session',g:'Conexão',label:'Conexão moderna com chave',set:{},
    what:'<p>Cliente e servidor modernos, chave do servidor já no known_hosts e login por chave pública. É o caminho ideal: negociação, troca de chaves com curve25519, autenticação sem senha e um shell.</p><p>Acompanhe como tudo passa a ser cifrado depois do NEWKEYS.</p>'},
  {id:'tofu',sub:'session',g:'Conexão',label:'Primeira conexão (TOFU)',set:{known:'new'},
    what:'<p>O cliente nunca viu este servidor. Com StrictHostKeyChecking=ask, o ssh mostra o fingerprint e pergunta se deve continuar. A resposta "yes" grava a chave em known_hosts.</p><p>É a confiança no primeiro uso (TOFU): só é segura se o fingerprint for conferido por outro canal.</p>'},
  {id:'changed',sub:'session',g:'Conexão',label:'Chave do servidor mudou',set:{known:'changed'},
    what:'<p>O servidor apresenta uma chave diferente da registrada. O cliente recusa e aborta antes de enviar qualquer credencial.</p><p>Pode ser uma reinstalação legítima ou uma interceptação (MITM). A resposta correta é confirmar com o administrador por outro meio, nunca apagar a linha e seguir.</p>'},
  {id:'nomatch',sub:'session',g:'Algoritmos',label:'Sem algoritmo em comum',set:{cProf:'legado',sProf:'endurecido'},
    what:'<p>Um cliente antigo (OpenSSH 5.x) tenta falar com um servidor endurecido. Eles não têm nenhum algoritmo de troca de chaves em comum, e a conexão cai no KEXINIT, antes de qualquer cifragem ou credencial.</p><p>Veja a mensagem "no matching key exchange method found".</p>'},
  {id:'legacy',sub:'session',g:'Algoritmos',label:'Algoritmos fracos aceitos',set:{cProf:'legado',sProf:'legado'},
    what:'<p>Cliente e servidor legados negociam com sucesso, mas com SHA-1, RSA/DSA e CBC ou 3DES. Funciona, e é justamente o problema: a conexão aceita proteção fraca sem avisar o usuário.</p><p>Compare a nota na aba Configuração com a do cenário moderno.</p>'},
  {id:'pw',sub:'session',g:'Autenticação',label:'Login por senha',set:{cMethod:'password'},
    what:'<p>O cliente autentica com senha. Ela viaja cifrada dentro do canal, então ninguém na rede a vê, mas o servidor a recebe em claro e ela pode ser adivinhada por tentativas repetidas.</p>'},
  {id:'nopw',sub:'session',g:'Autenticação',label:'Senha desativada no servidor',set:{cMethod:'password',sPass:false},
    what:'<p>O servidor está com PasswordAuthentication no. A lista de métodos devolvida ao método "none" só traz publickey, e o cliente que só tem senha não consegue nem tentar.</p>'},
  {id:'brute',sub:'session',g:'Autenticação',label:'Muitas tentativas de senha',set:{cMethod:'password',credOk:false,maxTries:3},openAdv:true,
    what:'<p>Senha errada repetidas vezes. Com MaxAuthTries = 3, o servidor derruba a conexão na terceira falha. Cada falha fica registrada em auth.log.</p><p>Isso só limita tentativas por conexão: o atacante pode reconectar. A defesa real é desativar a senha, usar chaves e ferramentas como fail2ban.</p>'},
  {id:'mfa',sub:'session',g:'Autenticação',label:'Chave + TOTP (2 fatores)',set:{sMfa:true},
    what:'<p>O servidor exige duas etapas: chave pública e depois um código TOTP. A primeira etapa termina em "sucesso parcial" (USERAUTH_FAILURE com partial success), e o cliente passa ao keyboard-interactive.</p>'},
  {id:'root',sub:'session',g:'Autenticação',label:'Login de root bloqueado',set:{user:'root',cMethod:'password'},
    what:'<p>O usuário root tenta entrar por senha, mesmo com a credencial correta. PermitRootLogin = prohibit-password só aceita root com chave, então o servidor recusa e registra "ROOT LOGIN REFUSED".</p>'},
  {id:'cmd',sub:'session',g:'Canais',label:'Comando remoto',set:{use:'exec'},
    what:'<p>Em vez de um shell, o cliente executa um único comando (<code>ssh servidor uname -a</code>). É o modo de scripts, rsync e git sobre SSH: um canal, um pedido exec, a saída e o código de saída.</p>'},
  {id:'sftp',sub:'session',g:'Canais',label:'Transferência SFTP',set:{use:'sftp'},
    what:'<p>O SFTP é um subsistema do SSH: abre um canal, pede o subsistema e troca pacotes SFTP (INIT, OPEN, READ, DATA) dentro do canal cifrado. A janela do canal (WINDOW_ADJUST) controla o fluxo.</p>'},
  {id:'agent',sub:'session',g:'Canais',label:'ForwardAgent e seus riscos',set:{fwdAgent:true},openAdv:true,
    what:'<p>Com ForwardAgent, o servidor recebe um socket que fala com o agente SSH do cliente. Cômodo para saltar entre máquinas, mas quem controla o servidor (root) pode usar suas chaves enquanto a sessão estiver aberta.</p><p>Prefira ProxyJump, que não expõe o agente.</p>'},
  {id:'t-local',sub:'tunnel',g:'Túneis',label:'Túnel local (-L)',set:{tunKind:'local'},
    what:'<p>Uma porta do cliente (5433) leva ao banco interno, passando pelo servidor SSH. O trecho entre cliente e servidor vai cifrado; o trecho do servidor até o banco segue em claro, a menos que o banco use TLS.</p>'},
  {id:'t-remote',sub:'tunnel',g:'Túneis',label:'Túnel remoto (-R)',set:{tunKind:'remote',gateway:true},openAdv:true,
    what:'<p>O servidor abre a porta 9000 e encaminha as conexões de volta ao serviço local do cliente. Aqui GatewayPorts está ligado, então um usuário externo consegue usar o túnel: o serviço local fica exposto na internet.</p>'},
  {id:'t-remote-nogw',sub:'tunnel',g:'Túneis',label:'Túnel remoto sem GatewayPorts',set:{tunKind:'remote',gateway:false},openAdv:true,
    what:'<p>Com o padrão (GatewayPorts no), a porta remota só existe no loopback do servidor. O usuário externo recebe RST. Só quem já está no servidor usa o túnel.</p>'},
  {id:'t-dyn',sub:'tunnel',g:'Túneis',label:'Proxy SOCKS (-D)',set:{tunKind:'dynamic'},
    what:'<p>O cliente SSH vira um proxy SOCKS5. Cada destino pedido pelo navegador abre um canal direct-tcpip, e o servidor SSH resolve o nome e conecta. O HTTPS continua de ponta a ponta entre o navegador e o site.</p>'},
  {id:'t-jump',sub:'tunnel',g:'Túneis',label:'ProxyJump (bastion)',set:{tunKind:'jump'},
    what:'<p>O cliente chega a um alvo interno passando por um bastion. Dentro do canal aberto pelo bastion corre uma sessão SSH completa e independente com o alvo: a chave de host verificada é a do alvo, e o bastion só enxerga bytes cifrados.</p>'},
  {id:'t-denied',sub:'tunnel',g:'Túneis',label:'Encaminhamento bloqueado',set:{tunKind:'local',allowFwd:false},
    what:'<p>O servidor está com AllowTcpForwarding no. O pedido direct-tcpip recebe CHANNEL_OPEN_FAILURE (administratively prohibited) e a aplicação local é desconectada.</p>'}
];
const GROUP_DOC={
  'Conexão':'Abertura da sessão: banner, negociação, troca de chaves e a verificação da chave do servidor.',
  'Algoritmos':'O que acontece quando cliente e servidor não concordam, ou concordam em algo fraco.',
  'Autenticação':'Chave, senha, 2 fatores e as defesas contra tentativas repetidas.',
  'Canais':'O que o cliente faz depois de autenticado: shell, comando e arquivos.',
  'Túneis':'Encaminhamento de portas e salto por bastion, dentro do canal cifrado.'
};
const D=(short,concept,observe,cols,msgs,why)=>({short:short,concept:concept,observe:observe,cols:cols,msgs:msgs,why:why});
const COLS=['Mensagem','Função','Quem envia'];
const SCEN_DOC={
  ok:D('Do banner ao shell, tudo cifrado depois do NEWKEYS.',
    'O <b>SSH-2</b> tem três camadas: <b>transporte</b> (RFC 4253: versões, algoritmos, troca de chaves, cifragem), <b>autenticação</b> (RFC 4252) e <b>conexão</b> (RFC 4254: canais). A troca de chaves usa Diffie-Hellman efêmero: as duas pontas obtêm o mesmo segredo sem enviá-lo, e o servidor prova quem é assinando o hash da troca com a chave de host.',
    ['No diagrama: setas âmbar (em claro) até o NEWKEYS e setas verdes com cadeado (cifradas) depois.','Na aba Chaves e sessão: K, H e as seis chaves derivadas.','Na aba Captura: depois do NEWKEYS só aparecem "Encrypted packet".'],COLS,
    [['SSH-2.0-... (banner)','versão do protocolo e do software','os dois'],['KEXINIT','listas de algoritmos','os dois'],['KEX_ECDH_INIT e REPLY','troca de chaves e assinatura do servidor','cliente e servidor'],['NEWKEYS','liga a cifragem','os dois'],['USERAUTH_*','autenticação do usuário','cliente e servidor'],['CHANNEL_*','sessão, dados e encerramento','cliente e servidor']],
    'O SSH protege confidencialidade, integridade e autenticidade do servidor (e do cliente), em uma só conexão. É a base da administração remota segura, de rsync, git e do túnel de outros protocolos.'),
  tofu:D('O cliente nunca viu o servidor: o fingerprint precisa ser conferido.',
    'No <b>known_hosts</b>, o cliente guarda o fingerprint da chave de cada servidor. Na primeira conexão não há o que comparar: o ssh mostra o fingerprint e pergunta. É o modelo <b>TOFU</b> (trust on first use): confia-se no primeiro contato e passa-se a detectar mudanças.',
    ['O evento do cliente mostra a pergunta e a resposta "yes".','Depois disso, a conexão segue como no cenário moderno.','Teste StrictHostKeyChecking = yes (Ajustes avançados): o cliente recusa o servidor desconhecido.'],COLS,
    [['KEX_ECDH_REPLY','traz a chave pública de host','servidor'],['Pergunta ao usuário','mostra o fingerprint','cliente (local)']],
    'Quem aceita o fingerprint sem conferir fica exposto a um intermediário na primeira conexão. Publicar os fingerprints (ou usar certificados de host e SSHFP no DNS) elimina o risco do TOFU.'),
  changed:D('A chave do servidor não confere: pode ser interceptação.',
    'Quando a chave apresentada difere da registrada, o ssh imprime <b>WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!</b> e aborta. Um atacante no caminho (MITM) apresentaria outra chave, pois não tem a chave privada do servidor verdadeiro.',
    ['O cliente aborta logo após o KEX_ECDH_REPLY, antes do NEWKEYS e de qualquer credencial.','Na aba Experimento: o fingerprint esperado e o recebido.','Ajustes avançados: com StrictHostKeyChecking = no o cliente segue, e a senha é desativada.'],COLS,
    [['KEX_ECDH_REPLY','chave de host diferente da registrada','servidor (ou intermediário)'],['FIN','o cliente encerra a conexão','cliente']],
    'É o principal alerta do SSH contra interceptação. A cultura de "apagar a linha do known_hosts e seguir" derruba a proteção. Confirme a mudança por outro canal.'),
  nomatch:D('Sem algoritmo em comum: a conexão cai no KEXINIT.',
    'Em cada categoria (troca de chaves, chave de host, cifra, MAC), vale o primeiro algoritmo da lista do <b>cliente</b> que o servidor também aceita. Se não houver nenhum, o resultado é <b>no matching ... found</b> e o DISCONNECT 3 (KEY_EXCHANGE_FAILED).',
    ['No KEXINIT do cliente: algoritmos fracos aparecem destacados na aba Mensagem.','Nada foi cifrado nem enviado como credencial.','Troque o cliente para Intermediário: a conexão volta a funcionar.'],COLS,
    [['KEXINIT','listas dos dois lados','cliente e servidor'],['DISCONNECT (3)','falha na troca de chaves','cliente']],
    'Endurecer o servidor tem custo de compatibilidade: dispositivos e clientes antigos deixam de conectar. Faça a transição planejada e atualize os clientes.'),
  legacy:D('Funciona, mas com SHA-1, DSA/RSA e CBC ou 3DES.',
    'Algoritmos <b>fracos</b> continuam sendo negociados quando os dois lados os aceitam. O servidor não os recusa e o cliente não avisa. SHA-1 em assinaturas, DSA de 1024 bits, 3DES e CBC são considerados inadequados.',
    ['Veja o evento "algoritmo fraco escolhido".','Aba Configuração: a nota de hardening cai.','Os marcadores da aba Mensagem destacam os algoritmos fracos oferecidos.'],COLS,
    [['KEXINIT','oferece algoritmos fracos','cliente e servidor']],
    'A conexão cifrada não é necessariamente segura: depende dos algoritmos. Ferramentas como o ssh-audit apontam esses problemas.'),
  pw:D('A senha viaja cifrada, mas continua sendo um segredo reutilizável.',
    'No método <b>password</b>, o cliente envia a senha dentro do canal cifrado. Ninguém na rede a lê, mas o <b>servidor</b> a recebe: um servidor falso ou comprometido a captura, e senhas fracas são adivinhadas por tentativas.',
    ['USERAUTH_REQUEST password: o conteúdo só existe nas pontas.','Compare com a chave pública: nenhum segredo reutilizável viaja.','Aba Configuração: PasswordAuthentication yes reduz a nota.'],COLS,
    [['USERAUTH_REQUEST none','pergunta os métodos aceitos','cliente'],['USERAUTH_REQUEST password','envia a senha cifrada','cliente'],['USERAUTH_SUCCESS','aceita o login','servidor']],
    'Senhas são alvo de força bruta e de reutilização de credenciais vazadas. Chaves públicas e segundo fator são a prática recomendada.'),
  nopw:D('Sem senha no servidor, a força bruta de senhas perde o alvo.',
    'Com <b>PasswordAuthentication no</b>, o servidor só lista <b>publickey</b> como método. O cliente que só tem senha recebe "Permission denied (publickey)" sem poder tentar nada.',
    ['A lista de métodos do USERAUTH_FAILURE ao método "none".','O cliente não envia nenhum USERAUTH_REQUEST password.','Aba Configuração: a nota sobe.'],COLS,
    [['USERAUTH_FAILURE','lista só publickey','servidor']],
    'Desativar a senha é uma das medidas de maior efeito: o ataque de adivinhação deixa de existir, restando proteger as chaves privadas.'),
  brute:D('Falhas repetidas: o servidor desconecta e registra cada uma.',
    'O sshd conta as falhas de autenticação por conexão. Ao atingir <b>MaxAuthTries</b>, desconecta com "Too many authentication failures". Cada falha vai para o auth.log, base para detecção e para o bloqueio automático por ferramentas como o fail2ban.',
    ['Contador "Falhas de login" no painel lateral.','O DISCONNECT do servidor na 3ª falha (MaxAuthTries = 3).','Aba Configuração: as linhas do auth.log geradas.'],COLS,
    [['USERAUTH_REQUEST password','tentativa com senha incorreta','cliente'],['USERAUTH_FAILURE','recusa e continua','servidor'],['DISCONNECT (2)','Too many authentication failures','servidor']],
    'Limitar tentativas por conexão não basta: o atacante reconecta. Defesas em camadas: sem senha, chaves, 2 fatores, fail2ban, restrição de origem por firewall e portas não padrão como complemento.'),
  mfa:D('Duas etapas: chave e código TOTP.',
    'Com <b>AuthenticationMethods publickey,keyboard-interactive</b>, o servidor exige os dois métodos em sequência. A chave termina com <b>sucesso parcial</b>; o servidor então envia um prompt (keyboard-interactive) pedindo o código <b>TOTP</b>, válido por cerca de 30 s.',
    ['USERAUTH_FAILURE com "partial success" depois da chave.','O prompt do código e a resposta, ambos cifrados.','Desmarque "Credencial correta" para ver a falha do 2º fator.'],COLS,
    [['USERAUTH_REQUEST publickey','1º fator','cliente'],['USERAUTH_FAILURE (parcial)','falta o 2º fator','servidor'],['INFO_REQUEST e RESPONSE','código TOTP','servidor e cliente'],['USERAUTH_SUCCESS','acesso liberado','servidor']],
    'Um segundo fator impede que uma chave privada roubada ou uma senha vazada dê acesso sozinha.'),
  root:D('Root recusado, mesmo com a credencial certa.',
    'O <b>PermitRootLogin</b> controla o acesso direto do root. Com <b>prohibit-password</b>, só chave é aceita; com <b>no</b>, nunca. Mesmo com a senha correta, o sshd recusa e registra "ROOT LOGIN REFUSED".',
    ['A senha correta é recusada, e o evento do servidor explica o motivo.','Troque PermitRootLogin para yes (Ajustes avançados) e veja a diferença.','O contador de falhas aumenta.'],COLS,
    [['USERAUTH_REQUEST password','senha do root','cliente'],['USERAUTH_FAILURE','recusa por política','servidor']],
    'Contas nominais e sudo deixam rastro de quem fez o quê. O root direto por SSH concentra risco e apaga a responsabilização individual.'),
  cmd:D('Um canal, um comando, um código de saída.',
    'O pedido <b>exec</b> roda um comando sem terminal interativo. Scripts, rsync e git usam esse modo. O resultado chega em CHANNEL_DATA e o código de saída em <b>exit-status</b>.',
    ['CHANNEL_REQUEST exec com o comando.','CHANNEL_DATA com a saída, depois exit-status.','Não há pty-req: não é uma sessão interativa.'],['Mensagem','Função','Quem envia'],
    [['CHANNEL_OPEN session','abre o canal','cliente'],['CHANNEL_REQUEST exec','define o comando','cliente'],['CHANNEL_DATA','saída do comando','servidor'],['exit-status','código de retorno','servidor']],
    'O comando executa com os privilégios do usuário. Chaves com "command=" em authorized_keys limitam o que cada chave pode executar.'),
  sftp:D('Arquivos sobre o canal SSH, com controle de fluxo.',
    'O <b>SFTP</b> é um subsistema do SSH (não é FTP sobre SSL). O cliente pede <b>subsystem sftp</b> e passa a trocar pacotes SFTP (INIT, OPEN, READ, DATA, CLOSE) em CHANNEL_DATA. A janela do canal limita quanto pode ser enviado; <b>WINDOW_ADJUST</b> a repõe.',
    ['Os pacotes SFTP aparecem dentro de CHANNEL_DATA (cifrados).','CHANNEL_WINDOW_ADJUST libera mais envio.','Na captura, nada indica que é uma transferência de arquivo.'],['Mensagem','Função','Quem envia'],
    [['subsystem sftp','pede o subsistema','cliente'],['SFTP READ / DATA','lê o arquivo em blocos','cliente e servidor'],['WINDOW_ADJUST','controle de fluxo do canal','cliente']],
    'Substitui o FTP e o scp clássico com autenticação e cifragem. O servidor pode restringir o usuário a um diretório (ChrootDirectory).'),
  agent:D('O agente encaminhado dá acesso às suas chaves enquanto a sessão durar.',
    'O <b>ssh-agent</b> guarda as chaves privadas e assina desafios. Com <b>ForwardAgent</b>, o servidor ganha um socket para o agente do cliente: não vê a chave, mas pede assinaturas. Quem tem privilégio no servidor pode se autenticar como você em outras máquinas.',
    ['CHANNEL_REQUEST auth-agent-req no início da sessão.','O evento do servidor avisa do risco.','Alternativa: ProxyJump, que nunca expõe o agente.'],COLS,
    [['auth-agent-req','pede o encaminhamento do agente','cliente'],['CHANNEL_SUCCESS','servidor aceita','servidor']],
    'Em máquinas compartilhadas ou comprometidas, o agente encaminhado vira trampolim para o resto da infraestrutura. Use ProxyJump e chaves por máquina.'),
  't-local':D('Porta local até um serviço interno, passando pelo servidor SSH.',
    'Com <b>-L</b>, o cliente escuta numa porta local. Cada conexão vira um canal <b>direct-tcpip</b>: o servidor abre uma conexão TCP até o destino e repassa os bytes. O trecho cliente-servidor é cifrado; o trecho do servidor ao destino não faz parte do SSH.',
    ['Três trechos no painel lateral: local, cifrado pelo SSH e em claro na rede interna.','CHANNEL_OPEN direct-tcpip com host e porta de destino.','O destino vê a origem como o servidor SSH.'],['Mensagem','Função','Quem envia'],
    [['CHANNEL_OPEN direct-tcpip','pede a conexão ao destino','cliente'],['CHANNEL_OPEN_CONFIRMATION','canal pronto','servidor'],['CHANNEL_DATA','bytes da aplicação','os dois']],
    'Permite acessar serviços internos sem expô-los. Também pode servir de pivô: restrinja o encaminhamento e use bastions com política clara.'),
  't-remote':D('O servidor abre uma porta e leva as conexões até o cliente.',
    'Com <b>-R</b>, o cliente pede ao servidor (GLOBAL_REQUEST <b>tcpip-forward</b>) que escute numa porta. Cada conexão recebida vira um canal <b>forwarded-tcpip</b> de volta ao cliente. Com <b>GatewayPorts</b> ligado, a porta fica aberta a toda a rede.',
    ['GLOBAL_REQUEST tcpip-forward e REQUEST_SUCCESS.','O usuário externo chega ao serviço local pelo servidor.','Evento de aviso: o serviço local ficou exposto.'],['Mensagem','Função','Quem envia'],
    [['tcpip-forward','pede escuta no servidor','cliente'],['forwarded-tcpip','canal de volta ao cliente','servidor'],['CHANNEL_DATA','requisição e resposta','os dois']],
    'É a técnica usada para expor serviços atrás de NAT, e também para contornar firewalls. Monitore e restrinja túneis reversos.'),
  't-remote-nogw':D('Sem GatewayPorts, a porta remota só aceita conexões locais.',
    'O padrão do sshd (<b>GatewayPorts no</b>) abre a porta do túnel reverso só no <b>loopback</b> do servidor. Quem vem de outro host recebe RST. É uma proteção padrão contra exposição acidental.',
    ['RST ao usuário externo.','Compare com o cenário com GatewayPorts ligado.','O túnel em si foi aberto: só está restrito ao próprio servidor.'],['Mensagem','Função','Quem envia'],
    [['tcpip-forward 127.0.0.1:9000','escuta só no loopback','cliente'],['SYN :9000','tentativa externa','usuário externo'],['RST','recusado','servidor']],
    'Boas práticas: manter GatewayPorts no e expor serviços por proxy reverso controlado, com autenticação e TLS.'),
  't-dyn':D('O cliente SSH vira um proxy SOCKS5.',
    'Com <b>-D</b>, o navegador envia pedidos SOCKS5 ao cliente SSH. Cada destino abre um canal direct-tcpip, e o servidor SSH resolve o nome (DNS) e conecta. O HTTPS segue de ponta a ponta entre o navegador e o site.',
    ['SOCKS5 CONNECT com o nome do site.','O ClientHello do TLS passa em CHANNEL_DATA.','Evento: o servidor SSH não vê o conteúdo do HTTPS.'],['Mensagem','Função','Quem envia'],
    [['SOCKS5 CONNECT','pede o destino','navegador'],['direct-tcpip','canal até o destino','cliente'],['CHANNEL_DATA','TLS do navegador ao site','os dois']],
    'Protege o trecho até o servidor SSH em redes não confiáveis, mas o servidor passa a ver os destinos acessados (nomes e IPs).'),
  't-jump':D('Salto por bastion com SSH de ponta a ponta até o alvo.',
    'No <b>ProxyJump</b>, o cliente abre um canal direct-tcpip até a porta 22 do alvo e roda <b>uma segunda sessão SSH</b> dentro dele. O bastion só repassa bytes cifrados. A chave de host verificada é a do <b>alvo</b>, e a autenticação ocorre direto no alvo.',
    ['Duas camadas de cifragem: sessão interna e sessão externa.','O KEX_ECDH_REPLY interno traz a chave do alvo.','Mude "Chave do servidor" para Diferente: o cliente recusa o alvo, mesmo pelo bastion.'],['Mensagem','Função','Quem envia'],
    [['direct-tcpip 10.0.0.50:22','canal até o alvo','cliente'],['SSH interno','sessão completa com o alvo','cliente e alvo']],
    'Melhor que o ForwardAgent: o bastion não vê credenciais nem tem acesso ao agente, e continua sendo um ponto único de entrada auditável.'),
  't-denied':D('AllowTcpForwarding no: o pedido de túnel é recusado.',
    'O servidor pode proibir o encaminhamento (<b>AllowTcpForwarding no</b>). O pedido direct-tcpip recebe <b>CHANNEL_OPEN_FAILURE</b> com o motivo "administratively prohibited" (código 1).',
    ['A recusa vem do servidor, depois do pedido do cliente.','O cliente fecha a conexão local.','Aba Configuração: a regra aparece no sshd_config.'],['Mensagem','Função','Quem envia'],
    [['direct-tcpip','pede o túnel','cliente'],['CHANNEL_OPEN_FAILURE','recusa por política','servidor']],
    'Em servidores que só precisam de shell, desativar o encaminhamento reduz o risco de usar a máquina como pivô.')
};

// ---------- Nota de hardening ----------
function grade(P){
  const S=PROF[P.sProf];
  const it=[
    ['Troca de chaves moderna (sem SHA-1 nem grupos antigos)',!S.kex.some(isWeak)],
    ['Chave de host ed25519 e sem DSA ou RSA com SHA-1',!S.hostkey.some(isWeak)&&S.hostkey.indexOf('ssh-ed25519')>=0],
    ['Cifras sem CBC e sem 3DES',!S.enc.some(isWeak)],
    ['MACs sem MD5 e sem SHA-1',!S.mac.some(isWeak)],
    ['Senha desativada (PasswordAuthentication no)',!P.sPass],
    ['Root sem senha (PermitRootLogin no ou prohibit-password)',P.permitRoot!=='yes'],
    ['MaxAuthTries baixo (3)',P.maxTries<=3],
    ['Segundo fator exigido (chave + TOTP)',!!P.sMfa],
    ['Encaminhamento de portas restrito (AllowTcpForwarding no)',!P.allowFwd],
    ['Cliente verifica a chave do servidor (StrictHostKeyChecking diferente de no)',P.hkCheck!=='no'],
    ['Agente não encaminhado (ForwardAgent no)',!P.fwdAgent]
  ];
  const ok=it.filter(x=>x[1]).length, pct=Math.round(ok/it.length*100);
  return {items:it,ok:ok,total:it.length,pct:pct,letter:pct>=85?'A':(pct>=65?'B':(pct>=45?'C':'D'))};
}
function sshdConf(P){
  const S=PROF[P.sProf];
  return '# /etc/ssh/sshd_config  (servidor: '+S.nome+')\nPort 22\nKexAlgorithms '+list(S.kex)+'\nHostKeyAlgorithms '+list(S.hostkey)+'\nCiphers '+list(S.enc)+'\nMACs '+list(S.mac)+
    '\nPubkeyAuthentication yes\nPasswordAuthentication '+(P.sPass?'yes':'no')+'\nKbdInteractiveAuthentication '+((P.sMfa||P.sPass)?'yes':'no')+'\nPermitRootLogin '+P.permitRoot+'\nMaxAuthTries '+P.maxTries+
    (P.sMfa?'\nAuthenticationMethods publickey,keyboard-interactive':'')+'\nAllowTcpForwarding '+(P.allowFwd?'yes':'no')+'\nGatewayPorts '+(P.gateway?'yes':'no')+'\nX11Forwarding no';
}
function sshConf(P){
  const C=PROF[P.cProf];
  let s='# ~/.ssh/config  (cliente: '+C.nome+')\nHost srv\n  HostName 203.0.113.22\n  User '+P.user+'\n  IdentityFile ~/.ssh/id_ed25519\n  KexAlgorithms '+list(C.kex)+'\n  HostKeyAlgorithms '+list(C.hostkey)+'\n  Ciphers '+list(C.enc)+'\n  StrictHostKeyChecking '+P.hkCheck+'\n  ForwardAgent '+(P.fwdAgent?'yes':'no');
  const k=P.tunKind;
  if(k==='local') s+='\n  LocalForward 5433 db.interno:5432'; else if(k==='remote') s+='\n  RemoteForward 9000 localhost:3000'; else if(k==='dynamic') s+='\n  DynamicForward 1080'; else if(k==='jump') s+='\n  ProxyJump aluno@bastion';
  return s;
}
function authLog(P,raw){
  const L=[], ip='192.168.1.20', pt='port 50122 ssh2';
  if(raw.fail){
    if(raw.fail.stage==='neg') L.push('sshd[812]: Unable to negotiate with '+ip+' port 50122: '+raw.fail.msg.slice(0,90)+'... [preauth]');
    else L.push('sshd[812]: Connection closed by '+ip+' port 50122 [preauth]');
    return L;
  }
  if(raw.sub==='tunnel'){
    if(raw.blocked) L.push('sshd[812]: error: channel 0: open failed: administratively prohibited: open failed');
    else L.push('sshd[812]: Accepted publickey for aluno from '+ip+' '+pt+': ED25519 SHA256:'+SS.b64('lg',20));
    return L;
  }
  const A=raw.auth;
  for(let i=0;i<A.tries;i++){
    if(A.denied==='root') L.push('sshd[812]: ROOT LOGIN REFUSED FROM '+ip+' port 50122');
    else if(A.denied==='key') L.push('sshd[812]: Failed publickey for '+P.user+' from '+ip+' '+pt+': ED25519 SHA256:'+SS.b64('lg',20));
    else L.push('sshd[812]: Failed password for '+P.user+' from '+ip+' '+pt);
  }
  if(A.serverDisconnect) L.push('sshd[812]: error: maximum authentication attempts exceeded for '+P.user+' from '+ip+' '+pt+' [preauth]');
  if(A.ok) L.push('sshd[812]: Accepted '+(A.via||'password')+' for '+P.user+' from '+ip+' '+pt+(A.via==='chave pública'||A.via==='chave + TOTP'?': ED25519 SHA256:'+SS.b64('lg',20):''));
  if(A.ok&&raw.use) L.push('sshd[812]: pam_unix(sshd:session): session opened for user '+P.user);
  if(!A.ok&&!A.tries) L.push('sshd[812]: Connection closed by authenticating user '+P.user+' '+ip+' port 50122 [preauth]');
  return L;
}
const TABS=[
  {id:'keys',label:'Chaves e sessão',render:(tr,ctx)=>{
    const r=tr.raw, now=ctx.timeAt(ctx.c);
    let h='<h3>Da troca de chaves às chaves da sessão</h3>';
    if(r.sub==='tunnel') return h+'<p>Os túneis usam a sessão SSH já estabelecida, então esta aba mostra as chaves da sessão (modo Sessão). Aqui o que muda é o <b>canal</b>: cada conexão encaminhada abre um canal dentro da mesma conexão cifrada.</p>'+KEYTABLE();
    if(!r.keys) return h+'<p>Esta execução terminou antes da derivação das chaves ('+(r.fail?'falha na '+(r.fail.stage==='neg'?'negociação de algoritmos':'verificação da chave do servidor'):'sem sessão')+'). Sem chaves de sessão, nada foi cifrado e nenhuma credencial foi enviada.</p>'+KEYTABLE();
    const k=r.keys;
    h+='<p>Algoritmo de troca de chaves: <b>'+esc(k.kex)+'</b>. Cada lado gera um par efêmero; os valores públicos viajam (em claro) e o segredo <b>K</b> é calculado nas pontas, sem nunca ser enviado.</p>';
    if(now<k.tK) return h+'<p class="muted">Aguardando a resposta do servidor (KEX_ECDH_REPLY)...</p>'+KEYTABLE();
    h+='<h3>Segredo e hash da troca</h3><div class="key-box">K (segredo compartilhado): '+k.K+'</div><div class="key-box">H (hash da troca) = session_id: '+k.H+'</div>'+
       '<p>O servidor assinou <b>H</b> com a chave de host ('+esc(k.hk)+', '+esc(k.fp)+'). Quem verifica a assinatura confirma que fala com o dono da chave. O <b>session_id</b> (o primeiro H) identifica esta sessão e é incluído nas assinaturas de autenticação.</p>';
    if(now<k.tNew) return h+'<p class="muted">As chaves da sessão são derivadas quando as duas pontas trocam NEWKEYS.</p>'+KEYTABLE();
    h+='<h3>Chaves derivadas (RFC 4253, seção 7.2)</h3><table><thead><tr><th>Letra</th><th>Finalidade</th><th>Valor (ilustrativo)</th></tr></thead><tbody>'+k.derived.map(d=>'<tr><td>'+d[0]+'</td><td>'+d[1]+'</td><td style="font-family:\'IBM Plex Mono\',monospace;word-break:break-all">'+esc(d[2])+'</td></tr>').join('')+'</tbody></table>'+
       '<p>Cada chave vem de <code>HASH(K || H || letra || session_id)</code>. Cifra: <b>'+esc(k.enc)+'</b>'+(isAead(k.enc)?' (AEAD: a própria cifra autentica, as chaves E e F não são usadas)':'')+'. Os valores são ilustrativos: o simulador não faz criptografia real.</p>';
    return h+KEYTABLE();
  }},
  {id:'cfg',label:'Configuração',render:(tr,ctx)=>{
    const P=ctx.P, g=grade(P), raw=tr.raw;
    let h='<h3>Nota de hardening</h3><p><span class="grade '+g.letter+'">'+g.letter+'</span><b>'+g.ok+' de '+g.total+' boas práticas ('+g.pct+'%)</b></p><ul>'+g.items.map(x=>'<li><span class="'+(x[1]?'chk-ok':'chk-bad')+'">'+(x[1]?'OK':'FALTA')+'</span> '+esc(x[0])+'</li>').join('')+'</ul>'+
      '<p>A nota é didática: mede o que a configuração escolhida no painel faz ou deixa de fazer. Em produção, use o <b>ssh-audit</b> e revise a política de acesso.</p>';
    h+='<div class="cfg-two"><div><h3>Servidor (sshd_config)</h3><pre class="conf">'+esc(sshdConf(P))+'</pre></div><div><h3>Cliente (ssh_config)</h3><pre class="conf">'+esc(sshConf(P))+'</pre></div></div>';
    const log=authLog(P,raw);
    h+='<h3>O que o servidor registra (auth.log)</h3><pre class="conf">'+esc(log.join('\n')||'(sem registros)')+'</pre><p>Esses registros alimentam a detecção de ataques e o bloqueio automático de origens.</p>';
    return h;
  }}
];
function KEYTABLE(){
  return '<h3>O que cada elemento protege</h3><table><thead><tr><th>Elemento</th><th>Para que serve</th></tr></thead><tbody>'+
    '<tr><td>Chave de host do servidor</td><td>autenticar o servidor (assina H); conferida no known_hosts</td></tr>'+
    '<tr><td>Par Diffie-Hellman efêmero</td><td>obter o segredo K sem enviá-lo; dá sigilo futuro (forward secrecy)</td></tr>'+
    '<tr><td>session_id (H)</td><td>amarrar a autenticação do usuário a esta sessão</td></tr>'+
    '<tr><td>Chaves de cifra e integridade (A a F)</td><td>cifrar e autenticar cada pacote nos dois sentidos</td></tr>'+
    '<tr><td>Chave do usuário (authorized_keys)</td><td>autenticar o cliente sem enviar segredo reutilizável</td></tr></tbody></table>';
}
window.__SSH.SCENARIOS=SCENARIOS; window.__SSH.GROUP_DOC=GROUP_DOC; window.__SSH.SCEN_DOC=SCEN_DOC; window.__SSH.TABS=TABS; window.__SSH.grade=grade;
})();
