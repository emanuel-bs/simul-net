// Cenários e documentação do SSH (portados do simulador legado, removido; veja o histórico do git).
import type { ScenarioDef, ScenarioDoc } from '../../../sim-core/ui';

export const scenarios: ScenarioDef[] = [
  { id: 'ok', sub: 'session', g: 'Conexão', label: 'Conexão moderna com chave', set: {  }, what: '<p>Cliente e servidor modernos, chave do servidor já no known_hosts e login por chave pública. É o caminho ideal: negociação, troca de chaves com curve25519, autenticação sem senha e um shell.</p><p>Acompanhe como tudo passa a ser cifrado depois do NEWKEYS.</p>' },
  { id: 'tofu', sub: 'session', g: 'Conexão', label: 'Primeira conexão (TOFU)', set: { known: 'new' }, what: '<p>O cliente nunca viu este servidor. Com StrictHostKeyChecking=ask, o ssh mostra o fingerprint e pergunta se deve continuar. A resposta "yes" grava a chave em known_hosts.</p><p>É a confiança no primeiro uso (TOFU): só é segura se o fingerprint for conferido por outro canal.</p>' },
  { id: 'changed', sub: 'session', g: 'Conexão', label: 'Chave do servidor mudou', set: { known: 'changed' }, what: '<p>O servidor apresenta uma chave diferente da registrada. O cliente recusa e aborta antes de enviar qualquer credencial.</p><p>Pode ser uma reinstalação legítima ou uma interceptação (MITM). A resposta correta é confirmar com o administrador por outro meio, nunca apagar a linha e seguir.</p>' },
  { id: 'nomatch', sub: 'session', g: 'Algoritmos', label: 'Sem algoritmo em comum', set: { cProf: 'legado', sProf: 'endurecido' }, what: '<p>Um cliente antigo (OpenSSH 5.x) tenta falar com um servidor endurecido. Eles não têm nenhum algoritmo de troca de chaves em comum, e a conexão cai no KEXINIT, antes de qualquer cifragem ou credencial.</p><p>Veja a mensagem "no matching key exchange method found".</p>' },
  { id: 'legacy', sub: 'session', g: 'Algoritmos', label: 'Algoritmos fracos aceitos', set: { cProf: 'legado', sProf: 'legado' }, what: '<p>Cliente e servidor legados negociam com sucesso, mas com SHA-1, RSA/DSA e CBC ou 3DES. Funciona, e é justamente o problema: a conexão aceita proteção fraca sem avisar o usuário.</p><p>Compare a nota na aba Configuração com a do cenário moderno.</p>' },
  { id: 'pw', sub: 'session', g: 'Autenticação', label: 'Login por senha', set: { cMethod: 'password' }, what: '<p>O cliente autentica com senha. Ela viaja cifrada dentro do canal, então ninguém na rede a vê, mas o servidor a recebe em claro e ela pode ser adivinhada por tentativas repetidas.</p>' },
  { id: 'nopw', sub: 'session', g: 'Autenticação', label: 'Senha desativada no servidor', set: { cMethod: 'password', sPass: false }, what: '<p>O servidor está com PasswordAuthentication no. A lista de métodos devolvida ao método "none" só traz publickey, e o cliente que só tem senha não consegue nem tentar.</p>' },
  { id: 'brute', sub: 'session', g: 'Autenticação', label: 'Muitas tentativas de senha', set: { cMethod: 'password', credOk: false, maxTries: 3 }, openAdv: true, what: '<p>Senha errada repetidas vezes. Com MaxAuthTries = 3, o servidor derruba a conexão na terceira falha. Cada falha fica registrada em auth.log.</p><p>Isso só limita tentativas por conexão: o atacante pode reconectar. A defesa real é desativar a senha, usar chaves e ferramentas como fail2ban.</p>' },
  { id: 'mfa', sub: 'session', g: 'Autenticação', label: 'Chave + TOTP (2 fatores)', set: { sMfa: true }, what: '<p>O servidor exige duas etapas: chave pública e depois um código TOTP. A primeira etapa termina em "sucesso parcial" (USERAUTH_FAILURE com partial success), e o cliente passa ao keyboard-interactive.</p>' },
  { id: 'root', sub: 'session', g: 'Autenticação', label: 'Login de root bloqueado', set: { user: 'root', cMethod: 'password' }, what: '<p>O usuário root tenta entrar por senha, mesmo com a credencial correta. PermitRootLogin = prohibit-password só aceita root com chave, então o servidor recusa e registra "ROOT LOGIN REFUSED".</p>' },
  { id: 'cmd', sub: 'session', g: 'Canais', label: 'Comando remoto', set: { use: 'exec' }, what: '<p>Em vez de um shell, o cliente executa um único comando (<code>ssh servidor uname -a</code>). É o modo de scripts, rsync e git sobre SSH: um canal, um pedido exec, a saída e o código de saída.</p>' },
  { id: 'sftp', sub: 'session', g: 'Canais', label: 'Transferência SFTP', set: { use: 'sftp' }, what: '<p>O SFTP é um subsistema do SSH: abre um canal, pede o subsistema e troca pacotes SFTP (INIT, OPEN, READ, DATA) dentro do canal cifrado. A janela do canal (WINDOW_ADJUST) controla o fluxo.</p>' },
  { id: 'agent', sub: 'session', g: 'Canais', label: 'ForwardAgent e seus riscos', set: { fwdAgent: true }, openAdv: true, what: '<p>Com ForwardAgent, o servidor recebe um socket que fala com o agente SSH do cliente. Cômodo para saltar entre máquinas, mas quem controla o servidor (root) pode usar suas chaves enquanto a sessão estiver aberta.</p><p>Prefira ProxyJump, que não expõe o agente.</p>' },
  { id: 't-local', sub: 'tunnel', g: 'Túneis', label: 'Túnel local (-L)', set: { tunKind: 'local' }, what: '<p>Uma porta do cliente (5433) leva ao banco interno, passando pelo servidor SSH. O trecho entre cliente e servidor vai cifrado; o trecho do servidor até o banco segue em claro, a menos que o banco use TLS.</p>' },
  { id: 't-remote', sub: 'tunnel', g: 'Túneis', label: 'Túnel remoto (-R)', set: { tunKind: 'remote', gateway: true }, openAdv: true, what: '<p>O servidor abre a porta 9000 e encaminha as conexões de volta ao serviço local do cliente. Aqui GatewayPorts está ligado, então um usuário externo consegue usar o túnel: o serviço local fica exposto na internet.</p>' },
  { id: 't-remote-nogw', sub: 'tunnel', g: 'Túneis', label: 'Túnel remoto sem GatewayPorts', set: { tunKind: 'remote', gateway: false }, openAdv: true, what: '<p>Com o padrão (GatewayPorts no), a porta remota só existe no loopback do servidor. O usuário externo recebe RST. Só quem já está no servidor usa o túnel.</p>' },
  { id: 't-dyn', sub: 'tunnel', g: 'Túneis', label: 'Proxy SOCKS (-D)', set: { tunKind: 'dynamic' }, what: '<p>O cliente SSH vira um proxy SOCKS5. Cada destino pedido pelo navegador abre um canal direct-tcpip, e o servidor SSH resolve o nome e conecta. O HTTPS continua de ponta a ponta entre o navegador e o site.</p>' },
  { id: 't-jump', sub: 'tunnel', g: 'Túneis', label: 'ProxyJump (bastion)', set: { tunKind: 'jump' }, what: '<p>O cliente chega a um alvo interno passando por um bastion. Dentro do canal aberto pelo bastion corre uma sessão SSH completa e independente com o alvo: a chave de host verificada é a do alvo, e o bastion só enxerga bytes cifrados.</p>' },
  { id: 't-denied', sub: 'tunnel', g: 'Túneis', label: 'Encaminhamento bloqueado', set: { tunKind: 'local', allowFwd: false }, what: '<p>O servidor está com AllowTcpForwarding no. O pedido direct-tcpip recebe CHANNEL_OPEN_FAILURE (administratively prohibited) e a aplicação local é desconectada.</p>' },
];

export const groupDoc: Record<string, string> = {
  'Conexão': 'Abertura da sessão: banner, negociação, troca de chaves e a verificação da chave do servidor.',
  Algoritmos: 'O que acontece quando cliente e servidor não concordam, ou concordam em algo fraco.',
  'Autenticação': 'Chave, senha, 2 fatores e as defesas contra tentativas repetidas.',
  Canais: 'O que o cliente faz depois de autenticado: shell, comando e arquivos.',
  'Túneis': 'Encaminhamento de portas e salto por bastion, dentro do canal cifrado.',
};

export const scenDoc: Record<string, ScenarioDoc> = {
  ok: { short: 'Do banner ao shell, tudo cifrado depois do NEWKEYS.', concept: 'O <b>SSH-2</b> tem três camadas: <b>transporte</b> (RFC 4253: versões, algoritmos, troca de chaves, cifragem), <b>autenticação</b> (RFC 4252) e <b>conexão</b> (RFC 4254: canais). A troca de chaves usa Diffie-Hellman efêmero: as duas pontas obtêm o mesmo segredo sem enviá-lo, e o servidor prova quem é assinando o hash da troca com a chave de host.', observe: ['No diagrama: setas âmbar (em claro) até o NEWKEYS e setas verdes com cadeado (cifradas) depois.', 'Na aba Chaves e sessão: K, H e as seis chaves derivadas.', 'Na aba Captura: depois do NEWKEYS só aparecem "Encrypted packet".'], cols: ['Mensagem', 'Função', 'Quem envia'], msgs: [
      ['SSH-2.0-... (banner)', 'versão do protocolo e do software', 'os dois'],
      ['KEXINIT', 'listas de algoritmos', 'os dois'],
      ['KEX_ECDH_INIT e REPLY', 'troca de chaves e assinatura do servidor', 'cliente e servidor'],
      ['NEWKEYS', 'liga a cifragem', 'os dois'],
      ['USERAUTH_*', 'autenticação do usuário', 'cliente e servidor'],
      ['CHANNEL_*', 'sessão, dados e encerramento', 'cliente e servidor'],
    ], why: 'O SSH protege confidencialidade, integridade e autenticidade do servidor (e do cliente), em uma só conexão. É a base da administração remota segura, de rsync, git e do túnel de outros protocolos.' },
  tofu: { short: 'O cliente nunca viu o servidor: o fingerprint precisa ser conferido.', concept: 'No <b>known_hosts</b>, o cliente guarda o fingerprint da chave de cada servidor. Na primeira conexão não há o que comparar: o ssh mostra o fingerprint e pergunta. É o modelo <b>TOFU</b> (trust on first use): confia-se no primeiro contato e passa-se a detectar mudanças.', observe: ['O evento do cliente mostra a pergunta e a resposta "yes".', 'Depois disso, a conexão segue como no cenário moderno.', 'Teste StrictHostKeyChecking = yes (Ajustes avançados): o cliente recusa o servidor desconhecido.'], cols: ['Mensagem', 'Função', 'Quem envia'], msgs: [
      ['KEX_ECDH_REPLY', 'traz a chave pública de host', 'servidor'],
      ['Pergunta ao usuário', 'mostra o fingerprint', 'cliente (local)'],
    ], why: 'Quem aceita o fingerprint sem conferir fica exposto a um intermediário na primeira conexão. Publicar os fingerprints (ou usar certificados de host e SSHFP no DNS) elimina o risco do TOFU.' },
  changed: { short: 'A chave do servidor não confere: pode ser interceptação.', concept: 'Quando a chave apresentada difere da registrada, o ssh imprime <b>WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!</b> e aborta. Um atacante no caminho (MITM) apresentaria outra chave, pois não tem a chave privada do servidor verdadeiro.', observe: ['O cliente aborta logo após o KEX_ECDH_REPLY, antes do NEWKEYS e de qualquer credencial.', 'Na aba Experimento: o fingerprint esperado e o recebido.', 'Ajustes avançados: com StrictHostKeyChecking = no o cliente segue, e a senha é desativada.'], cols: ['Mensagem', 'Função', 'Quem envia'], msgs: [
      ['KEX_ECDH_REPLY', 'chave de host diferente da registrada', 'servidor (ou intermediário)'],
      ['FIN', 'o cliente encerra a conexão', 'cliente'],
    ], why: 'É o principal alerta do SSH contra interceptação. A cultura de "apagar a linha do known_hosts e seguir" derruba a proteção. Confirme a mudança por outro canal.' },
  nomatch: { short: 'Sem algoritmo em comum: a conexão cai no KEXINIT.', concept: 'Em cada categoria (troca de chaves, chave de host, cifra, MAC), vale o primeiro algoritmo da lista do <b>cliente</b> que o servidor também aceita. Se não houver nenhum, o resultado é <b>no matching ... found</b> e o DISCONNECT 3 (KEY_EXCHANGE_FAILED).', observe: ['No KEXINIT do cliente: algoritmos fracos aparecem destacados na aba Mensagem.', 'Nada foi cifrado nem enviado como credencial.', 'Troque o cliente para Intermediário: a conexão volta a funcionar.'], cols: ['Mensagem', 'Função', 'Quem envia'], msgs: [
      ['KEXINIT', 'listas dos dois lados', 'cliente e servidor'],
      ['DISCONNECT (3)', 'falha na troca de chaves', 'cliente'],
    ], why: 'Endurecer o servidor tem custo de compatibilidade: dispositivos e clientes antigos deixam de conectar. Faça a transição planejada e atualize os clientes.' },
  legacy: { short: 'Funciona, mas com SHA-1, DSA/RSA e CBC ou 3DES.', concept: 'Algoritmos <b>fracos</b> continuam sendo negociados quando os dois lados os aceitam. O servidor não os recusa e o cliente não avisa. SHA-1 em assinaturas, DSA de 1024 bits, 3DES e CBC são considerados inadequados.', observe: ['Veja o evento "algoritmo fraco escolhido".', 'Aba Configuração: a nota de hardening cai.', 'Os marcadores da aba Mensagem destacam os algoritmos fracos oferecidos.'], cols: ['Mensagem', 'Função', 'Quem envia'], msgs: [
      ['KEXINIT', 'oferece algoritmos fracos', 'cliente e servidor'],
    ], why: 'A conexão cifrada não é necessariamente segura: depende dos algoritmos. Ferramentas como o ssh-audit apontam esses problemas.' },
  pw: { short: 'A senha viaja cifrada, mas continua sendo um segredo reutilizável.', concept: 'No método <b>password</b>, o cliente envia a senha dentro do canal cifrado. Ninguém na rede a lê, mas o <b>servidor</b> a recebe: um servidor falso ou comprometido a captura, e senhas fracas são adivinhadas por tentativas.', observe: ['USERAUTH_REQUEST password: o conteúdo só existe nas pontas.', 'Compare com a chave pública: nenhum segredo reutilizável viaja.', 'Aba Configuração: PasswordAuthentication yes reduz a nota.'], cols: ['Mensagem', 'Função', 'Quem envia'], msgs: [
      ['USERAUTH_REQUEST none', 'pergunta os métodos aceitos', 'cliente'],
      ['USERAUTH_REQUEST password', 'envia a senha cifrada', 'cliente'],
      ['USERAUTH_SUCCESS', 'aceita o login', 'servidor'],
    ], why: 'Senhas são alvo de força bruta e de reutilização de credenciais vazadas. Chaves públicas e segundo fator são a prática recomendada.' },
  nopw: { short: 'Sem senha no servidor, a força bruta de senhas perde o alvo.', concept: 'Com <b>PasswordAuthentication no</b>, o servidor só lista <b>publickey</b> como método. O cliente que só tem senha recebe "Permission denied (publickey)" sem poder tentar nada.', observe: ['A lista de métodos do USERAUTH_FAILURE ao método "none".', 'O cliente não envia nenhum USERAUTH_REQUEST password.', 'Aba Configuração: a nota sobe.'], cols: ['Mensagem', 'Função', 'Quem envia'], msgs: [
      ['USERAUTH_FAILURE', 'lista só publickey', 'servidor'],
    ], why: 'Desativar a senha é uma das medidas de maior efeito: o ataque de adivinhação deixa de existir, restando proteger as chaves privadas.' },
  brute: { short: 'Falhas repetidas: o servidor desconecta e registra cada uma.', concept: 'O sshd conta as falhas de autenticação por conexão. Ao atingir <b>MaxAuthTries</b>, desconecta com "Too many authentication failures". Cada falha vai para o auth.log, base para detecção e para o bloqueio automático por ferramentas como o fail2ban.', observe: ['Contador "Falhas de login" no painel lateral.', 'O DISCONNECT do servidor na 3ª falha (MaxAuthTries = 3).', 'Aba Configuração: as linhas do auth.log geradas.'], cols: ['Mensagem', 'Função', 'Quem envia'], msgs: [
      ['USERAUTH_REQUEST password', 'tentativa com senha incorreta', 'cliente'],
      ['USERAUTH_FAILURE', 'recusa e continua', 'servidor'],
      ['DISCONNECT (2)', 'Too many authentication failures', 'servidor'],
    ], why: 'Limitar tentativas por conexão não basta: o atacante reconecta. Defesas em camadas: sem senha, chaves, 2 fatores, fail2ban, restrição de origem por firewall e portas não padrão como complemento.' },
  mfa: { short: 'Duas etapas: chave e código TOTP.', concept: 'Com <b>AuthenticationMethods publickey,keyboard-interactive</b>, o servidor exige os dois métodos em sequência. A chave termina com <b>sucesso parcial</b>; o servidor então envia um prompt (keyboard-interactive) pedindo o código <b>TOTP</b>, válido por cerca de 30 s.', observe: ['USERAUTH_FAILURE com "partial success" depois da chave.', 'O prompt do código e a resposta, ambos cifrados.', 'Desmarque "Credencial correta" para ver a falha do 2º fator.'], cols: ['Mensagem', 'Função', 'Quem envia'], msgs: [
      ['USERAUTH_REQUEST publickey', '1º fator', 'cliente'],
      ['USERAUTH_FAILURE (parcial)', 'falta o 2º fator', 'servidor'],
      ['INFO_REQUEST e RESPONSE', 'código TOTP', 'servidor e cliente'],
      ['USERAUTH_SUCCESS', 'acesso liberado', 'servidor'],
    ], why: 'Um segundo fator impede que uma chave privada roubada ou uma senha vazada dê acesso sozinha.' },
  root: { short: 'Root recusado, mesmo com a credencial certa.', concept: 'O <b>PermitRootLogin</b> controla o acesso direto do root. Com <b>prohibit-password</b>, só chave é aceita; com <b>no</b>, nunca. Mesmo com a senha correta, o sshd recusa e registra "ROOT LOGIN REFUSED".', observe: ['A senha correta é recusada, e o evento do servidor explica o motivo.', 'Troque PermitRootLogin para yes (Ajustes avançados) e veja a diferença.', 'O contador de falhas aumenta.'], cols: ['Mensagem', 'Função', 'Quem envia'], msgs: [
      ['USERAUTH_REQUEST password', 'senha do root', 'cliente'],
      ['USERAUTH_FAILURE', 'recusa por política', 'servidor'],
    ], why: 'Contas nominais e sudo deixam rastro de quem fez o quê. O root direto por SSH concentra risco e apaga a responsabilização individual.' },
  cmd: { short: 'Um canal, um comando, um código de saída.', concept: 'O pedido <b>exec</b> roda um comando sem terminal interativo. Scripts, rsync e git usam esse modo. O resultado chega em CHANNEL_DATA e o código de saída em <b>exit-status</b>.', observe: ['CHANNEL_REQUEST exec com o comando.', 'CHANNEL_DATA com a saída, depois exit-status.', 'Não há pty-req: não é uma sessão interativa.'], cols: ['Mensagem', 'Função', 'Quem envia'], msgs: [
      ['CHANNEL_OPEN session', 'abre o canal', 'cliente'],
      ['CHANNEL_REQUEST exec', 'define o comando', 'cliente'],
      ['CHANNEL_DATA', 'saída do comando', 'servidor'],
      ['exit-status', 'código de retorno', 'servidor'],
    ], why: 'O comando executa com os privilégios do usuário. Chaves com "command=" em authorized_keys limitam o que cada chave pode executar.' },
  sftp: { short: 'Arquivos sobre o canal SSH, com controle de fluxo.', concept: 'O <b>SFTP</b> é um subsistema do SSH (não é FTP sobre SSL). O cliente pede <b>subsystem sftp</b> e passa a trocar pacotes SFTP (INIT, OPEN, READ, DATA, CLOSE) em CHANNEL_DATA. A janela do canal limita quanto pode ser enviado; <b>WINDOW_ADJUST</b> a repõe.', observe: ['Os pacotes SFTP aparecem dentro de CHANNEL_DATA (cifrados).', 'CHANNEL_WINDOW_ADJUST libera mais envio.', 'Na captura, nada indica que é uma transferência de arquivo.'], cols: ['Mensagem', 'Função', 'Quem envia'], msgs: [
      ['subsystem sftp', 'pede o subsistema', 'cliente'],
      ['SFTP READ / DATA', 'lê o arquivo em blocos', 'cliente e servidor'],
      ['WINDOW_ADJUST', 'controle de fluxo do canal', 'cliente'],
    ], why: 'Substitui o FTP e o scp clássico com autenticação e cifragem. O servidor pode restringir o usuário a um diretório (ChrootDirectory).' },
  agent: { short: 'O agente encaminhado dá acesso às suas chaves enquanto a sessão durar.', concept: 'O <b>ssh-agent</b> guarda as chaves privadas e assina desafios. Com <b>ForwardAgent</b>, o servidor ganha um socket para o agente do cliente: não vê a chave, mas pede assinaturas. Quem tem privilégio no servidor pode se autenticar como você em outras máquinas.', observe: ['CHANNEL_REQUEST auth-agent-req no início da sessão.', 'O evento do servidor avisa do risco.', 'Alternativa: ProxyJump, que nunca expõe o agente.'], cols: ['Mensagem', 'Função', 'Quem envia'], msgs: [
      ['auth-agent-req', 'pede o encaminhamento do agente', 'cliente'],
      ['CHANNEL_SUCCESS', 'servidor aceita', 'servidor'],
    ], why: 'Em máquinas compartilhadas ou comprometidas, o agente encaminhado vira trampolim para o resto da infraestrutura. Use ProxyJump e chaves por máquina.' },
  't-local': { short: 'Porta local até um serviço interno, passando pelo servidor SSH.', concept: 'Com <b>-L</b>, o cliente escuta numa porta local. Cada conexão vira um canal <b>direct-tcpip</b>: o servidor abre uma conexão TCP até o destino e repassa os bytes. O trecho cliente-servidor é cifrado; o trecho do servidor ao destino não faz parte do SSH.', observe: ['Três trechos no painel lateral: local, cifrado pelo SSH e em claro na rede interna.', 'CHANNEL_OPEN direct-tcpip com host e porta de destino.', 'O destino vê a origem como o servidor SSH.'], cols: ['Mensagem', 'Função', 'Quem envia'], msgs: [
      ['CHANNEL_OPEN direct-tcpip', 'pede a conexão ao destino', 'cliente'],
      ['CHANNEL_OPEN_CONFIRMATION', 'canal pronto', 'servidor'],
      ['CHANNEL_DATA', 'bytes da aplicação', 'os dois'],
    ], why: 'Permite acessar serviços internos sem expô-los. Também pode servir de pivô: restrinja o encaminhamento e use bastions com política clara.' },
  't-remote': { short: 'O servidor abre uma porta e leva as conexões até o cliente.', concept: 'Com <b>-R</b>, o cliente pede ao servidor (GLOBAL_REQUEST <b>tcpip-forward</b>) que escute numa porta. Cada conexão recebida vira um canal <b>forwarded-tcpip</b> de volta ao cliente. Com <b>GatewayPorts</b> ligado, a porta fica aberta a toda a rede.', observe: ['GLOBAL_REQUEST tcpip-forward e REQUEST_SUCCESS.', 'O usuário externo chega ao serviço local pelo servidor.', 'Evento de aviso: o serviço local ficou exposto.'], cols: ['Mensagem', 'Função', 'Quem envia'], msgs: [
      ['tcpip-forward', 'pede escuta no servidor', 'cliente'],
      ['forwarded-tcpip', 'canal de volta ao cliente', 'servidor'],
      ['CHANNEL_DATA', 'requisição e resposta', 'os dois'],
    ], why: 'É a técnica usada para expor serviços atrás de NAT, e também para contornar firewalls. Monitore e restrinja túneis reversos.' },
  't-remote-nogw': { short: 'Sem GatewayPorts, a porta remota só aceita conexões locais.', concept: 'O padrão do sshd (<b>GatewayPorts no</b>) abre a porta do túnel reverso só no <b>loopback</b> do servidor. Quem vem de outro host recebe RST. É uma proteção padrão contra exposição acidental.', observe: ['RST ao usuário externo.', 'Compare com o cenário com GatewayPorts ligado.', 'O túnel em si foi aberto: só está restrito ao próprio servidor.'], cols: ['Mensagem', 'Função', 'Quem envia'], msgs: [
      ['tcpip-forward 127.0.0.1:9000', 'escuta só no loopback', 'cliente'],
      ['SYN :9000', 'tentativa externa', 'usuário externo'],
      ['RST', 'recusado', 'servidor'],
    ], why: 'Boas práticas: manter GatewayPorts no e expor serviços por proxy reverso controlado, com autenticação e TLS.' },
  't-dyn': { short: 'O cliente SSH vira um proxy SOCKS5.', concept: 'Com <b>-D</b>, o navegador envia pedidos SOCKS5 ao cliente SSH. Cada destino abre um canal direct-tcpip, e o servidor SSH resolve o nome (DNS) e conecta. O HTTPS segue de ponta a ponta entre o navegador e o site.', observe: ['SOCKS5 CONNECT com o nome do site.', 'O ClientHello do TLS passa em CHANNEL_DATA.', 'Evento: o servidor SSH não vê o conteúdo do HTTPS.'], cols: ['Mensagem', 'Função', 'Quem envia'], msgs: [
      ['SOCKS5 CONNECT', 'pede o destino', 'navegador'],
      ['direct-tcpip', 'canal até o destino', 'cliente'],
      ['CHANNEL_DATA', 'TLS do navegador ao site', 'os dois'],
    ], why: 'Protege o trecho até o servidor SSH em redes não confiáveis, mas o servidor passa a ver os destinos acessados (nomes e IPs).' },
  't-jump': { short: 'Salto por bastion com SSH de ponta a ponta até o alvo.', concept: 'No <b>ProxyJump</b>, o cliente abre um canal direct-tcpip até a porta 22 do alvo e roda <b>uma segunda sessão SSH</b> dentro dele. O bastion só repassa bytes cifrados. A chave de host verificada é a do <b>alvo</b>, e a autenticação ocorre direto no alvo.', observe: ['Duas camadas de cifragem: sessão interna e sessão externa.', 'O KEX_ECDH_REPLY interno traz a chave do alvo.', 'Mude "Chave do servidor" para Diferente: o cliente recusa o alvo, mesmo pelo bastion.'], cols: ['Mensagem', 'Função', 'Quem envia'], msgs: [
      ['direct-tcpip 10.0.0.50:22', 'canal até o alvo', 'cliente'],
      ['SSH interno', 'sessão completa com o alvo', 'cliente e alvo'],
    ], why: 'Melhor que o ForwardAgent: o bastion não vê credenciais nem tem acesso ao agente, e continua sendo um ponto único de entrada auditável.' },
  't-denied': { short: 'AllowTcpForwarding no: o pedido de túnel é recusado.', concept: 'O servidor pode proibir o encaminhamento (<b>AllowTcpForwarding no</b>). O pedido direct-tcpip recebe <b>CHANNEL_OPEN_FAILURE</b> com o motivo "administratively prohibited" (código 1).', observe: ['A recusa vem do servidor, depois do pedido do cliente.', 'O cliente fecha a conexão local.', 'Aba Configuração: a regra aparece no sshd_config.'], cols: ['Mensagem', 'Função', 'Quem envia'], msgs: [
      ['direct-tcpip', 'pede o túnel', 'cliente'],
      ['CHANNEL_OPEN_FAILURE', 'recusa por política', 'servidor'],
    ], why: 'Em servidores que só precisam de shell, desativar o encaminhamento reduz o risco de usar a máquina como pivô.' },
};
