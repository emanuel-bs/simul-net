// Controles do painel do SSH (portados do simulador legado, removido; veja o histórico do git).
import type { ControlDef } from '../../../sim-core/ui';

export const controls: ControlDef[] = [
  { id: 'rtt', num: true, grp: 'Rede', label: 'RTT (ms)', type: 'select', opts: [
      [5, '5'],
      [20, '20'],
      [50, '50'],
      [100, '100'],
      [200, '200'],
    ], def: 20, help: { t: 'RTT', p: ['Tempo de ida e volta entre cliente e servidor.', 'Cada mensagem do SSH que espera resposta custa meia ida e volta. O handshake do SSH leva vários RTTs antes do primeiro comando.'] } },
  { id: 'cProf', grp: 'Cliente', label: 'Perfil do cliente', type: 'select', wide: true, opts: [
      ['moderno', 'Moderno (OpenSSH 9.x)'],
      ['intermediario', 'Intermediário (OpenSSH 7.x)'],
      ['legado', 'Legado (OpenSSH 5.x)'],
    ], def: 'moderno', help: { t: 'Perfil do cliente', s: 'Conjunto de algoritmos que o cliente oferece.', p: ['<b>Moderno:</b> curve25519, ed25519, chacha20 e AES-GCM.', '<b>Intermediário:</b> OpenSSH 7.x, ainda aceita RSA com SHA-1, CBC e MACs antigos.', '<b>Legado:</b> OpenSSH 5.x, só DH com SHA-1, DSA, 3DES e CBC. Vários servidores atuais recusam.'] } },
  { id: 'known', grp: 'Cliente', label: 'Chave do servidor no known_hosts', type: 'select', wide: true, opts: [
      ['known', 'Conhecida (confere)'],
      ['new', 'Primeira conexão (não consta)'],
      ['changed', 'Diferente da registrada'],
    ], def: 'known', help: { t: 'known_hosts', s: 'O que o cliente já sabe sobre a chave deste servidor.', p: ['<b>Conhecida:</b> o fingerprint recebido é igual ao guardado em ~/.ssh/known_hosts.', '<b>Primeira conexão:</b> o cliente nunca viu este servidor. É o momento de confiar no primeiro uso (TOFU) e conferir o fingerprint por outro canal.', '<b>Diferente:</b> o servidor apresenta outra chave. Pode ser reinstalação ou interceptação (MITM).'] } },
  { id: 'cMethod', subs: ['session'], grp: 'Cliente', label: 'Método de autenticação', type: 'select', wide: true, opts: [
      ['publickey', 'Chave pública (ed25519)'],
      ['password', 'Senha'],
      ['kbd', 'Senha + código TOTP (keyboard-interactive)'],
    ], def: 'publickey', help: { t: 'Método de autenticação', s: 'Como o cliente prova quem é.', p: ['<b>Chave pública:</b> o cliente assina um desafio com a chave privada. A senha nunca viaja.', '<b>Senha:</b> viaja dentro do canal cifrado, mas pode ser adivinhada por tentativas repetidas.', '<b>Senha + TOTP:</b> o servidor pergunta a senha e depois um código temporário (keyboard-interactive).'] } },
  { id: 'credOk', subs: ['session'], grp: 'Cliente', label: 'Credencial correta', type: 'check', def: true, help: { t: 'Credencial correta', s: 'Se a chave, a senha ou o código estão certos.', p: ['Desmarcado, a chave não consta em authorized_keys, ou a senha e o código estão errados. Serve para ver a falha e as tentativas.'] } },
  { id: 'user', subs: ['session'], grp: 'Cliente', label: 'Usuário', type: 'select', opts: [
      ['aluno', 'aluno'],
      ['root', 'root'],
    ], def: 'aluno', help: { t: 'Usuário', s: 'Conta usada no login.', p: ['<b>root</b> costuma ser recusado pela configuração PermitRootLogin, mesmo com a credencial certa.'] } },
  { id: 'use', subs: ['session'], grp: 'Sessão', label: 'Uso da sessão', type: 'select', opts: [
      ['shell', 'Shell interativo'],
      ['exec', 'Comando remoto'],
      ['sftp', 'Transferência SFTP'],
    ], def: 'shell', help: { t: 'Uso da sessão', s: 'O que o cliente pede depois de autenticado.', p: ['<b>Shell:</b> terminal interativo (pty + shell).', '<b>Comando:</b> executa um comando e encerra.', '<b>SFTP:</b> subsistema de transferência de arquivos sobre o mesmo canal SSH.'] } },
  { id: 'tunKind', subs: ['tunnel'], grp: 'Túnel', label: 'Tipo de túnel', type: 'select', wide: true, opts: [
      ['local', 'Local (-L): acessar um serviço interno'],
      ['remote', 'Remoto (-R): expor um serviço local'],
      ['dynamic', 'Dinâmico (-D): proxy SOCKS'],
      ['jump', 'ProxyJump (-J): salto por bastion'],
    ], def: 'local', help: { t: 'Tipo de túnel', s: 'Direção do encaminhamento de porta.', p: ['<b>-L:</b> uma porta local leva ao serviço interno, passando pelo servidor SSH.', '<b>-R:</b> uma porta do servidor leva a um serviço da máquina do cliente.', '<b>-D:</b> o cliente vira um proxy SOCKS5 e cada destino abre um canal.', '<b>-J:</b> o cliente chega a um alvo interno passando por um bastion, com SSH de ponta a ponta.'] } },
  { id: 'sProf', grp: 'Servidor', label: 'Perfil do servidor', type: 'select', wide: true, opts: [
      ['moderno', 'Moderno (OpenSSH 9.x)'],
      ['intermediario', 'Intermediário (OpenSSH 7.x)'],
      ['legado', 'Legado (OpenSSH 5.x)'],
      ['endurecido', 'Endurecido (só algoritmos modernos)'],
    ], def: 'moderno', help: { t: 'Perfil do servidor', s: 'Algoritmos que o sshd aceita.', p: ['Se não houver algoritmo em comum com o cliente, a conexão falha antes da troca de chaves.', '<b>Endurecido:</b> só curve25519, ed25519, chacha20/AES-GCM e HMAC-SHA2-512-ETM.'] } },
  { id: 'sPass', subs: ['session'], grp: 'Servidor', label: 'PasswordAuthentication', type: 'check', def: true, help: { t: 'PasswordAuthentication', s: 'Aceitar login por senha.', p: ['Desligar a senha e exigir chave pública elimina a adivinhação de senhas.'] } },
  { id: 'sMfa', subs: ['session'], grp: 'Servidor', label: 'Exigir 2º fator (chave + TOTP)', type: 'check', def: false, help: { t: 'Segundo fator', s: 'AuthenticationMethods publickey,keyboard-interactive.', p: ['O servidor só libera o acesso depois de duas etapas: chave pública e um código TOTP.', 'A primeira etapa termina com "sucesso parcial" (partial success).'] } },
  { id: 'allowFwd', subs: ['tunnel'], grp: 'Servidor', label: 'AllowTcpForwarding', type: 'check', def: true, help: { t: 'AllowTcpForwarding', s: 'Permitir túneis pelo servidor.', p: ['Desligado, o servidor recusa os canais direct-tcpip e o tcpip-forward (administratively prohibited).', 'Em bastions, restringir o encaminhamento reduz o risco de pivoteamento.'] } },
  { id: 'permitRoot', adv: true, subs: ['session'], grp: 'Servidor', label: 'PermitRootLogin', type: 'select', opts: [
      ['prohibit-password', 'prohibit-password (só chave)'],
      ['no', 'no'],
      ['yes', 'yes'],
    ], def: 'prohibit-password', help: { t: 'PermitRootLogin', s: 'Se o root pode entrar por SSH.', p: ['<b>no:</b> nunca. <b>prohibit-password:</b> só por chave. <b>yes:</b> também por senha (arriscado).'] } },
  { id: 'maxTries', adv: true, num: true, subs: ['session'], grp: 'Servidor', label: 'MaxAuthTries', type: 'select', opts: [
      [3, '3'],
      [6, '6 (padrão)'],
    ], def: 6, help: { t: 'MaxAuthTries', s: 'Falhas de autenticação antes de o servidor desconectar.', p: ['O cliente OpenSSH tenta no máximo 3 senhas por conexão. Com MaxAuthTries = 3 é o servidor que encerra a conexão.'] } },
  { id: 'hkCheck', adv: true, grp: 'Cliente', label: 'StrictHostKeyChecking', type: 'select', wide: true, opts: [
      ['ask', 'ask (pergunta ao usuário)'],
      ['accept-new', 'accept-new'],
      ['yes', 'yes (só hosts conhecidos)'],
      ['no', 'no (não verifica, inseguro)'],
    ], def: 'ask', help: { t: 'StrictHostKeyChecking', s: 'Política do cliente para chaves de servidor.', p: ['<b>ask:</b> pergunta na primeira conexão e recusa chave alterada.', '<b>accept-new:</b> grava chaves novas sem perguntar e recusa as alteradas.', '<b>yes:</b> recusa qualquer servidor ausente do known_hosts.', '<b>no:</b> aceita tudo. Desliga a proteção contra interceptação.'] } },
  { id: 'fwdAgent', adv: true, subs: ['session'], grp: 'Cliente', label: 'ForwardAgent', type: 'check', def: false, help: { t: 'ForwardAgent', s: 'Encaminhar o agente SSH ao servidor.', p: ['Permite usar suas chaves a partir do servidor, sem copiá-las. Quem tiver privilégio no servidor pode usar o agente enquanto a sessão durar. Prefira ProxyJump.'] } },
  { id: 'gateway', adv: true, subs: ['tunnel'], grp: 'Servidor', label: 'GatewayPorts', type: 'check', def: false, help: { t: 'GatewayPorts', s: 'Porta remota aberta para toda a rede.', p: ['Em túneis -R, o padrão é abrir a porta só no loopback do servidor. Com GatewayPorts ligado, qualquer host que alcance o servidor usa o túnel.'] } },
];
