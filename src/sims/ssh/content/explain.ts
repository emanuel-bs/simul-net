// Texto da aba Experimento e do cabeçalho do cenário.
import { esc, plural, type Trace } from '../../../sim-core';
import type { ScenarioDef } from '../../../sim-core/ui';
import { PROF, isAead, type SshParams } from '../engine';
import { controls } from './controls';
import { grade } from './config';

/** Texto "Configuração do cenário" mostrado sob o título do cenário. */
export function setup(s: ScenarioDef): string {
  const P: Record<string, unknown> = {};
  controls.forEach((c) => {
    P[c.id] = c.def;
  });
  Object.keys(s.set || {}).forEach((k) => {
    P[k] = (s.set as Record<string, unknown>)[k];
  });
  const q = P as unknown as SshParams;
  const p: string[] = [];
  if (s.sub === 'tunnel') {
    p.push('Túnel ' + { local: 'local (-L)', remote: 'remoto (-R)', dynamic: 'dinâmico (-D)', jump: 'ProxyJump (-J)' }[q.tunKind], 'RTT de ' + q.rtt + ' ms', 'AllowTcpForwarding ' + (q.allowFwd ? 'yes' : 'no'));
    if (q.tunKind === 'remote') p.push('GatewayPorts ' + (q.gateway ? 'yes' : 'no'));
  } else {
    p.push(
      'cliente ' + PROF[q.cProf].nome,
      'servidor ' + PROF[q.sProf].nome,
      'RTT de ' + q.rtt + ' ms',
      'known_hosts: ' + { known: 'conhecida', new: 'primeira conexão', changed: 'chave diferente' }[q.known],
      'método: ' + { publickey: 'chave pública', password: 'senha', kbd: 'senha + TOTP' }[q.cMethod] + (q.credOk ? '' : ' (credencial errada)'),
      'usuário ' + q.user,
    );
    p.push('PasswordAuthentication ' + (q.sPass ? 'yes' : 'no'), 'MaxAuthTries ' + q.maxTries);
    if (q.sMfa) p.push('2º fator exigido');
    if (q.fwdAgent) p.push('ForwardAgent');
  }
  return 'Configuração do cenário: <code>' + esc(p.join('; ')) + '</code>';
}

const concepts = (a: string[]): string => '<h3>Conceitos observados</h3><ul>' + a.map((x) => '<li>' + x + '</li>').join('') + '</ul>';

function next(tr: Trace, P: SshParams): string {
  const s: string[] = [];
  const r = tr.raw;
  const g = grade(P);
  if (r.sub === 'session') {
    if (P.known === 'known') s.push('Mude "Chave do servidor no known_hosts" para <b>Diferente</b> e veja o cliente abortar antes da autenticação.');
    if (P.cProf !== 'legado') s.push('Troque o cliente para <b>Legado</b> e o servidor para <b>Endurecido</b>: a negociação falha no KEXINIT.');
    if (P.sPass && P.cMethod === 'publickey') s.push('Desmarque PasswordAuthentication e mude o método para <b>Senha</b>: o servidor não oferece a opção.');
    if (!P.sMfa) s.push('Marque <b>Exigir 2º fator</b> e veja o sucesso parcial depois da chave.');
    if (P.cMethod !== 'password' || P.credOk) s.push('Use método <b>Senha</b> com "Credencial correta" desmarcada e MaxAuthTries = 3 (Ajustes avançados): o servidor derruba a conexão na 3ª falha.');
  }
  s.push('Abra a aba <b>Configuração</b>: a nota é ' + g.letter + ' (' + g.pct + '%). Quais itens faltam para chegar a A?');
  if (r.sub === 'tunnel') {
    s.push('Desmarque <b>AllowTcpForwarding</b> e compare a recusa do servidor.', 'Veja o <b>ProxyJump</b>: a sessão interna é cifrada de ponta a ponta, e o bastion só repassa bytes.');
  }
  return '<h3>Para explorar em seguida</h3><ul>' + s.slice(0, 4).map((x) => '<li>' + x + '</li>').join('') + '</ul>';
}

function explainSession(tr: Trace, P: SshParams): string {
  const r = tr.raw;
  const C = PROF[P.cProf];
  const S = PROF[P.sProf];
  const n = r.neg;
  let h =
    '<h3>Configuração</h3><p>O cliente (' + esc(C.nome) + ') conecta a um servidor SSH (' + esc(S.nome) + ') com <b>RTT de ' + P.rtt + ' ms</b>. O known_hosts do cliente indica: <b>' +
    { known: 'chave conhecida (confere)', new: 'primeira conexão (a chave não consta)', changed: 'chave registrada diferente da apresentada' }[P.known] + '</b>, com StrictHostKeyChecking = ' + esc(P.hkCheck) + '. ' +
    'O usuário <b>' + esc(P.user) + '</b> tenta entrar por <b>' + { publickey: 'chave pública', password: 'senha', kbd: 'senha + código TOTP' }[P.cMethod] + '</b>' + (P.credOk ? '' : ' (com credencial incorreta)') +
    '. No servidor: PasswordAuthentication ' + (P.sPass ? 'yes' : 'no') + ', PermitRootLogin ' + esc(P.permitRoot) + ', MaxAuthTries ' + P.maxTries + (P.sMfa ? ', segundo fator exigido' : '') + '.</p>';
  h += '<h3>O que aconteceu</h3>';
  h += '<p><b>Conexão e versões.</b> Depois do handshake TCP (1 RTT), os dois lados trocaram as linhas de versão em texto puro: <code>' + esc(C.banner) + '</code> e <code>' + esc(S.banner) + '</code>. Já aqui o servidor revela o software e a versão a qualquer observador.</p>';
  if (r.fail && r.fail.stage === 'neg') {
    h +=
      '<p><b>Negociação.</b> Cada lado enviou o KEXINIT com suas listas. Para <b>' + { kex: 'a troca de chaves', hostkey: 'a chave de host', enc: 'a cifra', mac: 'o MAC' }[r.fail.what as 'kex' | 'hostkey' | 'enc' | 'mac'] +
      '</b> não existe nenhum algoritmo em comum, então a negociação falhou (' + esc(r.fail.msg.slice(0, 110)) + '...). O cliente enviou DISCONNECT 3 e encerrou o TCP. <b>Nada foi cifrado e nenhuma credencial foi enviada.</b> Servidores endurecidos deixam de atender clientes antigos: esse é o custo de recusar algoritmos fracos.</p>';
    return h + concepts(['<b>Banner</b> e <b>KEXINIT</b> em claro', '<b>Negociação de algoritmos</b>: vale o primeiro da lista do cliente que o servidor aceita', '<b>Falha de negociação</b> (KEY_EXCHANGE_FAILED)']) + next(tr, P);
  }
  h +=
    '<p><b>Negociação.</b> Pela regra do SSH, vale o primeiro algoritmo da lista do cliente que o servidor também tem: troca de chaves <b>' + esc(n.kex) + '</b>, chave de host <b>' + esc(n.hostkey) + '</b>, cifra <b>' + esc(n.enc) + '</b>' +
    (isAead(n.enc) ? ' (AEAD, sem MAC separado)' : ', MAC <b>' + esc(n.mac) + '</b>') + '.' +
    (r.weakChosen && r.weakChosen.length
      ? ' <b>Atenção:</b> foram negociados algoritmos fracos (' + esc(r.weakChosen.join(', ')) + '). A conexão funciona, mas a proteção é menor e o cliente não avisa.'
      : ' Todos os algoritmos escolhidos são considerados fortes.') + '</p>';
  h += '<p><b>Troca de chaves.</b> O cliente enviou a metade pública de um segredo Diffie-Hellman efêmero e o servidor respondeu com a sua, a chave pública de host (' + esc(r.hk.type) + ') e a assinatura do hash H. O segredo K foi calculado nas duas pontas, <b>sem nunca trafegar</b>. Como o par é descartado depois, uma chave comprometida no futuro não decifra esta sessão (<i>forward secrecy</i>).</p>';
  const newText =
    'O servidor era desconhecido. ' +
    ({
      'aceita após pergunta': 'O ssh mostrou o fingerprint e o usuário digitou "yes": a chave foi gravada (confiança no primeiro uso, TOFU). Só é seguro se o fingerprint for conferido por outro canal.',
      'gravada sem perguntar': 'Com accept-new, a chave foi gravada sem pergunta: protege contra mudanças futuras, mas não contra um intermediário já na primeira conexão.',
      'aceita sem verificar': 'Com StrictHostKeyChecking = no, o cliente aceitou sem verificar nada: não há proteção contra interceptação.',
    } as Record<string, string>)[r.hk.action] || 'O cliente exigia que o servidor já constasse no known_hosts (StrictHostKeyChecking = yes) e abortou.';
  const hk = {
    known: 'O fingerprint recebido (' + esc((r.hk.recv || '').slice(0, 26)) + '…) conferiu com o known_hosts: o servidor é o que o cliente esperava.',
    new: newText,
    changed: 'A chave apresentada (' + esc((r.hk.recv || '').slice(0, 26)) + '…) é <b>diferente</b> da registrada (' + esc((r.hk.reg || '').slice(0, 26)) + '…).',
  }[P.known];
  h += '<p><b>Verificação do servidor.</b> ' + hk + '</p>';
  if (r.fail && r.fail.stage === 'hostkey') {
    h += '<p>O cliente <b>abortou antes do NEWKEYS e de qualquer credencial</b>. É exatamente a proteção do SSH contra interceptação: um intermediário não tem a chave privada do servidor verdadeiro e não consegue assinar H com ela. A resposta correta é confirmar com o administrador, por outro canal, se a chave mudou de propósito.</p>';
    return h + concepts(['<b>known_hosts</b> e fingerprint da chave de host', '<b>Assinatura de H</b>: prova de posse da chave de host', '<b>MITM</b> detectado pela chave diferente']) + next(tr, P);
  }
  h += '<p><b>Cifragem.</b> Depois do NEWKEYS, seis chaves foram derivadas de K, H e do session_id (veja a aba Chaves e sessão). Tudo daqui em diante vai <b>cifrado e autenticado</b>: um observador vê só pacotes "Encrypted packet" com tamanho e tempo.</p>';
  const A = r.auth;
  if (A.ok) {
    h +=
      '<p><b>Autenticação.</b> O método "none" consultou o que o servidor aceita (' + esc(A.methods.join(', ')) + '). O usuário entrou por <b>' + esc(A.via) + '</b>' +
      (A.partial ? ', em duas etapas: a chave terminou em sucesso parcial e o servidor pediu o código TOTP' : '') + (A.tries ? ', depois de ' + plural(A.tries, 'falha', 'falhas') : '') + '. ' +
      ({
        'chave pública': 'A chave privada assinou o session_id: nenhum segredo reutilizável trafegou.',
        senha: 'A senha viajou cifrada, mas o servidor a recebeu em claro.',
        'senha + TOTP': 'A senha e o código TOTP foram enviados em respostas cifradas.',
        'chave + TOTP': 'Mesmo que a chave seja roubada, sem o código TOTP o acesso não é concedido.',
      } as Record<string, string>)[A.via] + '</p>';
    const use = {
      shell: 'abriu um canal de sessão, pediu um pseudoterminal e um shell, e o usuário digitou comandos',
      exec: 'abriu um canal de sessão e executou um único comando (exec), recebendo a saída e o código de saída',
      sftp: 'abriu um canal de sessão e pediu o subsistema SFTP, trocando pacotes SFTP (INIT, OPEN, READ, DATA) em CHANNEL_DATA',
    }[P.use];
    h += '<p><b>Canal.</b> O cliente ' + use + '. Vários canais podem coexistir na mesma conexão cifrada, cada um com a sua janela de controle de fluxo.' +
      (P.fwdAgent ? ' Com <b>ForwardAgent</b>, o servidor ganhou acesso ao agente do cliente durante a sessão: quem tem privilégio nele pode usar suas chaves.' : '') + '</p>';
  } else {
    const why =
      ({
        root: 'o usuário <b>root</b> foi recusado por PermitRootLogin (' + esc(P.permitRoot) + ') mesmo com a credencial correta',
        key: 'a chave não consta em authorized_keys',
        pw: 'a senha estava incorreta',
        nopass: 'o servidor <b>não oferece senha</b> (PasswordAuthentication no), então o cliente nem chegou a tentar',
        nokbd: 'o servidor não aceita keyboard-interactive como primeiro método',
        kbd: 'a senha ou o código TOTP estavam incorretos',
        totp: 'o código TOTP estava incorreto',
        restricted: 'o cliente desativa a senha quando a chave do servidor mudou',
      } as Record<string, string>)[A.denied] || 'as credenciais não foram aceitas';
    h +=
      '<p><b>Autenticação.</b> O acesso foi <b>negado</b>: ' + why + '. ' + (A.tries ? 'O servidor contou ' + plural(A.tries, 'falha', 'falhas') + ' (MaxAuthTries = ' + P.maxTries + ')' : '') +
      (A.serverDisconnect
        ? ' e <b>derrubou a conexão</b> ao atingir o limite ("Too many authentication failures"). Limitar as tentativas por conexão atrasa a adivinhação de senhas, mas o atacante pode reconectar; a defesa de fato é desativar a senha, usar chaves e bloquear origens (fail2ban).'
        : '.') + ' Cada falha vai para o auth.log (veja a aba Configuração).</p>';
  }
  const cs = [
    '<b>Banner</b> e <b>KEXINIT</b> em claro',
    '<b>Negociação</b>: o primeiro algoritmo do cliente que o servidor aceita',
    '<b>Diffie-Hellman efêmero</b> e <b>forward secrecy</b>',
    '<b>Chave de host</b>, <b>known_hosts</b> e assinatura de H',
    '<b>NEWKEYS</b> e derivação das chaves (A a F)',
  ];
  if (r.hk.action === 'aceita após pergunta') cs.push('<b>TOFU</b>: confiança no primeiro uso');
  cs.push(A.ok ? '<b>Autenticação</b> por ' + esc(A.via) : '<b>Autenticação recusada</b> e contagem de falhas');
  if (A.ok) cs.push('<b>Canais</b> e janela de controle de fluxo');
  if (r.weakChosen && r.weakChosen.length) cs.push('<b>Algoritmos fracos</b> negociados');
  return h + concepts(cs) + next(tr, P);
}

function explainTunnel(tr: Trace, P: SshParams): string {
  const r = tr.raw;
  const k = r.kind as SshParams['tunKind'];
  const nm = { local: 'o túnel local (-L)', remote: 'o túnel remoto (-R)', dynamic: 'o proxy dinâmico (-D)', jump: 'o ProxyJump (-J)' }[k];
  let h =
    '<h3>Configuração</h3><p>Sessão SSH já autenticada, com <b>RTT de ' + P.rtt + ' ms</b>. Cenário: <b>' + nm + '</b>, com <b>AllowTcpForwarding ' + (P.allowFwd ? 'yes' : 'no') + '</b>' +
    (k === 'remote' ? ' e <b>GatewayPorts ' + (P.gateway ? 'yes' : 'no') + '</b>' : '') +
    '. O foco aqui é o que acontece depois do login: os canais abertos dentro da conexão cifrada.</p><h3>O que aconteceu</h3>';
  if (r.blocked) {
    h +=
      '<p>O cliente pediu ' + { local: 'um canal direct-tcpip', remote: 'o encaminhamento tcpip-forward', dynamic: 'um canal direct-tcpip para o destino do SOCKS', jump: 'um canal direct-tcpip até o alvo' }[k] +
      ' e o servidor <b>recusou</b> (' + (k === 'remote' ? 'REQUEST_FAILURE' : 'CHANNEL_OPEN_FAILURE, código 1, administratively prohibited') +
      ') porque <b>AllowTcpForwarding</b> está desativado. A sessão SSH continua de pé; só o encaminhamento é negado. Essa política evita que o servidor sirva de pivô para alcançar a rede interna.</p>';
    return h + concepts(['<b>AllowTcpForwarding</b>', '<b>Canais</b> e o código de falha (administratively prohibited)']) + next(tr, P);
  }
  if (k === 'local') {
    h += '<p>O cliente escuta na porta 5433 do loopback. Cada conexão da aplicação virou um canal <b>direct-tcpip</b> até <code>db.interno:5432</code>: o servidor abriu uma conexão TCP nova até o banco e repassou os bytes. O trecho <b>cliente ↔ servidor</b> foi cifrado e autenticado pelo SSH. O trecho <b>servidor ↔ banco</b> não faz parte do SSH e segue <b>em claro</b>, a menos que o banco use TLS. Para o banco, a conexão vem do servidor SSH, não do cliente.</p>';
  } else if (k === 'remote') {
    h += r.refused
      ? '<p>O cliente pediu ao servidor que escutasse na porta 9000 (<b>tcpip-forward</b>). Sem <b>GatewayPorts</b>, o sshd abriu a porta só no <b>loopback</b>. Quando o usuário externo tentou conectar, recebeu <b>RST</b>: só quem já está no servidor alcança a porta. É o padrão seguro contra exposição acidental.</p>'
      : '<p>O cliente pediu ao servidor que escutasse na porta 9000 (<b>tcpip-forward</b>). Com <b>GatewayPorts</b> ligado, a porta ficou aberta em 0.0.0.0. Um usuário externo conectou, o servidor abriu um canal <b>forwarded-tcpip</b> de volta ao cliente, e o cliente chegou ao serviço local. O trecho do usuário externo até o servidor está <b>fora do SSH</b> e o serviço local ficou <b>exposto na internet</b>: protegido só pela autenticação e pelo TLS que o próprio serviço tiver.</p>';
  } else if (k === 'dynamic') {
    h += '<p>O navegador falou SOCKS5 com o cliente SSH e pediu <code>example.org:443</code> pelo <b>nome</b>. Cada destino virou um canal <b>direct-tcpip</b>; o servidor SSH resolveu o DNS e conectou ao site. O HTTPS seguiu de ponta a ponta (TLS entre o navegador e o site): o servidor SSH repassa bytes e <b>vê os destinos</b> (nomes e IPs), mas não o conteúdo cifrado pelo TLS. Quem usa o proxy passa a confiar no servidor SSH quanto a metadados.</p>';
  } else {
    h += r.refused
      ? '<p>O cliente abriu um canal até o alvo e iniciou uma sessão SSH interna. A chave de host do <b>alvo</b> não conferiu com a registrada, e o cliente <b>abortou</b>: o bastion não consegue encobrir a troca de chave do alvo porque não tem a chave privada dele.</p>'
      : '<p>O cliente pediu ao bastion um canal <b>direct-tcpip</b> até a porta 22 do alvo e, dentro dele, rodou uma <b>segunda sessão SSH completa</b> (banner, KEXINIT, troca de chaves, NEWKEYS, autenticação). A chave de host verificada é a do <b>alvo</b>, e a autenticação ocorre direto nele. Os pacotes internos vão <b>cifrados duas vezes</b>; o bastion só repassa bytes e não consegue lê-los nem alterá-los. É por isso que o ProxyJump é preferível ao ForwardAgent.</p>';
  }
  const cs = {
    local: ['<b>direct-tcpip</b> (canal para um destino)', '<b>Trechos</b> do túnel: o que é cifrado e o que não é', '<b>Origem vista pelo destino</b>: o servidor SSH'],
    remote: ['<b>tcpip-forward</b> e <b>forwarded-tcpip</b>', '<b>GatewayPorts</b> e exposição do serviço local', '<b>Túnel reverso</b> para alcançar serviços atrás de NAT'],
    dynamic: ['<b>SOCKS5</b> sobre SSH', '<b>direct-tcpip</b> por destino', '<b>TLS de ponta a ponta</b> dentro do túnel'],
    jump: ['<b>ProxyJump</b> e sessão SSH aninhada', '<b>Cifragem em duas camadas</b>', '<b>Chave de host do alvo</b> verificada de ponta a ponta'],
  }[k];
  return h + concepts(cs) + next(tr, P);
}

export function explain(tr: Trace, P: SshParams): string {
  const obj =
    tr.raw.sub === 'tunnel'
      ? 'Observar como o SSH encaminha portas e protocolos dentro do canal cifrado, e o que continua sem proteção em cada trecho.'
      : 'Observar como o SSH estabelece uma sessão segura: negociação, troca de chaves, verificação do servidor, autenticação e canais.';
  return '<p><b>Objetivo.</b> ' + obj + '</p>' + (tr.raw.sub === 'tunnel' ? explainTunnel(tr, P) : explainSession(tr, P));
}
