// Cenários e documentação do simulador de 802.1X e RADIUS.
import type { ScenarioDef, ScenarioDoc } from '../../../sim-core/ui';

const abase = { method: 'tls' };
const fbase = { cause: 'cred' };
const pbase = { method: 'peap', pact: 'reauth', pdef: 'none' };
const sbase = { risk: 'md5', sdef: 'none' };

export const scenarios: ScenarioDef[] = [
  { id: 'a-tls', g: 'Autenticação bem-sucedida', sub: 'auth', label: 'EAP-TLS: certificados nos dois lados', set: { ...abase }, what: '<p>O Notebook liga o cabo. A porta começa <b>fechada</b>: só o EAPOL passa. O switch repassa o EAP ao servidor RADIUS, que valida o certificado do cliente. Com o <b>Access-Accept</b>, a porta abre e o tráfego de dados passa.</p>' },
  { id: 'a-peap', g: 'Autenticação bem-sucedida', sub: 'auth', label: 'PEAP: certificado no servidor, senha no cliente', set: { ...abase, method: 'peap' }, what: '<p>O servidor prova quem é com um certificado e abre um <b>túnel TLS</b>. Dentro dele, o Notebook prova a senha com MSCHAPv2. Só então o servidor aceita e a porta abre.</p>' },
  { id: 'a-md5', g: 'Autenticação bem-sucedida', sub: 'auth', label: 'EAP-MD5: só desafio e resposta', set: { ...abase, method: 'md5' }, what: '<p>O método mais simples: um desafio e a resposta calculada com a senha. Funciona e abre a porta, mas <b>não autentica o servidor</b>, não protege nada com um túnel e não deriva chaves.</p>' },
  { id: 'f-cred', g: 'Credencial recusada', sub: 'falha', label: 'Senha incorreta (PEAP)', set: { ...fbase }, what: '<p>O túnel TLS se forma normalmente, mas a prova da senha dentro dele <b>não confere</b>. O servidor responde com <b>Access-Reject</b>, o switch envia EAP-Failure e a porta continua fechada.</p>' },
  { id: 'f-cert', g: 'Credencial recusada', sub: 'falha', label: 'Certificado do cliente expirado (EAP-TLS)', set: { ...fbase, cause: 'cert' }, what: '<p>O Notebook apresenta um certificado fora da validade. O servidor <b>recusa</b> na rodada em que recebe o certificado, e a porta continua fechada.</p>' },
  { id: 'f-noserver', g: 'Sem resposta', sub: 'falha', label: 'Servidor RADIUS inalcançável', set: { ...fbase, cause: 'noserver' }, what: '<p>O switch envia o Access-Request e não recebe resposta. Ele <b>retransmite</b> e, ao fim das tentativas, desiste. A porta continua fechada: o acesso falha de modo seguro.</p>' },
  { id: 'f-secret', g: 'Sem resposta', sub: 'falha', label: 'Segredo compartilhado diferente', set: { ...fbase, cause: 'secret' }, what: '<p>O pedido <b>chega</b> ao servidor, mas o segredo compartilhado é outro. O servidor descarta o pacote em silêncio, sem enviar Reject. Para o switch, é igual a um servidor fora do ar.</p>' },
  { id: 'f-nosup', g: 'Sem resposta', sub: 'falha', label: 'Dispositivo sem suplicante', set: { ...fbase, cause: 'nosup' }, what: '<p>Uma impressora sem suplicante 802.1X não responde ao EAP-Request/Identity. O switch repete o pedido, esgota as tentativas e <b>mantém a porta fechada</b>.</p>' },
  { id: 'p-reauth', g: 'Sessão e estado da porta', sub: 'porta', label: 'Reautenticação sem cortar a sessão', set: { ...pbase }, what: '<p>A sessão já está autorizada, com um <b>Session-Timeout</b> de 3600 s. Ao expirar, o switch autentica de novo. A porta <b>permanece autorizada</b> durante o processo, e o tráfego não é interrompido.</p>' },
  { id: 'p-logoff', g: 'Sessão e estado da porta', sub: 'porta', label: 'EAPOL-Logoff fecha a porta', set: { ...pbase, pact: 'logoff' }, what: '<p>O suplicante envia <b>EAPOL-Logoff</b>. O switch fecha a porta de imediato, e o quadro seguinte é descartado. Não há resposta ao Logoff.</p>' },
  { id: 'p-extra', g: 'Mais de um dispositivo na porta', sub: 'porta', label: 'Segundo dispositivo aproveita a porta', set: { ...pbase, pact: 'extra' }, what: '<p>Um segundo dispositivo, ligado à mesma porta, <b>nunca se autenticou</b>. Como a autorização vale para a porta inteira, o quadro dele é encaminhado.</p>' },
  { id: 'p-extra-def', g: 'Mais de um dispositivo na porta', sub: 'porta', label: 'Defesa: autorização por endereço MAC', set: { ...pbase, pact: 'extra', pdef: 'permac' }, what: '<p>O switch autoriza só o endereço MAC que se autenticou. O quadro do segundo dispositivo é <b>descartado</b>.</p>' },
  { id: 's-md5', g: 'Sem autenticação mútua', sub: 'seg', label: 'EAP-MD5 aceita um autenticador falso', set: { ...sbase }, what: '<p>Um equipamento de terceiro faz o papel do autenticador. Como o EAP-MD5 não autentica o servidor, o Notebook <b>aceita o Success</b> e entrega o desafio e a resposta do usuário a quem controla o equipamento.</p>' },
  { id: 's-md5-def', g: 'Sem autenticação mútua', sub: 'seg', label: 'Defesa: EAP-TLS com autenticação mútua', set: { ...sbase, sdef: 'def' }, what: '<p>Com EAP-TLS, o suplicante valida o certificado do servidor. A cadeia do equipamento falso termina numa CA desconhecida, e o Notebook <b>interrompe o handshake</b> antes de enviar qualquer credencial.</p>' },
  { id: 's-peap', g: 'Servidor falso e certificado', sub: 'seg', label: 'PEAP sem validar o certificado do servidor', set: { ...sbase, risk: 'peap' }, what: '<p>O túnel TLS é aberto com qualquer servidor, porque o suplicante não confere o certificado. A prova da senha, mesmo protegida pelo túnel, <b>chega a quem controla o equipamento falso</b>.</p>' },
  { id: 's-peap-def', g: 'Servidor falso e certificado', sub: 'seg', label: 'Defesa: validar a CA e o nome do servidor', set: { ...sbase, risk: 'peap', sdef: 'def' }, what: '<p>O suplicante confere a cadeia do certificado e o nome do servidor RADIUS. Nada coincide, e ele <b>aborta o túnel</b> antes de enviar usuário ou senha.</p>' },
];

export const groupDoc: Record<string, string> = {
  'Autenticação bem-sucedida': 'O 802.1X mantém a porta fechada até o servidor RADIUS aceitar o suplicante. O EAP carrega a prova de identidade; o método EAP define como ela é feita; o switch só repassa o EAP e abre ou fecha a porta conforme o resultado.',
  'Credencial recusada': 'O servidor foi alcançado e disse não. A recusa é explícita (Access-Reject), e a porta continua fechada.',
  'Sem resposta': 'O servidor não respondeu, ou o dispositivo não participou. Nos três casos a porta continua fechada, pois o 802.1X falha de modo seguro. O diagnóstico depende de saber onde a conversa parou.',
  'Sessão e estado da porta': 'Uma porta autorizada não fica assim para sempre. O Session-Timeout força uma nova autenticação, e o suplicante pode encerrar a sessão com o EAPOL-Logoff.',
  'Mais de um dispositivo na porta': 'O 802.1X autoriza a porta, não o dispositivo. Se algo mais estiver ligado ao mesmo ponto, o modelo básico não o distingue. Nível defensivo: aviso, efeito e defesa.',
  'Sem autenticação mútua': 'Provar quem é o suplicante não basta: o suplicante também precisa saber quem é o servidor. Nível defensivo: aviso, efeito e defesa.',
  'Servidor falso e certificado': 'Um túnel TLS só protege se o suplicante confere com quem o abriu. Nível defensivo: aviso, efeito e defesa.',
};

export const scenDoc: Record<string, ScenarioDoc> = {
  'a-tls': {
    short: 'A porta só abre depois do Accept.',
    concept: 'Antes de qualquer coisa, a porta controlada do switch está fechada: o quadro de dados (um DHCPDISCOVER) é descartado, e só o EAPOL, pela porta não controlada, é aceito. O suplicante inicia com EAPOL-Start, o switch pede a identidade e repassa o EAP ao servidor RADIUS dentro de Access-Request. O servidor conduz o EAP-TLS: handshake TLS com certificado nos dois lados. Quando valida o certificado do cliente, responde Access-Accept, o switch envia EAP-Success ao suplicante e abre a porta.',
    observe: ['O primeiro quadro de dados é descartado pelo switch.', 'O EAP viaja em EAPOL entre o Notebook e o switch, e em RADIUS (EAP-Message) entre o switch e o servidor.', 'Só o Access-Accept abre a porta; o EAP-Success vai ao suplicante.', 'Depois, o mesmo quadro de dados é encaminhado.'],
    msgs: [['EAPOL-Start', 'o suplicante pede a autenticação', 'Notebook para SW1'], ['EAP-Request/Identity', 'o switch pede a identidade', 'SW1 para Notebook'], ['Access-Request', 'o switch repassa o EAP ao servidor', 'SW1 para RADIUS'], ['Access-Challenge', 'o servidor pede o próximo passo do método', 'RADIUS para SW1'], ['Access-Accept', 'o servidor aceita', 'RADIUS para SW1'], ['EAP-Success', 'o switch avisa o suplicante', 'SW1 para Notebook']],
    why: 'É a base de todo controle de acesso à rede por porta: nenhum dado entra enquanto o servidor não autorizar.',
  },
  'a-peap': {
    short: 'Um túnel TLS protege a senha.',
    concept: 'O PEAP primeiro autentica o servidor: um handshake TLS em que o servidor apresenta o certificado. Com o túnel de pé, o suplicante prova a senha com MSCHAPv2 dentro dele, protegida de quem observa o enlace. O servidor decide depois da resposta MSCHAPv2 e ainda confirma a autenticação interna antes do Accept. O PEAP não é um padrão da IETF, e o simulador agrupa as mensagens do túnel.',
    observe: ['As primeiras rodadas (handshake TLS) vão em claro; as seguintes aparecem em verde-azulado, protegidas pelo túnel.', 'O servidor decide só depois da resposta MSCHAPv2.', 'Um State acompanha cada Access-Request e Access-Challenge.'],
    msgs: [['EAP-Request/PEAP (Start)', 'o servidor abre o túnel', 'SW1 para Notebook'], ['EAP-Response/PEAP (resposta MSCHAPv2)', 'a prova da senha, dentro do túnel', 'Notebook para SW1'], ['Access-Accept', 'o servidor aceita', 'RADIUS para SW1']],
    why: 'É o método mais comum em redes que não emitem certificados de cliente. Mostra por que a senha só é segura se o suplicante validar o servidor.',
  },
  'a-md5': {
    short: 'Simples, e sem autenticar o servidor.',
    concept: 'No EAP-MD5 (RFC 3748, seção 5.4), o servidor envia um desafio de 16 bytes e o suplicante responde com o MD5 do identificador, da senha e do desafio, como no CHAP. A troca tem uma só rodada. O método não oferece autenticação mútua, integridade, confidencialidade nem derivação de chaves, e não protege contra ataques de dicionário.',
    observe: ['Uma só rodada de desafio e resposta.', 'Nada é cifrado.', 'Nenhuma verificação do servidor pelo suplicante.'],
    msgs: [['EAP-Request/MD5-Challenge', 'o desafio de 16 bytes', 'SW1 para Notebook'], ['EAP-Response/MD5-Challenge', 'o MD5 de identificador, senha e desafio', 'Notebook para SW1']],
    why: 'Serve para ver o mínimo que o EAP exige e por que ele não basta em redes reais. O cenário de risco com EAP-MD5 mostra o motivo.',
  },
  'f-cred': {
    short: 'Reject explícito.',
    concept: 'O túnel PEAP se forma e o suplicante envia a prova MSCHAPv2. O servidor compara com o hash da senha do usuário, não confere e responde com Access-Reject, que leva um EAP-Failure. O switch repassa o EAP-Failure ao suplicante e mantém a porta fechada. O quadro de dados seguinte é descartado.',
    observe: ['O servidor decide depois da resposta MSCHAPv2.', 'O Access-Reject leva o EAP-Failure; o EAP-Failure não é confirmado pelo suplicante.', 'A porta continua fechada.'],
    msgs: [['Access-Reject', 'o servidor nega o acesso', 'RADIUS para SW1'], ['EAP-Failure', 'o switch informa o suplicante', 'SW1 para Notebook']],
    why: 'A recusa explícita é o caso fácil de diagnosticar: o log do servidor diz o motivo. Compare com os cenários sem resposta.',
  },
  'f-cert': {
    short: 'Certificado fora da validade.',
    concept: 'No EAP-TLS o servidor decide logo depois de receber o certificado do cliente e a prova de posse da chave. Com o certificado expirado, a validação da cadeia falha (alerta TLS certificate_expired) e o servidor responde com Access-Reject. A porta continua fechada.',
    observe: ['A decisão vem na segunda rodada, antes do fim do handshake.', 'O motivo (certificado expirado) aparece só no servidor; o suplicante recebe um EAP-Failure.'],
    msgs: [['EAP-Response/EAP-TLS (Certificate, CertificateVerify, Finished)', 'o certificado do cliente', 'Notebook para SW1'], ['Access-Reject', 'o servidor nega o acesso', 'RADIUS para SW1']],
    why: 'Certificados vencidos são uma das causas mais comuns de falha em redes com EAP-TLS. Vale monitorar a validade deles.',
  },
  'f-noserver': {
    short: 'O switch retransmite e desiste.',
    concept: 'O switch envia o Access-Request e não recebe nada. Ele retransmite o mesmo pacote (mesmo Identifier) algumas vezes, com um intervalo, e depois desiste (RFC 5080, seção 2.2.1). O intervalo e o número de tentativas são ajustes do equipamento. Sem resposta, o suplicante recebe EAP-Failure e a porta continua fechada: o acesso falha de modo seguro.',
    observe: ['Três Access-Request iguais, perdidos, com 5 s de intervalo.', 'O EAP-Failure vem do próprio switch, sem Access-Reject.', 'A porta continua fechada.'],
    msgs: [['Access-Request', 'a primeira tentativa, perdida', 'SW1 para RADIUS'], ['Access-Request (retransmissão)', 'as tentativas seguintes', 'SW1 para RADIUS'], ['EAP-Failure', 'o switch desiste', 'SW1 para Notebook']],
    why: 'Se o servidor cai, ninguém novo entra. É o preço de falhar fechado, e um motivo para ter mais de um servidor RADIUS.',
  },
  'f-secret': {
    short: 'O pacote chega, e o servidor o ignora.',
    concept: 'O segredo compartilhado liga o switch ao servidor: ele entra no cálculo do Message-Authenticator. Se o segredo difere, o servidor recalcula o valor, vê que não confere e descarta o pacote em silêncio (RFC 3579, seção 3.2). Nenhuma mensagem de erro volta. O switch vê o mesmo que num servidor fora do ar.',
    observe: ['Os Access-Request chegam ao servidor (não são perdidos).', 'O servidor registra o descarte, mas não responde.', 'O sintoma no switch é o mesmo do cenário anterior.'],
    msgs: [['Access-Request', 'chega e é descartado', 'SW1 para RADIUS'], ['EAP-Failure', 'o switch desiste por tempo', 'SW1 para Notebook']],
    why: 'Quem só olha o switch confunde um segredo errado com um servidor inacessível. O diagnóstico está no log do servidor.',
  },
  'f-nosup': {
    short: 'Ninguém responde ao EAPOL.',
    concept: 'Um dispositivo sem suplicante não entende o EAPOL e ignora o EAP-Request/Identity. O autenticador repete o pedido em intervalos fixos (aqui, 30 s) e, esgotadas as repetições, deixa a porta fechada. O servidor RADIUS nem é consultado. Dispositivos assim exigem outra política, que não faz parte do modelo básico do 802.1X.',
    observe: ['Nenhuma mensagem RADIUS: o servidor não participa.', 'O EAP-Request/Identity é repetido três vezes, com 30 s entre elas.', 'O quadro de dados é descartado no fim.'],
    msgs: [['EAP-Request/Identity', 'o pedido, repetido', 'SW1 para Impressora']],
    why: 'Mostra por que impressoras, câmeras e telefones antigos são um desafio em redes com 802.1X.',
  },
  'p-reauth': {
    short: 'A porta segue aberta durante a renovação.',
    concept: 'O Access-Accept inicial trouxe um Session-Timeout (RFC 2865, seção 5.27). Quando ele expira, o autenticador reautentica o suplicante, começando por um novo EAP-Request/Identity. Durante todo o processo a porta permanece autorizada, e o quadro enviado no meio da troca passa normalmente. Se a reautenticação falhasse, a porta seria fechada.',
    observe: ['O estado da porta continua autorizado do início ao fim.', 'Um quadro de dados passa no meio da reautenticação.', 'O novo Access-Accept traz outro Session-Timeout.'],
    msgs: [['EAP-Request/Identity', 'o switch inicia a reautenticação', 'SW1 para Notebook'], ['Dados durante a reautenticação', 'a porta segue aberta', 'Notebook para SW1'], ['Access-Accept', 'a sessão é renovada', 'RADIUS para SW1']],
    why: 'A reautenticação limita por quanto tempo uma credencial roubada ou revogada continua valendo, sem derrubar o usuário.',
  },
  'p-logoff': {
    short: 'O logoff fecha a porta na hora.',
    concept: 'Ao encerrar a sessão, o suplicante envia EAPOL-Logoff. O autenticador volta a porta ao estado não autorizado imediatamente, sem esperar o Session-Timeout. O Logoff não tem resposta e, nas implementações sem MACsec, não é autenticado.',
    observe: ['A porta passa de autorizada a não autorizada assim que o Logoff chega.', 'O quadro de dados seguinte é descartado.', 'O servidor RADIUS não participa.'],
    msgs: [['EAPOL-Logoff', 'o suplicante encerra a sessão', 'Notebook para SW1']],
    why: 'Fechar a porta ao fim da sessão evita que o próximo dispositivo ligado ao mesmo cabo aproveite a autorização.',
  },
  'p-extra': {
    short: 'A autorização vale para a porta.',
    concept: 'No modelo básico do 802.1X, a porta controlada é aberta ou fechada como um todo. Depois que o Notebook se autentica, qualquer dispositivo ligado à mesma porta (por um hub ou um mini-switch) passa a usar a rede sem se autenticar. É o que se chama de carona na autorização.',
    observe: ['O quadro do Notebook é encaminhado.', 'O quadro do segundo dispositivo também, embora ele nunca tenha se autenticado.'],
    msgs: [['DHCPDISCOVER', 'do Notebook, encaminhado', 'Notebook para SW1'], ['DHCPDISCOVER', 'do segundo dispositivo, também encaminhado', '2º dispositivo para SW1']],
    why: 'O 802.1X controla a porta, não o dispositivo. Por isso a topologia física importa: portas devem ligar um só equipamento.',
  },
  'p-extra-def': {
    short: 'Cada MAC precisa se autenticar.',
    concept: 'Com a autorização por endereço MAC, o switch libera só os endereços que passaram pela autenticação. O quadro do segundo dispositivo, de outro MAC, é descartado até que ele próprio se autentique. Os nomes e o comportamento exato desse modo variam por fabricante. O MACsec (IEEE 802.1AE) vai além, pois protege o enlace e ata a sessão à chave negociada.',
    observe: ['O Notebook continua com acesso.', 'O segundo dispositivo tem o quadro descartado.'],
    msgs: [['DHCPDISCOVER', 'do Notebook, encaminhado', 'Notebook para SW1'], ['DHCPDISCOVER', 'do segundo dispositivo, descartado', '2º dispositivo para SW1']],
    why: 'É a forma comum de dar suporte a mais de um equipamento por porta, como um telefone IP e um computador, sem abrir a porta a todos.',
  },
  's-md5': {
    short: 'O suplicante não confere o servidor.',
    concept: 'Num cenário em que um equipamento de terceiro faz o papel do autenticador e do servidor, o EAP-MD5 não dá ao suplicante meio de desconfiar: o desafio e o Success parecem os de sempre. O suplicante envia a resposta ao desafio, que contém uma prova da senha, para quem controla o equipamento. O método não protege contra ataques de dicionário (RFC 3748, seção 5.4).',
    observe: ['O Notebook aceita o EAP-Success.', 'A resposta MD5 foi entregue a um equipamento que ninguém autenticou.'],
    msgs: [['EAP-Request/MD5-Challenge', 'o desafio do equipamento falso', 'Equipamento falso para Notebook'], ['EAP-Response/MD5-Challenge', 'a prova da senha', 'Notebook para Equipamento falso'], ['EAP-Success', 'aceito sem nenhuma prova do servidor', 'Equipamento falso para Notebook']],
    why: 'Autenticar só o cliente não basta. O suplicante também precisa de uma forma de saber com quem está falando.',
  },
  's-md5-def': {
    short: 'O certificado do servidor decide.',
    concept: 'Com EAP-TLS, o servidor apresenta um certificado, e o suplicante valida a cadeia até uma CA em que confia. Como a cadeia do equipamento falso termina numa CA desconhecida, o suplicante envia um alerta TLS unknown_ca (48) e interrompe. Nenhuma credencial foi enviada.',
    observe: ['O suplicante interrompe antes de enviar o certificado ou a senha.', 'O equipamento falso fica sem nada.'],
    msgs: [['EAP-Request/EAP-TLS (ServerHello, Certificate, CertificateRequest)', 'o certificado do equipamento falso', 'Equipamento falso para Notebook'], ['EAP-Response/EAP-TLS (alerta unknown_ca)', 'o suplicante aborta', 'Notebook para Equipamento falso']],
    why: 'A autenticação mútua é o que transforma o suplicante em quem desconfia, e não só em quem obedece.',
  },
  's-peap': {
    short: 'O túnel abriu com o interlocutor errado.',
    concept: 'O PEAP abre um túnel TLS e protege a senha dentro dele. Mas, se o suplicante não valida o certificado do servidor, o túnel pode ser aberto com qualquer um, e a prova da senha chega a quem controla o equipamento falso. O túnel protegeu o caminho, e não o destino.',
    observe: ['O suplicante segue com o túnel sem conferir o certificado.', 'A prova MSCHAPv2 da senha é entregue ao equipamento falso.'],
    msgs: [['EAP-Request/PEAP (ServerHello, Certificate)', 'o certificado do equipamento falso', 'Equipamento falso para Notebook'], ['EAP-Response/PEAP (resposta MSCHAPv2)', 'a prova da senha, dentro do túnel', 'Notebook para Equipamento falso']],
    why: 'É um erro de configuração comum: a validação do certificado do servidor vem desligada ou é deixada a cargo do usuário.',
  },
  's-peap-def': {
    short: 'Validar a CA e o nome.',
    concept: 'Com o suplicante configurado para confiar apenas na CA da organização e para conferir o nome do servidor RADIUS, o certificado do equipamento falso é recusado. O suplicante envia um alerta TLS bad_certificate (42) e interrompe o túnel antes de enviar usuário ou senha.',
    observe: ['O suplicante recusa o certificado.', 'Nenhum usuário nem senha saem do Notebook.'],
    msgs: [['EAP-Request/PEAP (ServerHello, Certificate)', 'o certificado do equipamento falso', 'Equipamento falso para Notebook'], ['EAP-Response/PEAP (alerta bad_certificate)', 'o suplicante aborta', 'Notebook para Equipamento falso']],
    why: 'A defesa está na configuração do suplicante: confiar só na CA certa, conferir o nome e não deixar o usuário aceitar certificados novos.',
  },
};

export const stageTitles: Record<string, string> = {
  auth: 'Diagrama de sequência: autenticação EAP entre suplicante, autenticador e servidor RADIUS',
  falha: 'Diagrama de sequência: falhas de autenticação e a porta que continua fechada',
  porta: 'Diagrama de sequência: estado da porta, reautenticação, logoff e segundo dispositivo',
  seg: 'Diagrama de sequência: riscos de autenticação e as defesas (nível defensivo)',
};
