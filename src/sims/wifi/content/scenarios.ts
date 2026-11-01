// Cenários e documentação do simulador de Wi-Fi (IEEE 802.11).
import type { ScenarioDef, ScenarioDoc } from '../../../sim-core/ui';

const dbase = { scan: 'passivo', ssid: 'visivel', ch: 6, sec: 'aberta', res: 'ok' };
const mbase = { mkind: 'basico', rts: false };
const rbase = { mov: 'roam', ft: false, lis: 1 };
const cbase = { ch2: 6, larg: 20 };

export const stageTitles: Record<string, string> = {
  desc: 'Descoberta e associação: varredura, autenticação e associação',
  meio: 'Acesso ao meio: CSMA/CA, ACK, backoff e RTS/CTS',
  mov: 'Roaming e economia de energia',
  canal: 'Canais: duas redes vizinhas',
};

export const scenarios: ScenarioDef[] = [
  { id: 'd-passivo', g: 'Descobrir e entrar na rede', sub: 'desc', label: 'Varredura passiva e rede aberta', set: { ...dbase }, what: '<p>O Notebook liga o rádio e <b>só escuta</b>, canal por canal, até ouvir o <b>beacon</b> do AP. Depois passa pelos três passos do padrão: <b>autenticação</b> (sistema aberto), <b>associação</b> e o primeiro frame de dados, que a rede aberta deixa passar.</p>' },
  { id: 'd-ativo', g: 'Descobrir e entrar na rede', sub: 'desc', label: 'Varredura ativa com Probe Request', set: { ...dbase, scan: 'ativo' }, what: '<p>Em vez de esperar o beacon, o cliente <b>pergunta</b> com um Probe Request em cada canal e espera 20 ms pela resposta. Acha o AP mais rápido, mas anuncia a própria presença.</p>' },
  { id: 'd-oculta', g: 'Descobrir e entrar na rede', sub: 'desc', label: 'Rede com SSID oculto', set: { ...dbase, ssid: 'oculto' }, what: '<p>O beacon chega com o <b>nome vazio</b>. O cliente, que tem o perfil salvo, pergunta pelo nome com um Probe Request dirigido, e o AP responde. O nome da rede aparece <b>em claro</b> no ar: ocultar o SSID não protege nada.</p>' },
  { id: 'd-rsn', g: 'Descobrir e entrar na rede', sub: 'desc', label: 'Rede protegida: a associação não basta', set: { ...dbase, sec: 'rsn' }, what: '<p>O AP anuncia o elemento <b>RSN</b>. A autenticação 802.11 continua "aberta", e o cliente se associa, mas o primeiro frame de dados é <b>descartado</b>: a porta só abre depois do handshake de quatro vias (WPA2 ou WPA3).</p>' },
  { id: 'd-cheio', g: 'Quando a associação falha', sub: 'desc', label: 'AP lotado recusa a associação', set: { ...dbase, res: 'cheio' }, what: '<p>O AP responde à Association Request com o <b>Status Code 17</b>: não consegue tratar mais estações. O cliente continua no <b>estado 2</b> (autenticado, mas não associado) e precisa procurar outro AP.</p>' },
  { id: 'm-basico', g: 'CSMA/CA: o acesso normal', sub: 'meio', label: 'Esperar, sortear o backoff, transmitir e receber o ACK', set: { ...mbase }, what: '<p>O cliente <b>escuta antes de falar</b>: espera o meio ficar livre por um DIFS (34 µs), sorteia um backoff e conta os slots de 9 µs. Só então transmite, e o AP confirma com um <b>ACK</b> um SIFS (16 µs) depois.</p>' },
  { id: 'm-ack', g: 'CSMA/CA: o acesso normal', sub: 'meio', label: 'O ACK se perde e o frame é repetido', set: { ...mbase, mkind: 'ack' }, what: '<p>O frame chega, mas o <b>ACK não volta</b>. Sem ele, o cliente presume falha, <b>dobra a janela de contenção</b> (15 para 31), sorteia outro backoff e repete. O AP reconhece a duplicata pelo número de sequência e não a entrega duas vezes.</p>' },
  { id: 'm-colisao', g: 'Colisões entre clientes', sub: 'meio', label: 'Dois clientes escolhem o mesmo slot', set: { ...mbase, mkind: 'colisao' }, what: '<p>Os dois sorteiam <b>3 slots</b> e transmitem juntos: o AP não decodifica nenhum frame. Cada um espera o ACK, desiste, dobra a janela e sorteia de novo. Na segunda rodada os valores diferem e <b>um passa à frente do outro</b>, que congela a contagem.</p>' },
  { id: 'm-colisao-rts', g: 'Colisões entre clientes', sub: 'meio', label: 'A mesma colisão, agora com RTS/CTS', set: { ...mbase, mkind: 'colisao', rts: true }, what: '<p>A colisão agora acontece entre dois <b>RTS</b> de 52 µs, e não entre dois frames de dados de 250 µs. O tempo desperdiçado é bem menor. Depois, quem ouve o RTS ou o CTS ajusta o <b>NAV</b> e espera.</p>' },
  { id: 'm-oculto', g: 'O problema do nó oculto', sub: 'meio', label: 'Nó oculto sem RTS/CTS', set: { ...mbase, mkind: 'oculto' }, what: '<p>O Cliente A e o Cliente C <b>não se ouvem</b>. Cada um acha o meio livre e transmite; os frames chegam juntos ao AP e <b>colidem repetidamente</b>, a cada tentativa com um frame inteiro de dados perdido, até a sorte do backoff separá-los.</p>' },
  { id: 'm-oculto-rts', g: 'O problema do nó oculto', sub: 'meio', label: 'Nó oculto com RTS/CTS', set: { ...mbase, mkind: 'oculto', rts: true }, what: '<p>Com o RTS/CTS, o Cliente C não ouve o RTS do Cliente A, mas <b>ouve o CTS do AP</b> e fica em silêncio pelo tempo reservado (NAV). As colisões que restam são só entre RTS curtos.</p>' },
  { id: 'r-roam', g: 'Roaming: trocar de AP', sub: 'mov', label: 'O cliente se afasta e troca de AP', set: { ...rbase }, what: '<p>O sinal do AP-01 enfraquece. O cliente procura o AP-02 (Probe), <b>autentica</b>, envia uma <b>Reassociation Request</b> com o endereço do AP anterior e refaz o <b>handshake de quatro vias</b>. A conexão fica parada durante a troca.</p>' },
  { id: 'r-ft', g: 'Roaming: trocar de AP', sub: 'mov', label: 'Roaming rápido com 802.11r', set: { ...rbase, ft: true }, what: '<p>Com o <b>Fast BSS Transition</b>, o material das chaves já viaja nos frames de Authentication e Reassociation, e o handshake de quatro vias <b>desaparece</b>. A interrupção encurta.</p>' },
  { id: 'r-sticky', g: 'Cliente preso ao AP distante', sub: 'mov', label: 'O cliente não troca de AP', set: { ...rbase, mov: 'sticky' }, what: '<p>O cliente fica no AP-01 mesmo com o AP-02 mais perto. A taxa cai de 54 para 6 Mb/s e o mesmo frame passa a <b>ocupar o meio mais de oito vezes mais tempo</b>, atrasando todos os outros clientes do AP.</p>' },
  { id: 'r-btm', g: 'Cliente preso ao AP distante', sub: 'mov', label: 'O AP sugere a troca (802.11v)', set: { ...rbase, mov: 'btm' }, what: '<p>O AP-01 percebe o sinal fraco e envia um <b>BSS Transition Management Request</b> com o AP-02 como candidato. O cliente aceita e troca. É uma sugestão: o cliente ainda decide.</p>' },
  { id: 'r-ps', g: 'Economia de energia', sub: 'mov', label: 'Cliente que acorda a cada beacon', set: { ...rbase, mov: 'ps', lis: 1 }, what: '<p>O cliente avisa o AP que vai dormir (<b>PM=1</b>). Um pacote chega durante o sono e o AP o <b>guarda</b>. No próximo beacon, o <b>TIM</b> marca o cliente, que acorda, pede o frame com um <b>PS-Poll</b> e o recebe.</p>' },
  { id: 'r-ps-long', g: 'Economia de energia', sub: 'mov', label: 'Cliente que acorda a cada 5 beacons', set: { ...rbase, mov: 'ps', lis: 5 }, what: '<p>Com o intervalo de escuta de 5 beacons, o rádio fica desligado por mais tempo e <b>gasta menos energia</b>, mas o pacote que chegou durante o sono espera <b>cerca de 360 ms</b> até a entrega.</p>' },
  { id: 'c-ok', g: 'Planejamento de canais', sub: 'canal', label: 'Canais 1 e 6: independentes', set: { ...cbase }, what: '<p>Com 20 MHz, os canais 1 e 6 <b>não se sobrepõem</b>. As duas redes transmitem ao mesmo tempo, cada uma no seu canal, sem se atrapalhar.</p>' },
  { id: 'c-co', g: 'Planejamento de canais', sub: 'canal', label: 'Mesmo canal: as redes dividem o tempo', set: { ...cbase, ch2: 1 }, what: '<p>As duas redes no canal 1 <b>se ouvem</b> e usam o CSMA/CA entre si: uma espera a outra. Funciona, mas a capacidade do canal é dividida.</p>' },
  { id: 'c-adj', g: 'Planejamento de canais', sub: 'canal', label: 'Canais 1 e 3: sobrepostos', set: { ...cbase, ch2: 3 }, what: '<p>Os canais 1 e 3 se sobrepõem em frequência. Os clientes <b>não reconhecem</b> a outra rede para esperar a vez, e os sinais se misturam: os frames chegam corrompidos até o backoff separá-los. Costuma ser pior que o mesmo canal.</p>' },
  { id: 'c-40', g: 'Planejamento de canais', sub: 'canal', label: 'Canais de 40 MHz em 2,4 GHz', set: { ...cbase, larg: 40 }, what: '<p>Com 40 MHz, os canais 1 e 6 deixam de ser independentes: cada rede ocupa o dobro da faixa. Na faixa de 2,4 GHz, canais largos quase sempre geram sobreposição entre vizinhos.</p>' },
];

export const groupDoc: Record<string, string> = {
  'Descobrir e entrar na rede': 'Um cliente Wi-Fi passa por três passos antes de usar a rede: descobrir os APs (varredura passiva ou ativa), autenticar (no 802.11, um passo de sistema aberto) e associar. O padrão descreve isso como três estados do cliente em relação ao AP.',
  'Quando a associação falha': 'O AP pode recusar a associação e diz o motivo no Status Code. O cliente continua no estado intermediário e precisa tentar outro AP.',
  'CSMA/CA: o acesso normal': 'O meio de rádio é compartilhado e o cliente não consegue ouvir enquanto fala. Por isso o Wi-Fi evita colisões (CSMA/CA) em vez de detectá-las: espera, sorteia um atraso aleatório e exige a confirmação de cada frame.',
  'Colisões entre clientes': 'Quando dois clientes sorteiam o mesmo slot, os frames colidem. A resposta é o backoff exponencial: a janela dobra a cada falha, e a chance de repetir o mesmo sorteio cai.',
  'O problema do nó oculto': 'Dois clientes podem ouvir o AP sem ouvir um ao outro. Cada um acha que o meio está livre, e os frames colidem no AP. O RTS/CTS reduz o custo dessas colisões.',
  'Roaming: trocar de AP': 'Numa rede com vários APs, quem decide trocar de AP é o cliente. A troca exige procurar, autenticar, reassociar e, em redes protegidas, refazer as chaves, e a conexão fica parada durante esse tempo.',
  'Cliente preso ao AP distante': 'Um cliente que não troca de AP, mesmo com sinal ruim, pesa na rede toda: o frame lento ocupa o meio por mais tempo. Os recursos 802.11k e 802.11v ajudam o AP a empurrar o cliente.',
  'Economia de energia': 'O rádio é um dos maiores consumidores de energia de um celular ou notebook. O cliente dorme e o AP guarda os frames até ele acordar para ouvir o beacon.',
  'Planejamento de canais': 'Na faixa de 2,4 GHz só há três canais de 20 MHz que não se sobrepõem (1, 6 e 11). Escolher o canal de cada AP é uma decisão de planejamento que afeta a capacidade de todos os vizinhos.',
};

export const scenDoc: Record<string, ScenarioDoc> = {
  'd-passivo': {
    short: 'Escutar, autenticar, associar e só então enviar dados.',
    concept: 'Na varredura passiva, o cliente não transmite: sintoniza cada canal por cerca de 110 ms, o bastante para ouvir pelo menos um beacon (enviado a cada 102,4 ms), e aprende o nome da rede, o canal, as taxas e a segurança. Depois vêm dois passos de gerência: a autenticação, que na prática é um ritual de sistema aberto, e a associação, em que o AP atribui um AID ao cliente. Só no estado 3 (autenticado e associado) os frames de dados são aceitos. Todo frame unicast é confirmado com ACK.',
    observe: ['O canal 1 sem beacon, pois o AP está no canal 6.', 'O Beacon em broadcast, sem ACK.', 'O estado do cliente passando de 1 para 2 e para 3.', 'Um ACK depois de cada frame unicast.', 'O DHCPDISCOVER sendo encaminhado ao fio como Ethernet.'],
    msgs: [['Beacon', 'anuncia a rede', 'AP para o cliente'], ['Authentication (1 e 2)', 'ritual do sistema aberto', 'cliente e AP'], ['Association Request', 'pede um lugar no BSS', 'cliente para o AP'], ['Association Response', 'aceita e atribui o AID', 'AP para o cliente'], ['DHCPDISCOVER', 'primeiro tráfego de dados', 'cliente para o AP']],
    why: 'É o caminho que todo cliente Wi-Fi percorre. Entender os três estados explica por que um cliente "conectado" ainda pode estar sem acesso.',
  },
  'd-ativo': {
    short: 'Perguntar em vez de esperar.',
    concept: 'Na varredura ativa, o cliente envia um Probe Request, em broadcast e com SSID curinga, em cada canal e espera um tempo curto (MinChannelTime, aqui 20 ms) por respostas. O AP que o ouve responde com um Probe Response por unicast, que é confirmado com ACK. O resultado é o mesmo do beacon, obtido mais depressa, ao custo de o cliente transmitir e, com isso, revelar a própria presença.',
    observe: ['Os canais sem AP: o Probe Request fica sem resposta e o cliente passa ao próximo.', 'O Probe Request vai em broadcast e não tem ACK; o Probe Response é unicast e tem.', 'A resposta traz o mesmo conteúdo do beacon.'],
    msgs: [['Probe Request', 'pergunta quem está por perto', 'cliente em broadcast'], ['Probe Response', 'responde com o conteúdo do beacon', 'AP para o cliente'], ['ACK', 'confirma o Probe Response', 'cliente para o AP']],
    why: 'Os celulares usam a varredura ativa para reconectar-se depressa. O efeito colateral é que os Probe Requests denunciam as redes que o aparelho já conhece.',
  },
  'd-oculta': {
    short: 'Esconder o nome não esconde a rede.',
    concept: 'Num AP com SSID oculto, o beacon traz o elemento SSID com comprimento zero. O cliente ouve o beacon, mas não sabe o nome da rede. Se já conhecer o nome (perfil salvo), pergunta por ele com um Probe Request dirigido, e o AP responde revelando-o. O nome passa em claro nesse pedido e na Association Request. Ocultar o SSID reduz o ruído na lista de redes, mas não protege nada: a defesa é a criptografia e a autenticação.',
    observe: ['O campo SSID do beacon, com comprimento zero.', 'O Probe Request dirigido, com o nome LabRedes em claro.', 'O Probe Response revelando o nome.'],
    msgs: [['Beacon', 'anuncia a rede sem nome', 'AP para o cliente'], ['Probe Request (SSID)', 'pergunta pelo nome salvo', 'cliente para o AP'], ['Probe Response', 'revela o nome da rede', 'AP para o cliente']],
    why: 'É um erro comum tratar o SSID oculto como proteção. Além de ineficaz, ele obriga o cliente a procurar a rede por nome, o que o expõe em qualquer lugar.',
  },
  'd-rsn': {
    short: 'Associado não é autorizado.',
    concept: 'Em redes WPA2 e WPA3, o beacon e o Probe Response trazem o elemento RSN, e o bit Privacy fica ligado. A autenticação 802.11 continua de sistema aberto (nas redes WPA3 com SAE ela é substituída pelo próprio SAE), e o cliente se associa normalmente, chegando ao estado 3. Mas a porta de dados (controlada, como no 802.1X) só abre depois do handshake de quatro vias, que deriva as chaves. Por isso o primeiro frame de dados é descartado.',
    observe: ['O elemento RSN no Beacon (aba Mensagem).', 'A Association Request também leva o RSN.', 'O AP confirma o frame de dados com ACK, no nível do MAC, mas o descarta logo depois.'],
    msgs: [['Beacon', 'anuncia a rede com o elemento RSN', 'AP para o cliente'], ['Association Request', 'leva o RSN escolhido pelo cliente', 'cliente para o AP'], ['DHCPDISCOVER', 'descartado: a porta está fechada', 'cliente para o AP']],
    why: 'Mostra a separação entre associar (receber um AID) e ser autorizado (ter chaves). O assunto continua no simulador Wi-Fi: segurança, quando publicado.',
  },
  'd-cheio': {
    short: 'O AP pode dizer não.',
    concept: 'O AP responde à Association Request com um Status Code. O código 0 é sucesso; o 17 informa que o AP não consegue tratar mais estações associadas. O cliente permanece no estado 2 (autenticado, não associado), no qual só frames de gerência são aceitos, e deve procurar outro AP ou esperar. Em redes com muitos APs, é assim que se distribui a carga.',
    observe: ['O campo Status Code da Association Response, com 17.', 'Nenhum AID atribuído.', 'O estado do cliente parado em 2.'],
    msgs: [['Association Request', 'pede um lugar no BSS', 'cliente para o AP'], ['Association Response', 'recusa com status 17', 'AP para o cliente']],
    why: 'Explica por que um aparelho pode "ver" a rede e não conseguir entrar nela em locais lotados, como auditórios e estádios.',
  },
  'm-basico': {
    short: 'Escutar antes de falar, e esperar o ACK.',
    concept: 'O rádio não consegue ouvir enquanto transmite, então o Wi-Fi não detecta colisões: evita-as (CSMA/CA). O cliente que quer transmitir espera o meio ficar livre por um DIFS (SIFS mais dois slots, 34 µs na camada física OFDM) e sorteia um backoff entre 0 e CW (inicialmente 15). Conta os slots de 9 µs só enquanto o meio está livre e transmite quando chega a zero. O AP confirma com um ACK um SIFS (16 µs) depois, sem disputar o meio, já que o SIFS é menor que o DIFS.',
    observe: ['O meio ocupado até 200 µs e a espera do DIFS.', 'O backoff de 5 slots (45 µs).', 'O ACK chegando um SIFS depois do frame.', 'O estado do meio mudando de ocupado para livre.'],
    msgs: [['Dados', 'frame de 1500 bytes', 'cliente para o AP'], ['ACK', 'confirmação, um SIFS depois', 'AP para o cliente']],
    why: 'Todo o desempenho do Wi-Fi decorre dessas esperas: elas são a "taxa" que se paga para dividir o ar. Por isso a vazão real fica bem abaixo da taxa anunciada.',
  },
  'm-ack': {
    short: 'Sem ACK, o frame é repetido e a duplicata é descartada.',
    concept: 'Um frame unicast só é considerado entregue se o ACK voltar. Se o ACK se perde, o transmissor não sabe se o frame chegou: ele espera o ACKTimeout, dobra a janela de contenção (backoff exponencial, até 1023) e retransmite com o bit Retry ligado e o mesmo número de sequência. O receptor usa esse número para reconhecer a duplicata: confirma de novo, mas não entrega o frame duas vezes à rede. Há um limite de tentativas (7 para frames curtos, por padrão), depois do qual o frame é descartado.',
    observe: ['O ACK perdido (vermelho).', 'A mensagem no AP: frame recebido, ACK enviado.', 'O ACKTimeout no cliente e a janela passando de 15 para 31.', 'O frame repetido com Retry=1 e o mesmo número de sequência (aba Mensagem).'],
    msgs: [['Dados', 'primeira tentativa', 'cliente para o AP'], ['ACK (perdido)', 'confirmação que não chega', 'AP para o cliente'], ['Dados (repetição)', 'Retry=1, mesmo número de sequência', 'cliente para o AP'], ['ACK', 'confirmação da repetição', 'AP para o cliente']],
    why: 'É a confiabilidade do Wi-Fi na camada de enlace, que o Ethernet cabeado não tem. Também explica por que uma rede congestionada tem latência variável.',
  },
  'm-colisao': {
    short: 'Mesmo slot, mesma colisão.',
    concept: 'Se dois clientes sorteiam o mesmo backoff, eles transmitem no mesmo instante e os frames colidem no AP. Nenhum dos dois ouve o ACK. Cada um espera o timeout, dobra a janela (15 para 31) e sorteia de novo, agora entre 0 e 31. Na rodada seguinte os valores são diferentes: quem sorteou o menor transmite primeiro, e o outro, que ouve a transmissão, congela o contador e só o retoma quando o meio ficar livre de novo (por um DIFS).',
    observe: ['Os dois frames de dados em vermelho, sobrepostos.', 'O tempo perdido (frame inteiro mais o timeout).', 'O Cliente C congelando o contador depois que o Cliente A transmite.', 'A aba Temporização com as rodadas e as janelas.'],
    msgs: [['Dados (colisão)', 'os dois frames sobrepostos', 'Cliente A e Cliente C'], ['Dados', 'frame do primeiro, na segunda rodada', 'Cliente A para o AP'], ['ACK', 'confirmação', 'AP para o Cliente A'], ['Dados', 'frame do segundo', 'Cliente C para o AP']],
    why: 'O backoff exponencial é o que mantém a rede estável sob carga. Quanto mais clientes, mais colisões e mais tempo desperdiçado.',
  },
  'm-colisao-rts': {
    short: 'Colidir com um frame curto custa pouco.',
    concept: 'Com o RTS/CTS, a colisão acontece entre dois RTS de 20 bytes, que duram 52 µs, e não entre dois frames de 1500 bytes, que duram 250 µs. Quem recebe o RTS ou o CTS preenche o NAV (Network Allocation Vector) com o valor do campo Duration/ID e considera o meio ocupado pelo tempo da troca inteira, mesmo sem ouvir a transmissão: é a escuta virtual de portadora. O custo é o tráfego extra de RTS e CTS em toda transmissão.',
    observe: ['A colisão de RTS (52 µs) e o tempo perdido, menor que o do cenário sem RTS.', 'O NAV ativo no cliente que ouviu o RTS (frame Topologia).', 'O campo Duration/ID do RTS, de 386 µs.'],
    msgs: [['RTS (colisão)', 'os dois pedidos se sobrepõem', 'Cliente A e Cliente C'], ['RTS', 'pedido do primeiro', 'cliente para o AP'], ['CTS', 'autorização e reserva', 'AP para o cliente'], ['Dados', 'o frame', 'cliente para o AP'], ['ACK', 'confirmação', 'AP para o cliente']],
    why: 'Mostra a troca entre custo fixo e custo de colisão. Em redes com frames curtos o RTS/CTS não compensa; com frames longos e muita disputa, sim.',
  },
  'm-oculto': {
    short: 'Quem não se ouve, colide.',
    concept: 'No problema do nó oculto, o Cliente A e o Cliente C alcançam o AP, mas um não alcança o outro. A escuta de portadora de cada um não percebe a transmissão do outro, e os dois transmitem sem saber. No AP, os sinais se sobrepõem, e um frame inteiro de dados se perde a cada colisão. Como o backoff sorteia só até CW, vários slots depois do início do outro frame ainda caem dentro dos 250 µs que ele dura, e a colisão se repete até que a diferença entre os sorteios seja maior que o frame.',
    observe: ['A Topologia: o enlace entre os clientes caído.', 'Três rodadas: duas colisões e depois sucesso.', 'O tempo perdido, bem maior que o do cenário com RTS/CTS.', 'O Cliente C congelando ao ouvir o ACK do AP, que ele alcança.'],
    msgs: [['Dados (colisão)', 'os frames se sobrepõem no AP', 'Cliente A e Cliente C'], ['Dados', 'frame do primeiro, na terceira rodada', 'Cliente A para o AP'], ['ACK', 'confirmação', 'AP para o Cliente A'], ['Dados', 'frame do segundo', 'Cliente C para o AP']],
    why: 'É o problema clássico das redes sem fio. Aparece em salas grandes, depósitos e escritórios com divisórias, e se resolve com RTS/CTS, posicionamento dos APs ou mais APs.',
  },
  'm-oculto-rts': {
    short: 'O AP avisa quem o cliente não ouve.',
    concept: 'Com o RTS/CTS, o Cliente C continua sem ouvir o RTS do Cliente A, mas ouve o CTS do AP, que o AP envia para todos. O CTS traz o campo Duration/ID, e o Cliente C o grava no NAV, adiando a transmissão pelo tempo restante da troca. As colisões que sobram são entre os próprios RTS, curtos, e custam pouco. O RTS/CTS não elimina o problema do nó oculto, mas reduz muito o seu custo.',
    observe: ['A colisão de RTS (52 µs) nas duas primeiras rodadas.', 'O evento no Cliente C: ouve o CTS e ajusta o NAV.', 'O NAV ativo no Cliente C na Topologia.', 'Os dados do Cliente A sem interferência.'],
    msgs: [['RTS (colisão)', 'os pedidos se sobrepõem', 'Cliente A e Cliente C'], ['RTS', 'pedido do primeiro', 'cliente para o AP'], ['CTS', 'o AP reserva o meio, ouvido pelos dois clientes', 'AP para o cliente'], ['Dados', 'o frame, protegido pela reserva', 'cliente para o AP'], ['ACK', 'confirmação', 'AP para o cliente']],
    why: 'Mostra que o AP é o ponto em comum que enxerga todos os clientes, e por isso é quem pode coordenar quem não se ouve.',
  },
  'r-roam': {
    short: 'Para o AP novo, o cliente começa do zero.',
    concept: 'O cliente, e não a rede, decide quando trocar de AP. Quando o sinal do AP atual cai abaixo de um limiar do driver (valor de implementação), ele procura outro: envia um Probe Request no canal do candidato, autentica e envia uma Reassociation Request, que carrega o endereço do AP anterior. O novo AP avisa o antigo pelo sistema de distribuição (o mecanismo depende do fabricante). Em redes protegidas, o cliente ainda precisa do handshake de quatro vias para ter as chaves do novo AP, e o AP novo anuncia o endereço do cliente à rede cabeada para atualizar a tabela do switch.',
    observe: ['O sinal do AP-01 caindo para -78 dBm (Topologia).', 'A Reassociation Request com o Current AP Address.', 'Os quatro frames EAPOL-Key do handshake, resumidos.', 'O frame de anúncio ao switch.', 'A interrupção medida no Experimento.'],
    msgs: [['Probe Request e Response', 'procura o AP-02', 'cliente e AP-02'], ['Authentication', 'sistema aberto', 'cliente e AP-02'], ['Reassociation Request', 'traz o endereço do AP antigo', 'cliente para o AP-02'], ['EAPOL-Key 1 a 4', 'handshake que deriva as chaves', 'AP-02 e cliente'], ['Dados', 'volta a trafegar', 'cliente para o AP-02']],
    why: 'Quem usa chamadas de voz ou vídeo sente cada milissegundo da troca. Por isso os recursos de roaming rápido existem.',
  },
  'r-ft': {
    short: 'As chaves viajam junto com a reassociação.',
    concept: 'O Fast BSS Transition (IEEE 802.11r) usa um algoritmo de autenticação próprio (FT). Na associação inicial, o cliente e a rede derivam uma chave de topo do domínio de mobilidade, e os APs do domínio recebem dela chaves próprias (PMK-R1). Na troca de AP, o cliente envia ao novo AP, dentro da Authentication e da Reassociation, os nonces e os identificadores necessários, e as chaves ficam prontas sem o handshake de quatro vias separado. A interrupção cai, o que importa para voz e vídeo.',
    observe: ['O algoritmo 2 (Fast BSS Transition) na Authentication, com os FT IEs.', 'A ausência do handshake de quatro vias.', 'A interrupção menor que a do roaming comum.'],
    msgs: [['Authentication FT (1 e 2)', 'leva o material das chaves', 'cliente e AP-02'], ['Reassociation Request e Response', 'confirmam as chaves', 'cliente e AP-02'], ['Dados', 'tráfego logo em seguida', 'cliente para o AP-02']],
    why: 'O padrão corporativo para dispositivos móveis em andamento. Só funciona se o AP e o cliente suportarem o recurso, que costuma vir desativado por padrão.',
  },
  'r-sticky': {
    short: 'Um cliente lento atrasa todos.',
    concept: 'Muitos clientes só procuram outro AP quando perdem a conexão. Enquanto isso, o sinal fraco obriga a taxa a cair (de 54 para 24 e depois 6 Mb/s no exemplo). O mesmo frame de 1500 bytes passa a ocupar o meio por muito mais tempo, e como o acesso ao meio dá a mesma chance de transmitir a cada cliente, o cliente lento consome uma parte desproporcional do tempo de ar. É a chamada anomalia de desempenho do Wi-Fi: todos os clientes do AP passam a ter a vazão do mais lento.',
    observe: ['A duração do frame de dados subindo de 250 µs para cerca de 2 ms.', 'O AP-02 a -58 dBm, mais perto, mas ignorado.', 'O evento no AP-01 sobre o tempo de ar consumido.'],
    msgs: [['Dados (54 Mb/s)', 'sinal bom', 'cliente para o AP-01'], ['Dados (24 Mb/s)', 'sinal médio', 'cliente para o AP-01'], ['Dados (6 Mb/s)', 'sinal ruim: ocupa o meio por mais de 8 vezes o tempo', 'cliente para o AP-01']],
    why: 'Explica por que "uma pessoa com sinal fraco deixa a rede lenta para todos" e por que as redes corporativas empurram os clientes distantes para outro AP.',
  },
  'r-btm': {
    short: 'O AP empurra o cliente, sem forçá-lo.',
    concept: 'O IEEE 802.11v define a gerência de transição de BSS: o AP envia ao cliente um BSS Transition Management Request com uma lista de APs candidatos, no formato do Neighbor Report do 802.11k, e o cliente responde aceitando ou recusando. A sugestão não obriga; um cliente pode ignorá-la. Em geral o AP também avisa que vai desassociar o cliente em breve (Disassociation Imminent), o que dá força ao pedido.',
    observe: ['A lista de candidatos no BTM Request.', 'O BTM Response com status 0 e o BSSID de destino.', 'O roaming que se segue, igual ao do cenário comum.'],
    msgs: [['BTM Request', 'sugere o AP-02', 'AP-01 para o cliente'], ['BTM Response', 'aceita e informa o destino', 'cliente para o AP-01'], ['Reassociation Request', 'a troca em si', 'cliente para o AP-02']],
    why: 'É a ferramenta que o administrador tem para resolver clientes presos ao AP distante, junto com limites mínimos de sinal para manter a associação.',
  },
  'r-ps': {
    short: 'Dormir entre os beacons, acordar só para o que importa.',
    concept: 'O cliente avisa o AP, com o bit Power Management ligado num frame Null, que vai dormir. O AP passa a guardar os frames dele e, em cada beacon, indica no TIM (Traffic Indication Map) quais clientes dormindo têm frames guardados. O cliente acorda para os beacons (aqui, todos), confere o bit do seu AID e, se estiver marcado, envia um PS-Poll. O AP responde com o frame, e o bit More Data diz se há mais. Depois o cliente volta a dormir, ainda em modo de economia.',
    observe: ['O Null Data com PM=1.', 'O pacote da rede cabeada chegando entre dois beacons.', 'O TIM do beacon seguinte, com o AID 1 marcado.', 'O PS-Poll e o frame entregue, com More Data=0.', 'A aba Energia, comparando intervalos de escuta.'],
    msgs: [['Null Data (PM=1)', 'avisa que vai dormir', 'cliente para o AP'], ['Beacon (TIM)', 'indica quem tem frames guardados', 'AP para o cliente'], ['PS-Poll', 'pede o frame guardado', 'cliente para o AP'], ['Dados guardados', 'a entrega', 'AP para o cliente']],
    why: 'É o que permite a um celular ficar horas conectado sem esgotar a bateria. O preço é a latência: o pacote espera o próximo beacon.',
  },
  'r-ps-long': {
    short: 'Mais sono, mais espera.',
    concept: 'O Listen Interval é o número de beacons que o cliente aceita deixar passar dormindo. Com 5, o rádio liga só a cada 512 ms. O AP precisa guardar os frames por pelo menos esse tempo. O pacote que chegou logo depois de um beacon espera boa parte do intervalo até a entrega, o que não serve para voz ou jogos, mas funciona para sensores e dispositivos que enviam dados de vez em quando.',
    observe: ['Os beacons 1 a 4 passando sem o cliente acordar.', 'O pacote guardado por mais de 350 ms.', 'A comparação da aba Energia entre os intervalos 1, 3 e 5.'],
    msgs: [['Null Data (PM=1)', 'avisa que vai dormir', 'cliente para o AP'], ['Beacon 5 (TIM)', 'o primeiro que o cliente ouve', 'AP para o cliente'], ['PS-Poll', 'pede o frame', 'cliente para o AP'], ['Dados guardados', 'a entrega, bem depois da chegada', 'AP para o cliente']],
    why: 'Mostra a troca direta entre energia e latência, que o projetista de um dispositivo alimentado por bateria precisa escolher.',
  },
  'c-ok': {
    short: 'Canais separados, redes independentes.',
    concept: 'Na faixa de 2,4 GHz, os canais de 20 MHz têm centros a 5 MHz uns dos outros. Dois canais só deixam de se sobrepor quando os centros estão a pelo menos 25 MHz, ou seja, 5 canais de distância: o 1, o 6 e o 11. Com a primeira rede no canal 1 e a segunda no 6, cada uma transmite no próprio canal, sem que uma perceba a outra, e as duas usam a capacidade inteira do seu canal ao mesmo tempo.',
    observe: ['Os dois frames de dados em paralelo.', 'Os dois ACKs sem interferência.', 'O tempo total, igual ao de uma só rede.', 'A aba Canais mostrando as frequências.'],
    msgs: [['Dados (rede 1)', 'canal 1', 'Cliente 1 para o AP-01'], ['Dados (rede 2)', 'canal 6', 'Cliente 2 para o AP-02']],
    why: 'É a regra prática de planejamento em 2,4 GHz: use 1, 6 e 11. Em 5 GHz há muito mais canais independentes.',
  },
  'c-co': {
    short: 'Mesmo canal: uma rede espera pela outra.',
    concept: 'Duas redes no mesmo canal conseguem decodificar o preâmbulo uma da outra. Assim, o CSMA/CA funciona entre elas, como se fossem uma rede só: uma espera a outra terminar. Não há colisões em excesso, mas o tempo de ar do canal é dividido entre as duas redes e os seus clientes. É a interferência cocanal, e em ambientes densos é a mais comum.',
    observe: ['O Cliente 2 ouvindo a transmissão do Cliente 1 e congelando o contador.', 'Os frames em sequência, e não em paralelo.', 'O tempo total, quase o dobro do cenário independente.'],
    msgs: [['Dados (rede 1)', 'transmite primeiro', 'Cliente 1 para o AP-01'], ['Dados (rede 2)', 'espera a vez', 'Cliente 2 para o AP-02']],
    why: 'Mostra que dois APs no mesmo canal não dobram a capacidade, mesmo estando em salas diferentes. Planeje canais diferentes para vizinhos.',
  },
  'c-adj': {
    short: 'Meio-termo é pior que o mesmo canal.',
    concept: 'Os canais 1 e 3 se sobrepõem em boa parte da faixa. Os clientes de cada rede não conseguem decodificar o preâmbulo da outra, então o CSMA/CA não os faz esperar, e os sinais chegam misturados aos receptores, que recebem os frames com erros (FCS inválido). Sem ACK, os dois repetem, e só depois de algumas rodadas os sorteios os separam no tempo. Na prática o efeito depende da potência e da distância; o simulador mostra o caso desfavorável.',
    observe: ['Os dois frames corrompidos, em vermelho.', 'A janela de contenção dobrando a cada rodada.', 'O tempo total, maior que no mesmo canal.'],
    msgs: [['Dados (corrompido)', 'sinais sobrepostos em frequência', 'Cliente 1 e Cliente 2'], ['Dados (repetição)', 'depois da separação pelo backoff', 'Cliente 1 e Cliente 2']],
    why: 'É o argumento para nunca escolher canais "no meio": use o mesmo canal que o vizinho (1, 6 ou 11) ou um canal sem sobreposição, nunca o 3 ou o 8.',
  },
  'c-40': {
    short: 'Canal largo não cabe em 2,4 GHz.',
    concept: 'Com canais de 40 MHz, cada rede ocupa o dobro da faixa. Os centros precisam estar a pelo menos 45 MHz, ou 9 canais: no canal 1 e no 11 ainda cabem, mas o 1 e o 6 passam a se sobrepor. Em 2,4 GHz, onde só há três canais de 20 MHz independentes, o canal de 40 MHz costuma gerar mais interferência do que benefício em ambientes com vizinhos. Em 5 GHz e 6 GHz há espaço para canais largos.',
    observe: ['Os canais 1 e 6 com 40 MHz, agora marcados como sobrepostos.', 'A aba Canais, com a largura de cada rede.', 'A repetição dos frames corrompidos.'],
    msgs: [['Dados (corrompido)', 'redes com 40 MHz se sobrepõem', 'Cliente 1 e Cliente 2'], ['Dados (repetição)', 'depois da separação pelo backoff', 'Cliente 1 e Cliente 2']],
    why: 'Muitos roteadores domésticos vêm com 40 MHz em 2,4 GHz por padrão e atrapalham os vizinhos e a si mesmos. Em 2,4 GHz, prefira 20 MHz.',
  },
};
