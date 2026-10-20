// Cenários e documentação das versões do HTTP.
import type { ScenarioDef, ScenarioDoc } from '../../../sim-core/ui';

export const scenarios: ScenarioDef[] = [
  { id: 'h1-six', g: 'Conexões', sub: 'h1', label: 'Seis conexões paralelas', set: {}, what: '<p>O navegador carrega a página em HTTP/1.1 sobre TLS, com 6 conexões TCP paralelas (o limite típico por servidor).</p><p>Depois do HTML, ele abre mais 5 conexões. Cada uma paga o próprio handshake de TCP e TLS antes de pedir o primeiro recurso.</p>' },
  { id: 'h1-serial', g: 'Conexões', sub: 'h1', label: 'Uma conexão, pedidos em fila', set: { conns: 1 }, what: '<p>Só uma conexão: cada recurso é pedido depois que o anterior termina. Entre dois recursos há sempre uma ida e volta inteira sem dados na linha.</p><p>Veja na aba Cascata os degraus, um recurso depois do outro.</p>' },
  { id: 'h1-hol', g: 'Conexões', sub: 'h1', label: 'Imagem grande ocupa a conexão', set: { conns: 2, big: true }, what: '<p>Duas conexões e uma imagem de 400 KB logo depois do HTML. A conexão que a recebe fica ocupada até o último byte, e os outros recursos se acumulam na fila da outra.</p><p>É o bloqueio de cabeça de fila do HTTP/1.1, na camada da aplicação.</p>' },
  { id: 'h1-plain', g: 'Variações', sub: 'h1', label: 'HTTP sem TLS', set: { tls: false }, what: '<p>Sem TLS, a conexão fica pronta em 1 RTT (só o TCP) e todo o conteúdo viaja em texto claro.</p><p>Compare a aba Mensagem de um pedido: os cabeçalhos aparecem legíveis, o que não acontece com o TLS.</p>' },
  { id: 'h1-loss', g: 'Variações', sub: 'h1', label: 'Perda de um pacote', set: { loss: true, rtt: 200 }, what: '<p>Um pacote de /app.js se perde. No HTTP/1.1 cada recurso tem a sua conexão TCP, então só a conexão afetada espera pela retransmissão.</p>' },

  { id: 'h2-mux', g: 'Multiplexação', sub: 'h2', label: 'Uma conexão, vários fluxos', set: {}, what: '<p>Uma única conexão TCP com TLS. Depois do HTML, todos os pedidos saem de uma vez, cada um em seu fluxo (stream), e as respostas voltam intercaladas.</p><p>Repare no HPACK: o primeiro pedido tem cerca de 330 bytes de cabeçalho e os seguintes, cerca de 50.</p>' },
  { id: 'h2-many', g: 'Multiplexação', sub: 'h2', label: 'Muitos recursos', set: { res: 16 }, what: '<p>16 recursos na mesma conexão. Não há limite de seis conexões nem fila: o número de fluxos simultâneos só é limitado pelo parâmetro do servidor (tipicamente 100).</p>' },
  { id: 'h2-big', g: 'Multiplexação', sub: 'h2', label: 'Imagem grande sem bloquear', set: { big: true }, what: '<p>A imagem de 400 KB divide a banda com os demais fluxos. Os recursos pequenos terminam antes dela, ao contrário do HTTP/1.1.</p><p>A imagem fica pronta mais tarde porque disputa a banda, mas nada fica parado esperando por ela.</p>' },
  { id: 'h2-far', g: 'Latência e perda', sub: 'h2', label: 'Rede de alta latência', set: { rtt: 200 }, what: '<p>Com RTT de 200 ms, os 2 RTT de TCP e TLS pesam: o primeiro pedido só sai depois de 400 ms.</p><p>Compare com o HTTP/3 na aba Comparação.</p>' },
  { id: 'h2-loss', g: 'Latência e perda', sub: 'h2', label: 'Perda: bloqueio no TCP', set: { loss: true, rtt: 200 }, what: '<p>Um pacote de /app.js se perde. Como todos os fluxos compartilham uma só conexão TCP, os bytes que chegam depois do buraco ficam retidos até a retransmissão, e os fluxos que terminariam nesse intervalo são atrasados junto.</p><p>É o bloqueio de cabeça de fila na camada de transporte.</p>' },

  { id: 'h3-1rtt', g: 'Conexão e fluxos', sub: 'h3', label: 'Handshake de 1 RTT', set: {}, what: '<p>O QUIC junta o transporte e o TLS 1.3 em um só handshake sobre UDP: o primeiro pedido sai depois de 1 RTT, contra 2 do HTTP/2.</p><p>Cada pedido usa um fluxo QUIC próprio, com ordem e recuperação de perda independentes.</p>' },
  { id: 'h3-0rtt', g: 'Conexão e fluxos', sub: 'h3', label: 'Retomada com 0-RTT', set: { resume: true }, what: '<p>O cliente já visitou o servidor e guarda um ticket de sessão. O pedido do HTML vai no primeiro pacote, sem esperar o handshake.</p><p>Os dados 0-RTT podem ser reenviados por um atacante; por isso só pedidos que não alteram estado são aceitos.</p>' },
  { id: 'h3-far', g: 'Conexão e fluxos', sub: 'h3', label: 'Rede de alta latência', set: { rtt: 200 }, what: '<p>Mesmo cenário do HTTP/2 em rede de 200 ms. O handshake de 1 RTT poupa 200 ms antes do primeiro pedido.</p>' },
  { id: 'h3-loss', g: 'Perda e rede', sub: 'h3', label: 'Perda: só um fluxo espera', set: { loss: true, rtt: 200 }, what: '<p>O mesmo pacote de /app.js se perde. No QUIC, cada fluxo tem a sua própria ordem de entrega, então só /app.js espera pela retransmissão.</p><p>Os outros fluxos entregam seus dados normalmente. Compare com o cenário de perda do HTTP/2.</p>' },
  { id: 'h3-blocked', g: 'Perda e rede', sub: 'h3', label: 'UDP bloqueado: volta ao HTTP/2', set: { udpBlocked: true }, what: '<p>Um firewall descarta o UDP 443. O QUIC Initial se perde, o navegador espera e recorre ao HTTP/2 sobre TCP.</p><p>Por isso o HTTP/3 é sempre uma melhoria opcional: a página carrega mesmo sem ele, só que depois de uma espera.</p>' },
];

export const groupDoc: Record<string, string> = {
  'Conexões': 'Como o HTTP/1.1 usa conexões TCP: um pedido por vez em cada uma, com várias conexões paralelas para ganhar tempo.',
  'Variações': 'O HTTP/1.1 sem TLS e com perda de pacote.',
  'Multiplexação': 'O HTTP/2 divide uma só conexão em fluxos independentes, com cabeçalhos comprimidos.',
  'Latência e perda': 'Onde o TCP limita o HTTP/2: o custo dos dois RTT de abertura e o bloqueio de todos os fluxos quando um pacote se perde.',
  'Conexão e fluxos': 'O HTTP/3 sobre QUIC: handshake de 1 RTT (ou zero, na retomada) e fluxos com ordem própria.',
  'Perda e rede': 'Como o HTTP/3 reage à perda de pacote e a uma rede que bloqueia o UDP.',
};

export const scenDoc: Record<string, ScenarioDoc> = {
  'h1-six': {
    short: 'Seis conexões TCP paralelas, um pedido por vez em cada uma.',
    concept: 'No <b>HTTP/1.1</b> (RFC 9112) uma conexão atende um pedido de cada vez: o próximo só é enviado depois que a resposta anterior termina (o <b>pipelining</b> existe na especificação, mas os navegadores o desativaram). Para ganhar tempo, o navegador abre <b>várias conexões</b> em paralelo, tipicamente até 6 por servidor. Cada conexão paga o seu handshake de TCP e de TLS.',
    observe: ['Na Captura: o handshake da primeira conexão e, depois do HTML, mais cinco handshakes simultâneos.', 'Na aba Cascata: cada recurso com a sua conexão; quando uma termina, ela pega o próximo da fila.', 'Na aba Mensagem de um pedido: os mesmos cabeçalhos (User-Agent, Accept, Cookie) repetidos em todo pedido.'],
    msgs: [['SYN, SYN/ACK, ACK', 'abre uma conexão TCP', 'cliente e servidor'], ['ClientHello, ServerHello', 'handshake do TLS 1.3', 'cliente e servidor'], ['GET /recurso', 'pedido em texto', 'cliente'], ['200 /recurso', 'resposta com o corpo inteiro', 'servidor']],
    why: 'Seis conexões consomem memória no servidor, repetem handshakes e competem entre si pela banda. Foi a solução possível dentro do HTTP/1.1, e deu origem a práticas como dividir recursos em vários domínios.',
  },
  'h1-serial': {
    short: 'Com uma conexão, cada pedido espera a resposta anterior.',
    concept: 'Sem paralelismo, o navegador pede um recurso, espera a resposta inteira e só então pede o próximo. Entre o fim de uma resposta e o início da seguinte passa <b>1 RTT</b> (o tempo de o pedido chegar e o primeiro byte voltar), durante o qual a conexão fica ociosa.',
    observe: ['Na aba Cascata: as barras formam degraus, sem sobreposição.', 'Na Captura: cada GET sai logo depois da chegada da resposta anterior.', 'Mude para 6 conexões e compare o tempo da página completa na aba Comparação.'],
    msgs: [['GET /recurso', 'só sai quando a conexão está livre', 'cliente'], ['200 /recurso', 'ocupa a conexão até o último byte', 'servidor']],
    why: 'É o comportamento do HTTP/1.1 antes do paralelismo de conexões e explica por que a latência (RTT), mais que a banda, domina o tempo de carregamento de páginas com muitos recursos.',
  },
  'h1-hol': {
    short: 'Uma resposta grande ocupa a conexão e atrasa o que está na fila.',
    concept: 'Em uma conexão HTTP/1.1, as respostas voltam na ordem dos pedidos e uma de cada vez. Se a resposta da vez é grande, tudo o que depende da mesma conexão espera: é o <b>bloqueio de cabeça de fila</b> (head-of-line blocking) da camada de aplicação. Com poucas conexões, o efeito aparece logo.',
    observe: ['Na aba Cascata: uma barra longa (/hero.jpg) e, na outra conexão, os recursos pequenos em fila.', 'Na Captura: a resposta de /hero.jpg dura bastante, e a conexão não recebe outro GET nesse intervalo.', 'Aumente para 6 conexões: o efeito diminui, mas não desaparece.'],
    msgs: [['GET /hero.jpg', 'pedido da imagem grande', 'cliente'], ['200 /hero.jpg', 'ocupa a conexão por todo o corpo', 'servidor']],
    why: 'O HTTP/2 resolve esse bloqueio na aplicação com fluxos independentes na mesma conexão.',
  },
  'h1-plain': {
    short: 'Sem TLS: 1 RTT para abrir, mas tudo em texto claro.',
    concept: 'Em <b>HTTP</b> (porta 80), a conexão fica pronta depois do handshake do TCP, em 1 RTT. O preço é que cabeçalhos e corpo viajam <b>sem cifragem e sem autenticação</b>: quem está no caminho pode ler, e também alterar, as respostas (por exemplo, injetar conteúdo).',
    observe: ['Na aba Mensagem de um pedido: a seção Transporte indica cifragem nenhuma.', 'Na Captura: não há mensagens de TLS e as mensagens não têm o cadeado.', 'O tempo até o primeiro pedido cai em 1 RTT, e é essa vantagem que o TLS 1.3 e o QUIC reduzem.'],
    msgs: [['SYN, SYN/ACK, ACK', 'abre a conexão TCP', 'cliente e servidor'], ['GET /index.html', 'pedido em texto claro', 'cliente']],
    why: 'Sem TLS não há confidencialidade, integridade nem autenticação do servidor. O HTTP/2 e o HTTP/3 são usados na prática apenas sobre conexões cifradas.',
  },
  'h1-loss': {
    short: 'A perda afeta só a conexão TCP que perdeu o pacote.',
    concept: 'Cada conexão HTTP/1.1 é uma conexão TCP separada. Quando um segmento se perde, o TCP retém os bytes seguintes <b>daquela conexão</b> até a retransmissão (cerca de 1 RTT depois). As outras conexões seguem normalmente.',
    observe: ['Na Captura: o segmento perdido (vermelho), o ACK duplicado e a retransmissão.', 'No estado Rede: a perda e a retransmissão recebida.', 'Na aba Cascata: só a barra de /app.js é afetada.'],
    msgs: [['segmento perdido', 'um pacote de /app.js não chega', 'servidor'], ['ACK duplicado (SACK)', 'o cliente avisa do buraco', 'cliente'], ['retransmissão', 'o servidor reenvia o trecho', 'servidor']],
    why: 'Seis conexões isolam as perdas umas das outras, e esse é um dos poucos benefícios de usar várias conexões.',
  },
  'h2-mux': {
    short: 'Uma conexão, muitos fluxos, cabeçalhos comprimidos.',
    concept: 'O <b>HTTP/2</b> (RFC 9113) usa uma só conexão TCP com TLS (ALPN <code>h2</code>) e a divide em <b>fluxos</b> (streams) identificados por número. O navegador envia todos os pedidos de uma vez, e o servidor devolve as respostas <b>intercaladas</b> em quadros (frames). Os cabeçalhos são comprimidos pelo <b>HPACK</b> (RFC 7541): o que se repete vira um índice.',
    observe: ['Na Captura: depois do HTML, todos os HEADERS saem no mesmo instante, cada um em um fluxo ímpar.', 'Na aba Mensagem: o primeiro pedido tem cerca de 330 bytes de cabeçalho; os seguintes, cerca de 50.', 'Na aba Cascata: as barras começam juntas e terminam em tempos diferentes, conforme o tamanho.'],
    msgs: [['SETTINGS', 'parâmetros da conexão', 'cliente e servidor'], ['HEADERS (GET)', 'abre o fluxo com o pedido', 'cliente'], ['HEADERS + DATA', 'resposta em quadros', 'servidor']],
    why: 'Uma conexão só paga um handshake e deixa o controle de congestionamento do TCP trabalhar com mais dados em trânsito. Em compensação, depende de uma única sequência de bytes do TCP.',
  },
  'h2-many': {
    short: 'Dezesseis recursos sem fila nem limite de conexões.',
    concept: 'Com a multiplexação, o número de recursos deixa de ser um problema de conexões. O limite passa a ser o <b>MAX_CONCURRENT_STREAMS</b> (o servidor anuncia no SETTINGS; ao menos 100 é o valor recomendado) e a banda disponível.',
    observe: ['Na Captura: 15 pedidos saindo juntos depois do HTML.', 'Na aba Comparação: o HTTP/1.1 perde mais tempo quanto mais recursos a página tem.', 'Na aba Mensagem: o identificador dos fluxos (1, 3, 5...).'],
    msgs: [['HEADERS (GET)', 'um por recurso, no mesmo instante', 'cliente'], ['200', 'respostas intercaladas', 'servidor']],
    why: 'Páginas modernas têm dezenas ou centenas de recursos. O HTTP/2 elimina a fila de pedidos sem exigir mais conexões.',
  },
  'h2-big': {
    short: 'A imagem grande divide a banda e não bloqueia os outros.',
    concept: 'No HTTP/2 as respostas são fatiadas em quadros DATA (até 16 KB, por padrão) e os quadros de fluxos diferentes se alternam. Uma resposta grande <b>não impede</b> as pequenas de terminar. Em implementações reais, o servidor pode priorizar fluxos (RFC 9218); o simulador divide a banda em partes iguais.',
    observe: ['Na aba Cascata: os recursos pequenos terminam cedo, a imagem grande, por último.', 'Compare com o cenário Imagem grande ocupa a conexão, do HTTP/1.1.', 'Na aba Mensagem da resposta: o número de quadros DATA do recurso.'],
    msgs: [['HEADERS (GET /hero.jpg)', 'pedido da imagem grande', 'cliente'], ['DATA (vários)', 'quadros da imagem, intercalados com os dos outros fluxos', 'servidor']],
    why: 'É o ganho central da multiplexação: o bloqueio de cabeça de fila da aplicação deixa de existir.',
  },
  'h2-far': {
    short: 'Com RTT alto, os dois RTT de abertura pesam.',
    concept: 'O HTTP/2 sobre TCP e TLS 1.3 gasta <b>2 RTT</b> antes do primeiro pedido: um para o handshake do TCP e outro para o do TLS. Em redes de alta latência, esse custo fixo domina o tempo de carregamento de páginas pequenas.',
    observe: ['Na Captura: o primeiro GET só sai em 2 RTT (400 ms).', 'Na aba Comparação: o HTTP/3 sai 1 RTT na frente.', 'O tempo do HTML (TTFB) não muda entre as versões; muda o instante em que o pedido pode sair.'],
    msgs: [['SYN, SYN/ACK, ACK', '1 RTT', 'cliente e servidor'], ['ClientHello, ServerHello + Finished', '1 RTT', 'cliente e servidor']],
    why: 'Parte do projeto do QUIC foi reduzir esse custo de abertura, que não depende da versão do HTTP, e sim do transporte.',
  },
  'h2-loss': {
    short: 'Um pacote perdido retém todos os fluxos da conexão TCP.',
    concept: 'O TCP entrega uma sequência de bytes <b>em ordem</b>. Quando um segmento se perde, os bytes que chegam depois dele ficam retidos no receptor até a retransmissão (cerca de 1 RTT). Como o HTTP/2 mistura todos os fluxos nessa sequência, <b>todos</b> são afetados, mesmo os que não perderam nada: é o bloqueio de cabeça de fila na camada de transporte.',
    observe: ['Na Captura: o segmento perdido, o ACK duplicado e a retransmissão.', 'Na aba Cascata: as barras vermelhas de /app.js e de outros fluxos cuja entrega foi retida.', 'Na aba Comparação: o número de fluxos atrasados pela perda no HTTP/2 e no HTTP/3.'],
    msgs: [['segmento perdido', 'um pacote de /app.js não chega', 'servidor'], ['ACK duplicado (SACK)', 'o cliente avisa do buraco', 'cliente'], ['retransmissão', 'o servidor reenvia o trecho', 'servidor']],
    why: 'Quanto maior o RTT e a perda, pior o efeito. Em redes móveis com perdas frequentes, esse bloqueio é uma das motivações do HTTP/3.',
  },
  'h3-1rtt': {
    short: 'QUIC: transporte e TLS 1.3 num só handshake, sobre UDP.',
    concept: 'O <b>HTTP/3</b> (RFC 9114) roda sobre o <b>QUIC</b> (RFC 9000), que usa UDP e incorpora o TLS 1.3. O primeiro voo já leva o ClientHello e, com 1 RTT, o cliente termina o handshake e envia o pedido. Cada pedido usa um <b>fluxo QUIC</b> próprio, com ordem e recuperação de perda independentes. Os cabeçalhos são comprimidos pelo <b>QPACK</b> (RFC 9204).',
    observe: ['Na Captura: apenas três mensagens de abertura, contra sete do HTTP/2 (TCP, TLS e SETTINGS).', 'Na aba Mensagem: o pacote QUIC e o fluxo, com identificador múltiplo de 4.', 'No estado Conexões: a conexão pronta depois de 1 RTT.'],
    msgs: [['Initial (ClientHello)', 'primeiro voo, em UDP', 'cliente'], ['Initial + Handshake', 'ServerHello, certificado e Finished', 'servidor'], ['Handshake (Finished)', 'conclui o handshake', 'cliente']],
    why: 'O QUIC roda em espaço de usuário e criptografa quase todo o cabeçalho de transporte, o que dificulta intervenções de equipamentos no meio do caminho e facilita evoluir o protocolo.',
  },
  'h3-0rtt': {
    short: 'Com sessão anterior, o pedido vai no primeiro pacote.',
    concept: 'Se o cliente já falou com o servidor, guarda um <b>ticket de sessão</b>. Na visita seguinte, o QUIC envia o pedido <b>junto do primeiro pacote</b> (dados 0-RTT), antes de o handshake terminar. O custo de abertura vai a zero. Em contrapartida, os dados 0-RTT <b>não são protegidos contra replay</b>: um atacante pode reenviar o pacote capturado.',
    observe: ['Na Captura: o GET sai no instante zero, junto do Initial.', 'A tag 0-RTT na mensagem Initial.', 'Na Referência: por que só pedidos idempotentes são aceitos em 0-RTT.'],
    msgs: [['Initial + 0-RTT', 'ClientHello e o pedido, no mesmo voo', 'cliente'], ['Initial + Handshake', 'servidor aceita o 0-RTT', 'servidor']],
    why: 'O ganho é real, mas exige cuidado: o servidor deve recusar 0-RTT em pedidos que alteram estado (RFC 8470 define a resposta 425 Too Early).',
  },
  'h3-far': {
    short: 'Em rede de 200 ms, o handshake de 1 RTT poupa 200 ms.',
    concept: 'O custo de abertura do HTTP/3 é metade do HTTP/2 sobre TLS 1.3: 1 RTT contra 2. A vantagem é fixa em número de RTT, então cresce com a latência da rede.',
    observe: ['Na Captura: o primeiro GET sai em 200 ms, em vez de 400 ms.', 'Na aba Comparação: a diferença entre as três versões no tempo da página completa.'],
    msgs: [['Initial (ClientHello)', 'primeiro voo', 'cliente'], ['Initial + Handshake', 'resposta do servidor', 'servidor']],
    why: 'Em redes de satélite ou móveis ruins, 1 RTT a menos pode ser mais perceptível que qualquer outra otimização do protocolo.',
  },
  'h3-loss': {
    short: 'Só o fluxo que perdeu dados espera pela retransmissão.',
    concept: 'No QUIC cada fluxo tem a sua <b>própria ordem de entrega</b>. Quando um pacote se perde, apenas o fluxo cujos dados estavam nele espera. Os demais entregam à aplicação o que já chegou. O pacote perdido é reenviado em um <b>pacote novo</b>, com número novo (RFC 9002).',
    observe: ['Na Captura: o pacote perdido, o ACK com intervalo e a retransmissão.', 'Na aba Cascata: só a barra de /app.js fica vermelha.', 'Na aba Comparação: um fluxo atrasado no HTTP/3, contra mais de um no HTTP/2.'],
    msgs: [['pacote QUIC perdido', 'dados de /app.js', 'servidor'], ['ACK com intervalo', 'aponta o buraco', 'cliente'], ['retransmissão (novo pacote)', 'mesmo conteúdo, número novo', 'servidor']],
    why: 'Na prática um pacote QUIC pode carregar quadros de mais de um fluxo e afetar todos eles. O simulador supõe que os dados perdidos pertencem a um só fluxo.',
  },
  'h3-blocked': {
    short: 'O QUIC não passa pelo firewall; o navegador recorre ao TCP.',
    concept: 'Muitas redes bloqueiam ou limitam o UDP na porta 443. O navegador tenta o QUIC (descoberto por <code>Alt-Svc</code>, RFC 7838, ou por registro DNS HTTPS), não recebe resposta e <b>recorre ao HTTP/2 sobre TCP</b>. O tempo perdido na tentativa é o custo do fallback.',
    observe: ['Na Captura: o QUIC Initial perdido (vermelho) e, 300 ms depois, o handshake TCP e TLS.', 'No estado Protocolo: de tentando HTTP/3 para HTTP/2 (fallback).', 'Na aba Comparação: o tempo da página completa passa a incluir a espera.'],
    msgs: [['QUIC Initial', 'descartado pelo firewall', 'cliente'], ['SYN, ClientHello...', 'handshake TCP e TLS depois da espera', 'cliente e servidor']],
    why: 'A possibilidade de fallback é o que permite implantar o HTTP/3 aos poucos, sem quebrar redes que não o suportam. A espera de 300 ms do simulador é ilustrativa.',
  },
};

export const stageTitles: Record<string, string> = {
  h1: 'Diagrama de sequência: HTTP/1.1, conexões TCP e pedidos em série',
  h2: 'Diagrama de sequência: HTTP/2, uma conexão e fluxos multiplexados',
  h3: 'Diagrama de sequência: HTTP/3, QUIC sobre UDP e fluxos independentes',
};
