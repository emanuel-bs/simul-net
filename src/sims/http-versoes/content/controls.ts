// Controles do painel das versões do HTTP: rede, página, conexão e falhas.
import type { ControlDef } from '../../../sim-core/ui';

export const controls: ControlDef[] = [
  {
    id: 'rtt', num: true, grp: 'Rede', label: 'Latência da rede (RTT)', type: 'select', wide: true,
    opts: [[20, 'Fibra ou rede local (20 ms)'], [80, 'Móvel 4G (80 ms)'], [200, 'Satélite ou rede ruim (200 ms)']], def: 80,
    help: { t: 'Latência da rede (RTT)', s: 'Tempo de ida e volta entre o navegador e o servidor.', p: ['Quanto maior o RTT, mais caro é cada viagem de ida e volta: abrir conexões, esperar a resposta de um pedido antes de enviar o seguinte e recuperar uma perda.', 'A largura de banda é fixa em 10 Mbit/s e dividida em partes iguais entre as respostas em andamento. O que muda entre as versões do HTTP é quantas viagens de ida e volta cada uma gasta.'] },
  },
  {
    id: 'res', num: true, grp: 'Página', label: 'Recursos da página', type: 'select',
    opts: [[4, '4 recursos'], [8, '8 recursos'], [16, '16 recursos']], def: 8,
    help: { t: 'Recursos da página', s: 'Quantos arquivos o navegador baixa, contando o HTML.', p: ['O primeiro é sempre o documento HTML. Os demais (CSS, JavaScript, imagens, fonte, dados) só são pedidos depois que o navegador lê o HTML e descobre que precisa deles.', 'Com muitos recursos, o HTTP/1.1 esbarra no limite de conexões; o HTTP/2 e o HTTP/3 enviam todos os pedidos de uma vez.'] },
  },
  {
    id: 'big', grp: 'Página', label: 'Incluir uma imagem grande (400 KB)', type: 'check', def: false,
    help: { t: 'Imagem grande', s: 'Acrescenta /hero.jpg, de 400 KB, logo depois do HTML.', p: ['No HTTP/1.1, a conexão que baixa a imagem fica ocupada até o último byte e nenhum outro pedido passa por ela (bloqueio de cabeça de fila).', 'No HTTP/2 e no HTTP/3, a imagem divide a banda com os demais fluxos e não impede que os outros terminem.'] },
  },
  {
    id: 'tls', subs: ['h1'], grp: 'Conexão', label: 'Usar TLS (HTTPS)', type: 'check', def: true,
    help: { t: 'Usar TLS', s: 'HTTP/1.1 sobre TLS (https) ou em texto claro (http).', p: ['Com TLS 1.3, a conexão gasta 2 RTT antes do primeiro pedido (1 do TCP e 1 do TLS). Sem TLS, gasta 1 RTT, mas o conteúdo e os cabeçalhos viajam em texto claro e podem ser lidos ou alterados no caminho.', 'No HTTP/2 e no HTTP/3 do simulador o TLS é sempre usado: os navegadores só falam essas versões sobre conexões cifradas.'] },
  },
  {
    id: 'conns', num: true, subs: ['h1'], grp: 'Conexão', label: 'Conexões paralelas', type: 'select', wide: true,
    opts: [[1, '1 conexão'], [2, '2 conexões'], [6, '6 conexões (como os navegadores)']], def: 6,
    help: { t: 'Conexões paralelas', s: 'Quantas conexões TCP o navegador abre para o servidor.', p: ['No HTTP/1.1 cada conexão atende um pedido por vez, sem pipelining. Os navegadores contornam isso abrindo até 6 conexões por servidor, e cada uma paga seu próprio handshake.', 'Com 1 conexão, os pedidos esperam em fila: cada recurso só é pedido depois que o anterior termina.'] },
  },
  {
    id: 'resume', subs: ['h3'], grp: 'Conexão', label: 'Retomar sessão anterior (0-RTT)', type: 'check', def: false,
    help: { t: 'Retomada com 0-RTT', s: 'O cliente já conhece o servidor e envia o pedido no primeiro pacote.', p: ['Com um ticket de uma visita anterior, o QUIC envia o pedido junto do primeiro voo, sem esperar o handshake: o tempo de conexão cai de 1 RTT para zero.', 'Os dados 0-RTT podem ser reenviados por um atacante (replay). Por isso os servidores só os aceitam para pedidos que não alteram estado, como GET (RFC 8470).'] },
  },
  {
    id: 'loss', grp: 'Falhas', label: 'Perder um pacote de /app.js', type: 'check', def: false,
    help: { t: 'Perda de pacote', s: 'Um pacote com dados de /app.js se perde na metade da transferência.', p: ['O TCP entrega os bytes em ordem: enquanto o trecho perdido não for retransmitido, nada que chegou depois dele é entregue à aplicação. No HTTP/2, isso vale para todos os fluxos da conexão.', 'No QUIC, cada fluxo tem sua própria ordem. Só o fluxo que perdeu dados espera pela retransmissão.'] },
  },
  {
    id: 'udpBlocked', subs: ['h3'], grp: 'Falhas', label: 'UDP 443 bloqueado na rede', type: 'check', def: false,
    help: { t: 'UDP 443 bloqueado', s: 'Um firewall descarta o tráfego QUIC.', p: ['O navegador tenta o QUIC, não recebe resposta e recorre ao HTTP/2 sobre TCP. O tempo de espera do simulador (300 ms) é ilustrativo: cada navegador usa a sua estratégia, como disputar QUIC e TCP em paralelo.', 'É por isso que o HTTP/3 é sempre oferecido junto com uma alternativa por TCP.'] },
  },
];
