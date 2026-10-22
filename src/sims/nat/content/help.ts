// Ajuda dos campos do NAT.
import type { ControlHelp } from '../../../sim-core/ui';

export const help: Record<string, ControlHelp> = {
  tipo: {
    t: 'Tipo de tradução',
    s: 'O que o NAT traduz (RFC 3022).',
    p: [
      '<b>Basic NAT estático:</b> cada host interno tem um endereço público fixo (1:1). Só o endereço IP é traduzido e o mapeamento é permanente, nos dois sentidos.',
      '<b>Basic NAT dinâmico:</b> o host recebe um endereço de um pool quando começa a falar e o devolve depois do tempo de inatividade. Também traduz só o endereço.',
      '<b>NAPT (PAT):</b> traduz o endereço <b>e a porta</b> (ou o identificador do ICMP). Muitos hosts compartilham um único endereço público. É o que o mercado chama de PAT, <i>overload</i> ou, no Linux, <i>masquerade</i>.',
    ],
  },
  pool: {
    t: 'Endereços públicos no pool',
    s: 'Quantos endereços o NAT dinâmico pode distribuir.',
    p: ['Vale para o Basic NAT dinâmico. Com menos endereços que hosts, o host que chega depois fica sem tradução até um vínculo expirar.', 'Os endereços do pool (203.0.113.11 em diante) são da faixa de documentação da RFC 5737 e fazem o papel de endereços públicos.'],
  },
  proto: {
    t: 'Protocolo',
    s: 'O protocolo do pacote que atravessa o NAT.',
    p: [
      '<b>TCP e UDP:</b> o NAPT usa as portas de origem e de destino.',
      '<b>ICMP:</b> não há porta; o NAT usa o campo <i>Identifier</i> do Echo como se fosse a porta (RFC 5508).',
      '<b>ESP (IPsec):</b> não há porta. O Basic NAT atravessa sem problema (se não houver AH), mas o NAPT não tem como distinguir dois hosts. A saída é encapsular o ESP em UDP (NAT-T).',
    ],
  },
  mapeamento: {
    t: 'Comportamento de mapeamento',
    s: 'Quando o NAPT reaproveita a porta externa (RFC 4787).',
    p: [
      '<b>Independente do destino (EIM):</b> a mesma porta interna usa sempre a mesma porta externa, qualquer que seja o destino. Facilita aplicações ponto a ponto.',
      '<b>Dependente de endereço e porta (APDM):</b> cada destino distinto recebe sua própria porta externa. É o comportamento do NAT dito "simétrico" e dificulta a conexão direta entre dois hosts atrás de NATs.',
    ],
  },
  conex: {
    t: 'Conexões por host',
    s: 'Quantas conexões cada host abre, em sequência.',
    p: ['Cada conexão usa uma porta de origem diferente (50000, 50001...). Mais conexões ocupam mais entradas da tabela e mais portas externas.', 'No ICMP, cada conexão usa um identificador diferente; no ESP, há uma associação por host.'],
  },
  mesmaPorta: {
    t: 'PC2 usa a mesma porta de origem do PC1',
    s: 'Provoca colisão de portas no NAPT.',
    p: ['Por padrão o PC2 usa portas na faixa 40000. Marcado, ele passa a usar as mesmas portas do PC1 (50000...), e o NAPT precisa escolher outra porta externa para um dos dois.', 'Os hosts não sabem que há outro host na mesma situação: a colisão é resolvida só pelo NAT.'],
  },
  dois: {
    t: 'PC1 usa a mesma porta para dois destinos',
    s: 'Compara os comportamentos de mapeamento do NAPT.',
    p: ['O PC1 envia da mesma porta de origem para duas portas de destino do mesmo servidor. Com mapeamento independente do destino, as duas conexões compartilham a porta externa; com mapeamento dependente, cada uma recebe a sua.', 'Só vale para TCP e UDP. Com este campo, só o PC1 envia.'],
  },
  faixa: {
    t: 'Faixa de portas do NAT',
    s: 'O conjunto de portas externas que o NAT pode usar.',
    p: ['<b>Ampla:</b> 1024 a 65535 (64.512 portas por endereço e protocolo).', '<b>Pequena (didática):</b> 50000 a 50002, só 3 portas, para mostrar o esgotamento com poucas conexões. Em redes reais, o esgotamento é o mesmo fenômeno em escala muito maior.'],
  },
  timeout: {
    t: 'Tempo de inatividade (timeout)',
    s: 'Quanto tempo uma entrada sobrevive sem tráfego.',
    p: ['Parâmetro do simulador, não um padrão de fabricante: em equipamentos reais, o valor varia por protocolo e por estado da conexão (a RFC 4787 e a RFC 5382 dão orientações mínimas).', 'Passado o tempo sem tráfego, a entrada é removida e a porta é liberada.'],
  },
  tardia: {
    t: 'Resposta tardia do servidor',
    s: 'O servidor responde depois do timeout.',
    p: ['A primeira resposta chega 30 s depois do timeout configurado. A entrada já expirou e o NAT não sabe a quem entregar o pacote.', 'Com este campo, só o PC1 envia, uma conexão.'],
  },
  entrada: {
    t: 'Pacote não solicitado de fora',
    s: 'O servidor envia um pacote que ninguém de dentro pediu.',
    p: ['No fim da simulação, o servidor externo envia um pacote para o endereço público do NAT.', 'No NAPT, sem entrada na tabela, o pacote é descartado. No Basic NAT, o mapeamento vale nos dois sentidos e o pacote é entregue. <b>O NAT não é um filtro de segurança:</b> o bloqueio de entrada vem de uma regra de filtragem com estado.'],
  },
  cgnat: {
    t: 'NAT em duas camadas (CGNAT)',
    s: 'Um CPE doméstico e um CGN da operadora, em cascata.',
    p: ['O CPE traduz o endereço privado para um endereço de 100.64.0.0/10 (RFC 6598). O CGN traduz esse endereço para o público, dividindo as portas com outros assinantes (RFC 6888).', 'Neste cenário, o CGN já tem as portas 50000 e 50001 ocupadas por outro assinante. Força o NAPT nos dois dispositivos.'],
  },
  natt: {
    t: 'NAT traversal (NAT-T)',
    s: 'Encapsula o ESP em UDP porta 4500 (RFC 3948).',
    p: ['Vale quando o protocolo é ESP. Com o ESP dentro de um datagrama UDP, o NAPT passa a ver portas e consegue distinguir os hosts.'],
  },
  acao: {
    t: 'Situação',
    s: 'Qual redirecionamento de destino é mostrado.',
    p: [
      '<b>Publicar serviço:</b> um cliente externo acessa o endereço público e a porta 443; o NAT redireciona para o servidor interno na porta 8443.',
      '<b>Hairpin:</b> um cliente interno acessa o endereço público do serviço.',
      '<b>Proxy transparente:</b> o NAT desvia o tráfego HTTP (porta 80) dos clientes internos para um proxy interno.',
    ],
  },
  gwOutro: {
    t: 'O servidor interno usa outro gateway',
    s: 'O gateway padrão do WEB não é o R-NAT.',
    p: ['A resposta sai por outro caminho e chega ao cliente com o endereço privado como origem. O cliente espera o endereço público e descarta o pacote.', 'Só vale na situação "Publicar serviço".'],
  },
  hairpin: {
    t: 'Suporte a hairpin',
    s: 'O que o roteador faz quando um cliente interno acessa o endereço público.',
    p: ['<b>Sem suporte:</b> o roteador não aplica o DNAT a esse caminho e o pacote é descartado ou tratado como destino local.', '<b>Só DNAT:</b> o servidor recebe o pedido com a origem do cliente, na mesma rede, e responde direto, sem passar pelo roteador. A resposta é recusada.', '<b>DNAT e SNAT:</b> o roteador reescreve também a origem. O servidor responde ao roteador e a conexão funciona.', 'Só vale na situação "Hairpin".'],
  },
};
