export type CategoryId = 'camada-de-rede' | 'transporte' | 'protocolos-seguros';

export interface Category {
  id: CategoryId;
  title: string;
  description: string;
}

/**
 * Como o simulador é entregue:
 * - 'legado': página autônoma em public/sims (HTML, CSS e JavaScript em um único arquivo);
 * - 'nativo': componente React com motor de simulação testado (migração gradual, veja docs/arquitetura.md).
 */
export type Engine = 'legado' | 'nativo';

export interface SimMeta {
  id: string;
  category: CategoryId;
  title: string;
  summary: string;
  topics: string[];
  rfcs: string[];
  status: 'available' | 'planned';
  /** Destaque "Novo" na página inicial: marcar no máximo os 3 simuladores publicados mais recentemente. */
  novo?: boolean;
  /** Presentes somente em simuladores disponíveis. */
  engine?: Engine;
  /** Nome do arquivo em public/sims (engine 'legado'). */
  file?: string;
}

export const CATEGORIES: Category[] = [
  {
    id: 'camada-de-rede',
    title: 'Roteamento e serviços de rede',
    description: 'Roteamento, endereçamento automático, diagnóstico e redes de operadora, em diagramas de sequência e topologias animadas.',
  },
  {
    id: 'transporte',
    title: 'Camada de transporte e segurança',
    description: 'TCP e UDP passo a passo e o laboratório defensivo com ataques, mitigações e resposta a incidentes.',
  },
  {
    id: 'protocolos-seguros',
    title: 'Protocolos de rede seguros',
    description: 'SSH, HTTPS e transferência de arquivos por dentro: negociação, troca de chaves, autenticação, certificados e hardening.',
  },
];

// Para adicionar um simulador: coloque o arquivo em public/sims (ou crie um componente em src/sims/<nome>/)
// e acrescente uma entrada aqui. A página inicial, as categorias e os testes usam este registro.
export const SIMS: SimMeta[] = [
  {
    id: 'roteamento',
    category: 'camada-de-rede',
    title: 'Roteamento (OSPF e RIPv2)',
    summary: 'Roteamento dinâmico passo a passo: OSPF em área única e multiárea (Hello, adjacências, LSAs e SPF) e RIPv2 com Bellman-Ford e split horizon, com falhas de enlace e custos editáveis.',
    topics: ['Hello e adjacências', 'LSAs e SPF', 'Bellman-Ford e split horizon', 'Falhas de enlace'],
    rfcs: ['RFC 2328', 'RFC 2453'],
    status: 'available',
    engine: 'legado',
    file: 'router-simulator.html',
  },
  {
    id: 'dhcp',
    category: 'camada-de-rede',
    title: 'DHCP (DORA)',
    summary: 'Simulação interativa do DHCP: Discover, Offer, Request e Acknowledge, com gestão de leases e prevenção de conflitos por ARP.',
    topics: ['DORA', 'Leases e renovação', 'Conflitos de endereço (ARP)'],
    rfcs: ['RFC 2131', 'RFC 2132', 'RFC 5227'],
    status: 'available',
        engine: 'nativo',
  },
  {
    id: 'icmp',
    category: 'camada-de-rede',
    title: 'ICMP (ping e traceroute)',
    summary: 'ping, traceroute, tracert e hping3 em uma rede simulada: Echo, Time Exceeded, Destination Unreachable, fragmentação, PMTUD, ACLs e loops, com captura e hex dump.',
    topics: ['Echo e Time Exceeded', 'Fragmentação e PMTUD', 'ACLs e loops de roteamento', 'Captura e hex dump'],
    rfcs: ['RFC 792', 'RFC 1191', 'RFC 1812', 'RFC 2923'],
    status: 'available',
    novo: true,
    engine: 'nativo',
  },
  {
    id: 'bgp',
    category: 'camada-de-rede',
    title: 'BGP (sessões e seleção de caminho)',
    summary: 'BGP-4 entre seis sistemas autônomos: sessões, OPEN, UPDATE e KEEPALIVE, relações comerciais, LOCAL_PREF, AS-path prepend, falhas e reconvergência, mais sequestro de prefixo, vazamento de rota e flapping com as defesas (filtros, RPKI/ROV, flap damping).',
    topics: ['Sessões e mensagens', 'Seleção de caminho', 'Sequestro, vazamento e flapping', 'Defesas (RPKI/ROV, filtros)'],
    rfcs: ['RFC 4271', 'RFC 6811'],
    status: 'available',
    engine: 'legado',
    file: 'bgp-simulator.html',
  },
  {
    id: 'mpls',
    category: 'camada-de-rede',
    title: 'MPLS (LDP e L3VPN)',
    summary: 'Núcleo MPLS com seis LSRs: sessões LDP, LIB e LFIB, push, swap e pop, PHP, modelos de TTL, traceroute com rótulos e L3VPN com pilha de dois rótulos.',
    topics: ['LDP, LIB e LFIB', 'Push, swap e pop', 'PHP e TTL', 'L3VPN com dois rótulos'],
    rfcs: ['RFC 3031', 'RFC 5036', 'RFC 4364'],
    status: 'available',
    engine: 'legado',
    file: 'mpls-simulator.html',
  },
  {
    id: 'tcp-udp',
    category: 'transporte',
    title: 'TCP e UDP',
    summary: 'Camada de transporte em diagrama de sequência: handshake e estados do TCP, ACKs, RTO, fast retransmit, SACK, slow start e gráfico da cwnd, UDP com perdas e DNS, comparação TCP x UDP, download de arquivo por TCP e vídeo em streaming por UDP.',
    topics: ['Handshake e estados', 'Controle de congestionamento e SACK', 'Download TCP e vídeo UDP', 'Comparação TCP x UDP'],
    rfcs: ['RFC 9293', 'RFC 768', 'RFC 5681', 'RFC 2018'],
    status: 'available',
    engine: 'legado',
    file: 'tcp-udp-simulator.html',
  },
  {
    id: 'ataques-tcp-udp',
    category: 'transporte',
    title: 'Ataques e defesas TCP/UDP',
    summary: 'Laboratório defensivo com 12 ataques (SYN flood, Slowloris, RST injection, varreduras, DDoS por botnet, amplificação, DNS water torture e outros), mitigação upstream, falsos positivos e ciclo de resposta a incidente.',
    topics: ['SYN flood e Slowloris', 'Varreduras e amplificação', 'Mitigação e falsos positivos', 'Resposta a incidente'],
    rfcs: ['RFC 4987', 'BCP 38'],
    status: 'available',
    engine: 'legado',
    file: 'tcp-udp-security-simulator.html',
  },
  {
    id: 'ssh',
    category: 'protocolos-seguros',
    title: 'SSH',
    summary: 'SSH-2 por dentro: negociação de versão e algoritmos, troca de chaves, known_hosts, autenticação (senha, chave pública e TOTP), canais, SFTP e túneis (-L, -R, -D e ProxyJump), com nota de hardening.',
    topics: ['Negociação e troca de chaves', 'known_hosts e autenticação', 'Canais e SFTP', 'Túneis e encaminhamento'],
    rfcs: ['RFC 4253', 'RFC 4252', 'RFC 4254', 'RFC 8709'],
    status: 'available',
    engine: 'nativo',
  },
  {
    id: 'https',
    category: 'protocolos-seguros',
    title: 'HTTPS e TLS',
    summary: 'Handshake TLS 1.3 e 1.2, validação de certificados X.509, retomada e 0-RTT, HSTS e a comparação entre HTTP e HTTPS, com nota de hardening.',
    topics: ['Handshake TLS 1.3 e 1.2', 'Certificados e validação', 'Retomada, 0-RTT e HSTS', 'Comparação HTTP x HTTPS'],
    rfcs: ['RFC 8446', 'RFC 5246', 'RFC 6797', 'RFC 5280'],
    status: 'available',
    engine: 'nativo',
  },
  {
    id: 'ftp',
    category: 'protocolos-seguros',
    title: 'FTP, FTPS e SFTP',
    summary: 'Transferência de arquivos por dentro: FTP com canais de controle e de dados (modos ativo e passivo, NAT e firewall), FTPS explícito e implícito, SFTP sobre SSH e a comparação do que um observador na rede enxerga em cada um.',
    topics: ['Canais de controle e de dados', 'Modos ativo e passivo atrás de NAT', 'FTPS: AUTH TLS, PROT P e PROT C', 'SFTP e comparação dos três'],
    rfcs: ['RFC 959', 'RFC 4217', 'RFC 2428', 'RFC 4253'],
    status: 'available',
    engine: 'nativo',
  },
  {
    id: 'dnssec',
    category: 'protocolos-seguros',
    title: 'DNS e DNSSEC',
    summary: 'Resolução de nomes e a cadeia de confiança do DNSSEC: DNSKEY, RRSIG, DS e a validação pelo resolvedor.',
    topics: [],
    rfcs: ['RFC 4033', 'RFC 4034', 'RFC 4035'],
    status: 'planned',
  },
  {
    id: 'vpn',
    category: 'protocolos-seguros',
    title: 'VPN (IPsec e WireGuard)',
    summary: 'Túneis cifrados entre redes: IKEv2 e ESP no IPsec, o handshake do WireGuard e a comparação entre os dois.',
    topics: [],
    rfcs: ['RFC 7296', 'RFC 4303'],
    status: 'planned',
  },
  {
    id: 'smtp',
    category: 'protocolos-seguros',
    title: 'SMTP e segurança de e-mail',
    summary: 'Entrega de e-mail passo a passo: diálogo SMTP, STARTTLS e a autenticação de domínio com SPF, DKIM e DMARC.',
    topics: [],
    rfcs: ['RFC 5321', 'RFC 3207', 'RFC 7208', 'RFC 6376', 'RFC 7489'],
    status: 'planned',
  },
  {
    id: 'is-is',
    category: 'camada-de-rede',
    title: 'IS-IS',
    summary: 'Roteamento por estado de enlace no IS-IS: adjacências, PDUs Hello, LSPs, níveis 1 e 2 e o cálculo SPF.',
    topics: [],
    rfcs: ['RFC 1195', 'ISO/IEC 10589'],
    status: 'planned',
  },
  {
    id: 'snmp',
    category: 'camada-de-rede',
    title: 'SNMP',
    summary: 'Gerência de redes com SNMP: GET, SET, GETNEXT, traps, a MIB e o modelo de segurança SNMPv3.',
    topics: [],
    rfcs: ['RFC 3411', 'RFC 3416', 'RFC 3414'],
    status: 'planned',
  },
  {
    id: 'arp',
    category: 'camada-de-rede',
    title: 'ARP',
    summary: 'Resolução de endereços na rede local: requisição em broadcast e resposta unicast, tabela ARP e seus estados, destino remoto via gateway, proxy ARP, ARP gratuito, detecção e defesa de endereço duplicado, failover de IP e o envenenamento de cache com as defesas.',
    topics: ['Requisição e resposta', 'Tabela ARP (REACHABLE, STALE, FAILED)', 'Gateway e proxy ARP', 'ARP Probe e Announce', 'Conflito de endereço e failover', 'Envenenamento de cache e defesas (DAI, entradas estáticas)'],
    rfcs: ['RFC 826', 'RFC 1027', 'RFC 1122', 'RFC 5227'],
    status: 'available',
    engine: 'nativo',
  },
  {
    id: 'nat',
    category: 'camada-de-rede',
    title: 'NAT (SNAT, DNAT e NAPT)',
    summary: 'Tradução de endereços e portas: Basic NAT estático e dinâmico, NAPT (PAT), SNAT e DNAT, com a tabela de traduções, colisão de portas, esgotamento, expiração, hairpinning, ESP com NAT-T e CGNAT.',
    topics: ['Basic NAT e NAPT (PAT)', 'SNAT e DNAT', 'Tabela de traduções e portas', 'Hairpinning e redirecionamento transparente', 'Esgotamento de portas e expiração', 'ESP, NAT-T e CGNAT'],
    rfcs: ['RFC 2663', 'RFC 3022', 'RFC 4787', 'RFC 5382', 'RFC 5508', 'RFC 6598', 'RFC 6888'],
    status: 'available',
    novo: true,
    engine: 'nativo',
  },
  {
    id: 'http-versoes',
    category: 'transporte',
    title: 'HTTP/1.1, HTTP/2 e HTTP/3',
    summary: 'O carregamento de uma página em HTTP/1.1, HTTP/2 e HTTP/3: conexões paralelas e fila de pedidos, multiplexação de fluxos com HPACK, QUIC sobre UDP com handshake de 1 RTT e 0-RTT, perda de pacote (bloqueio de cabeça de fila no TCP) e fallback quando o UDP é bloqueado.',
    topics: ['Conexões e fila no HTTP/1.1', 'Fluxos e HPACK no HTTP/2', 'QUIC, 0-RTT e fallback no HTTP/3', 'Perda de pacote e bloqueio de cabeça de fila'],
    rfcs: ['RFC 9110', 'RFC 9112', 'RFC 9113', 'RFC 9114', 'RFC 9000'],
    status: 'available',
    novo: true,
    engine: 'nativo',
  },
  {
    id: 'congestionamento',
    category: 'transporte',
    title: 'Controle de congestionamento (Reno, CUBIC e BBR)',
    summary: 'Como cada algoritmo ajusta a janela de congestionamento diante de perdas e de atraso: Reno, CUBIC e BBR comparados no mesmo cenário. Estende o simulador de TCP.',
    topics: [],
    rfcs: ['RFC 5681', 'RFC 9438', 'RFC 6582'],
    status: 'planned',
  },
  {
    id: '802-1x',
    category: 'protocolos-seguros',
    title: '802.1X e RADIUS (EAP)',
    summary: 'Autenticação de acesso à rede: suplicante, autenticador e servidor RADIUS trocando mensagens EAP até liberar ou bloquear a porta.',
    topics: [],
    rfcs: ['RFC 3748', 'RFC 2865', 'IEEE 802.1X'],
    status: 'planned',
  },
];

export const simsByCategory = (id: CategoryId) => SIMS.filter((s) => s.category === id);
export const findSim = (id: string | undefined) => SIMS.find((s) => s.id === id);
/** Endereço do arquivo de um simulador legado, respeitando o caminho base da publicação. */
export const simUrl = (sim: SimMeta) => `${import.meta.env.BASE_URL}sims/${sim.file}`;
