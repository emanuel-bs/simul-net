// Glossário de siglas: fonte única do significado e da finalidade de cada sigla usada nos documentos e nos simuladores.
// Uso: seção "Siglas deste documento" no fim de cada documento gerado. A cobertura é verificada por tests/glossario.test.ts.
// Redação: português do Brasil, sem travessão longo nem meia-risca. As expansões seguem os nomes oficiais em inglês.

export interface Sigla {
  /** A sigla como aparece no texto (ex.: "CSMA/CA"). */
  sigla: string;
  /** Expansão oficial, em geral em inglês. */
  expansao: string;
  /** Nome em português, quando existe um uso corrente. */
  pt?: string;
  /** Uma frase: para que serve. */
  serve: string;
  /** Ids dos simuladores em que o sentido vale. Sem este campo, a entrada vale em todos. */
  escopo?: string[];
  /** Siglas que compõem esta (ex.: CSMA/CA tem CSMA e CA). */
  partes?: string[];
}

export const GLOSSARIO: Sigla[] = [
  // ---- projeto e normas ----
  { sigla: 'IA', expansao: 'Inteligência Artificial', serve: 'no rodapé do projeto, indica que o conteúdo foi elaborado com apoio de IA generativa, sob revisão do autor' },
  { sigla: 'MIT', expansao: 'Massachusetts Institute of Technology (licença MIT)', pt: 'licença MIT', serve: 'licença de código aberto permissiva sob a qual o Simul-Net é distribuído' },
  { sigla: 'RFC', expansao: 'Request for Comments', pt: 'pedido de comentários', serve: 'documento numerado do IETF que define ou descreve um protocolo da Internet; cada documento do projeto cita as RFCs com link para o RFC Editor' },
  { sigla: 'IETF', expansao: 'Internet Engineering Task Force', serve: 'organização aberta que desenvolve e publica os padrões da Internet, as RFCs' },
  { sigla: 'IEEE', expansao: "Institute of Electrical and Electronics Engineers", serve: 'entidade que publica padrões de redes locais, como o 802.3 (Ethernet), o 802.1 (comutação) e o 802.11 (Wi-Fi)' },
  { sigla: 'BCP', expansao: 'Best Current Practice', pt: 'melhor prática atual', serve: 'série de RFCs com práticas recomendadas de operação, como a BCP 38 (filtragem de endereços de origem forjados)' },
  // ---- internet e transporte ----
  { sigla: 'IP', expansao: 'Internet Protocol', pt: 'protocolo de internet', serve: 'endereça e encaminha pacotes entre redes, de origem a destino' },
  { sigla: 'TCP', expansao: 'Transmission Control Protocol', pt: 'protocolo de controle de transmissão', serve: 'entrega dados de forma ordenada e confiável, com conexão, confirmação e controle de congestionamento' },
  { sigla: 'UDP', expansao: 'User Datagram Protocol', serve: 'entrega datagramas sem conexão nem confirmação, com baixo custo; usado em consultas curtas e em tempo real' },
  { sigla: 'TCP/UDP', expansao: 'Transmission Control Protocol e User Datagram Protocol', serve: 'refere-se aos dois protocolos de transporte da pilha da Internet', partes: ['TCP', 'UDP'] },
  { sigla: 'TCP-AO', expansao: 'TCP Authentication Option', pt: 'opção de autenticação do TCP', serve: 'autentica cada segmento TCP por chave compartilhada; sucede a opção TCP MD5 e protege sessões como as do BGP' },
  { sigla: 'SYN', expansao: 'Synchronize', serve: 'flag do TCP que inicia uma conexão e sincroniza os números de sequência' },
  { sigla: 'SYN-ACK', expansao: 'Synchronize-Acknowledge', serve: 'resposta do servidor ao SYN no handshake de três vias: aceita a conexão e envia o próprio número de sequência' },
  { sigla: 'ACK', expansao: 'Acknowledgment', pt: 'confirmação', serve: 'flag ou frame que confirma o recebimento de dados anteriores' },
  { sigla: 'FIN', expansao: 'Finish', serve: 'flag do TCP que encerra a conexão de forma ordenada' },
  { sigla: 'RST', expansao: 'Reset', serve: 'flag do TCP que derruba a conexão de imediato, por exemplo ao receber segmento de uma conexão que não existe' },
  { sigla: 'RTT', expansao: 'Round-Trip Time', pt: 'tempo de ida e volta', serve: 'mede o tempo entre enviar um pacote e receber a resposta; base dos temporizadores e da latência' },
  { sigla: 'TTL', expansao: 'Time To Live', pt: 'tempo de vida', serve: 'limita quantos saltos um pacote pode dar; cada roteador o reduz de 1, e ao chegar a zero o pacote é descartado' },
  { sigla: 'ICMP', expansao: 'Internet Control Message Protocol', serve: 'leva mensagens de controle e de erro da camada IP, como o eco do ping e o aviso de destino inalcançável' },
  { sigla: 'QUIC', expansao: 'nome do protocolo, que não é uma sigla oficial', serve: 'transporte sobre UDP com criptografia embutida e múltiplos fluxos independentes; base do HTTP/3' },
  { sigla: 'NTP', expansao: 'Network Time Protocol', serve: 'sincroniza o relógio dos equipamentos com uma fonte de tempo confiável' },
  { sigla: 'CDN', expansao: 'Content Delivery Network', pt: 'rede de distribuição de conteúdo', serve: 'serviço com servidores espalhados que entregam o conteúdo perto do usuário e absorvem volume de tráfego' },
  // ---- enlace e comutação ----
  { sigla: 'MAC', expansao: 'Media Access Control', serve: 'camada de enlace que controla o acesso ao meio; também nomeia o endereço físico de 48 bits de uma interface' },
  { sigla: 'FCS', expansao: 'Frame Check Sequence', pt: 'sequência de verificação do frame', serve: 'código (CRC) no fim do frame que permite ao receptor descartar frames corrompidos' },
  { sigla: 'L2', expansao: 'Layer 2', pt: 'camada 2 (enlace)', serve: 'indica que o equipamento encaminha por endereço MAC, como um switch' },
  { sigla: 'ARP', expansao: 'Address Resolution Protocol', pt: 'protocolo de resolução de endereços', serve: 'descobre o endereço MAC que corresponde a um endereço IPv4 na rede local' },
  { sigla: 'VLAN', expansao: 'Virtual Local Area Network', pt: 'rede local virtual', serve: 'separa logicamente uma rede em domínios de broadcast isolados no mesmo equipamento físico' },
  { sigla: 'STP', expansao: 'Spanning Tree Protocol', pt: 'protocolo de árvore de abrangência', serve: 'evita laços em redes comutadas, bloqueando enlaces redundantes até que sejam necessários' },
  { sigla: 'ACL', expansao: 'Access Control List', pt: 'lista de controle de acesso', serve: 'conjunto ordenado de regras que permite ou nega tráfego conforme endereços, portas e protocolos' },
  { sigla: 'VPN', expansao: 'Virtual Private Network', pt: 'rede privada virtual', serve: 'cria um canal protegido, em geral cifrado, sobre uma rede pública' },
  { sigla: 'NAT', expansao: 'Network Address Translation', pt: 'tradução de endereços de rede', serve: 'troca endereços e portas dos pacotes, para que uma rede privada compartilhe poucos endereços públicos' },
  { sigla: 'DHCP', expansao: 'Dynamic Host Configuration Protocol', pt: 'protocolo de configuração dinâmica de hosts', serve: 'entrega ao cliente endereço IP, máscara, gateway e DNS, por empréstimo (lease)' },
  { sigla: 'DHCPDISCOVER', expansao: 'DHCP Discover', serve: 'primeira mensagem do DORA: o cliente, ainda sem endereço, pergunta em broadcast se há servidor DHCP', escopo: ['dhcp'] },
  // ---- roteamento ----
  { sigla: 'BGP', expansao: 'Border Gateway Protocol', pt: 'protocolo de roteador de borda', serve: 'troca rotas entre sistemas autônomos e sustenta o roteamento entre operadoras na Internet' },
  { sigla: 'OSPF', expansao: 'Open Shortest Path First', serve: 'protocolo de roteamento interno que calcula o menor caminho a partir do mapa completo da rede' },
  // ---- nomes e aplicação ----
  { sigla: 'DNS', expansao: 'Domain Name System', pt: 'sistema de nomes de domínio', serve: 'traduz nomes (www.exemplo.org) em endereços IP e guarda outros registros do domínio' },
  { sigla: 'FTP', expansao: 'File Transfer Protocol', pt: 'protocolo de transferência de arquivos', serve: 'transfere arquivos entre cliente e servidor, com canal de controle e canal de dados separados' },
  { sigla: 'HTTP', expansao: 'Hypertext Transfer Protocol', pt: 'protocolo de transferência de hipertexto', serve: 'transporta páginas e dados entre navegador e servidor web' },
  { sigla: 'HTTP/1', expansao: 'HTTP versão 1.1', serve: 'versão textual do HTTP, com uma requisição por vez em cada conexão' },
  { sigla: 'HTTP/2', expansao: 'HTTP versão 2', serve: 'versão binária do HTTP que multiplexa vários fluxos em uma só conexão TCP' },
  { sigla: 'HTTP/3', expansao: 'HTTP versão 3', serve: 'versão do HTTP sobre QUIC e UDP, que evita o bloqueio de um fluxo por perda em outro' },
  { sigla: 'HTTPS', expansao: 'HTTP Secure', serve: 'HTTP protegido por TLS: cifra o conteúdo e autentica o servidor' },
  { sigla: 'TLS', expansao: 'Transport Layer Security', pt: 'segurança da camada de transporte', serve: 'estabelece um canal cifrado e autenticado entre dois pontos, a base do HTTPS' },
  { sigla: 'SSH', expansao: 'Secure Shell', serve: 'acesso remoto e transferência de arquivos por um canal cifrado, com autenticação do servidor e do usuário' },
  // ---- segurança ----
  { sigla: 'CA', expansao: 'Certification Authority', pt: 'autoridade certificadora', serve: 'entidade que assina certificados digitais e é a âncora de confiança de quem os valida', escopo: ['802-1x', 'https'] },
  { sigla: 'ID', expansao: 'Identifier', pt: 'identificador', serve: 'valor que distingue uma entidade ou uma consulta, como o router ID do BGP e o ID da consulta DNS' },
  // ---- lote A: siglas de dois documentos ----
  { sigla: 'LAN', expansao: 'Local Area Network', pt: 'rede local', serve: 'rede de alcance restrito, como a de um prédio ou laboratório, ligada por switches ou por Wi-Fi' },
  { sigla: 'ISP', expansao: 'Internet Service Provider', pt: 'provedor de acesso à Internet', serve: 'operadora que liga o cliente à Internet e anuncia os prefixos dele a outras redes' },
  { sigla: 'URL', expansao: 'Uniform Resource Locator', pt: 'localizador uniforme de recursos', serve: 'endereço completo de um recurso, com protocolo, nome do servidor e caminho' },
  { sigla: 'IGP', expansao: 'Interior Gateway Protocol', pt: 'protocolo de roteamento interno', serve: 'roteamento dentro de um sistema autônomo, como o OSPF; contrasta com o BGP, que liga sistemas autônomos' },
  { sigla: 'LSR', expansao: 'Label Switching Router', pt: 'roteador de comutação por rótulos', serve: 'roteador MPLS que encaminha pacotes pelo rótulo, sem consultar o endereço IP de destino' },
  { sigla: 'FEC', expansao: 'Forwarding Equivalence Class', pt: 'classe de equivalência de encaminhamento', serve: 'conjunto de pacotes que recebe o mesmo rótulo e o mesmo caminho no MPLS', escopo: ['mpls'] },
  { sigla: 'FEC', expansao: 'Forward Error Correction', pt: 'correção antecipada de erros', serve: 'envia redundância junto com os dados para o receptor recuperar perdas sem retransmissão', escopo: ['tcp-udp'] },
  { sigla: 'BFD', expansao: 'Bidirectional Forwarding Detection', serve: 'detecta em milissegundos a falha de um enlace ou vizinho, para o roteamento reagir depressa' },
  { sigla: 'MSS', expansao: 'Maximum Segment Size', pt: 'tamanho máximo de segmento', serve: 'maior quantidade de dados que o TCP aceita por segmento; negociada no SYN' },
  { sigla: 'SACK', expansao: 'Selective Acknowledgment', pt: 'confirmação seletiva', serve: 'o receptor informa quais blocos chegaram fora de ordem, e o emissor reenvia só o que faltou' },
  { sigla: 'PMTUD', expansao: 'Path MTU Discovery', pt: 'descoberta da MTU do caminho', serve: 'descobre o maior pacote que passa pelo caminho sem fragmentar, usando mensagens ICMP' },
  { sigla: 'RSTP', expansao: 'Rapid Spanning Tree Protocol', serve: 'versão do STP que converge em segundos, pela negociação direta entre as pontes' },
  { sigla: 'MSTP', expansao: 'Multiple Spanning Tree Protocol', serve: 'versão do STP com várias árvores, cada uma para um grupo de VLANs' },
  { sigla: 'BPDU', expansao: 'Bridge Protocol Data Unit', serve: 'frame que as pontes trocam no STP para eleger a raiz e calcular as portas' },
  { sigla: 'EAPOL', expansao: 'Extensible Authentication Protocol over LAN', serve: 'leva o EAP entre o cliente e o switch ou AP no 802.1X, antes de a porta liberar tráfego' },
  { sigla: 'DS', expansao: 'Delegation Signer', pt: 'assinante da delegação', serve: 'registro na zona pai que guarda o hash da chave da zona filha e liga a cadeia de confiança do DNSSEC', escopo: ['dns'] },
  { sigla: 'DS', expansao: 'Distribution System', pt: 'sistema de distribuição', serve: 'rede, em geral cabeada, que liga os APs entre si e ao restante da infraestrutura', escopo: ['wifi'] },
  { sigla: 'RA', expansao: 'Recursion Available', pt: 'recursão disponível', serve: 'flag da resposta DNS que informa que o servidor faz consultas recursivas', escopo: ['dns'] },
  { sigla: 'RA', expansao: 'Receiver Address', pt: 'endereço do receptor', serve: 'primeiro endereço do cabeçalho 802.11: quem deve receber o frame', escopo: ['wifi'] },
  { sigla: 'RD', expansao: 'Recursion Desired', pt: 'recursão desejada', serve: 'flag da consulta DNS em que o cliente pede ao servidor que resolva o nome por inteiro', escopo: ['dns'] },
  { sigla: 'RD', expansao: 'Route Distinguisher', pt: 'distinguidor de rota', serve: 'prefixo de 64 bits que torna únicos prefixos IP repetidos de clientes diferentes numa VPN MPLS', escopo: ['mpls'] },
  { sigla: 'NSEC', expansao: 'Next Secure', serve: 'registro DNSSEC que prova que um nome não existe, apontando o próximo nome da zona' },
  { sigla: 'DNSSEC', expansao: 'DNS Security Extensions', pt: 'extensões de segurança do DNS', serve: 'assina as respostas DNS para que o resolvedor confira a autenticidade e a integridade' },
  { sigla: 'NXDOMAIN', expansao: 'Non-Existent Domain', pt: 'domínio inexistente', serve: 'código de resposta do DNS que informa que o nome consultado não existe' },
  { sigla: 'RRL', expansao: 'Response Rate Limiting', pt: 'limitação da taxa de respostas', serve: 'limita respostas DNS idênticas para o servidor não servir de amplificador de ataques' },
  { sigla: 'SPF', expansao: 'Sender Policy Framework', serve: 'registro DNS que lista os servidores autorizados a enviar e-mail por um domínio' },
  { sigla: 'SNMP', expansao: 'Simple Network Management Protocol', pt: 'protocolo simples de gerência de rede', serve: 'consulta e configura equipamentos de rede, e recebe alertas deles' },
  { sigla: 'SFTP', expansao: 'SSH File Transfer Protocol', serve: 'transfere arquivos dentro de um canal SSH, não relacionado ao FTP' },
  { sigla: 'SNI', expansao: 'Server Name Indication', pt: 'indicação do nome do servidor', serve: 'extensão do TLS em que o cliente informa o nome do site, para o servidor escolher o certificado; costuma ir em claro' },
  { sigla: 'ALPN', expansao: 'Application-Layer Protocol Negotiation', serve: 'extensão do TLS que negocia o protocolo de aplicação, como HTTP/2 ou HTTP/3, no próprio handshake' },
  { sigla: 'HSTS', expansao: 'HTTP Strict Transport Security', serve: 'cabeçalho com que o servidor manda o navegador usar sempre HTTPS, dificultando o rebaixamento para HTTP' },
  { sigla: 'SSL', expansao: 'Secure Sockets Layer', serve: 'antecessor do TLS, com versões obsoletas e inseguras; o nome ainda é usado, de forma imprecisa, para o TLS' },
  { sigla: 'MITM', expansao: 'Man-in-the-Middle', pt: 'homem no meio', serve: 'ataque em que alguém se interpõe entre duas partes para ler ou alterar a comunicação; a autenticação e a cifra o defendem' },
  { sigla: 'AEAD', expansao: 'Authenticated Encryption with Associated Data', pt: 'cifra autenticada com dados associados', serve: 'cifra os dados e garante a integridade num só passo, como o AES-GCM' },
  { sigla: 'AES-GCM', expansao: 'Advanced Encryption Standard, Galois/Counter Mode', serve: 'cifra autenticada (AEAD) muito usada no TLS e no SSH', partes: ['AEAD'] },
  { sigla: 'CBC', expansao: 'Cipher Block Chaining', pt: 'encadeamento de blocos', serve: 'modo de cifra de blocos mais antigo, sem autenticação própria, hoje desaconselhado' },
  { sigla: 'MD5', expansao: 'Message Digest 5', serve: 'função de hash antiga, considerada insegura para assinaturas; ainda aparece em protocolos legados' },
  { sigla: 'RSA', expansao: 'Rivest, Shamir e Adleman', serve: 'algoritmo de chave pública usado para assinaturas e troca de chaves' },
  { sigla: 'NIST', expansao: 'National Institute of Standards and Technology', serve: 'instituto dos Estados Unidos que publica padrões e guias de segurança, como a série SP 800' },
  { sigla: 'SP', expansao: 'Special Publication', pt: 'publicação especial', serve: 'série de guias técnicos do NIST, como a SP 800-41, sobre firewalls', escopo: ['ataques-tcp-udp', 'firewall'] },
  { sigla: 'ALG', expansao: 'Application Layer Gateway', serve: 'componente do NAT ou do firewall que entende um protocolo, como o FTP, e reescreve endereços dentro dos dados' },
  { sigla: 'IPS', expansao: 'Intrusion Prevention System', pt: 'sistema de prevenção de intrusão', serve: 'inspeciona o tráfego e bloqueia o que casa com ataques conhecidos; o IDS apenas alerta' },
  { sigla: 'CGNAT', expansao: 'Carrier-Grade NAT', serve: 'NAT em grande escala feito pela operadora, que compartilha um endereço público entre muitos clientes' },
  { sigla: 'RTBH', expansao: 'Remotely Triggered Black Hole', pt: 'buraco negro acionado remotamente', serve: 'descarta, perto da origem, todo o tráfego para um alvo atacado, pelo anúncio de uma rota (RFC 7999)' },
  { sigla: 'AP', expansao: 'Access Point', pt: 'ponto de acesso', serve: 'liga os clientes sem fio à rede cabeada e faz a ponte entre o 802.11 e o Ethernet' },
  { sigla: 'EAP', expansao: 'Extensible Authentication Protocol', pt: 'protocolo de autenticação extensível', serve: 'arcabouço que transporta métodos de autenticação, como EAP-TLS, entre o cliente e o servidor de autenticação' },
  { sigla: 'IDS', expansao: 'Intrusion Detection System', pt: 'sistema de detecção de intrusão', serve: 'inspeciona o tráfego e gera alertas sobre padrões de ataque, sem bloquear' },
  { sigla: 'MTU', expansao: 'Maximum Transmission Unit', pt: 'unidade máxima de transmissão', serve: 'maior pacote que um enlace transporta sem fragmentar' },
  { sigla: 'MPLS', expansao: 'Multiprotocol Label Switching', pt: 'comutação multiprotocolo por rótulos', serve: 'encaminha pacotes por rótulos curtos, usado em redes de operadora e em VPNs' },
  { sigla: 'CRC', expansao: 'Cyclic Redundancy Check', pt: 'verificação de redundância cíclica', serve: 'código que detecta erros de transmissão, como o do FCS dos frames Ethernet e 802.11' },
  // ---- sentidos específicos de um simulador ----
  { sigla: 'TC', expansao: 'Truncated', pt: 'truncada', serve: 'flag da resposta DNS que avisa não ter cabido no limite do UDP; o resolvedor repete por TCP', escopo: ['dns'] },
  { sigla: 'TC', expansao: 'Traffic Class', pt: 'classe de tráfego', serve: 'campo de 3 bits do rótulo MPLS usado para qualidade de serviço (antigo EXP)', escopo: ['mpls'] },
  { sigla: 'IOS', expansao: 'Internetwork Operating System', serve: 'sistema operacional dos equipamentos Cisco; os valores padrão citados nos exemplos vêm dele' },
  { sigla: 'CPU', expansao: 'Central Processing Unit', pt: 'unidade central de processamento', serve: 'processador do equipamento; nos exemplos, o recurso que um ataque ou uma consulta pesada esgota' },
];

/** Siglas que aparecem nos documentos mas não são siglas de glossário: métodos, estados, nomes de equipamentos de exemplo. */
export const NAO_SIGLAS = new Set([
  'GET', 'POST', 'OK', 'DATA', 'ESTABLISHED',
  'SW1', 'SW2', 'PC-A', 'PC-B', 'R1', 'R2', 'R3', 'SW1-SW2', 'SRV',
  // nomes de mensagens e de estados dos protocolos: ficam para um glossário de mensagens
  'INIT', 'OPEN', 'READ', 'KEXINIT', 'NEWKEYS', 'REFUSED', 'DHCPDECLINE',
]);

/** Siglas citadas em um texto, com o número de ocorrências. Ignora blocos e trechos de código, links e números de RFC. */
export function siglasDoTexto(texto: string): Map<string, number> {
  const rx = /(?<![\w/#.-])([A-Z][A-Z0-9]+(?:[/-][A-Z0-9]+)*)(?!\w)/g;
  const limpo = texto
    .replace(/```[\s\S]*?```/g, '')
    .replace(/`[^`]*`/g, '')
    .replace(/\]\([^)]*\)/g, '](')
    .replace(/RFC \d+/g, '');
  const out = new Map<string, number>();
  for (const m of limpo.matchAll(rx)) out.set(m[1], (out.get(m[1]) || 0) + 1);
  return out;
}

/** Entrada do glossário para uma sigla, preferindo a do simulador informado e, na falta, a de escopo geral. */
export function buscarSigla(sigla: string, simId?: string): Sigla | undefined {
  const todas = GLOSSARIO.filter((e) => e.sigla === sigla);
  return todas.find((e) => simId && e.escopo?.includes(simId)) || todas.find((e) => !e.escopo) || todas[0];
}

/** Entrada para uma sigla num simulador: a de escopo próprio ou a geral. Sem a de outro simulador (sentido errado). */
export function siglaNoSimulador(sigla: string, simId: string): Sigla | undefined {
  const todas = GLOSSARIO.filter((e) => e.sigla === sigla);
  return todas.find((e) => e.escopo?.includes(simId)) || todas.find((e) => !e.escopo);
}

const significado = (e: Sigla): string => e.expansao + (e.pt ? ', ' + e.pt : '');
const FIM_DOC = '\n\n---\n\n*';

/**
 * Acrescenta ao documento gerado a seção "Siglas deste documento", com o significado e a finalidade de cada sigla do
 * glossário que aparece no texto (no sentido do simulador). O texto corrido não é alterado e o rodapé de crédito fica no fim.
 */
export function comSecaoDeSiglas(texto: string, simId: string): string {
  const fim = texto.lastIndexOf(FIM_DOC);
  const corpo = fim >= 0 ? texto.slice(0, fim) : texto.replace(/\s+$/, '');
  const rodape = fim >= 0 ? texto.slice(fim) : '\n';
  const presentes = [...siglasDoTexto(corpo).keys()]
    .map((s) => siglaNoSimulador(s, simId))
    .filter((e): e is Sigla => !!e)
    .sort((a, b) => a.sigla.localeCompare(b.sigla, 'en'));
  if (!presentes.length) return corpo + rodape;
  const numerada = [...corpo.matchAll(/^## (\d+)\. /gm)].pop();
  const titulo = numerada ? `## ${Number(numerada[1]) + 1}. Siglas deste documento` : '## Siglas deste documento';
  const cel = (s: string) => s.replace(/\|/g, '\|');
  const tabela = presentes.map((e) => `| **${cel(e.sigla)}** | ${cel(significado(e))} | ${cel(e.serve)} |`);
  const secao = [titulo, '', 'Significado e finalidade das siglas usadas neste documento.', '', '| Sigla | Significado | Para que serve |', '| --- | --- | --- |', ...tabela].join('\n');
  return corpo + '\n\n' + secao + '\n' + rodape;
}
