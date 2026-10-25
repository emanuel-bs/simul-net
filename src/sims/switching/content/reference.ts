// Aba Referência do simulador de switching.
export const reference: string = [
  '<h3>O que um switch faz</h3><p>Um <b>switch</b> Ethernet é uma ponte multiporta (<i>MAC bridge</i>, IEEE 802.1D): recebe quadros em cada porta e decide, <b>só pelo endereço MAC</b>, por onde enviá-los. Ele não olha o endereço IP. A especificação de pontes do 802.1D foi incorporada ao IEEE 802.1Q, que hoje é a referência vigente; o simulador usa os dois nomes como os livros-texto. A Ethernet em si é definida pelo IEEE 802.3.</p>',
  '<h3>Os três passos para cada quadro</h3><ol>' +
    '<li><b>Aprendizado:</b> o MAC de <b>origem</b> é associado à porta de entrada, ou o relógio da entrada é renovado. Endereços de grupo e de broadcast nunca são aprendidos como origem.</li>' +
    '<li><b>Decisão:</b> o switch procura o MAC de <b>destino</b> na tabela. Destino conhecido em outra porta: <b>encaminha</b>. Destino conhecido na própria porta de entrada: <b>filtra</b>. Destino desconhecido, broadcast ou multicast: <b>inunda</b> (todas as portas, menos a de entrada).</li>' +
    '<li><b>Envelhecimento:</b> sem tráfego da origem, a entrada expira. O valor recomendado é de 300 s e é configurável.</li></ol>',
  '<h3>Quadro Ethernet II</h3><table class="sc-msgs"><thead><tr><th>Campo</th><th>Tamanho</th><th>Observação</th></tr></thead><tbody>' +
    '<tr><td>Destino</td><td>6 bytes</td><td class="meaning">o primeiro bit transmitido, o menos significativo do primeiro byte, indica endereço de grupo</td></tr>' +
    '<tr><td>Origem</td><td>6 bytes</td><td class="meaning">sempre unicast</td></tr>' +
    '<tr><td>Tipo</td><td>2 bytes</td><td class="meaning">0x0800 IPv4, 0x0806 ARP, 0x88cc LLDP</td></tr>' +
    '<tr><td>Dados</td><td>46 a 1500 bytes</td><td class="meaning">preenchidos até o mínimo</td></tr>' +
    '<tr><td>FCS</td><td>4 bytes</td><td class="meaning">verificação do quadro; o simulador não a mostra</td></tr></tbody></table>' +
    '<p>O menor quadro tem 64 bytes (do destino ao FCS). Os tamanhos mostrados no simulador (42 para o ARP, 98 para o ping) são os do cabeçalho e dos dados, sem o preenchimento e sem o FCS.</p>',
  '<h3>Hub, switch e domínios</h3><ul>' +
    '<li>Um <b>hub</b> (repetidor) repete cada bit para todas as portas: todos os hosts atrás dele formam um único <b>domínio de colisão</b> e ouvem tudo. É o segmento da porta 3 do simulador.</li>' +
    '<li>Um <b>switch</b> isola o tráfego por porta: cada porta é um domínio de colisão à parte, e em full-duplex nem há colisão. O <b>domínio de broadcast</b>, porém, continua sendo a rede local inteira.</li>' +
    '<li>Para dividir o domínio de broadcast é preciso VLANs ou um roteador (outros simuladores do projeto).</li></ul>',
  '<h3>Multicast e IGMP snooping</h3><ul>' +
    '<li>O endereço MAC de um grupo IP é derivado do IP: os 23 bits de baixa ordem do IP entram em <code>01:00:5e:00:00:00</code> (RFC 1112, seção 6.4). Como o IP tem 28 bits de grupo, 32 grupos IP diferentes compartilham o mesmo MAC.</li>' +
    '<li>Sem ajuda, o switch trata o multicast como broadcast. O <b>IGMP snooping</b> lê os relatórios dos hosts e encaminha cada grupo só às portas com assinantes. O simulador usa o relatório do IGMPv3 (RFC 9776), enviado a 224.0.0.22.</li>' +
    '<li>A RFC 4541 (informativa, não normativa) descreve as regras de encaminhamento de um switch com snooping, entre elas a de que os grupos 224.0.0.x (de controle local) continuam sendo inundados. Um switch real precisa também de um consultor IGMP (<i>querier</i>) para renovar as assinaturas, e envia o fluxo às portas de roteador multicast; o simulador não tem nenhum dos dois.</li></ul>',
  '<h3>Endereços de grupo reservados</h3><p>Os endereços de <code>01-80-C2-00-00-00</code> a <code>01-80-C2-00-00-0F</code> são reservados pelo IEEE a protocolos que valem só entre vizinhos diretos, como o spanning tree (00) e o LLDP (0E). Uma ponte processa esses quadros e <b>não os encaminha</b>. Alguns equipamentos simples não respeitam isso e os inundam.</p>',
  '<h3>Inundação de MAC e segurança de porta (nível defensivo)</h3><ul>' +
    '<li><b>Por que é possível:</b> a tabela de endereços é finita e o switch aprende qualquer origem, sem autenticá-la. Um host que envia quadros com origens inventadas ocupa as vagas.</li>' +
    '<li><b>Efeito:</b> com a tabela cheia, hosts novos (e os que expiraram) não são aprendidos. O tráfego para eles é inundado e chega a todas as portas, inclusive à do atacante. O switch passa a se comportar como um hub.</li>' +
    '<li><b>Alcance:</b> só dentro da rede local (e da VLAN) do atacante. A inundação não atravessa roteadores.</li>' +
    '<li><b>Impacto:</b> em tráfego sem cifra, o conteúdo é lido. Com TLS ou SSH, o conteúdo segue protegido, mas há perda de desempenho, pelo tráfego a mais.</li>' +
    '<li><b>Aviso:</b> este modo explica o mecanismo para fins de defesa. Atacar a rede de terceiros pode configurar crime; pratique apenas em laboratório isolado, com autorização.</li></ul>' +
    '<h3>Defesas</h3><table class="sc-msgs"><thead><tr><th>Defesa</th><th>Onde atua</th><th>Observação</th></tr></thead><tbody>' +
    '<tr><td>Segurança de porta (limite de MACs)</td><td class="meaning">na porta do switch</td><td class="meaning">recurso de fabricantes; os modos protect, restrict e shutdown variam por equipamento</td></tr>' +
    '<tr><td>IEEE 802.1X</td><td class="meaning">na porta do switch</td><td class="meaning">autentica o dispositivo antes de liberar a porta; é o padrão do IEEE</td></tr>' +
    '<tr><td>Tabelas maiores e envelhecimento ajustado</td><td class="meaning">no switch</td><td class="meaning">reduzem o impacto, mas não eliminam o ataque</td></tr>' +
    '<tr><td>Monitoramento de alertas e de MACs por porta</td><td class="meaning">na rede</td><td class="meaning">detecta o ataque e permite isolar a porta</td></tr>' +
    '<tr><td>Cifra de ponta a ponta (TLS, SSH, VPN)</td><td class="meaning">nas aplicações</td><td class="meaning">protege o conteúdo mesmo com a rede local comprometida</td></tr></tbody></table>',
  '<h3>Segurança</h3><p>O aprendizado de endereços <b>não tem autenticação</b>: o switch confia no MAC de origem de qualquer quadro. É a base de ataques de camada 2 como a inundação de MAC e o envenenamento de ARP (outro simulador do projeto). A proteção vem de limites por porta, de autenticação de acesso (802.1X) e da cifra de ponta a ponta.</p>',
  '<h3>Limitações do simulador</h3><p>O simulador mostra um único switch com quatro portas, sem VLANs, sem spanning tree e sem agregação de enlaces. Os endereços são de documentação (RFC 5737 para IPv4; RFC 7042 e RFC 9542 para MAC). A tabela do modo de inundação tem 4 ou 6 entradas, enquanto a de um switch real guarda de milhares a centenas de milhares. Quando a tabela enche, o simulador não aprende o endereço novo e inunda o destino desconhecido, mas o comportamento de um equipamento real varia (alguns removem entradas antigas, outros descartam o quadro). Os tempos de trânsito são didáticos e o simulador não representa colisões, modos de encaminhamento (<i>store-and-forward</i> e <i>cut-through</i>), velocidade das portas nem a negociação automática. Os modos da segurança de porta seguem a terminologia de um fabricante comum. Não foram citadas subcláusulas do IEEE 802.1D e do 802.1Q por falta de um texto aberto para conferência; as RFCs citadas foram conferidas no rfc-editor.org. Fora do escopo: IPv6 (MLD snooping), VLANs, STP, QoS e as funções de camada 3 do switch.</p>',
].join('');
