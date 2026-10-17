// Aba Referência do ARP.
export const reference: string = [
  '<h3>O que o ARP resolve</h3><p>O <b>ARP</b> (<i>Address Resolution Protocol</i>, RFC 826) descobre o endereço físico (MAC) de um host a partir do endereço IPv4 dele, <b>dentro da mesma rede local</b>. A Ethernet entrega quadros por MAC, e o IP só sabe de endereços IP: o ARP liga as duas coisas. No IPv6 essa função é do NDP, tratado em outro protocolo.</p>',
  '<h3>Formato do pacote (RFC 826, para IPv4 sobre Ethernet)</h3><table class="sc-msgs"><thead><tr><th>Campo</th><th>Tamanho</th><th>Valor</th></tr></thead><tbody>' +
    '<tr><td>Tipo de hardware</td><td>2 bytes</td><td class="meaning">1 (Ethernet)</td></tr>' +
    '<tr><td>Tipo de protocolo</td><td>2 bytes</td><td class="meaning">0x0800 (IPv4)</td></tr>' +
    '<tr><td>Tamanho do endereço físico</td><td>1 byte</td><td class="meaning">6</td></tr>' +
    '<tr><td>Tamanho do endereço de protocolo</td><td>1 byte</td><td class="meaning">4</td></tr>' +
    '<tr><td>Operação</td><td>2 bytes</td><td class="meaning">1 requisição, 2 resposta</td></tr>' +
    '<tr><td>Endereço físico do remetente (SHA)</td><td>6 bytes</td><td class="meaning">MAC de quem envia</td></tr>' +
    '<tr><td>IP do remetente (SPA)</td><td>4 bytes</td><td class="meaning">IP de quem envia</td></tr>' +
    '<tr><td>Endereço físico do alvo (THA)</td><td>6 bytes</td><td class="meaning">zerado na requisição</td></tr>' +
    '<tr><td>IP do alvo (TPA)</td><td>4 bytes</td><td class="meaning">o IP perguntado</td></tr></tbody></table>' +
    '<p>O quadro Ethernet que carrega o pacote usa o tipo 0x0806. São 28 bytes de ARP e 14 do cabeçalho Ethernet: 42 bytes, que a placa completa até o mínimo de 60 bytes no meio físico.</p>',
  '<h3>Requisição, resposta e aprendizado</h3><ul>' +
    '<li>A <b>requisição</b> vai para o broadcast (ff:ff:ff:ff:ff:ff): todos os hosts da rede a recebem e só o dono do IP perguntado responde.</li>' +
    '<li>A <b>resposta</b> vai em unicast para quem perguntou.</li>' +
    '<li>Quem é o alvo da requisição guarda o par IP e MAC do remetente (RFC 826), e por isso a resposta de volta (o <i>Echo Reply</i> do ping) não exige outra consulta.</li></ul>',
  '<h3>Tabela ARP e estados das entradas</h3><p>O resultado fica numa tabela, que no Linux se vê com <code>ip neigh</code>. Os estados mostrados pelo simulador são os do kernel Linux:</p><table class="sc-msgs"><thead><tr><th>Estado</th><th>Significado</th></tr></thead><tbody>' +
    '<tr><td>INCOMPLETE</td><td class="meaning">requisição enviada, resposta ainda não chegou</td></tr>' +
    '<tr><td>REACHABLE</td><td class="meaning">o vizinho respondeu há pouco; a entrada é confiável</td></tr>' +
    '<tr><td>STALE</td><td class="meaning">passou o tempo de validade; ainda é usada, mas será confirmada</td></tr>' +
    '<tr><td>FAILED</td><td class="meaning">sem resposta depois das tentativas</td></tr></tbody></table>' +
    '<p>Os tempos variam entre sistemas: no Linux, a retransmissão padrão é de 1 s com 3 tentativas, e a validade (REACHABLE) é de algumas dezenas de segundos, sorteada. Em roteadores, o padrão costuma ser de horas. O simulador usa os valores do Linux.</p>',
  '<h3>Fora da sub-rede e proxy ARP</h3><ul>' +
    '<li>O broadcast <b>não atravessa roteadores</b>. Para um destino em outra rede, o host faz o ARP do <b>gateway</b>, e o quadro leva o MAC do gateway com o IP de destino remoto.</li>' +
    '<li>No <b>proxy ARP</b> (RFC 1027), o roteador responde a requisições por endereços de outras redes usando o próprio MAC. Serve para hosts sem gateway, mas esconde erros de máscara e de rota.</li></ul>',
  '<h3>ARP gratuito, Probe e Announce (RFC 5227)</h3><ul>' +
    '<li>O <b>ARP Probe</b> é uma requisição com o IP do remetente <b>zerado</b> (0.0.0.0): pergunta se alguém usa o endereço sem contaminar as tabelas dos vizinhos. A RFC prevê 3 Probes, com 1 a 2 s entre eles, depois de uma espera inicial de até 1 s.</li>' +
    '<li>O <b>ARP Announce</b> é uma requisição em que o IP do remetente e o do alvo são o mesmo endereço. A RFC prevê 2 Announces, a cada 2 s, depois de uma espera de 2 s. Os vizinhos que já tinham uma entrada para o IP a atualizam; ninguém cria entrada por causa de um Announce.</li>' +
    '<li>O <b>ARP gratuito</b> clássico também pode ser uma resposta (operação 2) que ninguém pediu, em broadcast. É o que muitas implementações enviam ao assumir um IP em um failover. O valor do endereço físico do alvo varia entre sistemas.</li>' +
    '<li>Se o dono de um endereço vê um conflito, ele o <b>defende</b> com um Announce, no máximo uma vez a cada 10 s. Um segundo conflito dentro desse intervalo faz o host abandonar o endereço.</li>' +
    '<li>Com DHCP, quem detecta o endereço em uso recusa a oferta com <code>DHCPDECLINE</code> (RFC 2131).</li></ul>',
  '<h3>Segurança</h3><p>O ARP <b>não tem autenticação</b>: o host aceita qualquer resposta que pareça válida e a guarda na tabela. É o que torna a camada 2 uma superfície de ataque dentro da rede local, e é a razão de existirem entradas estáticas, inspeção de ARP em switches (DAI) e monitoramento da tabela. O ARP gratuito e a defesa de endereço tratam conflitos acidentais: um host malicioso pode enviar os mesmos pacotes para enganar a tabela dos vizinhos.</p>',
  '<h3>Limitações do simulador</h3><p>O simulador mostra um único segmento Ethernet com três hosts (o switch não aparece, mas é ele que entrega o broadcast a todos). Os endereços são de documentação (RFC 5737 e RFC 7042), os tempos são didáticos e, no destino remoto, a resposta do ping é gerada pelo gateway, sem simular a rede além dele. No modo de conflito, os tempos da RFC 5227 são valores fixos (a RFC sorteia intervalos). Fora do escopo: o NDP do IPv6.</p>',
].join('');
