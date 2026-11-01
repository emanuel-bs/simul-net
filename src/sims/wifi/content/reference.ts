// Aba Referência do simulador de Wi-Fi (IEEE 802.11).
export const reference: string = [
  '<h3>Para que serve</h3><p>O <b>IEEE 802.11</b> define a camada de enlace (MAC) e a camada física das redes locais sem fio, conhecidas como Wi-Fi (marca da Wi-Fi Alliance). A base é o IEEE 802.11-2020, ampliado por emendas publicadas depois (por exemplo 802.11ax-2021 e 802.11be-2024). O texto é do IEEE e não é de acesso livre: confira a edição vigente no site do IEEE antes de citar uma cláusula. Este simulador trata da <b>operação da camada MAC</b>: descobrir e entrar numa rede, disputar o meio, trocar de AP, economizar energia e escolher canais. A segurança (WPA2 e WPA3) fica para o simulador Wi-Fi: segurança.</p>',
  '<h3>Os atores</h3><table class="sc-msgs"><thead><tr><th>Termo</th><th>Significado</th></tr></thead><tbody>' +
    '<tr><td>STA</td><td class="meaning">estação: o cliente (notebook, celular)</td></tr>' +
    '<tr><td>AP</td><td class="meaning">ponto de acesso: liga os clientes sem fio à rede cabeada e faz a ponte entre o 802.11 e o Ethernet</td></tr>' +
    '<tr><td>BSS e BSSID</td><td class="meaning">o conjunto de um AP e seus clientes. O BSSID é o endereço MAC do AP</td></tr>' +
    '<tr><td>SSID</td><td class="meaning">o nome da rede, até 32 bytes. Vários APs com o mesmo SSID formam um ESS, em que o cliente pode circular</td></tr>' +
    '<tr><td>DS</td><td class="meaning">sistema de distribuição: a rede (em geral cabeada) que liga os APs entre si</td></tr></tbody></table>',
  '<h3>Os três tipos de quadro</h3><table class="sc-msgs"><thead><tr><th>Tipo</th><th>Exemplos no simulador</th><th>Função</th></tr></thead><tbody>' +
    '<tr><td>Gerência (0)</td><td class="meaning">Beacon, Probe, Authentication, Association, Reassociation, Action</td><td class="meaning">descobrir, entrar, sair e negociar recursos</td></tr>' +
    '<tr><td>Controle (1)</td><td class="meaning">RTS, CTS, ACK, PS-Poll</td><td class="meaning">coordenar o acesso ao meio; são quadros curtos e sem corpo</td></tr>' +
    '<tr><td>Dados (2)</td><td class="meaning">Data, Null</td><td class="meaning">carregar os dados do usuário (cabeçalho com até 4 endereços)</td></tr></tbody></table>' +
    '<p>O cabeçalho MAC traz o Frame Control (tipo, subtipo e flags como To DS, From DS, Retry, Power Management e More Data), o Duration/ID, os endereços (RA, TA e o terceiro, que é o BSSID ou o destino) e o Sequence Control. O quadro termina com o FCS (CRC-32). A aba Mensagem mostra esses campos.</p>',
  '<h3>Descoberta e os três estados do cliente</h3><ul>' +
    '<li><b>Beacon:</b> o AP anuncia a rede a cada 100 TU (1 TU = 1024 µs, ou 102,4 ms), em broadcast, sem ACK. Traz SSID, taxas, canal, capacidades, TIM e, em redes protegidas, o elemento RSN.</li>' +
    '<li><b>Varredura passiva e ativa:</b> o cliente escuta os beacons ou envia Probe Request e recebe Probe Response. Os tempos por canal do simulador (20 ms e 110 ms) são valores típicos de implementação, não exigências do padrão.</li>' +
    '<li><b>Os três estados</b> (cláusula do MLME, gerenciamento da camada MAC): 1, não autenticado e não associado; 2, autenticado e não associado; 3, autenticado e associado. Cada estado admite classes de quadros (aba Estados).</li>' +
    '<li><b>Autenticação de sistema aberto:</b> dois quadros (algoritmo 0). Não verifica identidade nenhuma. A autenticação de verdade vem do WPA2 e WPA3, após a associação (RSN) ou no lugar da autenticação aberta (SAE, algoritmo 3 do WPA3).</li>' +
    '<li><b>Associação:</b> o AP atribui um AID (Association ID). O Status Code da resposta informa o resultado: 0 é sucesso e 17 é "AP incapaz de tratar mais estações". Outros códigos existem.</li></ul>',
  '<h3>Acesso ao meio: DCF (CSMA/CA)</h3><ul>' +
    '<li><b>Por que evitar, e não detectar:</b> o rádio não ouve enquanto transmite, então a colisão não é detectável. O Wi-Fi a evita (CSMA/CA) e confirma cada quadro unicast com um ACK.</li>' +
    '<li><b>Escuta de portadora:</b> física (o receptor detecta sinal no canal) e virtual (o NAV, preenchido pelo campo Duration/ID dos quadros ouvidos).</li>' +
    '<li><b>Intervalos:</b> SIFS (entre um quadro e a resposta imediata), DIFS (antes de disputar o meio) e o slot (unidade do backoff). O simulador usa SIFS de 16 µs, slot de 9 µs e DIFS de 34 µs, valores do OFDM em 5 GHz, em todos os cenários.</li>' +
    '<li><b>Backoff exponencial:</b> o sorteio vai de 0 a CW; a janela começa em 15, dobra a cada falha (31, 63, ...) até 1023 e volta ao mínimo após um sucesso. O contador só desce enquanto o meio está livre e congela quando outro transmite.</li>' +
    '<li><b>Limite de repetições:</b> há um número máximo de tentativas por quadro (por padrão, 7 para quadros curtos e 4 para quadros longos, com RTS), depois do qual ele é descartado.</li>' +
    '<li><b>RTS/CTS:</b> reserva o meio antes dos dados, por meio do Duration/ID. Resolve em parte o nó oculto, ao custo de dois quadros a mais. Costuma ser usado só acima de um limiar de tamanho (o simulador o liga ou desliga por cenário).</li>' +
    '<li><b>Duplicatas:</b> o receptor descarta um quadro com o mesmo número de sequência e o bit Retry ligado, mas o confirma de novo.</li></ul>',
  '<h3>Roaming e mobilidade</h3><ul>' +
    '<li>É o <b>cliente</b> que decide trocar de AP. O limiar de sinal é uma escolha do driver (o simulador usa -75 dBm como exemplo).</li>' +
    '<li><b>Reassociation Request:</b> leva o endereço do AP anterior (Current AP Address). O AP novo avisa o antigo pelo DS; o mecanismo depende do fabricante, pois a prática recomendada IEEE 802.11F foi retirada.</li>' +
    '<li><b>IEEE 802.11r (Fast BSS Transition):</b> troca o handshake de quatro vias por uma derivação de chaves embutida na autenticação e reassociação.</li>' +
    '<li><b>IEEE 802.11k e 802.11v:</b> o 802.11k fornece ao cliente a lista de vizinhos (Neighbor Report); o 802.11v permite ao AP sugerir a troca (BSS Transition Management).</li>' +
    '<li>O AP novo anuncia o MAC do cliente à rede cabeada para o switch atualizar a tabela (veja o simulador de Switching).</li></ul>',
  '<h3>Economia de energia</h3><ul>' +
    '<li>O cliente avisa com o bit <b>Power Management</b> (PM=1) num quadro Null e passa a dormir. O AP guarda os quadros dele.</li>' +
    '<li>O <b>TIM</b> (Traffic Indication Map) do beacon indica por AID quem tem quadros guardados. O <b>DTIM</b> é um TIM especial, a cada vários beacons, depois do qual o AP envia os quadros multicast e broadcast guardados.</li>' +
    '<li>O cliente pede o quadro com um <b>PS-Poll</b>, e o bit <b>More Data</b> indica se há mais. O <b>Listen Interval</b>, informado na associação, é de quantos em quantos beacons o cliente acorda.</li>' +
    '<li>Existem mecanismos mais modernos (U-APSD, e o Target Wake Time do 802.11ax) que o simulador não representa.</li></ul>',
  '<h3>Canais em 2,4 GHz</h3><p>Os canais 1 a 13 têm centros espaçados de 5 MHz a partir de 2412 MHz (centro = 2407 + 5 x n MHz). Com 20 MHz de largura, só canais a 25 MHz ou mais um do outro (1, 6 e 11) não se sobrepõem. A faixa de 5 GHz e a de 6 GHz têm muito mais canais independentes. Os canais e as potências permitidos dependem do país e da regulamentação local, e o simulador não os trata.</p>',
  '<h3>Riscos e defesas (nível defensivo)</h3><table class="sc-msgs"><thead><tr><th>Risco</th><th>Efeito</th><th>Defesa</th></tr></thead><tbody>' +
    '<tr><td>SSID oculto tomado como segurança</td><td class="meaning">o nome aparece em claro nos pedidos dos clientes e a rede dá falsa sensação de proteção</td><td class="meaning">usar WPA3 ou WPA2 com 802.1X, e tratar o SSID oculto como mera preferência de exibição</td></tr>' +
    '<tr><td>Rede aberta</td><td class="meaning">qualquer um se associa e vê o tráfego em claro</td><td class="meaning">preferir redes protegidas; o Enhanced Open (OWE, RFC 8110) cifra mesmo sem senha</td></tr>' +
    '<tr><td>Quadros de gerência sem proteção</td><td class="meaning">Deauthentication e Disassociation podem ser forjados e derrubar clientes</td><td class="meaning">ativar a proteção dos quadros de gerência (IEEE 802.11w, PMF), obrigatória no WPA3</td></tr>' +
    '<tr><td>AP falso com o mesmo SSID</td><td class="meaning">o cliente pode se associar ao AP errado</td><td class="meaning">autenticação mútua (802.1X com validação do servidor, WPA3) e monitoramento de APs não autorizados</td></tr>' +
    '<tr><td>Probe Requests com os nomes das redes salvas</td><td class="meaning">revelam onde o aparelho já esteve</td><td class="meaning">sistemas modernos limitam isso e usam endereços MAC aleatórios; mantenha o recurso ativo</td></tr></tbody></table>',
  '<h3>O que o simulador simplifica</h3><ul>' +
    '<li>Um BSS por vez (ou duas redes vizinhas, no modo Canais), um fluxo por cliente e taxas fixas: 54 Mb/s nos dados e 6 Mb/s nos quadros de controle e de gerência. Sem agregação de quadros, sem fragmentação, sem QoS (EDCA) e sem camada física detalhada.</li>' +
    '<li>Os tempos usam os valores do OFDM em 5 GHz (SIFS de 16 µs, slot de 9 µs) em todos os cenários, inclusive nos de 2,4 GHz, onde o SIFS é de 10 µs. O foco são as proporções.</li>' +
    '<li>Os sorteios do backoff são fixos por cenário, para o resultado ser reproduzível. No mundo real eles são aleatórios.</li>' +
    '<li>A interferência entre canais sobrepostos é representada no caso desfavorável. A potência, a distância e os obstáculos mudam o efeito real.</li>' +
    '<li>As durações de varredura, roaming e handshake são ilustrativas e menores que as de equipamentos reais, em que a varredura e o handshake somam dezenas de milissegundos ou mais.</li>' +
    '<li>O handshake de quatro vias aparece resumido em quatro quadros EAPOL-Key, com valores ilustrativos. Sem criptografia real, sem PMF, sem SAE e sem OWE.</li>' +
    '<li>Sem Wi-Fi 6, 6E e 7 (OFDMA, MU-MIMO, TWT, múltiplos links), sem mesh, sem modo ad hoc (IBSS) e sem Wi-Fi Direct.</li>' +
    '<li>Os endereços MAC seguem a faixa de documentação (RFC 9542).</li></ul>',
].join('');
