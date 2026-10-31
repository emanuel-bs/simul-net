// Aba Referência do simulador de 802.1X e RADIUS.
export const reference: string = [
  '<h3>Para que serve</h3><p>O <b>IEEE 802.1X</b> é o controle de acesso à rede baseado em porta. A porta de um switch (ou um ponto de acesso Wi-Fi) só encaminha dados de um dispositivo depois que ele se autentica. A edição vigente é o IEEE 802.1X-2020, que incorpora as anteriores. Confira o texto oficial do IEEE antes de citar uma cláusula. A autenticação em si usa o <b>EAP</b> (Extensible Authentication Protocol, RFC 3748), e o servidor costuma falar <b>RADIUS</b> (RFC 2865).</p>',
  '<h3>Os três papéis</h3><table class="sc-msgs"><thead><tr><th>Papel</th><th>Quem é</th><th>O que faz</th></tr></thead><tbody>' +
    '<tr><td>Suplicante</td><td class="meaning">o dispositivo que quer entrar na rede</td><td class="meaning">responde ao EAP e prova a identidade</td></tr>' +
    '<tr><td>Autenticador</td><td class="meaning">o switch ou o ponto de acesso (NAS)</td><td class="meaning">mantém a porta fechada, repassa o EAP ao servidor e abre a porta conforme o resultado. Não interpreta o método EAP</td></tr>' +
    '<tr><td>Servidor de autenticação</td><td class="meaning">o servidor RADIUS</td><td class="meaning">conduz o método EAP e decide entre Accept e Reject</td></tr></tbody></table>',
  '<h3>Porta controlada e não controlada</h3><p>O autenticador expõe duas portas lógicas. A <b>não controlada</b> aceita sempre o EAPOL (EtherType 0x888E). A <b>controlada</b> só encaminha os dados depois da autorização. O simulador mostra três estados: <b>não autorizada</b>, <b>em autenticação</b> (a porta continua fechada para dados) e <b>autorizada</b>. O estado é decidido pelo autenticador, e quem o abre é o Access-Accept do servidor, não o EAP-Success enviado ao suplicante.</p>',
  '<h3>Duas camadas de transporte do EAP</h3><table class="sc-msgs"><thead><tr><th>Trecho</th><th>Transporte</th><th>Como o EAP viaja</th></tr></thead><tbody>' +
    '<tr><td>Suplicante e autenticador</td><td class="meaning">EAPOL, direto sobre Ethernet (EtherType 0x888E), sem IP</td><td class="meaning">pacote EAP-Packet dentro do quadro. Há também EAPOL-Start e EAPOL-Logoff. O endereço de grupo do PAE é 01:80:c2:00:00:03</td></tr>' +
    '<tr><td>Autenticador e servidor</td><td class="meaning">RADIUS sobre UDP, porta 1812 (RFC 2865, seção 3)</td><td class="meaning">atributo EAP-Message (79), em pedaços de até 253 bytes, junto com o Message-Authenticator (80) (RFC 3579, seções 3.1 e 3.2)</td></tr></tbody></table>',
  '<h3>O EAP</h3><ul>' +
    '<li><b>Códigos</b> (RFC 3748, seção 4): 1 Request, 2 Response, 3 Success e 4 Failure. O servidor faz pedidos, o suplicante responde, e o resultado final vem como Success ou Failure.</li>' +
    '<li><b>Success e Failure não são confirmados</b> e, por isso, podem se perder (seção 4.2). O autenticador é quem os envia.</li>' +
    '<li><b>Tipos</b> (seção 5): 1 Identity, 2 Notification, 3 Nak e 4 MD5-Challenge. Os métodos têm outros números, atribuídos pela IANA (13 para EAP-TLS e 25 para PEAP).</li>' +
    '<li>O EAP é um arcabouço de <b>métodos</b>. Para o EAP-TLS, a RFC 5216 define o método e a RFC 9190 o atualiza para o TLS 1.3. O PEAP não é um padrão da IETF.</li></ul>',
  '<h3>RADIUS e EAP no simulador</h3><ul>' +
    '<li><b>Access-Request</b> (RFC 2865, seção 4.1): leva User-Name, NAS-IP-Address, NAS-Port, NAS-Port-Type, Calling-Station-Id, o EAP-Message e o Message-Authenticator.</li>' +
    '<li><b>Access-Challenge</b> (seção 4.4): o servidor pede o próximo passo do método e devolve um <b>State</b> (seção 5.24), que o autenticador repete no próximo Access-Request.</li>' +
    '<li><b>Access-Accept</b> (seção 4.2) e <b>Access-Reject</b> (seção 4.3): o resultado. No Reject só se permitem as mensagens EAP e o Proxy-State (RFC 5080, seção 2.6.1).</li>' +
    '<li><b>Session-Timeout</b> (seção 5.27): por quanto tempo a sessão vale antes de uma nova autenticação.</li>' +
    '<li><b>Retransmissão</b> (RFC 5080, seção 2.2.1): o cliente repete o pedido com o mesmo Identifier; o intervalo e o limite de tentativas são ajustes do equipamento.</li>' +
    '<li><b>Segredo compartilhado:</b> liga o switch ao servidor e entra no cálculo do Message-Authenticator. Se o segredo difere, o servidor descarta o pacote em silêncio (RFC 3579, seção 3.2).</li></ul>',
  '<h3>Métodos EAP do simulador</h3><table class="sc-msgs"><thead><tr><th>Método</th><th>Referência</th><th>Característica</th></tr></thead><tbody>' +
    '<tr><td>EAP-MD5</td><td class="meaning">RFC 3748, seção 5.4</td><td class="meaning">desafio e resposta com a senha. Sem autenticação mútua, sem integridade, sem confidencialidade, sem derivação de chaves e sem proteção contra ataque de dicionário</td></tr>' +
    '<tr><td>PEAP com MSCHAPv2</td><td class="meaning">não é um padrão da IETF</td><td class="meaning">o servidor se autentica por certificado e abre um túnel TLS, dentro do qual o cliente prova a senha. O simulador agrupa as mensagens do túnel</td></tr>' +
    '<tr><td>EAP-TLS</td><td class="meaning">RFC 5216 e RFC 9190</td><td class="meaning">autenticação mútua por certificados. O número de rodadas depende da versão do TLS, e o simulador mostra três rodadas esquemáticas</td></tr></tbody></table>',
  '<h3>Temporizadores e valores do simulador</h3><ul>' +
    '<li>Repetição do EAP-Request/Identity: a cada 30 s, até 2 repetições. Retransmissão do RADIUS: 3 tentativas, a cada 5 s. Session-Timeout: 3600 s. São valores típicos de implementação, não exigências do padrão.</li>' +
    '<li>Depois de uma falha, muitas implementações mantêm a porta num intervalo de quarentena antes de aceitar outra tentativa. O simulador não representa esse intervalo.</li></ul>',
  '<h3>Riscos e defesas (nível defensivo)</h3><table class="sc-msgs"><thead><tr><th>Risco</th><th>Efeito</th><th>Defesa</th></tr></thead><tbody>' +
    '<tr><td>EAP-MD5</td><td class="meaning">o suplicante não confere quem está do outro lado, e a resposta ao desafio pode ser alvo de tentativas de adivinhar a senha</td><td class="meaning">usar um método com autenticação mútua e túnel, como o EAP-TLS ou o PEAP com validação do servidor</td></tr>' +
    '<tr><td>PEAP sem validar o certificado</td><td class="meaning">o túnel abre com qualquer servidor, e a credencial chega a quem o controla</td><td class="meaning">configurar a CA confiável e o nome do servidor RADIUS no suplicante e impedir a aceitação manual de certificados</td></tr>' +
    '<tr><td>Vários dispositivos na mesma porta</td><td class="meaning">a autorização vale para a porta, e quem estiver atrás dela aproveita</td><td class="meaning">uma porta para um equipamento, autorização por endereço MAC (recurso de implementação) ou MACsec (IEEE 802.1AE)</td></tr>' +
    '<tr><td>RADIUS sobre UDP</td><td class="meaning">o Message-Authenticator e o Response Authenticator usam MD5 e o segredo compartilhado, o que enfraquece a proteção do trecho entre o switch e o servidor</td><td class="meaning">segredos longos e aleatórios, Message-Authenticator em todos os pacotes, rede de gerência isolada e, quando possível, RADIUS sobre TLS (RFC 6614, experimental) ou RADIUS/1.1 (RFC 9765, experimental)</td></tr></tbody></table>',
  '<h3>O que o simulador simplifica</h3><ul>' +
    '<li>Um suplicante, um autenticador, um servidor RADIUS e uma rede. Sem proxy RADIUS, sem servidores redundantes e sem contabilização (RFC 2866).</li>' +
    '<li>Sem fragmentação do EAP-TLS: o voo do servidor, com a cadeia de certificados, ocuparia várias mensagens EAP no mundo real. Os handshakes TLS aparecem agrupados em poucas rodadas.</li>' +
    '<li>Valores de desafios, State e autenticadores são ilustrativos (determinísticos). Não há criptografia real.</li>' +
    '<li>Sem derivação nem uso de chaves (MSK e EMSK, RFC 5247) e sem MACsec. No Wi-Fi o resultado do EAP serve também para derivar as chaves da rede sem fio, que não é o foco deste simulador.</li>' +
    '<li>Sem autorização por atributos do servidor (VLAN, listas de controle de acesso), sem mudança de autorização durante a sessão e sem verificação de postura do dispositivo. Dispositivos sem suplicante exigem uma política à parte, que não é tratada.</li>' +
    '<li>A autorização por endereço MAC é um recurso das implementações, com nomes e comportamentos que variam por fabricante. O simulador mostra só a ideia.</li>' +
    '<li>Os endereços MAC seguem a faixa de documentação (RFC 9542) e os endereços IP, as redes de documentação (RFC 5737).</li></ul>',
].join('');
