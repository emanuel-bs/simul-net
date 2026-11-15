# Arquitetura do Simul-Net

## 1. Objetivo

O Simul-Net reúne simuladores visuais de redes e protocolos seguros em um único projeto, com registro central, testes automatizados e publicação própria.

## 2. Estrutura de pastas

```text
Simul-Net/
  public/
    favicon.svg
  src/
    sim-core/             núcleo dos simuladores nativos: trace, valores determinísticos e, em ui/, a bancada React
    sims/registry.ts      registro de categorias e simuladores (fonte única)
    sims/native.ts        mapa dos módulos nativos (carregados sob demanda)
    sims/ssh, https, ftp  motor (engine) e conteúdo (content) de cada simulador nativo
    pages/                Home, Category, SimPage, NativeSim, NotFound
    components/           SimCard
    layouts/              AppLayout (cabeçalho, navegação, tema, rodapé de crédito)
    docs/                 página de documentação: leitor de Markdown (DocView), diagramas (Mermaid) e âncoras
    hooks/                useTheme
  tests/                  registro, interface, núcleo, motores, integridade e impressões digitais dos módulos
  e2e/                    testes ponta a ponta (Playwright)
  docs/                   esta documentação
  .github/workflows/      testes e publicação no GitHub Pages
```

## 3. Registro de simuladores

`src/sims/registry.ts` é a única fonte de verdade. A página inicial, as categorias, os links de navegação e os testes leem dele. Cada entrada tem identificador (kebab-case), categoria, título, resumo, tópicos, especificações (RFCs), situação (`available` ou `planned`) e, quando disponível, o motor (`nativo`).

## 4. Simuladores nativos

- **Simulador nativo:** componente React com motor de simulação separado da interface e testado, na rota `/sim/:id`. SSH, HTTPS e TLS, FTP, FTPS e SFTP, ARP, IPv4, IPv6, ICMP, DHCP, NAT, DNS e DNSSEC e as versões do HTTP (HTTP/1.1, HTTP/2 e HTTP/3), o Firewall, o Switching, o STP, RSTP e MSTP, o VLAN e trunking (802.1Q), o 802.1X e RADIUS (EAP), o Wi-Fi (802.11), o MPLS (LDP e L3VPN), o OSPF, o RIP, o BGP, o TCP, o UDP, os ataques e defesas TCP/UDP, o controle de congestionamento (Reno, NewReno, CUBIC e BBR) e o modelo OSI (jornada de um quadro) estão disponíveis. Seguem o padrão visual e didático dos demais (abas, ajuda nos campos, rodapé de crédito) e têm a bancada de trabalho: tela única, frames que destacam, movem, redimensionam, maximizam e recolhem, zoom do diagrama e alça de altura das abas.
- **Motor compartilhado por mais de um simulador:** quando dois simuladores usam as mesmas regras, o motor e os textos ficam em uma pasta `-base` (`roteamento-base` para OSPF e RIP, `transporte-base` para TCP e UDP). Cada simulador declara só os seus modos: em `transporte-base/derive.ts`, a função `derive(subs, override)` seleciona controles, cenários, grupos, documentação e abas dos modos pedidos e permite trocar o texto de cenários que mudam de foco (a comparação TCP x UDP tem um texto em cada simulador).
- **Por que o motor nativo:** o motor é uma função pura (os mesmos parâmetros produzem o mesmo `Trace`), separada da interface, o que permite testar cada regra, fixar o comportamento por impressões digitais e reutilizar a bancada de trabalho (diagrama, captura, mensagem, estados, abas, log).
- **Execução por ciclos e interatividade:** simuladores que antes eram animações contínuas (o TCP, o UDP e os ataques e defesas) rodam hoje a simulação inteira de uma vez e a reproduzem no diagrama. Parâmetros que o aluno antes mudava durante a animação viraram controles: por exemplo, a mitigação upstream é escolhida como "ativa desde o início" ou "acionada depois do ciclo N".

## 5. Contrato do motor de simulação

O núcleo está em `src/sim-core/` (`trace.ts`, `hash.ts`, `types.ts`) e a bancada em `src/sim-core/ui/`. O contrato:

1. **Motor puro:** uma função `build(parâmetros, modo)` devolve um *trace* e não toca na tela. O mesmo parâmetro produz o mesmo trace (valores como chaves e hashes são determinísticos e ilustrativos).
2. **Trace:** colunas (atores), mensagens (origem, destino, instantes de envio e chegada, rótulo, campos, se vai cifrada), eventos anotados por ator, estados por ator, fases, marcos e métricas. `prepare()` converte os tempos em linhas, de modo que o diagrama é compacto e a animação tem ritmo constante.
3. **Módulo de simulador (`ProtocolDef`, em `src/sim-core/ui/module.ts`):** declara controles do painel, cenários, documentação de cada cenário, abas extras, texto do Experimento e Referência. A bancada (`Workbench`) cuida do diagrama, da captura, do detalhe da mensagem, do log, do estado e da reprodução (Simular, Passo, velocidade).
3a. **Topologia (opcional):** o módulo pode declarar `topology` (nós, enlaces, caminho de cada mensagem e notas sob cada nó, como a tabela ARP). A bancada então mostra um seletor "Sequência / Topologia" no painel principal, e os pacotes percorrem os enlaces com o mesmo relógio, o mesmo Passo e o mesmo zoom. Usado pelo ARP, pelo ICMP, pelo DHCP, pelo HTTP, pelo NAT, pelo DNS e pelo Firewall. O módulo também pode configurar a legenda de cores (`legend`) e a formatação do tempo (`timeLabel`), por exemplo para mostrar horas num ciclo de lease.
3b. **Palco próprio (opcional):** o módulo pode declarar `stage`, uma função pura `(trace, relógio) => HTML` que substitui o diagrama de sequência e a topologia. A bancada só desenha o resultado e mantém Simular, Passo, velocidade, zoom (Zoom -, Ajustada e Zoom +, pela variável CSS `--zoom`) e os painéis. Os demais simuladores não são afetados. Usado só pelo modelo OSI, que anima as pilhas de camadas e o encapsulamento da PDU em `src/sims/osi/stage.ts`, interpolando a posição entre quadros-chave derivados dos passos e das mensagens do trace. Com palco próprio, o botão Passo não salta: o relógio desliza até o próximo passo (`usePlayer`, parâmetro `smooth`), exceto com movimento reduzido, e cada camada de cada nó é um passo próprio (o switch passa por 1, 2 e 1; o roteador, por 1, 2, 3, 2 e 1).
3c. **Fundamentação (opcional):** o módulo pode declarar `fundamentacao`, um texto em Markdown (com diagramas Mermaid e tabelas) usado só na documentação gerada: o gerador o insere como a seção "Fundamentação", logo depois de "Modos", e numera as subseções. Usado pelo modelo OSI, para explicar o diagrama das sete camadas (`src/sims/osi/content/fundamentacao.ts`). O texto passa pelo teste de ausência de travessão.
3d. **Gráfico de cenário (opcional):** o módulo pode declarar `docChart`, uma função `(cenário) => Markdown` que devolve um gráfico (bloco Mermaid `xychart-beta`, montado por `src/sim-core/doc-chart.ts`) calculado pelo próprio motor. O gerador o insere depois de "O que observar", na documentação e na wiki; o site desenha a legenda dentro da figura, e o Markdown mantém a linha "Legenda:" em texto. Quando o cenário não tem curva, devolve texto vazio e nada é inserido. Usado por TCP, HTTP e RIP; os testes estão em `tests/sim-core/doc-chart.test.ts`.
4. **Padrão visual e didático:** abas Cenário, Captura, Mensagem, abas próprias, Experimento, Referência e Log; ajuda em cada campo; uma informação em um único lugar.
5. **Estilo:** `src/sim-core/ui/simnet.css`, com todos os seletores restritos a `.simnet`, para não interferir no hub (Tailwind).

## 6. Plano de evolução

| Fase | Entrega | Situação |
| --- | --- | --- |
| 1 | Hub com registro, categorias e cartões | concluída |
| 2 | Núcleo (`src/sim-core`) e bancada React | concluída |
| 3 | Simuladores de enlace, rede, transporte e protocolos seguros sobre o núcleo (DNS e DNSSEC, ARP, HTTP, 802.1X, Wi-Fi, MPLS, OSPF, RIP, BGP, IPv4, IPv6, TCP, UDP, ataques e defesas TCP/UDP e os demais já listados no registro) | concluída |
| 4 | Novos simuladores (VPN, SMTP, IS-IS, SNMP; o controle de congestionamento já está disponível) | prevista; usam o núcleo e a bancada desde o início |

## 7. Testes

- **Registro:** identificadores únicos, categorias válidas, documento de cada simulador existente, todos os simuladores disponíveis com motor nativo, ausência de travessão longo e de meia-risca.
- **Interface:** páginas inicial, de categoria e de simulador, com verificação de acessibilidade (axe-core).
- **Página de documentação (`doc-ui.test.tsx`):** leitura dos documentos, índice lateral, âncoras, links, diagramas (o Mermaid é simulado no jsdom), página 404 e axe-core.
- **Núcleo e bancada (`tests/sim-core/`):** valores determinísticos e trace (`core.test.ts`); geometria do diagrama, reprodução e cenários (`ui-logic.test.ts`); e a bancada completa com um protocolo de exemplo, incluindo destacar, maximizar, recolher, Esc, zoom, a alça de altura e a alternância entre sequência e topologia, com axe-core em todas as abas (`workbench.test.tsx`).
- **Motores (`ssh-engine`, `https-engine`, `ftp-engine`, `http-engine`, `osi-engine`, `transporte-engine`, `ipv4-engine`, `ipv6-engine`):** regras específicas de cada protocolo (negociação, downgrade, adulteração, política de encaminhamento, modos ativo e passivo, certificado inválido, RTT de abertura, bloqueio de cabeça de fila e fallback do QUIC; CRC-32 e checksum do IP, passos por camada e palco do OSI; aritmética de endereços, prefixo mais específico, TTL, uRPF e decisão do host no IPv4).
- **Passo a passo suave (`player-step.test.tsx`):** com palco próprio, o botão Passo desliza o relógio até o destino, e Voltar ao início e Simular cancelam o deslize.
- **Integridade (`protocol-integrity.test.ts`):** vale para qualquer módulo registrado em `src/sims/native.ts`: ids únicos, parâmetros dos cenários existentes e com valores permitidos, documentação completa de cada cenário e modo, e ausência de travessão nos textos.
- **Conformidade normativa (`tests/conformidade/`):** testes independentes das impressões digitais, escritos a partir do texto das RFCs (um arquivo por simulador). Cada teste cita a RFC e a seção, foi escrito antes da correção e falhava com o comportamento incorreto. Cobrem, por exemplo, o Identifier do RADIUS, o campo Window e o Window Scale do TCP, o ClientHello por versão do TLS, o TTL do RRSIG e a topologia de NAT do proxy transparente. Ao corrigir um erro de protocolo, acrescente primeiro o teste que o reproduz.
- **Navegação e falhas da bancada:** `tests/navegacao-simuladores.test.tsx` e `e2e/navegacao.spec.ts` (troca direta de um simulador para outro, link da aba Referência e voltar no histórico) e `tests/erro-bancada.test.tsx` (a falha de um simulador não derruba o site).
- **Impressões digitais (`golden.test.ts` e `golden.json`):** hash SHA-256 do trace, do Experimento, do texto do cenário e das abas de cada cenário, e de 300 combinações aleatórias por modo (semente fixa). Qualquer mudança de comportamento falha o teste. Quando a mudança é intencional: `UPDATE_GOLDEN=1 npx vitest run tests/sim-core/golden.test.ts`, e revisar o diff de `golden.json` antes de versionar.
- **Páginas nativas (`tests/native-page.test.tsx`):** cada simulador nativo carrega, percorre todos os modos e passa no axe-core.
- **Contraste (Playwright, `e2e/contraste.spec.ts`):** o axe mede o contraste de cores (WCAG AA) no Chrome real, o que não funciona no jsdom: páginas do hub nos temas claro e escuro, e cada simulador nativo em todos os modos, numa amostra dos cenários e em todas as abas.
- **Ponta a ponta (Playwright, em `e2e/`):** todos os cenários de cada simulador sem erro de JavaScript, layout da bancada, painéis destacáveis e o hub. Roda no fluxo de publicação.

## 8. Publicação

O fluxo `.github/workflows/deploy.yml` roda `npm ci`, `npm test`, `npm run build` com `VITE_BASE=/<repositório>/`, os testes ponta a ponta e publica `dist/` no GitHub Pages. Endereço previsto: `https://peotta.github.io/Simul-Net/`.

## 9. Relação com o portal (peotta.github.io)

O portal continua com suas páginas de simuladores até o Simul-Net estar publicado. Depois disso, a seção "Simuladores de Rede e Protocolos" do portal passa a apontar para o Simul-Net e as páginas antigas viram redirecionamentos, para não quebrar links existentes.

## 10. Como adicionar um simulador

1. **Levante as fontes antes de escrever.** Liste as RFCs e os padrões vigentes do protocolo em https://www.rfc-editor.org e confira se algum foi substituído ou atualizado (por exemplo, a RFC 8446 foi substituída pela RFC 9846). Anote o que o simulador vai simplificar em relação a elas.
2. Crie `src/sims/<nome>/` (ou reutilize uma pasta `-base` já existente, se o motor for o mesmo de outro simulador) com o motor (`engine`, função pura que devolve um `Trace`), o conteúdo (`content`: controles, cenários, textos, abas, Experimento e Referência) e `protocol.ts`, que exporta um `ProtocolDef`. Cada cenário precisa de `scenDoc` completo (conceito, o que observar, mensagens, por que importa), cada campo precisa de ajuda e a aba Referência precisa citar a RFC e a seção nos pontos técnicos e registrar as limitações. Declare `topology` quando houver topologia.
3. Registre o módulo em `src/sims/native.ts` e acrescente a entrada em `src/sims/registry.ts` com `engine: 'nativo'`, preenchendo `rfcs`. O mesmo vale para `rfcs` no `protocol.ts`.
4. Inclua o módulo em `tests/sim-core/golden.test.ts`, grave as impressões digitais com `UPDATE_GOLDEN=1`, e rode `npm test` (integridade, páginas e registro são verificados) e `npm run test:e2e`.
5. **Documentação.** Rode `npm run docs:simuladores`. Isso gera `docs/simuladores/<id>.md` e atualiza o índice. Confira o arquivo (travessões, diagramas, textos) e versione-o junto com o simulador. O gerador transforma toda citação de RFC (e de BCP) em link para o rfc-editor.org; IEEE e ISO ficam em texto. O texto dos cenários dentro do simulador pode citar a RFC sem link. O teste do registro falha se o documento não existir ou se houver uma RFC sem link.
6. **Wiki.** Rode `npm run wiki -- <pasta>`, clone `Simul-Net.wiki.git`, copie os `.md` gerados, faça o commit e o push. Como a wiki é pública, a publicação só é feita com autorização expressa do autor.
7. **Link no cartão.** Nada a fazer: o cartão do hub mostra o link "Documentação" a partir do `id` do registro (`docUrl`).

## 11. Convenção de tamanhos (campo `len`)

O campo `len` de uma mensagem do trace é o tamanho, em bytes, do quadro ou da PDU mostrada, conforme a camada:

| Camada ou protocolo | O que `len` mede |
|---|---|
| Quadros sobre Ethernet (ARP, IPv4, IPv6, ICMP, TCP, UDP, STP, OSPF, FTP, NAT e outros) | do cabeçalho Ethernet até o último byte do payload, **sem FCS e sem padding**, como numa captura do Wireshark. Cabeçalhos sem opções, salvo quando o simulador mostra as opções. Exemplos: ARP 42, TCP de controle sem opções 54, BPDU 52, quadro de 1500 bytes de MTU 1514 |
| Wi-Fi (IEEE 802.11) | o quadro 802.11 inteiro, **com** o FCS de 4 bytes (ACK 14, RTS 20, PS-Poll 20) |
| Mensagens de protocolos sobre TCP (BGP, LDP, EAP) | o tamanho da própria mensagem do protocolo, sem os cabeçalhos de baixo |
| Congestionamento | rodadas de bytes enviados; não é tamanho de quadro |

Quando um simulador desvia desta convenção, a aba Referência dele deve dizer. Desvios conhecidos, ainda não padronizados: o OSPF Hello (78 bytes) não conta os vizinhos listados; os registros TLS cifrados do FTP/SFTP e do SSH usam tamanhos ilustrativos. Qualquer mudança de convenção deve ser acompanhada do teste em `tests/conformidade/tamanhos.test.ts`.

## 12. Limitações

Os simuladores são didáticos: parâmetros pequenos, valores ilustrativos e nenhuma criptografia real. Os modelos seguem as RFCs citadas em cada página, mas simplificam detalhes que são explicitados na aba Referência de cada simulador.

## 13. Pendências conhecidas

Itens da auditoria de conformidade (NC-01 a NC-33) que não foram encerrados. Cada um diz o que falta e por que ainda está aberto.

### NC-04 (P2): oráculo de teste dependente da implementação

- **Situação:** atendida só em parte. O golden (`tests/sim-core/golden.json`) compara o trace com o hash gravado pelo próprio motor, então não prova conformidade. A correção prevista, os testes de `tests/conformidade/`, existe para 802-1x, arp, bgp, dhcp, dns, http, https, ipv4, ipv6, mpls, nat, ssh e tcp (mais `tamanhos`).
- **Falta:** arquivo de conformidade para os demais simuladores nativos, entre eles wifi, rip, stp, vlan, switching, tls e ftp.
- **Como fechar:** para cada simulador, escrever os testes a partir do texto da RFC (citando a seção), vê-los falhar com o comportamento incorreto, e só então corrigir (ver seção 7).

### NC-32 (P3): Wi-Fi, Address 3 e temporizações de 5 GHz

- **Situação:** aberta. Depende do texto do IEEE 802.11, que não é público e não foi consultado, então não foi corrigida nem testada.
- **Address 3 (`src/sims/wifi/engine.ts`, quadros de dados nas linhas 363, 587 e 692):** em quadros com To DS=1 o campo recebe o endereço de broadcast. O rótulo do campo (`model.ts`, "BSSID ou destino final, conforme To DS e From DS") exige que o valor corresponda ao destino final nesses quadros. Na linha 750 (From DS=1) o campo recebe o endereço do AP, quando deveria ser o originador (SA). A tabela de endereços por To DS e From DS do padrão precisa ser conferida.
- **Temporizações (`src/sims/wifi/model.ts`):** SLOT 9 µs, SIFS 16 µs e DIFS 34 µs são valores OFDM de 5 GHz, mas os cenários usam os canais 1, 6 e 11 (2,4 GHz), onde o SIFS é de 10 µs. Os valores corretos por faixa e modo de transmissão também dependem do padrão.
- **Como fechar:** obter o trecho do IEEE 802.11 (tabela de endereços e parâmetros de temporização da camada física), escrever `tests/conformidade/wifi.test.ts` e então corrigir. Até lá, a aba Referência do Wi-Fi deve manter o aviso de que os valores de 5 GHz são usados em todo o simulador.
