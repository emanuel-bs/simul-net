# Arquitetura do Simul-Net

## 1. Objetivo

O Simul-Net reúne simuladores visuais de redes e protocolos seguros em um único projeto, com registro central, testes automatizados e publicação própria. Ele substitui a organização anterior, em que cada simulador era um arquivo HTML independente, com CSS e JavaScript duplicados.

## 2. Estrutura de pastas

```text
Simul-Net/
  public/
    sims/                 simuladores legados (HTML autônomo, um arquivo por simulador)
    favicon.svg
  src/
    sims/registry.ts      registro de categorias e simuladores (fonte única)
    pages/                Home, Category, SimPage, NotFound
    components/           SimCard
    layouts/              AppLayout (cabeçalho, navegação, tema, rodapé de crédito)
    hooks/                useTheme
  tests/                  registro, páginas legadas e acessibilidade da interface
  docs/                   esta documentação
  .github/workflows/      testes e publicação no GitHub Pages
```

## 3. Registro de simuladores

`src/sims/registry.ts` é a única fonte de verdade. A página inicial, as categorias, os links de navegação e os testes leem dele. Cada entrada tem identificador (kebab-case), categoria, título, resumo, tópicos, especificações (RFCs), situação (`available` ou `planned`) e, quando disponível, o motor (`legado` ou `nativo`) e o arquivo.

## 4. Simuladores legados e nativos

- **Legado:** página autônoma em `public/sims/`, incorporada por `iframe` na rota `/sim/:id` e acessível em tela cheia. É o estado atual de todos os simuladores. Cada página mantém título, descrição, URL canônica, tags de compartilhamento e o rodapé de crédito padrão. O link de volta usa `target="_top"` para funcionar dentro e fora do `iframe`.
- **Nativo:** componente React com motor de simulação separado da interface e testado. É o destino da migração.

## 5. Contrato do motor de simulação

O núcleo comum já existe, em forma experimental, nos simuladores de SSH e HTTPS (objeto `SecureSim`, em `sources/protocolos/core.js`; as páginas são geradas por `npm run build:sims`). O contrato a ser extraído para `src/sim-core/`:

1. **Motor puro:** uma função `build(parâmetros, modo)` devolve um *trace* e não toca na tela. O mesmo parâmetro e a mesma semente produzem o mesmo trace.
2. **Trace:** colunas (atores), mensagens (origem, destino, instantes de envio e chegada, rótulo, campos, se vai cifrada), eventos anotados por ator, estados por ator, fases, marcos e métricas. O núcleo converte os tempos em linhas, de modo que o diagrama é compacto e a animação tem ritmo constante.
3. **Módulo de simulador:** declara controles do painel, cenários, documentação de cada cenário, abas extras, texto do Experimento e Referência. O núcleo cuida do diagrama, da captura, do detalhe da mensagem, do log, do estado e da reprodução (Simular, Passo, velocidade).
4. **Padrão visual e didático:** abas Cenário, Captura, Mensagem, abas próprias, Experimento, Referência e Log; ajuda em cada campo; uma informação em um único lugar.

## 6. Plano de migração

| Fase | Entrega | Verificação |
| --- | --- | --- |
| 1 | Hub com registro e simuladores legados incorporados (concluída: 10 simuladores, ponta a ponta no fluxo de publicação) | testes do registro e acessibilidade da interface |
| 2 | (próxima) Extração do núcleo (`src/sim-core`) a partir do `SecureSim` e migração do SSH e HTTPS para módulos TypeScript | testes unitários dos motores e comparação de saída com a versão legada |
| 3 | Migração de TCP e UDP e do laboratório de ataques e defesas | comparação de saída por cenário (mesma semente, mesmos resultados) |
| 4 | Migração de roteamento, DHCP, ICMP, BGP e MPLS | idem |
| 5 | Novos simuladores já nativos (DNS e DNSSEC, VPN) | testes do motor desde o início |

Em cada migração, o simulador legado só é removido depois de a versão nativa reproduzir os resultados de todos os cenários.

## 7. Testes

- **Registro:** identificadores únicos, categorias válidas, arquivos existentes, ausência de travessão longo e de meia-risca.
- **Páginas legadas:** título, descrição, canônica, crédito e link de volta ao Simul-Net.
- **Interface:** páginas inicial, de categoria e de simulador, com verificação de acessibilidade (axe-core).
- **Ponta a ponta (Playwright, em `e2e/`):** todos os cenários de cada simulador sem erro de JavaScript, layout da bancada e quadros destacáveis, e o hub. Roda no fluxo de publicação.
- **A criar:** testes unitários dos motores nativos.

## 8. Publicação

O fluxo `.github/workflows/deploy.yml` roda `npm ci`, `npm test` e `npm run build` com `VITE_BASE=/<repositório>/` e publica `dist/` no GitHub Pages. Endereço previsto: `https://peotta.github.io/Simul-Net/`.

## 9. Relação com o portal (peotta.github.io)

O portal continua com suas páginas de simuladores até o Simul-Net estar publicado. Depois disso, a seção "Simuladores de Rede e Protocolos" do portal passa a apontar para o Simul-Net e as páginas antigas viram redirecionamentos, para não quebrar links existentes.

## 10. Como adicionar um simulador

1. Coloque o arquivo em `public/sims/` (legado) ou crie o componente em `src/sims/<nome>/` (nativo).
2. Acrescente a entrada em `src/sims/registry.ts`.
3. Rode `npm test`: o registro verifica o arquivo e os requisitos da página.

## 11. Limitações

Os simuladores são didáticos: parâmetros pequenos, valores ilustrativos e nenhuma criptografia real. Os modelos seguem as RFCs citadas em cada página, mas simplificam detalhes que são explicitados na aba Referência de cada simulador.
