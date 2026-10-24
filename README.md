# Simul-Net

Simuladores visuais de redes e protocolos seguros, da Universidade de Brasília (UnB). Cada simulador mostra, passo a passo, como um protocolo funciona, como falha e como se defende, com diagrama de sequência, captura de pacotes, campos das mensagens e explicação do experimento. Tudo roda no navegador, sem servidor.

Projeto acadêmico do curso de Engenharia de Redes de Comunicação, sob responsabilidade do Prof. Dr. Laerte Peotta de Melo. Projeto irmão: [CryptoNet Lab](https://peotta.github.io/CryptoNet/#/).

## Simuladores

| Categoria | Simulador |
| --- | --- |
| Roteamento e serviços de rede | Roteamento (OSPF e RIPv2), ARP (resolução de endereços, proxy ARP, ARP gratuito, conflito de endereço, failover e envenenamento de cache com as defesas), DHCP (DORA), ICMP (ping e traceroute), BGP (sessões e seleção de caminho), MPLS (LDP e L3VPN), NAT, Firewall (filtragem sem estado e com estado, DMZ e defesas) |
| Camada de transporte e segurança | TCP e UDP (com SACK, download TCP e vídeo UDP), Ataques e defesas TCP/UDP, HTTP/1.1, HTTP/2 e HTTP/3 (conexões, fluxos, QUIC, 0-RTT, perda de pacote e fallback) |
| Protocolos de rede seguros | SSH (negociação, chaves, autenticação, túneis), HTTPS e TLS (handshake, certificados, HSTS e comparação HTTP x HTTPS), DNS e DNSSEC (resolução, cache e TTL, cadeia de confiança, envenenamento de cache, amplificação, DoT e DoH), FTP, FTPS e SFTP (canais de controle e dados, NAT e firewall, TLS e SSH) |

Em preparação: VPN (IPsec e WireGuard), SMTP e segurança de e-mail, IS-IS, SNMP, HTTP/1.1, 2 e 3, controle de congestionamento (Reno, CUBIC e BBR), 802.1X e RADIUS.

> Os simuladores têm finalidade didática. Valores de chaves, hashes e assinaturas são ilustrativos e não oferecem segurança real.

## Desenvolvimento

Requer Node.js 20 ou superior.

```bash
npm install          # instala as dependências
npm run dev          # servidor de desenvolvimento (http://localhost:5173)
```

## Testes

```bash
npm test             # executa os testes (Vitest) uma vez
npm run test:watch   # modo contínuo
npm run typecheck    # verificação de tipos
npm run build && npm run test:e2e   # testes de ponta a ponta (veja abaixo)
```

Os testes unitários verificam a integridade do registro de simuladores (arquivos existentes, identificadores, categorias, pontuação), os requisitos de cada página legada (título, descrição, canônica, crédito, volta ao Simul-Net) e a acessibilidade da interface (axe-core).

### Testes de ponta a ponta

`npm run test:e2e` abre o site gerado (`dist/`) em um Chrome real, com o Playwright, e para **cada simulador disponível no registro** (um simulador novo entra sozinho):

- percorre todos os modos e todos os cenários prontos, clicando nos botões de ação e abrindo todas as abas, e falha se houver qualquer erro de JavaScript;
- confere que a bancada de trabalho cabe na tela (sem rolagem da página em 1366x768 e 1600x900) e que cada quadro destaca e encaixa de volta na posição original;
- mede o contraste de cores (WCAG AA) no hub, nos dois temas, e em cada simulador nativo;
- confere o hub: as categorias, a página de cada simulador com o iframe e o redirecionamento do endereço antigo.

Usa o Chrome instalado na máquina (sem baixar navegadores). No GitHub Actions o teste roda antes da publicação, com o build feito com `VITE_BASE=/Simul-Net/`; a variável `E2E_BASE` acompanha esse caminho. Se falhar, o relatório fica como artefato da execução.

## Build e publicação

```bash
npm run build        # gera a pasta dist/
npm run preview      # serve dist/ localmente
```

O caminho base vem da variável `VITE_BASE` (padrão `/`). O roteamento usa `HashRouter`, então recarregar qualquer página funciona em hospedagem estática.

Para publicar no GitHub Pages: em *Settings > Pages*, escolha *Source: GitHub Actions* e envie o código para a branch `main`. O fluxo [.github/workflows/deploy.yml](.github/workflows/deploy.yml) executa os testes, gera o build com `VITE_BASE=/<nome-do-repositório>/` e publica em `https://peotta.github.io/Simul-Net/`.

## Documentação

### Arquitetura

A arquitetura, o contrato do motor de simulação, o modelo misto (simuladores nativos em React e TypeScript e simuladores legados em HTML) e os testes estão em [docs/arquitetura.md](docs/arquitetura.md). O passo a passo para adicionar um simulador está na seção 10 desse documento.

### Documentação dos simuladores

Cada simulador disponível tem um documento em [docs/simuladores/](docs/simuladores/) (arquivo `<id>.md`, com índice em [docs/simuladores/README.md](docs/simuladores/README.md)). O documento reúne conceito, cenários, mensagens, campos, ajuda, referências e limitações, e todas as RFCs citadas têm link para o [rfc-editor.org](https://www.rfc-editor.org). Ele é gerado a partir dos próprios módulos, para não divergir do código, e o cartão de cada simulador no hub mostra o link "Documentação" automaticamente.

```bash
npm run docs:simuladores   # gera ou atualiza docs/simuladores/
```

O teste do registro falha se faltar o documento de algum simulador disponível. Versione o documento junto com o simulador.

### Wiki

A [wiki do projeto](https://github.com/peotta/Simul-Net/wiki) reúne a mesma documentação em formato de páginas navegáveis: página inicial, arquitetura, índice de simuladores, guia para contribuir e uma página por simulador. Também é gerada pelo código:

```bash
npm run wiki -- <pasta-de-saida>   # gera as páginas .md da wiki
```

Para publicar, clone `Simul-Net.wiki.git`, copie os `.md` gerados, faça o commit e o push. Como a wiki é pública, a publicação só ocorre com autorização expressa do autor.

## Licença

Este projeto está sob a licença MIT. Consulte o arquivo [LICENSE](LICENSE).
