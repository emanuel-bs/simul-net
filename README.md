# Simul-Net

Simuladores visuais de redes e protocolos seguros, da Universidade de Brasília (UnB). Cada simulador mostra, passo a passo, como um protocolo funciona, como falha e como se defende, com diagrama de sequência, captura de pacotes, campos das mensagens e explicação do experimento. Tudo roda no navegador, sem servidor.

Projeto acadêmico do curso de Engenharia de Redes de Comunicação, sob responsabilidade do Prof. Dr. Laerte Peotta de Melo. Projeto irmão: [CryptoNet Lab](https://peotta.github.io/CryptoNet/#/).

## Simuladores

| Categoria | Simulador |
| --- | --- |
| Roteamento e serviços de rede | Roteamento (OSPF e RIPv2), ARP (resolução de endereços, proxy ARP, ARP gratuito, conflito de endereço e failover), DHCP (DORA), ICMP (ping e traceroute), BGP (sessões e seleção de caminho), MPLS (LDP e L3VPN) |
| Camada de transporte e segurança | TCP e UDP (com SACK, download TCP e vídeo UDP), Ataques e defesas TCP/UDP |
| Protocolos de rede seguros | SSH (negociação, chaves, autenticação, túneis), HTTPS e TLS (handshake, certificados, HSTS e comparação HTTP x HTTPS), FTP, FTPS e SFTP (canais de controle e dados, NAT e firewall, TLS e SSH) |

Em preparação: DNS e DNSSEC, VPN (IPsec e WireGuard), SMTP e segurança de e-mail, IS-IS, SNMP, HTTP/1.1, 2 e 3, controle de congestionamento (Reno, CUBIC e BBR), 802.1X e RADIUS.

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

A arquitetura, o contrato do motor de simulação, o modelo misto (simuladores nativos em React e TypeScript e simuladores legados em HTML) e os testes estão em [docs/arquitetura.md](docs/arquitetura.md).

## Licença

Este projeto está sob a licença MIT. Consulte o arquivo [LICENSE](LICENSE).
