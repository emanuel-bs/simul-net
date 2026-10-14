# Simul-Net

Simuladores visuais de redes e protocolos seguros, da Universidade de Brasília (UnB). Cada simulador mostra, passo a passo, como um protocolo funciona, como falha e como se defende, com diagrama de sequência, captura de pacotes, campos das mensagens e explicação do experimento. Tudo roda no navegador, sem servidor.

Projeto acadêmico do curso de Engenharia de Redes de Comunicação, sob responsabilidade do Prof. Dr. Laerte Peotta de Melo. Projeto irmão: [CryptoNet Lab](https://peotta.github.io/CryptoNet/#/).

## Simuladores

| Categoria | Simulador |
| --- | --- |
| Roteamento e serviços de rede | Roteamento (OSPF e RIPv2), DHCP (DORA), ICMP (ping e traceroute), BGP (sessões e seleção de caminho), MPLS (LDP e L3VPN) |
| Camada de transporte e segurança | TCP e UDP (com SACK, download TCP e vídeo UDP), Ataques e defesas TCP/UDP |
| Protocolos de rede seguros | SSH (negociação, chaves, autenticação, túneis), HTTPS e TLS (handshake, certificados, HSTS e comparação HTTP x HTTPS), FTP, FTPS e SFTP (canais de controle e dados, NAT e firewall, TLS e SSH) |

Em preparação: DNS e DNSSEC, VPN (IPsec e WireGuard).

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
```

Os testes verificam a integridade do registro de simuladores (arquivos existentes, identificadores, categorias, pontuação), os requisitos de cada página legada (título, descrição, canônica, crédito, volta ao Simul-Net) e a acessibilidade da interface (axe-core).

## Build e publicação

```bash
npm run build        # gera a pasta dist/
npm run preview      # serve dist/ localmente
```

O caminho base vem da variável `VITE_BASE` (padrão `/`). O roteamento usa `HashRouter`, então recarregar qualquer página funciona em hospedagem estática.

Para publicar no GitHub Pages: em *Settings > Pages*, escolha *Source: GitHub Actions* e envie o código para a branch `main`. O fluxo [.github/workflows/deploy.yml](.github/workflows/deploy.yml) executa os testes, gera o build com `VITE_BASE=/<nome-do-repositório>/` e publica em `https://peotta.github.io/Simul-Net/`.

## Documentação

A arquitetura, o contrato do motor de simulação e o plano de migração dos simuladores legados para componentes nativos estão em [docs/arquitetura.md](docs/arquitetura.md).

## Licença

Este projeto está sob a licença MIT. Consulte o arquivo [LICENSE](LICENSE).
