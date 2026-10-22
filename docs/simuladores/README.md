# Documentação dos simuladores

Lista dos simuladores do Simul-Net por categoria. A fonte única é `src/sims/registry.ts`.

## Camada de enlace e redes locais

Switching, VLANs, spanning tree e Wi-Fi: como os quadros são encaminhados, como a rede local evita laços e como as redes sem fio operam.

| Simulador | Motor | Situação | RFCs e padrões |
| --- | --- | --- | --- |
| Switching e aprendizado de MAC | - | planejado | IEEE 802.1D, IEEE 802.3 |
| STP, RSTP e MSTP | - | planejado | IEEE 802.1D, IEEE 802.1w, IEEE 802.1s |
| VLAN e trunking (802.1Q) | - | planejado | IEEE 802.1Q |
| Wi-Fi: operação (802.11) | - | planejado | IEEE 802.11 |

## Roteamento e serviços de rede

Roteamento, endereçamento automático, diagnóstico e redes de operadora, em diagramas de sequência e topologias animadas.

| Simulador | Motor | Situação | RFCs e padrões |
| --- | --- | --- | --- |
| [Roteamento (OSPF e RIPv2)](roteamento.md) | legado | disponível | RFC 2328, RFC 2453 |
| [DHCP (DORA)](dhcp.md) | nativo | disponível | RFC 2131, RFC 2132, RFC 5227 |
| [ICMP (ping e traceroute)](icmp.md) | nativo | disponível | RFC 792, RFC 1191, RFC 1812, RFC 2923 |
| [BGP (sessões e seleção de caminho)](bgp.md) | legado | disponível | RFC 4271, RFC 6811 |
| [MPLS (LDP e L3VPN)](mpls.md) | legado | disponível | RFC 3031, RFC 5036, RFC 4364 |
| IS-IS | - | planejado | RFC 1195, ISO/IEC 10589 |
| SNMP | - | planejado | RFC 3411, RFC 3416, RFC 3414 |
| NTP (sincronização de tempo) | - | planejado | RFC 5905, RFC 8915, RFC 5906 |
| [ARP](arp.md) | nativo | disponível | RFC 826, RFC 1027, RFC 1122, RFC 5227 |
| [NAT (SNAT, DNAT e NAPT)](nat.md) | nativo | disponível | RFC 2663, RFC 3022, RFC 4787, RFC 5382, RFC 5508, RFC 6598, RFC 6888 |

## Camada de transporte e segurança

TCP e UDP passo a passo e o laboratório defensivo com ataques, mitigações e resposta a incidentes.

| Simulador | Motor | Situação | RFCs e padrões |
| --- | --- | --- | --- |
| [TCP e UDP](tcp-udp.md) | legado | disponível | RFC 9293, RFC 768, RFC 5681, RFC 2018 |
| [Ataques e defesas TCP/UDP](ataques-tcp-udp.md) | legado | disponível | RFC 4987, BCP 38 |
| [HTTP/1.1, HTTP/2 e HTTP/3](http-versoes.md) | nativo | disponível | RFC 9110, RFC 9112, RFC 9113, RFC 9114, RFC 9000 |
| Controle de congestionamento (Reno, CUBIC e BBR) | - | planejado | RFC 5681, RFC 9438, RFC 6582 |

## Protocolos de rede seguros

SSH, HTTPS e transferência de arquivos por dentro: negociação, troca de chaves, autenticação, certificados e hardening.

| Simulador | Motor | Situação | RFCs e padrões |
| --- | --- | --- | --- |
| [SSH](ssh.md) | nativo | disponível | RFC 4253, RFC 4252, RFC 4254, RFC 8709 |
| [HTTPS e TLS](https.md) | nativo | disponível | RFC 8446, RFC 5246, RFC 6797, RFC 5280 |
| [FTP, FTPS e SFTP](ftp.md) | nativo | disponível | RFC 959, RFC 4217, RFC 2428, RFC 4253 |
| [DNS e DNSSEC](dns.md) | nativo | disponível | RFC 1034, RFC 4033, RFC 4035, RFC 7858, RFC 8484 |
| VPN (IPsec e WireGuard) | - | planejado | RFC 7296, RFC 4303 |
| SMTP e segurança de e-mail | - | planejado | RFC 5321, RFC 3207, RFC 7208, RFC 6376, RFC 7489 |
| Wi-Fi: segurança (WPA2 e WPA3) | - | planejado | IEEE 802.11i, IEEE 802.11w, IEEE 802.1X, RFC 3748 |
| 802.1X e RADIUS (EAP) | - | planejado | RFC 3748, RFC 2865, IEEE 802.1X |


---

*Simulador desenvolvido pelo Prof. Dr. Laerte Peotta de Melo. Conteúdo elaborado com apoio de IA generativa, sob revisão do autor. Uso exclusivo para fins de ensino e pesquisa.*
