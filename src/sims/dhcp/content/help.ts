// Ajuda dos campos do DHCP (textos portados do simulador legado).
import type { ControlHelp } from '../../../sim-core/ui';

export const help: Record<string, ControlHelp> = {
  servers: { t: "Servidores DHCP", s: "Quantos servidores respondem na rede.", p: ["<b>1 servidor:</b> só o DHCP-1 (192.168.10.1), com o pool 192.168.10.100 a .150.","<b>2 servidores:</b> o DHCP-2 (192.168.10.2, pool .200 a .250) também responde ao DISCOVER, e o cliente escolhe uma das ofertas.","Mudar este valor reinicia a simulação."] },
  lease: { t: "Tempo de lease", s: "Duração do empréstimo do endereço (opção 51).", p: ["O servidor empresta o endereço por este prazo. Na metade (<b>T1</b>, opção 58), o cliente tenta renovar com o mesmo servidor; a 87,5% (<b>T2</b>, opção 59), com qualquer servidor.","Vale para as próximas concessões.","Leases curtos devolvem endereços ao pool mais rápido, ao custo de mais renovações."] },
  conflict: { t: "Simular conflito de IP", s: "O PC-B passa a usar o primeiro endereço concedido.", p: ["O PC-B, com IP estático, responde ao ARP Probe do cliente como se já usasse o endereço recebido.","O cliente detecta o conflito, envia DHCPDECLINE ao servidor e recomeça a negociação.","Vale para a próxima concessão."] },
};
