// Controles do painel do DHCP: servidores, lease, conflito e o estado da rede (servidores e enlaces).
import type { ControlDef } from '../../../sim-core/ui';
import { help } from './help';

export const controls: ControlDef[] = [
  { id: 'servers', num: true, grp: 'Servidores', label: 'Servidores DHCP', type: 'select', opts: [[1, '1 servidor'], [2, '2 servidores']], def: 1, help: help.servers },
  { id: 'lease', num: true, grp: 'Servidores', label: 'Tempo de lease', type: 'select', opts: [[1, '1 hora'], [8, '8 horas'], [24, '24 horas']], def: 8, help: help.lease },
  { id: 'conflict', subs: ['dora'], grp: 'Falhas', label: 'Simular conflito de IP', type: 'check', def: false, help: help.conflict },
  { id: 's1up', grp: 'Falhas', label: 'DHCP-1 ativo', type: 'check', def: true, help: { t: 'DHCP-1 ativo', s: 'Se o servidor responde.', p: ['Desmarcado, o DHCP-1 não responde a nenhuma mensagem. Com um só servidor, o cliente fica sem OFFER e retransmite o DISCOVER com espera crescente (4, 8, 16 s).'] } },
  { id: 's2up', grp: 'Falhas', label: 'DHCP-2 ativo (com 2 servidores)', type: 'check', def: true, adv: true, help: { t: 'DHCP-2 ativo', s: 'Se o segundo servidor responde.', p: ['Só vale com 2 servidores. Desmarcado, apenas o DHCP-1 oferece endereço.'] } },
  { id: 'l1up', grp: 'Falhas', label: 'Enlace PC-A / SW1 ativo', type: 'check', def: true, adv: true, help: { t: 'Enlace PC-A / SW1', s: 'A porta Fa0/1 do switch.', p: ['Derrubado, o cliente não consegue transmitir nada e o DISCOVER nem sai da placa de rede.'] } },
  { id: 'l2up', grp: 'Falhas', label: 'Enlace SW1 / DHCP-1 ativo', type: 'check', def: true, adv: true, help: { t: 'Enlace SW1 / DHCP-1', s: 'A porta Gi0/1 do switch.', p: ['Derrubado, o DHCP-1 não recebe o DISCOVER nem responde, mesmo estando ligado.'] } },
  { id: 'l3up', grp: 'Falhas', label: 'Enlace SW1 / DHCP-2 ativo', type: 'check', def: true, adv: true, help: { t: 'Enlace SW1 / DHCP-2', s: 'A porta Gi0/2 do switch.', p: ['Só vale com 2 servidores.'] } },
  { id: 'action', subs: ['lease'], grp: 'Ciclo do lease', label: 'O que o cliente faz depois do BOUND', type: 'select', wide: true, opts: [['renew', 'Renovar o lease (T1)'], ['release', 'Liberar o endereço (RELEASE)']], def: 'renew', help: { t: 'Depois do BOUND', s: 'Como o ciclo do lease continua.', p: ['<b>Renovar:</b> na metade do lease (T1), o cliente pede a renovação em unicast ao servidor que concedeu o endereço.', '<b>Liberar:</b> o cliente devolve o endereço com DHCPRELEASE, por exemplo ao desligar. O servidor não responde.'] } },
  { id: 'srvFail', subs: ['lease'], grp: 'Ciclo do lease', label: 'O servidor cai depois da concessão', type: 'check', def: false, help: { t: 'Servidor cai depois da concessão', s: 'Falha do servidor que concedeu o lease, antes do T1.', p: ['Na renovação: sem resposta no T1, o cliente segue usando o endereço, tenta qualquer servidor no T2 (REBINDING) e, ao fim do lease, perde o endereço.', 'Na liberação: o RELEASE se perde e o lease continua registrado no servidor até expirar.'] } },
];
