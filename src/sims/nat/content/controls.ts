// Controles do painel do NAT: tipo e protocolo, hosts, limites do NAT e o redirecionamento de destino (DNAT).
import type { ControlDef } from '../../../sim-core/ui';
import { help } from './help';

const SAIDA = ['snat', 'limites'];

export const controls: ControlDef[] = [
  { id: 'tipo', subs: SAIDA, grp: 'Tradução', label: 'Tipo de tradução', type: 'select', wide: true, opts: [['estatico', 'Basic NAT estático (1:1)'], ['dinamico', 'Basic NAT dinâmico (pool)'], ['napt', 'NAPT (PAT): endereço e porta']], def: 'napt', help: help.tipo },
  { id: 'pool', subs: SAIDA, num: true, grp: 'Tradução', label: 'Endereços públicos no pool (dinâmico)', type: 'select', opts: [[1, '1 endereço'], [2, '2 endereços'], [3, '3 endereços']], def: 2, help: help.pool },
  { id: 'proto', subs: SAIDA, grp: 'Tradução', label: 'Protocolo', type: 'select', opts: [['tcp', 'TCP'], ['udp', 'UDP'], ['icmp', 'ICMP (ping)'], ['esp', 'ESP (IPsec)']], def: 'tcp', help: help.proto },
  { id: 'mapeamento', subs: ['snat'], grp: 'Tradução', label: 'Comportamento de mapeamento (NAPT)', type: 'select', wide: true, opts: [['eim', 'Independente do destino (EIM)'], ['apdm', 'Dependente de endereço e porta (APDM)']], def: 'eim', adv: true, help: help.mapeamento },
  { id: 'conex', subs: SAIDA, num: true, grp: 'Hosts', label: 'Conexões por host', type: 'select', opts: [[1, '1 conexão'], [2, '2 conexões']], def: 1, help: help.conex },
  { id: 'mesmaPorta', subs: SAIDA, grp: 'Hosts', label: 'PC2 usa a mesma porta de origem do PC1', type: 'check', def: false, help: help.mesmaPorta },
  { id: 'dois', subs: ['snat'], grp: 'Hosts', label: 'PC1 usa a mesma porta para dois destinos', type: 'check', def: false, help: help.dois },
  { id: 'faixa', subs: ['limites'], grp: 'Limites do NAT', label: 'Faixa de portas do NAT', type: 'select', opts: [['ampla', 'Ampla (1024 a 65535)'], ['pequena', 'Pequena, didática (3 portas)']], def: 'ampla', help: help.faixa },
  { id: 'timeout', subs: ['limites'], num: true, grp: 'Limites do NAT', label: 'Tempo de inatividade (timeout)', type: 'select', opts: [[30, '30 s'], [60, '60 s'], [120, '120 s'], [300, '300 s']], def: 120, help: help.timeout },
  { id: 'tardia', subs: ['limites'], grp: 'Limites do NAT', label: 'Resposta tardia do servidor', type: 'check', def: false, help: help.tardia },
  { id: 'entrada', subs: ['limites'], grp: 'Limites do NAT', label: 'Pacote não solicitado de fora', type: 'check', def: false, help: help.entrada },
  { id: 'cgnat', subs: ['limites'], grp: 'Limites do NAT', label: 'NAT em duas camadas (CGNAT)', type: 'check', def: false, help: help.cgnat },
  { id: 'natt', subs: ['limites'], grp: 'Limites do NAT', label: 'NAT-T: ESP dentro de UDP 4500', type: 'check', def: false, adv: true, help: help.natt },
  { id: 'acao', subs: ['dnat'], grp: 'Redirecionamento (DNAT)', label: 'Situação', type: 'select', wide: true, opts: [['forward', 'Publicar serviço (cliente externo)'], ['hairpin', 'Hairpin (cliente interno)'], ['proxy', 'Proxy transparente']], def: 'forward', help: help.acao },
  { id: 'gwOutro', subs: ['dnat'], grp: 'Redirecionamento (DNAT)', label: 'O servidor interno usa outro gateway', type: 'check', def: false, help: help.gwOutro },
  { id: 'hairpin', subs: ['dnat'], grp: 'Redirecionamento (DNAT)', label: 'Suporte a hairpin', type: 'select', wide: true, opts: [['nao', 'Sem suporte'], ['dnat', 'Só DNAT'], ['completo', 'DNAT e SNAT']], def: 'completo', help: help.hairpin },
];
