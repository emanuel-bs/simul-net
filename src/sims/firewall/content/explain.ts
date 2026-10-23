// Texto da aba Experimento e do cabeçalho do cenário.
import type { Trace } from '../../../sim-core';
import type { ScenarioDef } from '../../../sim-core/ui';
import type { FwParams } from '../engine';

/** Texto "Configuração do cenário": só o que o cenário define (o restante vem dos padrões). */
export function setup(s: ScenarioDef): string {
  const P = (s.set || {}) as Partial<FwParams>;
  const p: string[] = [];
  if (s.sub === 'acl') {
    p.push({ tcp: 'conexão TCP de dentro para fora', udp: 'consulta DNS de dentro para fora', fora: 'pacote de fora com porta de origem 443' }[P.aFluxo || 'tcp']);
    p.push({ porta: 'retorno por porta de origem', ack: 'retorno pelo flag ACK', nenhum: 'sem regra de retorno' }[P.aRetorno || 'porta']);
    if (P.aOrdem === 'invertida') p.push('regra genérica antes da específica');
    p.push('política padrão: ' + (P.aPolitica === 'permit' ? 'permitir' : 'negar'));
  } else if (s.sub === 'est') {
    p.push({ tcp: 'conexão TCP', 'tcp-fim': 'conexão TCP até o encerramento', espuria: 'pacotes de fora sem conexão', udp: 'consulta e resposta UDP', icmp: 'ping', cheia: 'tabela de conexões cheia' }[P.eFluxo || 'tcp']);
    if (P.eFluxo === 'udp') p.push(P.eAtraso === 'tardia' ? 'resposta depois da validade' : 'resposta dentro da validade');
    if (P.eFluxo === 'cheia') p.push('tabela de ' + (P.eLimite ?? 4) + ' entradas');
  } else if (s.sub === 'dmz') {
    p.push({ pub: 'Internet para a DMZ', 'ext-int': 'Internet para a rede interna', admin: 'rede interna para a DMZ', lateral: 'DMZ para a rede interna', egresso: 'DMZ para a Internet' }[P.dFluxo || 'pub']);
    if (P.dFluxo === 'lateral') p.push(P.dDmzInt === 'permissiva' ? 'regra permissiva da DMZ para a interna' : 'DMZ para interna negada');
    if (P.dFluxo === 'egresso') p.push(P.dEgresso === 'permitir' ? 'saída da DMZ liberada (80 e 443)' : 'saída da DMZ negada');
  } else {
    p.push({ 'forja-in': 'origem interna vinda de fora', 'forja-out': 'origem alheia saindo da rede interna', varredura: 'varredura de cinco portas', rajada: 'rajada de seis pedidos de conexão', cego: 'conexão HTTPS permitida' }[P.fFluxo || 'forja-in']);
    if (P.fFluxo === 'forja-in' || P.fFluxo === 'forja-out') p.push('filtro de origem ' + (P.fAntispoof ? 'ligado' : 'desligado'));
    if (P.fFluxo === 'varredura') p.push(P.fResp === 'rejeitar' ? 'negadas rejeitadas com RST' : 'negadas descartadas em silêncio');
    if (P.fFluxo === 'rajada') p.push(P.fTaxa ? 'limite de 3 por segundo' : 'sem limite de taxa');
  }
  return p.join('; ');
}

const LESSON: Record<string, string> = {
  ok: '<li><span class="chk-ok">Conexão estabelecida:</span> a regra de ida e a de retorno bastam para o filtro sem estado.</li>',
  'sem-retorno': '<li><span class="chk-bad">Conexão não estabelecida:</span> o SYN passou, mas o SYN+ACK foi negado, porque nenhuma regra descreve o retorno.</li><li>Lição: um filtro sem estado precisa de regra para cada sentido.</li>',
  ordem: '<li><span class="chk-bad">Conexão negada:</span> uma regra genérica antes da específica casou primeiro. A regra de baixo nunca foi usada.</li><li>Lição: a ordem da lista é parte da política.</li>',
  implicita: '<li><span class="chk-ok">Negado pela política padrão:</span> nenhuma regra descreve UDP 53, e a lista termina em negar.</li><li>Lição: com negação implícita, esquecer uma regra deixa algo indisponível, e não exposto.</li>',
  'politica-permit': '<li><span class="chk-bad">Permitido pela política padrão:</span> funcionou sem regra, e o mesmo valeria para qualquer serviço não listado.</li><li>Lição: a política de permitir expõe tudo o que a lista esquece.</li>',
  fraco: '<li><span class="chk-bad">A conexão de fora se completou:</span> a regra de retorno por porta de origem aceitou um pacote que não respondia a nada.</li><li>Lição: sem memória das conexões, o filtro não distingue resposta de imitação. A defesa é o filtro com estado.</li>',
  'ack-barra': '<li><span class="chk-ok">O pedido de fora foi negado:</span> o SYN não tem ACK, e a regra de retorno o exige.</li><li>Lição: ajuda, mas um pacote com ACK forjado ainda casaria com a regra.</li>',
  'fora-barrado': '<li><span class="chk-ok">O pedido de fora foi negado.</span></li>',
  tcp: '<li><span class="chk-ok">Conexão estabelecida só com regra de saída:</span> as respostas passaram pela tabela de conexões.</li><li>Lição: o estado substitui a regra de retorno.</li>',
  fim: '<li><span class="chk-ok">Ciclo completo:</span> a entrada passou por SYN_SENT, SYN_RECV, ESTABLISHED, FIN_WAIT e TIME_WAIT, e foi removida.</li><li>Lição: encerramento e expiração mantêm a tabela do tamanho do tráfego real.</li>',
  espuria: '<li><span class="chk-ok">Nada de fora entrou:</span> as respostas sem pedido foram negadas como fora de estado, e o pedido novo, pela política padrão.</li>',
  udp: '<li><span class="chk-ok">Resposta aceita:</span> casou com a entrada criada pela consulta.</li><li>Lição: o UDP não tem conexão, mas o firewall cria uma pseudoconexão por tempo limitado.</li>',
  'udp-tardia': '<li><span class="chk-bad">Resposta negada:</span> chegou depois da expiração da entrada e foi tratada como pedido novo vindo de fora.</li><li>Lição: o prazo de UDP é um compromisso entre respostas lentas e tamanho da tabela.</li>',
  icmp: '<li><span class="chk-ok">A primeira resposta passou e consumiu a entrada;</span> a segunda foi negada como fora de estado.</li>',
  cheia: '<li><span class="chk-bad">Tabela cheia:</span> os pedidos que excederam o limite foram negados, legítimos ou não.</li><li>Lição: o esgotamento da tabela é uma negação de serviço. Defesas: limites por origem, prazos curtos para entradas semiabertas e tabela bem dimensionada.</li>',
  'nao-cheia': '<li>A tabela comportou todos os pedidos. Reduza o tamanho da tabela para ver o esgotamento.</li>',
  pub: '<li><span class="chk-ok">Acesso público permitido:</span> a Internet alcançou só o servidor web, na porta 443.</li>',
  admin: '<li><span class="chk-ok">Administração permitida:</span> de dentro para a DMZ, nunca no sentido inverso.</li>',
  'ext-int': '<li><span class="chk-ok">Negado:</span> nenhuma regra permite que a Internet alcance a rede interna, e a política padrão nega.</li>',
  'lateral-barrado': '<li><span class="chk-ok">Movimento lateral contido:</span> a regra DMZ para interna negou, e o dano fica na DMZ.</li>',
  'lateral-livre': '<li><span class="chk-bad">O servidor da DMZ alcançou o banco de dados interno:</span> a regra permissiva desfez o isolamento.</li><li>Lição: permitir só o necessário (um host, uma porta) em vez de qualquer protocolo.</li>',
  'egresso-barrado': '<li><span class="chk-ok">Saída negada:</span> o servidor da DMZ não inicia conexões para a Internet.</li>',
  'egresso-livre': '<li><span class="chk-bad">Saída permitida:</span> qualquer código no servidor também consegue abrir conexões para fora por esse caminho.</li><li>Lição: restringir os destinos da saída reduz o risco.</li>',
  'forja-passou': '<li><span class="chk-bad">O pacote com origem interna entrou:</span> a regra olha o endereço, e o endereço foi forjado. O dono verdadeiro respondeu com RST.</li><li>Lição: ligue o filtro de origem (BCP 38).</li>',
  'forja-barrada': '<li><span class="chk-ok">Negado pelo filtro de origem:</span> uma origem interna não pode chegar pela interface externa.</li>',
  'saida-passou': '<li><span class="chk-bad">O pacote com origem alheia saiu da rede.</span> A resposta irá ao dono do endereço forjado.</li><li>Lição: cada rede deve impedir o que parte dela com origem que não lhe pertence.</li>',
  'saida-barrada': '<li><span class="chk-ok">Negado pelo filtro de origem:</span> a origem não pertence à zona interna.</li>',
  'varredura-drop': '<li>Portas 22, 23 e 3389: sem resposta (<b>filtradas</b>). Portas 80 e 443: abertas.</li><li>Lição: o descarte atrasa a sondagem e revela menos. Registre as tentativas negadas.</li>',
  'varredura-reject': '<li>Portas 22, 23 e 3389: recusadas com RST (parecem <b>fechadas</b>). Portas 80 e 443: abertas.</li><li>Lição: a rejeição é mais amigável e informa mais a quem sonda.</li>',
  'rajada-livre': '<li><span class="chk-bad">Todos os seis pedidos chegaram ao servidor,</span> e o firewall acumulou seis entradas semiabertas.</li>',
  'rajada-limitada': '<li><span class="chk-ok">Só os três primeiros pedidos passaram;</span> os demais foram negados pelo limite de taxa.</li><li>Lição: o limite protege o servidor, mas não substitui as defesas dele.</li>',
  cego: '<li>A conexão foi permitida, e o conteúdo cifrado atravessou sem exame.</li><li>Lição: o firewall de camadas 3 e 4 decide por cabeçalhos e estado. Examinar o conteúdo é papel de outros controles, como um WAF.</li>',
};

export function explain(tr: Trace, _P: FwParams): string {
  const R = tr.raw;
  const permit = R.permit as number;
  const deny = R.deny as number;
  let h = '<ul>';
  h += '<li>' + permit + (permit === 1 ? ' pacote permitido' : ' pacotes permitidos') + ' e ' + deny + (deny === 1 ? ' negado' : ' negados') + ' pelo firewall.</li>';
  h += LESSON[R.result as string] ?? '';
  h += '</ul>';
  return h;
}
