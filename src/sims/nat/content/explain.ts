// Texto da aba Experimento e do cabeçalho do cenário do NAT.
import type { Trace } from '../../../sim-core';
import { scenarioParams, type ScenarioDef } from '../../../sim-core/ui';
import { fmtTime, NAT_OUT, normalize, type DevInfo, type JournalEntry, type NatParams } from '../engine';
import { entriesAt } from '../topology';
import { controls } from './controls';

const plural = (n: number, s: string, p: string) => n + ' ' + (n === 1 ? s : p);
const TIPO: Record<string, string> = { estatico: 'Basic NAT estático', dinamico: 'Basic NAT dinâmico', napt: 'NAPT (PAT)' };
const PROTO: Record<string, string> = { tcp: 'TCP', udp: 'UDP', icmp: 'ICMP', esp: 'ESP' };

/** Texto "Configuração do cenário": o que o cenário define. */
export const setup = (s: ScenarioDef): string => paramsText(normalize(scenarioParams(controls, s) as unknown as NatParams, s.sub), s.sub);

function paramsText(P: NatParams, sub: string): string {
  if (sub === 'dnat') {
    const a = P.acao === 'forward' ? 'publicação de serviço (443 para 8443)' : P.acao === 'hairpin' ? 'hairpin (' + (P.hairpin === 'nao' ? 'sem suporte' : P.hairpin === 'dnat' ? 'só DNAT' : 'DNAT e SNAT') + ')' : 'proxy transparente (80 para 3128)';
    return a + (P.acao === 'forward' && P.gwOutro ? '; o servidor interno usa outro gateway' : '');
  }
  const p = [TIPO[P.tipo], PROTO[P.proto] + (P.natt ? ' em UDP 4500 (NAT-T)' : '')];
  if (P.tipo === 'dinamico') p.push('pool de ' + plural(P.pool, 'endereço', 'endereços'));
  if (P.mapeamento === 'apdm') p.push('mapeamento dependente do destino');
  if (P.mesmaPorta) p.push('PC2 usa a mesma porta do PC1');
  if (P.dois) p.push('PC1 envia da mesma porta a dois destinos');
  if (P.faixa === 'pequena') p.push('faixa de 3 portas');
  if (P.tardia) p.push('resposta tardia, timeout de ' + P.timeout + ' s');
  if (P.entrada) p.push('pacote não solicitado de fora');
  if (P.cgnat) p.push('CGNAT');
  p.push(plural(P.conex, 'conexão', 'conexões') + ' por host');
  return p.join('; ');
}

function concepts(flags: string[]): string {
  const has = (k: string) => flags.includes(k);
  const items: string[] = [];
  if (has('basic-estatico')) items.push('O <b>Basic NAT estático</b> traduz só o endereço, 1:1, com mapeamento permanente e bidirecional (RFC 3022).');
  if (has('basic-dinamico')) items.push('O <b>Basic NAT dinâmico</b> empresta um endereço do pool e o recupera depois da inatividade. Hosts simultâneos ficam limitados ao tamanho do pool.');
  if (has('napt')) items.push('O <b>NAPT</b> (PAT) traduz endereço e porta. É um <b>SNAT</b> com tradução de porta: a origem é reescrita na saída e a tabela reverte o destino na volta.');
  if (has('colisao')) items.push('Duas conexões com a mesma porta de origem geram <b>colisão</b>: o NAT escolhe outra porta externa para uma delas, e o host não percebe.');
  if (has('eim-reuso')) items.push('No mapeamento <b>independente do destino</b> (EIM, RFC 4787), a mesma porta interna reaproveita a porta externa, qualquer que seja o destino.');
  if (has('icmp')) items.push('No ICMP, o NAT usa o <b>Identifier</b> do Echo no lugar da porta (RFC 5508).');
  if (has('esgotamento-pool')) items.push('Com o pool menor que o número de hosts, o <b>Basic NAT</b> descarta o excedente: não multiplexa por porta.');
  if (has('esgotamento-portas')) items.push('Sem <b>porta livre</b>, novas conexões não entram na tabela e são descartadas. Limitar conexões por host reduz o risco de um host esgotar o pool.');
  if (has('expirou')) items.push('A entrada é removida depois do <b>tempo de inatividade</b>, para devolver a porta. O simulador usa um valor único; equipamentos reais variam por protocolo.');
  if (has('expirou-resp')) items.push('Uma resposta que chega depois da expiração não encontra entrada e é descartada. Os <i>keepalives</i> evitam o problema em conexões ociosas.');
  if (has('entrada-descartada')) items.push('Um pacote sem entrada na tabela é descartado, mas isso é <b>efeito da tradução</b>, e não uma política de segurança: a proteção vem de uma regra de filtragem com estado.');
  if (has('entrada-entregue')) items.push('O mapeamento do Basic NAT vale nos dois sentidos: um pacote de fora para o endereço mapeado é <b>entregue</b>. O NAT, sozinho, não protege o host.');
  if (has('esp-bloqueado')) items.push('O <b>ESP</b> não tem portas: o NAPT só enxerga endereços e não distingue dois hosts. O NAT-T encapsula o ESP em UDP para resolver (RFC 3948).');
  if (has('esp-ok')) items.push('O Basic NAT traduz só o endereço do cabeçalho IP, e o <b>ESP</b> atravessa. O AH, que protege o cabeçalho IP, não atravessa.');
  if (has('nat-t')) items.push('No <b>NAT-T</b>, o ESP vai dentro de UDP 4500 e o NAPT o trata como um fluxo UDP comum.');
  if (has('cgnat')) items.push('No <b>CGNAT</b>, o pacote é traduzido duas vezes (CPE e CGN), por um espaço intermediário 100.64.0.0/10 (RFC 6598), e a tabela do CGN é compartilhada entre assinantes (RFC 6888).');
  if (has('dnat')) items.push('O <b>DNAT</b> reescreve o destino <b>antes</b> do roteamento, e a resposta é revertida pela tabela de conexões, sem regra extra.');
  if (has('assimetrico')) items.push('Se a resposta não passa pelo NAT, a origem não é revertida e o cliente descarta o pacote: o tráfego de retorno precisa passar pelo mesmo dispositivo.');
  if (has('hairpin-nao')) items.push('Sem <b>hairpinning</b>, o acesso de dentro ao endereço público do próprio serviço falha. Um DNS interno (split DNS) evita o problema.');
  if (has('hairpin-dnat')) items.push('Só o DNAT não basta no hairpin: o servidor responde direto ao cliente, na mesma rede, e a resposta é recusada.');
  if (has('hairpin-ok')) items.push('No hairpin completo, DNAT e SNAT atuam no mesmo pacote (<i>Twice NAT</i>). O servidor responde ao roteador, que reverte os dois campos.');
  if (has('proxy')) items.push('O redirecionamento transparente usa DNAT na interface interna para desviar o tráfego a um proxy sem configurar o cliente.');
  if (!items.length) items.push('Execute para ver os conceitos que aparecem nesta sessão.');
  items.push('<b>Segurança:</b> NAT não é firewall. A reescrita de endereços não substitui a filtragem, e o DNAT apenas redireciona: quem pode acessar o serviço publicado é decidido por regras de filtragem.');
  return '<ul>' + items.map((t) => '<li>' + t + '</li>').join('') + '</ul>';
}

function next(P: NatParams, sub: string): string {
  const out: string[] = [];
  if (sub === 'snat') {
    if (P.tipo !== 'estatico') out.push('Escolha <b>Basic NAT estático</b> e compare a tabela: os mapeamentos existem antes do tráfego.');
    if (P.tipo !== 'napt') out.push('Escolha <b>NAPT</b>: um único endereço atende os dois hosts.');
    if (!P.mesmaPorta && P.tipo === 'napt') out.push('Marque <b>PC2 usa a mesma porta de origem do PC1</b> e veja a colisão.');
    if (P.proto === 'tcp') out.push('Troque o protocolo para <b>ICMP</b> e veja o Identifier no lugar da porta.');
    out.push('Mude para o modo <b>Limites do NAT</b> e esgote as portas.');
  } else if (sub === 'dnat') {
    if (P.acao !== 'forward') out.push('Escolha <b>Publicar serviço</b> e acompanhe o DNAT e a reversão da origem.');
    if (P.acao === 'forward' && !P.gwOutro) out.push('Marque <b>O servidor interno usa outro gateway</b> e veja a resposta sem reversão.');
    if (P.acao !== 'hairpin') out.push('Escolha <b>Hairpin</b> e compare as três configurações de suporte.');
    if (P.acao === 'hairpin' && P.hairpin !== 'completo') out.push('Escolha <b>DNAT e SNAT</b> e veja o servidor responder ao roteador.');
    if (P.acao !== 'proxy') out.push('Escolha <b>Proxy transparente</b> e veja o DNAT na interface interna.');
  } else {
    if (P.faixa === 'ampla') out.push('Escolha a <b>faixa pequena</b> e 2 conexões por host para esgotar as portas.');
    if (!P.tardia) out.push('Marque <b>Resposta tardia do servidor</b> e veja a entrada expirar.');
    if (!P.entrada) out.push('Marque <b>Pacote não solicitado de fora</b> e compare NAPT e Basic NAT estático.');
    if (!P.cgnat) out.push('Marque <b>NAT em duas camadas (CGNAT)</b> e veja duas traduções por pacote.');
    if (P.proto !== 'esp') out.push('Escolha o protocolo <b>ESP</b> e veja por que o IPsec sofre com o NAPT.');
  }
  return '<ul>' + out.slice(0, 4).map((t) => '<li>' + t + '</li>').join('') + '</ul>';
}

export function explain(tr: Trace, Pin: NatParams): string {
  const R = tr.raw;
  if (!R || !R.journal) return '';
  const P = (R.P as NatParams) || Pin;
  const sub = R.sub as string;
  const j = R.journal as JournalEntry[];
  const devs = R.devs as DevInfo[];
  const flags = R.flags as string[];
  const endNow = (tr.times ? tr.times[tr.times.length - 1] : tr.t) + 1;
  let h = '<h3>Experimento: tradução de endereços de rede</h3>';
  h += '<p><b>Objetivo.</b> Acompanhar como o NAT reescreve campos do cabeçalho (a origem na saída, o destino na entrada), guarda a tradução em uma tabela e reverte a mudança na resposta, e ver onde esse mecanismo chega ao limite.</p>';
  h += '<h3>Configuração</h3>';
  if (sub === 'dnat') {
    h += '<p>Rede interna 192.168.1.0/24, com o R-NAT (interno ' + '192.168.1.1, externo ' + NAT_OUT + '), o servidor interno 192.168.1.50 e o servidor ou cliente externo 198.51.100.10. Situação: <b>' + paramsText(P, sub) + '</b>.</p>';
  } else {
    h += '<p>Rede interna 192.168.1.0/24 atrás de ' + (P.cgnat ? 'um CPE e do CGN da operadora' : 'um R-NAT (interno 192.168.1.1, externo ' + NAT_OUT + ')') + '. O servidor externo é 198.51.100.10. Tipo: <b>' + TIPO[P.tipo] + '</b>; protocolo: <b>' + PROTO[P.proto] + (P.natt ? ' em UDP 4500 (NAT-T)' : '') + '</b>.</p>';
    if (P.tipo === 'dinamico') h += '<p>Pool de endereços públicos: ' + devs[0].pool.join(', ') + '.</p>';
    if (sub === 'limites') h += '<p>Faixa de portas do NAT: ' + devs[devs.length - 1].min + ' a ' + devs[devs.length - 1].max + '. Timeout de inatividade: ' + P.timeout + ' s (parâmetro do simulador).</p>';
  }
  h += '<h3>O que aconteceu</h3><ol>' + j.map((e) => '<li>' + fmtTime(e.t) + ': ' + e.text + '</li>').join('') + '</ol>';
  const total = tr.msgs.length;
  const lost = tr.msgs.filter((m) => m.lost).length;
  h += '<p>Foram trocadas <b>' + plural(total, 'mensagem', 'mensagens') + '</b>, das quais ' + plural(R.drops as number, 'foi descartada', 'foram descartadas') + ' (' + lost + ' marcada' + (lost === 1 ? '' : 's') + ' na Captura).</p>';
  const left = devs.map((d) => d.name + ': ' + plural(entriesAt(tr, d.key, endNow).length, 'entrada', 'entradas')).join('; ');
  h += '<p>Ao fim, a tabela tem: ' + left + '.</p>';
  h += '<h3>Conceitos observados</h3>' + concepts(flags);
  h += '<h3>Para explorar em seguida</h3>' + next(P, sub);
  return h;
}
