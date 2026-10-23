// Texto da aba Experimento e do cabeçalho do cenário do DHCP (portado do simulador legado; veja o histórico do git).
import type { Trace } from '../../../sim-core';
import { scenarioParams, type ScenarioDef } from '../../../sim-core/ui';
import { CLIENT_MAC, DNS_LIST, GATEWAY, NET, SERVERS, t1Secs, t2Secs, type DhcpParams, type JournalEntry } from '../engine';
import { controls } from './controls';

const plural = (n: number, s: string, p: string) => n + ' ' + (n === 1 ? s : p);
const hoursTxt = (h: number) => plural(h, 'hora', 'horas');
const b = (x: string) => '<b>' + x + '</b>';

function fmtT(t: number): string {
  if (t < 1) return 't = ' + (Math.round(t * 1000) / 1000).toString().replace('.', ',') + ' s';
  if (t < 3600) return 't = ' + Math.round(t) + ' s';
  return 't = ' + (Math.round(t / 360) / 10).toString().replace('.', ',') + ' h';
}

/** Texto "Configuração do cenário": o que o cenário define. */
export function setup(s: ScenarioDef): string {
  const P = scenarioParams(controls, s) as unknown as DhcpParams;
  const p = [plural(P.servers, 'servidor', 'servidores'), 'lease de ' + hoursTxt(P.lease), 'conflito ' + (P.conflict ? 'ativado' : 'desativado')];
  if (!P.s1up) p.push('DHCP-1 inativo');
  if (s.sub === 'lease') p.push(P.action === 'release' ? 'o cliente libera o endereço' : 'o cliente renova no T1', ...(P.srvFail ? ['o servidor cai depois da concessão'] : []));
  return p.join('; ');
}

function step(e: JournalEntry): string {
  switch (e.type) {
    case 'discover': return 'PC-A, ainda sem endereço, enviou o ' + b('DHCPDISCOVER') + ' em broadcast (xid ' + e.xid + '). ' + (e.reached.length ? 'Receberam: ' + e.reached.join(' e ') + '.' : 'Nenhum servidor recebeu.') + (e.missed.length ? ' Não receberam: ' + e.missed.join('; ') + '.' : '');
    case 'nooffer': return 'Nenhum ' + b('OFFER') + ' chegou (' + e.why.join('; ') + '). O cliente esperou ' + e.delay + ' s (backoff exponencial) e retransmitiu o DISCOVER.';
    case 'offer': return plural(e.offers.length, 'servidor ofereceu', 'servidores ofereceram') + ' endereço: ' + e.offers.map((o: { s: string; ip: string }) => o.s + ' (' + o.ip + ')').join(', ') + '. O cliente escolheu a oferta de ' + b(e.chosen) + (e.offers.length > 1 ? ', a primeira que chegou' : '') + '.';
    case 'request': return 'PC-A enviou o ' + b('DHCPREQUEST') + ' em broadcast pedindo ' + e.ip + ' a ' + e.s + (e.cancelled.length ? '. ' + e.cancelled.join(' e ') + ' viu que não foi escolhido e devolveu a oferta ao pool.' : '.');
    case 'conflict': return e.s + ' concedeu ' + e.ip + ', mas o ' + b('ARP Probe') + ' recebeu resposta de PC-B, que já usava o endereço. PC-A enviou ' + b('DHCPDECLINE') + ', o servidor marcou ' + e.ip + ' como indisponível e o cliente voltou a INIT.';
    case 'bound': return e.s + ' confirmou com ' + b('DHCPACK') + '. Sem resposta ao ARP Probe, PC-A configurou ' + b(e.ip + '/24') + ', gateway ' + GATEWAY + ' e DNS ' + DNS_LIST.join(', ') + ', com lease de ' + hoursTxt(e.hours) + '. Estado: BOUND.';
    case 'renew': return 'No T1, PC-A pediu a renovação em unicast a ' + e.s + ', que respondeu com ' + b('DHCPACK') + ': o lease de ' + e.ip + ' foi estendido por mais ' + hoursTxt(e.hours) + '.';
    case 'expire': return 'No T1, a renovação em unicast para ' + e.s + ' ficou sem resposta (' + e.why + '). No T2, o REQUEST foi para broadcast (REBINDING), mas nenhum outro servidor conhecia o lease. Ao fim do lease, PC-A perdeu ' + b(e.ip) + ' e voltou a INIT.';
    case 'release': return 'PC-A enviou ' + b('DHCPRELEASE') + ' para ' + e.s + (e.ok ? ', que devolveu ' + e.ip + ' ao pool.' : ', mas a mensagem não chegou: o lease de ' + e.ip + ' continua reservado no servidor até expirar.') + ' O servidor não responde ao RELEASE.';
    case 'linkdown': return 'Tentativa de enviar com o enlace PC-A / SW1 caído: o cliente não consegue transmitir.';
  }
  return '';
}

function concepts(j: JournalEntry[]): string {
  const has = (t: string) => j.some((e) => e.type === t);
  const items: string[] = [];
  if (has('discover')) items.push('O cliente ainda não tem endereço, então o DISCOVER sai de <b>0.0.0.0:68</b> para <b>255.255.255.255:67</b>. O switch inunda o quadro por todas as portas e só servidores DHCP o processam.');
  if (has('offer')) items.push('O <b>xid</b> amarra todas as mensagens de uma mesma negociação. O OFFER reserva um endereço e traz a configuração (máscara, gateway, DNS, lease, T1 e T2) nas opções.');
  if (j.some((e) => e.type === 'offer' && e.offers.length > 1)) items.push('Com dois servidores, o REQUEST vai em <b>broadcast</b> e leva a opção 54 (Server Identifier): o escolhido confirma e os outros sabem que devem devolver a oferta ao pool.');
  if (has('bound') || has('conflict')) items.push('Antes de usar o endereço, o cliente faz um <b>ARP Probe</b> (RFC 2131, seção 3.1) para descobrir se alguém já o usa.');
  if (has('conflict')) items.push('O <b>DHCPDECLINE</b> avisa o servidor do conflito; o endereço sai do pool e o cliente recomeça do zero.');
  if (has('nooffer')) items.push('Sem resposta, o cliente retransmite com <b>backoff exponencial</b> (4, 8, 16 s... até 64 s, com sorteio de ±1 s), para não inundar a rede. Os valores são os do exemplo da RFC 2131 (seção 4.1), dado para Ethernet de 10 Mb/s; implementações reais variam.');
  if (has('renew')) items.push('A renovação no <b>T1</b> é feita em unicast, direto com o servidor que concedeu o lease; o cliente mantém o endereço o tempo todo.');
  if (has('expire')) items.push('No <b>T2</b>, o cliente tenta qualquer servidor em broadcast (REBINDING). Se ninguém confirmar até o fim do lease, ele perde o endereço. Por isso redes com dois servidores precisam de failover ou pools coordenados.');
  if (has('release')) items.push('O <b>DHCPRELEASE</b> não tem resposta. Se ele se perde, o endereço só volta ao pool quando o lease expira.');
  if (has('offer')) items.push('<b>Segurança:</b> o DHCP não autentica ninguém. Qualquer host pode responder a um DISCOVER (servidor falso, rogue DHCP) ou pedir endereços até esgotar o pool (starvation). Os controles são DHCP snooping, port security e a opção 82 no switch.');
  if (!items.length) items.push('Execute para ver os conceitos que aparecem nesta sessão.');
  return '<ul>' + items.map((t) => '<li>' + t + '</li>').join('') + '</ul>';
}

function next(P: DhcpParams, j: JournalEntry[], sub: string): string {
  const has = (t: string) => j.some((e) => e.type === t);
  const out: string[] = [];
  if (P.servers === 1) out.push('Escolha <b>2 servidores</b> e veja as duas ofertas e o descarte da que não foi escolhida.');
  if (sub === 'dora' && !P.conflict) out.push('Marque <b>Simular conflito de IP</b>: veja o ARP Probe detectar o conflito e o DECLINE.');
  if (sub === 'dora' && has('bound')) out.push('Mude para o modo <b>Ciclo do lease</b> e veja a renovação em unicast no T1.');
  if (sub === 'lease' && !P.srvFail && P.action === 'renew') out.push('Marque <b>O servidor cai depois da concessão</b>: o cliente passa por REBINDING e perde o endereço.');
  if (!has('nooffer')) out.push('Desmarque <b>DHCP-1 ativo</b> e observe as retransmissões com backoff.');
  if (sub === 'lease' && P.action === 'renew') out.push('Troque para <b>Liberar o endereço</b> e veja que o servidor não responde, mas devolve o endereço ao pool.');
  return '<ul>' + out.slice(0, 4).map((t) => '<li>' + t + '</li>').join('') + '</ul>';
}

export function explain(tr: Trace, P: DhcpParams): string {
  const R = tr.raw;
  if (!R || !R.journal) return '';
  const j = R.journal as JournalEntry[];
  const sub = R.sub as string;
  const pools = SERVERS.slice(0, P.servers).map((s) => s.id + ' (' + s.ip + ', pool ' + NET + '.' + s.start + ' a .' + s.end + ')').join(' e ');
  let h = '<h3>Experimento: obtenção de endereço com DHCP</h3>';
  h += '<p><b>Objetivo.</b> Acompanhar como o PC-A, sem endereço IP, obtém sua configuração pelo processo <b>DORA</b> (Discover, Offer, Request, Ack) e como o cliente reage a falhas: servidor ausente, conflito de endereço, renovação e liberação do lease (RFC 2131).</p>';
  h += '<h3>Configuração</h3><p>Rede ' + NET + '.0/24 com ' + plural(P.servers, 'servidor DHCP', 'servidores DHCP') + ': ' + pools + '. O PC-A (MAC ' + CLIENT_MAC + ') começa sem endereço; o PC-B tem IP estático.</p>';
  h += '<p>Lease de <b>' + hoursTxt(P.lease) + '</b>: T1 (renovação, 50%) em ' + t1Secs(P.lease) + ' s e T2 (rebinding, 87,5%) em ' + t2Secs(P.lease) + ' s.</p>';
  h += '<p>Simulação de conflito: ' + (P.conflict && sub === 'dora' ? '<b>ativa</b>. O PC-B responde ao ARP Probe pelo primeiro endereço concedido, como se já o usasse.' : 'desativada.') + '</p>';
  const down: string[] = [];
  if (!P.l1up) down.push('enlace PC-A / SW1 caído');
  if (!P.l2up) down.push('enlace SW1 / DHCP-1 caído');
  if (P.servers > 1 && !P.l3up) down.push('enlace SW1 / DHCP-2 caído');
  if (!P.s1up) down.push('DHCP-1 inativo');
  if (P.servers > 1 && !P.s2up) down.push('DHCP-2 inativo');
  if (down.length) h += '<p>Situação da rede: ' + down.join('; ') + '.</p>';
  h += '<h3>O que aconteceu</h3><ol>' + j.map((e) => '<li>' + fmtT(e.t) + ': ' + step(e) + '</li>').join('') + '</ol>';
  const cap = (R.capture || []) as { kind: string; type: string; dstMac: string }[];
  if (cap.length) {
    const cnt: Record<string, number> = {};
    let bc = 0;
    cap.forEach((c) => {
      const k = c.kind === 'arp' ? 'ARP' : 'DHCP' + c.type;
      cnt[k] = (cnt[k] || 0) + 1;
      if (c.dstMac === 'ff:ff:ff:ff:ff:ff') bc++;
    });
    h += '<p>Foram enviadas <b>' + plural(cap.length, 'mensagem', 'mensagens') + '</b> (' + Object.keys(cnt).map((k) => cnt[k] + ' ' + k).join(', ') + '), das quais ' + bc + ' em broadcast e ' + (cap.length - bc) + ' em unicast.</p>';
  }
  h += '<h3>Conceitos observados</h3>' + concepts(j);
  h += '<h3>Para explorar em seguida</h3>' + next(P, j, sub);
  return h;
}
