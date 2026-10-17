// Texto da aba Experimento e do cabeçalho do cenário do ICMP (portado do simulador legado; veja o histórico do git).
import { esc, type Trace } from '../../../sim-core';
import { scenarioParams, type ScenarioDef } from '../../../sim-core/ui';
import { buildNodes, commandLine, plural, toolOf, type CaptureRec, type IcmpParams, type ProbeRec, type Tool } from '../engine';
import { controls } from './controls';
import { dstInfo } from './help';

const ERROR_TYPES = new Set([3, 4, 5, 11, 12]);
const nodes = buildNodes();
const nodeOfIp = (ip: string) => Object.values(nodes).find((n) => n.ifaces && n.ifaces.some((i) => i.ip === ip));
const who = (ip: string) => {
  const n = nodeOfIp(ip);
  return n ? ip + ' (' + n.id + ')' : ip;
};
const fmtMsBr = (v: number) => (Math.round(v * 100) / 100).toString().replace('.', ',') + ' ms';

/** Mudanças da rede em relação à configuração padrão, em linguagem corrida. */
export function netChanges(P: IcmpParams): string[] {
  const out: string[] = [];
  const L: [boolean, number, string][] = [[P.l1up, P.l1mtu, 'PC-A / R1'], [P.l2up, P.l2mtu, 'R1 / R2 (WAN)'], [P.l3up, P.l3mtu, 'R2 / R3 (WAN)'], [P.l4up, P.l4mtu, 'LAN do servidor']];
  L.forEach(([up, mtu, name]) => {
    if (!up) out.push('enlace ' + name + ' caído');
    else if (mtu !== 1500) out.push('MTU ' + mtu + ' no enlace ' + name);
  });
  if (P.r1acl === 'deny-icmp') out.push('ACL de entrada em R1 (g0/1) negando todo ICMP');
  if (P.r1acl === 'deny-icmp-errors') out.push('ACL de entrada em R1 (g0/1) que só aceita Echo Reply e bloqueia os erros ICMP');
  if (P.r3acl === 'deny-unreach') out.push('ACL de saída em R3 (g0/1) negando o tráfego e respondendo com 3/13');
  if (P.r3acl === 'deny-silent') out.push('ACL de saída em R3 (g0/1) descartando em silêncio');
  if (!P.r2lan) out.push('R2 sem a rota para 10.0.4.0/24');
  if (!P.srvEcho) out.push('firewall do SRV bloqueando ping');
  ([['R1', P.unr1], ['R2', P.unr2], ['R3', P.unr3]] as [string, boolean][]).forEach(([id, on]) => {
    if (!on) out.push(id + ' com no ip unreachables');
  });
  return out;
}

/** Texto "Configuração do cenário": o comando e o que a rede tem de diferente do padrão. */
export function setup(s: ScenarioDef): string {
  const P = scenarioParams(controls, s) as unknown as IcmpParams;
  const ch = netChanges(P);
  return 'comando: ' + commandLine(toolOf(s.sub, P), P) + '; ' + (ch.length ? ch.join('; ') : 'rede na configuração padrão');
}

function errDesc(type: number, code: number, src: string, mtu: number): string {
  const at = '<b>' + esc(who(src)) + '</b>';
  if (type === 11) return 'Time Exceeded (11/0) gerado por ' + at + ': o datagrama chegou com TTL 1, o roteador descartou e avisou a origem.';
  if (type === 3 && code === 0) return 'Net Unreachable (3/0) gerado por ' + at + ': o roteador não tem rota para a rede de destino, nem rota padrão.';
  if (type === 3 && code === 1) return 'Host Unreachable (3/1) gerado por ' + at + ': a rede existe, mas ninguém respondeu ao ARP pelo endereço de destino.';
  if (type === 3 && code === 3) return 'Port Unreachable (3/3) gerado por ' + at + ': o datagrama chegou ao destino, mas nenhuma aplicação escuta aquela porta.';
  if (type === 3 && code === 4) return 'Fragmentation Needed (3/4) gerado por ' + at + ': o datagrama tinha DF ligado e não cabia na MTU ' + mtu + ' do próximo enlace.';
  if (type === 3 && code === 13) return 'Communication Administratively Prohibited (3/13) gerado por ' + at + ': uma ACL negou o tráfego e anunciou o bloqueio.';
  return 'ICMP tipo ' + type + ' código ' + code + ' gerado por ' + at + '.';
}

function goal(tool: Tool, P: IcmpParams): string {
  const d = '<b>' + esc(P.dst) + '</b>';
  if (tool === 'ping') return 'Testar se ' + d + ' responde e medir o tempo de ida e volta (RTT), usando Echo Request (tipo 8) e Echo Reply (tipo 0).';
  if (tool === 'traceroute') return 'Descobrir o caminho até ' + d + ' salto a salto, como o traceroute do Linux: sondas UDP com TTL crescente.';
  if (tool === 'traceroute-I') return 'Descobrir o caminho até ' + d + ' salto a salto com sondas ICMP Echo e TTL crescente (traceroute -I).';
  if (tool === 'tracert') return 'Descobrir o caminho até ' + d + ' como o Windows faz: Echo Request com TTL crescente.';
  return 'Verificar se a porta UDP <b>' + P.port + '</b> de ' + d + ' está aberta, interpretando as respostas ICMP (técnica de scan UDP).';
}

function setupText(tool: Tool, P: IcmpParams, line: string, changes: string[]): string {
  let h = '<p>Comando executado no PC-A (10.0.1.10): <code>' + esc(line) + '</code>.</p><p>';
  if (tool === 'ping') {
    const df = P.pmtu === 'dont' ? 'DF desligado (-M dont): os roteadores podem fragmentar' : P.pmtu === 'do' ? 'DF ligado e fragmentação proibida também no PC-A (-M do)' : 'DF ligado; se aprender uma PMTU menor, o PC-A fragmenta localmente (-M want, padrão do Linux)';
    h += plural(P.count, 'Echo Request', 'Echo Requests') + ' com TTL inicial ' + P.ttl + ' e datagramas de ' + (P.size + 28) + ' bytes (' + P.size + ' de dados + 8 do cabeçalho ICMP + 20 do IP). ' + df + '.';
  } else if (tool === 'hping3') {
    h += plural(P.count, 'datagrama UDP', 'datagramas UDP') + ' para a porta ' + P.port + ', com TTL inicial ' + P.ttl + '. O hping3 não espera resposta da aplicação: interpreta o ICMP que volta (ou a falta dele).';
  } else {
    h += 'Até ' + P.max + ' saltos, com 3 sondas por salto. ' + (tool === 'traceroute' ? 'As sondas são datagramas UDP para portas altas (33434 em diante), que nenhuma aplicação usa.' : 'As sondas são Echo Request.') + ' O TTL começa em 1 e sobe a cada salto.';
  }
  h += '</p><p>Estado da rede: ' + (changes.length ? changes.map(esc).join('; ') + '.' : 'configuração padrão (caminho PC-A, R1, R2, R3 até a LAN do SRV, MTU 1500 em todos os enlaces).') + '</p>';
  return h;
}

function results(R: Record<string, any>, changes: string[], tool: Tool): string {
  const probes = R.probes as ProbeRec[];
  const capture = R.capture as CaptureRec[];
  const P = probes;
  if (!P.length) return '<p>Nenhuma sonda foi enviada.</p>';
  let h = '<p>' + (P.length === 1 ? 'Foi enviada ' : 'Foram enviadas ') + '<b>' + plural(P.length, 'sonda', 'sondas') + '</b>.</p>';
  const items: string[] = [];
  const replies = P.filter((p) => p.kind === 'reply');
  if (replies.length) {
    const avg = replies.reduce((a, p) => a + (p.rtt as number), 0) / replies.length;
    const src = replies[0].src as string;
    const n = nodeOfIp(src);
    let t = plural(replies.length, 'Echo Reply recebido', 'Echo Replies recebidos') + ' de <b>' + esc(who(src)) + '</b>, RTT médio de ' + fmtMsBr(avg) + ' e TTL recebido ' + replies[0].ttl + '.';
    if (n && n.ttl0) t += ' Como ' + n.id + ' começa com TTL ' + n.ttl0 + (n.kind === 'router' ? ' (roteador)' : ' (Linux)') + ', a resposta atravessou ' + plural(n.ttl0 - (replies[0].ttl as number), 'roteador', 'roteadores') + '.';
    items.push(t);
  }
  const groups: Record<string, { p: ProbeRec; n: number }> = {};
  P.filter((p) => p.kind === 'error').forEach((p) => {
    const k = p.type + '/' + p.code + '@' + p.src;
    (groups[k] = groups[k] || { p, n: 0 }).n++;
  });
  Object.values(groups).forEach((g) => items.push((g.n > 1 ? g.n + 'x ' : '') + errDesc(g.p.type as number, g.p.code as number, g.p.src as string, g.p.mtu)));
  const genErr: Record<string, { n: number; p: CaptureRec['pkt']; where: string }> = {};
  capture.forEach((e) => {
    const p = e.pkt;
    if (p.proto === 1 && p.icmp && ERROR_TYPES.has(p.icmp.type)) {
      const k = p.icmp.type + '/' + p.icmp.code + '@' + e.where;
      (genErr[k] = genErr[k] || { n: 0, p, where: e.where }).n++;
    }
  });
  Object.values(genErr).forEach((g) => {
    const ic = g.p.icmp as { type: number; code: number };
    const got = P.filter((p) => p.kind === 'error' && p.type === ic.type && p.code === ic.code).length;
    if (g.n > got) items.push('<b>' + esc(g.where) + '</b> gerou ' + plural(g.n - got, 'erro', 'erros') + ' ' + ic.type + '/' + ic.code + (g.n - got === 1 ? ' (está na Captura), mas ' : ' (estão na Captura), mas ') + (g.n - got === 1 ? 'ele foi descartado' : 'eles foram descartados') + ' no caminho de volta e não ' + (g.n - got === 1 ? 'chegou' : 'chegaram') + ' ao PC-A.');
  });
  const tos = P.filter((p) => p.kind === 'timeout').length;
  if (tos) {
    const causes: string[] = [];
    if (changes.some((x) => x.indexOf('em silêncio') >= 0)) causes.push('a ACL silenciosa em R3');
    if (changes.some((x) => x.indexOf('bloqueia os erros') >= 0)) causes.push('a ACL de R1, que descarta os erros ICMP no caminho de volta');
    if (changes.some((x) => x.indexOf('negando todo ICMP') >= 0)) causes.push('a ACL de R1, que nega todo ICMP');
    if (changes.some((x) => x.indexOf('bloqueando ping') >= 0)) causes.push('o firewall do SRV');
    if (changes.some((x) => x.indexOf('no ip unreachables') >= 0)) causes.push('um roteador com no ip unreachables, que descarta sem avisar');
    items.push(plural(tos, 'sonda ficou', 'sondas ficaram') + ' sem resposta (timeout). ' + (causes.length ? 'Causa provável: ' + causes.join('; ') + '.' : 'Algo descartou o pacote ou a resposta sem gerar ICMP.') + ' Um timeout não diz <b>onde</b> o pacote morreu.');
  }
  const loc = P.filter((p) => p.kind === 'local');
  if (loc.length) {
    const m = loc.find((p) => p.msg === 'mtu');
    if (m) items.push('O próprio PC-A recusou enviar ' + plural(loc.filter((p) => p.msg === 'mtu').length, 'sonda', 'sondas') + ' (local error: message too long): o datagrama excede a PMTU de ' + m.lmtu + ' bytes já conhecida e -M do proíbe fragmentar.');
    else items.push('O PC-A não conseguiu enviar: ' + (loc[0].msg === 'net' ? 'não há rota na própria máquina.' : 'o gateway não respondeu ao ARP.'));
  }
  h += '<ul>' + items.map((t) => '<li>' + t + '</li>').join('') + '</ul>';
  if (tool !== 'ping' && tool !== 'hping3') {
    const hops: Record<number, ProbeRec[]> = {};
    P.forEach((p) => (hops[p.ttl0] = hops[p.ttl0] || []).push(p));
    h += '<p>Caminho descoberto:</p><ul>' + Object.keys(hops).map(Number).sort((a, b) => a - b).map((t) => {
      const ok = hops[t].find((p) => p.kind !== 'timeout' && p.src);
      if (!ok) return '<li>TTL ' + t + ': * (nenhuma resposta)</li>';
      const what = ok.kind === 'reply' ? 'Echo Reply, destino alcançado' : ok.type === 11 ? 'Time Exceeded' : 'Destination Unreachable ' + ok.type + '/' + ok.code;
      return '<li>TTL ' + t + ': ' + esc(who(ok.src as string)) + ' (' + what + ')</li>';
    }).join('') + '</ul>';
  }
  if (capture.length) {
    const cnt: Record<string, number> = {};
    const add = (k: string) => (cnt[k] = (cnt[k] || 0) + 1);
    capture.forEach((e) => {
      const p = e.pkt;
      if (p.frag) add('fragmentos IP');
      else if (p.proto === 17) add('UDP');
      else {
        const ic = p.icmp as { type: number; code: number };
        if (ic.type === 8) add('Echo Request');
        else if (ic.type === 0) add('Echo Reply');
        else if (ic.type === 11) add('Time Exceeded');
        else add('Destination Unreachable ' + ic.type + '/' + ic.code);
      }
    });
    const fragSet: Record<string, string> = {};
    capture.filter((e) => e.pkt.frag).forEach((e) => (fragSet[e.where + '/' + e.pkt.ipid] = e.where));
    const fragWhere = Array.from(new Set(Object.values(fragSet)));
    const frags = Object.keys(fragSet).length;
    h += '<p>Foram gerados <b>' + plural(capture.length, 'pacote', 'pacotes') + '</b> nesta execução: ' + Object.keys(cnt).map((k) => cnt[k] + ' ' + k).join(', ') + '.' + (frags ? ' ' + plural(frags, 'datagrama foi fragmentado', 'datagramas foram fragmentados') + ' no caminho (fragmentação feita por ' + fragWhere.join(' e ') + ').' : '') + '</p>';
  }
  const learned = Object.keys(R.pmtuCache || {});
  if (learned.length) h += '<p>O PC-A gravou no cache de PMTU: ' + learned.map((k) => esc(k) + ' = ' + R.pmtuCache[k] + ' bytes').join(', ') + '. Os próximos envios para esse destino respeitam esse limite.</p>';
  return h;
}

function concepts(R: Record<string, any>, changes: string[]): string {
  const P = R.probes as ProbeRec[];
  const capture = R.capture as CaptureRec[];
  const seen = new Set(P.filter((p) => p.kind === 'error').map((p) => p.type + '/' + p.code));
  const items: string[] = [];
  if (P.some((p) => p.kind === 'reply')) items.push('<b>Echo Request e Reply</b> carregam o mesmo identificador e a mesma sequência; é assim que o ping associa cada resposta à sua pergunta. O TTL recebido revela o sistema de origem (64 no Linux, 128 no Windows, 255 em roteadores) e o número de saltos.');
  if (seen.has('11/0')) items.push('<b>Time Exceeded</b> existe para impedir que pacotes circulem para sempre. Todo erro ICMP volta para a <b>origem</b> e cita o cabeçalho IP original mais 8 bytes, o que permite casar o erro com a sonda certa. O traceroute explora exatamente isso.');
  if (seen.has('3/0')) items.push('<b>Net Unreachable</b> é obrigatório quando um roteador não tem nenhuma rota (RFC 1812). O endereço de quem gera o erro mostra onde o caminho termina.');
  if (seen.has('3/1')) items.push('<b>Host Unreachable</b> só sai depois de o ARP falhar (3 tentativas), por isso demora cerca de 3 s.');
  if (seen.has('3/3')) items.push('<b>Port Unreachable</b> vem do próprio destino. Porta fechada responde 3/3; porta aberta ou filtrada em silêncio não responde. É a base do scan UDP.');
  if (seen.has('3/4')) items.push('<b>Path MTU Discovery</b> (RFC 1191): com DF ligado, o roteador não fragmenta; devolve 3/4 com a MTU do próximo enlace e a origem passa a enviar pacotes menores.');
  if (seen.has('3/13')) items.push('Um filtro que responde <b>3/13</b> denuncia a própria existência e o local do bloqueio. É uma escolha entre facilitar o diagnóstico e esconder a rede.');
  if (P.some((p) => p.kind === 'timeout')) items.push('Descartar em <b>silêncio</b> esconde a rede de quem faz reconhecimento, mas também dificulta o diagnóstico: só sobra o timeout.');
  if (changes.some((x) => x.indexOf('bloqueia os erros') >= 0) && P.some((p) => p.kind === 'timeout')) items.push('<b>Buraco negro de PMTUD</b> (RFC 2923): bloquear os erros ICMP impede o 3/4 de chegar. Pacotes pequenos funcionam e os grandes somem. Nunca filtre o tipo 3 código 4.');
  if (capture.some((e) => e.pkt.frag)) items.push('<b>Fragmentação IPv4</b>: os fragmentos compartilham o mesmo ID, o offset é contado em blocos de 8 bytes e o bit MF marca que há mais. Só o destino remonta.');
  if (changes.some((x) => x.indexOf('LAN do servidor caído') >= 0) && seen.has('11/0')) items.push('<b>Loop de roteamento</b>: sem a rota conectada, R3 devolve o pacote para R2 pela rota padrão. O TTL cai a cada volta até o Time Exceeded.');
  if (!items.length) items.push('Execute o comando para ver os conceitos que aparecem nesta execução.');
  return '<ul>' + items.map((t) => '<li>' + t + '</li>').join('') + '</ul>';
}

function next(R: Record<string, any>, tool: Tool, P: IcmpParams): string {
  const pr = R.probes as ProbeRec[];
  const out: string[] = [];
  const seen = new Set(pr.filter((p) => p.kind === 'error').map((p) => p.type + '/' + p.code));
  if (tool === 'ping' && pr.some((p) => p.kind === 'reply')) out.push('Mude para o modo <b>Traceroute</b> com o mesmo destino (' + esc(P.dst) + ') para ver por quais roteadores a resposta passou.');
  if (tool === 'traceroute') out.push('Compare com <b>tracert</b> (Windows): as sondas viram Echo Request e o último salto responde com Echo Reply.');
  if (seen.has('3/3')) out.push('Troque a porta para <b>53</b> (aberta no SRV) e observe a ausência de resposta ICMP.');
  if (seen.has('3/4') && P.pmtu === 'do') out.push('Repita com <b>-M want</b>: depois de aprender a PMTU, o PC-A fragmenta localmente e o ping passa.');
  if (pr.some((p) => p.kind === 'timeout')) out.push('Compare com o cenário <b>Proibido (3/13)</b>: o mesmo bloqueio, mas anunciado.');
  out.push('Altere uma ACL, a MTU de um enlace ou <b>ip unreachables</b> nos controles e rode de novo para comparar as duas execuções.');
  return '<ul>' + out.slice(0, 4).map((t) => '<li>' + t + '</li>').join('') + '</ul>';
}

export function explain(tr: Trace, P: IcmpParams, scen: ScenarioDef | undefined): string {
  const R = tr.raw;
  if (!R || !R.probes) return '';
  const tool = R.tool as Tool;
  const changes = netChanges(P);
  let h = '<h3>' + (scen ? 'Experimento: ' + esc(scen.label) : 'Experimento personalizado') + '</h3>';
  h += '<p><b>Objetivo.</b> ' + goal(tool, P) + '</p>';
  h += '<h3>Configuração</h3>' + setupText(tool, P, R.line, changes);
  h += '<h3>O que aconteceu</h3>' + results(R, changes, tool);
  h += '<h3>Conceitos observados</h3>' + concepts(R, changes);
  h += '<h3>Para explorar em seguida</h3>' + next(R, tool, P);
  return h;
}

/** Explicação de cada parte do comando montado: pares [trecho, significado]. */
export function explainCommand(tool: Tool, P: IcmpParams): [string, string][] {
  const out: [string, string][] = [];
  const short = P.dst === '10.0.4.20' && P.ttl <= 3;
  const ttlTxt = short ? 'TTL inicial ' + P.ttl + ': não alcança o SRV, que está a 3 roteadores. R' + P.ttl + ' recebe com TTL 1, descarta e devolve Time Exceeded (11/0).' : 'TTL inicial ' + P.ttl + '.';
  const add = (tok: string, txt: string) => out.push([tok, txt]);
  if (tool === 'ping') {
    add('ping', 'envia ICMP Echo Request (tipo 8) e espera Echo Reply (tipo 0).');
    add('-c ' + P.count, plural(P.count, 'sonda', 'sondas') + ', uma por segundo.');
    add(P.ttl !== 64 ? '-t ' + P.ttl : '(TTL 64)', P.ttl !== 64 ? ttlTxt : 'TTL padrão do Linux; a opção -t foi omitida.');
    add(P.size !== 56 ? '-s ' + P.size : '(56 bytes)', P.size + ' bytes de dados; o datagrama IP tem ' + (P.size + 28) + ' bytes' + (P.size + 28 > 1500 ? ', mais que a MTU Ethernet de 1500' : '') + '.');
    add(P.pmtu !== 'want' ? '-M ' + P.pmtu : '(-M want)', P.pmtu === 'do' ? 'DF ligado e fragmentação proibida: se não couber num enlace, o roteador devolve 3/4 e, depois disso, o próprio PC-A recusa enviar.' : P.pmtu === 'dont' ? 'DF desligado: os roteadores podem fragmentar.' : 'DF ligado; com uma PMTU aprendida, o PC-A fragmenta localmente.');
  } else if (tool === 'hping3') {
    add('hping3 --udp', 'envia datagramas UDP e interpreta o ICMP que volta.');
    add('-p ' + P.port, 'porta de destino ' + P.port + (P.dst === '10.0.4.20' && !short ? ([53, 123].indexOf(P.port) >= 0 ? ': aberta no SRV, não deve haver resposta.' : ': fechada no SRV, espere Port Unreachable (3/3).') : '.'));
    add('-c ' + P.count, plural(P.count, 'datagrama', 'datagramas') + '.');
    if (P.ttl !== 64) add('-t ' + P.ttl, ttlTxt);
  } else {
    const win = tool === 'tracert';
    add(win ? 'tracert -d' : tool === 'traceroute-I' ? 'traceroute -n -I' : 'traceroute -n', (win || tool === 'traceroute-I' ? 'sondas Echo Request' : 'sondas UDP para portas a partir de 33434') + ' com TTL 1, 2, 3...; ' + (win ? '-d' : '-n') + ' mostra só os endereços, sem consultar DNS.');
    add((win ? '-h ' : '-m ') + P.max, 'testa no máximo ' + plural(P.max, 'salto', 'saltos') + '.');
    add('3 sondas por salto', win ? 'padrão do tracert.' : 'padrão do traceroute (opção -q).');
  }
  add(P.dst, dstInfo[P.dst] || 'endereço informado.');
  return out;
}
