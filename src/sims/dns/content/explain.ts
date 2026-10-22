// Texto da aba Experimento e do cabeçalho do cenário do DNS: gerado a partir do que aconteceu na execução.
import type { Trace } from '../../../sim-core';
import { scenarioParams, type ScenarioDef } from '../../../sim-core/ui';
import { fmtTime, type DnsParams, type Step } from '../engine';
import { controls } from './controls';

const plural = (n: number, s: string, p: string) => n + ' ' + (n === 1 ? s : p);
const yes = (v: boolean) => (v ? 'sim' : 'não');

const REG: Record<string, string> = { A: 'A (IPv4)', AAAA: 'AAAA (IPv6)', MX: 'MX', TXT: 'TXT', CNAME: 'CNAME', NXDOMAIN: 'nome inexistente' };
const CACHE: Record<string, string> = { vazio: 'cache frio', tld: 'delegação do .com em cache', ns: 'delegações do .com e do domínio em cache', completo: 'resposta em cache' };
const ZONA: Record<string, string> = { ok: 'zona assinada e correta', nx: 'nome inexistente em zona assinada', insegura: 'zona sem DS no .com', expirada: 'assinatura RRSIG vencida', dsruim: 'DS no .com que não casa com a chave' };
const DEFESA: Record<string, string> = { nenhuma: 'nenhuma (porta fixa e ID previsível)', aleatoria: 'porta e ID aleatórios', x20: 'porta e ID aleatórios com 0x20', dnssec: 'validação DNSSEC' };
const RESOLV: Record<string, string> = { aberto: 'aberto a qualquer endereço', acl: 'fechado (ACL)', rrl: 'aberto com limite de taxa' };
const TRANSP: Record<string, string> = { udp: 'DNS puro (UDP 53)', dot: 'DoT (TLS, porta 853)', doh: 'DoH (HTTPS, porta 443)' };

/** Texto "Configuração do cenário": o que o cenário define. */
export function setup(s: ScenarioDef): string {
  const P = scenarioParams(controls, s) as unknown as DnsParams;
  switch (s.sub) {
    case 'sec': return [ZONA[P.zona], 'resolvedor ' + (P.validar ? 'valida' : 'não valida') + ' o DNSSEC'].join('; ');
    case 'env': return ['defesa: ' + DEFESA[P.defesa], 'o atacante ' + (P.sorte ? 'acerta' : 'não acerta') + ' porta e ID por palpite'].join('; ');
    case 'amp': return ['resolvedor ' + RESOLV[P.resolvedor], 'consulta ' + (P.consulta === 'any' ? 'ANY' : 'A'), 'BCP 38 ' + (P.bcp38 ? 'aplicado' : 'ausente')].join('; ');
    case 'priv': return [TRANSP[P.transporte], ...(P.transporte === 'dot' ? ['porta 853 ' + (P.bloqueio ? 'bloqueada' : 'liberada'), 'política ' + P.politica] : [])].join('; ');
    default: return [REG[P.registro], CACHE[P.cache], 'ns1 ' + (P.ns1 ? 'no ar' : 'fora do ar'), 'perda ' + yes(P.perda), 'TCP por truncamento ' + yes(P.tcp)].join('; ');
  }
}

const OBJ: Record<string, string> = {
  res: 'Acompanhar como um resolvedor recursivo responde a uma pergunta do cliente: o percurso pela hierarquia (raiz, TLD e autoritativo), o papel do cache e do TTL, os tipos de registro e as falhas comuns (RFC 1034 e RFC 1035).',
  sec: 'Acompanhar como o DNSSEC prova a autenticidade de uma resposta pela cadeia de confiança (DS, DNSKEY e RRSIG), e o que acontece quando um elo falha ou o resolvedor não valida (RFC 4033 a 4035).',
  env: 'Observar uma tentativa de envenenamento de cache e como cada defesa (porta e ID aleatórios, 0x20, DNSSEC) a impede, em nível defensivo (RFC 5452).',
  amp: 'Observar como um resolvedor aberto é usado para amplificar tráfego contra uma vítima e quais controles interrompem o ataque, em nível defensivo (BCP 38 e RFC 8482).',
  priv: 'Comparar o que um observador na rede enxerga quando o DNS viaja em texto claro, em DoT ou em DoH, e o efeito de bloquear a porta do DoT (RFC 7858 e RFC 8484).',
};

function next(P: DnsParams, sub: string): string {
  const o: string[] = [];
  if (sub === 'res') {
    if (P.cache === 'vazio') o.push('Escolha <b>Delegações do .com e do domínio</b> no cache e compare o número de consultas e o tempo.');
    if (P.cache !== 'completo') o.push('Escolha <b>A própria resposta</b> e veja a resolução sem nenhuma consulta à Internet.');
    if (P.ns1) o.push('Desmarque <b>ns1 está no ar</b> e veja o resolvedor passar para ns2.');
    if (!P.perda) o.push('Marque <b>A primeira consulta se perde</b> e veja o tempo limite de 800 ms.');
    if (P.registro !== 'NXDOMAIN') o.push('Pergunte por um <b>nome que não existe</b> e veja o cache negativo na aba Cache.');
    o.push('Passe ao modo <b>DNSSEC</b> para ver como as respostas são autenticadas.');
  } else if (sub === 'sec') {
    if (P.validar) o.push('Desmarque <b>O resolvedor valida o DNSSEC</b> com a assinatura vencida e veja o erro passar sem aviso.');
    if (P.zona !== 'dsruim') o.push('Escolha <b>DS que não casa com a chave</b> e compare com a assinatura vencida na aba Cadeia.');
    if (P.zona !== 'insegura') o.push('Escolha <b>Sem DS no .com</b> e veja a cadeia terminar no .com.');
    if (P.zona !== 'nx') o.push('Escolha <b>nome que não existe</b> e veja a prova de inexistência (NSEC).');
    o.push('No modo <b>Envenenamento</b>, veja por que a validação é a defesa estrutural.');
  } else if (sub === 'env') {
    if (P.defesa === 'nenhuma') o.push('Escolha <b>Porta e ID aleatórios</b> e veja as respostas forjadas serem descartadas.');
    if (P.defesa !== 'dnssec') o.push('Escolha <b>Validação DNSSEC</b> com <b>palpite certo</b>: a assinatura vence a sorte.');
    if (!P.sorte) o.push('Marque <b>O atacante acerta porta e ID</b> com porta e ID aleatórios e veja que a probabilidade não é garantia.');
    if (P.defesa !== 'x20') o.push('Escolha <b>0x20</b> com o palpite certo e veja a caixa do nome impedir o ataque.');
  } else if (sub === 'amp') {
    if (P.resolvedor === 'aberto') o.push('Escolha <b>Fechado (ACL)</b> e compare o fator de amplificação.');
    if (!P.bcp38) o.push('Marque <b>O provedor filtra origem forjada</b> e veja a reflexão nem começar.');
    if (P.consulta === 'any') o.push('Troque o tipo para <b>A</b> e veja o ganho cair.');
    if (P.resolvedor !== 'rrl') o.push('Escolha <b>Limite de taxa</b> e veja a resposta truncada.');
  } else {
    if (P.transporte === 'udp') o.push('Escolha <b>DoT</b> ou <b>DoH</b> e veja o que o observador deixa de enxergar.');
    if (P.transporte !== 'dot') o.push('Escolha <b>DoT</b>, bloqueie a porta 853 e compare as políticas estrita e oportunista.');
    if (P.transporte === 'dot' && P.bloqueio) o.push(P.politica === 'estrita' ? 'Troque para a política <b>oportunista</b> e veja o rebaixamento.' : 'Troque para a política <b>estrita</b> e veja a falha fechada.');
    o.push('Pense: o resolvedor ainda vê todas as consultas. Quem deve ser o operador de confiança?');
  }
  return '<ul>' + o.slice(0, 4).map((t) => '<li>' + t + '</li>').join('') + '</ul>';
}

export function explain(tr: Trace, P: DnsParams): string {
  const R = tr.raw;
  if (!R || !R.steps) return '';
  const sub = R.sub as string;
  const steps = R.steps as Step[];
  const concepts = R.concepts as string[];
  let h = '<h3>Experimento: ' + ({ res: 'resolução de nomes', sec: 'validação com DNSSEC', env: 'envenenamento de cache', amp: 'reflexão e amplificação', priv: 'privacidade do DNS' } as Record<string, string>)[sub] + '</h3>';
  h += '<p><b>Objetivo.</b> ' + OBJ[sub] + '</p>';
  h += '<h3>Configuração</h3><p>' + setup({ sub, set: P as never } as unknown as ScenarioDef).replace(/^./, (c) => c.toUpperCase()) + '.</p>';
  h += '<h3>O que aconteceu</h3><ol>' + steps.map((s) => '<li>' + fmtTime(s.t) + ': ' + s.text + '</li>').join('') + '</ol>';
  if (sub === 'res') h += '<p>Total: <b>' + plural(R.queries, 'consulta', 'consultas') + '</b> do resolvedor a servidores da hierarquia e resposta ao cliente em <b>' + fmtTime(R.tEnd) + '</b>.</p>';
  if (sub === 'amp') h += '<p>O atacante enviou <b>' + R.sentB + ' bytes</b> e a vítima recebeu <b>' + R.recvB + ' bytes</b> (fator ' + (Math.round(R.fator * 10) / 10).toString().replace('.', ',') + 'x). Consulta de ' + R.reqLen + ' bytes; resposta completa de ' + R.respLen + ' bytes (tamanhos aproximados).</p>';
  if (sub === 'env') h += '<p>Resultado: cache <b>' + (R.poisoned ? 'envenenado' : 'preservado') + '</b>.</p>';
  if (concepts.length) h += '<h3>Conceitos observados</h3><ul>' + concepts.map((c) => '<li>' + c + '</li>').join('') + '</ul>';
  h += '<h3>Para explorar em seguida</h3>' + next(P, sub);
  return h;
}
