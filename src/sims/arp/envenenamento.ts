// Motor do modo envenenamento do cache ARP (nível defensivo: o mecanismo, o efeito e as defesas, sem roteiro de ataque).
// O ARP não autentica respostas: um host da mesma rede local pode declarar um IP no MAC dele e, se a vítima aceitar,
// passa a receber o tráfego destinado àquele IP (posição de intermediário). O simulador mostra:
//   o ataque e o que ele consegue ler (HTTP em claro ou HTTPS cifrado), em um ou nos dois sentidos;
//   as defesas: entradas estáticas, Dynamic ARP Inspection (DAI) no switch e monitoramento de mudança de MAC.
// Valores ilustrativos: nenhum tráfego real é gerado.
import { COLORS as C0, newTrace, type Column, type Field, type StateDef, type Trace } from '../../sim-core';
import { arpFrame, ethHeader, HOSTS, type NeighEvent, type NeighState } from './engine';

export interface EnvParams {
  rtt: number;
  attack: boolean;
  eboth: boolean;
  etraffic: 'http' | 'https';
  edefense: 'none' | 'static' | 'dai' | 'monitor';
}

export const SERVER = '192.0.2.50';
const fl = (...f: Field[]): Field[] => f;

export const ENV_COLS: Column[] = [
  { key: 'a', label: 'Host A', sub: 'vítima', addr: HOSTS.a.ip },
  { key: 'm', label: 'Host M', sub: 'host malicioso', addr: HOSTS.m.ip },
  { key: 'g', label: 'Gateway', sub: 'roteador', addr: HOSTS.g.ip },
];

export const ENV_STATES: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'ta', label: 'MAC do gateway na tabela de A' },
  { key: 'tg', label: 'MAC de A na tabela do gateway' },
  { key: 'path', label: 'Caminho do tráfego' },
  { key: 'seen', label: 'O que M consegue ler' },
];

export function buildEnvenenamento(P: EnvParams): Trace {
  const A = HOSTS.a;
  const G = HOSTS.g;
  const M = HOSTS.m;
  const tr = newTrace(ENV_COLS, ENV_STATES, P.rtt);
  const ow = tr.ow;
  const https = P.etraffic === 'https';
  const def = P.edefense;
  const neigh: NeighEvent[] = [];
  const R: Record<string, any> = { sub: 'env', t0: 0, attack: P.attack, both: P.eboth, traffic: P.etraffic, defense: def, neigh, poisonedA: false, poisonedG: false, seen: 'nada', result: '' };
  tr.raw = R;
  const ne = (host: 'a' | 'g', ip: string, mac: string, state: NeighState, t: number) => neigh.push({ host, ip, mac, state, t });
  const ev = (t: number, who: 'a' | 'm' | 'g', text: string, k = '') => tr.ev(t + 0.4, who, text, k);
  const stat = def === 'static';

  // ---- 1. situação normal ----
  const sA = stat ? 'PERMANENT' : 'REACHABLE';
  ne('a', G.ip, G.mac, sA, 0);
  ne('g', A.ip, A.mac, sA, 0);
  tr.phase('1. Situação normal', 'normal');
  tr.st(0, 'phase', 'normal', 'est');
  tr.st(0, 'ta', G.ip + ' → MAC do gateway' + (stat ? ' (estática)' : ''), 'est');
  tr.st(0, 'tg', A.ip + ' → MAC de A' + (stat ? ' (estática)' : ''), 'est');
  tr.st(0, 'path', 'A e gateway, direto', 'est');
  tr.st(0, 'seen', '-', 'closed');
  tr.mile(0, 'Normal', 'tabelas corretas');
  tr.ev(0, 'a', stat ? 'Entrada estática para o gateway' : 'Tabela correta: o gateway está no MAC do gateway', 'ok');
  tr.lg(0, 'Situação inicial: o host A conhece o MAC do gateway e o gateway conhece o de A' + (stat ? ' (entradas estáticas, configuradas pelo administrador).' : '.'), 'conn');
  tr.wait(ow / 2);

  // ---- 2. respostas ARP forjadas ----
  let poisonedA = false;
  let poisonedG = false;
  if (P.attack) {
    tr.phase('2. Respostas ARP forjadas', 'forge');
    tr.st(tr.t, 'phase', 'ataque', 'warn');
    tr.mile(tr.t, 'Ataque', 'respostas forjadas');
    const forged = (to: 'a' | 'g') => {
      const victim = HOSTS[to];
      const claimedIp = to === 'a' ? G.ip : A.ip;
      return arpFrame(tr, 'm', to, 2, {
        sha: M.mac, spa: claimedIp, tha: victim.mac, tpa: victim.ip, dmac: victim.mac, label: 'ARP Reply (forjada)', info: claimedIp + ' is at ' + M.mac + ' (não solicitada)',
        about: 'Resposta que ninguém pediu: M declara que ' + claimedIp + ' está no MAC dele. O ARP não autentica, e quem aceita a resposta passa a enviar a M o tráfego daquele IP.', bad: true, tags: ['forjada'],
        lost: def === 'dai',
      });
    };
    const f1 = forged('a');
    const f2 = P.eboth ? forged('g') : null;
    if (def === 'dai') {
      ev(f1.tArr, 'm', 'Descartada pelo switch (DAI)', 'ok');
      tr.st(f1.tArr, 'phase', 'bloqueado (DAI)', 'est');
      tr.lg(f1.tArr, 'O switch com DAI compara o par IP e MAC de cada resposta ARP com a tabela de DHCP snooping, vê que ' + G.ip + ' não pertence a ' + M.mac + ' e descarta o quadro. Nenhuma tabela é alterada.', 'conn');
      R.result = 'blocked-dai';
    } else if (stat) {
      ev(f1.tArr, 'a', 'Entrada estática: ignora a resposta', 'ok');
      if (f2) ev(f2.tArr, 'g', 'Entrada estática: ignora a resposta', 'ok');
      tr.st(f1.tArr, 'phase', 'ignorado (estática)', 'est');
      tr.lg(f1.tArr, 'Hosts com entrada estática (PERMANENT) não aceitam resposta ARP que a altere: as tabelas continuam corretas.', 'conn');
      R.result = 'blocked-static';
    } else {
      poisonedA = true;
      ne('a', G.ip, M.mac, 'REACHABLE', f1.tArr);
      ev(f1.tArr, 'a', 'Aceita: o gateway agora está no MAC de M', 'warn');
      tr.st(f1.tArr, 'ta', G.ip + ' → MAC de M (envenenada)', 'bad');
      tr.st(f1.tArr, 'phase', 'envenenado', 'bad');
      if (f2) {
        poisonedG = true;
        ne('g', A.ip, M.mac, 'REACHABLE', f2.tArr);
        ev(f2.tArr, 'g', 'Aceita: A agora está no MAC de M', 'warn');
        tr.st(f2.tArr, 'tg', A.ip + ' → MAC de M (envenenada)', 'bad');
      }
      tr.lg(f1.tArr, 'O host A aceita a resposta forjada e passa a enviar a M o que seria do gateway' + (f2 ? '; o gateway também é enganado e envia a M o que seria de A.' : ' (só o sentido de ida é desviado).'), 'loss');
      if (def === 'monitor') {
        const tAlert = (f2 ? f2.tArr : f1.tArr) + 0.4;
        tr.st(tAlert, 'seen', 'ALERTA: o MAC do gateway mudou', 'warn');
        ev(tAlert, 'a', 'Monitoramento: alerta, o MAC do gateway mudou', 'warn');
        tr.lg(tAlert, 'Uma ferramenta de monitoramento da tabela ARP registra que o MAC associado a ' + G.ip + ' mudou e gera um alerta. Ela detecta, mas não impede o desvio.', 'conn');
        R.alert = true;
      }
      R.result = 'poisoned';
    }
    tr.wait(ow / 2);
  }
  R.poisonedA = poisonedA;
  R.poisonedG = poisonedG;

  // ---- 3. tráfego da vítima ----
  tr.phase('3. Tráfego da vítima para o servidor', 'traffic');
  tr.st(tr.t, 'phase', poisonedA ? 'tráfego desviado' : 'tráfego', poisonedA ? 'bad' : 'warn');
  tr.mile(tr.t, 'Tráfego', https ? 'HTTPS' : 'HTTP');
  const kind = (req: boolean): Field[] =>
    https
      ? fl({ sec: 'TLS 1.3 (RFC 9846)' }, ['Registro', 'Application Data (cifrado)', 'o conteúdo só é legível nas pontas', 'expert'], ['Visível a quem captura', 'tamanho e momento dos registros', 'metadados, não o conteúdo'])
      : req
        ? fl({ sec: 'HTTP (RFC 9110)' }, ['Requisição', 'GET /notas HTTP/1.1', 'em texto puro'], ['Cookie', 'sessao=abc123 (ilustrativo)', 'em texto puro', 'expert'])
        : fl({ sec: 'HTTP (RFC 9110)' }, ['Resposta', '200 OK', 'em texto puro'], ['Corpo', 'notas do aluno (ilustrativo)', 'em texto puro', 'expert']);
  const data = (from: 'a' | 'm' | 'g', to: 'a' | 'm' | 'g', dmac: string, smac: string, req: boolean, forwarded = false) => {
    const label = (https ? 'TLS dados' : req ? 'HTTP GET' : 'HTTP 200') + (forwarded ? ' (repassado)' : '');
    return tr.add(from, to, {
      label, proto: https ? 'TLS' : 'HTTP', color: https ? C0.enc : C0.plain, enc: https, len: https ? 120 : 380, info: label,
      phaseName: 'Tráfego',
      fields: [...ethHeader(dmac, smac, '0x0800 (IPv4)'), ...fl({ sec: 'IPv4 (RFC 791)' }, ['Origem', req ? A.ip : SERVER, ''], ['Destino', req ? SERVER : A.ip, ''], ['Protocolo', '6 (TCP)', '']), ...kind(req)],
      about: forwarded
        ? 'M repassa o quadro ao destino verdadeiro, trocando só os endereços físicos. Por isso a vítima não percebe o desvio: a comunicação continua funcionando.'
        : to === 'm'
          ? 'O quadro sai com o MAC de destino que a tabela de ' + (from === 'a' ? 'A' : 'do gateway') + ' tem para o IP do ' + (from === 'a' ? 'gateway' : 'host A') + ': o de M.'
          : 'Quadro normal, com o MAC de destino correto.',
    });
  };
  // o texto fica numa linha própria, entre a chegada e o repasse, para não cobrir as setas
  const seeing = (arr: number, what: string) => tr.ev(arr + 0.2, 'm', what, https ? 'ok' : 'warn');
  const looks = https ? 'Vê só dados cifrados (TLS)' : 'Lê o conteúdo em texto puro';
  const readReq = !!poisonedA;
  const readResp = !!poisonedG;
  if (poisonedA) {
    tr.st(tr.t, 'path', P.eboth ? 'passa por M nos dois sentidos' : 'ida por M, volta direta', 'bad');
    const r1 = data('a', 'm', M.mac, A.mac, true);
    seeing(r1.tArr, looks);
    data('m', 'g', G.mac, M.mac, true, true);
    if (poisonedG) {
      const s1 = data('g', 'm', M.mac, G.mac, false);
      seeing(s1.tArr, looks);
      const s2 = data('m', 'a', A.mac, M.mac, false, true);
      tr.ev(s2.tArr, 'a', 'Resposta recebida: nada parece errado', 'warn');
    } else {
      const s1 = data('g', 'a', A.mac, G.mac, false);
      tr.ev(s1.tArr, 'a', 'Resposta recebida direto do gateway', '');
    }
  } else {
    tr.st(tr.t, 'path', 'A e gateway, direto', 'est');
    data('a', 'g', G.mac, A.mac, true);
    const s = data('g', 'a', A.mac, G.mac, false);
    tr.ev(s.tArr, 'a', 'Resposta recebida', 'ok');
  }
  const seen = !readReq ? 'nada' : https ? 'só dados cifrados' : readResp ? 'requisição e resposta em claro' : 'só a requisição em claro';
  R.seen = seen;
  R.readReq = readReq;
  R.readResp = readResp;
  if (poisonedA) {
    tr.st(tr.t, 'seen', seen, https ? 'est' : 'bad');
    tr.lg(tr.t, https ? 'M recebeu os quadros, mas o conteúdo está cifrado de ponta a ponta (TLS): ele vê apenas tamanhos e momentos, e poderia atrasar ou descartar o tráfego, mas não ler nem alterar o conteúdo sem ser detectado.' : 'M leu ' + (readResp ? 'a requisição e a resposta' : 'a requisição') + ' em texto puro, inclusive o cookie de sessão.', https ? 'conn' : 'loss');
  } else {
    tr.st(tr.t, 'seen', def === 'monitor' ? 'ALERTA: o MAC do gateway mudou' : '-', def === 'monitor' ? 'warn' : 'closed');
  }
  tr.st(tr.t, 'phase', poisonedA ? (https ? 'protegido pelo TLS' : 'interceptado') : 'concluído', poisonedA ? (https ? 'est' : 'bad') : 'est');
  tr.mile(tr.t, poisonedA ? (https ? 'Protegido (TLS)' : 'Interceptado') : 'Concluído', poisonedA ? 'M no meio do caminho' : 'sem desvio');
  R.tEnd = tr.t;
  return tr;
}
