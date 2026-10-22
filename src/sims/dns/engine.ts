// Motor do DNS (RFC 1034, RFC 1035, RFC 2308, RFC 6891, RFC 7766) e do DNSSEC (RFC 4033, RFC 4034, RFC 4035, RFC 8914), com os
// ataques e as defesas mais estudados (envenenamento de cache, RFC 5452 e RFC 7873; reflexão e amplificação, BCP 38; DoT, RFC 7858;
// DoH, RFC 8484). Função pura: dados os parâmetros, devolve o Trace.
// Modelo didático: nomes e endereços são de documentação (example.com, RFC 5737 e RFC 3849); as chaves, os resumos (digests)
// e as assinaturas são valores ilustrativos, sem criptografia real; os tamanhos das mensagens são aproximados; o resolvedor
// não faz minimização de nome (RFC 9156) e a raiz e o .com aparecem com um único servidor cada.
import { COLORS as C0, b64, h32, hex, newTrace, type Column, type Field, type Message, type StateDef, type Trace } from '../../sim-core';

export type Registro = 'A' | 'AAAA' | 'MX' | 'TXT' | 'CNAME' | 'NXDOMAIN';

export interface DnsParams {
  registro: Registro;
  cache: 'vazio' | 'tld' | 'ns' | 'completo';
  perda: boolean;
  ns1: boolean;
  tcp: boolean;
  zona: 'ok' | 'insegura' | 'expirada' | 'dsruim' | 'nx';
  validar: boolean;
  defesa: 'nenhuma' | 'aleatoria' | 'x20' | 'dnssec';
  sorte: boolean;
  resolvedor: 'aberto' | 'acl' | 'rrl';
  bcp38: boolean;
  consulta: 'any' | 'a';
  transporte: 'udp' | 'dot' | 'doh';
  bloqueio: boolean;
  politica: 'estrita' | 'oportunista';
}

export const IPS: Record<string, string> = {
  cl: '192.168.1.10',
  rs: '203.0.113.53',
  rt: '198.51.100.1',
  tl: '198.51.100.2',
  au: '192.0.2.53',
  a2: '192.0.2.54',
  at: '198.51.100.66',
  vi: '192.0.2.200',
  ob: '-',
};
export const ATK_ANSWER = '198.51.100.66';
export const TIMEOUT = 800;

export const STATES: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'srv', label: 'Último servidor consultado' },
  { key: 'cache', label: 'Cache do resolvedor' },
  { key: 'ans', label: 'Resposta ao cliente' },
];

export interface RR { n: string; t: string; ttl: number; d: string }
export interface DnsMsg {
  id: number;
  qr: 0 | 1;
  aa?: boolean;
  tc?: boolean;
  rd?: boolean;
  ra?: boolean;
  ad?: boolean;
  cd?: boolean;
  edns?: boolean;
  dok?: boolean;
  rcode?: number;
  q: [string, string];
  an?: RR[];
  ns?: RR[];
  ar?: RR[];
}
export interface CacheEv { t: number; op: 'set' | 'del'; key: string; n: string; ty: string; d: string; ttl: number; src: string; bad?: boolean; neg?: boolean }
export interface Step { t: number; text: string }
export interface ChainRow { zona: string; passo: string; estado: 'ok' | 'falhou' | 'sem-ds' | 'nao-verificado' }

const RCODES = ['NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED'];
export const rcodeName = (n: number) => RCODES[n] || String(n);

/** Tempo simulado em ms ou s. */
export function fmtTime(ms: number): string {
  const f = (v: number) => (Math.round(v * 10) / 10).toString().replace('.', ',');
  return ms < 1000 ? f(ms) + 'ms' : f(ms / 1000) + 's';
}

const rrSize = (r: RR): number => 12 + (r.t === 'RRSIG' ? 96 : r.t === 'DNSKEY' ? 70 : r.t === 'DS' ? 36 : r.t === 'NSEC' ? 40 : Math.ceil(r.d.length * 0.6));
/** Tamanho aproximado do datagrama (IP e UDP incluídos). */
export function sizeOf(m: DnsMsg): number {
  const all = [...(m.an || []), ...(m.ns || []), ...(m.ar || [])];
  return 28 + 12 + m.q[0].length + 6 + (m.edns ? 11 : 0) + all.reduce((s, r) => s + rrSize(r), 0);
}

export function flagsText(m: DnsMsg): string {
  const f: string[] = [m.qr ? 'QR' : ''];
  if (m.aa) f.push('AA');
  if (m.tc) f.push('TC');
  if (m.rd) f.push('RD');
  if (m.ra) f.push('RA');
  if (m.ad) f.push('AD');
  if (m.cd) f.push('CD');
  return f.filter(Boolean).join(' ') || '-';
}

interface Ends { src: string; dst: string; sport: number; dport: number; tcp?: boolean; plain?: boolean }

export function dnsFields(m: DnsMsg, e: Ends): Field[] {
  const f: Field[] = [];
  if (!e.plain) f.push({ sec: 'IP e ' + (e.tcp ? 'TCP' : 'UDP') }, ['Origem', e.src + ':' + e.sport, 'endereço e porta de quem envia'], ['Destino', e.dst + ':' + e.dport, e.dport === 53 ? 'porta 53: servidor DNS' : 'porta de origem da consulta']);
  const meaning: Record<string, string> = {
    QR: m.qr ? 'é uma resposta' : 'é uma consulta',
    AA: 'resposta autoritativa (vem do dono da zona)',
    TC: 'resposta truncada: refaça a consulta por TCP',
    RD: 'recursão desejada: o cliente pede que o servidor resolva por ele',
    RA: 'recursão disponível neste servidor',
    AD: 'dados autenticados: o resolvedor validou o DNSSEC',
    CD: 'validação desligada nesta consulta',
  };
  const on = flagsText(m).split(' ').filter((x) => x !== '-');
  f.push(
    { sec: 'Cabeçalho DNS (RFC 1035)' },
    ['ID', '0x' + m.id.toString(16).padStart(4, '0'), 'casa a resposta com a consulta'],
    ['Flags', on.join(' ') || '-', on.map((x) => x + ': ' + meaning[x]).join('; ')],
    ['RCODE', m.rcode ?? 0 ? (m.rcode ?? 0) + ' (' + rcodeName(m.rcode ?? 0) + ')' : '0 (NOERROR)', ''],
    ['Contagens', 'QD=1 AN=' + (m.an?.length || 0) + ' NS=' + (m.ns?.length || 0) + ' AR=' + (m.ar?.length || 0), 'pergunta, resposta, autoridade e adicional'],
  );
  if (m.edns) f.push({ sec: 'EDNS(0) (RFC 6891)' }, ['Tamanho UDP', '1232', 'maior datagrama que o remetente aceita'], ['DO', m.dok ? '1' : '0', m.dok ? 'DNSSEC OK: quer RRSIG, DNSKEY, DS e NSEC na resposta' : 'não pede dados DNSSEC']);
  f.push({ sec: 'Pergunta' }, [m.q[0], 'IN ' + m.q[1], 'nome e tipo consultados']);
  const sect = (title: string, rrs?: RR[]) => {
    if (!rrs || !rrs.length) return;
    f.push({ sec: title });
    rrs.forEach((r) => f.push([r.n, r.t + ' ' + r.d, 'TTL ' + r.ttl + ' s']));
  };
  sect('Resposta', m.an);
  sect('Autoridade', m.ns);
  sect('Adicional', m.ar);
  return f;
}

// ---------------------------------------------------------------------------------------------------------------------
// Dados das zonas
// ---------------------------------------------------------------------------------------------------------------------

const SOA: RR = { n: 'example.com', t: 'SOA', ttl: 3600, d: 'ns1.example.com. hostmaster.example.com. 2026102201 7200 3600 1209600 3600' };
const WWW_A: RR = { n: 'www.example.com', t: 'A', ttl: 300, d: '192.0.2.80' };

export interface Resposta { qname: string; qtype: string; an: RR[]; ns: RR[]; ar: RR[]; rcode: number }

export function respostaDe(reg: Registro): Resposta {
  switch (reg) {
    case 'AAAA': return { qname: 'www.example.com', qtype: 'AAAA', an: [{ n: 'www.example.com', t: 'AAAA', ttl: 300, d: '2001:db8::80' }], ns: [], ar: [], rcode: 0 };
    case 'MX': return { qname: 'example.com', qtype: 'MX', an: [{ n: 'example.com', t: 'MX', ttl: 3600, d: '10 mail.example.com' }], ns: [], ar: [{ n: 'mail.example.com', t: 'A', ttl: 3600, d: '192.0.2.25' }], rcode: 0 };
    case 'TXT': return { qname: 'example.com', qtype: 'TXT', an: [{ n: 'example.com', t: 'TXT', ttl: 3600, d: '"v=spf1 ip4:192.0.2.0/24 -all"' }], ns: [], ar: [], rcode: 0 };
    case 'CNAME': return { qname: 'blog.example.com', qtype: 'A', an: [{ n: 'blog.example.com', t: 'CNAME', ttl: 300, d: 'www.example.com' }, WWW_A], ns: [], ar: [], rcode: 0 };
    case 'NXDOMAIN': return { qname: 'nao-existe.example.com', qtype: 'A', an: [], ns: [SOA], ar: [], rcode: 3 };
    default: return { qname: 'www.example.com', qtype: 'A', an: [WWW_A], ns: [], ar: [], rcode: 0 };
  }
}

const REF_ROOT: { ns: RR[]; ar: RR[] } = {
  ns: [{ n: 'com', t: 'NS', ttl: 172800, d: 'a.gtld-servers.net' }],
  ar: [{ n: 'a.gtld-servers.net', t: 'A', ttl: 172800, d: IPS.tl }],
};
const REF_TLD: { ns: RR[]; ar: RR[] } = {
  ns: [{ n: 'example.com', t: 'NS', ttl: 172800, d: 'ns1.example.com' }, { n: 'example.com', t: 'NS', ttl: 172800, d: 'ns2.example.com' }],
  ar: [{ n: 'ns1.example.com', t: 'A', ttl: 172800, d: IPS.au }, { n: 'ns2.example.com', t: 'A', ttl: 172800, d: IPS.a2 }],
};

// Material DNSSEC ilustrativo (algoritmo 13, ECDSA P-256; resumo SHA-256)
export const keyTag = (z: string, k: 'ksk' | 'zsk'): number => 1000 + (h32(z + k, 3) % 60000);
export const dsDigest = (z: string): string => hex('ds' + z, 16).toUpperCase();
export const dnskeyRR = (z: string, k: 'ksk' | 'zsk'): RR => ({ n: z, t: 'DNSKEY', ttl: 3600, d: (k === 'ksk' ? '257' : '256') + ' 3 13 ' + b64(z + k, 20) + '... (tag ' + keyTag(z, k) + ')' });
export const dsRR = (z: string, bad = false): RR => ({ n: z, t: 'DS', ttl: 86400, d: keyTag(z, 'ksk') + ' 13 2 ' + (bad ? dsDigest(z + 'antiga') : dsDigest(z)).slice(0, 24) + '...' });
export const rrsigRR = (n: string, covered: string, signer: string, k: 'ksk' | 'zsk', expired = false): RR => ({
  n,
  t: 'RRSIG',
  ttl: 300,
  d: covered + ' 13 ' + (n === '.' ? 0 : n.split('.').length) + ' 300 ' + (expired ? '20260930000000' : '20261031000000') + ' 20260901000000 ' + keyTag(signer, k) + ' ' + signer + ' ' + b64(n + covered + signer + (expired ? 'x' : ''), 14) + '...',
});

// ---------------------------------------------------------------------------------------------------------------------
// Ferramentas comuns aos modos
// ---------------------------------------------------------------------------------------------------------------------

const hopMs = (a: string, b: string): number => {
  const far = a === 'cl' || a === 'rs' ? b : a;
  return ({ cl: 1, rs: 1, rt: 12, tl: 15, au: 20, a2: 22, at: 5, vi: 8, ob: 1 } as Record<string, number>)[far] ?? 10;
};

interface SendO {
  label: string;
  info: string;
  about: string;
  m: DnsMsg;
  color?: string;
  lost?: boolean;
  par?: boolean;
  at?: number;
  dur?: number;
  sport?: number;
  dport?: number;
  srcIp?: string;
  tcp?: boolean;
  tags?: string[];
  len?: number;
  enc?: boolean;
  plain?: boolean;
  extra?: Field[];
  phaseName?: string;
}

function kit(tr: Trace) {
  let seq = 0;
  const nid = (): number => h32('dns-id-' + seq++, 11) & 0xffff;
  const send = (from: string, to: string, o: SendO): Message => {
    const qry = o.m.qr === 0;
    const sport = o.sport ?? (qry ? 1024 + (h32('sp' + o.m.id, 5) % 60000) : 53);
    const dport = o.dport ?? (qry ? 53 : 40000);
    const fields = [...dnsFields(o.m, { src: IPS[o.srcIp ?? from], dst: IPS[to], sport, dport, tcp: o.tcp, plain: o.plain }), ...(o.extra || [])];
    return tr.add(from, to, {
      label: o.label,
      info: o.info,
      about: o.about,
      proto: o.tcp ? 'DNS/TCP' : 'DNS',
      color: o.color ?? (o.enc ? C0.enc : qry ? C0.plain : C0.data),
      len: o.len ?? sizeOf(o.m),
      lost: !!o.lost,
      par: !!o.par,
      at: o.at,
      dur: o.dur ?? hopMs(from, to),
      enc: !!o.enc,
      tags: o.tags || [],
      fields,
      sport,
      dport,
      phaseName: o.phaseName ?? (qry ? 'Consulta' : 'Resposta'),
    });
  };
  const seg = (from: string, to: string, label: string, flags: string, about: string, o: { dur?: number; lost?: boolean; tags?: string[] } = {}): Message =>
    tr.add(from, to, {
      label,
      info: label + ' ' + IPS[from] + ' > ' + IPS[to],
      about,
      proto: 'TCP',
      color: o.lost ? C0.bad : C0.tcp,
      len: 60,
      lost: !!o.lost,
      dur: o.dur ?? hopMs(from, to),
      tags: o.tags || [],
      phaseName: 'TCP',
      fields: [{ sec: 'TCP (RFC 9293)' }, ['Flags', flags, ''], ['Origem', IPS[from], ''], ['Destino', IPS[to], '']],
    });
  return { nid, send, seg };
}

const q1 = (id: number, name: string, type: string, o: Partial<DnsMsg> = {}): DnsMsg => ({ id, qr: 0, rd: false, edns: true, q: [name, type], ...o });

function newRaw(tr: Trace, sub: string, P: DnsParams) {
  const R: Record<string, any> = { sub, P, steps: [], concepts: [], cacheEv: [], chain: [], queries: 0, tEnd: 0 };
  tr.raw = R;
  const step = (t: number, text: string) => (R.steps as Step[]).push({ t, text });
  const concept = (c: string) => {
    if (!(R.concepts as string[]).includes(c)) R.concepts.push(c);
  };
  const cache = (t: number, rr: RR, src: string, o: { bad?: boolean; neg?: boolean } = {}) =>
    (R.cacheEv as CacheEv[]).push({ t, op: 'set', key: rr.n + '|' + rr.t + (o.neg ? '|neg' : ''), n: rr.n, ty: o.neg ? 'NXDOMAIN' : rr.t, d: rr.d, ttl: rr.ttl, src, bad: o.bad, neg: o.neg });
  return { R, step, concept, cache };
}

const colCl: Column = { key: 'cl', label: 'Cliente', sub: 'stub resolver', addr: IPS.cl };
const colRs: Column = { key: 'rs', label: 'Resolvedor', sub: 'recursivo', addr: IPS.rs };
const colRt: Column = { key: 'rt', label: 'Raiz', sub: 'a.root-servers.net', addr: IPS.rt };
const colTl: Column = { key: 'tl', label: '.com', sub: 'a.gtld-servers.net', addr: IPS.tl };
const colAu: Column = { key: 'au', label: 'ns1', sub: 'autoritativo de example.com', addr: IPS.au };
const colA2: Column = { key: 'a2', label: 'ns2', sub: 'autoritativo (secundário)', addr: IPS.a2 };

// ---------------------------------------------------------------------------------------------------------------------
// Modo 'res': resolução recursiva e iterativa
// ---------------------------------------------------------------------------------------------------------------------

export function buildRes(P: DnsParams): Trace {
  const A = respostaDe(P.registro);
  const nx = A.rcode === 3;
  const tr = newTrace([colCl, colRs, colRt, colTl, colAu, ...(P.ns1 ? [] : [colA2])], STATES);
  const { nid, send, seg } = kit(tr);
  const { R, step, concept, cache } = newRaw(tr, 'res', P);
  const key = A.qname + ' ' + A.qtype;
  const ansRemaining = (r: RR) => Math.max(1, Math.round(r.ttl / 2));

  // cache inicial
  if (P.cache !== 'vazio') cache(0, REF_ROOT.ns[0], 'consulta anterior');
  if (P.cache === 'ns' || P.cache === 'completo') REF_TLD.ns.forEach((r) => cache(0, r, 'consulta anterior'));
  if (P.cache === 'completo') (nx ? [] : A.an).forEach((r) => cache(0, { ...r, ttl: ansRemaining(r) }, 'consulta anterior'));
  if (P.cache === 'completo' && nx) cache(0, { n: A.qname, t: 'A', ttl: 1800, d: 'NXDOMAIN (cache negativo)' }, 'consulta anterior', { neg: true });
  tr.st(0, 'cache', P.cache === 'vazio' ? 'vazio' : P.cache === 'tld' ? 'delegação do .com' : P.cache === 'ns' ? 'delegações do .com e do domínio' : 'inclui a resposta', P.cache === 'completo' ? 'est' : 'closed');
  tr.st(0, 'srv', '-', 'closed');
  tr.st(0, 'ans', 'aguardando', 'warn');

  // 1. cliente pergunta ao resolvedor
  tr.phase('1. Consulta do cliente', 'cli');
  tr.st(0, 'phase', 'consulta', 'warn');
  tr.mile(0, 'Consulta', key);
  const id0 = nid();
  const qc = send('cl', 'rs', {
    label: A.qtype + ' ' + A.qname,
    info: 'Standard query 0x' + id0.toString(16) + ' ' + A.qtype + ' ' + A.qname,
    about: 'O cliente (stub resolver) não percorre a hierarquia: faz uma única pergunta ao resolvedor recursivo, com RD=1 ("resolva por mim"). Quem conhece a rede do cliente é o resolvedor, em geral o do provedor ou o da empresa.',
    m: q1(id0, A.qname, A.qtype, { rd: true }),
  });
  tr.ev(0, 'cl', 'Precisa de ' + A.qtype + ' de ' + A.qname, '');
  tr.lg(0, 'Cliente pergunta ' + A.qtype + ' ' + A.qname + ' ao resolvedor ' + IPS.rs + '.', 'conn');
  step(0, 'O cliente enviou ao resolvedor a consulta <b>' + A.qtype + ' ' + A.qname + '</b> com RD=1 (recursão desejada).');
  concept('Resolvedor recursivo e servidor autoritativo são papéis diferentes: o primeiro pesquisa, o segundo responde pelas zonas que possui.');

  // 2. cache
  if (P.cache === 'completo') {
    R.cacheHit = true;
    tr.ev(qc.tArr, 'rs', 'Acerto no cache: responde sem consultar ninguém', 'ok');
    tr.lg(qc.tArr, 'Resolvedor: ' + key + ' está no cache (TTL restante ' + (nx ? 1800 : ansRemaining(A.an[0])) + ' s).', 'conn');
    tr.phase('2. Resposta do cache', 'cache');
    tr.st(tr.t, 'phase', 'cache', 'est');
    const an = nx ? [] : A.an.map((r) => ({ ...r, ttl: ansRemaining(r) }));
    const rep = send('rs', 'cl', {
      label: nx ? 'NXDOMAIN (cache)' : 'Resposta (cache)',
      info: 'Standard query response 0x' + id0.toString(16) + ' ' + (nx ? 'No such name' : A.an.map((r) => r.t + ' ' + r.d).join(', ')),
      about: 'O resolvedor tinha a resposta guardada e o TTL ainda não acabou: responde na hora. Repare que o TTL na resposta é o que restava, não o original. AA não vem marcado, porque quem responde não é o dono da zona.',
      m: { id: id0, qr: 1, rd: true, ra: true, edns: true, q: [A.qname, A.qtype], an, ns: nx ? [SOA] : [], rcode: A.rcode },
      dport: qc.sport as number,
    });
    tr.st(rep.tArr, 'ans', nx ? 'NXDOMAIN (do cache)' : 'resposta do cache', 'est');
    tr.st(rep.tArr, 'phase', 'concluído', 'est');
    tr.mile(rep.tArr, 'Resposta', 'do cache');
    tr.ev(rep.tArr, 'cl', nx ? 'Recebeu NXDOMAIN' : 'Recebeu ' + A.an[A.an.length - 1].d, 'ok');
    tr.lg(rep.tArr, 'Cliente recebeu a resposta do cache em ' + fmtTime(rep.tArr) + ', sem nenhuma consulta à Internet.', 'conn');
    step(qc.tArr, 'O resolvedor encontrou ' + (nx ? 'a negação' : 'a resposta') + ' no cache e respondeu sem consultar ninguém. Nenhum servidor da hierarquia foi incomodado.');
    concept('O cache reduz latência e carga: a resposta sai em ' + fmtTime(rep.tArr) + ' em vez de passar pela raiz, pelo .com e pelo autoritativo.');
    concept('O TTL define por quanto tempo uma resposta pode ser reutilizada.');
    R.queries = 0;
    R.tEnd = rep.tArr;
    return tr;
  }

  tr.phase('2. Resolução iterativa', 'iter');
  tr.st(qc.tArr, 'phase', 'iterando', 'warn');
  tr.ev(qc.tArr, 'rs', 'Cache sem resposta: começa a iterar', 'warn');
  const iter = (to: string, name: string): { q: Message; id: number } => {
    const id = nid();
    const q = send('rs', to, {
      label: A.qtype + ' ' + A.qname,
      info: 'Standard query 0x' + id.toString(16) + ' ' + A.qtype + ' ' + A.qname + ' (RD=0)',
      about: 'O resolvedor pergunta a ' + name + ' sem pedir recursão (RD=0): servidores da hierarquia só respondem pelo que sabem, e o resolvedor segue as indicações.',
      m: q1(id, A.qname, A.qtype),
    });
    R.queries++;
    tr.st(q.tSend, 'srv', name, 'warn');
    return { q, id };
  };

  if (P.cache === 'vazio') {
    const { q, id } = iter('rt', 'a raiz');
    tr.lg(q.tSend, 'Resolvedor consulta a raiz (' + IPS.rt + '): quem cuida de .com?', 'conn');
    const r = send('rt', 'rs', {
      label: 'Referral para .com',
      info: 'Standard query response 0x' + id.toString(16) + ' NS com',
      about: 'A raiz não conhece www.example.com, mas sabe quem cuida do .com. Responde com uma <b>delegação</b> (referral): registros NS na seção Autoridade e o endereço do servidor (glue) na seção Adicional. Sem AA: não é uma resposta autoritativa sobre o nome.',
      m: { id, qr: 1, edns: true, q: [A.qname, A.qtype], ns: REF_ROOT.ns, ar: REF_ROOT.ar },
      dport: q.sport as number,
    });
    REF_ROOT.ns.forEach((x) => cache(r.tArr, x, 'raiz'));
    tr.ev(r.tArr, 'rs', 'Guarda a delegação do .com (TTL 2 dias)', 'ok');
    tr.mile(r.tArr, 'Raiz', 'delegação do .com');
    step(r.tArr, 'A <b>raiz</b> indicou os servidores do <b>.com</b> (referral com NS e glue). O resolvedor guardou a delegação por 172800 s.');
    concept('A hierarquia é percorrida de cima para baixo: raiz, TLD e servidor autoritativo do domínio.');
    concept('Delegação (NS) e glue (A do servidor de nomes) evitam a dependência circular: para achar ns1.example.com não dá para perguntar a ele mesmo.');
  }
  if (P.cache === 'vazio' || P.cache === 'tld') {
    if (P.cache === 'tld') tr.lg(tr.t, 'Delegação do .com já está no cache: a raiz não é consultada.', 'sys');
    const { q, id } = iter('tl', 'o .com');
    tr.lg(q.tSend, 'Resolvedor consulta o servidor do .com (' + IPS.tl + ').', 'conn');
    const r = send('tl', 'rs', {
      label: 'Referral para example.com',
      info: 'Standard query response 0x' + id.toString(16) + ' NS example.com',
      about: 'O servidor do .com sabe quais são os servidores de nomes de example.com e devolve outra delegação, agora com dois NS (ns1 e ns2) e o endereço de cada um.',
      m: { id, qr: 1, edns: true, q: [A.qname, A.qtype], ns: REF_TLD.ns, ar: REF_TLD.ar },
      dport: q.sport as number,
    });
    REF_TLD.ns.forEach((x) => cache(r.tArr, x, '.com'));
    tr.ev(r.tArr, 'rs', 'Guarda a delegação de example.com', 'ok');
    tr.mile(r.tArr, '.com', 'delegação do domínio');
    step(r.tArr, 'O <b>.com</b> indicou ns1.example.com e ns2.example.com como servidores do domínio.');
  }
  if (P.cache === 'ns') {
    tr.lg(tr.t, 'Delegação de example.com já está no cache: o resolvedor vai direto ao autoritativo.', 'sys');
    step(tr.t, 'As delegações já estavam no cache: o resolvedor <b>foi direto ao autoritativo</b>, sem passar pela raiz nem pelo .com.');
    concept('Quase toda consulta real pula a raiz e o TLD, porque as delegações têm TTL longo e ficam no cache.');
  }

  // 3. servidor autoritativo
  tr.phase('3. Servidor autoritativo', 'auth');
  tr.st(tr.t, 'phase', 'autoritativo', 'warn');
  let resp: 'au' | 'a2' = 'au';
  if (!P.ns1) {
    const idx = nid();
    const lostQ = send('rs', 'au', {
      label: A.qtype + ' ' + A.qname,
      info: 'Standard query 0x' + idx.toString(16) + ' ' + A.qtype + ' ' + A.qname + ' (sem resposta)',
      about: 'O primeiro servidor da lista (ns1) está fora do ar: a consulta não obtém resposta.',
      m: q1(idx, A.qname, A.qtype),
      lost: true,
      color: C0.bad,
      tags: ['sem resposta'],
    });
    R.queries++;
    R.failover = true;
    tr.lg(lostQ.tSend, 'ns1 (' + IPS.au + ') não responde. Esperando ' + TIMEOUT + ' ms.', 'loss');
    tr.ev(lostQ.tArr, 'rs', 'Sem resposta de ns1: tenta ns2 após ' + TIMEOUT + ' ms', 'warn');
    tr.wait(TIMEOUT);
    resp = 'a2';
    step(lostQ.tArr, 'ns1 não respondeu. Passados ' + TIMEOUT + ' ms, o resolvedor tentou o <b>segundo servidor de nomes (ns2)</b>.');
    concept('Todo domínio deve ter pelo menos dois servidores autoritativos: um deles pode falhar sem derrubar o domínio.');
  }
  const rn = resp === 'au' ? 'ns1' : 'ns2';
  if (P.perda) {
    const idp = nid();
    const lost1 = send('rs', resp, {
      label: A.qtype + ' ' + A.qname,
      info: 'Standard query 0x' + idp.toString(16) + ' ' + A.qtype + ' ' + A.qname + ' (perdida)',
      about: 'A consulta foi perdida no caminho (o DNS sobre UDP não retransmite sozinho: quem consulta controla o tempo limite).',
      m: q1(idp, A.qname, A.qtype),
      lost: true,
      color: C0.bad,
      tags: ['perdida'],
    });
    R.queries++;
    R.retries = 1;
    tr.lg(lost1.tSend, 'Consulta a ' + rn + ' perdida. Retransmite em ' + TIMEOUT + ' ms.', 'loss');
    tr.ev(lost1.tArr, 'rs', 'Consulta perdida: retransmite', 'warn');
    tr.wait(TIMEOUT);
    step(lost1.tArr, 'A primeira consulta a ' + rn + ' se perdeu. O resolvedor esperou ' + TIMEOUT + ' ms e <b>retransmitiu</b>.');
    concept('O UDP não garante entrega: o resolvedor decide o tempo limite e a retransmissão.');
  }
  const { q, id } = iter(resp, rn + ' (autoritativo)');
  tr.lg(q.tSend, 'Resolvedor consulta ' + rn + ' (' + IPS[resp] + ').', 'conn');
  const answer: DnsMsg = { id, qr: 1, aa: true, edns: true, q: [A.qname, A.qtype], an: A.an, ns: A.ns, ar: A.ar, rcode: A.rcode };
  const lblAns = nx ? 'NXDOMAIN' : 'Resposta autoritativa';
  const infoAns = 'Standard query response 0x' + id.toString(16) + ' ' + (nx ? 'No such name' : A.an.map((r) => r.t + ' ' + r.d).join(', '));
  const aboutAns = nx
    ? 'O servidor é autoritativo (AA=1) e afirma que o nome não existe: RCODE 3 (NXDOMAIN). A seção Autoridade traz o SOA, cujo campo "minimum" define por quanto tempo essa negação pode ser guardada (RFC 2308).'
    : 'Agora sim, o dono da zona responde (AA=1). Cada registro vem com seu TTL: é o prazo que o resolvedor tem para reutilizá-lo.';
  let finalReply: Message;
  if (P.tcp) {
    const big: DnsMsg = { ...answer, tc: true, an: [], ns: [], ar: [] };
    const tcMsg = send(resp, 'rs', {
      label: 'Truncada (TC=1)',
      info: 'Standard query response 0x' + id.toString(16) + ' (truncated)',
      about: 'A resposta completa não cabe num datagrama UDP. O servidor devolve só o cabeçalho com TC=1 ("truncada"), para o resolvedor repetir a pergunta por TCP (RFC 7766).',
      m: big,
      dport: q.sport as number,
      color: C0.plain,
      tags: ['TC=1'],
    });
    R.truncated = true;
    tr.lg(tcMsg.tArr, 'Resposta truncada (TC=1): o resolvedor repete a consulta por TCP.', 'sys');
    tr.ev(tcMsg.tArr, 'rs', 'TC=1: abre conexão TCP', 'warn');
    seg('rs', resp, 'SYN', 'SYN', 'O resolvedor abre uma conexão TCP com a porta 53 do servidor.');
    seg(resp, 'rs', 'SYN+ACK', 'SYN ACK', 'O servidor aceita a conexão.');
    const idt = nid();
    const qt = send('rs', resp, {
      label: A.qtype + ' ' + A.qname + ' (TCP)',
      info: 'Standard query 0x' + idt.toString(16) + ' ' + A.qtype + ' ' + A.qname + ' (TCP)',
      about: 'A mesma pergunta, agora por TCP (o ACK final do handshake vai junto). No TCP, as mensagens DNS levam 2 bytes de tamanho à frente.',
      m: q1(idt, A.qname, A.qtype),
      tcp: true,
    });
    R.queries++;
    finalReply = send(resp, 'rs', {
      label: lblAns + ' (TCP)',
      info: infoAns + ' (TCP)',
      about: aboutAns + ' Por TCP não há limite de tamanho de datagrama.',
      m: { ...answer, id: idt },
      tcp: true,
      dport: qt.sport as number,
    });
    step(tcMsg.tArr, 'A resposta não coube no UDP: veio com <b>TC=1</b> e o resolvedor repetiu a consulta por <b>TCP</b> (SYN, SYN+ACK, consulta e resposta).');
    concept('O DNS usa UDP por padrão e TCP quando a resposta é grande (TC=1) e nas transferências de zona.');
  } else {
    finalReply = send(resp, 'rs', { label: lblAns, info: infoAns, about: aboutAns, m: answer, dport: q.sport as number });
  }
  tr.mile(finalReply.tArr, 'Autoritativo', nx ? 'NXDOMAIN' : 'resposta final');
  tr.ev(finalReply.tArr, 'rs', nx ? 'Recebe NXDOMAIN e guarda a negação' : 'Recebe a resposta e guarda no cache', 'ok');
  step(finalReply.tArr, nx ? '<b>' + rn + '</b> respondeu NXDOMAIN com o SOA; o resolvedor guardou a <b>negação por ' + SOA.ttl + ' s</b> (cache negativo).' : '<b>' + rn + '</b> respondeu com autoridade: ' + A.an.map((r) => '<code>' + r.n + ' ' + r.t + ' ' + r.d + '</code> (TTL ' + r.ttl + ' s)').join('; ') + '.');
  if (nx) {
    cache(finalReply.tArr, { n: A.qname, t: 'A', ttl: SOA.ttl, d: 'NXDOMAIN (cache negativo)' }, rn, { neg: true });
    concept('Cache negativo (RFC 2308): até a inexistência de um nome é guardada, pelo TTL do SOA.');
  } else {
    [...A.an, ...A.ar].forEach((r) => cache(finalReply.tArr, r, rn));
  }
  if (P.registro === 'CNAME') concept('CNAME é um apelido: a resposta traz o alias e o registro final, e o resolvedor segue a cadeia.');
  if (P.registro === 'MX') concept('A resposta de MX traz o endereço do servidor de e-mail na seção Adicional, poupando uma consulta.');
  if (P.registro === 'TXT') concept('TXT guarda texto livre; é usado por SPF, DKIM e DMARC para segurança de e-mail.');
  if (P.registro === 'AAAA') concept('AAAA responde com o endereço IPv6; o tipo da consulta decide qual registro vem.');

  // 4. resposta ao cliente
  tr.phase('4. Resposta ao cliente', 'resp');
  tr.st(finalReply.tArr, 'phase', 'respondendo', 'warn');
  tr.st(finalReply.tArr, 'cache', (nx ? 'negação' : 'resposta') + ' guardada (TTL ' + (nx ? SOA.ttl : A.an[0].ttl) + ' s)', 'est');
  const rep = send('rs', 'cl', {
    label: nx ? 'NXDOMAIN' : 'Resposta',
    info: 'Standard query response 0x' + id0.toString(16) + ' ' + (nx ? 'No such name' : A.an.map((r) => r.t + ' ' + r.d).join(', ')),
    about: 'O resolvedor entrega o resultado ao cliente. RA=1 informa que a recursão está disponível; AA não vem marcado, porque quem respondeu foi o resolvedor. Os próximos clientes que perguntarem a mesma coisa serão atendidos pelo cache.',
    m: { id: id0, qr: 1, rd: true, ra: true, edns: true, q: [A.qname, A.qtype], an: A.an, ns: A.ns, ar: [], rcode: A.rcode },
    dport: qc.sport as number,
  });
  tr.st(rep.tArr, 'ans', nx ? 'NXDOMAIN' : A.an[A.an.length - 1].d, nx ? 'warn' : 'est');
  tr.st(rep.tArr, 'phase', 'concluído', 'est');
  tr.mile(rep.tArr, 'Resposta', fmtTime(rep.tArr));
  tr.ev(rep.tArr, 'cl', nx ? 'Recebe NXDOMAIN' : 'Recebe ' + A.an[A.an.length - 1].d, 'ok');
  tr.lg(rep.tArr, 'Cliente recebeu a resposta em ' + fmtTime(rep.tArr) + ' (' + R.queries + ' consultas ao lado da Internet).', 'conn');
  step(rep.tArr, 'O resolvedor respondeu ao cliente em <b>' + fmtTime(rep.tArr) + '</b> depois de <b>' + R.queries + ' consulta(s)</b> a servidores da hierarquia.');
  R.tEnd = rep.tArr;
  return tr;
}

// ---------------------------------------------------------------------------------------------------------------------
// Modo 'sec': DNSSEC, a cadeia de confiança e a validação
// ---------------------------------------------------------------------------------------------------------------------

export function buildSec(P: DnsParams): Trace {
  const nx = P.zona === 'nx';
  const qname = nx ? 'nao-existe.example.com' : 'www.example.com';
  const insegura = P.zona === 'insegura';
  const tr = newTrace([colCl, colRs, colRt, colTl, colAu], STATES);
  const { nid, send } = kit(tr);
  const { R, step, concept, cache } = newRaw(tr, 'sec', P);
  const EDE: Record<string, [number, string]> = { expirada: [7, 'Signature Expired'], dsruim: [6, 'DNSSEC Bogus'] };
  tr.st(0, 'cache', 'vazio', 'closed');
  tr.st(0, 'srv', '-', 'closed');
  tr.st(0, 'ans', 'aguardando', 'warn');

  tr.phase('1. Consulta do cliente', 'cli');
  tr.st(0, 'phase', 'consulta', 'warn');
  tr.mile(0, 'Consulta', qname);
  const id0 = nid();
  const qc = send('cl', 'rs', {
    label: 'A ' + qname,
    info: 'Standard query 0x' + id0.toString(16) + ' A ' + qname,
    about: 'O cliente pergunta ao resolvedor. Ele confia no resolvedor para validar o DNSSEC: o aluno pode ver a resposta com AD=1 (autenticada) ou, se a validação falhar, um erro.',
    m: q1(id0, qname, 'A', { rd: true, ad: true }),
  });
  tr.ev(0, 'cl', 'Pergunta A ' + qname, '');
  step(0, 'O cliente pediu <b>A ' + qname + '</b> ao resolvedor' + (P.validar ? ', que <b>valida o DNSSEC</b>.' : ', que <b>não valida o DNSSEC</b>.'));
  tr.phase('2. Resolução com DO=1', 'iter');
  tr.st(qc.tArr, 'phase', 'resolvendo', 'warn');

  const ask = (to: string, name: string, type: string, label: string, about: string, resp: Partial<DnsMsg>, respLabel: string, respAbout: string, extraTags: string[] = []) => {
    const id = nid();
    const q = send('rs', to, {
      label,
      info: 'Standard query 0x' + id.toString(16) + ' ' + type + ' ' + name + ' (DO=1)',
      about,
      m: q1(id, name, type, { dok: true }),
    });
    R.queries++;
    tr.st(q.tSend, 'srv', to === 'rt' ? 'a raiz' : to === 'tl' ? 'o .com' : 'ns1', 'warn');
    const r = send(to, 'rs', {
      label: respLabel,
      info: 'Standard query response 0x' + id.toString(16) + ' ' + (resp.an || resp.ns || []).map((x) => x.t).join(', '),
      about: respAbout,
      m: { id, qr: 1, edns: true, dok: true, q: [name, type], ...resp },
      dport: q.sport as number,
      tags: extraTags,
    });
    return r;
  };

  // referral da raiz com DS(com)
  const dsCom = dsRR('com');
  const rr1 = ask('rt', qname, 'A', 'A ' + qname, 'Com DO=1, o resolvedor pede os registros DNSSEC junto com a resposta.',
    { ns: [...REF_ROOT.ns, dsCom, rrsigRR('com', 'DS', '.', 'zsk')], ar: REF_ROOT.ar }, 'Referral + DS(com)',
    'A raiz delega o .com e entrega o <b>DS</b> (Delegation Signer) do .com, assinado pela raiz (RRSIG). O DS é o resumo da chave do .com: é o elo que amarra uma zona à zona de cima.');
  tr.mile(rr1.tArr, 'Raiz', 'DS(com)');
  step(rr1.tArr, 'A raiz indicou o .com e entregou o <b>DS(com)</b> com sua assinatura (RRSIG).');

  // referral do .com com DS(example.com) ou prova de inexistência
  const dsEx = P.zona === 'dsruim' ? dsRR('example.com', true) : dsRR('example.com');
  const tldNs: RR[] = insegura
    ? [...REF_TLD.ns, { n: 'example.com', t: 'NSEC3', ttl: 3600, d: 'prova: não existe DS para este nome (sem opt-out de segurança)' }, rrsigRR('example.com', 'NSEC3', 'com', 'zsk')]
    : [...REF_TLD.ns, dsEx, rrsigRR('example.com', 'DS', 'com', 'zsk')];
  const rr2 = ask('tl', qname, 'A', 'A ' + qname, 'O resolvedor repete a pergunta ao .com, também com DO=1.', { ns: tldNs, ar: REF_TLD.ar },
    insegura ? 'Referral sem DS' : 'Referral + DS(example.com)',
    insegura
      ? 'O .com delega example.com, mas <b>não há DS</b>: o domínio não assinou a zona ou não publicou o DS no registro. O .com prova a ausência com NSEC3 assinado, para que ninguém possa esconder um DS que existe.'
      : 'O .com delega example.com e entrega o <b>DS(example.com)</b>, assinado pela chave do .com' + (P.zona === 'dsruim' ? '. Neste cenário o DS é antigo: o resumo não corresponde à chave atual do domínio.' : '.'));
  tr.mile(rr2.tArr, '.com', insegura ? 'sem DS' : 'DS(example.com)');
  step(rr2.tArr, insegura ? 'O .com indicou example.com <b>sem DS</b> (provado por NSEC3): a zona é <b>insegura</b>.' : 'O .com indicou example.com e entregou o <b>DS(example.com)</b>' + (P.zona === 'dsruim' ? ' (desatualizado)' : '') + '.');

  // resposta autoritativa
  tr.phase('3. Resposta autoritativa assinada', 'auth');
  tr.st(tr.t, 'phase', 'autoritativo', 'warn');
  let ansMsg: Partial<DnsMsg>;
  let ansAbout: string;
  if (nx) {
    const nsec: RR = { n: 'mail.example.com', t: 'NSEC', ttl: 3600, d: 'www.example.com A MX RRSIG NSEC' };
    ansMsg = { aa: true, rcode: 3, ns: [SOA, rrsigRR('example.com', 'SOA', 'example.com', 'zsk'), nsec, rrsigRR('mail.example.com', 'NSEC', 'example.com', 'zsk')] };
    ansAbout = 'NXDOMAIN assinado. O registro <b>NSEC</b> prova que entre mail.example.com e www.example.com não existe nenhum nome, logo nao-existe.example.com não existe. Sem essa prova, um atacante poderia forjar "o nome não existe" sem deixar rastro.';
  } else {
    ansMsg = { aa: true, an: [WWW_A, rrsigRR('www.example.com', 'A', 'example.com', 'zsk', P.zona === 'expirada')] };
    ansAbout = 'A resposta vem com o registro A e o <b>RRSIG</b> que o assina. O RRSIG diz quem assinou, com qual chave (key tag) e por quanto tempo vale' + (P.zona === 'expirada' ? '. Neste cenário a validade <b>acabou em 30/09/2026</b>: a assinatura está vencida.' : '.');
  }
  const ra = ask('au', qname, 'A', 'A ' + qname, 'Pergunta final ao autoritativo, com DO=1.', ansMsg, nx ? 'NXDOMAIN + NSEC' : 'A + RRSIG', ansAbout);
  tr.mile(ra.tArr, 'Autoritativo', nx ? 'NXDOMAIN assinado' : 'A + RRSIG');
  step(ra.tArr, nx ? 'O autoritativo respondeu NXDOMAIN com SOA, <b>NSEC</b> e as assinaturas.' : 'O autoritativo respondeu <b>' + WWW_A.d + '</b> com o <b>RRSIG</b>' + (P.zona === 'expirada' ? ' (já vencido)' : '') + '.');

  // validação
  let chainOk = true;
  const rows = R.chain as ChainRow[];
  const fetchKey = (to: string, zone: string, signer: string, about: string) => {
    const keys = [dnskeyRR(zone, 'ksk'), dnskeyRR(zone, 'zsk')];
    return ask(to, zone === '.' ? '.' : zone, 'DNSKEY', 'DNSKEY ' + (zone === '.' ? '.' : zone), 'Para validar, o resolvedor busca as chaves públicas da zona.',
      { aa: true, an: [...keys, rrsigRR(zone, 'DNSKEY', signer, 'ksk')] }, 'DNSKEY ' + (zone === '.' ? '.' : zone), about);
  };
  if (P.validar) {
    tr.phase('4. Validação da cadeia de confiança', 'val');
    tr.st(tr.t, 'phase', 'validando', 'warn');
    // raiz
    const k1 = fetchKey('rt', '.', '.', 'As chaves da raiz. O resolvedor já tem a KSK da raiz como <b>âncora de confiança</b> (trust anchor): é o único ponto que precisa ser configurado manualmente.');
    tr.ev(k1.tArr, 'rs', 'DNSKEY(.) confere com a âncora de confiança', 'ok');
    tr.mile(k1.tArr, 'Âncora', 'raiz validada');
    rows.push({ zona: '. (raiz)', passo: 'DNSKEY da raiz assinada pela KSK que é a âncora de confiança', estado: 'ok' });
    step(k1.tArr, 'O resolvedor obteve a DNSKEY da raiz e confirmou que a KSK é a <b>âncora de confiança</b>.');
    // .com
    const k2 = fetchKey('tl', 'com', 'com', 'As chaves do .com. O resumo (hash) da KSK do .com precisa ser igual ao DS que a raiz entregou.');
    tr.ev(k2.tArr, 'rs', 'hash(KSK de .com) = DS(com) assinado pela raiz', 'ok');
    rows.push({ zona: 'com', passo: 'DS(com) da raiz = hash da KSK do .com; DNSKEY(com) assinada pela KSK', estado: 'ok' });
    step(k2.tArr, 'O hash da KSK do .com <b>coincide com o DS(com)</b> assinado pela raiz: o elo raiz/.com está validado.');
    if (insegura) {
      chainOk = true;
      rows.push({ zona: 'example.com', passo: 'Sem DS no .com (provado por NSEC3): a cadeia termina aqui, a zona é insegura', estado: 'sem-ds' });
      rows.push({ zona: 'www.example.com A', passo: 'Sem assinatura a verificar', estado: 'sem-ds' });
      R.status = 'insegura';
      step(k2.tArr, 'Como não há DS para example.com, a cadeia <b>não continua</b>: a resposta é aceita como <b>insegura</b> (sem AD), mas não é recusada.');
      concept('Uma zona sem DS é insegura: o resolvedor aceita a resposta, mas sem garantia de autenticidade.');
    } else {
      const k3 = fetchKey('au', 'example.com', 'example.com', 'As chaves de example.com. O hash da KSK precisa ser igual ao DS(example.com) entregue pelo .com.');
      if (P.zona === 'dsruim') {
        chainOk = false;
        tr.ev(k3.tArr, 'rs', 'hash(KSK) ≠ DS(example.com): cadeia quebrada', 'bad');
        rows.push({ zona: 'example.com', passo: 'DS(example.com) do .com ≠ hash da KSK atual (resumo ' + dsDigest('example.com').slice(0, 8) + ' esperado, DS traz ' + dsDigest('example.comantiga').slice(0, 8) + ')', estado: 'falhou' });
        rows.push({ zona: 'www.example.com A', passo: 'Não verificado: a cadeia já está quebrada', estado: 'nao-verificado' });
        R.status = 'bogus';
        step(k3.tArr, 'O hash da KSK de example.com <b>não coincide com o DS</b> publicado no .com: a cadeia de confiança está <b>quebrada</b> (resposta "bogus").');
        concept('Se o DS no registro do domínio não acompanha a troca da KSK, o domínio inteiro fica inalcançável para quem valida.');
      } else {
        tr.ev(k3.tArr, 'rs', 'hash(KSK de example.com) = DS(example.com)', 'ok');
        rows.push({ zona: 'example.com', passo: 'DS(example.com) do .com = hash da KSK; DNSKEY assinada pela KSK', estado: 'ok' });
        step(k3.tArr, 'O hash da KSK de example.com <b>coincide com o DS(example.com)</b> assinado pelo .com.');
        if (P.zona === 'expirada') {
          chainOk = false;
          tr.ev(k3.tArr + 0.4, 'rs', 'RRSIG(A) venceu em 30/09/2026', 'bad');
          rows.push({ zona: 'www.example.com A', passo: 'RRSIG com a ZSK correta, mas fora do período de validade (venceu em 30/09/2026)', estado: 'falhou' });
          R.status = 'bogus';
          step(k3.tArr, 'A assinatura RRSIG do registro A estava <b>vencida</b> (30/09/2026): a validação falhou.');
          concept('Assinaturas DNSSEC têm validade; se o operador não as renova, o domínio some para os resolvedores que validam.');
        } else {
          rows.push({ zona: nx ? 'nao-existe.example.com' : 'www.example.com A', passo: nx ? 'NSEC prova a inexistência e a assinatura da ZSK é válida' : 'RRSIG verificada com a ZSK, dentro da validade', estado: 'ok' });
          R.status = 'segura';
          tr.ev(k3.tArr + 0.4, 'rs', nx ? 'Inexistência provada pelo NSEC' : 'RRSIG válida', 'ok');
          step(k3.tArr, nx ? 'O <b>NSEC</b> assinado prova que o nome não existe: a negação é <b>autenticada</b>.' : 'A assinatura RRSIG do registro A foi verificada com a ZSK: resposta <b>autêntica</b>.');
          concept('A cadeia de confiança: âncora (raiz) valida o DS do .com, que valida a KSK do .com, que valida o DS do domínio, e assim até o registro.');
          if (nx) concept('NSEC prova a inexistência de um nome; NSEC3 faz o mesmo sem listar os nomes da zona.');
        }
      }
    }
  } else {
    R.status = P.zona === 'ok' || P.zona === 'nx' ? 'nao-validada' : insegura ? 'insegura' : 'nao-validada-ruim';
    rows.push({ zona: '. (raiz)', passo: 'Resolvedor sem validação: nada é verificado', estado: 'nao-verificado' });
    rows.push({ zona: 'com', passo: 'Não verificado', estado: 'nao-verificado' });
    rows.push({ zona: 'example.com', passo: 'Não verificado', estado: 'nao-verificado' });
    rows.push({ zona: nx ? 'nao-existe.example.com' : 'www.example.com A', passo: 'Não verificado', estado: 'nao-verificado' });
    step(tr.t, 'O resolvedor <b>não valida</b>: ele ignora os registros DNSSEC e aceita a resposta como veio.');
    concept('Publicar DNSSEC não adianta se o resolvedor não valida: a proteção está na validação, no resolvedor.');
  }

  // resposta ao cliente
  tr.phase('5. Resposta ao cliente', 'resp');
  const bogus = P.validar && !chainOk;
  let rep: Message;
  if (bogus) {
    const [code, name] = EDE[P.zona] || [6, 'DNSSEC Bogus'];
    rep = send('rs', 'cl', {
      label: 'SERVFAIL',
      info: 'Standard query response 0x' + id0.toString(16) + ' Server failure (EDE ' + code + ')',
      about: 'Validação falhou: o resolvedor <b>não entrega a resposta</b> e devolve SERVFAIL. O erro estendido (RFC 8914) explica o motivo. É o comportamento correto: uma resposta que não pode ser provada não deve ser usada.',
      m: { id: id0, qr: 1, rd: true, ra: true, edns: true, q: [qname, 'A'], rcode: 2 },
      dport: qc.sport as number,
      color: C0.bad,
      tags: ['SERVFAIL'],
      extra: [{ sec: 'Erro DNS estendido (RFC 8914)' }, ['Código', code + ' (' + name + ')', 'motivo do SERVFAIL']],
    });
    tr.st(rep.tArr, 'ans', 'SERVFAIL (DNSSEC bogus)', 'bad');
    tr.st(rep.tArr, 'cache', 'resposta descartada', 'bad');
    tr.mile(rep.tArr, 'SERVFAIL', 'validação falhou');
    tr.ev(rep.tArr, 'cl', 'Recebe SERVFAIL: sem resposta', 'bad');
    tr.lg(rep.tArr, 'Validação falhou (' + name + '): o resolvedor devolve SERVFAIL e não guarda a resposta.', 'loss');
    step(rep.tArr, 'O resolvedor devolveu <b>SERVFAIL</b> ao cliente (erro estendido ' + code + ', ' + name + '). O nome ficou inalcançável.');
    R.result = 'servfail';
  } else {
    const secure = R.status === 'segura';
    rep = send('rs', 'cl', {
      label: nx ? 'NXDOMAIN' + (secure ? ' (AD)' : '') : 'Resposta' + (secure ? ' (AD)' : ''),
      info: 'Standard query response 0x' + id0.toString(16) + (nx ? ' No such name' : ' A ' + WWW_A.d) + (secure ? ' (AD=1)' : ''),
      about: secure
        ? 'Resposta validada: o resolvedor marca <b>AD=1</b> (Authenticated Data). O cliente só pode confiar nesse bit se a ligação até o resolvedor for confiável (rede local, DoT ou DoH).'
        : P.validar
          ? 'A zona é insegura: a resposta chega sem AD. O resolvedor não pode provar nem refutar a autenticidade.'
          : 'O resolvedor entrega o que recebeu, <b>sem AD</b>' + (P.zona === 'expirada' || P.zona === 'dsruim' ? ', mesmo com a assinatura inválida: sem validação, o erro passa despercebido.' : '.'),
      m: { id: id0, qr: 1, rd: true, ra: true, ad: secure, edns: true, q: [qname, 'A'], an: nx ? [] : [WWW_A], ns: nx ? [SOA] : [], rcode: nx ? 3 : 0 },
      dport: qc.sport as number,
      color: secure ? C0.enc : C0.data,
      tags: secure ? ['AD=1'] : [],
    });
    if (!nx) cache(rep.tArr, WWW_A, 'ns1');
    else cache(rep.tArr, { n: qname, t: 'A', ttl: SOA.ttl, d: 'NXDOMAIN (cache negativo)' }, 'ns1', { neg: true });
    tr.st(rep.tArr, 'ans', (nx ? 'NXDOMAIN' : WWW_A.d) + (secure ? ' (autenticada)' : ' (sem AD)'), secure ? 'est' : 'warn');
    tr.st(rep.tArr, 'cache', secure ? 'validada' : 'sem validação', secure ? 'est' : 'warn');
    tr.mile(rep.tArr, 'Resposta', secure ? 'AD=1' : 'sem AD');
    tr.ev(rep.tArr, 'cl', secure ? 'Recebe resposta autenticada (AD=1)' : 'Recebe resposta sem autenticação', secure ? 'ok' : 'warn');
    tr.lg(rep.tArr, secure ? 'Resposta autenticada pela cadeia de confiança.' : 'Resposta entregue sem autenticação DNSSEC.', secure ? 'conn' : 'loss');
    step(rep.tArr, secure ? 'O cliente recebeu a resposta com <b>AD=1</b>: autenticada de ponta a ponta até a raiz.' : 'O cliente recebeu a resposta <b>sem AD</b>.' + (P.zona === 'expirada' || P.zona === 'dsruim' ? ' <b>A assinatura estava inválida e ninguém verificou.</b>' : ''));
    R.result = secure ? 'ok' : 'semAD';
  }
  tr.st(rep.tArr, 'phase', 'concluído', bogus ? 'bad' : 'est');
  R.tEnd = rep.tArr;
  R.qname = qname;
  return tr;
}

// ---------------------------------------------------------------------------------------------------------------------
// Modo 'env': envenenamento de cache e defesas
// ---------------------------------------------------------------------------------------------------------------------

export function buildEnv(P: DnsParams): Trace {
  const cols: Column[] = [colCl, colRs, { ...colAu, sub: 'autoritativo legítimo' }, { key: 'at', label: 'Atacante', sub: 'resposta forjada', addr: IPS.at }];
  const tr = newTrace(cols, STATES);
  const { nid, send } = kit(tr);
  const { R, step, concept, cache } = newRaw(tr, 'env', P);
  const fixed = P.defesa === 'nenhuma';
  const accepted = fixed || (P.defesa === 'aleatoria' && P.sorte);
  const qname = 'www.example.com';
  const realPort = fixed ? 53 : 1024 + (h32('env-port', 9) % 60000);
  const qnameWire = P.defesa === 'x20' ? 'wWw.eXaMpLe.CoM' : qname;
  tr.st(0, 'cache', 'vazio', 'closed');
  tr.st(0, 'srv', '-', 'closed');
  tr.st(0, 'ans', 'aguardando', 'warn');

  tr.phase('1. Consulta que abre a janela', 'cli');
  tr.st(0, 'phase', 'consulta', 'warn');
  tr.mile(0, 'Consulta', qname);
  const id0 = nid();
  const qc = send('cl', 'rs', {
    label: 'A ' + qname,
    info: 'Standard query 0x' + id0.toString(16) + ' A ' + qname,
    about: 'Um cliente pergunta por um nome que o resolvedor não tem no cache. Enquanto o resolvedor espera a resposta do autoritativo, existe uma <b>janela de oportunidade</b> para quem tentar se passar por ele.',
    m: q1(id0, qname, 'A', { rd: true }),
  });
  tr.ev(0, 'cl', 'Pergunta A ' + qname, '');
  step(0, 'O cliente pediu <b>A ' + qname + '</b>; o resolvedor não tinha a resposta no cache.');

  tr.phase('2. Corrida entre a resposta legítima e a forjada', 'race');
  tr.st(qc.tArr, 'phase', 'janela aberta', 'warn');
  const idq = nid();
  const sport = realPort;
  const qs = send('rs', 'au', {
    label: 'A ' + qname,
    info: 'Standard query 0x' + idq.toString(16) + ' A ' + qnameWire + ' (porta de origem ' + sport + ')',
    about: fixed
      ? 'O resolvedor consulta o autoritativo usando <b>porta de origem fixa (53)</b> e um ID de 16 bits previsível. Quem enxerga o padrão só precisa acertar o ID, entre 65536 valores.'
      : 'O resolvedor consulta o autoritativo com <b>porta de origem aleatória (' + sport + ')</b> e ID aleatório (RFC 5452)' + (P.defesa === 'x20' ? ', e escreve o nome com letras maiúsculas e minúsculas aleatórias (0x20, RFC 7873 e draft de 0x20): o autoritativo devolve o nome com a mesma caixa.' : '. Para acertar, o atacante precisaria adivinhar porta e ID juntos: cerca de 2^32 combinações.'),
    m: q1(idq, qnameWire, 'A'),
    sport,
  });
  R.queries = 1;
  tr.st(qs.tSend, 'srv', 'ns1', 'warn');
  tr.lg(qs.tSend, 'Resolvedor consulta ns1 (porta de origem ' + sport + ', ID 0x' + idq.toString(16) + ').', 'conn');
  tr.ev(qs.tSend, 'rs', 'Janela aberta: aguarda o autoritativo', 'warn');

  const forgedAns: RR[] = [{ n: qname, t: 'A', ttl: 86400, d: ATK_ANSWER }];
  const forged = (n: number, matchPort: boolean, matchId: boolean, caseOk: boolean, label: string, about: string, lost: boolean) =>
    send('at', 'rs', {
      label,
      info: 'Resposta forjada ' + n + ' 0x' + (matchId ? idq : (idq + n * 7919) & 0xffff).toString(16) + ' para ' + (matchPort ? sport : sport + n * 13),
      about,
      m: { id: matchId ? idq : (idq + n * 7919) & 0xffff, qr: 1, aa: true, q: [caseOk ? qnameWire : qname, 'A'], an: forgedAns },
      srcIp: 'au',
      dport: matchPort ? sport : sport + n * 13,
      par: true,
      at: qs.tSend + 1 + n * 0.6,
      dur: 5,
      lost,
      color: C0.bad,
      tags: lost ? ['descartada'] : ['forjada'],
      phaseName: 'Forjada',
    });

  let poisoned = false;
  if (accepted) {
    const f = forged(1, true, true, true, 'Resposta forjada', 'O atacante responde <b>antes</b> do autoritativo, com o IP de origem do ns1 forjado' + (fixed ? ' e o ID acertado (porta fixa e ID previsível).' : ' e <b>acertou porta e ID por sorte</b>.') + ' O resolvedor não tem como distinguir: porta, ID e pergunta conferem.', false);
    R.forged = 1;
    poisoned = true;
    cache(f.tArr, forgedAns[0], 'forjada', { bad: true });
    tr.ev(f.tArr, 'rs', 'Aceita a resposta forjada: cache envenenado', 'bad');
    tr.lg(f.tArr, 'Resposta forjada aceita (porta e ID conferem). Cache envenenado: ' + qname + ' → ' + ATK_ANSWER + ' (TTL 86400 s).', 'loss');
    tr.mile(f.tArr, 'Envenenado', ATK_ANSWER);
    tr.st(f.tArr, 'cache', qname + ' → ' + ATK_ANSWER, 'bad');
    step(f.tArr, 'A resposta <b>forjada</b> chegou primeiro e foi aceita (' + (fixed ? 'porta fixa e ID previsível' : 'o atacante acertou porta e ID por sorte') + '): o cache passou a apontar ' + qname + ' para <b>' + ATK_ANSWER + '</b> por 24 horas.');
    concept(fixed ? 'Porta de origem fixa e ID previsível deixam só 16 bits de segurança: a base do ataque de Kaminsky (2008).' : 'Aleatorizar porta e ID eleva o custo do ataque, mas não o elimina: um palpite certo ainda envenena o cache.');
    const rl = send('au', 'rs', {
      label: 'Resposta legítima',
      info: 'Standard query response 0x' + idq.toString(16) + ' A 192.0.2.80',
      about: 'A resposta verdadeira chega tarde. O resolvedor já aceitou outra e fechou a consulta: descarta esta como "resposta sem consulta pendente".',
      m: { id: idq, qr: 1, aa: true, q: [qnameWire, 'A'], an: [WWW_A] },
      dport: sport,
      color: C0.tcp,
      lost: true,
      tags: ['tarde demais'],
    });
    tr.ev(rl.tArr, 'rs', 'Descarta a resposta verdadeira (consulta já respondida)', '');
    const rep = send('rs', 'cl', {
      label: 'Resposta (' + ATK_ANSWER + ')',
      info: 'Standard query response 0x' + id0.toString(16) + ' A ' + ATK_ANSWER,
      about: 'O resolvedor entrega ao cliente o endereço do atacante. Para o cliente, nada indica o problema.',
      m: { id: id0, qr: 1, rd: true, ra: true, q: [qname, 'A'], an: forgedAns },
      dport: qc.sport as number,
      color: C0.bad,
      tags: ['envenenada'],
    });
    tr.st(rep.tArr, 'ans', ATK_ANSWER + ' (do atacante)', 'bad');
    tr.ev(rep.tArr, 'cl', 'Recebe ' + ATK_ANSWER + ' em vez de 192.0.2.80', 'bad');
    tr.phase('3. Efeito: o cache continua envenenado', 'efeito');
    tr.st(rep.tArr, 'phase', 'envenenado', 'bad');
    tr.wait(30000);
    const id2 = nid();
    const q2 = send('cl', 'rs', {
      label: 'A ' + qname + ' (depois)',
      info: 'Standard query 0x' + id2.toString(16) + ' A ' + qname,
      about: 'Meia hora depois, outro cliente faz a mesma pergunta.',
      m: q1(id2, qname, 'A', { rd: true }),
    });
    const rep2 = send('rs', 'cl', {
      label: 'Resposta (' + ATK_ANSWER + ')',
      info: 'Standard query response 0x' + id2.toString(16) + ' A ' + ATK_ANSWER,
      about: 'O resolvedor responde pelo cache, sem consultar ninguém: <b>todos os clientes</b> dele recebem o endereço do atacante até o TTL expirar. Por isso o envenenamento de cache é mais grave que um ataque a um cliente só.',
      m: { id: id2, qr: 1, rd: true, ra: true, q: [qname, 'A'], an: [{ ...forgedAns[0], ttl: 86370 }] },
      dport: q2.sport as number,
      color: C0.bad,
      tags: ['envenenada'],
    });
    tr.st(rep2.tArr, 'ans', ATK_ANSWER + ' (do atacante)', 'bad');
    tr.mile(rep2.tArr, 'Todos afetados', 'TTL 24 h');
    step(rep2.tArr, 'Um <b>segundo cliente</b> perguntou depois e recebeu o mesmo endereço do cache: o dano atinge todos os usuários do resolvedor.');
    concept('Envenenado, o cache serve a resposta falsa a todos os clientes até o TTL expirar.');
    R.tEnd = rep2.tArr;
  } else {
    const reasons: Record<string, [string, string]> = {
      aleatoria: ['Resposta forjada (palpite)', 'A resposta forjada não casa com a consulta pendente: a porta de destino e o ID não conferem (a porta de origem do resolvedor é aleatória). O resolvedor a descarta sem alterar o cache.'],
      x20: ['Resposta forjada (palpite)', P.sorte ? 'Mesmo acertando porta e ID, o nome vem com a <b>caixa errada</b> (wwW.example.com em vez de ' + qnameWire + '): o atacante teria de adivinhar também cada letra maiúscula ou minúscula, o que multiplica o esforço (0x20).' : 'Não casa: porta e ID não conferem. A caixa das letras do nome é um terceiro campo a adivinhar.'],
      dnssec: ['Resposta forjada (palpite)', P.sorte ? 'Porta e ID conferem, mas a resposta <b>não tem RRSIG válido</b>: o resolvedor valida o DNSSEC e rejeita. A defesa deixa de depender de sorte ou de segredo na camada de transporte.' : 'Porta e ID não conferem e, mesmo que conferissem, a resposta não teria RRSIG válido.'],
    };
    const [fl, fa] = reasons[P.defesa] || reasons.aleatoria;
    const matchAll = P.sorte && (P.defesa === 'x20' || P.defesa === 'dnssec');
    const f1 = forged(1, false, false, true, 'Forjada 1 (palpite)', 'Primeiro palpite do atacante: ID e porta errados. O resolvedor a descarta.', true);
    const f2 = forged(2, matchAll, matchAll, false, fl, fa, true);
    R.forged = 2;
    tr.ev(f1.tArr, 'rs', 'Descarta: ID e porta não conferem', '');
    tr.ev(f2.tArr, 'rs', P.defesa === 'dnssec' && P.sorte ? 'Descarta: sem RRSIG válido (bogus)' : P.defesa === 'x20' && P.sorte ? 'Descarta: caixa do nome diferente (0x20)' : 'Descarta: não casa com a consulta', '');
    tr.lg(f1.tArr, 'Respostas forjadas descartadas; o cache não foi alterado.', 'sys');
    step(f2.tArr, 'Duas respostas <b>forjadas</b> chegaram antes da legítima e foram <b>descartadas</b> (' + (P.defesa === 'dnssec' ? 'validação DNSSEC' : P.defesa === 'x20' ? 'caixa do nome (0x20) e porta/ID' : 'porta e ID aleatórios') + ').');
    concept('Porta e ID aleatórios (RFC 5452) tornam o palpite improvável: cerca de 2^32 combinações em vez de 2^16.');
    if (P.defesa === 'x20') concept('0x20 acrescenta mais entropia: o autoritativo copia a caixa das letras da pergunta, e o atacante precisa adivinhá-la.');
    if (P.defesa === 'dnssec') concept('DNSSEC é a defesa estrutural: a resposta é aceita pela assinatura, não pela sorte.');
    const rl = send('au', 'rs', {
      label: 'Resposta legítima',
      info: 'Standard query response 0x' + idq.toString(16) + ' A 192.0.2.80',
      about: 'A resposta verdadeira chega, com porta, ID' + (P.defesa === 'x20' ? ', caixa do nome' : '') + (P.defesa === 'dnssec' ? ' e RRSIG' : '') + ' corretos. O resolvedor a aceita.',
      m: { id: idq, qr: 1, aa: true, q: [qnameWire, 'A'], an: P.defesa === 'dnssec' ? [WWW_A, rrsigRR(qname, 'A', 'example.com', 'zsk')] : [WWW_A], edns: true, dok: P.defesa === 'dnssec' },
      dport: sport,
      color: C0.data,
    });
    cache(rl.tArr, WWW_A, 'ns1');
    tr.st(rl.tArr, 'cache', qname + ' → 192.0.2.80', 'est');
    tr.ev(rl.tArr, 'rs', 'Aceita a resposta legítima', 'ok');
    tr.mile(rl.tArr, 'Legítima', 'aceita');
    tr.phase('3. Resposta ao cliente', 'resp');
    const rep = send('rs', 'cl', {
      label: 'Resposta (192.0.2.80)',
      info: 'Standard query response 0x' + id0.toString(16) + ' A 192.0.2.80',
      about: 'O cliente recebe o endereço correto. A tentativa de envenenamento não teve efeito.',
      m: { id: id0, qr: 1, rd: true, ra: true, q: [qname, 'A'], an: [WWW_A] },
      dport: qc.sport as number,
    });
    tr.st(rep.tArr, 'ans', '192.0.2.80', 'est');
    tr.st(rep.tArr, 'phase', 'seguro', 'est');
    tr.ev(rep.tArr, 'cl', 'Recebe 192.0.2.80', 'ok');
    step(rep.tArr, 'A resposta legítima foi aceita e o cliente recebeu <b>192.0.2.80</b>.');
    R.tEnd = rep.tArr;
  }
  R.poisoned = poisoned;
  return tr;
}

// ---------------------------------------------------------------------------------------------------------------------
// Modo 'amp': reflexão e amplificação
// ---------------------------------------------------------------------------------------------------------------------

export function buildAmp(P: DnsParams): Trace {
  const cols: Column[] = [{ key: 'at', label: 'Atacante', sub: 'origem forjada', addr: IPS.at }, { key: 'rs', label: 'Resolvedor', sub: 'recursivo', addr: IPS.rs }, { key: 'vi', label: 'Vítima', sub: 'alvo da inundação', addr: IPS.vi }];
  const tr = newTrace(cols, [{ key: 'phase', label: 'Fase' }, { key: 'sent', label: 'Bytes do atacante' }, { key: 'recv', label: 'Bytes que chegam à vítima' }, { key: 'fator', label: 'Fator de amplificação' }]);
  const { nid, send } = kit(tr);
  const { R, step, concept } = newRaw(tr, 'amp', P);
  const any = P.consulta === 'any';
  const qtype = any ? 'ANY' : 'A';
  const qname = 'example.com';
  const big: RR[] = [
    { n: qname, t: 'A', ttl: 300, d: '192.0.2.80' }, { n: qname, t: 'AAAA', ttl: 300, d: '2001:db8::80' }, { n: qname, t: 'MX', ttl: 3600, d: '10 mail.example.com' },
    { n: qname, t: 'TXT', ttl: 3600, d: '"v=spf1 ip4:192.0.2.0/24 -all"' }, { n: qname, t: 'NS', ttl: 86400, d: 'ns1.example.com' }, { n: qname, t: 'SOA', ttl: 3600, d: SOA.d },
    { n: qname, t: 'TXT', ttl: 3600, d: '"v=DKIM1; k=rsa; p=' + b64('dkim', 380) + '"' },
    { n: qname, t: 'DNSKEY', ttl: 3600, d: dnskeyRR(qname, 'ksk').d }, { n: qname, t: 'DNSKEY', ttl: 3600, d: dnskeyRR(qname, 'zsk').d }, rrsigRR(qname, 'ANY', qname, 'zsk'),
  ];
  const answer: RR[] = any ? big : [big[0]];
  tr.st(0, 'phase', 'preparação', 'warn');
  tr.st(0, 'sent', '0', 'closed');
  tr.st(0, 'recv', '0', 'closed');
  tr.st(0, 'fator', '-', 'closed');

  tr.phase('1. Consultas com origem forjada', 'forja');
  tr.mile(0, 'Consulta', qtype + ' ' + qname);
  const probe: DnsMsg = q1(nid(), qname, qtype, { rd: true });
  const reqLen = sizeOf(probe);
  const respFull: DnsMsg = { id: probe.id, qr: 1, rd: true, ra: true, edns: true, q: [qname, qtype], an: answer };
  const respLen = sizeOf(respFull);
  let sentB = 0;
  let recvB = 0;
  const N = 3;
  R.reqLen = reqLen;
  R.respLen = respLen;
  R.n = N;
  step(0, 'O atacante enviou <b>' + N + ' consultas de ' + reqLen + ' bytes</b> (' + qtype + ' ' + qname + ') com o <b>endereço de origem trocado pelo da vítima</b> (' + IPS.vi + ').');
  concept('O UDP não confirma a origem: quem envia pode escrever qualquer IP de origem, e a resposta vai para esse endereço.');

  for (let i = 0; i < N; i++) {
    const m: DnsMsg = q1(nid(), qname, qtype, { rd: true });
    const filtered = P.bcp38;
    const q = send('at', 'rs', {
      label: qtype + ' ' + qname,
      info: 'Standard query 0x' + m.id.toString(16) + ' ' + qtype + ' ' + qname + ' (origem forjada ' + IPS.vi + ')',
      about: filtered
        ? 'O provedor do atacante aplica o filtro de origem (<b>BCP 38 / uRPF</b>): um pacote cuja origem não pertence à rede de onde saiu é descartado na borda. A reflexão nem começa.'
        : 'A consulta é pequena e traz como origem o IP da <b>vítima</b>. O resolvedor, sem como saber, responderá a ela.',
      m,
      srcIp: 'vi',
      lost: filtered,
      color: filtered ? C0.bad : C0.plain,
      tags: filtered ? ['filtrado (BCP 38)'] : ['origem forjada'],
      phaseName: 'Consulta forjada',
    });
    sentB += q.len;
    if (filtered) {
      tr.ev(q.tArr, 'at', 'Descartado na borda (BCP 38)', 'ok');
      continue;
    }
    if (i === 0) tr.phase('2. O resolvedor responde à vítima', 'refl');
    if (P.resolvedor === 'acl') {
      const r = send('rs', 'vi', {
        label: 'REFUSED',
        info: 'Standard query response 0x' + m.id.toString(16) + ' Refused',
        about: 'O resolvedor só atende a rede interna (ACL): para um endereço de fora devolve <b>REFUSED</b>, uma resposta mínima, sem dados. O fator de amplificação cai a cerca de 1.',
        m: { id: m.id, qr: 1, rd: true, ra: false, edns: true, q: [qname, qtype], rcode: 5 },
        color: C0.plain,
        tags: ['REFUSED'],
      });
      recvB += r.len;
      tr.ev(r.tArr, 'rs', 'ACL: recusa quem é de fora', 'ok');
      continue;
    }
    if (P.resolvedor === 'rrl' && i > 0) {
      tr.ev(q.tArr, 'rs', 'Limite de taxa: descarta', 'ok');
      tr.lg(q.tArr, 'Limite de taxa por origem: consulta ' + (i + 1) + ' descartada.', 'sys');
      continue;
    }
    if (P.resolvedor === 'rrl' && i === 0) {
      const r = send('rs', 'vi', {
        label: 'Truncada (TC=1)',
        info: 'Standard query response 0x' + m.id.toString(16) + ' (truncated, slip)',
        about: 'Com o limite de taxa (RRL), a primeira resposta sai <b>truncada</b> (TC=1, o "slip"): um cliente legítimo repete por TCP, mas quem forjou a origem não recebe nada e a vítima só recebe um pacote pequeno.',
        m: { id: m.id, qr: 1, rd: true, ra: true, tc: true, edns: true, q: [qname, qtype] },
        color: C0.plain,
        tags: ['TC=1'],
      });
      recvB += r.len;
      continue;
    }
    const r = send('rs', 'vi', {
      label: 'Resposta grande',
      info: 'Standard query response 0x' + m.id.toString(16) + ' ' + answer.length + ' registros (' + respLen + ' bytes)',
      about: 'O resolvedor aberto responde a quem perguntar, e a resposta (<b>' + respLen + ' bytes</b>) é muito maior que a pergunta (' + reqLen + ' bytes). Tudo vai para a vítima, que nunca pediu nada.',
      m: respFull,
      color: C0.bad,
      tags: ['amplificada'],
    });
    recvB += r.len;
    tr.ev(r.tArr, 'vi', 'Recebe ' + r.len + ' B que não pediu', 'bad');
    tr.st(r.tArr, 'recv', recvB + ' B', 'bad');
  }
  tr.phase('3. Resultado', 'res');
  const fator = sentB ? recvB / sentB : 0;
  R.sentB = sentB;
  R.recvB = recvB;
  R.fator = fator;
  const fmtF = (v: number) => (Math.round(v * 10) / 10).toString().replace('.', ',');
  tr.st(tr.t, 'sent', sentB + ' B', 'warn');
  tr.st(tr.t, 'recv', recvB + ' B', recvB > sentB * 3 ? 'bad' : 'est');
  tr.st(tr.t, 'fator', fmtF(fator) + 'x', fator > 3 ? 'bad' : 'est');
  tr.st(tr.t, 'phase', fator > 3 ? 'ataque amplificado' : 'neutralizado', fator > 3 ? 'bad' : 'est');
  tr.mile(tr.t, 'Resultado', fmtF(fator) + 'x');
  tr.lg(tr.t, 'Atacante enviou ' + sentB + ' B; a vítima recebeu ' + recvB + ' B (fator ' + fmtF(fator) + 'x).', fator > 3 ? 'loss' : 'sys');
  if (P.bcp38) {
    step(tr.t, 'O provedor do atacante <b>filtrou</b> as consultas com origem forjada (BCP 38): nenhum byte chegou ao resolvedor nem à vítima.');
    concept('BCP 38 corta o problema na origem, mas só funciona se cada provedor o aplicar.');
  } else if (P.resolvedor === 'acl') {
    step(tr.t, 'O resolvedor recusou as consultas externas (ACL): a vítima recebeu apenas <b>' + recvB + ' bytes</b> de REFUSED.');
    concept('Resolvedor recursivo deve atender só a própria rede. Um resolvedor aberto é uma arma à disposição de qualquer um.');
  } else if (P.resolvedor === 'rrl') {
    step(tr.t, 'O limite de taxa deixou passar uma resposta truncada e descartou o resto: <b>' + recvB + ' bytes</b> chegaram à vítima contra ' + sentB + ' do atacante.');
    concept('Response Rate Limiting limita respostas idênticas por origem e responde truncado: quem forjou a origem não completa o TCP.');
  } else {
    step(tr.t, 'O resolvedor aberto respondeu a todas: a vítima recebeu <b>' + recvB + ' bytes</b> contra ' + sentB + ' do atacante, um fator de <b>' + fmtF(fator) + 'x</b>.');
    concept('Amplificação: uma pergunta pequena gera uma resposta grande; o ganho é a razão entre os dois tamanhos.');
    if (any) concept('Consultas do tipo ANY e respostas com DNSSEC são as que mais amplificam; por isso muitos servidores recusam ou reduzem o ANY (RFC 8482).');
    else concept('Mesmo uma consulta A comum amplifica pouco; o fator cresce com o tamanho da resposta (ANY, DNSKEY, TXT longos).');
  }
  R.tEnd = tr.t;
  return tr;
}

// ---------------------------------------------------------------------------------------------------------------------
// Modo 'priv': DNS puro, DoT e DoH diante de um observador na rede
// ---------------------------------------------------------------------------------------------------------------------

export function buildPriv(P: DnsParams): Trace {
  const cols: Column[] = [colCl, { key: 'ob', label: 'Observador', sub: 'na rede (provedor, Wi-Fi)' }, { key: 'rs', label: 'Resolvedor', sub: 'dns.example.net', addr: IPS.rs }];
  const tr = newTrace(cols, [{ key: 'phase', label: 'Fase' }, { key: 'canal', label: 'Canal' }, { key: 'ob', label: 'O que o observador enxerga' }, { key: 'ans', label: 'Resposta ao cliente' }]);
  const { nid, send, seg } = kit(tr);
  const { R, step, concept } = newRaw(tr, 'priv', P);
  const qname = 'www.example.com';
  const WAN = 15;
  const mode = P.transporte;
  const blocked = mode === 'dot' && P.bloqueio;
  const fallback = blocked && P.politica === 'oportunista';
  tr.st(0, 'phase', 'preparação', 'warn');
  tr.st(0, 'canal', mode === 'udp' ? 'UDP 53 (texto claro)' : mode === 'dot' ? 'TLS na porta 853 (DoT)' : 'HTTPS na porta 443 (DoH)', mode === 'udp' ? 'warn' : 'est');
  tr.st(0, 'ob', '-', 'closed');
  tr.st(0, 'ans', 'aguardando', 'warn');
  const idq = nid();
  const dnsQ = q1(idq, qname, 'A', { rd: true });
  const dnsA: DnsMsg = { id: idq, qr: 1, rd: true, ra: true, edns: true, q: [qname, 'A'], an: [WWW_A] };

  const plainExchange = (why: string) => {
    tr.phase('Consulta em texto claro (UDP 53)', 'plain');
    tr.st(tr.t, 'phase', 'texto claro', 'warn');
    const q = send('cl', 'rs', { label: 'A ' + qname, info: 'Standard query 0x' + idq.toString(16) + ' A ' + qname, about: why + ' A consulta passa em texto claro: qualquer equipamento no caminho lê o nome e pode alterar a resposta.', m: dnsQ, dur: WAN });
    tr.ev(q.tSend + WAN / 2, 'ob', 'Lê: A ' + qname, 'bad');
    tr.st(q.tSend + WAN / 2, 'ob', 'o nome consultado: ' + qname, 'bad');
    const r = send('rs', 'cl', { label: 'Resposta ' + WWW_A.d, info: 'Standard query response 0x' + idq.toString(16) + ' A ' + WWW_A.d, about: 'A resposta também é legível e <b>não tem autenticação</b>: quem está no caminho pode trocá-la por outra (sem DNSSEC, o cliente não percebe).', m: dnsA, dport: q.sport as number, dur: WAN });
    tr.ev(r.tSend + WAN / 2, 'ob', 'Lê: ' + qname + ' → ' + WWW_A.d, 'bad');
    tr.st(r.tArr, 'ans', WWW_A.d, 'est');
    return r;
  };

  let last: Message;
  if (mode === 'udp') {
    tr.mile(0, 'Consulta', 'UDP 53');
    last = plainExchange('Cliente e resolvedor falam DNS puro (Do53).');
    step(0, 'Cliente e resolvedor trocaram DNS <b>puro sobre UDP 53</b>: o observador leu o nome consultado e a resposta.');
    concept('DNS puro não tem confidencialidade, integridade nem autenticação do servidor.');
  } else if (blocked) {
    tr.phase('1. Tentativa de conexão DoT (porta 853)', 'dot');
    tr.mile(0, 'DoT', 'porta 853');
    const s1 = seg('cl', 'rs', 'SYN :853', 'SYN', 'O cliente tenta abrir a conexão TCP na porta 853 (DNS sobre TLS, RFC 7858). A rede bloqueia a porta e o pacote não chega.', { dur: WAN, lost: true, tags: ['bloqueado'] });
    tr.ev(s1.tSend + WAN / 2, 'ob', 'Bloqueia a porta 853', 'warn');
    tr.st(s1.tSend + WAN / 2, 'ob', 'porta 853 bloqueada', 'warn');
    tr.wait(1000);
    tr.lg(s1.tArr, 'Conexão DoT na porta 853 bloqueada (tempo esgotado).', 'loss');
    if (fallback) {
      tr.ev(tr.t, 'cl', 'Política oportunista: volta ao UDP 53', 'warn');
      step(s1.tArr, 'A porta 853 estava bloqueada. Com a política <b>oportunista</b>, o cliente <b>voltou ao UDP 53 em texto claro</b>: o bloqueio forçou o rebaixamento (downgrade).');
      concept('O modo oportunista tolera falhas, mas permite o ataque de rebaixamento: quem bloqueia a 853 devolve o tráfego ao texto claro.');
      last = plainExchange('Sem DoT disponível, o cliente aceita falar em texto claro.');
    } else {
      tr.ev(tr.t, 'cl', 'Política estrita: não consulta em claro', 'bad');
      tr.st(tr.t, 'ans', 'sem resposta (falha fechada)', 'bad');
      tr.st(tr.t, 'phase', 'falhou', 'bad');
      tr.mile(tr.t, 'Falha', 'estrita');
      tr.lg(tr.t, 'Política estrita: sem canal cifrado, o cliente não envia a consulta.', 'loss');
      step(s1.tArr, 'A porta 853 estava bloqueada. Com a política <b>estrita</b>, o cliente <b>não consultou</b> em texto claro: o nome ficou sem resolução, mas nada vazou.');
      concept('A política estrita falha fechada: prefere ficar sem resposta a revelar a consulta.');
      R.tEnd = tr.t;
      R.result = 'falhou';
      return tr;
    }
  } else {
    const dot = mode === 'dot';
    const port = dot ? 853 : 443;
    tr.phase('1. Conexão TCP e handshake TLS', 'tls');
    tr.mile(0, dot ? 'DoT' : 'DoH', 'porta ' + port);
    const sy = seg('cl', 'rs', 'SYN :' + port, 'SYN', 'O cliente abre uma conexão TCP com o resolvedor na porta ' + port + (dot ? ' (DNS sobre TLS, RFC 7858).' : ' (HTTPS, a mesma porta de qualquer site; DNS sobre HTTPS, RFC 8484).'), { dur: WAN });
    tr.ev(sy.tSend + WAN / 2, 'ob', 'Vê: conexão para ' + IPS.rs + ':' + port, '');
    seg('rs', 'cl', 'SYN+ACK', 'SYN ACK', 'O resolvedor aceita a conexão.', { dur: WAN });
    const tls = (from: string, to: string, label: string, about: string, enc: boolean): Message =>
      tr.add(from, to, { label, info: label, about, proto: 'TLS 1.3', color: enc ? C0.enc : C0.plain, len: 220, enc, dur: WAN, tags: enc ? ['cifrado'] : [], phaseName: 'TLS', fields: [{ sec: 'TLS 1.3 (RFC 8446)' }, ['Mensagem', label, ''], ['Extensão SNI', enc ? '(cifrada)' : 'dns.example.net', enc ? '' : 'nome do servidor, ainda em claro']] });
    const ch = tls('cl', 'rs', 'ClientHello', 'O cliente propõe o TLS 1.3 e informa o nome do servidor (SNI). É a única informação em claro que revela <b>com quem</b> se fala, não <b>o que</b> se pergunta.', false);
    tr.ev(ch.tSend + WAN / 2, 'ob', 'Vê: SNI dns.example.net', '');
    tr.st(ch.tSend + WAN / 2, 'ob', 'o resolvedor usado, não os nomes', 'est');
    tls('rs', 'cl', 'ServerHello + Certificado', 'O servidor apresenta o certificado. O cliente <b>autentica o resolvedor</b> (nome e cadeia de certificados): ninguém no caminho se passa por ele sem ser detectado.', true);
    tls('cl', 'rs', 'Finished', 'O handshake termina. A partir daqui tudo vai cifrado e com integridade.', true);
    tr.phase('2. Consulta cifrada', 'enc');
    tr.st(tr.t, 'phase', 'cifrado', 'est');
    const body: Field[] = dot
      ? [{ sec: 'Camada TLS' }, ['Conteúdo', 'mensagem DNS com 2 bytes de tamanho (cifrada)', 'o observador vê apenas bytes aleatórios']]
      : [{ sec: 'HTTP/2 sobre TLS' }, [':method', 'POST', ''], [':path', '/dns-query', 'endpoint do DoH (RFC 8484)'], ['content-type', 'application/dns-message', 'a mensagem DNS vai no corpo da requisição']];
    const q = send('cl', 'rs', {
      label: 'A ' + qname + ' (cifrada)',
      info: (dot ? 'TLS' : 'HTTP/2 POST /dns-query') + ': dados da aplicação (cifrados)',
      about: 'A consulta DNS vai <b>dentro do TLS</b>. O observador vê o tamanho e o ritmo dos pacotes, mas não o nome. O quadro abaixo mostra o conteúdo como o cliente e o resolvedor o enxergam.',
      m: dnsQ, tcp: true, enc: true, dur: WAN, extra: [...body], tags: ['cifrado'], plain: false,
    });
    tr.ev(q.tSend + WAN / 2, 'ob', 'Vê: dados cifrados', 'ok');
    tr.st(q.tSend + WAN / 2, 'ob', 'só bytes cifrados e tamanhos', 'est');
    last = send('rs', 'cl', {
      label: 'Resposta ' + WWW_A.d + ' (cifrada)',
      info: (dot ? 'TLS' : 'HTTP/2 200') + ': dados da aplicação (cifrados)',
      about: 'A resposta volta cifrada e autenticada pelo TLS: não pode ser lida nem trocada no caminho.',
      m: dnsA, tcp: true, enc: true, dur: WAN, dport: q.sport as number, tags: ['cifrado'],
      extra: dot ? [{ sec: 'Camada TLS' }, ['Conteúdo', 'mensagem DNS (cifrada)', '']] : [{ sec: 'HTTP/2 sobre TLS' }, [':status', '200', ''], ['content-type', 'application/dns-message', '']],
    });
    tr.st(last.tArr, 'ans', WWW_A.d, 'est');
    step(last.tArr, 'Cliente e resolvedor trocaram a consulta <b>dentro de TLS</b> (' + (dot ? 'DoT, porta 853' : 'DoH, porta 443, HTTP/2') + '). O observador viu só a conexão com ' + IPS.rs + ' e o SNI.');
    concept('DoT e DoH dão confidencialidade, integridade e autenticação do resolvedor entre o cliente e ele.');
    if (dot) concept('DoT usa uma porta própria (853): protege, mas é fácil de identificar e de bloquear.');
    else concept('DoH se mistura ao tráfego HTTPS da porta 443: é difícil de distinguir e de bloquear sem bloquear a web.');
    concept('O resolvedor continua vendo todas as consultas: a confiança passa do provedor da rede para o operador do resolvedor.');
  }
  tr.st(last.tArr, 'phase', 'concluído', 'est');
  tr.mile(last.tArr, 'Resposta', fmtTime(last.tArr));
  tr.ev(last.tArr, 'cl', 'Recebe ' + WWW_A.d, 'ok');
  tr.lg(last.tArr, 'Resposta recebida em ' + fmtTime(last.tArr) + '.', 'conn');
  R.tEnd = last.tArr;
  return tr;
}

export function buildDns(P: DnsParams, sub: string): Trace {
  switch (sub) {
    case 'sec': return buildSec(P);
    case 'env': return buildEnv(P);
    case 'amp': return buildAmp(P);
    case 'priv': return buildPriv(P);
    default: return buildRes(P);
  }
}
