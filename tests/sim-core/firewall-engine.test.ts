// Regras do motor do Firewall: filtro sem estado, tabela de conexões, expiração, zonas, filtro de origem e limite de taxa.
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { controls } from '../../src/sims/firewall/content/controls';
import { scenarios } from '../../src/sims/firewall/content/scenarios';
import { buildFirewall, connsAt, type FwParams, type Hit } from '../../src/sims/firewall/engine';

const run = (id: string, over: Partial<FwParams> = {}) => {
  const s = scenarios.find((x) => x.id === id)!;
  const P = { ...scenarioParams(controls, s), ...over } as unknown as FwParams;
  return buildFirewall(P, s.sub);
};
const lost = (tr: ReturnType<typeof run>) => tr.msgs.filter((m) => m.lost);
const hits = (tr: ReturnType<typeof run>) => tr.raw.hits as Hit[];

describe('filtro sem estado', () => {
  it('com regra de ida e de volta a conexão se completa, sem nenhum pacote negado', () => {
    const tr = run('a-ok');
    expect(lost(tr)).toHaveLength(0);
    expect(tr.raw.result).toBe('ok');
    expect(tr.raw.stateful).toBe(false);
  });

  it('sem regra de retorno o SYN+ACK é negado e o SYN é retransmitido depois de 1 s', () => {
    const tr = run('a-noret');
    expect(lost(tr).map((m) => m.label)).toEqual(['SYN+ACK', 'SYN+ACK']);
    const syns = tr.msgs.filter((m) => m.label === 'SYN' && m.from === 'int');
    expect(syns).toHaveLength(2);
    expect(syns[1].tSend - syns[0].tSend).toBeGreaterThanOrEqual(1000);
  });

  it('a regra genérica antes da específica nega o SYN, e a específica nunca é usada', () => {
    const tr = run('a-order');
    expect(hits(tr).every((h) => h.n === 1 && !h.ok)).toBe(true);
    expect(hits(tr).some((h) => h.n === 2)).toBe(false);
  });

  it('política padrão: negar bloqueia o UDP 53 e permitir o deixa passar', () => {
    expect(lost(run('a-implicit'))).toHaveLength(1);
    expect(lost(run('a-defpermit'))).toHaveLength(0);
    expect(hits(run('a-implicit'))[0].via).toBe('politica');
  });

  it('o retorno por porta de origem deixa passar um pacote de fora; por ACK, não', () => {
    expect(run('a-weak').raw.result).toBe('fraco');
    expect(lost(run('a-weak'))).toHaveLength(0);
    expect(run('a-ack').raw.result).toBe('ack-barra');
    expect(lost(run('a-ack'))).toHaveLength(1);
  });
});

describe('filtro com estado', () => {
  it('o retorno passa pela tabela, e só o SYN é decidido por regra', () => {
    const tr = run('e-tcp');
    expect(hits(tr).filter((h) => h.via === 'regra')).toHaveLength(1);
    expect(hits(tr).filter((h) => h.via === 'estado')).toHaveLength(4);
    expect(lost(tr)).toHaveLength(0);
  });

  it('a entrada TCP passa por SYN_SENT, SYN_RECV e ESTABLISHED', () => {
    const tr = run('e-tcp');
    expect(connsAt(tr, tr.msgs[0].tArr)[0].state).toBe('SYN_SENT');
    expect(connsAt(tr, tr.msgs[2].tArr)[0].state).toBe('SYN_RECV');
    expect(connsAt(tr, 1e9)[0].state).toBe('ESTABLISHED');
  });

  it('no encerramento a entrada passa por FIN_WAIT e TIME_WAIT e depois some', () => {
    const tr = run('e-fim');
    const states = (tr.raw.conns as { op: string; c: { state: string } }[]).filter((e) => e.op === 'set').map((e) => e.c.state);
    expect(states).toEqual(['SYN_SENT', 'SYN_RECV', 'ESTABLISHED', 'FIN_WAIT', 'TIME_WAIT']);
    expect(connsAt(tr, 1e9)).toHaveLength(0);
  });

  it('pacotes sem conexão são negados como fora de estado, e o pedido novo pela política', () => {
    const tr = run('e-esp');
    expect(hits(tr).map((h) => h.via)).toEqual(['invalido', 'invalido', 'politica']);
    expect(connsAt(tr, 1e9)).toHaveLength(0);
  });

  it('a resposta UDP dentro da validade passa; depois da validade é negada', () => {
    expect(lost(run('e-udp'))).toHaveLength(0);
    const tr = run('e-udp-late');
    expect(lost(tr).map((m) => m.label)).toEqual(['Resposta DNS']);
    expect(connsAt(tr, 1e9)).toHaveLength(0);
  });

  it('o ICMP Echo Reply consome a entrada, e uma segunda resposta é negada', () => {
    const tr = run('e-icmp');
    expect(hits(tr).map((h) => [h.via, h.ok])).toEqual([['regra', true], ['estado', true], ['invalido', false]]);
  });

  it('com a tabela cheia, os pedidos seguintes são negados', () => {
    const tr = run('e-full');
    expect(tr.raw.result).toBe('cheia');
    expect(lost(tr)).toHaveLength(2);
    expect(hits(tr).filter((h) => h.via === 'tabela')).toHaveLength(2);
    expect(run('e-full', { eLimite: 6 }).raw.result).toBe('nao-cheia');
  });
});

describe('zonas e DMZ', () => {
  it('só a Internet para o servidor web e a administração interna passam', () => {
    expect(lost(run('d-pub'))).toHaveLength(0);
    expect(lost(run('d-admin'))).toHaveLength(0);
    expect(lost(run('d-in')).length).toBeGreaterThan(0);
  });

  it('a regra DMZ para interna nega; a permissiva deixa o servidor alcançar o banco de dados', () => {
    expect(run('d-contain').raw.result).toBe('lateral-barrado');
    expect(run('d-leaky').raw.result).toBe('lateral-livre');
    expect(hits(run('d-contain')).every((h) => h.n === 5 && !h.ok)).toBe(true);
  });

  it('o filtro de saída da DMZ nega, e liberado permite', () => {
    expect(run('d-egress').raw.result).toBe('egresso-barrado');
    expect(run('d-egress-open').raw.result).toBe('egresso-livre');
  });
});

describe('forja, varredura e limite de taxa', () => {
  it('sem filtro de origem o pacote com origem interna vindo de fora entra e o dono responde RST', () => {
    const tr = run('f-in-off');
    expect(tr.raw.result).toBe('forja-passou');
    expect(tr.msgs.some((m) => m.label === 'RST' && m.from === 'int')).toBe(true);
    expect(hits(tr)[0].n).toBe(4);
  });

  it('com o filtro de origem, a decisão vem do filtro e antes das regras', () => {
    expect(hits(run('f-in-on'))[0].via).toBe('antispoof');
    expect(hits(run('f-out-on'))[0].via).toBe('antispoof');
    expect(run('f-out-off').raw.result).toBe('saida-passou');
  });

  it('a varredura: 80 e 443 respondem; as demais são descartadas ou recusadas com RST', () => {
    const drop = run('f-scan-drop');
    expect(lost(drop)).toHaveLength(3);
    expect(drop.msgs.filter((m) => (m.label ?? '').startsWith('RST'))).toHaveLength(0);
    const rej = run('f-scan-reject');
    expect(rej.msgs.filter((m) => (m.label ?? '').startsWith('RST'))).toHaveLength(3);
    expect(rej.msgs.filter((m) => m.label === 'SYN+ACK' && m.to === 'fw')).toHaveLength(2);
  });

  it('o limite de taxa deixa passar 3 de 6 pedidos; sem ele, passam todos', () => {
    expect(lost(run('f-rate-on'))).toHaveLength(3);
    expect(hits(run('f-rate-on')).filter((h) => h.via === 'taxa')).toHaveLength(3);
    expect(lost(run('f-rate-off'))).toHaveLength(0);
  });

  it('o conteúdo cifrado atravessa o firewall sem exame', () => {
    const tr = run('f-blind');
    expect(tr.msgs.filter((m) => m.enc).length).toBeGreaterThan(0);
    expect(lost(tr)).toHaveLength(0);
  });
});
