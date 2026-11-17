// Conformidade do RIPv2 com a RFC 2453, independente das impressões digitais (golden).
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { SINGLE } from '../../src/sims/roteamento-base/topologia';
import { liveLinks } from '../../src/sims/roteamento-base/topologia';
import { INF, initTables, ripRound, type Tables } from '../../src/sims/rip/model';
import { ripProtocol } from '../../src/sims/rip/protocol';

const traces = () => ripProtocol.scenarios.map((s) => ({ s, tr: ripProtocol.build(scenarioParams(ripProtocol.controls, s), s.sub) }));
const responses = () => traces().flatMap(({ s, tr }) => tr.msgs.filter((m) => m.proto === 'RIPv2' && !m.lost).map((m) => ({ s, m })));

describe('RIPv2: métrica (RFC 2453, seções 3.5 e 3.9.2)', () => {
  // 3.5: a métrica de uma rede diretamente conectada é o custo dela, normalmente 1. 3.9.2: métrica válida está entre 1 e 16.
  it('a tabela inicial de cada roteador tem a rota própria com métrica 1 (custo da rede conectada)', () => {
    const tb = initTables(SINGLE);
    SINGLE.routers.forEach((r) => expect(tb[r.id].get(r.id)!.metric, r.id).toBe(1));
  });
  it('nenhuma entrada de Response anuncia métrica fora de 1 a 16', () => {
    let vistas = 0;
    responses().forEach(({ s, m }) => {
      m.fields.forEach((f) => {
        if (!Array.isArray(f) || !/^Rota /.test(f[0])) return;
        vistas++;
        const n = Number(/métrica (\d+)/.exec(f[1])![1]);
        expect(n, `${s.id}: ${m.label} ${f[0]}`).toBeGreaterThanOrEqual(1);
        expect(n, `${s.id}: ${m.label} ${f[0]}`).toBeLessThanOrEqual(INF);
      });
    });
    expect(vistas).toBeGreaterThan(0);
  });
});

describe('RIPv2: processamento de Response (RFC 2453, seção 3.9.2)', () => {
  // "If there is no such route, add this route to the routing table, unless the metric is infinity."
  it('não cria rota nova para um destino desconhecido quando a métrica recebida é infinito', () => {
    const links = liveLinks(SINGLE);
    const tb: Tables = initTables(SINGLE);
    // R2 anuncia a R1 um destino que R1 não conhece, com métrica 16.
    tb.R2.set('X', { metric: INF, next: 'R3' });
    const r = ripRound(SINGLE, links, tb, true);
    expect(r.next.R1.has('X')).toBe(false);
  });
});

describe('RIPv2: formato da mensagem (RFC 2453, seções 3.6 e 4.5)', () => {
  it('Response é enviada ao multicast 224.0.0.9', () => {
    const rs = responses();
    expect(rs.length).toBeGreaterThan(0);
    rs.forEach(({ s, m }) => expect(m.fields.find((f) => Array.isArray(f) && f[0] === 'Destino IP'), `${s.id}`).toEqual(expect.arrayContaining(['224.0.0.9'])));
  });
  it('cada mensagem leva no máximo 25 entradas', () => {
    responses().forEach(({ s, m }) => {
      const e = m.fields.find((f) => Array.isArray(f) && f[0] === 'Entradas') as string[];
      expect(Number(e[1]), `${s.id}: ${m.label}`).toBeLessThanOrEqual(25);
    });
  });
  // Convenção de tamanhos (arquitetura, seção 11): Ethernet 14 + IPv4 20 + UDP 8 + cabeçalho RIP 4 + 20 por entrada (seção 3.6).
  it('len = 14 + 20 + 8 + 4 + 20 por entrada', () => {
    responses().forEach(({ s, m }) => {
      const e = m.fields.find((f) => Array.isArray(f) && f[0] === 'Entradas') as string[];
      expect(m.len, `${s.id}: ${m.label}`).toBe(46 + 20 * Number(e[1]));
    });
  });
});
