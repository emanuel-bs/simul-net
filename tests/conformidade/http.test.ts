// Conformidade do HTTP/2 e HTTP/3 com as RFCs, independente das impressões digitais (golden).
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { httpProtocol } from '../../src/sims/http-versoes/protocol';

const todos = () =>
  httpProtocol.scenarios.flatMap((s) => {
    const tr = httpProtocol.build(scenarioParams(httpProtocol.controls, s), s.sub);
    return tr.msgs.map((m) => ({ id: s.id, m, campos: (m.fields as unknown[]).filter((f) => Array.isArray(f)) as string[][] }));
  });

describe('HPACK e QPACK: tabelas estáticas (RFC 7541, Apêndice A; RFC 9204, Apêndice A)', () => {
  // ":method GET" e ":scheme https" estão na tabela estática (HPACK: índices 2 e 7; QPACK: 17 e 23), logo vão como índice
  // já no primeiro pedido e nunca entram na tabela dinâmica.
  it('no primeiro pedido HTTP/2, :method e :scheme aparecem como índice da tabela estática, e não como literal', () => {
    const campos = todos().flatMap(({ campos }) => campos).filter((c) => c[0] === ':method' || c[0] === ':scheme');
    expect(campos.length).toBeGreaterThan(0);
    campos.forEach((c) => {
      expect(c[2], c[0]).toMatch(/tabela estática/);
      expect(c[2], c[0]).not.toMatch(/(?<!não )entra na tabela dinâmica/);
    });
  });

  it('no HTTP/3, o campo agrupado distingue o que é índice estático (:method, :scheme) do que é literal (:authority)', () => {
    const campos = todos().flatMap(({ campos }) => campos).filter((c) => c[0] === ':method / :scheme / :authority');
    expect(campos.length).toBeGreaterThan(0);
    campos.forEach((c) => expect(c[2]).toMatch(/estática|índices/));
    const primeiros = campos.filter((c) => /literal/.test(c[2]));
    primeiros.forEach((c) => expect(c[2]).toMatch(/:authority/));
  });
});
