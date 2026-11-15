// Conformidade do BGP com as RFCs, independente das impressões digitais (golden).
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { ASES } from '../../src/sims/bgp/model';
import { bgpProtocol } from '../../src/sims/bgp/protocol';

const campo = (m: { fields: unknown[] }, nome: string) => (m.fields.find((f) => Array.isArray(f) && f[0] === nome) as string[] | undefined)?.[1];

describe('BGP: campo My Autonomous System do OPEN (RFC 6793, seção 3)', () => {
  // Todos os ASN do simulador cabem em 2 octetos: o campo leva o próprio número. O AS_TRANS (23456) só vale
  // quando o falante não tem um ASN de 2 octetos.
  it('com ASN de 2 octetos, o OPEN leva o próprio ASN, nunca o AS_TRANS', () => {
    Object.values(ASES).forEach((a) => expect(a.asn).toBeLessThanOrEqual(65535));
    const validos = new Set(Object.values(ASES).map((a) => String(a.asn)));
    let abertos = 0;
    bgpProtocol.scenarios.forEach((s) => {
      const tr = bgpProtocol.build(scenarioParams(bgpProtocol.controls, s), s.sub);
      tr.msgs.forEach((m) => {
        const v = campo(m, 'My Autonomous System');
        if (v === undefined) return;
        abertos++;
        expect(validos.has(v), `${s.id}: ${v}`).toBe(true);
        expect(v).not.toContain('23456');
      });
    });
    expect(abertos).toBeGreaterThan(0);
  });
});
