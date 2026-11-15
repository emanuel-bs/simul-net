// Conformidade do ARP com a RFC 826, independente das impressões digitais (golden).
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { arpProtocol } from '../../src/sims/arp/protocol';

describe('ARP: rótulos dos campos (RFC 826)', () => {
  // THA é o endereço físico do alvo; TPA é o endereço de protocolo (IP) do alvo. A nota do THA não pode citar o TPA.
  it('a nota do endereço físico do alvo fala de THA, e não de TPA', () => {
    let vistos = 0;
    arpProtocol.scenarios.forEach((s) => {
      const tr = arpProtocol.build(scenarioParams(arpProtocol.controls, s), s.sub);
      tr.msgs.forEach((m) => {
        const f = m.fields.find((x) => Array.isArray(x) && x[0] === 'Endereço físico do alvo') as string[] | undefined;
        if (!f) return;
        vistos++;
        expect(f[2], `${s.id}: ${m.label}`).toMatch(/THA/);
        expect(f[2], `${s.id}: ${m.label}`).not.toMatch(/TPA/);
      });
    });
    expect(vistos).toBeGreaterThan(0);
  });
});
