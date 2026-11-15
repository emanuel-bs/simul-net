// Conformidade do MPLS/LDP com a RFC 5036, independente das impressões digitais (golden).
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { mplsProtocol } from '../../src/sims/mpls/protocol';

describe('LDP: mensagem Initialization (RFC 5036, seção 3.5.3)', () => {
  // A mensagem leva Protocol Version, KeepAlive Time, os bits A (modo de anúncio) e D (detecção de laço), PVLim, Max PDU Length
  // e o Receiver LDP Identifier. Os modos de controle e de retenção (seções 2.6.1 e 2.6.2) são comportamento local, não campos.
  it('não apresenta controle nem retenção como campos da mensagem', () => {
    let vistas = 0;
    mplsProtocol.scenarios.forEach((s) => {
      const tr = mplsProtocol.build(scenarioParams(mplsProtocol.controls, s), s.sub);
      tr.msgs.filter((m) => m.label === 'Initialization' || String(m.label).startsWith('Initialization')).forEach((m) => {
        vistas++;
        const nomes = (m.fields as unknown[]).filter((f) => Array.isArray(f)).map((f) => (f as string[])[0]);
        expect(nomes, s.id).not.toContain('Controle');
        expect(nomes, s.id).not.toContain('Retenção');
        expect(nomes.join('|'), s.id).toMatch(/Protocol Version/);
        expect(nomes.join('|'), s.id).toMatch(/KeepAlive Time/);
      });
    });
    expect(vistas).toBeGreaterThan(0);
  });
});
