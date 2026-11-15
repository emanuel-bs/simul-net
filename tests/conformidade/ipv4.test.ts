// Conformidade do IPv4/ARP com as RFCs, independente das impressões digitais (golden).
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { ipv4Protocol } from '../../src/sims/ipv4/protocol';

const campo = (m: { fields: unknown[] }, nome: string) => (m.fields.find((f) => Array.isArray(f) && f[0] === nome) as string[] | undefined)?.[1];
const MAC: Record<string, string> = { a: '00:00:5e:00:53:0a', b: '00:00:5e:00:53:14', r: '00:00:5e:00:53:01', s: '00:00:5e:00:53:32' };

describe('ARP no IPv4 (RFC 826)', () => {
  // A resposta ARP é unicast para quem perguntou: o destino do quadro Ethernet é o MAC do solicitante, e não o de quem responde.
  it('o quadro da resposta ARP é endereçado ao MAC do solicitante; a requisição vai em broadcast', () => {
    let respostas = 0;
    ipv4Protocol.scenarios.forEach((s) => {
      const tr = ipv4Protocol.build(scenarioParams(ipv4Protocol.controls, s), s.sub);
      tr.msgs.filter((m) => m.proto === 'ARP').forEach((m) => {
        const dest = campo(m, 'Destino');
        if ((m.label as string).includes('quem tem')) expect(dest, `${s.id}: requisição`).toBe('ff:ff:ff:ff:ff:ff');
        else {
          respostas++;
          expect(dest, `${s.id}: ${m.label}`).toBe(MAC[m.to as string]);
        }
      });
    });
    expect(respostas).toBeGreaterThan(0);
  });
});
