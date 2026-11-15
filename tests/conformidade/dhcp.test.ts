// Conformidade do DHCP com a RFC 2131, independente das impressões digitais (golden).
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { dhcpProtocol } from '../../src/sims/dhcp/protocol';

const roda = (s: (typeof dhcpProtocol.scenarios)[number]) => dhcpProtocol.build(scenarioParams(dhcpProtocol.controls, s), s.sub);
const todas = () => dhcpProtocol.scenarios.flatMap((s) => roda(s).msgs.map((m) => ({ id: s.id, m })));

describe('DHCP (RFC 2131)', () => {
  // Seção 4.4.4: "the client broadcasts DHCPDECLINE messages" (o cliente ainda não tem o endereço que está recusando).
  it('o DHCPDECLINE é enviado em broadcast, com origem 0.0.0.0 e Server Identifier', () => {
    const declines = todas().filter(({ m }) => (m.label as string).includes('DECLINE'));
    expect(declines.length).toBeGreaterThan(0);
    declines.forEach(({ id, m }) => {
      const campos = JSON.stringify(m.fields);
      expect(campos, `${id}: IP de destino`).toContain('255.255.255.255');
      expect(campos, `${id}: MAC de destino`).toContain('ff:ff:ff:ff:ff:ff');
      expect(campos, `${id}: Server Identifier`).toMatch(/Server Identifier|Identificador do servidor/i);
    });
  });

  // Seção 4.4.4: o DHCPRELEASE é unicast para o servidor.
  it('o DHCPRELEASE continua em unicast para o servidor', () => {
    const releases = todas().filter(({ m }) => (m.label as string).includes('RELEASE'));
    releases.forEach(({ id, m }) => expect(JSON.stringify(m.fields), id).not.toContain('255.255.255.255'));
  });

  // Seção 2 e Tabela 1: siaddr é o servidor do próximo passo do bootstrap, e não "o servidor que respondeu".
  it('a nota do campo siaddr descreve o próximo servidor do bootstrap', () => {
    const notas = todas().flatMap(({ m }) => m.fields.filter((f) => Array.isArray(f) && f[0] === 'siaddr').map((f) => (f as string[])[2] ?? ''));
    expect(notas.length).toBeGreaterThan(0);
    notas.forEach((n) => {
      expect(n).toMatch(/bootstrap/i);
      expect(n).not.toMatch(/que respondeu/i);
    });
  });
});
