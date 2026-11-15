// Conformidade do TCP com as RFCs, independente das impressões digitais (golden).
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { tcpProtocol } from '../../src/sims/tcp/protocol';

const roda = (id: string, rwnd: number) => {
  const s = tcpProtocol.scenarios.find((x) => x.id === id)!;
  return tcpProtocol.build({ ...scenarioParams(tcpProtocol.controls, s), rwnd }, s.sub);
};
const campo = (m: { fields: unknown[] }, nome: string) => (m.fields.find((f) => Array.isArray(f) && f[0] === nome) as string[] | undefined)?.[1] ?? '';
const tcp = (tr: ReturnType<typeof roda>) => tr.msgs.filter((m) => m.proto === 'TCP');

describe('TCP: campo Janela e Window Scale (RFC 9293, seção 3.1; RFC 7323, seções 2.2 e 2.3)', () => {
  // O campo Window tem 16 bits. Acima de 65535 bytes só é possível com a opção Window Scale, negociada nos dois SYN.
  it('com janela de 256 segmentos (256000 bytes), o campo nunca passa de 65535 e o Window Scale é negociado', () => {
    const msgs = tcp(roda('ss', 256));
    expect(msgs.length).toBeGreaterThan(5);
    msgs.forEach((m) => expect(parseInt(campo(m, 'Janela'), 10), String(m.label)).toBeLessThanOrEqual(65535));
    const syns = msgs.filter((m) => /^SYN/.test(m.label as string));
    expect(syns.length).toBe(2);
    syns.forEach((m) => expect(campo(m, 'Opções'), String(m.label)).toContain('WS=2 (x4)'));
    const comJanelaGrande = msgs.filter((m) => /256000/.test(campo(m, 'Janela')));
    expect(comJanelaGrande.length).toBeGreaterThan(0);
  });

  it('com janela de até 64 segmentos, não há Window Scale e o campo traz os bytes', () => {
    const msgs = tcp(roda('ss', 32));
    msgs.filter((m) => /^SYN/.test(m.label as string)).forEach((m) => expect(campo(m, 'Opções')).not.toMatch(/WS=/));
    expect(msgs.some((m) => campo(m, 'Janela').startsWith('32000'))).toBe(true);
  });

  it('o SYN não escala a janela (RFC 7323, seção 2.2)', () => {
    tcp(roda('ss', 256)).filter((m) => /^SYN/.test(m.label as string)).forEach((m) => expect(campo(m, 'Janela')).not.toMatch(/256000/));
  });
});
