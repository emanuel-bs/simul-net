// Conformidade do DNS e do DNSSEC com as RFCs, independente das impressões digitais (golden).
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { dnsProtocol } from '../../src/sims/dns/protocol';

type Campo = [string, string, string?];
const todos = () =>
  dnsProtocol.scenarios.flatMap((s) => {
    const tr = dnsProtocol.build(scenarioParams(dnsProtocol.controls, s), s.sub);
    return tr.msgs.map((m) => ({ id: s.id, m, campos: (m.fields as unknown[]).filter((f) => Array.isArray(f)) as Campo[] }));
  });
const ttlDe = (c: Campo) => Number(/TTL (\d+) s/.exec(c[2] ?? '')?.[1]);

describe('DNSSEC: RRSIG (RFC 4034, seções 3.1.3 e 3.1.4; RFC 4035, seção 2.2)', () => {
  // O Original TTL e o TTL do próprio RRSIG são iguais ao TTL do RRset coberto.
  it('o TTL do RRSIG e o Original TTL são os do RRset que ele cobre', () => {
    let rrsigs = 0;
    let comPar = 0;
    todos().forEach(({ id, m, campos }) => {
      campos.filter((c) => c[1].startsWith('RRSIG ')).forEach((c) => {
        rrsigs++;
        const [, coberto, , , origTtl] = c[1].split(' ');
        expect(coberto, `${id}: tipo coberto`).not.toBe('ANY');
        expect(Number(origTtl), `${id}: ${c[0]} Original TTL`).toBe(ttlDe(c));
        const par = campos.find((x) => x !== c && x[0] === c[0] && x[1].startsWith(coberto + ' ') && !x[1].startsWith('RRSIG '));
        if (par) {
          comPar++;
          expect(ttlDe(c), `${id}: ${m.label}: RRSIG de ${coberto} em ${c[0]}`).toBe(ttlDe(par));
        }
      });
    });
    expect(rrsigs).toBeGreaterThan(0);
    expect(comPar).toBeGreaterThan(0);
  });
});

describe('DNS: textos (RFC 2308, seção 5; draft do 0x20)', () => {
  const textos = () => todos().flatMap(({ m }) => [String(m.about ?? ''), String(m.info ?? '')]);
  // RFC 2308, seção 5: o TTL do cache negativo é o menor entre o TTL do SOA e o campo MINIMUM.
  it('a regra do cache negativo cita os dois valores (TTL do SOA e MINIMUM)', () => {
    const negativos = textos().filter((t) => /cache negativ|NXDOMAIN/i.test(t) && /minimum|TTL do SOA/i.test(t));
    expect(negativos.length).toBeGreaterThan(0);
    negativos.forEach((t) => expect(t).toMatch(/menor/i));
  });

  // O RFC 7873 trata de DNS Cookies; a técnica 0x20 é descrita num Internet-Draft, que nunca virou RFC.
  it('a técnica 0x20 não é atribuída ao RFC 7873', () => {
    todos().forEach(({ id, m }) => expect(String(m.about ?? ''), id).not.toMatch(/0x20[^.]*RFC 7873/));
  });
});
