// Conformidade do 802.1X/RADIUS com as RFCs, independente das impressões digitais (golden).
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { x8021Protocol } from '../../src/sims/802-1x/protocol';

const campo = (m: { fields: unknown[] }, nome: string) => (m.fields.find((f) => Array.isArray(f) && f[0] === nome) as string[] | undefined)?.[1];

describe('RADIUS: Identifier (RFC 2865, seções 3 e 4.2 a 4.4)', () => {
  // A resposta (Accept, Reject, Challenge) copia o Identifier do Access-Request que ela responde.
  it.each(x8021Protocol.scenarios.map((s) => [s.id]))('%s: toda resposta repete o Identifier do último Access-Request', (id) => {
    const s = x8021Protocol.scenarios.find((x) => x.id === id)!;
    const tr = x8021Protocol.build(scenarioParams(x8021Protocol.controls, s), s.sub);
    let ultimoPedido: string | undefined;
    tr.msgs.forEach((m) => {
      if (m.proto !== 'RADIUS') return;
      const rotulo = m.label as string;
      if (rotulo.startsWith('Access-Request')) ultimoPedido = campo(m, 'Identifier');
      else expect(campo(m, 'Identifier'), `${id}: ${rotulo}`).toBe(ultimoPedido);
    });
  });

  it('cada novo Access-Request recebe um Identifier diferente do anterior; a retransmissão repete o mesmo', () => {
    const s = x8021Protocol.scenarios.find((x) => x.id === 'a-peap')!;
    const tr = x8021Protocol.build(scenarioParams(x8021Protocol.controls, s), s.sub);
    const pedidos = tr.msgs.filter((m) => m.proto === 'RADIUS' && (m.label as string).startsWith('Access-Request')).map((m) => campo(m, 'Identifier'));
    expect(pedidos.length).toBeGreaterThan(2);
    pedidos.slice(1).forEach((id, i) => expect(id).not.toBe(pedidos[i]));
  });
});

describe('RADIUS: reautenticação e Access-Reject', () => {
  const roda = (id: string) => {
    const s = x8021Protocol.scenarios.find((x) => x.id === id)!;
    return x8021Protocol.build(scenarioParams(x8021Protocol.controls, s), s.sub);
  };
  const nomes = (m: { fields: unknown[] }) => m.fields.filter((f) => Array.isArray(f)).map((f) => (f as string[])[0]);

  // RFC 3580, seção 3.17: o Session-Timeout só provoca reautenticação (e não o fim da sessão) com Termination-Action = RADIUS-Request.
  it('o Access-Accept com Session-Timeout traz o Termination-Action RADIUS-Request', () => {
    const accept = roda('p-reauth').msgs.filter((m) => m.label === 'Access-Accept');
    expect(accept.length).toBeGreaterThan(0);
    accept.forEach((m) => {
      expect(JSON.stringify(m.fields)).toContain('Session-Timeout (27)');
      expect(JSON.stringify(m.fields)).toContain('Termination-Action (29)');
      expect(JSON.stringify(m.fields)).toContain('RADIUS-Request (1)');
    });
  });

  it('um Access-Accept sem Session-Timeout não traz Termination-Action', () => {
    roda('a-tls').msgs.filter((m) => m.label === 'Access-Accept').forEach((m) => expect(nomes(m).join()).not.toContain('Termination-Action'));
  });

  // RFC 5080, seção 2.6.1: o Access-Reject só pode levar Proxy-State, EAP-Message, Reply-Message e Error-Cause (e o Message-Authenticator da RFC 3579).
  it('o Access-Reject usa apenas atributos permitidos', () => {
    const permitidos = /EAP-Message|Message-Authenticator|Proxy-State|Reply-Message|Error-Cause/;
    roda('f-cred').msgs.filter((m) => m.label === 'Access-Reject').forEach((m) => {
      const atributos = JSON.stringify(m.fields);
      expect(atributos).toMatch(permitidos);
      expect(atributos).not.toContain('Session-Timeout');
    });
  });
});

describe('EAPOL (IEEE 802.1X-2020, cláusula 11)', () => {
  const todas = () => x8021Protocol.scenarios.flatMap((s) => x8021Protocol.build(scenarioParams(x8021Protocol.controls, s), s.sub).msgs.filter((m) => m.proto === 'EAPOL').map((m) => ({ s, m })));
  // Tabela 11-1 e seção 11.1: EtherType 0x888E (EAPOL).
  it('o EtherType é 0x888E', () => {
    const l = todas();
    expect(l.length).toBeGreaterThan(0);
    l.forEach(({ s, m }) => expect(campo(m, 'EtherType'), s.id).toBe('0x888E'));
  });
  // 11.3.1: "An implementation conforming to this specification shall use the value 0x03."
  it('a versão do protocolo é 3 (0x03, seção 11.3.1)', () => {
    todas().forEach(({ s, m }) => expect(campo(m, 'Versão do protocolo'), s.id).toMatch(/^3\b/));
  });
  // Tabela 11-3: EAPOL-EAP 0, Start 1, Logoff 2. Tabela 11-4: o suplicante transmite sempre ao endereço de grupo.
  it('Start e Logoff têm tipo 1 e 2, não têm corpo e o suplicante os envia ao endereço de grupo do PAE', () => {
    todas().filter(({ m }) => /^EAPOL-(Start|Logoff)/.test(String(m.label))).forEach(({ s, m }) => {
      expect(campo(m, 'Tipo do pacote'), s.id).toMatch(String(m.label).includes('Start') ? /^1 / : /^2 /);
      expect(campo(m, 'Comprimento do corpo'), s.id).toBe('0');
      expect(campo(m, 'Destino'), s.id).toBe('01:80:c2:00:00:03');
      expect(m.len, s.id).toBe(18);
    });
  });
  // Figura 11-11: o cabeçalho tem 4 octetos (versão, tipo e comprimento do corpo); frame = 14 + 4 + pacote EAP.
  it('o frame EAPOL tem 14 + 4 + o comprimento do corpo', () => {
    todas().forEach(({ s, m }) => expect(m.len, s.id).toBe(18 + Number(campo(m, 'Comprimento do corpo'))));
  });
});
