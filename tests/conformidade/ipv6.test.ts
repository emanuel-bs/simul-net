// Conformidade do IPv6 com as RFCs, independente das impressões digitais (golden).
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { classify6, scope6 } from '../../src/sims/ipv6/model';
import { ipv6Protocol } from '../../src/sims/ipv6/protocol';

const campo = (m: { fields: unknown[] }, nome: string) => (m.fields.find((f) => Array.isArray(f) && f[0] === nome) as string[] | undefined)?.[1];

describe('IPv6: classificação de endereços (RFC 4291, seção 2.4)', () => {
  it('só 2000::/3 é unicast global; o resto do espaço não delegado não é', () => {
    expect(classify6('2606:4700::1').nome).toBe('Unicast global');
    expect(classify6('3fff:ffff::1').nome).toBe('Unicast global');
    ['4000::1', '8000::1', 'c000::1', '1000::1', '::ffff:102:304', '100::1'].forEach((ip) => expect(classify6(ip).nome, ip).not.toBe('Unicast global'));
  });

  it('os blocos especiais continuam classificados pelo prefixo mais longo', () => {
    expect(classify6('2001:db8::1').nome).toBe('Documentação');
    expect(classify6('fe80::1').nome).toBe('Link-local');
    expect(classify6('fd00::1').nome).toBe('Local único (ULA)');
    expect(classify6('ff02::1').nome).toBe('Multicast');
    expect(classify6('::1').nome).toBe('Loopback');
  });
});

describe('IPv6: escopo do multicast (RFC 4291, seção 2.7)', () => {
  // ff0X: o escopo é o último dígito do primeiro grupo de 16 bits (os 4 bits baixos do segundo octeto).
  it('o escopo vem do último dígito hexadecimal do primeiro grupo', () => {
    expect(scope6('ff02::1')).toMatch(/enlace/i);
    expect(scope6('ff05::2')).toMatch(/local|site/i);
    expect(scope6('ff0e::1')).toMatch(/global/i);
  });
});

describe('IPv6: Neighbor Advertisement (RFC 4861, seção 4.4)', () => {
  // O flag R indica que quem anuncia é um roteador; um host não o liga.
  it('o flag R aparece apenas quando quem responde é roteador', () => {
    let nas = 0;
    let deHost = 0;
    ipv6Protocol.scenarios.forEach((s) => {
      const tr = ipv6Protocol.build(scenarioParams(ipv6Protocol.controls, s), s.sub);
      tr.msgs.filter((m) => (m.label as string).startsWith('NA: ')).forEach((m) => {
        nas++;
        const flags = campo(m, 'Flags') ?? '';
        const roteador = /^r/.test(m.from as string);
        if (!roteador) deHost++;
        expect(/\bR\b/.test(flags), `${s.id}: ${m.label} de ${m.from}`).toBe(roteador);
        // a resposta a uma solicitação liga o S; o NA não solicitado do DAD ("já é meu") não o liga
        expect(/\bS\b/.test(flags), `${s.id}: ${m.label}`).toBe((m.label as string).includes(' está em '));
      });
    });
    expect(nas).toBeGreaterThan(0);
    expect(deHost).toBeGreaterThan(0);
  });
});
