// Conformidade do NAT com as RFCs 2663 e 3022, independente das impressões digitais (golden).
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { IP, NAT_IN } from '../../src/sims/nat/engine';
import { natProtocol } from '../../src/sims/nat/protocol';

const campo = (m: { fields: unknown[] }, nome: string) => (m.fields.find((f) => Array.isArray(f) && f[0] === nome) as string[] | undefined)?.[1] ?? '';

describe('NAT: redirecionamento transparente para um proxy na mesma rede do cliente', () => {
  const s = natProtocol.scenarios.find((x) => x.id === 'n-proxy')!;
  const tr = natProtocol.build(scenarioParams(natProtocol.controls, s), s.sub);

  // O proxy (192.168.1.50) está na mesma sub-rede do cliente. Sem trocar também a origem (SNAT), o proxy responderia
  // direto ao cliente, que descartaria a resposta por vir de endereço inesperado (o mesmo problema do hairpin, RFC 4787, seção 6).
  it('o pedido ao proxy sai do roteador com a origem trocada (SNAT), e a resposta volta ao roteador', () => {
    const paraProxy = tr.msgs.find((m) => m.to === 'web')!;
    expect(campo(paraProxy, 'Origem')).toContain(NAT_IN);
    expect(campo(paraProxy, 'Origem')).not.toContain(IP.pc1);
    const doProxy = tr.msgs.find((m) => m.from === 'web')!;
    expect(doProxy.to).toBe('nat');
  });

  it('o roteador devolve ao cliente a resposta com a origem do servidor original e o destino do cliente', () => {
    const final = tr.msgs[tr.msgs.length - 1];
    expect(final.to).toBe('pc1');
    expect(campo(final, 'Origem')).toContain('198.51.100.10');
    expect(campo(final, 'Destino')).toContain(IP.pc1);
  });
});
