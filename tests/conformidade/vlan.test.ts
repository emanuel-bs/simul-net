// Conformidade da VLAN com a IEEE Std 802.1Q-2022 (e 802.3-2022 para o tamanho), independente das impressões digitais (golden).
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { HOSTS, makeNet, ping, spread, type Wire } from '../../src/sims/vlan/model';
import { vlanProtocol } from '../../src/sims/vlan/protocol';

const traces = () => vlanProtocol.scenarios.map((s) => ({ s, tr: vlanProtocol.build(scenarioParams(vlanProtocol.controls, s), s.sub) }));
const msgs = () => traces().flatMap(({ s, tr }) => tr.msgs.map((m) => ({ s, m })));
const campos = (m: { fields: unknown[] }, nome: string): string[] => m.fields.filter((x) => Array.isArray(x) && x[0] === nome).map((x) => (x as string[])[1]);

describe('VLAN: formato da tag (IEEE 802.1Q-2022, seções 9.5 e 9.6, Tabelas 9-1 e 9-2)', () => {
  it('toda tag C-TAG usa o TPID 0x8100', () => {
    let n = 0;
    msgs().forEach(({ s, m }) => campos(m, 'TPID').forEach((t) => { n++; expect(t, `${s.id}: ${m.label}`).toBe('0x8100'); }));
    expect(n).toBeGreaterThan(0);
  });
  // Tabela 9-2: VID 0 é o "null VID" (só prioridade) e 0xFFF (4095) é reservado e "shall not be transmitted in a tag header".
  it('nenhuma tag transmitida leva VID 0 nem 4095, e o VID cabe em 12 bits', () => {
    msgs().forEach(({ s, m }) => campos(m, 'VID').forEach((v) => {
      const n = Number(v);
      expect(n, `${s.id}: ${m.label}`).toBeGreaterThanOrEqual(1);
      expect(n, `${s.id}: ${m.label}`).toBeLessThanOrEqual(4094);
    }));
  });
  // 4 octetos por tag (TPID de 2 e TCI de 2, seção 9.5) sobre o tamanho do frame sem tag.
  it('cada tag soma 4 bytes ao tamanho do frame', () => {
    const base = (m: { len?: number; fields: unknown[] }) => (m.len as number) - 4 * campos(m, 'VID').length;
    msgs().filter(({ m }) => m.proto === '802.1Q').forEach(({ s, m }) => expect([42, 70, 98], `${s.id}: ${m.label}`).toContain(base(m)));
  });
});

describe('VLAN: classificação na entrada e remarcação na saída (IEEE 802.1Q-2022, seções 6.9 e 8.6)', () => {
  const net = makeNet();
  it('frame sem tag em porta de acesso entra na VLAN da porta (PVID) e chega sem tag ao host da mesma VLAN', () => {
    const sp = spread(net, 'a', ping(HOSTS.a, HOSTS.c));
    expect(sp.delivered).toContain('c');
    const ultimo = sp.steps.filter((s) => s.t === 'msg' && s.to === 'c')[0] as { wire: Wire };
    expect(ultimo.wire.tags).toEqual([]);
  });
  it('o tronco leva o frame da VLAN 10 com tag 10 e a VLAN nativa sem tag', () => {
    const tronco = (nat: number) => (spread(makeNet({ nat1: nat, nat2: nat }), 'a', ping(HOSTS.a, HOSTS.c)).steps.find((s) => s.t === 'msg' && s.from === 'sw1' && s.to === 'sw2') as { wire: Wire }).wire.tags;
    expect(tronco(1)).toEqual([10]);
    expect(tronco(10)).toEqual([]);
  });
  // Filtragem na entrada (ingress filtering): um frame cuja VLAN não é membro da porta é descartado.
  it('frame com tag de outra VLAN em porta de acesso é descartado', () => {
    const w = ping(HOSTS.a, HOSTS.b);
    w.tags = [20];
    const sp = spread(net, 'a', w);
    expect(sp.delivered).not.toContain('b');
    expect(sp.dropped).toContain('sw1');
  });
  it('VLAN fora da lista permitida do tronco não atravessa', () => {
    expect(spread(makeNet({ allowed: [20] }), 'a', ping(HOSTS.a, HOSTS.c)).delivered).not.toContain('c');
  });
  it('broadcast fica contido na VLAN da porta de entrada', () => {
    const w = { ...ping(HOSTS.a, HOSTS.c), dmac: 'ff:ff:ff:ff:ff:ff' };
    const sp = spread(net, 'a', w);
    expect(sp.delivered).toContain('c');
    expect(sp.delivered).not.toContain('b');
    expect(sp.delivered).not.toContain('d');
  });
});
