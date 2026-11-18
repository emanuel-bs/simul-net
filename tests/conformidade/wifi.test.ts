// Conformidade do Wi-Fi com a IEEE Std 802.11-2024, independente das impressões digitais (golden).
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { BROADCAST, MAC } from '../../src/sims/wifi/model';
import { wifiProtocol } from '../../src/sims/wifi/protocol';

const roda = (s: (typeof wifiProtocol.scenarios)[number]) => wifiProtocol.build(scenarioParams(wifiProtocol.controls, s), s.sub);
const todas = () => wifiProtocol.scenarios.flatMap((s) => roda(s).msgs.filter((m) => !m.lost).map((m) => ({ id: s.id, m })));
const campo = (m: { fields: unknown[] }, nome: string): string | undefined => {
  const f = m.fields.find((x) => Array.isArray(x) && String(x[0]).startsWith(nome)) as string[] | undefined;
  return f?.[1];
};
const ehDadosComMsdu = (m: { fields: unknown[] }) => campo(m, 'Tipo') === 'Dados (2)' && campo(m, 'Subtipo') === 'Data (0)';
const AP = [MAC.ap, MAC.ap1, MAC.ap2];

describe('Wi-Fi: campos de endereço dos frames de dados (IEEE 802.11-2024, Tabela 9-60)', () => {
  // Tabela 9-60, To DS=1 e From DS=0: Address 1 = BSSID, Address 2 = SA, Address 3 = DA.
  it('To DS=1: o Address 3 é o destino final (DA) e nunca o BSSID', () => {
    const fr = todas().filter(({ m }) => ehDadosComMsdu(m) && /To DS=1; From DS=0/.test(campo(m, 'Flags') ?? ''));
    expect(fr.length).toBeGreaterThan(0);
    fr.forEach(({ id, m }) => {
      expect(AP, `${id}: ${m.label}`).toContain(campo(m, 'Address 1'));
      expect(AP, `${id}: ${m.label} Address 3 não pode ser um AP`).not.toContain(campo(m, 'Address 3'));
    });
  });
  // Um DA de grupo (broadcast) só cabe em quadro de difusão, como o DHCPDISCOVER; os dados unicast de 1500 bytes vão a um destino individual.
  it('dados unicast de 1500 bytes não têm DA de broadcast', () => {
    const fr = todas().filter(({ m }) => ehDadosComMsdu(m) && /1500/.test(JSON.stringify(m.fields)));
    expect(fr.length).toBeGreaterThan(0);
    fr.forEach(({ id, m }) => expect(campo(m, 'Address 3'), `${id}: ${m.label}`).not.toBe(BROADCAST));
  });
  // Tabela 9-60, To DS=0 e From DS=1: Address 1 = DA, Address 2 = BSSID, Address 3 = SA (a origem, e não o AP).
  it('From DS=1: o Address 2 é o BSSID e o Address 3 é a origem (SA), diferente do AP', () => {
    const fr = todas().filter(({ m }) => ehDadosComMsdu(m) && /To DS=0; From DS=1/.test(campo(m, 'Flags') ?? ''));
    expect(fr.length).toBeGreaterThan(0);
    fr.forEach(({ id, m }) => {
      expect(AP, `${id}: ${m.label}`).toContain(campo(m, 'Address 2'));
      expect(campo(m, 'Address 3'), `${id}: ${m.label}`).not.toBe(campo(m, 'Address 2'));
    });
  });
});
