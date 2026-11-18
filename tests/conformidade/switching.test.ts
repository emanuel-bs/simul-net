// Conformidade do switching (ponte MAC) com a IEEE Std 802.1Q-2022 (cláusula 8), independente das impressões digitais (golden).
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { AGING_S, BCAST } from '../../src/sims/switching/model';
import { switchingProtocol } from '../../src/sims/switching/protocol';

const run = (id: string) => {
  const s = switchingProtocol.scenarios.find((x) => x.id === id)!;
  return switchingProtocol.build(scenarioParams(switchingProtocol.controls, s), s.sub);
};
const campo = (m: { fields: unknown[] }, nome: string): string | undefined => (m.fields.find((x) => Array.isArray(x) && x[0] === nome) as string[] | undefined)?.[1];
const daSw = (tr: ReturnType<typeof run>, label: string) => tr.msgs.filter((m) => m.from === 'sw' && m.label === label).map((m) => m.to as string);

describe('Switching: tabela de endereços (IEEE 802.1Q-2022, seção 8.8 e Tabela 8-9)', () => {
  // Tabela 8-9: tempo de envelhecimento padrão de 300 s, faixa de 10 a 1.000.000 s.
  it('o tempo de envelhecimento padrão é 300 s e as opções do simulador ficam dentro da faixa 10 a 1.000.000 s', () => {
    expect(AGING_S).toBe(300);
    const c = switchingProtocol.controls.find((x) => x.id === 'aging')!;
    (c.opts as [number, string][]).forEach(([v]) => {
      expect(v).toBeGreaterThanOrEqual(10);
      expect(v).toBeLessThanOrEqual(1_000_000);
    });
  });
});

describe('Switching: encaminhamento e filtragem (IEEE 802.1Q-2022, seções 8.6.1 e 8.6.3)', () => {
  it('destino desconhecido: inunda todas as portas, menos a de entrada; depois do aprendizado, só a porta do destino', () => {
    const tr = run('a-first');
    const req = daSw(tr, 'Echo Request');
    // primeiro frame: B, C e D (portas 2 e 3); segundo frame: só B
    expect(req.slice(0, 3).sort()).toEqual(['b', 'c', 'd']);
    expect(req.slice(3)).toEqual(['b']);
    expect(req).not.toContain('a');
  });
  it('broadcast é sempre inundado e a resposta unicast vai só ao solicitante', () => {
    const tr = run('a-bcast');
    expect(daSw(tr, 'ARP Request').sort()).toEqual(['b', 'c', 'd']);
    expect(daSw(tr, 'ARP Reply')).toEqual(['a']);
    expect(tr.msgs.find((m) => m.label === 'ARP Request' && m.from === 'a' && m.to === 'sw' && campo(m, 'Destino') === BCAST)).toBeDefined();
  });
  // 8.6.1: o frame não é enviado pela porta em que o destino está, se for a de recepção (filtragem).
  it('destino na mesma porta de entrada: o switch filtra (não envia cópia)', () => {
    const tr = run('a-filter');
    const copias = tr.msgs.filter((m) => m.from === 'sw' && m.label === 'Echo Request');
    // o primeiro Echo Request é de C para D (mesma porta 3): nenhuma cópia; o segundo é de C para A: uma cópia, à porta 1
    expect(copias.map((m) => m.to)).toEqual(['a']);
  });
});

describe('Switching: endereços de grupo reservados (IEEE 802.1Q-2022, 8.6.3 e Tabela 8-1)', () => {
  // "The FDB entries for reserved MAC addresses shall specify filtering for all Bridge Ports and all VIDs."
  it('frames para 01-80-C2-00-00-00 (BPDU) e 01-80-C2-00-00-0E (LLDP) não são encaminhados', () => {
    const tr = run('e-reserved');
    expect(daSw(tr, 'BPDU')).toEqual([]);
    expect(daSw(tr, 'LLDP')).toEqual([]);
    // para comparar, o unicast desconhecido é inundado
    expect(daSw(tr, 'Echo Request').length).toBeGreaterThan(0);
  });
});

describe('Switching: tamanhos dos frames (convenção de docs/arquitetura.md, seção 11, e IEEE 802.1Q-2022, Figura 14-1)', () => {
  it('ARP = 42 e ICMP Echo = 98 bytes', () => {
    run('a-bcast').msgs.filter((m) => /^ARP/.test(String(m.label))).forEach((m) => expect(m.len).toBe(42));
    run('a-first').msgs.filter((m) => /^Echo/.test(String(m.label))).forEach((m) => expect(m.len).toBe(98));
  });
  // Ethernet 14 + LLC 3 + BPDU de configuração de 35 octetos, sem preenchimento (mesmo valor do simulador de spanning tree).
  it('a BPDU de configuração tem 52 bytes (14 + 3 + 35)', () => {
    run('e-reserved').msgs.filter((m) => m.label === 'BPDU').forEach((m) => expect(m.len).toBe(52));
  });
  // LLDPDU mínimo: Chassis ID (9), Port ID (4), TTL (4) e fim (2) depois dos 14 do Ethernet.
  it('o LLDP mínimo tem 33 bytes (14 + 9 + 4 + 4 + 2)', () => {
    const l = run('e-reserved').msgs.filter((m) => m.label === 'LLDP');
    expect(l.length).toBeGreaterThan(0);
    l.forEach((m) => expect(m.len).toBe(33));
  });
  // RFC 9776, 4.1.8 e 4.2: cabeçalho IP com Router Alert de 24 bytes, 8 do relatório IGMPv3 e 8 do registro de grupo sem fontes.
  it('o relatório IGMPv3 com um grupo tem 54 bytes (14 + 24 + 8 + 8)', () => {
    const r = run('e-mc-snoop').msgs.filter((m) => m.label === 'IGMP Membership Report');
    expect(r.length).toBeGreaterThan(0);
    r.forEach((m) => expect(m.len).toBe(54));
  });
});
