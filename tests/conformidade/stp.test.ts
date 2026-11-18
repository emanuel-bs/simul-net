// Conformidade do spanning tree com a IEEE Std 802.1Q-2022 (cláusulas 13 e 14), independente das impressões digitais (golden).
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { BPDU_MAC, COST, compute, makeBridges, makeLinks } from '../../src/sims/stp/model';
import { stpProtocol } from '../../src/sims/stp/protocol';

const traces = () => stpProtocol.scenarios.map((s) => ({ s, tr: stpProtocol.build(scenarioParams(stpProtocol.controls, s), s.sub) }));
const bpdus = () => traces().flatMap(({ s, tr }) => tr.msgs.filter((m) => ['STP', 'RSTP', 'MSTP'].includes(m.proto as string)).map((m) => ({ s, m })));
const campo = (m: { fields: unknown[] }, nome: string): string | undefined => (m.fields.find((x) => Array.isArray(x) && x[0] === nome) as string[] | undefined)?.[1];

describe('Spanning tree: custos de porta (IEEE 802.1Q-2022, Tabela 13-4)', () => {
  it('os custos recomendados por velocidade são os da Tabela 13-4', () => {
    expect(COST['10m']).toBe(2_000_000);
    expect(COST['100m']).toBe(200_000);
    expect(COST['1g']).toBe(20_000);
    expect(COST['10g']).toBe(2_000);
  });
});

describe('Spanning tree: eleição e papéis das portas (IEEE 802.1Q-2022, seções 13.10 a 13.12)', () => {
  // A ponte de menor Bridge Identifier (prioridade e depois endereço) é a raiz; o SW2 tem o menor MAC.
  it('com prioridades iguais, a raiz é a ponte de menor endereço MAC', () => {
    const t = compute(makeBridges('mac'), makeLinks('1g'));
    expect(t.root).toBe(2);
  });
  it('uma prioridade menor vence o endereço MAC', () => {
    expect(compute(makeBridges('sw1'), makeLinks('1g')).root).toBe(1);
    expect(compute(makeBridges('sw3'), makeLinks('1g')).root).toBe(3);
  });
  // Segmento com dois caminhos de mesmo custo até a raiz: a porta designada é a da ponte de melhor identificador (SW1); a outra fica alternativa.
  it('no enlace SW1-SW3 (custos iguais até a raiz SW2) a porta do SW1 é designada e a do SW3 é alternativa', () => {
    const t = compute(makeBridges('mac'), makeLinks('1g'));
    expect(t.role(1, 'L13')).toBe('designated');
    expect(t.role(3, 'L13')).toBe('alternate');
    expect(t.role(1, 'L12')).toBe('root');
    expect(t.role(3, 'L23')).toBe('root');
  });
  it('um enlace mais lento (100 Mb/s) deixa de ser o caminho de menor custo', () => {
    const t = compute(makeBridges('sw1'), makeLinks('100m'));
    // raiz SW1: SW3 vai pela soma dos enlaces de 1 Gb/s (40000) e não pelo enlace direto de 200000.
    expect(t.rootLink[3]).toBe('L23');
  });
});

describe('Spanning tree: formato das BPDUs (IEEE 802.1Q-2022, seção 14.3)', () => {
  it('toda BPDU vai ao endereço de grupo 01-80-C2-00-00-00 com Protocol ID 0x0000', () => {
    const l = bpdus();
    expect(l.length).toBeGreaterThan(0);
    l.forEach(({ s, m }) => {
      expect(campo(m, 'Destino'), `${s.id}`).toBe(BPDU_MAC);
      expect(campo(m, 'Protocol ID'), `${s.id}`).toBe('0x0000');
    });
  });
  // 14.3: STP Config = versão 0 e tipo 0x00; TCN = versão 0 e tipo 0x80; RST = versão 2 e tipo 0x02; MST = versão 3 e tipo 0x02.
  it('versão e tipo de cada BPDU seguem a seção 14.3', () => {
    const esperado: Record<string, [string, string]> = {
      'Config BPDU': ['0 (STP)', '0x00 (Configuração)'],
      'TCN BPDU': ['0 (STP)', '0x80 (TCN)'],
      'RST BPDU': ['2 (RSTP)', '0x02 (RST BPDU)'],
      'MST BPDU': ['3 (MSTP)', '0x02 (RST BPDU)'],
    };
    bpdus().forEach(({ s, m }) => {
      const e = esperado[String(m.label).replace(/ \(.*\)$/, '')];
      expect(e, `${s.id}: ${m.label}`).toBeDefined();
      expect([campo(m, 'Versão'), campo(m, 'Tipo')], `${s.id}: ${m.label}`).toEqual(e);
    });
  });
  // Figuras 14-1 e 14-2: STP Config 35 octetos, TCN 4, RST 36 (com Version 1 Length) e MST 102 mais 16 por MSTI; mais 14 do Ethernet e 3 do LLC.
  it('tamanho do frame = 14 + 3 + comprimento da BPDU', () => {
    bpdus().forEach(({ s, m }) => {
      const rotulo = String(m.label);
      if (/^TCN/.test(rotulo)) expect(m.len, `${s.id}`).toBe(14 + 3 + 4);
      else if (/^Config/.test(rotulo)) expect(m.len, `${s.id}`).toBe(14 + 3 + 35);
      else if (/^RST/.test(rotulo)) expect(m.len, `${s.id}`).toBe(14 + 3 + 36);
      else if (/^MST/.test(rotulo)) {
        // Version 3 Length (14.1) = 64 + 16 por MSTI; a BPDU tem 38 + Version 3 Length octetos.
        const v3 = Number(campo(m, 'Versão 3 Length'));
        expect(v3 % 16, `${s.id}`).toBe(0);
        expect(m.len, `${s.id}: v3 ${v3}`).toBe(14 + 3 + 38 + v3);
        // m-one: só o CIST (64); m-two: duas MSTIs (64 + 32).
        expect(v3, `${s.id}`).toBe(s.id === 'm-two' ? 96 : 64);
      }
    });
  });
  it('os temporizadores anunciados são os padrões da Tabela 13-5 (Hello 2 s, Max Age 20 s, Forward Delay 15 s)', () => {
    bpdus().filter(({ m }) => !/^TCN/.test(String(m.label))).forEach(({ s, m }) => {
      expect(campo(m, 'Hello Time'), `${s.id}`).toBe('2 s');
      expect(campo(m, 'Max Age'), `${s.id}`).toBe('20 s');
      expect(campo(m, 'Forward Delay'), `${s.id}`).toBe('15 s');
    });
  });
  // 14.2.7: o Port Identifier tem 4 bits de prioridade (múltiplo de 16; padrão 128) e 12 bits de número, que nunca é 0.
  it('o Port ID tem prioridade 128 e número de porta maior que 0', () => {
    bpdus().filter(({ m }) => campo(m, 'ID da porta')).forEach(({ s, m }) => {
      const [p, n] = (campo(m, 'ID da porta') as string).split('.').map(Number);
      expect(p, `${s.id}`).toBe(128);
      expect(n, `${s.id}`).toBeGreaterThanOrEqual(1);
    });
  });
});
