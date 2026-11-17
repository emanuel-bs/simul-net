import { describe, expect, it } from 'vitest';
import { COR, degrau, grafico, teto } from '../../src/sim-core/doc-chart';
import { tcpProtocol } from '../../src/sims/tcp/protocol';
import { ripProtocol } from '../../src/sims/rip/protocol';
import { httpProtocol } from '../../src/sims/http-versoes/protocol';

const linhasDe = (md: string): number[][] => [...md.matchAll(/^ {2}line \[([^\]]*)\]$/gm)].map((m) => m[1].split(', ').map(Number));

describe('gráficos da documentação: módulo comum', () => {
  it('a série em degraus segura o valor até a próxima amostra e é zero antes da primeira', () => {
    const a = [{ t: 10, v: 1 }, { t: 20, v: 5 }];
    expect(degrau(a, 0, 30, 4, (x) => x.v)).toEqual([0, 1, 5, 5]);
  });

  it('o teto do eixo fica acima do maior valor', () => {
    expect(teto([{ nome: 'a', cor: COR.azul, v: [3, 97] }])).toBeGreaterThanOrEqual(97);
  });

  it('o bloco traz a legenda em texto, o comentário para a figura e uma cor por linha', () => {
    const md = grafico({ titulo: 'T', x: 'X', y: 'Y', de: 0, ate: 10 }, [{ nome: 'A', cor: COR.vermelho, v: [1, 2] }, { nome: 'B', cor: COR.verde, v: [2, 3] }]);
    expect(md).toContain('**Legenda:** 🟥 A · 🟩 B');
    expect(md).toContain('%% legenda: A | B');
    expect(md).toContain('"plotColorPalette": "#dd2e44, #2e9e4f"');
    expect(linhasDe(md)).toEqual([[1, 2], [2, 3]]);
  });
});

describe('gráficos da documentação: TCP e HTTP', () => {
  const tcp = (id: string) => tcpProtocol.scenarios.find((s) => s.id === id)!;
  const http = (id: string) => httpProtocol.scenarios.find((s) => s.id === id)!;

  it('TCP: o handshake não tem curva; o slow start mostra a cwnd chegando ao ssthresh de 8', () => {
    expect(tcpProtocol.docChart!(tcp('hs'))).toBe('');
    const g = tcpProtocol.docChart!(tcp('ss'));
    const [cwnd, ssthresh] = linhasDe(g);
    expect(cwnd[0]).toBe(1);
    expect(Math.max(...ssthresh)).toBe(8);
    expect(Math.max(...cwnd)).toBeGreaterThan(8);
  });

  it('TCP: no cenário da janela do receptor, a rwnd aparece como terceira linha', () => {
    expect(linhasDe(tcpProtocol.docChart!(tcp('rwnd'))).length).toBe(3);
    expect(linhasDe(tcpProtocol.docChart!(tcp('ss'))).length).toBe(2);
  });

  it('HTTP: cada cenário tem as três versões, de 0 até o total de recursos', () => {
    const g = httpProtocol.docChart!(http('h2-many'));
    const linhas = linhasDe(g);
    expect(linhas.length).toBe(3);
    linhas.forEach((l) => {
      expect(l[0]).toBe(0);
      expect(l[l.length - 1]).toBe(16);
      expect(l).toEqual([...l].sort((a, b) => a - b));
    });
  });

  it('HTTP: a perda segura recursos do HTTP/2 e atrasa só um recurso no HTTP/3', () => {
    const [h1, h2, h3] = linhasDe(httpProtocol.docChart!(http('h2-loss')));
    // Nos instantes em que o HTTP/3 já recebeu tudo menos o recurso perdido, o HTTP/2 ainda segura os que ficaram atrás dele.
    const i = h3.findIndex((n) => n === 7);
    expect(i).toBeGreaterThan(0);
    expect(h2[i]).toBeLessThan(7);
    expect(h1[h1.length - 1]).toBe(8);
  });
});

describe('gráficos da documentação: RIP', () => {
  const rip = (id: string) => ripProtocol.scenarios.find((s) => s.id === id)!;

  it('convergência: R1 aprende um salto por rodada, de 16 (sem rota) até a métrica final (saltos + 1)', () => {
    const [r2, r3, r6] = linhasDe(ripProtocol.docChart!(rip('rip')));
    expect(r2.slice(0, 3)).toEqual([16, 2, 2]);
    expect(r3.slice(0, 4)).toEqual([16, 16, 3, 3]);
    expect(r6.slice(0, 5)).toEqual([16, 16, 16, 4, 4]);
  });

  it('queda de enlace: R2 perde a rota para R3 na hora e a recupera por outro caminho', () => {
    const [, r2, , inf] = linhasDe(ripProtocol.docChart!(rip('ripfail')));
    expect(r2[0]).toBe(2);
    expect(r2[1]).toBe(16);
    expect(r2[r2.length - 1]).toBe(4);
    expect(new Set(inf)).toEqual(new Set([16]));
  });

  it('contagem ao infinito: a menor métrica para R6 sobe uma unidade por rodada até 16, com ou sem split horizon', () => {
    for (const id of ['infinity', 'ripiso']) {
      const [menor] = linhasDe(ripProtocol.docChart!(rip(id)));
      expect(menor.slice(0, 15)).toEqual(Array.from({ length: 15 }, (_, i) => i + 2));
    }
  });
});
