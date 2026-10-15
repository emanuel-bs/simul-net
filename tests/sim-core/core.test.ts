import { describe, expect, it } from 'vitest';
import { COLORS, b64, esc, fmtMs, hex, newTrace, plural, prepare, timeAt } from '../../src/sim-core';

describe('sim-core: valores determinísticos', () => {
  it('hex e b64 são estáveis e do tamanho pedido', () => {
    expect(hex('a', 16)).toBe(hex('a', 16));
    expect(hex('a', 16)).toHaveLength(32);
    expect(hex('a', 16)).not.toBe(hex('b', 16));
    expect(b64('fp', 43)).toHaveLength(43);
    expect(b64('fp', 43)).toMatch(/^[A-Za-z0-9+/]+$/);
  });

  it('formata tempo, plural e escapa HTML', () => {
    expect(fmtMs(12.34)).toBe('12,3 ms');
    expect(fmtMs(20)).toBe('20 ms');
    expect(plural(1, 'tentativa', 'tentativas')).toBe('1 tentativa');
    expect(plural(3, 'tentativa', 'tentativas')).toBe('3 tentativas');
    expect(esc('<a href="x">&</a>')).toBe('&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;');
  });
});

describe('sim-core: trace', () => {
  it('usa meio RTT por mensagem e avança o cursor com o processamento', () => {
    const tr = newTrace([{ key: 'c', label: 'C' }, { key: 's', label: 'S' }], [], 40);
    expect(tr.ow).toBe(20);
    const m = tr.add('c', 's', { label: 'x' });
    expect([m.tSend, m.tArr, m.id]).toEqual([0, 20, 0]);
    expect(tr.t).toBeCloseTo(20.4);
    const n = tr.add('s', 'c', { proc: 0 });
    expect([n.tSend, n.tArr]).toEqual([tr.msgs[0].tArr + 0.4, tr.msgs[0].tArr + 0.4 + 20]);
    expect(tr.t).toBe(n.tArr);
  });

  it('mensagens simultâneas (par) e instante fixo (at) não avançam o cursor', () => {
    const tr = newTrace([], [], 20);
    tr.add('c', 's', { par: true });
    expect(tr.t).toBe(0);
    const m = tr.add('s', 'c', { par: true, at: 5, dur: 3 });
    expect([m.tSend, m.tArr, tr.t]).toEqual([5, 8, 0]);
  });

  it('prepare converte tempos em linhas distintas e crescentes', () => {
    const tr = newTrace([], [], 20);
    tr.add('c', 's', { color: COLORS.enc });
    tr.add('s', 'c', {});
    tr.ev(0, 'c', 'a');
    tr.lg(10, 'b');
    const endR = prepare(tr);
    expect(tr.times).toEqual([0, 10, 10.4, 20.4]);
    expect(endR).toBeCloseTo(3.6);
    expect(tr.msgs.map((m) => [m.rS, m.rA])).toEqual([[0, 1], [2, 3]]);
    expect(tr.log[0].r).toBe(1);
    expect(timeAt(tr, 1.5)).toBeCloseTo(10.2);
    expect(timeAt(tr, 99)).toBe(20.4);
    expect(timeAt(tr, -1)).toBe(0);
  });
});
