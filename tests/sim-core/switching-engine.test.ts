// Regras do motor do Switching: aprendizado, inundação, filtragem, envelhecimento, mudança de porta, inundação de MAC e multicast.
import { describe, expect, it } from 'vitest';
import { scenarioParams, type Params } from '../../src/sim-core/ui';
import { controls } from '../../src/sims/switching/content/controls';
import { scenarios } from '../../src/sims/switching/content/scenarios';
import { switchingProtocol } from '../../src/sims/switching/protocol';
import { tableAt, type Decision, type MacEv } from '../../src/sims/switching/model';

const run = (id: string, over: Params = {}) => {
  const s = scenarios.find((x) => x.id === id)!;
  return switchingProtocol.build({ ...scenarioParams(controls, s), ...over }, s.sub);
};
const dec = (tr: ReturnType<typeof run>) => tr.raw.dec as Decision[];
const table = (tr: ReturnType<typeof run>) => tableAt(tr.raw.mac as MacEv[], 1e9);

describe('aprendizado e encaminhamento', () => {
  it('destino desconhecido é inundado, e depois da resposta o encaminhamento é unicast', () => {
    const d = dec(run('a-first'));
    expect(d.map((x) => x.action)).toEqual(['flood', 'forward', 'forward']);
    expect(d[1].out).toEqual([1]);
    expect(d[2].out).toEqual([2]);
  });

  it('sem resposta de B, o switch nunca o aprende', () => {
    const tr = run('a-noreply');
    expect(dec(tr).map((x) => x.action)).toEqual(['flood', 'flood']);
    expect(table(tr).map((r) => r.port)).toEqual([1]);
  });

  it('o broadcast é sempre inundado e nunca entra na tabela', () => {
    const tr = run('a-bcast');
    expect(dec(tr)[0].action).toBe('flood');
    expect(table(tr).some((r) => r.mac === 'ff:ff:ff:ff:ff:ff')).toBe(false);
  });

  it('origem e destino na mesma porta: o quadro é filtrado', () => {
    const d = dec(run('a-filter'));
    expect(d[0].action).toBe('filter');
    expect(d[0].out).toEqual([]);
  });

  it('o quadro enviado à porta antiga se perde, e a transmissão de B corrige a tabela', () => {
    const tr = run('a-move');
    expect(tr.msgs.filter((m) => m.lost)).toHaveLength(1);
    expect(table(tr).find((r) => r.mac.endsWith('14'))!.port).toBe(4);
    expect(dec(tr).map((x) => x.out[0])).toEqual([2, 2, 1, 4]);
  });

  it('as entradas expiram depois do tempo de envelhecimento e o destino volta a ser inundado', () => {
    const tr = run('a-aging');
    expect(dec(tr).map((x) => x.action)).toEqual(['forward', 'flood', 'forward']);
    expect((tr.raw.mac as MacEv[]).filter((e) => e.op === 'del')).toHaveLength(2);
    const t = run('a-aging', { aging: 60 });
    expect((t.raw.mac as MacEv[]).filter((e) => e.op === 'del')[0].t).toBeLessThan(61000);
  });
});

describe('inundação de MAC e segurança de porta', () => {
  it('com a tabela cheia, o tráfego de A e B é inundado e M o recebe', () => {
    const tr = run('i-leak');
    expect(tr.raw.full).toBe(true);
    expect(tr.raw.seen).toBe(3);
    expect(tr.raw.result).toBe('leak');
  });

  it('entradas anteriores não são apagadas: M não recebe quadros legítimos', () => {
    const tr = run('i-present');
    expect(tr.raw.seen).toBe(0);
    expect(tr.raw.result).toBe('safe');
  });

  it('sem ataque, M recebe só o primeiro quadro', () => {
    expect(run('i-normal').raw.seen).toBe(1);
  });

  it('protect e restrict descartam o excedente e impedem que a tabela encha', () => {
    for (const id of ['i-protect', 'i-restrict']) {
      const tr = run(id);
      expect(tr.raw.full).toBe(false);
      expect(tr.raw.accepted).toBe(1);
      expect(tr.raw.violations).toBe(3);
      expect(tr.raw.seen).toBe(1);
    }
  });

  it('shutdown desativa a porta na primeira violação e tira M da rede', () => {
    const tr = run('i-shutdown');
    expect(tr.raw.down).toBe(true);
    expect(tr.raw.forged).toBe(2);
    expect(tr.raw.seen).toBe(0);
  });
});

describe('broadcast, multicast e reservados', () => {
  it('sem snooping o multicast é inundado; com snooping vai só à porta do assinante', () => {
    const flood = dec(run('e-mc-flood')).filter((x) => x.label.startsWith('Dados'));
    expect(flood.every((x) => x.action === 'flood' && x.out.length === 2)).toBe(true);
    const snoop = dec(run('e-mc-snoop')).filter((x) => x.label.startsWith('Dados'));
    expect(snoop.every((x) => x.action === 'group' && x.out.join() === '2')).toBe(true);
  });

  it('grupo sem assinantes não sai por nenhuma porta', () => {
    const d = dec(run('e-mc-none')).filter((x) => x.label.startsWith('Dados'));
    expect(d.every((x) => x.out.length === 0)).toBe(true);
  });

  it('endereços reservados são consumidos e a origem não é aprendida', () => {
    const tr = run('e-reserved');
    expect(dec(tr).slice(0, 2).map((x) => x.action)).toEqual(['consume', 'consume']);
    expect(dec(tr)[2].action).toBe('flood');
  });
});
