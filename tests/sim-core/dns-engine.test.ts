// Regras do motor do DNS: percurso da resolução, cache, falhas, DNSSEC, envenenamento, amplificação e DoT/DoH.
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { controls } from '../../src/sims/dns/content/controls';
import { scenarios } from '../../src/sims/dns/content/scenarios';
import { buildDns, type CacheEv, type ChainRow, type DnsParams } from '../../src/sims/dns/engine';
import { cacheAt } from '../../src/sims/dns/topology';

const run = (id: string, over: Partial<DnsParams> = {}) => {
  const s = scenarios.find((x) => x.id === id)!;
  const P = { ...scenarioParams(controls, s), ...over } as unknown as DnsParams;
  return buildDns(P, s.sub);
};
const labels = (tr: ReturnType<typeof run>) => tr.msgs.map((m) => m.label as string);
const to = (tr: ReturnType<typeof run>, who: string) => tr.msgs.filter((m) => m.to === who && !m.lost);
const chain = (tr: ReturnType<typeof run>) => (tr.raw.chain as ChainRow[]).map((r) => r.estado);

describe('resolução', () => {
  it('cache frio: raiz, .com e autoritativo, nessa ordem, e uma resposta ao cliente', () => {
    const tr = run('r-completa');
    expect(tr.raw.queries).toBe(3);
    expect(tr.msgs.filter((m) => m.from === 'rs' && m.to !== 'cl').map((m) => m.to)).toEqual(['rt', 'tl', 'au']);
    expect(to(tr, 'cl')).toHaveLength(1);
  });

  it('delegações em cache reduzem as consultas', () => {
    expect(run('r-tld').raw.queries).toBe(2);
    expect(run('r-ns').raw.queries).toBe(1);
  });

  it('resposta em cache: nenhuma consulta a servidores e resposta sem AA', () => {
    const tr = run('r-cache');
    expect(tr.raw.queries).toBe(0);
    expect(tr.msgs).toHaveLength(2);
    expect(tr.msgs[1].fields.some((f) => !('sec' in f) && f[0] === 'Flags' && f[1].includes('AA'))).toBe(false);
  });

  it('o autoritativo responde com AA e o resolvedor guarda a resposta no cache', () => {
    const tr = run('r-ns');
    const au = to(tr, 'rs').find((m) => m.from === 'au')!;
    expect(au.fields.some((f) => !('sec' in f) && f[0] === 'Flags' && f[1].includes('AA'))).toBe(true);
    expect(cacheAt(tr, 1e12).some((e) => e.n === 'www.example.com' && e.ty === 'A')).toBe(true);
  });

  it('NXDOMAIN guarda a negação (cache negativo)', () => {
    const tr = run('r-nx');
    expect((tr.raw.cacheEv as CacheEv[]).some((e) => e.neg)).toBe(true);
  });

  it('CNAME devolve o apelido e o registro final numa só resposta', () => {
    const m = to(run('r-cname'), 'rs').find((x) => x.from === 'au')!;
    expect(m.info).toContain('CNAME');
    expect(m.info).toContain('192.0.2.80');
  });

  it('perda: retransmite depois de 800 ms; ns1 fora do ar: tenta ns2', () => {
    const perda = run('r-perda');
    const lost = perda.msgs.find((m) => m.lost)!;
    const retry = perda.msgs.find((m) => !m.lost && m.from === 'rs' && m.to === 'au')!;
    expect(retry.tSend - lost.tSend).toBeGreaterThanOrEqual(800);
    const falha = run('r-ns1');
    expect(falha.msgs.some((m) => m.to === 'a2' && !m.lost)).toBe(true);
    expect(falha.msgs.some((m) => m.to === 'au' && m.lost)).toBe(true);
  });

  it('resposta truncada: TC=1 e nova consulta por TCP', () => {
    const tr = run('r-tcp');
    expect(tr.raw.truncated).toBe(true);
    expect(labels(tr)).toContain('SYN');
    expect(tr.msgs.some((m) => m.proto === 'DNS/TCP')).toBe(true);
  });
});

describe('DNSSEC', () => {
  it('cadeia válida: todos os elos ok e resposta com AD', () => {
    const tr = run('s-ok');
    expect(chain(tr)).toEqual(['ok', 'ok', 'ok', 'ok']);
    expect(tr.raw.result).toBe('ok');
    expect(tr.msgs[tr.msgs.length - 1].tags).toContain('AD=1');
  });

  it('assinatura vencida e DS que não casa: SERVFAIL', () => {
    const exp = run('s-expirada');
    expect(chain(exp)).toEqual(['ok', 'ok', 'ok', 'falhou']);
    expect(exp.raw.result).toBe('servfail');
    const ds = run('s-dsruim');
    expect(chain(ds)).toEqual(['ok', 'ok', 'falhou', 'nao-verificado']);
    expect(ds.raw.result).toBe('servfail');
  });

  it('sem DS: zona insegura, resposta aceita sem AD', () => {
    const tr = run('s-insegura');
    expect(tr.raw.result).toBe('semAD');
    expect(chain(tr)).toContain('sem-ds');
  });

  it('resolvedor que não valida entrega a resposta mesmo com assinatura inválida', () => {
    const tr = run('s-semval');
    expect(tr.raw.result).toBe('semAD');
    expect(chain(tr).every((x) => x === 'nao-verificado')).toBe(true);
  });

  it('negação autenticada traz NSEC e AD', () => {
    const tr = run('s-nx');
    expect(tr.raw.result).toBe('ok');
    expect(tr.msgs.some((m) => m.fields.some((f) => !('sec' in f) && f[1].startsWith('NSEC')))).toBe(true);
  });
});

describe('envenenamento de cache', () => {
  it('sem defesa o cache é envenenado; com porta e ID aleatórios, não', () => {
    expect(run('e-nenhuma').raw.poisoned).toBe(true);
    expect(run('e-aleatoria').raw.poisoned).toBe(false);
  });
  it('palpite certo: envenena com porta e ID aleatórios, mas não com 0x20 nem com DNSSEC', () => {
    expect(run('e-sorte').raw.poisoned).toBe(true);
    expect(run('e-x20').raw.poisoned).toBe(false);
    expect(run('e-dnssec').raw.poisoned).toBe(false);
  });
  it('o cache envenenado fica marcado como falso', () => {
    expect(cacheAt(run('e-nenhuma'), 1e12).some((e) => e.bad)).toBe(true);
    expect(cacheAt(run('e-dnssec'), 1e12).some((e) => e.bad)).toBe(false);
  });
});

describe('amplificação', () => {
  it('resolvedor aberto com ANY amplifica muito; consulta A amplifica pouco', () => {
    expect(run('a-aberto').raw.fator).toBeGreaterThan(10);
    expect(run('a-a').raw.fator).toBeLessThan(run('a-aberto').raw.fator);
  });
  it('BCP 38, ACL e RRL neutralizam', () => {
    expect(run('a-bcp38').raw.recvB).toBe(0);
    expect(run('a-acl').raw.fator).toBeLessThan(2);
    expect(run('a-rrl').raw.fator).toBeLessThan(2);
  });
});

describe('DoT e DoH', () => {
  it('DNS puro: o observador lê o nome; DoT e DoH: só dados cifrados', () => {
    const lerNome = (tr: ReturnType<typeof run>) => tr.events.some((e) => e.who === 'ob' && e.text.includes('www.example.com'));
    expect(lerNome(run('p-udp'))).toBe(true);
    expect(lerNome(run('p-dot'))).toBe(false);
    expect(lerNome(run('p-doh'))).toBe(false);
  });
  it('porta 853 bloqueada: política estrita não consulta; oportunista volta ao UDP', () => {
    expect(run('p-estrita').raw.result).toBe('falhou');
    expect(run('p-estrita').msgs.some((m) => m.proto === 'DNS')).toBe(false);
    const op = run('p-oport');
    expect(op.msgs.some((m) => m.proto === 'DNS' && !m.enc)).toBe(true);
  });
});
