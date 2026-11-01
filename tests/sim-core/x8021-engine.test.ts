// Regras do motor de 802.1X: porta fechada até o Accept, EAP sobre EAPOL e RADIUS, recusas, falta de resposta,
// reautenticação, logoff, segundo dispositivo e riscos com defesas.
import { describe, expect, it } from 'vitest';
import { scenarioParams, type Params } from '../../src/sim-core/ui';
import { controls } from '../../src/sims/802-1x/content/controls';
import { scenarios } from '../../src/sims/802-1x/content/scenarios';
import { METHODS, RADIUS_TRIES } from '../../src/sims/802-1x/model';
import { x8021Protocol } from '../../src/sims/802-1x/protocol';

const run = (id: string, over: Params = {}) => {
  const s = scenarios.find((x) => x.id === id)!;
  return x8021Protocol.build({ ...scenarioParams(controls, s), ...over }, s.sub);
};
const labels = (tr: ReturnType<typeof run>) => tr.msgs.map((m) => m.label as string);
const states = (tr: ReturnType<typeof run>) => (tr.raw.port as { state: string }[]).map((p) => p.state);
const frames = (tr: ReturnType<typeof run>) => tr.raw.frames as { ok: boolean; who: string }[];

describe('autenticação bem-sucedida', () => {
  it.each(['tls', 'peap', 'md5'] as const)('%s: a porta começa fechada, abre só com o Access-Accept e o dado passa depois', (method) => {
    const tr = run('a-tls', { method });
    expect(states(tr)).toEqual(['unauth', 'authing', 'auth']);
    expect(frames(tr).map((f) => f.ok)).toEqual([false, true]);
    const l = labels(tr);
    expect(l.indexOf('Access-Accept')).toBeGreaterThan(-1);
    expect(l.indexOf('EAP-Success')).toBeGreaterThan(l.indexOf('Access-Accept'));
    expect(tr.raw.res).toBe('ok');
  });

  it.each(['tls', 'peap', 'md5'] as const)('%s: uma rodada de EAP por Access-Challenge, e o Success repete o último Identifier', (method) => {
    const tr = run('a-tls', { method });
    const n = METHODS[method].rounds.length;
    expect(tr.msgs.filter((m) => m.proto === 'RADIUS' && (m.label as string).startsWith('Access-Challenge')).length).toBe(n);
    const requests = tr.msgs.filter((m) => m.proto === 'EAPOL' && (m.label as string).startsWith('EAP-Request/') && m.label !== 'EAP-Request/Identity');
    expect(requests.length).toBe(n);
    const success = tr.msgs.find((m) => m.label === 'EAP-Success')!;
    const eapIds = (m: typeof success) => (m.fields.find((f) => Array.isArray(f) && f[0] === 'Identifier') as string[])[1];
    expect(eapIds(success)).toBe(eapIds(requests[requests.length - 1]));
  });

  it('o EAP viaja em EAPOL do lado do suplicante e em RADIUS do lado do servidor', () => {
    const tr = run('a-peap');
    tr.msgs.forEach((m) => {
      if (m.proto === 'EAPOL') expect([m.from, m.to].sort()).toEqual(['nas', 'sup']);
      if (m.proto === 'RADIUS') expect([m.from, m.to].sort()).toEqual(['nas', 'srv']);
    });
  });

  it('o PEAP protege as últimas rodadas com o túnel e o EAP-MD5 não protege nenhuma', () => {
    expect(run('a-peap').msgs.some((m) => m.enc)).toBe(true);
    expect(run('a-md5').msgs.some((m) => m.enc)).toBe(false);
  });

  it('é determinístico', () => {
    expect(JSON.stringify(run('a-tls'))).toBe(JSON.stringify(run('a-tls')));
  });
});

describe('recusas', () => {
  it('senha incorreta: Reject depois da rodada decisiva e a porta continua fechada', () => {
    const tr = run('f-cred');
    expect(labels(tr)).toContain('Access-Reject');
    expect(labels(tr)).not.toContain('Access-Accept');
    expect(states(tr).pop()).toBe('unauth');
    expect(frames(tr).map((f) => f.ok)).toEqual([false]);
    // o servidor decide depois da resposta decisiva do PEAP: ainda faltam rodadas que nem chegam a acontecer
    expect(tr.msgs.filter((m) => m.proto === 'RADIUS' && (m.label as string).startsWith('Access-Challenge')).length).toBe(METHODS.peap.decisive + 1);
  });

  it('certificado expirado no EAP-TLS: o servidor recusa na segunda rodada', () => {
    const tr = run('f-cert');
    expect(tr.raw.res).toBe('cert');
    expect(tr.msgs.filter((m) => m.proto === 'RADIUS' && (m.label as string).startsWith('Access-Challenge')).length).toBe(METHODS.tls.decisive + 1);
    expect(labels(tr)).toContain('Access-Reject');
  });
});

describe('sem resposta', () => {
  it('servidor inalcançável: três Access-Request perdidos com o mesmo Identifier e EAP-Failure do próprio switch', () => {
    const tr = run('f-noserver');
    const reqs = tr.msgs.filter((m) => m.proto === 'RADIUS');
    expect(reqs.length).toBe(RADIUS_TRIES);
    expect(reqs.every((m) => m.lost)).toBe(true);
    const ids = new Set(reqs.map((m) => (m.fields.find((f) => Array.isArray(f) && f[0] === 'Identifier') as string[])[1]));
    expect(ids.size).toBe(1);
    expect(labels(tr)).toContain('EAP-Failure');
    expect(labels(tr)).not.toContain('Access-Reject');
    expect(states(tr).pop()).toBe('unauth');
    expect(tr.raw.res).toBe('noserver');
  });

  it('segredo diferente: os pedidos chegam, e o servidor os descarta em silêncio', () => {
    const tr = run('f-secret');
    const reqs = tr.msgs.filter((m) => m.proto === 'RADIUS');
    expect(reqs.length).toBe(RADIUS_TRIES);
    expect(reqs.every((m) => !m.lost)).toBe(true);
    expect(tr.events.filter((e) => e.who === 'srv' && /Descarta em silêncio/.test(e.text)).length).toBe(RADIUS_TRIES);
    expect(tr.msgs.filter((m) => m.from === 'srv')).toEqual([]);
  });

  it('sem suplicante: o servidor RADIUS não participa e a porta continua fechada', () => {
    const tr = run('f-nosup');
    expect(tr.msgs.some((m) => m.proto === 'RADIUS')).toBe(false);
    expect(tr.msgs.every((m) => m.from === 'nas' || m.from === 'sup')).toBe(true);
    expect(tr.msgs.filter((m) => String(m.label).startsWith('EAP-Request/Identity')).length).toBe(3);
    expect(states(tr).pop()).toBe('unauth');
    expect(tr.cols.some((c) => c.key === 'srv')).toBe(false);
  });
});

describe('porta e sessão', () => {
  it('reautenticação: a porta fica autorizada o tempo todo e o frame do meio passa', () => {
    const tr = run('p-reauth');
    expect(new Set(states(tr))).toEqual(new Set(['auth']));
    expect(frames(tr).every((f) => f.ok)).toBe(true);
    expect(frames(tr).length).toBe(2);
    const acc = tr.msgs.find((m) => m.label === 'Access-Accept')!;
    expect(JSON.stringify(acc.fields)).toContain('Session-Timeout (27)');
  });

  it('logoff: a porta fecha na hora e o frame seguinte é descartado', () => {
    const tr = run('p-logoff');
    expect(states(tr)).toEqual(['auth', 'unauth']);
    expect(frames(tr).map((f) => f.ok)).toEqual([true, false]);
    expect(tr.msgs.some((m) => m.label === 'EAPOL-Logoff')).toBe(true);
    expect(tr.msgs.some((m) => m.proto === 'RADIUS')).toBe(false);
  });

  it('segundo dispositivo: passa na autorização por porta e é barrado por endereço MAC', () => {
    const leak = run('p-extra');
    expect(frames(leak).map((f) => f.who + ':' + f.ok)).toEqual(['sup:true', 'dev2:true']);
    expect(leak.raw.res).toBe('extra-leak');
    const safe = run('p-extra-def');
    expect(frames(safe).map((f) => f.who + ':' + f.ok)).toEqual(['sup:true', 'dev2:false']);
    expect(safe.raw.res).toBe('extra-def');
  });
});

describe('riscos e defesas', () => {
  it('EAP-MD5 diante de um equipamento falso: o Notebook aceita o Success', () => {
    const tr = run('s-md5');
    expect(tr.raw.res).toBe('md5-exposed');
    expect(labels(tr)).toContain('EAP-Success');
    expect(tr.cols.map((c) => c.key)).toEqual(['sup', 'fake']);
  });

  it('com EAP-TLS, o suplicante aborta com o alerta unknown_ca e nenhuma credencial sai', () => {
    const tr = run('s-md5-def');
    expect(tr.raw.res).toBe('tls-reject');
    expect(labels(tr).some((l) => l.includes('unknown_ca'))).toBe(true);
    expect(labels(tr)).not.toContain('EAP-Success');
    expect(labels(tr).some((l) => l.includes('MD5'))).toBe(false);
  });

  it('PEAP sem validação entrega a prova MSCHAPv2; com validação, aborta antes', () => {
    const bad = run('s-peap');
    expect(bad.raw.res).toBe('peap-exposed');
    expect(labels(bad).some((l) => l.includes('resposta MSCHAPv2'))).toBe(true);
    const good = run('s-peap-def');
    expect(good.raw.res).toBe('peap-reject');
    expect(labels(good).some((l) => l.includes('resposta MSCHAPv2'))).toBe(false);
    expect(labels(good).some((l) => l.includes('bad_certificate'))).toBe(true);
  });
});

describe('todos os cenários', () => {
  it.each(scenarios.map((s) => s.id))('%s: tempo não decresce e todo Success ou Failure vem depois de um Request', (id) => {
    const tr = run(id);
    tr.msgs.forEach((m) => expect(m.tArr).toBeGreaterThanOrEqual(m.tSend));
    const first = tr.msgs.findIndex((m) => (m.label as string).startsWith('EAP-Request') || m.label === 'EAPOL-Logoff' || m.proto === 'dados');
    tr.msgs.forEach((m, i) => {
      if (m.label === 'EAP-Success' || m.label === 'EAP-Failure') expect(i).toBeGreaterThan(first);
    });
    expect(tr.raw.res).not.toBe('');
  });
});
