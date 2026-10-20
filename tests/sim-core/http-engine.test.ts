import { describe, expect, it } from 'vitest';
import { buildHttp, catalog, FALLBACK_MS, type HttpParams, type Metrics } from '../../src/sims/http-versoes/engine';
import { httpProtocol } from '../../src/sims/http-versoes/protocol';
import { scenarioParams } from '../../src/sim-core/ui';

const base = scenarioParams(httpProtocol.controls, httpProtocol.scenarios[0]) as unknown as HttpParams;
const run = (v: string, o: Partial<HttpParams> = {}) => buildHttp({ ...base, ...o }, v);
const metrics = (v: string, o: Partial<HttpParams> = {}) => run(v, o).raw.metrics as Metrics;
const labels = (v: string, o: Partial<HttpParams> = {}) => run(v, o).msgs.map((m) => m.label);

describe('motor HTTP: regras', () => {
  it('RTT até o primeiro pedido: 2 no HTTP/1.1 com TLS, 1 sem TLS, 2 no HTTP/2, 1 no HTTP/3 e 0 com 0-RTT', () => {
    expect(metrics('h1').rttsBeforeRequest).toBe(2);
    expect(metrics('h1', { tls: false }).rttsBeforeRequest).toBe(1);
    expect(metrics('h2').rttsBeforeRequest).toBe(2);
    expect(metrics('h3').rttsBeforeRequest).toBe(1);
    expect(metrics('h3', { resume: true }).rttsBeforeRequest).toBe(0);
  });

  it('o ACK do handshake TCP vai junto do ClientHello (ou do primeiro GET sem TLS)', () => {
    expect(labels('h1')).toContain('ACK + ClientHello');
    expect(labels('h1', { tls: false })).toContain('ACK + GET /index.html');
    expect(labels('h1')).not.toContain('ACK');
  });

  it('uma conexão em fila é mais lenta que seis, e HTTP/2 e HTTP/3 vencem o HTTP/1.1', () => {
    expect(metrics('h1', { conns: 1 }).tDone).toBeGreaterThan(metrics('h1', { conns: 6 }).tDone);
    expect(metrics('h2').tDone).toBeLessThan(metrics('h1').tDone);
    expect(metrics('h3').tDone).toBeLessThan(metrics('h2').tDone);
  });

  it('o número de conexões do HTTP/1.1 não passa do número de subrecursos nem do limite escolhido', () => {
    expect(metrics('h1', { conns: 6, res: 4 }).conns).toBe(3);
    expect(metrics('h1', { conns: 2 }).conns).toBe(2);
    expect(metrics('h2').conns).toBe(1);
  });

  it('o HPACK e o QPACK reduzem os bytes de cabeçalho', () => {
    expect(metrics('h2').hdrBytes).toBeLessThan(metrics('h1').hdrBytes / 4);
    expect(metrics('h3').hdrBytes).toBeLessThan(metrics('h1').hdrBytes / 4);
  });

  it('perda: o TCP do HTTP/2 retém vários fluxos, o HTTP/3 e o HTTP/1.1 só o afetado', () => {
    const o = { loss: true, rtt: 200 };
    expect(metrics('h2', o).delayed).toBeGreaterThan(1);
    expect(metrics('h3', o).delayed).toBe(1);
    expect(metrics('h1', o).delayed).toBe(1);
    expect(metrics('h2').delayed).toBe(0);
  });

  it('com perda, o trace traz o segmento perdido, o ACK duplicado e a retransmissão', () => {
    const tr = run('h2', { loss: true });
    expect(tr.msgs.filter((m) => m.lost).map((m) => m.label)).toContain('segmento perdido');
    expect(tr.msgs.map((m) => m.label)).toEqual(expect.arrayContaining(['ACK duplicado (SACK)', 'retransmissão']));
    expect(run('h3', { loss: true }).msgs.map((m) => m.label)).toContain('pacote QUIC perdido');
  });

  it('a imagem grande entra no catálogo e, no HTTP/1.1 com 2 conexões, atrasa a página mais que no HTTP/2', () => {
    expect(catalog({ res: 8, big: true })).toHaveLength(9);
    const o = { big: true, conns: 2 };
    expect(metrics('h1', o).tDone).toBeGreaterThan(metrics('h2', o).tDone);
  });

  it('UDP bloqueado: o QUIC Initial se perde e o fluxo segue como HTTP/2 depois da espera', () => {
    const tr = run('h3', { udpBlocked: true });
    expect(tr.msgs[0]).toMatchObject({ label: 'QUIC Initial', lost: true });
    expect(tr.raw.eff).toBe('h2');
    expect(metrics('h3', { udpBlocked: true }).ready).toBe(FALLBACK_MS + 2 * base.rtt);
  });

  it('o mesmo parâmetro gera o mesmo trace e o diagrama não tem mensagens fora de ordem no tempo', () => {
    const a = JSON.stringify(run('h2', { loss: true }));
    expect(JSON.stringify(run('h2', { loss: true }))).toBe(a);
    const tr = run('h1');
    tr.msgs.forEach((m, i) => { if (i) expect(m.tSend).toBeGreaterThanOrEqual(tr.msgs[i - 1].tSend); expect(m.tArr).toBeGreaterThanOrEqual(m.tSend); });
  });

  it('toda resposta chega depois do pedido correspondente', () => {
    for (const v of ['h1', 'h2', 'h3']) {
      for (const j of run(v, { loss: true }).raw.jobs) {
        expect(j.reqSend).toBeLessThan(j.reqArr);
        expect(j.start).toBeGreaterThan(j.reqArr);
        expect(j.arr).toBeGreaterThanOrEqual(j.rawArr);
      }
    }
  });
});
