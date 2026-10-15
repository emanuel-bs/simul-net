import { describe, expect, it } from 'vitest';
import { buildHttps, certChecks, compat, hasFS, isWeakSuite, type TlsParams } from '../../src/sims/https/engine';
import { httpsProtocol } from '../../src/sims/https/protocol';
import { scenarioParams } from '../../src/sim-core/ui';

const plain = (t: unknown) => JSON.parse(JSON.stringify(t));

describe('motor HTTPS: regras', () => {
  const base = scenarioParams(httpsProtocol.controls, httpsProtocol.scenarios[0]) as unknown as TlsParams;

  it('classifica suítes e compatibilidade com o tipo de chave', () => {
    expect(isWeakSuite('TLS_RSA_WITH_AES_128_CBC_SHA')).toBe(true);
    expect(isWeakSuite('ECDHE-RSA-AES128-GCM-SHA256')).toBe(false);
    expect(hasFS('TLS_AES_128_GCM_SHA256')).toBe(true);
    expect(hasFS('TLS_RSA_WITH_AES_128_CBC_SHA')).toBe(false);
    expect(compat('ECDHE-ECDSA-AES128-GCM-SHA256', 'rsa')).toBe(false);
    expect(compat('ECDHE-RSA-AES128-GCM-SHA256', 'rsa')).toBe(true);
  });

  it('reprova o primeiro teste que falha no certificado', () => {
    expect(certChecks({ certState: 'valid' })).toMatchObject({ ok: true, failed: null });
    expect(certChecks({ certState: 'expired' }).failed).toContain('validade');
    expect(certChecks({ certState: 'name' }).failed).toContain('SAN');
    expect(certChecks({ certState: 'revoked' }).failed).toContain('Revogação');
  });

  it('negocia TLS 1.3 entre perfis modernos e é determinístico', () => {
    const tr = buildHttps({ ...base, cProf: 'moderno', sProf: 'moderno', downgrade: false, mode: 'full' }, 'handshake');
    expect(tr.raw.tls.ver).toBe('TLS 1.3');
    expect(tr.raw.tls.fs).toBe(true);
    expect(plain(tr)).toEqual(plain(buildHttps({ ...base, cProf: 'moderno', sProf: 'moderno', downgrade: false, mode: 'full' }, 'handshake')));
  });

  it('cliente legado contra servidor endurecido falha por versão', () => {
    const tr = buildHttps({ ...base, cProf: 'legado', sProf: 'endurecido' }, 'handshake');
    expect(tr.raw.tls.fail).toMatchObject({ stage: 'neg', what: 'version', alert: 'protocol_version' });
  });

  it('o sentinela DOWNGRD faz o cliente abortar', () => {
    const tr = buildHttps({ ...base, cProf: 'moderno', sProf: 'moderno', downgrade: true }, 'handshake');
    expect(tr.raw.tls.fail).toMatchObject({ stage: 'downgrade', alert: 'illegal_parameter' });
  });

  it('adulteração em HTTPS é detectada e em HTTP não é', () => {
    const tr = buildHttps({ ...base, cProf: 'moderno', sProf: 'moderno', tamper: true, action: 'login' }, 'cmp');
    expect(tr.raw.https.tampered).toBe(true);
    expect(tr.raw.tamper).toBe(true);
  });
});
