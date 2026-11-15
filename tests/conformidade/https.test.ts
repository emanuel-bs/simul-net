// Conformidade do TLS com as RFCs, independente das impressões digitais (golden).
import { describe, expect, it } from 'vitest';
import { scenarioParams, type Params } from '../../src/sim-core/ui';
import { httpsProtocol } from '../../src/sims/https/protocol';

const roda = (id: string, over: Params) => {
  const s = httpsProtocol.scenarios.find((x) => x.id === id)!;
  return httpsProtocol.build({ ...scenarioParams(httpsProtocol.controls, s), ...over }, s.sub);
};
const clientHello = (tr: ReturnType<typeof roda>) => tr.msgs.find((m) => (m.label as string).includes('Client Hello'))!;
const nomes = (m: { fields: unknown[] }) => m.fields.filter((f) => Array.isArray(f)).map((f) => (f as string[])[0]);
const valor = (m: { fields: unknown[] }, nome: string) => (m.fields.find((f) => Array.isArray(f) && f[0] === nome) as string[] | undefined)?.[1] ?? '';

describe('TLS: ClientHello por perfil de cliente (RFC 8446, seção 4.1.2 e 4.2.1; RFC 5246, seção 7.4.1.2; RFC 4346)', () => {
  // supported_versions é uma extensão do TLS 1.3: um cliente que só fala TLS 1.2 ou anterior não a envia, e declara a versão
  // mais alta no campo client_version. signature_algorithms nasceu no TLS 1.2 (RFC 5246, seção 7.4.1.4.1).
  it('cliente moderno (TLS 1.3 e 1.2): legacy_version 0x0303 e supported_versions presente', () => {
    const ch = clientHello(roda('h13', { cProf: 'moderno', sProf: 'moderno' }));
    expect(valor(ch, 'legacy_version')).toContain('0x0303');
    expect(nomes(ch)).toContain('Extensão: supported_versions');
    expect(nomes(ch)).toContain('Extensão: signature_algorithms');
  });

  it('cliente só TLS 1.2: client_version 0x0303 e sem supported_versions', () => {
    const ch = clientHello(roda('h12', { cProf: 'intermediario', sProf: 'intermediario' }));
    expect(valor(ch, 'client_version') + valor(ch, 'legacy_version')).toContain('0x0303');
    expect(nomes(ch)).not.toContain('Extensão: supported_versions');
    expect(nomes(ch)).toContain('Extensão: signature_algorithms');
  });

  it('cliente legado (TLS 1.1 e 1.0): client_version 0x0302 e sem supported_versions, signature_algorithms nem ALPN', () => {
    const ch = clientHello(roda('h12', { cProf: 'legado', sProf: 'legado' }));
    expect(valor(ch, 'client_version')).toContain('0x0302');
    ['Extensão: supported_versions', 'Extensão: signature_algorithms', 'Extensão: ALPN', 'Extensão: key_share'].forEach((e) => expect(nomes(ch), e).not.toContain(e));
  });
});

describe('TLS 1.2 com autenticação mútua (RFC 5246, seções 7.3, 7.4.6 e 7.4.8)', () => {
  // O servidor pede o certificado do cliente (CertificateRequest). O voo do cliente é: Certificate, ClientKeyExchange,
  // CertificateVerify, ChangeCipherSpec, Finished. Sem as duas mensagens o servidor não teria como autenticar o cliente.
  it('o cliente envia Certificate antes do Client Key Exchange e Certificate Verify depois dele', () => {
    const tr = roda('h12', { cProf: 'intermediario', sProf: 'intermediario', mtls: true });
    const rotulos = tr.msgs.map((m) => m.label as string);
    const cert = rotulos.findIndex((l, i) => l === 'Certificate' && tr.msgs[i].from === 'c');
    const cke = rotulos.indexOf('Client Key Exchange');
    const cv = rotulos.indexOf('Certificate Verify');
    const ccs = rotulos.findIndex((l, i) => l.startsWith('Change Cipher Spec') && tr.msgs[i].from === 'c');
    expect(cert).toBeGreaterThan(-1);
    expect(cke).toBeGreaterThan(cert);
    expect(cv).toBeGreaterThan(cke);
    expect(ccs).toBeGreaterThan(cv);
    expect(rotulos.some((l) => l.includes('Certificate Request'))).toBe(true);
  });

  it('sem mTLS, o cliente não envia Certificate nem Certificate Verify', () => {
    const tr = roda('h12', { cProf: 'intermediario', sProf: 'intermediario', mtls: false });
    expect(tr.msgs.some((m) => m.from === 'c' && (m.label === 'Certificate' || m.label === 'Certificate Verify'))).toBe(false);
  });
});
