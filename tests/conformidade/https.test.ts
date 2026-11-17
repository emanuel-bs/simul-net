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

const extensoes = (m: { fields: unknown[] }) => nomes(m).filter((n) => n.startsWith('Extensão: '));
const serverHello = (tr: ReturnType<typeof roda>) => tr.msgs.find((m) => m.label === 'Server Hello')!;

describe('TLS 1.3: pre_shared_key é a última extensão do ClientHello (RFC 9846, seção 4.3.11; RFC 8446, seção 4.2.11)', () => {
  // "The pre_shared_key extension MUST be the last extension in the ClientHello. Servers MUST check that it is the last extension
  // and otherwise fail the handshake with an illegal_parameter alert."
  ['hres', 'hzero'].forEach((id) =>
    it('cenário ' + id + ': pre_shared_key vem depois de todas as outras extensões', () => {
      const ex = extensoes(clientHello(roda(id, {})));
      expect(ex).toContain('Extensão: pre_shared_key');
      expect(ex[ex.length - 1]).toBe('Extensão: pre_shared_key');
    }));
});

describe('TLS 1.3: CertificateRequest não vai no handshake principal com PSK (RFC 9846, seção 4.4.2)', () => {
  // "Servers which are authenticating with a resumption PSK MUST NOT send the CertificateRequest message in the main handshake."
  ['hres', 'hzero'].forEach((id) =>
    it('cenário ' + id + ' com mTLS: sem CertificateRequest e sem Certificate do cliente', () => {
      const tr = roda(id, { mtls: true });
      tr.msgs.forEach((m) => {
        expect(nomes(m), `${id}: ${m.label}`).not.toContain('CertificateRequest');
        expect(nomes(m), `${id}: ${m.label}`).not.toContain('Certificate');
        expect(m.label as string, `${id}`).not.toMatch(/Certificate/);
      });
    }));
  it('retomada no TLS 1.2 com mTLS: sem Certificate Request nem Certificate Verify (handshake abreviado, RFC 5246, seção 7.3)', () => {
    const tr = roda('hres', { cProf: 'intermediario', sProf: 'intermediario', mtls: true });
    tr.msgs.forEach((m) => expect(m.label as string).not.toMatch(/Certificate/));
  });
});

describe('TLS 1.2: NewSessionTicket só com a extensão SessionTicket (RFC 5077, seções 3.2 e 3.3)', () => {
  // "This message MUST NOT be sent if the server did not include a SessionTicket extension in the ServerHello", e o servidor só a
  // inclui se o cliente a enviou no ClientHello.
  it('o ticket enviado no handshake completo tem a extensão session_ticket no ClientHello e no ServerHello', () => {
    const tr = roda('h12', { cProf: 'intermediario', sProf: 'intermediario' });
    expect(tr.msgs.some((m) => m.label === 'New Session Ticket')).toBe(true);
    expect(nomes(clientHello(tr))).toContain('Extensão: session_ticket');
    expect(nomes(serverHello(tr))).toContain('Extensão: session_ticket');
  });
  it('em nenhum cenário há NewSessionTicket do TLS 1.2 sem a extensão nas duas mensagens', () => {
    let vistos = 0;
    httpsProtocol.scenarios.filter((s) => s.sub === 'handshake').forEach((s) => {
      const tr = httpsProtocol.build(scenarioParams(httpsProtocol.controls, s), s.sub);
      if (!tr.msgs.some((m) => m.label === 'New Session Ticket')) return;
      vistos++;
      expect(nomes(clientHello(tr)), s.id).toContain('Extensão: session_ticket');
      expect(nomes(serverHello(tr)), s.id).toContain('Extensão: session_ticket');
    });
    expect(vistos).toBeGreaterThan(0);
  });
});

describe('ALPN: o servidor só responde se o cliente ofereceu (RFC 7301, seção 3.1)', () => {
  it('cliente legado, sem ALPN no ClientHello: o ServerHello não traz ALPN', () => {
    const tr = roda('hlegacy', {});
    expect(nomes(clientHello(tr))).not.toContain('Extensão: ALPN');
    expect(nomes(serverHello(tr))).not.toContain('Extensão: ALPN');
  });
  it('em todo cenário de handshake, ALPN no ServerHello implica ALPN no ClientHello', () => {
    httpsProtocol.scenarios.filter((s) => s.sub === 'handshake').forEach((s) => {
      const tr = httpsProtocol.build(scenarioParams(httpsProtocol.controls, s), s.sub);
      const sh = tr.msgs.find((m) => m.label === 'Server Hello');
      if (sh && nomes(sh).includes('Extensão: ALPN')) expect(nomes(clientHello(tr)), s.id).toContain('Extensão: ALPN');
    });
  });
});

describe('TLS 1.3: sentinela de downgrade no random do ServerHello (RFC 9846, seção 4.2.3; RFC 8446, seção 4.1.3)', () => {
  // "TLS 1.3 servers which negotiate TLS 1.2 or below in response to a ClientHello MUST set the last 8 bytes of their Random":
  // 44 4F 57 4E 47 52 44 01 para o TLS 1.2 e 44 4F 57 4E 47 52 44 00 para o TLS 1.1 ou anterior.
  it('servidor com TLS 1.3 que negocia TLS 1.2 com um cliente só 1.2 põe o sentinela 01', () => {
    const sh = serverHello(roda('h12', { cProf: 'intermediario', sProf: 'moderno', keyType: 'rsa' }));
    expect(valor(sh, 'random')).toMatch(/444f574e47524401$/i);
  });
  it('servidor sem TLS 1.3 não põe sentinela', () => {
    const sh = serverHello(roda('h12', { cProf: 'intermediario', sProf: 'intermediario' }));
    expect(valor(sh, 'random')).not.toMatch(/444f574e4752440[01]$/i);
  });
});
