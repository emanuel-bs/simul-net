import { describe, expect, it } from 'vitest';
import { buildSsh, isAead, pick, PROF, type SshParams } from '../../src/sims/ssh/engine';
import { sshProtocol } from '../../src/sims/ssh/protocol';
import { scenarioParams } from '../../src/sim-core/ui';

const plain = (t: unknown) => JSON.parse(JSON.stringify(t));

describe('motor SSH: regras de negociação', () => {
  it('escolhe o primeiro algoritmo do cliente que o servidor também oferece', () => {
    expect(pick(['a', 'b', 'c'], ['c', 'b'])).toBe('b');
    expect(pick(['a'], ['b'])).toBeNull();
    expect(pick(PROF.moderno.kex, PROF.endurecido.kex)).toBe('curve25519-sha256');
  });

  it('reconhece cifras AEAD', () => {
    expect(isAead('chacha20-poly1305@openssh.com')).toBe(true);
    expect(isAead('aes256-gcm@openssh.com')).toBe(true);
    expect(isAead('aes256-ctr')).toBe(false);
  });

  const base = scenarioParams(sshProtocol.controls, sshProtocol.scenarios[0]) as unknown as SshParams;

  it('cliente legado contra servidor endurecido falha antes da troca de chaves', () => {
    const tr = buildSsh({ ...base, cProf: 'legado', sProf: 'endurecido' }, 'session');
    expect(tr.raw.fail).toMatchObject({ stage: 'neg', what: 'kex' });
    expect(tr.msgs.some((m) => m.enc)).toBe(false);
  });

  it('chave de host diferente da registrada aborta antes de qualquer credencial', () => {
    const tr = buildSsh({ ...base, known: 'changed', hkCheck: 'ask' }, 'session');
    expect(tr.raw.fail).toMatchObject({ stage: 'hostkey', what: 'changed' });
    expect(tr.raw.auth.tries).toBe(0);
    expect(tr.msgs.some((m) => String(m.label).includes('USERAUTH'))).toBe(false);
  });

  it('é determinístico: mesmos parâmetros, mesmo trace', () => {
    expect(plain(buildSsh(base, 'session'))).toEqual(plain(buildSsh(base, 'session')));
  });

  it('túnel -L é recusado quando AllowTcpForwarding está desligado', () => {
    const tr = buildSsh({ ...base, tunKind: 'local', allowFwd: false }, 'tunnel');
    expect(tr.raw.blocked).toBe(true);
  });
});
