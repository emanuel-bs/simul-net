import { describe, expect, it } from 'vitest';
import { buildFtp, type FtpParams } from '../../src/sims/ftp/engine';
import { ftpProtocol } from '../../src/sims/ftp/protocol';
import { scenarioParams } from '../../src/sim-core/ui';

const plain = (t: unknown) => JSON.parse(JSON.stringify(t));

describe('motor FTP: regras', () => {
  const base = scenarioParams(ftpProtocol.controls, ftpProtocol.scenarios[0]) as unknown as FtpParams;

  it('o modo ativo atrás de NAT falha com 425 e a passiva funciona', () => {
    expect(buildFtp({ ...base, mode: 'active', cfw: 'nat' }, 'ftp').raw.R.fail).toMatchObject({ stage: 'data' });
    const ok = buildFtp({ ...base, mode: 'passive', cfw: 'nat' }, 'ftp').raw.R;
    expect(ok.fail).toBeNull();
    expect(ok.conns).toBe(2);
  });

  it('o helper de FTP só funciona com o controle em claro', () => {
    expect(buildFtp({ ...base, mode: 'active', cfw: 'helper' }, 'ftp').raw.R.helper).toBe(true);
    const ftps = buildFtp({ ...base, mode: 'active', cfw: 'helper', tlsMode: 'explicit', prot: 'P', certOk: true }, 'ftps').raw.R;
    expect(ftps.fail).toMatchObject({ stage: 'data' });
  });

  it('certificado inválido encerra antes de qualquer credencial', () => {
    const R = buildFtp({ ...base, certOk: false }, 'ftps').raw.R;
    expect(R.fail).toMatchObject({ stage: 'cert' });
    expect(R.conns).toBe(1); // nenhum canal de dados chegou a abrir
  });

  it('o SFTP usa uma única conexão e o FTP em claro expõe a senha', () => {
    expect(buildFtp(base, 'sftp').raw.R.conns).toBe(1);
    expect(buildFtp({ ...base, cred: 'ok' }, 'ftp').raw.R.credSeen).toBe(true);
    expect(buildFtp({ ...base, tlsMode: 'explicit', prot: 'P' }, 'ftps').raw.R.credSeen).toBe(false);
  });

  it('é determinístico', () => {
    expect(plain(buildFtp(base, 'cmp'))).toEqual(plain(buildFtp(base, 'cmp')));
  });
});
