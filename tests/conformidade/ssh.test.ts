// Conformidade do SSH com as RFCs 4253 e 5647, independente das impressões digitais (golden).
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { sshProtocol } from '../../src/sims/ssh/protocol';

const campo = (m: { fields: unknown[] }, nome: string) => (m.fields.find((f) => Array.isArray(f) && f[0] === nome) as string[] | undefined)?.[1] ?? '';

describe('SSH: pacote binário no fio (RFC 4253, seção 6.3; RFC 5647, seção 7.3)', () => {
  // RFC 4253 6.3 cifra o packet_length; a RFC 5647 7.3 abre uma exceção no AES-GCM (o comprimento vira dado autenticado,
  // não cifrado) e o modo ETM também não o cifra. O chacha20-poly1305@openssh cifra o comprimento com chave própria.
  it('o packet_length é descrito conforme a cifra e o MAC negociados, e o tamanho do MAC acompanha o algoritmo', () => {
    let verificados = 0;
    const casos = new Set<string>();
    sshProtocol.scenarios.filter((s) => s.sub === 'session').forEach((s) => {
      const tr = sshProtocol.build(scenarioParams(sshProtocol.controls, s), s.sub);
      const neg = tr.raw.neg as { enc: string | null; mac: string | null };
      if (!neg.enc || !neg.mac) return;
      const enc: string = neg.enc;
      const mac: string = neg.mac;
      const aead = /chacha20-poly1305|gcm@openssh/.test(enc);
      const claro = /gcm@openssh/.test(enc) || (!aead && /-etm@/.test(mac));
      tr.msgs.filter((m) => m.enc && m.proto === 'SSHv2').forEach((m) => {
        verificados++;
        casos.add(enc + '+' + mac);
        expect(campo(m, 'packet_length'), `${s.id}: ${enc}`).toMatch(claro ? /^em claro/ : /^cifrado/);
        const tag = campo(m, 'MAC ou tag de autenticação');
        const esperado = aead ? 16 : /sha2-512/.test(mac) ? 64 : /sha2-256/.test(mac) ? 32 : /sha1/.test(mac) ? 20 : /md5/.test(mac) ? 16 : NaN;
        expect(tag, `${s.id}: ${mac}`).toBe(esperado + ' bytes');
      });
    });
    expect(verificados).toBeGreaterThan(0);
    expect(casos.size).toBeGreaterThan(1);
  });
});
