// Conformidade do FTP com a RFC 959 (e 4217 no FTPS), independente das impressões digitais (golden).
import { describe, expect, it } from 'vitest';
import { scenarioParams, type Params } from '../../src/sim-core/ui';
import { ftpProtocol } from '../../src/sims/ftp/protocol';

const roda = (id: string, over: Params = {}) => {
  const s = ftpProtocol.scenarios.find((x) => x.id === id)!;
  return ftpProtocol.build({ ...scenarioParams(ftpProtocol.controls, s), ...over }, s.sub);
};
const rotulos = (tr: ReturnType<typeof roda>) => tr.msgs.map((m) => String(m.info));
const valor = (m: { fields: unknown[] }, nome: string) => (m.fields.find((f) => Array.isArray(f) && f[0] === nome) as string[] | undefined)?.[1] ?? '';

describe('FTP: porta de dados do servidor no modo ativo (RFC 959, seção 3.2)', () => {
  // "The server-process default data port is the port adjacent to the control connection port (i.e., L-1)."
  it('FTP na porta 21: o servidor conecta ao cliente a partir da porta 20', () => {
    const tr = roda('f-act-ok');
    expect(rotulos(tr)).toContain('20 → 50001 [SYN]');
  });
  it('FTPS implícito na porta 990, modo ativo: a porta de dados do servidor é 989', () => {
    const tr = roda('s-imp', { mode: 'active', cfw: 'none' });
    expect(rotulos(tr)).toContain('989 → 50001 [SYN]');
    expect(rotulos(tr).some((i) => i.startsWith('20 → '))).toBe(false);
  });
});

describe('FTP: tipo de representação da listagem (RFC 959, seção 4.1.3, comando LIST)', () => {
  // A resposta ao LIST deve ser ASCII ou EBCDIC ("ensure that the TYPE is appropriately ASCII or EBCDIC"); TYPE I é só para arquivos.
  it('listar o diretório usa TYPE A, e não TYPE I', () => {
    const r = rotulos(roda('f-list'));
    expect(r).toContain('TYPE A');
    expect(r).not.toContain('TYPE I');
    expect(r.some((i) => /BINARY/.test(i))).toBe(false);
  });
  it('baixar e enviar arquivo continuam em TYPE I (binário)', () => {
    ['f-pasv', 'f-stor'].forEach((id) => {
      const r = rotulos(roda(id));
      expect(r, id).toContain('TYPE I');
      expect(r.some((i) => /BINARY/.test(i)), id).toBe(true);
    });
  });
});

describe('FTP: tamanho dos quadros em claro (convenção de tamanhos: Ethernet 14 + IPv4 20 + TCP 20 + dados)', () => {
  // Cada comando e cada resposta termina em CRLF (RFC 959, seção 5.3.1 e Telnet): 2 bytes.
  it('comando ou resposta no canal de controle: 54 + texto + CRLF', () => {
    let vistos = 0;
    ftpProtocol.scenarios.filter((s) => s.sub === 'ftp').forEach((s) => {
      const tr = ftpProtocol.build(scenarioParams(ftpProtocol.controls, s), s.sub);
      tr.msgs.filter((m) => m.proto === 'FTP').forEach((m) => {
        vistos++;
        expect(m.len, `${s.id}: ${m.info}`).toBe(54 + String(m.info).length + 2);
      });
    });
    expect(vistos).toBeGreaterThan(0);
  });
  it('listagem em claro no canal de dados: 54 + texto da listagem + CRLF', () => {
    const m = roda('f-list').msgs.find((x) => x.proto === 'FTP-DATA')!;
    expect(m.len).toBe(54 + valor(m, 'Conteúdo').length + 2);
  });
});
