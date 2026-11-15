// Convenção de tamanhos (campo len das mensagens), documentada em docs/arquitetura.md, seção "Convenção de tamanhos".
// Quadros Ethernet: do cabeçalho Ethernet ao último byte do payload, sem FCS e sem padding (como numa captura).
// Quadros Wi-Fi: o quadro 802.11 inteiro, com o FCS de 4 bytes. Cabeçalhos sem opções, salvo quando o simulador as mostra.
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { ftpProtocol } from '../../src/sims/ftp/protocol';
import { LEN } from '../../src/sims/wifi/model';

describe('Wi-Fi: tamanho dos quadros de controle e de gerência, com FCS', () => {
  it('ACK e CTS: 10 bytes de cabeçalho e 4 de FCS', () => {
    expect(LEN.ack).toBe(14);
    expect(LEN.cts).toBe(14);
  });
  it('RTS: Frame Control, Duration, RA e TA (16 bytes) e o FCS', () => expect(LEN.rts).toBe(20));
  it('PS-Poll: Frame Control, AID, RA e TA (16 bytes) e o FCS', () => expect(LEN.psPoll).toBe(20));
  it('Authentication de sistema aberto: cabeçalho de 24, corpo de 6 (algoritmo, sequência e status) e o FCS', () => expect(LEN.auth).toBe(34));
  it('Null Data: cabeçalho de 24 e o FCS', () => expect(LEN.nullData).toBe(28));
});

describe('FTP: segmentos TCP de controle sobre Ethernet e IPv4, sem opções', () => {
  it('SYN, ACK e FIN têm 14 + 20 + 20 = 54 bytes', () => {
    let vistos = 0;
    ftpProtocol.scenarios.forEach((s) => {
      const tr = ftpProtocol.build(scenarioParams(ftpProtocol.controls, s), s.sub);
      tr.msgs.filter((m) => m.proto === 'TCP' && /^(SYN|ACK|FIN)/.test(m.label as string)).forEach((m) => {
        vistos++;
        expect(m.len, `${s.id}: ${m.label}`).toBe(54);
      });
    });
    expect(vistos).toBeGreaterThan(0);
  });
});
