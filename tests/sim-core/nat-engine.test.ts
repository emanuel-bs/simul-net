// Regras do motor do NAT: Basic NAT, NAPT, mapeamento, colisão, esgotamento, expiração, DNAT, hairpin, ESP e CGNAT.
import { describe, expect, it } from 'vitest';
import { scenarioParams } from '../../src/sim-core/ui';
import { buildNat, type Entry, type NatParams, type TabEv } from '../../src/sims/nat/engine';
import { controls } from '../../src/sims/nat/content/controls';
import { scenarios } from '../../src/sims/nat/content/scenarios';
import { entriesAt } from '../../src/sims/nat/topology';

const run = (id: string, over: Partial<NatParams> = {}) => {
  const s = scenarios.find((x) => x.id === id)!;
  const P = { ...scenarioParams(controls, s), ...over } as unknown as NatParams;
  return buildNat(P, s.sub);
};
const infos = (tr: ReturnType<typeof run>, label: string) => tr.msgs.filter((m) => m.label === label).map((m) => m.info as string);
/** Pacotes que o NAT envia ao lado externo (já traduzidos). */
const saida = (tr: ReturnType<typeof run>, label: string) => tr.msgs.filter((m) => m.label === label && m.to === 'srv').map((m) => m.info as string);
const dropped = (tr: ReturnType<typeof run>) => tr.msgs.filter((m) => m.lost);
const finalEntries = (tr: ReturnType<typeof run>, dev = 'nat'): Entry[] => entriesAt(tr, dev, 1e12);

describe('Basic NAT', () => {
  it('estático: mapeia o endereço 1:1 e mantém a porta', () => {
    const tr = run('n-estatico');
    expect(infos(tr, 'SYN')).toContain('203.0.113.11:50000 > 198.51.100.10:443');
    expect(infos(tr, 'SYN')).toContain('203.0.113.12:40000 > 198.51.100.10:443');
    expect(dropped(tr)).toHaveLength(0);
    expect(finalEntries(tr).every((e) => e.perm && e.kind === 'estatico')).toBe(true);
  });

  it('estático: as entradas existem antes do primeiro pacote', () => {
    const tr = run('n-estatico');
    expect(entriesAt(tr, 'nat', 0)).toHaveLength(2);
  });

  it('dinâmico: cada host recebe um endereço do pool, só depois do primeiro pacote', () => {
    const tr = run('n-dinamico');
    expect(entriesAt(tr, 'nat', 0)).toHaveLength(0);
    expect(infos(tr, 'SYN')).toContain('203.0.113.11:50000 > 198.51.100.10:443');
    expect(infos(tr, 'SYN')).toContain('203.0.113.12:40000 > 198.51.100.10:443');
  });

  it('dinâmico: com o pool menor que os hosts, o excedente é descartado', () => {
    const tr = run('n-pool');
    const d = dropped(tr);
    expect(d).toHaveLength(1);
    expect(String((d[0].tags as string[])[0])).toMatch(/pool de endereços públicos esgotado/);
    expect(d[0].from).toBe('pc2');
  });
});

describe('NAPT', () => {
  it('dois hosts compartilham o endereço e se distinguem pela porta', () => {
    const tr = run('n-napt');
    const e = finalEntries(tr);
    expect(e).toHaveLength(2);
    expect(new Set(e.map((x) => x.extIp))).toEqual(new Set(['203.0.113.1']));
    expect(new Set(e.map((x) => x.extPort)).size).toBe(2);
    expect(dropped(tr)).toHaveLength(0);
  });

  it('colisão: a segunda conexão com a mesma porta recebe outra porta externa e a resposta volta ao host certo', () => {
    const tr = run('n-colisao');
    expect(infos(tr, 'SYN')).toContain('203.0.113.1:50000 > 198.51.100.10:443');
    expect(infos(tr, 'SYN')).toContain('203.0.113.1:50001 > 198.51.100.10:443');
    const back = tr.msgs.filter((m) => m.label === 'SYN+ACK' && m.to === 'pc2');
    expect(back).toHaveLength(1);
    expect(back[0].info).toBe('198.51.100.10:443 > 192.168.1.11:50000');
    expect(tr.raw.flags).toContain('colisao');
  });

  it('ICMP: o identificador faz o papel da porta', () => {
    const tr = run('n-icmp');
    expect(infos(tr, 'Echo Request')).toContain('203.0.113.1:4660 > 198.51.100.10');
    const rep = tr.msgs.filter((m) => m.label === 'Echo Reply' && m.to === 'pc1');
    expect(rep).toHaveLength(1);
    expect(rep[0].info).toBe('198.51.100.10 > 192.168.1.10:4660');
  });
});

describe('mapeamento (RFC 4787)', () => {
  it('EIM: a mesma porta interna reaproveita a porta externa para outro destino', () => {
    const tr = run('n-eim');
    expect(saida(tr, 'UDP')).toEqual(['203.0.113.1:50000 > 198.51.100.10:53', '203.0.113.1:50000 > 198.51.100.10:123']);
    expect(dropped(tr)).toHaveLength(0);
    expect(new Set(finalEntries(tr).map((e) => e.extPort)).size).toBe(1);
  });

  it('APDM: cada destino recebe uma porta externa própria', () => {
    const tr = run('n-apdm');
    expect(saida(tr, 'UDP')).toEqual(['203.0.113.1:50000 > 198.51.100.10:53', '203.0.113.1:50001 > 198.51.100.10:123']);
    expect(dropped(tr)).toHaveLength(0);
  });
});

describe('limites do NAT', () => {
  it('esgotamento: com 3 portas e 4 conexões, a quarta é descartada', () => {
    const tr = run('n-portas');
    const d = dropped(tr);
    expect(d).toHaveLength(1);
    expect(String((d[0].tags as string[])[0])).toMatch(/sem porta livre/);
    const ports = finalEntries(tr).map((e) => e.extPort);
    expect(ports.sort()).toEqual([50000, 50001, 50002]);
  });

  it('expiração: a entrada some no instante exato e a resposta tardia é descartada', () => {
    const tr = run('n-expira');
    const evs = (tr.raw.tabEv as TabEv[]).filter((e) => e.op === 'del');
    expect(evs).toHaveLength(1);
    const created = (tr.raw.tabEv as TabEv[]).find((e) => e.op === 'set')!;
    expect(evs[0].t).toBeCloseTo(created.t + 60000, 6);
    const d = dropped(tr);
    expect(d).toHaveLength(1);
    expect(String((d[0].tags as string[])[0])).toMatch(/expirou por inatividade/);
    expect(d[0].tSend).toBeGreaterThan(evs[0].t);
  });

  it('entrada não solicitada: descartada no NAPT e entregue no Basic NAT estático', () => {
    const napt = run('n-entrada-napt');
    const lastN = napt.msgs[napt.msgs.length - 1];
    expect(lastN.lost).toBe(true);
    expect(String((lastN.tags as string[])[0])).toMatch(/ninguém de dentro iniciou/);
    const est = run('n-entrada-estatico');
    expect(dropped(est)).toHaveLength(0);
    const lastE = est.msgs[est.msgs.length - 1];
    expect(lastE.to).toBe('pc1');
    expect(lastE.info).toBe('198.51.100.10:33000 > 192.168.1.10:8080');
  });

  it('ESP: o NAPT recusa o segundo host, o Basic NAT estático aceita os dois e o NAT-T resolve', () => {
    const esp = run('n-esp');
    expect(dropped(esp)).toHaveLength(1);
    expect(dropped(esp)[0].from).toBe('pc2');
    expect(dropped(run('n-esp-basic'))).toHaveLength(0);
    const natt = run('n-natt');
    expect(dropped(natt)).toHaveLength(0);
    expect(infos(natt, 'ESP em UDP')).toContain('203.0.113.1:4500 > 198.51.100.10:4500');
    expect(infos(natt, 'ESP em UDP')).toContain('203.0.113.1:4501 > 198.51.100.10:4500');
  });

  it('CGNAT: duas traduções na ida e a reversão em ordem inversa; a porta preferida já está ocupada no CGN', () => {
    const tr = run('n-cgnat');
    expect(dropped(tr)).toHaveLength(0);
    const syn = infos(tr, 'SYN');
    expect(syn).toContain('192.168.1.10:50000 > 198.51.100.10:443');
    expect(syn).toContain('100.64.10.2:50000 > 198.51.100.10:443');
    expect(syn).toContain('203.0.113.1:50002 > 198.51.100.10:443');
    const rev = tr.msgs.filter((m) => m.label === 'SYN+ACK' && (m.to === 'cgn' || m.to === 'nat' || m.to === 'pc1')).map((m) => m.to);
    expect(rev.slice(0, 3)).toEqual(['cgn', 'nat', 'pc1']);
  });
});

describe('DNAT', () => {
  it('publica o serviço: o destino é reescrito e a origem é revertida na resposta', () => {
    const tr = run('n-dnat');
    expect(tr.msgs.map((m) => m.info)).toEqual([
      '198.51.100.10:41000 > 203.0.113.1:443',
      '198.51.100.10:41000 > 192.168.1.50:8443',
      '192.168.1.50:8443 > 198.51.100.10:41000',
      '203.0.113.1:443 > 198.51.100.10:41000',
    ]);
    expect(dropped(tr)).toHaveLength(0);
  });

  it('retorno assimétrico: a resposta com origem privada é descartada', () => {
    const tr = run('n-assimetrico');
    const d = dropped(tr);
    expect(d).toHaveLength(1);
    expect(d[0].info).toBe('192.168.1.50:8443 > 198.51.100.10:41000');
  });

  it('hairpin: sem suporte descarta; só DNAT quebra no retorno; DNAT com SNAT funciona', () => {
    expect(dropped(run('n-hairpin-nao'))).toHaveLength(1);
    const so = run('n-hairpin-dnat');
    expect(dropped(so)).toHaveLength(1);
    expect(dropped(so)[0].from).toBe('web');
    const ok = run('n-hairpin');
    expect(dropped(ok)).toHaveLength(0);
    expect(ok.msgs.map((m) => m.info)).toEqual([
      '192.168.1.10:50000 > 203.0.113.1:443',
      '192.168.1.1:50000 > 192.168.1.50:8443',
      '192.168.1.50:8443 > 192.168.1.1:50000',
      '203.0.113.1:443 > 192.168.1.10:50000',
    ]);
  });

  it('proxy transparente: o destino vai ao proxy e a origem original volta no retorno', () => {
    const tr = run('n-proxy');
    expect(tr.msgs.map((m) => m.info)).toEqual([
      '192.168.1.10:50000 > 198.51.100.10:80',
      '192.168.1.10:50000 > 192.168.1.50:3128',
      '192.168.1.50:3128 > 192.168.1.10:50000',
      '198.51.100.10:80 > 192.168.1.10:50000',
    ]);
  });
});

describe('determinismo', () => {
  it('o mesmo cenário produz o mesmo trace', () => {
    scenarios.forEach((s) => {
      const a = JSON.stringify(run(s.id));
      expect(JSON.stringify(run(s.id)), s.id).toBe(a);
    });
  });

  it('controles ocultos no modo não alteram o trace', () => {
    expect(JSON.stringify(run('n-napt', { hairpin: 'nao', acao: 'proxy', gwOutro: true } as Partial<NatParams>))).toBe(JSON.stringify(run('n-napt')));
    expect(JSON.stringify(run('n-dnat', { tipo: 'estatico', proto: 'icmp', cgnat: true } as Partial<NatParams>))).toBe(JSON.stringify(run('n-dnat')));
  });
});
