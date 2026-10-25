// Motor do modo Inundação de MAC e segurança de porta (nível defensivo).
// O host M envia quadros com endereços de origem forjados até encher a tabela de endereços do switch. Com a tabela cheia,
// o switch não aprende hosts novos e inunda o tráfego de destino desconhecido, que passa a chegar também a M.
// A segurança de porta (recurso de fabricantes, não do IEEE) limita quantos MACs a porta aceita.
// A capacidade real de um switch é de milhares de endereços; o simulador usa valores pequenos para caber no diagrama.
import { COLORS as C0, newTrace, type Column, type StateDef, type Trace } from '../../sim-core';
import { GHOST, HOSTS, Switch, forged, ipFields, sendFrame, type Decision, type Frame, type HostKey } from './model';

export interface InuParams {
  rtt: number;
  iattack: boolean;
  ientries: 'present' | 'absent';
  icap: number;
  idefense: 'none' | 'protect' | 'restrict' | 'shutdown';
}

export const COLS_INU: Column[] = [
  { key: 'a', label: 'Host A', sub: 'porta 1', addr: HOSTS.a.ip },
  { key: 'b', label: 'Host B', sub: 'porta 2', addr: HOSTS.b.ip },
  { key: 'sw', label: 'Switch', sub: 'camada 2' },
  { key: 'm', label: 'Host M', sub: 'porta 3 (atacante)', addr: HOSTS.m.ip },
];

export const STATES_INU: StateDef[] = [
  { key: 'phase', label: 'Fase' },
  { key: 'tab', label: 'Tabela de endereços do switch' },
  { key: 'dec', label: 'Última decisão do switch' },
  { key: 'p3', label: 'Porta 3 (de M)' },
  { key: 'seen', label: 'Quadros de A e B que M recebeu' },
];

const legit = (from: HostKey, to: HostKey, reply: boolean): Frame => ({
  label: reply ? 'Echo Reply' : 'Echo Request',
  proto: 'ICMP',
  color: C0.tcp,
  len: 98,
  info: HOSTS[from].ip + ' → ' + HOSTS[to].ip,
  about: 'Tráfego legítimo entre A e B. Se o switch não souber a porta do destino, o quadro é inundado e M também o recebe.',
  dst: HOSTS[to].mac,
  etype: '0x0800 (IPv4)',
  body: [...ipFields(HOSTS[from].ip, HOSTS[to].ip, '1 (ICMP)'), { sec: 'ICMP (RFC 792)' }, ['Tipo', reply ? '0 (Echo Reply)' : '8 (Echo Request)', '']],
});

export function buildInu(P: InuParams): Trace {
  const tr = newTrace(COLS_INU, STATES_INU, P.rtt);
  const sw = new Switch({ 1: ['a'], 2: ['b'], 3: ['m'] }, P.icap);
  const decs: Decision[] = [];
  const R = (tr.raw = { sub: 'inu', mac: sw.ev, dec: decs, attack: P.iattack, defense: P.idefense, cap: P.icap, entries: P.ientries, seen: 0, forged: 0, accepted: 0, violations: 0, down: false, full: false, tEnd: 0 } as Record<string, any>);
  const phase = (label: string, st: string) => {
    tr.phase(label, st);
    tr.st(tr.t, 'phase', st, 'warn');
  };

  tr.st(0, 'dec', '-', 'closed');
  tr.st(0, 'p3', P.idefense === 'none' ? 'sem proteção' : 'segurança de porta: máximo de 1 MAC', P.idefense === 'none' ? 'closed' : 'est');
  tr.st(0, 'seen', '0', 'closed');
  if (P.ientries === 'present') sw.preload('a', 'b');
  tr.st(0, 'tab', sw.stateText(), P.ientries === 'present' ? 'est' : 'closed');
  tr.ev(0, 'sw', P.ientries === 'present' ? 'A e B já estão na tabela (capacidade de ' + P.icap + ')' : 'Tabela sem A e B (nunca falaram ou já expiraram); capacidade de ' + P.icap, '');

  if (P.iattack) {
    phase('1. M inunda a tabela com origens forjadas', 'inundação de MAC');
    tr.mile(tr.t, 'Ataque', 'origens forjadas');
    let secure: string | null = null;
    for (let i = 1; i <= P.icap && !R.down; i++) {
      const src = forged(i);
      R.forged++;
      const gate =
        P.idefense === 'none'
          ? undefined
          : (s: string) => {
              if (secure === null || s === secure) {
                secure = s;
                return null;
              }
              R.violations++;
              if (P.idefense === 'protect') return { note: 'Violação (protect): excede 1 MAC na porta; descarta em silêncio', log: 'Segurança de porta (protect): ' + s + ' excede o limite de 1 MAC na porta 3; quadro descartado sem registro.' };
              if (P.idefense === 'restrict') return { note: 'Violação (restrict): descarta e gera alerta (' + R.violations + ')', log: 'Segurança de porta (restrict): violação ' + R.violations + ' por ' + s + '; quadro descartado e alerta registrado.' };
              R.down = true;
              return { note: 'Violação (shutdown): a porta 3 é desativada', log: 'Segurança de porta (shutdown): violação por ' + s + '; a porta 3 foi colocada em err-disable.' };
            };
      const f: Frame = {
        label: 'Quadro forjado #' + i,
        proto: 'Ethernet',
        len: 64,
        info: 'origem ' + src + ' (inventada por M)',
        about: 'M inventa um endereço de origem novo a cada quadro. O switch tenta aprender cada um e gasta uma entrada da tabela.',
        dst: GHOST,
        src,
        etype: '0x0800 (IPv4)',
        body: [],
        color: C0.plain,
      };
      const s = sendFrame(tr, sw, decs, 'm', f, { gate, learnTy: P.idefense === 'none' ? 'dynamic' : 'secure', phaseName: 'Forjado' });
      if (s.action !== 'drop') R.accepted++;
      if (R.down) {
        sw.flushPort(tr, tr.t, 3);
        sw.ports[3] = [];
        tr.st(tr.t, 'tab', sw.stateText(), 'est');
        tr.st(tr.t, 'p3', 'desativada (err-disable)', 'bad');
        tr.ev(tr.t, 'm', 'Enlace caído: M não envia nem recebe mais', 'warn');
        tr.wait(P.rtt / 2);
      } else if (P.idefense === 'restrict' || P.idefense === 'protect') tr.st(tr.t, 'p3', (P.idefense === 'restrict' ? 'restrita' : 'protegida') + ': ' + R.violations + ' violações', R.violations ? 'warn' : 'est');
    }
    R.full = sw.rows.size >= sw.cap;
    if (R.full) tr.mile(tr.t, 'Tabela cheia', P.icap + ' entradas');
  } else {
    tr.ev(0, 'm', 'M não ataca neste cenário', '');
  }

  phase('2. Tráfego legítimo entre A e B', 'tráfego de A e B');
  const count = (s: { hosts: HostKey[] }) => {
    if (s.hosts.includes('m')) R.seen++;
    tr.st(tr.t, 'seen', String(R.seen), R.seen > 1 ? 'bad' : R.seen ? 'warn' : 'closed');
  };
  count(sendFrame(tr, sw, decs, 'a', legit('a', 'b', false), { phaseName: 'Legítimo' }));
  count(sendFrame(tr, sw, decs, 'b', legit('b', 'a', true), { phaseName: 'Legítimo' }));
  count(sendFrame(tr, sw, decs, 'a', legit('a', 'b', false), { phaseName: 'Legítimo' }));
  R.tEnd = tr.t;
  R.result = R.seen > 1 ? 'leak' : R.seen === 1 ? 'first' : 'safe';
  return tr;
}
