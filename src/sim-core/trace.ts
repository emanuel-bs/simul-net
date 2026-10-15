import type { Column, Message, MessageOptions, StateDef, Trace } from './types';

export const COLORS = { plain: '#F2A65A', enc: '#5FD4C0', bad: '#E2574C', data: '#6FB8E8', tcp: '#8FA9C7' } as const;

/**
 * Cria um trace vazio. Os tempos são em ms; add() avança o cursor t, a menos que a mensagem seja
 * simultânea (par) ou tenha instante fixo (at).
 */
export function newTrace(cols: Column[], stateDefs?: StateDef[], rtt?: number): Trace {
  const tr: Trace = {
    cols,
    stateDefs: stateDefs || [],
    msgs: [],
    events: [],
    log: [],
    states: [],
    phases: [],
    metro: [],
    raw: {},
    tabData: {},
    t: 0,
    ow: (rtt || 20) / 2,
    rtt: rtt || 20,
    add(from, to, o = {}) {
      const tS = o.at !== undefined ? o.at : tr.t;
      const dur = o.dur !== undefined ? o.dur : tr.ow;
      const m = Object.assign(
        { from, to, tSend: tS, tArr: tS + dur, color: COLORS.plain as string, enc: false, proto: 'SSHv2', len: 0, fields: [], tags: [], lost: false },
        o,
      ) as unknown as Message;
      m.id = tr.msgs.length;
      tr.msgs.push(m);
      if (!o.par) tr.t = m.tArr + (o.proc !== undefined ? o.proc : 0.4);
      return m;
    },
    wait(ms) {
      tr.t += ms;
    },
    ev(t, who, text, kind) {
      tr.events.push({ t, who, text, kind: kind || '' });
    },
    lg(t, text, tag) {
      tr.log.push({ t, text, tag: tag || 'sys' });
    },
    st(t, key, val, cls) {
      tr.states.push({ t, key, val, cls: cls || '' });
    },
    phase(label, key) {
      tr.phases.push({ t: tr.t, label, key });
    },
    mile(t, label, sub) {
      tr.metro.push({ t, label, sub });
    },
  };
  return tr;
}

/**
 * Converte os tempos em linhas: uma linha por instante distinto. O diagrama fica compacto e a
 * animação tem ritmo constante, qualquer que seja o RTT. Devolve a linha final (endR).
 */
export function prepare(t: Trace): number {
  const set = new Set<number>([0]);
  t.msgs.forEach((m) => {
    set.add(m.tSend);
    set.add(m.tArr);
  });
  t.events.forEach((e) => set.add(e.t));
  t.states.forEach((s) => set.add(s.t));
  t.log.forEach((l) => set.add(l.t));
  t.phases.forEach((p) => set.add(p.t));
  t.metro.forEach((m) => set.add(m.t));
  const arr = Array.from(set).sort((a, b) => a - b);
  const idx = new Map<number, number>();
  arr.forEach((v, i) => idx.set(v, i));
  t.times = arr;
  t.msgs.forEach((m) => {
    m.rS = idx.get(m.tSend);
    m.rA = idx.get(m.tArr);
  });
  t.events.forEach((e) => (e.r = idx.get(e.t)));
  t.states.forEach((s) => (s.r = idx.get(s.t)));
  t.log.forEach((l) => (l.r = idx.get(l.t)));
  t.phases.forEach((p) => (p.r = idx.get(p.t)));
  t.metro.forEach((m) => (m.r = idx.get(m.t)));
  return arr.length - 1 + 0.6;
}

/** Tempo (ms) correspondente a uma posição fracionária do relógio em linhas. */
export function timeAt(t: Trace, c: number): number {
  const a = t.times!;
  const i = Math.max(0, Math.min(a.length - 1, Math.floor(c)));
  const j = Math.min(a.length - 1, i + 1);
  const f = Math.max(0, Math.min(1, c - i));
  return a[i] + (a[j] - a[i]) * f;
}

export type { MessageOptions };
