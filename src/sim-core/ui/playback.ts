// Lógica pura de reprodução: dado um trace preparado e a posição do relógio (em linhas), decide o que aparece.
import type { LogEntry, Message, StateChange, Trace } from '../types';

/** Próxima linha em que algo acontece (envio, chegada ou evento); a linha final se não houver mais nada. */
export function nextStep(tr: Trace, clock: number, endR: number): number {
  const rows: number[] = [];
  tr.msgs.forEach((m) => rows.push(m.rS!, m.rA!));
  tr.events.forEach((e) => rows.push(e.r!));
  const n = rows.filter((r) => r > clock + 0.01).sort((a, b) => a - b)[0];
  return n === undefined ? endR : n;
}

export const visibleMessages = (tr: Trace, clock: number): Message[] => tr.msgs.filter((m) => m.rS! <= clock);

export const visibleLog = (tr: Trace, clock: number): LogEntry[] =>
  tr.log
    .slice()
    .sort((a, b) => a.t - b.t)
    .filter((l) => l.r! <= clock);

/** Último valor definido para a chave até o relógio atual. */
export function stateAt(tr: Trace, key: string, clock: number): StateChange | null {
  let s: StateChange | null = null;
  tr.states.forEach((x) => {
    if (x.key === key && x.r! <= clock + 1e-9) s = x;
  });
  return s;
}

/** Índice do marco ativo no metrô; igual ao total quando a simulação terminou. */
export function milestoneIndex(tr: Trace, clock: number, endR: number): number {
  let a = 0;
  tr.metro.forEach((x, i) => {
    if (x.r! <= clock + 1e-9) a = i;
  });
  return clock >= endR - 0.7 ? tr.metro.length : a;
}

export interface Progress {
  visible: boolean;
  /** Fração percorrida (0 a 1, já limitada pelo ponto de perda). */
  f: number;
  done: boolean;
}

/** Progresso do desenho de uma mensagem no relógio atual. Mensagens perdidas param a 55% do caminho. */
export function messageProgress(m: Message, clock: number): Progress {
  if (clock < m.rS!) return { visible: false, f: 0, done: false };
  const endF = m.lost ? 0.55 : 1;
  const f = Math.min(1, (clock - m.rS!) / (m.rA! - m.rS! || 1)) * endF;
  return { visible: true, f, done: f >= endF - 1e-9 };
}
