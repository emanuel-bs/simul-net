// Geometria do diagrama de sequência (porta de drawLadder do núcleo legado), separada da renderização.
import type { Message, Trace } from '../types';

export const W = 900;
const TOP = 78;
const ROW_H = 26;
const HH = 26;

export interface EventLayout {
  r: number;
  x: number;
  y: number;
  anchor: 'start' | 'end';
  lines: string[];
  kind: string;
}

export interface MessageLayout {
  m: Message;
  xa: number;
  xb: number;
  y1: number;
  y2: number;
}

export interface LadderLayout {
  width: number;
  height: number;
  minWidth: number;
  xs: Record<string, number>;
  y: (r: number) => number;
  columns: { key: string; label: string; sub: string; x: number }[];
  /** Linha pontilhada e rótulo de cada fase. */
  phases: { y: number; label: string }[];
  timeLabels: { y: number; text: string }[];
  events: EventLayout[];
  messages: MessageLayout[];
}

/** Quebra o texto em linhas de no máximo `max` caracteres, sem cortar palavras. */
export function wrapText(text: string, max: number): string[] {
  const lines: string[] = [];
  let cur = '';
  text.split(' ').forEach((w) => {
    if ((cur + ' ' + w).trim().length > max && cur) {
      lines.push(cur);
      cur = w;
    } else cur = (cur + ' ' + w).trim();
  });
  if (cur) lines.push(cur);
  return lines;
}

export function layoutLadder(tr: Trace, endR: number, fmtTime?: (ms: number) => string): LadderLayout {
  const N = tr.cols.length;
  const x0 = N <= 2 ? 230 : N === 3 ? 200 : 150;
  const xs: Record<string, number> = {};
  tr.cols.forEach((c, i) => {
    xs[c.key] = N === 1 ? W / 2 : x0 + ((W - 2 * x0) * i) / (N - 1);
  });
  const offs = (r: number) => {
    let k = 0;
    tr.phases.forEach((p) => {
      if (p.r! <= r + 1e-9) k++;
    });
    return k * HH;
  };
  const y = (r: number) => TOP + r * ROW_H + offs(r);

  const seen = new Set<number>();
  const timeLabels: LadderLayout['timeLabels'] = [];
  tr.msgs.forEach((m) => {
    if (seen.has(m.rS!)) return;
    seen.add(m.rS!);
    timeLabels.push({ y: y(m.rS!) + 4, text: fmtTime ? fmtTime(m.tSend) : Math.round(m.tSend * 10) / 10 + ' ms' });
  });

  // por coluna: onde terminou o último texto, para os eventos não se sobreporem
  const lastEv: Record<string, number> = {};
  const events: EventLayout[] = tr.events
    .slice()
    .sort((a, b) => a.r! - b.r!)
    .map((e) => {
      const ci = tr.cols.findIndex((c) => c.key === e.who);
      const right = N > 2 ? ci > 0 && ci < N - 1 : ci > 0 || N === 1;
      const wrapAt = N > 2 && ci === 0 ? Math.max(14, Math.floor((xs[e.who] - 26) / 6.3)) : 30;
      const lines = wrapText(e.text, wrapAt);
      const ey = Math.max(y(e.r!) + 4, lastEv[e.who] === undefined ? -1e9 : lastEv[e.who] + 16);
      lastEv[e.who] = ey + 13 * (lines.length - 1);
      return { r: e.r!, x: xs[e.who] + (right ? 12 : -12), y: ey, anchor: right ? 'start' : 'end', lines, kind: e.kind };
    });

  // os textos de evento podem passar do fim da linha do tempo: a altura os acompanha
  const evBottom = events.reduce((m, e) => Math.max(m, e.y + 13 * (e.lines.length - 1)), 0);
  const height = Math.max(y(endR) + 36, evBottom + 24);
  return {
    width: W,
    height,
    minWidth: N > 2 ? 760 : 640,
    xs,
    y,
    columns: tr.cols.map((c) => ({ key: c.key, label: c.label, sub: c.sub || '', x: xs[c.key] })),
    phases: tr.phases.map((p) => ({ y: y(p.r!) - HH, label: p.label })),
    timeLabels,
    events,
    messages: tr.msgs.map((m) => ({ m, xa: xs[m.from], xb: xs[m.to], y1: y(m.rS!), y2: y(m.rA!) })),
  };
}
