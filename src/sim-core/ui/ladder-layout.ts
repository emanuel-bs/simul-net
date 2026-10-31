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
  // Espaço extra inserido antes de certas linhas, para que os textos de evento (que ocupam várias linhas de texto) não passem por cima das mensagens e das fases seguintes
  const gaps: { at: number; add: number }[] = [];
  const extra = (r: number) => gaps.reduce((k, g) => (g.at <= r + 1e-9 ? k + g.add : k), 0);
  const y = (r: number) => TOP + r * ROW_H + offs(r) + extra(r);

  const phaseRows = new Set<number>(tr.phases.map((p) => p.r!));
  const rows = [...new Set<number>([...tr.msgs.flatMap((m) => [m.rS!, m.rA!]), ...tr.phases.map((p) => p.r!), ...tr.events.map((e) => e.r!)])].sort((a, b) => a - b);

  // por coluna: onde terminou o último texto, para os eventos não se sobreporem
  const lastEv: Record<string, number> = {};
  const events: EventLayout[] = tr.events
    .slice()
    .sort((a, b) => a.r! - b.r!)
    .map((e) => {
      const ci = tr.cols.findIndex((c) => c.key === e.who);
      const right = N > 2 ? ci > 0 && ci < N - 1 : ci > 0 || N === 1;
      // na primeira coluna o texto vai para a esquerda e não pode invadir a faixa dos rótulos de tempo (até x = 64)
      const wrapAt = N > 2 && ci === 0 ? Math.max(12, Math.floor((xs[e.who] - 12 - 64) / 6.3)) : 30;
      const lines = wrapText(e.text, wrapAt);
      // se uma mensagem parte desta coluna na mesma linha, na direção do texto, o rótulo dela (no meio da seta) ocuparia o mesmo espaço: o texto desce até a linha de chegada da seta
      const side = right ? 1 : -1;
      const out = tr.msgs.filter((m) => m.from === e.who && Math.abs(m.rS! - e.r!) < 1e-9 && Math.sign(xs[m.to] - xs[m.from]) === side);
      const effR = out.reduce((k, m) => Math.max(k, m.rA!), e.r!);
      const ey = Math.max(y(effR) + 4, lastEv[e.who] === undefined ? -1e9 : lastEv[e.who] + 16);
      const bottom = ey + 13 * (lines.length - 1);
      lastEv[e.who] = bottom;
      // a próxima linha com conteúdo precisa começar depois do fim do texto
      const next = Math.min(...rows.filter((n) => n > effR + 1e-9), Infinity);
      if (next !== Infinity) {
        // o rótulo de uma mensagem fica uns 12 px acima da seta: deixa espaço para ele também
        const clear = phaseRows.has(next) ? HH + 8 : 24;
        const need = bottom + clear - y(next);
        if (need > 0) gaps.push({ at: next, add: need });
      }
      return { r: e.r!, x: xs[e.who] + (right ? 12 : -12), y: ey, anchor: right ? 'start' : 'end', lines, kind: e.kind };
    });

  // os rótulos de tempo seguem as linhas já deslocadas
  const seen = new Set<number>();
  const timeLabels: LadderLayout['timeLabels'] = [];
  tr.msgs.forEach((m) => {
    if (seen.has(m.rS!)) return;
    seen.add(m.rS!);
    timeLabels.push({ y: y(m.rS!) + 4, text: fmtTime ? fmtTime(m.tSend) : Math.round(m.tSend * 10) / 10 + ' ms' });
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
    // fases na mesma linha (sem mensagem entre elas) ficam empilhadas, uma acima da outra
    phases: tr.phases.map((p, i) => {
      const same = tr.phases.filter((q) => Math.abs(q.r! - p.r!) < 1e-9);
      return { y: y(p.r!) - HH * (same.length - same.indexOf(tr.phases[i])), label: p.label };
    }),
    timeLabels,
    events,
    messages: tr.msgs.map((m) => ({ m, xa: xs[m.from], xb: xs[m.to], y1: y(m.rS!), y2: y(m.rA!) })),
  };
}
