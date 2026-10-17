import { forwardRef, type CSSProperties } from 'react';
import type { Message, Trace } from '../types';
import { timeAt } from '../trace';
import type { TopoNode, TopologyDef } from './module';
import { messageProgress } from './playback';

const OUTLINE = { stroke: '#0B2447', strokeWidth: '4px', paintOrder: 'stroke', strokeLinejoin: 'round' } as const;
const NODE_W = 128;
const NODE_H = 44;
const KIND_LABEL: Record<TopoNode['kind'], string> = { host: 'host', switch: 'switch', router: 'roteador', cloud: 'outras redes', attacker: 'host malicioso' };

interface Pt {
  x: number;
  y: number;
}

/** Pontos do caminho de uma mensagem: os centros dos nós por onde ela passa. */
export function routePoints(def: TopologyDef, m: Message): Pt[] {
  const keys = def.route ? def.route(m) : [m.from, m.to];
  const at = new Map(def.nodes.map((n) => [n.key, n]));
  return keys.map((k) => at.get(k)).filter((n): n is TopoNode => !!n).map((n) => ({ x: n.x, y: n.y }));
}

/** Ponto a uma fração (0 a 1) do comprimento total da poligonal. */
function along(pts: Pt[], f: number): Pt {
  if (pts.length === 1) return pts[0];
  const seg = pts.slice(1).map((p, i) => Math.hypot(p.x - pts[i].x, p.y - pts[i].y));
  let left = seg.reduce((a, b) => a + b, 0) * f;
  for (let i = 0; i < seg.length; i++) {
    if (left <= seg[i] || i === seg.length - 1) {
      const t = seg[i] ? Math.min(1, left / seg[i]) : 1;
      return { x: pts[i].x + (pts[i + 1].x - pts[i].x) * t, y: pts[i].y + (pts[i + 1].y - pts[i].y) * t };
    }
    left -= seg[i];
  }
  return pts[pts.length - 1];
}

/** Zoom 1 ajusta o quadro à largura e à altura do painel; acima disso a área rola; abaixo, encolhe e centraliza. */
function topoStyle(zoom: number): CSSProperties {
  if (zoom === 1) return { width: '100%', height: '100%', minWidth: 0 };
  const w = `${Math.round(zoom * 100)}%`;
  return zoom < 1 ? { width: w, height: w, minWidth: 0, margin: '0 auto' } : { width: w, height: 'auto', minWidth: 560 };
}

const path = (pts: Pt[]) => pts.map((p) => `${p.x},${p.y}`).join(' ');

function wrap(text: string, max: number): string[] {
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

interface Props {
  def: TopologyDef;
  tr: Trace;
  zoom: number;
  clock: number;
  selectedId: number | null;
  onSelect: (m: Message) => void;
}

/** Topologia em SVG: os pacotes percorrem os enlaces conforme o relógio, e cada nó mostra seu último evento e suas notas. */
export const Topology = forwardRef<HTMLDivElement, Props>(function Topology({ def, tr, zoom, clock, selectedId, onSelect }, ref) {
  const now = timeAt(tr, clock);
  const notes = def.notes ? def.notes(tr, now) : {};
  const shown = tr.msgs.filter((m) => m.rS! <= clock);
  const latest = shown.length ? shown.reduce((a, b) => (b.rS! >= a.rS! ? b : a)) : null;
  const at = new Map(def.nodes.map((n) => [n.key, n]));
  // último evento de cada ator até o relógio atual
  const lastEv = new Map<string, { text: string; kind: string }>();
  tr.events
    .filter((e) => e.r! <= clock)
    .sort((a, b) => a.r! - b.r!)
    .forEach((e) => lastEv.set(e.who, { text: e.text, kind: e.kind }));
  return (
    <div className="topo-wrap" ref={ref}>
      <svg className="topo" xmlns="http://www.w3.org/2000/svg" viewBox={`0 0 ${def.width} ${def.height}`} style={topoStyle(zoom)} role="group" aria-label="Topologia da rede">
        {def.links.map(([a, b, o], i) => {
          const A = at.get(a);
          const B = at.get(b);
          if (!A || !B) return null;
          return (
            <g key={i}>
              <line x1={A.x} y1={A.y} x2={B.x} y2={B.y} className={'topo-link' + (o && o.down ? ' down' : '') + (o && o.dashed ? ' dashed' : '')} />
              {o && o.label && (
                <text x={(A.x + B.x) / 2} y={(A.y + B.y) / 2 - 8} textAnchor="middle" className={'topo-linklabel' + (o.down ? ' down' : '')}>
                  {o.label}
                </text>
              )}
            </g>
          );
        })}
        {latest && (
          <polyline points={path(routePoints(def, latest))} fill="none" style={{ stroke: latest.color, strokeWidth: '4px', opacity: 0.35, strokeLinecap: 'round', strokeLinejoin: 'round' }} />
        )}
        {def.nodes.map((n) => {
          const ev = lastEv.get(n.key);
          const tableLines = notes[n.key] || [];
          const evLines = ev ? wrap(ev.text, 30) : [];
          return (
            <g key={n.key} className={'topo-node ' + n.kind}>
              {n.kind === 'cloud' ? (
                <ellipse cx={n.x} cy={n.y} rx={(n.w || NODE_W) / 2} ry={NODE_H / 2 + 4} className="topo-box" />
              ) : (
                <rect x={n.x - (n.w || NODE_W) / 2} y={n.y - NODE_H / 2} width={n.w || NODE_W} height={NODE_H} rx={n.kind === 'switch' ? 4 : 10} className="topo-box" />
              )}
              <text x={n.x} y={n.y - 4} textAnchor="middle" className="col-title">
                {n.label}
              </text>
              <text x={n.x} y={n.y + 12} textAnchor="middle" className="col-sub">
                {n.sub || KIND_LABEL[n.kind]}
              </text>
              <text x={n.x} y={n.y + NODE_H / 2 + 16} textAnchor="middle" className="topo-notes">
                {tableLines.map((ln, k) => (
                  <tspan key={k} x={n.x} dy={k === 0 ? 0 : 12}>
                    {ln}
                  </tspan>
                ))}
              </text>
              {evLines.length > 0 && (
                <text x={n.x} y={n.y + NODE_H / 2 + 16 + (tableLines.length ? 12 * tableLines.length + 8 : 0)} textAnchor="middle" className={'ev-label' + (ev!.kind ? ' ' + ev!.kind : '')} style={OUTLINE}>
                  {evLines.map((ln, k) => (
                    <tspan key={k} x={n.x} dy={k === 0 ? 0 : 13}>
                      {ln}
                    </tspan>
                  ))}
                </text>
              )}
            </g>
          );
        })}
        {shown.map((m) => {
          const p = messageProgress(m, clock);
          const pts = routePoints(def, m);
          if (pts.length < 2) return null;
          // em voo, ou perdida (o ✕ fica até a próxima mensagem), ou selecionada
          if (p.done && selectedId !== m.id && !(m.lost && m === latest)) return null;
          const q = along(pts, p.f);
          const label = String(m.label || '');
          return (
            <g
              key={m.id}
              className={'seg-g' + (selectedId === m.id ? ' selected' : '')}
              role="button"
              tabIndex={0}
              aria-label={`Mensagem ${m.id + 1}: ${label}${m.enc ? ' (cifrada)' : ''}`}
              onClick={() => onSelect(m)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  onSelect(m);
                }
              }}
            >
              {p.done && m.lost ? (
                <text x={q.x} y={q.y + 5} textAnchor="middle" className="seg-label" style={{ fill: 'var(--red)', fontSize: '18px' }}>
                  ✕
                </text>
              ) : (
                <circle cx={q.x} cy={q.y} r={7} style={{ fill: m.color, stroke: '#0B2447', strokeWidth: '2px' }} />
              )}
              <text x={q.x} y={q.y - 12} textAnchor="middle" className="seg-label" style={{ fill: m.color, ...OUTLINE }}>
                {label}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
});
