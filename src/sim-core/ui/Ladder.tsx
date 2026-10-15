import { forwardRef, type CSSProperties } from 'react';
import type { Message } from '../types';
import type { LadderLayout } from './ladder-layout';
import { messageProgress } from './playback';

const OUTLINE = { stroke: '#0B2447', strokeWidth: '4px', paintOrder: 'stroke', strokeLinejoin: 'round' } as const;

/** Zoom 1 ajusta o diagrama ao painel; acima disso ele cresce e a área rola; abaixo, encolhe e centraliza. */
export const ZOOM_STEPS = [0.5, 0.65, 0.8, 1, 1.25, 1.5, 2];
export const ZOOM_FIT = ZOOM_STEPS.indexOf(1);

function zoomStyle(zoom: number, minWidth: number): CSSProperties {
  if (zoom === 1) return { minWidth };
  return zoom < 1 ? { width: `${Math.round(zoom * 100)}%`, minWidth: 0, margin: '0 auto' } : { width: `${Math.round(zoom * 100)}%`, minWidth };
}

interface Props {
  layout: LadderLayout;
  zoom: number;
  clock: number;
  selectedId: number | null;
  onSelect: (m: Message) => void;
}

/** Diagrama de sequência em SVG. A geometria vem de layoutLadder; aqui só se desenha o que o relógio já alcançou. */
export const Ladder = forwardRef<HTMLDivElement, Props>(function Ladder({ layout, zoom, clock, selectedId, onSelect }, ref) {
  return (
    <div className="ladder-wrap" ref={ref}>
      <svg
        className="ladder"
        xmlns="http://www.w3.org/2000/svg"
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        style={zoomStyle(zoom, layout.minWidth)}
        role="group"
        aria-label="Diagrama de sequência da conexão"
      >
        {layout.columns.map((c) => (
          <g key={c.key}>
            <text x={c.x} y={28} textAnchor="middle" className="col-title">
              {c.label}
            </text>
            <text x={c.x} y={44} textAnchor="middle" className="col-sub">
              {c.sub}
            </text>
            <line x1={c.x} y1={66} x2={c.x} y2={layout.height - 10} style={{ stroke: 'var(--muted)', strokeWidth: '2px' }} />
          </g>
        ))}
        {layout.phases.map((p, i) => (
          <g key={i}>
            <line x1={20} y1={p.y + 4} x2={layout.width - 20} y2={p.y + 4} style={{ stroke: 'var(--border)', strokeDasharray: '4,4' }} />
            <text x={layout.width / 2} y={p.y + 19} textAnchor="middle" className="phase-label">
              {p.label}
            </text>
          </g>
        ))}
        {layout.timeLabels.map((t, i) => (
          <text key={i} x={60} y={t.y} textAnchor="end" className="time-label">
            {t.text}
          </text>
        ))}
        {layout.events.map((e, i) =>
          clock >= e.r ? (
            <text key={i} x={e.x} y={e.y} textAnchor={e.anchor} className={'ev-label' + (e.kind ? ' ' + e.kind : '')} style={OUTLINE}>
              {e.lines.map((ln, k) => (
                <tspan key={k} x={e.x} dy={k === 0 ? 0 : 13}>
                  {ln}
                </tspan>
              ))}
            </text>
          ) : null,
        )}
        {layout.messages.map(({ m, xa, xb, y1, y2 }) => {
          const p = messageProgress(m, clock);
          if (!p.visible) return null;
          const x = xa + (xb - xa) * p.f;
          const yy = y1 + (y2 - y1) * p.f;
          const fx = (xa + xb) / 2;
          const fy = (y1 + y2) / 2;
          const ang = (Math.atan2(y2 - y1, xb - xa) * 180) / Math.PI;
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
              <line x1={xa} y1={y1} x2={x} y2={yy} style={{ stroke: m.color, strokeWidth: m.enc ? '2.4px' : '2px' }} />
              {p.done && !m.lost && <polygon points="0,0 -9,-4 -9,4" transform={`translate(${x},${yy}) rotate(${ang})`} style={{ fill: m.color }} />}
              {p.done && m.lost && (
                <text x={x} y={yy + 5} textAnchor="middle" className="seg-label" style={{ fill: 'var(--red)', fontSize: '15px' }}>
                  ✕
                </text>
              )}
              <text x={fx} y={fy - 7} textAnchor="middle" className="seg-label" style={{ fill: m.color, ...OUTLINE }}>
                {label}
              </text>
              <line x1={xa} y1={y1} x2={xb} y2={y2} stroke="transparent" strokeWidth={10} />
              {m.enc && (
                <g transform={`translate(${fx - 5},${fy + 4})`} aria-hidden="true">
                  <rect x={0} y={5} width={10} height={8} rx={1.5} style={{ fill: m.color }} />
                  <path d="M2 5 V3 a3 3 0 0 1 6 0 V5" fill="none" style={{ stroke: m.color, strokeWidth: '1.6px' }} />
                </g>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
});
