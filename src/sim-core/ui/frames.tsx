// Quadros da bancada: destacar, mover, redimensionar, maximizar e recolher (porta de public/sims/bench/bench.js).
// A posição e o tamanho de um quadro flutuante são aplicados direto no elemento durante o arrasto, para não
// redesenhar a bancada inteira a cada movimento do mouse; o React só controla o estado e as classes.
import { createContext, useCallback, useContext, useEffect, useRef, useState, type PointerEvent as ReactPointerEvent, type ReactNode } from 'react';

interface Rect {
  left: number;
  top: number;
  width: number;
  height: number;
}

interface Entry {
  undock: () => void;
  time: number;
}

interface Manager {
  /** Maior z-index entregue: clicar em um quadro o traz para a frente. */
  z: number;
  floating: Map<symbol, Entry>;
}

const FloatContext = createContext<Manager | null>(null);

const clamp = (v: number, a: number, b: number) => Math.max(a, Math.min(b, v));
const INTERACTIVE = 'button,select,input,a';

/** Reúne os quadros flutuantes: a tecla Esc encaixa o mais recente e, em tela estreita, todos voltam ao lugar. */
export function FloatProvider({ children }: { children: ReactNode }) {
  const mgr = useRef<Manager>({ z: 60, floating: new Map() });
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      const latest = Array.from(mgr.current.floating.values()).sort((a, b) => b.time - a.time)[0];
      if (latest) latest.undock();
    };
    document.addEventListener('keydown', onKey);
    const mq = typeof window !== 'undefined' && window.matchMedia ? window.matchMedia('(min-width:961px)') : null;
    const onMq = () => {
      if (mq && !mq.matches) mgr.current.floating.forEach((x) => x.undock());
    };
    mq?.addEventListener('change', onMq);
    return () => {
      document.removeEventListener('keydown', onKey);
      mq?.removeEventListener('change', onMq);
    };
  }, []);
  return <FloatContext.Provider value={mgr.current}>{children}</FloatContext.Provider>;
}

export interface FrameOptions {
  /** Começa recolhido (só a barra de título). */
  collapsedInitial?: boolean;
  /** Painel de abas: ao destacar, ocupa a parte baixa e central da tela. */
  tabsPanel?: boolean;
}

const POS_KEYS = ['left', 'top', 'width', 'height', 'right', 'bottom', 'zIndex'] as const;
const DIRS = ['n', 's', 'e', 'w', 'ne', 'nw', 'sw', 'se'] as const;

/**
 * Comportamento de um quadro destacável. O chamador liga `rootProps` ao elemento do quadro, `barProps` à barra de
 * título (arrastar com o mouse, duplo clique para encaixar), e coloca `buttons` na barra e `handles` no fim do quadro.
 */
export function useFrame(opts: FrameOptions = {}) {
  const mgr = useContext(FloatContext);
  const el = useRef<HTMLElement | null>(null);
  const [floating, setFloating] = useState(false);
  // tamanho que o quadro ocupava no fluxo antes de destacar: um marcador guarda o lugar para os outros quadros não se moverem
  const [flow, setFlow] = useState<{ height: number } | null>(null);
  const [maxed, setMaxed] = useState(false);
  const [collapsed, setCollapsed] = useState(!!opts.collapsedInitial);
  const saved = useRef<Rect | null>(null);
  const prev = useRef<Rect | null>(null);
  const key = useRef(Symbol('frame'));
  const dragged = useRef(false);

  const cur = (): Rect => {
    const r = el.current!.getBoundingClientRect();
    return { left: r.left, top: r.top, width: r.width, height: r.height };
  };
  const place = (r: Rect) => {
    const s = el.current!.style;
    s.left = r.left + 'px';
    s.top = r.top + 'px';
    s.width = r.width + 'px';
    s.height = r.height + 'px';
    s.right = 'auto';
    s.bottom = 'auto';
  };
  const bringToFront = () => {
    if (mgr && el.current) el.current.style.zIndex = String(++mgr.z);
  };

  const undock = useCallback(() => {
    const node = el.current;
    if (node) {
      saved.current = cur();
      POS_KEYS.forEach((k) => (node.style[k] = ''));
    }
    mgr?.floating.delete(key.current);
    setFloating(false);
    setFlow(null);
    setMaxed(false);
  }, [mgr]);

  const float = () => {
    if (!el.current) return;
    setFlow({ height: Math.round(el.current.getBoundingClientRect().height) });
    const r = saved.current ? { ...saved.current } : cur();
    if (!saved.current && opts.tabsPanel) {
      r.width = Math.round(window.innerWidth * 0.72);
      r.left = Math.round((window.innerWidth - r.width) / 2);
      r.height = Math.max(r.height, 260);
      r.top = window.innerHeight - r.height - 30;
    }
    r.width = clamp(r.width, 320, window.innerWidth - 16);
    r.height = clamp(r.height, 170, window.innerHeight - 16);
    r.left = clamp(r.left, 8, window.innerWidth - r.width - 8);
    r.top = clamp(r.top, 8, window.innerHeight - r.height - 8);
    setCollapsed(false);
    place(r);
    bringToFront();
    mgr?.floating.set(key.current, { undock, time: Date.now() });
    setFloating(true);
  };

  useEffect(() => {
    const k = key.current;
    return () => {
      mgr?.floating.delete(k);
    };
  }, [mgr]);

  const toggleFloat = () => (floating ? undock() : float());

  const toggleMax = () => {
    if (!floating) return;
    if (maxed) {
      if (prev.current) place(prev.current);
      setMaxed(false);
    } else {
      prev.current = cur();
      place({ left: 12, top: 12, width: window.innerWidth - 24, height: window.innerHeight - 24 });
      setMaxed(true);
    }
  };

  const startDrag = (e: ReactPointerEvent) => {
    const hit = (e.target as HTMLElement).closest(INTERACTIVE);
    // o título do quadro é um botão, mas também serve de alça para arrastar
    if (!floating || maxed || e.button > 0 || (hit && !hit.hasAttribute('data-drag'))) return;
    const node = el.current!;
    const sx = e.clientX;
    const sy = e.clientY;
    const r = cur();
    dragged.current = false;
    const mv = (ev: PointerEvent) => {
      if (Math.abs(ev.clientX - sx) + Math.abs(ev.clientY - sy) > 3) dragged.current = true;
      node.style.left = clamp(r.left + ev.clientX - sx, 0, window.innerWidth - 80) + 'px';
      node.style.top = clamp(r.top + ev.clientY - sy, 0, window.innerHeight - 40) + 'px';
    };
    const up = () => {
      window.removeEventListener('pointermove', mv);
      window.removeEventListener('pointerup', up);
      window.removeEventListener('pointercancel', up);
      // o clique que encerra um arrasto não deve recolher o quadro (o título é um botão)
      setTimeout(() => (dragged.current = false), 0);
    };
    window.addEventListener('pointermove', mv);
    window.addEventListener('pointerup', up);
    window.addEventListener('pointercancel', up);
  };

  const startResize = (e: ReactPointerEvent, dir: string) => {
    if (e.button > 0) return;
    e.preventDefault();
    e.stopPropagation();
    const sx = e.clientX;
    const sy = e.clientY;
    const r = cur();
    setMaxed(false);
    const mv = (ev: PointerEvent) => {
      const dx = ev.clientX - sx;
      const dy = ev.clientY - sy;
      let { left: l, top: t, width: w, height: h } = r;
      if (dir.includes('e')) w = clamp(r.width + dx, 300, window.innerWidth - r.left);
      if (dir.includes('w')) {
        w = clamp(r.width - dx, 300, r.left + r.width);
        l = r.left + r.width - w;
      }
      if (dir.includes('s')) h = clamp(r.height + dy, 150, window.innerHeight - r.top);
      if (dir.includes('n')) {
        h = clamp(r.height - dy, 150, r.top + r.height);
        t = r.top + r.height - h;
      }
      place({ left: l, top: t, width: w, height: h });
    };
    const up = () => {
      window.removeEventListener('pointermove', mv);
      window.removeEventListener('pointerup', up);
      window.removeEventListener('pointercancel', up);
    };
    window.addEventListener('pointermove', mv);
    window.addEventListener('pointerup', up);
    window.addEventListener('pointercancel', up);
  };

  const stop = (fn: () => void) => (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    fn();
  };

  return {
    floating,
    collapsed,
    setCollapsed,
    /** Marcador que ocupa o lugar do quadro enquanto ele está destacado; vai logo antes do elemento do quadro. */
    placeholder: floating && flow ? (
      <div className="frame-ph" aria-hidden="true" style={{ '--ph-h': flow.height + 'px' } as React.CSSProperties}>
        <span>Quadro destacado</span>
      </div>
    ) : null,
    /** Classes do elemento do quadro, somadas às de `base`. */
    className: (base: string) => base + (floating ? ' is-floating' : '') + (collapsed ? ' body-collapsed' : ''),
    rootProps: {
      ref: (node: HTMLElement | null) => {
        el.current = node;
      },
      onPointerDownCapture: () => {
        if (floating) bringToFront();
      },
    },
    barProps: {
      onPointerDown: startDrag,
      onDoubleClick: (e: React.MouseEvent) => {
        if (floating && !(e.target as HTMLElement).closest(INTERACTIVE)) {
          e.preventDefault();
          toggleFloat();
        }
      },
      onClickCapture: (e: React.MouseEvent) => {
        if (dragged.current) {
          e.preventDefault();
          e.stopPropagation();
        }
      },
    },
    buttons: (
      <>
        <button type="button" className="fbtn fpush" aria-pressed={floating} onClick={stop(toggleFloat)}>
          {floating ? 'Encaixar' : 'Destacar'}
        </button>
        <button type="button" className="fbtn" hidden={!floating} onClick={stop(toggleMax)}>
          {maxed ? 'Restaurar' : 'Maximizar'}
        </button>
        <button type="button" className="fbtn" aria-expanded={!collapsed} onClick={stop(() => setCollapsed(!collapsed))}>
          {collapsed ? 'Expandir painel' : 'Recolher painel'}
        </button>
      </>
    ),
    handles: floating
      ? DIRS.map((d) => <div key={d} className={(d === 'se' ? 'fresize' : 'frz') + ' frz-' + d} onPointerDown={(e) => startResize(e, d)} />)
      : null,
  };
}
