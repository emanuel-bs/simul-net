import { useCallback, useEffect, useRef, useState } from 'react';

/** Preferência do sistema por movimento reduzido (falso onde matchMedia não existe, como em testes). */
export function prefersReducedMotion(): boolean {
  try {
    return typeof window !== 'undefined' && !!window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  } catch {
    return false;
  }
}

/** Fator de velocidade da topologia, em relação ao diagrama de sequência. */
export const TOPO_SLOW = 0.4;

export interface Player {
  clock: number;
  playing: boolean;
  speed: number;
  setSpeed: (s: number) => void;
  /** Inicia, ou recomeça se já terminou. Com movimento reduzido, salta para o fim. */
  play: () => void;
  pause: () => void;
  restart: () => void;
  /** Avança até a posição indicada e pausa. */
  stepTo: (row: number) => void;
}

/** Relógio da simulação, em linhas do trace. `endR` é a linha final; a troca de trace deve usar `key` no chamador. */
export function usePlayer(endR: number, factor = 1): Player {
  const [clock, setClock] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1.8);
  const clockRef = useRef(0);
  const speedRef = useRef(speed);
  speedRef.current = speed * factor;

  const set = useCallback((c: number) => {
    clockRef.current = c;
    setClock(c);
  }, []);

  useEffect(() => {
    if (!playing) return;
    let id = 0;
    let last = performance.now();
    const frame = (ts: number) => {
      const dt = Math.min(100, ts - last);
      last = ts;
      const next = Math.min(endR, clockRef.current + (dt / 1000) * speedRef.current);
      set(next);
      if (next >= endR) setPlaying(false);
      else id = requestAnimationFrame(frame);
    };
    id = requestAnimationFrame(frame);
    return () => cancelAnimationFrame(id);
  }, [playing, endR, set]);

  const restart = useCallback(() => {
    setPlaying(false);
    set(0);
  }, [set]);

  const play = useCallback(() => {
    if (clockRef.current >= endR) set(0);
    if (prefersReducedMotion()) {
      set(endR);
      setPlaying(false);
    } else setPlaying(true);
  }, [endR, set]);

  const pause = useCallback(() => setPlaying(false), []);
  const stepTo = useCallback(
    (row: number) => {
      setPlaying(false);
      set(row);
    },
    [set],
  );

  return { clock, playing, speed, setSpeed, play, pause, restart, stepTo };
}
