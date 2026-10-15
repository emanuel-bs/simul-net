import type { ControlDef, Params, ParamValue, ScenarioDef } from './module';

export const visibleControl = (c: ControlDef, sub: string): boolean => !c.subs || c.subs.indexOf(sub) >= 0;

export function defaultParams(controls: ControlDef[]): Params {
  const P: Params = {};
  controls.forEach((c) => (P[c.id] = c.def));
  return P;
}

/** Parâmetros de um cenário: padrão de cada controle sobreposto por scenario.set. */
export function scenarioParams(controls: ControlDef[], s: ScenarioDef): Params {
  return Object.assign(defaultParams(controls), s.set || {});
}

const labelOf = (c: ControlDef, v: ParamValue): string =>
  c.type === 'check' ? (v ? 'sim' : 'não') : ((c.opts || []).find((o) => String(o[0]) === String(v)) || [0, String(v)])[1];

export interface ControlChange {
  id: string;
  label: string;
  from: string;
  to: string;
}

/** Campos que hoje diferem da configuração pronta do cenário (controles ocultos no modo atual não contam). */
export function changedControls(controls: ControlDef[], sub: string, current: Params, s: ScenarioDef): ControlChange[] {
  const out: ControlChange[] = [];
  controls.filter((c) => visibleControl(c, sub)).forEach((c) => {
    const expected = s.set && c.id in s.set ? (s.set[c.id] as ParamValue) : c.def;
    if (String(current[c.id]) !== String(expected)) out.push({ id: c.id, label: c.label, from: labelOf(c, expected), to: labelOf(c, current[c.id]) });
  });
  return out;
}

/** Converte o valor lido de um select conforme o tipo do controle (numérico ou texto). */
export const parseSelect = (c: ControlDef, raw: string): ParamValue => (c.num ? Number(raw) : raw);
