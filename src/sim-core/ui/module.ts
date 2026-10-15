// Contrato de um simulador nativo (docs/arquitetura.md, seção 5). A forma é a mesma dos módulos
// legados (SecureSim.register), para que os textos e controles possam ser portados sem reescrita.
import type { Trace } from '../types';

export type ParamValue = string | number | boolean;
export type Params = Record<string, ParamValue>;

export interface ControlHelp {
  t: string;
  s?: string;
  /** Parágrafos em HTML restrito (b, code). Conteúdo autoral, nunca entrada do usuário. */
  p: string[];
}

export interface ControlDef {
  id: string;
  label: string;
  type: 'select' | 'check';
  opts?: [ParamValue, string][];
  def: ParamValue;
  /** Grupo (título da seção no painel). */
  grp: string;
  /** Mostrado em "Ajustes avançados". */
  adv?: boolean;
  /** Modos em que o controle aparece; sem o campo, aparece em todos. */
  subs?: string[];
  wide?: boolean;
  /** O valor do select é numérico. */
  num?: boolean;
  help?: ControlHelp;
}

export interface ScenarioDef {
  id: string;
  /** Grupo do cenário. */
  g: string;
  label: string;
  sub: string;
  set?: Params;
  /** HTML da seção "Neste cenário". */
  what: string;
  openAdv?: boolean;
}

export interface ScenarioDoc {
  short: string;
  concept: string;
  observe: string[];
  msgs: string[][];
  why: string;
  cols?: string[];
  msgsTitle?: string;
}

export interface TabContext {
  /** Posição do relógio, em linhas. */
  c: number;
  timeAt: (c: number) => number;
  P: Params;
}

export interface TabDef {
  id: string;
  label: string;
  /** Modos em que a aba aparece. */
  subs?: string[];
  render: (tr: Trace, ctx: TabContext) => string;
}

export interface SubDef {
  key: string;
  label: string;
  /** Cenário carregado ao escolher o modo. */
  default: string;
}

export interface ProtocolDef {
  id: string;
  label: string;
  stateTitle?: string;
  rfcs: [number, string][];
  subs: SubDef[];
  controls: ControlDef[];
  scenarios: ScenarioDef[];
  groupDoc: Record<string, string>;
  scenDoc: Record<string, ScenarioDoc>;
  tabs?: TabDef[];
  stageTitle?: (sub: string) => string;
  /** Motor puro: o mesmo parâmetro produz o mesmo trace. */
  build: (P: Params, sub: string) => Trace;
  explain: (tr: Trace, P: Params, scen: ScenarioDef | undefined) => string;
  reference: string;
  setup?: (s: ScenarioDef) => string;
}
