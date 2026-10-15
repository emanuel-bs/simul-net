// Tipos do contrato do motor de simulação (docs/arquitetura.md, seção 5).
// O motor é puro: recebe parâmetros e devolve um Trace, sem tocar na tela.

/** Linha de campo de uma mensagem: [nome, valor, significado, classe] ou separador de seção. */
export type Field = [string, string, string?, string?] | { sec: string };

export interface Column {
  key: string;
  label: string;
  sub?: string;
  addr?: string;
}

export interface StateDef {
  key: string;
  label: string;
}

export interface Message {
  id: number;
  from: string;
  to: string;
  tSend: number;
  tArr: number;
  color: string;
  enc: boolean;
  proto: string;
  len: number;
  fields: Field[];
  tags: string[];
  lost: boolean;
  label?: string;
  info?: string;
  about?: string;
  phaseName?: string;
  /** Linhas do diagrama, preenchidas por prepare(). */
  rS?: number;
  rA?: number;
  [extra: string]: unknown;
}

export interface MessageOptions {
  tSend?: number;
  tArr?: number;
  color?: string;
  enc?: boolean;
  proto?: string;
  len?: number;
  fields?: Field[];
  tags?: string[];
  lost?: boolean;
  label?: string;
  info?: string;
  about?: string;
  phaseName?: string;
  /** Instante de envio fixo (ms). */
  at?: number;
  /** Duração do trânsito (ms); padrão: meio RTT. */
  dur?: number;
  /** Mensagem simultânea: não avança o cursor de tempo. */
  par?: boolean;
  /** Tempo de processamento somado depois da chegada (ms). */
  proc?: number;
  [extra: string]: unknown;
}

export interface TraceEvent {
  t: number;
  who: string;
  text: string;
  kind: string;
  r?: number;
}

export interface LogEntry {
  t: number;
  text: string;
  tag: string;
  r?: number;
}

export interface StateChange {
  t: number;
  key: string;
  val: string;
  cls: string;
  r?: number;
}

export interface Phase {
  t: number;
  label: string;
  key: string;
  r?: number;
}

export interface Milestone {
  t: number;
  label: string;
  sub?: string;
  r?: number;
}

export interface Trace {
  cols: Column[];
  stateDefs: StateDef[];
  msgs: Message[];
  events: TraceEvent[];
  log: LogEntry[];
  states: StateChange[];
  phases: Phase[];
  metro: Milestone[];
  /** Dados brutos do cenário, consumidos pelas abas e pelo texto do Experimento. */
  raw: Record<string, any>;
  tabData: Record<string, unknown>;
  /** Cursor de tempo (ms). */
  t: number;
  /** Atraso de ida (meio RTT, ms). */
  ow: number;
  rtt: number;
  /** Instantes distintos em ordem crescente, preenchido por prepare(). */
  times?: number[];
  add(from: string, to: string, o?: MessageOptions): Message;
  wait(ms: number): void;
  ev(t: number, who: string, text: string, kind?: string): void;
  lg(t: number, text: string, tag?: string): void;
  st(t: number, key: string, val: string, cls?: string): void;
  phase(label: string, key: string): void;
  mile(t: number, label: string, sub?: string): void;
}
