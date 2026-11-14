// Gráficos do TCP para a documentação gerada: a janela de congestionamento (cwnd) calculada pelo próprio motor.
import { scenarioParams, type ControlDef, type ScenarioDef } from '../../../sim-core/ui';
import { COR, degrau, grafico, type Cor, type Linha } from '../../../sim-core/doc-chart';
import { derive } from '../../transporte-base/derive';
import { buildTcpUdp, type TcpUdpParams } from '../../transporte-base/modes';
import { comparacao } from './comparacao';

interface Amostra {
  t: number;
  cwnd: number;
  ssthresh: number;
}

interface Corrida {
  amostras: Amostra[];
  /** Instante da primeira amostra: o eixo de tempo começa aí, e não na abertura da conexão. */
  inicio: number;
  fim: number;
  rwnd: number;
}

/** Roda o motor no cenário e devolve as amostras da cwnd do TCP. */
function rodar(controls: ControlDef[], s: ScenarioDef): Corrida {
  const P = scenarioParams(controls, s) as unknown as TcpUdpParams;
  const tr = buildTcpUdp(P, s.sub);
  const R = tr.raw as { sims: { samples: Amostra[] }[]; end: number; P: { rwnd: number } };
  const amostras = R.sims[0].samples;
  return { amostras, inicio: amostras[0].t, fim: R.end, rwnd: R.P.rwnd };
}

const N = 80;

/** Unidade do eixo de tempo: ms em transferências curtas, s nas longas. */
function unidade(fim: number): { k: number; nome: string } {
  return fim >= 2000 ? { k: 1000, nome: 's' } : { k: 1, nome: 'ms' };
}

const arredonda = (v: number): number => Math.round(v * 100) / 100;

/** Gráfico do cenário: a cwnd, o ssthresh e, quando limita, a janela do receptor. O handshake não tem curva. */
export function cwndDoCenario(controls: ControlDef[], s: ScenarioDef): string {
  if (s.id === 'hs') return '';
  const c = rodar(controls, s);
  const u = unidade(c.fim);
  const cw = degrau(c.amostras, c.inicio, c.fim, N, (a) => a.cwnd);
  const topo = Math.max(...cw);
  // O ssthresh inicial costuma ser alto demais: o gráfico o limita ao teto da cwnd para não achatar a curva.
  const lim = Math.ceil(topo * 1.25);
  const linhas: Linha[] = [
    { nome: 'cwnd (janela de congestionamento)', cor: COR.vermelho, v: cw },
    { nome: 'ssthresh', cor: COR.laranja, v: degrau(c.amostras, c.inicio, c.fim, N, (a) => Math.min(a.ssthresh, lim)) },
  ];
  if (c.rwnd <= lim) linhas.push({ nome: 'rwnd (janela do receptor)', cor: COR.azul, v: cw.map(() => c.rwnd) });
  const g = grafico({ titulo: 'Janela de congestionamento: ' + s.label, x: 'Tempo (' + u.nome + ')', y: 'Segmentos', de: arredonda(c.inicio / u.k), ate: arredonda(c.fim / u.k) }, linhas, Math.ceil(Math.max(topo, ...linhas.map((l) => Math.max(...l.v))) * 1.1));
  return g + '\n\n*Gráfico do cenário (cwnd).* A janela de congestionamento e o limiar do slow start ao longo da conexão, calculados pelo motor do simulador. Corresponde à aba Janela (cwnd).';
}

/** Gráfico da fundamentação: a cwnd de vários cenários na mesma escala de tempo (a linha se mantém depois do fim do cenário). */
export function compararCwnd(controls: ControlDef[], scenarios: ScenarioDef[], titulo: string, ids: [string, string, Cor][], comSsthresh = false): string {
  const corridas = ids.map(([id]) => rodar(controls, scenarios.find((x) => x.id === id) as ScenarioDef));
  const fim = Math.max(...corridas.map((c) => c.fim));
  const ini = Math.min(...corridas.map((c) => c.inicio));
  const u = unidade(fim);
  const linhas: Linha[] = ids.map(([, nome, cor], i) => ({ nome, cor, v: degrau(corridas[i].amostras, ini, fim, N, (a) => a.cwnd) }));
  if (comSsthresh) {
    const topo = Math.max(...linhas.flatMap((l) => l.v));
    linhas.push({ nome: 'ssthresh', cor: COR.laranja, v: degrau(corridas[0].amostras, ini, fim, N, (a) => Math.min(a.ssthresh, Math.ceil(topo * 1.25))) });
  }
  return grafico({ titulo, x: 'Tempo (' + u.nome + ')', y: 'cwnd (segmentos)', de: arredonda(ini / u.k), ate: arredonda(fim / u.k) }, linhas);
}

// Gráficos da fundamentação, calculados uma vez ao carregar o módulo.
const d = derive(['tcp', 'dl', 'cmp'], comparacao);

export const CURVA_SLOW_START = compararCwnd(d.controls, d.scenarios, 'Slow start e congestion avoidance (cenário Slow start)', [['ss', 'cwnd', COR.vermelho]], true);
export const CURVA_PERDA = compararCwnd(d.controls, d.scenarios, 'Uma perda: fast retransmit contra timeout', [['fr', 'Fast retransmit (3 ACKs duplicados)', COR.vermelho], ['rto', 'Timeout (RTO)', COR.azul]]);
export const CURVA_SACK = compararCwnd(d.controls, d.scenarios, 'Várias perdas na mesma janela: sem SACK e com SACK', [['nosack', 'Sem SACK', COR.vermelho], ['sack', 'Com SACK', COR.verde]]);
