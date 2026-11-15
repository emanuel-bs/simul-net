// Gráficos do RIP para a documentação gerada: a métrica das rotas a cada rodada, calculada pelo próprio motor.
import { scenarioParams, type ScenarioDef } from '../../../sim-core/ui';
import { COR, grafico, type Cor, type Linha } from '../../../sim-core/doc-chart';
import { INF } from '../model';
import { buildConv, buildFalha, type ConvParams, type FalhaParams, type Snap } from '../modes';
import { controls } from './controls';

const FALHA_BASE: FalhaParams = { dir: 'PC-A', link: 'L3', link2: 'none', sh: true };
const ROTEADORES = ['R1', 'R2', 'R3', 'R4', 'R5'];

const snapsFalha = (P: FalhaParams): Snap[] => (buildFalha(P).raw as { snaps: Snap[] }).snaps;
const snapsConv = (P: ConvParams): Snap[] => (buildConv(P).raw as { snaps: Snap[] }).snaps;

/** Métrica que o roteador guarda para o destino em cada instantâneo; 16 quando não há rota. */
const metrica = (snaps: Snap[], roteador: string, destino: string): number[] => snaps.map((s) => s.tables[roteador][destino]?.metric ?? INF);

/** Menor métrica para o destino entre os roteadores (exceto o próprio destino): a "melhor notícia" que a rede acredita ter. */
const menor = (snaps: Snap[], destino: string): number[] => snaps.map((s) => Math.min(...ROTEADORES.map((r) => s.tables[r][destino]?.metric ?? INF)));

const rotulosFalha = (n: number): string[] => ['antes', 'falha', ...Array.from({ length: n - 2 }, (_, i) => String(i + 1))];
const rotulosConv = (n: number): string[] => ['início', ...Array.from({ length: n - 1 }, (_, i) => String(i + 1))];

const lin = (nome: string, cor: Cor, v: number[]): Linha => ({ nome, cor, v });
const infinito = (n: number): Linha => lin('16 (infinito)', COR.laranja, Array(n).fill(INF));

/** Métrica de R1, R2 e R4 para R3 quando um enlace cai, mas a rede continua conectada. */
function recuperacao(P: FalhaParams, titulo: string): string {
  const s = snapsFalha(P);
  return grafico({ titulo, x: 'Rodada de atualização', y: 'Métrica para R3 (saltos)', categorias: rotulosFalha(s.length) }, [
    lin('R1', COR.vermelho, metrica(s, 'R1', 'R3')), lin('R2', COR.azul, metrica(s, 'R2', 'R3')), lin('R4', COR.verde, metrica(s, 'R4', 'R3')), infinito(s.length),
  ], 17);
}

/** Menor métrica para R6 quando o destino fica isolado: sobe uma unidade por rodada até 16. */
function isolamento(Ps: [string, FalhaParams][], titulo: string): string {
  const todos = Ps.map(([nome, P]) => ({ nome, s: snapsFalha(P) }));
  const n = Math.max(...todos.map((t) => t.s.length));
  const pad = (v: number[]) => [...v, ...Array(n - v.length).fill(v[v.length - 1])];
  const cores = [COR.vermelho, COR.azul];
  return grafico({ titulo, x: 'Rodada de atualização', y: 'Menor métrica para R6 (saltos)', categorias: rotulosFalha(n) }, [
    ...todos.map((t, i) => lin(t.nome, cores[i], pad(menor(t.s, 'R6')))), infinito(n),
  ], 17);
}

/** Métrica de R1 para R2, R3 e R6 durante a convergência: 16 enquanto não há rota. */
function aprendizado(P: ConvParams, titulo: string): string {
  const s = snapsConv(P);
  return grafico({ titulo, x: 'Rodada de Response', y: 'Métrica de R1 (16 = sem rota)', categorias: rotulosConv(s.length) }, [
    lin('R2 (1 salto)', COR.vermelho, metrica(s, 'R1', 'R2')), lin('R3 (2 saltos)', COR.azul, metrica(s, 'R1', 'R3')), lin('R6 (3 saltos)', COR.verde, metrica(s, 'R1', 'R6')),
  ], 17);
}

const ISOLA = { dir: 'PC-A', link: 'L5', link2: 'L7' };

/** Gráfico do cenário: a métrica das rotas a cada rodada, nas condições do cenário. */
export function metricaDoCenario(s: ScenarioDef): string {
  const P = scenarioParams(controls, s) as unknown as ConvParams & FalhaParams;
  if (s.sub === 'conv') {
    return aprendizado(P, 'Rotas de R1 aprendidas a cada rodada: ' + s.label) + '\n\n*Gráfico do cenário (métrica de R1).* A métrica que R1 guarda para R2, R3 e R6 a cada rodada de Response. Vale 16 enquanto R1 ainda não tem rota para o destino. Calculado pelo motor do simulador.';
  }
  if (P.link2 !== 'none') {
    return isolamento([[P.sh ? 'Com split horizon' : 'Sem split horizon', P]], 'Contagem ao infinito: ' + s.label) + '\n\n*Gráfico do cenário (menor métrica para R6).* A menor métrica para R6 entre R1, R2, R3, R4 e R5 a cada rodada, depois que R6 ficou isolado. Sobe de 1 em 1 até 16, quando a rede enfim reconhece que o destino sumiu. Calculado pelo motor do simulador.';
  }
  return recuperacao(P, 'Reconvergência após a falha: ' + s.label) + '\n\n*Gráfico do cenário (métrica para R3).* A métrica de R1, R2 e R4 para R3 antes da falha, logo após ela (16 nas rotas que usavam o enlace) e em cada rodada seguinte. Calculado pelo motor do simulador.';
}

// Gráficos da fundamentação, calculados uma vez ao carregar o módulo.
export const CURVA_APRENDIZADO = aprendizado({ dir: 'PC-A', cost23: 10, sh: true }, 'Convergência: a métrica de R1 a cada rodada');
export const CURVA_RECUPERACAO = recuperacao(FALHA_BASE, 'Queda do enlace R2 / R3: a rede se recupera em poucas rodadas');
export const CURVA_INFINITO = isolamento([['Sem split horizon', { ...ISOLA, sh: false }], ['Com split horizon e poison reverse', { ...ISOLA, sh: true }]], 'Contagem ao infinito: R6 isolado');
