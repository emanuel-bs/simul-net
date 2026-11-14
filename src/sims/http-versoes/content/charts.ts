// Gráficos do HTTP para a documentação gerada: calculados pelo próprio motor, para as três versões nas mesmas condições.
import { scenarioParams, type ScenarioDef } from '../../../sim-core/ui';
import { COR, degrau, grafico, type Linha } from '../../../sim-core/doc-chart';
import { buildHttp, VERSION_NAME, type HttpParams, type Job, type Version } from '../engine';
import { controls } from './controls';

const VERSOES: Version[] = ['h1', 'h2', 'h3'];
const COR_VERSAO = { h1: COR.vermelho, h2: COR.azul, h3: COR.verde };
const N = 80;

/** Base dos gráficos: o cenário padrão do simulador (80 ms, 8 recursos, TLS, 6 conexões). */
const BASE = scenarioParams(controls, { id: '', g: '', sub: 'h1', label: '', what: '', set: {} } as ScenarioDef) as unknown as HttpParams;

function rodar(P: HttpParams, v: Version): { jobs: Job[]; tDone: number } {
  const tr = buildHttp(P, v);
  const R = tr.raw as { jobs: Job[]; tDone: number };
  return { jobs: R.jobs, tDone: R.tDone };
}

/** Recursos já recebidos em função do tempo, para as três versões: uma curva em degraus. */
function curvaRecursos(P: HttpParams, titulo: string): string {
  const rs = VERSOES.map((v) => rodar(P, v));
  const fim = Math.ceil(Math.max(...rs.map((r) => r.tDone)) / 10) * 10;
  const linhas: Linha[] = VERSOES.map((v, i) => {
    const chegadas = rs[i].jobs.map((j) => j.arr).sort((a, b) => a - b);
    const amostras = [{ t: 0, n: 0 }, ...chegadas.map((t, k) => ({ t, n: k + 1 }))];
    return { nome: VERSION_NAME[v], cor: COR_VERSAO[v], v: degrau(amostras, 0, fim, N, (a) => a.n) };
  });
  return grafico({ titulo, x: 'Tempo (ms)', y: 'Recursos recebidos (de ' + P.res + ')', de: 0, ate: fim }, linhas, P.res);
}

/** Gráfico do cenário: como chegam os recursos em cada versão, nas condições do cenário. */
export function recursosDoCenario(s: ScenarioDef): string {
  const P = scenarioParams(controls, s) as unknown as HttpParams;
  const g = curvaRecursos(P, 'Recursos recebidos ao longo do tempo: ' + s.label);
  return g + '\n\n*Gráfico do cenário (recursos recebidos).* Quantos dos ' + P.res + ' recursos da página já chegaram ao navegador em cada instante, nas condições deste cenário, para as três versões. Vale o instante em que o recurso fica disponível para a página (o retido por perda só conta depois da retransmissão). Calculado pelo motor do simulador.';
}

// Gráficos da fundamentação, calculados uma vez ao carregar o módulo.

/** Tempo até a página carregar, em função do RTT. */
export const CURVA_RTT = (() => {
  const rtts = [20, 80, 200];
  const linhas: Linha[] = VERSOES.map((v) => ({ nome: VERSION_NAME[v], cor: COR_VERSAO[v], v: rtts.map((rtt) => Math.round(rodar({ ...BASE, rtt }, v).tDone)) }));
  return grafico({ titulo: 'Tempo para carregar a página (8 recursos) conforme o RTT', x: 'RTT da rede', y: 'Tempo até o último recurso (ms)', categorias: rtts.map((r) => r + ' ms') }, linhas);
})();

export const CURVA_CHEGADA = curvaRecursos({ ...BASE, res: 16 }, 'Chegada de 16 recursos, RTT de 80 ms');
export const CURVA_PERDA = curvaRecursos({ ...BASE, rtt: 200, loss: true }, 'Perda de um pacote de /app.js, RTT de 200 ms');
