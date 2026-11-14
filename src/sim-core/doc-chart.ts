// Gráficos da documentação gerada (docs e wiki): Mermaid xychart calculado pelo próprio motor de cada simulador.
// Cada gráfico traz o comentário "%% legenda: a | b | c": o site desenha a legenda dentro da figura (src/docs/Mermaid.tsx)
// e a linha "Legenda:" em texto, que o site oculta, serve ao GitHub e à wiki.

/** Cores das linhas, cada uma com o quadrado de emoji do mesmo matiz (usado na legenda em texto). */
export const COR = {
  vermelho: { cor: '#dd2e44', emoji: '🟥' },
  azul: { cor: '#2f80ed', emoji: '🟦' },
  verde: { cor: '#2e9e4f', emoji: '🟩' },
  laranja: { cor: '#f4900c', emoji: '🟧' },
  roxo: { cor: '#8250df', emoji: '🟪' },
  preto: { cor: '#24292f', emoji: '⬛' },
} as const;

export type Cor = (typeof COR)[keyof typeof COR];

export interface Linha {
  nome: string;
  cor: Cor;
  v: number[];
}

/** Valor de um degrau: o da última amostra com t <= x (a série "segura" o valor até a próxima amostra). */
export function degrau<T extends { t: number }>(amostras: T[], x0: number, x1: number, n: number, val: (a: T) => number): number[] {
  const out: number[] = [];
  let k = 0;
  for (let i = 0; i < n; i++) {
    const x = x0 + ((x1 - x0) * i) / (n - 1);
    while (k + 1 < amostras.length && amostras[k + 1].t <= x + 1e-9) k++;
    out.push(amostras.length && amostras[0].t <= x + 1e-9 ? Math.round(val(amostras[k]) * 100) / 100 : 0);
  }
  return out;
}

/** Teto "redondo" do eixo Y, com folga acima do maior valor. */
export function teto(linhas: Linha[], folga = 1.1): number {
  const m = Math.max(...linhas.map((l) => Math.max(...l.v))) * folga;
  const passo = m > 2000 ? 500 : m > 200 ? 50 : m > 40 ? 10 : m > 8 ? 5 : 1;
  return Math.ceil(m / passo) * passo;
}

export interface Eixos {
  titulo: string;
  /** Nome do eixo X e do eixo Y. */
  x: string;
  y: string;
  /** Intervalo numérico do eixo X, ou as categorias (um valor por ponto das linhas). */
  de?: number;
  ate?: number;
  categorias?: string[];
}

/** Linha "Legenda:" em texto, para o Markdown (GitHub e wiki). O site a oculta: a legenda fica dentro da figura. */
export const legendaTexto = (linhas: Linha[]): string => '**Legenda:** ' + linhas.map((l) => l.cor.emoji + ' ' + l.nome).join(' · ');

/** Bloco Mermaid do gráfico (largura e altura fixas) com a legenda em texto acima. */
export function grafico(e: Eixos, linhas: Linha[], topo = teto(linhas)): string {
  const eixoX = e.categorias ? '[' + e.categorias.map((c) => '"' + c + '"').join(', ') + ']' : e.de + ' --> ' + e.ate;
  return [
    legendaTexto(linhas),
    '',
    '```mermaid',
    '%%{init: {"xyChart": {"width": 900, "height": 560}, "themeVariables": {"xyChart": {"plotColorPalette": "' + linhas.map((l) => l.cor.cor).join(', ') + '"}}}}%%',
    '%% legenda: ' + linhas.map((l) => l.nome).join(' | '),
    'xychart-beta',
    '  title "' + e.titulo + '"',
    '  x-axis "' + e.x + '" ' + eixoX,
    '  y-axis "' + e.y + '" 0 --> ' + topo,
    ...linhas.map((l) => '  line [' + l.v.join(', ') + ']'),
    '```',
  ].join('\n');
}
