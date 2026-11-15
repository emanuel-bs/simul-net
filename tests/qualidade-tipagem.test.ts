// Catraca de qualidade da tipagem (NC-17). O projeto não usa ESLint; o tsc já roda em modo estrito, sem variáveis e
// parâmetros não usados, sem retorno implícito e com `override` explícito. Aqui o uso de `any` em src/ não pode crescer:
// quem reduzir o número deve baixar o limite; quem precisar de mais `any` deve justificar e subir o limite no mesmo commit.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const LIMITE_ANY = 244; // medido em 2026-11-15 com este mesmo padrão (ocorrências, não linhas)
const raiz = join(__dirname, '..', 'src');

function arquivos(dir: string): string[] {
  return readdirSync(dir).flatMap((nome) => {
    const p = join(dir, nome);
    return statSync(p).isDirectory() ? arquivos(p) : /\.(ts|tsx)$/.test(nome) ? [p] : [];
  });
}

describe('tipagem', () => {
  it(`o uso explícito de any em src/ não passa de ${LIMITE_ANY} ocorrências`, () => {
    const padrao = /(:\s*any\b|\bas any\b|<any>|\bany\[\])/g;
    let total = 0;
    arquivos(raiz).forEach((f) => (total += (readFileSync(f, 'utf8').match(padrao) ?? []).length));
    expect(total).toBeLessThanOrEqual(LIMITE_ANY);
  });
});
