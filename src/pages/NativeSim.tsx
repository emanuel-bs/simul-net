import { lazy, Suspense, type ComponentType } from 'react';
import { NATIVE } from '../sims/native';

/**
 * Um componente carregado sob demanda por simulador, criado uma única vez e guardado fora da renderização.
 * Criar o `lazy` dentro do componente (useMemo) fazia a navegação direta de um simulador para outro nunca concluir:
 * o roteador troca de página numa transição, a renderização suspende no carregamento do módulo e o React descarta o
 * que foi criado nela, então cada nova tentativa criava outra promessa pendente e a tela ficava no simulador anterior.
 */
const CARREGADOS = new Map<string, ComponentType>();

function componenteDe(id: string): ComponentType | null {
  const pronto = CARREGADOS.get(id);
  if (pronto) return pronto;
  const load = NATIVE[id];
  if (!load) return null;
  const Sim = lazy(async () => {
    const [{ Workbench }, mod] = await Promise.all([import('../sim-core/ui/Workbench'), load()]);
    return { default: () => <Workbench def={mod.default} /> };
  });
  CARREGADOS.set(id, Sim);
  return Sim;
}

/** Carrega o módulo do simulador nativo sob demanda e mostra a bancada. */
export function NativeSim({ id }: { id: string }) {
  const Sim = componenteDe(id);
  if (!Sim) return <p className="p-6 text-lg">Este simulador nativo ainda não está registrado.</p>;
  return (
    <Suspense fallback={<p role="status" className="p-6 text-lg">Carregando o simulador...</p>}>
      <Sim />
    </Suspense>
  );
}
