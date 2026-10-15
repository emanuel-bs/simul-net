import { lazy, Suspense, useMemo } from 'react';
import { NATIVE } from '../sims/native';

/** Carrega o módulo do simulador nativo sob demanda e mostra a bancada. */
export function NativeSim({ id }: { id: string }) {
  const Sim = useMemo(() => {
    const load = NATIVE[id];
    if (!load) return null;
    return lazy(async () => {
      const [{ Workbench }, mod] = await Promise.all([import('../sim-core/ui/Workbench'), load()]);
      return { default: () => <Workbench def={mod.default} /> };
    });
  }, [id]);

  if (!Sim) return <p className="p-6 text-lg">Este simulador nativo ainda não está registrado.</p>;
  return (
    <Suspense fallback={<p role="status" className="p-6 text-lg">Carregando o simulador...</p>}>
      <Sim />
    </Suspense>
  );
}
