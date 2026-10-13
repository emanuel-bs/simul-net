import { Link, useParams } from 'react-router-dom';
import { CATEGORIES, findSim, simUrl } from '../sims/registry';
import { NotFound } from './NotFound';

export function SimPage() {
  const { id } = useParams();
  const sim = findSim(id);
  if (!sim) return <NotFound />;
  const category = CATEGORIES.find((c) => c.id === sim.category);

  if (sim.status !== 'available' || !sim.file) {
    return (
      <div className="mx-auto w-full max-w-7xl space-y-4 px-4 py-8">
        <h1 className="text-3xl font-bold">{sim.title}</h1>
        <p className="max-w-4xl text-lg">{sim.summary}</p>
        <p className="rounded-xl border border-dashed border-line bg-surface p-5 text-lg">Este simulador está em preparação e será publicado em breve.</p>
      </div>
    );
  }

  // Bancada de trabalho: faixa fina de contexto e o simulador ocupando toda a altura restante.
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-line bg-surface px-3 py-1.5 text-sm">
        <nav aria-label="Trilha de navegação" className="flex flex-wrap items-center gap-1">
          <Link to="/" className="text-accent underline">
            Início
          </Link>
          <span aria-hidden="true">/</span>
          {category && (
            <>
              <Link to={`/categoria/${category.id}`} className="text-accent underline">
                {category.title}
              </Link>
              <span aria-hidden="true">/</span>
            </>
          )}
          <h1 className="font-semibold">{sim.title}</h1>
        </nav>
        <details className="group relative ml-auto">
          <summary className="cursor-pointer select-none rounded-md border border-line px-2.5 py-1 text-sm font-semibold hover:bg-surface2">Sobre este simulador</summary>
          <div className="absolute right-0 z-20 mt-1 w-[min(34rem,90vw)] rounded-xl border border-line bg-surface p-4 shadow-xl">
            <p className="text-base">{sim.summary}</p>
            {sim.topics.length > 0 && (
              <ul className="mt-2 list-disc space-y-0.5 pl-5 text-sm text-muted">
                {sim.topics.map((t) => (
                  <li key={t}>{t}</li>
                ))}
              </ul>
            )}
          </div>
        </details>
        <a href={simUrl(sim)} className="rounded-md bg-accent px-3 py-1 text-sm font-semibold text-accent-ink hover:opacity-90">
          Abrir em tela cheia<span className="sr-only">: {sim.title}</span>
        </a>
      </div>
      <iframe title={`Simulador: ${sim.title}`} src={simUrl(sim)} className="min-h-0 w-full flex-1 border-0 bg-bg" />
    </div>
  );
}
