import { Link, useParams } from 'react-router-dom';
import { CATEGORIES, findSim, simUrl } from '../sims/registry';
import { NotFound } from './NotFound';

export function SimPage() {
  const { id } = useParams();
  const sim = findSim(id);
  if (!sim) return <NotFound />;
  const category = CATEGORIES.find((c) => c.id === sim.category);
  const available = sim.status === 'available' && sim.file;
  return (
    <div className="space-y-6">
      <nav aria-label="Trilha de navegação" className="text-base">
        <Link to="/" className="text-accent underline">
          Início
        </Link>{' '}
        /{' '}
        {category && (
          <Link to={`/categoria/${category.id}`} className="text-accent underline">
            {category.title}
          </Link>
        )}{' '}
        / {sim.title}
      </nav>
      <h1 className="text-3xl font-bold">{sim.title}</h1>
      <p className="max-w-4xl text-lg">{sim.summary}</p>
      {sim.rfcs.length > 0 && (
        <ul aria-label="Especificações" className="flex flex-wrap gap-2">
          {sim.rfcs.map((r) => (
            <li key={r} className="rounded-full border border-line px-3 py-0.5 font-mono text-sm text-muted">
              {r}
            </li>
          ))}
        </ul>
      )}
      {available ? (
        <>
          {sim.topics.length > 0 && (
            <ul className="list-disc space-y-1 pl-5 text-base text-muted">
              {sim.topics.map((t) => (
                <li key={t}>{t}</li>
              ))}
            </ul>
          )}
          <p>
            <a href={simUrl(sim)} className="inline-flex min-h-11 items-center rounded-lg bg-accent px-5 text-base font-semibold text-accent-ink hover:opacity-90">
              Abrir em tela cheia<span className="sr-only">: {sim.title}</span>
            </a>
          </p>
          <iframe
            title={`Simulador: ${sim.title}`}
            src={simUrl(sim)}
            loading="lazy"
            className="h-[85vh] min-h-[640px] w-full rounded-xl border border-line bg-bg"
          />
        </>
      ) : (
        <p className="rounded-xl border border-dashed border-line bg-surface p-5 text-lg">Este simulador está em preparação e será publicado em breve.</p>
      )}
    </div>
  );
}
