import { Link } from 'react-router-dom';
import type { SimMeta } from '../sims/registry';

export function SimCard({ sim, headingLevel = 3 }: { sim: SimMeta; headingLevel?: 2 | 3 }) {
  const Heading = `h${headingLevel}` as 'h2' | 'h3';
  const available = sim.status === 'available';
  return (
    <article className={`flex flex-col rounded-xl border bg-surface p-5 ${available ? 'border-line' : 'border-dashed border-line'}`}>
      <Heading className="text-xl font-bold">{sim.title}</Heading>
      <p className={`mt-1 inline-block self-start rounded-md px-2 py-0.5 text-base font-semibold ${available ? 'bg-ok/15 text-ok' : 'bg-surface2 text-muted'}`}>
        {available ? 'Disponível' : 'Em breve'}
      </p>
      <p className="mt-2 flex-1 text-base">{sim.summary}</p>
      {sim.rfcs.length > 0 && (
        <ul aria-label="Especificações" className="mt-3 flex flex-wrap gap-2">
          {sim.rfcs.map((r) => (
            <li key={r} className="rounded-full border border-line px-2.5 py-0.5 font-mono text-sm text-muted">
              {r}
            </li>
          ))}
        </ul>
      )}
      {available && (
        <Link to={`/sim/${sim.id}`} className="mt-4 inline-flex min-h-11 items-center justify-center rounded-lg bg-accent px-5 text-base font-semibold text-accent-ink hover:opacity-90">
          Abrir simulador<span className="sr-only">: {sim.title}</span>
        </Link>
      )}
    </article>
  );
}
