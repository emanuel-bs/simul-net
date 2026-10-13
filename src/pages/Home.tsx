import { Link } from 'react-router-dom';
import { SimCard } from '../components/SimCard';
import { CATEGORIES, SIMS, simsByCategory } from '../sims/registry';

export function Home() {
  const available = SIMS.filter((s) => s.status === 'available');
  const planned = SIMS.filter((s) => s.status === 'planned');
  return (
    <div className="space-y-12">
      <section aria-labelledby="titulo" className="max-w-4xl space-y-3">
        <h1 id="titulo" className="text-4xl font-bold">
          Simul-Net
        </h1>
        <p className="text-2xl text-muted">Simuladores visuais de redes e protocolos seguros</p>
        <p className="text-lg">
          Projeto acadêmico do curso de Engenharia de Redes de Comunicação da Universidade de Brasília (UnB), sob responsabilidade do Prof. Dr. Laerte Peotta de Melo. Cada simulador mostra, passo a
          passo, como um protocolo funciona, como falha e como se defende, com diagramas de sequência, captura de pacotes, campos das mensagens e explicação do experimento. Tudo roda no navegador,
          sem servidor.
        </p>
      </section>

      <section aria-labelledby="categorias" className="space-y-4">
        <h2 id="categorias" className="text-2xl font-bold">
          Categorias
        </h2>
        <div className="grid gap-4 md:grid-cols-3">
          {CATEGORIES.map((c) => {
            const list = simsByCategory(c.id);
            return (
              <Link key={c.id} to={`/categoria/${c.id}`} className="block rounded-xl border border-line bg-surface p-5 hover:bg-surface2">
                <h3 className="text-xl font-bold">{c.title}</h3>
                <p className="mt-1 text-base">{c.description}</p>
                <p className="mt-2 text-base font-semibold text-accent">
                  {list.filter((s) => s.status === 'available').length} disponível(is) · {list.filter((s) => s.status === 'planned').length} em breve
                </p>
              </Link>
            );
          })}
        </div>
      </section>

      <section aria-labelledby="disponiveis" className="space-y-4">
        <h2 id="disponiveis" className="text-2xl font-bold">
          Simuladores disponíveis
        </h2>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {available.map((s) => (
            <SimCard key={s.id} sim={s} />
          ))}
        </div>
      </section>

      <section aria-labelledby="futuros" className="space-y-4">
        <h2 id="futuros" className="text-2xl font-bold">
          Simuladores futuros
        </h2>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {planned.map((s) => (
            <SimCard key={s.id} sim={s} />
          ))}
        </div>
      </section>
    </div>
  );
}
