import { Link } from 'react-router-dom';
import { SimCard } from '../components/SimCard';
import { CATEGORIES, SIMS, simsByCategory } from '../sims/registry';

// RFCs distintas citadas pelos simuladores disponíveis, arredondadas para baixo na dezena ("mais de 90").
function rfcsCitadas(): number {
  const nums = new Set<string>();
  for (const s of SIMS) if (s.status === 'available') for (const r of s.rfcs) if (/^RFC \d+$/.test(r)) nums.add(r);
  return Math.floor(nums.size / 10) * 10;
}

export function Home() {
  const available = SIMS.filter((s) => s.status === 'available');
  const totalRfcs = rfcsCitadas();
  const planned = SIMS.filter((s) => s.status === 'planned');
  return (
    <div className="space-y-12">
      <section aria-labelledby="titulo" className="max-w-5xl space-y-3">
        <div className="flex flex-col items-start gap-6 md:flex-row md:items-center md:gap-8">
          <img src={`${import.meta.env.BASE_URL}favicon.svg`} alt="Logotipo do Simul-Net: três nós de rede ligados por enlaces" width={160} height={160} className="h-28 w-28 shrink-0 md:h-40 md:w-40" />
          <div className="max-w-4xl space-y-3">
            <h1 id="titulo" className="text-4xl font-bold">
              Simul-Net
            </h1>
            <p className="text-2xl text-muted">Simuladores visuais de redes e protocolos seguros</p>
            <p className="text-lg">
              Projeto acadêmico do curso de Engenharia de Redes de Comunicação da Universidade de Brasília (UnB), sob responsabilidade do Prof. Dr. Laerte Peotta de Melo. Cada simulador mostra,
              passo a passo, como um protocolo funciona, como falha e como se defende, com diagramas de sequência, captura de pacotes, campos das mensagens e explicação do experimento. Tudo roda no
              navegador, sem servidor.
            </p>
          </div>
        </div>
        <aside aria-labelledby="rfcs-vigentes" className="mt-4 rounded-xl border-l-4 border-accent bg-surface p-5">
          <h2 id="rfcs-vigentes" className="text-xl font-bold">
            Baseados nas RFCs vigentes e com documentação própria
          </h2>
          <p className="mt-1 text-lg">
            Todos os simuladores são desenvolvidos a partir das RFCs e dos padrões mais recentes, conferidos no texto oficial do{' '}
            <a href="https://www.rfc-editor.org" target="_blank" rel="noopener noreferrer" className="font-semibold text-accent underline">
              RFC Editor
            </a>
            , com atenção às versões substituídas ou atualizadas. No total, o projeto referencia <strong>mais de {totalRfcs} RFCs</strong>.
          </p>
          <p className="mt-3 text-lg">
            Cada simulador tem ainda uma documentação própria, parte essencial do estudo. Ela apresenta os <strong>cenários</strong> (o funcionamento normal, as falhas e as defesas), as{' '}
            <strong>topologias</strong> de rede usadas em cada um e os <strong>diagramas de sequência</strong>, que mostram a ordem exata das mensagens trocadas. Com esse material, o estudante
            relaciona o que vê na simulação com o que a especificação determina e chega a um entendimento aprofundado dos protocolos estudados.
            Use o link &quot;Documentação&quot; no cartão de cada simulador.
          </p>
        </aside>
      </section>

      <section aria-labelledby="categorias" className="space-y-4">
        <h2 id="categorias" className="text-2xl font-bold">
          Categorias
        </h2>
        <div className="grid gap-4 md:grid-cols-3">
          {CATEGORIES.map((c) => {
            const list = simsByCategory(c.id);
            const ready = list.filter((s) => s.status === 'available').length;
            const planned = list.filter((s) => s.status === 'planned').length;
            return (
              <Link key={c.id} to={`/categoria/${c.id}`} className="block rounded-xl border border-line bg-surface p-5 hover:bg-surface2">
                <h3 className="text-xl font-bold">{c.title}</h3>
                <p className="mt-1 text-base">{c.description}</p>
                <p className="mt-2 text-base font-semibold text-accent">
                  {ready} {ready === 1 ? 'disponível' : 'disponíveis'}
                  {planned > 0 && ` · ${planned} em breve`}
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
