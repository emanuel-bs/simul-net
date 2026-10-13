import { NavLink, Outlet } from 'react-router-dom';
import { CATEGORIES } from '../sims/registry';
import { useTheme } from '../hooks/useTheme';

const link = ({ isActive }: { isActive: boolean }) =>
  `rounded-lg px-3 py-2 text-base font-semibold ${isActive ? 'bg-accent text-accent-ink' : 'hover:bg-surface2'}`;

const SHORT: Record<string, string> = {
  'camada-de-rede': 'Rede',
  transporte: 'Transporte',
  'protocolos-seguros': 'Protocolos seguros',
};

export function AppLayout() {
  const { theme, toggle } = useTheme();
  return (
    <div className="flex min-h-screen flex-col">
      <a href="#conteudo" className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded-lg focus:bg-accent focus:px-4 focus:py-2 focus:text-accent-ink">
        Pular para o conteúdo
      </a>
      <header className="border-b border-line bg-surface">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-3 px-4 py-3">
          <NavLink to="/" className="mr-4 text-xl font-bold">
            Simul<span className="text-accent">-Net</span>
          </NavLink>
          <nav aria-label="Principal" className="flex flex-wrap gap-1">
            <NavLink to="/" end className={link}>
              Início
            </NavLink>
            {CATEGORIES.map((c) => (
              <NavLink key={c.id} to={`/categoria/${c.id}`} className={link}>
                {SHORT[c.id] ?? c.title}
              </NavLink>
            ))}
          </nav>
          <button
            type="button"
            onClick={toggle}
            aria-pressed={theme === 'dark'}
            className="ml-auto min-h-11 rounded-lg border border-line px-4 text-base font-semibold hover:bg-surface2"
          >
            Tema: {theme === 'dark' ? 'escuro' : 'claro'}
          </button>
        </div>
      </header>
      <main id="conteudo" className="mx-auto w-full max-w-7xl flex-1 px-4 py-8">
        <Outlet />
      </main>
      <footer className="border-t border-line bg-surface">
        <p className="mx-auto max-w-7xl px-4 py-4 text-center text-base text-muted">
          Simulador desenvolvido pelo <strong className="text-ink">Prof. Dr. Laerte Peotta de Melo</strong>. Conteúdo elaborado com apoio de IA generativa, sob revisão do autor. Uso exclusivo para fins de
          ensino e pesquisa. Universidade de Brasília (UnB), Departamento de Engenharia Elétrica. Código aberto (licença MIT).
        </p>
      </footer>
    </div>
  );
}
