import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  /** Nome do simulador, para a mensagem. */
  titulo: string;
  children: ReactNode;
}

interface Estado {
  erro: Error | null;
}

/**
 * Contém uma falha de execução na bancada de um simulador: sem isto, uma exceção em qualquer componente desmonta a
 * aplicação inteira e a tela fica em branco. Aqui o restante do site (cabeçalho, menu, outros simuladores) continua
 * funcionando, e o aluno recebe uma mensagem e a opção de tentar de novo.
 */
export class ErroBancada extends Component<Props, Estado> {
  state: Estado = { erro: null };

  static getDerivedStateFromError(erro: Error): Estado {
    return { erro };
  }

  componentDidCatch(erro: Error, info: ErrorInfo) {
    console.error(`Falha no simulador ${this.props.titulo}:`, erro, info.componentStack);
  }

  render() {
    if (!this.state.erro) return this.props.children;
    return (
      <div role="alert" className="mx-auto max-w-3xl space-y-3 p-6">
        <h2 className="text-2xl font-bold">Não foi possível exibir este simulador</h2>
        <p className="text-lg">Ocorreu uma falha inesperada em {this.props.titulo}. O restante do site continua disponível.</p>
        <button type="button" onClick={() => this.setState({ erro: null })} className="min-h-9 rounded-lg border border-line px-4 text-base font-semibold hover:bg-surface2">
          Tentar novamente
        </button>
      </div>
    );
  }
}
