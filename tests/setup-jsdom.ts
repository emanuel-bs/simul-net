// O axe-core usa canvas para detectar ícones de fonte, e o jsdom não implementa getContext (a falta só gera
// ruído de "Not implemented" no terminal). Um contexto mínimo silencia o aviso sem alterar nenhuma regra avaliada.
if (typeof HTMLCanvasElement !== 'undefined') {
  const ctx = {
    font: '',
    measureText: () => ({ width: 0 }),
    fillText: () => {},
    clearRect: () => {},
    getImageData: () => ({ data: new Uint8ClampedArray(4) }),
  };
  HTMLCanvasElement.prototype.getContext = (() => ctx) as unknown as HTMLCanvasElement['getContext'];
}
