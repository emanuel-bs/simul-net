// Gera as páginas dos simuladores de protocolos seguros (SSH e HTTPS) a partir de sources/protocolos.
// Cada página reúne o núcleo comum (core.js) e os módulos de um único protocolo.
// Uso: npm run build:sims
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const src = join(root, 'sources', 'protocolos');
const out = join(root, 'public', 'sims');
const read = (...p) => readFileSync(join(src, ...p), 'utf-8');

const shell = read('shell.html');
const css = read('base.css');
const core = read('core.js');

const PAGES = [
  {
    file: 'ssh-simulator.html',
    modules: ['ssh1', 'ssh2', 'ssh3', 'ssh4', 'ssh5'],
    title: 'Simulador Visual de SSH (Secure Shell)',
    h1: 'Simulador Visual de SSH',
    description:
      'Simulador interativo de SSH: negociação de versão e algoritmos, troca de chaves, known_hosts, autenticação, canais, SFTP e túneis (-L, -R, -D e ProxyJump), com diagrama de sequência, captura de pacotes e nota de hardening.',
    ogTitle: 'Simulador Visual de SSH',
    ogDescription: 'Veja o SSH por dentro: negociação, troca de chaves, known_hosts, autenticação, canais, túneis e hardening.',
  },
  {
    file: 'https-simulator.html',
    // tls6 (comparação HTTP x HTTPS) é carregado antes de tls5, que registra o módulo
    modules: ['tls1', 'tls2', 'tls3', 'tls4', 'tls6', 'tls5'],
    title: 'Simulador Visual de HTTPS e TLS',
    h1: 'Simulador Visual de HTTPS e TLS',
    description:
      'Simulador interativo de HTTPS: handshake TLS 1.3 e 1.2, validação de certificados X.509, retomada e 0-RTT, HSTS e comparação HTTP x HTTPS, com diagrama de sequência, captura de pacotes e nota de hardening.',
    ogTitle: 'Simulador Visual de HTTPS e TLS',
    ogDescription: 'Veja o HTTPS por dentro: handshake TLS, certificados, retomada, HSTS e a comparação entre HTTP e HTTPS.',
  },
  {
    file: 'ftp-simulator.html',
    modules: ['ftp'],
    title: 'Simulador Visual de FTP, FTPS e SFTP',
    h1: 'Simulador Visual de FTP, FTPS e SFTP',
    description:
      'Simulador interativo de transferência de arquivos: FTP com canais de controle e de dados (modos ativo e passivo, NAT e firewall), FTPS explícito e implícito, SFTP sobre SSH e a comparação do que um observador na rede enxerga em cada um.',
    ogTitle: 'Simulador Visual de FTP, FTPS e SFTP',
    ogDescription: 'Veja o FTP, o FTPS e o SFTP por dentro: canais de controle e dados, modos ativo e passivo, TLS e SSH.',
  },
];

for (const p of PAGES) {
  const modules = p.modules.map((m) => read('modules', `${m}.js`)).join('\n');
  const fill = {
    '{{TITLE}}': p.title,
    '{{DESCRIPTION}}': p.description,
    '{{FILE}}': p.file,
    '{{OG_TITLE}}': p.ogTitle,
    '{{OG_DESCRIPTION}}': p.ogDescription,
    '{{H1}}': p.h1,
  };
  let html = shell;
  for (const [k, v] of Object.entries(fill)) html = html.split(k).join(v);
  html = html.replace('/*CSS*/\n', () => css).replace('/*CORE*/\n', () => core).replace('/*MODULES*/\n', () => modules);
  writeFileSync(join(out, p.file), html, 'utf-8');
  console.log(`${p.file}: ${html.length} caracteres`);
}
