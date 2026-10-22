// Gera as páginas da wiki (Markdown) a partir do registro, dos módulos nativos e das páginas legadas.
// Uso: npm run wiki -- <pasta-de-saida>   (a pasta de saída recebe os .md; não é versionada aqui)
// Os nativos são lidos pelo Vite (módulos TypeScript); os legados são executados no jsdom e o texto
// de cada cenário é capturado da aba Cenário. Edições manuais nas páginas geradas são sobrescritas.
import { createServer } from 'vite';
import { JSDOM } from 'jsdom';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// --docs: gera os documentos por simulador (docs/simuladores) em vez das páginas da wiki.
const DOCS = process.argv.includes('--docs');
const outArg = process.argv.slice(2).find((a) => !a.startsWith('--'));
if (!outArg) { console.error('Uso: npm run wiki -- <pasta-de-saida> [--docs]'); process.exit(1); }
const out = path.resolve(outArg);
fs.mkdirSync(out, { recursive: true });

const server = await createServer({
  root,
  configFile: false,
  server: { middlewareMode: true },
  appType: 'custom',
  logLevel: 'error',
  define: { 'import.meta.env.BASE_URL': JSON.stringify('/') },
});

const ent = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'", '&nbsp;': ' ' };

/** HTML restrito dos textos autorais para Markdown. */
function md(html = '') {
  let s = String(html);
  s = s.replace(/<table[^>]*>([\s\S]*?)<\/table>/gi, (_, t) => {
    const rows = [...t.matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/gi)].map((r) =>
      [...r[1].matchAll(/<t[hd][^>]*>([\s\S]*?)<\/t[hd]>/gi)].map((c) => inline(c[1]).replace(/\|/g, '\\|')),
    );
    if (!rows.length) return '';
    const head = rows[0];
    const lines = ['| ' + head.join(' | ') + ' |', '| ' + head.map(() => '---').join(' | ') + ' |'];
    for (const r of rows.slice(1)) lines.push('| ' + r.join(' | ') + ' |');
    return '\n\n' + lines.join('\n') + '\n\n';
  });
  s = s.replace(/<h3[^>]*>([\s\S]*?)<\/h3>/gi, (_, t) => `\n\n#### ${inline(t)}\n\n`);
  s = s.replace(/<ol[^>]*>([\s\S]*?)<\/ol>/gi, (_, t) => {
    let n = 0;
    return '\n\n' + [...t.matchAll(/<li[^>]*>([\s\S]*?)<\/li>/gi)].map((m) => `${++n}. ${inline(m[1])}`).join('\n') + '\n\n';
  });
  s = s.replace(/<ul[^>]*>([\s\S]*?)<\/ul>/gi, (_, t) =>
    '\n\n' + [...t.matchAll(/<li[^>]*>([\s\S]*?)<\/li>/gi)].map((m) => `- ${inline(m[1])}`).join('\n') + '\n\n');
  s = s.replace(/<p[^>]*>([\s\S]*?)<\/p>/gi, (_, t) => `\n\n${inline(t)}\n\n`);
  s = inline(s);
  return s.replace(/\n{3,}/g, '\n\n').trim();
}

function inline(html = '') {
  let s = String(html);
  s = s.replace(/<br\s*\/?>/gi, '  \n');
  s = s.replace(/<(b|strong)[^>]*>([\s\S]*?)<\/\1>/gi, '**$2**');
  s = s.replace(/<(i|em)[^>]*>([\s\S]*?)<\/\1>/gi, '*$2*');
  s = s.replace(/<code[^>]*>([\s\S]*?)<\/code>/gi, '`$1`');
  s = s.replace(/<[^>]+>/g, '');
  s = s.replace(/&(amp|lt|gt|quot|#39|nbsp);/g, (m) => ent[m]);
  return s.trim();
}

const q = (v) => (typeof v === 'boolean' ? (v ? 'sim' : 'não') : String(v));

const { SIMS, CATEGORIES } = await server.ssrLoadModule('/src/sims/registry.ts');
const { NATIVE } = await server.ssrLoadModule('/src/sims/native.ts');

const CRED = 'Simulador desenvolvido pelo Prof. Dr. Laerte Peotta de Melo. Conteúdo elaborado com apoio de IA generativa, sob revisão do autor. Uso exclusivo para fins de ensino e pesquisa.';
// Na wiki, o crédito vem do _Footer.md (não repetir no corpo); nos documentos, cada arquivo leva o seu.
const footer = DOCS ? `\n\n---\n\n*${CRED}*\n` : '\n';
const pageName = (id) => (DOCS ? id : `simulador-${id}`);
const pageRef = (id) => (DOCS ? `${id}.md` : pageName(id));
const catTitle = Object.fromEntries(CATEGORIES.map((c) => [c.id, c.title]));
const files = {};

const mmId = (k) => 'n_' + String(k).replace(/[^A-Za-z0-9_]/g, '_');
const mmText = (s) => String(s).replace(/"/g, '#quot;');

/** Converte a topologia do simulador (nós e enlaces) em um fluxograma Mermaid. As posições não são preservadas. */
function toMermaid(topo) {
  const L = ['flowchart LR'];
  for (const n of topo.nodes) {
    const t = `"${mmText(n.label)}${n.sub ? '<br/>' + mmText(n.sub) : ''}"`;
    const id = mmId(n.key);
    L.push('  ' + id + ({ switch: `{{${t}}}`, router: `(${t})`, cloud: `([${t}])` }[n.kind] ?? `[${t}]`));
  }
  const attackers = topo.nodes.filter((n) => n.kind === 'attacker').map((n) => mmId(n.key));
  for (const [a, b, o] of topo.links) {
    const lab = o?.label ? `"${mmText(o.label)}"` : o?.down ? '"caído"' : '';
    const dashed = o?.dashed || o?.down;
    L.push('  ' + mmId(a) + (dashed ? (lab ? ` -. ${lab} .- ` : ' -.- ') : (lab ? ` -- ${lab} --- ` : ' --- ')) + mmId(b));
  }
  if (attackers.length) {
    L.push('  classDef atacante fill:#fde2e2,stroke:#b42318,color:#111');
    L.push('  class ' + attackers.join(',') + ' atacante');
  }
  return L.join('\n');
}

const mmMsg = (s) => String(s ?? '').replace(/<[^>]*>/g, '').replace(/;/g, ',').replace(/#/g, 'nº ').replace(/\s+/g, ' ').trim().slice(0, 90);

/** Diagrama de sequência Mermaid de um cenário, a partir das mensagens do trace (mesma fonte do diagrama da bancada). */
function sequenceDiagram(def, s, base) {
  const tr = def.build({ ...base, ...(s.set ?? {}) }, s.sub);
  const L = ['sequenceDiagram'];
  for (const c of tr.cols) L.push(`  participant ${mmId(c.key)} as ${mmMsg(c.label)}${c.sub ? '<br/>' + mmMsg(c.sub) : ''}`);
  const msgs = [...tr.msgs].sort((a, b) => a.tSend - b.tSend || a.id - b.id);
  const phases = [...tr.phases].sort((a, b) => a.t - b.t);
  const first = mmId(tr.cols[0].key);
  const last = mmId(tr.cols[tr.cols.length - 1].key);
  let p = 0;
  for (const m of msgs) {
    while (p < phases.length && phases[p].t <= m.tSend + 1e-9) {
      L.push(`  Note over ${first},${last}: ${mmMsg(phases[p].label)}`);
      p++;
    }
    const text = mmMsg(m.label ?? m.info ?? m.proto) || 'mensagem';
    const arrow = m.lost ? '-x' : '->>';
    L.push(`  ${mmId(m.from)} ${arrow} ${mmId(m.to)}: ${m.enc ? '[cifrado] ' : ''}${text}`);
  }
  return '```mermaid\n' + L.join('\n') + '\n```';
}

/** Um diagrama por topologia distinta: percorre os cenários de cada modo e agrupa os que compartilham o mesmo desenho. */
function topologySection(def) {
  const L = ['## Topologia\n', 'Diagramas gerados a partir da mesma definição de topologia que a bancada usa. O Mermaid reorganiza o layout automaticamente, então as posições diferem do simulador.\n'];
  const base = Object.fromEntries(def.controls.map((c) => [c.id, c.def]));
  let any = false;
  for (const sub of def.subs) {
    const all = def.scenarios.filter((x) => x.sub === sub.key);
    const found = [];
    for (const s of all) {
      try {
        const topo = def.topology(sub.key, def.build({ ...base, ...(s.set ?? {}) }, sub.key));
        const nodes = new Set(topo.nodes.map((n) => [n.key, n.label, n.sub, n.kind].join('|')));
        const links = new Set(topo.links.map(([a, b, o]) => [a, b, o?.label, o?.dashed, o?.down].join('|')));
        found.push({ mm: toMermaid(topo), nodes, links, labels: [s.label], size: nodes.size + links.size });
      } catch { /* cenário sem topologia gerável */ }
    }
    // Une as variantes que são subconjunto de outra (por exemplo, cenários em que só um dos hosts participa).
    const kept = [];
    let reduced = false;
    for (const v of found.sort((a, b) => b.size - a.size)) {
      const host = kept.find((k) => [...v.nodes].every((n) => k.nodes.has(n)) && [...v.links].every((l) => k.links.has(l)));
      if (host) { host.labels.push(...v.labels); if (v.size < host.size) reduced = true; } else kept.push(v);
    }
    if (!kept.length) continue;
    any = true;
    L.push(`### ${sub.label}\n`);
    for (const v of kept) {
      L.push(kept.length > 1 ? `**${v.labels.length === all.length ? 'Todos os cenários' : 'Cenários: ' + v.labels.join('; ')}**\n` : '');
      L.push('```mermaid\n' + v.mm + '\n```\n');
    }
    if (reduced) L.push('*Em alguns cenários, parte dos elementos do desenho não existe ou não participa da troca (por exemplo, o segundo host ou o segundo servidor).*\n');
  }
  return any ? L : [];
}

function nativePage(sim, def) {
  const L = [];
  L.push(`# ${sim.title}\n`);
  L.push(`${sim.summary}\n`);
  L.push(`- **Categoria:** ${catTitle[sim.category]}`);
  L.push(`- **Motor:** nativo (TypeScript puro, apresentado pela bancada genérica)`);
  L.push(`- **Código-fonte:** \`src/sims/${sim.id === 'http-versoes' ? 'http-versoes' : sim.id}/\``);
  L.push(`- **RFCs e padrões:** ${def.rfcs.length ? def.rfcs.map(([n, t]) => `RFC ${n} (${t})`).join(', ') : sim.rfcs.join(', ')}`);
  if (sim.topics?.length) L.push(`- **Tópicos:** ${sim.topics.join('; ')}`);
  L.push('');

  L.push('## Modos\n');
  L.push('| Modo | Cenário inicial |', '| --- | --- |');
  const byId = Object.fromEntries(def.scenarios.map((s) => [s.id, s]));
  for (const s of def.subs) L.push(`| ${s.label} | ${byId[s.default]?.label ?? s.default} |`);
  L.push('');

  if (def.topology) L.push(...topologySection(def));

  L.push('## Abas da bancada\n');
  const fixed = ['Cenário', 'Captura', 'Mensagem'];
  const own = (def.tabs ?? []).map((t) => {
    const only = t.subs?.length ? ` (modos: ${t.subs.map((k) => def.subs.find((x) => x.key === k)?.label ?? k).join('; ')})` : '';
    return `${t.label}${only}`;
  });
  L.push(`Cenário, Captura, Mensagem${own.length ? ', ' + own.join(', ') : ''}, Experimento, Referência e Log.\n`);

  L.push('## Configurações (campos do painel)\n');
  const subLabel = (k) => def.subs.find((x) => x.key === k)?.label ?? k;
  const groups = [...new Set(def.controls.map((c) => c.grp))];
  for (const g of groups) {
    L.push(`### ${g}\n`);
    for (const c of def.controls.filter((x) => x.grp === g)) {
      const opts = c.type === 'check' ? 'caixa de seleção' : (c.opts ?? []).map(([v, l]) => l).join('; ');
      const modos = c.subs?.length ? c.subs.map(subLabel).join('; ') : 'todos';
      L.push(`- **${c.label}**${c.adv ? ' (ajuste avançado)' : ''}. Valores: ${opts}. Padrão: ${c.type === 'check' ? q(c.def) : (c.opts?.find(([v]) => v === c.def)?.[1] ?? q(c.def))}. Modos: ${modos}.`);
      if (c.help) {
        if (c.help.s) L.push(`  - ${c.help.s}`);
        for (const p of c.help.p) L.push(`  - ${md(p).replace(/\n+/g, ' ')}`);
      }
    }
    L.push('');
  }

  L.push('## Cenários\n');
  for (const sub of def.subs) {
    L.push(`### Modo: ${sub.label}\n`);
    const sc = def.scenarios.filter((s) => s.sub === sub.key);
    const groups = [...new Set(sc.map((s) => s.g))];
    for (const g of groups) {
      L.push(`#### ${g}\n`);
      if (def.groupDoc[g]) L.push(`${md(def.groupDoc[g])}\n`);
      for (const s of sc.filter((x) => x.g === g)) {
        const d = def.scenDoc[s.id];
        L.push(`##### ${s.label}\n`);
        if (d?.short) L.push(`*${md(d.short)}*\n`);
        const set = s.set ? Object.entries(s.set).map(([k, v]) => `${def.controls.find((c) => c.id === k)?.label ?? k} = ${q(v)}`).join('; ') : '';
        if (set) L.push(`**Configuração aplicada:** ${set}\n`);
        if (s.what) L.push(`${md(s.what)}\n`);
        if (d?.concept) L.push(`**Conceito.** ${md(d.concept)}\n`);
        if (d?.observe?.length) { L.push('**O que observar**\n'); for (const o of d.observe) L.push(`- ${md(o)}`); L.push(''); }
        try { L.push(`**Diagrama de sequência**\n`, sequenceDiagram(def, s, Object.fromEntries(def.controls.map((c) => [c.id, c.def]))), ''); } catch { /* sem diagrama */ }
        if (d?.msgs?.length) {
          L.push(`**${d.msgsTitle ?? 'Mensagens'}**\n`);
          L.push('| Mensagem | Significado | Origem |', '| --- | --- | --- |');
          for (const m of d.msgs) L.push(`| ${m.map((c) => md(c).replace(/\|/g, '\\|')).join(' | ')} |`);
          L.push('');
        }
        if (d?.why) L.push(`**Por que importa.** ${md(d.why)}\n`);
      }
    }
  }

  L.push('## Referência\n');
  L.push(md(def.reference).replace(/^#### /gm, '### ') + '\n');
  return L.join('\n') + footer;
}

/**
 * Particularidades das páginas legadas. O TCP e UDP tem cinco modos escolhidos por botões (protocolo e
 * aplicação) e uma tabela de captura que o botão Passo revela; hosts nomeia os endereços da captura
 * (CLI e SRV nas constantes da página).
 */
const LEGACY = {
  'tcp-udp-simulator.html': {
    capture: true,
    hosts: { '192.168.10.10': 'Cliente', '203.0.113.80': 'Servidor' },
    modes: [
      { label: 'TCP: conexão', proto: 'tcp', sub: 0 },
      { label: 'TCP: download de arquivo', proto: 'tcp', sub: 1 },
      { label: 'UDP: fluxo de datagramas e DNS', proto: 'udp', sub: 0 },
      { label: 'UDP: vídeo em streaming', proto: 'udp', sub: 2 },
      { label: 'Comparação TCP x UDP', proto: 'cmp', sub: 0 },
    ],
  },
};

/** Diagrama de sequência a partir da tabela de captura: [nº, tempo, origem, destino, protocolo, tamanho, informação]. */
function captureSequence(rows, hosts = {}) {
  const ips = [];
  for (const r of rows) for (const ip of [r[2], r[3]]) if (!ips.includes(ip)) ips.push(ip);
  const id = (ip) => 'h_' + ip.replace(/[^A-Za-z0-9]/g, '_');
  const L = ['sequenceDiagram'];
  for (const ip of ips) L.push(`  participant ${id(ip)} as ${hosts[ip] ? hosts[ip] + '<br/>' : ''}${ip}`);
  for (const r of rows) L.push(`  ${id(r[2])} ${/perdid/i.test(r[6]) ? '-x' : '->>'} ${id(r[3])}: ${mmMsg(r[4] + ' ' + r[6])}`);
  return '```mermaid\n' + L.join('\n') + '\n```';
}

/** Executa uma página legada no jsdom e captura controles, ajuda, abas, cenários e referência. */
function extractLegacy(file) {
  const html = fs.readFileSync(path.join(root, 'public', 'sims', file), 'utf8');
  const stub = new Proxy(function () {}, { get: (t, k) => (k === 'measureText' ? () => ({ width: 0 }) : stub), set: () => true, apply: () => stub });
  const dom = new JSDOM(html, {
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    url: 'http://localhost/' + file,
    beforeParse(w) {
      w.HTMLCanvasElement.prototype.getContext = () => stub;
      w.matchMedia = () => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} });
      w.scrollTo = () => {};
      w.Element.prototype.scrollIntoView = () => {};
    },
  });
  const w = dom.window;
  const d = w.document;
  const r = { scenarios: [], groupDoc: {} };
  // Controles lidos antes de percorrer os cenários (cada cenário altera os valores). A ajuda vem do
  // balão que a própria página abre ao focar o campo.
  r.controls = [...d.querySelectorAll('label')].filter((l) => l.querySelector('select,input')).map((l) => {
    const ctl = l.querySelector('select,input');
    const c = l.cloneNode(true);
    c.querySelectorAll('select,input,option,.info').forEach((n) => n.remove());
    ctl.dispatchEvent(new w.Event('focus'));
    const box = d.getElementById('fieldHelp') ?? d.querySelector('.field-help');
    const help = box && box.style.display !== 'none' && box.innerHTML
      ? { t: box.querySelector('.fh-title')?.textContent.trim(), p: [...box.querySelectorAll('p')].map((p) => p.innerHTML) }
      : undefined;
    ctl.dispatchEvent(new w.Event('blur'));
    return {
      id: ctl.id,
      label: c.textContent.replace(/\s+/g, ' ').trim(),
      check: ctl.tagName === 'INPUT',
      opts: ctl.tagName === 'SELECT' ? [...ctl.options].map((o) => o.textContent.trim()) : [],
      def: ctl.tagName === 'SELECT' ? ctl.selectedOptions[0]?.textContent.trim() : (ctl.checked ? 'sim' : 'não'),
      help,
    };
  });
  const cfg = LEGACY[file] ?? {};
  const capRows = () => [...d.querySelectorAll('#capBody tr')].filter((tr) => !tr.classList.contains('placeholder-row'));
  for (const mode of cfg.modes ?? [{ label: '' }]) {
    if (mode.proto) {
      d.querySelector(`#protoSeg [data-proto="${mode.proto}"]`).click();
      const subs = [...d.querySelectorAll('#subSeg button')];
      if (subs[mode.sub]) subs[mode.sub].click();
    }
    let grp = '';
    for (const el of [...d.getElementById('scenRow').children]) {
      if (el.classList.contains('scen-group')) { grp = el.textContent.trim(); continue; }
      if (el.tagName !== 'BUTTON') continue;
      el.click();
      const body = d.getElementById('scenBody');
      const main = body.querySelector('.sc-main');
      let capture;
      if (cfg.capture) {
        // Avança passo a passo até a captura parar de crescer (o motor calcula tudo de uma vez; o passo só revela).
        let stable = 0, prev = -1, i = 0;
        while (stable < 15 && i++ < 5000) {
          const b = d.getElementById('btnStep');
          if (!b || b.disabled) break;
          b.click();
          const n = capRows().length;
          stable = n === prev ? stable + 1 : 0;
          prev = n;
        }
        capture = capRows().map((tr) => [...tr.children].map((td) => td.textContent.trim()));
      }
      r.scenarios.push({
        mode: mode.label,
        group: grp,
        label: el.textContent.trim(),
        title: main?.querySelector('.sc-title')?.textContent.trim(),
        cmd: main?.querySelector('.sc-cmd')?.textContent.trim(),
        html: [...(main?.children ?? [])].filter((c) => !c.matches('.sc-kicker, .sc-title, .sc-cmd')).map((c) => c.outerHTML).join(''),
        capture,
      });
      for (const h of body.querySelectorAll('.sc-side h4')) {
        const g = h.nextElementSibling;
        if (g?.classList.contains('sc-gdoc')) r.groupDoc[h.textContent.trim()] = g.innerHTML;
      }
    }
  }
  r.tabs = [...d.querySelectorAll('.tab-btn')].map((b) => b.textContent.trim());
  r.ref = d.querySelector('[data-tab-content="ref"] .tab-scroll')?.innerHTML ?? '';
  w.close();
  return r;
}

function legacyPage(sim) {
  const x = extractLegacy(sim.file);
  const L = [`# ${sim.title}\n`, `${sim.summary}\n`];
  L.push(`- **Categoria:** ${catTitle[sim.category]}`);
  L.push(`- **Motor:** legado (página autônoma em \`public/sims/${sim.file}\`, incorporada por \`iframe\`)`);
  L.push(`- **RFCs e padrões:** ${sim.rfcs.join(', ')}`);
  if (sim.topics?.length) L.push(`- **Tópicos:** ${sim.topics.join('; ')}`);
  L.push('', '## Abas\n', `${x.tabs.join(', ')}.\n`);

  L.push('## Configurações (campos do painel)\n');
  for (const c of x.controls) {
    const opts = c.check ? 'caixa de seleção' : c.opts.join('; ');
    L.push(`- **${c.label.replace(/ⓘ/g, '').trim()}**. Valores: ${opts}. Padrão: ${c.def}.`);
    for (const p of c.help?.p ?? []) L.push(`  - ${md(p).replace(/\n+/g, ' ')}`);
  }
  L.push('', '## Cenários\n');
  let lastMode = null, last = '';
  const multi = x.scenarios.some((s) => s.mode);
  const H = multi ? '#' : '';
  for (const s of x.scenarios) {
    if (multi && s.mode !== lastMode) { lastMode = s.mode; last = ''; L.push(`### Modo: ${s.mode}\n`); }
    if (s.group !== last) {
      last = s.group;
      L.push(`###${H} ${s.group}\n`);
      if (x.groupDoc[s.group]) L.push(`${md(x.groupDoc[s.group])}\n`);
    }
    L.push(`####${H} ${s.title ?? s.label}\n`);
    if (s.cmd) L.push(`${md(s.cmd)}\n`);
    L.push(`${md(s.html.replace(/<h4>([\s\S]*?)<\/h4>/gi, '<p><b>$1.</b></p>'))}\n`);
    if (s.capture?.length) L.push('**Diagrama de sequência** (a partir da aba Captura)\n', captureSequence(s.capture, LEGACY[sim.file]?.hosts), '');
  }
  L.push('## Referência\n', md(x.ref).replace(/^#### /gm, '### ') + '\n');
  return L.join('\n') + footer;
}

const avail = SIMS.filter((s) => s.status === 'available');
const planned = SIMS.filter((s) => s.status === 'planned');
let nNative = 0, nScen = 0;

for (const sim of avail) {
  if (sim.engine === 'nativo') {
    const def = (await NATIVE[sim.id]()).default;
    files[`${pageName(sim.id)}.md`] = nativePage(sim, def);
    nNative++; nScen += def.scenarios.length;
  } else {
    files[`${pageName(sim.id)}.md`] = legacyPage(sim);
  }
}

// Índice de simuladores
{
  const L = ['# Simuladores\n', 'Lista dos simuladores do Simul-Net por categoria. A fonte única é `src/sims/registry.ts`.\n'];
  for (const c of CATEGORIES) {
    L.push(`## ${c.title}\n`, `${c.description}\n`);
    L.push('| Simulador | Motor | Situação | RFCs e padrões |', '| --- | --- | --- | --- |');
    for (const s of SIMS.filter((x) => x.category === c.id)) {
      const link = s.status === 'available' ? `[${s.title}](${pageRef(s.id)})` : s.title;
      L.push(`| ${link} | ${s.engine ?? '-'} | ${s.status === 'available' ? 'disponível' : 'planejado'} | ${s.rfcs.join(', ')} |`);
    }
    L.push('');
  }
  files['simuladores.md'] = L.join('\n') + footer;
}

// Arquitetura (cópia do docs/arquitetura.md)
{
  const a = fs.readFileSync(path.join(root, 'docs', 'arquitetura.md'), 'utf8');
  files['arquitetura.md'] = a.trimEnd() + footer;
}

// Home e barra lateral
{
  const L = ['# Simul-Net\n',
    'Simuladores visuais de redes e protocolos seguros, desenvolvidos para ensino e pesquisa na Universidade de Brasília (Departamento de Engenharia Elétrica). Projeto irmão: CryptoNet Lab.\n',
    '- **Site:** https://peotta.github.io/Simul-Net/',
    '- **Código:** https://github.com/peotta/Simul-Net\n',
    '## Como usar esta wiki\n',
    '- [Arquitetura](arquitetura): estrutura de pastas, registro, contrato do motor de simulação, testes e publicação.',
    '- [Simuladores](simuladores): índice por categoria, com o motor e as RFCs de cada um.',
    '- [Contribuindo](contribuindo): como criar ou alterar um simulador e como esta wiki é gerada.\n',
    '## Simuladores disponíveis\n'];
  for (const s of avail) L.push(`- [${s.title}](${pageName(s.id)}) (${s.engine})`);
  L.push('', `São ${avail.length} simuladores disponíveis (${nNative} nativos, com ${nScen} cenários documentados) e ${planned.length} planejados.`);
  files['Home.md'] = L.join('\n') + footer;

  const S = ['**[Simul-Net](Home)**\n', '- [Arquitetura](arquitetura)', '- [Simuladores](simuladores)', '- [Contribuindo](contribuindo)\n'];
  for (const c of CATEGORIES) {
    const items = avail.filter((s) => s.category === c.id);
    if (!items.length) continue;
    S.push(`**${c.title}**\n`);
    for (const s of items) S.push(`- [${s.title}](${pageName(s.id)})`);
    S.push('');
  }
  files['_Sidebar.md'] = S.join('\n');
  files['_Footer.md'] = CRED + '\n';
}

// Contribuindo
files['contribuindo.md'] = `# Contribuindo\n
## Criar um simulador novo

1. Crie a pasta \`src/sims/<id>/\` em kebab-case com \`engine.ts\`, \`protocol.ts\`, \`topology.ts\` (opcional) e \`content/\` (controles, cenários, ajuda, abas, explicação e referência).
2. Registre o módulo em \`src/sims/native.ts\` e acrescente a entrada em \`src/sims/registry.ts\` (fonte única).
3. Siga o padrão visual e didático: abas Cenário, Captura, Mensagem, abas próprias, Experimento, Referência e Log; ajuda em cada campo; uma informação, um lugar.
4. Inclua o rodapé de crédito padrão e respeite a acessibilidade (imagens com \`alt\`, foco visível, contraste AA, \`prefers-reduced-motion\`).
5. Atualize as impressões digitais apenas quando a mudança de comportamento for intencional: \`UPDATE_GOLDEN=1 npx vitest run tests/sim-core/golden.test.ts\`.
6. Antes de entregar, rode \`npm run typecheck\` e \`npm test\`.

## Regras de texto

- Português do Brasil, tom acadêmico e impessoal.
- Sem travessão longo nem meia-risca (há teste automático).
- Conteúdo baseado nas RFCs; nunca inventar comandos, parâmetros ou saídas; explicitar as limitações do simulador.
- Cenários de ataque no nível defensivo (aviso, efeito e defesa), sem passo a passo ofensivo.

## Como esta wiki é gerada

As páginas dos simuladores nativos são geradas a partir dos próprios módulos (\`controls\`, \`scenarios\`, \`scenDoc\`, \`help\` e \`reference\`), e as dos legados, a partir da execução da página (campos, ajuda, cenários e aba Referência). Assim a wiki não diverge do código.

1. Altere o conteúdo do módulo ou da página legada.
2. Gere as páginas: \`npm run wiki -- <pasta-de-saida>\`.
3. Clone \`Simul-Net.wiki.git\`, copie os \`.md\` gerados, faça o commit e o push.

Edições manuais diretas nas páginas geradas são sobrescritas na próxima geração. As páginas \`Home\`, \`arquitetura\` (cópia de \`docs/arquitetura.md\`), \`simuladores\`, \`contribuindo\`, \`_Sidebar\` e \`_Footer\` também são geradas.
` + footer;

if (DOCS) {
  // Só os documentos dos simuladores e o índice; a arquitetura e as demais páginas da wiki não entram.
  const keep = new Set(avail.map((x) => `${pageName(x.id)}.md`));
  for (const k of Object.keys(files)) if (!keep.has(k) && k !== 'simuladores.md') delete files[k];
  files['README.md'] = files['simuladores.md'].replace('# Simuladores\n', '# Documentação dos simuladores\n');
  delete files['simuladores.md'];
}

/**
 * Transforma cada citação de RFC e de BCP em link para o rfc-editor.org (mesmo endereço dos chips do cabeçalho).
 * Intervalos como "RFC 4033 a 4035" têm o segundo número linkado também. Blocos de código (inclusive os diagramas
 * Mermaid), código em linha e links já existentes não são tocados. IEEE e ISO ficam em texto: não têm endereço gratuito estável.
 */
const rfcUrl = (n) => `https://www.rfc-editor.org/rfc/rfc${n}`;
const bcpUrl = (n) => `https://www.rfc-editor.org/info/bcp${n}`;
function linkRfcs(text) {
  const SKIP = /(`[^`\n]*`|\[[^\]\n]*\]\([^)\n]*\))/;
  let fenced = false;
  return text
    .split('\n')
    .map((line) => {
      if (/^```/.test(line)) { fenced = !fenced; return line; }
      if (fenced) return line;
      return line
        .split(SKIP)
        .map((part, i) => {
          if (i % 2 === 1) return part; // código em linha ou link existente
          return part
            .replace(/\bRFC (\d{2,5})(?: a (\d{2,5}))?\b/g, (_, a, b) => `[RFC ${a}](${rfcUrl(a)})` + (b ? ` a [${b}](${rfcUrl(b)})` : ''))
            .replace(/\bBCP (\d{1,3})\b/g, (_, n) => `[BCP ${n}](${bcpUrl(n)})`);
        })
        .join('');
    })
    .join('\n');
}
for (const k of Object.keys(files)) files[k] = linkRfcs(files[k]);

for (const [name, text] of Object.entries(files)) fs.writeFileSync(path.join(out, name), text, 'utf8');
console.log(`${Object.keys(files).length} arquivos em ${out}; ${nNative} nativos, ${nScen} cenários`);
await server.close();
