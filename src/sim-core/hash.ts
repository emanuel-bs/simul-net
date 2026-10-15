// Valores determinísticos que parecem chaves e hashes. São ilustrativos: não há criptografia real.

export function h32(str: string, seed: number): number {
  let h = (0x811c9dc5 ^ seed) >>> 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  h ^= h >>> 13;
  h = Math.imul(h, 0x5bd1e995);
  h ^= h >>> 15;
  return h >>> 0;
}

export function hex(seed: string | number, n: number): string {
  let o = '';
  for (let i = 0; i < n; i++) o += (h32(String(seed), i * 7919 + 13) & 255).toString(16).padStart(2, '0');
  return o;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function b64(seed: string | number, n: number): string {
  let o = '';
  for (let i = 0; i < n; i++) o += B64[h32(String(seed), i * 104729 + 5) % 64];
  return o;
}

export const fmtMs = (v: number): string => (Math.round(v * 10) / 10).toString().replace('.', ',') + ' ms';

export const plural = (n: number, s: string, p: string): string => n + ' ' + (n === 1 ? s : p);

const ESC: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' };
export const esc = (t: unknown): string => String(t).replace(/[&<>"]/g, (c) => ESC[c]);
