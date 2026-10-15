import type { Trace } from '../../../sim-core';
import { simCompare } from './compare';
import { simHandshake } from './handshake';
import type { TlsParams } from './profiles';
import { simWeb } from './web';

export * from './profiles';
export { STATES, WSTATES, closeSession, mkTrace, runTls, simHandshake, tcp3, toolkit } from './handshake';
export { ACTIONS, CSTATES, simCompare } from './compare';
export { simWeb } from './web';

/** Motor do HTTPS: modos web (HSTS), cmp (comparação HTTP x HTTPS) e handshake/cert (TLS). */
export function buildHttps(P: TlsParams, sub: string): Trace {
  return sub === 'web' ? simWeb(P) : sub === 'cmp' ? simCompare(P) : simHandshake(P, sub);
}
