import type { Trace } from '../../../sim-core';
import type { SshParams } from './profiles';
import { simSession } from './session';
import { simTunnel } from './tunnel';

export type { SshParams } from './profiles';
export * from './profiles';
export { STATES, simSession } from './session';
export { TSTATES, simTunnel } from './tunnel';

/** Motor do SSH: o modo "tunnel" gera túneis e encaminhamento; qualquer outro, a sessão completa. */
export function buildSsh(P: SshParams, sub: string): Trace {
  return sub === 'tunnel' ? simTunnel(P) : simSession(P);
}
