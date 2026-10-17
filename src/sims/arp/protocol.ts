import type { ProtocolDef } from '../../sim-core/ui';
import { controls } from './content/controls';
import { explain, setup } from './content/explain';
import { reference } from './content/reference';
import { groupDoc, scenDoc, scenarios, stageTitles } from './content/scenarios';
import { tabs } from './content/tabs';
import { buildArp, type ArpParams } from './engine';
import { topology } from './topology';

/** Simulador de ARP nativo: motor TypeScript puro e apresentação pela bancada genérica. */
export const arpProtocol: ProtocolDef = {
  id: 'arp',
  label: 'ARP',
  stateTitle: 'Estado da resolução',
  rfcs: [[826, 'ARP'], [1027, 'Proxy ARP'], [1122, 'Requisitos de hosts']],
  subs: [{ key: 'res', label: 'Resolução', default: 'r-local' }],
  controls,
  scenarios,
  groupDoc,
  scenDoc,
  tabs,
  stageTitle: (sub) => stageTitles[sub],
  topology,
  topologyTitle: 'Topologia: rede local com switch e gateway',
  build: (P, sub) => buildArp(P as unknown as ArpParams, sub),
  explain: (tr, P) => explain(tr, P as unknown as ArpParams),
  reference,
  setup,
};

export default arpProtocol;
