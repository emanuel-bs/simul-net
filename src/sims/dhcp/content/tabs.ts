// Aba própria do DHCP: os leases de cada servidor no instante mostrado.
import { esc } from '../../../sim-core';
import type { TabDef } from '../../../sim-core/ui';
import { SERVERS, type DhcpParams, type LeaseEv } from '../engine';

const leases: TabDef = {
  id: 'leases',
  label: 'Leases',
  render: (tr, ctx) => {
    const R = tr.raw;
    const P = R.P as DhcpParams | undefined;
    if (!P) return '';
    const ev = (R.leaseEv || []) as LeaseEv[];
    const now = ctx.timeAt(ctx.c);
    let h = '<h3>Leases de cada servidor</h3><table class="sc-msgs"><thead><tr><th>Servidor</th><th>Endereço</th><th>Cliente (MAC)</th><th>Estado</th><th>Lease</th></tr></thead><tbody>';
    SERVERS.slice(0, P.servers).forEach((s) => {
      const last = new Map<string, LeaseEv>();
      ev.filter((e) => e.server === s.id && e.t <= now + 1e-9).forEach((e) => (e.state === 'FREE' ? last.delete(e.ip) : last.set(e.ip, e)));
      const head = '<b>' + esc(s.id) + '</b><br><span class="muted">pool .' + s.start + ' a .' + s.end + '</span>';
      const rows = Array.from(last.values());
      if (!rows.length) h += '<tr><td>' + head + '</td><td colspan="4" class="meaning">nenhum endereço reservado ou em uso</td></tr>';
      rows.forEach((l, i) => {
        const cls = l.state === 'BOUND' ? 'chk-ok' : l.state === 'DECLINED' ? 'chk-bad' : 'meaning';
        h += '<tr><td>' + (i === 0 ? head : '') + '</td><td>' + l.ip + '</td><td>' + esc(l.mac) + '</td><td class="' + cls + '">' + l.state + '</td><td>' + (l.state === 'BOUND' ? l.hours + ' h (T1 ' + (l.hours as number) / 2 + ' h)' : '-') + '</td></tr>';
      });
    });
    return h + '</tbody></table><p>OFFERED: reservado e oferecido. BOUND: em uso pelo cliente. DECLINED: recusado por conflito e fora do pool.</p>';
  },
};

export const tabs: TabDef[] = [leases];
