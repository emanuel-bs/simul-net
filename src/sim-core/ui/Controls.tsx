import { useState } from 'react';
import type { ControlDef, ParamValue, Params } from './module';
import { parseSelect, visibleControl } from './scenarios';

interface Props {
  controls: ControlDef[];
  sub: string;
  P: Params;
  onChange: (id: string, value: ParamValue) => void;
  advOpen: boolean;
  onAdvToggle: (open: boolean) => void;
}

interface HelpState {
  c: ControlDef;
  left: number;
  top: number;
}

const HELP_ID = 'simnet-field-help';
const HELP_W = 330;

function Field({ c, P, onChange, showHelp, hideHelp }: { c: ControlDef; P: Params; onChange: Props['onChange']; showHelp: (c: ControlDef, el: HTMLElement) => void; hideHelp: () => void }) {
  const id = 'c_' + c.id;
  const events = {
    onMouseEnter: (e: React.MouseEvent<HTMLLabelElement>) => showHelp(c, e.currentTarget),
    onMouseLeave: (e: React.MouseEvent<HTMLLabelElement>) => {
      if (!e.currentTarget.contains(document.activeElement)) hideHelp();
    },
    onFocus: (e: React.FocusEvent<HTMLLabelElement>) => showHelp(c, e.currentTarget),
    onBlur: hideHelp,
    onKeyDown: (e: React.KeyboardEvent<HTMLLabelElement>) => {
      if (e.key === 'Escape') hideHelp();
    },
  };
  const describedBy = c.help ? HELP_ID : undefined;
  if (c.type === 'check') {
    return (
      <label className="check" data-ctl={c.id} {...events}>
        <input type="checkbox" id={id} checked={!!P[c.id]} onChange={(e) => onChange(c.id, e.target.checked)} aria-describedby={describedBy} />
        {c.label}
        <span className="info" aria-hidden="true">
          ⓘ
        </span>
      </label>
    );
  }
  return (
    <label className="field" data-ctl={c.id} {...events}>
      <span className="lbl">
        {c.label}
        <span className="info" aria-hidden="true">
          ⓘ
        </span>
      </span>
      <select id={id} value={String(P[c.id])} onChange={(e) => onChange(c.id, parseSelect(c, e.target.value))} aria-describedby={describedBy}>
        {(c.opts || []).map((o) => (
          <option key={String(o[0])} value={String(o[0])}>
            {o[1]}
          </option>
        ))}
      </select>
    </label>
  );
}

/** Agrupa campos consecutivos que não são "wide" em pares (grade de duas colunas), como no legado. */
function Rows({ list, ...rest }: { list: ControlDef[] } & Omit<Parameters<typeof Field>[0], 'c'>) {
  const out: React.ReactNode[] = [];
  let grid: ControlDef[] = [];
  const flush = () => {
    if (grid.length)
      out.push(
        <div className="grid2" key={'g' + out.length}>
          {grid.map((c) => (
            <Field key={c.id} c={c} {...rest} />
          ))}
        </div>,
      );
    grid = [];
  };
  list.forEach((c) => {
    if (c.type === 'select' && !c.wide) grid.push(c);
    else {
      flush();
      out.push(<Field key={c.id} c={c} {...rest} />);
    }
  });
  flush();
  return <>{out}</>;
}

/** Painel de configuração. Cada campo tem ajuda (ícone ⓘ) ao passar o mouse, tocar ou focar. */
export function Controls({ controls, sub, P, onChange, advOpen, onAdvToggle }: Props) {
  const [help, setHelp] = useState<HelpState | null>(null);
  const showHelp = (c: ControlDef, el: HTMLElement) => {
    if (!c.help) return;
    const r = el.getBoundingClientRect();
    const left = r.left - HELP_W - 10 > 8 ? r.left - HELP_W - 10 : Math.max(8, Math.min(r.left, window.innerWidth - HELP_W - 8));
    setHelp({ c, left, top: Math.max(8, Math.min(r.top, window.innerHeight - 200)) });
  };
  const hideHelp = () => setHelp(null);

  const visible = controls.filter((c) => visibleControl(c, sub));
  const groups: { t: string; list: ControlDef[] }[] = [];
  visible
    .filter((c) => !c.adv)
    .forEach((c) => {
      let g = groups.find((x) => x.t === c.grp);
      if (!g) groups.push((g = { t: c.grp, list: [] }));
      g.list.push(c);
    });
  const adv = visible.filter((c) => c.adv);
  const rest = { P, onChange, showHelp, hideHelp };

  return (
    <div className="ctl-body">
      {groups.map((g, i) => (
        <div className="ctl-group" key={g.t}>
          {i > 0 && <div className="sep" />}
          <div className="sub-title">{g.t}</div>
          <Rows list={g.list} {...rest} />
        </div>
      ))}
      {adv.length > 0 && (
        <details className="adv" open={advOpen} onToggle={(e) => onAdvToggle((e.currentTarget as HTMLDetailsElement).open)}>
          <summary>Ajustes avançados</summary>
          <Rows list={adv} {...rest} />
        </details>
      )}
      {help?.c.help && (
        <div id={HELP_ID} role="tooltip" className="field-help" style={{ display: 'block', left: help.left, top: help.top, width: HELP_W }}>
          <div className="fh-title">{help.c.help.t}</div>
          {help.c.help.p.map((p, i) => (
            <p key={i} dangerouslySetInnerHTML={{ __html: p }} />
          ))}
        </div>
      )}
    </div>
  );
}
