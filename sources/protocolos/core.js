(function(){
'use strict';
/* ==========================================================================
   NÚCLEO DO SIMULADOR DE PROTOCOLOS SEGUROS

   O núcleo não conhece nenhum protocolo. Cada protocolo (SSH, HTTPS/TLS, DNSSEC, VPN...)
   é um módulo que chama SecureSim.register({...}) com:

     id, label            identificador e nome no seletor do topo
     rfcs                 [[número, rótulo], ...] chips de especificação
     subs                 [{key,label,default}] modos do protocolo (segunda linha do topo);
                          "default" é o id do cenário carregado ao escolher o modo
     controls             campos do painel lateral (veja renderControls)
     scenarios            [{id,g,label,sub,set:{idDoControle:valor},what}]
     groupDoc, scenDoc    textos da aba Cenário
     tabs                 abas extras [{id,label,render(trace,ctx)}] (ctx = {c, timeAt, P})
     build(P,sub)         devolve um trace (use SecureSim.newTrace)
     explain(tr,P,scen)   HTML da aba Experimento
     reference            HTML da aba Referência
     setup(scen)          texto da configuração do cenário (opcional)

   O trace é uma lista de mensagens, eventos, estados e fases com tempos em ms. O núcleo converte os
   tempos em "linhas" (uma linha por instante distinto), então o diagrama fica compacto e a animação
   tem ritmo constante, qualquer que seja o RTT.
   ========================================================================== */
const NS='http://www.w3.org/2000/svg';
const $=id=>document.getElementById(id);
const esc=t=>String(t).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function elNS(tag,attrs){ const e=document.createElementNS(NS,tag); for(const k in attrs) e.setAttribute(k,attrs[k]); return e; }
const COLORS={plain:'#F2A65A',enc:'#5FD4C0',bad:'#E2574C',data:'#6FB8E8',tcp:'#8FA9C7'};

// ---------- Valores determinísticos que parecem chaves e hashes (ilustrativos, sem criptografia real) ----------
function h32(str,seed){ let h=(0x811c9dc5^seed)>>>0; for(let i=0;i<str.length;i++){ h^=str.charCodeAt(i); h=Math.imul(h,16777619); } h^=h>>>13; h=Math.imul(h,0x5bd1e995); h^=h>>>15; return h>>>0; }
function hex(seed,n){ let o=''; for(let i=0;i<n;i++) o+=(h32(String(seed),i*7919+13)&255).toString(16).padStart(2,'0'); return o; }
const B64='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function b64(seed,n){ let o=''; for(let i=0;i<n;i++) o+=B64[h32(String(seed),i*104729+5)%64]; return o; }
const fmtMs=v=>(Math.round(v*10)/10).toString().replace('.',',')+' ms';
const plural=(n,s,p)=>n+' '+(n===1?s:p);

// ---------- Trace ----------
function newTrace(cols,stateDefs,rtt){
  const tr={cols:cols,stateDefs:stateDefs||[],msgs:[],events:[],log:[],states:[],phases:[],metro:[],raw:{},tabData:{},t:0,ow:(rtt||20)/2,rtt:rtt||20};
  // Mensagem de "from" para "to". o.at fixa o instante; o.par não avança o cursor (mensagens simultâneas).
  tr.add=(from,to,o)=>{
    const tS=o.at!==undefined?o.at:tr.t, dur=o.dur!==undefined?o.dur:tr.ow;
    const m=Object.assign({from:from,to:to,tSend:tS,tArr:tS+dur,color:COLORS.plain,enc:false,proto:'SSHv2',len:0,fields:[],tags:[],lost:false},o);
    m.id=tr.msgs.length; tr.msgs.push(m);
    if(!o.par) tr.t=m.tArr+(o.proc!==undefined?o.proc:0.4);
    return m;
  };
  tr.wait=ms=>{ tr.t+=ms; };
  tr.ev=(t,who,text,kind)=>{ tr.events.push({t:t,who:who,text:text,kind:kind||''}); };
  tr.lg=(t,text,tag)=>{ tr.log.push({t:t,text:text,tag:tag||'sys'}); };
  tr.st=(t,key,val,cls)=>{ tr.states.push({t:t,key:key,val:val,cls:cls||''}); };
  tr.phase=(label,key)=>{ tr.phases.push({t:tr.t,label:label,key:key}); };
  tr.mile=(t,label,sub)=>{ tr.metro.push({t:t,label:label,sub:sub}); };
  return tr;
}

// ---------- Registro ----------
const PROTOCOLS={}, ORDER=[];
function register(def){ PROTOCOLS[def.id]=def; ORDER.push(def.id); }

// ---------- Estado ----------
let proto=null, sub=null, tr=null, P={}, activeScen=null, baseScen=null, selMsg=null;
let clock=0, endR=0, playing=false, lastTs=0, speed=1.8;
let segEls=[], evEls=[], layout=null, capShown=0, logShown=0, logAll=[], protoTabs=[], lastTabHtml={};
let helpId=null;

const ladder=$('ladder'), ladderWrap=$('ladderWrap'), statePanel=$('statePanel'), inspector=$('inspector'), capBody=$('capBody'), msgBody=$('msgBody'), msgTitle=$('msgTitle'), logBody=$('logBody'), metroEl=$('metro');
const DEFAULT_INSPECTOR='<div class="muted-txt"><p>Escolha um cenário no topo ou ajuste a configuração e clique em <b>Simular</b>. Use <b>Passo</b> para avançar mensagem por mensagem.</p><p>Clique em uma seta do diagrama ou em uma linha da Captura para ver o conteúdo da mensagem.</p><p>Passe o mouse ou toque em qualquer campo de configuração (ⓘ) para ver a explicação dele.</p></div>';

// ---------- Controles do painel lateral ----------
// Cada controle: {id,label,type:'select'|'check',opts:[[valor,rótulo]],def,grp,adv,subs,wide,help:{t,s,p[]}}
function ctlEl(id){ return $('c_'+id); }
function visibleCtl(c){ return !c.subs || c.subs.indexOf(sub)>=0; }
function renderControls(){
  const host=$('ctlBody'); host.innerHTML='';
  const groups=[]; proto.controls.filter(c=>!c.adv).forEach(c=>{ let g=groups.find(x=>x.t===c.grp); if(!g){ g={t:c.grp,list:[]}; groups.push(g); } g.list.push(c); });
  const build=(list,parent)=>{
    let grid=null;
    list.forEach(c=>{
      const lab=document.createElement('label'); lab.dataset.ctl=c.id;
      const icon=document.createElement('span'); icon.className='info'; icon.setAttribute('aria-hidden','true'); icon.textContent='ⓘ';
      if(c.type==='check'){
        lab.className='check'; const inp=document.createElement('input'); inp.type='checkbox'; inp.id='c_'+c.id; inp.checked=!!c.def;
        lab.appendChild(inp); lab.appendChild(document.createTextNode(c.label)); lab.appendChild(icon);
        parent.appendChild(lab); grid=null;
      } else {
        lab.className='field'; const w=document.createElement('span'); w.className='lbl'; w.appendChild(document.createTextNode(c.label)); w.appendChild(icon);
        const sel=document.createElement('select'); sel.id='c_'+c.id;
        c.opts.forEach(o=>{ const op=document.createElement('option'); op.value=o[0]; op.textContent=o[1]; sel.appendChild(op); }); sel.value=c.def;
        lab.appendChild(w); lab.appendChild(sel);
        if(c.wide){ parent.appendChild(lab); grid=null; }
        else { if(!grid){ grid=document.createElement('div'); grid.className='grid2'; parent.appendChild(grid); } grid.appendChild(lab); }
      }
      const inp=ctlEl(c.id)||lab.querySelector('select,input');
      lab.addEventListener('mouseenter',()=>showHelp(c)); lab.addEventListener('mouseleave',()=>{ if(document.activeElement!==inp) hideHelp(); });
      inp.addEventListener('focus',()=>showHelp(c)); inp.addEventListener('blur',hideHelp);
      inp.addEventListener('keydown',e=>{ if(e.key==='Escape') hideHelp(); });
      inp.addEventListener('change',()=>{ activeScen=null; refreshAfterChange(); });
    });
  };
  groups.forEach((g,i)=>{
    const box=document.createElement('div'); box.className='ctl-group'; box.dataset.grp=g.t;
    if(i>0){ const sp=document.createElement('div'); sp.className='sep'; box.appendChild(sp); }
    const t=document.createElement('div'); t.className='sub-title'; t.textContent=g.t; box.appendChild(t);
    build(g.list,box); host.appendChild(box);
  });
  const adv=proto.controls.filter(c=>c.adv);
  if(adv.length){
    const d=document.createElement('details'); d.className='adv'; d.id='advBox';
    const sm=document.createElement('summary'); sm.textContent='Ajustes avançados'; d.appendChild(sm);
    build(adv,d); host.appendChild(d);
  }
}
function applyVisibility(){
  proto.controls.forEach(c=>{ const lab=document.querySelector('[data-ctl="'+c.id+'"]'); if(lab) lab.classList.toggle('hidden',!visibleCtl(c)); });
  document.querySelectorAll('.ctl-group').forEach(g=>{ g.classList.toggle('hidden',!Array.from(g.querySelectorAll('[data-ctl]')).some(l=>!l.classList.contains('hidden'))); });
  const adv=$('advBox'); if(adv) adv.classList.toggle('hidden',!Array.from(adv.querySelectorAll('[data-ctl]')).some(l=>!l.classList.contains('hidden')));
}
function readParams(){
  const o={};
  proto.controls.forEach(c=>{ const el=ctlEl(c.id); if(!el) return; if(c.type==='check') o[c.id]=el.checked; else { const v=el.value; o[c.id]=c.num?Number(v):v; } });
  return o;
}
function setCtl(id,v){ const c=proto.controls.find(x=>x.id===id); const el=ctlEl(id); if(!c||!el) return; if(c.type==='check') el.checked=!!v; else el.value=String(v); }
function resetCtls(){ proto.controls.forEach(c=>setCtl(c.id,c.def)); }

// ---------- Ajuda dos campos ----------
const helpBox=document.createElement('div'); helpBox.className='field-help'; helpBox.id='fieldHelp'; helpBox.setAttribute('role','tooltip'); document.body.appendChild(helpBox);
function showHelp(c){
  if(!c.help) return; const lab=document.querySelector('[data-ctl="'+c.id+'"]'); if(!lab) return;
  helpId=c;
  helpBox.innerHTML='<div class="fh-title">'+c.help.t+'</div>'+c.help.p.map(x=>'<p>'+x+'</p>').join('');
  helpBox.style.display='block';
  const r=lab.getBoundingClientRect(), bw=helpBox.offsetWidth, bh=helpBox.offsetHeight;
  if(r.bottom<0||r.top>window.innerHeight){ hideHelp(); return; }
  const left=Math.max(8,Math.min(r.left-bw-10>8?r.left-bw-10:r.left,window.innerWidth-bw-8));
  let top=r.top; if(top+bh>window.innerHeight-8) top=Math.max(8,window.innerHeight-bh-8);
  helpBox.style.left=left+'px'; helpBox.style.top=top+'px';
}
function hideHelp(){ helpBox.style.display='none'; helpId=null; }
const followHelp=()=>{ if(helpId) showHelp(helpId); };
document.querySelector('.side-col').addEventListener('scroll',followHelp,{passive:true});
window.addEventListener('scroll',followHelp,{passive:true});

// ---------- Preparação do trace: tempos viram linhas ----------
function prepare(t){
  const set=new Set([0]);
  t.msgs.forEach(m=>{ set.add(m.tSend); set.add(m.tArr); });
  t.events.forEach(e=>set.add(e.t)); t.states.forEach(s=>set.add(s.t)); t.log.forEach(l=>set.add(l.t)); t.phases.forEach(p=>set.add(p.t)); t.metro.forEach(m=>set.add(m.t));
  const arr=Array.from(set).sort((a,b)=>a-b), idx=new Map(); arr.forEach((v,i)=>idx.set(v,i));
  t.times=arr;
  t.msgs.forEach(m=>{ m.rS=idx.get(m.tSend); m.rA=idx.get(m.tArr); });
  t.events.forEach(e=>{ e.r=idx.get(e.t); }); t.states.forEach(s=>{ s.r=idx.get(s.t); }); t.log.forEach(l=>{ l.r=idx.get(l.t); });
  t.phases.forEach(p=>{ p.r=idx.get(p.t); }); t.metro.forEach(m=>{ m.r=idx.get(m.t); });
  endR=arr.length-1+0.6;
}
function timeAt(c){ const a=tr.times, i=Math.max(0,Math.min(a.length-1,Math.floor(c))), j=Math.min(a.length-1,i+1), f=Math.max(0,Math.min(1,c-i)); return a[i]+(a[j]-a[i])*f; }

// ---------- Diagrama ----------
function drawLadder(){
  ladder.innerHTML=''; segEls=[]; evEls=[];
  const N=tr.cols.length, W=900, top=78, rowH=26, hh=26;
  const x0=N<=2?230:(N===3?200:150), xs={};
  tr.cols.forEach((c,i)=>{ xs[c.key]=N===1?W/2:x0+(W-2*x0)*i/(N-1); });
  const offs=r=>{ let k=0; tr.phases.forEach(p=>{ if(p.r<=r+1e-9) k++; }); return k*hh; };
  const y=r=>top+r*rowH+offs(r);
  layout={y:y,W:W,xs:xs};
  const H=y(endR)+36;
  ladder.setAttribute('viewBox','0 0 '+W+' '+H); ladder.style.minWidth=(N>2?760:640)+'px';
  tr.cols.forEach(c=>{
    const t1=elNS('text',{x:xs[c.key],y:28,'text-anchor':'middle',class:'col-title'}); t1.textContent=c.label; ladder.appendChild(t1);
    const t2=elNS('text',{x:xs[c.key],y:44,'text-anchor':'middle',class:'col-sub'}); t2.textContent=c.sub||''; ladder.appendChild(t2);
    const lf=elNS('line',{x1:xs[c.key],y1:top-12,x2:xs[c.key],y2:H-10}); lf.style.stroke='var(--muted)'; lf.style.strokeWidth='2px'; ladder.appendChild(lf);
  });
  tr.phases.forEach(p=>{
    const yy=y(p.r)-hh;
    const ln=elNS('line',{x1:20,y1:yy+4,x2:W-20,y2:yy+4}); ln.style.stroke='var(--border)'; ln.style.strokeDasharray='4,4'; ladder.appendChild(ln);
    const tx=elNS('text',{x:W/2,y:yy+19,'text-anchor':'middle',class:'phase-label'}); tx.textContent=p.label; ladder.appendChild(tx);
  });
  const seen=new Set();
  tr.msgs.forEach(m=>{ if(seen.has(m.rS)) return; seen.add(m.rS); const tl=elNS('text',{x:60,y:y(m.rS)+4,'text-anchor':'end',class:'time-label'}); tl.textContent=Math.round(m.tSend*10)/10+' ms'; ladder.appendChild(tl); });
  const lastEv={};   // por coluna: onde terminou o último texto, para os eventos não se sobreporem
  tr.events.slice().sort((a,b)=>a.r-b.r).forEach(e=>{
    const ci=tr.cols.findIndex(c=>c.key===e.who), right=N>2?(ci>0&&ci<N-1):(ci>0||N===1);
    const wrapAt=(N>2&&ci===0)?Math.max(14,Math.floor((xs[e.who]-26)/6.3)):30;
    const xx=xs[e.who]+(right?12:-12);
    const words=e.text.split(' '), lines=[]; let cur='';
    words.forEach(w=>{ if((cur+' '+w).trim().length>wrapAt&&cur){ lines.push(cur); cur=w; } else cur=(cur+' '+w).trim(); }); if(cur) lines.push(cur);
    const ey=Math.max(y(e.r)+4,(lastEv[e.who]===undefined?-1e9:lastEv[e.who]+16));
    lastEv[e.who]=ey+13*(lines.length-1);
    const g=elNS('g',{}); g.style.display='none';
    const tt=elNS('text',{x:xx,y:ey,'text-anchor':right?'start':'end',class:'ev-label'+(e.kind?' '+e.kind:'')}); tt.style.stroke='#0B2447'; tt.style.strokeWidth='4px'; tt.style.paintOrder='stroke'; tt.style.strokeLinejoin='round';
    lines.forEach((ln,i)=>{ const sp=elNS('tspan',{x:xx,dy:i===0?0:13}); sp.textContent=ln; tt.appendChild(sp); });
    g.appendChild(tt); ladder.appendChild(g); evEls.push({r:e.r,g:g});
  });
  tr.msgs.forEach(m=>{
    const xa=xs[m.from], xb=xs[m.to];
    const g=elNS('g',{class:'seg-g'}); g.style.display='none';
    const line=elNS('line',{x1:xa,y1:y(m.rS),x2:xa,y2:y(m.rS)}); line.style.stroke=m.color; line.style.strokeWidth=m.enc?'2.4px':'2px';
    const head=elNS('polygon',{points:'0,0 -9,-4 -9,4'}); head.style.fill=m.color; head.style.display='none';
    const mark=elNS('text',{'text-anchor':'middle',class:'seg-label'}); mark.style.fill='var(--red)'; mark.style.fontSize='15px'; mark.style.display='none'; mark.textContent='✕';
    const fx=(xa+xb)/2, fy=(y(m.rS)+y(m.rA))/2;
    const lab=elNS('text',{x:fx,y:fy-7,'text-anchor':'middle',class:'seg-label'}); lab.style.fill=m.color; lab.style.stroke='#0B2447'; lab.style.strokeWidth='4px'; lab.style.paintOrder='stroke'; lab.style.strokeLinejoin='round'; lab.textContent=m.label;
    const hit=elNS('line',{x1:xa,y1:y(m.rS),x2:xb,y2:y(m.rA),stroke:'transparent','stroke-width':10});
    g.appendChild(line); g.appendChild(head); g.appendChild(mark); g.appendChild(lab); g.appendChild(hit);
    if(m.enc){ // cadeado desenhado em SVG, no meio da seta
      const lk=elNS('g',{transform:'translate('+(fx-5)+','+(fy+4)+')'});
      const bd=elNS('rect',{x:0,y:5,width:10,height:8,rx:1.5}); bd.style.fill=m.color;
      const sh=elNS('path',{d:'M2 5 V3 a3 3 0 0 1 6 0 V5',fill:'none'}); sh.style.stroke=m.color; sh.style.strokeWidth='1.6px';
      lk.appendChild(bd); lk.appendChild(sh); g.appendChild(lk);
    }
    g.addEventListener('click',()=>selectMsg(m,true));
    ladder.appendChild(g);
    segEls.push({m:m,g:g,line:line,head:head,mark:mark,xa:xa,xb:xb});
  });
  ladderWrap.scrollTop=0;
}
function updateLadder(){
  const y=layout.y;
  segEls.forEach(e=>{
    const m=e.m;
    if(clock<m.rS){ e.g.style.display='none'; return; }
    e.g.style.display='';
    const endF=m.lost?0.55:1, f=Math.min(1,(clock-m.rS)/((m.rA-m.rS)||1))*endF;
    const x=e.xa+(e.xb-e.xa)*f, yy=y(m.rS)+(y(m.rA)-y(m.rS))*f;
    e.line.setAttribute('x2',x); e.line.setAttribute('y2',yy);
    const done=f>=endF-1e-9;
    if(done&&!m.lost){ const ang=Math.atan2(y(m.rA)-y(m.rS),e.xb-e.xa)*180/Math.PI; e.head.setAttribute('transform','translate('+x+','+yy+') rotate('+ang+')'); e.head.style.display=''; } else e.head.style.display='none';
    if(done&&m.lost){ e.mark.setAttribute('x',x); e.mark.setAttribute('y',yy+5); e.mark.style.display=''; } else e.mark.style.display='none';
  });
  evEls.forEach(e=>{ e.g.style.display=clock>=e.r?'':'none'; });
}

// ---------- Painéis ----------
function stateOf(key){ let s=null; tr.states.forEach(x=>{ if(x.key===key&&x.r<=clock+1e-9) s=x; }); return s; }
function renderState(){
  let h='<div class="state-title">'+esc(proto.stateTitle||'Estado da conexão')+'</div>';
  tr.stateDefs.forEach(d=>{ const s=stateOf(d.key); h+='<div class="cfg-line">'+esc(d.label)+(s?'<span class="spill '+s.cls+'">'+esc(s.val)+'</span>':'<span class="spill closed">-</span>')+'</div>'; });
  h+='<div class="cfg-line">Relógio<b>'+timeAt(clock).toFixed(1)+' ms</b></div>';
  statePanel.innerHTML=h;
}
function renderMetro(){
  const m=tr.metro; let a=0; m.forEach((x,i)=>{ if(x.r<=clock+1e-9) a=i; });
  if(clock>=endR-0.7) a=m.length;
  metroEl.innerHTML='';
  m.forEach((x,i)=>{
    if(i>0){ const sg=document.createElement('div'); sg.className='seg'+(i<=a?' done':''); metroEl.appendChild(sg); }
    const d=document.createElement('div'); d.className='stop'+(i<a?' done':(i===a?' active':''));
    d.innerHTML='<div class="dot"></div><div class="stop-label"><b>'+esc(x.label)+'</b>'+esc(x.sub||'')+'</div>'; metroEl.appendChild(d);
  });
}
function capRow(m){
  const row=document.createElement('tr'); row.className='cap-row'+(m.lost?' lost':'')+(m===selMsg?' selected':''); row.tabIndex=0;
  const colOf=k=>tr.cols.find(c=>c.key===k);
  row.innerHTML='<td>'+(m.id+1)+'</td><td>'+(m.tSend/1000).toFixed(6)+'</td><td>'+esc(colOf(m.from).addr||colOf(m.from).label)+'</td><td>'+esc(colOf(m.to).addr||colOf(m.to).label)+'</td><td>'+esc(m.proto)+'</td><td>'+m.len+'</td><td><span class="dot-type" style="background:'+m.color+'"></span>'+esc(m.info||m.label)+'</td>';
  const open=()=>selectMsg(m,true);
  row.addEventListener('click',open); row.addEventListener('keydown',e=>{ if(e.key==='Enter'){ e.preventDefault(); open(); } });
  m.row=row; return row;
}
function updateCapture(){
  const list=tr.msgs;
  if(capShown===0&&(!list.length||clock<list[0].rS)){ capBody.innerHTML='<tr class="placeholder-row"><td colspan="7">Clique em Simular para começar.</td></tr>'; return; }
  if(capShown===0) capBody.innerHTML='';
  let added=false;
  while(capShown<list.length&&list[capShown].rS<=clock){ capBody.appendChild(capRow(list[capShown])); capShown++; added=true; }
  if(added){ const sc=capBody.parentElement.parentElement; sc.scrollTop=sc.scrollHeight; }
}
function updateLog(){
  let added=false;
  while(logShown<logAll.length&&logAll[logShown].r<=clock){
    const e=logAll[logShown], d=document.createElement('div');
    d.innerHTML='<span class="tag tag-'+e.tag+'">['+e.tag.toUpperCase()+']</span> '+e.t.toFixed(1)+' ms: '+esc(e.text); logBody.appendChild(d); logShown++; added=true;
  }
  if(added) logBody.parentElement.scrollTop=logBody.parentElement.scrollHeight;
}
function selectMsg(m,open){
  selMsg=m; tr.msgs.forEach(x=>{ if(x.row) x.row.classList.toggle('selected',x===m); });
  renderMessage();
  inspector.innerHTML='<div class="insp-kicker">'+esc(m.phaseName||'Mensagem')+(m.enc?' (cifrada)':' (em claro)')+'</div><div class="insp-title">'+esc(m.label)+'</div><div class="muted-txt">'+(m.about||'')+'</div>';
  if(open) activateTab('msg');
}
function renderMessage(){
  msgBody.innerHTML='';
  if(!selMsg){ msgTitle.textContent='Mensagem selecionada'; msgBody.innerHTML='<tr class="placeholder-row"><td colspan="3">Clique em uma seta do diagrama ou em uma linha da Captura.</td></tr>'; return; }
  const m=selMsg; msgTitle.textContent='#'+(m.id+1)+' '+m.proto+': '+(m.info||m.label);
  const rows=m.fields.slice();
  rows.push({sec:'Análise'}); rows.push(['Protegida?',m.enc?'sim: cifrada e autenticada':'não: trafega em claro',m.enc?'quem captura o tráfego vê só pacotes cifrados':'qualquer observador no caminho lê isto','expert']);
  m.tags.forEach(t=>rows.push(['Marcação',t,'equivalente ao "expert info" do Wireshark','expert']));
  rows.forEach(x=>{
    const r=document.createElement('tr');
    if(x.sec){ r.className='sec-row'; r.innerHTML='<td colspan="3">'+esc(x.sec)+'</td>'; }
    else r.innerHTML='<td>'+esc(x[0])+'</td><td'+(x[3]?' class="'+x[3]+'"':'')+'>'+esc(x[1])+'</td><td class="meaning">'+esc(x[2]||'')+'</td>';
    msgBody.appendChild(r);
  });
}

// ---------- Abas ----------
function activateTab(name){
  document.querySelectorAll('.tab-btn').forEach(b=>{ const on=b.dataset.tab===name; b.classList.toggle('active',on); b.setAttribute('aria-selected',on); });
  document.querySelectorAll('.tab-content').forEach(c=>c.classList.toggle('active',c.dataset.tabContent===name));
  renderProtoTabs();
}
function buildProtoTabs(){
  document.querySelectorAll('[data-ptab]').forEach(e=>e.remove());
  protoTabs=proto.tabs||[];
  const bar=$('tabBar'), expBtn=bar.querySelector('[data-tab="exp"]'), expBox=document.querySelector('[data-tab-content="exp"]');
  protoTabs.forEach(t=>{
    const b=document.createElement('button'); b.className='tab-btn'; b.dataset.tab=t.id; b.dataset.ptab='1'; b.type='button'; b.setAttribute('role','tab'); b.setAttribute('aria-selected','false'); b.textContent=t.label;
    b.addEventListener('click',()=>activateTab(t.id)); bar.insertBefore(b,expBtn);
    const c=document.createElement('div'); c.className='tab-content'; c.dataset.tabContent=t.id; c.dataset.ptab='1';
    c.innerHTML='<div class="tab-scroll"><article class="ref-body" id="ptab_'+t.id+'"></article></div>'; expBox.parentNode.insertBefore(c,expBox);
  });
  lastTabHtml={};
}
// Abas do protocolo com "subs" só aparecem nos modos listados.
function syncTabs(){
  protoTabs.forEach(t=>{
    const on=!t.subs||t.subs.indexOf(sub)>=0;
    const b=document.querySelector('.tab-btn[data-tab="'+t.id+'"]'), c=document.querySelector('[data-tab-content="'+t.id+'"]');
    if(b) b.classList.toggle('hidden',!on); if(c&&!on) c.classList.remove('active');
  });
}
function renderProtoTabs(){
  protoTabs.forEach(t=>{
    const box=document.querySelector('[data-tab-content="'+t.id+'"]'); if(!box||!box.classList.contains('active')) return;
    const h=t.render(tr,{c:clock,timeAt:timeAt,P:P});
    if(lastTabHtml[t.id]!==h){ lastTabHtml[t.id]=h; $('ptab_'+t.id).innerHTML=h; }
  });
}

// ---------- Aba Cenário ----------
function scenText(s){
  const d=proto.scenDoc[s.id];
  return '<div class="sc-kicker">'+esc(s.g)+'</div><h3 class="sc-title">'+esc(s.label)+'</h3>'+(proto.setup?'<p class="sc-cmd">'+proto.setup(s)+'</p>':'')+
    '<h4>O que é</h4><p>'+d.concept+'</p><h4>Neste cenário</h4>'+s.what+
    '<h4>O que observar</h4><ul>'+d.observe.map(x=>'<li>'+x+'</li>').join('')+'</ul>'+
    '<h4>'+(d.msgsTitle||'Mensagens envolvidas')+'</h4><table class="sc-msgs"><thead><tr><th>'+(d.cols?d.cols[0]:'Mensagem')+'</th><th>'+(d.cols?d.cols[1]:'Função')+'</th><th>'+(d.cols?d.cols[2]:'Quem envia')+'</th></tr></thead><tbody>'+
    d.msgs.map(m=>'<tr><td>'+m[0]+'</td><td>'+m[1]+'</td><td class="meaning">'+m[2]+'</td></tr>').join('')+'</tbody></table><h4>Por que importa</h4><p>'+d.why+'</p>';
}
// Campos que hoje diferem da configuração pronta do cenário (os controles ocultos no modo atual não contam).
function changedCtls(s){
  const out=[], lbl=(c,v)=>c.type==='check'?(v?'sim':'não'):((c.opts.find(o=>String(o[0])===String(v))||[0,String(v)])[1]);
  proto.controls.filter(visibleCtl).forEach(c=>{
    const el=ctlEl(c.id); if(!el) return;
    const cur=c.type==='check'?el.checked:el.value, exp=(s.set&&c.id in s.set)?s.set[c.id]:c.def;
    if(String(cur)!==String(exp)) out.push({label:c.label,from:lbl(c,exp),to:lbl(c,cur)});
  });
  return out;
}
function renderScenarioTab(){
  const body=$('scenBody'), list=proto.scenarios, s=list.find(x=>x.id===activeScen), D=proto.scenDoc;
  const base=!s&&proto.showBase&&baseScen?list.find(x=>x.id===baseScen):null;
  let left;
  if(base){
    const ch=changedCtls(base);
    left='<div class="sc-kicker">Baseado em</div><h3 class="sc-title">'+esc(base.label)+' <span class="sc-badge">modificado</span></h3>'+
      '<p>Você alterou a configuração. O texto do cenário descreve a configuração original, então o resultado desta simulação pode ser diferente: confira a aba <b>Experimento</b>. <button type="button" class="sc-restore">Restaurar o cenário</button></p>'+
      '<h4>O que mudou</h4><ul class="sc-diff">'+ch.map(x=>'<li><b>'+esc(x.label)+':</b> '+esc(x.from)+' &rarr; '+esc(x.to)+'</li>').join('')+'</ul>'+
      '<details class="sc-orig"><summary>Ver o texto do cenário original</summary>'+scenText(base)+'</details>';
  }
  else if(!s) left='<h3>Nenhum cenário selecionado</h3><p>A configuração foi alterada manualmente. Escolha um cenário à direita ou no topo para carregar a configuração pronta, ou continue explorando: a aba <b>Experimento</b> descreve cada execução.</p>';
  else left=scenText(s);
  let right='<h3>Tipos de cenário</h3>', group=null;
  list.filter(x=>x.sub===sub).forEach(x=>{
    if(x.g!==group){ if(group!==null) right+='</ul>'; group=x.g; right+='<h4>'+esc(x.g)+'</h4><p class="sc-gdoc">'+(proto.groupDoc[x.g]||'')+'</p><ul class="sc-list">'; }
    right+='<li><button type="button" class="sc-link'+(s&&s.id===x.id?' active':'')+'" data-scen="'+x.id+'">'+esc(x.label)+'</button> '+D[x.id].short+'</li>';
  });
  right+='</ul>';
  body.innerHTML='<div class="sc-main">'+left+'</div><aside class="sc-side">'+right+'</aside>';
  body.querySelectorAll('.sc-link').forEach(b=>b.addEventListener('click',()=>applyScenario(list.find(x=>x.id===b.dataset.scen))));
  const rs=body.querySelector('.sc-restore'); if(rs) rs.addEventListener('click',()=>applyScenario(base));
}
function renderExplain(){
  const scen=proto.scenarios.find(x=>x.id===activeScen);
  $('explainBody').innerHTML='<h3>'+(scen?'Experimento: '+esc(scen.label):'Experimento personalizado')+'</h3>'+proto.explain(tr,P,scen);
}

// ---------- Seletores do topo ----------
function renderProtoSeg(){
  const seg=$('protoSeg'); seg.innerHTML=''; seg.classList.toggle('hidden',ORDER.length<2);
  ORDER.forEach(id=>{
    const b=document.createElement('button'); b.type='button'; b.textContent=PROTOCOLS[id].label; const on=id===proto.id;
    b.classList.toggle('active',on); b.setAttribute('aria-pressed',on);
    b.addEventListener('click',()=>{ if(!on) activateProtocol(id); }); seg.appendChild(b);
  });
  const nav=$('rfcChips'); nav.innerHTML='';
  proto.rfcs.forEach(r=>{ const a=document.createElement('a'); a.className='rfc-chip'; a.href='https://www.rfc-editor.org/rfc/rfc'+r[0]; a.target='_blank'; a.rel='noreferrer'; a.textContent='RFC '+r[0]+' ('+r[1]+')'; nav.appendChild(a); });
}
function renderSubSeg(){
  const seg=$('subSeg'); seg.innerHTML=''; seg.classList.toggle('hidden',proto.subs.length<2);
  proto.subs.forEach(x=>{
    const b=document.createElement('button'); b.type='button'; b.textContent=x.label; const on=x.key===sub;
    b.classList.toggle('active',on); b.setAttribute('aria-pressed',on);
    b.addEventListener('click',()=>{ if(!on) applyScenario(proto.scenarios.find(s=>s.id===x.default)); }); seg.appendChild(b);
  });
}
function renderScenarios(){
  const row=$('scenRow'); row.innerHTML=''; let g=null;
  proto.scenarios.filter(s=>s.sub===sub).forEach(s=>{
    if(s.g!==g){ g=s.g; const sp=document.createElement('span'); sp.className='scen-group'; sp.textContent=g; row.appendChild(sp); }
    const b=document.createElement('button'); b.type='button'; b.className='chip'+(activeScen===s.id?' active':''); b.textContent=s.label; b.addEventListener('click',()=>applyScenario(s)); row.appendChild(b);
  });
}

// ---------- Construção e reprodução ----------
function build(){
  pause();
  P=readParams(); tr=proto.build(P,sub);
  prepare(tr);
  clock=0; capShown=0; logShown=0; selMsg=null; capBody.innerHTML=''; logBody.innerHTML='';
  logAll=tr.log.slice().sort((a,b)=>a.t-b.t);
  $('stageTitle').textContent=proto.stageTitle?proto.stageTitle(sub):'Diagrama de sequência';
  drawLadder(); renderExplain(); renderMessage(); inspector.innerHTML=DEFAULT_INSPECTOR; lastTabHtml={}; update();
}
function update(){
  updateLadder(); renderState(); renderMetro(); updateCapture(); updateLog(); renderProtoTabs();
  $('btnPlay').textContent=playing?'Pausar':(clock>0&&clock<endR?'Continuar':'Simular');
  if(playing){ const k=ladder.getBoundingClientRect().width/layout.W, target=layout.y(clock)*k-ladderWrap.clientHeight*0.6; if(target>ladderWrap.scrollTop) ladderWrap.scrollTop=target; }
}
function frame(ts){
  if(!playing) return;
  const dt=Math.min(100,ts-lastTs); lastTs=ts;
  clock=Math.min(endR,clock+dt/1000*speed);
  if(clock>=endR) playing=false;
  update();
  if(playing) requestAnimationFrame(frame);
}
function play(){ if(clock>=endR) restart(); playing=true; lastTs=performance.now(); update(); requestAnimationFrame(frame); }
function pause(){ playing=false; }
function restart(){ pause(); clock=0; capShown=0; logShown=0; capBody.innerHTML=''; logBody.innerHTML=''; ladderWrap.scrollTop=0; update(); }
function stepOnce(){
  pause();
  const rs=[]; tr.msgs.forEach(m=>{ rs.push(m.rS); rs.push(m.rA); }); tr.events.forEach(e=>rs.push(e.r));
  const n=rs.filter(r=>r>clock+0.01).sort((a,b)=>a-b)[0];
  clock=n===undefined?endR:n; update();
  const k=ladder.getBoundingClientRect().width/layout.W; ladderWrap.scrollTop=Math.max(0,layout.y(clock)*k-ladderWrap.clientHeight*0.5);
}
function refreshAfterChange(){
  activeScen=null;
  // se o aluno desfez a mudança, a configuração volta a coincidir com o cenário e ele é reativado
  const b=proto.showBase&&baseScen&&proto.scenarios.find(x=>x.id===baseScen); if(b&&!changedCtls(b).length) activeScen=b.id;
  renderScenarios(); build(); renderScenarioTab(); }

function applyScenario(s){
  sub=s.sub; resetCtls();
  Object.keys(s.set||{}).forEach(k=>setCtl(k,s.set[k]));
  activeScen=s.id; baseScen=s.id;
  const adv=$('advBox'); if(adv) adv.open=!!s.openAdv;
  renderSubSeg(); renderScenarios(); applyVisibility(); syncTabs(); build(); renderScenarioTab(); activateTab('scen');
}
function activateProtocol(id){
  proto=PROTOCOLS[id]; sub=proto.subs[0].key;
  renderProtoSeg(); renderControls(); buildProtoTabs(); $('refBody').innerHTML=proto.reference;
  applyScenario(proto.scenarios.find(x=>x.id===proto.subs[0].default));
}

function start(){
  $('btnPlay').addEventListener('click',()=>{ if(playing){ pause(); update(); } else play(); });
  $('btnStep').addEventListener('click',stepOnce);
  $('btnRestart').addEventListener('click',restart);
  $('speedSelect').addEventListener('change',()=>{ speed=parseFloat($('speedSelect').value); });
  document.querySelectorAll('.tab-btn').forEach(b=>{ if(!b.dataset.ptab) b.addEventListener('click',()=>activateTab(b.dataset.tab)); });
  activateProtocol(ORDER[0]);
}

window.SecureSim={register:register,newTrace:newTrace,start:start,COLORS:COLORS,hex:hex,b64:b64,h32:h32,esc:esc,fmtMs:fmtMs,plural:plural};
})();
