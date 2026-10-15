/* Aba Cenário dos simuladores legados: quando o aluno altera a configuração de um cenário, em vez de
   "Nenhum cenário selecionado" mostra "Baseado em: <cenário> (modificado)", o que mudou e um botão para restaurar.
   Funciona por observação do #scenBody, então não depende do código de cada simulador. */
(function(){
  'use strict';
  var body=document.getElementById('scenBody'); if(!body) return;
  var last=null, working=false;

  var css=document.createElement('style');
  css.textContent='.scen-body .sc-badge{font-family:"IBM Plex Mono",monospace;font-size:11px;font-weight:600;color:var(--amber,#F2A65A);border:1px solid var(--amber,#F2A65A);border-radius:20px;padding:1px 8px;vertical-align:middle;letter-spacing:.04em;text-transform:uppercase}'+
    '.scen-body .sc-diff{margin:4px 0 10px;padding-left:20px}'+
    '.scen-body .sc-orig{margin-top:14px;border-top:1px solid var(--border-soft,rgba(255,255,255,.12));padding-top:10px}'+
    '.scen-body .sc-orig summary{cursor:pointer;color:var(--teal,#5FD4C0);font-weight:600}';
  document.head.appendChild(css);

  function esc(t){ return String(t).replace(/[&<>"]/g,function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]; }); }

  // Controles do painel que entram na comparação: têm id e não são a velocidade nem o inspetor.
  function controls(){
    return Array.prototype.filter.call(document.querySelectorAll('select[id],input[id]'),function(e){
      if(e.id==='speedSelect'||e.closest('#inspector')||e.closest('.play-bar')) return false;
      var t=(e.type||'').toLowerCase();
      return e.tagName==='SELECT'||t==='checkbox'||t==='number'||t==='range';
    });
  }
  function labelOf(e){
    var lab=e.closest('label')||(e.id&&document.querySelector('label[for="'+e.id+'"]')), t='';
    if(lab){
      var c=lab.cloneNode(true);
      Array.prototype.forEach.call(c.querySelectorAll('select,input,option,.info'),function(n){ n.remove(); });
      t=c.textContent;
    }
    if(!t.trim()) t=e.getAttribute('aria-label')||'';
    if(!t.trim()&&e.parentElement){ var p=e.previousElementSibling; t=p?p.textContent:''; }
    t=t.replace(/\s+/g,' ').trim().replace(/[:\s]+$/,'');
    return (t||e.id).slice(0,70);
  }
  function show(e){
    if(e.tagName==='SELECT'){ var o=e.options[e.selectedIndex]; return o?o.textContent.replace(/\s+/g,' ').trim():e.value; }
    if((e.type||'')==='checkbox') return e.checked?'sim':'não';
    return e.value;
  }
  function snapshot(){ var m={}; controls().forEach(function(e){ m[e.id]=show(e); }); return m; }
  function diffs(){
    var out=[]; if(!last) return out;
    controls().forEach(function(e){
      var was=last.snap[e.id], now=show(e);
      if(was!==undefined&&was!==now) out.push({label:labelOf(e),from:was,to:now});
    });
    return out;
  }

  function capture(){
    var main=body.querySelector('.sc-main'), title=main&&main.querySelector('.sc-title'), on=body.querySelector('.sc-link.active');
    if(!main||!title||!on) return;
    last={id:on.getAttribute('data-scen'),html:main.innerHTML,snap:snapshot()};
    // o simulador pode terminar de ajustar os campos logo depois de desenhar a aba: confirma o retrato em seguida
    var mine=last; setTimeout(function(){ if(last===mine) mine.snap=snapshot(); },0);
    setTimeout(function(){ if(last===mine&&!body.querySelector('.sc-badge')) mine.snap=snapshot(); },300);
  }
  function diffList(){
    var d=diffs();
    if(!d.length) return '<p class="sc-diff-none">Nenhum campo do painel difere do cenário: a alteração foi feita no diagrama, no terminal ou no inspetor, ou os campos já voltaram aos valores do cenário.</p>';
    return '<ul class="sc-diff">'+d.map(function(x){ return '<li><b>'+esc(x.label)+':</b> '+esc(x.from)+' &rarr; '+esc(x.to)+'</li>'; }).join('')+'</ul>';
  }
  function render(){
    var main=body.querySelector('.sc-main'), h=main&&main.querySelector('h3');
    if(!last||!h||h.textContent.indexOf('Nenhum cenário selecionado')!==0) return;
    var m=/<h3 class="sc-title">([\s\S]*?)<\/h3>/.exec(last.html), name=m?m[1]:'';
    working=true;
    main.innerHTML='<div class="sc-kicker">Baseado em</div><h3 class="sc-title">'+name+' <span class="sc-badge">modificado</span></h3>'+
      '<p>Você alterou a configuração. O texto do cenário descreve a configuração original, então o resultado desta simulação pode ser diferente: confira a aba <b>Experimento</b>. <button type="button" class="sc-restore">Restaurar o cenário</button></p>'+
      '<h4>O que mudou</h4><div class="sc-difbox">'+diffList()+'</div>'+
      '<details class="sc-orig"><summary>Ver o texto do cenário original</summary>'+last.html+'</details>';
    working=false;
    main.querySelector('.sc-restore').addEventListener('click',function(){
      var b=body.querySelector('.sc-link[data-scen="'+last.id+'"]'); if(b&&!b.disabled) b.click();
    });
  }

  new MutationObserver(function(){
    if(working) return;
    if(body.querySelector('.sc-badge')) return;
    if(body.querySelector('.sc-main .sc-title')) capture(); else render();
  }).observe(body,{childList:true,subtree:true});

  // a lista "O que mudou" acompanha as alterações seguintes, que não redesenham a aba
  function refresh(){
    setTimeout(function(){ var box=body.querySelector('.sc-difbox'); if(box&&last) box.innerHTML=diffList(); },0);
  }
  document.addEventListener('change',refresh,true);
  document.addEventListener('input',refresh,true);
})();
