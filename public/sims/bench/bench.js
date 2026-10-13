/* Bancada de trabalho dos simuladores do Simul-Net (mesmo comportamento do simulador TCP/UDP):
   botões de reprodução no topo do diagrama, quadros "Estados do protocolo" e "Configurações do simulador" na lateral,
   e quadros que podem ser destacados, movidos, redimensionados, maximizados e recolhidos.
   Duplo clique na barra ou a tecla Esc encaixam o quadro de volta; clicar em um quadro o traz para a frente. */
(function () {
  'use strict';
  var root = document.documentElement;
  try { if (window.top !== window.self) root.classList.add('embedded'); } catch (e) { root.classList.add('embedded'); }

  var mq = window.matchMedia('(min-width:961px)');
  var all = [];
  var zTop = 60;
  function clamp(v, a, b) { return Math.max(a, Math.min(b, v)); }
  function mk(t) { var b = document.createElement('button'); b.type = 'button'; b.className = 'fbtn'; b.textContent = t; return b; }

  /* ---------- quadro destacável ---------- */
  function setup(el, bar, collapsed) {
    if (!el || !bar) return;
    var isDet = el.tagName === 'DETAILS';
    var st = { floating: false, maxed: false, rect: null, prev: null, t: 0 };
    var handles = [];
    var bF = mk('Destacar'), bM = mk('Maximizar'), bC = mk('Recolher painel');
    bM.hidden = true; bF.setAttribute('aria-pressed', 'false'); bF.className += ' fpush';
    function isCol() { return isDet ? !el.open : el.classList.contains('body-collapsed'); }
    function setCol(c) { if (isDet) el.open = !c; else el.classList.toggle('body-collapsed', c); label(); }
    function label() { bC.textContent = isCol() ? 'Expandir painel' : 'Recolher painel'; bC.setAttribute('aria-expanded', String(!isCol())); }
    el.__label = label; el.__setCol = setCol;
    bC.addEventListener('click', function (e) { e.preventDefault(); e.stopPropagation(); setCol(!isCol()); });
    if (isDet) el.addEventListener('toggle', label);
    bar.appendChild(bF); bar.appendChild(bM); bar.appendChild(bC);
    if (collapsed) setCol(true); else label();

    function place(r) { el.style.left = r.left + 'px'; el.style.top = r.top + 'px'; el.style.width = r.width + 'px'; el.style.height = r.height + 'px'; el.style.right = 'auto'; el.style.bottom = 'auto'; }
    function cur() { var r = el.getBoundingClientRect(); return { left: r.left, top: r.top, width: r.width, height: r.height }; }
    function undock() {
      st.floating = false; st.maxed = false; el.classList.remove('is-floating');
      ['left', 'top', 'width', 'height', 'right', 'bottom', 'zIndex'].forEach(function (k) { el.style[k] = ''; });
      handles.forEach(function (x) { x.remove(); }); handles = [];
      bF.textContent = 'Destacar'; bF.setAttribute('aria-pressed', 'false'); bM.hidden = true; bM.textContent = 'Maximizar';
    }
    function float() {
      var r = st.rect || cur();
      if (!st.rect && el.classList.contains('tabs-panel')) { r.width = Math.round(window.innerWidth * 0.72); r.left = Math.round((window.innerWidth - r.width) / 2); r.height = Math.max(r.height, 260); r.top = window.innerHeight - r.height - 30; }
      r.width = clamp(r.width, 320, window.innerWidth - 16); r.height = clamp(r.height, 170, window.innerHeight - 16);
      r.left = clamp(r.left, 8, window.innerWidth - r.width - 8); r.top = clamp(r.top, 8, window.innerHeight - r.height - 8);
      setCol(false);
      el.classList.add('is-floating'); place(r); st.floating = true; el.style.zIndex = ++zTop;
      ['n', 's', 'e', 'w', 'ne', 'nw', 'sw', 'se'].forEach(function (d) { var h = document.createElement('div'); h.className = (d === 'se' ? 'fresize' : 'frz') + ' frz-' + d; el.appendChild(h); handles.push(h); bindResize(h, d); });
      bF.textContent = 'Encaixar'; bF.setAttribute('aria-pressed', 'true'); bM.hidden = false;
    }
    function toggle() { if (st.floating) { st.rect = cur(); undock(); } else { st.t = Date.now(); float(); } }
    el.addEventListener('pointerdown', function () { if (st.floating) el.style.zIndex = ++zTop; }, true);
    bF.addEventListener('click', function (e) { e.preventDefault(); e.stopPropagation(); toggle(); });
    bar.addEventListener('dblclick', function (e) { if (st.floating && !e.target.closest('button,select,input,a')) { e.preventDefault(); toggle(); } });
    bM.addEventListener('click', function (e) {
      e.preventDefault(); e.stopPropagation(); if (!st.floating) return;
      if (st.maxed) { place(st.prev); st.maxed = false; bM.textContent = 'Maximizar'; }
      else { st.prev = cur(); place({ left: 12, top: 12, width: window.innerWidth - 24, height: window.innerHeight - 24 }); st.maxed = true; bM.textContent = 'Restaurar'; }
    });
    bar.addEventListener('pointerdown', function (e) {
      if (!st.floating || st.maxed || e.button > 0 || e.target.closest('button,select,input,a')) return;
      var sx = e.clientX, sy = e.clientY, r = cur();
      bar.setPointerCapture(e.pointerId);
      function mv(ev) { el.style.left = clamp(r.left + ev.clientX - sx, 0, window.innerWidth - 80) + 'px'; el.style.top = clamp(r.top + ev.clientY - sy, 0, window.innerHeight - 40) + 'px'; }
      function up(ev) { bar.removeEventListener('pointermove', mv); bar.removeEventListener('pointerup', up); bar.removeEventListener('pointercancel', up); try { bar.releasePointerCapture(ev.pointerId); } catch (x) {} }
      bar.addEventListener('pointermove', mv); bar.addEventListener('pointerup', up); bar.addEventListener('pointercancel', up);
    });
    function bindResize(h, dir) {
      h.addEventListener('pointerdown', function (e) {
        if (e.button > 0) return; e.preventDefault(); e.stopPropagation();
        var sx = e.clientX, sy = e.clientY, r = cur(); h.setPointerCapture(e.pointerId); st.maxed = false; bM.textContent = 'Maximizar';
        function mv(ev){ var dx=ev.clientX-sx, dy=ev.clientY-sy, l=r.left, t=r.top, w=r.width, hh=r.height;
          if(dir.indexOf('e')>-1) w=clamp(r.width+dx,300,window.innerWidth-r.left);
          if(dir.indexOf('w')>-1){ w=clamp(r.width-dx,300,r.left+r.width); l=r.left+r.width-w; }
          if(dir.indexOf('s')>-1) hh=clamp(r.height+dy,150,window.innerHeight-r.top);
          if(dir.indexOf('n')>-1){ hh=clamp(r.height-dy,150,r.top+r.height); t=r.top+r.height-hh; }
          place({left:l,top:t,width:w,height:hh}); }
        function up(ev) { h.removeEventListener('pointermove', mv); h.removeEventListener('pointerup', up); h.removeEventListener('pointercancel', up); try { h.releasePointerCapture(ev.pointerId); } catch (x) {} }
        h.addEventListener('pointermove', mv); h.addEventListener('pointerup', up); h.addEventListener('pointercancel', up);
      });
    }
    all.push({ undock: function () { st.rect = cur(); undock(); }, isFloating: function () { return st.floating; }, time: function () { return st.t; } });
  }

  function wrapPanel(p, title) {
    var w = document.createElement('div'); w.className = 'fpanel';
    var bar = document.createElement('div'); bar.className = 'fbar';
    var t = document.createElement('span'); t.className = 'ftitle'; t.textContent = title; bar.appendChild(t);
    p.parentNode.insertBefore(w, p); w.appendChild(bar); w.appendChild(p);
    setup(w, bar);
    return w;
  }

  /* ---------- reorganização da lateral e do topo do diagrama ---------- */
  var side = document.querySelector('.side-col');
  var stage = document.querySelector('.stage-panel');
  var header = document.querySelector('.stage-header');
  var controls = side && side.querySelector('.controls');
  var inspector = side && side.querySelector('.inspector');
  var state = side && side.querySelector('.state-panel');

  if (stage && header && controls) {
    // botões de ação e velocidade: vão para o topo do diagrama, sempre visíveis
    var bar = document.createElement('div'); bar.className = 'play-bar'; bar.setAttribute('role', 'group'); bar.setAttribute('aria-label', 'Controle da simulação');
    [].slice.call(controls.children).forEach(function (k) {
      var onlyButtons = k.classList.contains('row') && k.children.length > 0 && [].every.call(k.children, function (c) { return c.tagName === 'BUTTON'; });
      if (onlyButtons) { [].slice.call(k.children).forEach(function (b) { bar.appendChild(b); }); k.remove(); }
      else if (k.tagName === 'BUTTON') { bar.appendChild(k); }
      else if (k.tagName === 'LABEL' && k.querySelector('#speedSelect')) {
        k.classList.add('speed');
        var tw = document.createTreeWalker(k, NodeFilter.SHOW_TEXT), tn;
        while ((tn = tw.nextNode())) { if (/Velocidade da anima/.test(tn.nodeValue)) { tn.nodeValue = tn.nodeValue.replace(/Velocidade da anima[cç][aã]o/, 'Velocidade'); break; } }
        bar.appendChild(k);
      }
    });
    header.insertBefore(bar, header.firstChild);
    while (controls.firstElementChild && controls.firstElementChild.classList.contains('sep')) controls.firstElementChild.remove();

    // quadro único "Configurações do simulador": explicação do passo (O que acontece) no topo e os campos abaixo
    var cfg = document.createElement('details'); cfg.className = 'panel cfg'; cfg.open = true;
    var sum = document.createElement('summary'); sum.textContent = 'Configurações do simulador'; cfg.appendChild(sum);
    controls.classList.remove('panel');
    controls.parentNode.insertBefore(cfg, controls); cfg.appendChild(controls);
    if (inspector) { inspector.classList.add('panel'); controls.insertBefore(inspector, controls.firstChild); }

    if (state) { var sw = wrapPanel(state, 'Estados do protocolo'); side.insertBefore(sw, side.firstChild); }
    setup(cfg, sum);
  }
  // zoom da topologia: 1 = ajustada ao painel; acima disso o desenho cresce e a área rola
  var svg = document.getElementById('topology'), wrap = svg && svg.closest('.stage-svg-wrap');
  if (stage && header && svg && wrap) {
    var steps = [1, 1.25, 1.5, 2, 2.5], zi = 0;
    var zb = document.createElement('div'); zb.className = 'zoom-bar'; zb.setAttribute('role', 'group'); zb.setAttribute('aria-label', 'Zoom da topologia');
    var zOut = mk('Zoom -'), zFit = mk('Ajustar'), zIn = mk('Zoom +');
    zOut.title = 'Diminuir a topologia'; zIn.title = 'Aumentar a topologia'; zFit.title = 'Ajustar a topologia ao painel';
    [zOut, zFit, zIn].forEach(function (b) { zb.appendChild(b); });
    var applyZoom = function () {
      if (steps[zi] === 1) { svg.style.removeProperty('height'); svg.style.removeProperty('min-height'); }
      else { var h = Math.round(wrap.clientHeight * steps[zi]); svg.style.setProperty('height', h + 'px', 'important'); svg.style.setProperty('min-height', h + 'px', 'important'); }
      zOut.disabled = zi === 0; zIn.disabled = zi === steps.length - 1; zFit.textContent = zi === 0 ? 'Ajustada' : 'Ajustar (' + Math.round(steps[zi] * 100) + '%)';
    };
    zOut.addEventListener('click', function () { if (zi > 0) { zi--; applyZoom(); } });
    zIn.addEventListener('click', function () { if (zi < steps.length - 1) { zi++; applyZoom(); } });
    zFit.addEventListener('click', function () { zi = 0; applyZoom(); });
    header.appendChild(zb); applyZoom();
    if (window.ResizeObserver) new ResizeObserver(function () { if (zi > 0) applyZoom(); }).observe(wrap);
  }
  setup(stage, header);

  /* ---------- painel inferior (abas) com alça de altura ---------- */
  var tabs = document.querySelector('.tabs-panel');
  if (tabs) {
    var grip = document.createElement('div');
    grip.className = 'tabs-grip'; grip.setAttribute('role', 'separator'); grip.setAttribute('aria-orientation', 'horizontal'); grip.tabIndex = 0;
    grip.setAttribute('aria-label', 'Ajustar a altura do painel de abas (setas para cima e para baixo)');
    tabs.insertBefore(grip, tabs.firstChild);
    setup(tabs, tabs.querySelector('.tab-bar'), window.innerHeight < 800);
    tabs.querySelectorAll('.tab-btn').forEach(function (b) { b.addEventListener('click', function () { if (tabs.classList.contains('body-collapsed')) tabs.__setCol(false); }); });
    var setH = function (h) { tabs.__setCol(false); tabs.style.setProperty('height', clamp(h, 110, window.innerHeight * 0.75) + 'px', 'important'); };
    grip.addEventListener('pointerdown', function (e) {
      if (e.button > 0) return; e.preventDefault(); var sy = e.clientY, h0 = tabs.getBoundingClientRect().height; grip.setPointerCapture(e.pointerId);
      function mv(ev) { setH(h0 + (sy - ev.clientY)); }
      function up(ev) { grip.removeEventListener('pointermove', mv); grip.removeEventListener('pointerup', up); grip.removeEventListener('pointercancel', up); try { grip.releasePointerCapture(ev.pointerId); } catch (x) {} }
      grip.addEventListener('pointermove', mv); grip.addEventListener('pointerup', up); grip.addEventListener('pointercancel', up);
    });
    grip.addEventListener('keydown', function (e) {
      var h = tabs.getBoundingClientRect().height;
      if (e.key === 'ArrowUp') { e.preventDefault(); setH(h + 30); } else if (e.key === 'ArrowDown') { e.preventDefault(); setH(h - 30); }
    });
  }

  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    var fl = all.filter(function (a) { return a.isFloating(); }).sort(function (a, b) { return b.time() - a.time(); });
    if (fl.length) fl[0].undock();
  });
  mq.addEventListener('change', function () { if (!mq.matches) all.forEach(function (a) { if (a.isFloating()) a.undock(); }); });
})();
