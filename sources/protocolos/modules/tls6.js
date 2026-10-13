(function(){
'use strict';
/* ==========================================================================
   COMPARAÇÃO HTTP x HTTPS: a mesma ação do usuário feita em HTTP (porta 80) e em HTTPS (porta 443),
   com um observador na rede, para comparar confidencialidade, integridade, autenticação e custo.
   ========================================================================== */
const SS=window.SecureSim, T=window.__TLS, C0=SS.COLORS, hex=SS.hex, esc=SS.esc, fmtMs=SS.fmtMs;
const {SNI,runTls,closeSession,toolkit}=T;
const CSTATES=[{key:'phase',label:'Fase'},{key:'chan',label:'Canal'},{key:'conf',label:'Observador lê o conteúdo?'},{key:'integ',label:'Alteração é detectada?'},{key:'host',label:'Servidor autenticado'}];
const COOKIE='sessionid=7f3a9c2e41d8b6';

const ACTIONS={
  login:{name:'login com usuário e senha',reqLabel:'POST /login',
    reqLines:['POST /login HTTP/1.1','Host: '+SNI,'Content-Type: application/x-www-form-urlencoded','Content-Length: 29','','usuario=aluno&senha=S3nh@123'],hot:[5],
    reqFields:[['Request line','POST /login HTTP/1.1',''],['Host',SNI,''],['Content-Type','application/x-www-form-urlencoded',''],['Corpo','usuario=aluno&senha=S3nh@123','usuário e senha em texto puro','expert']],
    leak:'Lê o usuário e a senha: aluno / S3nh@123',leakItems:['usuário e senha','cookie de sessão (na resposta)','todo o conteúdo da página'],
    respLines:['HTTP/1.1 200 OK','Content-Type: text/html','Set-Cookie: '+COOKIE+'; Path=/','','<html>... Bem-vindo, aluno ...</html>'],respHot:[2],
    respFields:[['Status','200 OK',''],['Set-Cookie',COOKIE+'; Path=/','cookie de sessão em claro: quem o copiar assume a sessão','expert']],
    data:'POST /login (usuário e senha no corpo)',resp:'200 OK com Set-Cookie: sessionid (Secure; HttpOnly)',respShort:'200 OK + Set-Cookie'},
  search:{name:'busca (GET com termo)',reqLabel:'GET /busca?q=resultado+do+exame',
    reqLines:['GET /busca?q=resultado+do+exame HTTP/1.1','Host: '+SNI,'User-Agent: Mozilla/5.0'],hot:[0],
    reqFields:[['Request line','GET /busca?q=resultado+do+exame HTTP/1.1','o termo pesquisado vai na URL, em claro','expert'],['Host',SNI,'']],
    leak:'Lê a URL: o que o usuário está pesquisando',leakItems:['o termo pesquisado e a URL','as páginas visitadas','todo o conteúdo da resposta'],
    respLines:['HTTP/1.1 200 OK','Content-Type: text/html','','<html>... 3 resultados ...</html>'],respHot:[3],
    respFields:[['Status','200 OK',''],['Content-Type','text/html','']],
    data:'GET /busca?q=resultado+do+exame',resp:'200 OK com os resultados da busca',respShort:'200 OK (resultados)'},
  page:{name:'página com sessão (cookie)',reqLabel:'GET /notas',
    reqLines:['GET /notas HTTP/1.1','Host: '+SNI,'Cookie: '+COOKIE],hot:[2],
    reqFields:[['Request line','GET /notas HTTP/1.1',''],['Host',SNI,''],['Cookie',COOKIE,'o cookie identifica a sessão: quem o ler pode usá-lo','expert']],
    leak:'Lê o cookie de sessão e a página',leakItems:['o cookie de sessão','a página e as notas do aluno','as páginas visitadas'],
    respLines:['HTTP/1.1 200 OK','Content-Type: text/html','','<html>... Notas do aluno ...</html>'],respHot:[3],
    respFields:[['Status','200 OK',''],['Content-Type','text/html','conteúdo pessoal em claro','expert']],
    data:'GET /notas com Cookie: sessionid',resp:'200 OK com as notas do aluno',respShort:'200 OK (notas)'}
};

function simCompare(P){
  const cols=[{key:'c',label:'Navegador',sub:'192.168.1.20',addr:'192.168.1.20'},{key:'o',label:'Observador na rede',sub:'Wi-Fi público ou provedor',addr:'192.168.1.1'},{key:'s',label:'Servidor',sub:'203.0.113.80',addr:'203.0.113.80'}];
  const tr=SS.newTrace(cols,CSTATES,P.rtt), raw=tr.raw, ow=tr.ow, A=ACTIONS[P.action]||ACTIONS.login;
  raw.sub='cmp'; raw.action=P.action; raw.tamper=!!P.tamper;
  const tcp80=(from,to,label,flags)=>tr.add(from,to,{label:label,proto:'TCP',color:C0.tcp,len:40,info:(from==='c'?'50121 → 80':'80 → 50121')+' ['+flags+']',phaseName:'HTTP',fields:[{sec:'TCP (RFC 9293)'},['Flags',flags,''],['Porta','80 (HTTP)','porta sem proteção']],about:'Segmento TCP da conexão HTTP, na porta 80.'});
  const http=(from,to,label,fields,o)=>tr.add(from,to,Object.assign({label:label,proto:'HTTP',color:C0.plain,len:260,info:label,phaseName:'HTTP',about:'',
    fields:[{sec:'HTTP (texto puro, porta 80)'}].concat(fields,[['Cifrado?','não','qualquer observador no caminho lê e pode alterar','expert']])},o));
  tr.st(0,'phase','início','warn'); tr.st(0,'chan','-','closed'); tr.st(0,'conf','-','closed'); tr.st(0,'integ','-','closed'); tr.st(0,'host','-','closed');
  tr.mile(0,'A. HTTP','porta 80');

  // ---------- A. HTTP ----------
  tr.phase('A. HTTP (porta 80, sem proteção)','http');
  const tH0=tr.t, iH0=tr.msgs.length;
  tr.st(tr.t,'phase','HTTP','warn');
  tcp80('c','s','SYN','SYN'); tcp80('s','c','SYN, ACK','SYN, ACK'); const ack=tcp80('c','s','ACK','ACK');
  tr.st(tr.t,'chan','em claro','bad');
  const req=http('c','s',A.reqLabel,A.reqFields,{info:A.reqLines[0],about:'A requisição vai em texto puro. O observador na rede lê tudo o que o navegador envia.'});
  tr.ev(req.tSend+ow/2,'o',A.leak,'warn'); tr.st(req.tSend+ow/2,'conf','SIM: tudo legível','bad');
  const rsp=http('s','c',P.tamper?A.respShort+' (+ conteúdo injetado)':A.respShort,A.respFields,{len:1200,info:'HTTP/1.1 200 OK',color:P.tamper?C0.bad:C0.plain,about:P.tamper?'A resposta foi alterada no caminho: um banner foi injetado na página. O navegador não tem como perceber.':'A resposta, também em texto puro.'});
  if(P.tamper){
    rsp.tags.push('alterada no caminho (conteúdo injetado)');
    tr.ev(rsp.tSend+ow/2,'o','Um equipamento no caminho (proxy ou Wi-Fi público) injeta um banner na página','warn');
    tr.ev(rsp.tArr,'c','Exibe a página alterada: o HTTP não permite detectar a adulteração','warn');
    tr.st(rsp.tArr,'integ','NÃO: página alterada sem aviso','bad');
  } else tr.st(rsp.tArr,'integ','não há como saber','warn');
  tr.st(rsp.tArr,'host','NÃO (qualquer um pode se passar)','bad');
  tr.lg(req.tSend,'HTTP: a requisição ('+A.name+') trafega em texto puro e o observador na rede a lê.','loss');
  tr.lg(rsp.tArr,'HTTP: a resposta chega em '+fmtMs(rsp.tArr-tH0)+' desde o SYN'+(P.tamper?', mas foi alterada no caminho sem que ninguém perceba':'')+'.','data');
  tcp80('c','s','FIN, ACK','FIN, ACK'); tcp80('s','c','FIN, ACK','FIN, ACK');
  const iH1=tr.msgs.length;
  raw.http={t0:tH0,tResp:rsp.tArr,bytes:tr.msgs.slice(iH0,iH1).reduce((a,m)=>a+m.len,0),msgs:iH1-iH0,leak:A.leakItems,rtts:1};
  tr.mile(rsp.tArr,'HTTP concluído',fmtMs(rsp.tArr-tH0));

  // ---------- B. HTTPS ----------
  tr.wait(ow);
  tr.phase('B. HTTPS (porta 443, TLS)','https');
  const tS0=tr.t, iS0=tr.msgs.length;
  tr.st(tr.t,'phase','HTTPS','warn'); tr.st(tr.t,'integ','-','closed'); tr.st(tr.t,'conf','-','closed');
  tr.mile(tr.t,'B. HTTPS','porta 443');
  T.tcp3(tr,P,true);
  tr.st(tr.t,'chan','TLS (cifrado)','est');
  const R=runTls(tr,P,{sub:'cmp',mode:'full',cert:true,hsts:false,tamper:P.tamper,req:{label:A.reqLabel,data:A.data},resp:A.resp});
  raw.R=R;
  const ms=tr.msgs;
  // o observador vê o ClientHello e depois só registros cifrados
  let seenReq=false, seenFlight=false;
  for(let i=iS0;i<ms.length;i++){
    const m=ms[i];
    if(m.label==='Client Hello'){ tr.ev(m.tSend+ow/2,'o','Vê o ClientHello: o IP e o nome do site (SNI '+SNI+'), não o conteúdo',''); }
    else if(!seenFlight&&m.from==='s'&&m.to==='c'&&/Certificate/.test(m.label)){ seenFlight=true; tr.ev(m.tSend+ow/2,'o',m.enc?'Vê um registro cifrado: nem o certificado fica visível (TLS 1.3)':'Vê o certificado do servidor em claro (TLS 1.2)',m.enc?'ok':''); }
    else if(!seenReq&&m.enc&&m.from==='c'&&/^(HTTP\/2 )?(GET|POST)/.test(m.label)){ seenReq=true; tr.ev(m.tSend+ow/2,'o','Vê só bytes cifrados ('+m.len+' B): senha, cookie e URL ficam ocultos','ok'); tr.st(m.tSend+ow/2,'conf','NÃO: só bytes cifrados','est'); }
  }
  const respM=ms.slice(iS0).filter(m=>m.from==='s'&&m.to==='c'&&/^(HTTP\/2 |HTTP\/1\.1 )200/.test(m.label)).pop();
  const tResp=respM?respM.tArr:tr.t;
  const tamperDet=R.fail&&R.fail.stage==='tamper';
  if(R.ver&&!R.fail){ tr.st(tResp,'integ','SIM: AEAD detecta alteração','est'); tr.st(tResp,'host','SIM (certificado)','est'); closeSession(tr,P,R); }
  else if(tamperDet){ tr.st(tResp,'integ','SIM: bad_record_mac','est'); tr.st(tResp,'host','SIM (certificado)','est'); }
  const iS1=tr.msgs.length;
  raw.https={t0:tS0,tResp:tResp,bytes:tr.msgs.slice(iS0,iS1).reduce((a,m)=>a+m.len,0),msgs:iS1-iS0,ver:R.ver,suite:R.suite,fs:R.fs,tampered:!!tamperDet,failed:!!(R.fail&&!tamperDet),fail:R.fail,rtts:R.ver==='TLS 1.3'?2:(R.ver?3:0)};
  if(!R.fail) tr.mile(tResp,'HTTPS concluído',fmtMs(tResp-tS0));

  // ---------- o que o observador captura ----------
  const hot=(arr,idx)=>arr.map((t,i)=>({t:0,text:t,hot:idx.indexOf(i)>=0}));
  const hl=[{t:ack.tArr,text:'TCP  SYN, SYN-ACK, ACK  (porta 80)',hot:false}];
  hot(A.reqLines,A.hot).forEach(l=>{ l.t=req.tArr; hl.push(l); });
  hl.push({t:req.tArr,text:'',hot:false});
  hot(A.respLines,A.respHot).forEach(l=>{ l.t=rsp.tArr; hl.push(l); });
  if(P.tamper) hl.splice(hl.length,0,{t:rsp.tArr,text:'<div class="oferta">Clique aqui e ganhe um prêmio</div>   <- injetado no caminho',hot:true});
  const sl=[], tcpAck=ms[iS0+2];
  sl.push({t:tcpAck?tcpAck.tArr:tS0,text:'TCP  SYN, SYN-ACK, ACK  (porta 443)',hot:false});
  for(let i=iS0+3;i<ms.length;i++){
    const m=ms[i]; if(m.proto==='TCP') continue;
    if(m.label==='Client Hello') sl.push({t:m.tArr,text:'TLS Client Hello   SNI='+SNI+'   (em claro: o nome do site)',hot:false});
    else if(m.label==='Server Hello') sl.push({t:m.tArr,text:'TLS Server Hello   '+(R.ver||'')+', '+(R.suite||''),hot:false});
    else if(!m.enc&&/Certificate/.test(m.label)) sl.push({t:m.tArr,text:'TLS Certificate (em claro: '+SNI+')',hot:false});
    else if(m.enc){
      const sz=m.len-40, hx=hex('rec'+i+P.action,12).replace(/(..)/g,'$1 ').trim();
      const tag=/^(HTTP\/2 |HTTP\/1\.1 )?(GET|POST)/.test(m.label)||/^HTTP\/2 (GET|POST)/.test(m.label)?'   <- pedido (ilegível)':(/^(HTTP\/2 |HTTP\/1\.1 )200/.test(m.label)?'   <- resposta (ilegível)'+(/alterada/.test(m.label)?', ALTERADA: a tag não confere':''):(/Alert/.test(m.label)?'   <- alerta':''));
      sl.push({t:m.tArr,text:'17 03 03 '+(sz>>8).toString(16).padStart(2,'0')+' '+(sz&255).toString(16).padStart(2,'0')+'  '+hx+' ...  ('+sz+' B, cifrado)'+tag,hot:false,bad:/alterada/.test(m.label)});
    }
  }
  raw.dump={http:hl,https:sl};
  return tr;
}
T.simCompare=simCompare;

// ---------- Abas da comparação ----------
function nowMs(ctx){ return ctx.timeAt(ctx.c); }
const TAB_OBS={id:'obs',label:'O que o observador vê',subs:['cmp'],render:(tr,ctx)=>{
  const r=tr.raw, now=nowMs(ctx);
  if(!r.dump) return '';
  const view=(lines)=>lines.filter(l=>l.t<=now).map(l=>(l.hot||l.bad)?'<span class="chk-bad">'+esc(l.text)+'</span>':esc(l.text)).join('\n')||'(aguardando)';
  let h='<h3>Captura de quem está no meio do caminho (Wi-Fi público, provedor, proxy)</h3>';
  h+='<div class="cfg-two"><div><h3>HTTP (porta 80)</h3><pre class="conf">'+view(r.dump.http)+'</pre></div><div><h3>HTTPS (porta 443)</h3><pre class="conf">'+view(r.dump.https)+'</pre></div></div>';
  h+='<h3>O que o observador consegue concluir</h3><div class="cfg-two"><div><ul>'+r.http.leak.map(x=>'<li><span class="chk-bad">LÊ</span> '+esc(x)+'</li>').join('')+'<li><span class="chk-bad">ALTERA</span> o conteúdo da resposta sem ser notado</li><li><span class="chk-bad">SE PASSA</span> pelo servidor: não há autenticação</li></ul></div>'+
    '<div><ul><li><span class="chk-ok">VÊ</span> o IP do servidor e o nome do site (SNI)</li><li><span class="chk-ok">VÊ</span> a quantidade e o tamanho dos registros e quando ocorrem</li><li><span class="chk-ok">NÃO LÊ</span> senha, cookie, URL completa nem a página</li><li><span class="chk-ok">NÃO ALTERA</span> sem ser detectado (AEAD)</li><li><span class="chk-ok">NÃO SE PASSA</span> pelo servidor sem um certificado válido</li></ul></div></div>';
  h+='<p>Em HTTPS o observador ainda aprende <b>quem fala com quem e quanto</b> (metadados). O conteúdo, os cookies e a senha ficam protegidos.</p>';
  return h;
}};
const TAB_CMP={id:'cmpx',label:'Comparação',subs:['cmp'],render:(tr,ctx)=>{
  const r=tr.raw, now=nowMs(ctx);
  if(!r.http) return '';
  const H=r.http, S=r.https, R=r.R;
  let h='<h3>HTTP x HTTPS na mesma rede e com a mesma ação</h3>';
  if(now<S.tResp-0.001) return h+'<p class="muted">A tabela é preenchida quando as duas execuções terminam. Clique em Simular ou avance com Passo.</p>';
  const dH=H.tResp-H.t0, dS=S.tResp-S.t0, extra=dS-dH, rtt=ctx.P.rtt;
  const row=(a,b,c,bad)=>'<tr><td>'+a+'</td><td>'+b+'</td><td>'+c+'</td></tr>';
  h+='<table><thead><tr><th>Aspecto</th><th>HTTP (porta 80)</th><th>HTTPS (porta 443)</th></tr></thead><tbody>';
  h+=row('Idas e voltas até o pedido','1 RTT (só o TCP)',S.ver?(S.ver==='TLS 1.3'?'2 RTT (TCP + TLS 1.3)':'3 RTT (TCP + '+esc(S.ver)+')'):'(handshake não concluído)');
  h+=row('Tempo até a resposta chegar',fmtMs(dH),S.tampered?fmtMs(dS)+' (resposta descartada)':fmtMs(dS)+' (<b>+'+fmtMs(extra)+'</b>, cerca de +'+(Math.round(extra/rtt*10)/10).toString().replace('.',',')+' RTT)');
  h+=row('Bytes na rede (aprox.)',H.bytes+' B',S.bytes+' B (+'+Math.round((S.bytes/H.bytes-1)*100)+'%, handshake e registros)');
  h+=row('Mensagens trocadas',H.msgs,S.msgs);
  h+=row('Confidencialidade','<span class="chk-bad">nenhuma</span>: qualquer um no caminho lê','<span class="chk-ok">cifrada</span> ('+esc(S.suite||'-')+')');
  h+=row('Integridade','<span class="chk-bad">nenhuma</span>: o conteúdo pode ser alterado','<span class="chk-ok">AEAD</span>: qualquer alteração é detectada');
  h+=row('Autenticação do servidor','<span class="chk-bad">nenhuma</span>: qualquer um pode se passar pelo site','<span class="chk-ok">certificado X.509</span> validado pelo navegador');
  h+=row('Sigilo futuro','não se aplica',S.fs?'<span class="chk-ok">sim</span> (ECDHE)':'<span class="chk-bad">não</span> (troca RSA)');
  h+=row('O observador lê',H.leak.map(esc).join('; '),'só IP, SNI, tamanhos e tempos');
  h+=row('Com adulteração no caminho',r.tamper?'<span class="chk-bad">página alterada e exibida sem aviso</span>':'(ative "Equipamento no caminho altera a página")',r.tamper?'<span class="chk-ok">detectada</span>: conexão encerrada (bad_record_mac)':'(ative a adulteração para ver)');
  h+='</tbody></table>';
  h+='<p><b>Resumo:</b> o HTTPS custa '+(S.tampered?'um handshake':'<b>'+fmtMs(extra)+'</b> a mais na primeira resposta')+' (em conexões reutilizadas, na retomada ou no TLS 1.3 esse custo é pequeno) e, em troca, entrega confidencialidade, integridade e autenticação do servidor. O HTTP não entrega nenhuma das três.</p>';
  return h;
}};
T.TABS.unshift(TAB_CMP); T.TABS.unshift(TAB_OBS);

// ---------- Cenários ----------
const COMP=[
  {id:'k-login',sub:'cmp',g:'HTTP x HTTPS',label:'Login: senha em claro x cifrada',set:{action:'login'},
    what:'<p>O usuário faz login: um POST com usuário e senha e uma resposta com o cookie de sessão. Em HTTP, um observador na rede lê a senha e o cookie. Em HTTPS, só vê registros cifrados.</p>'},
  {id:'k-search',sub:'cmp',g:'HTTP x HTTPS',label:'Busca: o termo vai na URL',set:{action:'search'},
    what:'<p>Uma busca com o termo na URL. Em HTTP, o observador sabe exatamente o que o usuário pesquisou. Em HTTPS, ele só sabe qual site foi acessado (pelo SNI).</p>'},
  {id:'k-page',sub:'cmp',g:'HTTP x HTTPS',label:'Página com cookie de sessão',set:{action:'page'},
    what:'<p>Uma página pessoal acessada com o cookie de sessão. Em HTTP, o cookie e a página trafegam em claro, e quem copia o cookie assume a sessão. Em HTTPS, ficam protegidos.</p>'},
  {id:'k-tamper',sub:'cmp',g:'Integridade',label:'Conteúdo alterado no caminho',set:{action:'page',tamper:true},
    what:'<p>Um equipamento no caminho (proxy ou Wi-Fi público) injeta um banner na resposta. Em HTTP, a página alterada é exibida sem aviso. Em HTTPS, o registro alterado falha na verificação de autenticidade e o navegador encerra a conexão (<code>bad_record_mac</code>).</p>'},
  {id:'k-tls12',sub:'cmp',g:'Custo',label:'Custo do HTTPS com TLS 1.2',set:{action:'login',cProf:'intermediario',sProf:'intermediario',rtt:100},
    what:'<p>Com TLS 1.2, o HTTPS precisa de 3 RTT até a requisição (TCP e dois do TLS). Com RTT de 100 ms, a diferença para o HTTP fica bem visível na tabela de comparação.</p>'},
  {id:'k-rtt',sub:'cmp',g:'Custo',label:'Custo em RTT alto (TLS 1.3)',set:{action:'login',rtt:200},
    what:'<p>Com RTT de 200 ms, o TLS 1.3 acrescenta 1 RTT (200 ms) ao HTTP. É o preço da proteção, e diminui com conexões reutilizadas, retomada de sessão e HTTP/3.</p>'}
];
T.SCENARIOS.push(...COMP);
Object.assign(T.GROUP_DOC,{'HTTP x HTTPS':'A mesma ação do usuário em HTTP e em HTTPS, com um observador na rede.','Integridade':'O que acontece quando um equipamento no caminho altera a resposta.','Custo':'O que o HTTPS acrescenta em tempo e em bytes.'});
const D=(short,concept,observe,msgs,why)=>({short:short,concept:concept,observe:observe,cols:['Mensagem','Função','Quem envia'],msgs:msgs,why:why});
Object.assign(T.SCEN_DOC,{
  'k-login':D('A senha viaja em texto puro no HTTP e cifrada no HTTPS.',
    'O <b>HTTP</b> não tem proteção: o corpo do POST (usuário e senha) e o <b>cookie de sessão</b> da resposta trafegam em texto puro, e qualquer equipamento no caminho os lê. No <b>HTTPS</b>, o mesmo POST vai dentro do TLS: o observador vê só registros cifrados, além do IP e do nome do site (SNI).',
    ['As duas metades do diagrama, uma abaixo da outra: A (HTTP) e B (HTTPS).','A aba "O que o observador vê": a captura de cada lado, com a senha destacada em vermelho no HTTP.','A aba "Comparação": tempo, bytes, confidencialidade, integridade e autenticação.'],
    [['POST /login (HTTP)','usuário e senha em texto puro','navegador'],['200 OK + Set-Cookie (HTTP)','cookie de sessão em claro','servidor'],['Application Data (HTTPS)','o mesmo POST, cifrado','navegador']],
    'É a razão pela qual formulários de login, APIs e qualquer página com sessão precisam de HTTPS: a senha e o cookie são exatamente o que um observador quer capturar.'),
  'k-search':D('A URL e o termo pesquisado ficam expostos no HTTP.',
    'A URL, incluindo a <b>query string</b>, vai no cabeçalho da requisição. Em HTTP, o observador lê o que o usuário pesquisa e quais páginas visita. Em HTTPS, a URL fica dentro do canal cifrado; só o <b>nome do site</b> (SNI) e o IP aparecem.',
    ['A linha "GET /busca?q=..." em vermelho na captura HTTP.','No HTTPS, o SNI no ClientHello e nada da URL.','A linha "O observador lê" na aba Comparação.'],
    [['GET /busca?q=... (HTTP)','termo na URL, em claro','navegador'],['ClientHello (HTTPS)','SNI visível; URL oculta','navegador']],
    'Metadados também importam: o HTTPS protege o conteúdo e a URL, mas o SNI ainda revela o site (o ECH esconderia).'),
  'k-page':D('O cookie de sessão em claro permite assumir a sessão.',
    'O <b>cookie de sessão</b> identifica o usuário já autenticado. Em HTTP, ele trafega em claro e quem o copia pode usar a sessão do usuário (<i>session hijacking</i>). Em HTTPS, o cookie vai cifrado, e os atributos <code>Secure</code> e <code>HttpOnly</code> reforçam a proteção.',
    ['O cabeçalho Cookie destacado na captura HTTP.','No HTTPS, o pedido e a resposta como "Application Data".','Estado "Observador lê o conteúdo?" no painel lateral.'],
    [['GET /notas + Cookie (HTTP)','cookie em claro','navegador'],['Application Data (HTTPS)','pedido cifrado','navegador']],
    'Cookies de sessão sem HTTPS são uma das falhas mais antigas e ainda comuns. O atributo Secure impede o envio do cookie por HTTP.'),
  'k-tamper':D('O HTTPS não só esconde, também detecta a alteração.',
    'A <b>integridade</b> é diferente da confidencialidade. Em HTTP, um equipamento no caminho pode <b>alterar</b> a resposta (injetar anúncios ou código) e o navegador a exibe sem perceber. No HTTPS, cada registro tem uma <b>tag de autenticação</b> (AEAD): um registro alterado falha na verificação, é descartado e a conexão termina com <code>bad_record_mac</code>.',
    ['A seta vermelha da resposta alterada em HTTP e em HTTPS.','O evento do cliente: "Exibe a página alterada" contra "Tag de autenticação inválida".','A linha de cada captura marcada como alterada.'],
    [['Resposta alterada (HTTP)','banner injetado, exibido sem aviso','equipamento no caminho'],['Registro alterado (HTTPS)','tag AEAD não confere','equipamento no caminho'],['Alert bad_record_mac','cliente encerra a conexão','navegador']],
    'Isso impede a injeção de anúncios, de código e de conteúdo falso por provedores e redes Wi-Fi públicas, e protege também o conteúdo "público".'),
  'k-tls12':D('Com TLS 1.2, o HTTPS acrescenta 2 RTT ao TCP.',
    'O HTTPS tem custo: o <b>handshake TLS</b> acontece antes da primeira requisição. O TLS 1.3 gasta 1 RTT (total de 2 com o TCP); o TLS 1.2 gasta 2 (total de 3). O HTTP gasta só o do TCP. Em RTT alto, a diferença é perceptível na tabela.',
    ['A linha "Idas e voltas até o pedido" (3 RTT contra 1).','A linha "Tempo até a resposta": a diferença em ms.','Os bytes extras do handshake e do certificado.'],
    [['ClientHello e ServerHello','negociação','navegador e servidor'],['ClientKeyExchange e Finished','troca de chaves e confirmação','navegador']],
    'Para diminuir o custo: TLS 1.3, retomada de sessão, conexões persistentes (keep-alive) e HTTP/2 ou HTTP/3.'),
  'k-rtt':D('O preço do HTTPS cai com conexões reutilizadas.',
    'Em enlaces de RTT alto, o 1 RTT extra do TLS 1.3 fica evidente (200 ms nesta configuração). Na prática, o custo é <b>pago uma vez por conexão</b>: com keep-alive, HTTP/2 e retomada de sessão, as requisições seguintes não repetem o handshake.',
    ['A diferença de tempo na aba Comparação (cerca de +1 RTT).','Compare com o cenário do TLS 1.2.','Retomada e 0-RTT no modo Handshake TLS.'],
    [['Handshake TLS 1.3','1 RTT além do TCP','navegador e servidor']],
    'O custo do HTTPS é pequeno frente ao benefício, e desaparece quase por completo com conexões reutilizadas.')
});
})();
