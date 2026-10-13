(function(){
'use strict';
const SS=window.SecureSim, T=window.__TLS, esc=SS.esc;
const {SPROF,CPROF,hasFS,isWeakSuite,weakVer,certChecks,SNI,BROWSER_ERR}=T;

const SCENARIOS=[
  {id:'h13',sub:'handshake',g:'Handshake',label:'TLS 1.3 completo (1 RTT)',set:{},
    what:'<p>Navegador e servidor modernos. O ClientHello já leva a metade do ECDHE (key_share), e o servidor responde com o ServerHello e, <b>cifrados</b>, o certificado, a assinatura e o Finished. Depois de 1 RTT, o cliente envia a requisição HTTP.</p>'},
  {id:'h12',sub:'handshake',g:'Handshake',label:'TLS 1.2 completo (2 RTT)',set:{cProf:'intermediario',sProf:'intermediario'},
    what:'<p>Os dois lados só falam TLS 1.2. O handshake leva 2 RTT: ClientHello e ServerHello, depois a troca de chaves do cliente e o Finished. O <b>certificado trafega em claro</b>, visível a quem observa a rede.</p>'},
  {id:'hres',sub:'handshake',g:'Handshake',label:'Retomada de sessão (ticket)',set:{mode:'resume'},
    what:'<p>O navegador já visitou o site e tem um ticket (PSK) do NewSessionTicket. O ClientHello leva o ticket; o servidor dispensa certificado e assinatura. A troca ECDHE continua, então o sigilo futuro permanece.</p>'},
  {id:'hzero',sub:'handshake',g:'Handshake',label:'0-RTT e risco de replay',set:{mode:'zero'},
    what:'<p>Com 0-RTT, a requisição sai junto com o ClientHello, antes de qualquer resposta. Economiza 1 RTT, mas esses dados <b>podem ser repetidos</b> por um atacante (replay) e não têm sigilo futuro. Use só para requisições idempotentes (GET).</p>'},
  {id:'hmtls',sub:'handshake',g:'Handshake',label:'mTLS (certificado de cliente)',set:{mtls:true},
    what:'<p>O servidor envia CertificateRequest e o cliente apresenta o próprio certificado, com CertificateVerify. As duas pontas se autenticam. É comum entre serviços e em redes de confiança zero.</p>'},
  {id:'hnover',sub:'handshake',g:'Compatibilidade',label:'Sem versão em comum',set:{cProf:'legado',sProf:'moderno'},
    what:'<p>Um navegador antigo (só TLS 1.0 e 1.1) tenta falar com um servidor moderno. Não há versão em comum e o servidor responde com o alerta fatal <code>protocol_version</code>. Nada foi cifrado nem enviado.</p>'},
  {id:'hnosuite',sub:'handshake',g:'Compatibilidade',label:'Sem cifra em comum',set:{cProf:'legado',sProf:'legado',keyType:'ecdsa'},
    what:'<p>Há versão em comum, mas as únicas cifras de ambos usam troca RSA, e o certificado do servidor é ECDSA. As cifras RSA exigem chave RSA, então não há combinação e o servidor envia <code>handshake_failure</code>.</p>'},
  {id:'hlegacy',sub:'handshake',g:'Compatibilidade',label:'TLS legado sem sigilo futuro',set:{cProf:'legado',sProf:'legado',keyType:'rsa'},
    what:'<p>Os dois lados negociam TLS 1.1 com RSA e CBC. Funciona, mas o segredo viaja cifrado pela chave RSA do servidor: quem gravar o tráfego e obtiver a chave privada um dia decifra tudo (sem sigilo futuro).</p>'},
  {id:'hdown',sub:'handshake',g:'Compatibilidade',label:'Downgrade detectado',set:{downgrade:true},openAdv:true,
    what:'<p>Um equipamento no caminho remove o TLS 1.3 do ClientHello para forçar o TLS 1.2. O servidor, que suporta 1.3, responde em 1.2 mas põe o sentinela <code>DOWNGRD</code> no random. O cliente percebe e aborta com <code>illegal_parameter</code>.</p>'},
  {id:'c-ok',sub:'cert',g:'Validação',label:'Certificado válido',set:{},
    what:'<p>O navegador valida a cadeia (leaf, intermediário, raiz), as assinaturas, a validade, o nome no SAN, a revogação (OCSP grampeado) e a transparência (SCT). Todos os testes passam e o handshake segue.</p>'},
  {id:'c-exp',sub:'cert',g:'Validação',label:'Certificado expirado',set:{certState:'expired'},
    what:'<p>O certificado passou do notAfter. O navegador recusa, envia <code>certificate_expired</code> e mostra ERR_CERT_DATE_INVALID. Certificados vencem de propósito, para limitar o dano de chaves comprometidas.</p>'},
  {id:'c-name',sub:'cert',g:'Validação',label:'Nome não confere',set:{certState:'name'},
    what:'<p>O certificado é válido, mas emitido para outro nome (shop.example.net). O SNI diz <code>www.example.org</code>, e o navegador exige que o nome conste no SAN. Sem essa checagem, qualquer certificado válido serviria para qualquer site.</p>'},
  {id:'c-self',sub:'cert',g:'Validação',label:'Autoassinado (CA desconhecida)',set:{certState:'selfsigned'},
    what:'<p>O certificado é assinado por ele mesmo: nenhuma CA do repositório de confiança o garante. O navegador recusa (unknown_ca). Aceitar a exceção sem conferir o fingerprint remove a proteção contra interceptação.</p>'},
  {id:'c-chain',sub:'cert',g:'Validação',label:'Cadeia incompleta',set:{certState:'chain'},
    what:'<p>O servidor enviou só o certificado do site, sem o intermediário. Alguns clientes completam a cadeia sozinhos, mas outros não: o navegador não consegue ligar o leaf a uma raiz confiável e recusa.</p>'},
  {id:'c-rev',sub:'cert',g:'Validação',label:'Revogado (com stapling)',set:{certState:'revoked'},
    what:'<p>A CA revogou o certificado (chave comprometida). O servidor anexa a resposta OCSP "revoked" ao certificado (stapling), e o navegador a vê sem precisar consultar a CA. Conexão recusada com <code>certificate_revoked</code>.</p>'},
  {id:'c-nostaple',sub:'cert',g:'Revogação',label:'Sem stapling: consulta OCSP',set:{stapling:false},
    what:'<p>Sem stapling, o navegador pergunta à CA, por conta própria, se o certificado foi revogado. Isso gasta 1 RTT extra e <b>revela à CA qual site você visita</b>. É o motivo de o stapling ser recomendado.</p>'},
  {id:'c-revns',sub:'cert',g:'Revogação',label:'Revogado, sem stapling',set:{certState:'revoked',stapling:false},
    what:'<p>O navegador consulta a CA (OCSP) e recebe "revoked". A recusa acontece, mas depois de uma ida e volta extra e de expor o site visitado à CA.</p>'},
  {id:'w-none',sub:'web',g:'HSTS',label:'Primeiro acesso: HTTP e 301',set:{},
    what:'<p>O usuário digita só o nome do site. Sem HSTS, a primeira requisição sai em HTTP (porta 80), o servidor responde 301 para HTTPS e só então começa o TLS. Essa primeira troca em claro é a janela de exposição. Na resposta HTTPS, o servidor envia o cabeçalho HSTS.</p>'},
  {id:'w-cached',sub:'web',g:'HSTS',label:'Com HSTS em cache',set:{hsts:'cached'},
    what:'<p>O navegador lembra do cabeçalho Strict-Transport-Security de uma visita anterior. Antes de enviar qualquer pacote, ele troca http por https internamente. Nenhuma requisição HTTP sai.</p>'},
  {id:'w-preload',sub:'web',g:'HSTS',label:'HSTS preload',set:{hsts:'preload'},
    what:'<p>O domínio consta na lista de preload embutida no navegador. O HTTPS é exigido já na primeira visita, fechando a janela que o HSTS comum deixa.</p>'},
  {id:'w-nored',sub:'web',g:'Falhas comuns',label:'Sem redirecionamento',set:{redirect:false},
    what:'<p>O site tem HTTPS, mas o servidor atende HTTP sem redirecionar e não há HSTS. Quem digita o endereço sem https permanece em HTTP, em claro, embora o HTTPS exista.</p>'},
  {id:'w-nohttps',sub:'web',g:'Falhas comuns',label:'Sem HTTPS',set:{serverHttps:false},
    what:'<p>O site só existe em HTTP. Conteúdo, cookies e senhas trafegam em texto puro, sem integridade nem autenticação do servidor.</p>'}
];
const GROUP_DOC={
  'Handshake':'Como o TLS abre a conexão: versões, retomada e 0-RTT.',
  'Compatibilidade':'Versão e cifra em comum, TLS legado e a proteção contra downgrade.',
  'Validação':'O que o navegador confere em um certificado antes de confiar no servidor.',
  'Revogação':'Como o navegador descobre que um certificado foi revogado.',
  'HSTS':'Do HTTP ao HTTPS e como o HSTS fecha a janela de exposição.',
  'Falhas comuns':'Configurações que deixam o usuário exposto mesmo com certificado.'
};
const D=(short,concept,observe,msgs,why)=>({short:short,concept:concept,observe:observe,cols:['Mensagem','Função','Quem envia'],msgs:msgs,why:why});
const SCEN_DOC={
  h13:D('O handshake mais curto: 1 RTT e certificado cifrado.',
    'O <b>TLS 1.3</b> (RFC 8446) reduziu o handshake a <b>1 RTT</b>: o ClientHello já leva a metade pública do ECDHE (<b>key_share</b>). O ServerHello devolve a do servidor e, a partir daí, as duas pontas derivam as chaves de handshake com HKDF. O certificado, a assinatura (<b>CertificateVerify</b>) e o <b>Finished</b> já vão cifrados.',
    ['O SNI (nome do site) no ClientHello, em claro (aba Mensagem, marcado).','Depois do ServerHello, as setas ficam verdes com cadeado.','Na aba Chaves e sessão: segredo ECDHE e chaves de handshake e de aplicação.'],
    [['ClientHello','versões, cifras, SNI e key_share','navegador'],['ServerHello','versão, cifra e key_share','servidor'],['EncryptedExtensions, Certificate, CertificateVerify, Finished','identidade e confirmação, cifrados','servidor'],['Finished','confirma o handshake','navegador'],['Application Data','HTTP cifrado','os dois']],
    'Menos latência e menos exposição: o certificado deixa de ser visível a quem observa a rede, e só suítes com sigilo futuro existem no TLS 1.3.'),
  h12:D('Dois RTTs e o certificado trafegando em claro.',
    'No <b>TLS 1.2</b> (RFC 5246), o servidor responde com ServerHello, <b>Certificate</b> (em claro), ServerKeyExchange e ServerHelloDone. O cliente só então envia o ClientKeyExchange e o Finished: <b>2 RTT</b> até a primeira requisição. Com ECDHE há sigilo futuro; com troca RSA, não.',
    ['O Certificate aparece em claro na captura (aba Mensagem).','Dois ciclos de ida e volta antes dos dados.','O Finished e o NewSessionTicket já vão cifrados.'],
    [['ClientHello','abre a negociação','navegador'],['Certificate, ServerKeyExchange, ServerHelloDone','certificado e parâmetros ECDHE','servidor'],['ClientKeyExchange, ChangeCipherSpec, Finished','troca de chaves e confirmação','navegador'],['ChangeCipherSpec, Finished','confirmação do servidor','servidor']],
    'O TLS 1.2 ainda é muito usado. Os servidores que só o oferecem pagam mais latência e expõem o certificado e metadados.'),
  hres:D('Ticket de sessão: sem certificado, mantendo o sigilo futuro.',
    'Depois de um handshake completo, o servidor entrega um <b>NewSessionTicket</b>. Na visita seguinte, o ClientHello leva o ticket (<b>pre_shared_key</b>) e o modo <b>psk_dhe_ke</b>: o servidor dispensa Certificate e CertificateVerify, e ainda há uma troca ECDHE nova, preservando o sigilo futuro.',
    ['O ClientHello com pre_shared_key.','O voo do servidor sem Certificate nem CertificateVerify.','Estado "verificado (ticket)" no painel.'],
    [['ClientHello (pre_shared_key)','apresenta o ticket','navegador'],['ServerHello, EncryptedExtensions, Finished','aceita o ticket','servidor']],
    'Reduz CPU e tamanho do handshake. A chave de tickets do servidor precisa ser rotacionada, senão compromete o sigilo futuro.'),
  hzero:D('Dados antecipados: mais rápido, com risco de replay.',
    'No <b>0-RTT</b> (early data), o cliente envia a requisição junto do ClientHello, cifrada com a chave derivada do ticket. O servidor não consegue saber se é um envio novo ou uma <b>repetição</b> por um atacante, e esses dados não têm sigilo futuro.',
    ['A requisição sai no primeiro voo, antes do ServerHello.','O evento de aviso sobre replay.','A resposta pode sair antes do Finished do cliente (0,5 RTT).'],
    [['ClientHello + early_data','abre e já envia a requisição','navegador'],['Application Data (0-RTT)','requisição antecipada','navegador'],['Application Data (0,5-RTT)','resposta antecipada','servidor']],
    'Aceite 0-RTT apenas em requisições idempotentes (GET sem efeito colateral) e use proteção contra replay no servidor ou no CDN.'),
  hmtls:D('Cliente e servidor se autenticam com certificados.',
    'No <b>mTLS</b>, o servidor inclui <b>CertificateRequest</b> no voo cifrado. O cliente responde com o seu <b>Certificate</b> e <b>CertificateVerify</b> antes do Finished. O servidor valida o certificado do cliente contra a sua CA de clientes.',
    ['CertificateRequest no voo do servidor.','Certificate e CertificateVerify do cliente.','Estado "Cliente autenticado (mTLS)".'],
    [['CertificateRequest','pede o certificado do cliente','servidor'],['Certificate, CertificateVerify','identifica o cliente','navegador']],
    'É a base de muitas APIs internas e arquiteturas de confiança zero: o certificado de cliente substitui senhas e tokens estáticos.'),
  hnover:D('Sem versão em comum: alerta protocol_version.',
    'O servidor escolhe a maior versão suportada pelos dois. Se não houver nenhuma, responde com um alerta fatal <b>protocol_version</b> (70). Navegadores atuais não oferecem mais TLS 1.0 e 1.1, e servidores modernos os desativaram.',
    ['O ClientHello só com TLS 1.0 e 1.1.','O alerta em claro do servidor.','Nenhuma credencial ou dado foi enviado.'],
    [['ClientHello','versões antigas','navegador'],['Alert protocol_version','recusa','servidor']],
    'Desativar protocolos antigos reduz a superfície de ataque (POODLE, BEAST) ao custo de perder clientes muito velhos.'),
  hnosuite:D('Versão em comum, mas nenhuma cifra utilizável.',
    'As suítes de troca <b>RSA</b> (TLS_RSA_*) exigem certificado RSA; as ECDHE-ECDSA exigem ECDSA. Se as cifras comuns não combinam com o tipo de chave do certificado, o servidor envia <b>handshake_failure</b> (40).',
    ['A lista de cifras no ClientHello.','O alerta handshake_failure.','Mude "Chave do certificado" para RSA (Ajustes avançados) e veja funcionar.'],
    [['ClientHello','cifras RSA','navegador'],['Alert handshake_failure','sem cifra compatível','servidor']],
    'A escolha do tipo de chave do certificado também limita as cifras que o servidor consegue oferecer.'),
  hlegacy:D('TLS 1.1 com RSA e CBC: funciona, sem sigilo futuro.',
    'Na troca de chaves por <b>RSA</b>, o cliente cifra o pre-master secret com a chave pública do servidor. Como esse segredo fica protegido apenas pela chave de longo prazo do servidor, <b>quem gravar o tráfego e obtiver a chave privada um dia decifra tudo</b>. Combinado com CBC e TLS 1.1, é uma configuração obsoleta.',
    ['A marcação "sem sigilo futuro" no ClientKeyExchange.','Estado "Sigilo futuro: NÃO (RSA)".','Nota de hardening baixa na aba Configuração.'],
    [['ClientKeyExchange','pre-master secret cifrado com RSA','navegador']],
    'O sigilo futuro (ECDHE) é o que impede que um vazamento futuro da chave do servidor exponha o tráfego passado.'),
  hdown:D('A proteção do TLS 1.3 contra downgrade.',
    'Um atacante no caminho pode tentar <b>rebaixar</b> a versão removendo o TLS 1.3 do ClientHello. Para detectar isso, o servidor que suporta 1.3 mas negocia 1.2 coloca <b>DOWNGRD</b> (44 4F 57 4E 47 52 44 01) no final do random do ServerHello. O cliente que suporta 1.3 vê o sentinela e aborta com <b>illegal_parameter</b>.',
    ['O sentinela no random do ServerHello (aba Mensagem).','O alerta do cliente e o evento de downgrade.','A conexão não segue em TLS 1.2.'],
    [['ClientHello (sem 1.3)','alterado no caminho','equipamento no caminho'],['ServerHello (random com DOWNGRD)','denuncia o downgrade','servidor'],['Alert illegal_parameter','cliente aborta','navegador']],
    'Sem essa proteção, ataques de downgrade levariam o cliente a versões e cifras fracas.'),
  'c-ok':D('Sete testes antes de confiar no servidor.',
    'O navegador valida o certificado: <b>cadeia</b> até uma raiz do repositório, <b>assinaturas</b>, <b>validade</b>, <b>nome no SAN</b>, <b>uso permitido</b> (EKU), <b>revogação</b> (OCSP) e <b>Certificate Transparency</b>. Só se todos passarem o handshake continua. O CertificateVerify prova que o servidor tem a chave privada.',
    ['A aba Certificado: a cadeia e os testes.','O evento de validação no cliente.','Estado "Servidor autenticado".'],
    [['Certificate','cadeia leaf, intermediário e raiz','servidor'],['CertificateVerify','assinatura do hash da conversa','servidor']],
    'A confiança da web depende dessa validação: sem ela, qualquer um poderia se passar pelo site.'),
  'c-exp':D('Validade vencida: ERR_CERT_DATE_INVALID.',
    'Todo certificado tem <b>notBefore</b> e <b>notAfter</b>. Depois do prazo, o navegador recusa. Os prazos são curtos (hoje, até 398 dias, e a tendência é diminuir) para limitar o efeito de chaves comprometidas e forçar a automação da renovação (ACME).',
    ['O teste de validade falha na aba Certificado.','O alerta certificate_expired do cliente.','O erro mostrado ao usuário.'],
    [['Certificate','certificado vencido','servidor'],['Alert certificate_expired','recusa','navegador']],
    'Certificados expirados são uma das causas mais comuns de indisponibilidade. Automatize a renovação e monitore os prazos.'),
  'c-name':D('Certificado de outro nome: ERR_CERT_COMMON_NAME_INVALID.',
    'O navegador compara o nome acessado com a lista <b>SAN</b> do certificado (o CN é ignorado). Um certificado válido para outro nome não serve: caso contrário, qualquer certificado legítimo permitiria se passar por qualquer site.',
    ['O SAN do certificado e o nome acessado, na aba Certificado.','O teste "Nome do site na lista SAN" falha.','O alerta bad_certificate.'],
    [['Certificate','SAN não inclui o site','servidor'],['Alert bad_certificate','recusa','navegador']],
    'É a checagem que liga a chave ao nome do site: a identidade vem do SAN, validado pela CA.'),
  'c-self':D('Sem CA de confiança: ERR_CERT_AUTHORITY_INVALID.',
    'Um certificado <b>autoassinado</b> não tem emissor no repositório de confiança do navegador. O sistema de confiança da web depende de CAs: sem elas, o navegador não tem como saber se a chave pertence mesmo ao site.',
    ['O teste de cadeia falha na aba Certificado.','O alerta unknown_ca.','O que significa aceitar a exceção sem conferir o fingerprint.'],
    [['Certificate','só o próprio certificado','servidor'],['Alert unknown_ca','recusa','navegador']],
    'Em redes internas, use uma CA privada instalada nos clientes. Aceitar exceções por hábito derruba a proteção contra interceptação.'),
  'c-chain':D('Falta o certificado intermediário.',
    'O servidor deve enviar o <b>leaf</b> e os <b>intermediários</b>; a raiz já está no cliente. Se faltar o intermediário, o navegador não liga o leaf a uma raiz (<b>unable to get local issuer certificate</b>). Alguns clientes buscam o intermediário sozinhos (AIA), outros não.',
    ['A cadeia incompleta na aba Certificado.','O teste de cadeia falha.','O alerta unknown_ca.'],
    [['Certificate','só o leaf','servidor'],['Alert unknown_ca','recusa','navegador']],
    'É um erro comum de configuração: sempre sirva o "fullchain".'),
  'c-rev':D('Revogado: a CA diz que o certificado não vale mais.',
    'Quando uma chave é comprometida, a CA <b>revoga</b> o certificado. Com <b>OCSP stapling</b>, o servidor anexa a resposta assinada da CA ao certificado, e o navegador vê o status "revoked" sem consultar a CA.',
    ['O teste de revogação falha na aba Certificado.','O alerta certificate_revoked.','Nenhuma mensagem para a CA: a resposta já veio com o certificado.'],
    [['Certificate + resposta OCSP','status revoked grampeado','servidor'],['Alert certificate_revoked','recusa','navegador']],
    'A revogação só funciona se o cliente a verifica. Stapling torna isso rápido e privado.'),
  'c-nostaple':D('Sem stapling: o navegador pergunta à CA.',
    'Sem <b>OCSP stapling</b>, o navegador consulta o responder OCSP da CA em uma conexão separada (HTTP, porta 80). Isso custa <b>1 RTT</b> e <b>a CA fica sabendo qual site você visita</b>. Se o responder estiver fora do ar, o navegador costuma seguir mesmo assim (soft-fail).',
    ['A terceira coluna: a CA.','O OCSP request e a resposta "good".','A latência extra antes do Finished.'],
    [['OCSP request','pergunta se o serial foi revogado','navegador'],['OCSP response','good ou revoked','CA']],
    'Stapling e a extensão Must-Staple evitam a consulta e o vazamento de privacidade.'),
  'c-revns':D('Revogado e descoberto só depois da consulta à CA.',
    'O navegador consulta a CA, recebe <b>revoked</b> e aborta com <code>certificate_revoked</code>. O resultado é o mesmo do cenário com stapling, mas com uma ida e volta a mais e exposição do site visitado à CA.',
    ['O OCSP response "revoked".','O alerta do cliente depois da consulta.','Compare o tempo com o cenário com stapling.'],
    [['OCSP request e response','consulta e resposta revoked','navegador e CA'],['Alert certificate_revoked','recusa','navegador']],
    'Revogação em tempo real é difícil: por isso os certificados são cada vez mais curtos.'),
  'w-none':D('A primeira requisição em HTTP é a janela de exposição.',
    'Quando o usuário digita só o nome do site, o navegador tenta HTTP (porta 80). O servidor responde <b>301</b> para HTTPS, mas essa troca vai em claro: um atacante no caminho pode alterá-la ou impedir o upgrade (ataques de <i>SSL stripping</i>). O cabeçalho <b>Strict-Transport-Security</b>, recebido já em HTTPS, faz o navegador exigir HTTPS nas próximas visitas.',
    ['A requisição e o 301 em claro (aba Mensagem).','O cabeçalho HSTS na resposta HTTPS e o estado do HSTS.','O cenário "Com HSTS em cache" mostra a segunda visita.'],
    [['GET / (HTTP)','primeira requisição, em claro','navegador'],['301 Moved Permanently','redireciona para HTTPS','servidor'],['Strict-Transport-Security','ensina o navegador a exigir HTTPS','servidor']],
    'O redirecionamento sozinho não basta: HSTS (com preload) fecha a janela em que um intermediário poderia impedir o HTTPS.'),
  'w-cached':D('Segunda visita: o navegador nem tenta HTTP.',
    'Com o <b>HSTS</b> em cache, o navegador reescreve internamente http:// para https:// (307 Internal Redirect) antes de enviar qualquer pacote. Não há requisição em claro para interceptar, e os erros de certificado deixam de poder ser contornados pelo usuário.',
    ['Nenhum pacote na porta 80.','O evento de upgrade interno.','A conexão começa direto no TLS.'],
    [['(nenhuma requisição HTTP)','o navegador já sabe que o site é só HTTPS','navegador']],
    'HSTS elimina o SSL stripping para quem já visitou o site, e também torna os erros de certificado impossíveis de ignorar.'),
  'w-preload':D('A lista de preload protege até a primeira visita.',
    'O HSTS comum só protege depois da primeira visita. A <b>lista de preload</b>, embutida nos navegadores, inclui domínios que exigem HTTPS desde o início, sem depender de uma visita anterior. Para entrar, o site precisa enviar o cabeçalho com <code>includeSubDomains; preload</code> e ter HTTPS em todos os subdomínios.',
    ['Nenhum pacote HTTP, mesmo sem visita anterior.','O evento "Domínio na lista de preload".','O estado do HSTS: preload.'],
    [['(nenhuma requisição HTTP)','HTTPS exigido pela lista embutida','navegador']],
    'É a proteção mais forte do HSTS, mas difícil de desfazer: só entre se todos os subdomínios usam HTTPS.'),
  'w-nored':D('HTTPS existe, mas o usuário não é levado a ele.',
    'Sem redirecionamento e sem HSTS, quem digita o endereço sem <b>https://</b> permanece em HTTP. Ter um certificado não basta: o navegador precisa ser conduzido ao HTTPS.',
    ['A resposta 200 em HTTP, sem redirecionamento.','Os eventos de aviso.','Compare com o primeiro acesso com 301.'],
    [['GET / (HTTP)','requisição sem https','navegador'],['200 OK (HTTP)','conteúdo em claro','servidor']],
    'Configure o redirecionamento 301 e o cabeçalho HSTS em todos os hosts do domínio.'),
  'w-nohttps':D('Sem TLS: nada é cifrado nem autenticado.',
    'Um site só em <b>HTTP</b> expõe conteúdo, cookies e senhas, e permite que um intermediário altere páginas (injeção de anúncios ou de código). Navegadores marcam esses sites como "não seguros".',
    ['O cookie de sessão em claro (aba Mensagem).','Os avisos de exposição.','Nenhum TLS na linha do tempo.'],
    [['GET / (HTTP)','requisição em claro','navegador'],['200 OK (HTTP)','resposta em claro','servidor']],
    'Hoje HTTPS é o padrão mínimo: gratuito (ACME) e exigido por navegadores e APIs modernas.')
};

// ---------- Nota de hardening ----------
function grade(P){
  const S=SPROF[P.sProf], suites=S.s13.concat(S.s12);
  const it=[
    ['TLS 1.3 habilitado',S.vers.indexOf('TLS 1.3')>=0],
    ['Sem TLS 1.0 e 1.1',!S.vers.some(weakVer)],
    ['Só suítes com sigilo futuro (ECDHE ou TLS 1.3)',suites.every(hasFS)],
    ['Só cifras modernas (sem CBC e 3DES)',!suites.some(isWeakSuite)],
    ['Certificado válido, com cadeia completa e nome correto',P.certState==='valid'],
    ['OCSP stapling ligado',!!P.stapling],
    ['HSTS enviado e redirecionamento 301',!!(P.sendHsts&&P.redirect)],
    ['0-RTT desligado ou restrito',P.mode!=='zero'],
    ['HTTPS ativo (porta 443)',!!P.serverHttps]
  ];
  const ok=it.filter(x=>x[1]).length, pct=Math.round(ok/it.length*100);
  return {items:it,ok:ok,total:it.length,pct:pct,letter:pct>=85?'A':(pct>=65?'B':(pct>=45?'C':'D'))};
}
function nginx(P){
  const S=SPROF[P.sProf], vers=S.vers.map(v=>'TLSv'+v.slice(4)).join(' ');
  let s='# nginx (servidor: '+S.nome+')\nserver {\n  listen 443 ssl http2;\n  server_name www.example.org;\n  ssl_protocols '+vers+';\n';
  if(S.s12.length) s+="  ssl_ciphers '"+S.s12.join(':')+"';\n";
  if(S.s13.length) s+='  # TLS 1.3 (suítes fixas): '+S.s13.join(', ')+'\n';
  s+='  ssl_certificate     /etc/ssl/www.example.org.'+(P.certState==='chain'?'crt':'fullchain.pem')+';\n  ssl_certificate_key /etc/ssl/www.example.org.key;   # '+(P.keyType==='ecdsa'?'ECDSA P-256':'RSA 2048')+'\n  ssl_stapling '+(P.stapling?'on':'off')+';\n  ssl_stapling_verify '+(P.stapling?'on':'off')+';\n  ssl_early_data '+(P.mode==='zero'?'on':'off')+';\n'+(P.mtls?'  ssl_verify_client on;\n':'')+(P.sendHsts?'  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\n':'')+'}\n';
  s+=P.redirect?'server {\n  listen 80;\n  server_name www.example.org;\n  return 301 https://$host$request_uri;\n}':'# sem server na porta 80 redirecionando para HTTPS';
  return s;
}
function chainTable(P){
  const exp=P.certState==='expired', st=P.certState, kt=P.keyType==='ecdsa'?'ECDSA P-256':'RSA 2048';
  const leafSubj=st==='selfsigned'?'CN=www.example.org (autoassinado)':'CN=www.example.org', san=st==='name'?'shop.example.net':'www.example.org, example.org';
  const rows=[['Leaf (servidor)',leafSubj,st==='selfsigned'?'CN=www.example.org':'CN=Example CA R3',(exp?'12/03/2024 a 12/03/2025 (VENCIDO)':'01/09/2026 a 01/12/2026'),san+' | '+kt+(st==='revoked'?' | REVOGADO':'')]];
  if(st!=='selfsigned'){ rows.push(['Intermediário'+(st==='chain'?' (NÃO enviado)':''),'CN=Example CA R3','CN=Example Root CA X1','2024 a 2030','CA:TRUE, pathlen:0']); rows.push(['Raiz (no repositório de confiança)','CN=Example Root CA X1','CN=Example Root CA X1 (autoassinada)','2020 a 2040','CA:TRUE']); }
  return '<table><thead><tr><th>Certificado</th><th>Assunto</th><th>Emissor</th><th>Validade</th><th>SAN, chave e estado</th></tr></thead><tbody>'+rows.map(r=>'<tr>'+r.map((c,i)=>'<td'+(i===0?'':'')+'>'+esc(c)+'</td>').join('')+'</tr>').join('')+'</tbody></table>';
}
const KEYTAB='<h3>O que cada elemento protege</h3><table><thead><tr><th>Elemento</th><th>Para que serve</th></tr></thead><tbody>'+
  '<tr><td>Certificado e CertificateVerify</td><td>autenticar o servidor (e o cliente, no mTLS)</td></tr>'+
  '<tr><td>Par ECDHE efêmero</td><td>obter o segredo sem enviá-lo e dar sigilo futuro</td></tr>'+
  '<tr><td>Chaves de handshake</td><td>cifrar o resto do handshake (certificado inclusive, no TLS 1.3)</td></tr>'+
  '<tr><td>Chaves de aplicação</td><td>cifrar e autenticar os dados HTTP (AEAD)</td></tr>'+
  '<tr><td>Finished</td><td>garantir que ninguém alterou o handshake (anti-downgrade)</td></tr></tbody></table>';
const TABS=[
  {id:'keys',label:'Chaves e sessão',render:(tr,ctx)=>{
    const R=tr.raw.R||tr.raw.tls, now=ctx.timeAt(ctx.c);
    let h='<h3>Do ECDHE às chaves de tráfego</h3>';
    if(!R||!R.keys) return h+'<p>Esta execução terminou antes da derivação das chaves'+(R&&R.fail?' ('+({neg:'negociação de versão ou cifra',cert:'validação do certificado',downgrade:'detecção de downgrade'})[R.fail.stage]+')':'')+'. Sem chaves, nenhum dado da aplicação foi enviado.</p>'+KEYTAB;
    const k=R.keys, box=(l,v)=>'<div class="key-box">'+esc(l)+': '+v+'</div>';
    if(k.kind==='1.3'){
      h+='<p>No <b>TLS 1.3</b>, o segredo <b>ECDHE ('+esc(k.kex)+')</b> alimenta a cascata <b>HKDF</b>: Early Secret → Handshake Secret → Master Secret. Dela saem as chaves de cada fase.</p>';
      if(now<k.tHs) return h+'<p class="muted">Aguardando o ServerHello (key_share do servidor)...</p>'+KEYTAB;
      h+=box('Segredo ECDHE (calculado nas pontas, nunca enviado)',k.ecdhe)+box('Chave de handshake do cliente',k.hsC)+box('Chave de handshake do servidor',k.hsS);
      if(now<k.tApp) return h+'<p class="muted">As chaves de aplicação saem depois do Finished.</p>'+KEYTAB;
      h+=box('Chave de aplicação do cliente',k.apC)+box('Chave de aplicação do servidor',k.apS)+'<p>Cifra: <b>'+esc(R.suite)+'</b> (AEAD). Valores ilustrativos: o simulador não faz criptografia real.</p>';
    } else {
      h+='<p>No <b>TLS 1.2</b> ('+esc(R.ver)+'), o <b>pre-master secret</b> ('+esc(k.kex==='RSA'?'cifrado com a chave RSA do servidor':(k.kex==='ticket'?'recuperado do ticket':'calculado por ECDHE'))+') e os randoms geram o <b>master secret</b>, e dele o <b>key block</b> (chaves de cifra, integridade e IVs).</p>';
      if(now<k.tMs) return h+'<p class="muted">Aguardando o ClientKeyExchange e o ChangeCipherSpec...</p>'+KEYTAB;
      h+=box('Pre-master secret',k.pms)+box('Master secret (PRF com os randoms)',k.ms)+box('Key block (chaves e IVs)',k.block)+(R.fs?'':'<p><b>Sem sigilo futuro:</b> o pre-master secret viajou cifrado pela chave RSA do servidor. Quem gravar o tráfego e obtiver essa chave um dia decifra a conexão.</p>');
    }
    return h+KEYTAB;
  }},
  {id:'cert',label:'Certificado',render:(tr,ctx)=>{
    const P=ctx.P, R=tr.raw.R||tr.raw.tls, now=ctx.timeAt(ctx.c);
    let h='<h3>Cadeia de certificados do servidor</h3>'+chainTable(P);
    h+='<p>A cadeia vai de um certificado de entidade final (o do site) até uma <b>raiz</b> que o navegador já tem no seu repositório de confiança. O servidor envia o leaf e os intermediários.</p>';
    if(tr.raw.sub==='web'&&!(R&&R.cert)) return h+'<p class="muted">Nenhum certificado é apresentado nesta execução (sem TLS).</p>';
    if(!R||!R.cert) return h+'<p class="muted">O certificado ainda não foi apresentado nesta execução.</p>';
    if(now<(R.tCert||0)) return h+'<p class="muted">Aguardando o certificado do servidor...</p>';
    const cc=R.cert;
    h+='<h3>Testes do navegador</h3><table><thead><tr><th>Teste</th><th>Resultado</th><th>Detalhe</th></tr></thead><tbody>'+cc.checks.map(c=>'<tr><td>'+esc(c[0])+'</td><td><span class="'+(c[1]?'chk-ok':'chk-bad')+'">'+(c[1]?'OK':'FALHA')+'</span></td><td class="meaning">'+esc(c[2])+'</td></tr>').join('')+'</tbody></table>';
    if(R.fail&&R.fail.stage==='cert') h+='<p><b>Resultado:</b> conexão recusada. Alerta TLS <b>'+esc(R.fail.alert)+'</b>; o navegador mostra <b>'+esc(R.fail.browser)+'</b>.</p>';
    else if(cc.ok) h+='<p><b>Resultado:</b> todos os testes passaram. O servidor é quem diz ser.</p>';
    return h;
  }},
  {id:'cfg',label:'Configuração',render:(tr,ctx)=>{
    const P=ctx.P, g=grade(P);
    let h='<h3>Nota de hardening</h3><p><span class="grade '+g.letter+'">'+g.letter+'</span><b>'+g.ok+' de '+g.total+' boas práticas ('+g.pct+'%)</b></p><ul>'+g.items.map(x=>'<li><span class="'+(x[1]?'chk-ok':'chk-bad')+'">'+(x[1]?'OK':'FALTA')+'</span> '+esc(x[0])+'</li>').join('')+'</ul>'+
      '<p>A nota é didática: mede o que a configuração do painel faz ou deixa de fazer. Em produção, use o <b>SSL Labs</b>, o <b>testssl.sh</b> e o gerador de configuração da Mozilla.</p>';
    h+='<h3>Configuração do servidor (nginx)</h3><pre class="conf">'+esc(nginx(P))+'</pre>';
    return h;
  }}
];
window.__TLS.SCENARIOS=SCENARIOS; window.__TLS.GROUP_DOC=GROUP_DOC; window.__TLS.SCEN_DOC=SCEN_DOC; window.__TLS.TABS=TABS; window.__TLS.grade=grade;
})();
