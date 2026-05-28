// ── STATE ──────────────────────────────────────────────────
let currentVendor='sonicwall', currentData=null, radarChart=null, doughnutChart=null;
let loadedVendors=[];

const VENDOR_CONFIG = {
  sonicwall:{
    note:'Certifique-se que a API está habilitada: <b>Manage &gt; API &gt; Enable SonicOS API = on</b>',
    showApiKey:false, apiKeyHint:'',
  },
  fortigate:{
    note:'Crie uma API Key em FortiGate: <b>System &gt; Administrators &gt; REST API Admin</b>. Ou use usuário/senha.',
    showApiKey:true, apiKeyHint:'FortiOS: System > Administrators > REST API Admin > Create New',
  },
  pfsense:{
    note:'Instale o plugin <b>pfSense-pkg-API</b> e habilite a API em System > API.',
    showApiKey:true, apiKeyHint:'pfSense: System > API > Generate API Key',
  },
};

const DEFAULT_VENDOR_ICONS = {
  sonicwall: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4l3 2"/></svg>',
  fortigate: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="3"/><path d="M7 8h10M7 12h10M7 16h6"/></svg>',
  pfsense: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
  default: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="3"/><path d="M7 8h10M7 12h10M7 16h6"/></svg>',
};

const VENDOR_INFO={
  sonicwall:{icon:'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4l3 2"/></svg>',name:'SonicWall',version:'SonicOS 7.x'},
  fortigate:{icon:'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="3"/><path d="M7 8h10M7 12h10M7 16h6"/></svg>',name:'FortiGate',version:'FortiOS 7.x'},
  pfsense:{icon:'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',name:'pfSense',version:'API 2.7+'}
};

// ── THEME ──────────────────────────────────────────────────
const THEMES=['dark','light','modern'];
const THEME_ICONS={dark:'☀️',light:'◈',modern:'🌙'};
(function(){
  const t=localStorage.getItem('theme')||'dark';
  document.documentElement.setAttribute('data-theme',t);
  document.addEventListener('DOMContentLoaded',()=>{
    const b=document.getElementById('themeBtn'); if(b) b.textContent=THEME_ICONS[t]||'🌙';
  });
})();
function toggleTheme(){
  const cur=document.documentElement.getAttribute('data-theme')||'dark';
  const next=THEMES[(THEMES.indexOf(cur)+1)%THEMES.length];
  document.documentElement.setAttribute('data-theme',next);
  const b=document.getElementById('themeBtn'); if(b) b.textContent=THEME_ICONS[next];
  localStorage.setItem('theme',next);
  if(currentData) renderCharts(currentData.risk);
}

// ── VENDOR LOADING ─────────────────────────────────────────
async function loadVendors(){
  try{
    const r=await fetch('/api/vendors');
    if(!r.ok) throw new Error('Failed to load vendors');
    const vendorsWithVersions=await r.json();
    
    // Process vendors to get default version info
    loadedVendors=vendorsWithVersions.map(v=>{
      const defaultVer=v.versions?.find(ver=>ver.is_default)||v.versions?.[0]||{};
      return {
        slug: v.slug,
        name: v.name,
        description: v.description||'',
        icon: v.icon||'',
        version: defaultVer.version||'',
        version_label: defaultVer.label||defaultVer.version||'',
      };
    });
    
    // Merge with static config (preserves hardcoded configs)
    loadedVendors.forEach(v=>{
      if(!VENDOR_CONFIG[v.slug]){
        VENDOR_CONFIG[v.slug]={
          note:'Vendor adicionado via admin.',
          showApiKey:true,
          apiKeyHint:'Verificar documentacao do fabricante.',
        };
      }
      if(!VENDOR_INFO[v.slug]){
        VENDOR_INFO[v.slug]={
          icon: v.icon&&v.icon.trim()?v.icon:(DEFAULT_VENDOR_ICONS[v.slug]||DEFAULT_VENDOR_ICONS.default),
          name: v.name,
          version: v.version_label||v.version||'',
        };
      }
    });
    
    // Render dropdown
    renderVendorMenu();
    
    // Select first vendor if current not in list
    if(!loadedVendors.find(v=>v.slug===currentVendor)){
      if(loadedVendors.length>0){
        selectVendor(loadedVendors[0].slug);
      }
    }
  }catch(e){
    console.warn('Could not load vendors from API, using defaults:', e);
  }
}

function renderVendorMenu(){
  const menu=document.getElementById('vendorMenu');
  if(!menu) return;
  
  if(!loadedVendors.length){
    menu.innerHTML='<div style="padding:12px;text-align:center;color:var(--muted2);font-size:.75rem">Nenhum fabricante encontrado</div>';
    return;
  }
  
  menu.innerHTML=loadedVendors.map(v=>`
    <button class="vdm-item" data-vendor="${v.slug}" onclick="selectVendor('${v.slug}')">
      <span class="vdm-icon">${v.icon&&v.icon.trim()?v.icon:(DEFAULT_VENDOR_ICONS[v.slug]||DEFAULT_VENDOR_ICONS.default)}</span>
      <div class="vdm-text">
        <span class="vdm-name">${v.name}</span>
        <span class="vdm-version">${v.version_label||v.version||''}</span>
      </div>
      <span class="vdm-check">✓</span>
    </button>
  `).join('');
  
  // Restore active state
  const activeItem=menu.querySelector(`[data-vendor="${currentVendor}"]`);
  if(activeItem) activeItem.classList.add('active');
}

function toggleVendorMenu(){
  const dropdown=document.querySelector('.vendor-dropdown');
  dropdown.classList.toggle('open');
}

function closeVendorMenu(){
  const dropdown=document.querySelector('.vendor-dropdown');
  dropdown.classList.remove('open');
}

function selectVendor(v){
  if(currentVendor===v) return;
  currentVendor=v;
  
  // Update dropdown display using dynamic VENDOR_INFO
  const info=VENDOR_INFO[v]||{icon:DEFAULT_VENDOR_ICONS.default,name:v,version:''};
  document.getElementById('vendorIcon').innerHTML=info.icon;
  document.getElementById('vendorName').textContent=info.name;
  document.getElementById('vendorVersion').textContent=info.version||'';
  
  // Update active state in menu
  document.querySelectorAll('.vdm-item').forEach(item=>{
    item.classList.remove('active');
  });
  document.querySelector(`.vdm-item[data-vendor="${v}"]`)?.classList.add('active');
  
  // Close menu
  closeVendorMenu();
  
  // Update vendor note
  const cfg=VENDOR_CONFIG[v]||{note:'Vendor configurado.',showApiKey:true,apiKeyHint:''};
  const noteEl=document.getElementById('vendorNote');
  fadeElement(noteEl,()=>{
    noteEl.innerHTML='As credenciais são usadas apenas para autenticar na API REST e <strong>não são armazenadas</strong>. '+cfg.note;
  });
  
  // Show/hide API key field
  const akRow=document.getElementById('apikeyRow');
  if(cfg.showApiKey){
    akRow.style.display='block';
    akRow.style.animation='slideDown .3s ease-out';
  }else{
    akRow.style.animation='slideUp .3s ease-out';
    setTimeout(()=>akRow.style.display='none',300);
  }
  if(cfg.showApiKey) document.getElementById('apikeyHint').textContent=cfg.apiKeyHint||'';
  
  // Clear status
  setStatus('','');
}

function fadeElement(el,callback){
  el.style.opacity='0.5';
  el.style.transition='opacity .15s';
  setTimeout(()=>{
    callback();
    el.style.opacity='1';
  },150);
}

// Close dropdown when clicking outside
document.addEventListener('click',(e)=>{
  const dropdown=document.querySelector('.vendor-dropdown');
  if(!dropdown.contains(e.target)){
    closeVendorMenu();
  }
});

// Initialize first item as active
document.querySelector('.vdm-item[data-vendor="sonicwall"]')?.classList.add('active');

// ── STATUS ────────────────────────────────────────────────
function setStatus(msg,type){
  const el=document.getElementById('statusBox');
  if(!msg){el.className='status-box';return;}
  el.className=`status-box show ${type}`;
  el.innerHTML=msg;
}

function getFields(){
  return {
    vendor:   currentVendor,
    host:     document.getElementById('fHost').value.trim(),
    port:     parseInt(document.getElementById('fPort').value)||443,
    username: document.getElementById('fUser').value.trim(),
    password: document.getElementById('fPass').value,
    api_key:  document.getElementById('fApiKey')?.value.trim()||'',
    company:  document.getElementById('fCompany').value.trim(),
  };
}

// ── TEST ──────────────────────────────────────────────────
async function testConn(){
  const f=getFields();
  if(!f.host){setStatus('Informe o IP/hostname do dispositivo.','err');return;}
  if(!f.username&&!f.api_key){setStatus('Informe usuário/senha ou API Key.','err');return;}
  setStatus('⟳ Testando conexão...','info');
  try{
    const r=await fetch('/api/test',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify(f)});
    const d=await r.json();
    setStatus(d.ok?'✓ '+d.message:'✗ '+(d.error||'Falha na conexão'),d.ok?'ok':'err');
  }catch(e){setStatus('Erro: '+e.message,'err');}
}

// ── ANALYZE ───────────────────────────────────────────────
async function runAnalysis(){
  const f=getFields();
  if(!f.host){setStatus('Informe o IP/hostname do dispositivo.','err');return;}
  if(!f.username&&!f.api_key){setStatus('Informe usuário/senha ou API Key.','err');return;}

  document.getElementById('analyzeBtn').disabled=true;
  document.getElementById('results').style.display='none';
  document.getElementById('idleState').style.display='none';
  document.getElementById('loading').style.display='block';
  setStatus('','');

  const msgs=['CONECTANDO AO DISPOSITIVO...','AUTENTICANDO...','COLETANDO CONFIGURAÇÕES...','EXECUTANDO CONTROLES CIS...','CALCULANDO SCORE DE RISCO...'];
  let mi=0;
  const iv=setInterval(()=>document.getElementById('loadingLbl').textContent=msgs[Math.min(mi++,msgs.length-1)],1800);

  try{
    const r=await fetch('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify(f)});
    clearInterval(iv);
    document.getElementById('loading').style.display='none';
    if(!r.ok){
      const e=await r.json();
      document.getElementById('analyzeBtn').disabled=false;
      setStatus('✗ '+(e.error||'Erro desconhecido'),'err');
      return;
    }
    currentData=await r.json();
    renderResults(currentData);
  }catch(e){
    clearInterval(iv);
    document.getElementById('loading').style.display='none';
    document.getElementById('analyzeBtn').disabled=false;
    setStatus('Erro: '+e.message,'err');
  }
}

function newAnalysis(){
  document.getElementById('results').style.display='none';
  document.getElementById('idleState').style.display='flex';
  document.getElementById('analyzeBtn').disabled=false;
  window.scrollTo({top:0,behavior:'smooth'});
}

// ── RENDER ────────────────────────────────────────────────
const LVLS={BAIXO:'RISCO BAIXO',MÉDIO:'RISCO MÉDIO',ALTO:'RISCO ALTO',CRÍTICO:'RISCO CRÍTICO'};

function renderResults(data){
  const r=data.risk, rc=r.risk_color||'#2a8f9e';
  document.getElementById('riskHero').style.setProperty('--rc',rc);
  const ring=document.getElementById('ringVal');
  ring.style.stroke=rc;
  setTimeout(()=>ring.style.strokeDashoffset=307.9-(r.score/100)*307.9,80);
  document.getElementById('scoreNum').textContent=r.score;
  document.getElementById('scoreNum').style.color=rc;
  document.getElementById('riskLevel').textContent=LVLS[r.risk_level]||r.risk_level;
  document.getElementById('riskLevel').style.color=rc;
  document.getElementById('riskSub').textContent=
    `${data.company} · ${data.vendor_name} · ${data.version_label} · ${new Date(data.timestamp).toLocaleString('pt-BR')}`;
  document.getElementById('stTotal').textContent=r.total_checks;
  document.getElementById('stPass').textContent=r.passed;
  document.getElementById('stFail').textContent=r.failed;
  document.getElementById('progBar').style.width=r.score+'%';
  document.getElementById('progBar').style.background=rc;

  document.getElementById('sevGrid').innerHTML=['Critical','High','Medium','Low'].map(s=>{
    const sv=r.by_severity[s]||{};
    return`<div class="sev-card ${s}"><div class="sl">${s}</div><div class="sf">${sv.fail||0}</div><div class="st">de ${sv.total||0}</div></div>`;
  }).join('');

  renderCharts(r);

  // ── Tab CIS ──────────────────────────────────────────────
  const cis=data.cis_checks||data.checks?.filter(c=>!c.cid.startsWith('FWR'))||[];
  document.getElementById('tab-cis').innerHTML=`
    <div class="checks-card" id="cisCard">
      <div class="checks-head">
        <h3 id="cisTitle">controles CIS — ${cis.length} verificações</h3>
        <div class="filter-group">
          <span class="filter-label">Status:</span>
          <select class="filter-select" id="fStatus" onchange="filterChecks()">
            <option value="all">Todos</option><option value="FAIL">Reprovado</option><option value="PASS">Aprovado</option>
          </select>
          <span class="filter-label">Sev:</span>
          <select class="filter-select" id="fSev" onchange="filterChecks()">
            <option value="all">Todas</option>
            <option value="Critical">Crítico</option><option value="High">Alto</option>
            <option value="Medium">Médio</option><option value="Low">Baixo</option>
          </select>
        </div>
      </div>
      <div id="cisList">${renderCheckList(cis)}</div>
    </div>`;

  // ── Tab Firewall Rules Security ───────────────────────────
  renderFwRulesAudit(data.rules_audit||{});

  // Reset to CIS tab
  showResultTab('cis', document.querySelector('.rtab'));

  document.getElementById('results').style.display='block';
  setTimeout(()=>document.getElementById('results').scrollIntoView({behavior:'smooth'}),80);
}

const SEV_LABELS={Critical:'Critico',High:'Alto',Medium:'Medio',Low:'Baixo'};
const SEV_ICONS={Critical:'&#9888;',High:'&#9650;',Medium:'&#9679;',Low:'&#9661;'};
const STATUS_LABELS={PASS:'Aprovado',FAIL:'Reprovado'};

function renderCheckList(checks){
  const sevOrder={Critical:0,High:1,Medium:2,Low:3};
  return [...checks].sort((a,b)=>{
    if(a.status!==b.status)return a.status==='FAIL'?-1:1;
    return sevOrder[a.severity]-sevOrder[b.severity];
  }).map(c=>{
    const curVal=c.current_value||'';
    const curDisplay=curVal.length>60?curVal.slice(0,57)+'...':curVal;
    return `
    <div class="check-item ${c.status.toLowerCase()}" data-status="${c.status}" data-sev="${c.severity}" onclick="this.classList.toggle('expanded')">
      <div class="check-left-bar ${c.severity}"></div>
      <div class="check-head">
        <div class="check-id-wrap">
          <span class="check-id">${c.cid}</span>
          <span class="sevbadge ${c.severity}">${SEV_ICONS[c.severity]} ${SEV_LABELS[c.severity]||c.severity}</span>
        </div>
        <div class="check-body">
          <div class="check-title">${c.title}</div>
          <div class="check-meta">
            <span class="check-cat">${c.category}</span>
            ${curVal?`<span class="check-cur-inline" title="${curVal}">${curDisplay}</span>`:''}
          </div>
        </div>
        <div class="check-status">
          <span class="sbadge ${c.status}">${c.status==='PASS'?'&#10003;':'&#10007;'} ${STATUS_LABELS[c.status]||c.status}</span>
          <span class="check-expand-hint">&#9660;</span>
        </div>
      </div>
      <div class="check-detail">
        <div class="det-grid">
          <div class="det-block">
            <div class="det-lbl">Descricao</div>
            <div class="det-val">${c.description}</div>
          </div>
          <div class="det-block">
            <div class="det-lbl">Resultado da verificacao</div>
            <div class="det-val">${c.detail||'Sem detalhes adicionais'}</div>
          </div>
          ${curVal?`<div class="det-block">
            <div class="det-lbl">Valor encontrado na configuracao</div>
            <div class="det-cur">${curVal}</div>
          </div>`:''}
          <div class="det-block">
            <div class="det-lbl">Recomendacao</div>
            <div class="det-rec">${c.recommendation}</div>
          </div>
        </div>
      </div>
    </div>`;
  }).join('');
}

function filterChecks(){
  const st=document.getElementById('fStatus').value;
  const sv=document.getElementById('fSev').value;
  document.querySelectorAll('#cisList .check-item').forEach(i=>{
    i.classList.toggle('hidden',(st!=='all'&&i.dataset.status!==st)||(sv!=='all'&&i.dataset.sev!==sv));
  });
}
function filterRules(){
  const sv=document.getElementById('fRuleSev').value;
  document.querySelectorAll('#rulesList .check-item').forEach(i=>{
    i.classList.toggle('hidden',sv!=='all'&&i.dataset.sev!==sv);
  });
}
function filterFwRules(){
  const sv=document.getElementById('fFwSev').value;
  const ck=document.getElementById('fFwCheck').value;
  document.querySelectorAll('#fwRulesList .fw-finding').forEach(i=>{
    const svHide=sv!=='all'&&i.dataset.sev!==sv;
    const ckHide=ck!=='all'&&i.dataset.check!==ck;
    i.classList.toggle('hidden',svHide||ckHide);
  });
}

// ── RESULT TABS ──────────────────────────────────────────────
function showResultTab(id, el){
  ['cis','fw-rules'].forEach(t=>{
    const el2=document.getElementById('tab-'+t);
    if(el2)el2.style.display='none';
  });
  document.querySelectorAll('.rtab').forEach(b=>b.classList.remove('active'));
  const tab=document.getElementById('tab-'+id);
  if(tab)tab.style.display='block';
  if(el)el.classList.add('active');
}

// ── FIREWALL RULES AUDIT TAB ──────────────────────────────
const SEV_COLORS={Critical:'#ef4444',High:'#f87171',Medium:'#fbbf24',Low:'#38bbd0'};
const SEV_BG={Critical:'rgba(239,68,68,.08)',High:'rgba(248,113,113,.06)',Medium:'rgba(251,191,36,.06)',Low:'rgba(56,187,208,.06)'};

function renderFwRulesAudit(audit){
  if(!audit||audit.error||!audit.vendor){
    document.getElementById('fwRulesTitle').textContent='segurança de regras — dados não disponíveis';
    document.getElementById('fwCounters').innerHTML='<div style="padding:16px;color:var(--muted2);font-size:.8rem">Sem dados de auditoria de regras.</div>';
    document.getElementById('fwRulesList').innerHTML='';
    return;
  }

  const findings=audit.findings||[];
  const counters=audit.counters||{};
  const vname={sonicwall:'SonicWall',fortigate:'FortiGate',pfsense:'pfSense'}[audit.vendor]||audit.vendor;
  document.getElementById('fwRulesTitle').textContent=
    `segurança de regras — ${vname} · ${findings.length} problema(s) · ${audit.allow_rules||0} regras ALLOW`;

  // Severity counters
  const bySev={Critical:0,High:0,Medium:0,Low:0};
  findings.forEach(f=>{if(bySev[f.severity]!==undefined)bySev[f.severity]++;});

  // Vendor-specific counter labels
  const counterDefs={
    sonicwall:[
      ['dpi_disabled','DPI Desabilitado','#ef4444'],
      ['risky_ports','Portas Perigosas','#f87171'],
      ['no_profiles','Sem Perfis','#fbbf24'],
      ['any_source','Origem ANY','#fb923c'],
      ['no_logging','Sem Logging','#38bbd0'],
      ['unused','Sem Uso','#6b7280'],
    ],
    fortigate:[
      ['no_profiles','Sem Perfis','#ef4444'],
      ['risky_ports','Portas Perigosas','#f87171'],
      ['any_source','Origem ALL','#fb923c'],
      ['no_logging','Sem Logging','#38bbd0'],
      ['unused','Sem Uso/Desab.','#6b7280'],
    ],
    pfsense:[
      ['risky_ports','Portas Perigosas','#ef4444'],
      ['any_source','Origem ANY','#fb923c'],
      ['no_logging','Sem Logging','#38bbd0'],
      ['unused','Desabilitadas','#6b7280'],
    ],
  };
  const defs=counterDefs[audit.vendor]||[];
  document.getElementById('fwCounters').innerHTML=
    `<div style="display:flex;gap:10px;flex-wrap:wrap;padding:4px 0 14px">
      ${defs.map(([k,label,color])=>`
        <div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px 16px;text-align:center;min-width:90px">
          <div style="font-size:1.5rem;font-weight:700;color:${color}">${counters[k]||0}</div>
          <div style="font-size:.65rem;color:var(--muted2);margin-top:2px;white-space:nowrap">${label}</div>
        </div>`).join('')}
      <div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px 16px;text-align:center;min-width:90px">
        <div style="font-size:1.5rem;font-weight:700;color:var(--text)">${audit.total_rules||0}</div>
        <div style="font-size:.65rem;color:var(--muted2);margin-top:2px">Total Regras</div>
      </div>
    </div>`;

  // Populate check type filter
  const checkTypes=[...new Set(findings.map(f=>f.check))];
  const fck=document.getElementById('fFwCheck');
  fck.innerHTML='<option value="all">Todos os tipos</option>'+
    checkTypes.map(t=>`<option value="${t}">${t}</option>`).join('');

  if(!findings.length){
    document.getElementById('fwRulesList').innerHTML=
      `<div style="padding:24px;text-align:center;color:var(--pass);font-size:.9rem">&#10003; Nenhum problema encontrado nas regras de firewall!</div>`;
    return;
  }

  document.getElementById('fwRulesList').innerHTML=findings.map(f=>`
    <div class="fw-finding" data-sev="${f.severity}" data-check="${f.check}"
         style="display:flex;gap:0;border:1px solid var(--border);border-radius:8px;margin-bottom:8px;overflow:hidden;background:${SEV_BG[f.severity]||'transparent'}">
      <div style="width:4px;flex-shrink:0;background:${SEV_COLORS[f.severity]||'#6b7280'}"></div>
      <div style="padding:10px 14px;flex:1;min-width:0">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap">
          <span style="font-size:.65rem;font-weight:700;padding:2px 7px;border-radius:4px;background:${SEV_COLORS[f.severity]||'#6b7280'}22;color:${SEV_COLORS[f.severity]||'#6b7280'}">${f.severity}</span>
          <span style="font-size:.72rem;font-weight:600;color:var(--accent2)">${f.check}</span>
          <span style="font-size:.72rem;color:var(--muted2)">→ regra:</span>
          <span style="font-size:.72rem;font-family:'IBM Plex Mono',monospace;color:var(--text)">${f.rule}</span>
        </div>
        <div style="font-size:.78rem;color:var(--text2);margin-bottom:3px">${f.detail}</div>
        <div style="font-size:.7rem;color:var(--muted2)">&#128736; ${f.recommendation}</div>
      </div>
    </div>`).join('');
}

// ── CHARTS ────────────────────────────────────────────────
function renderCharts(risk){
  if(radarChart)radarChart.destroy();
  if(doughnutChart)doughnutChart.destroy();
  const theme=document.documentElement.getAttribute('data-theme')||'dark';
  const dk=theme==='dark'||theme==='modern';
  const gc=dk?'rgba(255,255,255,.05)':'rgba(0,0,0,.07)';
  const lc=dk?'#6a7280':'#64748b';
  const cats=Object.keys(risk.by_category||{});
  if(cats.length){
    const scores=cats.map(c=>risk.by_category[c].score);
    radarChart=new Chart(document.getElementById('radarChart').getContext('2d'),{type:'radar',
      data:{labels:cats.map(c=>c.length>14?c.slice(0,13)+'…':c),
        datasets:[{data:scores,backgroundColor:'rgba(42,143,158,.1)',borderColor:'#2a8f9e',
          borderWidth:2,pointBackgroundColor:scores.map(s=>s>=85?'#34d399':s>=65?'#fbbf24':'#f87171'),
          pointRadius:4}]},
      options:{responsive:true,maintainAspectRatio:false,
        scales:{r:{min:0,max:100,grid:{color:gc},angleLines:{color:gc},
          pointLabels:{color:lc,font:{size:9,family:'IBM Plex Mono'}},
          ticks:{color:lc,backdropColor:'transparent',stepSize:25,font:{size:7}}}},
        plugins:{legend:{display:false}}}});
  }
  const fails=['Critical','High','Medium','Low']
    .map(s=>({s,v:(risk.by_severity[s]||{}).fail||0})).filter(x=>x.v>0);
  const sc={Critical:'#ef4444',High:'#f87171',Medium:'#fbbf24',Low:'#38bbd0'};
  if(fails.length){
    doughnutChart=new Chart(document.getElementById('doughnutChart').getContext('2d'),{type:'doughnut',
      data:{labels:fails.map(x=>x.s),
        datasets:[{data:fails.map(x=>x.v),backgroundColor:fails.map(x=>sc[x.s]),
          borderColor:dk?'#111518':'#fff',borderWidth:3}]},
      options:{responsive:true,maintainAspectRatio:false,cutout:'62%',
        plugins:{legend:{position:'right',labels:{color:lc,font:{size:10,family:'IBM Plex Mono'},boxWidth:12,padding:10}},
          tooltip:{callbacks:{label:ctx=>`${ctx.label}: ${ctx.parsed} falha(s)`}}}}});
  }
}

// ── EXPORT ────────────────────────────────────────────────
function downloadJSON(){
  if(!currentData)return;
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([JSON.stringify(currentData,null,2)],{type:'application/json'}));
  a.download=`cis_${currentVendor}_${new Date().toISOString().slice(0,10)}.json`;
  a.click();
}
async function exportPDF(){
  if(!currentData)return;
  try{
    const payload={...currentData, theme: document.documentElement.getAttribute('data-theme')||'dark'};
    const r=await fetch('/api/pdf',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)});
    if(!r.ok)throw new Error();
    const a=document.createElement('a');
    a.href=URL.createObjectURL(await r.blob());
    a.download=`CIS_${currentVendor.toUpperCase()}_${new Date().toISOString().slice(0,10)}.pdf`;
    a.click();
  }catch{alert('Erro ao gerar PDF.');}
}

// ── INIT ──────────────────────────────────────────────────
(async function init(){
  await loadVendors();
  if(!document.querySelector('.vdm-item.active')){
    selectVendor('sonicwall');
  }
})();
