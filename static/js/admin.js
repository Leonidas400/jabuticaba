// ── STATE ──────────────────────────────────────────────────
let allVendors = [], allApiChecks = [], currentVendorSlug = null, editingCheckId = null, editingVendorSlug = null, currentRulesVendorSlug = null, editingRuleId = null, allRules = [];

// ── THEME ──────────────────────────────────────────────────
const THEMES = ['dark', 'light', 'modern'];
const THEME_LABELS = { dark: '☀️ Claro', light: '◈ Moderno', modern: '🌙 Escuro' };

(function () {
  const t = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', t);
  document.addEventListener('DOMContentLoaded', () => {
    const b = document.getElementById('themeBtn');
    if (b) b.textContent = THEME_LABELS[t];
  });
})();
function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme') || 'dark';
  const idx = THEMES.indexOf(cur);
  const next = THEMES[(idx + 1) % THEMES.length];
  document.documentElement.setAttribute('data-theme', next);
  document.getElementById('themeBtn').textContent = THEME_LABELS[next];
  localStorage.setItem('theme', next);
}

// ── TOAST ──────────────────────────────────────────────────
function toast(msg, type = 'ok') {
  const t = document.getElementById('toastEl');
  t.textContent = msg; t.className = `toast ${type} show`;
  setTimeout(() => t.classList.remove('show'), 3000);
}

// ── AUTH ───────────────────────────────────────────────────
async function checkAuth() {
  const r = await fetch('/api/admin/auth-check');
  const d = await r.json();
  if (d.authenticated) showAdmin();
  else document.getElementById('loginScreen').classList.add('show');
}
async function doLogin() {
  const pw = document.getElementById('loginPw').value;
  const r = await fetch('/api/admin/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: pw }) });
  const d = await r.json();
  if (d.ok) { document.getElementById('loginScreen').classList.remove('show'); showAdmin(); }
  else document.getElementById('loginErr').textContent = d.error || 'Senha incorreta';
}
async function doLogout() {
  await fetch('/api/admin/logout', { method: 'POST' });
  document.getElementById('loginScreen').classList.add('show');
  document.getElementById('adminLayout').style.display = 'none';
  document.getElementById('loginPw').value = '';
}
function showAdmin() {
  document.getElementById('adminLayout').style.display = 'grid';
  loadDashboard();
  loadVendors();
  loadEndpointsAndVendors();
  updateVendorSelect();
}

// ── NAV ────────────────────────────────────────────────────
function showPage(id, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.sb-item').forEach(b => b.classList.remove('active'));
  document.getElementById('page-' + id).classList.add('active');
  if (el) el.classList.add('active');
  const fns = {
    dashboard: loadDashboard,
    checks: loadChecksPage,
    weights: loadWeights,
    endpoints: loadEndpointsAndVendors,
    rules: loadRulesPage,
    security: () => {},
    history: loadHistory,
  };
  fns[id]?.();
}

// ── DASHBOARD ──────────────────────────────────────────────
async function loadDashboard() {
  const r = await fetch('/api/admin/stats'); const d = await r.json();
  const colors = ['#2a8f9e', '#fbbf24', '#34d399', '#38bbd0'];
  const labels = ['Fabricantes', 'Controles API', 'Controles Config', 'Analises'];
  const vals = [d.vendors, d.api_checks, d.checks, d.analyses];
  document.getElementById('statsGrid').innerHTML = vals.map((v, i) =>
    `<div class="stat-card"><div class="sv" style="color:${colors[i]}">${v}</div><div class="sl">${labels[i]}</div></div>`
  ).join('');
  document.getElementById('histDash').innerHTML = (d.history || []).map(h => `<tr>
    <td><b>${h.company || '—'}</b></td>
    <td>${(h.vendor_slug || '').toUpperCase()}</td>
    <td><b style="color:${sc(h.score)}">${h.score}</b></td>
    <td><span class="badge ${h.risk_level}">${h.risk_level}</span></td>
    <td style="color:var(--pass)">${h.passed}</td>
    <td style="color:var(--fail)">${h.failed}</td>
    <td style="font-size:.72rem;color:var(--muted2)">${new Date(h.created_at).toLocaleString('pt-BR')}</td>
  </tr>`).join('') || '<tr><td colspan="7" style="text-align:center;color:var(--muted2);padding:22px">Nenhuma analise ainda</td></tr>';
}
function sc(s) { return s >= 85 ? '#34d399' : s >= 65 ? '#fbbf24' : s >= 40 ? '#f87171' : '#ef4444'; }

// ── VENDORS ────────────────────────────────────────────────
async function loadVendors() {
  const r = await fetch('/api/vendors');
  allVendors = await r.json();
  renderChecksVendorTabs();
  updateVendorSelect();
}

// ── CHECKS PAGE (API-driven, uses api_checks table) ────────
function loadChecksPage() {
  if (!allVendors.length) { loadVendors().then(() => loadChecksPage()); return; }
  renderChecksVendorTabs();
  if (!currentVendorSlug && allVendors[0]) {
    selectChecksVendor(allVendors[0].slug);
  } else if (currentVendorSlug) {
    loadApiChecks(currentVendorSlug);
  }
}

function renderChecksVendorTabs() {
  const el = document.getElementById('checksVendorTabs');
  if (!el) return;
  el.innerHTML = allVendors.map(v =>
    `<button class="cvtab ${v.slug === currentVendorSlug ? 'active' : ''}" onclick="selectChecksVendor('${v.slug}')">
      ${v.icon || ''} ${v.name}
    </button>`
  ).join('');
}

function selectChecksVendor(slug) {
  currentVendorSlug = slug;
  document.querySelectorAll('.cvtab').forEach(b => {
    const v = allVendors.find(v => v.slug === slug);
    b.classList.toggle('active', v && b.textContent.includes(v.name));
  });
  loadApiChecks(slug);
}

async function loadApiChecks(slug) {
  currentVendorSlug = slug;
  const r = await fetch(`/api/admin/api-checks?vendor=${slug}`);
  allApiChecks = await r.json();
  renderChecksTable(allApiChecks);
  renderCheckCounters(allApiChecks);
}

function renderCheckCounters(checks) {
  const total = checks.length;
  const active = checks.filter(c => c.active).length;
  const byS = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  checks.forEach(c => { if (byS[c.severity] !== undefined) byS[c.severity]++; });
  document.getElementById('checkCounters').innerHTML = `
    <div class="counter-pill">${total} total</div>
    <div class="counter-pill active">${active} ativos</div>
    <div class="counter-pill crit">${byS.Critical} Critical</div>
    <div class="counter-pill high">${byS.High} High</div>
    <div class="counter-pill med">${byS.Medium} Medium</div>
    <div class="counter-pill low">${byS.Low} Low</div>
  `;
}

const OP_LABELS = {
  is_true: 'verdadeiro', is_false: 'falso', lte: '≤ valor',
  gte: '≥ valor', str_eq: 'texto igual', list_not_empty: 'lista não vazia', handler: 'handler Python'
};

function renderChecksTable(checks) {
  const tbody = document.getElementById('checksBody');
  const empty = document.getElementById('checksEmpty');
  if (!checks.length) { tbody.innerHTML = ''; empty.style.display = 'block'; return; }
  empty.style.display = 'none';
  tbody.innerHTML = checks.map(c => `<tr id="chk-${c.id}">
    <td><span style="font-family:'IBM Plex Mono',monospace;font-size:.7rem;font-weight:600">${c.cid}</span></td>
    <td style="max-width:220px">
      <div style="font-size:.82rem;font-weight:500">${c.title}</div>
      ${c.description ? `<div style="font-size:.68rem;color:var(--muted2);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px" title="${c.description}">${c.description}</div>` : ''}
    </td>
    <td><span style="font-size:.72rem;color:var(--muted2)">${c.category}</span></td>
    <td><span class="badge ${c.severity}">${c.severity}</span></td>
    <td><span style="font-family:'IBM Plex Mono',monospace;font-size:.6rem;color:var(--accent2)">${OP_LABELS[c.operator] || c.operator}</span></td>
    <td><label class="toggle"><input type="checkbox" ${c.active ? 'checked' : ''} onchange="toggleApiCheck(${c.id},this.checked)"><span class="toggle-slider"></span></label></td>
    <td style="white-space:nowrap">
      <button class="btn btn-ghost btn-sm btn-icon" onclick="openCheckModal(${c.id})" title="Editar">&#9998;</button>
      <button class="btn btn-danger btn-sm btn-icon" onclick="deleteApiCheck(${c.id})" title="Excluir">&#128465;</button>
    </td>
  </tr>`).join('');
}

function filterChecks() {
  const q = document.getElementById('checkSearch').value.toLowerCase();
  const filtered = allApiChecks.filter(c =>
    c.title.toLowerCase().includes(q) || c.cid.toLowerCase().includes(q) || c.category.toLowerCase().includes(q)
  );
  renderChecksTable(filtered);
}

async function toggleApiCheck(id, active) {
  await fetch(`/api/admin/api-checks/${id}/toggle`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ active: active ? 1 : 0 })
  });
}

async function deleteApiCheck(id) {
  if (!confirm('Excluir este controle permanentemente?')) return;
  const r = await fetch(`/api/admin/api-checks/${id}`, { method: 'DELETE' });
  const d = await r.json();
  if (d.ok) {
    allApiChecks = allApiChecks.filter(c => c.id !== id);
    renderChecksTable(allApiChecks); renderCheckCounters(allApiChecks);
    toast('Controle excluido', 'ok');
  } else alert(d.error || 'Erro ao excluir');
}

// ── CHECK MODAL ────────────────────────────────────────────
function openCheckModal(id) {
  const c = id ? allApiChecks.find(x => x.id === id) : null;
  editingCheckId = id || null;
  const get = (id) => document.getElementById(id);
  const set = (id, value) => { const el = get(id); if (el) el.value = value; };

  set('eCid', c?.cid || '');
  set('eTitle', c?.title || '');
  set('eCat', c?.category || 'System Hardening');
  set('eSev', c?.severity || 'High');
  
  // Converter valor interno para display text
  const operatorVal = c?.operator || 'is_true';
  const operatorDisplay = OPERATOR_DISPLAY[operatorVal] || OPERATOR_DISPLAY['is_true'];
  set('eOperator', operatorDisplay);

  const vendorValue = c?.vendor_slug || currentVendorSlug || (allVendors[0] && allVendors[0].slug) || '';
  set('cVendor', vendorValue);
  if (vendorValue) currentVendorSlug = vendorValue;
  updateEndpointSelect();
  set('eEndpoint', c?.api_endpoint || '');
  set('eJsonPath', c?.json_path || '');
  set('eExpected', c?.expected_value || '');
  set('eHandlerKey', c?.handler_key || '');
  set('eDesc', c?.description || '');
  set('eRec', c?.recommendation || '');

  const titleEl = get('checkModalTitle');
  if (titleEl) titleEl.textContent = c ? `Editar: ${c.cid} — ${c.title}` : 'Novo Controle CIS';
  updateOperatorHelp();

  const modal = get('checkModal');
  if (modal) modal.classList.add('show');
}
function closeCheckModal() { document.getElementById('checkModal').classList.remove('show'); }

// Mapa de display text → valor interno
const OPERATOR_MAP = {
  '✓ Está Habilitado (booleano)': 'is_true',
  '✗ Está Desabilitado (falsy)': 'is_false',
  '≥ Maior ou Igual a (número)': 'gte',
  '≤ Menor ou Igual a (número)': 'lte',
  '= Igual a (texto - case insensitive)': 'str_eq',
  'ao Não Vazia': 'list_not_empty',
  '⚙️ Lógica Python Customizada': 'handler'
};

const OPERATOR_DISPLAY = {
  'is_true': '✓ Está Habilitado (booleano)',
  'is_false': '✗ Está Desabilitado (falsy)',
  'gte': '≥ Maior ou Igual a (número)',
  'lte': '≤ Menor ou Igual a (número)',
  'str_eq': '= Igual a (texto - case insensitive)',
  'list_not_empty': 'ao Não Vazia',
  'handler': '⚙️ Lógica Python Customizada'
};

function filterOperators() {
  const input = document.getElementById('eOperator');
  const val = input?.value.toLowerCase() || '';
  // Filtro básico é feito pelo datalist nativamente
  // Esta função pode ser expandida para busca mais avançada
}

function updateOperatorHelp() {
  const inputEl = document.getElementById('eOperator');
  const inputVal = inputEl?.value || '';
  
  // Converter do texto de display para o valor interno
  let op = OPERATOR_MAP[inputVal];
  if (!op) {
    // Se não encontrou exato, tenta encontrar por palavra-chave
    for (const [display, value] of Object.entries(OPERATOR_MAP)) {
      if (display.toLowerCase().includes(inputVal.toLowerCase())) {
        op = value;
        break;
      }
    }
  }
  op = op || 'is_true';
  
  const helps = {
    is_true: '✓ Verifica se está habilitado: true, 1, "enable", "enabled", "yes", "on"',
    is_false: '✗ Verifica se está desabilitado ou ausente (qualquer valor falsy)',
    gte: '≥ Verifica se valor ≥ ao esperado. Use para mínimos (ex: versão mínima, timeout mínimo)',
    lte: '≤ Verifica se valor ≤ ao esperado. Use para máximos (ex: máximo de tentativas, tempo limite)',
    str_eq: '= Compara texto exatamente (case insensitive). Use para status, versão, tipo de configuração',
    list_not_empty: '📋 Verifica se a lista tem pelo menos 1 item (ex: servidores configurados, regras de acesso)',
    handler: '⚙️ Executa função Python customizada. Requer handler_key preenchida com o nome da função',
  };
  const el = document.getElementById('operatorHelp');
  if (el) el.textContent = helps[op] || '';
  
  // Show/hide expected_value field
  const needsExpected = ['lte','gte','str_eq'].includes(op);
  const expRow = document.getElementById('expectedRow');
  if (expRow) expRow.style.display = needsExpected ? '' : 'none';
  
  // Show/hide handler_key field  
  const hkRow = document.getElementById('handlerKeyRow');
  if (hkRow) hkRow.style.display = op === 'handler' ? '' : 'none';
}

async function saveCheck() {
  const cid   = document.getElementById('eCid')?.value.trim();
  const title = document.getElementById('eTitle')?.value.trim();
  if (!cid || !title) { alert('ID e Título são obrigatórios.'); return; }
  
  const selectedVendor = document.getElementById('cVendor')?.value.trim();
  const vendorSlug = selectedVendor || currentVendorSlug || (allVendors[0] && allVendors[0].slug) || '';
  if (!vendorSlug) { alert('Fornecedor é obrigatório.'); return; }
  
  // Converter do texto de display para o valor interno
  const operatorDisplay = document.getElementById('eOperator')?.value || '';
  let operator = OPERATOR_MAP[operatorDisplay];
  if (!operator) {
    for (const [display, value] of Object.entries(OPERATOR_MAP)) {
      if (display.toLowerCase().includes(operatorDisplay.toLowerCase())) {
        operator = value;
        break;
      }
    }
  }
  operator = operator || 'handler';
  
  const expected = document.getElementById('eExpected')?.value.trim() || '';
  const handlerKey = document.getElementById('eHandlerKey')?.value.trim() || '';
  
  // Validação: operadores que precisam expected_value
  if (['lte','gte','str_eq'].includes(operator) && !expected) {
    alert(`Operador "${operator}" requer que o VALOR ESPERADO seja preenchido.`);
    return;
  }
  
  // Validação: operador handler precisa da handler_key
  if (operator === 'handler' && !handlerKey) {
    alert('Operador "handler" requer que a HANDLER KEY seja preenchida (nome da função Python).');
    return;
  }

  const data = {
    vendor_slug:    vendorSlug,
    cid, title,
    category:       document.getElementById('eCat')?.value || '',
    severity:       document.getElementById('eSev')?.value || 'High',
    operator:       operator,
    api_endpoint:   document.getElementById('eEndpoint')?.value.trim() || '',
    json_path:      document.getElementById('eJsonPath')?.value.trim() || '',
    expected_value: expected,
    handler_key:    handlerKey,
    description:    document.getElementById('eDesc')?.value.trim() || '',
    recommendation: document.getElementById('eRec')?.value.trim() || '',
    active: 1,
  };

  let r;
  try {
    if (editingCheckId) {
      r = await fetch(`/api/admin/api-checks/${editingCheckId}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data)
      });
    } else {
      r = await fetch('/api/admin/api-checks', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data)
      });
    }
    const d = await r.json();
    if (d.ok || d.id) {
      currentVendorSlug = vendorSlug;
      selectChecksVendor(vendorSlug);
      closeCheckModal();
      loadApiChecks(vendorSlug);
      toast(`Controle ${editingCheckId ? 'atualizado' : 'criado'} com sucesso`, 'ok');
    } else {
      alert(d.error || 'Erro ao salvar controle');
    }
  } catch (err) {
    console.error('Erro ao salvar controle:', err);
    alert('Erro ao salvar controle: ' + err.message);
  }
}

// ── SYNC / DIFF MODAL ─────────────────────────────────────
async function openSyncModal() {
  if (!currentVendorSlug) { toast('Selecione um fabricante primeiro', 'err'); return; }
  document.getElementById('syncModal').classList.add('show');
  document.getElementById('syncBody').innerHTML = '<div style="padding:24px;text-align:center;color:var(--muted2)">Comparando...</div>';
  const r = await fetch(`/api/admin/api-checks/sync/compare?vendor=${currentVendorSlug}`);
  const d = await r.json();
  renderSyncDiff(d);
}
function closeSyncModal() { document.getElementById('syncModal').classList.remove('show'); }

function renderSyncDiff(d) {
  const s = d.summary;
  const pct = s.total_canonical ? Math.round((s.matched / s.total_canonical) * 100) : 100;
  let html = `
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:20px">
      ${[['Canônico',s.total_canonical,'var(--accent)'],['Sincronizado',s.matched,'var(--pass)'],
         ['Modificado',s.modified,'var(--warn)'],['Ausente no DB',s.removed,'var(--fail)']].map(([l,v,c]) =>
        `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:12px;text-align:center">
          <div style="font-size:1.4rem;font-weight:700;color:${c}">${v}</div>
          <div style="font-size:.7rem;color:var(--muted2);margin-top:2px">${l}</div>
        </div>`).join('')}
    </div>`;

  if (d.removed?.length) {
    html += `<div style="margin-bottom:14px">
      <div style="font-size:.8rem;font-weight:600;color:var(--fail);margin-bottom:8px">Ausentes no Banco (${d.removed.length})</div>
      <div style="display:flex;flex-direction:column;gap:6px">
        ${d.removed.map(c => `<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:rgba(248,113,113,.06);border:1px solid rgba(248,113,113,.15);border-radius:6px">
          <div>
            <span style="font-family:'IBM Plex Mono',monospace;font-size:.7rem;color:var(--fail)">${c.cid}</span>
            <span style="font-size:.8rem;margin-left:8px">${c.title}</span>
          </div>
          <button class="btn btn-sm" style="font-size:.7rem;padding:3px 10px" onclick="restoreCheck('${c.vendor_slug}','${c.cid}')">Restaurar</button>
        </div>`).join('')}
      </div>
    </div>`;
  }

  if (d.modified?.length) {
    html += `<div style="margin-bottom:14px">
      <div style="font-size:.8rem;font-weight:600;color:var(--warn);margin-bottom:8px">Modificados (${d.modified.length}) — diferem do canônico</div>
      <div style="display:flex;flex-direction:column;gap:6px">
        ${d.modified.map(m => {
          const diffKeys = Object.keys(m.diffs).join(', ');
          return `<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:rgba(251,191,36,.05);border:1px solid rgba(251,191,36,.15);border-radius:6px">
            <div>
              <span style="font-family:'IBM Plex Mono',monospace;font-size:.7rem;color:var(--warn)">${m.cid}</span>
              <span style="font-size:.8rem;margin-left:8px">${m.title}</span>
              <span style="font-size:.66rem;color:var(--muted2);margin-left:8px">Campos: ${diffKeys}</span>
            </div>
            <button class="btn btn-sm" style="font-size:.7rem;padding:3px 10px" onclick="restoreCheck('${currentVendorSlug}','${m.cid}')">Restaurar</button>
          </div>`;
        }).join('')}
      </div>
    </div>`;
  }

  if (d.added?.length) {
    html += `<div style="margin-bottom:14px">
      <div style="font-size:.8rem;font-weight:600;color:var(--accent2);margin-bottom:8px">Adicionados (customizações) (${d.added.length})</div>
      <div style="display:flex;flex-direction:column;gap:6px">
        ${d.added.map(c => `<div style="padding:8px 12px;background:rgba(56,187,208,.05);border:1px solid rgba(56,187,208,.12);border-radius:6px">
          <span style="font-family:'IBM Plex Mono',monospace;font-size:.7rem;color:var(--accent2)">${c.cid}</span>
          <span style="font-size:.8rem;margin-left:8px">${c.title}</span>
        </div>`).join('')}
      </div>
    </div>`;
  }

  if (!d.removed?.length && !d.modified?.length) {
    html += `<div style="text-align:center;padding:16px;color:var(--pass);font-size:.9rem">Todos os controles estão sincronizados com o canônico ✓</div>`;
  }

  html += `<div style="margin-top:16px;display:flex;gap:10px;justify-content:flex-end">
    ${(d.removed?.length || d.modified?.length) ? `<button class="btn" onclick="restoreAll()">Restaurar Todos (${(d.removed?.length||0)+(d.modified?.length||0)})</button>` : ''}
    <button class="btn btn-ghost" onclick="closeSyncModal()">Fechar</button>
  </div>`;

  document.getElementById('syncBody').innerHTML = html;
}

async function restoreCheck(vendor, cid) {
  const r = await fetch('/api/admin/api-checks/sync/restore', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ vendor_slug: vendor, cids: [cid] })
  });
  const d = await r.json();
  if (d.ok) { toast(`Controle ${cid} restaurado`, 'ok'); openSyncModal(); loadApiChecks(currentVendorSlug); }
  else toast(d.error || 'Erro ao restaurar', 'err');
}

async function restoreAll() {
  if (!confirm('Restaurar TODOS os controles ausentes/modificados ao canônico?')) return;
  const r = await fetch('/api/admin/api-checks/sync/restore', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ vendor_slug: currentVendorSlug, cids: [] })
  });
  const d = await r.json();
  if (d.ok) { toast(`${d.restored} controles restaurados`, 'ok'); openSyncModal(); loadApiChecks(currentVendorSlug); }
  else toast(d.error || 'Erro ao restaurar', 'err');
}

// ── SEVERITY WEIGHTS ───────────────────────────────────────
async function loadWeights() {
  const r = await fetch('/api/admin/weights'); const d = await r.json();
  document.getElementById('wCritical').value = d.Critical || 10;
  document.getElementById('wHigh').value = d.High || 6;
  document.getElementById('wMedium').value = d.Medium || 3;
  document.getElementById('wLow').value = d.Low || 1;
  renderWeightsPreview(d);
  // update live preview on input
  ['wCritical', 'wHigh', 'wMedium', 'wLow'].forEach(id => {
    document.getElementById(id).oninput = () => renderWeightsPreview({
      Critical: parseInt(document.getElementById('wCritical').value) || 10,
      High: parseInt(document.getElementById('wHigh').value) || 6,
      Medium: parseInt(document.getElementById('wMedium').value) || 3,
      Low: parseInt(document.getElementById('wLow').value) || 1,
    });
  });
}

function renderWeightsPreview(w) {
  const max = Math.max(...Object.values(w));
  const rows = [
    { sev: 'Critical', color: 'var(--crit)', icon: '⚠' },
    { sev: 'High', color: 'var(--fail)', icon: '▲' },
    { sev: 'Medium', color: 'var(--warn)', icon: '●' },
    { sev: 'Low', color: '#38bbd0', icon: '▽' },
  ];
  document.getElementById('weightsPreview').innerHTML = `
    <p style="font-size:.78rem;color:var(--text2);margin-bottom:16px;line-height:1.6">
      Impacto relativo de cada severidade no score final. Pesos sao aplicados na analise e no PDF exportado.
    </p>
    ${rows.map(({ sev, color, icon }) => {
      const val = w[sev] || 1;
      const pct = Math.round((val / max) * 100);
      return `
      <div style="margin-bottom:14px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:5px">
          <span style="font-size:.8rem;font-weight:600;color:${color}">${icon} ${sev}</span>
          <span style="font-family:'IBM Plex Mono',monospace;font-size:.7rem;color:var(--muted2)">peso ${val}</span>
        </div>
        <div style="height:8px;background:var(--border);border-radius:4px;overflow:hidden">
          <div style="height:100%;width:${pct}%;background:${color};border-radius:4px;transition:width .4s"></div>
        </div>
      </div>`;
    }).join('')}
    <div style="margin-top:16px;padding:12px;background:rgba(42,143,158,0.06);border:1px solid rgba(42,143,158,0.12);border-radius:8px;font-size:.75rem;color:var(--text2);line-height:1.6">
      Exemplo: com estes pesos, reprovar 1 controle <b style="color:var(--crit)">Critical</b> (${w.Critical})
      equivale a reprovar ${Math.round(w.Critical / (w.Low || 1))}x um controle <b style="color:#38bbd0">Low</b> (${w.Low}).
    </div>
  `;
}

async function saveWeights() {
  const data = {
    Critical: parseInt(document.getElementById('wCritical').value),
    High: parseInt(document.getElementById('wHigh').value),
    Medium: parseInt(document.getElementById('wMedium').value),
    Low: parseInt(document.getElementById('wLow').value),
  };
  const r = await fetch('/api/admin/weights', {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data)
  });
  const d = await r.json();
  if (d.ok) {
    const msg = document.getElementById('weightMsg');
    msg.textContent = '✓ Pesos salvos — proximas analises e PDFs usarao estes valores';
    setTimeout(() => msg.textContent = '', 4000);
    renderWeightsPreview(data);
    toast('Pesos de severidade salvos', 'ok');
  }
}

async function resetWeights() {
  if (!confirm('Restaurar pesos para o padrao (10/6/3/1)?')) return;
  document.getElementById('wCritical').value = 10;
  document.getElementById('wHigh').value = 6;
  document.getElementById('wMedium').value = 3;
  document.getElementById('wLow').value = 1;
  await saveWeights();
}

// ── SECURITY ───────────────────────────────────────────────
async function changePw() {
  const curr = document.getElementById('pwCurrent').value;
  const nw = document.getElementById('pwNew').value;
  const conf = document.getElementById('pwConfirm').value;
  const msg = document.getElementById('pwMsg');
  if (nw !== conf) { msg.style.color = 'var(--fail)'; msg.textContent = 'As senhas nao coincidem'; return; }
  const r = await fetch('/api/admin/change-password', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ current_password: curr, new_password: nw })
  });
  const d = await r.json();
  msg.style.color = d.ok ? 'var(--pass)' : 'var(--fail)';
  msg.textContent = d.ok ? '✓ Senha alterada com sucesso!' : (d.error || 'Erro');
  if (d.ok) ['pwCurrent', 'pwNew', 'pwConfirm'].forEach(id => document.getElementById(id).value = '');
}

// ── HISTORY ────────────────────────────────────────────────
async function loadHistory() {
  const r = await fetch('/api/admin/history'); const data = await r.json();
  document.getElementById('histCount').textContent = `${data.length} registros`;
  document.getElementById('histFull').innerHTML = data.map(h => `<tr>
    <td><b>${h.company || '—'}</b></td>
    <td>${(h.vendor_slug || '').toUpperCase()}</td>
    <td><b style="color:${sc(h.score)}">${h.score}</b></td>
    <td><span class="badge ${h.risk_level}">${h.risk_level}</span></td>
    <td style="color:var(--pass)">${h.passed}</td>
    <td style="color:var(--fail)">${h.failed}</td>
    <td style="color:var(--muted2)">${h.total}</td>
    <td style="font-size:.72rem;color:var(--muted2)">${new Date(h.created_at).toLocaleString('pt-BR')}</td>
  </tr>`).join('') || '<tr><td colspan="8" style="text-align:center;color:var(--muted2);padding:22px">Nenhuma analise ainda</td></tr>';
}

// ── ENDPOINTS ───────────────────────────────────────────────
let allEndpoints = [], allVendorsData = [], editingEndpointId = null;

async function loadEndpointsAndVendors() {
  // Carrega endpoints do banco de dados
  const epRes = await fetch('/api/admin/endpoints');
  allEndpoints = await epRes.json();

  const vendorDefaults = {
    sonicwall: {
      name: 'SonicWall - SonicOS 7.x',
      icon: '🔥',
      baseUrl: 'https://<host>/api/sonicos/',
      auth: 'Basic Auth → POST /api/sonicos/auth · Habilitar: Manage > API > Enable SonicOS API',
      description: ''
    },
    fortigate: {
      name: 'FortiGate - FortiOS 7.x',
      icon: '🟠',
      baseUrl: 'https://<host>/api/v2/',
      auth: 'API Key (Bearer) ou session cookie via /logincheck · Criar: System > Administrators > REST API Admin',
      description: ''
    },
    pfsense: {
      name: 'pfSense - API Plugin',
      icon: '🔵',
      baseUrl: 'https://<host>/api/v1/',
      auth: 'Basic Auth ou API Key (Bearer) · Instalar: System > Package Manager > pfSense-pkg-API',
      description: ''
    }
  };

  try {
    const vendorRes = await fetch('/api/vendors');
    const apiVendors = await vendorRes.json();
    allVendorsData = apiVendors.map(v => ({
      id: v.id,
      slug: v.slug,
      name: v.name || vendorDefaults[v.slug]?.name || v.slug,
      icon: v.icon || vendorDefaults[v.slug]?.icon || '🔧',
      baseUrl: v.base_url || vendorDefaults[v.slug]?.baseUrl || 'https://<host>/',
      auth: vendorDefaults[v.slug]?.auth || 'Configure a autenticação apropriada',
      description: v.description || vendorDefaults[v.slug]?.description || '',
      versions: v.versions || [],
    }));
  } catch (err) {
    allVendorsData = [
      {
        slug: 'sonicwall',
        name: 'SonicWall - SonicOS 7.x',
        icon: '🔥',
        baseUrl: 'https://<host>/api/sonicos/',
        auth: 'Basic Auth → POST /api/sonicos/auth · Habilitar: Manage > API > Enable SonicOS API',
        description: ''
      },
      {
        slug: 'fortigate',
        name: 'FortiGate - FortiOS 7.x',
        icon: '🟠',
        baseUrl: 'https://<host>/api/v2/',
        auth: 'API Key (Bearer) ou session cookie via /logincheck · Criar: System > Administrators > REST API Admin',
        description: ''
      },
      {
        slug: 'pfsense',
        name: 'pfSense - API Plugin',
        icon: '🔵',
        baseUrl: 'https://<host>/api/v1/',
        auth: 'Basic Auth ou API Key (Bearer) · Instalar: System > Package Manager > pfSense-pkg-API',
        description: ''
      }
    ];
  }

  renderVendorsWithEndpoints();
}

function renderVendorsWithEndpoints() {
  const container = document.getElementById('vendorsContainer');

  container.innerHTML = allVendorsData.map(vendor => {
    const vendorEndpoints = allEndpoints.filter(ep => ep.vendor_slug === vendor.slug);
    const versions = vendor.versions || [];

    const versionsRows = versions.length > 0
      ? versions.map(v => `
        <tr style="border-bottom:1px solid var(--border)">
          <td style="padding:6px 8px"><code style="font-size:.75rem;background:var(--bg3);padding:2px 6px;border-radius:4px">${v.version}</code></td>
          <td style="padding:6px 8px;font-size:.8rem">${v.label}</td>
          <td style="padding:6px 8px">
            <input id="minfw_${v.id}" value="${v.min_firmware_version || ''}"
              style="width:110px;background:var(--bg2);border:1px solid var(--border);color:var(--text1);border-radius:4px;padding:3px 7px;font-size:.74rem;font-family:'IBM Plex Mono',monospace"
              placeholder="ex: 7.1.1" title="Versão mínima para esta linha">
          </td>
          <td style="padding:6px 8px">
            <button class="btn-mini" onclick="saveVersionMinFw(${v.id})" title="Salvar versão mínima">✔</button>
            <button class="btn-mini" style="color:var(--fail)" onclick="deleteVersion(${v.id}, '${vendor.slug}')" title="Excluir versão">✖</button>
          </td>
        </tr>
      `).join('')
      : '<tr><td colspan="4" style="padding:10px;color:var(--muted2);text-align:center;font-size:.75rem">Nenhuma versão cadastrada</td></tr>';

    return `
      <div class="tcard" style="margin-bottom:14px">
        <div class="tcard-head">
          <h3>${vendor.icon} ${vendor.name}</h3>
          <div style="margin-left:auto;display:flex;gap:6px">
            <button class="btn btn-ghost btn-sm btn-icon" onclick="editVendor('${vendor.slug}')" title="Editar fornecedor">&#9998;</button>
            <button class="btn btn-danger btn-sm btn-icon" onclick="deleteVendor('${vendor.slug}')" title="Excluir fornecedor">&#128465;</button>
          </div>
        </div>
        <div style="padding:18px">
          <p style="font-size:.8rem;color:var(--text2);margin-bottom:14px">
            Base: <code class="ep-code">${vendor.baseUrl}</code>
          </p>

          <!-- Versions -->
          <div style="margin-bottom:16px">
            <div style="font-size:.72rem;text-transform:uppercase;color:var(--muted2);letter-spacing:.8px;margin-bottom:8px;font-weight:600">Versões Suportadas</div>
            <table style="width:100%">
              <thead>
                <tr style="border-bottom:1px solid var(--border)">
                  <th style="text-align:left;padding:6px 8px;font-size:.7rem;text-transform:uppercase;color:var(--muted2);width:80px">Linha</th>
                  <th style="text-align:left;padding:6px 8px;font-size:.7rem;text-transform:uppercase;color:var(--muted2)">Label</th>
                  <th style="text-align:left;padding:6px 8px;font-size:.7rem;text-transform:uppercase;color:var(--muted2);width:130px">Firmware Mínimo</th>
                  <th style="padding:6px 8px;width:70px"></th>
                </tr>
              </thead>
              <tbody>${versionsRows}</tbody>
            </table>
            <button class="btn btn-sm" style="margin-top:8px;background:var(--accent-light);color:var(--accent)" onclick="openVersionModal(${vendor.id}, '${vendor.slug}')">+ Versão</button>
          </div>

          <!-- Endpoints -->
          <div style="font-size:.72rem;text-transform:uppercase;color:var(--muted2);letter-spacing:.8px;margin-bottom:8px;font-weight:600">Endpoints API</div>
          <table style="width:100%;margin-bottom:10px">
            <thead>
              <tr style="border-bottom:1px solid var(--border)">
                <th style="text-align:left;padding:8px;font-size:.75rem;text-transform:uppercase;color:var(--muted2)">Secao</th>
                <th style="text-align:left;padding:8px;font-size:.75rem;text-transform:uppercase;color:var(--muted2)">Endpoint</th>
                <th style="text-align:left;padding:8px;width:80px;font-size:.75rem;text-transform:uppercase;color:var(--muted2)">Acao</th>
              </tr>
            </thead>
            <tbody>
              ${vendorEndpoints.length > 0
                ? vendorEndpoints.map(ep => `
                  <tr style="border-bottom:1px solid var(--border)">
                    <td style="padding:8px">${ep.section_name}</td>
                    <td style="padding:8px"><code class="ep-code2">${ep.endpoint_path}</code></td>
                    <td style="padding:8px">
                      <button class="btn-mini" onclick="editEndpoint(${ep.id}, '${vendor.slug}')">✎</button>
                      <button class="btn-mini" onclick="deleteEndpoint(${ep.id})">✖</button>
                    </td>
                  </tr>
                `).join('')
                : '<tr><td colspan="3" style="padding:12px;color:var(--muted2);text-align:center">Nenhum endpoint customizado</td></tr>'
              }
            </tbody>
          </table>
          <button class="btn btn-sm" style="background:var(--accent-light);color:var(--accent)" onclick="openEndpointModal('${vendor.slug}')">+ Endpoint</button>
          <p style="font-size:.72rem;color:var(--muted2);margin-top:10px">${vendor.auth}</p>
        </div>
      </div>
    `;
  }).join('');
}

function openVendorModal(vendorSlug) {
  editingVendorSlug = vendorSlug;
  const vendor = allVendorsData.find(v => v.slug === vendorSlug);
  if (vendor) {
    document.getElementById('vSlug').value = vendor.slug;
    document.getElementById('vName').value = vendor.name;
    document.getElementById('vBase').value = vendor.baseUrl;
    document.getElementById('vDesc').value = vendor.description || '';
    document.getElementById('vIcon').value = vendor.icon;
  }
  document.getElementById('vendorModal').classList.add('show');
}

function closeVendorModal() {
  editingVendorSlug = null;
  document.getElementById('vendorModal').classList.remove('show');
}

async function saveVendor() {
  const slug = document.getElementById('vSlug').value.trim();
  const name = document.getElementById('vName').value.trim();
  const baseUrl = document.getElementById('vBase').value.trim();
  const icon = document.getElementById('vIcon').value.trim() || '🔧';
  const description = document.getElementById('vDesc').value.trim();
  if (!slug || !name || !baseUrl) {
    toast('Preencha: Slug, Nome e Base URL', 'error');
    return;
  }

  const existingVendor = allVendorsData.find(v => v.slug === editingVendorSlug);
  if (!existingVendor) return;

  const r = await fetch(`/api/admin/vendors/${existingVendor.id}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ slug, name, icon, base_url: baseUrl, description })
  });
  const text = await r.text();
  let d;
  try { d = JSON.parse(text); } catch {
    toast('Erro ao salvar fornecedor: resposta invalida', 'error');
    return;
  }
  if (!d.ok) { toast(d.error || 'Erro ao salvar fornecedor', 'error'); return; }

  Object.assign(existingVendor, { slug, name, icon, baseUrl, description });
  closeVendorModal();
  renderVendorsWithEndpoints();
  toast('Fornecedor atualizado', 'ok');
  updateVendorSelect();
  loadVendors();
}

function editVendor(slug) {
  openVendorModal(slug);
}

async function deleteVendor(slug) {
  if (!confirm('Excluir este fornecedor permanentemente? Isso pode afetar controles e endpoints associados.')) return;
  
  const vendor = allVendorsData.find(v => v.slug === slug);
  if (!vendor) return;
  
  const r = await fetch(`/api/admin/vendors/${vendor.id}`, { method: 'DELETE' });
  const d = await r.json();
  if (d.ok) {
    allVendorsData = allVendorsData.filter(v => v.slug !== slug);
    renderVendorsWithEndpoints();
    updateVendorSelect();
    loadVendors();
    toast('Fornecedor excluido', 'ok');
  } else {
    toast(d.error || 'Erro ao excluir fornecedor', 'error');
  }
}

// ── VERSION MANAGEMENT ────────────────────────────────────────

function openVersionModal(vendorId, vendorSlug) {
  document.getElementById('vmVendorId').value = vendorId;
  document.getElementById('vmVersionId').value = '';
  document.getElementById('vmVersion').value = '';
  document.getElementById('vmLabel').value = '';
  document.getElementById('vmMinFw').value = '';
  document.getElementById('versionModalTitle').textContent = 'Nova Versão — ' + vendorSlug;
  document.getElementById('versionModal').classList.add('show');
}

function closeVersionModal() {
  document.getElementById('versionModal').classList.remove('show');
}

async function saveVersion() {
  const vendorId = document.getElementById('vmVendorId').value;
  const ver   = document.getElementById('vmVersion').value.trim();
  const label = document.getElementById('vmLabel').value.trim();
  const minFw = document.getElementById('vmMinFw').value.trim();
  if (!ver || !label) { toast('Preencha: Linha de Versão e Label', 'error'); return; }
  const r = await fetch('/api/admin/versions', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ vendor_id: vendorId, version: ver, label, min_firmware_version: minFw })
  });
  const d = await r.json();
  if (d.ok) {
    closeVersionModal();
    loadEndpointsAndVendors();
    toast('Versão adicionada', 'ok');
  } else {
    toast(d.error || 'Erro ao adicionar versão', 'error');
  }
}

async function saveVersionMinFw(versionId) {
  const input = document.getElementById(`minfw_${versionId}`);
  if (!input) return;
  const minFw = input.value.trim();
  const r = await fetch(`/api/admin/versions/${versionId}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ min_firmware_version: minFw })
  });
  const d = await r.json();
  if (d.ok) {
    // Update local data
    allVendorsData.forEach(v => {
      if (v.versions) v.versions.forEach(ver => {
        if (ver.id === versionId) ver.min_firmware_version = minFw;
      });
    });
    toast(minFw ? `Firmware mínimo ${minFw} salvo` : 'Firmware mínimo removido', 'ok');
  } else {
    toast(d.error || 'Erro ao salvar', 'error');
  }
}

async function deleteVersion(versionId, vendorSlug) {
  if (!confirm('Remover esta versão?')) return;
  const r = await fetch(`/api/admin/versions/${versionId}`, { method: 'DELETE' });
  const d = await r.json();
  if (d.ok) {
    loadEndpointsAndVendors();
    toast('Versão removida', 'ok');
  } else {
    toast(d.error || 'Erro ao remover versão', 'error');
  }
}

function updateVendorSelect() {
  const endpointSelect = document.getElementById('eVendor');
  endpointSelect.innerHTML = '<option value="">-- Selecione --</option>' + 
    allVendorsData.map(v => `<option value="${v.slug}">${v.icon} ${v.name}</option>`).join('');

  const checkVendorSelect = document.getElementById('cVendor');
  if (checkVendorSelect) {
    checkVendorSelect.innerHTML = '<option value="">-- Selecione fornecedor --</option>' + 
      allVendors.map(v => `<option value="${v.slug}">${v.icon || ''} ${v.name}</option>`).join('');
    if (currentVendorSlug) checkVendorSelect.value = currentVendorSlug;
  }
}

function updateEndpointSelect() {
  const vendor = document.getElementById('cVendor')?.value;
  const dl = document.getElementById('endpointsList');
  if (!dl) return;
  const items = vendor ? allEndpoints.filter(ep => ep.vendor_slug === vendor && ep.active === 1) : [];
  dl.innerHTML = items.map(ep => `<option value="${ep.endpoint_path}">${ep.section_name}</option>`).join('');
}

function openEndpointModal(vendorSlug = null) {
  editingEndpointId = null;
  document.getElementById('eVendor').value = vendorSlug || '';
  document.getElementById('eSection').value = '';
  document.getElementById('ePath').value = '';
  document.getElementById('eEndpointDesc').value = '';
  document.getElementById('endpointModalTitle').textContent = 'Novo Endpoint';
  document.getElementById('endpointModal').classList.add('show');
}

function closeEndpointModal() {
  document.getElementById('endpointModal').classList.remove('show');
}

async function saveEndpoint() {
  const vendor = document.getElementById('eVendor').value;
  const section = document.getElementById('eSection').value;
  const path = document.getElementById('ePath').value;
  const desc = document.getElementById('eEndpointDesc').value;
  
  if (!vendor || !section || !path) {
    toast('Preencha: Fornecedor, Secao e Caminho', 'error');
    return;
  }
  
  const method = editingEndpointId ? 'PUT' : 'POST';
  const url = editingEndpointId ? `/api/admin/endpoints/${editingEndpointId}` : '/api/admin/endpoints';
  const r = await fetch(url, {
    method, headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ vendor_slug: vendor, section_name: section, endpoint_path: path, description: desc })
  });
  const d = await r.json();
  if (d.ok) {
    closeEndpointModal();
    loadEndpointsAndVendors();
    toast(editingEndpointId ? 'Endpoint atualizado' : 'Endpoint criado', 'ok');
  } else {
    toast(d.error || 'Erro ao salvar endpoint', 'error');
  }
}

async function editEndpoint(id, vendorSlug) {
  const ep = allEndpoints.find(e => e.id === id);
  if (!ep) return;
  
  editingEndpointId = id;
  document.getElementById('eVendor').value = ep.vendor_slug;
  document.getElementById('eSection').value = ep.section_name;
  document.getElementById('ePath').value = ep.endpoint_path;
  document.getElementById('eEndpointDesc').value = ep.description || '';
  document.getElementById('endpointModalTitle').textContent = 'Editar Endpoint';
  document.getElementById('endpointModal').classList.add('show');
}

async function deleteEndpoint(id) {
  if (!confirm('Remover este endpoint?')) return;
  
  const r = await fetch(`/api/admin/endpoints/${id}`, { method: 'DELETE' });
  const d = await r.json();
  if (d.ok) {
    loadEndpointsAndVendors();
    toast('Endpoint removido', 'ok');
  } else {
    toast(d.error || 'Erro ao remover endpoint', 'error');
  }
}

// ── RULES PAGE ─────────────────────────────────────────────
function loadRulesPage() {
  if (!allVendors.length) { loadVendors().then(() => loadRulesPage()); return; }
  renderRulesVendorTabs();
  if (!currentRulesVendorSlug && allVendors[0]) {
    selectRulesVendor(allVendors[0].slug);
  } else if (currentRulesVendorSlug) {
    loadVendorRules(currentRulesVendorSlug);
  }
}

function renderRulesVendorTabs() {
  const el = document.getElementById('rulesVendorTabs');
  if (!el) return;
  el.innerHTML = allVendors.map(v =>
    `<button class="cvtab ${v.slug === currentRulesVendorSlug ? 'active' : ''}" onclick="selectRulesVendor('${v.slug}')">
      ${v.icon || ''} ${v.name}
    </button>`
  ).join('');
}

function selectRulesVendor(slug) {
  currentRulesVendorSlug = slug;
  document.querySelectorAll('#rulesVendorTabs .cvtab').forEach(b => {
    const v = allVendors.find(v => v.slug === slug);
    b.classList.toggle('active', v && b.textContent.includes(v.name));
  });
  loadVendorRules(slug);
}

async function loadVendorRules(slug) {
  currentRulesVendorSlug = slug;
  try {
    const r = await fetch(`/api/admin/rule-checks?vendor=${slug}`);
    const data = await r.json();
    allRules = Array.isArray(data) ? data : [];
    if (!Array.isArray(data)) console.error('rule-checks error:', data);
    renderRulesTable(allRules);
  } catch (e) {
    console.error('loadVendorRules error:', e);
    allRules = [];
    renderRulesTable([]);
  }
}

function renderRulesTable(rules) {
  const tbody = document.getElementById('rulesBody');
  const empty = document.getElementById('rulesEmpty');
  if (!rules.length) { tbody.innerHTML = ''; empty.style.display = 'block'; return; }
  empty.style.display = 'none';
  tbody.innerHTML = rules.map(r => `<tr id="rule-${r.id}">
    <td style="max-width:200px">
      <div style="font-size:.82rem;font-weight:500">${r.name}</div>
      ${r.description ? `<div style="font-size:.68rem;color:var(--muted2);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:180px" title="${r.description}">${r.description}</div>` : ''}
    </td>
    <td><span style="font-size:.72rem;color:var(--muted2)">${r.category}</span></td>
    <td><span class="badge ${r.severity}">${r.severity}</span></td>
    <td><label class="toggle"><input type="checkbox" ${r.active ? 'checked' : ''} onchange="toggleRule(${r.id},this.checked)"><span class="toggle-slider"></span></label></td>
    <td style="white-space:nowrap">
      <button class="btn btn-ghost btn-sm btn-icon" onclick="editRule(${r.id})" title="Editar">&#9998;</button>
      <button class="btn btn-danger btn-sm btn-icon" onclick="deleteRule(${r.id})" title="Excluir">&#128465;</button>
    </td>
  </tr>`).join('');
}

function filterRules() {
  const q = document.getElementById('ruleSearch').value.toLowerCase();
  const filtered = allRules.filter(r =>
    r.name.toLowerCase().includes(q) || r.category.toLowerCase().includes(q)
  );
  renderRulesTable(filtered);
}

async function toggleRule(id, active) {
  await fetch(`/api/admin/rule-checks/${id}/toggle`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ active: active ? 1 : 0 })
  });
}

async function deleteRule(id) {
  if (!confirm('Excluir esta regra permanentemente?')) return;
  const r = await fetch(`/api/admin/rule-checks/${id}`, { method: 'DELETE' });
  const d = await r.json();
  if (d.ok) {
    loadVendorRules(currentRulesVendorSlug);
    toast('Regra excluida', 'ok');
  } else toast(d.error || 'Erro ao excluir', 'err');
}

function openRuleModal(id) {
  const r = id ? allRules.find(rule => rule.id === id) : null;
  editingRuleId = id || null;
  const get = (id) => document.getElementById(id);
  const set = (id, value) => { const el = get(id); if (el) el.value = value; };

  set('rTag', r?.tag || '');
  set('rName', r?.name || '');
  set('rCategory', r?.category || '');
  set('rSeverity', r?.severity || 'High');
  set('rDescription', r?.description || '');
  set('rRecommendation', r?.recommendation || '');

  const titleEl = get('ruleModalTitle');
  if (titleEl) titleEl.textContent = r ? `Editar: ${r.name}` : 'Nova Regra';
  get('ruleModal').classList.add('show');
}
function closeRuleModal() { document.getElementById('ruleModal').classList.remove('show'); }

async function saveRule() {
  const tag = document.getElementById('rTag').value.trim();
  const name = document.getElementById('rName').value.trim();
  if (!tag) { alert('Tag é obrigatória.'); return; }
  if (!name) { alert('Nome é obrigatório.'); return; }
  const data = {
    tag,
    name,
    category: document.getElementById('rCategory').value.trim(),
    severity: document.getElementById('rSeverity').value,
    description: document.getElementById('rDescription').value.trim(),
    recommendation: document.getElementById('rRecommendation').value.trim(),
    active: 1,
  };
  let r;
  if (editingRuleId) {
    r = await fetch(`/api/admin/rule-checks/${editingRuleId}`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data)
    });
  } else {
    data.vendor_slug = currentRulesVendorSlug;
    r = await fetch('/api/admin/rule-checks', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data)
    });
  }
  const d = await r.json();
  if (d.ok || d.id) {
    closeRuleModal(); loadVendorRules(currentRulesVendorSlug);
    toast(`Regra ${editingRuleId ? 'atualizada' : 'criada'} com sucesso`, 'ok');
  } else {
    alert(d.error || 'Erro ao salvar regra');
  }
}

function editRule(id) {
  const r = allRules.find(rule => rule.id === id);
  if (!r) return;
  openRuleModal(id);
}

// ── INIT ───────────────────────────────────────────────────
checkAuth();
document.getElementById('checkModal').addEventListener('click', function (e) { if (e.target === this) closeCheckModal(); });
document.getElementById('vendorModal').addEventListener('click', function (e) { if (e.target === this) closeVendorModal(); });
document.getElementById('endpointModal').addEventListener('click', function (e) { if (e.target === this) closeEndpointModal(); });
document.getElementById('ruleModal').addEventListener('click', function (e) { if (e.target === this) closeRuleModal(); });
document.getElementById('loginPw').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
document.addEventListener('DOMContentLoaded', () => {
  const sm = document.getElementById('syncModal');
  if (sm) sm.addEventListener('click', function(e) { if (e.target === this) closeSyncModal(); });
});
