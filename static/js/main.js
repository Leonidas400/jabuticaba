import { DEMO, DEMO_PFSENSE } from './demo-data.js';
import { processAnalysis } from './analyzer.js';
import { renderResults } from './render.js';
import { downloadJSON, exportPDF } from './export.js';

// ─── STATE ─────────────────────────────────────────────────
let currentData = null;
let currentFilter = 'all';
let currentVendor = 'fortigate';
let demoConfigStr = null;

// ─── UI EVENTS SETUP ───────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  setupVendorSelection();
  setupDragAndDrop();
  setupFilterPills();
  setupAdvancedFilter();
  setupButtons();
  setupAccordion();
});

function setupVendorSelection() {
  window.selectVendor = (v) => {
    currentVendor = v;
    ['fortigate','pfsense'].forEach(vv => {
      const b = document.getElementById('vbtn-'+vv);
      if(b) {
        b.classList.toggle('active', vv === v);
        if (vv === 'pfsense') b.classList.toggle('pfsense', vv === v);
      }
    });

    document.getElementById('fileLabel').textContent = v === 'pfsense' ? 'Arquivo config.xml do pfSense' : 'Arquivo de Configuração FortiGate';
    document.getElementById('fileHint').textContent = v === 'pfsense' ? 'config.xml (Diagnostics > Backup)' : '.conf / .txt / .cfg';
    demoConfigStr = null;
    document.getElementById('fileName').textContent = '';
  };

  window.loadDemo = () => {
    if (currentVendor === 'pfsense') {
      document.getElementById('company').value = 'Empresa pfSense Demo';
      document.getElementById('fileName').textContent = '✓ demo-pfsense-config.xml';
      demoConfigStr = DEMO_PFSENSE;
    } else {
      document.getElementById('company').value = 'Empresa Demonstração Ltda';
      document.getElementById('fileName').textContent = '✓ demo-fortigate.conf';
      demoConfigStr = DEMO;
    }
  };
}

function setupDragAndDrop() {
  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');

  if(!dropZone || !fileInput) return;

  dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault(); dropZone.classList.remove('drag');
    const f = e.dataTransfer.files[0];
    if (f) { fileInput.files = e.dataTransfer.files; setFile(f.name); }
  });

  fileInput.addEventListener('change', () => { if (fileInput.files[0]) setFile(fileInput.files[0].name); });

  function setFile(name) {
    document.getElementById('fileName').textContent = '✓ ' + name;
    demoConfigStr = null;
  }
}

function setupButtons() {
  const analyzeBtn = document.getElementById('analyzeBtn');
  if (analyzeBtn) analyzeBtn.addEventListener('click', handleAnalyze);

  const btnJson = document.getElementById('btnExportJson');
  if (btnJson) btnJson.addEventListener('click', () => downloadJSON(currentData));

  const btnPdf = document.getElementById('btnExportPdf');
  if (btnPdf) btnPdf.addEventListener('click', () => exportPDF(currentData));
}

// ─── CORE ORCHESTRATION ────────────────────────────────────
async function handleAnalyze() {
  const company = document.getElementById('company').value || 'Organização';
  const fileInput = document.getElementById('fileInput');
  let configText = '';

  if (demoConfigStr) {
    configText = demoConfigStr;
  } else if (fileInput.files[0]) {
    configText = await fileInput.files[0].text();
  } else {
    alert('Selecione um arquivo ou carregue a demonstração.');
    return;
  }

  const btn = document.getElementById('analyzeBtn');
  btn.disabled = true;
  document.getElementById('loading').style.display = 'block';
  document.getElementById('results').style.display = 'none';

  try {
    currentData = await processAnalysis(configText, company, currentVendor);
    renderResults(currentData, currentFilter);
  } catch (err) {
    alert(err.message);
  } finally {
    btn.disabled = false;
    document.getElementById('loading').style.display = 'none';
  }
}

window.analyze = handleAnalyze;

// ─── EVENT DELEGATION FOR UI ───────────────────────────────
function setupFilterPills() {
  document.querySelectorAll('.pill[onclick]').forEach(pill => {
    pill.addEventListener('click', (e) => {
      const onclick = e.target.getAttribute('onclick');
      if (!onclick) return;

      const match = onclick.match(/'([^']+)'/);
      if (!match) return;

      const f = match[1];
      currentFilter = f;

      document.querySelectorAll('.pill[onclick]').forEach(p =>
        p.classList.remove('active')
      );
      e.target.classList.add('active');

      document.querySelectorAll('.check-item').forEach(item => {
        const show =
          f === 'all' ||
          item.dataset.status === f ||
          item.dataset.sev === f;

        item.classList.toggle('hidden', !show);
      });
    });
  });
}


function setupAdvancedFilter() {
  const btn = document.getElementById('advFilterBtn');
  const panel = document.getElementById('advFilter');

  if (!btn || !panel) return;

  btn.addEventListener('click', () => {
    panel.classList.toggle('open');
    btn.classList.toggle('active');
  });

  panel.querySelectorAll('.pill').forEach(pill => {
    pill.addEventListener('click', () => {
      pill.classList.toggle('active');
      applyAdvancedFilter();
    });
  });
}

function applyAdvancedFilter() {
  const selectedStatus = [...document.querySelectorAll('.pill.active[data-group="status"]')]
    .map(p => p.dataset.value);

  const selectedSev = [...document.querySelectorAll('.pill.active[data-group="sev"]')]
    .map(p => p.dataset.value);

  document.querySelectorAll('.check-item').forEach(item => {
    const statusOk =
      selectedStatus.length === 0 ||
      selectedStatus.includes(item.dataset.status);

    const sevOk =
      selectedSev.length === 0 ||
      selectedSev.includes(item.dataset.sev);

    item.classList.toggle('hidden', !(statusOk && sevOk));
  });
}



function setupAccordion() {
  // Substitui a necessidade do onclick="toggleExpand(this)" no HTML inline do renderChecks
  document.getElementById('checksList').addEventListener('click', (e) => {
    const item = e.target.closest('.toggle-check');
    if (item) {
      item.classList.toggle('expanded');
    }
  });
}