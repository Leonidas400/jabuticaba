let radarChart = null;
let doughnutChart = null;

export function renderResults(data, currentFilter = 'all') {
  const {risk, checks, company, timestamp, benchmark} = data;

  document.getElementById('riskHero').style.setProperty('--risk-color', risk.risk_color);
  document.getElementById('scoreRing').style.setProperty('--risk-color', risk.risk_color);

  const circumference = 339.3;
  const offset = circumference - (risk.score / 100) * circumference;
  const ring = document.getElementById('ringVal');
  ring.style.stroke = risk.risk_color;
  setTimeout(() => { ring.style.strokeDashoffset = offset; }, 100);

  document.getElementById('scoreNum').textContent = risk.score;
  document.getElementById('scoreNum').style.color = risk.risk_color;

  const labels = {BAIXO:'RISCO BAIXO', MÉDIO:'RISCO MÉDIO', ALTO:'RISCO ALTO', CRÍTICO:'RISCO CRÍTICO'};
  document.getElementById('riskLevel').textContent = labels[risk.risk_level] || risk.risk_level;
  document.getElementById('riskLevel').style.color = risk.risk_color;
  document.getElementById('riskMeta').textContent = `${company} · ${new Date(timestamp).toLocaleString('pt-BR')} · ${benchmark}`;
  
  document.getElementById('stTotal').textContent = risk.total_checks;
  document.getElementById('stPass').textContent = risk.passed;
  document.getElementById('stFail').textContent = risk.failed;
  
  document.getElementById('progBar').style.width = risk.score + '%';
  document.getElementById('progBar').style.background = risk.risk_color;

  const sevGrid = document.getElementById('sevGrid');
  sevGrid.innerHTML = ['Critical','High','Medium','Low'].map(sev => {
    const s = risk.by_severity[sev] || {total:0, pass:0, fail:0};
    return `
      <div class="sev-card ${sev}">
        <div class="s-label">${sev}</div>
        <div class="s-fail">${s.fail}</div>
        <div class="s-total">de ${s.total} controles</div>
      </div>`;
  }).join('');

  renderCharts(risk);
  renderChecks(checks, currentFilter);

  document.getElementById('results').style.display = 'block';
  setTimeout(() => document.getElementById('results').scrollIntoView({behavior:'smooth'}), 100);
}

function renderCharts(risk) {
  if (radarChart) radarChart.destroy();
  if (doughnutChart) doughnutChart.destroy();

  const cats = Object.keys(risk.by_category);
  const scores = cats.map(c => risk.by_category[c].score);
  const short = cats.map(c => c.length > 16 ? c.substring(0,14)+'…' : c);

  const rCtx = document.getElementById('radarChart').getContext('2d');
  radarChart = new Chart(rCtx, {
    type: 'radar',
    data: {
      labels: short,
      datasets: [{
        data: scores,
        backgroundColor: 'rgba(0,201,240,.12)',
        borderColor: '#00c9f0',
        borderWidth: 2,
        pointBackgroundColor: scores.map(s => s>=85?'#10b981':s>=65?'#f59e0b':'#ef4444'),
        pointBorderColor: '#080c14',
        pointRadius: 4,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: {
        r: {
          min: 0, max: 100,
          grid: {color: 'rgba(34, 118, 133,0.6)'},
          angleLines: {color: 'rgba(34, 118, 133, 0.6)'},
          pointLabels: {color: '#00c9f0', font: {size: 9, family: 'IBM Plex Mono'}},
          ticks: {color: 'rgb(16, 185, 129)', backdropColor: 'transparent', stepSize: 25, font: {size: 7}},
        }
      },
      plugins: {legend: {display: false}},
    }
  });

  const sevFails = ['Critical','High','Medium','Low']
    .map(sev => ({sev, val: (risk.by_severity[sev]||{}).fail||0}))
    .filter(x => x.val > 0);
    
  const dCtx = document.getElementById('doughnutChart').getContext('2d');
  
  if (sevFails.length === 0) {
    dCtx.fillStyle = '#00c9f0';
    dCtx.font = 'bold 18px Barlow Condensed';
    dCtx.textAlign = 'center';
    dCtx.fillText('0 falhas!', dCtx.canvas.width/2, dCtx.canvas.height/2);
    return;
  }

  const sevColors = {Critical:'#dc2626', High:'#ef4444', Medium:'#f59e0b', Low:'#818cf8'};
  doughnutChart = new Chart(dCtx, {
    type: 'doughnut',
    data: {
      labels: sevFails.map(x => x.sev),
      datasets: [{
        data: sevFails.map(x => x.val),
        backgroundColor: sevFails.map(x => sevColors[x.sev]),
        borderColor: '#0d1320',
        borderWidth: 3,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      cutout: '62%',
      plugins: {
        legend: {
          position: 'right',
          labels: {color: '#227685FF', font: {size: 10, family: 'IBM Plex Mono'}, boxWidth: 12, padding: 12}
        }
      }
    }
  });
}

export function renderChecks(checks, currentFilter) {
  const list = document.getElementById('checksList');
  const sevOrder = {Critical:0, High:1, Medium:2, Low:3};
  
  const sorted = [...checks].sort((a,b) => {
    if (a.status !== b.status) return a.status==='FAIL' ? -1 : 1;
    return sevOrder[a.severity] - sevOrder[b.severity];
  });

  list.innerHTML = sorted.map(c => {
    const hidden = currentFilter !== 'all' && c.status !== currentFilter && c.severity !== currentFilter ? 'hidden' : '';
    // A classe toggle-check permite delegar o evento de clique no main.js
    return `
      <div class="check-item toggle-check ${hidden}" data-status="${c.status}" data-sev="${c.severity}">
        <div class="check-id">${c.id}</div>
        <div>
          <div class="check-title">${c.title}</div>
          <div class="check-cat">${c.category}</div>
          <div class="check-detail">
            <div class="det-row"><div class="det-lbl">Descrição</div><div class="det-val">${c.description}</div></div>
            <div class="det-row"><div class="det-lbl">Resultado</div><div class="det-val">${c.detail}</div></div>
            <div class="det-row"><div class="det-lbl">Recomendação</div><div class="det-rec">${c.recommendation}</div></div>
          </div>
        </div>
        <div class="check-right">
          <span class="status-badge ${c.status}">Status: ${c.status}</span>
          <span class="sev-badge ${c.severity}">Severity: ${c.severity}</span>
        </div>
      </div>`;
  }).join('');
}