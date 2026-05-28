import { isBackup } from './utils.js';

export async function processAnalysis(configText, company, vendorInput) {
  let vendor = vendorInput.toLowerCase();

  const looksPfSense = 
    /<\s*(pfsense|m0n0wall)\b/i.test(configText) || 
    (/^\s*<\?xml\b/i.test(configText) && /<\s*(interfaces|filter|system|vlans|nat)\b/i.test(configText));

  if (looksPfSense) vendor = 'pfsense';

  if (!isBackup(configText, vendor)) {
    throw new Error('Arquivo inválido ou não corresponde ao fabricante selecionado.');
  }

  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ config_text: configText, company, vendor }),
    });
    if (!res.ok) throw new Error('Falha na API Backend');
    return await res.json();
  } catch (err) {
    console.warn('Backend indisponível. Usando processamento local (Fallback).', err);
    return runClientSide(configText, company, vendor);
  }
}

export function runClientSide(config, company, vendor='fortigate') {
  const has = p => new RegExp(p, 'i').test(config);
  const val = (p, def=null) => { const m = config.match(new RegExp(p,'i')); return m ? m[1] : def; };
  
  const c = (id,title,cat,sev,desc,rec,passed,detail) =>
    ({id,title,category:cat,severity:sev,description:desc,recommendation:rec,
      status:passed?'PASS':'FAIL',detail:detail||''});

  const checks = [
    c('1.1','Hostname Personalizado','System Hardening','Low','Hostname padrão identifica o fabricante.','config system global > set hostname <nome>', !has('set hostname\\s+(fortigate|fg|fgt|firewall)\\b'),`Hostname: ${val('set hostname (\\S+)','não definido')}`),
    c('1.2','Versão de Firmware Registrada','System Hardening','Medium','Versão deve ser monitorada.','Verificar manualmente',true,'Verificação informativa'),
    c('2.1','Gerenciamento HTTP Desabilitado','Access Control','Critical','HTTP expõe credenciais.','unset allowaccess http', !has('allowaccess[^\\n]*\\bhttp\\b'),has('allowaccess[^\\n]*\\bhttp\\b')?'HTTP detectado!':'HTTP OK'),
    // Adicione os demais checks aqui seguindo a estrutura original...
  ];

  const W = {Critical:10, High:6, Medium:3, Low:1};
  const tw = checks.reduce((s,r)=>s+W[r.severity],0);
  const fw = checks.filter(r=>r.status==='FAIL').reduce((s,r)=>s+W[r.severity],0);
  const score = Math.round(100 - fw/tw*100);
  
  const cats = ['System Hardening','Access Control']; // Adicione o resto
  const by_category = {};
  cats.forEach(cat => {
    const g = checks.filter(r=>r.category===cat);
    const gw = g.reduce((s,r)=>s+W[r.severity],0);
    const gf = g.filter(r=>r.status==='FAIL').reduce((s,r)=>s+W[r.severity],0);
    by_category[cat] = {
      total: g.length, pass: g.filter(r=>r.status==='PASS').length,
      fail: g.filter(r=>r.status==='FAIL').length, score: gw ? Math.round(100-gf/gw*100) : 100
    };
  });

  const by_severity = {};
  ['Critical','High','Medium','Low'].forEach(sev => {
    const g = checks.filter(r=>r.severity===sev);
    by_severity[sev] = {total: g.length, pass: g.filter(r=>r.status==='PASS').length, fail: g.filter(r=>r.status==='FAIL').length};
  });

  const rl = score>=85 ? 'BAIXO' : score>=65 ? 'MÉDIO' : score>=40 ? 'ALTO' : 'CRÍTICO';
  const rc = score>=85 ? '#10b981' : score>=65 ? '#f59e0b' : score>=40 ? '#ef4444' : '#dc2626';
  const bmark = vendor==='pfsense' ? 'pfSense Best Practices' : 'CIS FortiGate Benchmark';

  return {
    company, vendor, timestamp: new Date().toISOString(), benchmark: bmark,
    risk: {score, risk_level: rl, risk_color: rc, total_checks: checks.length, passed: checks.filter(r=>r.status==='PASS').length, failed: checks.filter(r=>r.status==='FAIL').length, by_severity, by_category}, 
    checks
  };
}