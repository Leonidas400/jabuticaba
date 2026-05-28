export function downloadJSON(data) {
  if (!data) return;
  const blob = new Blob([JSON.stringify(data, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `auditoria_cis_${new Date().toISOString().slice(0,10)}.json`;
  a.click();
}

export async function exportPDF(data) {
  if (!data) return;

  const theme = document.documentElement.getAttribute('data-theme') ||
    (localStorage.getItem('cis-theme') || (
      window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
    ));

  const payload = { ...data, theme };
  const spinner = document.getElementById('pdfSpinner');
  spinner.classList.add('show');

  try {
    const res = await fetch('/api/pdf', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    
    if (!res.ok) throw new Error(`status ${res.status}`);

    const blob = await res.blob();
    const a = document.createElement('a');
    const companySafe = (data.company || 'report').replace(/\s/g, '_');
    const dateStr = new Date().toISOString().slice(0,10);

    a.href = URL.createObjectURL(blob);
    a.download = `Auditoria_CIS_${companySafe}_${dateStr}${theme === 'light' ? '_LIGHT' : '_DARK'}.pdf`;
    a.click();
    URL.revokeObjectURL(a.href);
  } catch (err) {
    alert('Erro ao gerar PDF. O backend pode estar offline.');
    console.error('Erro ao exportar PDF:', err);
  } finally {
    spinner.classList.remove('show');
  }
}