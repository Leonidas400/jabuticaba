(function () {
  const STORAGE_KEY = 'cis-theme';
  const SWITCH_ID = 'themeSwitch';
  const root = document.documentElement;

  function getSavedTheme() {
    try {
      const t = localStorage.getItem(STORAGE_KEY);
      return t === 'light' || t === 'dark' ? t : null;
    } catch (_) { return null; }
  }

  function getSystemTheme() {
    const prefersLight = window.matchMedia &&
      window.matchMedia('(prefers-color-scheme: light)').matches;
    return prefersLight ? 'light' : 'dark';
  }

  function setSwitchState(theme) {
    const sw = document.getElementById(SWITCH_ID);
    if (!sw) return;
    // No seu switch, checked = LIGHT
    sw.checked = (theme === 'light');
    sw.setAttribute('aria-checked', sw.checked ? 'true' : 'false');
  }

  function applyChartTheme(theme) {
    if (!window.Chart) return;
    const isLight = theme === 'light';
    // Defaults globais
    Chart.defaults.color = isLight ? '#111827' : '#f1f1f1';
    Chart.defaults.borderColor = isLight ? 'rgba(0,0,0,.15)' : 'rgba(255,255,255,.15)';

    // Atualiza instâncias existentes (Chart.js v4)
    const instances = Chart.instances
      ? (Array.isArray(Chart.instances) ? Chart.instances : Object.values(Chart.instances))
      : [];

    instances.forEach((ch) => {
      try {
        if (ch.options?.plugins?.legend?.labels) {
          ch.options.plugins.legend.labels.color = Chart.defaults.color;
        }
        // Escalas radiais (radar/polarArea)
        if (ch.options?.scales?.r) {
          ch.options.scales.r.grid = ch.options.scales.r.grid || {};
          ch.options.scales.r.pointLabels = ch.options.scales.r.pointLabels || {};
          ch.options.scales.r.angleLines = ch.options.scales.r.angleLines || {};
          ch.options.scales.r.grid.color = Chart.defaults.borderColor;
          ch.options.scales.r.pointLabels.color = Chart.defaults.color;
          ch.options.scales.r.angleLines.color = Chart.defaults.borderColor;
          if (ch.options.scales.r.ticks) {
            ch.options.scales.r.ticks.color = Chart.defaults.color;
          }
        }
        // Eixos cartesianos
        ['x', 'y'].forEach(ax => {
          if (ch.options?.scales?.[ax]) {
            ch.options.scales[ax].grid = ch.options.scales[ax].grid || {};
            ch.options.scales[ax].ticks = ch.options.scales[ax].ticks || {};
            ch.options.scales[ax].grid.color = Chart.defaults.borderColor;
            ch.options.scales[ax].ticks.color = Chart.defaults.color;
          }
        });

        ch.update();
      } catch (_) { /* ignora */ }
    });
  }

  function applyTheme(theme, { persist = true } = {}) {
    root.setAttribute('data-theme', theme);
    if (persist) {
      try { localStorage.setItem(STORAGE_KEY, theme); } catch (_) { /* ignore */ }
    }
    setSwitchState(theme);
    applyChartTheme(theme);

    // Notifica outros módulos interessados
    try {
      window.dispatchEvent(new CustomEvent('themechange', { detail: { theme } }));
    } catch (_) { /* ignore */ }
  }

  function init() {
    // Tema inicial: salvo > sistema > dark
    const saved = getSavedTheme();
    const initial = saved ?? getSystemTheme();
    applyTheme(initial, { persist: false });

    // Reage à mudança do SO se o usuário ainda não escolheu
    const mql = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)');
    if (mql?.addEventListener) {
      mql.addEventListener('change', (e) => {
        // Só segue o SO se ainda não houver escolha do usuário
        if (!getSavedTheme()) applyTheme(e.matches ? 'light' : 'dark', { persist: false });
      });
    } else if (mql?.addListener) { // Safari antigo
      mql.addListener((e) => {
        if (!getSavedTheme()) applyTheme(e.matches ? 'light' : 'dark', { persist: false });
      });
    }

    // Liga o switch
    const sw = document.getElementById(SWITCH_ID);
    if (sw) {
      sw.addEventListener('change', function () {
        const next = this.checked ? 'light' : 'dark';
        applyTheme(next, { persist: true });
      });
    }

    // Garante que o switch reflete o estado inicial
    setSwitchState(initial);
  }

  // DOM pronto
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
