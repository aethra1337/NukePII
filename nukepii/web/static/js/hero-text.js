/* Hero TechText wordmark: mounts on #techTextHero, re-mounts on language
 * change so the wordmark follows the active locale. No dependencies. */
import { initTechText } from './tech-text.js';

(function () {
  const el = document.getElementById('techTextHero');
  if (!el) return;

  let destroy = null;

  function text() {
    const key = el.dataset.i18nKey || 'hero.title';
    const t = window.NukeI18n ? window.NukeI18n.t(key) : '';
    return t && t !== key ? t : 'Find PII before someone else does.';
  }

  function palette() {
    const light = document.documentElement.classList.contains('light');
    return light
      ? { color: '#14201A', accentColor: '#0BAE55' }
      : { color: '#ffffff', accentColor: '#18E875' };
  }

  function mount() {
    try {
      if (destroy) destroy();
      const pal = palette();
      destroy = initTechText(el, {
        text: text(),
        fontWeight: 600,
        fontSize: 150,
        letterSpacing: -0.03,
        align: 'left',
        alignPad: 0.01,
        color: pal.color,
        accentColor: pal.accentColor,
        reveal: 'letter',
        reach: 200,
        softness: 0.7,
        dashLength: 4,
        dashGap: 2,
        strokeWidth: 1.5,
        lineStyle: 'dashed',
        specks: 15,
        selection: true,
        labels: true,
        draggable: true,
        sweep: true,
        speed: 1
      });
      el.dataset.tech = 'on';
    } catch (e) {
      window.__techTextError = String((e && e.message) || e);
      el.style.display = 'none';
    }
  }

  mount();

  // Re-mount when language or theme flips (toggles live in guide.js / upload.js).
  let lastLang = document.documentElement.lang;
  let lastTheme = document.documentElement.classList.contains('light') ? 'light' : 'dark';
  new MutationObserver(() => {
    const lang = document.documentElement.lang;
    const theme = document.documentElement.classList.contains('light') ? 'light' : 'dark';
    if (lang !== lastLang || theme !== lastTheme) {
      lastLang = lang;
      lastTheme = theme;
      mount();
    }
  }).observe(document.documentElement, { attributes: true, attributeFilter: ['lang', 'class'] });
})();
