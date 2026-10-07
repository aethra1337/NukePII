// Guide + simple pages: theme / language toggles only.
(function () {
  var themeToggle = document.getElementById("themeToggle");
  var langToggle = document.getElementById("langToggle");

  function T(key, vars) {
    return window.NukeI18n ? window.NukeI18n.t(key, vars) : key;
  }

  function syncThemeLabel() {
    if (!themeToggle) return;
    var light = document.documentElement.classList.contains("light");
    themeToggle.setAttribute("data-mode", light ? "light" : "dark");
    themeToggle.setAttribute("aria-pressed", light ? "true" : "false");
  }

  function syncLang() {
    if (!langToggle || !window.NukeI18n) return;
    langToggle.setAttribute("data-cur", window.NukeI18n.lang());
    langToggle.setAttribute("aria-checked", window.NukeI18n.lang() === "en" ? "true" : "false");
  }

  if (langToggle) {
    langToggle.addEventListener("click", function () {
      if (window.NukeI18n) window.NukeI18n.toggle();
      syncThemeLabel();
      syncLang();
    });
  }

  if (themeToggle) {
    themeToggle.addEventListener("click", function () {
      var light = document.documentElement.classList.contains("light");
      document.documentElement.classList.toggle("light", !light);
      document.documentElement.classList.toggle("dark", light);
      try {
        localStorage.setItem("nukepii_theme", light ? "dark" : "light");
      } catch (e) {}
      syncThemeLabel();
    });
  }

  syncThemeLabel();
  syncLang();
})();
