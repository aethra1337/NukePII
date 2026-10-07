// Clean page: sanitization workspace. Reads the last /api/scan payload from
// sessionStorage and the stashed raw file from IndexedDB (both written by
// /scan). Nothing leaves the browser except the /api/clean POST itself.
(function () {
  var themeToggle = document.getElementById("themeToggle");
  var langToggle = document.getElementById("langToggle");
  var toastWrap = document.getElementById("toastWrap");

  function T(key, vars) {
    return window.NukeI18n ? window.NukeI18n.t(key, vars) : key;
  }

  function syncThemeLabel() {
    if (!themeToggle) return;
    var light = document.documentElement.classList.contains("light");
    themeToggle.setAttribute("data-mode", light ? "light" : "dark");
    themeToggle.setAttribute("aria-pressed", light ? "true" : "false");
  }

  if (langToggle) {
    langToggle.addEventListener("click", function () {
      if (window.NukeI18n) window.NukeI18n.toggle();
      window.location.reload();
    });
  }

  if (themeToggle) {
    syncThemeLabel();
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

  function toast(message) {
    if (!toastWrap) return;
    var el = document.createElement("div");
    el.className = "toast";
    el.textContent = message;
    toastWrap.appendChild(el);
    setTimeout(function () {
      el.remove();
    }, 6000);
  }

  var raw = null;
  try {
    raw = sessionStorage.getItem("nukepii_scan");
  } catch (e) {}

  var emptyState = document.getElementById("emptyState");
  var cleanGrid = document.getElementById("cleanGrid");

  if (!raw) {
    if (emptyState) emptyState.classList.remove("hidden");
    return;
  }

  var report;
  try {
    report = JSON.parse(raw);
  } catch (e) {
    if (emptyState) emptyState.classList.remove("hidden");
    return;
  }

  if (emptyState) emptyState.classList.add("hidden");
  if (cleanGrid) {
    cleanGrid.classList.remove("hidden");
    cleanGrid.style.display = "block";
  }

  var scanParams = {};
  try {
    scanParams = JSON.parse(sessionStorage.getItem("nukepii_params") || "{}");
  } catch (e) {}
  var defaults = {};
  try {
    defaults = JSON.parse(localStorage.getItem("nukepii_defaults") || "{}");
  } catch (e) {}

  var wsMode = scanParams.mode || defaults.mode || report.mode || "mask";
  var wsRegion = scanParams.region || defaults.region || report.region || "ALL";
  if (scanParams.salt) {
    var sf = document.getElementById("saltField");
    if (sf) sf.value = scanParams.salt;
  }

  function refreshWorkspace() {
    var rows = document.querySelectorAll("#modeRows .opt-row");
    for (var i = 0; i < rows.length; i++) {
      rows[i].setAttribute("aria-checked", rows[i].getAttribute("data-mode") === wsMode ? "true" : "false");
    }
    var segs = document.querySelectorAll("#regionSeg button");
    for (var j = 0; j < segs.length; j++) {
      segs[j].setAttribute("aria-pressed", segs[j].getAttribute("data-region") === wsRegion ? "true" : "false");
    }
    var exMode = document.getElementById("exMode");
    if (exMode) exMode.textContent = wsMode.toUpperCase();
    try {
      localStorage.setItem("nukepii_defaults", JSON.stringify({ mode: wsMode, region: wsRegion }));
    } catch (e) {}
  }

  var modeRows = document.querySelectorAll("#modeRows .opt-row");
  for (var mi = 0; mi < modeRows.length; mi++) {
    (function (btn) {
      btn.addEventListener("click", function () {
        wsMode = btn.getAttribute("data-mode");
        refreshWorkspace();
      });
    })(modeRows[mi]);
  }
  var segBtns = document.querySelectorAll("#regionSeg button");
  for (var si = 0; si < segBtns.length; si++) {
    (function (btn) {
      btn.addEventListener("click", function () {
        wsRegion = btn.getAttribute("data-region");
        refreshWorkspace();
      });
    })(segBtns[si]);
  }

  function workspaceSalt() {
    var el = document.getElementById("saltField");
    return el ? el.value.trim() : "";
  }

  var stem = report.filename.replace(/\.[^.]+$/, "");
  var ext = (report.filename.split(".").pop() || "txt").toLowerCase();
  var wsFile = document.getElementById("wsFile");
  if (wsFile) wsFile.textContent = report.filename + " · " + report.total_detections + " findings";
  document.getElementById("exInput").textContent = report.filename;
  document.getElementById("exFindings").textContent = report.total_detections;
  document.getElementById("exOutput").textContent = stem + ".nukepii." + ext;
  refreshWorkspace();

  var cleanUrl = null;
  var cleanName = stem + ".nukepii." + ext;

  function openStashed(cb) {
    try {
      var req = indexedDB.open("nukepii", 1);
      req.onsuccess = function () {
        var db = req.result;
        var tx = db.transaction("files", "readonly");
        var get = tx.objectStore("files").get("last-file");
        get.onsuccess = function () {
          cb(get.result || null);
          db.close();
        };
        get.onerror = function () {
          cb(null);
        };
      };
      req.onerror = function () {
        cb(null);
      };
    } catch (e) {
      cb(null);
    }
  }

  function runClean(cb) {
    openStashed(function (file) {
      if (!file) {
        toast(T("dl.gone"));
        cb(new Error("gone"));
        return;
      }
      var form = new FormData();
      form.append("file", file);
      form.append("mode", wsMode);
      form.append("region", wsRegion);
      var s = workspaceSalt();
      if (s) form.append("salt", s);
      fetch("/api/clean", { method: "POST", body: form })
        .then(function (res) {
          if (!res.ok) {
            return res.json().catch(function () { return {}; }).then(function (data) {
              throw new Error(data.error || T("err.clean"));
            });
          }
          return res.blob().then(function (blob) {
            return { blob: blob, disposition: res.headers.get("Content-Disposition") || "" };
          });
        })
        .then(function (out) {
          var m = out.disposition.match(/filename="([^"]+)"/);
          if (m) cleanName = m[1];
          if (cleanUrl) URL.revokeObjectURL(cleanUrl);
          cleanUrl = URL.createObjectURL(out.blob);
          cb(null);
        })
        .catch(function (err) {
          toast(err.message);
          cb(err);
        });
    });
  }

  function downloadCleanUrl() {
    if (!cleanUrl) return;
    var a = document.createElement("a");
    a.href = cleanUrl;
    a.download = cleanName;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  var generateBtn = document.getElementById("generateBtn");
  if (generateBtn) {
    generateBtn.addEventListener("click", function () {
      generateBtn.disabled = true;
      runClean(function (err) {
        generateBtn.disabled = false;
        if (err) return;
        var box = document.getElementById("exportReady");
        document.getElementById("exReadySub").textContent = T("ex.done", { n: report.total_detections });
        box.classList.remove("hidden");
        downloadCleanUrl();
      });
    });
  }
  var exportDlBtn = document.getElementById("exportDownloadBtn");
  if (exportDlBtn) exportDlBtn.addEventListener("click", downloadCleanUrl);
})();
