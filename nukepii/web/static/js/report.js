// Analysis page: renders the /api/scan payload stored as nukepii_scan.
// Cleaning lives on /clean (workspace.js); history on /history.
(function () {
  var themeToggle = document.getElementById("themeToggle");
  var langToggle = document.getElementById("langToggle");
  var toastWrap = document.getElementById("toastWrap");
  var loadingState = document.getElementById("loadingState");
  var emptyState = document.getElementById("emptyState");
  var reportGrid = document.getElementById("reportGrid");
  var truncBanner = document.getElementById("truncBanner");

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
      // Dynamic report texts are rendered once, so re-render in the new language.
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

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  // Rebuild from ordered segments so escaping stays safe with marks.
  function highlight(text, spans) {
    var safe = String(text);
    var valid = (spans || [])
      .filter(function (s) {
        return Number.isInteger(s.start) && Number.isInteger(s.end) && s.start < s.end && s.end <= safe.length;
      })
      .sort(function (a, b) {
        return a.start - b.start;
      });
    var out = "";
    var cursor = 0;
    for (var i = 0; i < valid.length; i++) {
      var s = valid[i];
      if (s.start < cursor) continue;
      out += escapeHtml(safe.slice(cursor, s.start));
      out += '<mark title="' + escapeHtml(s.type) + '">' + escapeHtml(safe.slice(s.start, s.end)) + "</mark>";
      cursor = s.end;
    }
    out += escapeHtml(safe.slice(cursor));
    return out;
  }

  var raw = null;
  try {
    raw = sessionStorage.getItem("nukepii_scan");
  } catch (e) {}

  if (loadingState) loadingState.style.display = "none";

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
  if (reportGrid) {
    reportGrid.classList.remove("hidden");
    reportGrid.style.display = "block";
  }

  var riskColors = { LOW: "#18E875", MODERATE: "#E5B84B", HIGH: "#FF5C67", CRITICAL: "#FF5C67" };
  var risk = riskColors[report.risk_label] || "#8d9bb8";
  var riskLabelTr = T("risk." + report.risk_label);
  var unitKindTr = T("unit." + report.unit_kind);

  var fileMeta = document.getElementById("fileMeta");
  if (fileMeta) {
    var kb = report.size_bytes > 1048576
      ? (report.size_bytes / 1048576).toFixed(1) + " MB"
      : (report.size_bytes / 1024).toFixed(1) + " KB";
    fileMeta.textContent = T("dash.meta", { f: report.filename, kb: kb, u: report.units, uk: unitKindTr, n: report.total_detections });
    fileMeta.removeAttribute("data-i18n");
  }
  var riskDot = document.getElementById("riskDot");
  var riskText = document.getElementById("riskText");
  if (riskDot) riskDot.style.background = risk;
  if (riskText) {
    riskText.textContent = riskLabelTr + " risk";
    riskText.removeAttribute("data-i18n");
  }

  if (report.truncated && truncBanner) {
    truncBanner.textContent = T("dash.trunc", { u: report.units, uk: unitKindTr });
    truncBanner.classList.remove("hidden");
  }

  document.getElementById("kpiRiskScore").textContent = report.risk_score;
  document.getElementById("kpiRiskLabel").textContent = T("riskn." + report.risk_label);
  document.getElementById("kpiDetections").textContent = report.total_detections.toLocaleString(window.NukeI18n && window.NukeI18n.lang() === "en" ? "en-US" : "tr-TR");
  document.getElementById("kpiTypes").textContent = T("kpi.types", { n: report.breakdown.length });
  document.getElementById("kpiUnits").textContent = report.units.toLocaleString(window.NukeI18n && window.NukeI18n.lang() === "en" ? "en-US" : "tr-TR");
  document.getElementById("kpiUnitKind").textContent = unitKindTr;
  var comp = report.compliance_summary || {};
  document.getElementById("kpiGdpr").textContent = comp.GDPR || 0;
  document.getElementById("kpiKvkk").textContent = comp.KVKK || 0;
  document.getElementById("kpiCcpa").textContent = comp.CCPA || 0;
  var kpiLgpd = document.getElementById("kpiLgpd");
  if (kpiLgpd) kpiLgpd.textContent = comp.LGPD || 0;
  var kpiHipaa = document.getElementById("kpiHipaa");
  if (kpiHipaa) kpiHipaa.textContent = comp.HIPAA || 0;
  document.getElementById("gaugeValue").textContent = report.risk_score;
  var riskBar = document.getElementById("riskBarFill");
  if (riskBar) {
    riskBar.style.width = report.risk_score + "%";
    riskBar.style.background = risk;
  }
  var riskInline = document.getElementById("kpiRiskLabelInline");
  if (riskInline) {
    riskInline.textContent = T("riskn." + report.risk_label);
    riskInline.style.color = risk;
  }

  var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Workspace mode remembered from /scan (used for the action column).
  var scanParams = {};
  try {
    scanParams = JSON.parse(sessionStorage.getItem("nukepii_params") || "{}");
  } catch (e) {}
  var defaults = {};
  try {
    defaults = JSON.parse(localStorage.getItem("nukepii_defaults") || "{}");
  } catch (e) {}
  var wsMode = scanParams.mode || defaults.mode || report.mode || "mask";

  if (window.Chart) {
    new Chart(document.getElementById("gaugeChart"), {
      type: "doughnut",
      data: {
        datasets: [{ data: [report.risk_score, 100 - report.risk_score], backgroundColor: [risk, "#1A2820"], borderWidth: 0 }]
      },
      options: {
        circumference: 180,
        rotation: -90,
        cutout: "72%",
        maintainAspectRatio: false,
        layout: { padding: { bottom: 4 } },
        animation: reduceMotion ? false : undefined,
        plugins: { legend: { display: false }, tooltip: { enabled: false } }
      }
    });

    var typeColors = {
      EMAIL: "#18E875", TR_PHONE: "#35F58A", US_PHONE: "#7FE8AC", INTL_PHONE: "#5A6E62",
      TR_NATIONAL_ID: "#0BAE55", TR_VKN: "#12C46A", PL_PESEL: "#0C8A48", US_SSN: "#2DD4A8",
      ES_NIF: "#0A6E3C", ES_NIE: "#5EEAD4", DE_TAX_ID: "#0E9E57",
      GB_NINO: "#12C46A", FR_NIR: "#0E9E57", DE_IDNR: "#0B7A45", IT_FISCAL: "#2BD98A",
      BR_CPF: "#E5B84B", IN_PAN: "#C9A227", AU_TFN: "#8FD694", CA_SIN: "#2DD4A8",
      IN_AADHAAR: "#0C8A48", US_NPI: "#7FE8AC", PASSPORT: "#A7B5AC", DRIVERS_LICENSE: "#66756C",
      HEALTH_INSURANCE_ID: "#8FD694",
      IBAN: "#A7B5AC", SWIFT_BIC: "#66756C", CREDIT_CARD: "#66756C",
      JWT: "#E5B84B", AWS_API_KEY: "#C99A2E", GITHUB_TOKEN: "#C99A2E", STRIPE_KEY: "#C99A2E",
      OPENAI_KEY: "#C99A2E", GOOGLE_API_KEY: "#C99A2E", AZURE_KEY: "#C99A2E",
      PRIVATE_KEY: "#C99A2E", SLACK_WEBHOOK: "#8A6D1B", DATABASE_URL: "#8A6D1B",
      GENERIC_API_KEY: "#8A6D1B",
      IPV4: "#3A4A40", IPV6: "#26332B", MAC_ADDRESS: "#3A4A40", COORDINATES: "#2BD98A"
    };
    var labels = report.breakdown.map(function (b) { return b.type; });
    var counts = report.breakdown.map(function (b) { return b.count; });
    var colors = labels.map(function (t) { return typeColors[t] || "#8d9bb8"; });

    new Chart(document.getElementById("donutChart"), {
      type: "doughnut",
      data: {
        labels: labels,
        datasets: [{ data: counts, backgroundColor: colors, borderColor: "#0a111f", borderWidth: 3 }]
      },
      options: {
        maintainAspectRatio: false,
        cutout: "68%",
        animation: reduceMotion ? false : undefined,
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: function (ctx) { return " " + T("tip.one", { c: ctx.parsed }); } } }
        }
      }
    });

    var legend = document.getElementById("donutLegend");
    legend.innerHTML = "";
    report.breakdown.forEach(function (b) {
      var li = document.createElement("li");
      li.innerHTML =
        '<span class="type-badge">' + escapeHtml(b.type) +
        '<span class="type-count">' + b.count + "</span></span>";
      legend.appendChild(li);
    });

    // Detection table: type | matches | risk | action (workspace mode from /scan).
    var weights = {
      TR_NATIONAL_ID: 10, PL_PESEL: 10, US_SSN: 10, ES_NIF: 10, ES_NIE: 10,
      CREDIT_CARD: 9, AWS_API_KEY: 9, IBAN: 9, JWT: 8, GENERIC_API_KEY: 7,
      EMAIL: 5, TR_PHONE: 5, IPV4: 3, IPV6: 3
    };
    var detectBody = document.getElementById("detectBody");
    if (detectBody) {
      detectBody.innerHTML = "";
      report.breakdown.forEach(function (b) {
        var w = weights[b.type] || 1;
        var rc = w >= 9 ? "#FF5C67" : w >= 5 ? "#E5B84B" : "#18E875";
        var rl = w >= 9 ? T("lvl.high") : w >= 5 ? T("lvl.med") : T("lvl.low");
        var tr = document.createElement("tr");
        tr.innerHTML =
          '<td><span class="type-badge">' + escapeHtml(b.type) + "</span></td>" +
          '<td class="col-count">' + b.count + "</td>" +
          '<td><span class="risk-tag" style="color:' + rc + '">' + escapeHtml(rl) + "</span></td>" +
          '<td class="col-name">' + escapeHtml(wsMode.toUpperCase()) + "</td>";
        detectBody.appendChild(tr);
      });
    }
  }

  var kindNames = { columns: T("kind.columns"), keys: T("kind.keys"), segments: T("kind.segments") };
  document.getElementById("heatKind").textContent = kindNames[report.heatmap.kind] || report.heatmap.kind;
  var heat = document.getElementById("heatmap");
  var peak = Math.max.apply(null, report.heatmap.items.map(function (item) { return item.count; }).concat([0]));
  heat.innerHTML = "";
  if (!report.heatmap.items.length) {
    var emptyRow = document.createElement("tr");
    emptyRow.innerHTML = '<td colspan="4" class="text-[13px]" style="color: var(--muted)">' + escapeHtml(T("heat.none")) + "</td>";
    heat.appendChild(emptyRow);
  }
  report.heatmap.items.forEach(function (item) {
    var ratio = peak ? item.count / peak : 0;
    var edge, level;
    if (item.count === 0) {
      edge = "#18E875";
      level = T("lvl.clean");
    } else if (ratio > 0.66) {
      edge = "#FF5C67";
      level = T("lvl.high");
    } else if (ratio > 0.33) {
      edge = "#E5B84B";
      level = T("lvl.med");
    } else {
      edge = "#18E875";
      level = T("lvl.low");
    }
    var tr = document.createElement("tr");
    tr.title = T("heat.tip", { l: item.label, c: item.count });
    tr.innerHTML =
      '<td class="col-name">' + escapeHtml(item.label) + "</td>" +
      '<td class="col-count">' + item.count + "</td>" +
      '<td class="col-bar"><div class="heat-bar"><div style="width:' + item.risk + "%;background:" + edge + '"></div></div></td>' +
      '<td><span class="risk-tag" style="color:' + edge + '">' + escapeHtml(level) + "</span></td>";
    heat.appendChild(tr);
  });

  var diff = document.getElementById("diffViewer");
  if (!report.preview.length) {
    diff.innerHTML = '<p class="text-[13px]" style="color: var(--muted)">' + escapeHtml(T("diff.none")) + "</p>";
  }
  report.preview.forEach(function (row) {
    var card = document.createElement("div");
    card.style.border = "1px solid var(--line)";
    card.style.borderRadius = "10px";
    card.style.overflow = "hidden";
    card.style.background = "var(--surface)";
    card.innerHTML =
      '<p class="mono px-4 py-2 text-[12px]" style="color: var(--muted); border-bottom: 1px solid var(--line)">' + escapeHtml(T("diff.line", { n: row.line })) + "</p>" +
      '<div class="grid md:grid-cols-2" style="min-width:0;">' +
      '<div class="diff-scroll p-4" style="min-width:0;"><p class="text-[12px] mono mb-2" style="color: var(--muted)">' + escapeHtml(T("diff.orig")) + "</p>" + '<pre class="diff-pane">' + highlight(row.raw, row.spans) + "</pre></div>" +
      '<div class="diff-scroll p-4" style="min-width:0;border-top: 1px solid var(--line);"><p class="text-[12px] mono mb-2" style="color: var(--muted)">' + escapeHtml(T("diff.clean")) + "</p>" + '<pre class="diff-pane">' + escapeHtml(row.clean) + "</pre></div>" +
      "</div>";
    diff.appendChild(card);
  });

  function copyCleaned() {
    var text = report.preview.map(function (row) { return row.clean; }).join("\n");
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(function () {
        toast(T("copy.ok"));
      }, function () {
        toast(T("copy.fail"));
      });
    }
  }

  function exportJson() {
    var blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = report.filename + ".nukepii-report.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function copySummary() {
    var text = T("sum.text", {
      f: report.filename, n: report.total_detections,
      s: report.risk_score, r: T("risk." + report.risk_label),
      u: report.units, uk: T("unit." + report.unit_kind)
    });
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(function () {
        toast(T("sum.copied"));
      }, function () {
        toast(T("copy.fail"));
      });
    }
  }

  var copyBtn = document.getElementById("copyCleanBtn");
  if (copyBtn) copyBtn.addEventListener("click", copyCleaned);
  var jsonBtn = document.getElementById("downloadJsonBtn");
  if (jsonBtn) jsonBtn.addEventListener("click", exportJson);
  var sumBtn = document.getElementById("copySummaryBtn");
  if (sumBtn) sumBtn.addEventListener("click", copySummary);

  document.addEventListener("keydown", function (e) {
    var tag = (document.activeElement && document.activeElement.tagName) || "";
    if (tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA") return;
    var k = (e.key || "").toLowerCase();
    if (k === "n") {
      window.location.href = "/scan";
    } else if (k === "c") {
      copyCleaned();
    } else if (k === "e") {
      exportJson();
    }
  });
})();
