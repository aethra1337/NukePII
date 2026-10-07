// SCAN FIELD — interactive hero figure for /scan.
//
// Mouse: crosshair + live x/y readout. Hover/focus a signal dot for a
// masked-sample tooltip. Click (or Enter) pins the detail readout.
// DEMO SCAN runs a radar sweep that reveals the 5 signals in order.
//
// Respects theme (CSS vars), language (NukeI18n, live via MutationObserver)
// and prefers-reduced-motion (static render, instant demo reveal).
(function () {
  "use strict";

  var W = 520, H = 340;
  var CX = 150, CY = 150; // radar center

  var SIGS = [
    { id: "EMAIL", x: 300, y: 72, lx: 300, ly: 60, sample: "j******e@e******.com", region: "GLOBAL", compliance: "GDPR" },
    { id: "TR_ID", x: 360, y: 162, lx: 360, ly: 150, sample: "100******46", region: "TR", compliance: "KVKK" },
    { id: "IBAN", x: 300, y: 262, lx: 300, ly: 250, sample: "TR******************26", region: "TR", compliance: "GDPR · KVKK" },
    { id: "PHONE", x: 120, y: 288, lx: 120, ly: 300, sample: "+90 532 *** ** 67", region: "TR", compliance: "KVKK" },
    { id: "API_KEY", x: 420, y: 288, lx: 420, ly: 300, sample: "ghp_••••••••••••", region: "GLOBAL", compliance: "—" }
  ];

  function T(key, fallback) {
    try {
      if (window.NukeI18n) {
        var s = window.NukeI18n.t(key);
        if (s && s !== key) return s;
      }
    } catch (e) {}
    return fallback;
  }

  function cssVar(name, fallback) {
    try {
      var v = getComputedStyle(document.documentElement).getPropertyValue(name);
      if (v && v.trim()) return v.trim();
    } catch (e) {}
    return fallback;
  }

  function pad4(n) {
    n = Math.max(0, Math.min(9999, Math.round(n)));
    return ("0000" + n).slice(-4);
  }

  var fig = document.getElementById("scanFieldFig");
  var field = document.getElementById("scanField");
  if (!fig || !field) return;
  var canvas = field.querySelector("canvas.scanfield-canvas");
  var tip = document.getElementById("scanFieldTip");
  var coordsEl = document.getElementById("sfCoords");
  var statusEl = document.getElementById("sfStatus");
  var demoBtn = document.getElementById("scanFieldDemo");
  var dots = Array.prototype.slice.call(field.querySelectorAll(".sf-dot"));
  if (!canvas || !canvas.getContext) return;
  var ctx = canvas.getContext("2d");

  var reduced = false;
  try {
    reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  } catch (e) {}

  var state = {
    mouse: null,          // {x, y} in field coords
    hover: null,          // signal id
    selected: null,       // signal id
    found: {},            // id -> true (demo reveal)
    demo: null,           // {t0, order:[ids], idx} while running
    raf: 0
  };

  function byId(id) {
    for (var i = 0; i < SIGS.length; i++) if (SIGS[i].id === id) return SIGS[i];
    return null;
  }

  function fitCanvas() {
    var dpr = 1;
    try { dpr = Math.min(2, window.devicePixelRatio || 1); } catch (e) {}
    canvas.width = W * dpr;
    canvas.height = H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function draw(now) {
    var accent = cssVar("--accent", "#18E875");
    var grid = cssVar("--border-light", "rgba(148,163,184,0.25)");
    var muted = cssVar("--muted", "#94a3b8");
    var faint = cssVar("--faint", "#64748b");
    var ring = cssVar("--text-muted", "#cbd5e1");

    ctx.clearRect(0, 0, W, H);

    // grid
    ctx.strokeStyle = grid;
    ctx.lineWidth = 1;
    ctx.beginPath();
    [85, 170, 255].forEach(function (y) { ctx.moveTo(0, y + 0.5); ctx.lineTo(W, y + 0.5); });
    [130, 260, 390].forEach(function (x) { ctx.moveTo(x + 0.5, 0); ctx.lineTo(x + 0.5, H); });
    ctx.stroke();

    // radar rings + cross
    ctx.strokeStyle = ring;
    ctx.globalAlpha = 0.85;
    [72, 46, 20].forEach(function (r) { ctx.beginPath(); ctx.arc(CX, CY, r, 0, Math.PI * 2); ctx.stroke(); });
    ctx.beginPath();
    ctx.moveTo(CX, CY - 84); ctx.lineTo(CX, CY + 84);
    ctx.moveTo(CX - 84, CY); ctx.lineTo(CX + 84, CY);
    ctx.stroke();
    ctx.globalAlpha = 1;

    // demo sweep wedge
    if (state.demo) {
      var t = ((now - state.demo.t0) / 2600) % 1;
      var a = -Math.PI / 2 + t * Math.PI * 2;
      ctx.save();
      ctx.strokeStyle = accent;
      ctx.globalAlpha = 0.9;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(CX, CY);
      ctx.lineTo(CX + Math.cos(a) * 110, CY + Math.sin(a) * 110);
      ctx.stroke();
      // fading trail
      for (var k = 1; k <= 8; k++) {
        var ta = a - k * 0.045;
        ctx.globalAlpha = 0.5 * (1 - k / 9);
        ctx.beginPath();
        ctx.moveTo(CX, CY);
        ctx.lineTo(CX + Math.cos(ta) * 110, CY + Math.sin(ta) * 110);
        ctx.stroke();
      }
      ctx.restore();
    }

    // signal trail curve
    ctx.save();
    ctx.strokeStyle = accent;
    ctx.lineWidth = 1.5;
    ctx.setLineDash([5, 4]);
    ctx.beginPath();
    ctx.moveTo(40, 300);
    ctx.bezierCurveTo(140, 290, 220, 220, 330, 200);
    ctx.bezierCurveTo(400, 187, 470, 170, 492, 120);
    ctx.stroke();
    ctx.restore();

    // crosshair
    if (state.mouse) {
      ctx.save();
      ctx.strokeStyle = accent;
      ctx.globalAlpha = 0.45;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(state.mouse.x + 0.5, 0); ctx.lineTo(state.mouse.x + 0.5, H);
      ctx.moveTo(0, state.mouse.y + 0.5); ctx.lineTo(W, state.mouse.y + 0.5);
      ctx.stroke();
      ctx.globalAlpha = 0.9;
      ctx.beginPath();
      ctx.arc(state.mouse.x, state.mouse.y, 5, 0, Math.PI * 2);
      ctx.stroke();
      ctx.restore();
    }

    // labels
    ctx.font = "11px 'IBM Plex Mono', ui-monospace, monospace";
    ctx.fillStyle = muted;
    ctx.fillText("FILE_01", 18, 30);
    ctx.fillText("COLUMN_17", 18, 48);

    SIGS.forEach(function (s) {
      var revealed = state.demo ? !!state.found[s.id] : true;
      var hot = state.hover === s.id || state.selected === s.id;
      ctx.fillStyle = revealed ? (hot ? accent : muted) : faint;
      ctx.globalAlpha = revealed ? 1 : 0.45;
      // keep labels inside the field
      var lx = Math.min(Math.max(s.lx, 8), W - 70);
      ctx.fillText(s.id, lx, s.ly);
      if (hot && revealed) {
        ctx.save();
        ctx.strokeStyle = accent;
        ctx.globalAlpha = 0.9;
        ctx.beginPath();
        ctx.arc(s.x, s.y, 9, 0, Math.PI * 2);
        ctx.stroke();
        ctx.restore();
      }
      ctx.globalAlpha = 1;
    });

    // coords readout (canvas copy, top-right)
    var cx = state.mouse ? state.mouse.x : 420;
    var cy = state.mouse ? state.mouse.y : 117;
    ctx.fillStyle = faint;
    ctx.fillText("x:" + pad4(cx), 452, 30);
    ctx.fillText("y:" + pad4(cy), 452, 48);
  }

  function scheduleDraw() {
    if (state.raf) return;
    state.raf = requestAnimationFrame(function () {
      state.raf = 0;
      draw(performance.now());
      if (state.demo) scheduleDraw(); // keep sweeping
    });
  }

  function setCoords(x, y) {
    if (coordsEl) coordsEl.textContent = "x:" + pad4(x) + " y:" + pad4(y);
  }

  function toField(evt) {
    var r = canvas.getBoundingClientRect();
    var x = (evt.clientX - r.left) * (W / r.width);
    var y = (evt.clientY - r.top) * (H / r.height);
    return {
      x: Math.max(0, Math.min(W, x)),
      y: Math.max(0, Math.min(H, y))
    };
  }

  // -- tooltip -----------------------------------------------------------
  function showTip(sig, anchorBtn) {
    if (!tip) return;
    var sampleLabel = T("scanfield.sample", "örnek");
    tip.innerHTML = "";
    var b = document.createElement("div");
    b.className = "scanfield-tip-type";
    b.textContent = sig.id;
    var s = document.createElement("div");
    s.className = "scanfield-tip-sample";
    s.textContent = sampleLabel + ": " + sig.sample;
    var c = document.createElement("div");
    c.className = "scanfield-tip-meta";
    c.textContent = sig.region + " · " + sig.compliance;
    tip.appendChild(b);
    tip.appendChild(s);
    tip.appendChild(c);
    tip.classList.remove("hidden");
    // position above the dot, clamped into the field
    var fr = field.getBoundingClientRect();
    var br = anchorBtn.getBoundingClientRect();
    var dx = br.left - fr.left + br.width / 2;
    var dy = br.top - fr.top;
    tip.style.left = "0";
    tip.style.top = "0";
    var tw = tip.offsetWidth, th = tip.offsetHeight;
    var left = Math.min(Math.max(dx - tw / 2, 6), fr.width - tw - 6);
    var top = dy - th - 12;
    if (top < 4) top = dy + br.height + 10;
    tip.style.transform = "translate(" + left + "px," + top + "px)";
  }

  function hideTip() {
    if (tip) tip.classList.add("hidden");
  }

  function select(sig) {
    state.selected = sig ? sig.id : null;
    dots.forEach(function (d) {
      d.classList.toggle("active", !!sig && d.getAttribute("data-sig") === sig.id);
    });
    if (statusEl) {
      if (sig) {
        var sampleLabel = T("scanfield.sample", "örnek");
        statusEl.textContent = sig.id + " · " + sig.region + " · " + sig.compliance +
          " — " + sampleLabel + ": " + sig.sample;
      } else {
        statusEl.textContent = T("scanfield.hint", "Alanın üzerinde gez — sinyale tıkla");
      }
    }
    scheduleDraw();
  }

  // -- events ------------------------------------------------------------
  field.addEventListener("mousemove", function (evt) {
    if (evt.target && evt.target.classList && evt.target.classList.contains("sf-dot")) return;
    var p = toField(evt);
    state.mouse = p;
    setCoords(p.x, p.y);
    scheduleDraw();
  });

  field.addEventListener("mouseleave", function () {
    state.mouse = null;
    scheduleDraw();
  });

  dots.forEach(function (btn) {
    var sig = byId(btn.getAttribute("data-sig"));
    if (!sig) return;
    btn.addEventListener("mouseenter", function () {
      state.hover = sig.id;
      showTip(sig, btn);
      scheduleDraw();
    });
    btn.addEventListener("mouseleave", function () {
      if (state.hover === sig.id) state.hover = null;
      hideTip();
      scheduleDraw();
    });
    btn.addEventListener("focus", function () {
      state.hover = sig.id;
      showTip(sig, btn);
      scheduleDraw();
    });
    btn.addEventListener("blur", function () {
      if (state.hover === sig.id) state.hover = null;
      hideTip();
      scheduleDraw();
    });
    btn.addEventListener("click", function (evt) {
      evt.stopPropagation();
      select(state.selected === sig.id ? null : sig);
      showTip(sig, btn);
    });
  });

  field.addEventListener("click", function (evt) {
    if (evt.target === canvas || evt.target === field) select(null);
  });

  document.addEventListener("keydown", function (evt) {
    if (evt.key === "Escape" && state.selected) select(null);
  });

  // -- demo sweep ----------------------------------------------------------
  function demoOrder() {
    // reveal in sweep-angle order from the radar center
    return SIGS.slice().sort(function (a, b) {
      var aa = Math.atan2(a.y - CY, a.x - CX);
      var bb = Math.atan2(b.y - CY, b.x - CX);
      return aa - bb;
    });
  }

  function setStatusFound(n) {
    var tpl = T("scanfield.found", "{n}/5 SİNYAL");
    if (statusEl) statusEl.textContent = tpl.replace("{n}", String(n));
  }

  function demoDone() {
    state.demo = null;
    if (demoBtn) {
      demoBtn.disabled = false;
      var label = demoBtn.querySelector("[data-i18n]");
      if (label) label.textContent = T("scanfield.demo", "Demo tara");
    }
    var tpl = T("scanfield.done", "{n} sinyal · 0 bayt yüklendi");
    if (statusEl) statusEl.textContent = tpl.replace("{n}", String(SIGS.length));
    dots.forEach(function (d) { d.classList.add("found"); });
    scheduleDraw();
  }

  function demoStep() {
    if (!state.demo) return;
    var next = state.demo.order[state.demo.idx];
    if (!next) { demoDone(); return; }
    state.found[next.id] = true;
    var btn = field.querySelector('.sf-dot[data-sig="' + next.id + '"]');
    if (btn) {
      btn.classList.add("ping");
      setTimeout(function () { btn.classList.remove("ping"); }, 700);
    }
    state.demo.idx += 1;
    setStatusFound(state.demo.idx);
    scheduleDraw();
    state.demo.timer = setTimeout(demoStep, 520);
  }

  if (demoBtn) {
    demoBtn.addEventListener("click", function () {
      if (state.demo) return;
      select(null);
      hideTip();
      state.found = {};
      dots.forEach(function (d) { d.classList.remove("found"); });
      if (reduced) {
        SIGS.forEach(function (s) { state.found[s.id] = true; });
        demoDone();
        return;
      }
      state.demo = { t0: performance.now(), order: demoOrder(), idx: 0, timer: 0 };
      demoBtn.disabled = true;
      var label = demoBtn.querySelector("[data-i18n]");
      var running = T("scanfield.running", "Taranıyor…");
      if (label) label.textContent = running;
      else demoBtn.textContent = running;
      setStatusFound(0);
      scheduleDraw();
      demoStep();
    });
  }

  // -- live theme / language ----------------------------------------------
  var refresh = function () {
    if (statusEl && !state.selected && !state.demo) {
      statusEl.textContent = T("scanfield.hint", "Alanın üzerinde gez — sinyale tıkla");
    }
    if (demoBtn && !state.demo) {
      var label = demoBtn.querySelector("[data-i18n]");
      if (label) label.textContent = T("scanfield.demo", "Demo tara");
    }
    scheduleDraw();
  };
  try {
    var mo = new MutationObserver(function () { refresh(); });
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["lang", "class"] });
  } catch (e) {
    document.addEventListener("DOMContentLoaded", refresh);
  }

  window.addEventListener("resize", scheduleDraw);

  fitCanvas();
  try {
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(scheduleDraw);
  } catch (e) {}
  scheduleDraw();
})();
