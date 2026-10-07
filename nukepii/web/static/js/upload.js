// Landing: file pick, file panel, live scan progress, detector grid.
(function () {
  var dropzone = document.getElementById("dropzone");
  var fileInput = document.getElementById("fileInput");
  var fileLabel = document.getElementById("fileLabel");
  var filePanel = document.getElementById("filePanel");
  var scanPanel = document.getElementById("scanPanel");
  var modeSelect = document.getElementById("modeSelect");
  var regionSelect = document.getElementById("regionSelect");
  var saltInput = document.getElementById("saltInput");
  var scanBtn = document.getElementById("scanBtn");
  var cleanBtn = document.getElementById("cleanBtn");
  var changeFileBtn = document.getElementById("changeFileBtn");
  var progress = document.getElementById("scanProgress");
  var busyLabel = document.getElementById("busyLabel");
  var scanSummary = document.getElementById("scanSummary");
  var toastWrap = document.getElementById("toastWrap");
  var themeToggle = document.getElementById("themeToggle");
  var langToggle = document.getElementById("langToggle");

  if (!dropzone || !fileInput) return;

  var selectedFile = null;
  var allowed = ["csv", "json", "jsonl", "sql", "log", "txt", "md"];
  var scanTimer = null;
  var scanStart = 0;

  function T(key, vars) {
    return window.NukeI18n ? window.NukeI18n.t(key, vars) : key;
  }

  function syncThemeLabel() {
    if (!themeToggle) return;
    var light = document.documentElement.classList.contains("light");
    themeToggle.setAttribute("data-mode", light ? "light" : "dark");
    themeToggle.setAttribute("aria-pressed", light ? "true" : "false");
  }

  function refreshTexts() {
    syncThemeLabel();
    if (!selectedFile) fileLabel.textContent = T("file.none");
  }

  if (langToggle) {
    langToggle.addEventListener("click", function () {
      if (window.NukeI18n) window.NukeI18n.toggle();
      refreshTexts();
      renderDetectors();
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

  document.addEventListener("DOMContentLoaded", function () {
    refreshTexts();
    renderDetectors();
  });
  refreshTexts();

  var DETECTORS = [
    ["EMAIL", "det.d.email"],
    ["TR_ID", "det.d.trid"],
    ["PHONE", "det.d.phone"],
    ["CREDIT_CARD", "det.d.card"],
    ["IBAN", "det.d.iban"],
    ["PESEL", "det.d.pesel"],
    ["SSN", "det.d.ssn"],
    ["NIF / NIE", "det.d.nif"],
    ["GB_NINO", "det.d.gb"],
    ["FR_NIR", "det.d.fr"],
    ["IT_FISCAL", "det.d.it"],
    ["BR_CPF", "det.d.br"],
    ["DE_IDNR", "det.d.de"],
    ["TR_VKN", "det.d.vkn"],
    ["DE_TAX_ID", "det.d.detax"],
    ["IN_PAN", "det.d.inpan"],
    ["AU_TFN", "det.d.tfn"],
    ["CA_SIN", "det.d.sin"],
    ["IN_AADHAAR", "det.d.aadhaar"],
    ["US_NPI", "det.d.npi"],
    ["PASSPORT", "det.d.passport"],
    ["DRIVERS_LICENSE", "det.d.dl"],
    ["HEALTH_ID", "det.d.health"],
    ["GITHUB_TOKEN", "det.d.github"],
    ["SLACK_TOKEN", "det.d.slack"],
    ["STRIPE_KEY", "det.d.stripe"],
    ["OPENAI_KEY", "det.d.openai"],
    ["GOOGLE_API_KEY", "det.d.google"],
    ["AZURE_KEY", "det.d.azure"],
    ["DATABASE_URL", "det.d.dburl"],
    ["PRIVATE_KEY", "det.d.pem"],
    ["MAC_ADDRESS", "det.d.mac"],
    ["COORDINATES", "det.d.coord"],
    ["SWIFT_BIC", "det.d.swift"],
    ["US_PHONE", "det.d.usphone"],
    ["INTL_PHONE", "det.d.intl"],
    ["JWT", "det.d.jwt"],
    ["AWS / API KEY", "det.d.apikey"],
    ["IPV4", "det.d.ipv4"],
    ["IPV6", "det.d.ipv6"],
    ["NL_BSN", "det.d.nlbsn"],
    ["BE_NATIONAL_ID", "det.d.benat"],
    ["FI_HETU", "det.d.hetu"],
    ["SE_PERSONNUMMER", "det.d.sepnr"],
    ["NO_FODSELSNUMMER", "det.d.nofnr"],
    ["PT_NIF", "det.d.ptnif"],
    ["RO_CNP", "det.d.rocnp"],
    ["GR_AFM", "det.d.grafm"],
    ["US_ABA", "det.d.aba"],
    ["US_ITIN", "det.d.itin"],
    ["ISIN", "det.d.isin"],
    ["SEDOL", "det.d.sedol"],
    ["IN_IFSC", "det.d.ifsc"],
    ["AU_ABN", "det.d.abn"],
    ["CN_ID", "det.d.cnid"],
    ["KR_RRN", "det.d.krrrn"],
    ["SG_NRIC", "det.d.sgnric"],
    ["IL_ID", "det.d.ilid"],
    ["ZA_ID", "det.d.zaid"],
    ["TH_ID", "det.d.thid"],
    ["TW_ID", "det.d.twid"],
    ["HK_ID", "det.d.hkid"],
    ["JP_MY_NUMBER", "det.d.jpnum"],
    ["IMEI", "det.d.imei"],
    ["VIN", "det.d.vin"],
    ["US_DEA", "det.d.dea"],
    ["US_MBI", "det.d.mbi"],
    ["BTC_ADDRESS", "det.d.btc"],
    ["ETH_ADDRESS", "det.d.eth"],
    ["TELEGRAM_TOKEN", "det.d.telegram"],
    ["ANTHROPIC_KEY", "det.d.anthropic"],
    ["HF_TOKEN", "det.d.hf"],
    ["GITLAB_TOKEN", "det.d.gitlab"],
    ["NPM_TOKEN", "det.d.npm"],
    ["PYPI_TOKEN", "det.d.pypi"],
    ["TWILIO_KEY", "det.d.twilio"],
    ["SENDGRID_KEY", "det.d.sendgrid"],
    ["DISCORD_WEBHOOK", "det.d.discord"]
  ];

  function renderDetectors() {
    var grid = document.getElementById("detGrid");
    if (!grid) return;
    grid.innerHTML = "";
    DETECTORS.forEach(function (d) {
      var cell = document.createElement("div");
      cell.className = "det-cell";
      cell.innerHTML =
        '<p class="nm">' + d[0] + "</p>" +
        '<p class="text-[12px] mt-1" style="color: var(--muted)">' + escapeHtml(T(d[1])) + "</p>" +
        '<p class="st mt-2">' + escapeHtml(T("det.active")) + "</p>";
      grid.appendChild(cell);
    });
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function toast(message) {
    var el = document.createElement("div");
    el.className = "toast";
    el.textContent = message;
    toastWrap.appendChild(el);
    setTimeout(function () {
      el.remove();
    }, 6000);
  }

  function setBusy(busy, percent) {
    progress.style.width = percent + "%";
    scanBtn.disabled = busy || !selectedFile;
    cleanBtn.disabled = busy || !selectedFile;
  }

  function setStatus(msg) {
    if (!msg) {
      busyLabel.classList.add("hidden");
      return;
    }
    busyLabel.textContent = msg;
    busyLabel.classList.remove("hidden");
  }

  function extOf(name) {
    var parts = String(name || "").toLowerCase().split(".");
    return parts.length > 1 ? parts.pop() : "";
  }

  function fmtSize(bytes) {
    if (bytes > 1048576) return (bytes / 1048576).toFixed(1) + " MB";
    return (bytes / 1024).toFixed(1) + " KB";
  }

  // Count newlines in 1 MB slices without holding the file in memory.
  function countRows(file, cb) {
    var slice = 1024 * 1024;
    var offset = 0;
    var count = 0;
    var reader = new FileReader();
    reader.onload = function () {
      var text = String(reader.result || "");
      for (var i = 0; i < text.length; i++) {
        if (text.charCodeAt(i) === 10) count++;
      }
      offset += slice;
      if (offset < file.size) {
        readNext();
      } else {
        cb(count);
      }
    };
    reader.onerror = function () {
      cb(null);
    };
    function readNext() {
      reader.readAsText(file.slice(offset, offset + slice));
    }
    readNext();
  }

  function pickFile(file) {
    scanSummary.classList.add("hidden");
    if (!file) {
      clearFile();
      return;
    }
    var ext = extOf(file.name);
    if (allowed.indexOf(ext) === -1) {
      toast(T("toast.badext", { ext: ext || "?" }));
      return;
    }
    if (file.size === 0) {
      toast(T("toast.empty"));
      return;
    }
    if (file.size > 256 * 1024 * 1024) {
      toast(T("toast.toobig"));
      return;
    }
    selectedFile = file;
    fileLabel.textContent = T("file.picked", { name: file.name, kb: (file.size / 1024).toFixed(1) });
    dropzone.classList.add("hidden");
    scanPanel.classList.add("hidden");
    filePanel.classList.remove("hidden");
    document.getElementById("fpName").textContent = file.name;
    document.getElementById("fpSize").textContent = fmtSize(file.size);
    document.getElementById("fpFormat").textContent = ext.toUpperCase();
    document.getElementById("fpRows").textContent = "…";
    scanBtn.disabled = false;
    cleanBtn.disabled = false;
    countRows(file, function (n) {
      if (file !== selectedFile) return;
      if (n !== null && n > 0) {
        document.getElementById("fpRows").textContent = n.toLocaleString(
          window.NukeI18n && window.NukeI18n.lang() === "en" ? "en-US" : "tr-TR"
        );
      } else {
        document.getElementById("fpRows").textContent = "—";
      }
    });
  }

  function clearFile() {
    selectedFile = null;
    fileInput.value = "";
    fileLabel.textContent = T("file.none");
    filePanel.classList.add("hidden");
    scanPanel.classList.add("hidden");
    dropzone.classList.remove("hidden");
    scanBtn.disabled = true;
    cleanBtn.disabled = true;
    setBusy(false, 0);
    setStatus("");
  }

  dropzone.addEventListener("click", function () {
    fileInput.click();
  });

  dropzone.addEventListener("keydown", function (e) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      fileInput.click();
    }
  });

  fileInput.addEventListener("change", function (e) {
    pickFile(e.target.files[0]);
  });

  ["dragenter", "dragover"].forEach(function (name) {
    dropzone.addEventListener(name, function (e) {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });
  });

  ["dragleave", "drop"].forEach(function (name) {
    dropzone.addEventListener(name, function (e) {
      e.preventDefault();
      dropzone.classList.remove("dragover");
    });
  });

  dropzone.addEventListener("drop", function (e) {
    var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    pickFile(f);
  });

  if (changeFileBtn) {
    changeFileBtn.addEventListener("click", clearFile);
  }

  function buildForm() {
    var form = new FormData();
    form.append("file", selectedFile);
    form.append("mode", modeSelect.value);
    form.append("region", regionSelect.value);
    var salt = saltInput.value.trim();
    if (salt) form.append("salt", salt);
    return form;
  }

  function rememberParams() {
    try {
      sessionStorage.setItem(
        "nukepii_params",
        JSON.stringify({ mode: modeSelect.value, region: regionSelect.value, salt: saltInput.value.trim() })
      );
    } catch (e) {}
  }

  function recordHistory(out) {
    try {
      var h = JSON.parse(localStorage.getItem("nukepii_history") || "[]");
      h.unshift({
        date: new Date().toISOString(),
        file: out.filename,
        findings: out.total_detections,
        risk: out.risk_label,
        mode: out.mode
      });
      localStorage.setItem("nukepii_history", JSON.stringify(h.slice(0, 30)));
    } catch (e) {}
  }

  // Keep the raw file locally so the dashboard can offer a cleaned download
  // without asking for the file again. Stays in this browser only.
  function stashFile() {
    return new Promise(function (resolve) {
      try {
        var req = indexedDB.open("nukepii", 1);
        req.onupgradeneeded = function () {
          req.result.createObjectStore("files");
        };
        req.onsuccess = function () {
          var db = req.result;
          var tx = db.transaction("files", "readwrite");
          tx.objectStore("files").put(selectedFile, "last-file");
          tx.oncomplete = function () {
            db.close();
            resolve();
          };
          tx.onerror = function () {
            resolve();
          };
        };
        req.onerror = function () {
          resolve();
        };
      } catch (e) {
        resolve();
      }
    });
  }

  function paintBar(frac) {
    var cells = 30;
    var full = Math.round(frac * cells);
    var s = "";
    for (var i = 0; i < cells; i++) s += i < full ? "█" : "░";
    document.getElementById("spBar").textContent = s;
  }

  function startClock() {
    scanStart = Date.now();
    var el = document.getElementById("spElapsed");
    scanTimer = setInterval(function () {
      el.textContent = ((Date.now() - scanStart) / 1000).toFixed(1) + "s";
    }, 100);
  }

  function stopClock() {
    if (scanTimer) clearInterval(scanTimer);
    scanTimer = null;
  }

  scanBtn.addEventListener("click", function () {
    if (!selectedFile) return;
    filePanel.classList.add("hidden");
    scanPanel.classList.remove("hidden");
    document.getElementById("spFile").textContent = selectedFile.name;
    document.getElementById("spRows").textContent = document.getElementById("fpRows").textContent;
    setBusy(true, 0);
    paintBar(0);
    startClock();
    // XHR (not fetch) so the bar reflects the real upload byte count.
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/scan");
    xhr.responseType = "json";
    xhr.upload.onprogress = function (e) {
      if (e.lengthComputable) {
        var p = Math.round((e.loaded / e.total) * 85);
        setBusy(true, p);
        paintBar(p / 100);
        document.getElementById("spUpload").textContent = p + "%";
      }
    };
    xhr.onload = function () {
      stopClock();
      var out = xhr.response;
      if (xhr.status < 200 || xhr.status >= 300 || !out) {
        toast((out && out.error) || T("err.scan"));
        setBusy(false, 0);
        scanPanel.classList.add("hidden");
        filePanel.classList.remove("hidden");
        return;
      }
      try {
        sessionStorage.setItem("nukepii_scan", JSON.stringify(out));
      } catch (e) {}
      rememberParams();
      recordHistory(out);
      setBusy(true, 100);
      paintBar(1);
      document.getElementById("spUpload").textContent = "100%";
      stashFile().then(function () {
        setTimeout(function () {
          window.location.href = "/analysis";
        }, 450);
      });
    };
    xhr.onerror = function () {
      stopClock();
      toast(T("err.scan"));
      setBusy(false, 0);
      scanPanel.classList.add("hidden");
      filePanel.classList.remove("hidden");
    };
    xhr.send(buildForm());
  });

  cleanBtn.addEventListener("click", function () {
    if (!selectedFile) return;
    setBusy(true, 30);
    setStatus(T("st.clean"));
    fetch("/api/clean", { method: "POST", body: buildForm() })
      .then(function (res) {
        if (!res.ok) {
          return res.json().catch(function () {
            return {};
          }).then(function (data) {
            throw new Error(data.error || T("err.clean"));
          });
        }
        return res.blob().then(function (blob) {
          return { blob: blob, disposition: res.headers.get("Content-Disposition") || "" };
        });
      })
      .then(function (out) {
        var m = out.disposition.match(/filename="([^"]+)"/);
        var url = URL.createObjectURL(out.blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = m ? m[1] : "cleaned.dat";
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        scanSummary.textContent = T("sum.clean");
        scanSummary.classList.remove("hidden");
        setBusy(false, 0);
        setStatus("");
      })
      .catch(function (err) {
        toast(err.message);
        setBusy(false, 0);
        setStatus("");
      });
  });

  // Shortcuts: typing in salt must never trigger actions.
  document.addEventListener("keydown", function (e) {
    var tag = (document.activeElement && document.activeElement.tagName) || "";
    if (tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA") return;
    if ((e.key === "s" || e.key === "S") && !scanBtn.disabled && !filePanel.classList.contains("hidden")) {
      e.preventDefault();
      scanBtn.click();
    }
  });

  renderDetectors();
})();
