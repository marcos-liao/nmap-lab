document.addEventListener("DOMContentLoaded", () => {
  const sidebar = document.getElementById("sidebar");
  const welcomeScreen = document.getElementById("welcome-screen");
  const scanDetail = document.getElementById("scan-detail");
  const consoleBody = document.getElementById("console-body");
  const btnRun = document.getElementById("btn-run");
  const btnClear = document.getElementById("btn-clear");
  const targetInput = document.getElementById("target-input");
  const commandPrefix = document.getElementById("command-prefix");

  const optVerbose = document.getElementById("opt-verbose");
  const optReason = document.getElementById("opt-reason");
  const optNoPing = document.getElementById("opt-no-ping");
  const optTiming = document.getElementById("opt-timing");
  const optPorts = document.getElementById("opt-ports");
  const portsWrapper = document.getElementById("ports-wrapper");

  let activeScan = null;
  let isScanning = false;

  checkNmap();
  buildSidebar();
  setupCardToggles();

  function checkNmap() {
    const el = document.getElementById("nmap-status");
    fetch("/api/check")
      .then(r => r.json())
      .then(data => {
        if (data.installed) {
          el.textContent = data.version;
          el.className = "nmap-status ok";
        } else {
          el.textContent = "nmap not found";
          el.className = "nmap-status err";
        }
      })
      .catch(() => {
        el.textContent = "backend offline";
        el.className = "nmap-status err";
      });
  }

  function buildSidebar() {
    sidebar.innerHTML = "";
    SCAN_CATEGORIES.forEach(cat => {
      const catDiv = document.createElement("div");
      catDiv.className = "cat-group";

      const header = document.createElement("div");
      header.className = "cat-header open";
      header.innerHTML = `
        <span class="cat-icon">${cat.icon}</span>
        <span>${cat.label}</span>
        <span class="cat-chevron">&#9662;</span>
      `;

      const items = document.createElement("div");
      items.className = "cat-items";

      cat.scans.forEach(scan => {
        const item = document.createElement("div");
        item.className = "scan-item";
        item.dataset.scanId = scan.id;
        item.innerHTML = `
          <span class="scan-item-flag">${scan.flag}</span>
          <span>${scan.name}</span>
        `;
        item.addEventListener("click", () => selectScan(scan));
        items.appendChild(item);
      });

      header.addEventListener("click", () => {
        header.classList.toggle("open");
        items.classList.toggle("collapsed");
      });

      catDiv.appendChild(header);
      catDiv.appendChild(items);
      sidebar.appendChild(catDiv);
    });
  }

  function selectScan(scan) {
    activeScan = scan;

    document.querySelectorAll(".scan-item").forEach(el => {
      el.classList.toggle("active", el.dataset.scanId === scan.id);
    });

    welcomeScreen.style.display = "none";
    scanDetail.style.display = "block";

    document.getElementById("scan-title").textContent = scan.name;
    document.getElementById("scan-flag").textContent = scan.flag;
    commandPrefix.textContent = scan.command;

    renderFungsi(scan.fungsi);
    renderKapanPakai(scan.kapanPakai);
    renderSkenario(scan.skenario);
    renderMitre(scan.mitre);
    renderPrecautions(scan.precautions);
    renderImpact(scan.impact);

    resetOptions(scan);
    resetConsole();

    scanDetail.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function resetOptions(scan) {
    const opts = scan.optionsConfig || {};
    const showVerbose = opts.verbose !== false;
    const showReason = opts.reason !== false;
    const showNoPing = opts.noPing !== false;
    const showTiming = opts.timing !== false;
    const showPorts = opts.ports !== false;

    optVerbose.closest(".option-label").style.display = showVerbose ? "" : "none";
    optReason.closest(".option-label").style.display = showReason ? "" : "none";
    optNoPing.closest(".option-label").style.display = showNoPing ? "" : "none";
    optTiming.style.display = showTiming ? "" : "none";
    portsWrapper.style.display = showPorts ? "" : "none";

    optVerbose.checked = false;
    optReason.checked = false;
    optNoPing.checked = false;
    optTiming.value = "";
    optPorts.value = "";
  }

  function renderFungsi(f) {
    document.getElementById("fungsi-subtitle").textContent = f.title;
    document.getElementById("fungsi-desc").innerHTML = f.description;

    const stepsEl = document.getElementById("fungsi-steps");
    stepsEl.innerHTML = `<h4>Cara Kerja</h4><ol class="step-list">
      ${f.howItWorks.map(s => `<li>${s}</li>`).join("")}
    </ol>`;

    document.getElementById("fungsi-output").innerHTML =
      `<strong>Output:</strong> ${f.output}`;
  }

  function renderKapanPakai(k) {
    const kondisiEl = document.getElementById("kapan-kondisi");
    kondisiEl.innerHTML = `<ul class="kondisi-list">
      ${k.kondisi.map(c => `<li>${c}</li>`).join("")}
    </ul>`;

    const flowEl = document.getElementById("kapan-flow");
    let flowHTML = `
      <div class="flow-item">
        <span class="flow-label before">Setelah</span>
        <span class="flow-text">${k.setelah}</span>
      </div>
      <div class="flow-item">
        <span class="flow-label after">Jika Gagal</span>
        <div class="flow-text">
          <ul class="flow-fail-list">
            ${k.jikaGagal.map(f => `<li>${f}</li>`).join("")}
          </ul>
        </div>
      </div>
    `;
    flowEl.innerHTML = flowHTML;
  }

  function renderSkenario(scenarios) {
    const el = document.getElementById("skenario-list");
    el.innerHTML = `<div class="skenario-grid">
      ${scenarios.map(s => `
        <div class="skenario-item">
          <div class="skenario-role">${s.role}</div>
          <div class="skenario-context">${s.context}</div>
        </div>
      `).join("")}
    </div>`;
  }

  function renderMitre(m) {
    const el = document.getElementById("mitre-content");
    let gridItems = `
      <div class="mitre-item">
        <div class="mitre-label">Tactic</div>
        <div class="mitre-value"><span class="mitre-id">${m.tactic.id}</span> <span class="mitre-name">${m.tactic.name}</span></div>
      </div>
      <div class="mitre-item">
        <div class="mitre-label">Technique</div>
        <div class="mitre-value"><span class="mitre-id">${m.technique.id}</span> <span class="mitre-name">${m.technique.name}</span></div>
      </div>
    `;

    if (m.additionalTactic) {
      gridItems += `
        <div class="mitre-item">
          <div class="mitre-label">Additional Tactic</div>
          <div class="mitre-value"><span class="mitre-id">${m.additionalTactic.id}</span> <span class="mitre-name">${m.additionalTactic.name}</span></div>
        </div>
      `;
    }

    gridItems += `
      <div class="mitre-item">
        <div class="mitre-label">Kill Chain Phase</div>
        <div class="mitre-value mitre-chain">${m.killChain}</div>
      </div>
    `;

    el.innerHTML = `
      <div class="mitre-grid">${gridItems}</div>
      <div class="mitre-desc">${m.description}</div>
    `;
  }

  function renderPrecautions(precs) {
    const el = document.getElementById("precautions-list");
    el.innerHTML = `<ul class="precaution-list">
      ${precs.map(p => `
        <li class="precaution-item">
          <span class="precaution-badge ${p.level}">${p.level}</span>
          <span>${p.text}</span>
        </li>
      `).join("")}
    </ul>`;
  }

  function renderImpact(imp) {
    const el = document.getElementById("impact-content");
    const items = [
      { label: "Network Traffic", value: imp.traffic },
      { label: "Detection Risk", value: imp.detection },
      { label: "Service Disruption", value: imp.disruption },
      { label: "Legal", value: imp.legal },
    ];
    el.innerHTML = `<div class="impact-grid">
      ${items.map(i => `
        <div class="impact-item">
          <div class="impact-label">${i.label}</div>
          <div class="impact-value">${i.value}</div>
        </div>
      `).join("")}
    </div>`;
  }

  function setupCardToggles() {
    document.querySelectorAll(".info-card-header").forEach(header => {
      header.addEventListener("click", () => {
        const targetId = header.dataset.toggle;
        const body = document.getElementById(targetId);
        if (!body) return;
        const isOpen = body.classList.contains("open");
        body.classList.toggle("open", !isOpen);
        header.classList.toggle("collapsed", isOpen);
      });
    });
  }

  function resetConsole() {
    consoleBody.innerHTML =
      '<div class="console-line dim">Ready. Enter a target and click Run Scan.</div>';
  }

  function appendConsole(text, cls = "") {
    const line = document.createElement("div");
    line.className = "console-line" + (cls ? " " + cls : "");
    line.textContent = text;
    consoleBody.appendChild(line);
    consoleBody.scrollTop = consoleBody.scrollHeight;
  }

  function buildFlags() {
    if (!activeScan) return [];
    const flags = activeScan.flags ? [...activeScan.flags] : [activeScan.flag];
    const opts = activeScan.optionsConfig || {};

    if (opts.verbose !== false && optVerbose.checked) flags.push("-v");
    if (opts.reason !== false && optReason.checked) flags.push("--reason");
    if (opts.noPing !== false && optNoPing.checked) flags.push("-Pn");

    if (opts.timing !== false) {
      const timing = optTiming.value;
      if (timing) flags.push(timing);
    }

    if (opts.ports !== false) {
      const ports = optPorts.value.trim();
      if (ports && /^[\d,\-]+$/.test(ports)) {
        flags.push("-p", ports);
      }
    }

    return flags;
  }

  btnRun.addEventListener("click", () => {
    if (isScanning || !activeScan) return;

    const target = targetInput.value.trim();
    if (!target) {
      appendConsole("Error: Please enter a target (IP, hostname, or CIDR).", "err");
      return;
    }

    const flags = buildFlags();
    const fullCmd = "nmap " + flags.join(" ") + " " + target;

    consoleBody.innerHTML = "";
    appendConsole("$ " + fullCmd, "cmd");
    appendConsole("Scanning... please wait.", "info");

    isScanning = true;
    btnRun.disabled = true;
    btnRun.textContent = "Scanning...";

    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, flags }),
    })
      .then(r => r.json())
      .then(data => {
        const scanningLine = consoleBody.querySelector(".console-line.info");
        if (scanningLine) scanningLine.remove();

        if (data.error) {
          appendConsole("Error: " + data.error, "err");
        } else {
          if (data.output) {
            data.output.split("\n").forEach(line => {
              appendConsole(line);
            });
          }
          appendConsole("");
          appendConsole("Exit code: " + data.exit_code, data.exit_code === 0 ? "dim" : "err");
        }
      })
      .catch(err => {
        appendConsole("Error: Could not connect to backend. Is server.py running?", "err");
        appendConsole(err.message, "err");
      })
      .finally(() => {
        isScanning = false;
        btnRun.disabled = false;
        btnRun.textContent = "Run Scan";
      });
  });

  targetInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") btnRun.click();
  });

  btnClear.addEventListener("click", resetConsole);
});
