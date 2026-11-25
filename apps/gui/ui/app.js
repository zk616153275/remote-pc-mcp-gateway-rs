const invoke = window.__TAURI__?.core?.invoke;

let currentConfig = null;
let isZh = true;

const $ = (id) => document.getElementById(id);

function showAlert(msg) {
  const box = $("alert-box");
  if (!msg) {
    box.classList.add("hidden");
    box.textContent = "";
    return;
  }
  box.textContent = msg;
  box.classList.remove("hidden");
}

function renderRoots() {
  const list = $("root-list");
  list.innerHTML = "";
  const roots = currentConfig?.allowedRoots || [];
  if (!roots.length) {
    const li = document.createElement("li");
    li.className = "hint";
    li.textContent = isZh ? "尚未添加任何授权目录，请先添加至少一个工作目录。" : "No allowed directories yet. Add at least one workspace folder.";
    list.appendChild(li);
    return;
  }
  roots.forEach((dir, idx) => {
    const li = document.createElement("li");
    li.className = "root-item";
    const span = document.createElement("span");
    span.textContent = dir;
    const btn = document.createElement("button");
    btn.className = "btn btn-ghost";
    btn.textContent = isZh ? "移除" : "Remove";
    btn.onclick = () => {
      currentConfig.allowedRoots.splice(idx, 1);
      renderRoots();
    };
    li.append(span, btn);
    list.appendChild(li);
  });
}

function applyConfigToUi(cfg) {
  currentConfig = cfg;
  isZh = (cfg.language || "zh") === "zh";
  $("cfg-label").value = cfg.instanceLabel || "My-Windows-PC";
  $("cfg-mode").value = cfg.connectionMode || "cloudflare-quick";
  $("cfg-gw-mode").value = cfg.gateway?.mode || "readwrite";
  $("cfg-gw-port").value = cfg.gateway?.localPort || 18787;
  $("cfg-cf-host").value = cfg.cloudflare?.publicHostname || "";
  $("cfg-cf-token").value = cfg.cloudflare?.namedTunnelToken || "";
  $("cfg-vps-host").value = cfg.vps?.host || "";
  $("cfg-vps-domain").value = cfg.vps?.domain || "";
  $("chk-delete-guard").checked = cfg.guardsAndHooks?.enableDeleteGuard !== false;
  $("chk-commands").checked = cfg.gateway?.enableCommands !== false;
  $("chk-chrome").checked = Boolean(cfg.gateway?.enableChrome);
  $("inp-approval-key").value = cfg.gateway?.approvalKey || "";
  renderRoots();
  applyLanguage();
}

function collectConfigFromUi() {
  return {
    ...currentConfig,
    instanceLabel: $("cfg-label").value.trim() || "My-Windows-PC",
    language: isZh ? "zh" : "en",
    connectionMode: $("cfg-mode").value,
    gateway: {
      ...currentConfig.gateway,
      mode: $("cfg-gw-mode").value,
      localPort: Number($("cfg-gw-port").value) || 18787,
      enableCommands: $("chk-commands").checked,
      enableChrome: $("chk-chrome").checked,
    },
    guardsAndHooks: {
      ...currentConfig.guardsAndHooks,
      enableDeleteGuard: $("chk-delete-guard").checked,
    },
    cloudflare: {
      ...currentConfig.cloudflare,
      mode: $("cfg-mode").value === "cloudflare-named" ? "named" : "quick",
      publicHostname: $("cfg-cf-host").value.trim(),
      namedTunnelToken: $("cfg-cf-token").value.trim(),
    },
    vps: {
      ...currentConfig.vps,
      host: $("cfg-vps-host").value.trim(),
      domain: $("cfg-vps-domain").value.trim(),
    },
  };
}

function applyStatus(st) {
  const pill = $("status-pill");
  if (st.running) {
    pill.classList.add("running");
    $("status-text").textContent = isZh ? "运行中 · 网关已就绪" : "Running · Gateway Ready";
    $("btn-start").disabled = true;
    $("btn-stop").disabled = false;
  } else {
    pill.classList.remove("running");
    $("status-text").textContent = isZh ? "已停止 · 待启动" : "Stopped · Idle";
    $("btn-start").disabled = false;
    $("btn-stop").disabled = true;
  }

  const setCard = (cardId, valId, ok, offLabel) => {
    const card = $(cardId);
    const val = $(valId);
    if (ok) {
      card.classList.add("ok");
      val.textContent = isZh ? "运行正常" : "Healthy";
    } else {
      card.classList.remove("ok");
      val.textContent = offLabel;
    }
  };

  setCard("card-fs", "val-fs", st.fsOk, isZh ? "未启动" : "Stopped");
  setCard("card-wb", "val-wb", st.workbenchOk, isZh ? "未启动" : "Stopped");
  setCard("card-gw", "val-gw", st.gatewayOk, isZh ? "未启动" : "Stopped");
  setCard("card-ch", "val-ch", st.chromeOk, isZh ? "未启用" : "Disabled");

  $("inp-mcp-url").value = st.mcpUrl || "";
  if (st.approvalKey) $("inp-approval-key").value = st.approvalKey;

  $("fakeip-hint").textContent = st.fakeIpBypassed
    ? (isZh ? "已自动检测到 Clash/Mihomo Fake-IP (198.18.0.0/15)，已切换 QUIC + Cloudflare Anycast 节点直连。" : "Detected TUN Fake-IP (198.18.0.0/15); switched to QUIC + Anycast edge.")
    : "";

  showAlert(st.lastError || "");
}

function applyLanguage() {
  $("nav-dashboard").textContent = isZh ? "运行面板" : "Dashboard";
  $("nav-wizard").textContent = isZh ? "配置向导" : "Setup Wizard";
  $("nav-roots").textContent = isZh ? "授权目录与守卫" : "Roots & Guards";
  $("btn-start").textContent = isZh ? "启动服务" : "Start";
  $("btn-stop").textContent = isZh ? "停止服务" : "Stop";
  $("tray-hint").textContent = isZh
    ? "关闭窗口自动缩入托盘，释放 WebView2 内存"
    : "Closing releases WebView2 to tray (~6 MB idle)";
}

// Tab switching
document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    $(`tab-${btn.dataset.tab}`).classList.add("active");
  });
});

// Reveal & copy buttons
document.querySelectorAll("[data-toggle]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const inp = $(btn.dataset.toggle);
    const showing = inp.type === "text";
    inp.type = showing ? "password" : "text";
    btn.textContent = showing ? (isZh ? "显示" : "Show") : (isZh ? "隐藏" : "Hide");
  });
});

document.querySelectorAll("[data-copy]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const val = $(btn.dataset.copy).value;
    if (!val) return;
    await navigator.clipboard.writeText(val);
    const old = btn.textContent;
    btn.textContent = isZh ? "已复制" : "Copied";
    setTimeout(() => { btn.textContent = old; }, 1200);
  });
});

$("btn-lang").addEventListener("click", () => {
  isZh = !isZh;
  applyLanguage();
  renderRoots();
});

$("btn-add-root").addEventListener("click", async () => {
  const raw = $("inp-new-root").value.trim();
  if (!raw) return;
  try {
    const valid = invoke ? await invoke("validate_root_dir", { dir: raw }) : raw;
    if (!currentConfig.allowedRoots.includes(valid)) {
      currentConfig.allowedRoots.push(valid);
    }
    $("inp-new-root").value = "";
    showAlert("");
    renderRoots();
  } catch (e) {
    showAlert(String(e));
  }
});

async function persist() {
  const next = collectConfigFromUi();
  if (!invoke) return;
  try {
    const saved = await invoke("save_config", { cfg: next });
    applyConfigToUi(saved);
    showAlert("");
  } catch (e) {
    showAlert(String(e));
  }
}

$("btn-save-wizard").addEventListener("click", persist);
$("btn-save-roots").addEventListener("click", persist);

$("btn-start").addEventListener("click", async () => {
  if (!invoke) return;
  $("btn-start").disabled = true;
  showAlert("");
  try {
    const st = await invoke("start_services", { cfg: collectConfigFromUi() });
    applyStatus(st);
  } catch (e) {
    showAlert(String(e));
    $("btn-start").disabled = false;
  }
});

$("btn-stop").addEventListener("click", async () => {
  if (!invoke) return;
  try {
    const st = await invoke("stop_services");
    applyStatus(st);
  } catch (e) {
    showAlert(String(e));
  }
});

async function init() {
  if (!invoke) return;
  try {
    const cfg = await invoke("load_config");
    applyConfigToUi(cfg);
    const st = await invoke("get_status");
    applyStatus(st);
  } catch (e) {
    showAlert(String(e));
  }
}

init();
