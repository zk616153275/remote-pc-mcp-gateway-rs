const invoke = window.__TAURI__?.core?.invoke;
const $ = (id) => document.getElementById(id);

let currentConfig = null;
let selectedMode = "cloudflare-quick";
let activeFilter = "all";
let lastActivities = [];
let lastLogSignature = "";
let isStarting = false;
let isZh = true;
let toastTimer = null;

const I18N = {
  zh: {
    navDashboard: "运行面板",
    navActivity: "AI 指挥动态",
    navWizard: "接入模式",
    navRoots: "目录与守卫",
    navLogs: "启动终端日志",
    envTitle: "本机依赖自检",
    trayHint: "关闭窗口自动缩入托盘，释放 WebView2 内存",
    unsavedChanges: "有未保存修改",
    btnStart: "启动服务",
    btnStarting: "启动中...",
    btnStop: "停止服务",
    statusStopped: "已停止 · 待启动",
    statusRunning: "运行中 · 网关已就绪",
    step1: "配置授权目录",
    step2: "启动网关与隧道",
    step3: "复制凭据绑定 AI",
    goConfig: "去添加 →",
    configured: "已配置",
    subFs: "内嵌 ripgrep · 白名单",
    subWb: "Win32 Job Object",
    subGw: "PKCE + DCR 双平台",
    subCh: "按需懒加载 Sidecar",
    credTitle: "连接凭据（ChatGPT & Google Gemini 通用）",
    show: "显示",
    hide: "隐藏",
    copyUrl: "复制 URL",
    copyKey: "复制密钥",
    recentAiTitle: "最近 AI 指挥操作",
    viewAll: "查看全部 →",
    miniLogTitle: "启动与隧道终端",
    fullTerminal: "完整终端 →",
    guideSummary: "如何绑定到 Google Gemini / OpenAI ChatGPT？（点击展开 3 步指引）",
    stTotal: "总操作次数",
    stFs: "文件读写与搜索",
    stCmd: "终端命令与 Git",
    stSec: "授权与守卫拦截",
    activityHeading: "Gemini / ChatGPT 实时本地操作流",
    fAll: "全部",
    fFs: "文件",
    fCmd: "命令",
    fChrome: "浏览器",
    fSec: "安全",
    modeTitle: "选择公网接入方式",
    rec: "新手推荐",
    descQuick: "免服务器、免域名、零成本；自动绕过 Clash/Mihomo Fake-IP。重启后临时地址会变化。",
    descNamed: "免 VPS，绑定你自己的 Cloudflare 固定域名，重启后 URL 永久不变。",
    titleVps: "自建 Linux VPS（SSH -R）",
    descVps: "通过 OpenSSH 反向隧道接入自建 Ubuntu/Debian VPS，适合长期稳定常驻。",
    titleLocal: "仅本机调试模式",
    descLocal: "仅监听 127.0.0.1，不拉起外部隧道，适合本机联调或外接自定义反代。",
    lblInstance: "实例名称（显示在授权页）",
    lblPerm: "文件系统权限级别",
    lblPort: "本地网关端口",
    cfNamedSub: "Cloudflare Named Tunnel 参数",
    lblCfHost: "固定公网域名",
    vpsSub: "Linux VPS SSH 反向隧道参数",
    lblVpsHost: "VPS IP / 主机名",
    lblVpsDomain: "公网 HTTPS 域名",
    lblVpsKey: "SSH 私钥路径（留空使用系统默认 ~/.ssh/id_ed25519）",
    btnSave: "保存配置",
    rootsTitle: "授权目录白名单（allowedRoots）",
    rootsDesc: "AI 只能读写和搜索以下文件夹内的文件；系统会自动拒绝磁盘根目录（如 C:\\）与用户主目录，防止越权。",
    btnBrowse: "浏览选择...",
    btnAdd: "+ 添加",
    guardsTitle: "安全守卫与可选能力",
    swDgTitle: "危险删除二次复核守卫（Delete Guard）",
    swDgDesc: "首次遇到 rm -rf、Remove-Item -Recurse、git reset --hard 自动拦截，10 分钟内原样重发才放行。",
    swCmdTitle: "AI Workbench 命令工作台与只读 Git",
    swCmdDesc: "允许在授权目录内执行 PowerShell 7 命令（Win32 Job Object 自动清理进程树）。",
    swChromeTitle: "Chrome DevTools MCP Sidecar",
    swChromeDesc: "按需懒加载上游 chrome-devtools-mcp（需本机 Chrome 开启 --remote-debugging-port=9222）。",
    btnSaveRoots: "保存目录与守卫设置",
    logsTitle: "启动与隧道实时终端",
    btnCopyLogs: "复制日志",
    btnClearLogs: "清空",
    healthy: "运行正常",
    stopped: "未启动",
    disabled: "未启用",
    remove: "移除",
    noRoots: "尚未添加任何授权目录，请点击上方「浏览选择...」添加至少一个工作目录。",
    noActivity: "等待 AI 发出第一条本地操作指令（读写文件、执行命令、授权或拦截都会实时显示在这里）...",
    noLogs: "点击右上角「启动服务」，这里会实时打印启动、端口、Cloudflare/VPS 隧道日志...",
    toastSaved: "配置已保存",
    toastCopied: "已复制到剪贴板",
    toastStarted: "服务已启动",
    toastStopped: "服务已停止",
  },
  en: {
    navDashboard: "Dashboard",
    navActivity: "AI Activity",
    navWizard: "Connection",
    navRoots: "Roots & Guards",
    navLogs: "Terminal Logs",
    envTitle: "Local Environment",
    trayHint: "Closing releases WebView2 to tray (~6 MB idle)",
    unsavedChanges: "Unsaved changes",
    btnStart: "Start",
    btnStarting: "Starting...",
    btnStop: "Stop",
    statusStopped: "Stopped · Idle",
    statusRunning: "Running · Ready",
    step1: "Add Allowed Folder",
    step2: "Start Gateway & Tunnel",
    step3: "Copy Credentials to AI",
    goConfig: "Configure →",
    configured: "Ready",
    subFs: "Embedded ripgrep · Sandboxed",
    subWb: "Win32 Job Object",
    subGw: "PKCE + DCR dual-platform",
    subCh: "Lazy-loaded Sidecar",
    credTitle: "Connection Credentials (ChatGPT & Google Gemini)",
    show: "Show",
    hide: "Hide",
    copyUrl: "Copy URL",
    copyKey: "Copy Key",
    recentAiTitle: "Recent AI Operations",
    viewAll: "View all →",
    miniLogTitle: "Startup & Tunnel Console",
    fullTerminal: "Full console →",
    guideSummary: "How to connect Google Gemini / OpenAI ChatGPT? (Click for 3 steps)",
    stTotal: "Total Actions",
    stFs: "File Ops & Search",
    stCmd: "Commands & Git",
    stSec: "Auth & Guard Blocks",
    activityHeading: "Live Gemini / ChatGPT Local Activity Stream",
    fAll: "All",
    fFs: "Files",
    fCmd: "Commands",
    fChrome: "Browser",
    fSec: "Security",
    modeTitle: "Choose Public Access Mode",
    rec: "Recommended",
    descQuick: "No VPS or domain needed. Auto-bypasses Clash/Mihomo Fake-IP. Temporary URL changes on restart.",
    descNamed: "No VPS needed. Bind your own fixed Cloudflare hostname so the URL never changes.",
    titleVps: "Self-Hosted Linux VPS (SSH -R)",
    descVps: "Forward local services over OpenSSH reverse tunnel to your own Ubuntu/Debian VPS.",
    titleLocal: "Localhost Only",
    descLocal: "Listen on 127.0.0.1 without starting a public tunnel. Great for local testing.",
    lblInstance: "Instance Label (shown on OAuth page)",
    lblPerm: "Filesystem Permission Mode",
    lblPort: "Local Gateway Port",
    cfNamedSub: "Cloudflare Named Tunnel Settings",
    lblCfHost: "Fixed Public Hostname",
    vpsSub: "Linux VPS SSH Reverse Tunnel Settings",
    lblVpsHost: "VPS IP / Hostname",
    lblVpsDomain: "Public HTTPS Domain",
    lblVpsKey: "SSH Private Key Path (leave blank for default ~/.ssh/id_ed25519)",
    btnSave: "Save Settings",
    rootsTitle: "Allowed Directories (allowedRoots)",
    rootsDesc: "AI can only access files inside these folders. Drive roots (e.g. C:\\) and home roots are blocked.",
    btnBrowse: "Browse...",
    btnAdd: "+ Add",
    guardsTitle: "Safety Guards & Optional Capabilities",
    swDgTitle: "Destructive Delete Guard (Two-Step Verification)",
    swDgDesc: "Intercepts first rm -rf / Remove-Item -Recurse / git reset --hard; exact retry within 10 min runs once.",
    swCmdTitle: "AI Workbench & Read-Only Git",
    swCmdDesc: "Run PowerShell 7 commands supervised by Win32 Job Objects inside allowed roots.",
    swChromeTitle: "Chrome DevTools MCP Sidecar",
    swChromeDesc: "Lazy-load upstream chrome-devtools-mcp (requires Chrome --remote-debugging-port=9222).",
    btnSaveRoots: "Save Roots & Guards",
    logsTitle: "Startup & Tunnel Terminal",
    btnCopyLogs: "Copy Logs",
    btnClearLogs: "Clear",
    healthy: "Healthy",
    stopped: "Stopped",
    disabled: "Disabled",
    remove: "Remove",
    noRoots: "No allowed directories yet. Click 'Browse...' above to add at least one workspace folder.",
    noActivity: "Waiting for the first AI command (file reads, writes, shell commands, and guard blocks appear here live)...",
    noLogs: "Click Start above to watch live startup, port binding, and Cloudflare/VPS tunnel logs...",
    toastSaved: "Settings saved",
    toastCopied: "Copied to clipboard",
    toastStarted: "Services started",
    toastStopped: "Services stopped",
  },
};

const t = (key) => (isZh ? I18N.zh[key] : I18N.en[key]) || key;
const esc = (s) =>
  String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

function toast(msg) {
  const el = $("toast");
  el.textContent = msg;
  el.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add("hidden"), 2200);
}

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

function setDirty(dirty) {
  $("dirty-tag").classList.toggle("hidden", !dirty);
}

function switchTab(tabName) {
  document.querySelectorAll(".nav-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.tab === tabName);
  });
  document.querySelectorAll(".panel").forEach((p) => {
    p.classList.toggle("active", p.id === `tab-${tabName}`);
  });
}

function updateModeUi(mode) {
  selectedMode = mode || "cloudflare-quick";
  document.querySelectorAll(".mode-card").forEach((c) => {
    c.classList.toggle("selected", c.dataset.mode === selectedMode);
  });
  $("group-cf-named").classList.toggle("hidden", selectedMode !== "cloudflare-named");
  $("group-vps").classList.toggle("hidden", selectedMode !== "vps");
}

function renderRoots() {
  const list = $("root-list");
  list.innerHTML = "";
  const roots = currentConfig?.allowedRoots || [];
  const badge = $("roots-count-badge");
  badge.textContent = String(roots.length);
  badge.classList.toggle("warn", roots.length === 0);

  $("step-1").classList.toggle("done", roots.length > 0);
  $("btn-go-roots").textContent = roots.length > 0 ? `${t("configured")} (${roots.length})` : t("goConfig");

  if (!roots.length) {
    const li = document.createElement("li");
    li.className = "sec-desc";
    li.textContent = t("noRoots");
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
    btn.textContent = t("remove");
    btn.onclick = () => {
      currentConfig.allowedRoots.splice(idx, 1);
      setDirty(true);
      renderRoots();
    };
    li.append(span, btn);
    list.appendChild(li);
  });
}

function activityHtml(item) {
  const badgeCls =
    item.platform === "Gemini"
      ? "badge-gemini"
      : item.platform === "ChatGPT"
        ? "badge-chatgpt"
        : "badge-guard";
  return `<div class="act-item cat-${esc(item.category)}">
    <span class="act-badge ${badgeCls}">${esc(item.platform)}</span>
    <span class="act-tool">${esc(item.tool)}</span>
    <span class="act-target" title="${esc(item.target)}">${esc(item.target || "—")}</span>
    <span class="act-time">${esc(item.time)}</span>
  </div>`;
}

function renderActivities(items, stats) {
  lastActivities = items || [];
  $("activity-count-badge").textContent = String(stats?.total || 0);
  $("st-total").textContent = String(stats?.total || 0);
  $("st-fs").textContent = String(stats?.fsCount || 0);
  $("st-cmd").textContent = String(stats?.cmdCount || 0);
  $("st-sec").textContent = String(stats?.securityCount || 0);

  const mini = $("mini-activity-feed");
  if (!lastActivities.length) {
    mini.innerHTML = `<div class="sec-desc" style="margin:8px 0;">${esc(t("noActivity"))}</div>`;
  } else {
    mini.innerHTML = lastActivities.slice(0, 5).map(activityHtml).join("");
  }

  const filtered =
    activeFilter === "all"
      ? lastActivities
      : lastActivities.filter((x) => x.category === activeFilter);
  const full = $("activity-list");
  if (!filtered.length) {
    full.innerHTML = `<div class="sec-desc" style="margin:8px 0;">${esc(t("noActivity"))}</div>`;
  } else {
    full.innerHTML = filtered.map(activityHtml).join("");
  }
}

function renderLogs(logs) {
  const sig =
    logs && logs.length
      ? `${isZh}:${logs.length}:${logs[0].time}:${logs[logs.length - 1].time}:${logs[logs.length - 1].message}`
      : `${isZh}:empty`;
  if (sig === lastLogSignature) {
    return;
  }
  lastLogSignature = sig;

  const html =
    logs && logs.length
      ? logs
          .map(
            (e) =>
              `<div class="log-line"><span class="log-time">[${esc(e.time)}]</span><span class="log-src">[${esc(e.source || "CORE")}]</span><span class="log-${esc(e.level)}">${esc(e.message)}</span></div>`
          )
          .join("")
      : `<div class="log-line" style="color:#64748b;">${esc(t("noLogs"))}</div>`;

  for (const id of ["log-console", "mini-log-console"]) {
    const el = $(id);
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    el.innerHTML = html;
    if (nearBottom) {
      el.scrollTop = el.scrollHeight;
    }
  }
}

function applyLanguage() {
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const k = el.getAttribute("data-i18n");
    if (I18N.zh[k]) el.textContent = t(k);
  });
  renderRoots();
}

function applyConfigToUi(cfg) {
  currentConfig = cfg;
  isZh = (cfg.language || "zh") === "zh";
  $("cfg-label").value = cfg.instanceLabel || "My-Windows-PC";
  updateModeUi(cfg.connectionMode || "cloudflare-quick");
  $("cfg-gw-mode").value = cfg.gateway?.mode || "readwrite";
  $("cfg-gw-port").value = cfg.gateway?.localPort || 18787;
  $("cfg-cf-host").value = cfg.cloudflare?.publicHostname || "";
  $("cfg-cf-token").value = cfg.cloudflare?.namedTunnelToken || "";
  $("cfg-vps-host").value = cfg.vps?.host || "";
  $("cfg-vps-port").value = cfg.vps?.sshPort || 22;
  $("cfg-vps-user").value = cfg.vps?.user || "root";
  $("cfg-vps-domain").value = cfg.vps?.domain || "";
  $("cfg-vps-key").value = cfg.vps?.sshKeyPath || "";
  $("chk-delete-guard").checked = cfg.guardsAndHooks?.enableDeleteGuard !== false;
  $("chk-commands").checked = cfg.gateway?.enableCommands !== false;
  $("chk-chrome").checked = Boolean(cfg.gateway?.enableChrome);
  $("inp-approval-key").value = cfg.gateway?.approvalKey || "";
  setDirty(false);
  applyLanguage();
}

function collectConfigFromUi() {
  return {
    ...currentConfig,
    instanceLabel: $("cfg-label").value.trim() || "My-Windows-PC",
    language: isZh ? "zh" : "en",
    connectionMode: selectedMode,
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
      mode: selectedMode === "cloudflare-named" ? "named" : "quick",
      publicHostname: $("cfg-cf-host").value.trim(),
      namedTunnelToken: $("cfg-cf-token").value.trim(),
    },
    vps: {
      ...currentConfig.vps,
      host: $("cfg-vps-host").value.trim(),
      sshPort: Number($("cfg-vps-port").value) || 22,
      user: $("cfg-vps-user").value.trim() || "root",
      domain: $("cfg-vps-domain").value.trim(),
      sshKeyPath: $("cfg-vps-key").value.trim(),
    },
  };
}

function applyStatus(st) {
  const pill = $("status-pill");
  pill.classList.toggle("running", st.running);
  $("status-text").textContent = st.running ? t("statusRunning") : t("statusStopped");
  if (!isStarting) {
    $("btn-start").disabled = st.running;
    $("btn-start-label").textContent = t("btnStart");
  }
  $("btn-stop").disabled = !st.running;

  $("step-2").classList.toggle("done", st.running);
  $("step-3").classList.toggle("done", st.running && Boolean(st.mcpUrl));

  const setCard = (cardId, valId, ok, offLabel) => {
    $(cardId).classList.toggle("ok", ok);
    $(valId).textContent = ok ? t("healthy") : offLabel;
  };
  setCard("card-fs", "val-fs", st.fsOk, t("stopped"));
  setCard("card-wb", "val-wb", st.workbenchOk, t("stopped"));
  setCard("card-gw", "val-gw", st.gatewayOk, t("stopped"));
  setCard("card-ch", "val-ch", st.chromeOk, t("disabled"));

  $("inp-mcp-url").value = st.mcpUrl || "";
  if (st.approvalKey) $("inp-approval-key").value = st.approvalKey;
  $("fakeip-badge").classList.toggle("hidden", !st.fakeIpBypassed);

  if (st.env) {
    $("env-pwsh").classList.toggle("ok", st.env.pwshOk);
    $("env-cf").classList.toggle("ok", st.env.cloudflaredOk);
    $("env-ssh").classList.toggle("ok", st.env.sshOk);
    $("env-node").classList.toggle("ok", st.env.nodeOk);
  }
  renderLogs(st.logs);
  renderActivities(st.activities, st.stats);
  if (st.lastError) {
    showAlert(st.lastError);
  }
}

// Navigation & buttons
document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});
$("btn-go-roots").addEventListener("click", () => switchTab("roots"));
$("btn-all-activity").addEventListener("click", () => switchTab("activity"));
$("btn-all-logs").addEventListener("click", () => switchTab("logs"));

document.querySelectorAll("#activity-filters .fpill").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#activity-filters .fpill").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    activeFilter = btn.dataset.filter;
    renderActivities(lastActivities, {
      total: Number($("st-total").textContent),
      fsCount: Number($("st-fs").textContent),
      cmdCount: Number($("st-cmd").textContent),
      securityCount: Number($("st-sec").textContent),
    });
  });
});

document.querySelectorAll(".mode-card").forEach((card) => {
  card.addEventListener("click", () => {
    updateModeUi(card.dataset.mode);
    setDirty(true);
  });
});

document.querySelectorAll("#tab-wizard input, #tab-wizard select, #tab-roots input[type=checkbox]").forEach((el) => {
  el.addEventListener("change", () => setDirty(true));
});

document.querySelectorAll("[data-toggle]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const inp = $(btn.dataset.toggle);
    const showing = inp.type === "text";
    inp.type = showing ? "password" : "text";
    btn.textContent = showing ? t("show") : t("hide");
  });
});

document.querySelectorAll("[data-copy]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const val = $(btn.dataset.copy).value;
    if (!val) return;
    await navigator.clipboard.writeText(val);
    toast(t("toastCopied"));
  });
});

$("btn-lang").addEventListener("click", () => {
  isZh = !isZh;
  applyLanguage();
  setDirty(true);
});

async function addRootPath(raw) {
  if (!raw) return;
  try {
    const valid = invoke ? await invoke("validate_root_dir", { dir: raw }) : raw;
    if (!currentConfig.allowedRoots.includes(valid)) {
      currentConfig.allowedRoots.push(valid);
      setDirty(true);
    }
    $("inp-new-root").value = "";
    showAlert("");
    renderRoots();
  } catch (e) {
    showAlert(String(e));
  }
}

$("btn-add-root").addEventListener("click", () => addRootPath($("inp-new-root").value.trim()));
$("inp-new-root").addEventListener("keydown", (e) => {
  if (e.key === "Enter") addRootPath($("inp-new-root").value.trim());
});

$("btn-pick-root").addEventListener("click", async () => {
  if (!invoke) return;
  try {
    const picked = await invoke("pick_folder");
    if (picked) await addRootPath(picked);
  } catch (e) {
    showAlert(String(e));
  }
});

async function persist() {
  if (!invoke) return;
  try {
    const saved = await invoke("save_config", { cfg: collectConfigFromUi() });
    applyConfigToUi(saved);
    showAlert("");
    toast(t("toastSaved"));
  } catch (e) {
    showAlert(String(e));
  }
}

$("btn-save-wizard").addEventListener("click", persist);
$("btn-save-roots").addEventListener("click", persist);

$("btn-start").addEventListener("click", async () => {
  if (!invoke) return;
  const cfg = collectConfigFromUi();
  if (!cfg.allowedRoots.length) {
    showAlert(isZh ? "请先添加至少一个授权目录再启动服务。" : "Please add at least one allowed directory first.");
    switchTab("roots");
    return;
  }
  isStarting = true;
  $("btn-start").disabled = true;
  $("btn-start-label").textContent = t("btnStarting");
  showAlert("");
  try {
    const st = await invoke("start_services", { cfg });
    isStarting = false;
    setDirty(false);
    applyStatus(st);
    toast(t("toastStarted"));
  } catch (e) {
    isStarting = false;
    showAlert(String(e));
    $("btn-start").disabled = false;
    $("btn-start-label").textContent = t("btnStart");
  }
});

$("btn-stop").addEventListener("click", async () => {
  if (!invoke) return;
  try {
    const st = await invoke("stop_services");
    showAlert("");
    applyStatus(st);
    toast(t("toastStopped"));
  } catch (e) {
    showAlert(String(e));
  }
});

$("btn-clear-logs").addEventListener("click", async () => {
  if (!invoke) return;
  await invoke("clear_logs");
  renderLogs([]);
});

$("btn-copy-logs").addEventListener("click", async () => {
  const txt = $("log-console").innerText;
  if (!txt) return;
  await navigator.clipboard.writeText(txt);
  toast(t("toastCopied"));
});

async function refreshLive() {
  if (!invoke) return;
  try {
    const st = await invoke("get_status");
    applyStatus(st);
  } catch {}
}

async function init() {
  if (!invoke) return;
  try {
    const cfg = await invoke("load_config");
    applyConfigToUi(cfg);
    await refreshLive();
    setInterval(refreshLive, 2000);
  } catch (e) {
    showAlert(String(e));
  }
}

init();
