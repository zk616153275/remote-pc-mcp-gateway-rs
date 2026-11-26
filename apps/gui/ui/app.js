const invoke = window.__TAURI__?.core?.invoke;
const $ = (id) => document.getElementById(id);

let currentConfig = null;
let selectedMode = "cloudflare-quick";
let activeTab = "dashboard";
let activeFilter = "all";
let activitySearch = "";
let activityPaused = false;
let lastActivities = [];
let lastStats = { total: 0, fsCount: 0, cmdCount: 0, securityCount: 0 };
let pendingActivities = null;
let lastActivitySignature = "";
let lastLogSignature = "";
let isStarting = false;
let isRestarting = false;
let lastRunning = false;
let dismissedAlertMsg = "";
let isZh = true;
let toastTimer = null;

const expandedIds = new Set();
const commandDetailCache = new Map();
const commandDetailLoading = new Set();

const I18N = {
  zh: {
    navDashboard: "运行面板",
    navActivity: "AI 指挥动态",
    navWizard: "接入模式",
    navRoots: "目录与守卫",
    navLogs: "启动终端日志",
    envTitle: "本机依赖自检",
    trayHint: "关闭窗口自动缩入托盘，释放 WebView2 内存",
    unsavedChanges: "有未保存修改 · 点此保存",
    btnStart: "启动服务",
    btnStarting: "启动中...",
    btnRestart: "重启",
    btnRestarting: "重启中...",
    btnStop: "停止服务",
    statusStopped: "已停止 · 待启动",
    statusRunning: "运行中 · 网关已就绪",
    statusRunningAttached: "运行中 · 已接入后台",
    modePillPrefix: "接入",
    attachedBadge: "已接入后台服务",
    modeQuickShort: "Cloudflare Quick",
    modeNamedShort: "Cloudflare Named",
    modeVpsShort: "VPS · SSH -R",
    modeLocalShort: "仅本机调试",
    remoteVpsOk: "VPS 远端运行",
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
    searchPlaceholder: "搜索命令、路径、工具名...",
    btnPause: "暂停刷新",
    btnResume: "恢复刷新",
    btnFlush: "立即刷新",
    refresh: "刷新",
    fAll: "全部",
    fFs: "文件",
    fCmd: "命令",
    fChrome: "浏览器",
    fSec: "安全",
    copy: "复制",
    reveal: "定位",
    openFolder: "打开",
    copyOutput: "复制输出",
    fullCommandLbl: "完整命令 / 参数",
    outputLbl: "终端输出 (stdout / stderr)",
    loadingDetail: "正在读取命令详情与输出...",
    noOutput: "(无输出)",
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
    noMatchActivity: "没有匹配当前筛选或搜索条件的操作记录。",
    noLogs: "点击右上角「启动服务」，这里会实时打印启动、端口、Cloudflare/VPS 隧道日志...",
    toastSaved: "配置已保存",
    toastSavedNeedRestart: "配置已保存，点击右上角「重启」后生效",
    toastCopied: "已复制到剪贴板",
    toastStarted: "服务已启动",
    toastRestarted: "服务已重启",
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
    unsavedChanges: "Unsaved · Click to save",
    btnStart: "Start",
    btnStarting: "Starting...",
    btnRestart: "Restart",
    btnRestarting: "Restarting...",
    btnStop: "Stop",
    statusStopped: "Stopped · Idle",
    statusRunning: "Running · Ready",
    statusRunningAttached: "Running · Attached",
    modePillPrefix: "Mode",
    attachedBadge: "Attached to Background",
    modeQuickShort: "Cloudflare Quick",
    modeNamedShort: "Cloudflare Named",
    modeVpsShort: "VPS · SSH -R",
    modeLocalShort: "Localhost Only",
    remoteVpsOk: "Remote on VPS",
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
    searchPlaceholder: "Search command, path, tool...",
    btnPause: "Pause",
    btnResume: "Resume",
    btnFlush: "Refresh now",
    refresh: "Refresh",
    fAll: "All",
    fFs: "Files",
    fCmd: "Commands",
    fChrome: "Browser",
    fSec: "Security",
    copy: "Copy",
    reveal: "Reveal",
    openFolder: "Open",
    copyOutput: "Copy Output",
    fullCommandLbl: "Full Command / Target",
    outputLbl: "Command Output (stdout / stderr)",
    loadingDetail: "Loading command detail & output...",
    noOutput: "(No output)",
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
    noMatchActivity: "No activity matches the current filter or search.",
    noLogs: "Click Start above to watch live startup, port binding, and Cloudflare/VPS tunnel logs...",
    toastSaved: "Settings saved",
    toastSavedNeedRestart: "Saved. Click Restart above to apply changes",
    toastCopied: "Copied to clipboard",
    toastStarted: "Services started",
    toastRestarted: "Services restarted",
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
    $("alert-msg").textContent = "";
    return;
  }
  $("alert-msg").textContent = msg;
  box.classList.remove("hidden");
}

function setDirty(dirty) {
  $("dirty-tag").classList.toggle("hidden", !dirty);
}

function switchTab(tabName) {
  activeTab = tabName;
  document.querySelectorAll(".nav-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.tab === tabName);
  });
  document.querySelectorAll(".panel").forEach((p) => {
    p.classList.toggle("active", p.id === `tab-${tabName}`);
  });
  $("main-area").classList.toggle(
    "no-outer-scroll",
    tabName === "activity" || tabName === "logs"
  );
}

/* =========================================================
   Movable, Resizable & Collapsible Sidebar
   ========================================================= */
const SB_STORAGE_KEY = "rpc_mcp_sidebar_v1";
const SB_DEFAULT = {
  mode: "docked", // "docked" | "floating"
  dockSide: "left", // "left" | "right"
  width: 238,
  height: 580,
  x: 20,
  y: 20,
  collapsed: false,
};

let sbState = loadSidebarState();

function loadSidebarState() {
  try {
    const raw = localStorage.getItem(SB_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      return { ...SB_DEFAULT, ...parsed };
    }
  } catch {}
  return { ...SB_DEFAULT };
}

function saveSidebarState() {
  try {
    localStorage.setItem(SB_STORAGE_KEY, JSON.stringify(sbState));
  } catch {}
}

function clamp(v, min, max) {
  return Math.max(min, Math.min(max, v));
}

function applySidebarLayout() {
  const shell = $("app-shell");
  const sb = $("sidebar");
  const btnFloat = $("btn-sb-float");

  const effectiveWidth = sbState.collapsed ? 64 : clamp(sbState.width, 180, 420);
  document.documentElement.style.setProperty("--sidebar-w", `${effectiveWidth}px`);

  sb.classList.toggle("collapsed", Boolean(sbState.collapsed));
  sb.classList.toggle("floating", sbState.mode === "floating");
  shell.classList.toggle("sb-floating", sbState.mode === "floating");
  shell.classList.toggle("dock-right", sbState.mode === "docked" && sbState.dockSide === "right");
  btnFloat.classList.toggle("active", sbState.mode === "floating");

  if (sbState.mode === "floating") {
    const w = sbState.collapsed ? 64 : clamp(sbState.width, 190, 440);
    sb.style.width = `${w}px`;
    if (sbState.collapsed) {
      sb.style.height = "auto";
    } else {
      const h = clamp(sbState.height, 340, Math.max(360, window.innerHeight - 24));
      sb.style.height = `${h}px`;
    }
    const actualH = sb.offsetHeight || (sbState.collapsed ? 400 : sbState.height);
    sbState.x = clamp(sbState.x, 8, Math.max(8, window.innerWidth - w - 8));
    sbState.y = clamp(sbState.y, 8, Math.max(8, window.innerHeight - actualH - 8));
    sb.style.transform = `translate3d(${sbState.x}px, ${sbState.y}px, 0)`;
  } else {
    sb.style.width = "";
    sb.style.height = "";
    sb.style.transform = "";
  }

  $("btn-lang").textContent = sbState.collapsed ? (isZh ? "EN" : "中") : "中文 / English";
}

function initSidebarControls() {
  const sb = $("sidebar");
  const resizer = $("sb-resizer");
  const cornerResizer = $("sb-corner-resizer");
  const dragHandle = $("sidebar-drag-handle");
  const dockPreview = $("dock-preview");

  $("btn-sb-collapse").addEventListener("click", (e) => {
    e.stopPropagation();
    sbState.collapsed = !sbState.collapsed;
    applySidebarLayout();
    saveSidebarState();
  });

  $("btn-sb-float").addEventListener("click", (e) => {
    e.stopPropagation();
    if (sbState.mode === "docked") {
      const rect = sb.getBoundingClientRect();
      const w = sbState.collapsed ? 64 : sbState.width;
      const h = sbState.collapsed ? Math.min(rect.height, 420) : sbState.height;
      sbState.mode = "floating";
      sbState.x = clamp(rect.left + 12, 12, Math.max(12, window.innerWidth - w - 12));
      sbState.y = clamp(rect.top + 12, 12, Math.max(12, window.innerHeight - h - 12));
    } else {
      sbState.mode = "docked";
    }
    applySidebarLayout();
    saveSidebarState();
  });

  // Docked edge width resize
  resizer.addEventListener("pointerdown", (e) => {
    if (sbState.mode !== "docked" || sbState.collapsed) return;
    e.preventDefault();
    resizer.classList.add("resizing");
    resizer.setPointerCapture(e.pointerId);
    const startX = e.clientX;
    const startW = sbState.width;
    const onMove = (ev) => {
      const delta = sbState.dockSide === "right" ? startX - ev.clientX : ev.clientX - startX;
      sbState.width = clamp(startW + delta, 180, 420);
      applySidebarLayout();
    };
    const onUp = () => {
      resizer.classList.remove("resizing");
      resizer.removeEventListener("pointermove", onMove);
      resizer.removeEventListener("pointerup", onUp);
      resizer.removeEventListener("pointercancel", onUp);
      saveSidebarState();
    };
    resizer.addEventListener("pointermove", onMove);
    resizer.addEventListener("pointerup", onUp);
    resizer.addEventListener("pointercancel", onUp);
  });

  resizer.addEventListener("dblclick", () => {
    sbState.width = SB_DEFAULT.width;
    applySidebarLayout();
    saveSidebarState();
  });

  // Floating corner resize
  cornerResizer.addEventListener("pointerdown", (e) => {
    if (sbState.mode !== "floating" || sbState.collapsed) return;
    e.preventDefault();
    e.stopPropagation();
    cornerResizer.setPointerCapture(e.pointerId);
    const startX = e.clientX;
    const startY = e.clientY;
    const startW = sbState.width;
    const startH = sbState.height;
    const onMove = (ev) => {
      sbState.width = clamp(startW + (ev.clientX - startX), 190, 440);
      sbState.height = clamp(startH + (ev.clientY - startY), 340, window.innerHeight - sbState.y - 8);
      applySidebarLayout();
    };
    const onUp = () => {
      cornerResizer.removeEventListener("pointermove", onMove);
      cornerResizer.removeEventListener("pointerup", onUp);
      cornerResizer.removeEventListener("pointercancel", onUp);
      saveSidebarState();
    };
    cornerResizer.addEventListener("pointermove", onMove);
    cornerResizer.addEventListener("pointerup", onUp);
    cornerResizer.addEventListener("pointercancel", onUp);
  });

  // Dragging sidebar header: freely move when floating, or drag out to detach when docked
  dragHandle.addEventListener("pointerdown", (e) => {
    if (e.target.closest("button")) return;
    e.preventDefault();
    dragHandle.setPointerCapture(e.pointerId);
    const startX = e.clientX;
    const startY = e.clientY;
    const rect = sb.getBoundingClientRect();
    let originX = sbState.mode === "floating" ? sbState.x : rect.left;
    let originY = sbState.mode === "floating" ? sbState.y : rect.top;
    let snapSide = null;
    let detachedDuringDrag = false;

    const onMove = (ev) => {
      const dx = ev.clientX - startX;
      const dy = ev.clientY - startY;
      if (sbState.mode === "docked") {
        if (Math.hypot(dx, dy) < 28) return;
        sbState.mode = "floating";
        detachedDuringDrag = true;
        originX = rect.left;
        originY = rect.top;
      }
      sb.classList.add("dragging");
      sbState.x = originX + dx;
      sbState.y = originY + dy;
      applySidebarLayout();

      // Edge snap detection
      if (ev.clientX <= 26) {
        snapSide = "left";
        dockPreview.classList.remove("hidden", "right");
        dockPreview.classList.add("left");
      } else if (ev.clientX >= window.innerWidth - 26) {
        snapSide = "right";
        dockPreview.classList.remove("hidden", "left");
        dockPreview.classList.add("right");
      } else {
        snapSide = null;
        dockPreview.classList.add("hidden");
      }
    };

    const onUp = () => {
      sb.classList.remove("dragging");
      dockPreview.classList.add("hidden");
      dragHandle.removeEventListener("pointermove", onMove);
      dragHandle.removeEventListener("pointerup", onUp);
      dragHandle.removeEventListener("pointercancel", onUp);
      if (snapSide) {
        sbState.mode = "docked";
        sbState.dockSide = snapSide;
        applySidebarLayout();
      }
      if (sbState.mode === "floating" || snapSide || detachedDuringDrag) {
        saveSidebarState();
      }
    };

    dragHandle.addEventListener("pointermove", onMove);
    dragHandle.addEventListener("pointerup", onUp);
    dragHandle.addEventListener("pointercancel", onUp);
  });

  window.addEventListener("resize", () => {
    if (sbState.mode === "floating") {
      applySidebarLayout();
    }
  });

  applySidebarLayout();
}

/* =========================================================
   Config & Roots Rendering
   ========================================================= */
function updateModeUi(mode) {
  selectedMode = mode || "cloudflare-quick";
  document.querySelectorAll(".mode-card").forEach((c) => {
    c.classList.toggle("selected", c.dataset.mode === selectedMode);
  });
  $("group-cf-named").classList.toggle("hidden", selectedMode !== "cloudflare-named");
  $("group-vps").classList.toggle("hidden", selectedMode !== "vps");
}

function updateChecklistVisibility(running, mcpUrl) {
  const rootsCount = (currentConfig?.allowedRoots || []).length;
  const allDone = rootsCount > 0 && running && Boolean(mcpUrl);
  $("checklist-bar").classList.toggle("hidden", allDone);
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
    const actWrap = document.createElement("div");
    actWrap.className = "root-item-actions";

    const btnOpen = document.createElement("button");
    btnOpen.className = "btn btn-ghost btn-sm";
    btnOpen.textContent = t("openFolder");
    btnOpen.onclick = async () => {
      if (!invoke) return;
      try {
        await invoke("reveal_in_explorer", { path: dir });
      } catch (e) {
        showAlert(String(e));
      }
    };

    const btnDel = document.createElement("button");
    btnDel.className = "btn btn-ghost btn-sm";
    btnDel.textContent = t("remove");
    btnDel.onclick = () => {
      currentConfig.allowedRoots.splice(idx, 1);
      setDirty(true);
      renderRoots();
    };
    actWrap.append(btnOpen, btnDel);
    li.append(span, actWrap);
    list.appendChild(li);
  });
}

/* =========================================================
   Activity Stream (Selectable, Expandable, Searchable)
   ========================================================= */
function badgeInfoFor(item) {
  if (item.isError && item.category !== "security") {
    return { cls: "badge-err", label: item.platform !== "AI Client" ? item.platform : "ERR" };
  }
  if (item.platform === "Gemini") return { cls: "badge-gemini", label: "Gemini" };
  if (item.platform === "ChatGPT") return { cls: "badge-chatgpt", label: "ChatGPT" };
  if (item.platform === "Delete Guard") return { cls: "badge-guard", label: "Delete Guard" };
  if (item.category === "fs") return { cls: "badge-fs", label: t("fFs") };
  if (item.category === "cmd") return { cls: "badge-cmd", label: t("fCmd") };
  if (item.category === "chrome") return { cls: "badge-chrome", label: t("fChrome") };
  return { cls: "badge-guard", label: t("fSec") };
}

function isRevealablePath(item) {
  const raw = (item.fullTarget || item.target || "").trim();
  if (!raw) return false;
  const firstLine = raw.split(/\r?\n/)[0].trim();
  if (item.category === "fs") return /^[a-zA-Z]:\\/.test(firstLine);
  return false;
}

function hasSelectionInActivityList() {
  const sel = window.getSelection();
  if (!sel || sel.isCollapsed || !sel.toString().trim()) return false;
  const list = $("activity-list");
  if (!list) return false;
  return (
    (sel.anchorNode && list.contains(sel.anchorNode)) ||
    (sel.focusNode && list.contains(sel.focusNode))
  );
}

function renderDetailHtml(item) {
  const fullText = item.fullTarget || item.target || "—";
  const detail = item.commandId ? commandDetailCache.get(item.commandId) : null;
  const loading = item.commandId && commandDetailLoading.has(item.commandId);
  const displayCmd = detail?.command || fullText;
  const cwd = detail?.cwd || item.cwd || "";

  let metaParts = [];
  if (cwd) metaParts.push(`<span>cwd: <code>${esc(cwd)}</code></span>`);
  if (item.source) metaParts.push(`<span>source: <code>${esc(item.source)}</code></span>`);
  if (item.commandId) metaParts.push(`<span>id: <code>${esc(item.commandId)}</code></span>`);
  if (detail) {
    const exitCls = detail.exitCode === 0 ? "act-exit-ok" : detail.exitCode != null ? "act-exit-err" : "";
    const exitTxt = detail.exitCode != null ? `exit ${detail.exitCode}` : detail.state;
    metaParts.push(`<span>status: <code class="${exitCls}">${esc(exitTxt)}</code></span>`);
  }

  let outputBlock = "";
  if (item.commandId) {
    if (loading && !detail) {
      outputBlock = `<div class="act-detail-head"><span>${esc(t("outputLbl"))}</span></div>
        <pre class="act-code act-out">${esc(t("loadingDetail"))}</pre>`;
    } else if (detail) {
      const outText = detail.output ? detail.output : t("noOutput");
      outputBlock = `<div class="act-detail-head">
          <span>${esc(t("outputLbl"))}</span>
          <div style="display:flex;gap:5px;">
            <button class="act-qbtn" type="button" data-act="refresh-detail" data-id="${esc(item.id)}">${esc(t("refresh"))}</button>
            ${detail.output ? `<button class="act-qbtn" type="button" data-act="copy-out" data-cid="${esc(item.commandId)}">${esc(t("copyOutput"))}</button>` : ""}
          </div>
        </div>
        <pre class="act-code act-out" data-scroll-key="out:${esc(item.id)}">${esc(outText)}</pre>`;
    }
  }

  return `<div class="act-detail">
    ${metaParts.length ? `<div class="act-meta-row">${metaParts.join("")}</div>` : ""}
    <div class="act-detail-head">
      <span>${esc(t("fullCommandLbl"))}</span>
      <div style="display:flex;gap:5px;">
        <button class="act-qbtn" type="button" data-act="copy-full" data-id="${esc(item.id)}">${esc(t("copy"))}</button>
        ${isRevealablePath(item) ? `<button class="act-qbtn" type="button" data-act="reveal" data-id="${esc(item.id)}">${esc(t("reveal"))}</button>` : ""}
      </div>
    </div>
    <pre class="act-code" data-scroll-key="cmd:${esc(item.id)}">${esc(displayCmd)}</pre>
    ${outputBlock}
  </div>`;
}

function activityHtml(item) {
  const b = badgeInfoFor(item);
  const expanded = expandedIds.has(item.id);
  const cls = [
    "act-item",
    `cat-${esc(item.category)}`,
    item.isError ? "is-error" : "",
    expanded ? "expanded" : "",
  ]
    .filter(Boolean)
    .join(" ");

  return `<div class="${cls}" data-id="${esc(item.id)}">
    <div class="act-row" data-act="toggle" data-id="${esc(item.id)}">
      <svg class="act-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polyline points="9 18 15 12 9 6"/></svg>
      <span class="act-badge ${b.cls}">${esc(b.label)}</span>
      <span class="act-tool">${esc(item.tool)}</span>
      <span class="act-target" title="${esc(item.target)}">${esc(item.target || "—")}</span>
      <div class="act-quick">
        <button class="act-qbtn" type="button" data-act="copy-full" data-id="${esc(item.id)}">${esc(t("copy"))}</button>
        ${isRevealablePath(item) ? `<button class="act-qbtn" type="button" data-act="reveal" data-id="${esc(item.id)}">${esc(t("reveal"))}</button>` : ""}
      </div>
      <span class="act-time">${esc(item.time)}</span>
    </div>
    ${expanded ? renderDetailHtml(item) : ""}
  </div>`;
}

function miniActivityHtml(item) {
  const b = badgeInfoFor(item);
  return `<div class="mini-act" data-mini-id="${esc(item.id)}">
    <span class="act-badge ${b.cls}">${esc(b.label)}</span>
    <span class="act-tool">${esc(item.tool)}</span>
    <span class="act-target" title="${esc(item.target)}">${esc(item.target || "—")}</span>
    <span class="act-time">${esc(item.time)}</span>
  </div>`;
}

function getFilteredActivities() {
  const q = activitySearch.trim().toLowerCase();
  return lastActivities.filter((x) => {
    if (activeFilter !== "all" && x.category !== activeFilter) return false;
    if (!q) return true;
    return (
      (x.tool || "").toLowerCase().includes(q) ||
      (x.target || "").toLowerCase().includes(q) ||
      (x.fullTarget || "").toLowerCase().includes(q) ||
      (x.cwd || "").toLowerCase().includes(q) ||
      (x.platform || "").toLowerCase().includes(q)
    );
  });
}

function renderActivityListDom() {
  const full = $("activity-list");
  const prevScrollTop = full.scrollTop;
  const codeScrolls = new Map();
  full.querySelectorAll("[data-scroll-key]").forEach((el) => {
    if (el.scrollTop > 0) codeScrolls.set(el.dataset.scrollKey, el.scrollTop);
  });

  if (!lastActivities.length) {
    full.innerHTML = `<div class="sec-desc" style="margin:8px 0;">${esc(t("noActivity"))}</div>`;
    return;
  }
  const filtered = getFilteredActivities();
  if (!filtered.length) {
    full.innerHTML = `<div class="sec-desc" style="margin:8px 0;">${esc(t("noMatchActivity"))}</div>`;
    return;
  }
  full.innerHTML = filtered.map(activityHtml).join("");
  if (prevScrollTop > 0) {
    full.scrollTop = prevScrollTop;
  }
  if (codeScrolls.size > 0) {
    full.querySelectorAll("[data-scroll-key]").forEach((el) => {
      const saved = codeScrolls.get(el.dataset.scrollKey);
      if (saved != null) el.scrollTop = saved;
    });
  }
}

async function ensureCommandDetail(item, force = false) {
  if (!invoke || !item?.commandId) return;
  const cached = commandDetailCache.get(item.commandId);
  if (!force && cached && cached.state !== "running") return;
  if (commandDetailLoading.has(item.commandId)) return;
  commandDetailLoading.add(item.commandId);
  renderActivityListDom();
  try {
    const detail = await invoke("get_command_detail", { commandId: item.commandId });
    commandDetailCache.set(item.commandId, detail);
  } catch (e) {
    commandDetailCache.set(item.commandId, {
      commandId: item.commandId,
      command: item.fullTarget || item.target || "",
      cwd: item.cwd || "",
      state: "unavailable",
      exitCode: null,
      timedOut: false,
      startedAt: "",
      finishedAt: "",
      output: String(e),
    });
  } finally {
    commandDetailLoading.delete(item.commandId);
    renderActivityListDom();
  }
}

function updateStatsAndMini(items, stats) {
  $("activity-count-badge").textContent = String(stats?.total || 0);
  $("st-total").textContent = String(stats?.total || 0);
  $("st-fs").textContent = String(stats?.fsCount || 0);
  $("st-cmd").textContent = String(stats?.cmdCount || 0);
  $("st-sec").textContent = String(stats?.securityCount || 0);

  const mini = $("mini-activity-feed");
  if (!items.length) {
    mini.innerHTML = `<div class="sec-desc" style="margin:8px 0;">${esc(t("noActivity"))}</div>`;
  } else {
    mini.innerHTML = items.slice(0, 6).map(miniActivityHtml).join("");
  }
}

function renderActivities(items, stats, force = false) {
  const safeItems = items || [];
  const safeStats = stats || { total: 0, fsCount: 0, cmdCount: 0, securityCount: 0 };
  const tailItem = safeItems[safeItems.length - 1];
  const sig = `${isZh}:${activeFilter}:${activitySearch}:${safeStats.total}:${safeStats.fsCount}:${safeStats.cmdCount}:${safeStats.securityCount}:${safeItems.length}:${safeItems[0]?.id || ""}:${tailItem?.id || ""}`;

  if (!force && sig === lastActivitySignature) {
    return;
  }

  // Always update badges/stats & dashboard mini preview
  updateStatsAndMini(safeItems, safeStats);

  // Protect user text selection or paused state on the full activity list
  if (!force && (activityPaused || hasSelectionInActivityList())) {
    pendingActivities = { items: safeItems, stats: safeStats };
    $("activity-pending-bar").classList.remove("hidden");
    $("activity-pending-text").textContent = activityPaused
      ? isZh
        ? "已暂停自动刷新，有新动态到达"
        : "Auto-refresh paused · new activity available"
      : isZh
        ? "检测到正在划选文本，已暂缓刷新列表"
        : "Selection active · list refresh deferred";
    return;
  }

  lastActivities = safeItems;
  lastStats = safeStats;
  pendingActivities = null;
  $("activity-pending-bar").classList.add("hidden");
  lastActivitySignature = sig;
  renderActivityListDom();
}

function flushPendingActivities() {
  activityPaused = false;
  updatePauseBtn();
  if (pendingActivities) {
    const p = pendingActivities;
    pendingActivities = null;
    renderActivities(p.items, p.stats, true);
  } else {
    $("activity-pending-bar").classList.add("hidden");
  }
}

function updatePauseBtn() {
  const btn = $("btn-pause-activity");
  btn.textContent = activityPaused ? t("btnResume") : t("btnPause");
  btn.classList.toggle("active-toggle", activityPaused);
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
  $("activity-search").placeholder = t("searchPlaceholder");
  updatePauseBtn();
  applySidebarLayout();
  renderRoots();
  renderActivityListDom();
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

function formatModeLabel(mode) {
  switch (mode) {
    case "vps":
    case "vps-ssh":
      return t("modeVpsShort");
    case "cloudflare-named":
      return t("modeNamedShort");
    case "local":
      return t("modeLocalShort");
    default:
      return t("modeQuickShort");
  }
}

function applyStatus(st) {
  lastRunning = Boolean(st.running);
  const isExternal = st.running && st.managedBy === "external";
  const pill = $("status-pill");
  pill.classList.toggle("running", st.running);
  $("status-text").textContent = st.running
    ? isExternal
      ? t("statusRunningAttached")
      : t("statusRunning")
    : t("statusStopped");

  const activeMode = st.connectionMode || currentConfig?.connectionMode || "cloudflare-quick";
  const modePill = $("mode-pill");
  modePill.classList.toggle("active", st.running);
  $("mode-pill-text").textContent = formatModeLabel(activeMode);
  modePill.title = st.tunnelDetail
    ? `${formatModeLabel(activeMode)} (${st.tunnelDetail})`
    : formatModeLabel(activeMode);

  $("attach-pill").classList.toggle("hidden", !isExternal);

  if (!isStarting && !isRestarting) {
    $("btn-start").disabled = st.running;
    $("btn-start-label").textContent = t("btnStart");
    $("btn-restart").classList.toggle("hidden", !st.running);
    $("btn-restart").disabled = false;
    $("btn-restart").textContent = t("btnRestart");
  }
  $("btn-stop").disabled = !st.running || isRestarting;

  $("step-2").classList.toggle("done", st.running);
  $("step-3").classList.toggle("done", st.running && Boolean(st.mcpUrl));
  updateChecklistVisibility(st.running, st.mcpUrl);

  const setCard = (cardId, valId, ok, offLabel, okLabel) => {
    $(cardId).classList.toggle("ok", ok);
    $(valId).textContent = ok ? okLabel || t("healthy") : offLabel;
  };
  const isVps = activeMode === "vps" || activeMode === "vps-ssh";
  setCard("card-fs", "val-fs", st.fsOk, t("stopped"));
  setCard("card-wb", "val-wb", st.workbenchOk, t("stopped"));
  if (st.running && isVps && !st.gatewayOk) {
    setCard("card-gw", "val-gw", true, t("stopped"), t("remoteVpsOk"));
  } else {
    setCard("card-gw", "val-gw", st.gatewayOk, t("stopped"));
  }
  setCard("card-ch", "val-ch", st.chromeOk, t("disabled"));

  if (st.ports) {
    $("port-fs").textContent = `:${st.ports.fsPort}`;
    $("port-wb").textContent = `:${st.ports.workbenchPort}`;
    $("port-gw").textContent = isVps ? "VPS" : `:${st.ports.gatewayPort}`;
    $("port-ch").textContent = `:${st.ports.chromePort}`;
  }

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

  if (st.lastError && st.lastError !== dismissedAlertMsg) {
    showAlert(st.lastError);
  } else if (!st.lastError) {
    dismissedAlertMsg = "";
  }
}

/* =========================================================
   Event Wiring
   ========================================================= */
document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});
$("btn-go-roots").addEventListener("click", () => switchTab("roots"));
$("mode-pill").addEventListener("click", () => switchTab("wizard"));
$("btn-all-activity").addEventListener("click", () => switchTab("activity"));
$("btn-all-logs").addEventListener("click", () => switchTab("logs"));

$("btn-alert-close").addEventListener("click", () => {
  dismissedAlertMsg = $("alert-msg").textContent || "";
  showAlert("");
});

$("dirty-tag").addEventListener("click", () => persist());

// Activity filters, search, pause, flush
document.querySelectorAll("#activity-filters .fpill").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#activity-filters .fpill").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    activeFilter = btn.dataset.filter;
    renderActivityListDom();
  });
});

$("activity-search").addEventListener("input", (e) => {
  activitySearch = e.target.value || "";
  renderActivityListDom();
});

$("btn-pause-activity").addEventListener("click", () => {
  if (activityPaused) {
    flushPendingActivities();
  } else {
    activityPaused = true;
    updatePauseBtn();
  }
});

$("btn-flush-activity").addEventListener("click", flushPendingActivities);

// Event delegation on full activity list
$("activity-list").addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-act]");
  if (!btn) return;
  const act = btn.dataset.act;

  if (act === "copy-full") {
    e.stopPropagation();
    const item = lastActivities.find((x) => x.id === btn.dataset.id);
    if (!item) return;
    const cached = item.commandId ? commandDetailCache.get(item.commandId) : null;
    const text = cached?.command || item.fullTarget || item.target || "";
    if (!text) return;
    await navigator.clipboard.writeText(text);
    toast(t("toastCopied"));
    return;
  }

  if (act === "copy-out") {
    e.stopPropagation();
    const cached = commandDetailCache.get(btn.dataset.cid);
    if (!cached?.output) return;
    await navigator.clipboard.writeText(cached.output);
    toast(t("toastCopied"));
    return;
  }

  if (act === "refresh-detail") {
    e.stopPropagation();
    const item = lastActivities.find((x) => x.id === btn.dataset.id);
    if (!item || !item.commandId) return;
    ensureCommandDetail(item, true);
    return;
  }

  if (act === "reveal") {
    e.stopPropagation();
    if (!invoke) return;
    const item = lastActivities.find((x) => x.id === btn.dataset.id);
    if (!item) return;
    try {
      await invoke("reveal_in_explorer", { path: item.fullTarget || item.target });
    } catch (err) {
      showAlert(String(err));
    }
    return;
  }

  if (act === "toggle") {
    // Do not toggle if user just dragged to select text
    if (window.getSelection()?.toString().trim()) return;
    const id = btn.dataset.id;
    const item = lastActivities.find((x) => x.id === id);
    if (!item) return;
    if (expandedIds.has(id)) {
      expandedIds.delete(id);
      renderActivityListDom();
    } else {
      expandedIds.add(id);
      renderActivityListDom();
      if (item.commandId) {
        ensureCommandDetail(item);
      }
    }
  }
});

// Dashboard mini activity click -> jump & expand
$("mini-activity-feed").addEventListener("click", (e) => {
  const row = e.target.closest("[data-mini-id]");
  if (!row) return;
  const id = row.dataset.miniId;
  const item = lastActivities.find((x) => x.id === id);
  if (!item) return;
  activeFilter = "all";
  activitySearch = "";
  $("activity-search").value = "";
  document.querySelectorAll("#activity-filters .fpill").forEach((b) => {
    b.classList.toggle("active", b.dataset.filter === "all");
  });
  expandedIds.add(id);
  switchTab("activity");
  renderActivityListDom();
  if (item.commandId) {
    ensureCommandDetail(item);
  }
  const el = $("activity-list").querySelector(`[data-id="${CSS.escape(id)}"]`);
  if (el) el.scrollIntoView({ block: "nearest", behavior: "smooth" });
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
    toast(lastRunning ? t("toastSavedNeedRestart") : t("toastSaved"));
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

$("btn-restart").addEventListener("click", async () => {
  if (!invoke || isRestarting) return;
  const cfg = collectConfigFromUi();
  isRestarting = true;
  $("btn-restart").disabled = true;
  $("btn-restart").textContent = t("btnRestarting");
  $("btn-stop").disabled = true;
  showAlert("");
  try {
    await invoke("stop_services");
    const st = await invoke("start_services", { cfg });
    isRestarting = false;
    setDirty(false);
    applyStatus(st);
    toast(t("toastRestarted"));
  } catch (e) {
    isRestarting = false;
    showAlert(String(e));
    await refreshLive();
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
  initSidebarControls();
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
