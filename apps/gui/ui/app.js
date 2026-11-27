const invoke = window.__TAURI__?.core?.invoke;
const $ = (id) => document.getElementById(id);

let currentConfig = null;
let selectedMode = "cloudflare-quick";
let activeTab = "dashboard";
let activityPaused = false;
let dashboardRecent = [];
let latestAllStats = { total: 0, fsCount: 0, cmdCount: 0, chromeCount: 0, securityCount: 0, errorCount: 0, todayCount: 0 };
let latestActivityRevision = "";
let actFetchSeq = 0;
let actSearchTimer = null;
let lastLogSignature = "";
let isStarting = false;
let isRestarting = false;
let lastRunning = false;
let dismissedAlertMsg = "";
let isZh = true;
let toastTimer = null;
let pollTimer = null;
let pollIntervalMs = 2000;
let lastEnv = { pwshOk: true, cloudflaredOk: true, sshOk: true, nodeOk: true };
let downloadingCf = false;
let activeDepModalKey = "";

const actQuery = {
  page: 1,
  pageSize: 50,
  preset: "all",
  date: "",
  timeFrom: "",
  timeTo: "",
  category: "all",
  errorsOnly: false,
  search: "",
};

let actPage = {
  items: [],
  page: 1,
  pageSize: 50,
  totalMatched: 0,
  totalPages: 1,
  allStats: { total: 0, fsCount: 0, cmdCount: 0, chromeCount: 0, securityCount: 0, errorCount: 0, todayCount: 0 },
  scopedStats: { total: 0, fsCount: 0, cmdCount: 0, chromeCount: 0, securityCount: 0, errorCount: 0, todayCount: 0 },
  availableDates: [],
  revision: "",
};

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
    navSettings: "系统设置",
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
    stChrome: "浏览器自动化",
    stSec: "授权与守卫拦截",
    activityHeading: "Gemini / ChatGPT 本地操作流",
    liveSyncing: "实时同步",
    livePaused: "已暂停",
    liveHistory: "历史视图",
    pAll: "全部",
    pToday: "今天",
    pYesterday: "昨天",
    p3d: "近3天",
    p7d: "近7天",
    p30d: "近30天",
    searchPlaceholder: "搜索命令、路径、工具名（空格多词匹配）...",
    btnPause: "暂停",
    btnResume: "恢复",
    btnFlush: "立即刷新",
    btnBackLatest: "返回最新",
    btnResetFilters: "重置筛选",
    refresh: "刷新",
    fAll: "全部",
    fFs: "文件",
    fCmd: "命令",
    fChrome: "浏览器",
    fSec: "安全",
    fErrorsOnly: "仅异常",
    pgJump: "跳至",
    todayLabel: "今天",
    yesterdayLabel: "昨天",
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
    setStorageTitle: "存储占用与自动清理",
    setStorageDesc: "自动按天数和体积上限清理过期日志与历史命令产物，兼顾历史回溯与磁盘空间安全。",
    btnRefreshStorage: "刷新占用",
    btnRunCleanup: "立即清理过期数据",
    storageTotalLbl: "state/ 目录当前占用",
    slAudit: "审计日志",
    slCmd: "命令输出",
    slMeta: "会话与任务",
    slAux: "辅助日志",
    swRetEnable: "启用后台自动清理",
    swRetEnableDesc: "服务启动后自动执行一次，之后按设定周期在后台静默清理（正在运行的命令受锁保护不会被删）。",
    lblRetInterval: "定时清理周期",
    lblRetAuditDays: "审计日志保留天数",
    lblRetWbDays: "命令输出与会话保留天数",
    lblRetAuditMb: "单审计文件轮转上限 (MB)",
    lblRetAuditFiles: "审计归档最大数量",
    lblRetWbMb: "命令输出总磁盘上限 (MB)",
    lblRetAuxMb: "辅助日志轮转上限 (MB)",
    setUiTitle: "动态流与界面偏好",
    lblUiPageSize: "动态流默认每页条数",
    lblUiPoll: "实时状态轮询间隔",
    lblUiLang: "界面语言",
    btnResetSidebar: "重置侧边栏停靠布局",
    setPortsTitle: "本地服务端口配置",
    setPortsDesc: "如遇本机端口冲突可在此调整；修改端口后需重启服务生效。",
    setAdvSummary: "高级能力与维护（视觉识别后端 / 目录快捷入口 / 密钥重置）",
    setVisionSub: "视觉识别后端（Vision）",
    lblVisionBackend: "识别模式",
    setMaintSub: "目录与凭据维护",
    btnOpenConfigDir: "打开配置目录",
    btnOpenLogsDir: "打开日志目录",
    btnRegenApproval: "重新生成 Owner Approval Key",
    btnSaveSettings: "保存系统设置",
    cfMissingTitle: "未检测到 cloudflared.exe（Cloudflare 隧道必需）",
    btnDlCf: "一键下载 cloudflared",
    btnDlCfBusy: "正在下载中...",
    btnRecheck: "重新检测",
    depOrCmd: "或打开终端执行命令行安装：",
  },
  en: {
    navDashboard: "Dashboard",
    navActivity: "AI Activity",
    navWizard: "Connection",
    navRoots: "Roots & Guards",
    navLogs: "Terminal Logs",
    navSettings: "Settings",
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
    stChrome: "Browser Auto",
    stSec: "Auth & Guards",
    activityHeading: "Gemini / ChatGPT Local Activity Stream",
    liveSyncing: "Live",
    livePaused: "Paused",
    liveHistory: "History",
    pAll: "All",
    pToday: "Today",
    pYesterday: "Yesterday",
    p3d: "3D",
    p7d: "7D",
    p30d: "30D",
    searchPlaceholder: "Search command, path, tool (space for AND)...",
    btnPause: "Pause",
    btnResume: "Resume",
    btnFlush: "Refresh now",
    btnBackLatest: "Back to latest",
    btnResetFilters: "Reset filters",
    refresh: "Refresh",
    fAll: "All",
    fFs: "Files",
    fCmd: "Commands",
    fChrome: "Browser",
    fSec: "Security",
    fErrorsOnly: "Errors",
    pgJump: "Go to",
    todayLabel: "Today",
    yesterdayLabel: "Yesterday",
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
    setStorageTitle: "Storage Usage & Auto Cleanup",
    setStorageDesc: "Automatically prune expired logs and workbench artifacts by age and disk budget.",
    btnRefreshStorage: "Refresh",
    btnRunCleanup: "Clean Expired Now",
    storageTotalLbl: "Current state/ disk usage",
    slAudit: "Audit Logs",
    slCmd: "Command Outputs",
    slMeta: "Sessions & Tasks",
    slAux: "Aux Logs",
    swRetEnable: "Enable Background Auto Cleanup",
    swRetEnableDesc: "Runs once shortly after startup and periodically thereafter (active locked commands are never deleted).",
    lblRetInterval: "Cleanup Interval",
    lblRetAuditDays: "Audit Log Retention",
    lblRetWbDays: "Command Output Retention",
    lblRetAuditMb: "Audit File Rotate Size (MB)",
    lblRetAuditFiles: "Max Audit Archives",
    lblRetWbMb: "Command Outputs Budget (MB)",
    lblRetAuxMb: "Aux Log Rotate Size (MB)",
    setUiTitle: "Activity Stream & UI Preferences",
    lblUiPageSize: "Default Page Size",
    lblUiPoll: "Live Polling Interval",
    lblUiLang: "Interface Language",
    btnResetSidebar: "Reset Sidebar Layout",
    setPortsTitle: "Local Service Ports",
    setPortsDesc: "Adjust local loopback ports if there is a port conflict; restart services to apply.",
    setAdvSummary: "Advanced & Maintenance (Vision Backend / Quick Folders / Key Reset)",
    setVisionSub: "Vision Backend",
    lblVisionBackend: "Vision Mode",
    setMaintSub: "Directories & Credentials",
    btnOpenConfigDir: "Open Config Folder",
    btnOpenLogsDir: "Open Logs Folder",
    btnRegenApproval: "Regenerate Owner Approval Key",
    btnSaveSettings: "Save Settings",
    cfMissingTitle: "cloudflared.exe not found (required for Cloudflare Tunnel)",
    btnDlCf: "Download cloudflared",
    btnDlCfBusy: "Downloading...",
    btnRecheck: "Re-check",
    depOrCmd: "Or install via terminal command:",
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
  if (tabName === "activity" && (!actPage.revision || actPage.revision !== latestActivityRevision)) {
    fetchActivityPage({ preserveScroll: false });
  }
  if (tabName === "settings") {
    refreshStorageUsage();
  }
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
  updateCfMissingBanner();
}

function updateCfMissingBanner() {
  const box = $("cf-missing-box");
  if (!box) return;
  const needCf = selectedMode === "cloudflare-quick" || selectedMode === "cloudflare-named";
  box.classList.toggle("hidden", !(needCf && !lastEnv.cloudflaredOk));
}

function applyEnvUi(env) {
  if (!env) return;
  lastEnv = env;
  $("env-pwsh").classList.toggle("ok", env.pwshOk);
  $("env-cf").classList.toggle("ok", env.cloudflaredOk);
  $("env-ssh").classList.toggle("ok", env.sshOk);
  $("env-node").classList.toggle("ok", env.nodeOk);
  updateCfMissingBanner();
}

async function runRecheckEnv() {
  if (!invoke) return;
  try {
    const env = await invoke("refresh_env");
    applyEnvUi(env);
    const modal = $("dep-modal");
    const depOkMap = { cf: env.cloudflaredOk, pwsh: env.pwshOk, node: env.nodeOk, ssh: env.sshOk };
    if (modal && !modal.classList.contains("hidden") && activeDepModalKey && depOkMap[activeDepModalKey]) {
      modal.classList.add("hidden");
      activeDepModalKey = "";
      toast(isZh ? "已检测到该依赖安装就绪" : "Dependency detected and ready");
    } else {
      toast(isZh ? "依赖状态已刷新" : "Environment re-checked");
    }
  } catch (e) {
    showAlert(String(e));
  }
}

async function runDownloadCloudflared() {
  if (!invoke || downloadingCf) return;
  downloadingCf = true;
  const btns = [$("btn-dl-cf"), $("btn-dep-dl-cf")].filter(Boolean);
  btns.forEach((b) => {
    b.disabled = true;
    b.textContent = t("btnDlCfBusy");
  });
  showAlert("");
  try {
    await invoke("download_cloudflared");
    const env = await invoke("refresh_env");
    applyEnvUi(env);
    $("dep-modal").classList.add("hidden");
    toast(isZh ? "cloudflared.exe 已就绪，可直接启动服务" : "cloudflared.exe is ready");
  } catch (e) {
    showAlert(String(e));
  } finally {
    downloadingCf = false;
    btns.forEach((b) => {
      b.disabled = false;
      b.textContent = t("btnDlCf");
    });
  }
}

function openDepModal(dep) {
  const infoMap = {
    cf: {
      ok: lastEnv.cloudflaredOk,
      zhTitle: "Cloudflared（公网穿透隧道）",
      enTitle: "Cloudflared (Public Tunnel)",
      zhDesc: "Cloudflare Quick / Named 隧道模式需要本机安装 cloudflared.exe。你可以点击下方按钮一键自动下载到 tools/cloudflared.exe，或在终端执行以下命令安装：",
      enDesc: "Required for Cloudflare Quick / Named Tunnel modes. Click below to auto-download to tools/cloudflared.exe, or install via terminal:",
      cmd: "winget install --id Cloudflare.cloudflared -e",
      canAutoDownload: true,
    },
    pwsh: {
      ok: lastEnv.pwshOk,
      zhTitle: "PowerShell 7（AI Workbench 命令执行）",
      enTitle: "PowerShell 7 (AI Workbench)",
      zhDesc: "AI Workbench 执行本机终端命令推荐使用 PowerShell 7（pwsh.exe）。可在终端执行以下命令一键安装：",
      enDesc: "Recommended for running local shell commands via AI Workbench. Install via terminal:",
      cmd: "winget install --id Microsoft.PowerShell -e",
      canAutoDownload: false,
    },
    node: {
      ok: lastEnv.nodeOk,
      zhTitle: "Node.js（Chrome DevTools MCP Sidecar）",
      enTitle: "Node.js (Chrome DevTools Sidecar)",
      zhDesc: "启用浏览器自动化（Chrome Broker）时需要 Node.js / npx。若不使用浏览器控制可忽略；需要时可执行：",
      enDesc: "Required only when Chrome DevTools MCP Sidecar is enabled. Install via terminal:",
      cmd: "winget install --id OpenJS.NodeJS.LTS -e",
      canAutoDownload: false,
    },
    ssh: {
      ok: lastEnv.sshOk,
      zhTitle: "OpenSSH Client（VPS 反向隧道）",
      enTitle: "OpenSSH Client (VPS Reverse Tunnel)",
      zhDesc: "自建 Linux VPS 模式需要 Windows OpenSSH 客户端（ssh.exe）。可在管理员终端执行以下命令启用：",
      enDesc: "Required for self-hosted Linux VPS SSH -R mode. Enable in an elevated terminal:",
      cmd: "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0",
      canAutoDownload: false,
    },
  };
  const info = infoMap[dep];
  if (!info) return;
  if (info.ok) {
    toast(isZh ? `${info.zhTitle} 已安装就绪` : `${info.enTitle} is ready`);
    return;
  }
  activeDepModalKey = dep;
  $("dep-modal-title").textContent = isZh ? info.zhTitle : info.enTitle;
  $("dep-modal-desc").textContent = isZh ? info.zhDesc : info.enDesc;
  $("dep-modal-cmd").textContent = info.cmd;
  $("btn-dep-dl-cf").classList.toggle("hidden", !info.canAutoDownload);
  $("dep-modal").classList.remove("hidden");
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
  if (item.fullTime) metaParts.push(`<span>time: <code>${esc(item.fullTime)}</code></span>`);
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
      <span class="act-time" title="${esc(item.fullTime || item.time)}">${esc(item.time)}</span>
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
    <span class="act-time" title="${esc(item.fullTime || item.time)}">${esc(item.time)}</span>
  </div>`;
}

function localDateIso(offsetDays = 0) {
  const d = new Date();
  d.setDate(d.getDate() + offsetDays);
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

function isLiveCompatibleView() {
  return (
    actQuery.page === 1 &&
    !actQuery.date &&
    !actQuery.timeFrom &&
    !actQuery.timeTo &&
    !["yesterday", "custom"].includes(actQuery.preset)
  );
}

function hasActiveFilters() {
  return (
    actQuery.preset !== "all" ||
    Boolean(actQuery.date) ||
    Boolean(actQuery.timeFrom) ||
    Boolean(actQuery.timeTo) ||
    actQuery.category !== "all" ||
    actQuery.errorsOnly ||
    Boolean(actQuery.search.trim())
  );
}

function updateLiveChipAndFilterUi() {
  const chip = $("activity-live-chip");
  const txt = $("activity-live-text");
  chip.classList.remove("live", "paused", "history");
  if (activityPaused) {
    chip.classList.add("paused");
    txt.textContent = t("livePaused");
  } else if (!isLiveCompatibleView()) {
    chip.classList.add("history");
    txt.textContent = t("liveHistory");
  } else {
    chip.classList.add("live");
    txt.textContent = t("liveSyncing");
  }

  $("btn-reset-filters").classList.toggle("hidden", !hasActiveFilters());
  $("btn-clear-search").classList.toggle("hidden", !actQuery.search);

  document.querySelectorAll("#activity-stat-strip .stat-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.statCat === actQuery.category);
  });
  document.querySelectorAll("#activity-filters .fpill").forEach((b) => {
    b.classList.toggle("active", b.dataset.filter === actQuery.category);
  });
  document.querySelectorAll("#activity-presets .seg-btn").forEach((b) => {
    b.classList.toggle("active", !actQuery.date && b.dataset.preset === actQuery.preset);
  });
  $("btn-errors-only").classList.toggle("active", actQuery.errorsOnly);
}

function updateScopedCounts(scoped) {
  const s = scoped || {};
  $("fcnt-all").textContent = String(s.total || 0);
  $("fcnt-fs").textContent = String(s.fsCount || 0);
  $("fcnt-cmd").textContent = String(s.cmdCount || 0);
  $("fcnt-chrome").textContent = String(s.chromeCount || 0);
  $("fcnt-security").textContent = String(s.securityCount || 0);
  $("fcnt-err").textContent = String(s.errorCount || 0);
}

function updateDatePickerBounds(availableDates) {
  const inp = $("activity-date");
  if (!availableDates || !availableDates.length) {
    inp.removeAttribute("min");
    inp.removeAttribute("max");
    return;
  }
  // availableDates is sorted newest first
  inp.max = availableDates[0].date;
  inp.min = availableDates[availableDates.length - 1].date;
}

function buildPageList(current, total) {
  if (total <= 7) {
    return Array.from({ length: total }, (_, i) => i + 1);
  }
  const pages = [1];
  const left = Math.max(2, current - 1);
  const right = Math.min(total - 1, current + 1);
  if (left > 2) pages.push("...");
  for (let p = left; p <= right; p++) pages.push(p);
  if (right < total - 1) pages.push("...");
  pages.push(total);
  return pages;
}

function renderPaginationDom() {
  const totalMatched = actPage.totalMatched || 0;
  const allTotal = actPage.allStats?.total || 0;
  const page = actPage.page || 1;
  const pageSize = actPage.pageSize || 50;
  const totalPages = Math.max(1, actPage.totalPages || 1);

  const summary = $("pg-summary");
  if (totalMatched === 0) {
    summary.textContent = isZh ? "共 0 条" : "0 items";
  } else {
    const start = (page - 1) * pageSize + 1;
    const end = Math.min(page * pageSize, totalMatched);
    if (hasActiveFilters() && allTotal > totalMatched) {
      summary.textContent = isZh
        ? `第 ${start}–${end} 条 / 共 ${totalMatched} 条（全量 ${allTotal} 条）`
        : `${start}–${end} of ${totalMatched} (${allTotal} total)`;
    } else {
      summary.textContent = isZh
        ? `第 ${start}–${end} 条 / 共 ${totalMatched} 条`
        : `${start}–${end} of ${totalMatched}`;
    }
  }

  $("pg-size").value = String(pageSize);
  $("pg-jump").value = String(page);
  $("pg-jump").max = String(totalPages);
  $("pg-total").textContent = String(totalPages);

  const btnWrap = $("pg-buttons");
  const pages = buildPageList(page, totalPages);
  const parts = [];
  parts.push(`<button class="pg-btn" type="button" data-pg="1" ${page <= 1 ? "disabled" : ""} title="${isZh ? "首页" : "First"}">«</button>`);
  parts.push(`<button class="pg-btn" type="button" data-pg="${page - 1}" ${page <= 1 ? "disabled" : ""} title="${isZh ? "上一页" : "Previous"}">‹</button>`);
  for (const p of pages) {
    if (p === "...") {
      parts.push(`<span class="pg-ellipsis">…</span>`);
    } else {
      parts.push(`<button class="pg-btn ${p === page ? "active" : ""}" type="button" data-pg="${p}">${p}</button>`);
    }
  }
  parts.push(`<button class="pg-btn" type="button" data-pg="${page + 1}" ${page >= totalPages ? "disabled" : ""} title="${isZh ? "下一页" : "Next"}">›</button>`);
  parts.push(`<button class="pg-btn" type="button" data-pg="${totalPages}" ${page >= totalPages ? "disabled" : ""} title="${isZh ? "末页" : "Last"}">»</button>`);
  btnWrap.innerHTML = parts.join("");
}

function renderActivityListDom({ preserveScroll = true } = {}) {
  const full = $("activity-list");
  const prevScrollTop = preserveScroll ? full.scrollTop : 0;
  const codeScrolls = new Map();
  if (preserveScroll) {
    full.querySelectorAll("[data-scroll-key]").forEach((el) => {
      if (el.scrollTop > 0) codeScrolls.set(el.dataset.scrollKey, el.scrollTop);
    });
  }

  const items = actPage.items || [];
  if (!actPage.allStats?.total && !items.length) {
    full.innerHTML = `<div class="sec-desc" style="margin:8px 0;">${esc(t("noActivity"))}</div>`;
    renderPaginationDom();
    return;
  }
  if (!items.length) {
    full.innerHTML = `<div class="sec-desc" style="margin:8px 0;">${esc(t("noMatchActivity"))}</div>`;
    renderPaginationDom();
    return;
  }

  const todayStr = localDateIso(0);
  const yesterdayStr = localDateIso(-1);
  let lastDate = null;
  const htmlParts = [];

  for (const item of items) {
    const d = item.date || "";
    if (d && d !== lastDate) {
      lastDate = d;
      let tag = "";
      if (d === todayStr) tag = `<span class="act-date-tag">${esc(t("todayLabel"))}</span>`;
      else if (d === yesterdayStr) tag = `<span class="act-date-tag">${esc(t("yesterdayLabel"))}</span>`;
      htmlParts.push(`<div class="act-date-divider"><span class="act-date-badge">${esc(d)}${tag}</span></div>`);
    }
    htmlParts.push(activityHtml(item));
  }

  full.innerHTML = htmlParts.join("");
  full.scrollTop = prevScrollTop;
  if (codeScrolls.size > 0) {
    full.querySelectorAll("[data-scroll-key]").forEach((el) => {
      const saved = codeScrolls.get(el.dataset.scrollKey);
      if (saved != null) el.scrollTop = saved;
    });
  }
  renderPaginationDom();
}

async function fetchActivityPage({ preserveScroll = false } = {}) {
  if (!invoke) return;
  const seq = ++actFetchSeq;
  try {
    const res = await invoke("query_activities", {
      query: {
        page: actQuery.page,
        pageSize: actQuery.pageSize,
        preset: actQuery.preset,
        date: actQuery.date || null,
        timeFrom: actQuery.timeFrom || null,
        timeTo: actQuery.timeTo || null,
        category: actQuery.category,
        errorsOnly: actQuery.errorsOnly,
        search: actQuery.search || null,
      },
    });
    if (seq !== actFetchSeq) return; // Discard stale response
    actPage = res;
    actQuery.page = res.page;
    latestAllStats = res.allStats || latestAllStats;
    latestActivityRevision = res.revision || latestActivityRevision;
    updateStatsCards(latestAllStats);
    updateScopedCounts(res.scopedStats);
    updateDatePickerBounds(res.availableDates);
    updateLiveChipAndFilterUi();
    $("activity-pending-bar").classList.add("hidden");
    renderActivityListDom({ preserveScroll });
  } catch (e) {
    showAlert(String(e));
  }
}

async function ensureCommandDetail(item, force = false) {
  if (!invoke || !item?.commandId) return;
  const cached = commandDetailCache.get(item.commandId);
  if (!force && cached && cached.state !== "running") return;
  if (commandDetailLoading.has(item.commandId)) return;
  commandDetailLoading.add(item.commandId);
  renderActivityListDom({ preserveScroll: true });
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
    renderActivityListDom({ preserveScroll: true });
  }
}

function updateStatsCards(stats) {
  const s = stats || {};
  $("activity-count-badge").textContent = String(s.total || 0);
  $("st-total").textContent = String(s.total || 0);
  $("st-fs").textContent = String(s.fsCount || 0);
  $("st-cmd").textContent = String(s.cmdCount || 0);
  $("st-chrome").textContent = String(s.chromeCount || 0);
  $("st-sec").textContent = String(s.securityCount || 0);
  const todayCnt = s.todayCount || 0;
  $("st-today").textContent = isZh ? `今日 +${todayCnt}` : `Today +${todayCnt}`;
}

function updateDashboardMini(items) {
  dashboardRecent = items || [];
  const mini = $("mini-activity-feed");
  if (!dashboardRecent.length) {
    mini.innerHTML = `<div class="sec-desc" style="margin:8px 0;">${esc(t("noActivity"))}</div>`;
  } else {
    mini.innerHTML = dashboardRecent.slice(0, 6).map(miniActivityHtml).join("");
  }
}

function handleStatusActivities(recentItems, stats, revision) {
  if (stats) latestAllStats = stats;
  updateStatsCards(latestAllStats);
  updateDashboardMini(recentItems);

  const rev = revision || "";
  const changed = rev !== latestActivityRevision;
  if (changed) {
    latestActivityRevision = rev;
  }

  if (activeTab !== "activity") {
    return;
  }

  if (!actPage.revision) {
    fetchActivityPage({ preserveScroll: false });
    return;
  }

  if (!changed) {
    return;
  }

  const liveView = isLiveCompatibleView();
  if (liveView && !activityPaused && !hasSelectionInActivityList()) {
    fetchActivityPage({ preserveScroll: true });
  } else {
    $("activity-pending-bar").classList.remove("hidden");
    const btnFlush = $("btn-flush-activity");
    if (activityPaused) {
      $("activity-pending-text").textContent = isZh
        ? "已暂停自动刷新，有新动态到达"
        : "Auto-refresh paused · new activity available";
      btnFlush.textContent = t("btnFlush");
    } else if (hasSelectionInActivityList()) {
      $("activity-pending-text").textContent = isZh
        ? "检测到正在划选文本，已暂缓刷新列表"
        : "Selection active · list refresh deferred";
      btnFlush.textContent = t("btnFlush");
    } else {
      $("activity-pending-text").textContent = isZh
        ? "正在浏览历史 / 分页视图，有新操作到达"
        : "Browsing history / page · new operations arrived";
      btnFlush.textContent = t("btnBackLatest");
    }
  }
}

function resetActivityFilters({ fetch = true } = {}) {
  actQuery.page = 1;
  actQuery.preset = "all";
  actQuery.date = "";
  actQuery.timeFrom = "";
  actQuery.timeTo = "";
  actQuery.category = "all";
  actQuery.errorsOnly = false;
  actQuery.search = "";
  $("activity-date").value = "";
  $("activity-time-from").value = "";
  $("activity-time-to").value = "";
  $("activity-search").value = "";
  updateLiveChipAndFilterUi();
  if (fetch) {
    return fetchActivityPage({ preserveScroll: false });
  }
  return Promise.resolve();
}

function flushPendingActivities() {
  activityPaused = false;
  updatePauseBtn();
  $("activity-pending-bar").classList.add("hidden");
  if (!isLiveCompatibleView()) {
    resetActivityFilters({ fetch: true });
  } else {
    fetchActivityPage({ preserveScroll: true });
  }
}

function updatePauseBtn() {
  const btn = $("btn-pause-activity");
  btn.textContent = activityPaused ? t("btnResume") : t("btnPause");
  btn.classList.toggle("active-toggle", activityPaused);
  updateLiveChipAndFilterUi();
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
  const pgSize = $("pg-size");
  if (pgSize) {
    pgSize.options[0].textContent = isZh ? "50 / 页" : "50 / page";
    pgSize.options[1].textContent = isZh ? "100 / 页" : "100 / page";
    pgSize.options[2].textContent = isZh ? "200 / 页" : "200 / page";
  }
  updatePauseBtn();
  updateStatsCards(latestAllStats);
  applySidebarLayout();
  renderRoots();
  renderActivityListDom({ preserveScroll: true });
}

function formatBytes(bytes) {
  const b = Number(bytes) || 0;
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 * 1024 * 1024) return `${(b / (1024 * 1024)).toFixed(2)} MB`;
  return `${(b / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

async function refreshStorageUsage() {
  if (!invoke) return;
  try {
    const u = await invoke("get_storage_usage");
    const total = u.totalBytes || 0;
    $("st-disk-total").textContent = formatBytes(total);
    $("st-disk-audit").textContent = `${formatBytes(u.auditBytes)} (${u.auditFiles || 0})`;
    $("st-disk-cmd").textContent = `${formatBytes(u.workbenchCommandsBytes)} (${u.workbenchCommandsCount || 0})`;
    $("st-disk-meta").textContent = `${formatBytes(u.workbenchMetaBytes)} (${u.workbenchMetaFiles || 0})`;
    $("st-disk-aux").textContent = `${formatBytes(u.auxLogsBytes)} (${u.auxLogsFiles || 0})`;

    const pct = (n) => (total > 0 ? Math.max(n > 0 ? 1.5 : 0, (n / total) * 100) : 0);
    $("bar-audit").style.width = `${pct(u.auditBytes)}%`;
    $("bar-cmd").style.width = `${pct(u.workbenchCommandsBytes)}%`;
    $("bar-meta").style.width = `${pct(u.workbenchMetaBytes)}%`;
    $("bar-aux").style.width = `${pct(u.auxLogsBytes)}%`;
  } catch (e) {
    showAlert(String(e));
  }
}

function restartPollTimer(ms) {
  const next = Math.max(1000, Math.min(10000, Number(ms) || 2000));
  if (pollTimer && pollIntervalMs === next) return;
  pollIntervalMs = next;
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(refreshLive, pollIntervalMs);
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

  // Retention & storage settings
  const ret = cfg.retention || {};
  $("chk-ret-enabled").checked = ret.enabled !== false;
  $("cfg-ret-interval").value = String(ret.intervalHours ?? 6);
  $("cfg-ret-audit-days").value = String(ret.auditRetentionDays ?? 30);
  $("cfg-ret-wb-days").value = String(ret.workbenchRetentionDays ?? 7);
  $("cfg-ret-audit-mb").value = String(ret.auditMaxFileMb ?? 10);
  $("cfg-ret-audit-files").value = String(ret.auditMaxFiles ?? 5);
  $("cfg-ret-wb-mb").value = String(ret.workbenchMaxTotalMb ?? 200);
  $("cfg-ret-aux-mb").value = String(ret.auxLogMaxMb ?? 5);

  // UI preferences
  const ui = cfg.ui || {};
  const defPageSize = Number(ui.defaultPageSize) || 50;
  $("cfg-ui-pagesize").value = String(defPageSize);
  if (actQuery.pageSize !== defPageSize) {
    actQuery.pageSize = defPageSize;
    actQuery.page = 1;
    actPage.revision = "";
  }
  const pollMs = Number(ui.pollIntervalMs) || 2000;
  $("cfg-ui-poll").value = String(pollMs);
  $("cfg-ui-lang").value = isZh ? "zh" : "en";
  restartPollTimer(pollMs);

  // Local ports
  const lp = cfg.localPorts || {};
  $("cfg-port-fs").value = String(lp.fsBearer ?? 18849);
  $("cfg-port-wb").value = String(lp.workbench ?? 18623);
  $("cfg-port-chrome-mcp").value = String(lp.chromeMcp ?? 18619);
  $("cfg-port-chrome-cdp").value = String(lp.chromeCdp ?? 9222);

  // Vision backend
  $("cfg-vision-backend").value = cfg.guardsAndHooks?.visionBackend || "auto";
  $("cfg-gemini-key").value = cfg.guardsAndHooks?.geminiApiKey || "";
  $("cfg-openai-key").value = cfg.guardsAndHooks?.openaiApiKey || "";

  setDirty(false);
  applyLanguage();
}

function collectRetentionFromUi() {
  const rawAuditDays = Number($("cfg-ret-audit-days").value);
  return {
    ...(currentConfig?.retention || {}),
    enabled: $("chk-ret-enabled").checked,
    intervalHours: Number($("cfg-ret-interval").value) || 6,
    auditRetentionDays: Number.isFinite(rawAuditDays) ? rawAuditDays : 30,
    auditMaxFileMb: Number($("cfg-ret-audit-mb").value) || 10,
    auditMaxFiles: Number($("cfg-ret-audit-files").value) || 5,
    workbenchRetentionDays: Number($("cfg-ret-wb-days").value) || 7,
    workbenchMaxTotalMb: Number($("cfg-ret-wb-mb").value) || 200,
    auxLogMaxMb: Number($("cfg-ret-aux-mb").value) || 5,
  };
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
      visionBackend: $("cfg-vision-backend").value || "auto",
      geminiApiKey: $("cfg-gemini-key").value.trim(),
      openaiApiKey: $("cfg-openai-key").value.trim(),
    },
    localPorts: {
      ...(currentConfig.localPorts || {}),
      fsBearer: Number($("cfg-port-fs").value) || 18849,
      workbench: Number($("cfg-port-wb").value) || 18623,
      chromeMcp: Number($("cfg-port-chrome-mcp").value) || 18619,
      chromeCdp: Number($("cfg-port-chrome-cdp").value) || 9222,
    },
    retention: collectRetentionFromUi(),
    ui: {
      ...(currentConfig.ui || {}),
      defaultPageSize: Number($("cfg-ui-pagesize").value) || 50,
      pollIntervalMs: Number($("cfg-ui-poll").value) || 2000,
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
    applyEnvUi(st.env);
  }
  renderLogs(st.logs);
  handleStatusActivities(st.activities, st.stats, st.activityRevision);

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

// Activity interactive stat cards (click to filter category)
document.querySelectorAll("#activity-stat-strip .stat-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const cat = btn.dataset.statCat || "all";
    actQuery.category = actQuery.category === cat && cat !== "all" ? "all" : cat;
    actQuery.page = 1;
    updateLiveChipAndFilterUi();
    fetchActivityPage({ preserveScroll: false });
  });
});

// Activity time presets
document.querySelectorAll("#activity-presets .seg-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    actQuery.preset = btn.dataset.preset || "all";
    actQuery.date = "";
    $("activity-date").value = "";
    actQuery.page = 1;
    updateLiveChipAndFilterUi();
    fetchActivityPage({ preserveScroll: false });
  });
});

// Specific date & time-of-day filters
$("activity-date").addEventListener("change", (e) => {
  const val = (e.target.value || "").trim();
  if (val) {
    actQuery.preset = "custom";
    actQuery.date = val;
  } else {
    actQuery.preset = "all";
    actQuery.date = "";
  }
  actQuery.page = 1;
  updateLiveChipAndFilterUi();
  fetchActivityPage({ preserveScroll: false });
});

$("activity-time-from").addEventListener("change", (e) => {
  actQuery.timeFrom = (e.target.value || "").trim();
  actQuery.page = 1;
  updateLiveChipAndFilterUi();
  fetchActivityPage({ preserveScroll: false });
});

$("activity-time-to").addEventListener("change", (e) => {
  actQuery.timeTo = (e.target.value || "").trim();
  actQuery.page = 1;
  updateLiveChipAndFilterUi();
  fetchActivityPage({ preserveScroll: false });
});

// Activity category pills, errors-only, reset, debounced search, pause, flush
document.querySelectorAll("#activity-filters .fpill").forEach((btn) => {
  btn.addEventListener("click", () => {
    actQuery.category = btn.dataset.filter || "all";
    actQuery.page = 1;
    updateLiveChipAndFilterUi();
    fetchActivityPage({ preserveScroll: false });
  });
});

$("btn-errors-only").addEventListener("click", () => {
  actQuery.errorsOnly = !actQuery.errorsOnly;
  actQuery.page = 1;
  updateLiveChipAndFilterUi();
  fetchActivityPage({ preserveScroll: false });
});

$("btn-reset-filters").addEventListener("click", () => {
  resetActivityFilters({ fetch: true });
});

$("activity-search").addEventListener("input", (e) => {
  actQuery.search = e.target.value || "";
  actQuery.page = 1;
  updateLiveChipAndFilterUi();
  clearTimeout(actSearchTimer);
  actSearchTimer = setTimeout(() => {
    fetchActivityPage({ preserveScroll: false });
  }, 180);
});

$("btn-clear-search").addEventListener("click", () => {
  actQuery.search = "";
  $("activity-search").value = "";
  actQuery.page = 1;
  updateLiveChipAndFilterUi();
  fetchActivityPage({ preserveScroll: false });
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

// Pagination controls
$("pg-buttons").addEventListener("click", (e) => {
  const btn = e.target.closest("[data-pg]");
  if (!btn || btn.disabled) return;
  const targetPage = Number(btn.dataset.pg);
  if (!Number.isFinite(targetPage) || targetPage < 1 || targetPage === actQuery.page) return;
  actQuery.page = targetPage;
  fetchActivityPage({ preserveScroll: false });
});

$("pg-size").addEventListener("change", (e) => {
  const nextSize = Number(e.target.value) || 50;
  actQuery.pageSize = nextSize;
  actQuery.page = 1;
  fetchActivityPage({ preserveScroll: false });
});

function commitPageJump() {
  const totalPages = Math.max(1, actPage.totalPages || 1);
  const raw = Number($("pg-jump").value);
  const clamped = Number.isFinite(raw) ? clamp(Math.floor(raw), 1, totalPages) : actQuery.page;
  $("pg-jump").value = String(clamped);
  if (clamped !== actQuery.page) {
    actQuery.page = clamped;
    fetchActivityPage({ preserveScroll: false });
  }
}

$("pg-jump").addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    commitPageJump();
  }
});
$("pg-jump").addEventListener("change", commitPageJump);

// Event delegation on full activity list
$("activity-list").addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-act]");
  if (!btn) return;
  const act = btn.dataset.act;
  const items = actPage.items || [];

  if (act === "copy-full") {
    e.stopPropagation();
    const item = items.find((x) => x.id === btn.dataset.id);
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
    const item = items.find((x) => x.id === btn.dataset.id);
    if (!item || !item.commandId) return;
    ensureCommandDetail(item, true);
    return;
  }

  if (act === "reveal") {
    e.stopPropagation();
    if (!invoke) return;
    const item = items.find((x) => x.id === btn.dataset.id);
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
    const item = items.find((x) => x.id === id);
    if (!item) return;
    if (expandedIds.has(id)) {
      expandedIds.delete(id);
      renderActivityListDom({ preserveScroll: true });
    } else {
      expandedIds.add(id);
      renderActivityListDom({ preserveScroll: true });
      if (item.commandId) {
        ensureCommandDetail(item);
      }
    }
  }
});

// Dashboard mini activity click -> jump to latest page 1 & expand
$("mini-activity-feed").addEventListener("click", async (e) => {
  const row = e.target.closest("[data-mini-id]");
  if (!row) return;
  const id = row.dataset.miniId;
  const item = dashboardRecent.find((x) => x.id === id);
  if (!item) return;
  expandedIds.add(id);
  resetActivityFilters({ fetch: false });
  actPage.revision = latestActivityRevision || "sync";
  switchTab("activity");
  await fetchActivityPage({ preserveScroll: false });
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

document.querySelectorAll("#tab-wizard input, #tab-wizard select, #tab-roots input[type=checkbox], #tab-settings input, #tab-settings select").forEach((el) => {
  el.addEventListener("change", () => setDirty(true));
});

$("cfg-ui-lang").addEventListener("change", (e) => {
  isZh = e.target.value === "zh";
  applyLanguage();
  setDirty(true);
});

$("btn-refresh-storage").addEventListener("click", () => {
  refreshStorageUsage();
  toast(isZh ? "已刷新存储占用" : "Storage usage refreshed");
});

$("btn-run-cleanup").addEventListener("click", async () => {
  if (!invoke) return;
  const btn = $("btn-run-cleanup");
  btn.disabled = true;
  try {
    const rep = await invoke("run_manual_cleanup", { retention: collectRetentionFromUi() });
    await refreshStorageUsage();
    if (activeTab === "activity") {
      await fetchActivityPage({ preserveScroll: false });
    }
    const freed = formatBytes(rep.freedBytes);
    const totalRemoved =
      (rep.auditFilesRemoved || 0) +
      (rep.auditLinesTrimmed || 0) +
      (rep.workbenchCommandsRemoved || 0) +
      (rep.workbenchMetaRemoved || 0) +
      (rep.auxFilesTrimmed || 0) +
      (rep.oldBinariesRemoved || 0);
    if (totalRemoved === 0 && !rep.freedBytes) {
      toast(
        rep.skippedActiveAudit
          ? isZh
            ? "无过期归档（外部后台正在写入活跃审计日志，已安全跳过）"
            : "Nothing expired (active audit skipped while external agent is running)"
          : isZh
            ? "当前没有需要清理的过期数据"
            : "No expired data to clean"
      );
    } else {
      toast(
        isZh
          ? `清理完成，释放 ${freed}（命令 ${rep.workbenchCommandsRemoved}，归档 ${rep.auditFilesRemoved}，裁剪 ${rep.auditLinesTrimmed} 行）`
          : `Cleaned ${freed} (cmds: ${rep.workbenchCommandsRemoved}, archives: ${rep.auditFilesRemoved}, lines: ${rep.auditLinesTrimmed})`
      );
    }
  } catch (e) {
    showAlert(String(e));
  } finally {
    btn.disabled = false;
  }
});

$("btn-reset-sidebar").addEventListener("click", () => {
  sbState = { ...SB_DEFAULT };
  applySidebarLayout();
  saveSidebarState();
  toast(isZh ? "已恢复默认侧边栏布局" : "Sidebar layout reset");
});

$("btn-open-config-dir").addEventListener("click", async () => {
  if (!invoke) return;
  try {
    await invoke("open_app_dir", { kind: "config" });
  } catch (e) {
    showAlert(String(e));
  }
});

$("btn-open-logs-dir").addEventListener("click", async () => {
  if (!invoke) return;
  try {
    await invoke("open_app_dir", { kind: "logs" });
  } catch (e) {
    showAlert(String(e));
  }
});

$("btn-regen-approval").addEventListener("click", async () => {
  if (!invoke || !currentConfig) return;
  const ok = window.confirm(
    isZh
      ? "确定要重新生成 Owner Approval Key 吗？\n保存并重启服务后，新客户端授权需使用新密钥。"
      : "Regenerate Owner Approval Key?\nAfter saving and restarting, new OAuth approvals will require the new key."
  );
  if (!ok) return;
  try {
    const nextKey = await invoke("regenerate_approval_key");
    currentConfig.gateway.approvalKey = nextKey;
    $("inp-approval-key").value = nextKey;
    setDirty(true);
    toast(isZh ? "已生成新密钥，请点击保存设置生效" : "New key generated; click Save to apply");
  } catch (e) {
    showAlert(String(e));
  }
});

$("btn-save-settings").addEventListener("click", persist);

// Dependency helper actions
document.querySelectorAll(".env-chip[data-dep]").forEach((btn) => {
  btn.addEventListener("click", () => openDepModal(btn.dataset.dep));
});
$("btn-dl-cf").addEventListener("click", runDownloadCloudflared);
$("btn-dep-dl-cf").addEventListener("click", runDownloadCloudflared);
$("btn-recheck-env").addEventListener("click", runRecheckEnv);
$("btn-dep-recheck").addEventListener("click", runRecheckEnv);
$("btn-copy-cf-cmd").addEventListener("click", async () => {
  await navigator.clipboard.writeText("winget install --id Cloudflare.cloudflared -e");
  toast(t("toastCopied"));
});
$("btn-dep-copy-cmd").addEventListener("click", async () => {
  const txt = $("dep-modal-cmd").textContent || "";
  if (!txt) return;
  await navigator.clipboard.writeText(txt);
  toast(t("toastCopied"));
});
$("btn-dep-modal-close").addEventListener("click", () => {
  $("dep-modal").classList.add("hidden");
  activeDepModalKey = "";
});
$("dep-modal").addEventListener("click", (e) => {
  if (e.target === $("dep-modal")) {
    $("dep-modal").classList.add("hidden");
    activeDepModalKey = "";
  }
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
  $("cfg-ui-lang").value = isZh ? "zh" : "en";
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
    restartPollTimer(pollIntervalMs);
  } catch (e) {
    showAlert(String(e));
  }
}

init();
