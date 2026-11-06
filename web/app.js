/* NetKit 管理后台前端 */
"use strict";

const $ = (s, el) => (el || document).querySelector(s);
const $$ = (s, el) => Array.from((el || document).querySelectorAll(s));

async function api(path, opts = {}) {
  // 30s 超时兜底：后端挂起时 fetch 会永远不返回，按钮表现为"点了没反应"
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 30000);
  let r;
  try {
    r = await fetch(path, {
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      signal: ctrl.signal,
      ...opts,
    });
  } catch (e) {
    if (e && e.name === "AbortError") throw new Error("请求超时（30 秒无响应）");
    throw e;
  } finally {
    clearTimeout(timer);
  }
  const data = await r.json().catch(() => ({}));

  // 登录接口的 401 属于"凭据错误"，应把后端原因透传给用户，
  // 不能当成会话过期处理（否则登录页会显示"未登录"而掩盖真实错误）
  const isLogin = path.startsWith("/api/login");
  if (r.status === 401 && !isLogin) {
    showLogin();
    throw new Error("未登录或会话已过期");
  }
  if (!r.ok) throw new Error(data.error || "请求失败");
  return data;
}

const uid = () => (crypto.randomUUID ? crypto.randomUUID() : "id-" + Date.now() + "-" + Math.random().toString(36).slice(2));
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const lines = t => String(t || "").split(/[\n,，]+/).map(x => x.trim()).filter(Boolean);
const nums = t => lines(t).map(Number).filter(n => Number.isInteger(n) && n > 0 && n < 65536);
// 解析 "Key: Value" 每行一条的文本为对象（按行分割，值内可含逗号）
const kvs = t => Object.fromEntries(
  String(t || "").split(/\r?\n/).map(x => x.trim()).filter(Boolean)
    .map(l => { const i = l.indexOf(":"); return i > 0 ? [l.slice(0, i).trim(), l.slice(i + 1).trim()] : null; })
    .filter(Boolean)
);
const kvText = o => Object.entries(o || {}).map(([k, v]) => `${k}: ${v}`).join("\n");

// parsePorts 支持 lucky 写法：22 / 80,443 / 20000-20010 / 混合
function parsePorts(text) {
  const out = [];
  for (const part of String(text || "").split(/[\s,，;]+/).map(x => x.trim()).filter(Boolean)) {
    const m = part.match(/^(\d+)\s*-\s*(\d+)$/);
    if (m) {
      const lo = +m[1], hi = +m[2];
      if (lo < 1 || hi > 65535 || lo > hi) throw new Error(`端口范围无效: ${part}`);
      if (hi - lo > 2000) throw new Error(`单个范围最多 2000 个端口: ${part}`);
      for (let p = lo; p <= hi; p++) out.push(p);
    } else {
      const v = Number(part);
      if (!Number.isInteger(v) || v < 1 || v > 65535) throw new Error(`端口无效: ${part}`);
      out.push(v);
    }
  }
  return out;
}

// formatPorts 把连续端口压缩成 a-b
function formatPorts(ports) {
  const arr = [...new Set(ports)].sort((a, b) => a - b);
  const parts = [];
  let i = 0;
  while (i < arr.length) {
    let j = i;
    while (j + 1 < arr.length && arr[j + 1] === arr[j] + 1) j++;
    if (j - i >= 2) parts.push(`${arr[i]}-${arr[j]}`);
    else for (let k = i; k <= j; k++) parts.push(String(arr[k]));
    i = j + 1;
  }
  return parts.join(",");
}

/* ---------- 登录 ---------- */
function showLogin() {
  $("#login-page").classList.remove("hidden");
  $("#app").classList.add("hidden");
}
let pendingLogin = { user: "", pass: "" };
// 会话角色：admin=主账号（全功能），backup=后备账号（仅配置备份与还原）
let sessionRole = "admin";

// playAIFx 播放"AI 接管登录"动效：机械手伸手按压 + 按钮涟漪 + 数据流粒子，
// 保证动效完整展示（至少 720ms）后再继续流程；失败时同样等动效结束再抛错。
async function playAIFx(run) {
  const lp = $("#login-page");
  if (!lp) return run();
  if (lp.classList.contains("lx-logging")) throw new Error("正在登录中…");
  const t0 = performance.now();
  lp.classList.add("lx-logging");
  let result, err;
  try { result = await run(); } catch (e) { err = e; }
  const wait = Math.max(0, 720 - (performance.now() - t0));
  if (wait) await new Promise(r => setTimeout(r, wait));
  lp.classList.remove("lx-logging");
  if (err) throw err;
  return result;
}

async function tryLogin(u, p) {
  const r = await api("/api/login", { method: "POST", body: JSON.stringify({ username: u, password: p }) });
  if (r && r.need2FA) {
    // 密码正确但需要两步验证：切换到第二步
    pendingLogin = { user: u, pass: p };
    $("#login-step1").classList.add("is-hidden");
    $("#login-step2").classList.remove("is-hidden");
    $("#login-code").value = "";
    $("#login-code").focus();
    return;
  }
  sessionRole = (r && r.role) || "admin";
  enterApp();
}

function enterApp() {
  // 复位登录页：下次退出登录回到第一步
  $("#login-step2").classList.add("is-hidden");
  $("#login-step1").classList.remove("is-hidden");
  $("#login-recovery-box").classList.add("is-hidden");
  const lp = $("#login-page");
  lp.classList.remove("lx-logging");
  lp.classList.add("hidden");
  $("#app").classList.remove("hidden");
  boot();
}

async function submit2FA(code, recovery) {
  if ($("#login-page").classList.contains("lx-logging")) return;
  $("#login-err").textContent = "";
  try {
    const body = { username: pendingLogin.user, password: pendingLogin.pass };
    if (recovery) body.recovery = recovery; else body.code = code;
    const r = await playAIFx(() => api("/api/login", { method: "POST", body: JSON.stringify(body) }));
    sessionRole = (r && r.role) || "admin";
    enterApp();
  } catch (e) {
    $("#login-err").textContent = e.message;
    $("#login-code").value = "";
    $("#login-code").focus();
  }
}
$("#login-btn").onclick = async () => {
  if ($("#login-page").classList.contains("lx-logging")) return;
  $("#login-err").textContent = "";
  try {
    await playAIFx(() => tryLogin($("#login-user").value.trim(), $("#login-pass").value));
  } catch (e) { $("#login-err").textContent = e.message; }
};
const doLogout = async () => {
  try { await api("/api/logout", { method: "POST" }); } catch (e) {}
  location.reload();
};
["#logout-btn", "#logout-btn2"].forEach(sel => { const b = $(sel); if (b) b.onclick = doLogout; });

// 用户胶囊：跳转到设置页（设置项在 #nav4，不能用 #nav 选择器）
const pill = $("#user-pill");
if (pill) {
  pill.onclick = () => gotoPage("settings");
  pill.onkeydown = e => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); gotoPage("settings"); }
  };
}
$("#login-pass").addEventListener("keydown", e => { if (e.key === "Enter") $("#login-btn").click(); });

// 第二步：验证码 / 恢复码 / 返回
$("#login-verify-btn").onclick = () => {
  const code = ($("#login-code").value || "").replace(/\s/g, "");
  if (code.length !== 6) { $("#login-err").textContent = "请输入 6 位验证码"; return; }
  submit2FA(code, "");
};
$("#login-code").addEventListener("keydown", e => { if (e.key === "Enter") $("#login-verify-btn").click(); });
$("#login-code").addEventListener("input", e => {
  // 自动补空格便于阅读：123456 -> 123 456
  const v = e.target.value.replace(/\s/g, "").slice(0, 6);
  e.target.value = v.length > 3 ? v.slice(0, 3) + " " + v.slice(3) : v;
});
$("#login-toggle-recovery").onclick = () => {
  $("#login-recovery-box").classList.toggle("is-hidden");
  $("#login-recovery").focus();
};
$("#login-recovery-btn").onclick = () => {
  const rc = ($("#login-recovery").value || "").trim();
  if (!rc) { $("#login-err").textContent = "请输入恢复码"; return; }
  submit2FA("", rc);
};
$("#login-back").onclick = () => {
  $("#login-step2").classList.add("is-hidden");
  $("#login-step1").classList.remove("is-hidden");
  $("#login-err").textContent = "";
  pendingLogin = { user: "", pass: "" };
};

/* ---------- 导航 ---------- */
const PAGE_LOADERS = {
  dashboard: () => loadDashboard(), bigscreen: () => loadBigScreen(), portforward: () => loadPF(), webproxy: () => loadWeb(),
  ddns: () => loadDDNS(), ssl: () => loadSSL(), cron: () => loadCron(),
  ipdb: () => loadIPDB(), secgroup: () => loadSG(), ipfilter: () => loadIPFilter(),
  honeypot: () => loadHoneypot(), ipvisitors: () => loadIPVisitors(),
  ai: () => loadAI(),
  waf: () => loadWAF(), logcenter: () => loadLogs(),
};

function gotoPage(name) {
  // 每页专属主题：data-page 驱动 CSS 变量换色（导航高亮/按钮/背景光晕跟随）
  document.body.dataset.page = name;
  // 科幻动效启停：盾牌只在 WAF 页运行，心跳波形只在总览运行
  if (name === "waf") startShieldFX(); else stopShieldFX();
  if (name !== "dashboard") stopHQWave();
  if (name === "portforward") startPFFX(); else stopPFFX();
  if (name === "ipfilter") startFilterFX(); else stopFilterFX();
  if (name === "webproxy") startProxyFX(); else stopProxyFX();
  if (name === "honeypot") startHpFX(); else stopHpFX();
  if (name === "ipvisitors") startIpvFX(); else stopIpvFX();
  // 离开数据大屏时停止其自动刷新与秒表
  if (name !== "bigscreen" && typeof stopBigScreen === "function") stopBigScreen();
  $$("#nav a, #nav2 a, #nav3 a, #nav4 a").forEach(x => {
    const on = x.dataset.page === name;
    x.classList.toggle("active", on);
    if (on) x.setAttribute("aria-current", "page"); else x.removeAttribute("aria-current");
  });
  $$(".page").forEach(p => p.classList.add("hidden"));
  const el = $("#page-" + name);
  if (el) el.classList.remove("hidden");
  // 键盘/读屏：切页后把焦点移到当前页标题
  const h2 = el && el.querySelector(".page-head h2");
  if (h2) { h2.setAttribute("tabindex", "-1"); h2.focus({ preventScroll: true }); }
  const fn = PAGE_LOADERS[name];
  if (fn) fn().catch(() => {});
}

$$("#nav a, #nav2 a, #nav3 a, #nav4 a").forEach(a => {
  // 补 href 让导航可被键盘/读屏识别为链接，点击时阻止默认跳转
  a.href = "#" + a.dataset.page;
  a.onclick = e => { e.preventDefault(); gotoPage(a.dataset.page); };
});

// applyTheme 应用主题：light / dark，并更新按钮图标
function applyTheme(mode) {
  const dark = mode === "dark";
  document.body.classList.toggle("dark", dark);
  const icon = dark ? "☾" : "☀";
  const tip = dark ? "切换到浅色主题" : "切换到深色主题";
  ["theme-btn", "login-theme-btn"].forEach(id => {
    const b = document.getElementById(id);
    if (!b) return;
    b.textContent = icon;
    b.title = tip;
  });
  try { localStorage.setItem("netkit_theme", dark ? "dark" : "light"); } catch (e) {}
}

// toggleTheme 在明暗之间切换并记住选择
function toggleTheme() {
  const dark = !document.body.classList.contains("dark");
  applyTheme(dark ? "dark" : "light");
}

// 启动时恢复上次主题（默认跟随系统偏好）
function initTheme() {
  let saved = null;
  try { saved = localStorage.getItem("netkit_theme"); } catch (e) {}
  if (saved) {
    applyTheme(saved);
  } else {
    const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    applyTheme(prefersDark ? "dark" : "light");
  }
}

/* ---------- 科幻 HUD 动效 ---------- */

// countUp 数字滚动动画
function countUp(el, to, dur = 800) {
  if (!el) return;
  const t0 = performance.now();
  const step = t => {
    const p = Math.min(1, (t - t0) / dur);
    const e = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(to * e);
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

const reducedMotion = () => window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// 工作台心跳波形（氛围动效：数据游走 + 偶发尖峰）
let hqWaveRAF = 0;
function stopHQWave() {
  if (hqWaveRAF) { cancelAnimationFrame(hqWaveRAF); hqWaveRAF = 0; }
}
function startHQWave() {
  stopHQWave();
  const cv = document.getElementById("hq-wave");
  if (!cv || reducedMotion()) return;
  const ctx = cv.getContext("2d");
  const N = 150;
  const vals = Array.from({ length: N }, () => 0.35 + Math.random() * 0.25);
  const dpr = Math.min(2, window.devicePixelRatio || 1);
  let frame = 0, accent = "#4a9eff";
  const draw = () => {
    const w = Math.max(1, cv.clientWidth), h = Math.max(1, cv.clientHeight);
    if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) {
      cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    if (frame % 20 === 0) accent = getComputedStyle(document.body).getPropertyValue("--accent").trim() || accent;
    frame++;
    // 随机游走向均值回归 + 偶发尖峰
    let v = vals[N - 1] + (Math.random() - 0.5) * 0.16;
    if (Math.random() < 0.03) v += 0.35;
    v += (0.48 - v) * 0.06;
    vals.push(Math.max(0.08, Math.min(0.95, v)));
    vals.shift();

    ctx.clearRect(0, 0, w, h);
    // 基线网格
    ctx.strokeStyle = "rgba(128,128,128,.16)";
    ctx.lineWidth = 1;
    for (let y = h / 4; y < h; y += h / 4) {
      ctx.beginPath(); ctx.moveTo(0, Math.round(y)); ctx.lineTo(w, Math.round(y)); ctx.stroke();
    }
    // 波形（发光描边）
    ctx.beginPath();
    for (let i = 0; i < N; i++) {
      const x = (i / (N - 1)) * w;
      const y = h - 8 - vals[i] * (h - 20);
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    }
    ctx.strokeStyle = accent;
    ctx.lineWidth = 1.6;
    ctx.shadowColor = accent;
    ctx.shadowBlur = 8;
    ctx.stroke();
    ctx.shadowBlur = 0;
    // 扫描头
    const hy = h - 8 - vals[N - 1] * (h - 20);
    ctx.beginPath();
    ctx.arc(w - 2, hy, 2.8, 0, Math.PI * 2);
    ctx.fillStyle = accent;
    ctx.fill();
    hqWaveRAF = requestAnimationFrame(draw);
  };
  draw();
}

// WAF 巨盾防御动效：攻击粒子飞向盾牌，撞上力场被拦截（冲击波 + 盾牌抖动）
let shieldRAF = 0, shieldTimer = 0;
function stopShieldFX() {
  if (shieldRAF) { cancelAnimationFrame(shieldRAF); shieldRAF = 0; }
  if (shieldTimer) { clearInterval(shieldTimer); shieldTimer = 0; }
}
async function startShieldFX() {
  stopShieldFX();
  const cv = document.getElementById("shield-fx");
  const stage = document.getElementById("shield-stage");
  if (!cv || !stage) return;

  // 拉取真实 WAF 状态：模式配色 + 拦截计数
  const refresh = async () => {
    try {
      const st = await api("/api/status");
      const mode = st.wafEnabled ? (st.wafMode === "detect" ? "detect" : "block") : "off";
      stage.dataset.mode = mode;
      const title = $("#shield-title"), label = $("#shield-mode");
      if (title) title.textContent = mode === "off" ? "SHIELD OFFLINE" : mode === "detect" ? "SHIELD DETECT" : "SHIELD ACTIVE";
      if (label) label.textContent = mode === "off" ? "WAF 引擎未启用" : mode === "detect" ? "仅记录模式 · 持续检测中" : "拦截模式 · 防护中";
      const cur = Number(($("#shield-count") || {}).textContent) || 0;
      countUp($("#shield-count"), Math.max(cur, st.wafHits || 0), 700);
    } catch (e) {}
  };
  refresh();
  shieldTimer = setInterval(refresh, 6000);

  if (reducedMotion()) return;
  const ctx = cv.getContext("2d");
  const dpr = Math.min(2, window.devicePixelRatio || 1);
  const parts = [];  // 攻击粒子
  const rings = [];  // 拦截冲击波
  let tick = 0;

  const frame = () => {
    const w = cv.clientWidth, h = cv.clientHeight;
    if (!w || !h) { shieldRAF = requestAnimationFrame(frame); return; }
    if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) {
      cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    const cx = w / 2, cy = h / 2;
    const R = 96; // 力场拦截半径
    tick++;

    // 每 0.5s 发射一个攻击粒子
    if (tick % 30 === 0) {
      const ang = Math.random() * Math.PI * 2;
      const dist = Math.max(w, h) * 0.6;
      parts.push({ x: cx + Math.cos(ang) * dist, y: cy + Math.sin(ang) * dist * 0.5, sp: 2.4 + Math.random() * 2.8 });
    }

    for (let i = parts.length - 1; i >= 0; i--) {
      const p = parts[i];
      const dx = cx - p.x, dy = cy - p.y;
      const d = Math.hypot(dx, dy) || 1;
      p.x += (dx / d) * p.sp;
      p.y += (dy / d) * p.sp;
      if (d <= R) {
        // 拦截：冲击波 + 盾牌受击抖动
        rings.push({ r: R, a: 0.9 });
        parts.splice(i, 1);
        const svg = document.querySelector(".shield-svg");
        if (svg) { svg.classList.remove("hit"); void svg.getBoundingClientRect(); svg.classList.add("hit"); }
        continue;
      }
      ctx.strokeStyle = "rgba(248,113,113,.5)";
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(p.x, p.y);
      ctx.lineTo(p.x - (dx / d) * 12, p.y - (dy / d) * 12);
      ctx.stroke();
      ctx.fillStyle = "#fca5a5";
      ctx.beginPath();
      ctx.arc(p.x, p.y, 2.2, 0, Math.PI * 2);
      ctx.fill();
    }

    for (let i = rings.length - 1; i >= 0; i--) {
      const r = rings[i];
      r.r += 2.6;
      r.a -= 0.05;
      if (r.a <= 0) { rings.splice(i, 1); continue; }
      ctx.strokeStyle = `rgba(251,113,133,${r.a})`;
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(cx, cy, r.r, 0, Math.PI * 2);
      ctx.stroke();
    }

    // 力场呼吸圈
    const pulse = 0.5 + 0.5 * Math.sin(Date.now() / 700);
    ctx.strokeStyle = `rgba(248,113,113,${0.12 + 0.16 * pulse})`;
    ctx.lineWidth = 1;
    ctx.setLineDash([4, 7]);
    ctx.beginPath();
    ctx.arc(cx, cy, R, 0, Math.PI * 2);
    ctx.stroke();
    ctx.setLineDash([]);

    shieldRAF = requestAnimationFrame(frame);
  };
  frame();
}

/* ---------- 各模块动态横幅（Qwen 方案：管道/过滤/瀑布） ---------- */

// 日志瀑布：生成彩色字符列（CSS 动画滚动，页面隐藏自动暂停）
function initMatrixRain() {
  const box = document.getElementById("matrix-rain");
  if (!box || box.childElementCount) return;
  const chars = "01ABCDEF{}[]<>/|;:=+*#";
  const pick = n => Array.from({ length: n }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
  const cls = ["", "", "warn", "", "err", ""];
  box.innerHTML = cls.map((c, i) => {
    const block = Array.from({ length: 12 }, () => pick(3)).join("\n");
    return `<span class="rcol ${c}" style="--sp:${7 + (i % 4) * 1.7}s;--rd:-${i * 1.4}s">${block}\n${block}</span>`;
  }).join("");
}

// 端口转发：流光管道（三条管道，蓝=TCP 紫=UDP 青=备用，光点带拖尾穿梭）
let pfRAF = 0;
function stopPFFX() {
  if (pfRAF) { cancelAnimationFrame(pfRAF); pfRAF = 0; }
}
function startPFFX() {
  stopPFFX();
  const cv = document.getElementById("pf-fx");
  if (!cv || reducedMotion()) return;
  const ctx = cv.getContext("2d");
  const dpr = Math.min(2, window.devicePixelRatio || 1);
  const pipes = [
    { color: "74,158,255", dots: [] },
    { color: "167,139,250", dots: [] },
    { color: "45,212,191", dots: [] },
  ];
  pipes.forEach(p => {
    const n = 5 + Math.floor(Math.random() * 4);
    for (let i = 0; i < n; i++) p.dots.push({ x: Math.random(), v: 0.0016 + Math.random() * 0.0034 });
  });
  const frame = () => {
    const w = cv.clientWidth, h = cv.clientHeight;
    if (!w || !h) { pfRAF = requestAnimationFrame(frame); return; }
    if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) {
      cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    const ys = [h * 0.3, h * 0.5, h * 0.68];
    pipes.forEach((p, pi) => {
      const y = ys[pi];
      // 管道槽 + 亮芯
      ctx.strokeStyle = `rgba(${p.color},.20)`;
      ctx.lineWidth = 7;
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
      ctx.strokeStyle = `rgba(${p.color},.55)`;
      ctx.lineWidth = 1;
      ctx.stroke();
      // 端口方块
      ctx.fillStyle = `rgba(${p.color},.85)`;
      ctx.fillRect(0, y - 7, 5, 14);
      ctx.fillRect(w - 5, y - 7, 5, 14);
      // 光点 + 拖尾
      p.dots.forEach(d => {
        d.x += d.v;
        if (d.x > 1.06) d.x = -0.06;
        const x = d.x * w;
        const g = ctx.createLinearGradient(x - 28, y, x, y);
        g.addColorStop(0, `rgba(${p.color},0)`);
        g.addColorStop(1, `rgba(${p.color},.85)`);
        ctx.strokeStyle = g;
        ctx.lineWidth = 3;
        ctx.beginPath();
        ctx.moveTo(Math.max(0, x - 28), y);
        ctx.lineTo(x, y);
        ctx.stroke();
        ctx.fillStyle = `rgb(${p.color})`;
        ctx.shadowColor = `rgba(${p.color},.9)`;
        ctx.shadowBlur = 8;
        ctx.beginPath();
        ctx.arc(x, y, 3, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;
      });
    });
    pfRAF = requestAnimationFrame(frame);
  };
  frame();
}

// IP 过滤：光栅过滤（白名单光点穿透闪光，黑名单撞栅粉碎成红色火花）
let flRAF = 0;
function stopFilterFX() {
  if (flRAF) { cancelAnimationFrame(flRAF); flRAF = 0; }
}
function startFilterFX() {
  stopFilterFX();
  const cv = document.getElementById("filter-fx");
  if (!cv || reducedMotion()) return;
  const ctx = cv.getContext("2d");
  const dpr = Math.min(2, window.devicePixelRatio || 1);
  const parts = [];
  const sparks = [];
  let tick = 0;
  const frame = () => {
    const w = cv.clientWidth, h = cv.clientHeight;
    if (!w || !h) { flRAF = requestAnimationFrame(frame); return; }
    if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) {
      cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    const mid = h / 2;
    tick++;
    if (tick % 8 === 0) {
      parts.push({ x: 12 + Math.random() * (w - 24), y: -6, v: 1 + Math.random() * 1.3, block: Math.random() < 0.3 });
    }
    // 发光光栅
    ctx.strokeStyle = "rgba(74,158,255,.5)";
    ctx.lineWidth = 2;
    ctx.setLineDash([9, 7]);
    ctx.beginPath(); ctx.moveTo(0, mid); ctx.lineTo(w, mid); ctx.stroke();
    ctx.setLineDash([]);

    for (let i = parts.length - 1; i >= 0; i--) {
      const p = parts[i];
      p.y += p.v;
      if (p.block && p.y >= mid - 3) {
        // 黑名单：撞栅粉碎
        for (let k = 0; k < 7; k++) {
          sparks.push({ x: p.x, y: mid, vx: (Math.random() - 0.5) * 4.4, vy: (Math.random() - 0.75) * 3.2, a: 1 });
        }
        parts.splice(i, 1);
        continue;
      }
      if (p.y > h + 6) { parts.splice(i, 1); continue; }
      ctx.fillStyle = p.block ? "#f87171" : "#a7f3d0";
      ctx.shadowColor = p.block ? "#f87171" : "#34d399";
      ctx.shadowBlur = 6;
      ctx.beginPath();
      ctx.arc(p.x, p.y, 2.4, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0;
      // 白名单穿透光栅时的扩散闪光
      if (!p.block && p.y > mid && p.y < mid + 16) {
        const t = (p.y - mid) / 16;
        ctx.strokeStyle = `rgba(52,211,153,${(1 - t).toFixed(2)})`;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(p.x, mid, 3 + 9 * (1 - t), 0, Math.PI * 2);
        ctx.stroke();
      }
    }

    for (let i = sparks.length - 1; i >= 0; i--) {
      const s = sparks[i];
      s.x += s.vx;
      s.y += s.vy;
      s.vy += 0.14;
      s.a -= 0.035;
      if (s.a <= 0) { sparks.splice(i, 1); continue; }
      ctx.fillStyle = `rgba(248,113,113,${s.a.toFixed(2)})`;
      ctx.fillRect(s.x, s.y, 3, 3);
    }
    flRAF = requestAnimationFrame(frame);
  };
  frame();
}

// Web 服务：请求路由（入口节点按轮询把请求光点沿曲线分发到后端节点，命中闪亮）
let pxyRAF = 0;
function stopProxyFX() {
  if (pxyRAF) { cancelAnimationFrame(pxyRAF); pxyRAF = 0; }
}
function startProxyFX() {
  stopProxyFX();
  const cv = document.getElementById("proxy-fx");
  if (!cv || reducedMotion()) return;
  const ctx = cv.getContext("2d");
  const dpr = Math.min(2, window.devicePixelRatio || 1);
  const N = 3;
  const flashes = [0, 0, 0];
  const reqs = [];
  let next = 0, tick = 0;
  const PUR = "167,139,250";
  const frame = () => {
    const w = cv.clientWidth, h = cv.clientHeight;
    if (!w || !h) { pxyRAF = requestAnimationFrame(frame); return; }
    if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) {
      cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    const inX = 48, inY = h / 2;
    const bx = w - 84;
    const bys = [h * 0.2, h * 0.5, h * 0.8];

    // 入口 → 后端的路由曲线
    bys.forEach(by => {
      ctx.strokeStyle = `rgba(${PUR},.30)`;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(inX + 16, inY);
      ctx.quadraticCurveTo(w / 2, inY, bx - 18, by);
      ctx.stroke();
    });

    // 每 0.36s 发出一个请求（轮询下一后端）
    tick++;
    if (tick % 22 === 0) { reqs.push({ t: 0, dst: next }); next = (next + 1) % N; }

    // 请求光点沿二次贝塞尔曲线移动
    for (let i = reqs.length - 1; i >= 0; i--) {
      const r = reqs[i];
      r.t += 0.013;
      if (r.t >= 1) { flashes[r.dst] = 1; reqs.splice(i, 1); continue; }
      const by = bys[r.dst];
      const mt = 1 - r.t;
      const x = mt * mt * (inX + 16) + 2 * mt * r.t * (w / 2) + r.t * r.t * (bx - 18);
      const y = mt * mt * inY + 2 * mt * r.t * inY + r.t * r.t * by;
      ctx.fillStyle = `rgb(${PUR})`;
      ctx.shadowColor = `rgba(${PUR},.95)`;
      ctx.shadowBlur = 9;
      ctx.beginPath();
      ctx.arc(x, y, 3.2, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    // 后端节点（服务器方块 + 命中闪亮衰减）
    bys.forEach((by, i) => {
      const fl = Math.max(0, flashes[i]);
      if (flashes[i] > 0) flashes[i] -= 0.04;
      ctx.fillStyle = `rgba(${PUR},${(0.14 + 0.45 * fl).toFixed(3)})`;
      ctx.strokeStyle = `rgba(${PUR},${(0.55 + 0.45 * fl).toFixed(3)})`;
      ctx.lineWidth = 1.5;
      ctx.fillRect(bx - 18, by - 15, 38, 30);
      ctx.strokeRect(bx - 18, by - 15, 38, 30);
      // 服务器纹理线
      ctx.fillStyle = `rgba(${PUR},.75)`;
      ctx.fillRect(bx - 11, by - 7, 22, 2);
      ctx.fillRect(bx - 11, by + 1, 16, 2);
      ctx.beginPath();
      ctx.arc(bx + 10, by + 8, 1.6, 0, Math.PI * 2);
      ctx.fill();
      // 命中扩散光环
      if (fl > 0) {
        ctx.strokeStyle = `rgba(${PUR},${(0.55 * fl).toFixed(3)})`;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(bx, by, 20 + 14 * (1 - fl), 0, Math.PI * 2);
        ctx.stroke();
      }
    });

    // 入口节点（域名入口）
    ctx.fillStyle = `rgba(${PUR},.16)`;
    ctx.strokeStyle = `rgba(${PUR},.9)`;
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.arc(inX, inY, 16, 0, Math.PI * 2);
    ctx.fill();
    ctx.stroke();
    ctx.fillStyle = `rgb(${PUR})`;
    ctx.shadowColor = `rgba(${PUR},.9)`;
    ctx.shadowBlur = 8;
    ctx.beginPath();
    ctx.arc(inX, inY, 5, 0, Math.PI * 2);
    ctx.fill();
    ctx.shadowBlur = 0;
    // 入口标签
    ctx.fillStyle = "rgba(148,163,184,.9)";
    ctx.font = "10px ui-monospace, monospace";
    ctx.textAlign = "center";
    ctx.fillText("IN", inX, inY + 30);
    ctx.fillText("BACKENDS", bx, bys[0] - 26);

    pxyRAF = requestAnimationFrame(frame);
  };
  frame();
}

// 蜜罐诱捕：诱捕网（扫描探针从四周扑向诱饵端口，撞上即被捕获泛起金色涟漪）
let hpRAF = 0;
function stopHpFX() {
  if (hpRAF) { cancelAnimationFrame(hpRAF); hpRAF = 0; }
}
function startHpFX() {
  stopHpFX();
  const cv = document.getElementById("hp-fx");
  if (!cv || reducedMotion()) return;
  const ctx = cv.getContext("2d");
  const dpr = Math.min(2, window.devicePixelRatio || 1);
  const AMB = "245,158,11", RED = "239,68,68", BLU = "74,158,255";
  const traps = [{ x: .2, y: .36 }, { x: .44, y: .66 }, { x: .64, y: .32 }, { x: .82, y: .6 }]
    .map(p => ({ ...p, flash: 0, phase: Math.random() * 6 }));
  const probes = [];
  const ripples = [];
  let tick = 0;
  const frame = () => {
    const w = cv.clientWidth, h = cv.clientHeight;
    if (!w || !h) { hpRAF = requestAnimationFrame(frame); return; }
    if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) {
      cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    tick++;

    // 诱捕网连线（节点间微光脉冲沿线游走）
    for (let i = 0; i < traps.length; i++) {
      const a = traps[i], b = traps[(i + 1) % traps.length];
      const ax = a.x * w, ay = a.y * h, bx = b.x * w, by = b.y * h;
      ctx.strokeStyle = `rgba(${BLU},.22)`;
      ctx.lineWidth = 1;
      ctx.setLineDash([6, 8]);
      ctx.lineDashOffset = -(tick / 2) % 14;
      ctx.beginPath(); ctx.moveTo(ax, ay); ctx.lineTo(bx, by); ctx.stroke();
      ctx.setLineDash([]);
    }

    // 每 ~26 帧放出一个扫描探针
    if (tick % 26 === 0) {
      const t = traps[Math.floor(Math.random() * traps.length)];
      const edge = Math.floor(Math.random() * 4);
      let x, y;
      if (edge === 0) { x = Math.random() * w; y = -8; }
      else if (edge === 1) { x = w + 8; y = Math.random() * h; }
      else if (edge === 2) { x = Math.random() * w; y = h + 8; }
      else { x = -8; y = Math.random() * h; }
      probes.push({ x, y, tx: t.x * w, ty: t.y * h, t: 0, v: 0.008 + Math.random() * 0.008, node: t });
    }

    // 探针飞行（红色 = 攻击者的扫描流量）
    for (let i = probes.length - 1; i >= 0; i--) {
      const p = probes[i];
      p.t += p.v;
      if (p.t >= 1) {
        // 命中诱饵：捕获涟漪 + 端口闪光
        ripples.push({ x: p.tx, y: p.ty, r: 4, a: 1 });
        p.node.flash = 1;
        probes.splice(i, 1);
        continue;
      }
      const x = p.x + (p.tx - p.x) * p.t;
      const y = p.y + (p.ty - p.y) * p.t;
      const g = ctx.createLinearGradient(x - 22 * (p.tx - p.x ? Math.sign(p.tx - p.x) : 1), y, x, y);
      g.addColorStop(0, `rgba(${RED},0)`);
      g.addColorStop(1, `rgba(${RED},.8)`);
      ctx.strokeStyle = g;
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(x - (p.tx - p.x) * 0.08, y - (p.ty - p.y) * 0.08);
      ctx.lineTo(x, y);
      ctx.stroke();
      ctx.fillStyle = `rgb(${RED})`;
      ctx.shadowColor = `rgba(${RED},.95)`;
      ctx.shadowBlur = 8;
      ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI * 2); ctx.fill();
      ctx.shadowBlur = 0;
    }

    // 捕获涟漪（金色扩散环）
    for (let i = ripples.length - 1; i >= 0; i--) {
      const r = ripples[i];
      r.r += 1.6; r.a -= 0.03;
      if (r.a <= 0) { ripples.splice(i, 1); continue; }
      ctx.strokeStyle = `rgba(${AMB},${r.a.toFixed(2)})`;
      ctx.lineWidth = 2;
      ctx.beginPath(); ctx.arc(r.x, r.y, r.r, 0, Math.PI * 2); ctx.stroke();
    }

    // 诱饵端口（呼吸方块 + 捕获时高亮）
    traps.forEach(t => {
      const x = t.x * w, y = t.y * h;
      const breath = 0.55 + 0.3 * Math.sin(t.phase + tick / 26);
      if (t.flash > 0) t.flash -= 0.035;
      const fl = Math.max(0, t.flash);
      ctx.fillStyle = `rgba(${AMB},${(0.16 + 0.5 * fl).toFixed(3)})`;
      ctx.strokeStyle = `rgba(${AMB},${(breath + 0.4 * fl).toFixed(3)})`;
      ctx.lineWidth = 2;
      ctx.fillRect(x - 13, y - 13, 26, 26);
      ctx.strokeRect(x - 13, y - 13, 26, 26);
      // 端口亮芯
      ctx.fillStyle = `rgba(${AMB},${(0.5 + 0.5 * fl).toFixed(2)})`;
      ctx.fillRect(x - 7, y - 2, 14, 4);
      // 命中扩散环
      if (fl > 0) {
        ctx.strokeStyle = `rgba(${AMB},${(0.6 * fl).toFixed(2)})`;
        ctx.lineWidth = 2;
        ctx.beginPath(); ctx.arc(x, y, 24 + 16 * (1 - fl), 0, Math.PI * 2); ctx.stroke();
      }
      ctx.fillStyle = "rgba(148,163,184,.85)";
      ctx.font = "9px ui-monospace, monospace";
      ctx.textAlign = "center";
      ctx.fillText("TRAP", x, y + 26);
    });

    hpRAF = requestAnimationFrame(frame);
  };
  frame();
}

// IP 访客：访客汇聚（来访光点从四周飞入中枢，中枢再向对应地区节点回传脉冲）
let ipvRAF = 0;
function stopIpvFX() {
  if (ipvRAF) { cancelAnimationFrame(ipvRAF); ipvRAF = 0; }
}
function startIpvFX() {
  stopIpvFX();
  const cv = document.getElementById("ipv-fx");
  if (!cv || reducedMotion()) return;
  const ctx = cv.getContext("2d");
  const dpr = Math.min(2, window.devicePixelRatio || 1);
  const NODES = [
    { c: "CN", x: .18, y: .3, col: "239,68,68" },
    { c: "US", x: .78, y: .26, col: "74,158,255" },
    { c: "DE", x: .14, y: .74, col: "245,158,11" },
    { c: "JP", x: .84, y: .72, col: "52,211,153" },
    { c: "SG", x: .5, y: .14, col: "167,139,250" },
  ];
  const flows = [];   // 来访光点
  const pulses = [];  // 中枢 → 地区节点 的回传脉冲
  let coreFlash = 0, tick = 0;
  const frame = () => {
    const w = cv.clientWidth, h = cv.clientHeight;
    if (!w || !h) { ipvRAF = requestAnimationFrame(frame); return; }
    if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) {
      cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    tick++;
    const cx = w / 2, cy = h / 2;

    // 中枢 → 地区 虚线辐条
    NODES.forEach(n => {
      ctx.strokeStyle = `rgba(${n.col},.22)`;
      ctx.lineWidth = 1;
      ctx.setLineDash([4, 7]);
      ctx.lineDashOffset = -(tick / 2) % 11;
      ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(n.x * w, n.y * h); ctx.stroke();
      ctx.setLineDash([]);
    });

    // 每 ~30 帧来一个访客（随机地区着色）
    if (tick % 30 === 0) {
      const n = NODES[Math.floor(Math.random() * NODES.length)];
      const edge = Math.floor(Math.random() * 4);
      let x, y;
      if (edge === 0) { x = Math.random() * w; y = -8; }
      else if (edge === 1) { x = w + 8; y = Math.random() * h; }
      else if (edge === 2) { x = Math.random() * w; y = h + 8; }
      else { x = -8; y = Math.random() * h; }
      flows.push({ x, y, col: n.col, cc: n.c, t: 0, v: 0.010 + Math.random() * 0.008 });
    }

    // 来访光点 → 中枢
    for (let i = flows.length - 1; i >= 0; i--) {
      const f = flows[i];
      f.t += f.v;
      if (f.t >= 1) {
        coreFlash = 1;
        pulses.push({ n: NODES.find(n => n.c === f.cc), t: 0, col: f.col });
        flows.splice(i, 1);
        continue;
      }
      const x = f.x + (cx - f.x) * f.t;
      const y = f.y + (cy - f.y) * f.t;
      const g = ctx.createLinearGradient(f.x + (cx - f.x) * Math.max(0, f.t - .16), f.y + (cy - f.y) * Math.max(0, f.t - .16), x, y);
      g.addColorStop(0, `rgba(${f.col},0)`);
      g.addColorStop(1, `rgba(${f.col},.85)`);
      ctx.strokeStyle = g;
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(f.x + (cx - f.x) * Math.max(0, f.t - .16), f.y + (cy - f.y) * Math.max(0, f.t - .16));
      ctx.lineTo(x, y);
      ctx.stroke();
      ctx.fillStyle = `rgb(${f.col})`;
      ctx.shadowColor = `rgba(${f.col},.95)`;
      ctx.shadowBlur = 8;
      ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI * 2); ctx.fill();
      ctx.shadowBlur = 0;
    }

    // 中枢 → 地区 的归属脉冲（沿辐条推进并淡出）
    for (let i = pulses.length - 1; i >= 0; i--) {
      const p = pulses[i];
      p.t += 0.045;
      if (p.t >= 1 || !p.n) { pulses.splice(i, 1); continue; }
      const nx = p.n.x * w, ny = p.n.y * h;
      const x = cx + (nx - cx) * p.t, y = cy + (ny - cy) * p.t;
      ctx.fillStyle = `rgba(${p.col},${(1 - p.t).toFixed(2)})`;
      ctx.shadowColor = `rgba(${p.col},.9)`;
      ctx.shadowBlur = 7;
      ctx.beginPath(); ctx.arc(x, y, 3.4, 0, Math.PI * 2); ctx.fill();
      ctx.shadowBlur = 0;
      // 节点接收时的微光
      if (p.t > .86) {
        ctx.strokeStyle = `rgba(${p.col},${((1 - p.t) * 6).toFixed(2)})`;
        ctx.lineWidth = 2;
        ctx.beginPath(); ctx.arc(nx, ny, 16 + 8 * (1 - p.t), 0, Math.PI * 2); ctx.stroke();
      }
    }

    // 中枢（多环呼吸 + 命中闪光）
    if (coreFlash > 0) coreFlash -= 0.04;
    const fl = Math.max(0, coreFlash);
    ctx.strokeStyle = `rgba(74,158,255,${(0.35 + 0.5 * fl).toFixed(2)})`;
    ctx.lineWidth = 1.5;
    ctx.setLineDash([7, 6]);
    ctx.lineDashOffset = -(tick / 3) % 13;
    ctx.beginPath(); ctx.arc(cx, cy, 24 + 4 * fl, 0, Math.PI * 2); ctx.stroke();
    ctx.setLineDash([]);
    ctx.strokeStyle = "rgba(74,158,255,.5)";
    ctx.beginPath(); ctx.arc(cx, cy, 15, 0, Math.PI * 2); ctx.stroke();
    ctx.fillStyle = `rgba(74,158,255,${(0.22 + 0.5 * fl).toFixed(2)})`;
    ctx.beginPath(); ctx.arc(cx, cy, 9, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = "rgba(148,163,184,.9)";
    ctx.font = "9px ui-monospace, monospace";
    ctx.textAlign = "center";
    ctx.fillText("CORE", cx, cy + 40);

    // 地区节点（圆环 + 国家码 + 浮沉）
    NODES.forEach((n, i) => {
      const x = n.x * w, y = n.y * h + Math.sin(tick / 30 + i) * 3;
      ctx.fillStyle = `rgba(${n.col},.14)`;
      ctx.strokeStyle = `rgba(${n.col},.85)`;
      ctx.lineWidth = 1.6;
      ctx.beginPath(); ctx.arc(x, y, 17, 0, Math.PI * 2); ctx.fill(); ctx.stroke();
      ctx.fillStyle = `rgb(${n.col})`;
      ctx.font = "600 11px ui-monospace, monospace";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(n.c, x, y);
      ctx.textBaseline = "alphabetic";
    });

    ipvRAF = requestAnimationFrame(frame);
  };
  frame();
}

/* ---------- 仪表盘 ---------- */
async function loadDashboard() {
  const s = await api("/api/status");
  const health = s.health || {};
  const score = health.score ?? 100;

  // —— 巨型指挥工作台：品牌 / 心跳波形 / 健康环 / 指标 ——
  const online = score >= 80 ? "SYSTEM ONLINE" : score >= 60 ? "SYSTEM WATCH" : "SYSTEM ALERT";
  const statusEl = $("#hq-status");
  if (statusEl) statusEl.textContent = `${online} · ${new Date().toLocaleTimeString("zh-CN", { hour12: false })}`;

  const ring = $("#hq-ring-fg");
  if (ring) {
    const C = 364.42;
    const pct = Math.max(0, Math.min(100, score)) / 100;
    ring.style.strokeDashoffset = String(C * (1 - pct));
  }
  countUp($("#hq-score-num"), score, 1100);

  const runs = (s.webRunning || 0) + (s.pfRunning || 0);
  const metricsEl = $("#hq-metrics");
  if (metricsEl) {
    metricsEl.innerHTML = `
      <div class="m">VERSION<b>${esc(s.version)}</b></div>
      <div class="m">UPTIME<b>${esc(s.uptime)}</b></div>
      <div class="m">ADMIN PORT<b>${esc(s.adminPort)}</b></div>
      <div class="m">RUNNING RULES<b>${runs}</b></div>`;
  }

  const cpu = Math.max(0, Math.min(100, Number(health.cpu) || 0));
  const mem = Math.max(0, Math.min(100, Number(health.mem) || 0));
  const wafGC = !s.wafEnabled ? "#64748b" : (s.wafHits > 0 ? "#ef4444" : "#22c55e");
  const sideEl = $("#hq-side");
  if (sideEl) {
    sideEl.innerHTML = `
      <div class="g" style="--gc:#4a9eff">
        <div class="l"><span>CPU</span><span>负荷</span></div>
        <div class="v">${cpu}<small>%</small></div>
        <div class="bar"><i style="width:${cpu}%"></i></div>
      </div>
      <div class="g" style="--gc:#a78bfa">
        <div class="l"><span>MEMORY</span><span>内存</span></div>
        <div class="v">${mem}<small>%</small></div>
        <div class="bar"><i style="width:${mem}%"></i></div>
      </div>
      <div class="g" style="--gc:#22c55e">
        <div class="l"><span>RUNNING</span><span>运行规则</span></div>
        <div class="v">${runs}<small>条</small></div>
      </div>
      <div class="g" style="--gc:${wafGC}">
        <div class="l"><span>WAF</span><span>累计拦截</span></div>
        <div class="v">${s.wafHits || 0}<small>次</small></div>
      </div>`;
  }

  const cards = [
    { key: "portforward", page: "portforward", label: "端口转发", sub: `${s.pfRunning || 0} 条运行中`, icon: "⇄", tone: "blue",
      hint: (s.portforward || 0) === 0 ? "尚未配置" : "运行正常" },
    { key: "webrules", page: "webproxy", label: "Web 服务", sub: `${s.webRunning || 0} 条运行中`, icon: "◎", tone: "violet",
      hint: (s.webrules || 0) === 0 ? "尚未配置" : "运行正常" },
    { key: "ddns", page: "ddns", label: "动态域名", sub: "DDNS 任务", icon: "⟳", tone: "cyan",
      hint: (s.ddns || 0) === 0 ? "尚未配置" : "已启用" },
    { key: "crons", page: "cron", label: "计划任务", sub: "定时执行", icon: "⏱", tone: "amber",
      hint: (s.crons || 0) === 0 ? "尚未配置" : "已启用" },
    { key: "ipdb", page: "ipdb", label: "IP 地址库", sub: `${s.secgroups || 0} 个安全组`, icon: "◫", tone: "teal",
      hint: (s.ipdb || 0) === 0 ? "尚未配置" : "已维护" },
    { key: "sslcerts", page: "ssl", label: "证书", sub: "SSL / TLS", icon: "✉", tone: "green",
      hint: (s.sslcerts || 0) === 0 ? "尚未配置" : "已签发" },
    { key: "wafHits", page: "waf", label: "WAF 拦截", sub: s.wafEnabled ? (s.wafMode === "detect" ? "仅记录模式" : "拦截模式") : "已关闭",
      icon: "⛨", tone: (s.wafHits > 0 ? "red" : "slate"),
      hint: s.wafEnabled ? ((s.wafHits || 0) > 0 ? "有拦截记录" : "暂无异常") : "未启用" },
    { key: "honeypotRecs", page: "honeypot", label: "蜜罐诱捕", sub: s.honeypotEnabled ? `${s.honeypotPorts || 0} 个诱饵端口在监听` : "诱捕已关闭",
      icon: "☗", tone: "red",
      hint: !s.honeypotEnabled ? "未启用" : ((s.honeypotRecs || 0) > 0 ? "已捕获连接" : "等待上钩") },
    { key: "ipvisitors", page: "ipvisitors", label: "IP 访客", sub: "来访 IP 地区统计", icon: "◎", tone: "cyan",
      hint: (s.ipvisitors || 0) === 0 ? "暂无记录" : "持续登记中" },
  ];

  const cardsBox = $("#dash-cards");
  cardsBox.innerHTML = cards.map(c => `
    <div class="stat-card tone-${c.tone}" title="点击进入 ${esc(c.label)}">
      <div class="stat-top">
        <span class="stat-icon">${c.icon}</span>
        <span class="stat-label">${esc(c.label)}</span>
      </div>
      <div class="stat-num">0</div>
      <div class="stat-foot"><span>${esc(c.sub)}</span><span class="stat-hint">${esc(c.hint)}</span></div>
    </div>`).join("");
  // 数字滚动 + 点击进入对应模块
  cardsBox.querySelectorAll(".stat-card").forEach((el, i) => {
    const c = cards[i];
    if (!c) return;
    el.style.cursor = "pointer";
    el.onclick = () => gotoPage(c.page);
    countUp(el.querySelector(".stat-num"), Number(s[c.key]) || 0, 700 + i * 70);
  });

  // 运行健康度状态（health/score 已在工作台部分取到）
  const status = score >= 80 ? "正常" : score >= 60 ? "关注" : "偏高";
  const tone = score >= 80 ? "ok" : score >= 60 ? "warn" : "bad";

  $("#dash-info").innerHTML = `
    <div class="info-grid">
      <div class="info-card">
        <div class="info-head">运行健康度 <span class="badge ${tone === "ok" ? "on" : tone === "warn" ? "warn" : "err"}">${status}</span></div>
        <div class="health-bar"><div class="health-fill ${tone}" style="width:${score}%"></div></div>
        <div class="health-meta">评分 ${score} · CPU ${health.cpu ?? "-"}% · 内存 ${health.mem ?? "-"}%</div>
      </div>
      <div class="info-card">
        <div class="info-head">程序信息</div>
        <dl class="kv-list">
          <dt>版本</dt><dd>${esc(s.version)}</dd>
          <dt>已运行</dt><dd>${esc(s.uptime)}</dd>
          <dt>后台端口</dt><dd>${esc(s.adminPort)}</dd>
          <dt>全局 IP 过滤</dt><dd>${s.ipfilterMode === "white" ? "白名单" : s.ipfilterMode === "black" ? "黑名单" : "未启用"}</dd>
        </dl>
      </div>
      <div class="info-card">
        <div class="info-head">安全状态</div>
        <dl class="kv-list">
          <dt>Coraza WAF</dt><dd>${s.wafEnabled ? `运行中（${s.wafMode === "detect" ? "仅记录" : "拦截"}）` : "已关闭"}</dd>
          <dt>累计拦截</dt><dd>${esc(s.wafHits || 0)} 次</dd>
          <dt>全局过滤</dt><dd>${s.ipfilterMode && s.ipfilterMode !== "none" ? "已启用" : "未启用"}</dd>
        </dl>
      </div>
    </div>`;

  startHQWave(); // 心跳波形（内部会先停掉旧循环，重复调用安全）
}

/* ---------- 分组 ---------- */
let groups = [];

async function loadGroups() {
  groups = (await api("/api/groups")) || [];
  window.__groups = groups;
}

// renderGroupBar 渲染分组筛选栏（含"全部"与"未分组"）
function renderGroupBar(containerID, module) {
  const box = document.getElementById(containerID);
  if (!box) return;
  const cur = window.__groupFilter && window.__groupFilter[module] || "";
  const items = [{ id: "", name: "全部" }, { id: "__none__", name: "未分组" }]
    .concat(groups.map(g => ({ id: g.id, name: g.name })));
  box.innerHTML = items.map(it => {
    const on = (cur || "") === it.id;
    return `<span class="group-chip ${on ? "active" : ""}" data-gid="${esc(it.id)}">${esc(it.name)}</span>`;
  }).join("") + (groups.length ? `<button class="btn sm" onclick="openGroupManager()">管理分组</button>` : `<button class="btn sm" onclick="openGroupManager()">+ 新建分组</button>`);
  box.querySelectorAll(".group-chip").forEach(chip => {
    chip.onclick = () => {
      window.__groupFilter = window.__groupFilter || {};
      window.__groupFilter[module] = chip.dataset.gid;
      const reload = { pf: loadPF, web: loadWeb, ddns: loadDDNS }[module];
      if (reload) reload();
    };
  });
}

// inGroup 判断规则是否属于当前筛选分组
function inGroup(item, module) {
  const f = (window.__groupFilter && window.__groupFilter[module]) || "";
  if (!f) return true;
  const tag = item.groupTag || item.groupID || "";
  if (f === "__none__") return !tag;
  return tag === f;
}

function groupName(id) {
  const g = groups.find(x => x.id === id);
  return g ? g.name : "";
}

/* ---------- 通用规则渲染 ---------- */
function ruleCard(id, title, enabled, status, metaHTML, actionsHTML) {
  const acts = [];
  if (actionsHTML.logs) acts.push(`<button class="btn sm" onclick="${actionsHTML.logs}">查看记录</button>`);
  // extra：调用方自定义的前置操作（如启用开关），放在最左侧
  if (actionsHTML.extra) acts.unshift(actionsHTML.extra);
  acts.push(`<button class="btn sm" onclick="${actionsHTML.edit}">编辑</button>`);
  acts.push(`<button class="btn sm danger" onclick="${actionsHTML.del}">删除</button>`);
  return `<div class="rule" id="${id}">
    <div class="rule-head">
      <span class="rule-dot ${enabled ? "on" : "off"}"></span>
      <span class="name">${esc(title)}</span>
      ${status || ""}
      <span class="spacer"></span>
      <div class="rule-actions">${acts.join("")}</div>
    </div>
    <div class="rule-meta">${metaHTML}</div>
    <div class="logbox"></div>
  </div>`;
}

// emptyState 统一的空状态展示
function emptyState(title, desc) {
  return `<div class="empty-state"><div class="empty-icon">◌</div>
    <div class="empty-title">${esc(title)}</div>
    <div class="empty-desc">${esc(desc || "")}</div></div>`;
}

// metric 生成一个键值小标签，用于规则卡片内的结构化展示
function metric(label, value, tone) {
  if (value === undefined || value === null || value === "") return "";
  return `<span class="metric ${tone || ""}"><em>${esc(label)}</em><b>${esc(value)}</b></span>`;
}

function dlgForm(title, bodyHTML, onSave) {
  const dlg = $("#dlg");
  dlg.innerHTML = `<h3>${esc(title)}</h3>${bodyHTML}<div class="row">
    <button class="btn" onclick="dlgClose()">取消</button>
    <button class="btn primary" id="dlg-save">保存</button></div>`;
  bindProviderSwitch(dlg);
  bindTLSWarnings(dlg);
  bindTabs(dlg);
  // CORS 开关联动
  const corsChk = dlg.querySelector("#f-cors");
  const corsBox = dlg.querySelector("#f-cors-box");
  if (corsChk && corsBox) {
    const syncCors = () => { corsBox.style.display = corsChk.checked ? "block" : "none"; };
    corsChk.addEventListener("change", syncCors);
    syncCors();
  }
  // 证书表单（若存在验证方式选择器）绑定联动
  if (typeof bindSSLChallenge === "function") bindSSLChallenge(dlg);
  $("#dlg-save").onclick = async () => {
    try { await onSave(dlg); dlgClose(); }
    catch (e) { alert(e.message); }
  };
  dlg.showModal();
}
function dlgClose() { $("#dlg").close(); }
function dlg2Close() { $("#dlg2").close(); }

// bindTabs 对话框标签页切换：.dlg-tab[data-pane] ↔ .dlg-pane[data-pane]
function bindTabs(root) {
  root.querySelectorAll(".dlg-tab").forEach(btn => {
    btn.onclick = () => {
      root.querySelectorAll(".dlg-tab").forEach(b => b.classList.toggle("active", b === btn));
      root.querySelectorAll(".dlg-pane").forEach(p =>
        p.classList.toggle("active", p.dataset.pane === btn.dataset.pane));
    };
  });
}

// bindTLSWarnings 未配置证书时，对同端口/跳转选项给出警示
function bindTLSWarnings(root) {
  const hasCert = () => {
    const certID = root.querySelector("#f-certid");
    const certFile = root.querySelector("#f-cert");
    const keyFile = root.querySelector("#f-key");
    const byLib = certID && certID.value !== "";
    const byFile = certFile && certFile.value.trim() !== "" && keyFile && keyFile.value.trim() !== "";
    return byLib || byFile;
  };
  const refresh = () => {
    const ok = hasCert();
    const sw = root.querySelector("#f-sameport-warn");
    const rw = root.querySelector("#f-redirect-warn");
    const sp = root.querySelector("#f-sameport");
    const rd = root.querySelector("#f-redirect");
    if (sw) sw.style.display = (!ok && sp && sp.checked) ? "block" : "none";
    if (rw) rw.style.display = (!ok && rd && rd.checked) ? "block" : "none";
  };
  ["#f-sameport", "#f-redirect", "#f-certid", "#f-cert", "#f-key"].forEach(sel => {
    const el = root.querySelector(sel);
    if (el) { el.addEventListener("change", refresh); el.addEventListener("input", refresh); }
  });
  refresh();
}

// bindProviderSwitch 根据所选 DNS 服务商切换凭据字段的标签与提示
function bindProviderSwitch(root) {
  const sel = root.querySelector("#f-provider");
  if (!sel) return;
  const tip = root.querySelector("#f-dnshe-tip");
  const tokenLabel = root.querySelector("#f-token-label");
  const akLabel = root.querySelector("#f-ak-label");
  const akID = root.querySelector("#f-akid");

  const apply = () => {
    const p = sel.value;
    if (tip) tip.style.display = p === "dnshe" ? "block" : "none";
    const acts = root.querySelector("#f-dnshe-actions");
    if (acts) acts.style.display = p === "dnshe" ? "block" : "none";
    if (tokenLabel) {
      tokenLabel.textContent = p === "dnshe" ? "API Key（DNSHE）"
        : p === "cloudflare" ? "API Token（Cloudflare）"
        : p === "dnspod" ? "Token（DNSPod，格式 ID,Token）"
        : "Token";
    }
    if (akLabel) {
      akLabel.textContent = p === "dnshe" ? "API Secret（DNSHE）" : "AccessKey（阿里云）";
    }
    // 阿里云才需要 AccessKeyID
    if (akID) {
      const row = akID.closest("label");
      if (row) row.style.display = p === "aliyun" ? "" : "none";
    }
  };
  sel.addEventListener("change", apply);
  apply();
}

/* ---------- 端口转发 ---------- */
let pfRules = [];
async function loadPF() {
  pfRules = (await api("/api/portforward")) || [];
  const st = await api("/api/portforward/status");
  renderGroupBar("pf-groupbar", "pf");
  const pfShown = pfRules.filter(r => inGroup(r, "pf"));
  $("#pf-list").innerHTML = pfShown.map(r => {
    const stText = st[r.id] || "";
    const bad = stText.startsWith("异常");
    const stat = stText ? `<span class="badge ${bad ? "err" : "on"}">${bad ? "运行异常" : "运行中"}</span>` : `<span class="badge off">未运行</span>`;
    const lp = (r.listenPorts || []).length;
    const meta = [
      metric("协议", (r.proto || "").toUpperCase(), "mono"),
      metric("监听", `${r.listenIP || "0.0.0.0"}:${formatPorts(r.listenPorts || []) || "-"}`, "mono"),
      metric("转发至", `${r.targetIP}:${formatPorts(r.targetPorts || []) || "-"}`, "mono green"),
      metric("并发上限", r.maxConns ? r.maxConns : "不限"),
      metric("端口数", lp),
      r.groupID ? metric("访问控制", "安全组", "amber") : "",
      r.groupTag ? metric("分组", groupName(r.groupTag), "blue") : "",
    ].join("");
    return ruleCard("pf-" + r.id, r.name, r.enabled, stat,
      `<div class="metrics">${meta}</div>${bad ? `<div class="rule-err">${esc(stText)}</div>` : ""}`,
      { logs: `pfLogs('${r.id}')`, edit: `pfEdit('${r.id}')`, del: `pfDel('${r.id}')` });
  }).join("") || emptyState("暂无端口转发规则", "点击右上角「添加转发规则」创建第一条");
}

function pfEdit(id) {
  const r = pfRules.find(x => x.id === id) || {
    id: uid(), name: "", proto: "tcpudp", listenIP: "", listenPorts: [], targetIP: "", targetPorts: [], enabled: true,
  };
  dlgForm(id ? "编辑端口转发规则" : "添加端口转发规则", `
    <label>规则名称 <input id="f-name" value="${esc(r.name)}"></label>
    <label>协议 <select id="f-proto">
      <option value="tcp" ${r.proto === "tcp" ? "selected" : ""}>TCP</option>
      <option value="udp" ${r.proto === "udp" ? "selected" : ""}>UDP</option>
      <option value="tcpudp" ${r.proto === "tcpudp" ? "selected" : ""}>TCP+UDP</option></select></label>
    <label>监听 IP（留空监听全部） <input id="f-lip" value="${esc(r.listenIP)}"></label>
    <label>监听端口 <input id="f-lports" value="${esc(formatPorts(r.listenPorts || []))}" placeholder="22 或 80,443 或 20000-20010"></label>
    <p class="hint" style="margin:-6px 0 6px">支持单个端口、逗号分隔多个、连续范围（如 <code>20000-20010</code>）。</p>
    <label>目标 IP（内网服务地址） <input id="f-tip" value="${esc(r.targetIP)}"></label>
    <label>目标端口（与监听端口按序对应；只填 1 个则全部转给它） <input id="f-tports" value="${esc(formatPorts(r.targetPorts || []))}" placeholder="留空则同监听端口"></label>
    <label>单规则最大并发连接（0 = 不限） <input id="f-maxconn" type="number" min="0" value="${r.maxConns || 0}"></label>
    <div style="display:flex;gap:10px">
      <label style="flex:1">分组 <select id="f-pf-group"><option value="">不分组</option>
        ${(window.__groups || []).map(g => `<option value="${esc(g.id)}" ${r.groupTag === g.id ? "selected" : ""}>${esc(g.name)}</option>`).join("")}</select></label>
      <label style="flex:1">备注 <input id="f-pf-remark" value="${esc(r.remark || "")}" placeholder="可选"></label>
    </div>
    <h4 style="margin-top:14px">异常通知 Webhook（可选）</h4>
    ${WHTemplate("pfwh", r.webhook)}
    <label>访问控制（安全组） <select id="f-group"><option value="">不启用</option>
      ${(typeof secGroups !== "undefined" ? secGroups : []).map(g => `<option value="${esc(g.id)}" ${r.groupID === g.id ? "selected" : ""}>${esc(g.name)}（${g.mode === "white" ? "白" : "黑"}名单）</option>`).join("")}</select></label>
    <label class="checkline"><input type="checkbox" id="f-enabled" ${r.enabled ? "checked" : ""}> 启用规则</label>
  `, async dlg => {
    const lports = parsePorts($("#f-lports", dlg).value);
    let tports = parsePorts($("#f-tports", dlg).value);
    if (!lports.length) throw new Error("请填写监听端口");
    if (!tports.length) tports = lports.slice(); // 留空则与监听端口相同
    if (tports.length !== 1 && tports.length !== lports.length) {
      throw new Error(`监听端口 ${lports.length} 个、目标端口 ${tports.length} 个，数量需一致（或只填 1 个）`);
    }
    const nr = {
      id: r.id, name: $("#f-name", dlg).value.trim() || "未命名",
      proto: $("#f-proto", dlg).value, listenIP: $("#f-lip", dlg).value.trim(),
      listenPorts: lports, targetIP: $("#f-tip", dlg).value.trim(),
      targetPorts: tports, maxConns: Number($("#f-maxconn", dlg).value) || 0,
      groupID: $("#f-group", dlg).value,
      groupTag: $("#f-pf-group", dlg).value,
      remark: $("#f-pf-remark", dlg).value.trim(),
      webhook: WHRead("pfwh", dlg),
      enabled: $("#f-enabled", dlg).checked,
    };
    if (!nr.targetIP) throw new Error("请填写目标 IP");
    pfRules = pfRules.filter(x => x.id !== r.id); pfRules.push(nr);
    await api("/api/portforward", { method: "POST", body: JSON.stringify(pfRules) });
    loadPF();
  });
}

async function pfDel(id) {
  if (!confirm("确定删除该规则？")) return;
  pfRules = pfRules.filter(x => x.id !== id);
  await api("/api/portforward", { method: "POST", body: JSON.stringify(pfRules) });
  loadPF();
}

async function pfLogs(id) {
  const logs = await api("/api/portforward/logs?id=" + id);
  const box = $("#pf-" + id + " .logbox");
  box.innerHTML = logs && logs.length ? `<pre class="logs">${esc(logs.join("\n"))}</pre>` : `<pre class="logs">暂无日志</pre>`;
}

/* ---------- Web 服务（反向代理） ---------- */
let webRules = [];
async function loadWeb() {
  webRules = (await api("/api/webrules")) || [];
  const st = await api("/api/webrules/status");
  let health = {};
  try { health = await api("/api/webrules/health"); } catch (e) { health = {}; }
  window.__webHealth = health;
  renderGroupBar("web-groupbar", "web");
  const webShown = webRules.filter(r => inGroup(r, "web"));
  // 地址链接辅助：前端/后端地址均可新窗口打开
  const schemeOf = r => ((r.tlsCertFile || r.certID) ? "https" : "http");
  const feLink = (r, d) => {
    if (!d || d.startsWith("*.")) return null; // 通配符域名无法直接访问
    const sc = schemeOf(r);
    const p = Number(r.port) || 80;
    const host = ((sc === "https" && p === 443) || (sc === "http" && p === 80)) ? d : `${d}:${p}`;
    return `${sc}://${host}`;
  };
  const beLink = b => (!b ? null : (/^https?:\/\//.test(b) ? b : `http://${b}`));
  const aLink = (t, h) => h
    ? `<a class="addr-link" href="${esc(h)}" target="_blank" rel="noopener">${esc(t)}<i>↗</i></a>`
    : esc(t || "");
  $("#web-list").innerHTML = webShown.map(r => {
    const stat = st[r.id] ? `<span class="badge ${st[r.id].startsWith("异常") ? "err" : "on"}">${esc(st[r.id])}</span>` : "";
    const tls = (r.tlsCertFile || r.certID) ? `<span class="badge on">TLS</span>` : "";
    const subTags = (s) => {
      const t = [];
      if (s.type === "redirect") t.push("重定向");
      else if (s.type === "urljump") t.push("URL跳转");
      else if (s.type === "file") t.push("静态文件");
      if (s.basicUser) t.push("BasicAuth");
      if (s.uaMode && s.uaMode !== "none") t.push(`UA${s.uaMode === "white" ? "白" : "黑"}名单`);
      if (s.customRobot) t.push("robots.txt");
      if (s.groupID) t.push("安全组");
      else if (s.filterMode && s.filterMode !== "none") t.push(`IP${s.filterMode === "white" ? "白" : "黑"}名单`);
      if (s.locations && s.locations.length) t.push("路由 " + s.locations.join(","));
      if (s.lb && s.lb.policy && s.lb.policy !== "roundrobin") t.push(s.lb.policy === "weighted" ? "加权" : "IP哈希");
      if (s.health && s.health.enabled) t.push("健康检查");
      return t.length ? `（${t.join("、")}）` : "";
    };
    const hd = (window.__webHealth || {})[r.id] || {};
    const healthLine = (key) => {
      const m = hd[key];
      if (!m || !Object.keys(m).length) return "";
      const bad = Object.entries(m).filter(([, v]) => v.indexOf("不健康") >= 0);
      return bad.length
        ? ` <span class="badge err">后端异常 ${bad.length}/${Object.keys(m).length}</span>`
        : "";
    };
    const subs = (r.subRules || []).map(s => {
      // 非反代类型展示跳转目标 / 静态目录，而不是后端地址
      let dstHTML;
      if (s.type === "redirect" || s.type === "urljump") {
        dstHTML = esc(s.target || "（未设目标）");
      } else if (s.type === "file") {
        dstHTML = esc(s.docRoot || "（未设目录）");
      } else {
        dstHTML = (s.backends || []).map(b => aLink(b, beLink(b))).join(", ");
      }
      const domainHTML = (s.domains || []).map(d => aLink(d, feLink(r, d))).join(" / ");
      const acts = `<span class="sub-acts">
        <button class="btn sm" onclick="openStats('${r.id}','${s.id}')" title="该子规则的流量统计">统计</button>
        <button class="btn sm" onclick="webSubLogs('${r.id}','${s.id}')" title="该子规则的访问记录">记录</button>
        <button class="btn sm" onclick="webSubEditAt('${r.id}','${s.id}')">编辑</button>
        <button class="btn sm danger" onclick="webSubDelAt('${r.id}','${s.id}')">删除</button>
      </span>`;
      return `<div class="subrule"><span class="sub-domain">${domainHTML}</span>
        <span class="sub-arrow">→</span>
        <span class="sub-backend">${dstHTML}</span>
        <span class="sub-tags">${subTags(s)}${healthLine(s.id)}</span>${acts}</div>`;
    }).join("");
    const meta = [
      metric("监听端口", `:${r.port}`, "mono"),
      tls ? metric("TLS", r.samePortTLS ? "同端口复用" : "已启用", "green") : "",
      r.redirectToHTTPS ? metric("HTTP→HTTPS", `${r.redirectCode || 301} 跳转`, "amber") : "",
      r.wafEnabled ? metric("WAF", "已开启", "violet") : "",
      (r.trustedCIDRs || []).length ? metric("可信代理", (r.trustedCIDRs || []).length + " 条", "amber") : "",
      metric("子规则", (r.subRules || []).length),
      groupName(r.groupID) ? metric("分组", groupName(r.groupID), "blue") : "",
    ].join("");
    return ruleCard("web-" + r.id, r.name, r.enabled, stat,
      `<div class="metrics">${meta}</div>
       <div class="rule-sub">
         <div class="sub-head">默认后端 <span class="sub-backend">${(r.defaultBackends || []).map(b => aLink(b, beLink(b))).join(", ") || "（未设置）"}</span>${healthLine("__default__")}</div>
         ${subs}
       </div>`,
      { logs: `webLogs('${r.id}')`, edit: `webEdit('${r.id}')`, del: `webDel('${r.id}')` })
      // 在"查看记录"前插入统计按钮
      .replace(`<button class="btn sm" onclick="webLogs('${r.id}')">查看记录</button>`,
        `<button class="btn sm" onclick="openStats('${r.id}')">统计</button>` +
        `<button class="btn sm" onclick="webLogs('${r.id}')">查看记录</button>`);
  }).join("") || emptyState("暂无 Web 服务规则", "点击右上角「添加 Web 规则」创建反向代理");
}

/* ---------- 子规则编辑（独立对话框，标签页分区，风格对齐 lucky） ---------- */
const SUB_TYPE_NAMES = { proxy: "反向代理", redirect: "重定向", urljump: "URL跳转", file: "静态文件" };

// subDlgHTML 子规则编辑表单：基础设置 / 访问控制 / Header / 健康检查 四个标签页
function subDlgHTML(s) {
  const t = s.type || "proxy";
  const pv = t === "proxy" ? "" : "none";
  const jv = (t === "redirect" || t === "urljump") ? "" : "none";
  const fv = t === "file" ? "" : "none";
  const cv = t === "redirect" ? "" : "none";
  return `
  <div class="dlg-tabs">
    <button class="dlg-tab active" data-pane="base">基础设置</button>
    <button class="dlg-tab" data-pane="auth">访问控制</button>
    <button class="dlg-tab" data-pane="hdr">Header 与兼容</button>
    <button class="dlg-tab" data-pane="hc">健康检查</button>
  </div>
  <div class="dlg-pane active" data-pane="base">
    <input type="hidden" class="s-id" value="${esc(s.id || "")}">
    <div style="display:flex;gap:10px">
      <label style="flex:1">子规则名称 <input class="s-name" value="${esc(s.name || "")}" placeholder="如：游戏站"></label>
      <label style="flex:1">服务类型 <select class="s-type" onchange="subTypeToggle(this)">
        <option value="proxy" ${t === "proxy" ? "selected" : ""}>反向代理</option>
        <option value="redirect" ${t === "redirect" ? "selected" : ""}>重定向（3xx）</option>
        <option value="urljump" ${t === "urljump" ? "selected" : ""}>URL跳转（HTML 页面）</option>
        <option value="file" ${t === "file" ? "selected" : ""}>静态文件</option></select></label>
    </div>
    <label>前端域名（多个逗号分隔，留空匹配全部） <input class="s-domains" value="${esc((s.domains || []).join(","))}" placeholder="ddz.example.com 或 *.example.com"></label>
    <label>URL 路由（可选，多个逗号分隔，留空匹配全部） <input class="s-locations" value="${esc((s.locations || []).join(","))}" placeholder="/api, /static"></label>
    <div class="s-proxy-only" style="display:${pv}">
      <label>后端地址（每行一个，多个自动负载均衡） <textarea class="s-backends" rows="3" style="width:100%" placeholder="127.0.0.1:8080">${esc((s.backends || []).join("\n"))}</textarea></label>
      <p class="hint">支持 <code>127.0.0.1:8080</code> 或 <code>https://…</code>；留空表示该子规则返回 502。</p>
      <div style="display:flex;gap:10px">
        <label style="flex:1">权重（与后端按序对应） <input class="s-weights" value="${esc((s.weights || []).join(","))}" placeholder="1,1,2"></label>
        <label style="flex:1">负载策略 <select class="s-policy">
          <option value="roundrobin" ${(!s.lb || !s.lb.policy || s.lb.policy === "roundrobin") ? "selected" : ""}>轮询</option>
          <option value="weighted" ${(s.lb && s.lb.policy === "weighted") ? "selected" : ""}>加权轮询</option>
          <option value="iphash" ${(s.lb && s.lb.policy === "iphash") ? "selected" : ""}>IP 哈希</option></select></label>
      </div>
      <div style="display:flex;gap:10px">
        <label style="flex:1">单后端最大并发（0=不限） <input class="s-maxactive" type="number" min="0" value="${(s.lb && s.lb.maxActive) || 0}"></label>
        <label style="flex:1">失败重试次数 <input class="s-retry" type="number" min="0" value="${(s.lb && s.lb.retryCount) || 0}"></label>
      </div>
    </div>
    <div class="s-jump-only" style="display:${jv}">
      <label>跳转目标地址 <input class="s-target" value="${esc(s.target || "")}" placeholder="https://{host}{path}{args}"></label>
      <p class="hint">支持变量：<code>{host}</code> <code>{port}</code> <code>{hostAndPort}</code> <code>{path}</code> <code>{args}</code> <code>{ClientIP}</code> <code>{RemoteIP}</code> <code>{time}</code></p>
      <div class="s-code-only" style="display:${cv}"><label>状态码 <select class="s-code">
        <option value="301" ${s.statusCode === 301 ? "selected" : ""}>301 永久重定向</option>
        <option value="302" ${!s.statusCode || s.statusCode === 302 ? "selected" : ""}>302 临时重定向</option>
        <option value="307" ${s.statusCode === 307 ? "selected" : ""}>307 临时（保留方法）</option>
        <option value="308" ${s.statusCode === 308 ? "selected" : ""}>308 永久（保留方法）</option></select></label></div>
    </div>
    <div class="s-file-only" style="display:${fv}">
      <label>静态文件根目录（服务器本地绝对路径） <input class="s-docroot" value="${esc(s.docRoot || "")}" placeholder="/www/html"></label>
      <p class="hint">URL 路由前缀会自动剥离：<code>/static/a.png</code> 对应目录下的 <code>a.png</code>。</p>
    </div>
  </div>
  <div class="dlg-pane" data-pane="auth">
    <h4>BasicAuth 网页认证</h4>
    <div style="display:flex;gap:10px">
      <label style="flex:1">用户 <input class="s-user" value="${esc(s.basicUser || "")}"></label>
      <label style="flex:1">密码 <input class="s-pass" value="${esc(s.basicPass || "")}"></label>
    </div>
    <p class="hint">用户名留空 = 不启用认证。</p>
    <h4>IP 过滤</h4>
    <div style="display:flex;gap:10px">
      <label style="flex:1">模式 <select class="s-fmode">
        <option value="none" ${s.filterMode === "none" || !s.filterMode ? "selected" : ""}>不过滤</option>
        <option value="white" ${s.filterMode === "white" ? "selected" : ""}>白名单（仅允许列表内）</option>
        <option value="black" ${s.filterMode === "black" ? "selected" : ""}>黑名单（仅拒绝列表内）</option></select></label>
      <label style="flex:2">IP 列表（支持 CIDR，逗号分隔） <input class="s-fips" value="${esc((s.filterIPs || []).join(","))}"></label>
    </div>
    <label>引用安全组（优先于上方 IP 过滤） <select class="s-group"><option value="">不引用</option>
      ${secGroups.map(g => `<option value="${esc(g.id)}" ${s.groupID === g.id ? "selected" : ""}>${esc(g.name)}（${g.mode === "white" ? "白" : "黑"}名单）</option>`).join("")}</select></label>
    <h4>UserAgent 过滤</h4>
    <div style="display:flex;gap:10px">
      <label style="flex:1">模式 <select class="s-uamode">
        <option value="none" ${!s.uaMode || s.uaMode === "none" ? "selected" : ""}>不过滤</option>
        <option value="white" ${s.uaMode === "white" ? "selected" : ""}>白名单（仅放行命中项）</option>
        <option value="black" ${s.uaMode === "black" ? "selected" : ""}>黑名单（拦截命中项）</option></select></label>
      <label style="flex:2">关键字（逗号分隔，包含匹配） <input class="s-ualist" value="${esc((s.uaList || []).join(","))}" placeholder="curl, python-requests"></label>
    </div>
    <h4>自定义 robots.txt</h4>
    <label class="checkline"><input type="checkbox" class="s-robot" ${s.customRobot ? "checked" : ""}> 返回自定义 robots.txt（仅本子规则域名生效）</label>
    <textarea class="s-robottxt" rows="3" style="width:100%" placeholder="User-agent: *&#10;Disallow: /admin">${esc(s.robotTxt || "")}</textarea>
  </div>
  <div class="dlg-pane" data-pane="hdr">
    <p class="hint" style="margin-top:0">仅「反向代理」类型生效；变量与跳转目标相同。</p>
    <label style="display:block">自定义请求头（每行 Key: Value，转发给后端） <textarea class="s-seth" rows="3" style="width:100%">${esc(kvText(s.setHeaders))}</textarea></label>
    <label>隐藏响应头（从后端响应中删除，逗号分隔） <input class="s-hideh" value="${esc((s.hideHeaders || []).join(","))}"></label>
    <label style="display:block">添加响应头（返回给客户端，每行 Key: Value） <textarea class="s-addh" rows="3" style="width:100%">${esc(kvText(s.addHeaders))}</textarea></label>
    <label>追加客户端 IP 到该请求头（头名，留空不启用） <input class="s-appendip" value="${esc(s.appendClientIPHeader || "")}" placeholder="X-Original-Forwarded-For"></label>
    <label class="checkline"><input type="checkbox" class="s-insecure" ${s.insecureSkipTLS ? "checked" : ""}> 忽略后端 HTTPS 证书验证（自签证书后端）</label>
    <label class="checkline"><input type="checkbox" class="s-uh" ${s.useTargetHost ? "checked" : ""}> 使用目标地址作为 Host（反代路由器管理页 / 部分 NAS 兼容）</label>
  </div>
  <div class="dlg-pane" data-pane="hc">
    <p class="hint" style="margin-top:0">仅「反向代理」类型生效。后端连续失败达到上限会被暂时摘除，恢复后自动加回。</p>
    <label class="checkline"><input type="checkbox" class="s-hc-on" ${(s.health && s.health.enabled) ? "checked" : ""}> 启用健康检查</label>
    <div style="display:flex;gap:10px">
      <label style="flex:1">检查类型 <select class="s-hc-type">
        <option value="http" ${(!s.health || !s.health.type || s.health.type === "http") ? "selected" : ""}>HTTP</option>
        <option value="tcp" ${(s.health && s.health.type === "tcp") ? "selected" : ""}>TCP</option></select></label>
      <label style="flex:1">检查路径（HTTP 类型） <input class="s-hc-path" value="${esc((s.health && s.health.path) || "")}" placeholder="/health"></label>
    </div>
    <div style="display:flex;gap:10px">
      <label style="flex:1">间隔（秒） <input class="s-hc-interval" type="number" min="1" value="${(s.health && s.health.interval) || 10}"></label>
      <label style="flex:1">超时（秒） <input class="s-hc-timeout" type="number" min="1" value="${(s.health && s.health.timeout) || 3}"></label>
      <label style="flex:1">失败上限 <input class="s-hc-max" type="number" min="1" value="${(s.health && s.health.maxFailed) || 3}"></label>
    </div>
  </div>`;
}

// collectSub 从子规则对话框收集数据（字段与 WebSubRule 对齐）
function collectSub(dlg) {
  const q = sel => dlg.querySelector(sel);
  return {
    id: q(".s-id").value || uid(),
    name: q(".s-name").value.trim() || "子规则",
    type: q(".s-type").value || "proxy",
    target: q(".s-target").value.trim(),
    statusCode: Number(q(".s-code").value) || 0,
    docRoot: q(".s-docroot").value.trim(),
    domains: lines(q(".s-domains").value),
    backends: lines(q(".s-backends").value),
    basicUser: q(".s-user").value.trim(),
    basicPass: q(".s-pass").value,
    filterMode: q(".s-fmode").value,
    filterIPs: lines(q(".s-fips").value),
    groupID: q(".s-group").value,
    locations: lines(q(".s-locations").value),
    weights: nums(q(".s-weights").value),
    uaMode: q(".s-uamode").value || "none",
    uaList: lines(q(".s-ualist").value),
    customRobot: q(".s-robot").checked,
    robotTxt: q(".s-robottxt").value,
    setHeaders: kvs(q(".s-seth").value),
    hideHeaders: lines(q(".s-hideh").value),
    addHeaders: kvs(q(".s-addh").value),
    appendClientIPHeader: q(".s-appendip").value.trim(),
    insecureSkipTLS: q(".s-insecure").checked,
    useTargetHost: q(".s-uh").checked,
    lb: {
      policy: q(".s-policy").value,
      maxActive: Number(q(".s-maxactive").value) || 0,
      retryCount: Number(q(".s-retry").value) || 0,
    },
    health: {
      enabled: q(".s-hc-on").checked,
      type: q(".s-hc-type").value,
      interval: Number(q(".s-hc-interval").value) || 10,
      timeout: Number(q(".s-hc-timeout").value) || 3,
      maxFailed: Number(q(".s-hc-max").value) || 3,
      path: q(".s-hc-path").value.trim(),
    },
  };
}

// subDlgOpen 打开子规则编辑对话框（叠在主对话框之上的第二层 dialog）
function subDlgOpen(title, s, onSave) {
  const dlg = $("#dlg2");
  dlg.innerHTML = `<h3>${esc(title)}</h3>${subDlgHTML(s)}<div class="row">
    <button class="btn" onclick="dlg2Close()">取消</button>
    <button class="btn primary" id="dlg2-save">保存</button></div>`;
  bindTabs(dlg);
  subTypeToggle(dlg.querySelector(".s-type"));
  $("#dlg2-save").onclick = () => {
    try {
      const p = onSave(collectSub(dlg));
      if (p && typeof p.then === "function") { // 异步保存（如卡片上直接改子规则要提交接口）
        p.then(() => dlg2Close()).catch(e => alert(e.message));
        return;
      }
      dlg2Close();
    }
    catch (e) { alert(e.message); }
  };
  dlg.showModal();
}

// renderWebSubs 渲染主对话框「子规则」标签页的列表
function renderWebSubs() {
  const box = $("#f-subs-list");
  if (!box) return;
  const subs = window.__webSubs || [];
  box.innerHTML = subs.map((s, i) => {
    const type = s.type || "proxy";
    const dst = type === "file" ? (s.docRoot || "（未设目录）")
      : (type === "redirect" || type === "urljump") ? (s.target || "（未设目标）")
      : ((s.backends || []).join(", ") || "（未设后端）");
    const match = [...(s.domains || []), ...(s.locations || [])].join(" ") || "全部请求";
    const tags = [];
    if (s.basicUser) tags.push("BasicAuth");
    if (s.uaMode && s.uaMode !== "none") tags.push(`UA${s.uaMode === "white" ? "白" : "黑"}名单`);
    if (s.groupID) tags.push("安全组");
    else if (s.filterMode && s.filterMode !== "none") tags.push(`IP${s.filterMode === "white" ? "白" : "黑"}名单`);
    if (s.customRobot) tags.push("robots.txt");
    if (s.health && s.health.enabled && type === "proxy") tags.push("健康检查");
    return `<div class="sublist-row">
      <div class="sl-main">
        <div class="sl-name">${esc(s.name || "未命名")} <span class="badge">${SUB_TYPE_NAMES[type] || "反向代理"}</span>${tags.length ? `<span class="sl-tags">${esc(tags.join("、"))}</span>` : ""}</div>
        <div class="sl-sub">匹配 ${esc(match)} → ${esc(dst)}</div>
      </div>
      <button class="btn sm" onclick="webSubEdit(${i})">编辑</button>
      <button class="btn sm danger" onclick="webSubDel(${i})">删除</button>
    </div>`;
  }).join("") || `<p class="hint">暂无子规则。不配置时，所有请求走「基础设置」里的默认后端。</p>`;
}

function webSubAdd() {
  const s = {
    id: uid(), name: "", type: "proxy", domains: [], locations: [], backends: [], weights: [],
    filterMode: "none", filterIPs: [], uaMode: "none", uaList: [],
    lb: { policy: "roundrobin", maxActive: 0, retryCount: 0 },
    health: { enabled: false, type: "http", interval: 10, timeout: 3, maxFailed: 3, path: "" },
  };
  subDlgOpen("添加子规则", s, sub => { window.__webSubs.push(sub); renderWebSubs(); });
}
function webSubEdit(i) {
  const s = (window.__webSubs || [])[i];
  if (!s) return;
  subDlgOpen("编辑子规则：" + (s.name || "未命名"), JSON.parse(JSON.stringify(s)),
    sub => { window.__webSubs[i] = sub; renderWebSubs(); });
}
function webSubDel(i) {
  if (!confirm("确定删除该子规则？")) return;
  window.__webSubs.splice(i, 1);
  renderWebSubs();
}

// 服务类型切换：按类型显隐 后端/跳转/静态目录/状态码 区块，并隐藏不适用的标签页
function subTypeToggle(sel) {
  const box = sel.closest(".subrow") || sel.closest("dialog");
  const t = sel.value;
  box.querySelectorAll(".s-proxy-only").forEach(e => e.style.display = t === "proxy" ? "" : "none");
  box.querySelectorAll(".s-jump-only").forEach(e => e.style.display = (t === "redirect" || t === "urljump") ? "" : "none");
  box.querySelectorAll(".s-file-only").forEach(e => e.style.display = t === "file" ? "" : "none");
  box.querySelectorAll(".s-code-only").forEach(e => e.style.display = t === "redirect" ? "" : "none");
  // Header 与健康检查仅反向代理类型有意义
  ["hdr", "hc"].forEach(pane => {
    const tab = box.querySelector(`.dlg-tab[data-pane="${pane}"]`);
    if (tab) tab.style.display = t === "proxy" ? "" : "none";
  });
  const active = box.querySelector(".dlg-pane.active");
  if (active && (active.dataset.pane === "hdr" || active.dataset.pane === "hc") && t !== "proxy") {
    const base = box.querySelector('.dlg-tab[data-pane="base"]');
    if (base) base.click();
  }
}

function webEdit(id) {
  const exist = webRules.find(x => x.id === id);
  const r = exist || {
    id: uid(), name: "", listenIP: "", port: 8080, tlsCertFile: "", tlsKeyFile: "",
    defaultBackends: [], subRules: [], enabled: true,
  };
  // 子规则暂存区：编辑过程不直接改 webRules，点保存才整体提交
  window.__webSubs = JSON.parse(JSON.stringify(r.subRules || []));
  dlgForm(exist ? "编辑 Web 服务规则" : "添加 Web 服务规则", `
    <div class="dlg-tabs">
      <button class="dlg-tab active" data-pane="base">基础设置</button>
      <button class="dlg-tab" data-pane="sec">HTTPS 与安全</button>
      <button class="dlg-tab" data-pane="subs">子规则</button>
    </div>
    <div class="dlg-pane active" data-pane="base">
      <label>规则名称 <input id="f-name" value="${esc(r.name)}" placeholder="如：游戏站反代"></label>
      <div style="display:flex;gap:10px">
        <label style="flex:1">监听地址（只填 IP） <input id="f-lip" value="${esc(r.listenIP)}" placeholder="留空=全部网卡 / 0.0.0.0"></label>
        <label style="flex:1">监听端口 <input id="f-port" type="number" value="${r.port}"></label>
      </div>
      <p class="hint">⚠ 监听地址只填 <b>IP</b>；<b>域名请填到「子规则」标签页的前端域名</b>，填在这里会导致端口绑定失败。</p>
      <label>引用证书（HTTPS） <select id="f-certid"><option value="">不使用 / 使用下方文件路径</option>
        ${sslCerts.filter(c => c.status === "ok").map(c => `<option value="${esc(c.id)}" ${r.certID === c.id ? "selected" : ""}>${esc(c.domain)}</option>`).join("")}</select></label>
      <div style="display:flex;gap:10px">
        <label style="flex:1">证书文件路径（可选） <input id="f-cert" value="${esc(r.tlsCertFile)}"></label>
        <label style="flex:1">私钥文件路径（可选） <input id="f-key" value="${esc(r.tlsKeyFile)}"></label>
      </div>
      <label>默认后端地址（未匹配任何子规则时兜底，每行一个） <textarea id="f-default" rows="2" style="width:100%">${esc((r.defaultBackends || []).join("\n"))}</textarea></label>
      <div style="display:flex;gap:10px">
        <label style="flex:1">分组 <select id="f-group-tag"><option value="">不分组</option>
          ${(window.__groups || []).map(g => `<option value="${esc(g.id)}" ${r.groupID === g.id ? "selected" : ""}>${esc(g.name)}</option>`).join("")}</select></label>
        <label style="flex:1">备注 <input id="f-remark" value="${esc(r.remark || "")}" placeholder="可选说明"></label>
      </div>
      <label class="checkline"><input type="checkbox" id="f-waf" ${r.wafEnabled ? "checked" : ""}> 启用 Coraza WAF（SQLi/XSS/扫描器拦截）</label>
      <label class="checkline"><input type="checkbox" id="f-enabled" ${r.enabled ? "checked" : ""}> 启用规则</label>
    </div>
    <div class="dlg-pane" data-pane="sec">
      <h4>HTTPS</h4>
      <label class="checkline"><input type="checkbox" id="f-sameport" ${r.samePortTLS ? "checked" : ""}>同一端口同时接受 HTTP 和 HTTPS</label>
      <p class="hint" id="f-sameport-warn" style="color:var(--warning-text);display:none">
        ⚠ 未选择证书，此选项不会生效。请在「基础设置」选择证书库证书或填写证书/私钥文件路径。</p>
      <p class="hint">开启后 <code>http://域名:端口</code> 与 <code>https://域名:端口</code> 都可用，无需为 HTTPS 单独开端口。</p>
      <label class="checkline"><input type="checkbox" id="f-redirect" ${r.redirectToHTTPS ? "checked" : ""}>自动将 HTTP 请求跳转到 HTTPS</label>
      <p class="hint" id="f-redirect-warn" style="color:var(--warning-text);display:none">
        ⚠ 未配置证书时，跳转后浏览器会因 TLS 握手失败而无法访问。</p>
      <div style="display:flex;gap:10px">
        <label style="flex:1">跳转状态码 <select id="f-redirect-code">
          <option value="301" ${(!r.redirectCode || r.redirectCode === 301) ? "selected" : ""}>301 永久重定向</option>
          <option value="302" ${r.redirectCode === 302 ? "selected" : ""}>302 临时重定向</option>
          <option value="308" ${r.redirectCode === 308 ? "selected" : ""}>308 永久重定向（保留方法）</option></select></label>
        <label style="flex:1">不跳转的路径（逗号分隔） <input id="f-redirect-exclude" value="${esc((r.redirectExclude || []).join(","))}" placeholder="/.well-known/,/health"></label>
      </div>
      <h4>可信代理 / CDN 网段</h4>
      <label>每行一条，用于还原真实客户端 IP；留空不信任 <textarea id="f-trusted" rows="2" style="width:100%">${esc((r.trustedCIDRs || []).join("\n"))}</textarea></label>
      <h4>跨域（CORS）</h4>
      <label class="checkline"><input type="checkbox" id="f-cors" ${r.corsEnabled ? "checked" : ""}> 启用跨域支持</label>
      <div id="f-cors-box" style="display:${r.corsEnabled ? "block" : "none"}">
        <div style="display:flex;gap:10px">
          <label style="flex:1">允许的来源 <input id="f-cors-origin" value="${esc(r.corsOrigin || "*")}" placeholder="* 或 https://a.com"></label>
          <label style="flex:1">允许的方法 <input id="f-cors-methods" value="${esc(r.corsMethods || "")}" placeholder="GET,POST,PUT,DELETE"></label>
        </div>
        <label>允许的请求头 <input id="f-cors-headers" value="${esc(r.corsHeaders || "")}" placeholder="Content-Type,Authorization"></label>
        <label class="checkline"><input type="checkbox" id="f-cors-cred" ${r.corsCredentials ? "checked" : ""}> 允许携带凭据（Cookie）</label>
      </div>
    </div>
    <div class="dlg-pane" data-pane="subs">
      <p class="hint" style="margin-top:0">子规则决定「什么请求交给谁处理」：按<b>前端域名 / URL 路径</b>匹配，命中后执行反向代理、跳转或静态文件。</p>
      <div id="f-subs-list"></div>
      <button class="btn sm" onclick="webSubAdd()">+ 添加子规则</button>
    </div>
  `, async dlg => {
    const subs = window.__webSubs || [];
    const seen = {};
    for (const s of subs) for (const d of (s.domains || [])) {
      const k = d.toLowerCase();
      if (seen[k]) throw new Error("前端域名冲突: " + d);
      seen[k] = true;
    }
    const nr = {
      id: r.id, name: $("#f-name", dlg).value.trim() || "未命名",
      listenIP: $("#f-lip", dlg).value.trim(), port: Number($("#f-port", dlg).value) || 8080,
      tlsCertFile: $("#f-cert", dlg).value.trim(), tlsKeyFile: $("#f-key", dlg).value.trim(),
      certID: $("#f-certid", dlg).value,
      wafEnabled: $("#f-waf", dlg).checked,
      trustedCIDRs: lines($("#f-trusted", dlg).value),
      samePortTLS: $("#f-sameport", dlg).checked,
      redirectToHTTPS: $("#f-redirect", dlg).checked,
      redirectCode: Number($("#f-redirect-code", dlg).value) || 301,
      redirectExclude: lines($("#f-redirect-exclude", dlg).value),
      groupID: $("#f-group-tag", dlg).value,
      remark: $("#f-remark", dlg).value.trim(),
      corsEnabled: $("#f-cors", dlg).checked,
      corsOrigin: $("#f-cors-origin", dlg).value.trim(),
      corsMethods: $("#f-cors-methods", dlg).value.trim(),
      corsHeaders: $("#f-cors-headers", dlg).value.trim(),
      corsCredentials: $("#f-cors-cred", dlg).checked,
      defaultBackends: lines($("#f-default", dlg).value), subRules: subs,
      enabled: $("#f-enabled", dlg).checked,
    };
    webRules = webRules.filter(x => x.id !== r.id); webRules.push(nr);
    await api("/api/webrules", { method: "POST", body: JSON.stringify(webRules) });
    delete window.__webSubs;
    loadWeb();
  });
  renderWebSubs();
}

async function webDel(id) {
  if (!confirm("确定删除该规则？")) return;
  webRules = webRules.filter(x => x.id !== id);
  await api("/api/webrules", { method: "POST", body: JSON.stringify(webRules) });
  loadWeb();
}

async function webLogs(id) {
  const box = $("#web-" + id + " .logbox");
  if (!box) return;
  box.innerHTML = `<pre class="logs">加载中…</pre>`; // 立即反馈，避免"点了没反应"
  try {
    const logs = await api("/api/webrules/logs?id=" + encodeURIComponent(id));
    box.innerHTML = logs && logs.length
      ? `<pre class="logs">${esc(logs.join("\n"))}</pre>`
      : `<pre class="logs">暂无日志</pre>`;
  } catch (e) {
    box.innerHTML = `<pre class="logs">读取失败：${esc(e.message)}</pre>`;
  }
}

// ---- 子规则快捷操作：统计浮窗 / 记录浮窗 / 编辑 / 删除 ----

// webSubLogs 子规则独立日志浮窗（后端 subLogs 环，4 秒自动刷新）
async function webSubLogs(ruleId, subId) {
  const r = webRules.find(x => x.id === ruleId);
  const sub = ((r && r.subRules) || []).find(s => s.id === subId);
  const dlg = $("#dlg2");
  dlg.innerHTML = `<h3>子规则记录 · ${esc((sub && sub.name) || subId)}</h3>
    <div id="sub-logs-body"><pre class="logs">加载中…</pre></div>
    <div class="row"><button class="btn" onclick="dlg2Close()">关闭</button></div>`;
  dlg.showModal();
  const render = async () => {
    if (!dlg.open) return;
    const body = $("#sub-logs-body");
    if (!body) return;
    try {
      const logs = await api("/api/webrules/logs?id=" + encodeURIComponent(ruleId) +
        "&sub=" + encodeURIComponent(subId));
      body.innerHTML = logs && logs.length
        ? `<pre class="logs">${esc(logs.join("\n"))}</pre>`
        : `<pre class="logs">暂无日志</pre>`;
    } catch (e) {
      body.innerHTML = `<pre class="logs">读取失败：${esc(e.message)}</pre>`;
    }
  };
  await render();
  const timer = setInterval(() => { if (dlg.open) render(); }, 4000);
  dlg.addEventListener("close", () => clearInterval(timer), { once: true });
}

// webSubEditAt 卡片上直接编辑某条子规则（不进主编辑对话框），保存后提交全量列表
function webSubEditAt(ruleId, subId) {
  const r = webRules.find(x => x.id === ruleId);
  if (!r) return;
  const i = (r.subRules || []).findIndex(s => s.id === subId);
  if (i < 0) return;
  subDlgOpen("编辑子规则：" + (r.subRules[i].name || "未命名"), JSON.parse(JSON.stringify(r.subRules[i])), async sub => {
    r.subRules[i] = sub;
    await api("/api/webrules", { method: "POST", body: JSON.stringify(webRules) });
    loadWeb();
  });
}

// webSubDelAt 卡片上直接删除子规则
async function webSubDelAt(ruleId, subId) {
  const r = webRules.find(x => x.id === ruleId);
  if (!r) return;
  const sub = (r.subRules || []).find(s => s.id === subId);
  if (!sub) return;
  if (!confirm(`确定删除子规则「${sub.name || subId}」？`)) return;
  r.subRules = (r.subRules || []).filter(s => s.id !== subId);
  await api("/api/webrules", { method: "POST", body: JSON.stringify(webRules) });
  loadWeb();
}

/* ---------- DDNS ---------- */
let ddnsTasks = [];
async function loadDDNS() {
  ddnsTasks = (await api("/api/ddns")) || [];
  const st = await api("/api/ddns/status");
  renderGroupBar("ddns-groupbar", "ddns");
  countUp($("#ddns-hero-count"), ddnsTasks.length, 900); // 横幅翻牌数字
  const ddnsShown = ddnsTasks.filter(t => inGroup(t, "ddns"));
  $("#ddns-list").innerHTML = ddnsShown.map(t => {
    const s = st[t.id] || (t.enabled ? "运行中" : "未运行");
    const cls = s.includes("异常") ? "err" : (s.includes("等待") || s === "未运行" ? "off" : "on");
    const meta = [
      metric("服务商", (t.provider || "").toUpperCase(), "mono"),
      metric("域名", (t.domains || []).join(", "), "mono"),
      metric("IPv4", t.ipv4 ? "同步" : "关闭", t.ipv4 ? "green" : ""),
      metric("IPv6", t.ipv6 ? "同步" : "关闭", t.ipv6 ? "green" : ""),
      metric("间隔", (t.intervalSec || 60) + " 秒"),
      t.webhook && t.webhook.url ? metric("Webhook", "已配置", "amber") : "",
      t.groupTag ? metric("分组", groupName(t.groupTag), "blue") : "",
    ].join("");
    return ruleCard("ddns-" + t.id, t.name, t.enabled,
      `<span class="badge ${cls}">${esc(s)}</span>`,
      `<div class="metrics">${meta}</div>`,
      { logs: `ddnsStatus('${t.id}')`, edit: `ddnsEdit('${t.id}')`, del: `ddnsDel('${t.id}')` });
  }).join("") || emptyState("暂无 DDNS 任务", "点击右上角「添加任务」绑定第一个域名");
}

function ddnsEdit(id) {
  const t = ddnsTasks.find(x => x.id === id) || {
    id: uid(), name: "", provider: "cloudflare", token: "", accessKeyID: "", accessKey: "",
    domains: [], ipv4: true, ipv6: false, intervalSec: 300, enabled: true,
    ipSource: "api", ipUrls: [], ipInterface: "", ipCmd: "", ttl: 0, cacheTimes: 0,
    callbackURL: "", callbackMethod: "", callbackBody: "",
  };
  dlgForm(id ? "编辑 DDNS 任务" : "添加 DDNS 任务", `
    <label>任务名称 <input id="f-name" value="${esc(t.name)}"></label>
    <label>DNS 服务商 <select id="f-provider" onchange="ddnsProviderChanged()">
      <option value="cloudflare" ${t.provider === "cloudflare" ? "selected" : ""}>Cloudflare</option>
      <option value="dnspod" ${t.provider === "dnspod" ? "selected" : ""}>DNSPod（腾讯云）</option>
      <option value="aliyun" ${t.provider === "aliyun" ? "selected" : ""}>阿里云 DNS</option>
      <option value="huaweicloud" ${t.provider === "huaweicloud" ? "selected" : ""}>华为云 DNS</option>
      <option value="godaddy" ${t.provider === "godaddy" ? "selected" : ""}>GoDaddy</option>
      <option value="porkbun" ${t.provider === "porkbun" ? "selected" : ""}>Porkbun</option>
      <option value="namecheap" ${t.provider === "namecheap" ? "selected" : ""}>Namecheap</option>
      <option value="namesilo" ${t.provider === "namesilo" ? "selected" : ""}>NameSilo</option>
      <option value="dnshe" ${t.provider === "dnshe" ? "selected" : ""}>DNSHE 免费域名</option>
      <option value="callback" ${t.provider === "callback" ? "selected" : ""}>Callback（自定义回调）</option></select></label>
    <p class="hint" id="f-dnshe-tip" style="display:${t.provider === "dnshe" ? "block" : "none"};margin:-4px 0 6px">
      DNSHE 使用 API Key + API Secret（控制台「API 管理」中创建）。域名需先在 DNSHE 免费注册为子域名，例如 <code>myapp.example.com</code>。<br>
      支持通配符：填 <code>*.myapp.example.com</code> 会创建 <code>*</code> 记录（所有子域生效）；直接填 <code>myapp.example.com</code> 则更新根记录 <code>@</code>。
    </p>
    <div id="f-cred-block">
      <label><span id="f-token-label">Token（Cloudflare 用 API Token；DNSPod 用 ID,Token 格式）</span> <input id="f-token" value="${esc(t.token)}"></label>
      <div id="f-dnshe-actions" style="display:none;margin:-6px 0 8px">
        <button type="button" class="btn sm" onclick="fetchDNSHEDomains(this)">拉取我的子域名（校验凭据）</button>
        <div id="f-dnshe-list" class="hint" style="margin-top:6px"></div>
      </div>
      <div style="display:flex;gap:10px">
        <label style="flex:1"><span id="f-akid-label">AccessKeyID（阿里云）</span> <input id="f-akid" value="${esc(t.accessKeyID)}"></label>
        <label style="flex:1"><span id="f-ak-label">AccessKey（阿里云）</span> <input id="f-ak" value="${esc(t.accessKey)}"></label>
      </div>
    </div>
    <div id="f-callback-block" style="display:${t.provider === "callback" ? "block" : "none"};margin:-4px 0 6px">
      <h4>Callback 自定义回调</h4>
      <p class="hint" style="margin:-4px 0 6px">回调地址支持变量 <code>#{ip}</code> <code>#{domain}</code> <code>#{recordType}</code> <code>#{ttl}</code>，可对接任意 DNS 服务商的更新接口。</p>
      <label>回调地址 <input id="f-cburl" value="${esc(t.callbackURL || "")}" placeholder="https://example.com/update?domain=#{domain}&amp;ip=#{ip}"></label>
      <div style="display:flex;gap:10px">
        <label>方法 <select id="f-cbmethod">
          <option value="" ${(t.callbackMethod || "") === "" ? "selected" : ""}>自动（有请求体用 POST）</option>
          <option value="GET" ${t.callbackMethod === "GET" ? "selected" : ""}>GET</option>
          <option value="POST" ${t.callbackMethod === "POST" ? "selected" : ""}>POST</option>
        </select></label>
        <label style="flex:1">请求体模板 <input id="f-cbbody" value="${esc(t.callbackBody || "")}" placeholder='{"ip":"#{ip}","domain":"#{domain}"}'></label>
      </div>
    </div>
    <label>域名（多个逗号分隔，如 home.example.com） <input id="f-domains" value="${esc((t.domains || []).join(","))}"></label>
    <div style="display:flex;gap:16px">
      <label class="checkline"><input type="checkbox" id="f-v4" ${t.ipv4 ? "checked" : ""}> 同步 IPv4</label>
      <label class="checkline"><input type="checkbox" id="f-v6" ${t.ipv6 ? "checked" : ""}> 同步 IPv6</label>
      <label style="flex:1">同步间隔(秒) <input id="f-interval" type="number" value="${t.intervalSec}"></label>
      <label style="flex:1">TTL(秒,0=默认) <input id="f-ttl" type="number" value="${t.ttl || 0}"></label>
      <label style="flex:1">每N轮比对(0=每轮) <input id="f-cachetimes" type="number" value="${t.cacheTimes || 0}"
        title="IP 未变时隔 N 轮才与服务商比对一次，防止触发接口限流"></label>
    </div>
    <h4 style="margin-top:14px">获取公网 IP</h4>
    <div style="display:flex;gap:10px">
      <label style="flex:1">方式 <select id="f-ipsrc" onchange="ddnsIPSChanged()">
        <option value="api" ${(t.ipSource || "api") === "api" ? "selected" : ""}>接口获取</option>
        <option value="netiface" ${t.ipSource === "netiface" ? "selected" : ""}>网卡获取</option>
        <option value="cmd" ${t.ipSource === "cmd" ? "selected" : ""}>自定义指令</option>
      </select></label>
      <label style="flex:2">自定义接口（每行一个，失败自动回退内置多源） <textarea id="f-ipurls" rows="2"
        placeholder="留空用内置接口（ipify/icanhazip/ipinfo 等）">${esc((t.ipUrls || []).join("\n"))}</textarea></label>
      <label style="flex:1">网卡名 <input id="f-ipiface" value="${esc(t.ipInterface || "")}"
        placeholder="如 eth0，留空自动"></label>
      <label style="flex:2">自定义指令 <input id="f-ipcmd" value="${esc(t.ipCmd || "")}"
        placeholder="如 curl -s https://api.ipify.org（stdout 输出 IP）"></label>
    </div>
    <h4 style="margin-top:14px">变更通知 Webhook（可选）</h4>
    ${WHTemplate("ddnswh", t.webhook, "DDNS 专属：<code>#{ipv4Addr}</code> <code>#{ipv4Result}</code> <code>#{ipv4Domains}</code> <code>#{ipv6Addr}</code> <code>#{ipv6Result}</code> <code>#{ipv6Domains}</code> <code>#{provider}</code> <code>#{domains}</code>")}

    <div style="display:flex;gap:10px">
      <label style="flex:1">分组 <select id="f-ddns-group"><option value="">不分组</option>
        ${(window.__groups || []).map(g => `<option value="${esc(g.id)}" ${t.groupTag === g.id ? "selected" : ""}>${esc(g.name)}</option>`).join("")}</select></label>
      <label style="flex:1">备注 <input id="f-ddns-remark" value="${esc(t.remark || "")}" placeholder="可选"></label>
    </div>
    <label class="checkline"><input type="checkbox" id="f-enabled" ${t.enabled ? "checked" : ""}> 吷用任务</label>
  `, async dlg => {
    const nt = {
      id: t.id, name: $("#f-name", dlg).value.trim() || "未命名",
      provider: $("#f-provider", dlg).value, token: $("#f-token", dlg).value.trim(),
      accessKeyID: $("#f-akid", dlg).value.trim(), accessKey: $("#f-ak", dlg).value.trim(),
      domains: lines($("#f-domains", dlg).value),
      ipv4: $("#f-v4", dlg).checked, ipv6: $("#f-v6", dlg).checked,
      intervalSec: Number($("#f-interval", dlg).value) || 300, enabled: $("#f-enabled", dlg).checked,
      groupTag: $("#f-ddns-group", dlg).value,
      remark: $("#f-ddns-remark", dlg).value.trim(),
      webhook: WHRead("ddnswh", dlg),
      ipSource: $("#f-ipsrc", dlg).value,
      ipUrls: lines($("#f-ipurls", dlg).value),
      ipInterface: $("#f-ipiface", dlg).value.trim(),
      ipCmd: $("#f-ipcmd", dlg).value.trim(),
      ttl: Number($("#f-ttl", dlg).value) || 0,
      cacheTimes: Number($("#f-cachetimes", dlg).value) || 0,
      callbackURL: $("#f-cburl", dlg).value.trim(),
      callbackMethod: $("#f-cbmethod", dlg).value,
      callbackBody: $("#f-cbbody", dlg).value,
    };
    if (nt.provider === "callback" && !nt.callbackURL) throw new Error("Callback 需要填写回调地址");
    if (!nt.domains.length) throw new Error("请填写域名");
    ddnsTasks = ddnsTasks.filter(x => x.id !== t.id); ddnsTasks.push(nt);
    await api("/api/ddns", { method: "POST", body: JSON.stringify(ddnsTasks) });
    loadDDNS();
  });
  ddnsProviderChanged();
  ddnsIPSChanged();
}

// ddnsProviderChanged 按所选服务商切换凭据区的标签、显隐与提示
function ddnsProviderChanged() {
  const p = ($("#f-provider") || {}).value;
  const cred = {
    cloudflare: { token: "Cloudflare API Token" },
    dnspod: { token: "DNSPod Token（ID,Token 格式）" },
    aliyun: { akid: "阿里云 AccessKeyID", ak: "阿里云 AccessKey" },
    dnshe: { token: "DNSHE API Key", ak: "DNSHE API Secret", dnshe: true },
    huaweicloud: { akid: "华为云 AK（Access Key Id）", ak: "华为云 SK（Secret Access Key）" },
    godaddy: { token: "GoDaddy 凭据（API Key,Secret 逗号组合）" },
    porkbun: { token: "Porkbun 凭据（API Key,Secret 逗号组合）" },
    namecheap: { akid: "Namecheap ApiUser（账号用户名）", ak: "Namecheap ApiKey" },
    namesilo: { token: "NameSilo API Key" },
    callback: { hidden: true },
  }[p] || {};
  const set = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
  if (cred.hidden) {
    $("#f-cred-block").style.display = "none";
    $("#f-callback-block").style.display = "block";
  } else {
    $("#f-cred-block").style.display = "block";
    $("#f-callback-block").style.display = "none";
    set("f-token-label", cred.token || "Token（Cloudflare 用 API Token；DNSPod 用 ID,Token 格式）");
    set("f-akid-label", cred.akid || "AccessKeyID（阿里云）");
    set("f-ak-label", cred.ak || "AccessKey（阿里云）");
    // 没有对应凭据的行隐藏，避免误填
    const showToken = !!cred.token;
    const showAK = !!(cred.akid || cred.ak);
    $("#f-token").closest("label").style.display = showToken ? "" : "none";
    $("#f-akid").closest("label").style.display = showAK && cred.akid ? "" : "none";
    $("#f-ak").closest("label").style.display = showAK && cred.ak ? "" : "none";
  }
  const tip = $("#f-dnshe-tip");
  if (tip) tip.style.display = cred.dnshe ? "block" : "none";
  const act = $("#f-dnshe-actions");
  if (act) act.style.display = cred.dnshe ? "block" : "none";
}

// ddnsIPSChanged 按获取 IP 方式高亮对应的输入框（其余留灰不隐藏，便于互相参照）
function ddnsIPSChanged() {
  const v = ($("#f-ipsrc") || {}).value || "api";
  const dim = (id, on) => { const el = document.getElementById(id); if (el) el.style.opacity = on ? "1" : "0.45"; };
  dim("f-ipurls", v === "api");
  dim("f-ipiface", v === "netiface");
  dim("f-ipcmd", v === "cmd");
  const ph = { api: "留空用内置接口（ipify/icanhazip/ipinfo 等）", netiface: "如 eth0，留空自动按默认路由判断", cmd: "如 curl -s https://api.ipify.org（stdout 输出 IP）" };
  const el = document.getElementById("f-ipcmd");
  if (el) el.placeholder = ph[v];
}

// fetchDNSHEDomains 用当前填写凭据拉取 DNSHE 子域名列表
async function fetchDNSHEDomains(btn) {
  const dlg = document.querySelector("#dlg");
  const key = dlg.querySelector("#f-token").value.trim();
  const secret = dlg.querySelector("#f-ak").value.trim();
  const box = dlg.querySelector("#f-dnshe-list");
  if (!key || !secret) { box.textContent = "请先填写 API Key 与 API Secret"; return; }
  box.textContent = "查询中…";
  btn.disabled = true;
  try {
    const q = new URLSearchParams({ key, secret });
    const r = await api("/api/ddns/dnshe/domains?" + q);
    if (!r.count) {
      box.textContent = "凭据有效，但账号下还没有子域名。请先到 DNSHE 控制台免费注册。";
    } else {
      box.innerHTML = `凭据有效，共 ${r.count} 个子域名：<br>` +
        r.domains.slice(0, 30).map(d => `<code>${esc(d)}</code>`).join(" ") +
        (r.count > 30 ? ` …等 ${r.count} 个` : "");
    }
  } catch (e) {
    box.textContent = "查询失败：" + e.message;
  } finally {
    btn.disabled = false;
  }
}

async function ddnsDel(id) {
  if (!confirm("确定删除该任务？")) return;
  ddnsTasks = ddnsTasks.filter(x => x.id !== id);
  await api("/api/ddns", { method: "POST", body: JSON.stringify(ddnsTasks) });
  loadDDNS();
}

// ddnsStatus 查看该 DDNS 任务的同步记录（在卡片内展开）
async function ddnsStatus(id) {
  const box = document.querySelector("#ddns-" + id + " .logbox");
  if (!box) return;
  // 已展开则收起，实现点击切换
  if (box.dataset.open === "1") {
    box.innerHTML = "";
    box.dataset.open = "0";
    return;
  }
  box.innerHTML = `<pre class="logs">加载中…</pre>`;
  box.dataset.open = "1";
  try {
    const logs = await api("/api/ddns/logs?id=" + encodeURIComponent(id));
    if (!logs || !logs.length) {
      box.innerHTML = `<pre class="logs">暂无同步记录。任务启用后会在每个同步周期执行一次，最近一次结果见上方状态标签。</pre>`;
      return;
    }
    box.innerHTML = `<pre class="logs">${esc(logs.slice().reverse().join("\n"))}</pre>`;
  } catch (e) {
    box.innerHTML = `<pre class="logs">读取失败：${esc(e.message)}</pre>`;
  }
}

/* ---------- 设置 ---------- */
async function loadSettings() {
  const s = await api("/api/settings");
  $("#set-user").value = s.username;
  $("#set-backup-user").value = s.backupUsername || "";
  $("#set-msg").textContent = "配置文件：" + s.configPath;
}
async function saveSettings() {
  $("#set-msg").textContent = "";
  try {
    await api("/api/settings", { method: "POST", body: JSON.stringify({
      username: $("#set-user").value.trim(),
      oldPassword: $("#set-old").value,
      newPassword: $("#set-new").value,
      backupUsername: $("#set-backup-user").value.trim(),
      backupPassword: $("#set-backup-pass").value,
    }) });
    $("#set-msg").textContent = "已保存";
    $("#set-old").value = ""; $("#set-new").value = ""; $("#set-backup-pass").value = "";
  } catch (e) { $("#set-msg").textContent = e.message; }
}

/* ---------- 启动 ---------- */
async function boot() {
  // 后备账号：只提供「配置备份与还原」，其余页面与接口均无权限
  if (sessionRole === "backup") {
    document.body.classList.add("role-backup");
    gotoPage("settings");
    $("#page-settings .page-head h2").textContent = "配置备份与还原";
    loadBackupList().catch(() => {});
    return;
  }
  initMatrixRain();
  loadDashboard();
  // 先取分组，再渲染列表（表单里的分组下拉依赖它）
  try { await loadGroups(); } catch (e) { groups = []; }
  loadPF().catch(() => {});
  loadWeb().catch(() => {});
  loadDDNS().catch(() => {});
  loadSettings().catch(() => {});
}
// 立即恢复主题（在登录页也生效）
initTheme();

// 会话恢复：用 /api/me 判断是否已登录及角色（/api/status 对后备账号是 403）
api("/api/me").then(r => {
  sessionRole = (r && r.role) || "admin";
  $("#app").classList.remove("hidden");
  boot();
}).catch(() => showLogin());

