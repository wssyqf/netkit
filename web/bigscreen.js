/* bigscreen.js —— 数据大屏：核心流量指标 / TOP 榜单 / 实时日志 / 运行状态 */

"use strict";

let bsRefreshTimer = null;
let bsClockTimer = null;
const bsHpSeen = new Set(); // 已渲染过的蜜罐捕获记录键（用于识别新记录）

// stopBigScreen 离开大屏页时停掉秒表与自动刷新（由 gotoPage 调用）
function stopBigScreen() {
  if (bsRefreshTimer) { clearInterval(bsRefreshTimer); bsRefreshTimer = null; }
  if (bsClockTimer) { clearInterval(bsClockTimer); bsClockTimer = null; }
}

// loadBigScreen 进入大屏页：启动时钟、立即渲染、每 5 秒自动刷新
async function loadBigScreen() {
  stopBigScreen();

  const fsBtn = $("#bs-fs");
  if (fsBtn && !fsBtn.dataset.bound) {
    fsBtn.dataset.bound = "1";
    fsBtn.onclick = () => {
      const el = $("#page-bigscreen");
      if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
      else if (el && el.requestFullscreen) el.requestFullscreen().catch(() => {});
    };
  }

  const tickClock = () => {
    const c = $("#bs-clock");
    if (c) c.textContent = new Date().toLocaleTimeString("zh-CN", { hour12: false });
  };
  tickClock();
  bsClockTimer = setInterval(tickClock, 1000);

  await bsRender().catch(() => {});
  bsRefreshTimer = setInterval(() => {
    if (document.body.dataset.page !== "bigscreen") { stopBigScreen(); return; }
    bsRender().catch(() => {});
  }, 5000);
}

// bsMergeStats 把多条规则的统计合并成一份全局数据
function bsMergeStats(arr) {
  const m = {
    requests: 0, bytesIn: 0, bytesOut: 0, blocked: 0, redirected: 0,
    status2xx: 0, status3xx: 0, status4xx: 0, status5xx: 0,
    qps: 0, avgMs: 0, startAt: "", lastAt: "",
    hourly: [], byRule: [], topPaths: [],
  };
  const hourlyMap = new Map();
  const pathMap = new Map();
  let wMsSum = 0, wReq = 0;

  for (const s of arr) {
    m.requests += s.requests || 0;
    m.bytesIn += s.bytesIn || 0;
    m.bytesOut += s.bytesOut || 0;
    m.blocked += s.blocked || 0;
    m.redirected += s.redirected || 0;
    m.status2xx += s.status2xx || 0;
    m.status3xx += s.status3xx || 0;
    m.status4xx += s.status4xx || 0;
    m.status5xx += s.status5xx || 0;
    m.qps += s.qps || 0;
    if (s.requests > 0) { wMsSum += (s.avgMs || 0) * s.requests; wReq += s.requests; }
    if (s.startAt && (!m.startAt || s.startAt < m.startAt)) m.startAt = s.startAt;
    if (s.lastAt && s.lastAt > m.lastAt) m.lastAt = s.lastAt;

    for (const h of s.hourly || []) hourlyMap.set(h.hour, (hourlyMap.get(h.hour) || 0) + (h.requests || 0));
    for (const r of s.byRule || []) m.byRule.push(r);
    for (const p of s.topPaths || []) {
      const old = pathMap.get(p.path);
      if (old) {
        old.requests += p.requests || 0;
        old.bytesOut += p.bytesOut || 0;
        old.avgMs = (old.avgMs + (p.avgMs || 0)) / 2;
      } else pathMap.set(p.path, { ...p });
    }
  }

  m.avgMs = wReq ? wMsSum / wReq : 0;
  m.hourly = [...hourlyMap.entries()].map(([hour, requests]) => ({ hour, requests }));
  m.byRule.sort((a, b) => (b.requests || 0) - (a.requests || 0));
  m.topPaths = [...pathMap.values()].sort((a, b) => (b.requests || 0) - (a.requests || 0));
  return m;
}

// bsRankList 渲染 TOP 榜单行（序号 / 名称 / 请求量 / 占比条）
function bsRankList(items, nameOf, valOf, subOf) {
  if (!items.length) return `<p class="bs-empty">暂无数据</p>`;
  const max = Math.max(...items.map(x => valOf(x)), 1);
  return items.map((it, i) => {
    const v = valOf(it);
    const pct = Math.max(3, Math.round(v / max * 100));
    return `<div class="bs-rank">
      <span class="n">${i + 1}</span>
      <div class="body">
        <div class="line"><span class="t" title="${esc(nameOf(it))}">${esc(nameOf(it))}</span>
          <span class="c">${fmtNum(v)}</span></div>
        <div class="track"><i style="width:${pct}%"></i></div>
      </div>
      <span class="s">${esc(subOf(it))}</span>
    </div>`;
  }).join("");
}

async function bsRender() {
  const status = await api("/api/status");
  const rules = ((await api("/api/webrules")) || []).filter(r => r.enabled !== false);
  const ids = rules.map(r => r.id);

  const [statsArr, logsArr, hpLog, ipvData] = await Promise.all([
    Promise.all(ids.map(id => api("/api/webrules/stats?id=" + encodeURIComponent(id) + "&top=10"))),
    Promise.all(ids.map(id => api("/api/webrules/logs?id=" + encodeURIComponent(id)))),
    api("/api/honeypot/logs?limit=12").catch(() => ({ records: [] })),
    api("/api/ipvisitors?limit=500").catch(() => ({ list: [], total: 0 })),
  ]);
  const S = bsMergeStats(statsArr);

  // —— 核心流量指标 ——
  const kpis = [
    { l: "总请求数", v: fmtNum(S.requests), u: "" },
    { l: "实时 QPS", v: (S.qps || 0).toFixed(3), u: "" },
    { l: "出站流量", v: fmtBytes(S.bytesOut), u: "" },
    { l: "入站流量", v: fmtBytes(S.bytesIn), u: "" },
    { l: "平均耗时", v: (S.avgMs || 0).toFixed(1), u: "ms" },
    { l: "拦截 / 跳转", v: fmtNum(S.blocked) + " / " + fmtNum(S.redirected), u: "" },
  ];
  const kBox = $("#bs-kpis");
  if (kBox) {
    // 只在首次或数量变化时重建结构，避免每次刷新闪动
    if (kBox.children.length !== kpis.length) {
      kBox.innerHTML = kpis.map(() =>
        `<div class="bs-kpi"><div class="l"></div><div class="v"></div></div>`).join("");
    }
    [...kBox.children].forEach((el, i) => {
      el.querySelector(".l").textContent = kpis[i].l;
      el.querySelector(".v").textContent = kpis[i].v + (kpis[i].u ? " " + kpis[i].u : "");
    });
  }

  // —— 24 小时趋势 ——
  const hourlyBox = $("#bs-hourly");
  if (hourlyBox) {
    const hours = S.hourly;
    const maxH = Math.max(1, ...hours.map(h => h.requests));
    hourlyBox.innerHTML = hours.length
      ? hours.map(h => `<div class="bs-bar" style="height:${Math.max(h.requests > 0 ? 4 : 1, Math.round(h.requests / maxH * 100))}%" title="${esc(h.hour)} — ${h.requests} 次"></div>`).join("")
      : `<p class="bs-empty">暂无数据</p>`;
    const peak = $("#bs-trend-peak");
    if (peak) peak.textContent = hours.length ? `峰值 ${maxH} 次/小时` : "";
    const axis = $("#bs-hourly-axis");
    if (axis) {
      axis.innerHTML = hours.length
        ? `<span>${esc(hours[0].hour)}</span><span>${esc(hours[Math.floor(hours.length / 2)].hour)}</span><span>${esc(hours[hours.length - 1].hour)}</span>`
        : "";
    }
  }

  // —— 状态码分布 ——
  const scBox = $("#bs-scode");
  if (scBox) {
    const total = S.status2xx + S.status3xx + S.status4xx + S.status5xx;
    if (!total) {
      scBox.innerHTML = `<p class="bs-empty">暂无数据</p>`;
    } else {
      const segs = [
        { n: S.status2xx, cls: "s2", name: "2xx 成功" },
        { n: S.status3xx, cls: "s3", name: "3xx 重定向" },
        { n: S.status4xx, cls: "s4", name: "4xx 客户端错误" },
        { n: S.status5xx, cls: "s5", name: "5xx 服务端错误" },
      ];
      scBox.innerHTML =
        `<div class="bs-sbar">${segs.filter(s => s.n > 0).map(s =>
          `<i class="${s.cls}" style="width:${(s.n / total * 100).toFixed(2)}%"></i>`).join("")}</div>
        <div class="bs-slegend">${segs.map(s =>
          `<div><i class="${s.cls}"></i><span>${s.name}</span><b>${fmtNum(s.n)}</b><small>${(s.n / total * 100).toFixed(1)}%</small></div>`).join("")}</div>`;
    }
  }

  // —— 运行状态 ——
  const sysBox = $("#bs-sys");
  if (sysBox) {
    const health = status.health || {};
    const cpu = Math.max(0, Math.min(100, Number(health.cpu) || 0));
    const mem = Math.max(0, Math.min(100, Number(health.mem) || 0));
    const runs = (status.webRunning || 0) + (status.pfRunning || 0);
    sysBox.innerHTML = `
      <div class="bs-sysgrid">
        <div class="bs-chip"><span>CPU</span><b>${cpu}<i>%</i></b>
          <div class="bs-track"><i style="width:${cpu}%"></i></div></div>
        <div class="bs-chip"><span>内存</span><b>${mem}<i>%</i></b>
          <div class="bs-track mem"><i style="width:${mem}%"></i></div></div>
        <div class="bs-chip"><span>运行规则</span><b>${runs}<i>条</i></b></div>
        <div class="bs-chip"><span>WAF 拦截</span><b>${status.wafHits || 0}<i>次</i></b></div>
        <div class="bs-chip"><span>DDNS</span><b>${status.ddns || 0}<i>任务</i></b></div>
        <div class="bs-chip"><span>证书</span><b>${status.sslcerts || 0}<i>张</i></b></div>
        <div class="bs-chip"><span>计划任务</span><b>${status.crons || 0}<i>个</i></b></div>
        <div class="bs-chip"><span>已运行</span><b class="txt">${esc(status.uptime || "-")}</b></div>
      </div>
      <div class="bs-sysfoot">v${esc(status.version || "")} · 后台端口 ${esc(status.adminPort || "")} ·
        健康评分 <b>${health.score ?? 100}</b></div>`;
  }

  // —— 蜜罐诱捕（最新捕获记录，新记录滑入高亮） ——
  const hpBox = $("#bs-honeypot");
  if (hpBox) {
    const recs = (hpLog && hpLog.records) || [];
    const hint = $("#bs-hp-hint");
    if (hint) {
      hint.innerHTML = status.honeypotEnabled
        ? `<span class="bs-live-dot"></span>${status.honeypotPorts || 0} 个诱饵端口在监听 · 累计 ${status.honeypotRecs || 0} 条`
        : "诱捕已关闭";
    }
    hpBox.innerHTML = recs.length ? recs.slice(0, 8).map((r, i) => {
      const key = `${r.time}|${r.ip}|${r.port}`;
      const isNew = !bsHpSeen.has(key);
      bsHpSeen.add(key);
      const cc = (r.geo || "").trim();
      return `<div class="bs-cap${isNew && i === 0 ? " new" : ""}">
        <span class="t">${esc(String(r.time || "").slice(5, 19))}</span>
        <span class="ip">${esc(r.ip || "-")}</span>
        <span class="geo">${esc(cc ? (typeof geoName === "function" ? geoName(cc) : cc) : "未知")}</span>
        <span class="p">:${esc(r.port || "")}</span>
      </div>`;
    }).join("") : `<p class="bs-empty">${status.honeypotEnabled ? "等待入侵者上钩…" : "蜜罐未启用"}</p>`;
    // 只保留本轮记录键，避免集合无限增长
    if (bsHpSeen.size > 400) bsHpSeen.clear();
  }

  // —— 访客地区分布（按国家聚合访问次数 TOP 榜） ——
  const geoBox = $("#bs-geo");
  if (geoBox) {
    const byCC = new Map();
    for (const e of (ipvData && ipvData.list) || []) {
      const cc = (e.cc || "").trim();
      byCC.set(cc, (byCC.get(cc) || 0) + (e.count || 1));
    }
    const items = [...byCC.entries()]
      .map(([cc, n]) => ({ cc, n }))
      .sort((a, b) => b.n - a.n)
      .slice(0, 8);
    const hint = $("#bs-geo-hint");
    if (hint) hint.textContent = `${ipvData.total || 0} 个 IP · ${byCC.size} 个国家/地区`;
    geoBox.innerHTML = bsRankList(
      items,
      it => (typeof geoName === "function" ? geoName(it.cc) : (it.cc || "未知")),
      it => it.n,
      it => it.cc || "?"
    );
  }

  // —— TOP 榜单 ——
  const domBox = $("#bs-domains");
  if (domBox) {
    domBox.innerHTML = bsRankList(
      S.byRule.slice(0, 8),
      r => r.name || r.id,
      r => r.requests || 0,
      r => fmtBytes(r.bytesOut || 0)
    );
  }
  const pathBox = $("#bs-paths");
  if (pathBox) {
    pathBox.innerHTML = bsRankList(
      S.topPaths.slice(0, 8),
      p => p.path,
      p => p.requests || 0,
      p => (p.avgMs || 0).toFixed(0) + "ms"
    );
  }

  // —— 实时日志（多规则合并，按时间倒序取最新 50 条） ——
  const logBox = $("#bs-logs");
  if (logBox) {
    const all = [];
    for (const arr of logsArr) for (const line of arr || []) if (typeof line === "string") all.push(line);
    all.sort((a, b) => b.localeCompare(a));
    const top = all.slice(0, 50);
    logBox.innerHTML = top.length ? top.map(line => {
      const t = line.slice(0, 19);
      const rest = line.slice(20);
      const warn = /拦截|拒绝|错误/.test(rest);
      return `<div class="bs-log${warn ? " warn" : ""}"><span class="t">${esc(t)}</span><span class="m">${esc(rest)}</span></div>`;
    }).join("") : `<p class="bs-empty">暂无访问日志</p>`;
  }
}
