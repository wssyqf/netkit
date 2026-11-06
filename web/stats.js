/* stats.js —— Web 服务流量统计面板 */

"use strict";

// fmtBytes 人类可读的字节数
function fmtBytes(n) {
  if (!n || n < 0) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v.toFixed(0) : v.toFixed(2)) + " " + u[i];
}

// fmtNum 千分位
function fmtNum(n) {
  return String(n || 0).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// openStats 打开流量统计面板：subId 非空时展示该子规则的独立统计
async function openStats(ruleId, subId) {
  const dlg = $("#dlg");
  let subName = "";
  if (subId) {
    // webRules 由 app.js 声明（顶层 let，跨脚本共享词法环境，非 window 属性）
    const wr = (typeof webRules !== "undefined" ? webRules : []) || [];
    const sub = (wr.find(x => x.id === ruleId)?.subRules || []).find(s => s.id === subId);
    subName = (sub && sub.name) || subId;
  }
  dlg.innerHTML = `<h3>${subName ? `子规则统计 · ${esc(subName)}` : "流量统计"}</h3><div id="stats-body"><p class="hint">加载中…</p></div>
    <div class="row">
      <button class="btn danger" id="stats-reset">清零统计</button>
      <button class="btn" onclick="dlgClose()">关闭</button>
    </div>`;
  dlg.showModal();

  const render = async () => {
    try {
      const s = await api("/api/webrules/stats?id=" + encodeURIComponent(ruleId) +
        (subId ? "&sub=" + encodeURIComponent(subId) : "") + "&top=8");
      $("#stats-body").innerHTML = statsHTML(s, !!subId);
    } catch (e) {
      $("#stats-body").innerHTML = `<p class="hint">读取失败：${esc(e.message)}</p>`;
    }
  };
  $("#stats-reset").onclick = async () => {
    if (!confirm(subId ? "确定清零该子规则的统计吗？" : "确定清零该规则的统计吗？")) return;
    try { await api("/api/webrules/stats/reset", { method: "POST", body: JSON.stringify({ id: ruleId, sub: subId || "" }) }); render(); }
    catch (e) { alert(e.message); }
  };

  await render();
  // 面板打开期间每 3 秒刷新
  const timer = setInterval(() => {
    if (!dlg.open) { clearInterval(timer); return; }
    render();
  }, 3000);
  dlg.addEventListener("close", () => clearInterval(timer), { once: true });
}

function statsHTML(s, perSub) {
  const cards = [
    { label: "总请求数", value: fmtNum(s.requests), tone: "blue" },
    { label: "出站流量", value: fmtBytes(s.bytesOut), tone: "violet" },
    { label: "入站流量", value: fmtBytes(s.bytesIn), tone: "cyan" },
    { label: "平均耗时", value: (s.avgMs || 0).toFixed(1) + " ms", tone: "amber" },
    { label: "QPS", value: (s.qps || 0).toFixed(3), tone: "teal" },
    { label: "拦截 / 跳转", value: fmtNum(s.blocked) + " / " + fmtNum(s.redirected), tone: "slate" },
  ];

  const cardHTML = cards.map(c => `
    <div class="stat-card tone-${c.tone}" style="padding:12px 14px">
      <div class="stat-top"><span class="stat-label">${esc(c.label)}</span></div>
      <div class="stat-num" style="font-size:22px;margin:6px 0 0">${esc(c.value)}</div>
    </div>`).join("");

  // 状态码分布条
  const total = (s.status2xx + s.status3xx + s.status4xx + s.status5xx) || 1;
  const seg = (n, cls, name) => {
    const pct = (n / total * 100);
    if (pct <= 0) return "";
    return `<div class="sc-seg ${cls}" style="width:${pct}%" title="${name} ${n} (${pct.toFixed(1)}%)"></div>`;
  };
  const statusBar = `
    <div class="sc-bar">
      ${seg(s.status2xx, "sc-2xx", "2xx")}
      ${seg(s.status3xx, "sc-3xx", "3xx")}
      ${seg(s.status4xx, "sc-4xx", "4xx")}
      ${seg(s.status5xx, "sc-5xx", "5xx")}
    </div>
    <div class="sc-legend">
      <span><i class="sc-dot sc-2xx"></i>2xx ${fmtNum(s.status2xx)}</span>
      <span><i class="sc-dot sc-3xx"></i>3xx ${fmtNum(s.status3xx)}</span>
      <span><i class="sc-dot sc-4xx"></i>4xx ${fmtNum(s.status4xx)}</span>
      <span><i class="sc-dot sc-5xx"></i>5xx ${fmtNum(s.status5xx)}</span>
    </div>`;

  // 24 小时柱状图
  const maxH = Math.max(1, ...(s.hourly || []).map(h => h.requests));
  const bars = (s.hourly || []).map(h => {
    const hp = Math.round(h.requests / maxH * 100);
    return `<div class="hb-col" title="${esc(h.hour)} — ${h.requests} 次">
      <div class="hb-bar" style="height:${Math.max(hp, h.requests > 0 ? 4 : 0)}%"></div>
    </div>`;
  }).join("");
  const hourly = `<div class="hb-wrap">${bars}</div>
    <div class="hint" style="margin-top:4px;font-size:11px">最近 24 小时（峰值 ${maxH} 次/小时）</div>`;

  // 热门路径
  const paths = (s.topPaths || []).length
    ? `<table style="font-size:12.5px"><thead><tr><th>路径</th><th style="width:90px">请求</th><th style="width:100px">流量</th><th style="width:80px">均值</th></tr></thead><tbody>` +
      s.topPaths.map(p => `<tr><td style="font-family:ui-monospace,monospace;word-break:break-all">${esc(p.path)}</td>
        <td>${fmtNum(p.requests)}</td><td>${fmtBytes(p.bytesOut)}</td><td>${(p.avgMs||0).toFixed(0)}ms</td></tr>`).join("") +
      `</tbody></table>`
    : `<p class="hint">暂无路径统计</p>`;

  // 子规则分布
  const ruleRows = (s.byRule || []).map(r => `
    <tr><td>${esc(r.name || r.id)}</td><td>${fmtNum(r.requests)}</td>
    <td>${fmtBytes(r.bytesOut)}</td><td>${fmtNum(r.errors)}</td></tr>`).join("");
  const byRule = ruleRows
    ? `<table style="font-size:12.5px"><thead><tr><th>子规则</th><th style="width:90px">请求</th><th style="width:100px">流量</th><th style="width:70px">错误</th></tr></thead><tbody>${ruleRows}</tbody></table>`
    : `<p class="hint">暂无子规则流量（请求都走了默认规则）</p>`;

  // 慢请求
  const slow = (s.slow || []).length
    ? `<pre class="logs" style="max-height:150px">${esc(s.slow.slice(0, 20).map(x =>
        `[${x.time}] ${x.elapsed}ms ${x.method} ${x.path} → ${x.status} (${fmtBytes(x.bytesOut)})`
      ).join("\n"))}</pre>`
    : `<p class="hint">暂无慢请求（阈值 500ms）</p>`;

  return `
    <div class="cards" style="grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:16px">${cardHTML}</div>
    <h4>状态码分布</h4>${statusBar}
    <h4 style="margin-top:16px">请求趋势</h4>${hourly}
    <h4 style="margin-top:16px">热门路径</h4>${paths}
    ${perSub ? "" : `<h4 style="margin-top:16px">子规则流量</h4>${byRule}`}
    <h4 style="margin-top:16px">慢请求</h4>${slow}
    <p class="hint" style="margin-top:14px;font-size:11.5px">
      统计开始于 ${esc(s.startAt)} ｜ 最近活动 ${esc(s.lastAt || "-")} ｜ 已运行 ${Math.floor((s.uptimeSec||0)/60)} 分钟
    </p>`;
}
