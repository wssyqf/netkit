/* NetKit 二期页面：证书 / 计划任务 / IP地址库 / 安全组 / IP过滤 / 日志中心 */
"use strict";

let sslCerts = [], secGroups = [], ipdbItems = [];

/* ---------- 证书 ---------- */
async function loadSSL() {
  sslCerts = (await api("/api/sslcerts")) || [];
  $("#ssl-list").innerHTML = sslCerts.map(c => {
    const cls = c.status === "ok" ? "on" : (c.status === "error" ? "err" : "off");
    const expire = c.notAfter ? new Date(c.notAfter * 1000).toLocaleDateString() : "-";
    const applying = c.status === "pending";
    return ruleCard("ssl-" + c.id, c.remark ? `${c.remark} (${c.domain})` : c.domain, !c.disabled,
      `<span class="badge ${cls}">${esc(c.status)}${c.errMsg ? "：" + esc(c.errMsg) : ""}</span>` +
        (c.disabled ? ` <span class="badge off">已停用</span>` : ""),
      `CA: ${esc(c.ca || "letsencrypt")} ｜ 邮箱 ${esc(c.email || "-")} ｜ 有效期至 ${esc(expire)} ｜ 自动续签 ${c.autoRenew ? `开（提前 ${c.advanceDays || 30} 天）` : "关"}`,
      { logs: `sslLogs('${c.id}')`, edit: `sslEdit('${c.id}')`, del: `sslDel('${c.id}')`,
        extra: `<label class="checkline" style="margin:0;white-space:nowrap"><input type="checkbox" ${c.disabled ? "" : "checked"} onchange="sslToggle('${c.id}')"> 启用</label>` })
      // 在"查看记录"后插入独立的申请按钮，避免混淆
      .replace(`<button class="btn sm danger" onclick="sslDel('${c.id}')">删除</button>`,
        `<button class="btn sm ${applying ? "" : "primary"}" onclick="sslApply('${c.id}')" ${applying ? "disabled" : ""}>${applying ? "申请中…" : "申请/续签"}</button>` +
        `<button class="btn sm danger" onclick="sslDel('${c.id}')">删除</button>`);
  }).join("") || emptyState("暂无证书", "点击右上角「申请证书」为域名签发 SSL 证书");

  // 若存在处于申请中的证书（如刷新页面时任务仍在跑），自动开始轮询
  const pending = sslCerts.find(c => c.status === "pending");
  if (pending && !sslPollTimer) startSSLPolling(pending.id);
}

function sslEdit(id) {
  const c = sslCerts.find(x => x.id === id) || {
    id: uid(), domain: "", email: "", ca: "letsencrypt", autoRenew: true,
  };
  dlgForm(id ? "编辑证书" : "申请域名证书", `
    <label>证书备注 <input id="f-remark" value="${esc(c.remark || "")}" placeholder="便于区分的名称"></label>
    <label>域名（多个用英文逗号分隔，将申请同一张证书）
      <input id="f-domain" value="${esc(c.domain)}" placeholder="ziuzu.cc.cd, *.ziuzu.cc.cd">
    </label>

    <label>验证方式 <select id="f-challenge">
      <option value="http-01" ${(!c.challenge || c.challenge === "http-01") ? "selected" : ""}>HTTP-01（需 80 端口公网可达，不支持泛域名）</option>
      <option value="dns-01" ${c.challenge === "dns-01" ? "selected" : ""}>DNS-01（自动写 TXT，支持泛域名）</option>
    </select></label>

    <div id="f-dns-box" style="display:${c.challenge === "dns-01" ? "block" : "none"}">
      <label>DNS 服务商 <select id="f-dns-source" onchange="sslDNSProviderChanged()">
        <option value="dnshe" ${(!c.dnsSource || c.dnsSource === "dnshe") ? "selected" : ""}>DNSHE 免费域名</option>
        <option value="cloudflare" ${c.dnsSource === "cloudflare" ? "selected" : ""}>Cloudflare</option>
        <option value="aliyun" ${c.dnsSource === "aliyun" ? "selected" : ""}>阿里云 DNS</option>
        <option value="dnspod" ${c.dnsSource === "dnspod" ? "selected" : ""}>DNSPod（腾讯云）</option>
      </select></label>
      <label><span id="f-dns-key-label">API Key / Token</span> <input id="f-dns-key" value="${esc(c.dnsKey || "")}"></label>
      <label><span id="f-dns-secret-label">API Secret（仅 DNSHE 需要）</span> <input id="f-dns-secret" value="${esc(c.dnsSecret || "")}"></label>
      <p class="hint" style="margin:-4px 0 8px">
        程序会自动在 <code>_acme-challenge.域名</code> 下创建 TXT 记录，验证完成后自动删除。
      </p>
    </div>

    <p class="hint" id="f-hint-challenge" style="margin:-4px 0 8px">
      支持通配符 <code>*.example.com</code>，但必须选择 DNS-01 验证。
    </p>
    <label>联系邮箱（ACME 注册用） <input id="f-email" value="${esc(c.email || "")}"></label>
    <label>证书颁发机构 <select id="f-ca">
      <option value="letsencrypt" ${(!c.ca || c.ca === "letsencrypt") ? "selected" : ""}>Let's Encrypt</option>
      <option value="custom" ${c.ca === "custom" ? "selected" : ""}>自定义 ACME 目录</option></select></label>
    <label>ACME 目录地址（自定义时填写，如 ZeroSSL） <input id="f-dir" value="${esc(c.directory || "")}" placeholder="https://acme.zerossl.com/v2/DV90"></label>
    <label>到期前多少天自动续签 <input id="f-advance" type="number" min="1" max="90" value="${c.advanceDays || 30}"></label>
    <label class="checkline"><input type="checkbox" id="f-renew" ${c.autoRenew ? "checked" : ""}> 启用自动续签</label>
    <p class="hint" id="f-hint-verify"></p>
  `, async dlg => {
    const nc = {
      id: c.id, remark: $("#f-remark", dlg).value.trim(),
      domain: $("#f-domain", dlg).value.trim(),
      challenge: $("#f-challenge", dlg).value,
      dnsSource: $("#f-dns-source", dlg).value,
      dnsKey: $("#f-dns-key", dlg).value.trim(),
      dnsSecret: $("#f-dns-secret", dlg).value.trim(),
      email: $("#f-email", dlg).value.trim(), ca: $("#f-ca", dlg).value,
      directory: $("#f-dir", dlg).value.trim(),
      advanceDays: Number($("#f-advance", dlg).value) || 30,
      autoRenew: $("#f-renew", dlg).checked,
      status: c.status || "pending", certPem: c.certPem || "", keyPem: c.keyPem || "",
      notAfter: c.notAfter || 0, errMsg: c.errMsg || "", disabled: c.disabled || false,
    };
    if (!nc.domain) throw new Error("请填写域名");
    sslCerts = sslCerts.filter(x => x.id !== c.id); sslCerts.push(nc);
    await api("/api/sslcerts", { method: "POST", body: JSON.stringify(sslCerts) });
    if (nc.status !== "ok") await api("/api/sslcerts/apply", { method: "POST", body: JSON.stringify({ id: nc.id }) }).catch(e => alert("提交申请: " + e.message));
    loadSSL();
  });
  sslDNSProviderChanged();
}

// sslDNSProviderChanged 按 DNS 服务商调整凭据标签（阿里云 AccessKeyID/AccessKey、DNSPod 单 Token）
function sslDNSProviderChanged() {
  const src = ($("#f-dns-source") || {}).value;
  const key = $("#f-dns-key-label"), sec = $("#f-dns-secret-label");
  const secRow = sec ? sec.closest("label") : null;
  if (!key || !sec) return;
  switch (src) {
    case "aliyun":
      key.textContent = "AccessKeyID（阿里云）";
      sec.textContent = "AccessKey（阿里云）";
      if (secRow) secRow.style.display = "";
      break;
    case "dnspod":
      key.textContent = "Token（DNSPod：ID,Token 格式）";
      sec.textContent = "API Secret（不需要）";
      if (secRow) secRow.style.display = "none";
      break;
    case "cloudflare":
      key.textContent = "API Token（Cloudflare）";
      sec.textContent = "API Secret（不需要）";
      if (secRow) secRow.style.display = "none";
      break;
    default:
      key.textContent = "API Key（DNSHE）";
      sec.textContent = "API Secret（DNSHE）";
      if (secRow) secRow.style.display = "";
  }
}

// 证书表单联动：验证方式 <-> DNS 配置显示，通配符自动提示
function bindSSLChallenge(root) {
  const sel = root.querySelector("#f-challenge");
  const box = root.querySelector("#f-dns-box");
  const domainInput = root.querySelector("#f-domain");
  if (!sel || !box) return;

  const sync = () => {
    const isDNS = sel.value === "dns-01";
    box.style.display = isDNS ? "block" : "none";
    // 底部验证方式说明随选择联动
    const hv = root.querySelector("#f-hint-verify");
    if (hv) hv.textContent = isDNS
      ? "DNS-01：自动在 DNS 服务商创建 TXT 记录验证，支持泛域名，不占用 80 端口。"
      : "HTTP-01：申请期间 NetKit 会临时占用本机 80 端口，需公网可访问；泛域名请改用 DNS-01。";
  };
  sel.addEventListener("change", sync);
  sync();

  if (domainInput) {
    domainInput.addEventListener("input", () => {
      // 检测到通配符但用的是 HTTP-01 时，自动切到 DNS-01
      if (domainInput.value.includes("*") && sel.value !== "dns-01") {
        sel.value = "dns-01";
        sync();
      }
    });
  }
}

// sslLogs 查看该证书的申请日志（展开/收起，不会触发申请）
async function sslLogs(id) {
  const box = document.querySelector("#ssl-" + id + " .logbox");
  if (!box) return;
  if (box.dataset.open === "1") {
    box.innerHTML = "";
    box.dataset.open = "0";
    return;
  }
  box.innerHTML = `<pre class="logs">加载中…</pre>`;
  box.dataset.open = "1";
  try {
    const logs = await api("/api/sslcerts/logs?id=" + encodeURIComponent(id));
    if (!logs || !logs.length) {
      box.innerHTML = `<pre class="logs">暂无申请记录。点击「申请/续签」开始申请。</pre>`;
      return;
    }
    box.innerHTML = `<pre class="logs">${esc(logs.slice().reverse().join("\n"))}</pre>`;
  } catch (e) {
    box.innerHTML = `<pre class="logs">读取失败：${esc(e.message)}</pre>`;
  }
}

// sslApply 主动发起申请/续签（仅此按钮会触发），并自动轮询状态直到完成
async function sslApply(id) {
  if (!confirm("确定要为这张证书发起申请/续签吗？\n\n申请过程会调用 CA 接口，可能需要 1-2 分钟。")) return;
  try {
    await api("/api/sslcerts/apply", { method: "POST", body: JSON.stringify({ id }) });
    await loadSSL();
    startSSLPolling(id);
  } catch (e) { alert(e.message); }
}

// startSSLPolling 申请期间定时刷新状态，完成后自动停止并提示
let sslPollTimer = null;
function startSSLPolling(id) {
  if (sslPollTimer) clearInterval(sslPollTimer);
  let ticks = 0;
  sslPollTimer = setInterval(async () => {
    ticks++;
    try {
      await loadSSL();
      const c = sslCerts.find(x => x.id === id);
      // 状态已不在 pending，或轮询超过 6 分钟则停止
      if (!c || c.status !== "pending" || ticks > 120) {
        clearInterval(sslPollTimer);
        sslPollTimer = null;
        if (c && c.status === "ok") {
          const t = document.createElement("div");
          t.className = "toast";
          t.textContent = "证书申请成功";
          document.body.appendChild(t);
          setTimeout(() => t.remove(), 4000);
        }
      }
    } catch (e) {
      clearInterval(sslPollTimer);
      sslPollTimer = null;
    }
  }, 3000);
}

// sslToggle 证书启用/停用开关：停用后反代不再下发该证书、自动续签跳过（数据保留）
async function sslToggle(id) {
  const c = sslCerts.find(x => x.id === id);
  if (!c) return;
  c.disabled = !c.disabled;
  await api("/api/sslcerts", { method: "POST", body: JSON.stringify(sslCerts) });
  const t = document.createElement("div");
  t.className = "toast";
  t.textContent = c.disabled
    ? `已停用：${c.domain}（反代不再下发该证书，也不自动续签）`
    : `已启用：${c.domain}`;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 4000);
  loadSSL();
}

async function sslDel(id) {
  if (!confirm("确定删除该证书条目？")) return;
  sslCerts = sslCerts.filter(x => x.id !== id);
  await api("/api/sslcerts", { method: "POST", body: JSON.stringify(sslCerts) });
  loadSSL();
}

/* ---------- 计划任务 ---------- */
let cronTasks = [];
// sysCronRow 系统内置任务行：只读展示，不提供编辑/删除入口
function sysCronRow(t) {
  const cls = t.status === "ok" ? "on" : "off";
  const badge = t.status === "ok" ? "已启用" : (t.status === "off" ? "未启用" : "由操作系统管理");
  return `<div class="rule builtin" id="cron-${esc(t.id)}">
    <div class="rule-head">
      <span class="rule-dot ${t.enabled ? "on" : "off"}"></span>
      <span class="name">${esc(t.name)}</span>
      <span class="badge ${cls}">${badge}</span>
      <span class="lock-tag">⛨ 系统任务 · 不可修改</span>
      <span class="spacer"></span>
    </div>
    <div class="rule-meta">${esc(t.desc)} ｜ 触发时机: <code>${esc(t.schedule)}</code>${t.detail ? " ｜ " + esc(t.detail) : ""}</div>
  </div>`;
}

async function loadCron() {
  cronTasks = (await api("/api/crons")) || [];
  const st = await api("/api/crons/status");
  let sysRows = "";
  try {
    const sys = await api("/api/crons/system");
    sysRows = (sys || []).map(sysCronRow).join("");
  } catch (e) { /* 系统任务仅作展示，取不到时忽略 */ }
  $("#cron-list").innerHTML = sysRows + cronTasks.map(t => {
    const s = st[t.id] || "";
    return ruleCard("cron-" + t.id, t.name, t.enabled,
      s ? `<span class="badge ${s.includes("失败") ? "err" : "on"}">${esc(s)}</span>` : "",
      `cron: <code>${esc(t.cron)}</code> ｜ 命令: <code>${esc(t.command)}</code> ｜ 超时 ${t.timeoutSec || 60}s`,
      { logs: `cronLogs('${t.id}')`, edit: `cronEdit('${t.id}')`, del: `cronDel('${t.id}')` })
      .replace(`>日志<`, `>执行记录<`)
      .replace(`>编辑<`, `>编辑</button><button class="btn sm" onclick="cronRun('${t.id}')">立即执行<`);
  }).join("") || emptyState("暂无计划任务", "点击右上角「添加任务」创建定时执行任务");
}

function cronEdit(id) {
  const t = cronTasks.find(x => x.id === id) || {
    id: uid(), name: "", cron: "*/5 * * * *", command: "", timeoutSec: 60, enabled: true,
  };
  dlgForm(id ? "编辑计划任务" : "添加计划任务", `
    <label>任务名称 <input id="f-name" value="${esc(t.name)}"></label>
    <label>cron 表达式（分 时 日 月 周） <input id="f-cron" value="${esc(t.cron)}"></label>
    <label>执行命令 <input id="f-cmd" value="${esc(t.command)}"></label>
    <label>超时(秒) <input id="f-to" type="number" value="${t.timeoutSec || 60}"></label>
    <label class="checkline"><input type="checkbox" id="f-enabled" ${t.enabled ? "checked" : ""}> 启用任务</label>
  `, async dlg => {
    const nt = {
      id: t.id, name: $("#f-name", dlg).value.trim() || "未命名",
      cron: $("#f-cron", dlg).value.trim(), command: $("#f-cmd", dlg).value,
      timeoutSec: Number($("#f-to", dlg).value) || 60, enabled: $("#f-enabled", dlg).checked,
    };
    cronTasks = cronTasks.filter(x => x.id !== t.id); cronTasks.push(nt);
    await api("/api/crons", { method: "POST", body: JSON.stringify(cronTasks) });
    loadCron();
  });
}

async function cronDel(id) {
  if (!confirm("确定删除该任务？")) return;
  cronTasks = cronTasks.filter(x => x.id !== id);
  await api("/api/crons", { method: "POST", body: JSON.stringify(cronTasks) });
  loadCron();
}

async function cronRun(id) {
  try { await api("/api/crons/run", { method: "POST", body: JSON.stringify({ id }) }); loadCron(); }
  catch (e) { alert(e.message); }
}

async function cronLogs(id) {
  const logs = await api("/api/crons/logs?id=" + id);
  const box = $("#cron-" + id + " .logbox");
  box.innerHTML = logs && logs.length ? `<pre class="logs">${esc(logs.join("\n---\n"))}</pre>` : `<pre class="logs">暂无执行记录</pre>`;
}

/* ---------- IP 地址库 ---------- */
async function loadIPDB() {
  ipdbItems = (await api("/api/ipdb")) || [];
  const now = Date.now() / 1000;
  $("#ipdb-list").innerHTML = ipdbItems.map(e => {
    const expired = e.expireAt > 0 && e.expireAt < now;
    const expireTxt = e.expireAt > 0 ? new Date(e.expireAt * 1000).toLocaleString() + (expired ? "（已过期）" : "") : "永久";
    return `<div class="rule">
      <div class="rule-head">
        <span class="name"><code>${esc(e.value)}</code></span>
        <span class="badge ${expired ? "err" : "on"}">${expired ? "已过期" : "生效中"}</span>
        <span class="spacer"></span>
        <button class="btn sm" onclick="ipdbEdit('${e.id}')">编辑</button>
        <button class="btn sm danger" onclick="ipdbDel('${e.id}')">删除</button>
      </div>
      <div class="rule-meta">备注: ${esc(e.remark || "-")} ｜ 有效期: ${esc(expireTxt)}</div>
    </div>`;
  }).join("") || emptyState("IP 地址库为空", "点击右上角「添加条目」维护 IP / CIDR 地址");
}

function ipdbEdit(id) {
  const e = ipdbItems.find(x => x.id === id) || { id: uid(), value: "", remark: "", expireAt: 0 };
  dlgForm(id ? "编辑条目" : "添加条目", `
    <label>IP / CIDR（如 1.2.3.4 或 10.0.0.0/24） <input id="f-value" value="${esc(e.value)}"></label>
    <label>备注 <input id="f-remark" value="${esc(e.remark)}"></label>
    <label>有效期（留空永久） <input id="f-expire" type="datetime-local" value="${e.expireAt ? new Date(e.expireAt * 1000 - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16) : ""}"></label>
  `, async dlg => {
    const ne = {
      id: e.id, value: $("#f-value", dlg).value.trim(),
      remark: $("#f-remark", dlg).value.trim(),
      expireAt: $("#f-expire", dlg).value ? Math.floor(new Date($("#f-expire", dlg).value).getTime() / 1000) : 0,
    };
    if (!ne.value) throw new Error("请填写 IP / CIDR");
    ipdbItems = ipdbItems.filter(x => x.id !== e.id); ipdbItems.push(ne);
    await api("/api/ipdb", { method: "POST", body: JSON.stringify(ipdbItems) });
    loadIPDB();
  });
}

async function ipdbDel(id) {
  if (!confirm("确定删除该条目？")) return;
  ipdbItems = ipdbItems.filter(x => x.id !== id);
  await api("/api/ipdb", { method: "POST", body: JSON.stringify(ipdbItems) });
  loadIPDB();
}

/* ---------- 安全组 ---------- */
async function loadSG() {
  secGroups = (await api("/api/securitygroups")) || [];
  $("#sg-list").innerHTML = secGroups.map(g => {
    const names = (g.itemIDs || []).map(iid => {
      const it = ipdbItems.find(x => x.id === iid);
      return it ? it.value : iid;
    });
    return ruleCard("sg-" + g.id, g.name, true,
      `<span class="badge ${g.mode === "white" ? "on" : "err"}">${g.mode === "white" ? "白名单" : "黑名单"}</span>`,
      `条目(${(g.itemIDs || []).length}): ${esc(names.join(", ")) || "-"}`,
      { logs: ``, edit: `sgEdit('${g.id}')`, del: `sgDel('${g.id}')` })
      .replace(`<button class="btn sm" onclick="">日志</button>`, "");
  }).join("") || emptyState("暂无安全组", "点击右上角「添加安全组」组合地址库条目");
}

function sgEdit(id) {
  const g = secGroups.find(x => x.id === id) || { id: uid(), name: "", mode: "white", itemIDs: [] };
  dlgForm(id ? "编辑安全组" : "添加安全组", `
    <label>安全组名称 <input id="f-name" value="${esc(g.name)}"></label>
    <label>过滤模式 <select id="f-mode">
      <option value="white" ${g.mode === "white" ? "selected" : ""}>白名单（仅名单内可访问）</option>
      <option value="black" ${g.mode === "black" ? "selected" : ""}>黑名单（名单内拒绝）</option></select></label>
    <label>包含的地址库条目（可多选） <select id="f-items" multiple size="7" style="width:100%">
      ${ipdbItems.map(e => `<option value="${esc(e.id)}" ${(g.itemIDs || []).includes(e.id) ? "selected" : ""}>${esc(e.value)}（${esc(e.remark || "无备注")}）</option>`).join("")}
    </select></label>
    <p class="hint">没有条目？先到"IP 地址库"添加。</p>
  `, async dlg => {
    const ng = {
      id: g.id, name: $("#f-name", dlg).value.trim() || "未命名",
      mode: $("#f-mode", dlg).value,
      itemIDs: Array.from($("#f-items", dlg).selectedOptions).map(o => o.value),
    };
    secGroups = secGroups.filter(x => x.id !== g.id); secGroups.push(ng);
    await api("/api/securitygroups", { method: "POST", body: JSON.stringify(secGroups) });
    loadSG();
  });
}

async function sgDel(id) {
  if (!confirm("确定删除该安全组？")) return;
  secGroups = secGroups.filter(x => x.id !== id);
  await api("/api/securitygroups", { method: "POST", body: JSON.stringify(secGroups) });
  loadSG();
}

/* ---------- IP 过滤 ---------- */
// 常见国家/地区 [ISO 二位码, 名称]
const GEO_COUNTRIES = [
  ["CN", "中国"], ["HK", "中国香港"], ["MO", "中国澳门"], ["TW", "中国台湾"],
  ["JP", "日本"], ["KR", "韩国"], ["KP", "朝鲜"], ["SG", "新加坡"],
  ["MY", "马来西亚"], ["TH", "泰国"], ["VN", "越南"], ["PH", "菲律宾"],
  ["ID", "印尼"], ["IN", "印度"], ["RU", "俄罗斯"], ["UA", "乌克兰"],
  ["US", "美国"], ["CA", "加拿大"], ["GB", "英国"], ["DE", "德国"],
  ["FR", "法国"], ["NL", "荷兰"], ["IT", "意大利"], ["ES", "西班牙"],
  ["BR", "巴西"], ["AU", "澳大利亚"], ["IL", "以色列"], ["IR", "伊朗"],
];
let geoPicked = [];

function renderGeoChips() {
  $("#gf-geo-picked").innerHTML = geoPicked.length
    ? geoPicked.map(c => `<span class="geo-chip">${esc(c)} <button type="button" class="geo-x" onclick="geoRemove('${esc(c)}')" aria-label="移除">✕</button></span>`).join("")
    : `<span class="hint" style="margin:0">未选择国家/地区</span>`;
}
function geoAdd(c) {
  c = String(c || "").trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(c)) { alert("国家码须为 2 位字母，如 CN"); return; }
  if (!geoPicked.includes(c)) { geoPicked.push(c); renderGeoChips(); }
}
function geoRemove(c) { geoPicked = geoPicked.filter(x => x !== c); renderGeoChips(); }
function geoAddSel() { Array.from($("#gf-geo-pool").selectedOptions).forEach(o => geoAdd(o.value)); }
function geoAddCode() { geoAdd($("#gf-geo-code").value); $("#gf-geo-code").value = ""; }

async function loadIPFilter() {
  const f = await api("/api/ipfilter");
  await Promise.all([loadIPDB(), loadSG()]);
  const sel = $("#gf-groups");
  sel.innerHTML = secGroups.map(g => `<option value="${esc(g.id)}">${esc(g.name)}（${g.mode === "white" ? "白" : "黑"}名单，${(g.itemIDs || []).length} 条）</option>`).join("");
  $("#gf-mode").value = f.mode || "none";
  $("#gf-admin").checked = !!f.applyAdmin;
  Array.from(sel.options).forEach(o => { o.selected = (f.groupIDs || []).includes(o.value); });
  // 区域拦截
  geoPicked = (f.geoCountries || []).map(s => String(s).toUpperCase());
  $("#gf-geomode").value = f.geoMode || "";
  const pool = $("#gf-geo-pool");
  if (!pool.options.length) {
    pool.innerHTML = GEO_COUNTRIES.map(([c, n]) => `<option value="${c}">${esc(n)}（${c}）</option>`).join("");
  }
  renderGeoChips();
  const gs = f.geoStatus || {};
  $("#gf-geo-status").innerHTML = gs.loaded
    ? `GeoIP 数据库已加载：<code>${esc(gs.path)}</code>（数据时间 ${esc(gs.modTime || "-")}）`
    : `<span style="color:var(--danger-text)">GeoIP 数据库未加载：${esc(gs.error || "文件不存在")}，区域拦截暂不生效</span>`;
}

async function saveIPFilter() {
  const sel = $("#gf-groups");
  if (!geoGuard()) return;
  await api("/api/ipfilter", { method: "POST", body: JSON.stringify({
    mode: $("#gf-mode").value,
    groupIDs: Array.from(sel.selectedOptions).map(o => o.value),
    applyAdmin: $("#gf-admin").checked,
    geoMode: $("#gf-geomode").value,
    geoCountries: geoPicked,
  }) });
  $("#gf-msg").textContent = "已保存，立即生效";
}

// geoGuard 模式已开启但名单为空时阻止保存（名单为空时区域过滤不会生效）
function geoGuard() {
  const msg = $("#gf-geo-msg");
  if ($("#gf-geomode").value && geoPicked.length === 0) {
    msg.innerHTML = `<span style="color:var(--danger-text)">已启用 ${esc($("#gf-geomode").selectedOptions[0].text)}，但名单为空、不会生效：请在下方选中国家后点「添加选中」再保存</span>`;
    return false;
  }
  msg.textContent = "";
  return true;
}

// saveGeo 仅保存区域拦截设置：先取回当前已存配置，只覆盖 geo 字段，
// 避免把过滤模式面板中尚未保存的改动一并提交。
async function saveGeo() {
  if (!geoGuard()) return;
  const cur = await api("/api/ipfilter");
  delete cur.geoStatus;
  cur.geoMode = $("#gf-geomode").value;
  cur.geoCountries = geoPicked;
  await api("/api/ipfilter", { method: "POST", body: JSON.stringify(cur) });
  $("#gf-geo-msg").textContent = cur.geoMode === ""
    ? "已保存（区域拦截已停用）"
    : `已保存，立即生效（${$("#gf-geomode").selectedOptions[0].text} · ${geoPicked.length} 个国家/地区）`;
}

/* ---------- 日志中心 ---------- */
let logTimer = null;
async function loadLogs() {
  const mods = (await api("/api/logcenter/modules")) || [];
  const sel = $("#lg-module");
  const cur = sel.value;
  sel.innerHTML = `<option value="">全部模块</option>` + mods.map(m => `<option>${esc(m)}</option>`).join("");
  if (cur) sel.value = cur;
  const q = new URLSearchParams({
    module: sel.value, level: $("#lg-level").value, keyword: $("#lg-kw").value, limit: "800",
  });
  const logs = (await api("/api/logcenter?" + q)) || [];
  $("#lg-list").textContent = logs.map(e => `[${e.time}] [${e.module}] [${e.level}] ${e.msg}`).join("\n") || "暂无日志";
}

function toggleLogAuto() {
  if (logTimer) { clearInterval(logTimer); logTimer = null; }
  if ($("#lg-auto").checked) logTimer = setInterval(loadLogs, 3000);
}

async function clearLogs() {
  if (!confirm("确定清空日志中心？")) return;
  await api("/api/logcenter", { method: "DELETE" });
  loadLogs();
}

$("#lg-auto") && $("#lg-auto").addEventListener("change", toggleLogAuto);
$("#lg-kw") && $("#lg-kw").addEventListener("keydown", e => { if (e.key === "Enter") loadLogs(); });

/* ---------- boot 扩展 ---------- */
const _oldBoot = boot;
boot = async function () {
  _oldBoot();
  loadSSL().catch(() => {});
  loadCron().catch(() => {});
  loadIPDB().catch(() => {});
  loadSG().catch(() => {});
  loadIPFilter().catch(() => {});
  loadLogs().catch(() => {});
};

/* ---------- WAF ---------- */
let wafRuleSets = [];

async function loadWAF() {
  const d = await api("/api/waf");
  const c = d.config || {};
  $("#waf-enabled").checked = !!c.enabled;
  $("#waf-admin").checked = !!c.applyAdmin;
  $("#waf-mode").value = c.mode || "block";
  $("#waf-maxbody").value = c.maxBodyKB || 128;
  $("#waf-ratelimit").value = c.rateLimit || 0;
  $("#waf-trusted").value = (c.trustedIPs || []).join("\n");
  $("#waf-extra").value = c.extraRules || "";
  $("#waf-autoupd").checked = !!c.rulesAutoUpdate;
  $("#waf-feed-url").value = c.rulesFeedURL || "";
  $("#waf-feed-hours").value = c.rulesUpdateHours || 24;
  const last = c.lastRulesUpdate
    ? new Date(c.lastRulesUpdate * 1000).toLocaleString() : "从未更新";
  $("#waf-feed-status").textContent =
    `上次更新：${last}${c.lastRulesMsg ? " ｜ " + c.lastRulesMsg : ""}`;
  wafRuleSets = d.ruleSets || [];
  $("#waf-rulesets").innerHTML = wafRuleSets.map(r => `
    <label class="waf-ruleset ${r.on ? "on" : ""}">
      <input type="checkbox" data-key="${esc(r.key)}" ${r.on ? "checked" : ""}>
      <div>
        <div class="waf-rs-name">${esc(r.name)}</div>
        <div class="waf-rs-desc">${esc(r.desc)}</div>
      </div>
    </label>`).join("");
  $$("#waf-rulesets input").forEach(cb => {
    cb.onchange = () => cb.closest(".waf-ruleset").classList.toggle("on", cb.checked);
  });
  $("#waf-msg").textContent = d.initErr ? "引擎错误：" + d.initErr : (d.engineOK ? "引擎已就绪" : "引擎未初始化");
  loadWAFHits();
}

async function saveWAF() {
  const rulesets = {};
  $$("#waf-rulesets input").forEach(cb => { rulesets[cb.dataset.key] = cb.checked; });
  const body = {
    enabled: $("#waf-enabled").checked,
    applyAdmin: $("#waf-admin").checked,
    mode: $("#waf-mode").value,
    maxBodyKB: Number($("#waf-maxbody").value) || 128,
    rateLimit: Number($("#waf-ratelimit").value) || 0,
    trustedIPs: lines($("#waf-trusted").value),
    extraRules: $("#waf-extra").value,
    rulesAutoUpdate: $("#waf-autoupd").checked,
    rulesFeedURL: $("#waf-feed-url").value.trim(),
    rulesUpdateHours: Number($("#waf-feed-hours").value) || 24,
    rulesets: {
      sqli: !!rulesets.sqli, xss: !!rulesets.xss, pathTraversal: !!rulesets.pathTraversal,
      sensitiveFile: !!rulesets.sensitiveFile, exploitPath: !!rulesets.exploitPath,
      scannerUA: !!rulesets.scannerUA, badBot: !!rulesets.badBot,
      cmdInjection: !!rulesets.cmdInjection,
    },
  };
  try {
    await api("/api/waf", { method: "POST", body: JSON.stringify(body) });
    $("#waf-msg").textContent = "已保存并生效";
    loadWAFHits();
  } catch (e) {
    $("#waf-msg").textContent = "保存失败：" + e.message;
  }
}

// updateWAFRules 立即拉取远程规则源并应用
async function updateWAFRules() {
  const url = $("#waf-feed-url").value.trim();
  const st = $("#waf-feed-status");
  st.textContent = "正在拉取规则…";
  try {
    const r = await api("/api/waf/update-rules", {
      method: "POST", body: JSON.stringify({ url }),
    });
    // 不整页刷新表单，避免覆盖用户尚未保存的勾选/输入
    st.textContent = `更新成功（${r.bytes} 字节）· ${new Date().toLocaleString()}，已生效`;
  } catch (e) {
    st.textContent = "更新失败：" + e.message;
  }
}

async function testWAF() {
  const uri = $("#waf-test-uri").value;
  const ua = $("#waf-test-ua").value;
  try {
    const r = await api("/api/waf/test", { method: "POST", body: JSON.stringify({ uri, ua }) });
    $("#waf-test-result").innerHTML = r.blocked
      ? `<span class="badge err">会被拦截</span> ${esc(r.msg)}`
      : `<span class="badge on">允许通过</span> ${esc(r.msg)}`;
  } catch (e) {
    $("#waf-test-result").textContent = "测试失败：" + e.message;
  }
}

async function loadWAFHits() {
  try {
    const hits = await api("/api/waf/hits?limit=200");
    $("#waf-hits").textContent = hits && hits.length
      ? hits.map(h => `[${h.time}] ${h.action === "deny" ? "拦截" : "记录"} ${h.ip}${h.geo ? "(" + geoName(h.geo) + ")" : ""} ${h.method} ${h.uri} — ${h.msg}`).join("\n")
      : "暂无拦截记录";
  } catch (e) {
    $("#waf-hits").textContent = "读取失败：" + e.message;
  }
}

async function clearWAFHits() {
  if (!confirm("确定清空拦截记录？")) return;
  await api("/api/waf", { method: "DELETE" });
  loadWAFHits();
}

/* ---------- 蜜罐诱捕 ---------- */
let hpItems = [];
let hpSvcs = [];   // 服务模板（后端下发）
let hpRunning = 0; // 当前运行中的诱饵端口数
const GEO_NAME = Object.fromEntries((typeof GEO_COUNTRIES !== "undefined" ? GEO_COUNTRIES : []).map(([c, n]) => [c, n]));
function geoName(cc) {
  if (!cc) return "未知";
  return GEO_NAME[cc.toUpperCase()] ? `${GEO_NAME[cc.toUpperCase()]}（${cc}）` : cc;
}

function hpSvcInfo(key) {
  return hpSvcs.find(t => t.key === (key || "custom")) || { key: "custom", name: "自定义", desc: "" };
}
function hpSvcBadge(key) {
  if (!key || key === "custom") return "";
  const t = hpSvcInfo(key);
  return `<span class="badge on" title="${esc(t.desc || t.name)}">${esc(t.name)}</span>`;
}

async function loadHoneypot() {
  const d = await api("/api/honeypot");
  const c = d.config || {};
  hpItems = c.ports || [];
  hpSvcs = d.services || hpSvcs;
  $("#hp-enabled").checked = !!c.enabled;
  const rs = d.reserved || {};
  const names = Object.values(rs);
  $("#hp-reserved").textContent = names.length
    ? "已占用端口（蜜罐不可使用）：" + names.map(n => n).join("、")
    : "无占用端口冲突提示";
  const gs = d.geoStatus || {};
  $("#hp-geo").innerHTML = gs.loaded
    ? `GeoIP 已加载（国家识别可用，数据 ${esc(gs.modTime || "-")}）`
    : `<span style="color:var(--danger-text)">GeoIP 未加载：${esc(gs.error || "文件不存在")}，地区列将显示"未知"</span>`;
  const status = {};
  (d.status || []).forEach(s => status[s.id] = s);
  hpRunning = (d.status || []).filter(s => s.running).length;
  $("#hp-list").innerHTML = hpItems.map(p => {
    const st = status[p.id];
    const on = !!st && st.running;
    const err = st && st.errMsg ? `<span class="badge err" title="${esc(st.errMsg)}">监听失败</span>` : "";
    const svc = hpSvcInfo(p.service);
    return `<div class="rule">
      <div class="rule-head">
        <span class="rule-dot ${on ? "on" : "off"}"></span>
        <span class="name">端口 <code>${p.port}</code> ${hpSvcBadge(p.service)} ${esc(p.remark || "")}</span>
        ${on ? `<span class="badge on">监听中</span>` : `<span class="badge off">未运行</span>`}${err}
        <span class="spacer"></span>
        <button class="btn sm" onclick="hpEdit('${esc(p.id)}')">编辑</button>
        <button class="btn sm danger" onclick="hpDel('${esc(p.id)}')">删除</button>
      </div>
      <div class="rule-meta">监听 ${esc(p.listenIP || "0.0.0.0")} ｜ ${p.service && p.service !== "custom" ? `服务: ${esc(svc.name)} — ${esc(svc.desc || "")} ｜` : ""} Banner: ${esc(p.banner || "（按模板默认）")} ｜ ${p.enabled ? "已启用" : "已停用"}</div>
    </div>`;
  }).join("") || emptyState("暂无诱饵端口", "点击下方「添加诱饵端口」开放第一个诱饵（如 2323、3306、6379）");
  loadHoneypotLogs().catch(() => {});
}

function hpEdit(id) {
  const p = hpItems.find(x => x.id === id) ||
    { id: uid(), listenIP: "", port: "", banner: "", remark: "", enabled: true, service: "custom" };
  const svcKey = p.service || "custom";
  const svcOpts = (hpSvcs.length ? hpSvcs : [{ key: "custom", name: "自定义（仅首包）" }])
    .map(t => `<option value="${t.key}" ${t.key === svcKey ? "selected" : ""}>${esc(t.name)}</option>`).join("");
  dlgForm(id ? "编辑诱饵端口" : "添加诱饵端口", `
    <label>服务模板（决定交互方式与捕获能力） <select id="f-service" onchange="hpSvcPick()">${svcOpts}</select></label>
    <p class="hint" id="f-svc-desc" style="margin:2px 0 8px"></p>
    <label>监听端口 <input id="f-port" type="number" min="1" max="65535" value="${esc(p.port)}" placeholder="留空 = 模板推荐端口"></label>
    <label>监听 IP（留空 = 0.0.0.0 全部网卡） <input id="f-lip" value="${esc(p.listenIP || "")}"></label>
    <label>备注 <input id="f-remark" value="${esc(p.remark || "")}" placeholder="如 Telnet 诱饵"></label>
    <label>Banner 欢迎语（留空 = 使用模板默认） <input id="f-banner" value="${esc(p.banner || "")}" placeholder="如 220 (vsFTPd 3.0.5)"></label>
    <label class="checkline" style="display:flex;gap:8px;align-items:center"><input type="checkbox" id="f-hp-enabled" ${p.enabled ? "checked" : ""}> 启用该端口</label>
    <p class="hint">端口不能与管理后台、端口转发、Web 服务已监听的端口相同。凭据与命令仅在诱饵端口内诱导获得，不涉及真实账号。</p>
  `, async dlg => {
    const service = $("#f-service", dlg).value;
    const t = hpSvcInfo(service);
    let port = Number($("#f-port", dlg).value);
    if (!port) port = t.port || 0;
    if (!port || port < 1 || port > 65535) throw new Error("请填写有效端口号（1-65535）");
    const np = {
      id: p.id, port,
      listenIP: $("#f-lip", dlg).value.trim(),
      remark: $("#f-remark", dlg).value.trim(),
      banner: $("#f-banner", dlg).value,
      service,
      enabled: $("#f-hp-enabled", dlg).checked,
    };
    hpItems = hpItems.filter(x => x.id !== p.id);
    hpItems.push(np);
    await saveHoneypot(true);
  });
  hpSvcPick();
}

// hpSvcPick 服务模板变更联动：更新能力说明，自动填推荐端口与默认 Banner
function hpSvcPick() {
  const sel = $("#f-service");
  if (!sel) return;
  const t = hpSvcInfo(sel.value);
  const desc = $("#f-svc-desc");
  if (desc) {
    const parts = [t.desc || "自定义：读取首包后可回写 Banner，仅记录不诱导交互"];
    if (t.banner) parts.push(`默认 Banner：${t.banner}`);
    if (t.port) parts.push(`推荐端口：${t.port}`);
    desc.textContent = parts.join(" ｜ ");
  }
  const port = $("#f-port");
  if (port && !String(port.value).trim() && t.port) port.value = t.port;
  const b = $("#f-banner");
  if (b) {
    const defaults = hpSvcs.map(x => x.banner).filter(Boolean);
    if (!b.value || defaults.includes(b.value)) b.value = t.banner || "";
  }
}

async function hpDel(id) {
  if (!confirm("确定删除该诱饵端口？")) return;
  hpItems = hpItems.filter(x => x.id !== id);
  await saveHoneypot(true);
}

// saveHoneypot 保存开关与端口列表；silent 时不提示（编辑弹窗内部调用）
async function saveHoneypot(silent) {
  const d = await api("/api/honeypot", {
    method: "POST",
    body: JSON.stringify({ enabled: $("#hp-enabled").checked, ports: hpItems }),
  });
  const failed = (d.status || []).filter(s => s.errMsg);
  if (!silent) {
    $("#hp-msg").innerHTML = failed.length
      ? `<span style="color:var(--danger-text)">已保存，但 ${failed.length} 个端口启动失败：${esc(failed[0].errMsg)}</span>`
      : "已保存并立即生效";
  }
  loadHoneypot();
}

async function loadHoneypotLogs() {
  const d = await api("/api/honeypot/logs?limit=200");
  const rows = d.records || [];
  const ips = new Set(rows.map(r => r.ip));
  const withCred = rows.filter(r => (r.creds || []).length).length;
  const withTag = rows.filter(r => r.tag).length;
  const stats = $("#hp-stats");
  if (stats) {
    stats.innerHTML = [
      `<span class="badge on">诱捕 ${rows.length} 次</span>`,
      `<span class="badge on">独立 IP ${ips.size}</span>`,
      `<span class="badge ${withCred ? "err" : "off"}">含凭据 ${withCred}</span>`,
      `<span class="badge ${withTag ? "warn" : "off"}">AI/扫描器 ${withTag}</span>`,
      `<span class="badge ${hpRunning ? "on" : "off"}">运行端口 ${hpRunning}</span>`,
    ].join("");
  }
  $("#hp-records").innerHTML = rows.length ? `<table>
    <thead><tr><th>时间</th><th>来源 IP</th><th>端口</th><th>服务</th><th>捕获凭据</th><th>标签</th><th>地区</th><th>首包/指令</th></tr></thead>
    <tbody>${rows.map(r => `<tr>
      <td style="white-space:nowrap">${esc(r.time)}</td>
      <td><code>${esc(r.ip)}</code></td>
      <td>${r.port}</td>
      <td>${r.service ? `<span class="badge on" title="${esc(r.remark || r.service)}">${esc(r.service)}</span>` : "自定义"}</td>
      <td>${(r.creds || []).length ? r.creds.map(c => `<span class="badge err">${esc(c)}</span>`).join(" ") : `<span style="color:var(--text-subtle)">—</span>`}</td>
      <td>${r.tag ? `<span class="badge warn">${esc(r.tag)}</span>` : `<span style="color:var(--text-subtle)">—</span>`}</td>
      <td style="white-space:nowrap">${esc(geoName(r.geo))}</td>
      <td title="${esc(r.payload || "")}">${esc(r.payload || "（无数据）")}</td>
    </tr>`).join("")}</tbody></table>` : emptyState("暂无诱捕记录", "开放诱饵端口后，命中连接会连同凭据与请求特征出现在这里");
  $("#hp-logs").textContent = (d.logs || []).length ? d.logs.join("\n") : "暂无日志";
}

async function clearHoneypotLogs() {
  if (!confirm("确定清空蜜罐诱捕记录？")) return;
  await api("/api/honeypot/logs", { method: "DELETE" });
  loadHoneypotLogs();
}

/* ---------- IP 访客（地区显示） ---------- */
async function loadIPVisitors() {
  const q = new URLSearchParams({ cc: $("#ipv-cc").value, kw: $("#ipv-kw").value.trim(), limit: "500" });
  const d = await api("/api/ipvisitors?" + q);
  const list = d.list || [];
  // 国家下拉：与聚合共用一次数据（下拉已有选项时不重建，保留用户选择）
  const agg = {};
  list.forEach(e => { const k = e.cc || ""; agg[k] = (agg[k] || 0) + 1; });
  const sel = $("#ipv-cc");
  if (sel.options.length <= 1) {
    const codes = Object.keys(agg).filter(Boolean).sort();
    sel.innerHTML = `<option value="">全部国家/地区</option>` +
      codes.map(c => `<option value="${c}">${esc(geoName(c))}</option>`).join("");
  }
  // 放行/拦截标记汇总（按当前全局 IP 过滤规则判定）
  const pass = list.filter(e => e.allowed).length;
  const block = list.length - pass;
  $("#ipv-total").textContent = `共 ${d.total} 个 IP · 本页放行 ${pass} · 拦截 ${block}`;
  $("#ipv-aggs").innerHTML = Object.entries(agg).sort((a, b) => b[1] - a[1])
    .map(([cc, n]) => `<span class="geo-chip">${esc(cc ? geoName(cc) : "未知/内网")} · ${n}</span>`)
    .join("") || `<span style="margin:0">暂无数据</span>`;
  $("#ipv-list").innerHTML = list.map(e => `<div class="rule">
      <div class="rule-head">
        <span class="name"><code>${esc(e.ip)}</code></span>
        <span class="badge ${e.allowed ? "on" : "err"}" title="${e.allowed ? "当前规则放行该 IP" : "当前规则拦截该 IP"}">${e.allowed ? "放行" : "拦截"}</span>
        <span class="badge ${e.cc ? "on" : "off"}">${esc(geoName(e.cc))}</span>
        <span class="spacer"></span>
        <span class="hint" style="margin:0">${e.count} 次</span>
      </div>
      <div class="rule-meta">来源: ${esc(e.sources || "-")} ｜ 首见: ${esc(e.first)} ｜ 最近: ${esc(e.last)}</div>
    </div>`).join("") || emptyState("暂无访客记录", "访问 Web 服务 / 触发 WAF 拦截 / 连接蜜罐后会出现在这里");
}

async function clearIPVisitors() {
  if (!confirm("确定清空 IP 访客记录？")) return;
  await api("/api/ipvisitors", { method: "DELETE" });
  loadIPVisitors();
}
$("#ipv-kw") && $("#ipv-kw").addEventListener("keydown", e => { if (e.key === "Enter") loadIPVisitors(); });

/* ---------- 两步验证（2FA） ---------- */
let tfaState = { enabled: false, secret: "", otpauth: "" };

async function loadTFA() {
  try {
    const st = await api("/api/2fa/status");
    tfaState.enabled = !!st.enabled;
    $("#tfa-badge").textContent = st.enabled ? "已启用" : "未启用";
    $("#tfa-badge").className = "badge " + (st.enabled ? "on" : "off");
    $("#tfa-recovery-left").textContent = st.enabled ? `剩余恢复码 ${st.recoveryLeft} 个` : "";
    $("#tfa-setup-box").classList.toggle("hidden", st.enabled);
    $("#tfa-active-box").classList.toggle("hidden", !st.enabled);
  } catch (e) {
    $("#tfa-badge").textContent = "读取失败";
  }
}

async function tfaSetup() {
  $("#tfa-setup-msg").textContent = "";
  try {
    const r = await api("/api/2fa/setup", { method: "POST" });
    tfaState.secret = r.secret;
    tfaState.otpauth = r.otpauth;
    $("#tfa-setup-detail").classList.remove("hidden");
    $("#tfa-secret").value = r.secret;
    // 由后端用成熟库渲染二维码，避免前端手写编码器出错
    const qr = await api("/api/2fa/qrcode?text=" + encodeURIComponent(r.otpauth));
    $("#tfa-qr").innerHTML = `<img src="${qr.png}" alt="2FA 二维码" style="display:block;width:180px;height:180px">`;
    $("#tfa-verify-code").focus();
  } catch (e) {
    $("#tfa-setup-msg").textContent = "生成失败：" + e.message;
  }
}

async function tfaEnable() {
  const code = ($("#tfa-verify-code").value || "").trim();
  if (!code) { $("#tfa-setup-msg").textContent = "请输入验证码"; return; }
  try {
    const r = await api("/api/2fa/enable", { method: "POST", body: JSON.stringify({ code }) });
    const codes = (r.recoveryCodes || []).join("\n");
    $("#tfa-setup-detail").classList.add("hidden");
    $("#tfa-setup-msg").innerHTML =
      `<span class="badge on">已启用</span> 请立即保存以下恢复码（每个只能用一次）：` +
      `<pre class="logs" style="margin-top:8px">${esc(codes)}</pre>`;
    loadTFA();
  } catch (e) {
    $("#tfa-setup-msg").textContent = "启用失败：" + e.message;
  }
}

async function tfaShowRecovery() {
  try {
    // 恢复码仅在启用时一次性返回给前端，这里提示用户重新生成查看更安全
    $("#tfa-recovery-list").classList.remove("hidden");
    $("#tfa-recovery-list").textContent = "出于安全考虑，恢复码不会再次显示。若已丢失，请停用后重新启用 2FA 以生成新的一组。";
  } catch (e) {}
}

async function tfaDisable() {
  const password = $("#tfa-off-pass").value;
  const code = ($("#tfa-off-code").value || "").trim();
  if (!password) { $("#tfa-off-msg").textContent = "请输入当前密码"; return; }
  if (!code) { $("#tfa-off-msg").textContent = "请输入当前验证码"; return; }
  try {
    await api("/api/2fa/disable", { method: "POST", body: JSON.stringify({ password, code }) });
    $("#tfa-off-msg").textContent = "已停用两步验证";
    $("#tfa-off-pass").value = ""; $("#tfa-off-code").value = "";
    loadTFA();
  } catch (e) {
    $("#tfa-off-msg").textContent = "停用失败：" + e.message;
  }
}

// 在设置页加载时一并刷新 2FA 状态
const _loadSettingsOrig = loadSettings;
loadSettings = async function () {
  await _loadSettingsOrig();
  try { await loadTFA(); } catch (e) {}
};

/* ---------- 配置备份与还原 ---------- */
async function backupDownload() {
  try {
    const r = await fetch("/api/backup", { credentials: "same-origin" });
    if (r.status === 401) { showLogin(); return; }
    if (!r.ok) throw new Error("导出失败 HTTP " + r.status);
    const blob = await r.blob();
    // 从 Content-Disposition 提取文件名
    let name = "netkit-backup.json";
    const cd = r.headers.get("Content-Disposition") || "";
    const m = cd.match(/filename="([^"]+)"/);
    if (m) name = m[1];
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    $("#backup-msg").textContent = `已导出 ${name}`;
    loadBackupList();
  } catch (e) {
    $("#backup-msg").textContent = "导出失败：" + e.message;
  }
}

async function backupRestore(file) {
  if (!file) return;
  if (!confirm(`确定用「${file.name}」覆盖当前全部配置吗？\n\n还原后会立即生效，当前配置会先自动备份一份。`)) {
    $("#backup-file").value = "";
    return;
  }
  $("#backup-msg").textContent = "正在还原…";
  try {
    const text = await file.text();
    let data;
    try { data = JSON.parse(text); } catch (e) { throw new Error("不是合法的 JSON 文件"); }
    const r = await api("/api/backup", { method: "POST", body: JSON.stringify(data) });
    $("#backup-msg").textContent = `还原成功，旧配置已存为 ${r.backupOf}。页面将刷新…`;
    loadBackupList();
    setTimeout(() => location.reload(), 1800);
  } catch (e) {
    $("#backup-msg").textContent = "还原失败：" + e.message;
  } finally {
    $("#backup-file").value = "";
  }
}

async function loadBackupList() {
  const box = $("#backup-list");
  if (!box) return;
  try {
    const list = await api("/api/backup/list");
    if (!list || !list.length) {
      box.innerHTML = `<span class="hint">暂无自动备份</span>`;
      return;
    }
    box.innerHTML = list.slice(0, 10).map(f =>
      `<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid var(--border-light)">
        <span style="font-family:ui-monospace,monospace">${esc(f.name)}</span>
        <span class="hint" style="margin:0">${esc(f.time)} · ${(f.size/1024).toFixed(1)} KB</span>
      </div>`).join("");
  } catch (e) {
    box.innerHTML = `<span class="hint">读取失败：${esc(e.message)}</span>`;
  }
}

// 设置页加载时刷新备份列表
const _loadSettingsOrig2 = loadSettings;
loadSettings = async function () {
  await _loadSettingsOrig2();
  try { await loadBackupList(); } catch (e) {}
};

/* ---------- 分组管理 ---------- */
async function openGroupManager() {
  await loadGroups();
  const rows = groups.map(g => `
    <div style="display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid var(--border-light)">
      <span style="flex:1;font-weight:600">${esc(g.name)}</span>
      <span class="hint" style="margin:0">${esc(g.note || "")}</span>
      <button class="btn sm" onclick="editGroup('${g.id}')">改名</button>
      <button class="btn sm danger" onclick="deleteGroup('${g.id}')">删除</button>
    </div>`).join("") || `<p class="hint">还没有分组</p>`;

  dlgForm("分组管理", `
    <p class="hint">分组用于把端口转发 / Web 服务 / DDNS 规则归类，便于在列表中筛选。</p>
    <div style="margin:12px 0">${rows}</div>
    <h4 style="margin-top:16px">新建分组</h4>
    <label>名称 <input id="ng-name" placeholder="例如：家庭服务"></label>
    <label>备注（可选） <input id="ng-note" placeholder="可选说明"></label>
  `, async dlg => {
    const name = (dlg.querySelector("#ng-name").value || "").trim();
    const note = (dlg.querySelector("#ng-note").value || "").trim();
    if (!name) throw new Error("请填写分组名称");
    await api("/api/groups", { method: "POST", body: JSON.stringify({ name, note }) });
    await loadGroups();
    // 刷新三个列表的分组栏
    try { loadPF(); loadWeb(); loadDDNS(); } catch (e) {}
  });
}

async function editGroup(id) {
  const g = groups.find(x => x.id === id);
  if (!g) return;
  const name = prompt("分组名称", g.name);
  if (name === null) return;
  const note = prompt("备注（可留空）", g.note || "");
  if (note === null) return;
  await api("/api/groups", { method: "POST", body: JSON.stringify({ id: g.id, name: name.trim(), note: note.trim() }) });
  await loadGroups();
  loadPF(); loadWeb(); loadDDNS();
  openGroupManager();
}

async function deleteGroup(id) {
  const g = groups.find(x => x.id === id);
  if (!confirm(`确定删除分组「${g ? g.name : id}」吗？\n引用该分组的规则会变为"未分组"，规则本身不受影响。`)) return;
  await api("/api/groups?id=" + encodeURIComponent(id), { method: "DELETE" });
  await loadGroups();
  loadPF(); loadWeb(); loadDDNS();
  openGroupManager();
}

/* ---------- 全局通知 Webhook ---------- */
async function loadGlobalWebhook() {
  const box = $("#global-wh-container");
  if (!box) return;
  try {
    const cfg = await api("/api/settings/webhook");
    box.innerHTML = WHTemplate("glbwh", cfg || {});
  } catch (e) {
    box.innerHTML = `<p class="hint">读取失败：${esc(e.message)}</p>`;
  }
}

async function saveGlobalWebhook() {
  const wh = WHRead("glbwh", document);
  $("#global-wh-msg").textContent = "";
  try {
    await api("/api/settings/webhook", { method: "POST", body: JSON.stringify(wh) });
    $("#global-wh-msg").textContent = "已保存";
  } catch (e) {
    $("#global-wh-msg").textContent = "保存失败：" + e.message;
  }
}

const _loadSettingsOrig3 = loadSettings;
loadSettings = async function () {
  await _loadSettingsOrig3();
  try { await loadGlobalWebhook(); } catch (e) {}
};
