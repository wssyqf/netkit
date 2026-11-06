/* webhook-form.js —— 可复用的 Webhook 配置表单组件
 * 供 DDNS / 端口转发 / 全局通知共用，支持模板变量、事件过滤、重试、签名与测试。
 */
"use strict";

// WHTemplate 渲染 Webhook 配置表单。prefix 用于隔离不同表单的 id；extraVars 为模块专属变量提示（HTML）。
function WHTemplate(prefix, wh, extraVars) {
  const w = wh || {};
  const events = [
    { k: "ddns", label: "DDNS 同步" },
    { k: "portforward", label: "端口转发异常" },
    { k: "cert", label: "证书事件" },
  ];
  const on = (w.events || []);
  const evBoxes = events.map(e =>
    `<label class="checkline" style="margin:4px 0"><input type="checkbox" data-ev="${e.k}" ${on.includes(e.k) ? "checked" : ""}> ${esc(e.label)}</label>`
  ).join("");

  return `
    <div class="wh-form" data-prefix="${prefix}">
      <label class="checkline"><input type="checkbox" id="${prefix}-enabled" ${w.enabled ? "checked" : ""}> 启用通知</label>
      <label>接口地址 <input id="${prefix}-url" value="${esc(w.url || "")}" placeholder="https://example.com/hook"></label>
      <div style="display:flex;gap:10px">
        <label style="flex:1">请求方法 <select id="${prefix}-method">
          ${["POST","GET","PUT","PATCH"].map(m => `<option value="${m}" ${(!w.method && m === "POST") || w.method === m ? "selected" : ""}>${m}</option>`).join("")}
        </select></label>
        <label style="flex:1">Content-Type <input id="${prefix}-ctype" value="${esc(w.contentType || "application/json")}"></label>
      </div>
      <label>请求体模板 <textarea id="${prefix}-body" rows="3" style="width:100%">${esc(w.body || '{"event":"#{event}","target":"#{target}","ip":"#{ipAddr}","status":"#{status}","result":"#{result}","time":"#{time}"}')}</textarea></label>
      <p class="hint wh-full" style="margin:-4px 0 8px">
        可用变量：<code>#{event}</code> <code>#{module}</code> <code>#{target}</code> <code>#{ipAddr}</code>
        <code>#{status}</code> <code>#{result}</code> <code>#{time}</code> <code>#{timestamp}</code>
        （也支持 <code>$ipAddr</code> 写法；URL 与请求头中同样可用）${extraVars ? "<br>" + extraVars : ""}
      </p>
      <label class="wh-full">成功判定关键字（命中任一即成功，多行；留空则按 HTTP 2xx 判定） <textarea id="${prefix}-ok" rows="2" style="width:100%">${esc(w.successText || "")}</textarea></label>
      <div style="display:flex;gap:10px">
        <label style="flex:1">总尝试次数 <input id="${prefix}-retry" type="number" min="1" max="10" value="${w.retry || 1}"></label>
        <label style="flex:1">超时（秒） <input id="${prefix}-timeout" type="number" min="1" max="120" value="${w.timeoutSec || 15}"></label>
      </div>
      <label>签名密钥（可选，配置后用 HMAC-SHA256 签名） <input id="${prefix}-secret" value="${esc(w.secret || "")}" placeholder="留空则不签名"></label>
      <div style="margin:8px 0">
        <div class="hint" style="margin-bottom:4px">触发事件（不选 = 全部事件）</div>
        ${evBoxes}
      </div>
      <label class="checkline"><input type="checkbox" id="${prefix}-skip" ${w.skipTLSVerify ? "checked" : ""}> 跳过 TLS 证书校验</label>
      <div style="display:flex;gap:10px;align-items:center;margin-top:10px">
        <button type="button" class="btn sm" onclick="WHTest('${prefix}', this)">发送测试通知</button>
        <span class="hint" id="${prefix}-test-msg" style="margin:0"></span>
      </div>
      <pre class="logs hidden" id="${prefix}-test-resp" style="max-height:140px;margin-top:8px"></pre>
    </div>`;
}

// WHRead 从表单读取 Webhook 配置对象。root 为包含该表单的容器。
function WHRead(prefix, root) {
  const d = root || document;
  const g = (id) => d.querySelector(`#${prefix}-${id}`);
  const events = [...d.querySelectorAll(`.wh-form[data-prefix="${prefix}"] input[data-ev]`)]
    .filter(c => c.checked).map(c => c.dataset.ev);
  return {
    enabled: g("enabled")?.checked || false,
    url: (g("url")?.value || "").trim(),
    method: g("method")?.value || "POST",
    contentType: (g("ctype")?.value || "").trim(),
    body: g("body")?.value || "",
    successText: g("ok")?.value || "",
    retry: Number(g("retry")?.value) || 1,
    timeoutSec: Number(g("timeout")?.value) || 15,
    secret: (g("secret")?.value || "").trim(),
    events,
    skipTLSVerify: g("skip")?.checked || false,
    headers: {},
  };
}

// WHTest 用当前表单内容发送测试通知
async function WHTest(prefix, btn) {
  const root = btn.closest("dialog") || document;
  const wh = WHRead(prefix, root);
  const msg = root.querySelector(`#${prefix}-test-msg`);
  const box = root.querySelector(`#${prefix}-test-resp`);
  box.classList.add("hidden");

  if (!wh.url) { msg.textContent = "请先填写接口地址"; return; }
  msg.textContent = "发送中…";
  btn.disabled = true;
  try {
    const r = await api("/api/webhook/test", { method: "POST", body: JSON.stringify(wh) });
    if (r.ok) {
      msg.innerHTML = `<span class="badge on">成功</span> HTTP ${r.status} · ${r.attempts} 次尝试 · ${r.elapsed}ms`;
    } else {
      msg.innerHTML = `<span class="badge err">失败</span> ${esc(r.message)} · HTTP ${r.status || "-"} · ${r.attempts} 次尝试`;
    }
    if (r.response) {
      box.textContent = r.response;
      box.classList.remove("hidden");
    }
  } catch (e) {
    msg.innerHTML = `<span class="badge err">失败</span> ${esc(e.message)}`;
  } finally {
    btn.disabled = false;
  }
}
