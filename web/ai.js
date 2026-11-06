/* NetKit AI 维护：模型配置 / 一键体检 / 运维问答 */
"use strict";

// aiApi 自带超时的 fetch（app.js 的 api() 固定 30s，AI 生成需要更长）
async function aiApi(path, body, timeoutMs = 65000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: ctrl.signal,
    });
    const data = await r.json().catch(() => ({}));
    if (r.status === 401) { showLogin(); throw new Error("未登录或会话已过期"); }
    if (!r.ok) throw new Error(data.error || "请求失败");
    return data;
  } catch (e) {
    if (e && e.name === "AbortError") throw new Error("请求超时（模型响应过慢）");
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

let aiHistory = []; // 对话历史（仅 user/assistant，system 由后端注入）

// aiRenderMd 极简 Markdown 渲染：先 esc 再转换，杜绝 HTML 注入
function aiRenderMd(src) {
  const inline = t => t
    .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
    .replace(/`([^`]+)`/g, "<code>$1</code>");
  const out = [];
  let inCode = false, list = ""; // list: "" | "ul" | "ol"
  const closeList = () => { if (list) { out.push(`</${list}>`); list = ""; } };
  for (const raw of String(src || "").split("\n")) {
    const line = esc(raw);
    if (/^\s*```/.test(line)) {
      closeList();
      out.push(inCode ? "</code></pre>" : "<pre><code>");
      inCode = !inCode;
      continue;
    }
    if (inCode) { out.push(line + "\n"); continue; }
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) { closeList(); out.push("<h4>" + inline(h[2]) + "</h4>"); continue; }
    const li = line.match(/^\s*[-*]\s+(.*)$/);
    if (li) {
      if (list !== "ul") { closeList(); out.push("<ul>"); list = "ul"; }
      out.push("<li>" + inline(li[1]) + "</li>");
      continue;
    }
    const oli = line.match(/^\s*\d+\.\s+(.*)$/);
    if (oli) {
      if (list !== "ol") { closeList(); out.push("<ol>"); list = "ol"; }
      out.push("<li>" + inline(oli[1]) + "</li>");
      continue;
    }
    closeList();
    if (!line.trim()) out.push('<div class="ai-gap"></div>');
    else out.push("<p>" + inline(line) + "</p>");
  }
  closeList();
  if (inCode) out.push("</code></pre>");
  return out.join("");
}

// aiAppend 往对话区追加一条消息
function aiAppend(role, html) {
  const box = document.getElementById("ai-chat");
  const empty = box.querySelector(".ai-empty");
  if (empty) empty.remove();
  const d = document.createElement("div");
  d.className = "ai-msg " + role;
  d.innerHTML = html;
  box.appendChild(d);
  box.scrollTop = box.scrollHeight;
  return d;
}

// setAIDot 更新 AI 状态条指示灯与文案（off 未启用 / on 已启用 / ok 连接正常 / err 连接异常）
function setAIDot(kind, text) {
  const d = document.getElementById("ai-dot");
  if (!d) return;
  d.className = "dot " + kind;
  document.getElementById("ai-st-state").textContent = text;
}

// setAILatency 写入状态条延迟
function setAILatency(ms) {
  const el = document.getElementById("ai-st-rtt");
  if (el && ms != null) el.textContent = ms + " ms";
}

// loadAI 进入页面时回填配置
async function loadAI() {
  const msg = document.getElementById("ai-cfg-msg");
  try {
    const c = await aiApi("/api/ai/config", undefined, 15000);
    document.getElementById("ai-enabled").checked = !!c.enabled;
    document.getElementById("ai-baseurl").value = c.baseURL || "";
    document.getElementById("ai-model").value = c.model || "";
    document.getElementById("ai-proxy").value = c.proxy || "";
    const keyEl = document.getElementById("ai-key");
    keyEl.value = "";
    keyEl.placeholder = c.apiKeySet ? "已保存（留空保留，覆盖请直接输入）" : "留空则保留已保存的 Key";
    msg.textContent = c.enabled ? "AI 维护已启用" : "AI 维护未启用";
    msg.style.color = "";
    // 同步状态条
    document.getElementById("ai-st-model").textContent = c.model || "--";
    document.getElementById("ai-st-url").textContent = c.baseURL || "--";
    setAIDot(c.enabled ? "on" : "off", c.enabled ? "已启用" : "未启用");
  } catch (e) {
    msg.textContent = "配置加载失败：" + e.message;
  }
}

// saveAIConfig 保存配置（apiKey 为空 = 保留旧值，后端处理）
async function saveAIConfig() {
  const btn = document.getElementById("ai-save-btn");
  const msg = document.getElementById("ai-cfg-msg");
  btn.disabled = true;
  msg.textContent = "保存中…";
  try {
    await aiApi("/api/ai/config", {
      enabled: document.getElementById("ai-enabled").checked,
      baseURL: document.getElementById("ai-baseurl").value.trim(),
      apiKey: document.getElementById("ai-key").value,
      model: document.getElementById("ai-model").value.trim(),
      proxy: document.getElementById("ai-proxy").value.trim(),
    }, 15000);
    msg.textContent = "已保存并生效";
    document.getElementById("ai-key").value = "";
    loadAI();
  } catch (e) {
    msg.textContent = "保存失败：" + e.message;
  } finally {
    btn.disabled = false;
  }
}

// testAIConn 用当前表单（可未保存）配置测试上游连通
async function testAIConn() {
  const btn = document.getElementById("ai-test-btn");
  const msg = document.getElementById("ai-cfg-msg");
  btn.disabled = true;
  btn.classList.add("is-loading");
  btn.textContent = "测试中…";
  msg.textContent = "";
  try {
    const r = await aiApi("/api/ai/test", {
      enabled: true,
      baseURL: document.getElementById("ai-baseurl").value.trim(),
      apiKey: document.getElementById("ai-key").value,
      model: document.getElementById("ai-model").value.trim(),
      proxy: document.getElementById("ai-proxy").value.trim(),
    }, 30000);
    setAILatency(r.elapsed);
    if (!r.ok) throw new Error(r.error || "上游返回失败");
    msg.textContent = `连接成功（${r.elapsed} ms）· 模型回复：${r.reply || "（空）"}`;
    msg.style.color = "var(--success-text)";
    setAIDot("ok", "连接正常");
  } catch (e) {
    msg.textContent = "连接失败：" + e.message;
    msg.style.color = "var(--danger-text)";
    setAIDot("err", "连接异常");
  } finally {
    btn.disabled = false;
    btn.classList.remove("is-loading");
    btn.textContent = "测试连接";
  }
}

// aiCheckup 一键体检
async function aiCheckup() {
  const btn = document.getElementById("ai-checkup-btn");
  const msg = document.getElementById("ai-checkup-msg");
  const rep = document.getElementById("ai-report");
  const prog = document.getElementById("ai-checkup-prog");
  btn.disabled = true;
  btn.classList.add("is-loading");
  btn.textContent = "体检中…";
  prog.classList.remove("hidden");
  msg.textContent = "正在聚合系统状态并生成报告（最长约 1 分钟）…";
  msg.style.color = "";
  try {
    const r = await aiApi("/api/ai/checkup", {}, 65000);
    if (r.ok) {
      rep.classList.remove("hidden");
      rep.innerHTML = aiRenderMd(r.report);
      msg.textContent = "体检完成，报告已写入日志中心（AI维护）。";
      msg.style.color = "var(--success-text)";
    } else {
      // 上游不可用：降级展示上下文预览，保证页面可用
      rep.classList.remove("hidden");
      rep.innerHTML = `<p><b>模型调用失败：</b>${esc(r.error || "未知错误")}</p>
        <h4>系统上下文预览（体检将基于以下数据生成）</h4><pre class="logs">${esc(r.context || "")}</pre>`;
      msg.textContent = "模型不可达，已降级为上下文预览。请检查 BaseURL / 代理设置。";
      msg.style.color = "var(--warning-text)";
    }
  } catch (e) {
    msg.textContent = "体检失败：" + e.message;
    msg.style.color = "var(--danger-text)";
  } finally {
    btn.disabled = false;
    btn.classList.remove("is-loading");
    btn.textContent = "开始体检";
    prog.classList.add("hidden");
  }
}

// aiSend 发送一条对话
async function aiSend() {
  const input = document.getElementById("ai-chat-input");
  const btn = document.getElementById("ai-send-btn");
  const msg = document.getElementById("ai-chat-msg");
  const prog = document.getElementById("ai-chat-prog");
  const text = input.value.trim();
  if (!text || btn.disabled) return;
  input.value = "";
  msg.textContent = "";
  aiAppend("user", "<p>" + esc(text) + "</p>");
  aiHistory.push({ role: "user", content: text });
  if (aiHistory.length > 20) aiHistory = aiHistory.slice(-20);

  btn.disabled = true;
  btn.classList.add("is-loading");
  prog.classList.remove("hidden");
  const thinking = aiAppend("bot", '<p class="ai-thinking">思考中…</p>');
  try {
    const r = await aiApi("/api/ai/chat", { messages: aiHistory }, 65000);
    const reply = r.reply || "";
    thinking.innerHTML = aiRenderMd(reply);
    aiHistory.push({ role: "assistant", content: reply });
  } catch (e) {
    thinking.remove();
    aiHistory.pop(); // 出错时撤回该问题，便于重试
    msg.textContent = "发送失败：" + e.message;
    msg.style.color = "var(--danger-text)";
  } finally {
    btn.disabled = false;
    btn.classList.remove("is-loading");
    prog.classList.add("hidden");
    document.getElementById("ai-chat-input").focus();
  }
}
