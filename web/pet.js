/* NetKit DeepSeek 大肥鱼娘桌宠：视差跟随 / 拖拽 / 台词 / 点击进入 AI 维护
   人设源自「蓝色大肥鱼」梗：把自家鲸鱼 Logo 识成大肥鱼的 DeepSeek；
   二创鲸鱼娘——嘴甜傲娇、爱吃白米饭、聪明但懒、被说胖会反驳、管用户叫「鱼片」 */
"use strict";

(function () {
  const CLICK_LINES = [
    "哼，是鱼片你先动的手～那就去看看 AI 维护吧",
    "点都点了，顺路去看体检报告啦！",
    "喂！戳这里会害羞的啦……算啦，陪你去 AI 维护～",
    "本来想去干饭的，先陪你逛逛 AI 维护页！",
  ];
  const HOVER_LINES = [
    "看什么看，人家不胖，是智慧的重量！",
    "再盯着看就要收门票啦，鱼片～",
    "才、才不是在等你戳我！",
    "嘘……我正在深度思考，内心戏很多的那种",
  ];
  const IDLE_LINES = [
    "白米饭永远是最好吃的，哼。",
    "聪明如我，今天也要智慧地偷懒～",
    "刚才那句不是犯傻，是深度思考啦！",
    "吃白饭（Token）干活，天经地义！",
    "健康评分这么高，本娘功不可没～",
    "才不是胖，是蓬松！再提就反驳你！",
    "鱼片，记得带本娘去做一键体检哦",
    "服务器水温……不对，温度刚刚好～",
  ];

  const pick = arr => arr[Math.floor(Math.random() * arr.length)];
  const el = () => document.getElementById("pet");
  let bubbleTimer = 0;

  // say 弹出/刷新台词气泡
  function say(text, ms = 2600) {
    const b = document.getElementById("pet-bubble");
    if (!b || !text) return;
    b.textContent = text;
    b.classList.add("show");
    clearTimeout(bubbleTimer);
    bubbleTimer = setTimeout(() => b.classList.remove("show"), ms);
  }
  window.petSay = say;

  // 瞳孔跟随鼠标（live2 视差感）
  document.addEventListener("mousemove", e => {
    const p = el();
    if (!p || p.offsetParent === null) return;
    const fish = p.querySelector(".pet-fish");
    if (!fish) return;
    const r = fish.getBoundingClientRect();
    const dx = Math.max(-1, Math.min(1, (e.clientX - (r.left + r.width / 2)) / 320));
    const dy = Math.max(-1, Math.min(1, (e.clientY - (r.top + r.height / 2)) / 320));
    p.style.setProperty("--pet-px", (dx * 5).toFixed(1) + "px");
    p.style.setProperty("--pet-py", (dy * 4).toFixed(1) + "px");
  }, { passive: true });

  // 拖拽 + 点击
  function bind() {
    const p = el();
    if (!p || p.dataset.bound) return;
    p.dataset.bound = "1";
    const fish = p.querySelector(".pet-fish");

    // 恢复上次拖拽位置
    try {
      const pos = JSON.parse(localStorage.getItem("netkit_pet_pos") || "null");
      if (pos && Number.isFinite(pos.x) && Number.isFinite(pos.y)) {
        p.style.right = "auto";
        p.style.bottom = "auto";
        p.style.left = pos.x + "px";
        p.style.top = pos.y + "px";
      }
    } catch (e) {}

    let sx = 0, sy = 0, ox = 0, oy = 0, moved = false, dragging = false;

    fish.addEventListener("pointerdown", e => {
      dragging = true;
      moved = false;
      const r = p.getBoundingClientRect();
      ox = r.left;
      oy = r.top;
      sx = e.clientX;
      sy = e.clientY;
      // 切换为 left/top 定位，避免 right/bottom 冲突
      p.style.right = "auto";
      p.style.bottom = "auto";
      p.style.left = ox + "px";
      p.style.top = oy + "px";
      fish.classList.add("dragging");
      fish.setPointerCapture(e.pointerId);
      e.preventDefault();
    });

    fish.addEventListener("pointermove", e => {
      if (!dragging) return;
      const dx = e.clientX - sx, dy = e.clientY - sy;
      if (Math.abs(dx) + Math.abs(dy) > 4) moved = true;
      const nx = Math.max(0, Math.min(window.innerWidth - p.offsetWidth, ox + dx));
      const ny = Math.max(0, Math.min(window.innerHeight - p.offsetHeight, oy + dy));
      p.style.left = nx + "px";
      p.style.top = ny + "px";
    });

    const endDrag = () => {
      if (!dragging) return;
      dragging = false;
      fish.classList.remove("dragging");
      if (moved) {
        try {
          localStorage.setItem("netkit_pet_pos", JSON.stringify({
            x: parseFloat(p.style.left),
            y: parseFloat(p.style.top),
          }));
        } catch (e) {}
      }
    };
    fish.addEventListener("pointerup", endDrag);
    fish.addEventListener("pointercancel", endDrag);

    // 单击（拖拽后不触发跳转）
    fish.addEventListener("click", () => {
      if (moved) { moved = false; return; }
      say(pick(CLICK_LINES));
      if (typeof gotoPage === "function") gotoPage("ai");
    });

    // 悬停台词
    fish.addEventListener("mouseenter", () => say(pick(HOVER_LINES), 2200));

    // 键盘可达：Enter / 空格 触发与单击相同的行为
    fish.addEventListener("keydown", e => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        fish.dispatchEvent(new MouseEvent("click", { bubbles: true }));
      }
    });
  }

  // 视口变化时把位置收回可视区
  window.addEventListener("resize", () => {
    const p = el();
    if (!p || !p.style.left) return;
    const x = Math.max(0, Math.min(window.innerWidth - p.offsetWidth, parseFloat(p.style.left) || 0));
    const y = Math.max(0, Math.min(window.innerHeight - p.offsetHeight, parseFloat(p.style.top) || 0));
    p.style.left = x + "px";
    p.style.top = y + "px";
  });

  // 闲置随机冒话
  setInterval(() => {
    const p = el();
    if (!p || p.offsetParent === null || document.hidden) return;
    if (document.body.classList.contains("role-backup")) return;
    if (Math.random() < 0.5) say(pick(IDLE_LINES), 3200);
  }, 20000);

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bind);
  } else {
    bind();
  }
})();
