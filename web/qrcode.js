/* qrcode.js —— 极简 QR 码生成器（纯 JS，无依赖）
 * 仅实现 2FA 所需的场景：字节模式、纠错等级 L、版本 1-10 自动选择。
 * 输出为 SVG 字符串，便于缩放且无需 canvas。
 */
"use strict";

const QR = (function () {
  // ---- GF(256) 运算 ----
  const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x; LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  const gmul = (a, b) => (a === 0 || b === 0) ? 0 : EXP[LOG[a] + LOG[b]];

  // ---- 纠错等级 L 的每块参数 [版本]: [每块纠错码字数, 块数, 数据码字总数] ----
  const EC_L = {
    1: [7, 1, 19], 2: [10, 1, 34], 3: [15, 1, 55], 4: [20, 1, 80],
    5: [26, 1, 108], 6: [18, 2, 136], 7: [20, 2, 156], 8: [24, 2, 194],
    9: [30, 2, 232], 10: [18, 4, 274],
  };
  // 对齐图案中心坐标
  const ALIGN = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30],
    6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
  };

  function utf8Bytes(str) {
    const out = [];
    for (const ch of str) {
      let c = ch.codePointAt(0);
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
      else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
      else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return out;
  }

  // Reed-Solomon 纠错码
  function rsEncode(data, ecLen) {
    let gen = [1];
    for (let i = 0; i < ecLen; i++) {
      const next = new Array(gen.length + 1).fill(0);
      for (let j = 0; j < gen.length; j++) {
        next[j] ^= gmul(gen[j], EXP[i]);
        next[j + 1] ^= gen[j];
      }
      gen = next;
    }
    const res = new Array(ecLen).fill(0);
    for (const d of data) {
      const factor = d ^ res[0];
      res.shift(); res.push(0);
      for (let i = 0; i < ecLen; i++) res[i] ^= gmul(gen[i + 1], factor);
    }
    return res;
  }

  function bitsPush(bits, val, len) {
    for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1);
  }

  // 选择最小可用版本
  function pickVersion(byteLen) {
    for (let v = 1; v <= 10; v++) {
      const capBytes = EC_L[v][2];
      const cci = v < 10 ? 8 : 16;
      const needed = Math.ceil((4 + cci + byteLen * 8) / 8);
      if (needed <= capBytes) return v;
    }
    throw new Error("内容过长，无法生成二维码");
  }

  function buildMatrix(version, codewords) {
    const size = version * 4 + 17;
    const m = Array.from({ length: size }, () => new Array(size).fill(null));
    const reserved = Array.from({ length: size }, () => new Array(size).fill(false));

    const setFunc = (r, c, v) => { if (r >= 0 && c >= 0 && r < size && c < size) { m[r][c] = v; reserved[r][c] = true; } };

    // 定位图案
    for (const [br, bc] of [[0, 0], [0, size - 7], [size - 7, 0]]) {
      for (let r = -1; r <= 7; r++) {
        for (let c = -1; c <= 7; c++) {
          const rr = br + r, cc = bc + c;
          if (rr < 0 || cc < 0 || rr >= size || cc >= size) continue;
          const inRing = (r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
                         (c >= 0 && c <= 6 && (r === 0 || r === 6));
          const inCore = r >= 2 && r <= 4 && c >= 2 && c <= 4;
          setFunc(rr, cc, (inRing || inCore) ? 1 : 0);
        }
      }
    }
    // 定时图案：第 6 行与第 6 列，从 8 到 size-9 交替黑白。
    // 注意 (6,8)/(8,6) 这两个交叉点也必须标记为功能模块，
    // 否则会被数据填充误写，导致整条数据流错位。
    for (let i = 8; i <= size - 9; i++) {
      setFunc(6, i, i % 2 === 0 ? 1 : 0);
      setFunc(i, 6, i % 2 === 0 ? 1 : 0);
    }
    // 补齐定时图案与格式区交界处的两个模块
    setFunc(6, 8, 1);
    setFunc(8, 6, 1);
    // 对齐图案
    const pos = ALIGN[version];
    const last = pos[pos.length - 1];
    for (const r of pos) for (const c of pos) {
      // 只排除与三个定位图案重叠的中心位置
      const overlapsFinder =
        (r === 6 && c === 6) ||
        (r === 6 && c === last) ||
        (r === last && c === 6);
      if (overlapsFinder) continue;
      for (let dr = -2; dr <= 2; dr++) for (let dc = -2; dc <= 2; dc++) {
        const on = Math.max(Math.abs(dr), Math.abs(dc)) !== 1;
        setFunc(r + dr, c + dc, on ? 1 : 0);
      }
    }
    // 预留格式信息区（15 位 × 2 处）。注意跳过定时图案交叉点 (8,6)/(6,8)。
    // 左上横排：(8,0..5),(8,7),(8,8)  —— 跳过 (8,6)
    for (let i = 0; i <= 5; i++) setFunc(8, i, 0);
    setFunc(8, 7, 0);
    setFunc(8, 8, 0);
    // 左上竖排：(7,8),(5..0,8) —— 跳过 (6,8)
    setFunc(7, 8, 0);
    for (let i = 0; i <= 5; i++) setFunc(i, 8, 0);

    // 右上横排：(8, size-1 .. size-8)
    for (let i = 0; i < 8; i++) setFunc(8, size - 1 - i, 0);
    // 左下竖排：(size-7 .. size-1, 8)
    for (let i = 0; i < 7; i++) setFunc(size - 1 - i, 8, 0);

    setFunc(size - 8, 8, 1); // 固定暗模块

    // 数据填充（之字形）
    let bitIdx = 0;
    const totalBits = codewords.length * 8;
    const getBit = (i) => i < totalBits ? (codewords[i >> 3] >> (7 - (i & 7))) & 1 : 0;

    // 之字形填充，严格对齐参考实现：
    //   for col := size-1; col > 0; col -= 2 { if col <= 6 { col-- } ; 列对 = (col, col-1) }
    //   每列对内：逐行按当前方向遍历，行到边界后反向
    let inc = -1;                 // -1 表示向上
    let row = size - 1;
    let bitIndex = 7;             // 当前字节内的位索引（从高位到低位）
    let byteIndex = 0;
    const dataLen = codewords.length;
    const maskOn = (r, c) => (r + c) % 2 === 0; // 掩码 0

    // 用 while + 局部变量控制，避免 for 的步进与 col-- 叠加造成列对错位
    let col = size - 1;
    while (col > 0) {
      if (col <= 6) col -= 1;
      const colRange = [col, col - 1];

      for (;;) {
        for (const c of colRange) {
          if (c < 0 || c >= size) continue;
          if (m[row][c] !== null) continue;

          let dark = false;
          if (byteIndex < dataLen) {
            dark = ((codewords[byteIndex] >> bitIndex) & 1) === 1;
          }
          if (maskOn(row, c)) dark = !dark;
          m[row][c] = dark ? 1 : 0;

          bitIndex--;
          if (bitIndex === -1) {
            byteIndex++;
            bitIndex = 7;
          }
        }
        row += inc;
        if (row < 0 || row >= size) {
          row -= inc;   // 回退到边界内
          inc = -inc;   // 反向
          break;
        }
      }
      col -= 2;
    }

    return { m, size };
  }

  function formatBits(mask) {
    // 纠错等级 L = 01
    let data = (0b01 << 3) | mask;
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    const bits = ((data << 10) | rem) ^ 0x5412;
    return bits;
  }

  function applyFormat(matrix, size) {
    // 格式信息共 15 位，按 QR 规范：
    //   bit14 是最高位（先写入），bit0 是最后一位。
    // 左上区域从 (8,0) 开始写入 bit14..bit0；右上/左下区域写入 bit0..bit14。
    const bits = formatBits(0);
    const bit = (i) => (bits >> i) & 1; // i=0 最低位

    // 依据实际矩阵验证得到的写入顺序：
    // 左上横排 (8,0..5)+(8,7)+(8,8) = bit14..bit6（跳过定时列 (8,6)）
    for (let i = 0; i <= 5; i++) matrix[8][i] = bit(14 - i);
    matrix[8][7] = bit(8);
    matrix[8][8] = bit(7);

    // 左上竖排 (0,8)..(5,8) 对应 bit0..bit5；(7,8) 对应 bit6；(8,8) 已在前面写入 bit7
    for (let i = 0; i <= 5; i++) matrix[i][8] = bit(i);
    matrix[7][8] = bit(6);

    // 右上横排 (8, size-1 .. size-8) = bit0..bit7
    for (let i = 0; i <= 7; i++) matrix[8][size - 1 - i] = bit(i);

    // 左下竖排 (size-7 .. size-1, 8) = bit7..bit13 自下而上
    // 实际矩阵: 自 size-7 往上依次为 bit8..bit14
    for (let i = 0; i <= 6; i++) matrix[size - 7 + i][8] = bit(14 - i);

    // 固定暗模块
    matrix[size - 8][8] = 1;
  }

  function encode(text) {
    const bytes = utf8Bytes(text);
    const version = pickVersion(bytes.length);
    const [ecLen, blocks, dataCap] = EC_L[version];

    // 构造数据位流
    const bits = [];
    bitsPush(bits, 0b0100, 4);           // 字节模式
    bitsPush(bits, bytes.length, version < 10 ? 8 : 16);
    for (const b of bytes) bitsPush(bits, b, 8);
    // 终止符与填充
    const cap = dataCap * 8;
    bitsPush(bits, 0, Math.min(4, cap - bits.length));
    while (bits.length % 8 !== 0) bits.push(0);
    const dataCw = [];
    for (let i = 0; i < bits.length; i += 8) {
      let v = 0;
      for (let j = 0; j < 8; j++) v = (v << 1) | bits[i + j];
      dataCw.push(v);
    }
    const padBytes = [0xec, 0x11];
    let pi = 0;
    while (dataCw.length < dataCap) dataCw.push(padBytes[pi++ % 2]);

    // 分块 + 纠错 + 交织
    const perBlock = Math.floor(dataCap / blocks);
    const extra = dataCap % blocks;
    const dataBlocks = [], ecBlocks = [];
    let off = 0;
    for (let b = 0; b < blocks; b++) {
      const len = perBlock + (b >= blocks - extra ? 1 : 0);
      const blk = dataCw.slice(off, off + len);
      off += len;
      dataBlocks.push(blk);
      ecBlocks.push(rsEncode(blk, ecLen));
    }
    const out = [];
    const maxLen = Math.max(...dataBlocks.map(b => b.length));
    for (let i = 0; i < maxLen; i++) for (const b of dataBlocks) if (i < b.length) out.push(b[i]);
    for (let i = 0; i < ecLen; i++) for (const b of ecBlocks) out.push(b[i]);

    const { m, size } = buildMatrix(version, out);
    applyFormat(m, size);
    return { matrix: m, size };
  }

  function toSVG(text, scale = 4, margin = 4) {
    const { matrix, size } = encode(text);
    const dim = (size + margin * 2) * scale;
    let rects = "";
    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        if (matrix[r][c] === 1) {
          rects += `<rect x="${(c + margin) * scale}" y="${(r + margin) * scale}" width="${scale}" height="${scale}"/>`;
        }
      }
    }
    return `<svg xmlns="http://www.w3.org/2000/svg" width="${dim}" height="${dim}" viewBox="0 0 ${dim} ${dim}">` +
      `<rect width="${dim}" height="${dim}" fill="#fff"/><g fill="#000">${rects}</g></svg>`;
  }

  return { encode, toSVG };
})();
