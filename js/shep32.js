(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory(root);
  else root.SHEP32 = factory(root);
})(typeof globalThis !== "undefined" ? globalThis : this, function (root) {
  function bigIntPow(base, exp) {
    let b = BigInt(base);
    let e = BigInt(exp);
    let res = 1n;
    while (e > 0n) {
      if (e % 2n === 1n) res *= b;
      b *= b;
      e /= 2n;
    }
    return res;
  }

  function pyMod(n, m) {
    const bn = BigInt(n);
    const bm = BigInt(m);
    return ((bn % bm) + bm) % bm;
  }

  const PI = 3.141592653589793;
  const gCharBase = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.:;<>?@[]^&()*$%/\\`\"',_!#";
  const ten79 = bigIntPow(10, 79);
  const digits16 = "0123456789abcdef";
  const tDecCache = new Map();

  function gChar(c) { return gCharBase.slice(0, Number(c)); }

  function splitWs(s) {
    const str = String(s);
    const words = [];
    let cur = "";
    for (let i = 0; i < str.length; i++) {
      const ch = str[i];
      if (ch <= " ") {
        if (cur.length) { words.push(cur); cur = ""; }
      } else cur += ch;
    }
    if (cur.length) words.push(cur);
    return words;
  }

  function isHex64(k) {
    if (typeof k !== "string" || k.length !== 64) return false;
    for (let i = 0; i < k.length; i++) {
      const o = k.charCodeAt(i);
      if (!((48 <= o && o <= 57) || (65 <= o && o <= 70) || (97 <= o && o <= 102))) return false;
    }
    return true;
  }

  function sanitizeHex64(s) {
    return String(s || "").toLowerCase().replace(/[^0-9a-f]/g, "");
  }

  function parseDec(s) {
    if (!s) return 0n;
    let res = 0n;
    for (let i = 0; i < s.length; i++) {
      const d = s.charCodeAt(i) - 48;
      res = res * 10n + BigInt(d);
    }
    return res;
  }

  function parseHex(s) {
    let res = 0n;
    const clean = String(s).toLowerCase();
    for (let i = 0; i < clean.length; i++) {
      const o = clean.charCodeAt(i);
      const v = (o >= 48 && o <= 57) ? o - 48 : 10 + (o - 97);
      res = res * 16n + BigInt(v);
    }
    return res;
  }

  function toHexSmall(n) {
    let x = BigInt(n);
    if (x === 0n) return "0";
    let out = "";
    while (x > 0n) {
      out = digits16[Number(x % 16n)] + out;
      x /= 16n;
    }
    return out;
  }

  function hexLower(n) {
    let x = BigInt(n);
    if (x === 0n) return "0";
    const base = bigIntPow(16, 6);
    const chunks = [];
    while (x > 0n) { chunks.push(x % base); x /= base; }
    chunks.reverse();
    let out = toHexSmall(chunks[0]);
    for (let i = 1; i < chunks.length; i++) out += toHexSmall(chunks[i]).padStart(6, "0");
    return out;
  }

  function toBinSmall(n) {
    let x = BigInt(n);
    if (x === 0n) return "0";
    let out = "";
    while (x > 0n) {
      out = (x % 2n === 0n ? "0" : "1") + out;
      x /= 2n;
    }
    return out;
  }

  function toBin(n) {
    let x = BigInt(n);
    if (x === 0n) return "0";
    const base = bigIntPow(2, 30);
    const chunks = [];
    while (x > 0n) { chunks.push(x % base); x /= base; }
    chunks.reverse();
    let out = toBinSmall(chunks[0]);
    for (let i = 1; i < chunks.length; i++) out += toBinSmall(chunks[i]).padStart(30, "0");
    return out;
  }

  function binTail(n) {
    const b = toBin(BigInt(n));
    return b.length <= 1 ? "" : b.slice(1);
  }

  function parseBase2(s) {
    let res = 0n;
    for (let i = 0; i < s.length; i++) res = res * 2n + (s[i] === "1" ? 1n : 0n);
    return res;
  }

  class DeterministicRng32 {
    constructor(seedValue = 1n) {
      this.n = 624;
      this.m = 397;
      this.matrixA = 0x9908b0dfn;
      this.upperMask = 0x80000000n;
      this.lowerMask = 0x7fffffffn;
      this.mt = new Array(this.n).fill(0n);
      this.mti = this.n + 1;
      this.setSeed(seedValue);
    }
    setSeed(seedValue) {
      let x = BigInt(seedValue);
      if (x < 0n) x = -x;
      const key = [];
      const base = 4294967296n;
      while (x > 0n) { key.push(x % base); x /= base; }
      if (!key.length) key.push(0n);
      this.initByArray(key);
    }
    initGenrand(s) {
      const mask = 0xffffffffn;
      this.mt[0] = BigInt(s) & mask;
      for (let i = 1; i < this.n; i++) {
        const prev = this.mt[i - 1];
        const v = prev ^ (prev >> 30n);
        this.mt[i] = (1812433253n * v + BigInt(i)) & mask;
      }
      this.mti = this.n;
    }
    initByArray(initKey) {
      const mask = 0xffffffffn;
      this.initGenrand(19650218n);
      let i = 1, j = 0;
      const keyLength = initKey.length;
      for (let k = Math.max(this.n, keyLength); k > 0; k--) {
        const v = this.mt[i - 1] ^ (this.mt[i - 1] >> 30n);
        this.mt[i] = ((this.mt[i] ^ (v * 1664525n)) + initKey[j] + BigInt(j)) & mask;
        i++; j++;
        if (i >= this.n) { this.mt[0] = this.mt[this.n - 1]; i = 1; }
        if (j >= keyLength) j = 0;
      }
      for (let k = this.n - 1; k > 0; k--) {
        const v = this.mt[i - 1] ^ (this.mt[i - 1] >> 30n);
        this.mt[i] = ((this.mt[i] ^ (v * 1566083941n)) - BigInt(i)) & mask;
        i++;
        if (i >= this.n) { this.mt[0] = this.mt[this.n - 1]; i = 1; }
      }
      this.mt[0] = 0x80000000n;
      this.mti = this.n;
    }
    nextU32() {
      const mask = 0xffffffffn;
      if (this.mti >= this.n) {
        for (let kk = 0; kk < this.n - this.m; kk++) {
          const y = (this.mt[kk] & this.upperMask) | (this.mt[kk + 1] & this.lowerMask);
          const twist = (y % 2n !== 0n) ? this.matrixA : 0n;
          this.mt[kk] = (this.mt[kk + this.m] ^ (y >> 1n) ^ twist) & mask;
        }
        for (let kk = this.n - this.m; kk < this.n - 1; kk++) {
          const y = (this.mt[kk] & this.upperMask) | (this.mt[kk + 1] & this.lowerMask);
          const twist = (y % 2n !== 0n) ? this.matrixA : 0n;
          this.mt[kk] = (this.mt[kk + (this.m - this.n)] ^ (y >> 1n) ^ twist) & mask;
        }
        const yLast = (this.mt[this.n - 1] & this.upperMask) | (this.mt[0] & this.lowerMask);
        const twistLast = (yLast % 2n !== 0n) ? this.matrixA : 0n;
        this.mt[this.n - 1] = (this.mt[this.m - 1] ^ (yLast >> 1n) ^ twistLast) & mask;
        this.mti = 0;
      }
      let y = this.mt[this.mti++];
      y ^= (y >> 11n);
      y ^= (y << 7n) & 0x9d2c5680n;
      y ^= (y << 15n) & 0xefc60000n;
      y ^= (y >> 18n);
      return y & mask;
    }
    getRandBits(k) {
      k = Number(k);
      if (k <= 0) return 0n;
      const words = Math.floor((k + 31) / 32);
      let x = 0n;
      const base = 4294967296n;
      for (let i = 0; i < words; i++) x = x * base + this.nextU32();
      const extra = words * 32 - k;
      if (extra) x /= bigIntPow(2, extra);
      return x;
    }
    randBelow(n) {
      const nn = BigInt(n);
      const k = nn.toString(2).length;
      while (true) {
        const r = this.getRandBits(k);
        if (r < nn) return r;
      }
    }
    randint(a, b) {
      return BigInt(a) + this.randBelow(BigInt(b) - BigInt(a) + 1n);
    }
    shuffle(arr) {
      for (let i = arr.length - 1; i > 0; i--) {
        const j = Number(this.randBelow(BigInt(i + 1)));
        const tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
      }
      return arr;
    }
  }

  function randBytes32() {
    const out = new Uint8Array(32);
    const c = root.crypto && typeof root.crypto.getRandomValues === "function" ? root.crypto : null;
    if (c) { c.getRandomValues(out); return out; }
    try {
      if (typeof require === "function") {
        const nodeCrypto = require("crypto");
        const b = nodeCrypto.randomBytes(32);
        out.set(b);
        return out;
      }
    } catch (e) {}
    for (let i = 0; i < out.length; i++) out[i] = (Math.random() * 256) | 0;
    return out;
  }

  function bytesToBigIntBE(bytes) {
    let n = 0n;
    for (let i = 0; i < bytes.length; i++) n = (n << 8n) | BigInt(bytes[i]);
    return n;
  }

  function bigIntToBytesBE(n) {
    let hex = BigInt(n).toString(16);
    if (hex.length % 2) hex = "0" + hex;
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    return out;
  }

  function utf16leEncodeBytes(str) {
    const s = String(str);
    const out = new Uint8Array(s.length * 2);
    for (let i = 0; i < s.length; i++) {
      const code = s.charCodeAt(i);
      out[i * 2] = code & 255;
      out[i * 2 + 1] = (code >> 8) & 255;
    }
    return out;
  }

  function utf16leDecodeBytes(bytes) {
    const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const chars = new Array(Math.ceil(b.length / 2));
    let j = 0;
    for (let i = 0; i < b.length; i += 2) {
      const low = b[i];
      const high = (i + 1 < b.length) ? b[i + 1] : 0;
      chars[j++] = String.fromCharCode((high << 8) | low);
    }
    return chars.join("");
  }

  function toBytes(t) {
    const raw = utf16leEncodeBytes(t);
    const bytes = new Uint8Array(1 + raw.length);
    bytes[0] = 1;
    bytes.set(raw, 1);
    return bytesToBigIntBE(bytes);
  }

  function fromBytes(n) {
    const b = bigIntToBytesBE(n);
    if (!b.length || b[0] !== 1) throw new Error("byte sentinel missing");
    return utf16leDecodeBytes(b.slice(1));
  }

  function fastAnyBaseList(val, b) {
    let v = BigInt(val);
    const bN = BigInt(b);
    if (v === 0n) return ["0"];
    const powers = [[1, bN]];
    while (powers[powers.length - 1][1] <= v) {
      const last = powers[powers.length - 1];
      powers.push([last[0] * 2, last[1] * last[1]]);
    }
    let n = 0;
    let curBn = 1n;
    for (let i = powers.length - 1; i >= 0; i--) {
      const pN = powers[i][0];
      const pVal = powers[i][1];
      if (curBn * pVal <= v) { curBn *= pVal; n += pN; }
    }
    n += 1;
    function convert(x, targetLen) {
      let vv = BigInt(x);
      if (targetLen <= 500) {
        const out = [];
        for (let i = 0; i < targetLen; i++) { out.push(String(vv % bN)); vv /= bN; }
        return out.reverse();
      }
      const half = Math.floor(targetLen / 2);
      const divisor = bigIntPow(bN, half);
      return convert(vv / divisor, targetLen - half).concat(convert(vv % divisor, half));
    }
    const res = convert(v, n);
    while (res.length > 1 && res[0] === "0") res.shift();
    return res;
  }

  function fromAnyBase(n, b) {
    const bN = BigInt(b);
    const parts = Array.isArray(n) ? n : splitWs(n);
    if (!parts.length) return 0n;
    const ints = parts.map((p) => BigInt(p));
    function evalRange(start, end) {
      if (end - start <= 200) {
        let res = 0n;
        for (let i = start; i < end; i++) res = res * bN + ints[i];
        return res;
      }
      const mid = Math.floor((start + end) / 2);
      return evalRange(start, mid) * bigIntPow(bN, end - mid) + evalRange(mid, end);
    }
    return evalRange(0, ints.length);
  }

  function fastBaseConvert(val, b, padTo, charset) {
    const bN = BigInt(b);
    const v0 = BigInt(val);
    if (padTo <= 500) {
      const out = [];
      let v = v0;
      for (let i = 0; i < padTo; i++) { out.push(charset[Number(v % bN)]); v /= bN; }
      return out.reverse().join("");
    }
    const half = Math.floor(padTo / 2);
    const divisor = bigIntPow(bN, half);
    return fastBaseConvert(v0 / divisor, b, padTo - half, charset) + fastBaseConvert(v0 % divisor, b, half, charset);
  }

  function fDecimal(d, b) {
    const dN = BigInt(d);
    const bN = BigInt(b);
    const c = gChar(b);
    if (b === 1) return c[0].repeat(Number(dN + 1n));
    const target = dN * (bN - 1n) + bN;
    const powers = [[1, bN]];
    while (powers[powers.length - 1][1] <= target) {
      const last = powers[powers.length - 1];
      powers.push([last[0] * 2, last[1] * last[1]]);
    }
    let n = 0;
    let curBn = 1n;
    for (let i = powers.length - 1; i >= 0; i--) {
      const pN = powers[i][0];
      const pVal = powers[i][1];
      if (curBn * pVal <= target) { curBn *= pVal; n += pN; }
    }
    const geomSum = n > 0 ? (bigIntPow(bN, n) - bN) / (bN - 1n) : 0n;
    const r = dN - geomSum;
    return n === 0 ? "" : fastBaseConvert(r, b, n, c);
  }

  function tDecimal(c, b) {
    const s = String(c);
    const l = s.length;
    const bN = BigInt(b);
    if (b === 10) return parseDec(s) + (l > 1 ? (bigIntPow(10, l) - 10n) / 9n : 0n);
    if (b === 16) return parseHex(s) + (l > 1 ? (bigIntPow(16, l) - 16n) / 15n : 0n);
    if (!tDecCache.has(b)) {
      const m = {};
      const cs = gChar(b);
      for (let i = 0; i < cs.length; i++) m[cs[i]] = BigInt(i);
      tDecCache.set(b, m);
    }
    const charMap = tDecCache.get(b);
    function evalRange(start, end) {
      if (end - start <= 200) {
        let res = 0n;
        for (let i = start; i < end; i++) res = res * bN + charMap[s[i]];
        return res;
      }
      const mid = Math.floor((start + end) / 2);
      return evalRange(start, mid) * bigIntPow(bN, end - mid) + evalRange(mid, end);
    }
    const v = evalRange(0, l);
    const geomSum = (b > 1 && l > 1) ? (bigIntPow(bN, l) - bN) / (bN - 1n) : (l > 1 && b === 1 ? BigInt(l - 1) : 0n);
    return v + geomSum;
  }

  function generateSeries(s, n) {
    const r = new DeterministicRng32(BigInt(s));
    let out = "";
    for (let i = 0; i < n; i++) out += String(r.randint(0, 8));
    return out;
  }

  function manipulateData(s, c) {
    const sStr = String(s);
    const k = generateSeries(c, sStr.length);
    let out = "";
    for (let i = 0; i < sStr.length; i++) {
      const val = (sStr.charCodeAt(i) + k.charCodeAt(i) - 96) % 10;
      out += String.fromCharCode(val + 48);
    }
    return out;
  }

  function inverseData(s, c) {
    const sStr = String(s);
    const k = generateSeries(c, sStr.length);
    let out = "";
    for (let i = 0; i < sStr.length; i++) {
      let val = (sStr.charCodeAt(i) - k.charCodeAt(i)) % 10;
      if (val < 0) val += 10;
      out += String.fromCharCode(val + 48);
    }
    return out;
  }

  function qRotate(s) { return s.slice(5) + s.slice(2, 5).split("").reverse().join("") + s.slice(0, 2); }
  function pRotate(s) { return s.slice(-2) + s.slice(-5, -2).split("").reverse().join("") + s.slice(0, -5); }

  function interject(s) {
    const str = String(s);
    const p = str.length % 2 !== 0 ? str[str.length - 1] : "";
    const sCore = str.length % 2 !== 0 ? str.slice(0, -1) : str;
    const h = Math.floor(sCore.length / 2);
    let out = "";
    for (let i = 0; i < h; i++) out += sCore[i] + sCore[i + h];
    return out + p;
  }

  function inverJect(s) {
    const str = String(s);
    const p = str.length % 2 !== 0 ? str[str.length - 1] : "";
    const sCore = str.length % 2 !== 0 ? str.slice(0, -1) : str;
    let evens = "", odds = "";
    for (let i = 0; i < sCore.length; i++) {
      if (i % 2 === 0) evens += sCore[i];
      else odds += sCore[i];
    }
    return evens + odds + p;
  }

  function bSplit(s, f = 4) {
    const bStr = binTail(s);
    const l = bStr.length;
    const rem = l % f;
    const parts = ["1"];
    for (let i = 0; i < l - rem; i += f) parts.push(bStr.slice(i, i + f).split("").reverse().join(""));
    if (rem) parts.push(bStr.slice(l - rem));
    return parseBase2(parts.join(""));
  }

  function kSplit(s, k) {
    const sBin = binTail(s);
    const kStr = String(k).replace(/0/g, "");
    if (!kStr) return parseBase2("1" + sBin.split("").reverse().join(""));
    const kDigits = kStr.split("").map((d) => parseInt(d, 10) + 1);
    const kLen = kDigits.length;
    const sLen = sBin.length;
    const chunks = [];
    let idx = 0;
    let kIdx = 0;
    while (idx < sLen) {
      const step = kDigits[kIdx % kLen];
      chunks.push(sBin.slice(idx, idx + step).split("").reverse().join(""));
      idx += step;
      kIdx++;
    }
    return parseBase2("1" + chunks.join(""));
  }

  function keySplit(n, k, y = 1) {
    const m = y === 1 ? String(k) : String(k).split("").reverse().join("");
    let res = BigInt(n);
    for (let i = 0; i < m.length; i++) res = bSplit(res, parseInt(m[i], 10) + 2);
    return res;
  }

  function baseSplit(n, k, b = 8, y = 1) {
    const bN = BigInt(b);
    const m = 65536;
    let nDigits = fastAnyBaseList(n, b);
    let z = fastAnyBaseList(k, m).filter((x) => x.length >= 2 && x.length <= 10);
    if (!z.length) z = [String(Number(BigInt(k) % BigInt(m - 2)) + 2)];
    const targetLen = (y === 1) ? nDigits.length + 1 : nDigits.length;
    let loops = 0;
    while (z.length < targetLen) {
      const nextK = BigInt(z[z.length - 1]) + BigInt(m);
      z.push(...fastAnyBaseList(nextK, m).filter((x) => x.length >= 2 && x.length <= 10));
      if (++loops > 1000) break;
    }
    if (z.length < targetLen) z.push(...new Array(targetLen - z.length).fill(z[z.length - 1]));
    if (y === 1) {
      const guard = pyMod(1n - (BigInt(z[0]) % bN), bN);
      nDigits = [String(guard)].concat(nDigits);
      return fromAnyBase(nDigits.map((x, i) => String(pyMod(BigInt(x) + BigInt(z[i]), bN))), b);
    }
    const outDigits = nDigits.map((x, i) => String(pyMod(BigInt(x) - BigInt(z[i]), bN)));
    return outDigits.length <= 1 ? 0n : fromAnyBase(outDigits.slice(1), b);
  }

  function Ap(n, m, p) { return (BigInt(n) * BigInt(m)).toString().slice(0, p); }
  function Bp(n, p) {
    const n0 = n.charCodeAt(0) - 48;
    let out = "";
    for (let i = 0; i < p; i++) out += String((n.charCodeAt(i % n.length) - 48 + n0) % 10);
    return out;
  }
  function Cp(n, m, p) { return (BigInt(n) * BigInt(n.slice(0, 3 % n.length))).toString().slice(0, p); }
  function Dp(n, m, p) {
    let out = "";
    for (let i = 0; i < p; i++) out += Math.abs((n.charCodeAt(i % n.length) - 48) * (m.charCodeAt(i % m.length) - 48));
    return out.slice(0, p);
  }

  function Ep(n, p) {
    let total = 0n;
    const ln = n.length;
    for (let i = 0; i < p; i++) {
      const a = (n.charCodeAt(i % ln) - 48) + 1;
      const b = (n.charCodeAt((i + 1) % ln) - 48) + 1;
      const v = PI * (1 / a / b);
      const frac = v - Math.floor(v);
      let sFrac = String(frac);
      if (sFrac === "0") sFrac = "0.0";
      else if (!sFrac.includes(".")) sFrac = sFrac + ".0";
      const token = sFrac.slice(2);
      total += token ? BigInt(token) : 0n;
    }
    return total.toString().slice(-p);
  }

  function processKey(n, m = 0) {
    let ns = String(n);
    let ms = m ? String(m) : String(n);
    const p = ns.length;
    const r = parseInt(ns[0], 10);
    const tIdx = (ms.length > r) ? (parseInt(ms[r], 10) % p) : (p - 1);
    const t = parseInt(ns[tIdx], 10);
    const a = (r + t) % 6;
    const b = pyMod(BigInt(r - t), 6n);

    let res =
      (a === 0) ? Ap(ns, ms, p) :
      (a === 1) ? Bp(ns, p) :
      (a === 2) ? Cp(ns, ms, p) :
      (a === 3) ? Dp(ns, ms, p) :
      (a === 4) ? Ep(ns, p) :
      Ap(Bp(Cp(Dp(Ep(ns, p), ms, p), ms, p), p), ms, p);

    res =
      (Number(b) === 0) ? Cp(res, ms, p) :
      (Number(b) === 1) ? Dp(res, ms, p) :
      (Number(b) === 2) ? Ap(Bp(Cp(Dp(Ep(res, p), ms, p), ms, p), p), ms, p) :
      (Number(b) === 3) ? Bp(res, p) :
      (Number(b) === 4) ? Ap(res, ms, p) :
      Ap(Bp(Cp(Dp(Ep(res, p), ms, p), ms, p), p), ms, p);

    const a2 = res.split("").find((x) => x !== "0" && !isNaN(x)) || "2";
    const b2 = res.slice(1).split("").find((x) => x !== "0" && !isNaN(x)) || "3";
    const folded = String(bSplit(bSplit(BigInt(res) + BigInt(pRotate(res)))));
    const finalNum = tDecimal(qRotate(folded), 10) + BigInt(a2 + b2 + "0".repeat(p - 2));
    return (finalNum + BigInt(ms)).toString().slice(-p);
  }

  function checkData(n, i) {
    let nv = BigInt(n);
    let iv = BigInt(i);
    while (nv < ten79) { nv *= 3n; nv += iv; iv += iv; }
    const s = nv.toString();
    let acc = 0n;
    for (let j = 0; j < s.length; j += 80) acc += parseDec(s.slice(j, j + 80));
    return kSplit(BigInt(qRotate(String(bSplit(acc))) + processKey(acc)), acc);
  }

  function getKey(n, x = 78) {
    let nv = BigInt(n);
    while (true) {
      nv = (nv / 8n) + BigInt(Ep((nv / 5n).toString(), nv.toString().length));
      if (nv.toString().length <= x) return nv.toString();
    }
  }

  function fold64(h) {
    let s = String(h).toLowerCase().replace(/[^0-9a-f]/g, "");
    if (!s) return "0".repeat(64);
    if (s.length < 64) s = s.repeat(Math.floor(64 / s.length) + 1);
    const out = new Array(64).fill(0);
    for (let i = 0; i < s.length; i++) out[i % 64] ^= parseInt(s[i], 16);
    return out.map((x) => digits16[x]).join("");
  }

  function getE(hex64) {
    const x = String(hex64).toLowerCase().padStart(64, "0").slice(-64);
    const s4 = (parseHex(x.slice(0, 4)) + parseHex(x.slice(-4))).toString().replace(/^0+/, "") || "0";
    const s4f = s4.slice(0, 4);
    const n = Number(parseDec(s4f));
    if (n < 4096) return n;
    if (n % 2 === 0) return Number(parseDec(s4f.slice(0, -1) || "0")) + (s4f.length > 1 && s4f[s4f.length - 2] === "0" ? 100 : 0);
    return Number(parseDec(s4f.slice(1) || "0")) + (s4f.length > 1 && s4f[1] === "0" ? 100 : 0);
  }

  function manipulateKey(n) {
    const nn = BigInt(n);
    return fDecimal(tDecimal(hexLower(nn), 16) + parseHex(fDecimal(nn, 16)), 16).slice(-63, -1);
  }

  function fetchKey(n) {
    const nn = BigInt(n);
    const cd = checkData(nn + 90n, (nn % 7n) + 1n);
    const gk = getKey(cd, 79);
    const md = manipulateData(gk, nn);
    return manipulateKey(tDecimal(md, 10));
  }

  function getB(hexStr) {
    const h = fold64(hexStr);
    const f = parseHex(h.slice(0, 4));
    const l = parseHex(h.slice(-4));
    const seedVal = Number((((f >> 8n) ^ (l & 255n) ^ (f & 255n) ^ (l >> 8n)) & 255n));

    let mh = "";
    for (let i = 0; i < 64; i += 2) {
      const byte = pyMod(parseHex(h.slice(i, i + 2)) - BigInt(seedVal), 256n);
      mh += digits16[Number(byte / 16n)] + digits16[Number(byte % 16n)];
    }

    const mhVal = hexLower(parseHex(mh) + parseHex(h));
    const baseParam = parseHex(mhVal.slice(0, 4).padStart(4, "0"));
    const nVal = parseHex(mhVal);
    const kVal = parseHex(mhVal.slice(-4).padStart(4, "0"));
    const splitVal = baseSplit(nVal, kVal, Number((baseParam & 4096n) + 64n), 1);
    const splitHex = hexLower(splitVal);
    const sFull = hexLower(parseHex(h) + parseHex(splitHex));
    const s = fold64(sFull);
    return [s, getE(s)];
  }

  function hashKey(n) { return getB(fetchKey(n)); }
  function shepKeyFromString(s) { return hashKey(toBytes(String(s)))[0].toLowerCase(); }

  function generatePKey(n = 0) {
    if (typeof n === "string") return hashKey(toBytes(n))[0].toLowerCase();
    const chars = gChar(62);
    const seedVal = bytesToBigIntBE(randBytes32()) ^ BigInt(Date.now());
    const r = new DeterministicRng32(seedVal);
    const ln = Number(r.randint(64, 256));
    const sArr = [];
    for (let i = 0; i < ln; i++) sArr.push(chars[Number(r.randBelow(62n))]);
    r.shuffle(sArr);
    const base62 = sArr.join("");
    return hashKey(tDecimal(base62, 62))[0].toLowerCase();
  }

  function pData(n, keys, b) {
    let res = BigInt(n);
    const bN = BigInt(b);
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      res = keySplit(res, key, 1);
      res = tDecimal(manipulateData(res.toString(), key), 10);
      res = baseSplit(res, key, Number(bN), 1);
      res = kSplit(res, key.toString());
      if (parseInt(key.toString()[0], 10) % 2 === 1) res = BigInt(interject(res.toString()));
    }
    return res;
  }

  function dData(n, keys, b) {
    let res = BigInt(n);
    const bN = BigInt(b);
    for (let i = keys.length - 1; i >= 0; i--) {
      const key = keys[i];
      if (parseInt(key.toString()[0], 10) % 2 === 1) res = BigInt(inverJect(res.toString()));
      res = kSplit(res, key.toString());
      const bs = baseSplit(res, key, Number(bN), 0);
      const fDecStr = fDecimal(bs, 10);
      const invStr = inverseData(fDecStr, key);
      res = keySplit(BigInt(invStr), key, 0);
    }
    return res;
  }

  function _plainSizeBytes(s) { return 1 + utf16leEncodeBytes(String(s)).length; }

  function _sepChar(i) {
    const a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    return a[i % a.length];
  }

  function _toBytesBin(b) {
    const bb = b instanceof Uint8Array ? b : new Uint8Array(b);
    const out = new Uint8Array(1 + bb.length);
    out[0] = 1;
    out.set(bb, 1);
    return bytesToBigIntBE(out);
  }

  function _fromBytesBin(n) {
    const b = bigIntToBytesBE(n);
    if (!b.length || b[0] !== 1) throw new Error("byte sentinel missing");
    return b.slice(1);
  }

  function _chunkBytes(b, chunkSize = 2048) {
    if (chunkSize <= 0) throw new Error("chunkSize must be > 0");
    const bb = b instanceof Uint8Array ? b : new Uint8Array(b);
    if (!bb.length) return [new Uint8Array(0)];
    const out = [];
    for (let i = 0; i < bb.length; i += chunkSize) out.push(bb.slice(i, i + chunkSize));
    return out;
  }

  function _buildHeader(chunkSize, origLen, compLen, lens) {
    const out = ["shz1"];
    const nums = [String(chunkSize), String(origLen), String(compLen), String(lens.length)];
    for (let i = 0; i < lens.length; i++) nums.push(String(lens[i]));
    for (let i = 0; i < nums.length; i++) {
      out.push(nums[i]);
      if (i !== nums.length - 1) out.push(_sepChar(i));
    }
    out.push("a0a0");
    return out.join("");
  }

  function _parseHeader(payload) {
    if (!payload.startsWith("shz1")) throw new Error("missing header prefix");
    const t = payload.indexOf("a0a0");
    if (t === -1) throw new Error("missing header terminator");
    const header = payload.slice(0, t + 4);
    const body = payload.slice(t + 4);
    const core = header.slice(4, -4);
    if (!core) throw new Error("empty header core");

    const nums = [];
    let i = 0;
    let sepIdx = 0;
    while (i < core.length) {
      let j = i;
      while (j < core.length) {
        const o = core.charCodeAt(j);
        if (o < 48 || o > 57) break;
        j++;
      }
      if (j === i) throw new Error("expected digits in header");
      nums.push(parseInt(core.slice(i, j), 10));
      if (j === core.length) break;
      const expected = _sepChar(sepIdx);
      if (core[j] !== expected) throw new Error("header separator mismatch");
      sepIdx++;
      i = j + 1;
    }

    if (nums.length < 4) throw new Error("header too short");
    const chunkSize = nums[0];
    const origLen = nums[1];
    const compLen = nums[2];
    const total = nums[3];
    const lens = nums.slice(4);
    if (total !== lens.length) throw new Error("chunk count mismatch");
    return { header, body, chunkSize, origLen, compLen, lens };
  }

  function _encryptIntWithKey(nInt, hKey) {
    const e = getE(hKey);
    const key0 = tDecimal(hKey, 16);
    const b = e;
    const keys = [key0];
    let key = key0;
    for (let i = 0; i < 9; i++) { key = BigInt(processKey(key)); keys.push(key); }
    let n = BigInt(nInt);
    n = n + (key / BigInt(b));
    n = pData(n, keys, b);
    return fDecimal(n, 62);
  }

  function _decryptIntWithKey(cText, hKey) {
    const e = getE(hKey);
    const key0 = tDecimal(hKey, 16);
    const b = e;
    let n = tDecimal(cText, 62);
    const keys = [key0];
    let key = key0;
    for (let i = 0; i < 9; i++) { key = BigInt(processKey(key)); keys.push(key); }
    n = dData(n, keys, b);
    n = n - (key / BigInt(b));
    return n;
  }

  function _hexNibble(c) {
    const o = c.charCodeAt(0);
    if (48 <= o && o <= 57) return o - 48;
    if (97 <= o && o <= 102) return o - 87;
    if (65 <= o && o <= 70) return o - 55;
    throw new Error("non-hex");
  }

  function _hexToNibbles(h) {
    if (typeof h !== "string" || h.length !== 64) throw new Error("keyHex must be 64 hex chars");
    const out = new Array(64);
    for (let i = 0; i < 64; i++) out[i] = _hexNibble(h[i]);
    return out;
  }

  function _lcg(x) {
    return (48271 * (x % 2147483647)) % 2147483647;
  }

  function _idx(n, s) {
    const r = new Array(n);
    for (let i = 0; i < n; i++) r[i] = i;
    let x = s || 1;
    for (let i = n - 1; i > 0; i--) {
      x = _lcg(x);
      const j = x % (i + 1);
      const tmp = r[i];
      r[i] = r[j];
      r[j] = tmp;
    }
    return r;
  }

  function permuteBySeed(t, s) {
    const n = t.length;
    if (n < 2) return t;
    const r = _idx(n, s);
    const out = new Array(n);
    for (let i = 0; i < n; i++) out[i] = t[r[i]];
    return out.join("");
  }

  function unpermuteBySeed(t, s) {
    const n = t.length;
    if (n < 2) return t;
    const r = _idx(n, s);
    const inv = new Array(n);
    for (let p = 0; p < n; p++) inv[r[p]] = p;
    const out = new Array(n);
    for (let i = 0; i < n; i++) out[i] = t[inv[i]];
    return out.join("");
  }

  function deriveSeeds(keyHex, steps) {
    const nibbles = _hexToNibbles(keyHex);
    const m = 2147483647;
    let acc = 1;
    let cum = 0;
    const out = new Array(steps);
    for (let i = 0; i < steps; i++) {
      const v = nibbles[i % nibbles.length];
      acc = (acc * 131 + v + 1) % m;
      cum = (cum + acc + (i + 1) * 17) % m;
      out[i] = cum || 1;
    }
    return out;
  }

  function obfuscate(text, keyHex, steps = 64) {
    const seeds = deriveSeeds(keyHex, steps);
    let t = text;
    for (let i = 0; i < seeds.length; i++) t = permuteBySeed(t, seeds[i]);
    return t;
  }

  function deobfuscate(obfText, keyHex, steps = 64) {
    const seeds = deriveSeeds(keyHex, steps);
    let t = obfText;
    for (let i = seeds.length - 1; i >= 0; i--) t = unpermuteBySeed(t, seeds[i]);
    return t;
  }

  function _getZlib() {
    try {
      if (typeof require === "function") return require("zlib");
    } catch (e) {}
    return null;
  }

  function zlibCompress(u8, level = 9) {
    const b = u8 instanceof Uint8Array ? u8 : new Uint8Array(u8);
    const z = _getZlib();
    if (z && z.deflateSync) {
      const buf = z.deflateSync(Buffer.from(b), { level });
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    }
    if (root.pako && typeof root.pako.deflate === "function") {
      const out = root.pako.deflate(b, { level });
      return out instanceof Uint8Array ? out : new Uint8Array(out);
    }
    throw new Error("zlib compress unavailable (need Node 'zlib' or browser 'pako')");
  }

  function zlibDecompress(u8) {
    const b = u8 instanceof Uint8Array ? u8 : new Uint8Array(u8);
    const z = _getZlib();
    if (z && z.inflateSync) {
      const buf = z.inflateSync(Buffer.from(b));
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    }
    if (root.pako && typeof root.pako.inflate === "function") {
      const out = root.pako.inflate(b);
      return out instanceof Uint8Array ? out : new Uint8Array(out);
    }
    throw new Error("zlib decompress unavailable (need Node 'zlib' or browser 'pako')");
  }

  function encryptData(n, k = 0) {
    if (typeof n !== "string") throw new Error("encryptData expects a string");

    if (_plainSizeBytes(n) <= 2048) {
      let nn = toBytes(n);
      let hKey;
      let e;
      if (k) {
        const kk = String(k).toLowerCase();
        if (!isHex64(kk)) throw new Error("personalKey must be exactly 64 hex digits");
        hKey = kk;
        e = getE(hKey);
      } else {
        const hk = hashKey(nn);
        hKey = hk[0];
        e = hk[1];
      }
      const key0 = tDecimal(hKey, 16);
      const b = e;
      const keys = [key0];
      let key = key0;
      for (let i = 0; i < 9; i++) { key = BigInt(processKey(key)); keys.push(key); }
      nn = nn + (key / BigInt(b));
      nn = pData(nn, keys, b);
      return [fDecimal(nn, 62), hKey];
    }

    let hKey;
    if (k) {
      const kk = String(k).toLowerCase();
      if (!isHex64(kk)) throw new Error("personalKey must be exactly 64 hex digits");
      hKey = kk;
    } else {
      hKey = shepKeyFromString(n);
    }

    const rawBytes = utf16leEncodeBytes(n);
    const compBytes = zlibCompress(rawBytes, 9);
    const parts = _chunkBytes(compBytes, 2048);

    const cipherParts = new Array(parts.length);
    const lens = new Array(parts.length);

    for (let i = 0; i < parts.length; i++) {
      const cPart = _encryptIntWithKey(_toBytesBin(parts[i]), hKey);
      cipherParts[i] = cPart;
      lens[i] = cPart.length;
    }

    const joinedCipher = cipherParts.join("");
    const header = _buildHeader(2048, rawBytes.length, compBytes.length, lens);
    const payload = header + joinedCipher;
    const mixed = obfuscate(payload, hKey, 64);
    return [mixed, hKey];
  }

  function decryptData(n, k) {
    const kk = String(k || "").toLowerCase();
    if (!isHex64(kk)) throw new Error("personalKey must be exactly 64 hex digits");

    if (typeof n === "string") {
      let payloadGuess = null;
      try { payloadGuess = deobfuscate(n, kk, 64); } catch (e) { payloadGuess = null; }

      if (payloadGuess && payloadGuess.startsWith("shz1") && payloadGuess.indexOf("a0a0") !== -1) {
        const payload = deobfuscate(n, kk, 64);
        const parsed = _parseHeader(payload);

        const body = parsed.body;
        const lens = parsed.lens;
        const compLen = parsed.compLen;
        const origLen = parsed.origLen;

        const compOut = new Uint8Array(compLen);
        let outPos = 0;
        let pos = 0;
        for (let i = 0; i < lens.length; i++) {
          const L = lens[i];
          const cPart = body.slice(pos, pos + L);
          pos += L;
          const pInt = _decryptIntWithKey(cPart, kk);
          const chunk = _fromBytesBin(pInt);
          compOut.set(chunk, outPos);
          outPos += chunk.length;
        }

        if (outPos !== compLen) throw new Error("compressed length mismatch");
        const rawBytes = zlibDecompress(compOut);
        if (rawBytes.length !== origLen) throw new Error("original length mismatch");
        return utf16leDecodeBytes(rawBytes);
      }
    }

    const e = getE(kk);
    const key0 = tDecimal(kk, 16);
    const b = e;
    let nn = tDecimal(n, 62);

    const keys = [key0];
    let key = key0;
    for (let i = 0; i < 9; i++) { key = BigInt(processKey(key)); keys.push(key); }

    nn = dData(nn, keys, b);
    nn = nn - (key / BigInt(b));
    return fromBytes(nn);
  }

  return {
    gChar,
    isHex64,
    sanitizeHex64,
    hexLower,

    DeterministicRng32,

    hashKey,
    shepKeyFromString,
    generatePKey,

    deriveSeeds,
    permuteBySeed,
    unpermuteBySeed,
    obfuscate,
    deobfuscate,

    encryptData,
    decryptData,

    zlibCompress,
    zlibDecompress,

    _buildHeader,
    _parseHeader
  };
});