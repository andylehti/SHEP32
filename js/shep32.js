/*
SHEP32 universal module.
Node:
  const shep = require("./shep32.js")
  const res = await shep.runCli(["--text", "abc"])
Browser:
  <script src="shep32.js"></script>
  const res = await SHEP32.runCli('--text "abc"')
  const withFiles = await SHEP32.runCli('--encrypt-file sample.txt --key secret', { files: { 'sample.txt': new TextEncoder().encode('hello') } })
  // res.files contains any files written by the command in browser mode.
*/

(function(root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory()
  else root.SHEP32 = factory()
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
const isNode = typeof process !== 'undefined' && process.versions && process.versions.node
let fs = null, path = null, crypto = null, zlib = null
if (isNode) {
  fs = require('fs')
  path = require('path')
  crypto = require('crypto')
  zlib = require('zlib')
} else {
  const textEncoder = new TextEncoder()
  const textDecoder = new TextDecoder()
  function u8(x) { return x instanceof Uint8Array ? x : new Uint8Array(x) }
  function utf8Encode(s) { return textEncoder.encode(String(s)) }
  function utf8Decode(b) { return textDecoder.decode(u8(b)) }
  function utf16leEncode(s) {
    s = String(s)
    const out = new Uint8Array(s.length * 2)
    for (let i = 0; i < s.length; ++i) {
      const c = s.charCodeAt(i)
      out[i * 2] = c & 255
      out[i * 2 + 1] = c >>> 8
    }
    return out
  }
  function utf16leDecode(b) {
    b = u8(b)
    let out = ''
    for (let i = 0; i + 1 < b.length; i += 2) out += String.fromCharCode(b[i] | (b[i + 1] << 8))
    return out
  }
  const BProto = Object.create(Uint8Array.prototype)
  BProto.toString = function(enc = 'utf8') {
    if (enc === 'hex') return Array.from(this, x => x.toString(16).padStart(2, '0')).join('')
    if (enc === 'utf16le') return utf16leDecode(this)
    return utf8Decode(this)
  }
  BProto.readUInt32LE = function(off) { return ((this[off]) | (this[off + 1] << 8) | (this[off + 2] << 16) | (this[off + 3] << 24)) >>> 0 }
  BProto.readUInt32BE = function(off) { return (((this[off] << 24) >>> 0) | (this[off + 1] << 16) | (this[off + 2] << 8) | this[off + 3]) >>> 0 }
  BProto.writeUInt32LE = function(v, off) { this[off] = v & 255; this[off + 1] = (v >>> 8) & 255; this[off + 2] = (v >>> 16) & 255; this[off + 3] = (v >>> 24) & 255; return off + 4 }
  BProto.writeUInt32BE = function(v, off) { this[off] = (v >>> 24) & 255; this[off + 1] = (v >>> 16) & 255; this[off + 2] = (v >>> 8) & 255; this[off + 3] = v & 255; return off + 4 }
  BProto.write = function(str, off = 0, enc = 'utf8') { const src = Buffer.from(str, enc); this.set(src, off); return src.length }
  BProto.copy = function(target, targetStart = 0, start = 0, end = this.length) { target.set(this.subarray(start, end), targetStart); return end - start }
  BProto.subarray = function(start, end) { return wrap(Uint8Array.prototype.subarray.call(this, start, end)) }
  BProto.slice = function(start, end) { return wrap(Uint8Array.prototype.slice.call(this, start, end)) }
  function wrap(arr) { Object.setPrototypeOf(arr, BProto); return arr }
  const Buffer = {
    from(val, enc) {
      if (val == null) return wrap(new Uint8Array(0))
      if (val instanceof Uint8Array) return wrap(new Uint8Array(val))
      if (ArrayBuffer.isView(val)) return wrap(new Uint8Array(val.buffer.slice(val.byteOffset, val.byteOffset + val.byteLength)))
      if (val instanceof ArrayBuffer) return wrap(new Uint8Array(val.slice(0)))
      if (Array.isArray(val)) return wrap(new Uint8Array(val))
      if (typeof val === 'string') {
        if (enc === 'hex') {
          const s = val.length % 2 ? '0' + val : val
          const out = new Uint8Array(s.length / 2)
          for (let i = 0; i < out.length; ++i) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16)
          return wrap(out)
        }
        if (enc === 'utf16le') return wrap(utf16leEncode(val))
        return wrap(utf8Encode(val))
      }
      if (typeof val === 'number') return wrap(new Uint8Array(val))
      return wrap(new Uint8Array(val))
    },
    alloc(n) { return wrap(new Uint8Array(n)) },
    concat(arrs) {
      let total = 0
      for (const a of arrs) total += a.length
      const out = new Uint8Array(total)
      let pos = 0
      for (const a of arrs) { out.set(a, pos); pos += a.length }
      return wrap(out)
    },
    byteLength(s, enc = 'utf8') { return Buffer.from(s, enc).length }
  }
  globalThis.Buffer = Buffer
  const _files = new Map()
  fs = {
    _files,
    setFiles(obj = {}) {
      _files.clear()
      for (const k of Object.keys(obj)) {
        const v = obj[k]
        _files.set(k, typeof v === 'string' ? Buffer.from(v, 'utf8') : Buffer.from(v))
      }
    },
    getFiles() {
      const out = {}
      for (const [k, v] of _files.entries()) out[k] = Buffer.from(v)
      return out
    },
    existsSync(p) { return _files.has(String(p)) },
    readFileSync(p, enc = null) {
      const v = _files.get(String(p))
      if (!v) throw new Error('failed to open file: ' + p)
      if (enc === 'utf8') return v.toString('utf8')
      return Buffer.from(v)
    },
    writeFileSync(p, data, enc = null) {
      const b = typeof data === 'string' ? Buffer.from(data, enc === 'utf16le' ? 'utf16le' : 'utf8') : Buffer.from(data)
      _files.set(String(p), b)
    },
    statSync(p) {
      const v = _files.get(String(p))
      if (!v) throw new Error('failed to stat file: ' + p)
      return { size: v.length }
    }
  }
  path = {
    basename(p) { p = String(p).replace(/\\/g, '/'); const i = p.lastIndexOf('/'); return i === -1 ? p : p.slice(i + 1) }
  }
  function rotr(x, n) { return (x >>> n) | (x << (32 - n)) }
  function sha256Sync(data) {
    data = Buffer.from(data)
    const K = [1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298]
    const H = [1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225]
    const bitLen = data.length * 8
    const withOne = data.length + 1
    const padLen = (withOne % 64 <= 56 ? 56 - (withOne % 64) : 120 - (withOne % 64))
    const msg = Buffer.alloc(data.length + 1 + padLen + 8)
    msg.set(data, 0)
    msg[data.length] = 0x80
    let hi = Math.floor(bitLen / 0x100000000), lo = bitLen >>> 0
    msg[msg.length - 8] = (hi >>> 24) & 255
    msg[msg.length - 7] = (hi >>> 16) & 255
    msg[msg.length - 6] = (hi >>> 8) & 255
    msg[msg.length - 5] = hi & 255
    msg[msg.length - 4] = (lo >>> 24) & 255
    msg[msg.length - 3] = (lo >>> 16) & 255
    msg[msg.length - 2] = (lo >>> 8) & 255
    msg[msg.length - 1] = lo & 255
    const W = new Uint32Array(64)
    for (let i = 0; i < msg.length; i += 64) {
      for (let t = 0; t < 16; ++t) {
        const j = i + t * 4
        W[t] = (((msg[j] << 24) >>> 0) | (msg[j + 1] << 16) | (msg[j + 2] << 8) | msg[j + 3]) >>> 0
      }
      for (let t = 16; t < 64; ++t) {
        const s0 = (rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3)) >>> 0
        const s1 = (rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10)) >>> 0
        W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0
      }
      let [a,b,c,d,e,f,g,h] = H
      for (let t = 0; t < 64; ++t) {
        const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0
        const ch = ((e & f) ^ (~e & g)) >>> 0
        const temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0
        const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0
        const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0
        const temp2 = (S0 + maj) >>> 0
        h = g; g = f; f = e; e = (d + temp1) >>> 0; d = c; c = b; b = a; a = (temp1 + temp2) >>> 0
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0
    }
    const out = Buffer.alloc(32)
    for (let i = 0; i < 8; ++i) out.writeUInt32BE(H[i], i * 4)
    return out
  }
  function poly1305Tag(oneTimeKey, aad, ciphertext) {
    oneTimeKey = Buffer.from(oneTimeKey); aad = Buffer.from(aad); ciphertext = Buffer.from(ciphertext)
    const rBytes = Buffer.from(oneTimeKey.subarray(0, 16))
    rBytes[3] &= 15; rBytes[7] &= 15; rBytes[11] &= 15; rBytes[15] &= 15
    rBytes[4] &= 252; rBytes[8] &= 252; rBytes[12] &= 252
    let r = 0n, s = 0n
    for (let i = 15; i >= 0; --i) r = (r << 8n) + BigInt(rBytes[i])
    for (let i = 31; i >= 16; --i) s = (s << 8n) + BigInt(oneTimeKey[i])
    const P = (1n << 130n) - 5n
    let acc = 0n
    function proc(bytes) {
      for (let off = 0; off < bytes.length; off += 16) {
        const chunk = bytes.subarray(off, Math.min(bytes.length, off + 16))
        let n = 1n
        for (let i = chunk.length - 1; i >= 0; --i) n = (n << 8n) + BigInt(chunk[i])
        acc = ((acc + n) * r) % P
      }
    }
    function pad16(bytes) { return bytes.length % 16 === 0 ? Buffer.alloc(0) : Buffer.alloc(16 - (bytes.length % 16)) }
    proc(aad); if (aad.length % 16) proc(pad16(aad))
    proc(ciphertext); if (ciphertext.length % 16) proc(pad16(ciphertext))
    const lens = Buffer.alloc(16)
    let al = BigInt(aad.length), cl = BigInt(ciphertext.length)
    for (let i = 0; i < 8; ++i) { lens[i] = Number(al & 255n); al >>= 8n; lens[8 + i] = Number(cl & 255n); cl >>= 8n }
    proc(lens)
    let tagNum = (acc + s) & ((1n << 128n) - 1n)
    const tag = Buffer.alloc(16)
    for (let i = 0; i < 16; ++i) { tag[i] = Number(tagNum & 255n); tagNum >>= 8n }
    return tag
  }
  function chacha20Block(key32, counter, nonce12) {
    const state = new Uint32Array(16)
    state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574
    for (let i = 0; i < 8; ++i) state[4 + i] = key32.readUInt32LE(i * 4)
    state[12] = counter >>> 0
    state[13] = nonce12.readUInt32LE(0); state[14] = nonce12.readUInt32LE(4); state[15] = nonce12.readUInt32LE(8)
    const work = new Uint32Array(state)
    function qr(a, b, c, d) {
      work[a] = (work[a] + work[b]) >>> 0; work[d] ^= work[a]; work[d] = ((work[d] << 16) | (work[d] >>> 16)) >>> 0
      work[c] = (work[c] + work[d]) >>> 0; work[b] ^= work[c]; work[b] = ((work[b] << 12) | (work[b] >>> 20)) >>> 0
      work[a] = (work[a] + work[b]) >>> 0; work[d] ^= work[a]; work[d] = ((work[d] << 8) | (work[d] >>> 24)) >>> 0
      work[c] = (work[c] + work[d]) >>> 0; work[b] ^= work[c]; work[b] = ((work[b] << 7) | (work[b] >>> 25)) >>> 0
    }
    for (let i = 0; i < 10; ++i) {
      qr(0,4,8,12); qr(1,5,9,13); qr(2,6,10,14); qr(3,7,11,15)
      qr(0,5,10,15); qr(1,6,11,12); qr(2,7,8,13); qr(3,4,9,14)
    }
    const out = Buffer.alloc(64)
    for (let i = 0; i < 16; ++i) out.writeUInt32LE((work[i] + state[i]) >>> 0, i * 4)
    return out
  }
  function chacha20Xor(key32, nonce12, counter, data) {
    data = Buffer.from(data)
    const out = Buffer.alloc(data.length)
    let blockCount = 0
    for (let off = 0; off < data.length; off += 64) {
      const block = chacha20Block(key32, (counter + blockCount) >>> 0, nonce12)
      const n = Math.min(64, data.length - off)
      for (let i = 0; i < n; ++i) out[off + i] = data[off + i] ^ block[i]
      ++blockCount
    }
    return out
  }
  function chacha20Poly1305EncryptRaw(key32, nonce12, data, aad) {
    const polyKey = chacha20Block(key32, 0, nonce12).subarray(0, 32)
    const ct = chacha20Xor(key32, nonce12, 1, data)
    const tag = poly1305Tag(polyKey, aad, ct)
    return { ct, tag }
  }
  function chacha20Poly1305DecryptRaw(key32, nonce12, data, aad, tag) {
    const polyKey = chacha20Block(key32, 0, nonce12).subarray(0, 32)
    const exp = poly1305Tag(polyKey, aad, data)
    let diff = exp.length ^ tag.length
    for (let i = 0; i < Math.max(exp.length, tag.length); ++i) diff |= (exp[i] || 0) ^ (tag[i] || 0)
    if (diff) throw new Error('wrong key or damaged ciphertext')
    return chacha20Xor(key32, nonce12, 1, data)
  }
  crypto = {
    randomBytes(n) { const out = new Uint8Array(n); globalThis.crypto.getRandomValues(out); return Buffer.from(out) },
    timingSafeEqual(a, b) {
      a = Buffer.from(a); b = Buffer.from(b)
      if (a.length !== b.length) return false
      let diff = 0
      for (let i = 0; i < a.length; ++i) diff |= a[i] ^ b[i]
      return diff === 0
    },
    createHash(name) {
      if (name !== 'sha256') throw new Error('only sha256 is supported in browser')
      const chunks = []
      return {
        update(x) { chunks.push(Buffer.from(x)); return this },
        digest(enc) { const out = sha256Sync(Buffer.concat(chunks)); return enc === 'hex' ? out.toString('hex') : out }
      }
    },
    createCipheriv(name, key, nonce, opts) {
      if (name !== 'chacha20-poly1305') throw new Error('unsupported cipher in browser')
      let aad = Buffer.alloc(0), ct = Buffer.alloc(0), tag = Buffer.alloc(0)
      return {
        setAAD(x) { aad = Buffer.from(x || []); return this },
        update(x) { const res = chacha20Poly1305EncryptRaw(Buffer.from(key), Buffer.from(nonce), Buffer.from(x), aad); ct = res.ct; tag = res.tag; return ct },
        final() { return Buffer.alloc(0) },
        getAuthTag() { return tag }
      }
    },
    createDecipheriv(name, key, nonce, opts) {
      if (name !== 'chacha20-poly1305') throw new Error('unsupported cipher in browser')
      let aad = Buffer.alloc(0), atag = null, out = null
      return {
        setAAD(x) { aad = Buffer.from(x || []); return this },
        setAuthTag(x) { atag = Buffer.from(x); return this },
        update(x) { out = chacha20Poly1305DecryptRaw(Buffer.from(key), Buffer.from(nonce), Buffer.from(x), aad, atag); return out },
        final() { return Buffer.alloc(0) }
      }
    },
    createPrivateKey() { throw new Error('sync private key is not available in browser; use runCli or async helpers') },
    createPublicKey() { throw new Error('sync public key is not available in browser; use runCli or async helpers') },
    sign() { throw new Error('sync sign is not available in browser; use runCli or async helpers') },
    verify() { throw new Error('sync verify is not available in browser; use runCli or async helpers') }
  }
  zlib = {
    deflateSync() { throw new Error('sync compression is not available in browser; use runCli') },
    inflateSync() { throw new Error('sync decompression is not available in browser; use runCli') }
  }
  globalThis.__SHEP32_BROWSER_HELPERS__ = {
    Buffer,
    async deflate(raw) {
      if (typeof CompressionStream === 'undefined') throw new Error('CompressionStream is not available in this browser')
      const cs = new CompressionStream('deflate')
      const w = cs.writable.getWriter()
      await w.write(Buffer.from(raw))
      await w.close()
      const ab = await new Response(cs.readable).arrayBuffer()
      return Buffer.from(ab)
    },
    async inflate(raw) {
      if (typeof DecompressionStream === 'undefined') throw new Error('DecompressionStream is not available in this browser')
      const ds = new DecompressionStream('deflate')
      const w = ds.writable.getWriter()
      await w.write(Buffer.from(raw))
      await w.close()
      const ab = await new Response(ds.readable).arrayBuffer()
      return Buffer.from(ab)
    },
    async edImportPriv(seed) {
      const prefix = Buffer.from('302e020100300506032b657004220420', 'hex')
      return await globalThis.crypto.subtle.importKey('pkcs8', Buffer.concat([prefix, Buffer.from(seed)]), 'Ed25519', true, ['sign'])
    },
    async edPubFromSeed(seed) {
      const priv = await this.edImportPriv(seed)
      const jwk = await globalThis.crypto.subtle.exportKey('jwk', priv)
      if (!jwk.x) throw new Error('browser Ed25519 JWK export did not return a public key')
      const b64 = jwk.x.replace(/-/g, '+').replace(/_/g, '/'); const raw = atob(b64 + '==='.slice((b64.length + 3) % 4)); const out = Buffer.alloc(raw.length); for (let i = 0; i < raw.length; ++i) out[i] = raw.charCodeAt(i); return out
    },
    async edSign(seed, data) {
      const priv = await this.edImportPriv(seed)
      const sig = await globalThis.crypto.subtle.sign('Ed25519', priv, Buffer.from(data, 'utf8'))
      return Buffer.from(sig)
    },
    async edVerify(pubRaw, data, sig) {
      const pub = await globalThis.crypto.subtle.importKey('raw', Buffer.from(pubRaw), 'Ed25519', false, ['verify'])
      return await globalThis.crypto.subtle.verify('Ed25519', pub, Buffer.from(sig), Buffer.from(data, 'utf8'))
    }
  }
}

const gCharBase = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.:;<>?@[]^&()*$%/\\`"\',_!#'
const gAuxBase = 'ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
const KEY_HEADER = '-----BEGIN SHEP KEY-----\n'
const KEY_FOOTER = '\n-----END SHEP KEY-----'
const FILE_MARKER = '__shep_file__'
const DEFAULT_MAX_BYTES = 1000 * 1024
const CHUNK_UNIT = 2048
const FIXED_COUNT = 8
const CLI_VERSION = '2.1.0'
const mask64 = (1n << 64n) - 1n

const piMatrix = [
  [14159265358979312n,5707963267948966n,4719755119659763n,7853981633974483n,6283185307179586n,5235987755982988n,4487989505128276n,39269908169872414n,3490658503988659n,3141592653589793n],
  [5707963267948966n,7853981633974483n,5235987755982988n,39269908169872414n,3141592653589793n,2617993877991494n,2243994752564138n,19634954084936207n,17453292519943295n,15707963267948966n],
  [4719755119659763n,5235987755982988n,3490658503988659n,2617993877991494n,20943951023931953n,17453292519943295n,14959965017094254n,1308996938995747n,11635528346628864n,10471975511965977n],
  [7853981633974483n,39269908169872414n,2617993877991494n,19634954084936207n,15707963267948966n,1308996938995747n,1121997376282069n,9817477042468103n,8726646259971647n,7853981633974483n],
  [6283185307179586n,3141592653589793n,20943951023931953n,15707963267948966n,12566370614359174n,10471975511965977n,8975979010256552n,7853981633974483n,6981317007977318n,6283185307179587n],
  [5235987755982988n,2617993877991494n,17453292519943295n,1308996938995747n,10471975511965977n,8726646259971647n,7479982508547127n,6544984694978735n,5817764173314432n,5235987755982988n],
  [4487989505128276n,2243994752564138n,14959965017094254n,1121997376282069n,8975979010256552n,7479982508547127n,641141357875468n,5609986881410345n,49866550056980846n,4487989505128276n],
  [39269908169872414n,19634954084936207n,1308996938995747n,9817477042468103n,7853981633974483n,6544984694978735n,5609986881410345n,4908738521234052n,4363323129985824n,39269908169872414n],
  [3490658503988659n,17453292519943295n,11635528346628864n,8726646259971647n,6981317007977318n,5817764173314432n,49866550056980846n,4363323129985824n,38785094488762877n,3490658503988659n],
  [3141592653589793n,15707963267948966n,10471975511965977n,7853981633974483n,6283185307179587n,5235987755982988n,4487989505128276n,39269908169872414n,3490658503988659n,31415926535897934n]
]

function lowerStr(s) { return String(s).toLowerCase() }
function trimStr(s) { return String(s).trim() }
function deriveCharset(c) { return gCharBase.slice(0, c) }
function deriveAuxCharset() { return gAuxBase }
function secureRandomBytes(n) { return Buffer.from(crypto.randomBytes(n)) }
function readFileBytes(p) { return Buffer.from(fs.readFileSync(p)) }
function bytesToInt(raw) { let out = 0n; for (const b of raw) out = (out << 8n) + BigInt(b); return out }
function parseDec(s) { if (typeof s === 'bigint') return s; s = String(s); if (!/^[-]?\d+$/.test(s)) throw new Error('bad decimal digit'); return BigInt(s) }
function decStr(n) { return (typeof n === 'bigint' ? n : BigInt(n)).toString(10) }
function parseU64(s, label = 'value') { const v = parseDec(s); if (v < 0n) throw new Error(label + ' must be >= 0'); if (v > 0xffffffffffffffffn) throw new Error(label + ' exceeds uint64 range'); return Number(v) }
function powInt(base, exp) { base = BigInt(base); let out = 1n; let e = BigInt(exp); while (e > 0n) { if (e & 1n) out *= base; e >>= 1n; if (e) base *= base } return out }
function hexNibble(ch) { const c = ch.charCodeAt(0); if (c >= 48 && c <= 57) return c - 48; if (c >= 97 && c <= 102) return c - 87; if (c >= 65 && c <= 70) return c - 55; throw new Error('bad hex digit') }
function hexPairValue(s, i) { return (hexNibble(s[i]) << 4) | hexNibble(s[i + 1]) }
function bytesToHex(data) { return Buffer.from(data).toString('hex') }
function appendHexByte(arr, v) { arr.push((v >> 4).toString(16), (v & 15).toString(16)) }
function parseBits(s) { let out = 0n; for (const ch of s) { out <<= 1n; if (ch === '1') out += 1n; else if (ch !== '0') throw new Error('bad binary digit') } return out }
function parseStdBase(s, base) {
  s = String(s)
  if (!s.length) throw new Error('empty parse string')
  let i = 0, neg = false, out = 0n
  if (s[0] === '-') { neg = true; i = 1 }
  if (i >= s.length) throw new Error('bad parse string')
  for (; i < s.length; ++i) {
    const ch = s[i]
    let v
    if (ch >= '0' && ch <= '9') v = ch.charCodeAt(0) - 48
    else if (ch >= 'a' && ch <= 'f') v = ch.charCodeAt(0) - 87
    else if (ch >= 'A' && ch <= 'F') v = ch.charCodeAt(0) - 55
    else throw new Error('bad digit')
    if (v >= base) throw new Error('digit out of range')
    out = out * BigInt(base) + BigInt(v)
  }
  return neg ? -out : out
}
function encodeHex(n) {
  n = typeof n === 'bigint' ? n : BigInt(n)
  if (n === 0n) return '0'
  const neg = n < 0n
  if (neg) n = -n
  const s = n.toString(16)
  return neg ? '-' + s : s
}
function dropPrefixBit(n) {
  n = typeof n === 'bigint' ? n : BigInt(n)
  if (n < 0n) n = -n
  if (n === 0n) return ''
  const out = n.toString(2)
  return out.length <= 1 ? '' : out.slice(1)
}
function leftPad(v, w) { const s = typeof v === 'string' ? v : decStr(v); return s.length >= w ? s : '0'.repeat(w - s.length) + s }
function truncatePrefix(v, n) { const s = decStr(v); return n <= 0 ? '' : (s.length >= n ? s.slice(0, n) : s + '0'.repeat(n - s.length)) }
function truncatePrefixStr(s, n) { s = String(s); return n <= 0 ? '' : (s.length >= n ? s.slice(0, n) : s + '0'.repeat(n - s.length)) }
function encodeUtf16Le(s) { return Buffer.from(String(s), 'utf16le') }
function decodeSafeText(b) { return Buffer.from(b).toString('utf16le') }
function encodeSentinel(raw) { let out = 1n; for (const x of raw) out = (out << 8n) + BigInt(x); return out }
function encodeTextBlock(t) { return encodeSentinel(encodeUtf16Le(t)) }
function cppIntToBytes(n) {
  n = parseDec(n)
  if (n < 0n) throw new Error('negative integer to bytes')
  if (n === 0n) return Buffer.alloc(0)
  const out = []
  while (n > 0n) { out.push(Number(n & 255n)); n >>= 8n }
  out.reverse()
  return Buffer.from(out)
}
function decodeSentinelBytes(n) {
  const b = cppIntToBytes(n)
  if (!b.length || b[0] !== 1) throw new Error('byte sentinel missing')
  return b.subarray(1)
}
function recoverSentinelBytes(n) {
  const b = cppIntToBytes(n)
  if (!b.length) return Buffer.alloc(0)
  if (b[0] === 1) return b.subarray(1)
  let i = 0
  while (i < b.length && b[i] === 0) ++i
  if (i < b.length && b[i] === 1) return b.subarray(i + 1)
  if (b.length > 1) return b.subarray(1)
  return Buffer.alloc(0)
}
function splitByteBlocks(b, chunkSize = 2048) {
  if (chunkSize <= 0) throw new Error('chunkSize must be > 0')
  if (!b.length) return [Buffer.alloc(0)]
  const out = []
  for (let i = 0; i < b.length; i += chunkSize) out.push(Buffer.from(b.subarray(i, Math.min(b.length, i + chunkSize))))
  return out
}
function verifyZlib(b) {
  if (b.length < 2) return false
  const cmf = b[0], flg = b[1]
  if ((cmf & 0x0f) !== 8) return false
  if ((cmf >> 4) > 7) return false
  return (((cmf << 8) + flg) % 31) === 0
}
function incDecString(s) {
  s = String(s)
  if (!s.length) return '1'
  if (s[0] === '-') {
    if (s === '-1') return '0'
    let a = s.split('')
    let i = a.length
    while (i > 1 && a[i - 1] === '0') { a[i - 1] = '9'; --i }
    if (i <= 1) throw new Error('bad negative decimal string')
    a[i - 1] = String.fromCharCode(a[i - 1].charCodeAt(0) - 1)
    s = a.join('')
    let p = 1
    while (p + 1 < s.length && s[p] === '0') ++p
    if (p > 1) s = '-' + s.slice(p)
    return s === '-0' ? '0' : s
  }
  const a = s.split('')
  let i = a.length
  while (i > 0 && a[i - 1] === '9') { a[i - 1] = '0'; --i }
  if (i === 0) a.unshift('1')
  else a[i - 1] = String.fromCharCode(a[i - 1].charCodeAt(0) + 1)
  return a.join('')
}
function validateFileCap(p, noLimit = false) { const size = fs.statSync(p).size; if (!noLimit && size > DEFAULT_MAX_BYTES) throw new Error('file exceeds default limit; use --no-limit to override') }
function resolveChunkBytes(chunkSizeUnits = 1, chunkBytes = -1) { const out = chunkBytes > 0 ? chunkBytes : chunkSizeUnits * CHUNK_UNIT; if (out < 1) throw new Error('chunk size must be >= 1 byte'); return out }

class DeterministicRng32 {
  constructor(seedValue = 1n) {
    this.n = 624
    this.m = 397
    this.matrixA = 0x9908b0df
    this.upperMask = 0x80000000
    this.lowerMask = 0x7fffffff
    this.mt = new Array(this.n).fill(0)
    this.mti = this.n + 1
    this.initializeSeed(seedValue)
  }
  initializeSeed(seedValue) {
    seedValue = parseDec(seedValue)
    if (seedValue < 0n) seedValue = -seedValue
    const key = []
    let x = seedValue
    while (x > 0n) { key.push(Number(x & 0xffffffffn)); x >>= 32n }
    if (!key.length) key.push(0)
    this.expandSeed(key)
  }
  initializeState(s) {
    this.mt[0] = s >>> 0
    for (let i = 1; i < this.n; ++i) this.mt[i] = (Math.imul(1812433253, (this.mt[i - 1] ^ (this.mt[i - 1] >>> 30))) + i) >>> 0
    this.mti = this.n
  }
  expandSeed(initKey) {
    this.initializeState(19650218)
    let i = 1, j = 0
    const keyLength = initKey.length
    for (let k = Math.max(this.n, keyLength); k > 0; --k) {
      this.mt[i] = (((this.mt[i] ^ Math.imul((this.mt[i - 1] ^ (this.mt[i - 1] >>> 30)), 1664525)) + initKey[j] + j)) >>> 0
      ++i; ++j
      if (i >= this.n) { this.mt[0] = this.mt[this.n - 1]; i = 1 }
      if (j >= keyLength) j = 0
    }
    for (let k = this.n - 1; k > 0; --k) {
      this.mt[i] = (((this.mt[i] ^ Math.imul((this.mt[i - 1] ^ (this.mt[i - 1] >>> 30)), 1566083941)) - i)) >>> 0
      ++i
      if (i >= this.n) { this.mt[0] = this.mt[this.n - 1]; i = 1 }
    }
    this.mt[0] = 0x80000000
    this.mti = this.n
  }
  generateWord() {
    if (this.mti >= this.n) {
      const mag01 = [0, this.matrixA]
      let y
      for (let kk = 0; kk < this.n - this.m; ++kk) {
        y = (this.mt[kk] & this.upperMask) | (this.mt[kk + 1] & this.lowerMask)
        this.mt[kk] = (this.mt[kk + this.m] ^ (y >>> 1) ^ mag01[y & 1]) >>> 0
      }
      for (let kk = this.n - this.m; kk < this.n - 1; ++kk) {
        y = (this.mt[kk] & this.upperMask) | (this.mt[kk + 1] & this.lowerMask)
        this.mt[kk] = (this.mt[kk + (this.m - this.n)] ^ (y >>> 1) ^ mag01[y & 1]) >>> 0
      }
      y = (this.mt[this.n - 1] & this.upperMask) | (this.mt[0] & this.lowerMask)
      this.mt[this.n - 1] = (this.mt[this.m - 1] ^ (y >>> 1) ^ mag01[y & 1]) >>> 0
      this.mti = 0
    }
    let y = this.mt[this.mti++]
    y ^= y >>> 11
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= y >>> 18
    return y >>> 0
  }
  generateBits(k) {
    if (k <= 0) return 0n
    const words = Math.floor((k + 31) / 32)
    let x = 0n
    for (let i = 0; i < words; ++i) x = (x << 32n) | BigInt(this.generateWord())
    const extra = words * 32 - k
    if (extra) x >>= BigInt(extra)
    return x
  }
  boundValue(nVal) {
    nVal = parseDec(nVal)
    if (nVal <= 0n) throw new Error('n must be > 0')
    let t = nVal - 1n, k = 0
    while (t > 0n) { ++k; t >>= 1n }
    if (k <= 0) k = 1
    while (true) { const r = this.generateBits(k); if (r < nVal) return r }
  }
  randint(a, b) { a = parseDec(a); b = parseDec(b); if (a > b) throw new Error('a must be <= b'); return a + this.boundValue(b - a + 1n) }
  shuffle(arr) { for (let i = arr.length - 1; i > 0; --i) { const j = Number(this.boundValue(BigInt(i + 1))); [arr[i], arr[j]] = [arr[j], arr[i]] } }
}

function computeRadixDigits(val, b) {
  val = parseDec(val)
  if (val === 0n) return [0]
  if (val < 0n) throw new Error('negative not supported in radix digits')
  const out = []
  while (val > 0n) { out.push(Number(val % BigInt(b))); val /= BigInt(b) }
  out.reverse()
  return out
}
function decodeRadixStream(parts, b) { let res = 0n; for (const p of parts) res = res * BigInt(b) + BigInt(p); return res }
function encodeRadix(val, b, padTo, charset) {
  val = parseDec(val)
  const out = new Array(padTo).fill(charset[0])
  for (let i = 0; i < padTo; ++i) { const rem = Number(val % BigInt(b)); val /= BigInt(b); out[padTo - 1 - i] = charset[rem] }
  return out.join('')
}
function encodeShift(d, b) {
  d = parseDec(d)
  const c = deriveCharset(b)
  if (b === 1) return c[0].repeat(Number(d + 1n))
  const target = d * BigInt(b - 1) + BigInt(b)
  let n = 0, curBn = 1n
  const powers = [[1, BigInt(b)]]
  while (powers[powers.length - 1][1] <= target) powers.push([powers[powers.length - 1][0] * 2, powers[powers.length - 1][1] * powers[powers.length - 1][1]])
  for (let i = powers.length - 1; i >= 0; --i) if (curBn * powers[i][1] <= target) { curBn *= powers[i][1]; n += powers[i][0] }
  const geomSum = n > 0 ? (powInt(b, n) - BigInt(b)) / BigInt(b - 1) : 0n
  const r = d - geomSum
  return n === 0 ? '' : encodeRadix(r, b, n, c)
}
function decodeShift(c, b) {
  const s = String(c), l = s.length
  if (b === 10) { const geom = l > 1 ? (powInt(10, l) - 10n) / 9n : 0n; return parseDec(s || '0') + geom }
  if (b === 16) {
    const geom = l > 1 ? (powInt(16, l) - 16n) / 15n : 0n
    let v = 0n
    for (const ch of s) v = (v << 4n) + BigInt(hexNibble(ch))
    return v + geom
  }
  const chars = deriveCharset(b)
  const charMap = new Map()
  for (let i = 0; i < b; ++i) charMap.set(chars[i], i)
  let v = 0n
  for (const ch of s) v = v * BigInt(b) + BigInt(charMap.get(ch))
  const geom = b > 1 && l > 1 ? (powInt(b, l) - BigInt(b)) / BigInt(b - 1) : 0n
  return v + geom
}
function generateKeystream(s, n) { const r = new DeterministicRng32(s); let out = ''; for (let i = 0; i < n; ++i) out += String(Number(r.randint(0n, 8n))); return out }
function diffuseSequence(s, c) { const r = new DeterministicRng32(c); let out = ''; for (let i = 0; i < s.length; ++i) out += String(((s.charCodeAt(i) - 48 + Number(r.randint(0n, 8n))) % 10)); return out }
function permutePrefix(s) { const mid = s.slice(2, 5).split('').reverse().join(''); return s.slice(5) + mid + s.slice(0, 2) }
function permuteSuffix(s) { const mid = s.slice(s.length - 5, s.length - 2).split('').reverse().join(''); return s.slice(s.length - 2) + mid + s.slice(0, s.length - 5) }
function distributeBits(s, f = 4) {
  const bitstream = dropPrefixBit(s)
  const width = bitstream.length, rem = width % f
  let out = '1'
  const stop = width - rem
  for (let idx = 0; idx < stop; idx += f) out += bitstream.slice(idx, idx + f).split('').reverse().join('')
  if (rem) out += bitstream.slice(stop)
  return parseBits(out)
}
function diffuseBits(s, k) {
  const bitstream = dropPrefixBit(s)
  let keyText = ''
  for (const ch of String(k)) if (ch !== '0') keyText += ch
  let out = '1'
  if (!keyText.length) return parseBits(out + bitstream.split('').reverse().join(''))
  const stride = [...keyText].map(ch => ch.charCodeAt(0) - 47)
  let pos = 0, turn = 0, width = bitstream.length
  while (pos < width) {
    const step = stride[turn % stride.length]
    const end = Math.min(width, pos + step)
    out += bitstream.slice(pos, end).split('').reverse().join('')
    pos = end
    ++turn
  }
  return parseBits(out)
}
function distributeRadix(n, k, b = 8, y = 1) {
  const seedBase = 1 << 16
  const stateDigits = computeRadixDigits(n, b)
  const schedule = []
  for (const x of computeRadixDigits(k, seedBase)) { const len = String(x).length; if (2 <= len && len <= 10) schedule.push(x) }
  if (!schedule.length) schedule.push(Number((parseDec(k) % BigInt(seedBase - 2)) + 2n))
  const limit = (stateDigits.length + 2) * 40
  const need = y === 1 ? stateDigits.length + 1 : stateDigits.length
  let loops = 0
  while (schedule.length < need) {
    const nextSeed = BigInt(schedule[schedule.length - 1]) + BigInt(seedBase)
    for (const x of computeRadixDigits(nextSeed, seedBase)) { const len = String(x).length; if (2 <= len && len <= 10) schedule.push(x) }
    ++loops
    if (loops > limit) break
  }
  while (schedule.length < need) schedule.push(schedule[schedule.length - 1])
  if (y === 1) {
    const guard = (1 + b - (schedule[0] % b)) % b
    const mixed = [guard, ...stateDigits]
    for (let i = 0; i < mixed.length; ++i) mixed[i] = (mixed[i] + (schedule[i] % b)) % b
    return decodeRadixStream(mixed, b)
  }
  const mixed = [...stateDigits]
  for (let i = 0; i < mixed.length; ++i) mixed[i] = (mixed[i] + b - (schedule[i] % b)) % b
  return mixed.length <= 1 ? 0n : decodeRadixStream(mixed.slice(1), b)
}
function decodeDigit(ch) { return ch.charCodeAt(0) - 48 }
function prefixProduct(n, m, p) { return decStr(parseDec(n) * parseDec(m)).slice(0, p) }
function biasTransform(n, p) { const seed = decodeDigit(n[0]); let out = ''; for (let i = 0; i < p; ++i) out += String((decodeDigit(n[i % n.length]) + seed) % 10); return out }
function prefixSquare(n, m, p) { const take = 3 % n.length; const left = n.slice(0, take); return decStr(parseDec(n) * parseDec(left)).slice(0, p) }
function digitProduct(n, m, p) { let out = '', i = 0; while (out.length < p) { const a = decodeDigit(n[i % n.length]), b = decodeDigit(m[i % m.length]); out += String(Math.abs(a * b)); ++i } return out.slice(0, p) }
function integratePi(n, p) { let acc = 0n; for (let i = 0; i < p; ++i) acc += piMatrix[decodeDigit(n[i % n.length])][decodeDigit(n[(i + 1) % n.length])]; const out = decStr(acc); return out.length <= p ? out : out.slice(out.length - p) }
function executeCascade(state, key, width) { return prefixProduct(biasTransform(prefixSquare(digitProduct(integratePi(state, width), key, width), key, width), width), key, width) }
function processKey(nIn, mIn = 0n) {
  let state = decStr(nIn)
  const key = parseDec(mIn) === 0n ? state : decStr(mIn)
  const width = state.length
  const seed = state.charCodeAt(0) - 48
  const tap = key.length > seed ? (state[(key.charCodeAt(seed) - 48) % width].charCodeAt(0) - 48) : (state[state.length - 1].charCodeAt(0) - 48)
  let routeA = (seed + tap) % 6
  let routeB = (seed - tap) % 6; if (routeB < 0) routeB += 6
  state = routeA === 0 ? prefixProduct(state, key, width) : routeA === 1 ? biasTransform(state, width) : routeA === 2 ? prefixSquare(state, key, width) : routeA === 3 ? digitProduct(state, key, width) : routeA === 4 ? integratePi(state, width) : executeCascade(state, key, width)
  state = routeB === 0 ? prefixSquare(state, key, width) : routeB === 1 ? digitProduct(state, key, width) : routeB === 2 ? executeCascade(state, key, width) : routeB === 3 ? biasTransform(state, width) : routeB === 4 ? prefixProduct(state, key, width) : executeCascade(state, key, width)
  let hi = '2', lo = '3'
  for (const ch of state) if (/\d/.test(ch) && ch !== '0') { hi = ch; break }
  for (let i = 1; i < state.length; ++i) if (/\d/.test(state[i]) && state[i] !== '0') { lo = state[i]; break }
  state = decStr(distributeBits(distributeBits(parseDec(state) + parseDec(permuteSuffix(state)))))
  state = decStr(decodeShift(permutePrefix(state), 10))
  const mask = parseDec(hi + lo + '0'.repeat(width >= 2 ? width - 2 : 0))
  const out = decStr(parseDec(state) + mask + parseDec(key))
  return out.length <= width ? out : out.slice(out.length - width)
}
function deriveBaseFactor(hex64) {
  let x = lowerStr(hex64)
  if (x.length < 64) x = '0'.repeat(64 - x.length) + x
  if (x.length > 64) x = x.slice(x.length - 64)
  let s4 = decStr(parseStdBase(x.slice(0, 4), 16) + parseStdBase(x.slice(x.length - 4), 16))
  while (s4.length > 1 && s4[0] === '0') s4 = s4.slice(1)
  if (!s4.length) s4 = '0'
  if (s4.length > 4) s4 = s4.slice(0, 4)
  const n = Number(s4)
  if (n < 4096) return n
  if ((n & 1) === 0) return Number(s4.slice(0, s4.length - 1)) + ((s4.length > 1 && s4[s4.length - 2] === '0') ? 100 : 0)
  return Number(s4.slice(1)) + ((s4.length > 1 && s4[1] === '0') ? 100 : 0)
}
function rot64(x, r) { x &= mask64; r &= 63n; return r === 0n ? x : (((x << r) | (x >> (64n - r))) & mask64) }
function mix64a(x) { x &= mask64; x ^= x >> 31n; x = (x * 0x7FB5D329728EA185n) & mask64; x ^= x >> 27n; x = (x * 0x81DADEF4BC2DD44Dn) & mask64; x ^= x >> 33n; x = (x * 0xD6E8FEB86659FD93n) & mask64; x ^= x >> 29n; return x & mask64 }
function word64(buf, i) { let out = 0n; for (let j = 0; j < 8; ++j) out |= BigInt(buf[i + j] || 0) << BigInt(8 * j); return out }
function fold64(h) {
  let data = Buffer.from(String(h), 'utf8')
  const n = BigInt(data.length)
  const bitLen = n * 8n
  data = Buffer.concat([data, Buffer.from([0x80])])
  while (data.length % 128 !== 112) data = Buffer.concat([data, Buffer.from([0])])
  const lenA = mix64a(bitLen ^ n ^ 0x9E3779B97F4A7C15n)
  const lenB = mix64a((bitLen << 1n) ^ n ^ 0xC2B2AE3D27D4EB4Fn)
  const tail = Buffer.alloc(24)
  for (let i = 0; i < 8; ++i) tail[i] = Number((bitLen >> BigInt(8 * i)) & 255n)
  for (let i = 0; i < 8; ++i) tail[8 + i] = Number((lenA >> BigInt(8 * i)) & 255n)
  for (let i = 0; i < 8; ++i) tail[16 + i] = Number((lenB >> BigInt(8 * i)) & 255n)
  data = Buffer.concat([data, tail])
  while (data.length % 128 !== 0) data = Buffer.concat([data, Buffer.from([0])])
  let a = 0x243F6A8885A308D3n ^ mix64a(bitLen ^ 0x01n)
  let b = 0x13198A2E03707344n ^ mix64a(bitLen ^ 0x02n)
  let c = 0xA4093822299F31D0n ^ mix64a(bitLen ^ 0x03n)
  let d = 0x082EFA98EC4E6C89n ^ mix64a(bitLen ^ 0x04n)
  let e = 0x452821E638D01377n ^ mix64a(bitLen ^ 0x05n)
  let f = 0xBE5466CF34E90C6Cn ^ mix64a(bitLen ^ 0x06n)
  let g = 0xC0AC29B7C97C50DDn ^ mix64a(bitLen ^ 0x07n)
  let j = 0x3F84D5B5B5470917n ^ mix64a(bitLen ^ 0x08n)
  for (let off = 0; off < data.length; off += 128) {
    const x = []
    for (let i = 0; i < 16; ++i) x.push(word64(data, off + i * 8))
    let w0 = mix64a(x[0] ^ a ^ x[8] ^ 0x9E3779B97F4A7C15n), w1 = mix64a(x[1] ^ b ^ x[9] ^ 0xC2B2AE3D27D4EB4Fn), w2 = mix64a(x[2] ^ c ^ x[10] ^ 0x165667B19E3779F9n), w3 = mix64a(x[3] ^ d ^ x[11] ^ 0x85EBCA77C2B2AE63n), w4 = mix64a(x[4] ^ e ^ x[12] ^ 0x27D4EB2F165667C5n), w5 = mix64a(x[5] ^ f ^ x[13] ^ 0x94D049BB133111EBn), w6 = mix64a(x[6] ^ g ^ x[14] ^ 0xD6E8FEB86659FD93n), w7 = mix64a(x[7] ^ j ^ x[15] ^ 0xA5A3564E27F8862Dn)
    for (let round = 0; round < 12; ++round) {
      const t0 = mix64a(a + w0 + rot64(e ^ w4, 17n) + rot64(f ^ w5, 9n))
      const t1 = mix64a(b + w1 + rot64(f ^ w5, 29n) + rot64(g ^ w6, 21n))
      const t2 = mix64a(c + w2 + rot64(g ^ w6, 41n) + rot64(j ^ w7, 33n))
      const t3 = mix64a(d + w3 + rot64(j ^ w7, 11n) + rot64(a ^ w0, 45n))
      const t4 = mix64a(e + w4 + rot64(a ^ w0, 23n) + rot64(b ^ w1, 37n))
      const t5 = mix64a(f + w5 + rot64(b ^ w1, 31n) + rot64(c ^ w2, 49n))
      const t6 = mix64a(g + w6 + rot64(c ^ w2, 13n) + rot64(d ^ w3, 57n))
      const t7 = mix64a(j + w7 + rot64(d ^ w3, 27n) + rot64(e ^ w4, 39n))
      a = mix64a(t0 ^ rot64(t3, 7n) ^ w1); b = mix64a(t1 ^ rot64(t4, 11n) ^ w2); c = mix64a(t2 ^ rot64(t5, 19n) ^ w3); d = mix64a(t3 ^ rot64(t6, 23n) ^ w4); e = mix64a(t4 ^ rot64(t7, 31n) ^ w5); f = mix64a(t5 ^ rot64(t0, 37n) ^ w6); g = mix64a(t6 ^ rot64(t1, 43n) ^ w7); j = mix64a(t7 ^ rot64(t2, 53n) ^ w0)
      w0 = mix64a(w0 ^ a ^ rot64(w4, 9n)); w1 = mix64a(w1 ^ b ^ rot64(w5, 13n)); w2 = mix64a(w2 ^ c ^ rot64(w6, 17n)); w3 = mix64a(w3 ^ d ^ rot64(w7, 21n)); w4 = mix64a(w4 ^ e ^ rot64(w0, 25n)); w5 = mix64a(w5 ^ f ^ rot64(w1, 29n)); w6 = mix64a(w6 ^ g ^ rot64(w2, 33n)); w7 = mix64a(w7 ^ j ^ rot64(w3, 37n))
      const oa = a, ob = b, oc = c, od = d, oe = e, of = f, og = g, oj = j
      a = oc; c = oe; e = og; g = oa; b = of; d = ob; f = oj; j = od
    }
    a = mix64a(a ^ x[0] ^ x[9] ^ w2); b = mix64a(b ^ x[1] ^ x[10] ^ w3); c = mix64a(c ^ x[2] ^ x[11] ^ w4); d = mix64a(d ^ x[3] ^ x[12] ^ w5); e = mix64a(e ^ x[4] ^ x[13] ^ w6); f = mix64a(f ^ x[5] ^ x[14] ^ w7); g = mix64a(g ^ x[6] ^ x[15] ^ w0); j = mix64a(j ^ x[7] ^ x[8] ^ w1)
  }
  let p = mix64a(a ^ c ^ e ^ g ^ 0x243F6A8885A308D3n), q = mix64a(b ^ d ^ f ^ j ^ 0x13198A2E03707344n), r = mix64a(a ^ b ^ e ^ f ^ 0xA4093822299F31D0n), t = mix64a(c ^ d ^ g ^ j ^ 0x082EFA98EC4E6C89n)
  p = mix64a(p ^ rot64(q, 17n) ^ rot64(r, 31n)); q = mix64a(q ^ rot64(r, 23n) ^ rot64(t, 41n)); r = mix64a(r ^ rot64(t, 29n) ^ rot64(p, 37n)); t = mix64a(t ^ rot64(p, 13n) ^ rot64(q, 47n))
  return leftPad(encodeHex(p), 16) + leftPad(encodeHex(q), 16) + leftPad(encodeHex(r), 16) + leftPad(encodeHex(t), 16)
}
function computeBound(hexStr) {
  let h = lowerStr(hexStr); if (!h.length) h = '0'
  const f = parseStdBase(h.length >= 4 ? h.slice(0, 4) : h, 16)
  const l = parseStdBase(h.length >= 4 ? h.slice(h.length - 4) : h, 16)
  const seedVal = Number((((f >> 8n) ^ (l & 0xffn) ^ (f & 0xffn) ^ (l >> 8n)) & 0xffn))
  const h2 = (h.length & 1) ? ('0' + h) : h
  const mhArr = []
  for (let i = 0; i < h2.length; i += 2) appendHexByte(mhArr, ((hexPairValue(h2, i) - seedVal) & 0xff))
  let mh = mhArr.join('')
  mh = encodeHex(parseStdBase(mh, 16) + parseStdBase(h, 16))
  const baseParam = parseStdBase(mh.length >= 4 ? mh.slice(0, 4) : mh, 16)
  const nVal = parseStdBase(mh, 16)
  const kVal = parseStdBase(mh.length >= 4 ? mh.slice(mh.length - 4) : mh, 16)
  const splitVal = distributeRadix(nVal, kVal, Number((baseParam & 4096n) + 64n), 1)
  const splitHex = encodeHex(splitVal)
  const s = fold64(h + mh + splitHex)
  return [s, deriveBaseFactor(s)]
}
function compressKey(n, width = 78) { n = parseDec(n); while (true) { n = (n / 8n) + parseDec(integratePi(decStr(n / 5n), decStr(n).length)); const s = decStr(n); if (s.length <= width) return s } }
function diffuseKey(n) { return encodeShift(decodeShift(encodeHex(n), 16) + parseStdBase(encodeShift(n, 16), 16), 16) }
function validateState(n, i = 10n) {
  n = parseDec(n); i = parseDec(i)
  if (n < 0n || i < 0n) throw new Error('n and i must be >= 0')
  n += 32n
  const ln = decStr(n).length
  const ten79 = powInt(10, 79)
  while (n < ten79) { n *= 3n; n = n + i; i = i + i }
  i = 10n * (1n << 163n)
  n = parseDec(decStr(n) + '0'.repeat(16) + String(ln))
  for (let k = 0; k < 8; ++k) { n *= 3n; n = n + i; i = i + i }
  n = parseDec(decStr(n * i) + '0'.repeat(8)) + i
  const s = decStr(n)
  const chunkBase = powInt(10, 80), packBase = powInt(10, 82)
  let packed = BigInt(s.length) + 1n
  for (let j = 0; j < s.length; j += 80) {
    const chunk = s.slice(j, j + 80)
    packed = packed * packBase + (BigInt(chunk.length) * chunkBase) + parseDec(chunk)
  }
  const left = permutePrefix(decStr(distributeBits(packed)))
  const right = processKey(packed)
  let leftLen = String(left.length); if (leftLen.length < 6) leftLen = '0'.repeat(6 - leftLen.length) + leftLen
  const mix = parseDec('1' + leftLen + left + right)
  return diffuseBits(mix, decStr(packed))
}
function deriveKeyState(n) {
  const seedState = validateState(parseDec(n) + 90n, (parseDec(n) % 7n) + 1n)
  const compactState = compressKey(seedState, 79)
  const diffusedState = diffuseSequence(compactState, n)
  const decodedState = decodeShift(diffusedState, 10)
  return diffuseKey(decodedState)
}
function computeKeyDigest(n) {
  const chainA = deriveKeyState(n)
  const a = parseStdBase(chainA + encodeHex(n), 16)
  const chainB = deriveKeyState(a)
  return computeBound(chainB)
}
function generateSeedSource() {
  const chars = deriveCharset(62)
  const raw = secureRandomBytes(32)
  const seedVal = bytesToInt(raw) ^ BigInt(process.hrtime.bigint())
  const r = new DeterministicRng32(seedVal)
  const ln = Number(r.randint(64n, 256n))
  const s = []
  for (let i = 0; i < ln; ++i) s.push(chars[Number(r.boundValue(62n))])
  r.shuffle(s)
  return s.join('')
}
function normalizeSeedBytes(x) {
  if (typeof x === 'string') return encodeUtf16Le(x)
  if (typeof x === 'bigint' || typeof x === 'number') return encodeUtf16Le(decStr(x))
  return Buffer.from(x)
}
function normalizeSeedInput(x) { return encodeSentinel(normalizeSeedBytes(x)) }
function diffuseWord64(x) { x = BigInt(x) & mask64; x ^= x >> 30n; x = (x * 0xBF58476D1CE4E5B9n) & mask64; x ^= x >> 27n; x = (x * 0x94D049BB133111EBn) & mask64; x ^= x >> 31n; return x }
function diffuseBlocks(data, v = 1, cols = 73, rows = 72) {
  let raw = Buffer.from(data)
  if (cols < 1 || rows < 1) throw new Error('cols and rows must be >= 1')
  const laneCount = cols
  const blockBytes = Math.max(1, Math.floor(((cols * rows) + 7) / 8))
  const outLen = cols * 5
  const rot = (x, r) => { x &= mask64; r = BigInt(r) & 63n; return r === 0n ? x : (((x << r) | (x >> (64n - r))) & mask64) }
  const mix = x => { x &= mask64; x ^= x >> 30n; x = (x * 0xBF58476D1CE4E5B9n) & mask64; x ^= x >> 27n; x = (x * 0x94D049BB133111EBn) & mask64; x ^= x >> 31n; return x & mask64 }
  const h64 = x => parseStdBase(fold64(x), 16) & mask64
  const runPass = (srcIn, seedA, seedB) => {
    const src = Buffer.from(srcIn)
    const state = new Array(laneCount).fill(0n)
    for (let i = 0; i < laneCount; ++i) state[i] = mix(seedA ^ (BigInt(i + 1) * 0x9E3779B185EBCA87n & mask64) ^ rot(seedB, (i % 31) + 1) ^ (BigInt(src.length + i) * 0xD6E8FEB86659FD93n))
    let blockCount = 0
    for (let off = 0; off < src.length; off += blockBytes) {
      const block = src.subarray(off, Math.min(src.length, off + blockBytes))
      const blockLen = block.length
      let blockState = mix(seedB ^ BigInt(blockCount) ^ BigInt(blockLen) ^ rot(state[blockCount % laneCount], (blockCount % 29) + 1))
      const wordCount = Math.floor((blockLen + 7) / 8)
      for (let wIndex = 0; wIndex < wordCount; ++wIndex) {
        const pos = wIndex * 8
        const word = word64(block, pos)
        const g = off + pos
        const i = Number((word + BigInt(g) + BigInt(blockCount)) % BigInt(laneCount))
        const j = (i + 17 + (wIndex % 13)) % laneCount
        const k = Number((BigInt(i) * 7n + 29n + (word >> 11n)) % BigInt(laneCount))
        const a = state[i], b = state[j], c = state[k]
        const x = mix(word ^ blockState ^ (BigInt(g + 1) * 0x9E3779B185EBCA87n) ^ BigInt(src.length))
        state[i] = mix((a + x + rot(b, 13) + rot(c, 29)) & mask64)
        state[j] = mix(b ^ x ^ rot(a, 17) ^ rot(c, 37))
        state[k] = mix((c + x + rot(b, 43) + rot(a, 53) + BigInt(wordCount) + BigInt(wIndex)) & mask64)
        blockState = mix(blockState ^ x ^ state[i] ^ rot(state[j], 11) ^ rot(state[k], 23))
        if ((wIndex & 7) === 7) {
          const t = (i + j + k + wIndex) % laneCount, u = (t + 31) % laneCount
          state[t] = mix(state[t] ^ blockState ^ rot(state[u], 19) ^ (BigInt(g + 1) * 0xD6E8FEB86659FD93n))
          state[u] = mix((state[u] + state[t] + rot(blockState, 27) + x) & mask64)
        }
      }
      const p = blockCount % laneCount, q = (p + 23) % laneCount, r = (p + 47) % laneCount
      const d = mix(blockState ^ BigInt(blockLen) ^ BigInt(off) ^ BigInt(src.length))
      state[p] = mix(state[p] ^ d ^ rot(blockState, 17))
      state[q] = mix((state[q] + d + rot(state[p], 9) + BigInt(src.length) + BigInt(blockCount)) & mask64)
      state[r] = mix(state[r] ^ rot(d, 33) ^ state[p] ^ state[q] ^ BigInt(blockLen))
      ++blockCount
    }
    const rounds = Math.max(6, Math.floor(rows / 12))
    for (let rnd = 0; rnd < rounds; ++rnd) {
      let seed = mix(seedA ^ seedB ^ BigInt(rnd) ^ BigInt(src.length) ^ state[rnd % laneCount])
      let prev = state[state.length - 1]
      for (let i = 0; i < laneCount; ++i) {
        const cur = state[i], nxt = state[(i + 1) % laneCount], far = state[(i * 7 + rnd + 3) % laneCount]
        const m = mix(cur ^ rot(nxt, ((i + rnd) % 31) + 1) ^ rot(far, ((i * 3 + rnd) % 31) + 1) ^ prev ^ seed ^ BigInt(i) ^ BigInt(src.length))
        state[i] = mix((cur + m + rot(prev, 13) + rot(seed, 1 + ((i + rnd) % 31))) & mask64)
        prev = cur
      }
      const pivot = rnd % laneCount
      state[pivot] = mix(state[pivot] ^ seed ^ rot(state[(pivot + 19) % laneCount], 7))
      state[(pivot + 37) % laneCount] = mix((state[(pivot + 37) % laneCount] + rot(seed, 23) + state[pivot]) & mask64)
    }
    const out = Buffer.alloc(outLen)
    let seed = mix(seedA ^ seedB ^ BigInt(src.length) ^ BigInt(blockCount))
    let pos = 0
    for (let phase = 0; phase < 5; ++phase) {
      for (let i = 0; i < laneCount; ++i) {
        const a = state[i], b = state[(i + phase + 1) % laneCount], c = state[(i * 11 + phase + 7) % laneCount]
        const q = mix(a ^ rot(b, ((phase + i) % 31) + 1) ^ rot(c, ((phase * 7 + i) % 31) + 1) ^ seed ^ (BigInt(phase) << 8n) ^ BigInt(i))
        out[pos++] = Number((q ^ (q >> 8n) ^ (q >> 16n) ^ (q >> 24n)) & 255n)
        state[i] = mix((a + q + rot(c, 17) + rot(seed, 1 + (i % 31))) & mask64)
      }
      seed = mix(seed ^ state[phase % laneCount] ^ rot(state[(phase * 11 + 3) % laneCount], 19))
    }
    return [blockCount, out]
  }
  const totalLen = raw.length
  const head = raw.subarray(0, Math.min(128, raw.length))
  const seedA = diffuseWord64(BigInt(totalLen) ^ BigInt(cols) ^ (BigInt(rows) << 32n) ^ 0x243F6A8885A308D3n)
  const seedB = raw.length === 0 ? diffuseWord64(seedA ^ 0x13198A2E03707344n) : h64(bytesToHex(raw.subarray(0, Math.min(256, raw.length))) + '|' + bytesToHex(raw.subarray(raw.length - Math.min(256, raw.length))) + '|' + String(totalLen))
  const passA = runPass(raw, seedA, seedB)
  const mixIn = Buffer.concat([passA[1], head])
  const arrA64 = passA[1].subarray(0, Math.min(64, passA[1].length))
  const seedC = diffuseWord64(seedB ^ h64(bytesToHex(head) + '|' + bytesToHex(arrA64) + '|' + String(mixIn.length)))
  const passB = runPass(mixIn, seedB, seedC)
  const merged = Buffer.alloc(outLen)
  let mergeSeed = diffuseWord64(seedA ^ seedB ^ seedC ^ BigInt(mixIn.length) ^ BigInt(outLen))
  const headLen = head.length
  for (let i = 0; i < outLen; ++i) {
    const a = passA[1][i], b = passB[1][i], c = headLen ? head[i % headLen] : ((i * 17 + totalLen) & 0xff)
    const m = diffuseWord64(mergeSeed ^ BigInt(a) ^ (BigInt(b) << 8n) ^ (BigInt(c) << 16n) ^ (BigInt(i) << 24n))
    merged[i] = Number((BigInt(a) ^ BigInt(b) ^ BigInt(c) ^ m ^ (m >> 8n) ^ (m >> 16n) ^ (m >> 24n)) & 255n)
    mergeSeed = diffuseWord64(mergeSeed ^ m ^ BigInt(a) ^ (BigInt(b) << 8n) ^ (BigInt(c) << 16n) ^ BigInt(i))
  }
  return merged
}
function computeKeyDigestStream(raw, directBits = 256, laneBits = 336, blockBytes = 4096) { const directBytes = Math.max(1, Math.floor((directBits + 7) / 8)); if (raw.length <= directBytes) return lowerStr(computeKeyDigest(encodeSentinel(raw))[0]); const diffused = diffuseBlocks(raw, 1); return lowerStr(computeKeyDigest(encodeSentinel(diffused))[0]) }
function computeKeyDigestFile(p, directBits = 256, laneBits = 336, blockBytes = 65536) { return computeKeyDigestStream(readFileBytes(p), directBits, laneBits, blockBytes) }
function traceWideState(nIn, i = 10n) {
  nIn = parseDec(nIn); i = parseDec(i)
  if (nIn < 0n || i < 0n) throw new Error('n and i must be >= 0')
  let n = nIn + 32n
  const start = n
  const ln = decStr(n).length
  const ten79 = powInt(10, 79)
  while (n < ten79) { n *= 3n; n = n + i; i = i + i }
  const first = n
  i = 10n * (1n << 163n)
  n = parseDec(decStr(n) + '0'.repeat(16) + String(ln))
  const firstPad = n
  for (let k = 0; k < 8; ++k) { n *= 3n; n = n + i; i = i + i }
  const second = n
  n = parseDec(decStr(n * i) + '0'.repeat(8)) + i
  const third = n
  const s = decStr(n)
  const chunkBase = powInt(10, 80), packBase = powInt(10, 82)
  let packed = BigInt(s.length) + 1n
  for (let j = 0; j < s.length; j += 80) { const chunk = s.slice(j, j + 80); packed = packed * packBase + (BigInt(chunk.length) * chunkBase) + parseDec(chunk) }
  const packedLen = BigInt(s.length), fourth = packed
  const left = permutePrefix(decStr(distributeBits(fourth))), right = processKey(fourth)
  const mix = parseDec('1' + leftPad(BigInt(left.length), 6) + left + right)
  const value = diffuseBits(mix, decStr(fourth))
  return { input:start, first, firstPad, second, third, packedLen, fourth, left, mix, right, value }
}
function bindState(trace, modeId = '32') {
  const parts = [modeId, truncatePrefix(trace.input,24), truncatePrefix(trace.first,96), truncatePrefix(trace.firstPad,96), truncatePrefix(trace.second,96), truncatePrefix(trace.third,96), truncatePrefix(trace.fourth,96), truncatePrefixStr(trace.left,96), truncatePrefix(trace.mix,96), truncatePrefixStr(trace.right,96), truncatePrefix(trace.value,96)]
  const joined = parts.join('|')
  const a = fold64(joined), b = computeBound(a)[0], c = processKey(decodeShift(b, 16)), d = fold64(a + b + c + truncatePrefix(trace.packedLen, 8)), e = computeBound(d + a)[0]
  return fold64(e + d + b + a)
}
function computeHex(trace, modeId = '333', seedHex = '') { const root = seedHex || bindState(trace, modeId + '|BASE'); const a = fold64(root + truncatePrefix(trace.value,128)), b = computeBound(a)[0], c = fold64(b + root + truncatePrefix(trace.mix,128)), d = computeBound(c + a)[0]; return (c + d).slice(0,64) }
function scheduleText(sched) { let out = ''; for (const [pos, ch, val] of sched) out += leftPad(BigInt(pos), 2) + ch + leftPad(BigInt(val), 2); return out }
function deriveInjection(trace, baseHexStr, count = 8, modeId = '333', seedHex = '') {
  if (count < 1 || count > 8) throw new Error('count must be in 1..8')
  const totalLen = 64 + count, aux = deriveAuxCharset(), avail = Array.from({length:totalLen}, (_,i)=>i)
  let state = seedHex || bindState(trace, modeId + '|LOTTERY')
  const sched = []
  for (let i = 0; i < count; ++i) {
    const posSeed = fold64('POS|' + i + '|' + state + '|' + truncatePrefixStr(trace.left,96) + '|' + baseHexStr)
    const valSeed = fold64('VAL|' + i + '|' + state + '|' + truncatePrefixStr(trace.right,96) + '|' + baseHexStr)
    const pick = Number(decodeShift(posSeed, 16) % BigInt(avail.length))
    const pos = avail[pick]
    avail.splice(pick, 1)
    const val = Number(decodeShift(valSeed, 16) % BigInt(aux.length))
    const ch = aux[val]
    sched.push([pos, ch, val])
    state = fold64('ROUND|' + i + '|' + state + '|' + pos + '|' + val + '|' + truncatePrefix(trace.mix,96) + '|' + baseHexStr)
  }
  return sched
}
function distributeSymbols(baseHexStr, sched, count = 8) { const totalLen = 64 + count, out = new Array(totalLen).fill('\0'); for (const [pos, ch] of sched) out[pos] = ch; let j = 0; for (let i = 0; i < totalLen; ++i) if (out[i] === '\0') out[i] = baseHexStr[j++]; return out.join('') }
function computeTraceExtended(trace, count = 8) { const root = bindState(trace, '333|ROOT'), bodyB = computeHex(trace, '333|BASE', root), pepperB = deriveInjection(trace, bodyB, count, '333|LOTTERY', root), raw = distributeSymbols(bodyB, pepperB, count), rebound = fold64(root + raw + scheduleText(pepperB) + truncatePrefix(trace.first,96)), body = computeHex(trace, '333|BASE2', rebound), pepper = deriveInjection(trace, body, count, '333|LOTTERY2', rebound); return distributeSymbols(body, pepper, count) }
function computeTraceDigest(trace) { const root = bindState(trace, '32|FINAL'), a = fold64(root + truncatePrefix(trace.value,128)), b = lowerStr(computeBound(a)[0]), c = fold64(b + root + truncatePrefixStr(trace.right,128)); return c.slice(0,64) }
function generatePrimaryKey(x, directBits = 256, laneBits = 336, blockBytes = 4096) { if (arguments.length === 0 || x === undefined) return computeKeyDigestStream(normalizeSeedBytes(generateSeedSource()), directBits, laneBits, blockBytes); return computeKeyDigestStream(normalizeSeedBytes(x), directBits, laneBits, blockBytes) }
function generateExtendedKey(x, count = 8, directBits = 256, laneBits = 336, blockBytes = 4096) { const raw = x === undefined ? normalizeSeedBytes(generateSeedSource()) : normalizeSeedBytes(x); const directBytes = Math.max(1, Math.floor((directBits + 7) / 8)); if (raw.length <= directBytes) return computeTraceExtended(traceWideState(encodeSentinel(raw)), count); const diffused = diffuseBlocks(raw, 1); return computeTraceExtended(traceWideState(encodeSentinel(diffused)), count) }
function generateKey(x, mode = 0, count = 8, directBits = 256, laneBits = 336, blockBytes = 4096) { return mode === 0 ? generatePrimaryKey(x, directBits, laneBits, blockBytes) : generateExtendedKey(x, count, directBits, laneBits, blockBytes) }
function generateKeyFile(p, mode = 0, count = 8, directBits = 256, laneBits = 336, blockBytes = 65536) { if (mode === 0) return computeKeyDigestFile(p, directBits, laneBits, blockBytes); const raw = readFileBytes(p), directBytes = Math.max(1, Math.floor((directBits + 7) / 8)); if (raw.length <= directBytes) return computeTraceExtended(traceWideState(encodeSentinel(raw)), count); const diffused = diffuseBlocks(raw, 1); return computeTraceExtended(traceWideState(encodeSentinel(diffused)), count) }
function isHex64(k) { return /^[0-9a-fA-F]{64}$/.test(k) }
function deriveSecureSeed() { let s = decStr(bytesToInt(secureRandomBytes(16))); if (s.length < 39) s = '0'.repeat(39 - s.length) + s; return s }
function encodeSeed(msgSeedDec) { let h = encodeHex(parseDec(msgSeedDec)); if (h.length < 32) h = '0'.repeat(32 - h.length) + h; if (h.length > 32) h = h.slice(h.length - 32); return lowerStr(h) }
function expandSeedState(msgSeedDec) { const msgSeedHex = encodeSeed(msgSeedDec), a = fold64('WRAP|SEED|A|' + msgSeedHex), b = fold64('WRAP|SEED|B|' + a + msgSeedHex), c = fold64('WRAP|SEED|C|' + b + a + msgSeedHex); return { saltHex: lowerStr(computeBound(a + b)[0]).slice(0,32), nonceHex: lowerStr(computeBound(b + c)[0]).slice(0,32), ivHex: lowerStr(computeBound(c + a)[0]).slice(0,32) } }
function deriveWrapSeed() { return deriveSecureSeed() }
function packPortableBytes(b) { return encodeShift(encodeSentinel(Buffer.from(b)), 62) }
function unpackPortableBytes(s) { return decodeSentinelBytes(decodeShift(s, 62)) }
function canonicalJson(obj) {
  const keys = Object.keys(obj).sort()
  const parts = []
  for (const k of keys) {
    const v = obj[k]
    if (Array.isArray(v)) parts.push(JSON.stringify(k) + ':[' + v.map(x => String(x)).join(',') + ']')
    else if (typeof v === 'string' && /^-?\d+$/.test(v) && k !== 'alg' && k !== 'authTag' && k !== 'ivHex' && k !== 'msgSeedDec' && k !== 'nonceHex' && k !== 'powHash' && k !== 'saltHex' && k !== 'verify' && k !== 'name' && k !== 'data' && k !== FILE_MARKER) parts.push(JSON.stringify(k) + ':' + v)
    else parts.push(JSON.stringify(k) + ':' + JSON.stringify(v))
  }
  return '{' + parts.join(',') + '}'
}
function parseJson(s) {
  let i = 0
  const ws = () => { while (i < s.length && /\s/.test(s[i])) ++i }
  const need = ch => { ws(); if (s[i] !== ch) throw new Error('bad json'); ++i }
  const parseString = () => {
    ws(); if (s[i] !== '"') throw new Error('bad json string'); ++i
    let out = ''
    while (i < s.length) {
      const ch = s[i++]
      if (ch === '"') return out
      if (ch === '\\') {
        if (i >= s.length) throw new Error('bad json escape')
        const e = s[i++]
        if (e === 'u') { const hx = s.slice(i, i + 4); i += 4; out += String.fromCodePoint(Number(parseStdBase(hx, 16))); }
        else if (e === '"') out += '"'
        else if (e === '\\') out += '\\'
        else if (e === '/') out += '/'
        else if (e === 'b') out += '\b'
        else if (e === 'f') out += '\f'
        else if (e === 'n') out += '\n'
        else if (e === 'r') out += '\r'
        else if (e === 't') out += '\t'
        else throw new Error('bad json escape')
      } else out += ch
    }
    throw new Error('unterminated json string')
  }
  const parseNumber = () => { ws(); const a = i; if (s[i] === '-') ++i; if (i >= s.length || !/[0-9]/.test(s[i])) throw new Error('bad json number'); while (i < s.length && /[0-9]/.test(s[i])) ++i; return s.slice(a, i) }
  const parseNumArray = () => { need('['); const out = []; ws(); if (s[i] === ']') { ++i; return out } while (true) { out.push(parseNumber()); ws(); if (s[i] === ']') { ++i; break } if (s[i] !== ',') throw new Error('bad json array'); ++i } return out }
  const parseObject = () => { const obj = {}; need('{'); ws(); if (s[i] === '}') { ++i; return obj } while (true) { const k = parseString(); need(':'); ws(); if (s[i] === '"') obj[k] = parseString(); else if (s[i] === '[') obj[k] = parseNumArray(); else obj[k] = parseNumber(); ws(); if (s[i] === '}') { ++i; break } if (s[i] !== ',') throw new Error('bad json object'); ++i } return obj }
  const obj = parseObject(); ws(); if (i !== s.length) throw new Error('trailing json'); return obj
}
function packFilePayload(filePath, dataBytes) { return canonicalJson({ [FILE_MARKER]:'1', name:path.basename(filePath), size:String(dataBytes.length), data:packPortableBytes(dataBytes) }) }
function unpackFilePayload(text) { try { const obj = parseJson(text); if (!obj[FILE_MARKER] || obj[FILE_MARKER] !== '1') return null; return { name: obj.name || 'restored.bin', data: unpackPortableBytes(obj.data) } } catch { return null } }
function metaToJsonObj(m, omit = new Set()) {
  const obj = {}
  const addNum = (k, v) => { if (!omit.has(k)) obj[k] = String(v) }
  const addStr = (k, v) => { if (!omit.has(k)) obj[k] = v }
  const addArr = (k, arr) => { if (!omit.has(k)) obj[k] = arr.map(v => String(v)) }
  if (m.alg) addStr('alg', m.alg)
  if (m.authTag) addStr('authTag', m.authTag)
  if (m.chunkSize) addNum('chunkSize', m.chunkSize)
  if (m.cmp || (!omit.has('cmp') && (m.alg || m.compLen || m.origLen))) addNum('cmp', m.cmp || 0)
  addNum('compLen', m.compLen || 0)
  if (m.count) addNum('count', m.count)
  if (m.flags) addNum('flags', m.flags)
  if (m.ivHex) addStr('ivHex', lowerStr(m.ivHex))
  addNum('kdfId', m.kdfId || 0)
  addArr('lens', m.lens || [])
  addNum('macId', m.macId || 0)
  addNum('mode', m.mode || 0)
  if (m.msgSeedDec) addStr('msgSeedDec', m.msgSeedDec)
  if (m.nonceHex) addStr('nonceHex', lowerStr(m.nonceHex))
  addNum('origLen', m.origLen || 0)
  addNum('powBits', m.powBits || 0)
  if (m.powHash) addStr('powHash', lowerStr(m.powHash))
  addNum('powNonce', m.powNonce || '0')
  if (m.saltHex) addStr('saltHex', lowerStr(m.saltHex))
  addNum('suite', m.suite || 0)
  if (m.verify) addStr('verify', lowerStr(m.verify))
  addNum('ver', m.ver || 0)
  return obj
}
function metaFromJsonObj(obj) {
  const getNum = (k, d = '0') => obj[k] === undefined ? d : obj[k]
  const getStr = (k, d = '') => obj[k] === undefined ? d : obj[k]
  return {
    ver:Number(getNum('ver')),
    mode:Number(getNum('mode')),
    alg:getStr('alg'),
    suite:Number(getNum('suite')),
    kdfId:Number(getNum('kdfId')),
    macId:Number(getNum('macId')),
    flags:Number(getNum('flags')),
    chunkSize:Number(getNum('chunkSize')),
    origLen:Number(getNum('origLen')),
    compLen:Number(getNum('compLen')),
    lens:(obj.lens || []).map(v => Number(v)),
    msgSeedDec:getStr('msgSeedDec'),
    saltHex:lowerStr(getStr('saltHex')),
    nonceHex:lowerStr(getStr('nonceHex')),
    ivHex:lowerStr(getStr('ivHex')),
    count:Number(getNum('count', (obj.lens || []).length ? String((obj.lens || []).length) : '0')),
    cmp:Number(getNum('cmp')),
    powBits:Number(getNum('powBits')),
    verify:lowerStr(getStr('verify')),
    authTag:lowerStr(getStr('authTag')),
    powNonce:getNum('powNonce', '0'),
    powHash:lowerStr(getStr('powHash'))
  }
}
function buildMetaCore(m, omit = new Set()) { return canonicalJson(metaToJsonObj(m, omit)) }
function sha256Bytes(data) { return crypto.createHash('sha256').update(Buffer.from(data)).digest() }
function sha256Hex(data) { return bytesToHex(sha256Bytes(data)) }
function leadingZeroBits(digest) { let n = 0; for (const b of digest) { if (b === 0) n += 8; else { let x = b, bits = 0; while (x > 0) { ++bits; x >>= 1 } return n + (8 - bits) } } return n }
function buildPowHeader(meta, bodyPacked) { const omit = new Set(['powNonce','powHash']); const core = buildMetaCore(meta, omit); const bodyHash = sha256Hex(Buffer.from(bodyPacked, 'utf8')); return Buffer.from(core + '|' + bodyHash, 'utf8') }
function fixedBigEndian(dec, len) { let n = parseDec(dec); if (n < 0n) throw new Error('negative fixed big-endian'); const lim = 1n << BigInt(len * 8); if (n >= lim) throw new Error('integer too large for fixed bytes'); const out = Buffer.alloc(len); for (let i = len - 1; i >= 0; --i) { out[i] = Number(n & 255n); n >>= 8n } return out }
function solvePow(meta, bodyPacked, bits = 0, startNonce = '0') { if (bits <= 0) return ['0','']; const prefix = buildPowHeader(meta, bodyPacked); let nonce = parseDec(startNonce); while (true) { const data = Buffer.concat([prefix, fixedBigEndian(decStr(nonce), 16)]); const digest = sha256Bytes(data); if (leadingZeroBits(digest) >= bits) return [decStr(nonce), bytesToHex(digest)]; nonce += 1n } }
function verifyEqual(aIn, bIn) { const a = Buffer.from(String(aIn)), b = Buffer.from(String(bIn)); if (a.length !== b.length) { let x = a.length ^ b.length; const m = Math.max(a.length, b.length); for (let i = 0; i < m; ++i) x |= ((a[i] || 0) ^ (b[i] || 0)); return x === 0 } return crypto.timingSafeEqual(a, b) }
function verifyPow(meta, bodyPacked) { if ((meta.powBits || 0) <= 0) return true; const data = Buffer.concat([buildPowHeader(meta, bodyPacked), fixedBigEndian(meta.powNonce || '0', 16)]); const digest = sha256Bytes(data); return verifyEqual(lowerStr(meta.powHash), bytesToHex(digest)) && leadingZeroBits(digest) >= meta.powBits }
function xrotl32(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0 }
function xquarter(state, a, b, c, d) { state[a] = (state[a] + state[b]) >>> 0; state[d] ^= state[a]; state[d] = xrotl32(state[d], 16); state[c] = (state[c] + state[d]) >>> 0; state[b] ^= state[c]; state[b] = xrotl32(state[b], 12); state[a] = (state[a] + state[b]) >>> 0; state[d] ^= state[a]; state[d] = xrotl32(state[d], 8); state[c] = (state[c] + state[d]) >>> 0; state[b] ^= state[c]; state[b] = xrotl32(state[b], 7) }
function hChaCha20(key32, nonce16) {
  if (key32.length !== 32 || nonce16.length !== 16) throw new Error('bad hchacha input')
  const state = new Uint32Array(16)
  const cst = [0x61707865,0x3320646e,0x79622d32,0x6b206574]
  state[0]=cst[0]; state[1]=cst[1]; state[2]=cst[2]; state[3]=cst[3]
  for (let i = 0; i < 8; ++i) state[4 + i] = key32.readUInt32LE(i * 4)
  for (let i = 0; i < 4; ++i) state[12 + i] = nonce16.readUInt32LE(i * 4)
  const work = new Uint32Array(state)
  for (let i = 0; i < 10; ++i) { xquarter(work,0,4,8,12); xquarter(work,1,5,9,13); xquarter(work,2,6,10,14); xquarter(work,3,7,11,15); xquarter(work,0,5,10,15); xquarter(work,1,6,11,12); xquarter(work,2,7,8,13); xquarter(work,3,4,9,14) }
  const outWords = [work[0],work[1],work[2],work[3],work[12],work[13],work[14],work[15]]
  const out = Buffer.alloc(32)
  for (let i = 0; i < 8; ++i) out.writeUInt32LE(outWords[i] >>> 0, i * 4)
  return out
}
function xChaCha20Poly1305Encrypt(key32, nonce24, data, aad = Buffer.alloc(0)) {
  key32 = Buffer.from(key32); nonce24 = Buffer.from(nonce24); data = Buffer.from(data); aad = Buffer.from(aad)
  if (key32.length !== 32) throw new Error('key must be 32 bytes')
  if (nonce24.length !== 24) throw new Error('nonce must be 24 bytes')
  const subkey = hChaCha20(key32, nonce24.subarray(0, 16))
  const nonce12 = Buffer.alloc(12)
  nonce24.copy(nonce12, 4, 16, 24)
  const cipher = crypto.createCipheriv('chacha20-poly1305', subkey, nonce12, { authTagLength: 16 })
  if (aad.length) cipher.setAAD(aad)
  const ct = Buffer.concat([cipher.update(data), cipher.final()])
  return Buffer.concat([ct, cipher.getAuthTag()])
}
function xChaCha20Poly1305Decrypt(key32, nonce24, data, aad = Buffer.alloc(0)) {
  key32 = Buffer.from(key32); nonce24 = Buffer.from(nonce24); data = Buffer.from(data); aad = Buffer.from(aad)
  if (key32.length !== 32) throw new Error('key must be 32 bytes')
  if (nonce24.length !== 24) throw new Error('nonce must be 24 bytes')
  if (data.length < 16) throw new Error('ciphertext too short')
  const subkey = hChaCha20(key32, nonce24.subarray(0, 16))
  const nonce12 = Buffer.alloc(12)
  nonce24.copy(nonce12, 4, 16, 24)
  const ct = data.subarray(0, data.length - 16), tag = data.subarray(data.length - 16)
  const decipher = crypto.createDecipheriv('chacha20-poly1305', subkey, nonce12, { authTagLength: 16 })
  if (aad.length) decipher.setAAD(aad)
  decipher.setAuthTag(tag)
  try { return Buffer.concat([decipher.update(ct), decipher.final()]) } catch { throw new Error('wrong key or damaged ciphertext') }
}
function isExtendedKey(k, count = 8) { if (k.length !== 64 + count) return false; let auxCount = 0; for (const ch of k) { if (!gCharBase.includes(ch)) return false; if (gAuxBase.includes(ch)) ++auxCount } return auxCount === count }
function unpackExtendedKey(k, count = 8) {
  if (!isExtendedKey(k, count)) throw new Error('invalid extended key')
  let body = '', cur = ''
  const sched = [], segments = []
  for (let pos = 0; pos < k.length; ++pos) {
    const ch = k[pos], p = gAuxBase.indexOf(ch)
    if (p !== -1) { segments.push(cur); cur = ''; sched.push([pos, ch, p]) }
    else { cur += ch; body += ch }
  }
  segments.push(cur)
  const bodyHex = lowerStr(body)
  if (!isHex64(bodyHex) || sched.length !== count) throw new Error('invalid extended key structure')
  const schedText = scheduleText(sched), mixHex = lowerStr(computeBound(fold64('EXT|ROOT|' + bodyHex + '|' + schedText + '|' + count) + bodyHex)[0])
  return { bodyHex, sched, schedText, mixHex, segments }
}
function remixExtendedKey(k, count = 8) {
  const ext = unpackExtendedKey(k, count)
  const peppers = [], vals = []
  for (const [, ch, val] of ext.sched) { peppers.push(ch); vals.push(val) }
  const avail = Array.from({length: ext.segments.length}, (_, i) => i), order = []
  let state = 0n
  for (let i = 0; i < vals.length; ++i) state += BigInt(i + 1) * BigInt(vals[i] + 1)
  state += BigInt(ext.bodyHex.length + count)
  for (let i = 0; i < vals.length; ++i) {
    const v = vals[i]
    const pick = Number((state + BigInt(v) + BigInt(i) + BigInt(v * (i + 3))) % BigInt(avail.length))
    order.push(avail[pick])
    avail.splice(pick, 1)
    state = diffuseWord64(state ^ (BigInt(v + 1) << BigInt((i * 7) % 29)))
  }
  order.push(...avail)
  const remixedSegments = order.map(idx => ext.segments[idx])
  let out = ''
  for (let i = 0; i < peppers.length; ++i) out += remixedSegments[i] + peppers[i]
  out += remixedSegments[remixedSegments.length - 1]
  return [out, order]
}
function computeKeyPair(masterKey, keyMode = 0, count = 8) {
  const mode = keyMode === 0 ? 0 : 333
  if (mode !== 0 && isExtendedKey(masterKey, count)) {
    const ext = unpackExtendedKey(masterKey, count), remix = remixExtendedKey(masterKey, count)
    return { key1: lowerStr(ext.bodyHex), key2: lowerStr(generatePrimaryKey(masterKey + remix[0])), schedText: ext.schedText, mixHex: ext.mixHex, remix: remix[0], order: remix[1] }
  }
  let base = lowerStr(trimStr(masterKey))
  if (!isHex64(base)) base = lowerStr(generatePrimaryKey(masterKey))
  return { key1: base, key2: lowerStr(generatePrimaryKey('PAIR|' + base)), schedText: '', mixHex: '', remix: '', order: [] }
}
function deriveInternalKey(masterKey, keyMode = 0, count = 8, label = 'ROOT') { const pair = computeKeyPair(masterKey, keyMode, count); const seed = fold64('KEY|' + label + '|' + pair.key1 + '|' + pair.key2 + '|' + pair.schedText + '|' + pair.mixHex + '|' + pair.remix + '|' + (keyMode === 0 ? 0 : 333) + '|' + count); return lowerStr(computeBound(seed + pair.key1 + pair.key2)[0]) }
function deriveObfKey(masterKey, keyMode = 0, count = 8) { return deriveInternalKey(masterKey, keyMode, count, 'OBF') }
function resolveKeyString(k, allowAuto = false, keyMode = 0, count = 8) {
  if (k == null) { if (!allowAuto) throw new Error('key/passphrase required'); return [generateKey(undefined, keyMode, count), 0] }
  if (keyMode === 0) { const s = trimStr(k); if (isHex64(s)) return [lowerStr(s), 0]; return [lowerStr(generatePrimaryKey(k)), 1] }
  const s = trimStr(k)
  if (isExtendedKey(s, count)) return [s, 0]
  return [generateExtendedKey(k, count), 1]
}
function deriveMessageKeys(masterKey, saltHex, nonceHex, ivHex, keyMode = 0, count = 8) {
  const encBase = deriveInternalKey(masterKey, keyMode, count, 'ENC'), authBase = deriveInternalKey(masterKey, keyMode, count, 'AUTH'), nonceBase = deriveInternalKey(masterKey, keyMode, count, 'NONCE'), verifyBase = deriveInternalKey(masterKey, keyMode, count, 'VERIFY'), pubBase = deriveInternalKey(masterKey, keyMode, count, 'PUBSEED')
  return {
    encRoot: lowerStr(computeBound(fold64(encBase + saltHex + nonceHex + ivHex) + encBase)[0]),
    authRoot: lowerStr(computeBound(fold64(authBase + ivHex + saltHex + nonceHex) + authBase)[0]),
    nonceRoot: lowerStr(computeBound(fold64(nonceBase + nonceHex + ivHex + saltHex) + nonceBase)[0]),
    verifyRoot: lowerStr(computeBound(fold64(verifyBase + saltHex + ivHex + nonceHex) + verifyBase)[0]),
    pubRoot: lowerStr(computeBound(fold64(pubBase + saltHex + nonceHex + ivHex) + pubBase)[0])
  }
}
function deriveBlockKey(encRoot, chunkIndex, saltHex, nonceHex, ivHex) { let idxHex = encodeHex(BigInt(chunkIndex)); if (idxHex.length < 16) idxHex = '0'.repeat(16 - idxHex.length) + idxHex; if (idxHex.length > 16) idxHex = idxHex.slice(idxHex.length - 16); return lowerStr(computeBound(fold64(encRoot + saltHex + nonceHex + ivHex + idxHex) + encRoot + idxHex)[0]) }
function hexToBytes(sIn) { const s = lowerStr(sIn); if (s.length % 2 !== 0) throw new Error('hex string must have even length'); return Buffer.from(s, 'hex') }
function deriveChunkNonce(nonceRoot, chunkIndex, saltHex, nonceHex, ivHex) { let idxHex = encodeHex(BigInt(chunkIndex)); if (idxHex.length < 16) idxHex = '0'.repeat(16 - idxHex.length) + idxHex; if (idxHex.length > 16) idxHex = idxHex.slice(idxHex.length - 16); const a = lowerStr(computeBound(fold64(nonceRoot + saltHex + idxHex + nonceHex) + nonceRoot)[0]), b = lowerStr(computeBound(fold64(ivHex + idxHex + nonceRoot + saltHex) + nonceHex)[0]); return hexToBytes((a + b).slice(0, 48)) }
function buildChunkAad(meta, idx) { return Buffer.from(canonicalJson({ alg: meta.alg, chunkSize: String(meta.chunkSize), compLen: String(meta.compLen), idx: String(idx), kdfId: String(meta.kdfId), mode: String(meta.mode), msgSeedDec: meta.msgSeedDec, origLen: String(meta.origLen), suite: String(meta.suite), ver: String(meta.ver) }), 'utf8') }
function computeVerifyToken(verifyRoot, meta) { const omit = new Set(['verify','authTag','powNonce','powHash']); return lowerStr(computeBound(fold64('VERIFY|' + verifyRoot + '|' + buildMetaCore(meta, omit)) + verifyRoot)[0]).slice(0, 32) }
function computeAuthTag(authRoot, meta, bodyPacked, detached = 0) { const omit = new Set(['authTag','powNonce','powHash']); let chain = lowerStr(computeBound(fold64('AUTH|' + authRoot + '|' + buildMetaCore(meta, omit) + '|' + detached) + authRoot)[0]); const stride = 256; let idx = 0; for (let off = 0; off < bodyPacked.length; off += stride) { const block = bodyPacked.slice(off, off + stride); let idxHex = encodeHex(BigInt(idx)); if (idxHex.length < 8) idxHex = '0'.repeat(8 - idxHex.length) + idxHex; chain = lowerStr(computeBound(fold64(chain + authRoot + idxHex + block) + authRoot)[0]); ++idx } let idxHex = encodeHex(BigInt(idx)); if (idxHex.length < 8) idxHex = '0'.repeat(8 - idxHex.length) + idxHex; return lowerStr(computeBound(fold64(chain + authRoot + idxHex) + authRoot)[0]) }
function encodeEnvelope(meta, bodyPacked) { const header = buildMetaCore(meta); const payload = Buffer.alloc(4 + Buffer.byteLength(header) + Buffer.byteLength(bodyPacked)); payload.writeUInt32BE(Buffer.byteLength(header), 0); payload.write(header, 4, 'utf8'); payload.write(bodyPacked, 4 + Buffer.byteLength(header), 'utf8'); return packPortableBytes(payload) }
function decodeEnvelope(token) { const payload = unpackPortableBytes(token); if (payload.length < 4) throw new Error('invalid ciphertext envelope'); const n = payload.readUInt32BE(0); if (payload.length < 4 + n) throw new Error('invalid ciphertext envelope'); const header = payload.subarray(4, 4 + n).toString('utf8'); const body = payload.subarray(4 + n).toString('utf8'); return [metaFromJsonObj(parseJson(header)), body] }
function zlibCompress(raw, level = 9) { return Buffer.from(zlib.deflateSync(Buffer.from(raw), { level })) }
function zlibDecompress(raw, expectLen) { return Buffer.from(zlib.inflateSync(Buffer.from(raw))) }
function encryptData(n, k = null, keyMode = 0, count = 8, detached = false, compress = true, chunkSize = 2048, powBits = 0, powStart = '0', saltHexIn = '', nonceHexIn = '', ivHexIn = '') {
  const modeMarker = keyMode === 0 ? 0 : 333
  const resolved = resolveKeyString(k, true, modeMarker, count)
  const hKey = resolved[0], kdfId = resolved[1]
  const msgSeedDec = deriveWrapSeed(), ds = expandSeedState(msgSeedDec)
  const saltHex = saltHexIn ? lowerStr(saltHexIn) : ds.saltHex, nonceHex = nonceHexIn ? lowerStr(nonceHexIn) : ds.nonceHex, ivHex = ivHexIn ? lowerStr(ivHexIn) : ds.ivHex
  const msgKeys = deriveMessageKeys(hKey, saltHex, nonceHex, ivHex, modeMarker, count)
  const rawBytes = encodeUtf16Le(n), compBytes = compress ? zlibCompress(rawBytes, 9) : rawBytes, parts = splitByteBlocks(compBytes, chunkSize)
  const cipherParts = [], lens = []
  for (let idx = 0; idx < parts.length; ++idx) {
    const chunkKey = hexToBytes(deriveBlockKey(msgKeys.encRoot, idx, saltHex, nonceHex, ivHex))
    const chunkNonce = deriveChunkNonce(msgKeys.nonceRoot, idx, saltHex, nonceHex, ivHex)
    const metaAad = { ver:2, alg:'XCHACHA20-POLY1305', mode:modeMarker, suite:keyMode === 0 ? 3 : 4, kdfId, chunkSize, origLen:rawBytes.length, compLen:compBytes.length, msgSeedDec }
    const cPart = xChaCha20Poly1305Encrypt(chunkKey, chunkNonce, parts[idx], buildChunkAad(metaAad, idx))
    const packed = packPortableBytes(cPart)
    cipherParts.push(packed)
    lens.push(packed.length)
  }
  const bodyPacked = cipherParts.join('')
  const meta = { ver:2, mode:modeMarker, alg:'XCHACHA20-POLY1305', suite:keyMode === 0 ? 3 : 4, kdfId, macId:3, flags:detached ? 7 : 3, chunkSize, origLen:rawBytes.length, compLen:compBytes.length, lens, msgSeedDec, saltHex, nonceHex, ivHex, count, cmp:compress ? 1 : 0, powBits }
  meta.verify = computeVerifyToken(msgKeys.verifyRoot, meta)
  meta.authTag = computeAuthTag(msgKeys.authRoot, meta, bodyPacked, detached ? 1 : 0)
  if (powBits > 0) { const pow = solvePow(meta, bodyPacked, powBits, powStart); meta.powNonce = pow[0]; meta.powHash = pow[1] } else { meta.powNonce = '0'; meta.powHash = '' }
  const out = { detached, key: hKey, cipher:'', meta:'', body:'' }
  if (detached) { out.meta = packPortableBytes(Buffer.from(buildMetaCore(meta), 'utf8')); out.body = bodyPacked }
  else out.cipher = encodeEnvelope(meta, bodyPacked)
  return out
}
function decryptDataEx(n, k, keyMode = -1, count = 8, metaPacked = null) {
  let metaObj, bodyPacked
  if (metaPacked) { metaObj = metaFromJsonObj(parseJson(unpackPortableBytes(metaPacked).toString('utf8'))); bodyPacked = n }
  else { const env = decodeEnvelope(n); metaObj = env[0]; bodyPacked = env[1] }
  const modeValue = keyMode < 0 ? metaObj.mode : keyMode, resolvedMode = modeValue === 0 ? 0 : 333, effectiveCount = resolvedMode === 0 ? 8 : (metaObj.count ? metaObj.count : (count >= 1 ? count : 8))
  const resolved = resolveKeyString(k, false, resolvedMode, effectiveCount), hKey = resolved[0]
  const msgKeys = deriveMessageKeys(hKey, metaObj.saltHex, metaObj.nonceHex, metaObj.ivHex, resolvedMode, effectiveCount)
  const expectVerify = computeVerifyToken(msgKeys.verifyRoot, metaObj); if (!verifyEqual(expectVerify, metaObj.verify)) throw new Error('wrong key or damaged ciphertext')
  const expectAuth = computeAuthTag(msgKeys.authRoot, metaObj, bodyPacked, (metaObj.flags & 4) ? 1 : 0); if (!verifyEqual(expectAuth, metaObj.authTag)) throw new Error('wrong key or damaged ciphertext')
  if (!verifyPow(metaObj, bodyPacked)) throw new Error('invalid proof-of-work')
  const parts = []
  let pos = 0
  for (const L of metaObj.lens) { if (pos + L > bodyPacked.length) throw new Error('wrong key or damaged ciphertext'); parts.push(bodyPacked.slice(pos, pos + L)); pos += L }
  if (pos !== bodyPacked.length) throw new Error('wrong key or damaged ciphertext')
  const compOut = []
  const metaAad = { ver:metaObj.ver, alg:metaObj.alg, mode:metaObj.mode, suite:metaObj.suite, kdfId:metaObj.kdfId, chunkSize:metaObj.chunkSize, origLen:metaObj.origLen, compLen:metaObj.compLen, msgSeedDec:metaObj.msgSeedDec }
  for (let idx = 0; idx < parts.length; ++idx) {
    const chunkKey = hexToBytes(deriveBlockKey(msgKeys.encRoot, idx, metaObj.saltHex, metaObj.nonceHex, metaObj.ivHex))
    const chunkNonce = deriveChunkNonce(msgKeys.nonceRoot, idx, metaObj.saltHex, metaObj.nonceHex, metaObj.ivHex)
    const packed = unpackPortableBytes(parts[idx])
    compOut.push(xChaCha20Poly1305Decrypt(chunkKey, chunkNonce, packed, buildChunkAad(metaAad, idx)))
  }
  let rawBytes = Buffer.concat(compOut)
  if (metaObj.cmp === 1) rawBytes = zlibDecompress(rawBytes, metaObj.origLen)
  return decodeSafeText(rawBytes)
}
function privateKeyFromSeed(seed) { const prefix = Buffer.from('302e020100300506032b657004220420', 'hex'); return crypto.createPrivateKey({ key: Buffer.concat([prefix, Buffer.from(seed)]), format: 'der', type: 'pkcs8' }) }
function generatePublicKey(k, keyMode = 0, count = 8) { const resolved = resolveKeyString(k, false, keyMode === 0 ? 0 : 333, count), hKey = resolved[0]; const seed = hexToBytes(deriveInternalKey(hKey, keyMode === 0 ? 0 : 333, count, 'PUBSEED')); const priv = privateKeyFromSeed(seed); const pub = crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' }); return packPortableBytes(pub.subarray(pub.length - 32)) }
function signData(data, k, keyMode = 0, count = 8) { const resolved = resolveKeyString(k, false, keyMode === 0 ? 0 : 333, count), hKey = resolved[0]; const seed = hexToBytes(deriveInternalKey(hKey, keyMode === 0 ? 0 : 333, count, 'PUBSEED')); const priv = privateKeyFromSeed(seed); const sig = crypto.sign(null, Buffer.from(data, 'utf8'), priv); const pub = crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' }); return { signature: packPortableBytes(sig), publicKey: packPortableBytes(pub.subarray(pub.length - 32)) } }
function verifySignature(data, signature, publicKey) { try { const sig = unpackPortableBytes(signature), pub = unpackPortableBytes(publicKey); const prefix = Buffer.from('302a300506032b6570032100', 'hex'); const key = crypto.createPublicKey({ key: Buffer.concat([prefix, pub]), format: 'der', type: 'spki' }); return crypto.verify(null, Buffer.from(data, 'utf8'), key, sig) } catch { return false } }
function generateHashRange(start, hashes, mode = 0, count = 8, directBits = 256, laneBits = 336, blockBytes = 4096, bare = false) { const out = []; let cur = parseDec(start), curText = decStr(start); for (let i = 0; i < hashes; ++i) { const hash = generateKey(curText, mode, count, directBits, laneBits, blockBytes); if (bare) out.push(hash); else { out.push(curText + ' = ' + hash) } cur += 1n; curText = incDecString(curText) } return out }
function writeHashRange(outPath, start, hashes, mode = 0, count = 8, directBits = 256, laneBits = 336, blockBytes = 4096, bare = false) { fs.writeFileSync(outPath, generateHashRange(start, hashes, mode, count, directBits, laneBits, blockBytes, bare).join('\n') + '\n') }
function formatKeyFile(token) { return KEY_HEADER + trimStr(token) + KEY_FOOTER }
function writeKeyFilePath(p, token) { fs.writeFileSync(p, formatKeyFile(token)) }
function parseKeyFileText(text) { const t = String(text).replace(/\r\n/g, '\n'), wrappers = [[trimStr(KEY_HEADER), trimStr(KEY_FOOTER)], ['-----BEGIN SHEP KEY-----', '-----END SHEP KEY-----'], ['-----BEGIN SHEP32 KEY-----', '-----END SHEP32 KEY-----'], ['-----BEGIN SHEP64 KEY-----', '-----END SHEP64 KEY-----'], ['-----BEGIN SHEP333 KEY-----', '-----END SHEP333 KEY-----']]; for (const [kh, kf] of wrappers) { const a = t.indexOf(kh), b = a === -1 ? -1 : t.indexOf(kf, a + kh.length); if (a !== -1 && b !== -1 && b > a) { let mid = t.slice(a + kh.length); const nl = mid.indexOf('\n'); if (nl !== -1) mid = mid.slice(nl + 1); const end = mid.indexOf(kf); if (end !== -1) mid = trimStr(mid.slice(0, end)); if (mid) return mid } } for (const line of t.split(/\r?\n/)) { const x = trimStr(line); if (x) return x } throw new Error('invalid key file format') }
function loadKeyFile(p) { return parseKeyFileText(fs.readFileSync(p, 'utf8')) }


function maybeLoadTokenText(value) {
  const s = trimStr(value)
  try {
    if (!s.length) return s
    if (fs && fs.existsSync && fs.existsSync(s)) {
      const out = fs.readFileSync(s, 'utf8')
      return trimStr(out)
    }
  } catch {}
  return s
}
function ensureExtPath(raw, ext, fallbackName) {
  let s = trimStr(raw)
  if (!s.length) s = fallbackName
  const slash = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'))
  const dot = s.lastIndexOf('.')
  if (dot <= slash) s += ext
  return s
}
function defaultEncOutPath(inPath) {
  const s = String(inPath)
  const slash = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'))
  const dot = s.lastIndexOf('.')
  return dot > slash ? s.slice(0, dot) + '.sh32' : s + '.sh32'
}
function defaultKeyOutPath(cipherPath) {
  const s = String(cipherPath)
  const slash = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'))
  const dot = s.lastIndexOf('.')
  return dot > slash ? s.slice(0, dot) + '.pkey' : s + '.pkey'
}
function endsWithNoCase(s, suffix) { return lowerStr(String(s)).endsWith(lowerStr(String(suffix))) }
function keyBasePath(rawPath) {
  let s = trimStr(rawPath)
  if (!s.length) return 'output'
  if (endsWithNoCase(s, '.sh32.body')) return s.slice(0, -10)
  if (endsWithNoCase(s, '.sh32.meta')) return s.slice(0, -10)
  if (endsWithNoCase(s, '.sh32')) return s.slice(0, -5)
  const slash = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'))
  const dot = s.lastIndexOf('.')
  return dot > slash ? s.slice(0, dot) : s
}
function defaultDetachedBodyPath(basePath) { return keyBasePath(basePath) + '.sh32.body' }
function defaultDetachedMetaPath(basePath) { return keyBasePath(basePath) + '.sh32.meta' }
function defaultDetachedKeyPath(basePath) { return keyBasePath(basePath) + '.pkey' }

async function generatePublicKeyAsync(k, keyMode = 0, count = 8) {
  if (isNode) return generatePublicKey(k, keyMode, count)
  const resolved = resolveKeyString(k, false, keyMode === 0 ? 0 : 333, count), hKey = resolved[0]
  const seed = hexToBytes(deriveInternalKey(hKey, keyMode === 0 ? 0 : 333, count, 'PUBSEED'))
  const pub = await globalThis.__SHEP32_BROWSER_HELPERS__.edPubFromSeed(seed)
  return packPortableBytes(pub)
}
async function signDataAsync(data, k, keyMode = 0, count = 8) {
  if (isNode) return signData(data, k, keyMode, count)
  const resolved = resolveKeyString(k, false, keyMode === 0 ? 0 : 333, count), hKey = resolved[0]
  const seed = hexToBytes(deriveInternalKey(hKey, keyMode === 0 ? 0 : 333, count, 'PUBSEED'))
  const signature = await globalThis.__SHEP32_BROWSER_HELPERS__.edSign(seed, data)
  const publicKey = await globalThis.__SHEP32_BROWSER_HELPERS__.edPubFromSeed(seed)
  return { signature: packPortableBytes(signature), publicKey: packPortableBytes(publicKey) }
}
async function verifySignatureAsync(data, signature, publicKey) {
  if (isNode) return verifySignature(data, signature, publicKey)
  try {
    return await globalThis.__SHEP32_BROWSER_HELPERS__.edVerify(unpackPortableBytes(publicKey), data, unpackPortableBytes(signature))
  } catch { return false }
}
async function encryptDataAsync(n, k = null, keyMode = 0, count = 8, detached = false, compress = true, chunkSize = 2048, powBits = 0, powStart = '0', saltHexIn = '', nonceHexIn = '', ivHexIn = '') {
  if (isNode) return encryptData(n, k, keyMode, count, detached, compress, chunkSize, powBits, powStart, saltHexIn, nonceHexIn, ivHexIn)
  const modeMarker = keyMode === 0 ? 0 : 333
  const resolved = resolveKeyString(k, true, modeMarker, count)
  const hKey = resolved[0], kdfId = resolved[1]
  const msgSeedDec = deriveWrapSeed(), ds = expandSeedState(msgSeedDec)
  const saltHex = saltHexIn ? lowerStr(saltHexIn) : ds.saltHex, nonceHex = nonceHexIn ? lowerStr(nonceHexIn) : ds.nonceHex, ivHex = ivHexIn ? lowerStr(ivHexIn) : ds.ivHex
  const msgKeys = deriveMessageKeys(hKey, saltHex, nonceHex, ivHex, modeMarker, count)
  const rawBytes = encodeUtf16Le(n)
  const compBytes = compress ? await globalThis.__SHEP32_BROWSER_HELPERS__.deflate(rawBytes) : rawBytes
  const parts = splitByteBlocks(compBytes, chunkSize)
  const cipherParts = [], lens = []
  for (let idx = 0; idx < parts.length; ++idx) {
    const chunkKey = hexToBytes(deriveBlockKey(msgKeys.encRoot, idx, saltHex, nonceHex, ivHex))
    const chunkNonce = deriveChunkNonce(msgKeys.nonceRoot, idx, saltHex, nonceHex, ivHex)
    const metaAad = { ver:2, alg:'XCHACHA20-POLY1305', mode:modeMarker, suite:keyMode === 0 ? 3 : 4, kdfId, chunkSize, origLen:rawBytes.length, compLen:compBytes.length, msgSeedDec }
    const cPart = xChaCha20Poly1305Encrypt(chunkKey, chunkNonce, parts[idx], buildChunkAad(metaAad, idx))
    const packed = packPortableBytes(cPart)
    cipherParts.push(packed)
    lens.push(packed.length)
  }
  const bodyPacked = cipherParts.join('')
  const meta = { ver:2, mode:modeMarker, alg:'XCHACHA20-POLY1305', suite:keyMode === 0 ? 3 : 4, kdfId, macId:3, flags:detached ? 7 : 3, chunkSize, origLen:rawBytes.length, compLen:compBytes.length, lens, msgSeedDec, saltHex, nonceHex, ivHex, count, cmp:compress ? 1 : 0, powBits }
  meta.verify = computeVerifyToken(msgKeys.verifyRoot, meta)
  meta.authTag = computeAuthTag(msgKeys.authRoot, meta, bodyPacked, detached ? 1 : 0)
  if (powBits > 0) { const pow = solvePow(meta, bodyPacked, powBits, powStart); meta.powNonce = pow[0]; meta.powHash = pow[1] } else { meta.powNonce = '0'; meta.powHash = '' }
  const out = { detached, key: hKey, cipher:'', meta:'', body:'' }
  if (detached) { out.meta = packPortableBytes(Buffer.from(buildMetaCore(meta), 'utf8')); out.body = bodyPacked }
  else out.cipher = encodeEnvelope(meta, bodyPacked)
  return out
}
async function decryptDataExAsync(n, k, keyMode = -1, count = 8, metaPacked = null) {
  if (isNode) return decryptDataEx(n, k, keyMode, count, metaPacked)
  let metaObj, bodyPacked
  if (metaPacked) { metaObj = metaFromJsonObj(parseJson(unpackPortableBytes(metaPacked).toString('utf8'))); bodyPacked = n }
  else { const env = decodeEnvelope(n); metaObj = env[0]; bodyPacked = env[1] }
  const modeValue = keyMode < 0 ? metaObj.mode : keyMode, resolvedMode = modeValue === 0 ? 0 : 333, effectiveCount = resolvedMode === 0 ? 8 : (metaObj.count ? metaObj.count : (count >= 1 ? count : 8))
  const resolved = resolveKeyString(k, false, resolvedMode, effectiveCount), hKey = resolved[0]
  const msgKeys = deriveMessageKeys(hKey, metaObj.saltHex, metaObj.nonceHex, metaObj.ivHex, resolvedMode, effectiveCount)
  const expectVerify = computeVerifyToken(msgKeys.verifyRoot, metaObj); if (!verifyEqual(expectVerify, metaObj.verify)) throw new Error('wrong key or damaged ciphertext')
  const expectAuth = computeAuthTag(msgKeys.authRoot, metaObj, bodyPacked, (metaObj.flags & 4) ? 1 : 0); if (!verifyEqual(expectAuth, metaObj.authTag)) throw new Error('wrong key or damaged ciphertext')
  if (!verifyPow(metaObj, bodyPacked)) throw new Error('invalid proof-of-work')
  const parts = []
  let pos = 0
  for (const L of metaObj.lens) { if (pos + L > bodyPacked.length) throw new Error('wrong key or damaged ciphertext'); parts.push(bodyPacked.slice(pos, pos + L)); pos += L }
  if (pos !== bodyPacked.length) throw new Error('wrong key or damaged ciphertext')
  const compOut = []
  const metaAad = { ver:metaObj.ver, alg:metaObj.alg, mode:metaObj.mode, suite:metaObj.suite, kdfId:metaObj.kdfId, chunkSize:metaObj.chunkSize, origLen:metaObj.origLen, compLen:metaObj.compLen, msgSeedDec:metaObj.msgSeedDec }
  for (let idx = 0; idx < parts.length; ++idx) {
    const chunkKey = hexToBytes(deriveBlockKey(msgKeys.encRoot, idx, metaObj.saltHex, metaObj.nonceHex, metaObj.ivHex))
    const chunkNonce = deriveChunkNonce(msgKeys.nonceRoot, idx, metaObj.saltHex, metaObj.nonceHex, metaObj.ivHex)
    const packed = unpackPortableBytes(parts[idx])
    compOut.push(xChaCha20Poly1305Decrypt(chunkKey, chunkNonce, packed, buildChunkAad(metaAad, idx)))
  }
  let rawBytes = Buffer.concat(compOut)
  if (metaObj.cmp === 1) rawBytes = await globalThis.__SHEP32_BROWSER_HELPERS__.inflate(rawBytes)
  return decodeSafeText(rawBytes)
}
function parseCliArgs(argv) {
  const opts = { _: [] }
  for (let i = 0; i < argv.length; ++i) {
    const a = argv[i]
    if (!String(a).startsWith('--')) { opts._.push(String(a)); continue }
    const next = argv[i + 1]
    if (next == null || String(next).startsWith('--')) opts[a] = true
    else { opts[a] = String(next); ++i }
  }
  return opts
}
function shellSplit(s) {
  if (Array.isArray(s)) return s.map(x => String(x))
  s = String(s)
  const out = []
  let cur = '', q = ''
  for (let i = 0; i < s.length; ++i) {
    const ch = s[i]
    if (q) {
      if (ch === q) q = ''
      else if (ch === '\\' && q === '"' && i + 1 < s.length) cur += s[++i]
      else cur += ch
    } else {
      if (ch === '"' || ch === "'") q = ch
      else if (/\s/.test(ch)) { if (cur) { out.push(cur); cur = '' } }
      else if (ch === '\\' && i + 1 < s.length) cur += s[++i]
      else cur += ch
    }
  }
  if (q) throw new Error('unterminated quote')
  if (cur) out.push(cur)
  return out
}
function printHelpText(exe) {
  return (
`Usage:
  ${exe} [hash input] [options]
  ${exe} --encrypt TEXT --key KEY [options]
  ${exe} --encrypt-file PATH --key KEY [options]
  ${exe} --decrypt TOKEN --key KEY [options]
  ${exe} --decrypt-file PATH --key KEY [options]
  ${exe} --body BODY --meta META --key KEY [options]

Hash inputs:
  --text TEXT         Generate a SHEP32 or SHEP333 key from UTF-8 text
  --file PATH         Generate a SHEP32 or SHEP333 key from file contents
  --start INT         Starting integer for range generation
  --hashes N          Number of keys to generate from --start
  --out PATH          Write range or cipher output to file

Encryption / decryption:
  --encrypt TEXT      Encrypt UTF-8 text into a .sh32 token
  --encrypt-file PATH Encrypt a file payload
  --decrypt TOKEN     Decrypt a .sh32 token
  --decrypt-file PATH Decrypt a token file
  --stdin             Read payload from stdin
  --delim NAME        Read NAME:BEGIN ... NAME:END from stdin
  --detached          Use detached meta/body format
  --meta META         Detached meta token or file path
  --body BODY         Detached body token or file path
  --key KEY           Explicit SHEP32 or SHEP333 key
  --phrase TEXT       Explicit phrase, even if it looks like a key
  --keyfile PATH      Read a SHEP key from a .pkey file
  --write-key PATH    Save the resulting SHEP key to a .pkey file
  --quiet-key         Do not print the key token
  --no-compress       Disable zlib compression before encryption
  --chunk-size N      Chunk units of 2048 bytes (default 1)
  --chunk-bytes N     Exact chunk size in bytes
  --pow-bits N        Proof-of-work difficulty bits
  --pow-start N       Starting nonce for proof-of-work
  --as-text           Do not auto-restore wrapped files on decrypt
  --no-limit          Override the default encrypt-file size cap
  --no-progress       Disable progress bars

Other features:
  --pubkey            Derive an Ed25519 public key from a SHEP key
  --sign TEXT         Sign UTF-8 text
  --verify TEXT       Verify UTF-8 text using --signature and --public-key
  --pair              Print the internal encryption key pair

General options:
  --mode N            0 = SHEP32 primary, 1 = SHEP333 extended
  --bare              Output only hashes in range mode
  --bench N           Benchmark N hashes; random inputs by default
  --input-bits N      Benchmark input width in 2..256 (default 128)
  --compare           Add diffusion audit against SHA-256
  --deep-audit        Include pair-dependence analysis in compare mode
  --top-count N       Top-cell count for compare mode (default 128)
  --audit-dir PATH    Write detailed audit TSV files to PATH
  --json              Emit JSON instead of plain text when supported
  --version           Show CLI version
  --help              Show this help

Advanced compatibility flags such as --direct-bits, --lane-bits, and --block-bytes are still accepted but hidden from the regular help output.
`)
}
async function runCli(argvInput, ctx = {}) {
  const argv = shellSplit(argvInput)
  const exe = ctx.exe || 'shepCLI.js'
  if (!isNode && ctx.files) fs.setFiles(ctx.files)
  let stdout = '', stderr = '', exitCode = 0
  const out = s => { stdout += String(s) }
  const err = s => { stderr += String(s) }
  try {
    const opts = parseCliArgs(argv)
    const has = name => Object.prototype.hasOwnProperty.call(opts, name)
    const need = name => { if (!has(name)) throw new Error('missing value for ' + name); return String(opts[name]) }
    const optInt = (name, defVal) => has(name) ? parseInt(String(opts[name]), 10) : defVal
    const jsonMode = has('--json')
    const emitObj = obj => out(JSON.stringify(obj) + '\n')
    const mode = has('--mode') ? parseInt(String(opts['--mode']), 10) : 0
    const count = 8
    const directBits = has('--direct-bits') ? parseInt(String(opts['--direct-bits']), 10) : 256
    const laneBits = has('--lane-bits') ? parseInt(String(opts['--lane-bits']), 10) : 336
    const blockBytes = has('--block-bytes') ? parseInt(String(opts['--block-bytes']), 10) : 4096
    const bare = has('--bare')
    const useStdin = has('--stdin')
    const delim = has('--delim') ? String(opts['--delim']) : ''
    const stdinText = ctx.stdin == null ? '' : String(ctx.stdin)
    const readStdinPayload = () => {
      const data = stdinText
      if (!delim) return trimStr(data)
      const start = delim + ':BEGIN', end = delim + ':END'
      const a = data.indexOf(start), b = a === -1 ? -1 : data.indexOf(end, a + start.length)
      if (a === -1 || b === -1) throw new Error('delimiter block not found in stdin')
      return trimStr(data.slice(a + start.length, b))
    }
    if (has('--help') || has('-h')) { out(printHelpText(exe)); return { stdout, stderr, exitCode, files: !isNode ? fs.getFiles() : null } }
    if (has('--version')) { out(exe + ' ' + CLI_VERSION + '\n'); return { stdout, stderr, exitCode, files: !isNode ? fs.getFiles() : null } }
    if (has('--value')) throw new Error('--value is not supported; use --text so leading zeros are preserved')
    if (mode !== 0 && mode !== 1 && mode !== 333) throw new Error('--mode must be 0 or 1')
    if (directBits < 1) throw new Error('--direct-bits must be >= 1')
    const chunkBytes = resolveChunkBytes(has('--chunk-size') ? parseInt(String(opts['--chunk-size']), 10) : 1, has('--chunk-bytes') ? parseInt(String(opts['--chunk-bytes']), 10) : -1)
    const powBits = has('--pow-bits') ? parseInt(String(opts['--pow-bits']), 10) : 0
    const powStart = has('--pow-start') ? String(opts['--pow-start']) : '0'
    const outPath = has('--out') ? String(opts['--out']) : ''
    const noCompress = has('--no-compress')
    const asText = has('--as-text')
    const noLimit = has('--no-limit')
    const quietKey = has('--quiet-key')
    const doDetached = has('--detached')
    const keySourceCount = (has('--key') ? 1 : 0) + (has('--phrase') ? 1 : 0) + (has('--keyfile') ? 1 : 0)
    if (keySourceCount > 1) throw new Error('provide only one of --key, --phrase, or --keyfile')
    const hasKey = keySourceCount > 0
    const keyText = has('--keyfile') ? loadKeyFile(String(opts['--keyfile'])) : (has('--key') ? String(opts['--key']) : (has('--phrase') ? String(opts['--phrase']) : ''))
    if (has('--pair')) {
      const pairMode = mode === 0 ? 0 : 333
      let master
      if (has('--file')) master = generateKeyFile(String(opts['--file']), pairMode === 0 ? 0 : 1, count, directBits, laneBits, blockBytes)
      else if (has('--text')) master = generateKey(String(opts['--text']), pairMode === 0 ? 0 : 1, count, directBits, laneBits, blockBytes)
      else throw new Error('--pair requires --text or --file')
      const pair = computeKeyPair(master, pairMode, count)
      if (jsonMode) emitObj({ ok: true, mode: 'pair', key1: pair.key1, key2: pair.key2, schedText: pair.schedText, mixHex: pair.mixHex, remix: pair.remix })
      else out('key1=' + pair.key1 + '\n' + 'key2=' + pair.key2 + '\n' + 'schedText=' + pair.schedText + '\n' + 'mixHex=' + pair.mixHex + '\n' + 'remix=' + pair.remix + '\n')
      return { stdout, stderr, exitCode, files: !isNode ? fs.getFiles() : null }
    }
    if (has('--pubkey')) {
      if (!hasKey) throw new Error('--key or --keyfile is required for --pubkey')
      const pub = await generatePublicKeyAsync(keyText, mode === 0 ? 0 : 333, count)
      if (jsonMode) emitObj({ ok: true, mode: 'pubkey', publicKey: pub })
      else out(pub + '\n')
      return { stdout, stderr, exitCode, files: !isNode ? fs.getFiles() : null }
    }
    if (has('--sign')) {
      if (!hasKey) throw new Error('--key or --keyfile is required for --sign')
      const payload = useStdin ? readStdinPayload() : String(opts['--sign'])
      const sig = await signDataAsync(payload, keyText, mode === 0 ? 0 : 333, count)
      if (jsonMode) emitObj({ ok: true, mode: 'sign', signature: sig.signature, publicKey: sig.publicKey })
      else out('signature=' + sig.signature + '\n' + 'publicKey=' + sig.publicKey + '\n')
      return { stdout, stderr, exitCode, files: !isNode ? fs.getFiles() : null }
    }
    if (has('--verify')) {
      if (!has('--signature') || !has('--public-key')) throw new Error('--signature and --public-key are required for --verify')
      const payload = useStdin ? readStdinPayload() : String(opts['--verify'])
      const ok = await verifySignatureAsync(payload, maybeLoadTokenText(String(opts['--signature'])), maybeLoadTokenText(String(opts['--public-key'])))
      if (jsonMode) emitObj({ ok: true, mode: 'verify', valid: !!ok })
      else out((ok ? 'true' : 'false') + '\n')
      return { stdout, stderr, exitCode, files: !isNode ? fs.getFiles() : null }
    }
    if (has('--encrypt-file') || (has('--encrypt') && has('--file'))) {
      const src = has('--encrypt-file') ? String(opts['--encrypt-file']) : String(opts['--file'])
      validateFileCap(src, noLimit)
      const keyPtr = hasKey ? keyText : null
      const payload = packFilePayload(src, readFileBytes(src))
      const res = await encryptDataAsync(payload, keyPtr, mode === 0 ? 0 : 333, count, doDetached, !noCompress, chunkBytes, powBits, powStart, '', '', '')
      if (doDetached) {
        const base = outPath ? outPath : keyBasePath(src)
        const bodyPath = defaultDetachedBodyPath(base), metaPath = defaultDetachedMetaPath(base)
        fs.writeFileSync(bodyPath, res.body, 'utf8'); fs.writeFileSync(metaPath, res.meta, 'utf8')
        const keyPath = has('--write-key') ? String(opts['--write-key']) : defaultDetachedKeyPath(base)
        writeKeyFilePath(keyPath, res.key)
        if (jsonMode) emitObj({ ok: true, mode: 'enc', detached: true, body_out: bodyPath, meta_out: metaPath, key_out: keyPath, key: quietKey ? '' : res.key, chunk_bytes: chunkBytes })
        else { out(bodyPath + '\n' + metaPath + '\n' + keyPath + '\n'); if (!quietKey) out(res.key + '\n') }
      } else {
        const cipherPath = outPath ? ensureExtPath(outPath, '.sh32', 'cipher.sh32') : defaultEncOutPath(src)
        fs.writeFileSync(cipherPath, res.cipher, 'utf8')
        const keyPath = has('--write-key') ? String(opts['--write-key']) : defaultKeyOutPath(cipherPath)
        writeKeyFilePath(keyPath, res.key)
        if (jsonMode) emitObj({ ok: true, mode: 'enc', detached: false, out: cipherPath, key_out: keyPath, key: quietKey ? '' : res.key, chunk_bytes: chunkBytes })
        else { out(cipherPath + '\n' + keyPath + '\n'); if (!quietKey) out(res.key + '\n') }
      }
      return { stdout, stderr, exitCode, files: !isNode ? fs.getFiles() : null }
    }
    if (has('--encrypt')) {
      const keyPtr = hasKey ? keyText : null
      const payload = useStdin ? readStdinPayload() : String(opts['--encrypt'])
      const res = await encryptDataAsync(payload, keyPtr, mode === 0 ? 0 : 333, count, doDetached, !noCompress, chunkBytes, powBits, powStart, '', '', '')
      if (doDetached) {
        if (outPath) {
          const bodyPath = defaultDetachedBodyPath(outPath), metaPath = defaultDetachedMetaPath(outPath)
          fs.writeFileSync(bodyPath, res.body, 'utf8'); fs.writeFileSync(metaPath, res.meta, 'utf8')
          const keyPath = has('--write-key') ? String(opts['--write-key']) : defaultDetachedKeyPath(outPath)
          writeKeyFilePath(keyPath, res.key)
          out(bodyPath + '\n' + metaPath + '\n' + keyPath + '\n')
        } else {
          if (jsonMode) emitObj({ ok: true, mode: 'enc', detached: true, body: res.body, meta: res.meta, key: quietKey ? '' : res.key, key_out: has('--write-key') ? String(opts['--write-key']) : '', chunk_bytes: chunkBytes })
          else { out('meta=' + res.meta + '\n' + 'body=' + res.body + '\n')
          if (has('--write-key')) { writeKeyFilePath(String(opts['--write-key']), res.key); out(String(opts['--write-key']) + '\n') }
          else if (!quietKey) out(res.key + '\n') }
        }
      } else {
        if (outPath) {
          const cipherPath = ensureExtPath(outPath, '.sh32', 'cipher.sh32')
          fs.writeFileSync(cipherPath, res.cipher, 'utf8')
          const keyPath = has('--write-key') ? String(opts['--write-key']) : defaultKeyOutPath(cipherPath)
          writeKeyFilePath(keyPath, res.key)
          if (jsonMode) emitObj({ ok: true, mode: 'enc', detached: false, out: cipherPath, key_out: keyPath, chunk_bytes: chunkBytes })
          else out(cipherPath + '\n' + keyPath + '\n')
        } else {
          if (jsonMode) emitObj({ ok: true, mode: 'enc', detached: false, cipher: res.cipher, key: quietKey ? '' : res.key, key_out: has('--write-key') ? String(opts['--write-key']) : '', chunk_bytes: chunkBytes })
          else { out(res.cipher + '\n')
          if (has('--write-key')) { writeKeyFilePath(String(opts['--write-key']), res.key); out(String(opts['--write-key']) + '\n') }
          else if (!quietKey) out(res.key + '\n') }
        }
      }
      return { stdout, stderr, exitCode, files: !isNode ? fs.getFiles() : null }
    }
    if (has('--decrypt-file') || (has('--decrypt') && has('--file')) || has('--body') || has('--meta') || has('--decrypt')) {
      if (!hasKey) throw new Error('--key or --keyfile is required for decryption')
      let pt = '', decMode = mode === 333 ? 333 : (mode === 1 ? 333 : (mode === 0 ? 0 : -1))
      if (has('--body') || has('--meta')) {
        if (!has('--body') || !has('--meta')) throw new Error('--body and --meta must both be provided for detached decryption')
        const metaMaybe = maybeLoadTokenText(String(opts['--meta']))
        pt = await decryptDataExAsync(maybeLoadTokenText(String(opts['--body'])), keyText, decMode, count, metaMaybe)
      } else if (has('--decrypt-file') || (has('--decrypt') && has('--file'))) {
        const src = has('--decrypt-file') ? String(opts['--decrypt-file']) : String(opts['--file'])
        pt = await decryptDataExAsync(trimStr(fs.readFileSync(src, 'utf8')), keyText, decMode, count, null)
      } else {
        const token = useStdin ? readStdinPayload() : String(opts['--decrypt'])
        pt = await decryptDataExAsync(token, keyText, decMode, count, null)
      }
      const restored = !asText ? unpackFilePayload(pt) : null
      if (restored) { const target = outPath ? outPath : restored.name; fs.writeFileSync(target, restored.data); if (jsonMode) emitObj({ ok: true, mode: 'dec', out: target, restored_name: restored.name }) ; else out(target + '\n') }
      else if (outPath) { fs.writeFileSync(outPath, pt, 'utf8'); if (jsonMode) emitObj({ ok: true, mode: 'dec', out: outPath }) ; else out(outPath + '\n') }
      else if (jsonMode) emitObj({ ok: true, mode: 'dec', text: pt })
      else out(pt + '\n')
      return { stdout, stderr, exitCode, files: !isNode ? fs.getFiles() : null }
    }
    if (has('--bench')) {
      const hashes = parseInt(String(opts['--bench']), 10)
      if (!(hashes >= 1)) throw new Error('--bench must be >= 1')
      const inputBits = has('--input-bits') ? parseInt(String(opts['--input-bits']), 10) : 128
      if (inputBits < 2 || inputBits > 256) throw new Error('--input-bits must be in 2..256')
      const randomInputs = !has('--start')
      let last = ''
      const started = Date.now()
      let cur = has('--start') ? parseDec(String(opts['--start'])) : 0n
      for (let i = 0; i < hashes; ++i) {
        let input
        if (randomInputs) {
          if (isNode) input = BigInt('0x' + require('crypto').randomBytes(Math.ceil(inputBits / 8)).toString('hex')) & ((1n << BigInt(inputBits)) - 1n)
          else {
            const bytes = new Uint8Array(Math.ceil(inputBits / 8)); globalThis.crypto.getRandomValues(bytes); input = 0n; for (const b of bytes) input = (input << 8n) + BigInt(b); input &= ((1n << BigInt(inputBits)) - 1n)
          }
        } else { input = cur; cur += 1n }
        last = generateKey(decStr(input), mode, count, directBits, laneBits, blockBytes)
      }
      const elapsed = Math.max(0.000001, (Date.now() - started) / 1000)
      if (jsonMode) emitObj({ ok: true, mode: 'bench', hashes, elapsed: Number(elapsed.toFixed(6)), hashesPerSec: Number((hashes / elapsed).toFixed(6)), last, randomInputs, inputBits })
      else { out('hashes=' + hashes + '\n')
      out('elapsed=' + elapsed.toFixed(6) + '\n')
      out('hashesPerSec=' + (hashes / elapsed).toFixed(6) + '\n')
      out('last=' + last + '\n')
      out('randomInputs=' + (randomInputs ? 'true' : 'false') + '\n')
      out('inputBits=' + inputBits + '\n') }
      return { stdout, stderr, exitCode, files: !isNode ? fs.getFiles() : null }
    }
    if (has('--start') || has('--hashes') || (!!outPath && !has('--encrypt') && !has('--encrypt-file'))) {
      if (!has('--start')) throw new Error('--start is required for range mode')
      if (!has('--hashes')) throw new Error('--hashes is required for range mode')
      const startValue = parseDec(String(opts['--start']))
      const hashes = parseInt(String(opts['--hashes']), 10)
      if (outPath) { writeHashRange(outPath, startValue, hashes, mode, count, directBits, laneBits, blockBytes, bare); if (jsonMode) emitObj({ ok: true, mode: 'range', out: outPath, start: decStr(startValue), hashes, bare }) }
      else { const lines = generateHashRange(startValue, hashes, mode, count, directBits, laneBits, blockBytes, bare); if (jsonMode) emitObj({ ok: true, mode: 'range', start: decStr(startValue), hashes, bare, lines }) ; else out(lines.join('\n') + '\n') }
      return { stdout, stderr, exitCode, files: !isNode ? fs.getFiles() : null }
    }
    if (has('--file')) { const key = generateKeyFile(String(opts['--file']), mode, count, directBits, laneBits, 65536); if (jsonMode) emitObj({ ok: true, mode: 'hash', value: key }) ; else out(key + '\n'); return { stdout, stderr, exitCode, files: !isNode ? fs.getFiles() : null } }
    if (has('--text')) { const key = generateKey(String(opts['--text']), mode, count, directBits, laneBits, blockBytes); if (jsonMode) emitObj({ ok: true, mode: 'hash', value: key }) ; else out(key + '\n'); return { stdout, stderr, exitCode, files: !isNode ? fs.getFiles() : null } }
    const key = generateKey(mode, count, directBits, laneBits, blockBytes)
    if (jsonMode) emitObj({ ok: true, mode: 'key', key })
    else out(key + '\n')
  } catch (e) {
    err('error: ' + e.message + '\n')
    exitCode = 1
  }
  return { stdout, stderr, exitCode, files: !isNode ? fs.getFiles() : null }
}
const api = {
  gCharBase, gAuxBase, KEY_HEADER, KEY_FOOTER, FILE_MARKER, DEFAULT_MAX_BYTES, CHUNK_UNIT, FIXED_COUNT,
  parseDec, parseStdBase, decStr, encodeHex, bytesToHex, bytesToInt, hexToBytes, encodeUtf16Le, decodeSafeText,
  encodeShift, decodeShift, encodeSentinel, decodeSentinelBytes, recoverSentinelBytes, packPortableBytes, unpackPortableBytes,
  generatePrimaryKey, generateExtendedKey, generateKey, generateKeyFile, computeKeyDigestStream, computeKeyDigestFile,
  isExtendedKey, unpackExtendedKey, remixExtendedKey, computeKeyPair, deriveInternalKey, deriveObfKey, resolveKeyString,
  deriveMessageKeys, deriveBlockKey, deriveChunkNonce, computeVerifyToken, computeAuthTag,
  encodeEnvelope, decodeEnvelope, encryptData, decryptDataEx, encryptDataAsync, decryptDataExAsync,
  generatePublicKey, signData, verifySignature, generatePublicKeyAsync, signDataAsync, verifySignatureAsync,
  generateHashRange, writeHashRange,
  packFilePayload, unpackFilePayload,
  formatKeyFile, writeKeyFilePath, parseKeyFileText, loadKeyFile,
  fold64, computeBound, diffuseBlocks, traceWideState, computeTraceExtended, computeTraceDigest,
  runCli, maybeLoadTokenText, ensureExtPath, defaultEncOutPath, defaultKeyOutPath, defaultDetachedBodyPath, defaultDetachedMetaPath, defaultDetachedKeyPath
}
return api
})
