// TAP-draft-private-files: reference derivation, sealing and opening, and the test vectors in vectors.json.
// Version 0x04 is the format of this TAP; 0x03 is the reference deployment's legacy format (Backwards Compatibility).
// Standalone (Node >= 20, WebCrypto and CompressionStream only). MIT License.
// Run: node vectors.mjs           → prints vectors.json
//      node vectors.mjs check     → checks vectors.json against this implementation
import fs from 'node:fs';
const te = new TextEncoder(), td = new TextDecoder();
const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
const unhex = (s) => Uint8Array.from(s.replace(/^0x/, '').match(/../g) || [], (b) => parseInt(b, 16));
const b64u = (u8) => Buffer.from(u8).toString('base64url');
const unb64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'));
const pipe = async (bytes, stream) => new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(stream)).arrayBuffer());
const sha = async (s) => new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(s)));
const hkdf = async (ikm, salt, info) => {
  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: te.encode(salt), info: te.encode(info) }, base, 256));
};

/** Where a file lives: chain ID, container address, path, holder address */
// loc = { chainId, container, path, address }
export const V = {
  4: {
    prfInput: () => sha('tap-private-files/prf/v1'),
    deriveKey: (prf, loc) => hkdf(prf, 'tap-private-files/v4|' + loc.address.toLowerCase(), 'tap-private-files/key|' + loc.path),
    aad: (loc, id, rp) => te.encode(['tap-private-files/v4', String(loc.chainId), loc.container.toLowerCase(), loc.path,
      loc.address.toLowerCase(), b64u(unb64u(id)), rp].join('|')),
  },
  3: {
    prfInput: () => sha('authenticator-backup-prf-v1'),
    deriveKey: (prf, loc) => hkdf(prf, 'authenticator-backup-v3:' + loc.address.toLowerCase(), 'chain-backup-passkey'),
    aad: (loc, id, rp) => te.encode(`${loc.address.toLowerCase()}|${b64u(unb64u(id))}|${rp}`),
  },
};
/** File bytes: version ‖ len ‖ credential ID ‖ len ‖ RP ID ‖ IV ‖ AES-256-GCM(deflate-raw(JSON)) */
export async function seal(version, keyBytes, loc, obj, id, rp, iv) {
  const idb = unb64u(id), rpb = te.encode(rp);
  if (idb.length > 255 || rpb.length > 255) throw new Error('header field longer than 255 bytes');
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const plain = await pipe(te.encode(JSON.stringify(obj)), new CompressionStream('deflate-raw'));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: V[version].aad(loc, id, rp) }, key, plain));
  return Uint8Array.from([version, idb.length, ...idb, rpb.length, ...rpb, ...iv, ...ct]);
}
export function header(bytes) {
  let i = 1;
  const id = bytes.subarray(i + 1, i + 1 + bytes[i]); i += 1 + bytes[i];
  const rp = td.decode(bytes.subarray(i + 1, i + 1 + bytes[i])); i += 1 + bytes[i];
  if (i + 12 + 16 > bytes.length) throw new Error('truncated');
  return { version: bytes[0], id: b64u(id), rp, iv: bytes.subarray(i, i + 12), ct: bytes.subarray(i + 12) };
}
/** Opens a file as `version` (the version the reader expects at this path, §7.4–7.5); any other first byte is refused */
export async function open(version, keyBytes, loc, bytes) {
  if (bytes[0] !== version || !V[version]) throw new Error('unknown version');
  const h = header(bytes);
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: h.iv, additionalData: V[version].aad(loc, h.id, h.rp) }, key, h.ct));
  return JSON.parse(td.decode(await pipe(pt, new DecompressionStream('deflate-raw'))));
}

const seq = (n, from = 0) => Uint8Array.from({ length: n }, (_, i) => (from + i) & 255);
async function build() {
  const prf = seq(32), id = b64u(seq(16, 0xa0)), rp = '288-732.aihashrate.stream', iv = seq(12, 1);
  const address = '0x' + '11'.repeat(20);
  const loc = { chainId: 56, container: '0x' + '33'.repeat(20), path: '.private/authenticator/backup.bin', address };
  const loc3 = { ...loc, path: '.authenticator/backup.bin' };
  const obj = { at: 1790000000000, v: 2, accounts: [], gone: {} };
  const k4 = await V[4].deriveKey(prf, loc), k3 = await V[3].deriveKey(prf, loc3);
  const f4 = await seal(4, k4, loc, obj, id, rp, iv), f3 = await seal(3, k3, loc3, obj, id, rp, iv);
  const flip = (f) => { const x = Uint8Array.from(f); x[x.length - 1] ^= 1; return hex(x); };
  const other = { ...loc, path: '.private/notes/backup.bin' };
  const t = (name, version, key, l, file, plaintext) => ({ name, version, key: hex(key), loc: l, file: typeof file === 'string' ? file : hex(file), ...(plaintext ? { plaintext } : { error: true }) });
  return {
    v4: {
      prfInput: hex(await V[4].prfInput()),
      derive: [{ prf: hex(prf), loc, key: hex(k4) }, { prf: hex(prf), loc: other, key: hex(await V[4].deriveKey(prf, other)) }],
      aad: { loc, id, rp, utf8: td.decode(V[4].aad(loc, id, rp)) },
      open: [
        t('valid', 4, k4, loc, f4, obj),
        t('last byte flipped', 4, k4, loc, flip(f4)),
        t('other address', 4, k4, { ...loc, address: '0x' + '22'.repeat(20) }, f4),
        t('other path, same key', 4, k4, other, f4),
        t('other path, its own key', 4, await V[4].deriveKey(prf, other), other, f4),
        t('other container', 4, k4, { ...loc, container: '0x' + '44'.repeat(20) }, f4),
        t('other chain', 4, k4, { ...loc, chainId: 196 }, f4),
        t('other key', 4, await V[4].deriveKey(seq(32, 1), loc), loc, f4),
        t('unknown version', 4, k4, loc, '09' + hex(f4).slice(2)),
        t('0x03 file read as 0x04', 4, k3, loc3, f3),
      ],
    },
    v3: {
      prfInput: hex(await V[3].prfInput()),
      derive: [{ prf: hex(prf), loc: loc3, key: hex(k3) }],
      aad: { loc: loc3, id, rp, utf8: td.decode(V[3].aad(loc3, id, rp)) },
      open: [
        t('valid', 3, k3, loc3, f3, obj),
        t('last byte flipped', 3, k3, loc3, flip(f3)),
        t('other address', 3, k3, { ...loc3, address: '0x' + '22'.repeat(20) }, f3),
        t('other key', 3, await V[3].deriveKey(seq(32, 1), loc3), loc3, f3),
        t('unknown version', 3, k3, loc3, '09' + hex(f3).slice(2)),
      ],
    },
    canonicalId: { given: 'abc_DEF-123', canonical: b64u(unb64u('abc_DEF-123')) },
  };
}
if (process.argv[2] === 'check') {
  const v = JSON.parse(fs.readFileSync(new URL('./vectors.json', import.meta.url)));
  let n = 0; const ok = (c, m) => { if (!c) throw new Error('FAIL ' + m); n++; };
  for (const ver of [4, 3]) {
    const s = v['v' + ver];
    ok(hex(await V[ver].prfInput()) === s.prfInput, ver + ' prf input');
    for (const d of s.derive) ok(hex(await V[ver].deriveKey(unhex(d.prf), d.loc)) === d.key, ver + ' derive ' + d.loc.path);
    ok(td.decode(V[ver].aad(s.aad.loc, s.aad.id, s.aad.rp)) === s.aad.utf8, ver + ' aad');
    for (const t of s.open) {
      let got, err = false;
      try { got = await open(t.version, unhex(t.key), t.loc, unhex(t.file)); } catch { err = true; }
      ok(t.error ? err : !err && JSON.stringify(got) === JSON.stringify(t.plaintext), ver + ' ' + t.name);
    }
  }
  ok(b64u(unb64u(v.canonicalId.given)) === v.canonicalId.canonical, 'canonical id');
  console.log(`all ${n} checks passed`);
} else console.log(JSON.stringify(await build(), null, 2));
