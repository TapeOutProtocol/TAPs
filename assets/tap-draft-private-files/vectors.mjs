// TAP-draft-private-files: reference derivation, sealing and opening, and the test vectors in vectors.json.
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

export const PRF_INPUT = async () => new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode('authenticator-backup-prf-v1')));
/** 32-byte AES-256-GCM key from the passkey's PRF output and the holder address */
export async function deriveKey(prf, address) {
  const base = await crypto.subtle.importKey('raw', prf, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256',
    salt: te.encode('authenticator-backup-v3:' + address.toLowerCase()), info: te.encode('chain-backup-passkey') }, base, 256));
}
export const aad = (address, id, rp) => te.encode(`${address.toLowerCase()}|${b64u(unb64u(id))}|${rp}`);
/** File bytes: 0x03 ‖ len ‖ credential ID ‖ len ‖ RP ID ‖ IV ‖ AES-256-GCM(deflate-raw(JSON)) */
export async function seal(keyBytes, address, obj, id, rp, iv) {
  const idb = unb64u(id), rpb = te.encode(rp);
  if (idb.length > 255 || rpb.length > 255) throw new Error('header field longer than 255 bytes');
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const plain = await pipe(te.encode(JSON.stringify(obj)), new CompressionStream('deflate-raw'));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(address, id, rp) }, key, plain));
  return Uint8Array.from([3, idb.length, ...idb, rpb.length, ...rpb, ...iv, ...ct]);
}
export function header(bytes) {
  if (bytes[0] !== 3) throw new Error('unknown version');
  let i = 1;
  const id = bytes.subarray(i + 1, i + 1 + bytes[i]); i += 1 + bytes[i];
  const rp = td.decode(bytes.subarray(i + 1, i + 1 + bytes[i])); i += 1 + bytes[i];
  if (i + 12 + 16 > bytes.length) throw new Error('truncated');
  return { id: b64u(id), rp, iv: bytes.subarray(i, i + 12), ct: bytes.subarray(i + 12) };
}
export async function open(keyBytes, address, bytes) {
  const h = header(bytes);
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: h.iv, additionalData: aad(address, h.id, h.rp) }, key, h.ct));
  return JSON.parse(td.decode(await pipe(pt, new DecompressionStream('deflate-raw'))));
}

const seq = (n, from = 0) => Uint8Array.from({ length: n }, (_, i) => (from + i) & 255);
async function build() {
  const prf = seq(32), address = '0x' + '11'.repeat(20), id = b64u(seq(16, 0xa0)), rp = '288-732.aihashrate.stream', iv = seq(12, 1);
  const obj = { at: 1790000000000, v: 2, accounts: [], gone: {} };
  const key = await deriveKey(prf, address);
  const file = await seal(key, address, obj, id, rp, iv);
  const flip = Uint8Array.from(file); flip[flip.length - 1] ^= 1;
  return {
    prfInput: hex(await PRF_INPUT()),
    derive: { prf: hex(prf), address, key: hex(key) },
    aad: { address, id, rp, utf8: td.decode(aad(address, id, rp)) },
    open: [
      { name: 'valid', key: hex(key), address, file: hex(file), plaintext: obj },
      { name: 'last byte flipped', key: hex(key), address, file: hex(flip), error: true },
      { name: 'other address', key: hex(key), address: '0x' + '22'.repeat(20), file: hex(file), error: true },
      { name: 'other key', key: hex(await deriveKey(seq(32, 1), address)), address, file: hex(file), error: true },
      { name: 'unknown version', key: hex(key), address, file: '09' + hex(file).slice(2), error: true },
    ],
    canonicalId: { given: 'abc_DEF-123', canonical: b64u(unb64u('abc_DEF-123')) },
  };
}
if (process.argv[2] === 'check') {
  const v = JSON.parse(fs.readFileSync(new URL('./vectors.json', import.meta.url)));
  let n = 0; const ok = (c, m) => { if (!c) throw new Error('FAIL ' + m); n++; };
  ok(hex(await PRF_INPUT()) === v.prfInput, 'prf input');
  ok(hex(await deriveKey(unhex(v.derive.prf), v.derive.address)) === v.derive.key, 'derive');
  ok(td.decode(aad(v.aad.address, v.aad.id, v.aad.rp)) === v.aad.utf8, 'aad');
  for (const t of v.open) {
    let got, err = false;
    try { got = await open(unhex(t.key), t.address, unhex(t.file)); } catch { err = true; }
    ok(t.error ? err : !err && JSON.stringify(got) === JSON.stringify(t.plaintext), t.name);
  }
  ok(b64u(unb64u(v.canonicalId.given)) === v.canonicalId.canonical, 'canonical id');
  console.log(`all ${n} checks passed`);
} else console.log(JSON.stringify(await build(), null, 2));
