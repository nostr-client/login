/**
 * login.js — <nostr-login> web component + NIP-98 authenticated fetch.
 * No build step. Zero dependencies for the NIP-07 (extension) path;
 * local-key signing lazy-loads nostr-tools from a pinned CDN URL.
 *
 * Part of https://github.com/nostr-client — one repo, one thing.
 * Inspired by https://github.com/melvincarvalho/xlogin
 * License: AGPL-3.0-or-later
 *
 * Usage:
 *   <script type="module" src="https://nostr-client.github.io/login/login.js"></script>
 *   <nostr-login></nostr-login>
 *
 * On login the component:
 *   - sets window.nostrSigner = { type, getPublicKey(), signEvent(evt) }  (NIP-07 shaped)
 *   - sets window.nostrPubkey  (hex)
 *   - dispatches 'nostr:login'  CustomEvent on window, detail: { pubkey, signer }
 * On logout it clears both and dispatches 'nostr:logout'.
 *
 * NIP-98:
 *   import { nip98Fetch } from 'https://nostr-client.github.io/login/login.js'
 *   const res = await nip98Fetch('https://api.example.com/thing', { method: 'POST', body })
 */

const NOSTR_TOOLS_URL = 'https://esm.sh/nostr-tools@2.10.4/pure'
const STORAGE_KEY = 'nostr-client:login'

// ---------------------------------------------------------------- bech32
// Plain BIP-173 bech32, enough for npub/nsec (NIP-19 bare keys).

const B32_CHARS = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
const B32_GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

function b32Polymod(values) {
  let chk = 1
  for (const v of values) {
    const b = chk >> 25
    chk = ((chk & 0x1ffffff) << 5) ^ v
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= B32_GEN[i]
  }
  return chk
}

function b32HrpExpand(hrp) {
  const out = []
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5)
  out.push(0)
  for (const c of hrp) out.push(c.charCodeAt(0) & 31)
  return out
}

function convertBits(data, from, to, pad) {
  let acc = 0, bits = 0
  const out = []
  const maxv = (1 << to) - 1
  for (const value of data) {
    acc = (acc << from) | value
    bits += from
    while (bits >= to) {
      bits -= to
      out.push((acc >> bits) & maxv)
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv)
  } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
    throw new Error('bech32: invalid padding')
  }
  return out
}

export function bech32Encode(hrp, bytes) {
  const data = convertBits(bytes, 8, 5, true)
  const values = [...b32HrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0]
  const polymod = b32Polymod(values) ^ 1
  const checksum = []
  for (let i = 0; i < 6; i++) checksum.push((polymod >> (5 * (5 - i))) & 31)
  return hrp + '1' + [...data, ...checksum].map((v) => B32_CHARS[v]).join('')
}

export function bech32Decode(str) {
  str = str.toLowerCase().trim()
  const pos = str.lastIndexOf('1')
  if (pos < 1 || pos + 7 > str.length) throw new Error('bech32: malformed')
  const hrp = str.slice(0, pos)
  const values = [...str.slice(pos + 1)].map((c) => {
    const v = B32_CHARS.indexOf(c)
    if (v === -1) throw new Error('bech32: invalid character')
    return v
  })
  if (b32Polymod([...b32HrpExpand(hrp), ...values]) !== 1) throw new Error('bech32: bad checksum')
  return { hrp, bytes: new Uint8Array(convertBits(values.slice(0, -6), 5, 8, false)) }
}

// ------------------------------------------------------------ hex + keys

export const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
export const hexToBytes = (hex) => new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)))

export const npubEncode = (hex) => bech32Encode('npub', hexToBytes(hex))
export const nsecEncode = (hex) => bech32Encode('nsec', hexToBytes(hex))

/** Accepts npub/nsec/hex, returns { type: 'npub'|'nsec'|'hex', hex }. */
export function decodeKey(str) {
  str = str.trim()
  if (/^[0-9a-fA-F]{64}$/.test(str)) return { type: 'hex', hex: str.toLowerCase() }
  const { hrp, bytes } = bech32Decode(str)
  if (bytes.length !== 32) throw new Error('key must be 32 bytes')
  if (hrp !== 'npub' && hrp !== 'nsec') throw new Error('expected npub or nsec, got ' + hrp)
  return { type: hrp, hex: bytesToHex(bytes) }
}

// --------------------------------------------------------------- signers

function extensionSigner() {
  return {
    type: 'nip07',
    getPublicKey: () => window.nostr.getPublicKey(),
    signEvent: (evt) => window.nostr.signEvent(evt),
  }
}

async function localSigner(secretHex) {
  const { getPublicKey, finalizeEvent } = await import(NOSTR_TOOLS_URL)
  const sk = hexToBytes(secretHex)
  const pubkey = getPublicKey(sk)
  return {
    type: 'local',
    secretHex,
    getPublicKey: async () => pubkey,
    signEvent: async (evt) => finalizeEvent({ created_at: Math.floor(Date.now() / 1000), ...evt }, sk),
  }
}

async function generateSecretHex() {
  const { generateSecretKey } = await import(NOSTR_TOOLS_URL)
  return bytesToHex(generateSecretKey())
}

// ---------------------------------------------------------------- NIP-98

/**
 * fetch() with a NIP-98 Authorization header (kind 27235), signed by the
 * given signer (defaults to window.nostrSigner).
 */
export async function nip98Fetch(url, init = {}, { signer = window.nostrSigner } = {}) {
  if (!signer) throw new Error('nip98Fetch: no signer — add <nostr-login> and log in first')
  const method = (init.method || 'GET').toUpperCase()
  const tags = [['u', String(url)], ['method', method]]
  if (init.body != null) {
    const bytes = typeof init.body === 'string' ? new TextEncoder().encode(init.body) : init.body
    const digest = await crypto.subtle.digest('SHA-256', bytes)
    tags.push(['payload', bytesToHex(new Uint8Array(digest))])
  }
  const event = await signer.signEvent({
    kind: 27235,
    created_at: Math.floor(Date.now() / 1000),
    tags,
    content: '',
  })
  const headers = new Headers(init.headers)
  headers.set('Authorization', 'Nostr ' + btoa(JSON.stringify(event)))
  return fetch(url, { ...init, headers })
}

/** Build (but don't send) the NIP-98 Authorization header value. */
export async function nip98Header(url, method = 'GET', { signer = window.nostrSigner } = {}) {
  if (!signer) throw new Error('nip98Header: no signer')
  const event = await signer.signEvent({
    kind: 27235,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['u', String(url)], ['method', method.toUpperCase()]],
    content: '',
  })
  return 'Nostr ' + btoa(JSON.stringify(event))
}

// ---------------------------------------------------------- session state

async function announceLogin(signer) {
  const pubkey = await signer.getPublicKey()
  window.nostrSigner = signer
  window.nostrPubkey = pubkey
  window.dispatchEvent(new CustomEvent('nostr:login', { detail: { pubkey, signer } }))
  return pubkey
}

function announceLogout() {
  window.nostrSigner = null
  window.nostrPubkey = null
  window.dispatchEvent(new CustomEvent('nostr:logout'))
}

function saveSession(session) {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(session)) } catch {}
}

function loadSession() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY)) } catch { return null }
}

function clearSession() {
  try { localStorage.removeItem(STORAGE_KEY) } catch {}
}

// ---------------------------------------------------------------- element

const TEMPLATE = /* html */ `
<style>
  :host { display: inline-block;
    font-family: var(--nc-font, ui-sans-serif, system-ui, sans-serif);
    font-size: .9rem; color: var(--nc-ink, #201d26); }
  :host([block]) { display: block; }
  :host([block]) #root > button { width: 100%; }
  button { font: inherit; cursor: pointer; border: none; border-radius: 999px;
    background: var(--nc-accent, #7c3aed); color: var(--nc-accent-ink, #fff);
    padding: .5em 1.2em; font-weight: 600;
    transition: filter .15s ease, transform .15s ease; }
  button:hover { filter: brightness(1.08); }
  button:active { transform: translateY(1px); }
  button.ghost { background: transparent; color: inherit; font-weight: 500;
    border: 1px solid var(--nc-line, #e9e6e0); }
  button.ghost:hover { filter: none; background: var(--nc-inset, #f4f2ee); }
  button:disabled { opacity: .45; cursor: default; filter: none; }
  .row { display: flex; gap: .6em; align-items: center; flex-wrap: wrap; }
  .menu { display: flex; flex-direction: column; gap: .6em; padding: 1em;
    background: var(--nc-surface, #fff);
    border: 1px solid var(--nc-line, #e9e6e0);
    border-radius: var(--nc-radius, 14px);
    box-shadow: var(--nc-shadow-pop, 0 2px 6px rgb(32 27 51 / 8%), 0 16px 48px -12px rgb(32 27 51 / 18%));
    min-width: 17em; }
  input { font: inherit; padding: .5em .7em; border-radius: 999px;
    border: 1px solid var(--nc-line, #e9e6e0);
    background: var(--nc-inset, #f4f2ee); color: inherit; min-width: 0; flex: 1; }
  input:focus { outline: 2px solid var(--nc-accent-soft, #f2ecfd);
    border-color: var(--nc-accent, #7c3aed); }
  .chip { display: flex; align-items: center; gap: .6em; max-width: 16rem;
    background: var(--nc-surface, #fff); border: 1px solid var(--nc-line, #e9e6e0);
    border-radius: 999px; padding: .3em .45em .3em .3em; cursor: pointer;
    transition: background .15s ease; }
  .chip:hover { background: var(--nc-inset, #f4f2ee); }
  .chip .avatar { width: 2.1em; height: 2.1em; border-radius: 50%; flex: none;
    object-fit: cover; background: var(--nc-accent-soft, #f2ecfd);
    color: var(--nc-accent, #7c3aed); display: grid; place-items: center;
    font-weight: 700; font-size: 1em; overflow: hidden; }
  .chip .meta { min-width: 0; line-height: 1.2; }
  .chip .name { display: block; font-weight: 650; font-size: .88em; overflow: hidden;
    text-overflow: ellipsis; white-space: nowrap; }
  .chip .sub { display: block; font-size: .72em; color: var(--nc-faint, #a8a4b0); overflow: hidden;
    text-overflow: ellipsis; white-space: nowrap; }
  .chip .out { flex: none; font: inherit; cursor: pointer; border: none;
    background: none; color: var(--nc-faint, #a8a4b0); font-size: 1.05em;
    border-radius: 50%; width: 1.9em; height: 1.9em; display: grid; place-items: center; }
  .chip .out:hover { background: var(--nc-accent-soft, #f2ecfd);
    color: var(--nc-danger, #c93a3a); }
  .err { color: var(--nc-danger, #c93a3a); font-size: .8rem; }
  .hint { font-size: .75rem; color: var(--nc-faint, #a8a4b0); line-height: 1.4; }
</style>
<span id="root"></span>
`

// Allow importing this module outside the DOM (node, workers) for the
// bech32/key/NIP-98 utilities — the element is only defined where it can be.
const BaseElement = typeof HTMLElement === 'undefined' ? class {} : HTMLElement

export class NostrLogin extends BaseElement {
  constructor() {
    super()
    this.attachShadow({ mode: 'open' }).innerHTML = TEMPLATE
    this.root = this.shadowRoot.getElementById('root')
    this.pubkey = null
    this.signer = null
  }

  connectedCallback() { this._restore() }

  async _restore() {
    const session = loadSession()
    try {
      if (session?.method === 'nip07') {
        if (window.nostr) {
          await this._finish(extensionSigner(), { method: 'nip07' })
          return
        }
        // extensions can inject window.nostr AFTER we load — show the button,
        // keep watching, and complete the login the moment it appears
        this._renderLoggedOut()
        for (let i = 0; i < 40 && this.isConnected && !this.pubkey; i++) {
          await new Promise((r) => setTimeout(r, 250))
          if (window.nostr) {
            await this._finish(extensionSigner(), { method: 'nip07' })
            return
          }
        }
        return
      }
      if (session?.method === 'local' && session.secretHex) {
        await this._finish(await localSigner(session.secretHex), session)
        return
      }
    } catch { clearSession() }
    this._renderLoggedOut()
  }

  async _finish(signer, session) {
    this.signer = signer
    this.pubkey = await announceLogin(signer)
    saveSession(session)
    this._renderLoggedIn()
  }

  _logout() {
    clearSession()
    this.signer = null
    this.pubkey = null
    announceLogout()
    this._renderLoggedOut()
  }

  _renderLoggedOut() {
    this.root.innerHTML = ''
    const btn = document.createElement('button')
    btn.textContent = this.getAttribute('label') || 'Login with Nostr'
    btn.onclick = () => this._renderMenu()
    this.root.append(btn)
  }

  _renderMenu() {
    this.root.innerHTML = ''
    const menu = document.createElement('div')
    menu.className = 'menu'

    const err = document.createElement('div')
    err.className = 'err'
    const fail = (e) => { err.textContent = e.message || String(e) }

    const ext = document.createElement('button')
    ext.textContent = window.nostr ? 'Browser extension (NIP-07)' : 'Browser extension — none detected'
    ext.disabled = !window.nostr
    ext.onclick = () => this._finish(extensionSigner(), { method: 'nip07' }).catch(fail)

    const guest = document.createElement('button')
    guest.className = 'ghost'
    guest.textContent = 'New guest key'
    guest.onclick = async () => {
      try {
        const secretHex = await generateSecretHex()
        await this._finish(await localSigner(secretHex), { method: 'local', secretHex })
      } catch (e) { fail(e) }
    }

    const keyRow = document.createElement('div')
    keyRow.className = 'row'
    const input = document.createElement('input')
    input.placeholder = 'nsec1…'
    input.type = 'password'
    const use = document.createElement('button')
    use.className = 'ghost'
    use.textContent = 'Use key'
    use.onclick = async () => {
      try {
        const { type, hex } = decodeKey(input.value)
        if (type === 'npub') throw new Error('that is a public key — need nsec or hex secret')
        await this._finish(await localSigner(hex), { method: 'local', secretHex: hex })
      } catch (e) { fail(e) }
    }
    keyRow.append(input, use)

    const hint = document.createElement('div')
    hint.className = 'hint'
    hint.textContent = 'Guest and pasted keys are kept in localStorage on this device. Prefer the extension for a real identity.'

    const cancel = document.createElement('button')
    cancel.className = 'ghost'
    cancel.textContent = 'Cancel'
    cancel.onclick = () => this._renderLoggedOut()

    menu.append(ext, guest, keyRow, hint, err, cancel)
    this.root.append(menu)
  }

  _renderLoggedIn() {
    this.root.innerHTML = ''
    const npub = npubEncode(this.pubkey)
    const short = npub.slice(0, 9) + '…' + npub.slice(-4)

    const chip = document.createElement('div')
    chip.className = 'chip'
    chip.title = npub

    const avatar = document.createElement('span')
    avatar.className = 'avatar'
    avatar.textContent = '☺'

    const meta = document.createElement('span')
    meta.className = 'meta'
    const name = document.createElement('span')
    name.className = 'name'
    name.textContent = short
    const sub = document.createElement('span')
    sub.className = 'sub'
    sub.textContent = this.signer?.type === 'nip07' ? 'extension' : 'local key'
    meta.append(name, sub)

    const out = document.createElement('button')
    out.className = 'out'
    out.title = 'Log out'
    out.textContent = '⏻'
    out.onclick = (e) => { e.stopPropagation(); this._logout() }

    chip.append(avatar, meta, out)
    chip.onclick = () => {
      this.dispatchEvent(new CustomEvent('nostr:profile-click', {
        detail: { pubkey: this.pubkey }, bubbles: true, composed: true, cancelable: true,
      }))
    }
    this.root.append(chip)

    // enhance with the profile (lazy; falls back silently to npub + method)
    const pubkey = this.pubkey
    import('https://nostr-client.github.io/note/note.js').then(({ profiles }) => {
      profiles().get(pubkey, (profile) => {
        if (this.pubkey !== pubkey || !profile) return
        const display = profile.display_name || profile.name
        if (display) {
          name.textContent = display
          sub.textContent = profile.nip05?.replace(/^_@/, '') || short
        }
        if (profile.picture?.startsWith('https://')) {
          avatar.textContent = ''
          const img = document.createElement('img')
          img.src = profile.picture
          img.alt = ''
          img.style.cssText = 'width:100%;height:100%;object-fit:cover'
          avatar.append(img)
        } else if (display) {
          avatar.textContent = [...display][0].toUpperCase()
        }
      })
    }).catch(() => {})
  }
}

if (typeof customElements !== 'undefined' && !customElements.get('nostr-login')) {
  customElements.define('nostr-login', NostrLogin)
}
