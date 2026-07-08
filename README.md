# login

`<nostr-login>` — a drop-in nostr login web component, plus **NIP-98**
authenticated fetch. **No build step.** One file: [`login.js`](login.js).

Part of [nostr-client](https://github.com/nostr-client) — a modular, composable
nostr client where each repo does one thing. Inspired by
[xlogin](https://github.com/melvincarvalho/xlogin).

**Live demo:** https://nostr-client.github.io/login/

## Use

```html
<script type="module" src="https://nostr-client.github.io/login/login.js"></script>
<nostr-login></nostr-login>
```

Login methods:

- **NIP-07 browser extension** (alby, nos2x, …) — zero dependencies
- **Paste a key** (`nsec1…` or hex)
- **New guest key** — generated on the fly

Local/guest key signing lazy-loads [nostr-tools](https://github.com/nbd-wtf/nostr-tools)
from a pinned CDN URL; the extension path loads nothing.

## The contract

On login, the component announces a normalized **NIP-07-shaped signer** that
any other component on the page can use:

```js
window.nostrSigner  // { type, getPublicKey(), signEvent(evt) }
window.nostrPubkey  // hex pubkey

window.addEventListener('nostr:login',  (e) => e.detail /* { pubkey, signer } */)
window.addEventListener('nostr:logout', () => {})
```

Swap this component for any other login implementation: as long as it sets
`window.nostrSigner` and fires the same events, every other nostr-client
component keeps working.

## NIP-98

```js
import { nip98Fetch, nip98Header } from 'https://nostr-client.github.io/login/login.js'

const res = await nip98Fetch('https://api.example.com/upload', {
  method: 'POST',
  body: JSON.stringify(data),
})
// sends Authorization: Nostr <base64 kind-27235 event>, with payload sha256 tag
```

## Also exported

Dependency-free NIP-19 helpers, usable in node/workers too:
`npubEncode`, `nsecEncode`, `decodeKey`, `bech32Encode`, `bech32Decode`,
`bytesToHex`, `hexToBytes`.

## Security notes

- Pasted and guest keys are stored in `localStorage` so sessions survive
  reloads — fine for guest identities, not for your main key. Use a NIP-07
  extension for real identities; the key never touches the page.
- Session storage is per-origin; any script on the page can read it.

## Theming

CSS custom properties: `--nostr-login-bg`, `--nostr-login-color`,
`--nostr-login-border`. Or ignore the element and build your own UI on the
exported functions.

## License

AGPL-3.0-or-later
