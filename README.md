# Vault — Deterministic Password Manager

No storage. No account. No cloud dependency. Just your seed phrase and math.

**Live:** https://topolino-claw.github.io/PasswordManagerWeb/  
**Offline:** download this repo and open `index.html` — works with zero internet

---

## How It Works

Every password is derived mathematically from:

```
password = "PASS" + SHA256(privateKey + "/" + username + "/" + domain + "/" + nonce).slice(0,16) + "249+"
```

Where `privateKey` is derived from your BIP39 seed phrase. Same inputs → same password, always. Nothing is stored — passwords are re-derived on demand.

**Nonce** = version counter (starts at 0). Increment it when you need to rotate a password.

---

## Quick Start

1. Open the app (online or local file)
2. **New vault:** generate seed phrase → write it on paper → verify it → done
3. **Restore:** enter your seed phrase → vault loads from Nostr backup
4. Add a site, enter your username, copy the password
5. Use that password on the site

---

## Master Keys (KEEP THESE SAFE)

You need two things to access your vault:

| Key | What it is | Where it lives |
|---|---|---|
| **Seed phrase** | 12 BIP39 words — the root of everything | Written on paper, 2 copies, separate locations |
| **Backup password** | Protects your Nostr cloud backup | Only in your head — NEVER written down |

**Lose the seed phrase = lose the vault. No recovery.**

---

## Nostr Backup

Your site list (not passwords) is encrypted and published to Nostr relays automatically after every change.

**Encryption:** two layers
1. `PBKDF2(backupPassword, npub, 600k iterations)` → `AES-256-GCM`
2. `NIP-44` with your Nostr key (derived from seed)

Relays used: relay.damus.io · nostr-pub.wellorder.net · relay.snort.social · nos.lol

Relay operators see only encrypted ciphertext. Useless without both keys.

---

## Restore on New Device

1. Open vault (online or local file)
2. Enter seed phrase
3. Vault fetches Nostr backup automatically
4. Enter backup password when prompted → site list restored
5. All passwords re-derive from the seed — nothing was ever stored

---

## Files (all local, zero CDN)

```
index.html          — the app
app.js              — all logic (~2300 lines)
bip39WordList.js    — BIP39 word list
crypto-js.min.js    — SHA256 + AES
lib/
  nostr-tools.min.js — Nostr protocol
sw.js               — service worker (PWA offline)
manifest.json       — PWA manifest
docs/               — technical documentation
```

---

## Security Model

- Seed phrase: **never transmitted**, derived locally every session
- Passwords: **never stored**, re-derived on demand
- Backup: **double-encrypted** before leaving your device
- Local vault: **AES-encrypted** in localStorage
- Zero CDN, zero third-party requests for core function

---

## Recreating From Scratch

If you lose everything except your seed phrase and backup password:

1. Download this repo (or clone from GitHub)
2. Open `index.html`
3. Click "Restore existing vault"
4. Enter seed phrase
5. Enter backup password
6. All sites and nonces are restored from Nostr

If you also lose the Nostr backup: seed phrase still derives all your passwords. You just need to re-add the site list manually (you'll remember your sites).

---

## Version

**v3.2** — double-encrypted backup, relay confirmation, debounced sync, DOM wipe on lock

Repo: https://github.com/topolino-claw/PasswordManagerWeb
