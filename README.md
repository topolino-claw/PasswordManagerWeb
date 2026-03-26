# Vault v3

A deterministic password manager that generates passwords on-the-fly using a BIP39 seed phrase. No storage, no sync, just math.

## Features

- **Deterministic passwords** — Same inputs = same password, every time
- **BIP39 seed phrase** — Industry standard, write it down and recover anywhere
- **Double-encrypted cloud backup** — AES-256-GCM + NIP-44 encryption to Nostr relays
- **Offline first** — Works without internet, even from a downloaded file
- **Local encryption** — Save to device with password protection
- **Installable PWA** — Add to home screen on mobile, runs fully offline

## Download for Offline Use

Vault works 100% offline. To download:

1. Clone or download this repo: `git clone https://github.com/topolino-claw/PasswordManagerWeb.git`
2. Open `index.html` in any modern browser
3. That's it — no build step, no server, no internet required

All dependencies are bundled locally:
- `crypto-js.min.js` — SHA-256 / AES
- `bip39WordList.js` — BIP39 word list
- `lib/nostr-tools.min.js` — Nostr protocol

No CDN calls, no external requests (except WebSocket connections to Nostr relays when you explicitly backup/restore).

### Install as PWA

On mobile or desktop, open [Vault](https://topolino-claw.github.io/PasswordManagerWeb/) and use "Add to Home Screen" / "Install App". The service worker caches everything for offline use.

## Quick Start

1. Open [Vault](https://topolino-claw.github.io/PasswordManagerWeb/) or `index.html` locally
2. Create a new vault or restore an existing seed phrase
3. Add sites by searching and hitting Enter
4. Copy your password — it's generated instantly

## How It Works

### Password Generation

```
password = "PASS" + SHA256(privateKey + "/" + username + "/" + site + "/" + version).slice(0, 16) + "249+"
```

- `privateKey`: Derived from your BIP39 seed phrase
- `username`: Your email or username for the site
- `site`: The domain (e.g., `github.com`)
- `version`: Starts at 0, increment if you need a new password

### Seed Phrase → Private Key

1. Each BIP39 word maps to an index (0–2047)
2. Indices are padded to 4 digits and concatenated
3. The decimal string is converted to hexadecimal

### Cloud Backup (Double Encryption)

Your site list (not your seed phrase) is protected with two independent encryption layers:

**Layer 1 — Backup Password (AES-256-GCM)**
```
key = PBKDF2(backupPassword, salt=npub, iterations=600000, hash=SHA-256)
envelope = AES-256-GCM(vaultData, key)
```

**Layer 2 — NIP-44 (Nostr)**
```
sharedSecret = nip44.getSharedSecret(nsec, npub)  // self-to-self
ciphertext = nip44.encrypt(sharedSecret, envelope)
```

Published as `kind:30078` event with `d` tag `vault-backup`.

**Why two layers:**
- Even if your nsec is compromised → attacker can't read without your backup password
- Even if your backup password leaks → attacker can't decrypt without your nsec
- Two independent factors required to access your data

**Legacy support:** Old backups (single-layer NIP-44 and NIP-04 kind:1) are auto-detected and restored without a password prompt.

## Files

- `index.html` — Main app (v3, redesigned UI)
- `app.js` — Application logic
- `sw.js` — Service worker for offline PWA support
- `manifest.json` — PWA manifest
- `index-legacy.html` — Previous version (v2)
- `script.js` — Legacy v2 logic
- `bip39WordList.js` — BIP39 wordlist
- `crypto-js.min.js` — SHA256/AES
- `lib/nostr-tools.min.js` — Nostr protocol

## Security

- **Seed phrase = master key** — Keep it safe, offline, written on paper
- **Backup password** — Second factor for cloud backups. Never stored, only in your head
- **Never transmitted** — Passwords are generated locally, never sent anywhere
- **PBKDF2 with 600,000 iterations** — OWASP 2023 recommendation for key derivation
- **AES-256-GCM** — Authenticated encryption via Web Crypto API
- **Auto-lock** — Vault locks after 5 minutes of inactivity

## Changelog

### v3.2
- **Double-encrypted cloud backup** — AES-256-GCM (backup password) + NIP-44 (nsec)
- PBKDF2 key derivation with 600,000 iterations (OWASP 2023)
- Backup password management UI (set, change, status indicator)
- Full legacy backup compatibility (single-layer NIP-44 and NIP-04)
- Updated README with offline download instructions

### v3.1
- Relay connection logging
- Sensitive log guarding (debug mode)
- Local encrypted nonce backup

### v3.0
- Complete UI redesign — dark mode, mobile-first
- Simplified navigation
- Site search with fuzzy matching
- One-tap copy with toast feedback

### v2.0
- Nostr backup/restore
- Configurable hash length
- Local encryption

## License

MIT

## Source

[GitHub](https://github.com/topolino-claw/PasswordManagerWeb)
