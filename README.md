# Vault v3

A deterministic password manager that generates passwords on-the-fly using a BIP39 seed phrase. No storage, no sync, just math.

## Features

- **Deterministic passwords** — Same inputs = same password, every time
- **BIP39 seed phrase** — Industry standard, write it down and recover anywhere
- **Offline first** — Works without internet, even from a local file
- **Optional cloud backup** — Sync your site list via Nostr relays
- **Local encryption** — Save to device with password protection
- **Mobile-friendly** — Touch-optimized, works great on phones

## Quick Start

1. Open [Vault](https://fabricio333.github.io/PasswordManagerWeb/) or download `index.html` for offline use
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

### Nostr Backup

Your site list (not your seed phrase) can be encrypted and published to Nostr relays:

1. Seed phrase → SHA256 → Nostr private key
2. Site list → NIP-04 encrypted → kind:1 event tagged `nostr-pwd-backup`
3. Published to multiple relays for redundancy

## Files

- `index.html` — Main app (v3, redesigned UI)
- `app.js` — Application logic
- `index-legacy.html` — Previous version (v2)
- `script.js` — Legacy v2 logic
- `bip39WordList.js` — BIP39 wordlist
- `crypto-js.min.js` — SHA256/AES
- `lib/nostr-tools.min.js` — Nostr protocol

## Security

- **Seed phrase = master key** — Keep it safe, offline, written on paper
- **Never transmitted** — Passwords are generated locally, never sent anywhere
- **Encryption password** — If you save locally, don't forget this password
- **Browser security** — Use a trusted browser, avoid extensions that might read inputs

## Changelog

### v3.0
- Complete UI redesign — dark mode, mobile-first
- Simplified navigation — 2 main flows instead of 8+ screens  
- Site search with fuzzy matching
- "Version" instead of "nonce"
- One-tap copy with toast feedback
- Cleaner settings organization

### v2.0
- Nostr backup/restore
- Configurable hash length
- Local encryption

## License

MIT

## Source

[GitHub](https://github.com/fabricio333/PasswordManagerWeb)
