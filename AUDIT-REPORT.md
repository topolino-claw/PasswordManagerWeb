# PasswordManagerWeb — Full Audit Report

**Date:** 2026-03-20  
**Auditor:** Adonis (dev agent)  
**Repo:** https://github.com/Fabricio333/PasswordManagerWeb  
**Files reviewed:** `index.html`, `script.js` (current), `scriptV32.js` (previous), `bip39WordList.js`, `audit.md`

---

## 1. Confirmed Bugs (broken right now)

### BUG-1: `deriveNostrKeys()` is called but never defined — CRASH
**File:** `script.js:625`  
```js
nostrKeys = deriveNostrKeys(privateKeyField.value);
```
This function doesn't exist anywhere in `script.js`, `scriptV32.js`, or `index.html`. When a user loads encrypted data from localStorage via the "Decrypt Local Storage" flow, this **throws `ReferenceError: deriveNostrKeys is not defined`** and the entire `loadEncryptedData()` function fails silently (caught by the try/catch).

**Impact:** The localStorage decryption flow is completely broken. Users who saved encrypted data cannot recover it through this path.

**Fix:** Define `deriveNostrKeys()` or inline the derivation logic (SHA-256 hash → nostr-tools nip19/getPublicKey), same as done in `verifySeedAndMoveNext()` lines 218-233.

---

### BUG-2: Missing external script — `../Nostr-DM-Tools/nostrCloud.js`
**File:** `index.html:483`  
```html
<script src="../Nostr-DM-Tools/nostrCloud.js"></script>
```
This path is **relative to the parent directory** and points to a repo/folder (`Nostr-DM-Tools`) that doesn't exist in this project. On GitHub Pages at `fabricio333.github.io/PasswordManagerWeb/`, this resolves to `fabricio333.github.io/Nostr-DM-Tools/nostrCloud.js` — which likely 404s.

**Impact:** If `nostrCloud.js` defines any functions or relay config used by the app, those are silently missing. If it's dead code, it's still a 404 on every page load.

**Fix:** Remove the script tag or bundle the needed code locally.

---

### BUG-3: Password entropy halved between versions — BREAKING CHANGE
**File:** `script.js:293` vs `scriptV32.js:253`

| Version | Line | Code |
|---------|------|------|
| scriptV32 (old) | 253 | `hash(concatenado).substring(0, 32)` |
| script.js (new) | 293 | `hash(concatenado).substring(0, 16)` |

The current version truncates the hash to 16 hex chars (64 bits of entropy). The old version used 32 hex chars (128 bits). **This means any password generated with the current code is different from passwords generated with the old code for the same inputs.**

**Impact:** Users who generated passwords with V32 and updated to the current version will get different passwords for the same seed+user+site+nonce. Their existing site passwords are effectively "lost."

**Fix:** Decide which length is canonical (32 is better for security). If 16 was intentional, document the migration. If accidental, revert to 32.

---

### BUG-4: `restoreFromNostr()` doesn't set `privateKeyField.value`
**File:** `script.js:950-965`  
After a successful Nostr restore, `localStoredData` is populated and `localStoredStatus` is set to "loaded", but `privateKeyField.value` is never set from `localStoredData["privateKey"]`. The management screen loads but the private key field is stale/empty unless it was already set from seed phrase entry.

Compare with `loadEncryptedData()` at line 623 which does:
```js
privateKeyField.value = localStoredData["privateKey"]
```

**Impact:** After Nostr restore, password generation will use whatever was in the private key field (possibly empty), producing wrong passwords.

**Fix:** After `localStoredData = parsedData`, add `privateKeyField.value = localStoredData["privateKey"]` and re-derive nostr keys.

---

### BUG-5: Same issue in `restoreFromNostrId()`
**File:** `script.js:1189-1196`  
Same as BUG-4 — after decryption, `privateKeyField.value` is never set from restored data.

---

## 2. Security Issues

### 🔴 CRITICAL

#### SEC-1: `Math.random()` used for seed verification — NOT CSPRNG
**File:** `script.js:447`
```js
indices.add(Math.floor(Math.random() * max));
```
`Math.random()` is not cryptographically secure. In this specific context (choosing which seed words to quiz the user on), the practical risk is low — it's a UX verification step, not key generation. But it's still a red flag in a security-critical app. The mnemonic generation itself correctly uses `crypto.getRandomValues` (line 311).

**Fix:** Replace with `crypto.getRandomValues`:
```js
function getRandomIndices(max, count) {
    const indices = new Set();
    const arr = new Uint32Array(1);
    while (indices.size < count) {
        crypto.getRandomValues(arr);
        indices.add(arr[0] % max);
    }
    return Array.from(indices);
}
```

---

#### SEC-2: SHA-256 used as KDF — No brute-force resistance
**File:** `script.js:257` (`hash()` function), used at `script.js:292` for password derivation and `script.js:755` for Nostr key derivation.

SHA-256 is a fast hash. An attacker who knows the password format (`PASS` + 16/32 hex chars + `249+`) and has a target password hash can brute-force seed phrases at billions of attempts per second on commodity hardware.

The app hashes `privateKey + "/" + user + "/" + site + "/" + nonce` with a single SHA-256 pass. No salt, no iterations, no memory-hardness.

**Fix:** Replace with Argon2id (via WASM, e.g., `argon2-browser`) or at minimum PBKDF2 with 600k+ iterations via `crypto.subtle.deriveBits`.

---

#### SEC-3: Nostr backup uses kind `1` (public note) — DATA PUBLICLY VISIBLE
**File:** `script.js:764`
```js
kind: 1,
```
Kind 1 is a public note. Even though the content is NIP-04 encrypted, the **event metadata is public**: pubkey, timestamp, tags (`nostr-pwd-backup`). Anyone watching relays can see that this pubkey is backing up a password manager, when they do it, and how often.

**Fix:** Use kind `4` (encrypted DM to self) or kind `30078` (application-specific data) with NIP-44 encryption. At minimum, never kind 1.

---

#### SEC-4: Private key stored in localStorage via `localStoredData["privateKey"]`
**File:** `script.js:660`
```js
localStoredData["privateKey"] = privateKeyField.value
```
The master private key is saved into `localStoredData` which then gets AES-encrypted and stored in localStorage. But:
1. The encryption uses CryptoJS AES with a string password (which defaults to CBC mode with a weak KDF internally — OpenSSL-compatible `EVP_BytesToKey` with MD5, single iteration)
2. The hash of the encryption password is used as the localStorage key, leaking which password slot exists
3. Any XSS can read localStorage directly

**Fix:** 
- Never store the master key. It's deterministic from the seed phrase — re-derive it each session.
- If local caching is needed, use `crypto.subtle` with non-extractable keys and IndexedDB.
- At minimum, use proper AEAD (AES-GCM via Web Crypto) instead of CryptoJS.

---

#### SEC-5: CryptoJS AES uses weak internal KDF (EVP_BytesToKey / MD5)
**File:** `script.js:663`
```js
CryptoJS.AES.encrypt(JSON.stringify(localStoredData), password1)
```
When you pass a string password to CryptoJS.AES.encrypt, it uses OpenSSL's `EVP_BytesToKey` with MD5 and 1 iteration. This is trivially brute-forceable.

**Fix:** Derive a proper key with Argon2id/PBKDF2, then use `crypto.subtle.encrypt` with AES-GCM.

---

#### SEC-6: NIP-04 encrypts to self using identity key — no key separation
**File:** `script.js:757-758`
```js
const encrypted = await nip04.encrypt(sk, pk, data);
```
The same key used for Nostr identity is used directly for backup encryption. If the key is ever compromised for social use, backups are also compromised.

**Fix:** Derive a backup-specific subkey via HKDF:
```js
const backupKey = await deriveSubkey(masterKey, "nostr-backup");
```

---

#### SEC-7: No Content Security Policy
**File:** `index.html` — no CSP meta tag or headers.

The app loads a script from a CDN (`cdn.jsdelivr.net`) with no Subresource Integrity (SRI) hash, and has no CSP to prevent XSS.

**Fix:** Add CSP meta tag:
```html
<meta http-equiv="Content-Security-Policy" content="
  default-src 'none';
  script-src 'self' https://cdn.jsdelivr.net;
  style-src 'self' 'unsafe-inline';
  connect-src wss://relay.damus.io wss://nostr-pub.wellorder.net wss://relay.snort.social wss://nos.lol;
  base-uri 'none';
  form-action 'none';
">
```
Better: bundle nostr-tools locally and drop the CDN allowance entirely.

---

#### SEC-8: CDN dependency without SRI
**File:** `index.html:482`
```html
<script src="https://cdn.jsdelivr.net/npm/nostr-tools@1.15.0/lib/nostr.bundle.min.js"></script>
```
No `integrity` attribute. If jsdelivr is compromised, the attacker gets full access to seed phrases and keys.

**Fix:** Add SRI hash or (better) bundle locally:
```html
<script src="https://cdn.jsdelivr.net/npm/nostr-tools@1.15.0/lib/nostr.bundle.min.js"
        integrity="sha384-XXXXX" crossorigin="anonymous"></script>
```

---

### 🟡 HIGH

#### SEC-9: 30+ `console.log()` statements leaking sensitive data
**File:** `script.js` — lines 72, 154, 205, 281, 283, 286, 578, 608, 618, 671, 672, 736, 750, 761, 773, 780, 811, 824, 831, 868, 885, 893, 900, 920, 931, 958, 989, 1002, 1023 (and more)

Specific dangerous ones:
- Line 286: `console.log(localStoredData)` — logs the entire data store including private key
- Line 608: `console.log('Encrypted data:', encryptedData)` — logs encrypted blob
- Line 618: `console.log('Decrypted data:', decryptedData)` — **logs the decrypted plaintext data**
- Line 671-672: Logs the hashed key and encrypted data
- Line 893: `console.log("🔑 Using pubkey:", pk)` — logs the derived public key

**Impact:** Anyone with access to browser DevTools (shared computer, shoulder surfing, browser extensions with console access) can see all secrets.

**Fix:** Remove all `console.log` calls or gate behind a `DEBUG` flag that's off in production.

---

#### SEC-10: Seed phrase derivation uses non-standard method — NOT BIP-32/BIP-39 compatible
**File:** `script.js:223-225`
```js
const longHex = decimalStringToHex(wordsToIndices(seedPhraseField.value));
privateKeyField.value = longHex;
```
The "private key" is derived by concatenating word indices as padded decimals, then converting to hex. This is NOT the standard BIP-39 → BIP-32 derivation path. It means:
1. The resulting key has **less entropy** than the seed phrase (word indices 0-2047 as 4-digit padded strings, concatenated as a decimal number)
2. It's incompatible with any standard wallet or tool
3. The mapping is deterministic but lossy — different seed phrases could theoretically produce the same hex

**Impact:** Users can't use their seed phrase with any other BIP-39 compatible tool. The entropy reduction may also weaken security.

**Fix:** Use proper PBKDF2-based BIP-39 seed derivation or at minimum document that this is a custom derivation and explain the entropy implications.

---

#### SEC-11: `innerHTML` with partially user-controlled data
**File:** `script.js:470-474`
```js
prompt.innerHTML = `
    <label class="input-label">Word #${index + 1}:</label>
    <input type="text" class="input-field" data-index="${index}">
`;
```
`index` is derived from `getRandomIndices()` which returns numbers, so this specific case is safe. But the pattern is dangerous.

**File:** `script.js:1099-1103` — `result.relay` and `result.id` are injected via `innerHTML`. These come from Nostr relay responses and could potentially contain malicious HTML if a relay is compromised.

**Fix:** Use `textContent` and DOM creation methods instead of `innerHTML` for any data that originates from external sources.

---

#### SEC-12: Password format is predictable — `PASS` + hex + `249+`
**File:** `script.js:294`
```js
passwordField.value = 'PASS' + entropiaContraseña + '249+';
```
The fixed prefix `PASS` and suffix `249+` reduce effective entropy and make the format fingerprint-able. With 16 hex chars, total password is 24 chars but only 64 bits of entropy. Some sites may also reject this format.

**Fix:** Use a configurable password format with higher entropy (at minimum 128 bits / 32 hex chars). Consider generating passwords that meet common site requirements (uppercase, lowercase, digits, special chars) derived from the hash.

---

## 3. Pending Features / UX Improvements

### UX-1: No password strength options
Users can't choose password length, character sets, or format. All passwords follow the fixed `PASS{hex}249+` pattern. Some sites require specific character classes or have max-length limits.

### UX-2: No "show generated seed phrase" copy button
On the `newMnemonicScreen`, the seed phrase is displayed in a readonly textarea but there's no copy button. Users must manually select and copy.

### UX-3: No auto-lock / session timeout
Once the management screen is open, it stays open indefinitely. No timeout to clear sensitive data from the DOM if the user walks away.

### UX-4: No site list / credential browser
Users must remember which sites they've generated passwords for. There's no UI to browse stored user/site/nonce combos.

### UX-5: No dark mode
The app is light-mode only. Given the security-conscious target audience, dark mode is expected.

### UX-6: No mobile-responsive improvements
The CSS is basic responsive but there's no PWA manifest, no service worker for offline use, no "Add to Home Screen" support.

### UX-7: Nonce editor is raw JSON
The "Edit Nonces" screen (`editNoncesScreen`) shows raw JSON in a textarea. Non-technical users will find this unusable. Should be a proper list UI with per-site edit/delete.

### UX-8: Alert-based notifications
All feedback uses `alert()` which blocks the UI and feels dated. Should use toast notifications or inline status messages.

### UX-9: No import/export for all data
There's a nonces JSON download but no full data export/import. Should support encrypted backup file download.

### UX-10: Relay list is hardcoded
Users can't configure which Nostr relays to use. The relay list is hardcoded in 4 separate places (backup, restore, history, restoreById), violating DRY.

### UX-11: `saveEditedNonces()` auto-triggers Nostr backup
**File:** `script.js:699`  
Saving edited nonces immediately calls `backupToNostr()` without confirmation. Unexpected network activity.

### UX-12: No user/email validation
The user/email field accepts anything with no validation or normalization. `user@site.com` and `User@Site.com` would generate different passwords.

---

## 4. Browser Extension

**There is no extension code in this repository.** No `manifest.json`, no `background.js`, no `content_scripts`, nothing related to a Chrome/Firefox extension.

**Question for Fabri:** Is the password manager extension:
- A separate private repo?
- A planned/pending feature?
- Referring to something else entirely?

If building an extension is planned, the architecture should be designed now — the current codebase would need significant refactoring to work as an extension (background script for key derivation, content script for autofill, popup UI, secure messaging between contexts).

---

## 5. Prioritized Action Plan

### P0: Must Fix Before Deploy (Security / Broken)

| # | Issue | Type | Effort |
|---|-------|------|--------|
| 1 | **BUG-1:** Define `deriveNostrKeys()` — localStorage flow crashes | Bug | 30 min |
| 2 | **BUG-2:** Remove or bundle `nostrCloud.js` reference | Bug | 15 min |
| 3 | **BUG-3:** Fix password entropy length (16 vs 32) — breaking change | Bug | 30 min + migration docs |
| 4 | **BUG-4/5:** Set `privateKeyField.value` after Nostr restore | Bug | 15 min |
| 5 | **SEC-9:** Remove all `console.log` with sensitive data | Security | 1 hr |
| 6 | **SEC-1:** Replace `Math.random()` with `crypto.getRandomValues` | Security | 15 min |
| 7 | **SEC-3:** Change Nostr backup from kind `1` to kind `4` or `30078` | Security | 2 hrs |
| 8 | **SEC-7:** Add Content Security Policy | Security | 30 min |
| 9 | **SEC-8:** Add SRI to CDN script or bundle locally | Security | 30 min |
| 10 | **SEC-11:** Replace `innerHTML` with safe DOM methods for relay data | Security | 1 hr |

### P1: Should Fix (Important but not blocking)

| # | Issue | Type | Effort |
|---|-------|------|--------|
| 11 | **SEC-2:** Replace SHA-256 with proper KDF (Argon2id/PBKDF2) | Security | 4-8 hrs |
| 12 | **SEC-4/5:** Replace CryptoJS with Web Crypto API (AES-GCM) | Security | 4-8 hrs |
| 13 | **SEC-6:** Derive backup subkey via HKDF instead of reusing identity key | Security | 2-4 hrs |
| 14 | **SEC-10:** Document non-standard derivation or switch to BIP-32 | Security/Docs | 2-8 hrs |
| 15 | **SEC-12:** Configurable password format with higher entropy | Security/UX | 4 hrs |
| 16 | **UX-10:** Extract relay list to single config, DRY up all 4 usages | Code quality | 1 hr |
| 17 | **UX-11:** Don't auto-backup on nonce edit without confirmation | UX | 15 min |
| 18 | **UX-12:** Normalize user/email input (lowercase trim) | UX | 30 min |

### P2: Nice to Have (Future Features)

| # | Issue | Type | Effort |
|---|-------|------|--------|
| 19 | **UX-3:** Auto-lock / session timeout | UX/Security | 2-4 hrs |
| 20 | **UX-4:** Site list / credential browser UI | UX | 4-8 hrs |
| 21 | **UX-5:** Dark mode | UX | 2-4 hrs |
| 22 | **UX-6:** PWA manifest + service worker for offline | UX | 4-8 hrs |
| 23 | **UX-7:** Proper nonce editor UI (not raw JSON) | UX | 4-8 hrs |
| 24 | **UX-8:** Toast notifications instead of `alert()` | UX | 2-4 hrs |
| 25 | **UX-9:** Full encrypted data export/import | Feature | 4-8 hrs |
| 26 | **UX-2:** Copy button for generated seed phrase | UX | 15 min |
| 27 | Browser extension | Feature | 40+ hrs |

---

## Summary

The app has **4 confirmed bugs** (one is a showstopper crash), **12 security issues** (3 critical), and ~12 UX improvements needed. The most urgent work is fixing the broken `deriveNostrKeys()` call, resolving the password length regression, removing console.log leaks, and switching Nostr backup from kind 1 to an encrypted kind.

The deeper architectural issues (SHA-256 as KDF, CryptoJS, non-standard derivation) should be tackled in a focused security hardening PR after the P0 fixes ship.

**Estimated total effort for P0:** ~6-8 hours  
**Estimated total effort for P0+P1:** ~25-35 hours
