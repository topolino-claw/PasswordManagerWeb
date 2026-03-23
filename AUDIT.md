# Audit Checklist

This document lists every change made in the four-issue batch, with file/location references,
manual test steps, and security considerations. Use this to audit before merging to master.

---

## Issue #36 — docs: detail derivation and nonce workflow

### Changes

| File | Change |
|------|--------|
| `docs/derivation-and-nonces.md` | **Created** — full derivation documentation |
| `docs/how-it-works.md` | Updated to reference derivation doc and local backup |

### What to verify

- [ ] `docs/derivation-and-nonces.md` exists and renders correctly in GitHub.
- [ ] Section §1 (mnemonic → private key) matches the logic in `wordsToIndices()` and `decimalStringToHex()`.
- [ ] Section §2 (password formula) matches `generatePassword()` in `app.js`.
- [ ] Section §3 (nonces) correctly describes how `vault.users[user][site]` stores the version counter.
- [ ] Section §4 (Nostr key derivation) matches `deriveNostrKeys()` in `app.js`.
- [ ] Section §5 (backup encryption) matches `saveLocalNonceBackup()` and `backupToNostr()`.
- [ ] Example passwords in §6 are placeholder values and NOT real keys.
- [ ] `docs/how-it-works.md` links correctly to `derivation-and-nonces.md` sections.

### Security considerations

- The examples in `derivation-and-nonces.md` use a deliberately trivial test phrase ("abandon abandon … about") and are clearly labelled as unsafe. Verify this warning is present in §6.
- No real private keys or seed phrases appear in any documentation file.

---

## Issue #38 — feat: persist encrypted nonce backup locally

### Changes

| File | Lines | Change |
|------|-------|--------|
| `app.js` | `saveLocalNonceBackup()` function | **Added** — encrypts `{users, settings}` with AES(privateKey) and stores to `localStorage['vaultNonceBackup']` |
| `app.js` | `initializeVault()` | Added local backup merge after key derivation |
| `app.js` | `silentRestoreFromNostr()` | Added `saveLocalNonceBackup()` call after successful restore |
| `app.js` | `restoreFromNostr()` | Added `saveLocalNonceBackup()` call after successful restore |
| `app.js` | `restoreFromId()` | Added `saveLocalNonceBackup()` call after successful restore |
| `app.js` | `copyPassword()` | Added `saveLocalNonceBackup()` call after nonce is persisted |

### What to verify

- [ ] `saveLocalNonceBackup()` exists and has a JSDoc comment explaining the feature.
- [ ] It calls `CryptoJS.AES.encrypt(payload, vault.privateKey)`.
- [ ] It stores the result in `localStorage.setItem('vaultNonceBackup', ...)`.
- [ ] It is called in `silentRestoreFromNostr()` after `return true`.
- [ ] It is called in `restoreFromNostr()` before `showToast('Restored from Nostr!')`.
- [ ] It is called in `restoreFromId()` before `showToast('Restored!')`.
- [ ] It is called in `copyPassword()` after the nonce is written to `vault.users`.
- [ ] `initializeVault()` attempts to load and merge `localStorage['vaultNonceBackup']`.
- [ ] Merge logic: local data is applied first; Nostr data (loaded later) overwrites it.
- [ ] Errors in backup read/write are caught and swallowed (non-fatal).

### Manual test steps

1. Open the app. Create a new vault or restore from a seed phrase.
2. Add a site and copy the password. Inspect `localStorage['vaultNonceBackup']` in DevTools — it should be a non-empty encrypted string.
3. Rotate the nonce (increment) and copy again. The localStorage value should change.
4. Lock the vault and reload the page. Restore from the same seed phrase.
5. Verify that nonces are pre-populated from the local backup (before Nostr check completes).
6. After Nostr sync, verify the nonces match the cloud backup (Nostr wins on conflicts).
7. Test with localStorage blocked (e.g. private browsing strict mode): the app should continue working without errors.

### Security considerations

- The local backup is encrypted with `CryptoJS.AES` using `vault.privateKey` as the key. This is acceptable because:
  - The private key never leaves the device and is derived anew from the seed phrase each session.
  - An attacker with localStorage access still needs the seed phrase to decrypt.
- `vault.privateKey` is used as a raw AES key string. CryptoJS will hash it via PBKDF2 internally in AES. This is consistent with existing usage in `saveEncrypted()`.
- The `vaultNonceBackup` key in localStorage contains **only** `{users, settings}` — NOT the seed phrase or private key itself.

---

## Issue #41 — feat: guard sensitive logs

### Changes

| File | Change |
|------|--------|
| `app.js` | Added `debugLog(...args)` function near the top of the file |
| `app.js` | Replaced sensitive `console.log` / `console.error` calls with `debugLog()` |
| `app.js` | Kept `console.error` for non-sensitive relay connection failures |

### Functions with replaced log calls

| Function | Original call | Replaced with |
|----------|---------------|---------------|
| `silentRestoreFromNostr()` | `console.error(url, e)` (decrypt failure) | `debugLog(...)` |
| `unlockVault()` | `console.error(e)` | `debugLog(...)` |
| `backupToNostr()` | `console.error(e)` (outer catch, may expose key context) | `debugLog(...)` |
| `restoreFromNostr()` | `console.error(e)` | `debugLog(...)` |
| `openNostrHistory()` | `console.error(e)` | `debugLog(...)` |
| `restoreFromId()` | `console.error(e)` | `debugLog(...)` |

### Kept as `console.error` (non-sensitive)

| Location | Reason |
|----------|--------|
| `checkForRemoteBackups()` | "Backup check failed" — no sensitive data |
| `backupToNostrSilent()` | "Silent backup failed" — relay name only |
| `backupToNostr()` per-relay failure | Relay URL only, no keys |
| `silentRestoreFromNostr()` per-relay failure | Relay URL + network error only |
| `restoreFromNostr()` per-relay failure | Relay URL only |
| `openNostrHistory()` per-relay failure | Relay URL only |
| `restoreFromId()` per-relay failure | Relay URL only |
| `triggerImport()` | JSON parse error — no secrets |

### What to verify

- [ ] `debugLog()` function exists, checks `debugMode === true` before logging.
- [ ] `debugLog()` has a JSDoc comment explaining the security rationale.
- [ ] In production (debugMode off): no private keys, encrypted blobs, or decrypted content appear in the console.
- [ ] In debug mode (toggle ON in Advanced Settings): logs appear with `[debug]` prefix.
- [ ] Relay connection errors still appear in the console in production.

### Manual test steps

1. Open the app with DevTools console open. debugMode should default to false.
2. Perform a Nostr backup and restore. Verify no key material appears in the console.
3. Go to Advanced Settings → enable Debug Mode. Perform backup/restore again.
4. Verify `[debug]` prefixed logs appear with connection attempts and outcomes.
5. Disable Debug Mode. Verify debug logs stop.
6. Trigger an intentional relay failure (e.g. add an invalid relay URL to RELAYS temporarily). Verify the error still shows in the console even with debugMode off.

### Security considerations

- `debugLog()` is the single control point for sensitive output. All future additions that log private keys, seed phrases, or encrypted content MUST use `debugLog()`.
- `debugMode` is stored in `vault.settings.debugMode` and is off by default. A user must explicitly enable it.
- Even with debugMode on, logs are written to the local browser console only — they are not transmitted anywhere.

---

## Issue #48 — Log Nostr relay connection outcomes

### Changes

| File | Function | Logs added |
|------|----------|------------|
| `app.js` | `connectRelay()` | Attempt, success, timeout, error — all via `debugLog()` |
| `app.js` | `backupToNostr()` | Per-relay success/failure + final summary via `debugLog()` |
| `app.js` | `restoreFromNostr()` | Per-relay event count via `debugLog()` |
| `app.js` | `silentRestoreFromNostr()` | Per-relay event count via `debugLog()` |
| `app.js` | `openNostrHistory()` | Per-relay event count + total unique events via `debugLog()` |
| `app.js` | `restoreFromId()` | Per-relay found/not-found via `debugLog()` |

### What to verify

- [ ] `connectRelay()` logs: `"attempting <url>"`, `"connected — <url>"`, `"timeout — <url>"`, `"error — <url>"`.
- [ ] `backupToNostr()` logs per-relay publish success and a final `"succeeded on X/N relays"` summary.
- [ ] `restoreFromNostr()` logs `"<url> returned N event(s)"` or `"returned no events"` per relay.
- [ ] `silentRestoreFromNostr()` logs the same per-relay counts.
- [ ] `openNostrHistory()` logs per-relay count and final unique count.
- [ ] `restoreFromId()` logs whether each relay returned the target event.
- [ ] All logs use `debugLog()` — none appear with debugMode off.

### Manual test steps

1. Enable Debug Mode in Advanced Settings.
2. Trigger a manual Nostr backup. In the console, verify:
   - One `attempting` log per relay.
   - `connected` or `timeout`/`error` per relay.
   - `published to <url>` for successful relays.
   - Final `succeeded on X/4 relays` summary.
3. Trigger a Nostr restore. Verify per-relay event count logs.
4. Open Nostr History. Verify per-relay and total unique event count logs.
5. Disable Debug Mode. Repeat steps 2–4. Verify no `[debug]` logs appear.

### Security considerations

- All relay outcome logs use only relay URLs and event counts — no key material.
- It is nonetheless correct to route them through `debugLog()` to avoid noisy production consoles and to respect the user's preference.
- Do not log event content or decrypted payloads in these log points.

---

## General — JSDoc and Inline Comments

### Changes

All functions in `app.js` now have JSDoc comments with:
- A brief description
- `@param` tags for each parameter
- `@returns` where applicable

Inline comments were added to explain:
- The BIP39 checksum calculation
- The decimal→hex conversion rationale
- The NIP-44 vs NIP-04 detection logic
- The nonce persistence model
- The local backup merge priority
- The clipboard auto-clear timer
- The visibility-based auto-lock logic

### What to verify

- [ ] Every function in `app.js` has at least a one-line JSDoc description.
- [ ] `@param` tags match actual parameter names and types.
- [ ] No JSDoc comment exposes sensitive information (e.g. describes a real key or phrase).

---

## Regression Checklist

After all changes, verify core functionality is intact:

- [ ] New wallet flow: generate seed → verify backup → arrive at main screen
- [ ] Restore wallet flow: enter seed phrase → arrive at main screen with saved sites
- [ ] Password copy: select site → copy → toast "Saved & copied!" appears
- [ ] Nonce increment/decrement: generates different passwords
- [ ] Save encrypted: vault can be locked and unlocked with a password
- [ ] Nostr backup/restore: round-trip works on at least one relay
- [ ] Nostr history: shows events, clicking restores
- [ ] Import/export JSON: round-trip preserves nonces
- [ ] Auto-lock: vault locks after 5 minutes of inactivity
- [ ] Tab-hide lock: vault locks if tab is hidden for 2+ minutes
- [ ] Debug mode toggle: persists across sessions
