# Vault — React Native Draft

## Why

Web version works but is limited to browsers. A native app gives:
- Biometric unlock (Face ID / fingerprint)
- Autofill integration (iOS/Android password autofill APIs)
- Offline-first with background Nostr sync
- Clipboard auto-clear (security)
- Push notifications for sync conflicts

---

## Architecture

```
┌─────────────────────────────────────────┐
│              React Native App           │
│                                         │
│  ┌───────────┐  ┌────────────────────┐  │
│  │   UI       │  │  Navigation        │  │
│  │  (Screens) │  │  (React Navigation)│  │
│  └─────┬─────┘  └────────────────────┘  │
│        │                                │
│  ┌─────▼──────────────────────────────┐ │
│  │         State (Zustand)            │ │
│  │  vault, nonce, settings, nostr     │ │
│  └─────┬──────────────────────────────┘ │
│        │                                │
│  ┌─────▼──────────────────────────────┐ │
│  │         Core Logic (shared)        │ │
│  │  crypto · bip39 · password-gen     │ │
│  │  nostr-backup · vault-ops          │ │
│  └─────┬──────────────────────────────┘ │
│        │                                │
│  ┌─────▼──────────────────────────────┐ │
│  │     Platform Layer                 │ │
│  │  SecureStore · Biometrics          │ │
│  │  Clipboard · Autofill             │ │
│  └────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

### Key Decisions

- **Expo** (managed workflow) — fast to ship, EAS builds, OTA updates
- **Zustand** for state — same pattern Fabri uses in other projects
- **expo-secure-store** for vault encryption at rest (replaces localStorage)
- **expo-local-authentication** for biometrics
- **Core logic as pure JS modules** — shared between web and native

---

## Code Reuse Audit

### 100% Reusable (pure JS, no DOM)

| Module | Lines | Notes |
|--------|-------|-------|
| BIP39 seed generation & validation | ~60 | Already pure functions |
| Key derivation (PBKDF2 → master key) | ~20 | Uses Web Crypto — needs polyfill or `react-native-quick-crypto` |
| Password generation (deterministic hash) | ~15 | Pure logic |
| Vault data model (users/sites/nonces) | ~30 | Just objects |
| Nostr backup/restore logic | ~250 | Relay connections, event signing, encryption — reusable with minor transport swap |
| Nonce tracking & management | ~20 | Pure state logic |
| **Subtotal** | **~395** | **~37% of app.js** |

### Partially Reusable (needs adaptation)

| Module | Lines | What Changes |
|--------|-------|-------------|
| Local encryption (AES-GCM) | ~70 | Web Crypto API → `expo-crypto` or `react-native-quick-crypto` |
| Seed autocomplete | ~120 | DOM manipulation → RN `FlatList` + `TextInput` |
| Navigation / screen flow | ~30 | `showScreen()` → React Navigation |
| **Subtotal** | **~220** | **Logic reusable, bindings change** |

### Must Rewrite (DOM-dependent)

| Module | Lines | RN Replacement |
|--------|-------|----------------|
| UI rendering (all HTML/CSS) | 983 | React Native components |
| Toast system | ~20 | `react-native-toast-message` |
| Clipboard | ~10 | `expo-clipboard` |
| Site list rendering | ~60 | `FlatList` |
| Password visibility toggle | ~15 | RN state + `secureTextEntry` |

### Summary

| Category | Lines | % of Total |
|----------|-------|-----------|
| 100% reusable | ~395 | ~19% |
| Logic reusable, bindings change | ~220 | ~11% |
| Must rewrite | ~1,426 | ~70% |

**Bottom line:** ~30% of the logic transfers directly. The crypto core, Nostr sync, and vault model are the valuable parts — and those all carry over. The UI is a full rewrite but the web version is simple enough that it's ~2 days of work.

---

## Proposed Structure

```
vault-mobile/
├── app/                        # Expo Router screens
│   ├── (tabs)/
│   │   ├── index.tsx           # Vault (site list)
│   │   └── settings.tsx        # Settings
│   ├── generate.tsx            # Password generation
│   ├── setup/
│   │   ├── welcome.tsx
│   │   ├── new-wallet.tsx
│   │   ├── import-wallet.tsx
│   │   └── verify-seed.tsx
│   └── _layout.tsx
├── core/                       # ← SHARED with web version
│   ├── bip39.ts                # Seed phrase gen/validate
│   ├── crypto.ts               # Key derivation, AES (abstract interface)
│   ├── password.ts             # Deterministic password generation
│   ├── vault.ts                # Vault data model & operations
│   ├── nostr.ts                # Backup/restore via Nostr relays
│   └── constants.ts            # Relays, defaults
├── platform/                   # Native-specific implementations
│   ├── storage.ts              # expo-secure-store wrapper
│   ├── biometrics.ts           # expo-local-authentication
│   ├── clipboard.ts            # expo-clipboard + auto-clear
│   └── crypto-native.ts        # react-native-quick-crypto
├── store/
│   └── vault-store.ts          # Zustand store
├── components/
│   ├── SiteList.tsx
│   ├── NonceControl.tsx
│   ├── PasswordDisplay.tsx
│   └── SeedInput.tsx
└── package.json
```

---

## Native-Only Features (phase 2)

1. **Biometric unlock** — skip password on trusted device
2. **Autofill provider** — register as password manager in iOS/Android settings
3. **Clipboard auto-clear** — wipe after 30s
4. **Background Nostr sync** — `expo-background-fetch`
5. **Sync conflict resolution** — merge nonce changes from multiple devices
6. **Widget** — quick-copy for favorite sites (iOS 17+ / Android)

---

## Effort Estimate

| Phase | Scope | Time |
|-------|-------|------|
| 1. Core extraction | Pull pure JS into `core/`, add TypeScript types | 0.5 day |
| 2. Expo scaffold | Navigation, screens, basic UI | 1 day |
| 3. Feature parity | All current web features working natively | 1.5 days |
| 4. Native enhancements | Biometrics, autofill, clipboard clear | 1 day |
| **Total MVP** | | **~4 days** |

---

## Open Questions

- **Monorepo or separate repo?** Could use a shared `core/` package via npm workspace
- **Web version migration?** Could rebuild web with React (shared components with RN Web)
- **Autofill:** iOS credential provider extension requires a native module — worth it in v1?
