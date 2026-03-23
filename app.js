/**
 * Vault v3 - Deterministic Password Manager
 * Clean rewrite with simplified UX
 *
 * Architecture:
 *  - Passwords are deterministic: derived from privateKey + user + site + nonce via SHA-256.
 *  - The private key never changes — it is deterministically derived from the BIP39 seed phrase.
 *  - Nonces are the only mutable state: they are persisted to Nostr (encrypted) and optionally
 *    to localStorage as an encrypted local backup (see saveLocalNonceBackup).
 *  - debugMode gates all sensitive log output via debugLog().
 */

// ============================================
// State
// ============================================
let vault = {
    privateKey: '',
    seedPhrase: '',
    users: {},
    settings: { hashLength: 16, debugMode: false }
};

let nostrKeys = { nsec: '', npub: '' };
let currentNonce = 0;
let originalNonce = 0;
let passwordVisible = false;
let navigationStack = ['welcomeScreen'];
let debugMode = false;
let inactivityTimer = null;
let unlockAttempts = 0;
let unlockLockoutUntil = 0;
let clipboardClearTimer = null;

const INACTIVITY_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
const VISIBILITY_LOCK_MS = 2 * 60 * 1000; // 2 minutes hidden = lock
const MAX_UNLOCK_ATTEMPTS = 5;
const UNLOCK_LOCKOUT_MS = 30 * 1000; // 30 seconds
const DEFAULT_HASH_LENGTH = 16;

const RELAYS = [
    "wss://relay.damus.io",
    "wss://nostr-pub.wellorder.net",
    "wss://relay.snort.social",
    "wss://nos.lol"
];

// ============================================
// Debug Guard
// ============================================

/**
 * Conditional logger that only emits output when debugMode is enabled.
 * Use this for ANY log that could expose sensitive data: private keys,
 * seed phrases, encrypted blobs, decrypted vault content, or Nostr keys.
 * Safe (non-sensitive) errors — e.g. relay connection failures — may use
 * console.error directly so they always surface in production.
 *
 * @param {...*} args - Arguments forwarded to console.log when debugMode is true.
 */
function debugLog(...args) {
    if (debugMode) {
        console.log('[debug]', ...args);
    }
}

// ============================================
// Navigation
// ============================================

/**
 * Show a named screen by its DOM id, hiding all others.
 * Pushes the screenId onto the navigation stack unless it is already the top.
 * Triggers screen-specific setup (e.g. rendering the site list, generating a seed).
 *
 * @param {string} screenId - The id of the <div class="screen"> element to display.
 */
function showScreen(screenId) {
    document.querySelectorAll('.screen').forEach(s => s.classList.add('hidden'));
    const target = document.getElementById(screenId);
    if (target) {
        target.classList.remove('hidden');
        if (navigationStack[navigationStack.length - 1] !== screenId) {
            navigationStack.push(screenId);
        }
    }

    // Screen-specific setup
    if (screenId === 'mainScreen') {
        renderSiteList();
    } else if (screenId === 'newWalletScreen') {
        generateNewSeed(true);
    } else if (screenId === 'advancedScreen') {
        document.getElementById('hashLengthSetting').value = vault.settings.hashLength || 16;
        debugMode = vault.settings.debugMode || false;
        document.getElementById('debugModeToggle').checked = debugMode;
    }
}

/**
 * Navigate back to the previous screen in the navigation stack.
 * Falls back to 'welcomeScreen' if the stack is empty.
 */
function goBack() {
    navigationStack.pop();
    const prev = navigationStack[navigationStack.length - 1] || 'welcomeScreen';
    showScreen(prev);
}

// ============================================
// Toast
// ============================================

/**
 * Display a brief status message at the bottom of the screen.
 * The toast automatically hides after 2 seconds.
 *
 * @param {string} message - The text to display.
 */
function showToast(message) {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 2000);
}

/**
 * Show the fullscreen loading modal with a status message.
 *
 * @param {string} text - Loading text shown inside the modal.
 */
function showLoading(text) {
    document.getElementById('loadingText').textContent = text;
    document.getElementById('loadingModal').classList.remove('hidden');
}

/**
 * Hide the fullscreen loading modal.
 */
function hideLoading() {
    document.getElementById('loadingModal').classList.add('hidden');
}

// ============================================
// BIP39 Seed Phrase Functions (preserved from original)
// ============================================

/**
 * Convert a decimal string (arbitrary precision) to a hexadecimal string.
 * Used to transform the concatenated BIP39 word indices into the private key.
 *
 * @param {string} decStr - A string of decimal digits (e.g. "0234107220153...").
 * @returns {string} Hexadecimal representation without leading "0x".
 * @throws {Error} If decStr contains non-digit characters.
 */
function decimalStringToHex(decStr) {
    if (!/^\d+$/.test(decStr)) throw new Error("Invalid decimal string");
    return BigInt(decStr).toString(16);
}

/**
 * Convert a space-separated list of BIP39 words into their concatenated
 * zero-padded 4-digit indices as a single decimal string.
 *
 * Example: "abandon abandon about" → "000000000002"
 * (indices 0, 0, 2 each padded to 4 digits)
 *
 * @param {string} inputWords - Space-separated BIP39 words (case-insensitive).
 * @returns {string} Concatenated decimal index string (each word = 4 chars).
 * @throws {Error} If any word is not found in the BIP39 word list.
 */
function wordsToIndices(inputWords) {
    const wordsArray = inputWords.trim().split(/\s+/);
    return wordsArray.map(word => {
        const index = words.indexOf(word.toLowerCase());
        if (index === -1) throw new Error(`Word "${word}" not found`);
        return index.toString().padStart(4, '0');
    }).join('');
}

/**
 * Verify that a BIP39 seed phrase has a valid checksum.
 * Accepts 12, 15, 18, 21, or 24 word phrases.
 *
 * @param {string} seedPhrase - Space-separated BIP39 mnemonic.
 * @returns {Promise<boolean>} True if valid, false otherwise.
 */
async function verifyBip39SeedPhrase(seedPhrase) {
    const normalized = seedPhrase.replace(/\s+/g, ' ').trim().toLowerCase();
    const seedWords = normalized.split(' ');

    if (![12, 15, 18, 21, 24].includes(seedWords.length)) return false;

    const invalid = seedWords.filter(w => !words.includes(w));
    if (invalid.length > 0) return false;

    const totalBits = seedWords.length * 11;
    const checksumBits = totalBits % 32;
    const entropyBits = totalBits - checksumBits;

    const binary = seedWords.map(w => words.indexOf(w).toString(2).padStart(11, '0')).join('');
    const entropy = binary.slice(0, entropyBits);
    const checksum = binary.slice(entropyBits);

    const entropyBytes = new Uint8Array(entropy.length / 8);
    for (let i = 0; i < entropy.length; i += 8) {
        entropyBytes[i / 8] = parseInt(entropy.slice(i, i + 8), 2);
    }

    const hashBuffer = await crypto.subtle.digest('SHA-256', entropyBytes);
    const hashBinary = Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(2).padStart(8, '0')).join('');

    return checksum === hashBinary.slice(0, checksumBits);
}

/**
 * Generate a random 12-word BIP39 mnemonic using 128 bits of entropy.
 * Uses the Web Crypto API for cryptographically secure randomness.
 *
 * @returns {Promise<string>} Space-separated 12-word mnemonic phrase.
 */
async function generateMnemonic() {
    const entropy = new Uint8Array(16); // 128 bits
    crypto.getRandomValues(entropy);

    const entropyBinary = Array.from(entropy).map(b => b.toString(2).padStart(8, '0')).join('');
    const hashBuffer = await crypto.subtle.digest('SHA-256', entropy);
    const hashBinary = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(2).padStart(8, '0')).join('');
    // BIP39: checksum = first (entropyBits/32) bits of SHA-256(entropy)
    const checksumBits = entropyBinary.length / 32;

    const fullBinary = entropyBinary + hashBinary.slice(0, checksumBits);
    const mnemonic = [];
    // Split into 11-bit groups and map each to a BIP39 word
    for (let i = 0; i < fullBinary.length; i += 11) {
        mnemonic.push(words[parseInt(fullBinary.slice(i, i + 11), 2)]);
    }

    return mnemonic.join(' ');
}

// ============================================
// Key Derivation (preserved from original)
// ============================================

/**
 * Derive the deterministic private key from a BIP39 seed phrase.
 * Process: normalize → word indices → decimal string → hex string.
 *
 * @param {string} seedPhrase - Valid BIP39 mnemonic (any case/spacing).
 * @returns {Promise<string>} Hex-encoded private key (variable length, no 0x prefix).
 */
async function derivePrivateKey(seedPhrase) {
    const normalized = seedPhrase.replace(/\s+/g, ' ').trim().toLowerCase();
    const indices = wordsToIndices(normalized);
    // Convert the big decimal number (concatenated 4-digit indices) to hex
    return decimalStringToHex(indices);
}

/**
 * Derive Nostr keys (nsec / npub) from the vault's private key.
 * The Nostr secret key is SHA-256(privateKey), ensuring the Nostr identity
 * is separate from but deterministically linked to the vault's private key.
 *
 * @param {string} privateKey - Hex private key from derivePrivateKey().
 * @returns {Promise<{nsec: string, npub: string, hex: string}>}
 *   nsec: bech32-encoded Nostr secret key
 *   npub: hex-encoded Nostr public key
 *   hex:  raw hex Nostr secret key
 */
async function deriveNostrKeys(privateKey) {
    const { nip19, getPublicKey } = window.NostrTools;
    const utf8 = new TextEncoder().encode(privateKey);
    const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
    // Nostr secret key = SHA-256 of the vault private key
    const nostrHex = Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, '0')).join('');

    const nsec = nip19.nsecEncode(nostrHex);
    const npub = getPublicKey(nostrHex);
    return { nsec, npub, hex: nostrHex };
}

// ============================================
// Password Generation (preserved from original)
// ============================================

/**
 * Compute the SHA-256 hash of a string and return it as a lowercase hex string.
 *
 * @param {string} text - Input string.
 * @returns {string} 64-character lowercase hex SHA-256 digest.
 */
function hash(text) {
    return CryptoJS.SHA256(text).toString();
}

/**
 * Generate a deterministic password for the given credentials.
 *
 * Algorithm:
 *   concat = "<privateKey>/<user>/<site>/<nonce>"
 *   entropy = SHA-256(concat).substring(0, hashLength)
 *   password = "PASS" + entropy + "249+"
 *
 * The fixed prefix "PASS" and suffix "249+" satisfy most complexity requirements
 * (uppercase, lowercase, digits, special characters) regardless of the hex portion.
 *
 * @param {string} privateKey  - Hex private key derived from seed phrase.
 * @param {string} user        - Username / email associated with the site.
 * @param {string} site        - Site name or domain (e.g. "github.com").
 * @param {number} nonce       - Version counter (0-based). Increment to rotate the password.
 * @param {number} [hashLength=16] - Number of hex characters to take from the SHA-256 output.
 * @returns {string} The generated password in the form "PASS<hex>249+".
 */
function generatePassword(privateKey, user, site, nonce, hashLength = 16) {
    const concat = `${privateKey}/${user}/${site}/${nonce}`;
    const entropy = hash(concat).substring(0, hashLength);
    return 'PASS' + entropy + '249+';
}

/**
 * Calculate effective entropy bits of a generated password.
 * hex chars = 4 bits each. Fixed prefix/suffix add known charset expansion.
 *
 * @param {number} hashLength - Number of hex chars used in the password entropy portion.
 * @returns {{bits: number, label: string, color: string, len: number}}
 *   bits:  entropy bits from the hex portion
 *   label: human-readable strength label
 *   color: CSS color variable string
 *   len:   total password character count (prefix + entropy + suffix)
 */
function getPasswordStrength(hashLength) {
    // Each hex character contributes 4 bits of entropy from SHA-256
    const hexBits = hashLength * 4;
    // Total length: "PASS" (4) + hex portion + "249+" (4)
    const totalLen = 4 + hashLength + 4;

    if (hexBits >= 80) return { bits: hexBits, label: 'Excellent', color: 'var(--success)', len: totalLen };
    if (hexBits >= 64) return { bits: hexBits, label: 'Strong', color: 'var(--success)', len: totalLen };
    if (hexBits >= 48) return { bits: hexBits, label: 'Good', color: 'var(--accent)', len: totalLen };
    return { bits: hexBits, label: 'Weak', color: 'var(--danger)', len: totalLen };
}

// ============================================
// Seed Phrase UI
// ============================================

/**
 * Generate a new random mnemonic and display it in the seed grid UI.
 * If a seed is already loaded and this is not the initial render, confirms
 * before replacing it.
 *
 * @param {boolean} [isInitial=false] - Skip confirmation when true (first display).
 */
async function generateNewSeed(isInitial = false) {
    // Only confirm if there's already a seed loaded (re-generating)
    if (!isInitial && vault.seedPhrase && vault.privateKey) {
        if (!confirm('Generate a new seed phrase? This will replace the current one.')) return;
    }
    const mnemonic = await generateMnemonic();
    vault.seedPhrase = mnemonic;

    const grid = document.getElementById('seedGrid');
    grid.innerHTML = '';

    mnemonic.split(' ').forEach((word, i) => {
        const div = document.createElement('div');
        div.className = 'seed-word';
        div.innerHTML = `<span>${i + 1}.</span>${word}`;
        grid.appendChild(div);
    });
}

/**
 * Begin the seed backup verification flow.
 * Picks 3 random word positions and renders text inputs for the user to fill in.
 * Transitions to the 'verifySeedScreen'.
 */
function confirmSeedBackup() {
    // Setup verification
    const seedWords = vault.seedPhrase.split(' ');
    const indices = [];
    while (indices.length < 3) {
        const r = Math.floor(Math.random() * seedWords.length);
        if (!indices.includes(r)) indices.push(r);
    }
    indices.sort((a, b) => a - b);

    const container = document.getElementById('verifyInputs');
    container.innerHTML = '';
    container.dataset.indices = JSON.stringify(indices);

    indices.forEach(i => {
        const div = document.createElement('div');
        div.className = 'input-group';
        div.innerHTML = `
            <label>Word #${i + 1}</label>
            <input type="text" class="verify-word" data-index="${i}" placeholder="Enter word ${i + 1}">
        `;
        container.appendChild(div);
    });

    // Bind Enter key on dynamically created verify inputs
    container.querySelectorAll('.verify-word').forEach(input => {
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') verifySeedBackup();
        });
    });

    showScreen('verifySeedScreen');
}

/**
 * Validate the user's seed verification inputs.
 * If all 3 words are correct, initialize the vault and proceed to the main screen.
 * On failure, highlights the incorrect fields and shows a toast.
 *
 * @returns {Promise<void>}
 */
async function verifySeedBackup() {
    const seedWords = vault.seedPhrase.split(' ');
    const inputs = document.querySelectorAll('.verify-word');
    let valid = true;

    inputs.forEach(input => {
        const idx = parseInt(input.dataset.index);
        if (input.value.trim().toLowerCase() !== seedWords[idx]) {
            input.style.borderColor = 'var(--danger)';
            valid = false;
        } else {
            input.style.borderColor = 'var(--success)';
        }
    });

    if (valid) {
        await initializeVault(vault.seedPhrase);
        await checkForRemoteBackups();
        showScreen('mainScreen');
    } else {
        showToast('Incorrect words. Try again.');
    }
}

/**
 * Validate and restore a vault from a user-entered seed phrase.
 * Validates BIP39 checksum, initializes the vault, checks for Nostr backups,
 * then navigates to the main screen.
 *
 * @returns {Promise<void>}
 */
async function restoreFromSeed() {
    const input = document.getElementById('restoreSeedInput').value;
    const valid = await verifyBip39SeedPhrase(input);

    if (!valid) {
        showToast('Invalid seed phrase');
        return;
    }

    await initializeVault(input);
    await checkForRemoteBackups();
    showScreen('mainScreen');
}

// ============================================
// Vault Management
// ============================================

/**
 * Initialize the vault from a seed phrase: derive keys, merge any local nonce backup.
 * After this call, vault.privateKey and nostrKeys are populated and the
 * inactivity timer is reset.
 *
 * Local backup merging: if a vaultNonceBackup exists in localStorage (written by
 * saveLocalNonceBackup), it is decrypted and merged as a low-priority fallback —
 * any data from a subsequent Nostr restore will win over local data.
 *
 * @param {string} seedPhrase - Valid BIP39 mnemonic.
 * @returns {Promise<void>}
 */
async function initializeVault(seedPhrase) {
    vault.seedPhrase = seedPhrase.replace(/\s+/g, ' ').trim().toLowerCase();
    vault.privateKey = await derivePrivateKey(vault.seedPhrase);
    nostrKeys = await deriveNostrKeys(vault.privateKey);

    // Attempt to load local nonce backup as a low-priority seed.
    // Nostr data (fetched later in checkForRemoteBackups) will overwrite this.
    try {
        const localBackupRaw = localStorage.getItem('vaultNonceBackup');
        if (localBackupRaw) {
            debugLog('initializeVault: local nonce backup found, attempting merge');
            const decrypted = CryptoJS.AES.decrypt(localBackupRaw, vault.privateKey)
                .toString(CryptoJS.enc.Utf8);
            if (decrypted) {
                const localData = JSON.parse(decrypted);
                // Merge users — only adopt local nonces if not already present in vault
                if (localData.users) {
                    Object.entries(localData.users).forEach(([user, sites]) => {
                        if (!vault.users[user]) vault.users[user] = {};
                        Object.entries(sites).forEach(([site, nonce]) => {
                            // Local backup wins only if vault has no entry for this site
                            if (vault.users[user][site] === undefined) {
                                vault.users[user][site] = nonce;
                            }
                        });
                    });
                }
                if (localData.settings) {
                    // Only adopt settings not already set
                    vault.settings = { ...localData.settings, ...vault.settings };
                }
                debugLog('initializeVault: local backup merged');
            }
        }
    } catch (e) {
        // Non-fatal: corrupted or missing local backup — just ignore
        debugLog('initializeVault: could not read local backup:', e);
    }

    resetInactivityTimer();
}

/**
 * After vault initialization, silently check Nostr relays for an existing backup.
 * Shows a loading modal during the check. On success, notifies the user.
 *
 * @returns {Promise<void>}
 */
async function checkForRemoteBackups() {
    const npubShort = nostrKeys.npub.slice(0, 16) + '...';

    showLoading(`Looking for remote backups...\n${npubShort}`);

    try {
        const found = await silentRestoreFromNostr();
        hideLoading();

        if (found) {
            showToast('Synced from cloud backup!');
        } else {
            showToast('Vault ready');
        }
    } catch (e) {
        console.error('Backup check failed:', e);
        hideLoading();
        showToast('Vault ready (offline)');
    }
}

/**
 * Silently attempt to restore vault data from Nostr relays without UI prompts.
 * Queries all configured relays for the latest backup event, decrypts it,
 * and merges users/settings into the current vault state.
 * After a successful restore, saves a local encrypted backup.
 *
 * @returns {Promise<boolean>} True if a backup was found and applied, false otherwise.
 */
async function silentRestoreFromNostr() {
    if (!vault.privateKey) return false;

    const { sk, pk } = await getNostrKeyPair();

    let latest = null;

    for (const url of RELAYS) {
        try {
            debugLog(`silentRestoreFromNostr: connecting to ${url}`);
            const relay = await connectRelay(url);

            // Query both new (kind:30078) and legacy (kind:1) formats
            const events = await subscribeAndCollect(relay, [
                { kinds: [30078], authors: [pk], "#d": [BACKUP_D_TAG], limit: 1 },
                { kinds: [1], authors: [pk], "#t": ["nostr-pwd-backup"], limit: 1 }
            ], 6000);

            relay.close();

            if (events.length > 0) {
                debugLog(`silentRestoreFromNostr: ${url} returned ${events.length} event(s)`);
            } else {
                debugLog(`silentRestoreFromNostr: ${url} returned no events`);
            }

            for (const e of events) {
                if (!latest || e.created_at > latest.created_at) latest = e;
            }
        } catch (e) {
            // Relay connection errors are not sensitive — log them always
            console.error(`silentRestoreFromNostr: relay error [${url}]`, e);
        }
    }

    if (latest) {
        try {
            const decrypted = await decryptBackupEvent(latest, sk, pk);
            const data = JSON.parse(decrypted);
            vault.users = { ...vault.users, ...data.users };
            if (data.settings) {
                vault.settings = { ...vault.settings, ...data.settings };
                debugMode = vault.settings.debugMode || false;
            }
            // Persist the freshly restored data to local backup
            saveLocalNonceBackup();
            return true;
        } catch (e) {
            // Decrypt failure may expose content context — use debugLog
            debugLog('silentRestoreFromNostr: decrypt failed:', e);
            return false;
        }
    }

    return false;
}

/**
 * Lock the vault, clearing all sensitive state from memory.
 * Clears the clipboard, cancels timers, resets navigation, and shows the welcome screen.
 *
 * @param {boolean} [skipConfirm=false] - If true, skip the confirmation dialog.
 */
function lockVault(skipConfirm = false) {
    if (!skipConfirm && vault.privateKey) {
        if (!confirm('Lock vault? Make sure you have your seed phrase saved.')) return;
    }
    if (inactivityTimer) clearTimeout(inactivityTimer);
    inactivityTimer = null;
    if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
    clipboardClearTimer = null;
    navigator.clipboard.writeText('').catch(() => {});
    // Wipe all sensitive data from memory
    vault = { privateKey: '', seedPhrase: '', users: {}, settings: { hashLength: 16 } };
    nostrKeys = { nsec: '', npub: '' };
    navigationStack = ['welcomeScreen'];
    showScreen('welcomeScreen');
    showToast('Vault locked');
}

// ============================================
// Local Nonce Backup (Issue #38)
// ============================================

/**
 * Encrypt and save the current vault nonce data to localStorage.
 *
 * This provides a local fallback so that nonce state (password versions) is not
 * lost if Nostr relays are temporarily unavailable. The backup is encrypted with
 * CryptoJS AES using the vault's private key as the encryption key, so it is
 * only useful to someone who already has the seed phrase.
 *
 * Priority on restore: Nostr > local backup. Local backup is merged first during
 * initializeVault(), and then any subsequent Nostr restore will overwrite it.
 *
 * Call this after:
 *   - Any successful Nostr restore (data changed)
 *   - copyPassword() (nonce may have changed)
 */
function saveLocalNonceBackup() {
    if (!vault.privateKey) return;
    try {
        const payload = JSON.stringify({ users: vault.users, settings: vault.settings });
        // Encrypt with the private key — only someone with the seed phrase can decrypt
        const encrypted = CryptoJS.AES.encrypt(payload, vault.privateKey).toString();
        localStorage.setItem('vaultNonceBackup', encrypted);
        debugLog('saveLocalNonceBackup: local backup saved');
    } catch (e) {
        // Non-fatal: if localStorage is full or unavailable, log and continue
        debugLog('saveLocalNonceBackup: failed to save local backup:', e);
    }
}

// ============================================
// Site List & Search
// ============================================

/**
 * Render the list of saved sites in the main screen.
 * Filters by the current search term (site name or username).
 * Shows the empty state element when there are no sites and no active search.
 */
function renderSiteList() {
    const container = document.getElementById('siteList');
    const emptyState = document.getElementById('emptyState');
    const searchTerm = document.getElementById('siteSearch').value.toLowerCase();

    // Collect all sites across all users
    const sites = [];
    Object.entries(vault.users || {}).forEach(([user, userSites]) => {
        Object.entries(userSites).forEach(([site, nonce]) => {
            sites.push({ user, site, nonce });
        });
    });

    // Filter by site name or username
    const filtered = sites.filter(s =>
        s.site.toLowerCase().includes(searchTerm) ||
        s.user.toLowerCase().includes(searchTerm)
    );

    if (filtered.length === 0 && !searchTerm) {
        container.innerHTML = '';
        emptyState.classList.remove('hidden');
        return;
    }

    emptyState.classList.add('hidden');
    container.innerHTML = filtered.map(s => `
        <div class="site-item" data-site="${escapeHtml(s.site)}" data-user="${escapeHtml(s.user)}" data-nonce="${s.nonce}">
            <div class="site-icon">${escapeHtml(s.site.charAt(0))}</div>
            <div class="site-info">
                <div class="site-name">${escapeHtml(s.site)}</div>
                <div class="site-user">${escapeHtml(s.user)}</div>
            </div>
            <button class="btn-delete" data-delete-site="${escapeHtml(s.site)}" data-delete-user="${escapeHtml(s.user)}" title="Delete">✕</button>
        </div>
    `).join('');
}

/**
 * Re-render the site list (called by the search input's oninput handler).
 */
function filterSites() {
    renderSiteList();
}

/**
 * Handle Enter key in the site search input.
 * If the search term matches no existing site, opens a new password generation
 * screen pre-filled with the search term as the site name.
 *
 * @param {KeyboardEvent} event - The keydown event from the search input.
 */
function handleSearchEnter(event) {
    if (event.key === 'Enter') {
        const term = document.getElementById('siteSearch').value.trim();
        if (term) {
            openSite(term, '', 0);
        }
    }
}

/**
 * Escape HTML special characters to prevent XSS when inserting user data into innerHTML.
 *
 * @param {string} str - Untrusted string.
 * @returns {string} HTML-escaped string safe for use in innerHTML.
 */
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

/** Escape a string for safe use inside a JS string literal in an HTML attribute (onclick, etc.) */
function escapeJsString(str) {
    return str.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '&quot;');
}

// ============================================
// Password Generation Screen
// ============================================

/**
 * Open the password generation screen for a given site/user combination.
 * Pre-fills the site and user fields, restores the nonce, and shows the
 * password strength indicator.
 *
 * @param {string} site  - Site name or domain.
 * @param {string} user  - Username / email.
 * @param {number} nonce - Current nonce (0-based version counter).
 */
function openSite(site, user, nonce) {
    document.getElementById('genSite').value = site;
    document.getElementById('genUser').value = user;
    currentNonce = nonce || 0;
    originalNonce = currentNonce;
    document.getElementById('nonceDisplay').textContent = currentNonce + 1;
    passwordVisible = false;
    document.getElementById('genPassword').textContent = '••••••••••••';
    document.getElementById('visibilityIcon').textContent = '👁️';
    updateNonceIndicator();

    // Always show strength indicator
    const strengthEl = document.getElementById('passwordStrength');
    if (strengthEl) {
        const s = getPasswordStrength(vault.settings.hashLength || DEFAULT_HASH_LENGTH);
        strengthEl.innerHTML = `<span style="color:${s.color}">● ${s.label}</span> · ${s.bits}-bit · ${s.len} chars`;
    }

    if (site && user) {
        updatePassword();
    }

    showScreen('generateScreen');
}

/**
 * Update the nonce control's visual indicator.
 * Adds the 'nonce-changed' CSS class when the current nonce differs from the
 * saved (original) nonce, alerting the user that copying will update the stored version.
 */
function updateNonceIndicator() {
    const nonceControl = document.querySelector('.nonce-control');
    if (currentNonce !== originalNonce) {
        nonceControl.classList.add('nonce-changed');
    } else {
        nonceControl.classList.remove('nonce-changed');
    }
}

/**
 * Recompute and display the generated password based on the current
 * site, user, and nonce inputs. Only updates the display if the password
 * is currently visible.
 */
function updatePassword() {
    const site = document.getElementById('genSite').value.trim();
    const user = document.getElementById('genUser').value.trim();
    const strengthEl = document.getElementById('passwordStrength');

    if (!site || !user || !vault.privateKey) {
        document.getElementById('genPassword').textContent = '••••••••••••';
        if (strengthEl) strengthEl.textContent = '';
        return;
    }

    const hl = vault.settings.hashLength || DEFAULT_HASH_LENGTH;
    const pass = generatePassword(vault.privateKey, user, site, currentNonce, hl);

    if (passwordVisible) {
        document.getElementById('genPassword').textContent = pass;
    }

    // Update strength indicator
    if (strengthEl) {
        const s = getPasswordStrength(hl);
        strengthEl.innerHTML = `<span style="color:${s.color}">● ${s.label}</span> · ${s.bits}-bit · ${s.len} chars`;
    }
}

/**
 * Toggle password visibility between the generated password and the masked placeholder.
 * Calls updatePassword() to reveal the current password when toggling on.
 */
function togglePasswordVisibility() {
    passwordVisible = !passwordVisible;
    document.getElementById('visibilityIcon').textContent = passwordVisible ? '🙈' : '👁️';

    if (passwordVisible) {
        updatePassword();
    } else {
        document.getElementById('genPassword').textContent = '••••••••••••';
    }
}

/**
 * Increment the nonce (password version) by 1.
 * Updates the display and regenerates the password if visible.
 */
function incrementNonce() {
    currentNonce++;
    document.getElementById('nonceDisplay').textContent = currentNonce + 1;
    updateNonceIndicator();
    if (passwordVisible) updatePassword();
}

/**
 * Decrement the nonce (password version) by 1, minimum 0.
 * Updates the display and regenerates the password if visible.
 */
function decrementNonce() {
    if (currentNonce > 0) {
        currentNonce--;
        document.getElementById('nonceDisplay').textContent = currentNonce + 1;
        updateNonceIndicator();
        if (passwordVisible) updatePassword();
    }
}

/**
 * Generate the current password, save the nonce to the vault, copy to clipboard,
 * save a local encrypted backup, and trigger a background Nostr sync.
 *
 * Saves the current nonce under vault.users[user][site] so the same password
 * can be reproduced later. The clipboard is auto-cleared after 30 seconds.
 */
function copyPassword() {
    const site = document.getElementById('genSite').value.trim();
    const user = document.getElementById('genUser').value.trim();

    if (!site || !user) {
        showToast('Enter site and username');
        return;
    }

    // Always save when copying — persist the current nonce
    if (!vault.users[user]) vault.users[user] = {};
    vault.users[user][site] = currentNonce;
    originalNonce = currentNonce;
    updateNonceIndicator();

    const pass = generatePassword(
        vault.privateKey, user, site, currentNonce,
        vault.settings.hashLength || DEFAULT_HASH_LENGTH
    );

    navigator.clipboard.writeText(pass).then(() => {
        showToast('Saved & copied!');
        // Auto-clear clipboard after 30 seconds for security
        if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
        clipboardClearTimer = setTimeout(() => {
            navigator.clipboard.writeText('').catch(() => {});
        }, 30000);
    }).catch(() => {
        showToast('Copy failed');
    });

    // Persist nonce changes to local backup immediately (nonce may have changed)
    saveLocalNonceBackup();

    // Background sync to Nostr
    backupToNostrSilent();
}

/**
 * Copy the password and navigate back to the main site list screen.
 */
function saveAndCopy() {
    copyPassword();
    showScreen('mainScreen');
}

/**
 * Delete a site entry from the vault after user confirmation.
 * Removes the site from the user's entry, cleans up empty user objects,
 * and triggers a background Nostr sync.
 *
 * @param {string} site - Site name to delete.
 * @param {string} user - Username the site is associated with.
 */
function deleteSite(site, user) {
    if (!confirm(`Delete ${site} (${user})?`)) return;

    if (vault.users[user]) {
        delete vault.users[user][site];
        // Clean up empty user objects
        if (Object.keys(vault.users[user]).length === 0) {
            delete vault.users[user];
        }
    }

    showToast('Site deleted');
    renderSiteList();
    backupToNostrSilent();
}

/**
 * Fire-and-forget wrapper for backupToNostr that suppresses UI feedback.
 * Used for background syncs triggered by user actions (copy, delete, import).
 */
function backupToNostrSilent() {
    backupToNostr(true).catch(e => console.error('Silent backup failed:', e));
}

// ============================================
// Local Encryption
// ============================================

/**
 * Unlock the vault from a locally encrypted backup stored in localStorage.
 * Enforces rate limiting: after MAX_UNLOCK_ATTEMPTS failures, locks out for
 * UNLOCK_LOCKOUT_MS milliseconds.
 *
 * Supports both the new 'vaultEncrypted' storage key and the legacy
 * 'encryptedDataStorage' key for backwards compatibility.
 *
 * @returns {Promise<void>}
 */
async function unlockVault() {
    // Rate limiting
    const now = Date.now();
    if (now < unlockLockoutUntil) {
        const secs = Math.ceil((unlockLockoutUntil - now) / 1000);
        showToast(`Too many attempts. Wait ${secs}s`);
        return;
    }

    const password = document.getElementById('unlockPassword').value;
    if (!password) {
        showToast('Enter password');
        return;
    }

    try {
        const key = hash(password);
        // Check both new and legacy storage keys for backwards compatibility
        let stored = JSON.parse(localStorage.getItem('vaultEncrypted') || '{}');
        const legacy = JSON.parse(localStorage.getItem('encryptedDataStorage') || '{}');
        stored = { ...legacy, ...stored };
        const encrypted = stored[key];

        if (!encrypted) {
            unlockAttempts++;
            if (unlockAttempts >= MAX_UNLOCK_ATTEMPTS) {
                unlockLockoutUntil = Date.now() + UNLOCK_LOCKOUT_MS;
                unlockAttempts = 0;
                showToast(`Too many attempts. Locked for 30s`);
            } else {
                showToast(`Wrong password (${MAX_UNLOCK_ATTEMPTS - unlockAttempts} attempts left)`);
            }
            return;
        }

        const decrypted = CryptoJS.AES.decrypt(encrypted, password).toString(CryptoJS.enc.Utf8);
        const data = JSON.parse(decrypted);

        // Handle both new format (users/settings/seedPhrase) and legacy format (privateKey/users)
        if (data.privateKey) {
            // Legacy format — privateKey was stored directly
            vault.privateKey = data.privateKey;
            vault.users = data.users || {};
            vault.settings = data.settings || { hashLength: 16 };
        } else {
            vault = data;
        }

        nostrKeys = await deriveNostrKeys(vault.privateKey);
        unlockAttempts = 0;

        resetInactivityTimer();
        showToast('Vault unlocked!');
        showScreen('mainScreen');
    } catch (e) {
        // Decrypt errors may include stack traces — guard with debugLog
        debugLog('unlockVault error:', e);
        unlockAttempts++;
        if (unlockAttempts >= MAX_UNLOCK_ATTEMPTS) {
            unlockLockoutUntil = Date.now() + UNLOCK_LOCKOUT_MS;
            unlockAttempts = 0;
            showToast(`Too many attempts. Locked for 30s`);
        } else {
            showToast('Invalid password');
        }
    }
}

/**
 * Encrypt and save the vault to localStorage with a user-chosen password.
 * The vault is keyed by SHA-256(password), allowing multiple password slots.
 * After saving, triggers a background Nostr sync.
 */
function saveEncrypted() {
    const pass1 = document.getElementById('encryptPass1').value;
    const pass2 = document.getElementById('encryptPass2').value;

    if (!pass1 || pass1 !== pass2) {
        showToast('Passwords don\'t match');
        return;
    }

    const key = hash(pass1);
    // Include privateKey for backwards compatibility with legacy unlock
    const saveData = {
        privateKey: vault.privateKey,
        seedPhrase: vault.seedPhrase,
        users: vault.users,
        settings: vault.settings
    };
    const encrypted = CryptoJS.AES.encrypt(JSON.stringify(saveData), pass1).toString();

    const stored = JSON.parse(localStorage.getItem('vaultEncrypted') || '{}');
    stored[key] = encrypted;
    localStorage.setItem('vaultEncrypted', JSON.stringify(stored));

    showToast('Vault saved!');
    backupToNostrSilent();
    showScreen('settingsScreen');
}

// ============================================
// Export & Import
// ============================================

/**
 * Download vault data (users + settings) as a JSON file.
 * Does NOT include the private key or seed phrase.
 */
function downloadData() {
    const data = { users: vault.users, settings: vault.settings };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'vault-export.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Downloaded!');
}

/**
 * Open a file picker to import vault data from a JSON file.
 * Merges the imported users with the current vault, preferring higher nonces
 * (more recent password rotations). Triggers a background Nostr sync after import.
 */
function triggerImport() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json,application/json';
    input.onchange = async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        try {
            const text = await file.text();
            const data = JSON.parse(text);
            if (!data.users || typeof data.users !== 'object') {
                showToast('Invalid vault file');
                return;
            }
            const siteCount = Object.values(data.users).reduce((n, u) => n + Object.keys(u).length, 0);
            if (!confirm(`Import ${siteCount} site(s)? This will merge with your current vault.`)) return;
            // Merge users — higher nonce wins (more recent password rotation)
            Object.entries(data.users).forEach(([user, sites]) => {
                if (!vault.users[user]) vault.users[user] = {};
                Object.entries(sites).forEach(([site, nonce]) => {
                    // Only overwrite if imported nonce is higher (newer version)
                    if (vault.users[user][site] === undefined || nonce > vault.users[user][site]) {
                        vault.users[user][site] = nonce;
                    }
                });
            });
            if (data.settings) vault.settings = { ...vault.settings, ...data.settings };
            renderSiteList();
            backupToNostrSilent();
            showToast(`Imported ${siteCount} site(s)!`);
        } catch (err) {
            // JSON parse errors are not sensitive
            console.error('triggerImport: failed to parse file:', err);
            showToast('Failed to import file');
        }
    };
    input.click();
}

// ============================================
// Settings
// ============================================

/**
 * Persist advanced settings (hash length, debug mode) and return to the settings screen.
 * Clamps hashLength to the range [8, 64].
 */
function saveAdvancedSettings() {
    const len = parseInt(document.getElementById('hashLengthSetting').value) || 16;
    vault.settings.hashLength = Math.max(8, Math.min(64, len));
    vault.settings.debugMode = debugMode;
    showToast('Settings saved');
    showScreen('settingsScreen');
}

/**
 * Toggle debug mode on/off from the advanced settings toggle.
 * Syncs the local debugMode variable and vault.settings.debugMode.
 */
function toggleDebugMode() {
    debugMode = document.getElementById('debugModeToggle').checked;
    vault.settings.debugMode = debugMode;
}

/**
 * Encode a Nostr event ID and optional relay hints as a bech32 nevent string.
 * Used for generating njump.me debug links.
 *
 * @param {string}   eventId        - Hex Nostr event ID.
 * @param {string[]} [relays=[]]    - Relay URLs to embed as hints (max 2).
 * @returns {string|null} bech32 nevent string, or null on error.
 */
function encodeNevent(eventId, relays = []) {
    const { nip19 } = window.NostrTools;
    try {
        return nip19.neventEncode({ id: eventId, relays: relays.slice(0, 2) });
    } catch (e) {
        return null;
    }
}

/**
 * Display the vault's seed phrase in the view seed screen.
 * Shows a toast if the seed phrase is not available (e.g. legacy unlock).
 */
function showSeedPhrase() {
    if (!vault.seedPhrase) {
        showToast('Seed phrase not available (unlocked from legacy storage)');
        return;
    }

    const grid = document.getElementById('viewSeedGrid');
    grid.innerHTML = '';

    vault.seedPhrase.split(' ').forEach((word, i) => {
        const div = document.createElement('div');
        div.className = 'seed-word';
        div.innerHTML = `<span>${i + 1}.</span>${word}`;
        grid.appendChild(div);
    });

    showScreen('viewSeedScreen');
}

/**
 * Copy the vault's seed phrase to the clipboard and show a confirmation toast.
 */
function copySeedPhrase() {
    navigator.clipboard.writeText(vault.seedPhrase).then(() => {
        showToast('Seed phrase copied!');
    });
}

// ============================================
// Nostr Key Helpers
// ============================================

/**
 * Derive the Nostr (sk, pk) key pair from the vault's private key.
 * The Nostr secret key is SHA-256(vault.privateKey) as a hex string.
 *
 * @returns {Promise<{sk: string, pk: string}>}
 *   sk: hex Nostr secret key
 *   pk: hex Nostr public key
 */
async function getNostrKeyPair() {
    const { getPublicKey } = window.NostrTools;
    const utf8 = new TextEncoder().encode(vault.privateKey);
    const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
    const sk = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    const pk = getPublicKey(sk);
    return { sk, pk };
}

/**
 * Connect to a Nostr relay with a configurable timeout.
 * Logs connection attempt and outcome via debugLog.
 *
 * @param {string} url                  - WebSocket URL of the relay.
 * @param {number} [timeoutMs=5000]     - Milliseconds before the connection attempt times out.
 * @returns {Promise<object>} Resolved relay object (from nostr-tools relayInit).
 * @throws {string} 'timeout' if the relay does not connect within timeoutMs.
 * @throws {*} Relay error event if the connection fails.
 */
async function connectRelay(url, timeoutMs = 5000) {
    const { relayInit } = window.NostrTools;
    debugLog(`connectRelay: attempting ${url} (timeout ${timeoutMs}ms)`);
    const relay = relayInit(url);
    await new Promise((resolve, reject) => {
        const t = setTimeout(() => {
            debugLog(`connectRelay: timeout — ${url}`);
            reject('timeout');
        }, timeoutMs);
        relay.on('connect', () => {
            clearTimeout(t);
            debugLog(`connectRelay: connected — ${url}`);
            resolve();
        });
        relay.on('error', (err) => {
            clearTimeout(t);
            debugLog(`connectRelay: error — ${url}`, err);
            reject(err);
        });
        relay.connect();
    });
    return relay;
}

/**
 * Subscribe to a relay with given filters and collect all received events.
 * Resolves when EOSE (End of Stored Events) is received or the timeout expires.
 *
 * @param {object}   relay          - Connected relay object from connectRelay().
 * @param {object[]} filters        - Array of Nostr filter objects.
 * @param {number}   [timeoutMs=8000] - Maximum wait time in milliseconds.
 * @returns {Promise<object[]>} Array of Nostr event objects.
 */
function subscribeAndCollect(relay, filters, timeoutMs = 8000) {
    return new Promise(resolve => {
        const events = [];
        const sub = relay.sub(filters);
        const t = setTimeout(() => { sub.unsub(); resolve(events); }, timeoutMs);
        sub.on('event', e => events.push(e));
        sub.on('eose', () => { clearTimeout(t); sub.unsub(); resolve(events); });
    });
}

// ============================================
// Nostr Backup — NIP-44 + kind:30078 (with NIP-04 legacy fallback)
// ============================================
const BACKUP_D_TAG = 'vault-backup';

/**
 * Encrypt and publish vault data to all configured Nostr relays.
 *
 * Uses NIP-44 encryption (nip44.encrypt with the self-to-self shared secret)
 * and publishes a kind:30078 parameterized replaceable event tagged with
 * BACKUP_D_TAG. Relays keep only the latest version of a replaceable event.
 *
 * Falls back gracefully: success on any relay is sufficient.
 * Logs per-relay success/failure via debugLog.
 *
 * @param {boolean} [silent=false] - If true, suppresses toast notifications.
 * @returns {Promise<void>}
 */
async function backupToNostr(silent = false) {
    const { nip44, getEventHash, signEvent, getPublicKey } = window.NostrTools;

    if (!vault.privateKey) {
        if (!silent) showToast('Vault not initialized');
        return;
    }

    try {
        const { sk, pk } = await getNostrKeyPair();
        const sharedSecret = nip44.getSharedSecret(sk, pk);

        const data = JSON.stringify({ users: vault.users, settings: vault.settings });
        const encrypted = nip44.encrypt(sharedSecret, data);

        // kind:30078 = parameterized replaceable event (app-specific data)
        // "d" tag makes it replaceable — only latest version stored per relay
        const event = {
            kind: 30078,
            pubkey: pk,
            created_at: Math.floor(Date.now() / 1000),
            tags: [["d", BACKUP_D_TAG]],
            content: encrypted,
        };
        event.id = getEventHash(event);
        event.sig = await signEvent(event, sk);

        let success = 0;
        let successRelays = [];
        for (const url of RELAYS) {
            try {
                const relay = await connectRelay(url);
                relay.publish(event);
                relay.close();
                success++;
                successRelays.push(url);
                debugLog(`backupToNostr: published to ${url}`);
            } catch (e) {
                // Relay publish failures are not sensitive — log always
                console.error(`backupToNostr: failed on relay [${url}]`, e);
            }
        }

        debugLog(`backupToNostr: succeeded on ${success}/${RELAYS.length} relays`, successRelays);

        if (success > 0) {
            if (!silent) showToast(`Backed up to ${success} relays`);

            if (debugMode) {
                const nevent = encodeNevent(event.id, successRelays);
                if (nevent) {
                    const link = `https://njump.me/${nevent}`;
                    setTimeout(() => {
                        if (confirm(`Debug: View event on njump.me?\n\n${event.id.slice(0, 32)}...`)) {
                            window.open(link, '_blank');
                        }
                    }, 500);
                }
            }
        } else {
            if (!silent) showToast('Backup failed');
        }
    } catch (e) {
        // Outer catch may include key material context — guard with debugLog
        debugLog('backupToNostr: unexpected error:', e);
        if (!silent) showToast('Backup error');
    }
}

/**
 * Decrypt a backup event, auto-detecting NIP-44 (kind:30078) vs NIP-04 (legacy kind:1).
 *
 * @param {object} event - Nostr event object with kind and content.
 * @param {string} sk    - Hex Nostr secret key.
 * @param {string} pk    - Hex Nostr public key.
 * @returns {Promise<string>} Decrypted plaintext JSON string.
 */
async function decryptBackupEvent(event, sk, pk) {
    const { nip44, nip04 } = window.NostrTools;

    if (event.kind === 30078) {
        // NIP-44 encryption (current format)
        const sharedSecret = nip44.getSharedSecret(sk, pk);
        return nip44.decrypt(sharedSecret, event.content);
    } else {
        // Legacy NIP-04 (kind:1 with nostr-pwd-backup tag)
        return await nip04.decrypt(sk, event.pubkey, event.content);
    }
}

/**
 * Restore vault data from the latest Nostr backup event with user feedback.
 * Queries all configured relays for the latest backup (kind:30078 or legacy kind:1),
 * decrypts it, merges into the vault, and saves a local encrypted backup.
 *
 * Logs which relays returned events via debugLog.
 *
 * @returns {Promise<void>}
 */
async function restoreFromNostr() {
    if (!vault.privateKey) {
        showToast('Vault not initialized');
        return;
    }

    try {
        const { sk, pk } = await getNostrKeyPair();

        let latest = null;

        for (const url of RELAYS) {
            try {
                const relay = await connectRelay(url);

                // Query both new format (kind:30078) and legacy (kind:1 with tag)
                const events = await subscribeAndCollect(relay, [
                    { kinds: [30078], authors: [pk], "#d": [BACKUP_D_TAG], limit: 1 },
                    { kinds: [1], authors: [pk], "#t": ["nostr-pwd-backup"], limit: 1 }
                ]);

                relay.close();

                if (events.length > 0) {
                    debugLog(`restoreFromNostr: ${url} returned ${events.length} event(s)`);
                } else {
                    debugLog(`restoreFromNostr: ${url} returned no events`);
                }

                for (const e of events) {
                    if (!latest || e.created_at > latest.created_at) latest = e;
                }
            } catch (e) {
                console.error(`restoreFromNostr: relay error [${url}]`, e);
            }
        }

        if (latest) {
            const decrypted = await decryptBackupEvent(latest, sk, pk);
            const data = JSON.parse(decrypted);
            vault.users = { ...vault.users, ...data.users };
            if (data.settings) vault.settings = { ...vault.settings, ...data.settings };
            // Save the freshly restored data locally
            saveLocalNonceBackup();
            showToast('Restored from Nostr!');
            renderSiteList();
        } else {
            showToast('No backup found');
        }
    } catch (e) {
        // May include decrypted content — guard
        debugLog('restoreFromNostr: error:', e);
        showToast('Restore error');
    }
}

/**
 * Fetch and display backup history from Nostr relays.
 * Shows all backup events (kind:30078 + legacy kind:1) sorted by timestamp.
 * Tapping a history item calls restoreFromId() to restore from that specific event.
 * Logs relay query results via debugLog.
 *
 * @returns {Promise<void>}
 */
async function openNostrHistory() {
    if (!vault.privateKey) {
        showToast('Vault not initialized');
        return;
    }

    const container = document.getElementById('nostrHistoryContainer');
    container.innerHTML = '<p class="text-muted">Loading...</p>';
    container.classList.remove('hidden');

    try {
        const { sk, pk } = await getNostrKeyPair();

        const allEvents = [];

        for (const url of RELAYS) {
            try {
                const relay = await connectRelay(url);

                // Fetch both new and legacy backup events
                const events = await subscribeAndCollect(relay, [
                    { kinds: [30078], authors: [pk], "#d": [BACKUP_D_TAG] },
                    { kinds: [1], authors: [pk], "#t": ["nostr-pwd-backup"] }
                ]);

                relay.close();

                debugLog(`openNostrHistory: ${url} returned ${events.length} event(s)`);
                events.forEach(e => allEvents.push({ ...e, relay: url }));
            } catch (e) {
                console.error(`openNostrHistory: relay error [${url}]`, e);
            }
        }

        // Deduplicate by event id and sort newest-first
        const unique = [...new Map(allEvents.map(e => [e.id, e])).values()]
            .sort((a, b) => b.created_at - a.created_at);

        debugLog(`openNostrHistory: ${unique.length} unique event(s) found`);

        if (unique.length === 0) {
            container.innerHTML = '<p class="text-muted">No backups found</p>';
            return;
        }

        container.innerHTML = `<h3 class="mb-8">${unique.length} backup(s)</h3>` +
            unique.map(e => {
                const kindLabel = e.kind === 30078 ? '🔒 NIP-44' : '⚠️ NIP-04 (legacy)';
                const nevent = encodeNevent(e.id, [e.relay]);
                const debugLink = debugMode && nevent
                    ? `<a class="debug-link" href="https://njump.me/${nevent}" target="_blank" data-debug-link="true">🔗 njump.me/${nevent.slice(0, 20)}...</a>`
                    : '';
                return `
                <div class="site-item" data-restore-id="${e.id}" data-restore-kind="${e.kind}">
                    <div class="site-info">
                        <div class="site-name">${new Date(e.created_at * 1000).toLocaleString()}</div>
                        <div class="site-user">${kindLabel} · ${e.id.slice(0, 16)}...</div>
                        ${debugLink}
                    </div>
                </div>
            `}).join('');

        // Bind event delegation for history items
        container.querySelectorAll('[data-restore-id]').forEach(item => {
            item.addEventListener('click', (e) => {
                // Don't trigger restore when clicking debug links
                if (e.target.closest('[data-debug-link]')) return;
                restoreFromId(item.dataset.restoreId, parseInt(item.dataset.restoreKind));
            });
        });
    } catch (e) {
        // May include key material context — guard
        debugLog('openNostrHistory: error:', e);
        container.innerHTML = '<p class="text-muted">Error loading history</p>';
    }
}

/**
 * Restore the vault from a specific Nostr event by ID.
 * Queries relays until the event is found, decrypts it, and applies it to the vault.
 * After a successful restore, saves a local encrypted backup.
 *
 * @param {string} eventId   - Hex event ID to fetch.
 * @param {number} eventKind - Event kind (30078 for NIP-44, 1 for legacy NIP-04).
 * @returns {Promise<void>}
 */
async function restoreFromId(eventId, eventKind) {
    try {
        const { sk, pk } = await getNostrKeyPair();

        let found = null;

        for (const url of RELAYS) {
            if (found) break;
            try {
                const relay = await connectRelay(url);
                const events = await subscribeAndCollect(relay, [{ ids: [eventId] }], 5000);
                relay.close();
                if (events.length > 0) {
                    debugLog(`restoreFromId: found event ${eventId.slice(0, 16)}... on ${url}`);
                    found = events[0];
                } else {
                    debugLog(`restoreFromId: event not found on ${url}`);
                }
            } catch (e) {
                console.error(`restoreFromId: relay error [${url}]`, e);
            }
        }

        if (found) {
            const decrypted = await decryptBackupEvent(found, sk, pk);
            const data = JSON.parse(decrypted);
            vault.users = data.users || vault.users;
            if (data.settings) vault.settings = { ...vault.settings, ...data.settings };
            // Persist the restored data locally
            saveLocalNonceBackup();
            showToast('Restored!');
            showScreen('mainScreen');
        } else {
            showToast('Backup not found');
        }
    } catch (e) {
        // May include decrypted content — guard
        debugLog('restoreFromId: error:', e);
        showToast('Restore error');
    }
}

// ============================================
// Seed Phrase Autocomplete
// ============================================
let activeSuggestionIndex = -1;
let currentSuggestions = [];

/**
 * Handle input events on the seed phrase textarea.
 * Extracts the current word being typed, queries the BIP39 word list for prefix
 * matches, and displays up to 6 suggestions.
 *
 * @param {InputEvent} event - The input event from the seed phrase textarea.
 */
function onSeedInput(event) {
    const textarea = event.target;
    const value = textarea.value;
    const cursorPos = textarea.selectionStart;

    // Extract the word currently being typed (letters only, before the cursor)
    const beforeCursor = value.slice(0, cursorPos);
    const wordMatch = beforeCursor.match(/[a-z]+$/i);
    const currentWord = wordMatch ? wordMatch[0].toLowerCase() : '';

    // Update word count display
    const wordCount = value.trim().split(/\s+/).filter(w => w.length > 0).length;
    document.getElementById('wordCount').textContent = wordCount;

    const suggestions = document.getElementById('seedSuggestions');

    if (currentWord.length < 1) {
        suggestions.classList.add('hidden');
        currentSuggestions = [];
        return;
    }

    // Find BIP39 words that start with the typed prefix
    currentSuggestions = words
        .filter(w => w.startsWith(currentWord))
        .slice(0, 6);

    if (currentSuggestions.length === 0) {
        suggestions.classList.add('hidden');
        return;
    }

    // Hide suggestions if there's an exact single match (word is complete)
    if (currentSuggestions.length === 1 && currentSuggestions[0] === currentWord) {
        suggestions.classList.add('hidden');
        return;
    }

    activeSuggestionIndex = 0;
    renderSuggestions(currentWord);
    suggestions.classList.remove('hidden');
}

/**
 * Render the autocomplete suggestion list, highlighting the currently typed prefix
 * in bold and marking the active suggestion.
 *
 * @param {string} typed - The current typed prefix to highlight in each suggestion.
 */
function renderSuggestions(typed) {
    const suggestions = document.getElementById('seedSuggestions');
    suggestions.innerHTML = currentSuggestions.map((word, i) => {
        const matchPart = word.slice(0, typed.length);
        const restPart = word.slice(typed.length);
        return `<div class="seed-suggestion ${i === activeSuggestionIndex ? 'active' : ''}" 
                     data-suggestion="${word}">
            <span class="seed-suggestion-match">${matchPart}</span>${restPart}
        </div>`;
    }).join('');

    // Bind click events on suggestions
    suggestions.querySelectorAll('[data-suggestion]').forEach(el => {
        el.addEventListener('click', () => selectSuggestion(el.dataset.suggestion));
    });
}

/**
 * Handle keyboard navigation within the seed phrase autocomplete suggestions.
 * Supports ArrowUp/ArrowDown to move selection, Tab/Enter to confirm, Escape to dismiss.
 *
 * @param {KeyboardEvent} event - The keydown event from the seed phrase textarea.
 */
function onSeedKeydown(event) {
    const suggestions = document.getElementById('seedSuggestions');

    if (suggestions.classList.contains('hidden') || currentSuggestions.length === 0) {
        return;
    }

    if (event.key === 'ArrowDown') {
        event.preventDefault();
        activeSuggestionIndex = (activeSuggestionIndex + 1) % currentSuggestions.length;
        renderSuggestions(getCurrentTypedWord());
    } else if (event.key === 'ArrowUp') {
        event.preventDefault();
        activeSuggestionIndex = activeSuggestionIndex <= 0
            ? currentSuggestions.length - 1
            : activeSuggestionIndex - 1;
        renderSuggestions(getCurrentTypedWord());
    } else if (event.key === 'Tab' || event.key === 'Enter') {
        if (currentSuggestions.length > 0) {
            event.preventDefault();
            selectSuggestion(currentSuggestions[activeSuggestionIndex]);
        }
    } else if (event.key === 'Escape') {
        suggestions.classList.add('hidden');
    }
}

/**
 * Get the word currently being typed at the cursor position in the seed textarea.
 *
 * @returns {string} The current partial word (lowercase), or empty string if none.
 */
function getCurrentTypedWord() {
    const textarea = document.getElementById('restoreSeedInput');
    const cursorPos = textarea.selectionStart;
    const beforeCursor = textarea.value.slice(0, cursorPos);
    const wordMatch = beforeCursor.match(/[a-z]+$/i);
    return wordMatch ? wordMatch[0].toLowerCase() : '';
}

/**
 * Insert a selected suggestion word into the seed textarea, replacing the
 * current partial word and appending a space.
 *
 * @param {string} word - The BIP39 word to insert.
 */
function selectSuggestion(word) {
    const textarea = document.getElementById('restoreSeedInput');
    const cursorPos = textarea.selectionStart;
    const value = textarea.value;

    // Find where the current partial word starts
    const beforeCursor = value.slice(0, cursorPos);
    const wordMatch = beforeCursor.match(/[a-z]+$/i);
    const wordStart = wordMatch ? cursorPos - wordMatch[0].length : cursorPos;

    // Replace current partial word with the selected word + a trailing space
    const newValue = value.slice(0, wordStart) + word + ' ' + value.slice(cursorPos);
    textarea.value = newValue;

    // Place cursor after the inserted word and space
    const newCursorPos = wordStart + word.length + 1;
    textarea.setSelectionRange(newCursorPos, newCursorPos);
    textarea.focus();

    // Hide suggestions and update word count
    document.getElementById('seedSuggestions').classList.add('hidden');
    currentSuggestions = [];

    const wordCount = newValue.trim().split(/\s+/).filter(w => w.length > 0).length;
    document.getElementById('wordCount').textContent = wordCount;
}

// ============================================
// Inactivity Auto-Lock
// ============================================

/**
 * Reset the inactivity auto-lock timer.
 * Clears any existing timer and sets a new one to lock the vault after
 * INACTIVITY_TIMEOUT_MS milliseconds of inactivity. Only active when the vault
 * is unlocked (vault.privateKey is set).
 */
function resetInactivityTimer() {
    if (inactivityTimer) clearTimeout(inactivityTimer);
    // Only set timer if vault is unlocked (privateKey present)
    if (vault.privateKey) {
        inactivityTimer = setTimeout(() => {
            lockVault(true);
        }, INACTIVITY_TIMEOUT_MS);
    }
}

let hiddenAt = null;

/**
 * Attach event listeners to reset the inactivity timer on user interaction
 * and to lock the vault if the tab has been hidden for too long.
 *
 * Visibility-based locking: if the tab is hidden for >= VISIBILITY_LOCK_MS,
 * the vault is locked when the user returns.
 */
function setupInactivityListeners() {
    const events = ['click', 'keydown', 'touchstart', 'scroll', 'mousemove'];
    events.forEach(evt => {
        document.addEventListener(evt, resetInactivityTimer, { passive: true });
    });

    // Lock vault when tab is hidden for too long (e.g. user switches app)
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            hiddenAt = Date.now();
        } else if (hiddenAt && vault.privateKey) {
            const elapsed = Date.now() - hiddenAt;
            hiddenAt = null;
            if (elapsed >= VISIBILITY_LOCK_MS) {
                lockVault(true);
            } else {
                resetInactivityTimer();
            }
        }
    });
}

// ============================================
// Keyboard Shortcuts
// ============================================

/**
 * Attach global keyboard shortcuts active on the password generation screen:
 *   Enter → copyPassword()
 *   Escape → navigate back to main screen
 *
 * Shortcuts are suppressed when focus is inside an input or textarea.
 */
function setupKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        // Only active on generate screen
        const genScreen = document.getElementById('generateScreen');
        if (genScreen.classList.contains('hidden')) return;

        // Don't trigger if typing in an input
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

        // Enter → copy password
        if (e.key === 'Enter') {
            e.preventDefault();
            copyPassword();
        }
        // Escape → back to site list
        if (e.key === 'Escape') {
            e.preventDefault();
            showScreen('mainScreen');
        }
    });
}

// ============================================
// Init
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    setupInactivityListeners();
    setupKeyboardShortcuts();

    // ── Delegated screen navigation ──
    document.addEventListener('click', (e) => {
        const screenEl = e.target.closest('[data-screen]');
        if (screenEl) {
            showScreen(screenEl.dataset.screen);
            return;
        }
        const backEl = e.target.closest('[data-action="back"]');
        if (backEl) {
            goBack();
            return;
        }
        const seedPhraseEl = e.target.closest('[data-action="showSeedPhrase"]');
        if (seedPhraseEl) {
            showSeedPhrase();
            return;
        }
    });

    // ── Delegated site list events ──
    document.getElementById('siteList').addEventListener('click', (e) => {
        const deleteBtn = e.target.closest('.btn-delete[data-delete-site]');
        if (deleteBtn) {
            e.stopPropagation();
            deleteSite(deleteBtn.dataset.deleteSite, deleteBtn.dataset.deleteUser);
            return;
        }
        const siteItem = e.target.closest('.site-item[data-site]');
        if (siteItem) {
            openSite(siteItem.dataset.site, siteItem.dataset.user, parseInt(siteItem.dataset.nonce));
        }
    });

    // ── Individual button bindings ──
    const btnBindings = {
        btnGenerateNewSeed: () => generateNewSeed(),
        btnConfirmSeedBackup: () => confirmSeedBackup(),
        btnVerifySeedBackup: () => verifySeedBackup(),
        btnRestoreFromSeed: () => restoreFromSeed(),
        btnUnlockVault: () => unlockVault(),
        btnLockVault: () => lockVault(),
        btnDecrementNonce: () => decrementNonce(),
        btnIncrementNonce: () => incrementNonce(),
        btnToggleVisibility: () => togglePasswordVisibility(),
        btnCopyPassword: () => copyPassword(),
        btnSaveAndCopy: () => saveAndCopy(),
        btnBackupToNostr: () => backupToNostr(),
        btnRestoreFromNostr: () => restoreFromNostr(),
        btnOpenNostrHistory: () => openNostrHistory(),
        btnSaveEncrypted: () => saveEncrypted(),
        btnDownloadData: () => downloadData(),
        btnTriggerImport: () => triggerImport(),
        btnSaveAdvancedSettings: () => saveAdvancedSettings(),
        btnCopySeedPhrase: () => copySeedPhrase(),
    };

    Object.entries(btnBindings).forEach(([id, handler]) => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('click', handler);
    });

    // ── Input event listeners ──
    const restoreSeedInput = document.getElementById('restoreSeedInput');
    if (restoreSeedInput) {
        restoreSeedInput.addEventListener('input', (e) => onSeedInput(e));
        restoreSeedInput.addEventListener('keydown', (e) => onSeedKeydown(e));
    }

    const unlockPassword = document.getElementById('unlockPassword');
    if (unlockPassword) {
        unlockPassword.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') unlockVault();
        });
    }

    const siteSearch = document.getElementById('siteSearch');
    if (siteSearch) {
        siteSearch.addEventListener('input', () => filterSites());
        siteSearch.addEventListener('keydown', (e) => handleSearchEnter(e));
    }

    const genSite = document.getElementById('genSite');
    if (genSite) {
        genSite.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') document.getElementById('genUser').focus();
        });
    }

    const genUser = document.getElementById('genUser');
    if (genUser) {
        genUser.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') saveAndCopy();
        });
    }

    const encryptPass1 = document.getElementById('encryptPass1');
    if (encryptPass1) {
        encryptPass1.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') document.getElementById('encryptPass2').focus();
        });
    }

    const encryptPass2 = document.getElementById('encryptPass2');
    if (encryptPass2) {
        encryptPass2.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') saveEncrypted();
        });
    }

    const hashLengthSetting = document.getElementById('hashLengthSetting');
    if (hashLengthSetting) {
        hashLengthSetting.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') saveAdvancedSettings();
        });
    }

    const debugModeToggle = document.getElementById('debugModeToggle');
    if (debugModeToggle) {
        debugModeToggle.addEventListener('change', () => toggleDebugMode());
    }

    // ── Service worker registration ──
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('sw.js').catch(() => {});
    }

    // Check if there's saved encrypted data
    const stored = localStorage.getItem('vaultEncrypted');
    const legacy = localStorage.getItem('encryptedDataStorage');
    if ((stored && Object.keys(JSON.parse(stored)).length > 0) ||
        (legacy && Object.keys(JSON.parse(legacy)).length > 0)) {
        // Could highlight unlock option
    }
});
