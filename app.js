/**
 * Vault v3 - Deterministic Password Manager
 * Clean rewrite with simplified UX
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

const INACTIVITY_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
const DEFAULT_HASH_LENGTH = 16;

const RELAYS = [
    "wss://relay.damus.io",
    "wss://nostr-pub.wellorder.net",
    "wss://relay.snort.social",
    "wss://nos.lol"
];

// ============================================
// Navigation
// ============================================
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
        generateNewSeed();
    } else if (screenId === 'advancedScreen') {
        document.getElementById('hashLengthSetting').value = vault.settings.hashLength || 16;
        debugMode = vault.settings.debugMode || false;
        document.getElementById('debugModeToggle').checked = debugMode;
    }
}

function goBack() {
    navigationStack.pop();
    const prev = navigationStack[navigationStack.length - 1] || 'welcomeScreen';
    showScreen(prev);
}

// ============================================
// Toast
// ============================================
function showToast(message) {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 2000);
}

function showLoading(text) {
    document.getElementById('loadingText').textContent = text;
    document.getElementById('loadingModal').classList.remove('hidden');
}

function hideLoading() {
    document.getElementById('loadingModal').classList.add('hidden');
}

// ============================================
// BIP39 Seed Phrase Functions (preserved from original)
// ============================================
function decimalStringToHex(decStr) {
    if (!/^\d+$/.test(decStr)) throw new Error("Invalid decimal string");
    return BigInt(decStr).toString(16);
}

function wordsToIndices(inputWords) {
    const wordsArray = inputWords.trim().split(/\s+/);
    return wordsArray.map(word => {
        const index = words.indexOf(word.toLowerCase());
        if (index === -1) throw new Error(`Word "${word}" not found`);
        return index.toString().padStart(4, '0');
    }).join('');
}

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

async function generateMnemonic() {
    const entropy = new Uint8Array(16);
    crypto.getRandomValues(entropy);
    
    const entropyBinary = Array.from(entropy).map(b => b.toString(2).padStart(8, '0')).join('');
    const hashBuffer = await crypto.subtle.digest('SHA-256', entropy);
    const hashBinary = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(2).padStart(8, '0')).join('');
    const checksumBits = entropyBinary.length / 32;
    
    const fullBinary = entropyBinary + hashBinary.slice(0, checksumBits);
    const mnemonic = [];
    for (let i = 0; i < fullBinary.length; i += 11) {
        mnemonic.push(words[parseInt(fullBinary.slice(i, i + 11), 2)]);
    }
    
    return mnemonic.join(' ');
}

// ============================================
// Key Derivation (preserved from original)
// ============================================
async function derivePrivateKey(seedPhrase) {
    const normalized = seedPhrase.replace(/\s+/g, ' ').trim().toLowerCase();
    const indices = wordsToIndices(normalized);
    return decimalStringToHex(indices);
}

async function deriveNostrKeys(privateKey) {
    const { nip19, getPublicKey } = window.NostrTools;
    const utf8 = new TextEncoder().encode(privateKey);
    const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
    const nostrHex = Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    
    const nsec = nip19.nsecEncode(nostrHex);
    const npub = getPublicKey(nostrHex);
    return { nsec, npub, hex: nostrHex };
}

// ============================================
// Password Generation (preserved from original)
// ============================================
function hash(text) {
    return CryptoJS.SHA256(text).toString();
}

function generatePassword(privateKey, user, site, nonce, hashLength = 16) {
    const concat = `${privateKey}/${user}/${site}/${nonce}`;
    const entropy = hash(concat).substring(0, hashLength);
    return 'PASS' + entropy + '249+';
}

// ============================================
// Seed Phrase UI
// ============================================
async function generateNewSeed() {
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
            <input type="text" class="verify-word" data-index="${i}" placeholder="Enter word ${i + 1}" onkeydown="if(event.key==='Enter')verifySeedBackup()">
        `;
        container.appendChild(div);
    });
    
    showScreen('verifySeedScreen');
}

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
async function initializeVault(seedPhrase) {
    vault.seedPhrase = seedPhrase.replace(/\s+/g, ' ').trim().toLowerCase();
    vault.privateKey = await derivePrivateKey(vault.seedPhrase);
    nostrKeys = await deriveNostrKeys(vault.privateKey);
    resetInactivityTimer();
}

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

async function silentRestoreFromNostr() {
    if (!vault.privateKey) return false;
    
    const { sk, pk } = await getNostrKeyPair();
    
    let latest = null;
    
    for (const url of RELAYS) {
        try {
            const relay = await connectRelay(url);
            
            // Query both new (kind:30078) and legacy (kind:1) formats
            const events = await subscribeAndCollect(relay, [
                { kinds: [30078], authors: [pk], "#d": [BACKUP_D_TAG], limit: 1 },
                { kinds: [1], authors: [pk], "#t": ["nostr-pwd-backup"], limit: 1 }
            ], 6000);
            
            relay.close();
            
            for (const e of events) {
                if (!latest || e.created_at > latest.created_at) latest = e;
            }
        } catch (e) { console.error(url, e); }
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
            return true;
        } catch (e) {
            console.error('Decrypt failed:', e);
            return false;
        }
    }
    
    return false;
}

function lockVault() {
    if (inactivityTimer) clearTimeout(inactivityTimer);
    inactivityTimer = null;
    vault = { privateKey: '', seedPhrase: '', users: {}, settings: { hashLength: 16 } };
    nostrKeys = { nsec: '', npub: '' };
    navigationStack = ['welcomeScreen'];
    showScreen('welcomeScreen');
    showToast('Vault locked');
}

// ============================================
// Site List & Search
// ============================================
function renderSiteList() {
    const container = document.getElementById('siteList');
    const emptyState = document.getElementById('emptyState');
    const searchTerm = document.getElementById('siteSearch').value.toLowerCase();
    
    // Collect all sites across users
    const sites = [];
    Object.entries(vault.users || {}).forEach(([user, userSites]) => {
        Object.entries(userSites).forEach(([site, nonce]) => {
            sites.push({ user, site, nonce });
        });
    });
    
    // Filter
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
        <div class="site-item" onclick="openSite('${escapeHtml(s.site)}', '${escapeHtml(s.user)}', ${s.nonce})">
            <div class="site-icon">${s.site.charAt(0)}</div>
            <div class="site-info">
                <div class="site-name">${escapeHtml(s.site)}</div>
                <div class="site-user">${escapeHtml(s.user)}</div>
            </div>
        </div>
    `).join('');
}

function filterSites() {
    renderSiteList();
}

function handleSearchEnter(event) {
    if (event.key === 'Enter') {
        const term = document.getElementById('siteSearch').value.trim();
        if (term) {
            openSite(term, '', 0);
        }
    }
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ============================================
// Password Generation Screen
// ============================================
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
    
    if (site && user) {
        updatePassword();
    }
    
    showScreen('generateScreen');
}

function updateNonceIndicator() {
    const nonceControl = document.querySelector('.nonce-control');
    if (currentNonce !== originalNonce) {
        nonceControl.classList.add('nonce-changed');
    } else {
        nonceControl.classList.remove('nonce-changed');
    }
}

function updatePassword() {
    const site = document.getElementById('genSite').value.trim();
    const user = document.getElementById('genUser').value.trim();
    
    if (!site || !user || !vault.privateKey) {
        document.getElementById('genPassword').textContent = '••••••••••••';
        return;
    }
    
    const pass = generatePassword(
        vault.privateKey, user, site, currentNonce, 
        vault.settings.hashLength || DEFAULT_HASH_LENGTH
    );
    
    if (passwordVisible) {
        document.getElementById('genPassword').textContent = pass;
    }
}

function togglePasswordVisibility() {
    passwordVisible = !passwordVisible;
    document.getElementById('visibilityIcon').textContent = passwordVisible ? '🙈' : '👁️';
    
    if (passwordVisible) {
        updatePassword();
    } else {
        document.getElementById('genPassword').textContent = '••••••••••••';
    }
}

function incrementNonce() {
    currentNonce++;
    document.getElementById('nonceDisplay').textContent = currentNonce + 1;
    updateNonceIndicator();
    if (passwordVisible) updatePassword();
}

function decrementNonce() {
    if (currentNonce > 0) {
        currentNonce--;
        document.getElementById('nonceDisplay').textContent = currentNonce + 1;
        updateNonceIndicator();
        if (passwordVisible) updatePassword();
    }
}

function copyPassword() {
    const site = document.getElementById('genSite').value.trim();
    const user = document.getElementById('genUser').value.trim();
    
    if (!site || !user) {
        showToast('Enter site and username');
        return;
    }
    
    // Always save when copying
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
    }).catch(() => {
        showToast('Copy failed');
    });
    
    // Background sync to Nostr
    backupToNostrSilent();
}

function saveAndCopy() {
    copyPassword();
    showScreen('mainScreen');
}

function backupToNostrSilent() {
    backupToNostr(true).catch(e => console.error('Silent backup failed:', e));
}

// ============================================
// Local Encryption
// ============================================
async function unlockVault() {
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
            showToast('No vault found for this password');
            return;
        }
        
        const decrypted = CryptoJS.AES.decrypt(encrypted, password).toString(CryptoJS.enc.Utf8);
        const data = JSON.parse(decrypted);
        
        // Handle both new format (users/settings/seedPhrase) and legacy format (privateKey/users)
        if (data.privateKey) {
            // Legacy format - privateKey was stored directly
            vault.privateKey = data.privateKey;
            vault.users = data.users || {};
            vault.settings = data.settings || { hashLength: 16 };
        } else {
            vault = data;
        }
        
        nostrKeys = await deriveNostrKeys(vault.privateKey);
        
        resetInactivityTimer();
        showToast('Vault unlocked!');
        showScreen('mainScreen');
    } catch (e) {
        console.error(e);
        showToast('Invalid password');
    }
}

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
// Export
// ============================================
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

// ============================================
// Settings
// ============================================
function saveAdvancedSettings() {
    const len = parseInt(document.getElementById('hashLengthSetting').value) || 16;
    vault.settings.hashLength = Math.max(8, Math.min(64, len));
    vault.settings.debugMode = debugMode;
    showToast('Settings saved');
    showScreen('settingsScreen');
}

function toggleDebugMode() {
    debugMode = document.getElementById('debugModeToggle').checked;
    vault.settings.debugMode = debugMode;
}

function encodeNevent(eventId, relays = []) {
    const { nip19 } = window.NostrTools;
    try {
        return nip19.neventEncode({ id: eventId, relays: relays.slice(0, 2) });
    } catch (e) {
        return null;
    }
}

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

function copySeedPhrase() {
    navigator.clipboard.writeText(vault.seedPhrase).then(() => {
        showToast('Seed phrase copied!');
    });
}

// ============================================
// Nostr Key Helpers
// ============================================
async function getNostrKeyPair() {
    const { getPublicKey } = window.NostrTools;
    const utf8 = new TextEncoder().encode(vault.privateKey);
    const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
    const sk = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    const pk = getPublicKey(sk);
    return { sk, pk };
}

async function connectRelay(url, timeoutMs = 5000) {
    const { relayInit } = window.NostrTools;
    const relay = relayInit(url);
    await new Promise((resolve, reject) => {
        const t = setTimeout(() => reject('timeout'), timeoutMs);
        relay.on('connect', () => { clearTimeout(t); resolve(); });
        relay.on('error', reject);
        relay.connect();
    });
    return relay;
}

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
            } catch (e) { console.error(url, e); }
        }
        
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
        console.error(e);
        if (!silent) showToast('Backup error');
    }
}

/**
 * Decrypt a backup event, auto-detecting NIP-44 (kind:30078) vs NIP-04 (legacy kind:1).
 */
async function decryptBackupEvent(event, sk, pk) {
    const { nip44, nip04 } = window.NostrTools;
    
    if (event.kind === 30078) {
        // NIP-44 encryption
        const sharedSecret = nip44.getSharedSecret(sk, pk);
        return nip44.decrypt(sharedSecret, event.content);
    } else {
        // Legacy NIP-04 (kind:1 with nostr-pwd-backup tag)
        return await nip04.decrypt(sk, event.pubkey, event.content);
    }
}

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
                
                for (const e of events) {
                    if (!latest || e.created_at > latest.created_at) latest = e;
                }
            } catch (e) { console.error(url, e); }
        }
        
        if (latest) {
            const decrypted = await decryptBackupEvent(latest, sk, pk);
            const data = JSON.parse(decrypted);
            vault.users = { ...vault.users, ...data.users };
            if (data.settings) vault.settings = { ...vault.settings, ...data.settings };
            showToast('Restored from Nostr!');
            renderSiteList();
        } else {
            showToast('No backup found');
        }
    } catch (e) {
        console.error(e);
        showToast('Restore error');
    }
}

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
                
                events.forEach(e => allEvents.push({ ...e, relay: url }));
            } catch (e) { console.error(url, e); }
        }
        
        // Dedupe by id
        const unique = [...new Map(allEvents.map(e => [e.id, e])).values()]
            .sort((a, b) => b.created_at - a.created_at);
        
        if (unique.length === 0) {
            container.innerHTML = '<p class="text-muted">No backups found</p>';
            return;
        }
        
        container.innerHTML = `<h3 class="mb-8">${unique.length} backup(s)</h3>` + 
            unique.map(e => {
                const kindLabel = e.kind === 30078 ? '🔒 NIP-44' : '⚠️ NIP-04 (legacy)';
                const nevent = encodeNevent(e.id, [e.relay]);
                const debugLink = debugMode && nevent 
                    ? `<a class="debug-link" href="https://njump.me/${nevent}" target="_blank" onclick="event.stopPropagation()">🔗 njump.me/${nevent.slice(0, 20)}...</a>` 
                    : '';
                return `
                <div class="site-item" onclick="restoreFromId('${e.id}', ${e.kind})">
                    <div class="site-info">
                        <div class="site-name">${new Date(e.created_at * 1000).toLocaleString()}</div>
                        <div class="site-user">${kindLabel} · ${e.id.slice(0, 16)}...</div>
                        ${debugLink}
                    </div>
                </div>
            `}).join('');
    } catch (e) {
        console.error(e);
        container.innerHTML = '<p class="text-muted">Error loading history</p>';
    }
}

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
                if (events.length > 0) found = events[0];
            } catch (e) { console.error(url, e); }
        }
        
        if (found) {
            const decrypted = await decryptBackupEvent(found, sk, pk);
            const data = JSON.parse(decrypted);
            vault.users = data.users || vault.users;
            if (data.settings) vault.settings = { ...vault.settings, ...data.settings };
            showToast('Restored!');
            showScreen('mainScreen');
        } else {
            showToast('Backup not found');
        }
    } catch (e) {
        console.error(e);
        showToast('Restore error');
    }
}

// ============================================
// Seed Phrase Autocomplete
// ============================================
let activeSuggestionIndex = -1;
let currentSuggestions = [];

function onSeedInput(event) {
    const textarea = event.target;
    const value = textarea.value;
    const cursorPos = textarea.selectionStart;
    
    // Find current word being typed
    const beforeCursor = value.slice(0, cursorPos);
    const wordMatch = beforeCursor.match(/[a-z]+$/i);
    const currentWord = wordMatch ? wordMatch[0].toLowerCase() : '';
    
    // Update word count
    const wordCount = value.trim().split(/\s+/).filter(w => w.length > 0).length;
    document.getElementById('wordCount').textContent = wordCount;
    
    // Show suggestions
    const suggestions = document.getElementById('seedSuggestions');
    
    if (currentWord.length < 1) {
        suggestions.classList.add('hidden');
        currentSuggestions = [];
        return;
    }
    
    // Filter BIP39 words
    currentSuggestions = words
        .filter(w => w.startsWith(currentWord))
        .slice(0, 6);
    
    if (currentSuggestions.length === 0) {
        suggestions.classList.add('hidden');
        return;
    }
    
    // If exact match and only one suggestion, hide
    if (currentSuggestions.length === 1 && currentSuggestions[0] === currentWord) {
        suggestions.classList.add('hidden');
        return;
    }
    
    activeSuggestionIndex = 0;
    renderSuggestions(currentWord);
    suggestions.classList.remove('hidden');
}

function renderSuggestions(typed) {
    const suggestions = document.getElementById('seedSuggestions');
    suggestions.innerHTML = currentSuggestions.map((word, i) => {
        const matchPart = word.slice(0, typed.length);
        const restPart = word.slice(typed.length);
        return `<div class="seed-suggestion ${i === activeSuggestionIndex ? 'active' : ''}" 
                     onclick="selectSuggestion('${word}')">
            <span class="seed-suggestion-match">${matchPart}</span>${restPart}
        </div>`;
    }).join('');
}

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

function getCurrentTypedWord() {
    const textarea = document.getElementById('restoreSeedInput');
    const cursorPos = textarea.selectionStart;
    const beforeCursor = textarea.value.slice(0, cursorPos);
    const wordMatch = beforeCursor.match(/[a-z]+$/i);
    return wordMatch ? wordMatch[0].toLowerCase() : '';
}

function selectSuggestion(word) {
    const textarea = document.getElementById('restoreSeedInput');
    const cursorPos = textarea.selectionStart;
    const value = textarea.value;
    
    // Find where current word starts
    const beforeCursor = value.slice(0, cursorPos);
    const wordMatch = beforeCursor.match(/[a-z]+$/i);
    const wordStart = wordMatch ? cursorPos - wordMatch[0].length : cursorPos;
    
    // Replace current word with selected word + space
    const newValue = value.slice(0, wordStart) + word + ' ' + value.slice(cursorPos);
    textarea.value = newValue;
    
    // Move cursor after the inserted word
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
function resetInactivityTimer() {
    if (inactivityTimer) clearTimeout(inactivityTimer);
    // Only set timer if vault is unlocked (privateKey present)
    if (vault.privateKey) {
        inactivityTimer = setTimeout(() => {
            lockVault();
            location.reload();
        }, INACTIVITY_TIMEOUT_MS);
    }
}

function setupInactivityListeners() {
    const events = ['click', 'keydown', 'touchstart', 'scroll', 'mousemove'];
    events.forEach(evt => {
        document.addEventListener(evt, resetInactivityTimer, { passive: true });
    });
}

// ============================================
// Init
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    setupInactivityListeners();

    // Check if there's saved encrypted data
    const stored = localStorage.getItem('vaultEncrypted');
    const legacy = localStorage.getItem('encryptedDataStorage');
    if ((stored && Object.keys(JSON.parse(stored)).length > 0) ||
        (legacy && Object.keys(JSON.parse(legacy)).length > 0)) {
        // Could highlight unlock option
    }
});
