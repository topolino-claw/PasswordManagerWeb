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
    settings: { hashLength: 16 }
};

let nostrKeys = { nsec: '', npub: '' };
let currentNonce = 0;
let passwordVisible = false;
let navigationStack = ['welcomeScreen'];

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
            <input type="text" class="verify-word" data-index="${i}" placeholder="Enter word ${i + 1}">
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
        showToast('Vault created!');
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
    showToast('Vault restored!');
    showScreen('mainScreen');
}

// ============================================
// Vault Management
// ============================================
async function initializeVault(seedPhrase) {
    vault.seedPhrase = seedPhrase.replace(/\s+/g, ' ').trim().toLowerCase();
    vault.privateKey = await derivePrivateKey(vault.seedPhrase);
    nostrKeys = await deriveNostrKeys(vault.privateKey);
}

function lockVault() {
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
    document.getElementById('nonceDisplay').textContent = currentNonce + 1;
    passwordVisible = false;
    document.getElementById('genPassword').textContent = '••••••••••••';
    document.getElementById('visibilityIcon').textContent = '👁️';
    
    if (site && user) {
        updatePassword();
    }
    
    showScreen('generateScreen');
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
    if (passwordVisible) updatePassword();
}

function decrementNonce() {
    if (currentNonce > 0) {
        currentNonce--;
        document.getElementById('nonceDisplay').textContent = currentNonce + 1;
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
    
    const pass = generatePassword(
        vault.privateKey, user, site, currentNonce,
        vault.settings.hashLength || DEFAULT_HASH_LENGTH
    );
    
    navigator.clipboard.writeText(pass).then(() => {
        showToast('Password copied!');
    }).catch(() => {
        showToast('Copy failed');
    });
}

function saveAndCopy() {
    const site = document.getElementById('genSite').value.trim();
    const user = document.getElementById('genUser').value.trim();
    
    if (!site || !user) {
        showToast('Enter site and username');
        return;
    }
    
    // Save to vault
    if (!vault.users[user]) vault.users[user] = {};
    vault.users[user][site] = currentNonce;
    
    // Copy password
    copyPassword();
    
    // Go back
    showScreen('mainScreen');
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
    showToast('Settings saved');
    showScreen('settingsScreen');
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
// Nostr Backup (preserved & simplified from original)
// ============================================
async function backupToNostr() {
    const { nip04, relayInit, getEventHash, signEvent, getPublicKey } = window.NostrTools;
    
    if (!vault.privateKey) {
        showToast('Vault not initialized');
        return;
    }
    
    try {
        const utf8 = new TextEncoder().encode(vault.privateKey);
        const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
        const sk = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
        const pk = getPublicKey(sk);
        
        const data = JSON.stringify({ users: vault.users, settings: vault.settings });
        const encrypted = await nip04.encrypt(sk, pk, data);
        
        const event = {
            kind: 1,
            pubkey: pk,
            created_at: Math.floor(Date.now() / 1000),
            tags: [["t", "nostr-pwd-backup"]],
            content: encrypted,
        };
        event.id = getEventHash(event);
        event.sig = await signEvent(event, sk);
        
        let success = 0;
        for (const url of RELAYS) {
            try {
                const relay = relayInit(url);
                await new Promise((resolve, reject) => {
                    const t = setTimeout(() => reject('timeout'), 5000);
                    relay.on('connect', () => { clearTimeout(t); resolve(); });
                    relay.on('error', reject);
                    relay.connect();
                });
                relay.publish(event);
                relay.close();
                success++;
            } catch (e) { console.error(url, e); }
        }
        
        showToast(success > 0 ? `Backed up to ${success} relays` : 'Backup failed');
    } catch (e) {
        console.error(e);
        showToast('Backup error');
    }
}

async function restoreFromNostr() {
    const { nip04, relayInit, getPublicKey } = window.NostrTools;
    
    if (!vault.privateKey) {
        showToast('Vault not initialized');
        return;
    }
    
    try {
        const utf8 = new TextEncoder().encode(vault.privateKey);
        const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
        const sk = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
        const pk = getPublicKey(sk);
        
        let latest = null;
        
        for (const url of RELAYS) {
            try {
                const relay = relayInit(url);
                await new Promise((resolve, reject) => {
                    const t = setTimeout(() => reject('timeout'), 5000);
                    relay.on('connect', () => { clearTimeout(t); resolve(); });
                    relay.on('error', reject);
                    relay.connect();
                });
                
                const sub = relay.sub([{ kinds: [1], authors: [pk], "#t": ["nostr-pwd-backup"] }]);
                
                await new Promise(resolve => {
                    const t = setTimeout(() => { sub.unsub(); resolve(); }, 8000);
                    sub.on('event', e => {
                        if (!latest || e.created_at > latest.created_at) latest = e;
                    });
                    sub.on('eose', () => { clearTimeout(t); sub.unsub(); resolve(); });
                });
                
                relay.close();
            } catch (e) { console.error(url, e); }
        }
        
        if (latest) {
            const decrypted = await nip04.decrypt(sk, latest.pubkey, latest.content);
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
    const { relayInit, getPublicKey } = window.NostrTools;
    
    if (!vault.privateKey) {
        showToast('Vault not initialized');
        return;
    }
    
    const container = document.getElementById('nostrHistoryContainer');
    container.innerHTML = '<p class="text-muted">Loading...</p>';
    container.classList.remove('hidden');
    
    try {
        const utf8 = new TextEncoder().encode(vault.privateKey);
        const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
        const sk = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
        const pk = getPublicKey(sk);
        
        const events = [];
        
        for (const url of RELAYS) {
            try {
                const relay = relayInit(url);
                await new Promise((resolve, reject) => {
                    const t = setTimeout(() => reject('timeout'), 5000);
                    relay.on('connect', () => { clearTimeout(t); resolve(); });
                    relay.on('error', reject);
                    relay.connect();
                });
                
                const sub = relay.sub([{ kinds: [1], authors: [pk], "#t": ["nostr-pwd-backup"] }]);
                
                await new Promise(resolve => {
                    const t = setTimeout(() => { sub.unsub(); resolve(); }, 8000);
                    sub.on('event', e => events.push({ ...e, relay: url }));
                    sub.on('eose', () => { clearTimeout(t); sub.unsub(); resolve(); });
                });
                
                relay.close();
            } catch (e) { console.error(url, e); }
        }
        
        // Dedupe by id
        const unique = [...new Map(events.map(e => [e.id, e])).values()]
            .sort((a, b) => b.created_at - a.created_at);
        
        if (unique.length === 0) {
            container.innerHTML = '<p class="text-muted">No backups found</p>';
            return;
        }
        
        container.innerHTML = `<h3 class="mb-8">${unique.length} backup(s)</h3>` + 
            unique.map(e => `
                <div class="site-item" onclick="restoreFromId('${e.id}')">
                    <div class="site-info">
                        <div class="site-name">${new Date(e.created_at * 1000).toLocaleString()}</div>
                        <div class="site-user">${e.id.slice(0, 16)}...</div>
                    </div>
                </div>
            `).join('');
    } catch (e) {
        console.error(e);
        container.innerHTML = '<p class="text-muted">Error loading history</p>';
    }
}

async function restoreFromId(eventId) {
    const { nip04, relayInit, getPublicKey } = window.NostrTools;
    
    try {
        const utf8 = new TextEncoder().encode(vault.privateKey);
        const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
        const sk = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
        
        let found = null;
        
        for (const url of RELAYS) {
            if (found) break;
            try {
                const relay = relayInit(url);
                await new Promise((resolve, reject) => {
                    const t = setTimeout(() => reject('timeout'), 5000);
                    relay.on('connect', () => { clearTimeout(t); resolve(); });
                    relay.on('error', reject);
                    relay.connect();
                });
                
                const sub = relay.sub([{ ids: [eventId] }]);
                
                await new Promise(resolve => {
                    const t = setTimeout(() => { sub.unsub(); resolve(); }, 5000);
                    sub.on('event', e => { found = e; clearTimeout(t); sub.unsub(); resolve(); });
                    sub.on('eose', () => { clearTimeout(t); sub.unsub(); resolve(); });
                });
                
                relay.close();
            } catch (e) { console.error(url, e); }
        }
        
        if (found) {
            const decrypted = await nip04.decrypt(sk, found.pubkey, found.content);
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
// Init
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    // Check if there's saved encrypted data
    const stored = localStorage.getItem('vaultEncrypted');
    if (stored && Object.keys(JSON.parse(stored)).length > 0) {
        // Show unlock option more prominently
    }
});
