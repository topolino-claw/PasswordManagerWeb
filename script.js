// MAIN.JS
var seedPhraseField = document.getElementById("seedPhraseField");
var privateKeyField = document.getElementById("privateKeyField");
var userOrMailField = document.getElementById("userOrMailField");
var siteField = document.getElementById("siteField");
var passwordField = document.getElementById("passwordField");
var nonceField = document.getElementById("nonceField");
var newSeedPhraseField = document.getElementById("newSeedPhraseField");
var localStoredData = {}
var localStoredStatus = ""
// Object to store derived nostr keys
var nostrKeys = { nsec: "", npub: "" };
// Navigation history stack
const navigationHistory = ["welcomeScreen"];
let currentScreenId = "welcomeScreen";

// Default settings
const DEFAULT_HASH_LENGTH = 16;
var settings = {
    hashLength: DEFAULT_HASH_LENGTH
};

// Update nonce UI from stored data when user or site changes
userOrMailField.addEventListener("input", updateNonceFromLocalStorage);
siteField.addEventListener("input", updateNonceFromLocalStorage);

/**
 * Toggle visibility of the private key input field.
 * @returns {void}
 */
function togglePrivateKeyVisibility() {
    const btn = document.getElementById("togglePrivateKeyBtn");
    if (privateKeyField.type === "password") {
        privateKeyField.type = "text";
        btn.textContent = "🙈";
    } else {
        privateKeyField.type = "password";
        btn.textContent = "👁️";
    }
}

/**
 * Display a given screen and manage navigation history.
 * @param {string} screenId - ID of the screen element to show.
 * @param {boolean} [isBackNavigation=false] - Indicates if navigation is backward.
 * @returns {void}
 */
function showScreen(screenId, isBackNavigation = false) {
    // Hide all screens
    document.querySelectorAll('.screen').forEach(screen => {
        screen.classList.add('hidden');
    });

    // Show the target screen
    const targetScreen = document.getElementById(screenId);
    if (targetScreen) {
        targetScreen.classList.remove("hidden");

        // Only update history if this is not a back navigation
        if (!isBackNavigation && currentScreenId !== screenId) {
            navigationHistory.push(currentScreenId);
            currentScreenId = screenId;
        } else if (isBackNavigation) {
            // Just update current screen ID without modifying history
            currentScreenId = screenId;
        }
    } else {
        alert("Screen Change Failed");
    }

    // Initialize verification screen if needed
    if (screenId === "verifySeedBackUpScreen") {
        setupVerificationScreen();
        // Clear any previous verification message
        document.getElementById("verificationResult").textContent = "";
    }

    console.log("Navigation History:", navigationHistory);
}

/**
 * Navigate to the previous screen using the navigation history stack.
 * @param {string} currentScreen - ID of the current screen.
 * @returns {void}
 */
function navigateBack(currentScreen) {
    // Don't proceed if we're already at the welcome screen or history is empty
    if (navigationHistory.length <= 1) {
        showScreen("welcomeScreen", true);
        navigationHistory.length = 0;
        navigationHistory.push("welcomeScreen");
        return;
    }

    // Get the previous screen
    const previousScreen = navigationHistory.pop();

    // Show the previous screen with flag to indicate this is a back navigation
    showScreen(previousScreen, true);
}

/**
 * Convert a decimal string to its hexadecimal representation.
 * @param {string} DecimalString - Decimal string to convert.
 * @returns {string} Hexadecimal representation.
 */
function decimalStringToHex(DecimalString) {
    // Check if the input is a valid number
    if (!/^\d+$/.test(DecimalString)) {
        throw new Error("Input must be a valid decimal string.");
    }
    const decimalNumber = BigInt(DecimalString); // Convert string to BigInt
    const hexadecimal = decimalNumber.toString(16); // Convert to hexadecimal
    return hexadecimal;
}

/**
 * Convert mnemonic words to their corresponding padded indices.
 * @param {string} inputWords - Space-separated list of mnemonic words.
 * @returns {string} Concatenated padded indices.
 */
function wordsToIndices(inputWords) {
    // Ensure inputWords is a string
    if (typeof inputWords !== "string") {
        throw new TypeError("inputWords must be a string");
    }

    // Split the string into an array of words
    const wordsArray = inputWords.split(" ");

    // Map each word to its index and pad the result, then join into a single string
    return wordsArray.map(word => {
        const index = words.indexOf(word);
        if (index === -1) {
            alert(`Word "${word}" not found in the list.`);
            throw new Error(`Word "${word}" not found in the list.`);


        }
        // Convert the index to a string with leading zeros
        return index.toString().padStart(4, '0');
    }).join('');
}

/**
 * Verify a BIP-39 seed phrase.
 * @param {string} seedPhrase - Seed phrase to validate.
 * @param {string[]} wordlist - BIP-39 wordlist for validation.
 * @returns {Promise<boolean>} Resolves to true if valid, otherwise false.
 */
async function verifyBip39SeedPhrase(seedPhrase, wordlist) {
        // Normalize all whitespace characters (including non-breaking spaces, tabs, etc.) to standard spaces
    const normalizedSeedPhrase = seedPhrase.replace(/\s+/g, ' ').trim();

    // Split into words using standard spaces
    const words = normalizedSeedPhrase.split(' ');
    const wordCount = words.length;

    // Log the words for debugging
    console.log('Words:', words);

    // Validate word count (12, 15, 18, 21, 24 are the only valid lengths)
    if (![12, 15, 18, 21, 24].includes(wordCount)) {
        console.error(`Invalid seed phrase length: ${wordCount} words. Valid lengths are 12, 15, 18, 21, or 24 words.`);
        return false;
    }

    // Validate that all words exist in the wordlist
    const invalidWords = words.filter(word => !wordlist.includes(word));
    if (invalidWords.length > 0) {
        console.error(`Invalid words found in seed phrase: ${invalidWords.join(', ')}`);
        return false;
    }

    // Calculate total bits, entropy bits, and checksum bits
    const totalBits = wordCount * 11; // Each word represents 11 bits
    const checksumBits = totalBits % 32;
    const entropyBits = totalBits - checksumBits;

    // Convert words to binary representation
    const binaryString = words
        .map(word => wordlist.indexOf(word).toString(2).padStart(11, '0'))
        .join('');

    // Split binary string into entropy and checksum
    const entropy = binaryString.slice(0, entropyBits);
    const checksum = binaryString.slice(entropyBits);

    // Convert entropy binary string to a Uint8Array
    const entropyBytes = new Uint8Array(entropy.length / 8);
    for (let i = 0; i < entropy.length; i += 8) {
        entropyBytes[i / 8] = parseInt(entropy.slice(i, i + 8), 2);
    }

    // Calculate the SHA-256 hash of the entropy
    const hashBuffer = await crypto.subtle.digest('SHA-256', entropyBytes);
    const hashArray = new Uint8Array(hashBuffer);

    // Convert hash to binary string
    const hashBinary = Array.from(hashArray)
        .map(byte => byte.toString(2).padStart(8, '0'))
        .join('');

    // Compare the calculated checksum with the provided checksum
    if (checksum !== hashBinary.slice(0, checksumBits)) {
        console.error('Invalid checksum. The seed phrase may be incorrect.');
        return false;
    }

    // If all checks pass, the seed phrase is valid
    console.log('Seed phrase is valid.');
    return true;
}
/**
 * Verify the entered seed phrase and derive Nostr keys.
 * @async
 * @returns {Promise<void>} Resolves when navigation completes.
 */
async function verifySeedAndMoveNext() {
    try {
        const { nip19, getPublicKey } = window.NostrTools;

        const isValid = await verifyBip39SeedPhrase(seedPhraseField.value, words);
        if (!isValid) {
            alert("Seed phrase is not valid");
            return;
        }

        // 1. Convert seed phrase to a long decimal string then hex
        const longHex = decimalStringToHex(wordsToIndices(seedPhraseField.value));
        privateKeyField.value = longHex;

        // 2. Hash the hex string to derive nostr private key
        const utf8 = new TextEncoder().encode(longHex);
        const hashBuffer = await crypto.subtle.digest("SHA-256", utf8);
        const nostrHex = Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0')).join('');

        // 3. Encode keys using Nostr tools
        const nsec = nip19.nsecEncode(nostrHex);
        const npub = getPublicKey(nostrHex);

        // 4. Save for global use
        nostrKeys = { nsec, npub };

        // 5. Continue
        showScreen('managementScreen');

    } catch (error) {
        console.error("Error verifying seed phrase:", error);
        alert("An error occurred while verifying the seed phrase");
    }
}


/**
 * Generate a SHA-256 hash for a given string.
 * @param {string} text - Text to hash.
 * @returns {string} Hex-encoded hash.
 */
function hash(text) {
    return CryptoJS.SHA256(text).toString();

}

/**
 * Derive and display a deterministic password based on user, site, and nonce.
 * @async
 * @returns {Promise<void>} Resolves after password is shown and nonce stored.
 */
async function showPassword() {
    if (!localStoredData["users"]) {
        localStoredData["users"] = {};
    }
    if (!localStoredData["users"][userOrMailField.value]) {
        localStoredData["users"][userOrMailField.value] = {};
    }
    // Check if the site input is empty
    if (!siteField.value) {
        alert('The site input is empty');
        return;
    }
    let nonces = localStoredData["users"][userOrMailField.value];
    const storedNonce = nonces[siteField.value];
    const nonceValue = parseInt(nonceField.value, 10) || 0;
    if (storedNonce !== undefined) {
        console.log(`Loaded nonce for site: ${siteField.value} = ${storedNonce}`);
    } else {
        console.log(`Initialized nonce for site: ${siteField.value} with ui value ${nonceValue}`);
    }

    console.log(localStoredData);

    /*
    prepare all the verification processes to ensure proper data input
    */
    const concatenado = privateKeyField.value + "/" + userOrMailField.value + "/" + siteField.value + "/" + nonceValue;
    // Derive password entropy by hashing key, user, site, and nonce together
    const hashLen = settings.hashLength || DEFAULT_HASH_LENGTH;
    const entropiaContraseña = hash(concatenado).substring(0, hashLen);
    passwordField.value = 'PASS' + entropiaContraseña + '249+';
    // Persist the nonce used to generate the password for reproducibility
    localStoredData["users"][userOrMailField.value][siteField.value] = nonceValue;
}

/**
 * Generate a valid BIP-39 mnemonic and corresponding private key.
 * @returns {void}
 */
function generateValidMnemonic() {
    if (words.length !== 2048) {
        throw new Error("The wordlist must contain exactly 2048 words.");
    }

    // Step 1: Generate cryptographically secure random entropy
    /**
     * Generate secure random bytes for entropy.
     * @param {number} [bytes=16] - Number of bytes to generate.
     * @returns {Uint8Array} Random entropy bytes.
     */
    function generateEntropy(bytes = 16) {
        if (window.crypto && window.crypto.getRandomValues) {
            const entropy = new Uint8Array(bytes);
            window.crypto.getRandomValues(entropy);
            return entropy;
        } else {
            throw new Error("Secure random generation not supported in this browser.");
        }
    }

    // Step 2: Convert entropy to binary string
    /**
     * Convert entropy bytes to a binary string.
     * @param {Uint8Array} entropy - Entropy bytes.
     * @returns {string} Binary representation.
     */
    function entropyToBinary(entropy) {
        return Array.from(entropy)
            .map(byte => byte.toString(2).padStart(8, "0"))
            .join("");
    }

    // Step 3: Generate checksum (Fixed to handle async digest)
    /**
     * Generate checksum bits for the given entropy.
     * @async
     * @param {Uint8Array} entropy - Entropy bytes.
     * @returns {Promise<string>} Binary checksum string.
     */
    async function generateChecksum(entropy) {
        const hashBuffer = await window.crypto.subtle.digest("SHA-256", entropy);
        const hashArray = new Uint8Array(hashBuffer);
        const hashBinary = Array.from(hashArray)
            .map(byte => byte.toString(2).padStart(8, "0"))
            .join("");
        const checksumBits = (entropy.length * 8) / 32; // Entropy length in bits / 32
        return hashBinary.substring(0, checksumBits);
    }

    // Step 4: Convert binary to mnemonic words
    /**
     * Convert a binary string into mnemonic words using the wordlist.
     * @param {string} binary - Binary string of entropy + checksum.
     * @param {string[]} wordlist - BIP-39 wordlist.
     * @returns {string} Space-separated mnemonic words.
     */
    function binaryToMnemonic(binary, wordlist) {
        const words = [];
        for (let i = 0; i < binary.length; i += 11) {
            const index = parseInt(binary.slice(i, i + 11), 2);
            words.push(wordlist[index]);
        }
        return words.join(" ");
    }

    // Generate the mnemonic
    return (async () => {
        const entropy = generateEntropy();
        const entropyBinary = entropyToBinary(entropy);
        const checksum = await generateChecksum(entropy); // Await the async checksum
        const mnemonicBinary = entropyBinary + checksum;
        var mnemonic = binaryToMnemonic(mnemonicBinary, words)
        newSeedPhraseField.value = mnemonic
        privateKeyField.value = decimalStringToHex(wordsToIndices(mnemonic));
        return;
    })();
    // Example usage generateValidMnemonic().then(mnemonic => console.log("Generated Mnemonic:", mnemonic)).catch(console.error);

}

/**
 * Update the nonce field using stored data for the current user and site.
 * @returns {void}
 */
function updateNonceFromLocalStorage() {
    const userOrMail = userOrMailField.value;
    const site = siteField.value;

    if (!userOrMail || !site) {
        nonceField.value = 0;
        return;
    }

    const nonce = localStoredData?.users?.[userOrMail]?.[site];
    // Populate field with stored nonce or default to 0 if none exists
    nonceField.value = (nonce !== undefined) ? nonce : 0;
}

/**
 * Increment and display the nonce for the current user-site pair.
 * @returns {void}
 */
function incrementSiteNonce() {
    const userOrMail = userOrMailField.value;
    const site = siteField.value;
    if (!userOrMail || !site){
        alert("there is no site or user value")
        return
    }
    let nonce = parseInt(nonceField.value, 10) || 0;
    nonce++;
    // Update UI with new nonce value
    nonceField.value = nonce;
}

/**
 * Decrement the nonce for the current user-site pair if greater than zero.
 * @returns {void}
 */
function decrementSiteNonce() {
    const userOrMail = userOrMailField.value;
    const site = siteField.value;
    if (!userOrMail || !site) {
        alert("there is no site or user value")
        return
    }
    let nonce = parseInt(nonceField.value, 10) || 0;
    if (nonce > 0) {
        nonce--;
        // Update UI after decrementing nonce
        nonceField.value = nonce;
    }
}

/**
 * Generate a list of unique random indices.
 * @param {number} max - Upper bound (exclusive) for index generation.
 * @param {number} count - Number of unique indices to return.
 * @returns {number[]} Array of unique random indices.
 */
function getRandomIndices(max, count) {
    const indices = new Set();
    while (indices.size < count) {
        indices.add(Math.floor(Math.random() * max));
    }
    return Array.from(indices);
}

/**
 * Prepare the seed phrase verification screen with random prompts.
 * @returns {void}
 */
function setupVerificationScreen() {
    const wordPrompts = document.getElementById("wordPrompts");
    wordPrompts.innerHTML = "";

    const newSeedPhraseField = document.getElementById("newSeedPhraseField");
    // Split on whitespace and remove any extra spaces
    const words = newSeedPhraseField.value.trim().split(/\s+/);

    // Choose 4 random unique indices from the seed words
    const randomIndices = getRandomIndices(words.length, 4);

    randomIndices.forEach((index) => {
        const prompt = document.createElement("div");
        prompt.className = "input-group";
        prompt.innerHTML = `
          <label class="input-label">Word #${index + 1}:</label>
          <input type="text" class="input-field" data-index="${index}">
      `;
        wordPrompts.appendChild(prompt);
    });
}

/**
 * Verify user-entered words against the generated seed phrase.
 * @returns {void}
 */
function verifySeedPhrase() {
    const newSeedPhraseField = document.getElementById("newSeedPhraseField");
    const words = newSeedPhraseField.value.trim().split(/\s+/);

    // Only select inputs within the verification screen
    const wordInputs = document.querySelectorAll(
        "#verifySeedBackUpScreen .input-field"
    );
    let allCorrect = true;

    wordInputs.forEach((input) => {
        const index = parseInt(input.dataset.index, 10);
        const enteredWord = input.value.trim().toLowerCase();

        // Safety check: if the index is invalid
        if (index >= words.length || !words[index]) {
            alert("Verification system error. Please regenerate seed phrase.");
            allCorrect = false;
            return;
        }

        const correctWord = words[index].toLowerCase();

        if (enteredWord !== correctWord) {
            allCorrect = false;
            input.style.border = "2px solid red";
        } else {
            input.style.border = "2px solid green";
        }
    });

    if (allCorrect) {
        alert("Verification successful!");
        moveToManagementScreen();
    } else {
        document.getElementById("verificationResult").textContent =
            "Verification failed. Please try again.";
    }
}

/**
 * Clear sensitive data and navigate to the management screen.
 * @returns {void}
 */
function moveToManagementScreen() {
    // Clear sensitive seed phrase data from the DOM
    document.getElementById("newSeedPhraseField").value = "";
    // Proceed to the next screen (e.g., wallet dashboard)
    showScreen("managementScreen");
}

/**
 * Copy the value of an input element to the clipboard.
 * @param {string} element - ID of the input element to copy.
 * @returns {boolean|void} False if empty selection, otherwise void.
 */
function copyElementToClipboard(element) {
    var outputText = document.getElementById(element);
    if (outputText && !outputText.value.trim()) { // Check if selected text is empty or null
        alert("Selected text is empty!");
        return false;
    }
    navigator.clipboard.writeText(outputText.value).then(
        function() {
            alert('Copied Succesfully to clipboard!');
        },
        function() {
            alert('Failed to copy text.');
        });
}

/**
 * Load a JSON dictionary from localStorage.
 * @param {string} key - Storage key to retrieve.
 * @returns {Object} Parsed object or empty object if not found.
 */
function loadDictionary(key) {
    // Check if the key exists in localStorage
    const storedData = localStorage.getItem(key);
    // If data exists, parse it, otherwise return an empty object
    if (storedData) {
        return JSON.parse(storedData);
    } else {
        return {};  // Return an empty object if nothing is found
    }
}

/**
 * Save a dictionary object to localStorage.
 * @param {string} key - Storage key to use.
 * @param {Object} dictionary - Data to save.
 * @returns {void}
 */
function saveDictionary(key, dictionary) {
    // Convert the dictionary to a JSON string and save it in localStorage
    localStorage.setItem(key, JSON.stringify(dictionary));
    console.log('Dict Saved')
}

/**
 * Load and decrypt data from localStorage using a user-provided password.
 * @returns {Object|void} Decrypted data object or void on failure.
 */
function loadEncryptedData() {
    const passwordInput = document.getElementById('encryptionPassword');
    const password = passwordInput.value.trim();
    if (!password || !passwordInput) {
        alert('No password to load encrypted data, no local storage will be used.');
        return {};
    }

    try {
        const key = hash(password); // Use the hashed password to retrieve the encrypted data
        const storedData = loadDictionary("encryptedDataStorage") || {}; // Load the dictionary

        if (!storedData || typeof storedData !== 'object') {
            alert('No stored data found or invalid data format.');
            return;
        }

        const encryptedData = storedData[key]; // Retrieve the encrypted data using the hashed key
        if (!encryptedData) {
            alert('No data found for the provided password.');
            return;
        }

        console.log('Encrypted data:', encryptedData);

        // Decrypt the data using the raw password
        const decryptedBytes = CryptoJS.AES.decrypt(encryptedData, password);
        const decryptedData = decryptedBytes.toString(CryptoJS.enc.Utf8);

        if (!decryptedData) {
            throw new Error('Failed to decrypt data. Possibly malformed UTF-8.');
        }

        console.log('Decrypted data:', decryptedData);
        localStoredData = JSON.parse(decryptedData)
        if(!localStoredData["privateKey"]){
            alert("There is no private key in the decrypted storage.")
            return;
        }
        privateKeyField.value = localStoredData["privateKey"]
        nostrKeys = deriveNostrKeys(privateKeyField.value);
        localStoredStatus = "loaded"
        loadSettings();
        alert('Data loaded successfully.');
        showScreen("managementScreen")
        return localStoredData; // Parse the JSON string back into an object
    } catch (error) {
        console.error('Error during decryption or parsing:', error.message);
        alert('Failed to decrypt. Invalid password or corrupted data.');
    }
}

/**
 * Encrypt and store current data using a user-provided password.
 * @returns {void}
 */
function saveEncryptedData() {
    const password1 = document.getElementById('encryptPass1').value;
    const password2 = document.getElementById('encryptPass2').value;
    if(password1!==password2) {
        alert('Password do not match.');
        return;
    }
    if (!password1) {
        alert('Please enter a password.');
        return;
    }

    if (Object.keys(localStoredData).length === 0) {
        alert('There is no data to save.');
        return;
    }
    if(localStoredStatus === "loaded"){
        alert("Overwriting encrypted storage, press again to confirm.")
        localStoredStatus = ""
        return;
    }

    localStoredData["privateKey"] = privateKeyField.value

    const key = hash(password1); // Use the hashed password as the dictionary key
    const encrypted = CryptoJS.AES.encrypt(JSON.stringify(localStoredData), password1).toString(); // Encrypt with the raw password

    // Load existing dictionary from localStorage
    const existingData = loadDictionary("encryptedDataStorage") || {};
    existingData[key] = encrypted; // Save the encrypted data using the hashed password as the key
    saveDictionary("encryptedDataStorage", existingData); // Save back to localStorage
    console.log('Data saved with hashed key:', key);
    console.log('Data:', existingData[key]);
    alert("Data encrypted succesfully")
    refreshPage()
}

/**
 * Reload the current page.
 * @returns {void}
 */
function refreshPage() {
    location.reload();
}

// ------ Nonce Editing Utilities ------
/**
 * Open the nonce editor populated with stored user nonces.
 * @returns {void}
 */
function openEditNonces() {
    if (!localStoredData['users']) localStoredData['users'] = {};
    document.getElementById('noncesEditor').value = JSON.stringify(localStoredData['users'], null, 2);
    showScreen('editNoncesScreen');
}

/**
 * Save nonce values edited by the user.
 * @returns {void}
 */
function saveEditedNonces() {
    try {
        const data = JSON.parse(document.getElementById('noncesEditor').value);
        localStoredData['users'] = data;
        alert('Nonces updated.');
        backupToNostr();
    } catch (e) {
        alert('Invalid JSON format.');
    }
}

/**
 * Download all stored nonces as a JSON file.
 * @returns {void}
 */
function downloadNoncesJson() {
    const data = localStoredData['users'] || {};
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'nonces.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Backup encrypted data to configured NOSTR relays.
 * @async
 * @returns {Promise<void>} Resolves when backup attempts complete.
 */
window.backupToNostr = async function () {
    const { nip04, relayInit, getEventHash, signEvent, getPublicKey } = window.NostrTools;

    console.log("📦 Starting NOSTR backup...");

    const entropy = privateKeyField.value.trim();
    if (!entropy) return alert("Missing private key");
    if (!localStoredData || Object.keys(localStoredData).length === 0) return alert("No data to backup");

    // Initialize relayList if not exists
    if (!window.relayList || !Array.isArray(window.relayList) || window.relayList.length === 0) {
        window.relayList = [
            "wss://relay.damus.io",
            "wss://nostr-pub.wellorder.net",
            "wss://relay.snort.social",
            "wss://nos.lol"
        ];
        console.log("🔧 Initialized default relay list");
    }

    try {
        const utf8 = new TextEncoder().encode(entropy);
        const hashBuffer = await crypto.subtle.digest("SHA-256", utf8);
        const sk = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
        const pk = getPublicKey(sk);

        const data = JSON.stringify(localStoredData);
        const encrypted = await nip04.encrypt(sk, pk, data);
        console.log("🔐 Data encrypted successfully");

        const event = {
            kind: 1,
            pubkey: pk,
            created_at: Math.floor(Date.now() / 1000),
            tags: [["t", "nostr-pwd-backup"]],
            content: encrypted,
        };

        event.id = getEventHash(event);
        event.sig = await signEvent(event, sk);
        console.log("📤 Event prepared for publishing");

        let successCount = 0;
        const totalRelays = window.relayList.length;

        const publishPromises = window.relayList.map(async (url) => {
            try {
                console.log(`🌐 Connecting to ${url}`);
                const relay = relayInit(url);

                await new Promise((resolve, reject) => {
                    const timeout = setTimeout(() => reject(new Error('Connection timeout')), 5000);

                    relay.on('connect', () => {
                        clearTimeout(timeout);
                        resolve();
                    });

                    relay.on('error', (err) => {
                        clearTimeout(timeout);
                        reject(err);
                    });

                    relay.connect();
                });

                // Try the newer publish method first, then fallback to older method
                let publishResult;
                try {
                    publishResult = relay.publish(event);

                    // Check if it has .on methods (newer version)
                    if (publishResult && typeof publishResult.on === 'function') {
                        await new Promise((resolve, reject) => {
                            const timeout = setTimeout(() => reject(new Error('Publish timeout')), 3000);

                            publishResult.on("ok", () => {
                                clearTimeout(timeout);
                                console.log(`✅ Successfully published to ${url}`);
                                successCount++;
                                resolve();
                            });

                            publishResult.on("failed", (reason) => {
                                clearTimeout(timeout);
                                console.warn(`❌ Failed to publish to ${url}:`, reason);
                                reject(new Error(reason));
                            });
                        });
                    } else {
                        // Older version - just assume success if no error thrown
                        console.log(`✅ Published to ${url} (legacy mode)`);
                        successCount++;
                    }
                } catch (publishError) {
                    // Try alternative publish method for older versions
                    try {
                        await relay.send(['EVENT', event]);
                        console.log(`✅ Published to ${url} (send method)`);
                        successCount++;
                    } catch (sendError) {
                        throw new Error(`Both publish methods failed: ${publishError.message}, ${sendError.message}`);
                    }
                }

                relay.close();
            } catch (e) {
                console.error(`🔥 Relay ${url} failed:`, e.message);
            }
        });

        await Promise.allSettled(publishPromises);

        if (successCount > 0) {
            alert(`✅ Backup successful! Published to ${successCount}/${totalRelays} relays`);
        } else {
            alert("❌ Failed to publish to any relays");
        }
    } catch (error) {
        console.error("🔥 Backup failed:", error);
        alert("❌ Backup failed: " + error.message);
    }
};

/**
 * Restore encrypted data from NOSTR relays.
 * @async
 * @returns {Promise<void>} Resolves when restore process finishes.
 */
window.restoreFromNostr = async function () {
    const { nip04, relayInit, getPublicKey } = window.NostrTools;

    if (window.restoreInProgress) return alert("Restore already in progress");
    window.restoreInProgress = true;

    console.log("🔄 Starting restore from NOSTR...");

    const entropy = privateKeyField.value.trim();
    if (!entropy) {
        alert("Missing private key");
        window.restoreInProgress = false;
        return;
    }

    // Initialize relayList if not exists
    if (!window.relayList || !Array.isArray(window.relayList) || window.relayList.length === 0) {
        window.relayList = [
            "wss://relay.damus.io",
            "wss://nostr-pub.wellorder.net",
            "wss://relay.snort.social",
            "wss://nos.lol"
        ];
        console.log("🔧 Initialized default relay list");
    }

    try {
        const utf8 = new TextEncoder().encode(entropy);
        const hashBuffer = await crypto.subtle.digest("SHA-256", utf8);
        const sk = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
        const pk = getPublicKey(sk);
        console.log("🔑 Using pubkey:", pk);

        let found = false;
        let latestEvent = null;

        const searchPromises = window.relayList.map(async (url) => {
            try {
                console.log(`🌐 Connecting to ${url}`);
                const relay = relayInit(url);

                await new Promise((resolve, reject) => {
                    const timeout = setTimeout(() => reject(new Error('Connection timeout')), 5000);

                    relay.on('connect', () => {
                        clearTimeout(timeout);
                        resolve();
                    });

                    relay.on('error', (err) => {
                        clearTimeout(timeout);
                        reject(err);
                    });

                    relay.connect();
                });

                const filter = { kinds: [1], authors: [pk], "#t": ["nostr-pwd-backup"] };
                console.log(`🛰️ Subscribing with filter:`, filter);

                const sub = relay.sub([filter]);

                await new Promise((resolve) => {
                    const timeout = setTimeout(() => {
                        sub.unsub();
                        resolve();
                    }, 10000);

                    sub.on("event", async (e) => {
                        console.log("📨 Got event:", e.id);

                        // Keep track of the latest event
                        if (!latestEvent || e.created_at > latestEvent.created_at) {
                            latestEvent = e;
                            found = true;
                        }
                    });

                    sub.on("eose", () => {
                        clearTimeout(timeout);
                        sub.unsub();
                        resolve();
                    });
                });

                relay.close();
            } catch (err) {
                console.error(`🔥 Error on relay ${url}:`, err.message);
            }
        });

        await Promise.allSettled(searchPromises);

        if (found && latestEvent) {
            try {
                const decrypted = await nip04.decrypt(sk, latestEvent.pubkey, latestEvent.content);
                console.log("🔓 Successfully decrypted data");

                const parsedData = JSON.parse(decrypted);
                localStoredData = parsedData;
                localStoredStatus = "loaded";
                loadSettings();

                alert("✅ Restore complete from NOSTR");
                showScreen("managementScreen");
            } catch (err) {
                console.error("❌ Failed to decrypt/parse:", err);
                alert("⚠️ Could not decrypt or parse restored data");
            }
        } else {
            alert("⚠️ No backup found on any relay");
        }
    } catch (error) {
        console.error("🔥 Restore failed:", error);
        alert("❌ Restore failed: " + error.message);
    } finally {
        window.restoreInProgress = false;
    }
};

/**
 * Display backup events found on configured NOSTR relays.
 * @async
 * @returns {Promise<void>} Resolves when history is displayed.
 */
window.openNostrHistory = async function () {
    const { relayInit, getPublicKey } = window.NostrTools;

    console.log("📖 Fetching backup history...");

    const entropy = privateKeyField.value.trim();
    if (!entropy) return alert("Missing private key");

    // Initialize relayList if not exists
    if (!window.relayList || !Array.isArray(window.relayList) || window.relayList.length === 0) {
        window.relayList = [
            "wss://relay.damus.io",
            "wss://nostr-pub.wellorder.net",
            "wss://relay.snort.social",
            "wss://nos.lol"
        ];
        console.log("🔧 Initialized default relay list");
    }

    try {
        const utf8 = new TextEncoder().encode(entropy);
        const hashBuffer = await crypto.subtle.digest("SHA-256", utf8);
        const sk = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
        const pk = getPublicKey(sk);

        const container = document.getElementById("nostrHistoryList");
        if (!container) {
            alert("History display element not found");
            return;
        }

        container.innerHTML = "<p>⏳ Fetching backup history from relays…</p>";

        let allResults = [];

        const historyPromises = window.relayList.map(async (url) => {
            try {
                console.log(`🌐 Connecting to ${url}`);
                const relay = relayInit(url);

                await new Promise((resolve, reject) => {
                    const timeout = setTimeout(() => reject(new Error('Connection timeout')), 5000);

                    relay.on('connect', () => {
                        clearTimeout(timeout);
                        resolve();
                    });

                    relay.on('error', (err) => {
                        clearTimeout(timeout);
                        reject(err);
                    });

                    relay.connect();
                });

                const sub = relay.sub([{ kinds: [1], authors: [pk], "#t": ["nostr-pwd-backup"] }]);

                await new Promise((resolve) => {
                    const timeout = setTimeout(() => {
                        sub.unsub();
                        resolve();
                    }, 8000);

                    sub.on("event", (e) => {
                        const date = new Date(e.created_at * 1000).toLocaleString();
                        console.log(`🕓 Backup from ${url} on ${date}`);
                        allResults.push({
                            date: date,
                            timestamp: e.created_at,
                            relay: url,
                            id: e.id
                        });
                    });

                    sub.on("eose", () => {
                        clearTimeout(timeout);
                        sub.unsub();
                        resolve();
                    });
                });

                relay.close();
            } catch (err) {
                console.error(`🔥 History fetch failed for ${url}:`, err.message);
            }
        });

        await Promise.allSettled(historyPromises);

        // Sort results by timestamp (newest first) and remove duplicates
        const uniqueResults = [];
        const seenIds = new Set();

        allResults
            .sort((a, b) => b.timestamp - a.timestamp)
            .forEach(result => {
                if (!seenIds.has(result.id)) {
                    seenIds.add(result.id);
                    uniqueResults.push(result);
                }
            });

        if (uniqueResults.length > 0) {
            container.innerHTML = `<h3>Found ${uniqueResults.length} backup(s):</h3>`;
            uniqueResults.forEach(result => {
                const el = document.createElement("div");
                el.style.padding = "10px";
                el.style.margin = "5px 0";
                el.style.border = "1px solid #ccc";
                el.style.borderRadius = "5px";
                el.style.cursor = "pointer";
                el.title = "Tap to restore this backup";
                el.innerHTML = `
                    <strong>📦 ${result.date}</strong><br>
                    <small>Relay: ${result.relay}</small><br>
                    <small>ID: ${result.id.substring(0, 16)}...</small>
                `;
                el.addEventListener("click", () => {
                    if (typeof window.restoreFromNostrId === "function") {
                        window.restoreFromNostrId(result.id);
                    } else {
                        alert("Restore function not available");
                    }
                });
                container.appendChild(el);
            });
        } else {
            container.innerHTML = "<p>⚠️ No backup history found on any relay.</p>";
        }

        showScreen("nostrHistoryScreen");
    } catch (error) {
        console.error("🔥 History fetch failed:", error);
        const container = document.getElementById("nostrHistoryList");
        if (container) {
            container.innerHTML = `<p>⚠️ Failed to fetch history: ${error.message}</p>`;
        }
        alert("❌ Failed to fetch history: " + error.message);
    }
};

/**
 * Restore encrypted data from a specific NOSTR event ID.
 * @async
 * @param {string} eventId - Identifier of the NOSTR event to restore.
 * @returns {Promise<void>} Resolves when restore completes.
 */
window.restoreFromNostrId = async function (eventId) {
    const { nip04, relayInit } = window.NostrTools;

    if (window.restoreInProgress) return alert("Restore already in progress");
    window.restoreInProgress = true;

    const entropy = privateKeyField.value.trim();
    if (!entropy) {
        alert("Missing private key");
        window.restoreInProgress = false;
        return;
    }

    if (!window.relayList || !Array.isArray(window.relayList) || window.relayList.length === 0) {
        window.relayList = [
            "wss://relay.damus.io",
            "wss://nostr-pub.wellorder.net",
            "wss://relay.snort.social",
            "wss://nos.lol"
        ];
        console.log("🔧 Initialized default relay list");
    }

    try {
        const utf8 = new TextEncoder().encode(entropy);
        const hashBuffer = await crypto.subtle.digest("SHA-256", utf8);
        const sk = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

        let foundEvent = null;

        const searchPromises = window.relayList.map(async (url) => {
            try {
                const relay = relayInit(url);

                await new Promise((resolve, reject) => {
                    const timeout = setTimeout(() => reject(new Error('Connection timeout')), 5000);

                    relay.on('connect', () => {
                        clearTimeout(timeout);
                        resolve();
                    });

                    relay.on('error', (err) => {
                        clearTimeout(timeout);
                        reject(err);
                    });

                    relay.connect();
                });

                const sub = relay.sub([{ ids: [eventId] }]);

                await new Promise((resolve) => {
                    const timeout = setTimeout(() => {
                        sub.unsub();
                        resolve();
                    }, 8000);

                    sub.on("event", (e) => {
                        foundEvent = e;
                        clearTimeout(timeout);
                        sub.unsub();
                        resolve();
                    });

                    sub.on("eose", () => {
                        clearTimeout(timeout);
                        sub.unsub();
                        resolve();
                    });
                });

                relay.close();
            } catch (err) {
                console.error(`🔥 Error on relay ${url}:`, err.message);
            }
        });

        await Promise.allSettled(searchPromises);

        if (foundEvent) {
            try {
                const decrypted = await nip04.decrypt(sk, foundEvent.pubkey, foundEvent.content);
                const parsedData = JSON.parse(decrypted);
                localStoredData = parsedData;
                localStoredStatus = "loaded";
                loadSettings();

                alert("✅ Restore complete from NOSTR");
                showScreen("managementScreen");
            } catch (err) {
                console.error("❌ Failed to decrypt/parse:", err);
                alert("⚠️ Could not decrypt or parse restored data");
            }
        } else {
            alert("⚠️ Backup not found on any relay");
        }
    } catch (error) {
        console.error("🔥 Restore failed:", error);
        alert("❌ Restore failed: " + error.message);
    } finally {
        window.restoreInProgress = false;
    }
};


/**
 * Load settings from localStoredData and populate the UI.
 * @returns {void}
 */
function loadSettings() {
    const hashLen = localStoredData.settings?.hashLength || settings.hashLength || DEFAULT_HASH_LENGTH;
    settings.hashLength = hashLen;
    const hashLengthField = document.getElementById('hashLengthField');
    if (hashLengthField) {
        hashLengthField.value = hashLen;
    }
}

/**
 * Save settings from UI to localStoredData.
 * @returns {void}
 */
function saveSettings() {
    const hashLengthField = document.getElementById('hashLengthField');
    let hashLen = parseInt(hashLengthField?.value, 10) || DEFAULT_HASH_LENGTH;
    
    // Clamp to valid range (8-64)
    hashLen = Math.max(8, Math.min(64, hashLen));
    
    settings.hashLength = hashLen;
    
    if (!localStoredData.settings) {
        localStoredData.settings = {};
    }
    localStoredData.settings.hashLength = hashLen;
    
    alert(`Settings saved. Hash length: ${hashLen} characters.`);
    navigateBack('settingsScreen');
}

/**
 * Derive Nostr keys from a hex private key string.
 * @param {string} hexPrivateKey - Hex-encoded private key.
 * @returns {Promise<Object>} Object containing nsec and npub.
 */
async function deriveNostrKeys(hexPrivateKey) {
    const { nip19, getPublicKey } = window.NostrTools;
    
    const utf8 = new TextEncoder().encode(hexPrivateKey);
    const hashBuffer = await crypto.subtle.digest("SHA-256", utf8);
    const nostrHex = Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    
    const nsec = nip19.nsecEncode(nostrHex);
    const npub = getPublicKey(nostrHex);
    
    return { nsec, npub };
}
