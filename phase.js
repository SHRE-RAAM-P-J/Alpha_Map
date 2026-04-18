// ============================================================
//   ALPHAMAP v1.0 — ULTRA COMPACT TOKENIZER (JavaScript)
// ============================================================

/*
Works in:
- Node.js (AES fully supported)
- React (browser-friendly except AES, use WebCrypto API)
- Electron (full support)
*/

const crypto = require("crypto");

// ============================================================
//   CONFIGURATION
// ============================================================

const WORD_LIMIT = 600;

const BIGRAM_MIN = 10;
const BIGRAM_MAX = 50;

const TRIGRAM_MIN = 10;
const TRIGRAM_MAX = 50;

const PHRASE_BASE = 950;
const BIGRAM_BASE = 600;
const TRIGRAM_BASE = 850;

const CASE_LOWER = 0;
const CASE_TITLE = 1;
const CASE_UPPER = 2;

const REBUILD_INTERVAL = 10;

// ============================================================
//   DICTIONARIES
// ============================================================

let wordFrequency = {};
let wordToId = {};
let idToWord = {};

let bigramFrequency = {};
let trigramFrequency = {};

let autoBigrams = {};  // phrase -> baseId
let autoTrigrams = {}; // phrase -> baseId

let encodeCounter = 0;

// Manual phrases
const manualPhrases = {
    "i am": 950,
    "thank you": 951,
    "good morning": 952,
    "how are you": 953,
    "see you soon": 954,
    "i love you": 955,
    "let us go": 956,
    "what is this": 957
};

// ============================================================
//   CASE HANDLING
// ============================================================

function detectCase(word) {
    if (word.toUpperCase() === word) return CASE_UPPER;
    if (word[0] === word[0].toUpperCase() && word.slice(1) === word.slice(1).toLowerCase())
        return CASE_TITLE;
    return CASE_LOWER;
}

function applyCase(word, caseDigit) {
    if (caseDigit === CASE_UPPER) return word.toUpperCase();
    if (caseDigit === CASE_TITLE) return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
    return word.toLowerCase();
}

// ============================================================
//   TOKEN PACKING (000–999)
// ============================================================

function packToken(baseId, caseDigit) {
    let final = baseId * 3 + caseDigit;
    return final.toString().padStart(3, "0");
}

function unpackToken(tokenStr) {
    let t = parseInt(tokenStr, 10);
    let caseDigit = t % 3;
    let base = Math.floor(t / 3);
    return [base, caseDigit];
}

// ============================================================
//   N-GRAM EXTRACTION
// ============================================================

function extractBigrams(words) {
    let res = [];
    for (let i = 0; i < words.length - 1; i++) {
        res.push(words[i] + " " + words[i + 1]);
    }
    return res;
}

function extractTrigrams(words) {
    let res = [];
    for (let i = 0; i < words.length - 2; i++) {
        res.push(words[i] + " " + words[i + 1] + " " + words[i + 2]);
    }
    return res;
}

// ============================================================
//   AUTO NGRAM LEARNING
// ============================================================

function updateAutoBigrams() {
    let sorted = Object.entries(bigramFrequency)
        .sort((a, b) => b[1] - a[1]);

    let count = Math.min(Math.max(sorted.length, BIGRAM_MIN), BIGRAM_MAX);

    autoBigrams = {};

    for (let i = 0; i < count && i < sorted.length; i++) {
        autoBigrams[sorted[i][0]] = BIGRAM_BASE + i;
    }
}

function updateAutoTrigrams() {
    let sorted = Object.entries(trigramFrequency)
        .sort((a, b) => b[1] - a[1]);

    let count = Math.min(Math.max(sorted.length, TRIGRAM_MIN), TRIGRAM_MAX);

    autoTrigrams = {};

    for (let i = 0; i < count && i < sorted.length; i++) {
        autoTrigrams[sorted[i][0]] = TRIGRAM_BASE + i;
    }
}

// ============================================================
//   WORD DICTIONARY REBUILD
// ============================================================

function rebuildWordDictionary() {
    let sorted = Object.entries(wordFrequency)
        .sort((a, b) => b[1] - a[1]);

    let top = sorted.slice(0, WORD_LIMIT);

    wordToId = {};
    idToWord = {};

    for (let i = 0; i < top.length; i++) {
        let word = top[i][0];
        wordToId[word] = i;
        idToWord[i] = word;
    }
}

// ============================================================
//   ENCODE
// ============================================================

function encodeSentence(sentence) {
    encodeCounter++;

    let words = sentence.split(/\s+/);
    let lw = words.map(w => w.toLowerCase());
    let out = [];

    // update freq
    lw.forEach(w => {
        wordFrequency[w] = (wordFrequency[w] || 0) + 1;
    });

    extractBigrams(lw).forEach(bg => {
        bigramFrequency[bg] = (bigramFrequency[bg] || 0) + 1;
    });

    extractTrigrams(lw).forEach(tg => {
        trigramFrequency[tg] = (trigramFrequency[tg] || 0) + 1;
    });

    updateAutoBigrams();
    updateAutoTrigrams();

    let i = 0;

    while (i < words.length) {

        // Try trigram
        if (i + 2 < words.length) {
            let tg = `${lw[i]} ${lw[i + 1]} ${lw[i + 2]}`;
            if (autoTrigrams[tg] !== undefined) {
                let caseDigit = detectCase(words[i]);
                let base = autoTrigrams[tg];
                out.push(packToken(base, caseDigit));
                i += 3;
                continue;
            }
        }

        // Try bigram
        if (i + 1 < words.length) {
            let bg = `${lw[i]} ${lw[i + 1]}`;
            if (autoBigrams[bg] !== undefined) {
                let caseDigit = detectCase(words[i]);
                let base = autoBigrams[bg];
                out.push(packToken(base, caseDigit));
                i += 2;
                continue;
            }
        }

        // Manual phrase as fallback
        let lw0 = lw[i];
        let caseDigit = detectCase(words[i]);

        if (wordToId[lw0] !== undefined) {
            out.push(packToken(wordToId[lw0], caseDigit));
        } else {
            // add new word dynamically
            if (Object.keys(wordToId).length < WORD_LIMIT) {
                let idx = Object.keys(wordToId).length;
                wordToId[lw0] = idx;
                idToWord[idx] = lw0;
                out.push(packToken(idx, caseDigit));
            } else {
                // fallback if dictionary full
                out.push(packToken(0, caseDigit));
            }
        }

        i++;
    }

    if (encodeCounter % REBUILD_INTERVAL === 0) rebuildWordDictionary();

    return out;
}

// ============================================================
//   DECODE
// ============================================================

function decodeTokens(tokens) {
    let out = [];

    let invAutoBi = {};
    for (let [k, v] of Object.entries(autoBigrams)) invAutoBi[v] = k;

    let invAutoTri = {};
    for (let [k, v] of Object.entries(autoTrigrams)) invAutoTri[v] = k;

    for (let t of tokens) {
        let [base, caseDigit] = unpackToken(t);
        let text = "";

        if (base < WORD_LIMIT) {
            text = idToWord[base] || "";
        } else if (base >= BIGRAM_BASE && base < TRIGRAM_BASE) {
            text = invAutoBi[base] || "";
        } else if (base >= TRIGRAM_BASE && base < PHRASE_BASE) {
            text = invAutoTri[base] || "";
        } else {
            // manual phrase
            for (let [phrase, id] of Object.entries(manualPhrases)) {
                if (id === base) text = phrase;
            }
        }

        if (text.includes(" ")) {
            let parts = text.split(" ");
            parts[0] = applyCase(parts[0], caseDigit);
            out.push(...parts);
        } else {
            out.push(applyCase(text, caseDigit));
        }
    }

    return out.join(" ");
}

// ============================================================
//   AES ENCRYPT/DECRYPT (Node.js)
// ============================================================

function aesEncrypt(jsonString, key) {
    if (key.length !== 32) throw new Error("AES key must be 32 chars.");

    let iv = crypto.randomBytes(16);
    let cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(key), iv);

    let encrypted = cipher.update(jsonString);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    return Buffer.concat([iv, encrypted]).toString("base64");
}

function aesDecrypt(encoded, key) {
    let raw = Buffer.from(encoded, "base64");
    let iv = raw.slice(0, 16);
    let data = raw.slice(16);

    let decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(key), iv);
    let dec = decipher.update(data);
    dec = Buffer.concat([dec, decipher.final()]);
    return dec.toString();
}

// ============================================================
//   SAVE/LOAD ALPHA FILE
// ============================================================

function saveAlphaFile(text, filename, key) {
    let tokens = encodeSentence(text);

    let data = {
        version: "1.0",
        tokens,
        wordToId
    };

    let encrypted = aesEncrypt(JSON.stringify(data), key);
    require("fs").writeFileSync(filename, encrypted);
}

function loadAlphaFile(filename, key) {
    let encrypted = require("fs").readFileSync(filename, "utf8");
    let decrypted = aesDecrypt(encrypted, key);
    let data = JSON.parse(decrypted);

    // restore dictionary
    wordToId = data.wordToId;
    idToWord = {};
    for (let w in wordToId) idToWord[wordToId[w]] = w;

    return decodeTokens(data.tokens);
}

// Export for React & Node
module.exports = {
    encodeSentence,
    decodeTokens,
    saveAlphaFile,
    loadAlphaFile
};
