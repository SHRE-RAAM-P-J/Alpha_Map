import json
from Crypto.Cipher import AES
import base64
import os

# ============================================================
#   ALPHAMAP v1.0 — CONFIGURATION
# ============================================================

WORD_LIMIT = 600                     # word tokens 0–599
BIGRAM_MIN = 10                      # adaptive based on usage
BIGRAM_MAX = 50
TRIGRAM_MIN = 10
TRIGRAM_MAX = 50

PHRASE_BASE = 950                    # Manual phrases (950–989)
BIGRAM_BASE = 600                    # Auto bigrams (600–849)
TRIGRAM_BASE = 850                   # Auto trigrams (850–949)

CASE_LOWER = 0
CASE_TITLE = 1
CASE_UPPER = 2

REBUILD_INTERVAL = 10

# ============================================================
#   DICTIONARIES & INTERNAL DATA
# ============================================================

word_frequency = {}
word_to_id = {}
id_to_word = {}

bigram_frequency = {}
trigram_frequency = {}

auto_bigrams = {}       # phrase -> base id (600–849)
auto_trigrams = {}      # phrase -> base id (850–949)

encode_counter = 0

# Preloaded base manual phrases:
manual_phrases = {
    "i am": 950,
    "thank you": 951,
    "good morning": 952,
    "how are you": 953,
    "see you soon": 954,
    "i love you": 955,
    "let us go": 956,
    "what is this": 957
}

# ==================================================================
#   CASE HANDLING (Option B compact embedding)
# ==================================================================

def detect_case(word):
    if word.isupper():
        return CASE_UPPER
    elif word[0].isupper() and word[1:].islower():
        return CASE_TITLE
    else:
        return CASE_LOWER

def apply_case(word, case_digit):
    if case_digit == CASE_UPPER:
        return word.upper()
    elif case_digit == CASE_TITLE:
        return word.capitalize()
    else:
        return word.lower()

# ==================================================================
#   TOKEN PACKING (base_id + case)
# ==================================================================

def pack_token(base_id, case_digit):
    """
    produce 3-digit compact token:
    final = base_id * 3 + case
    padded to 3 digits
    """
    final = base_id * 3 + case_digit
    return f"{final:03d}"

def unpack_token(token_str):
    t = int(token_str)
    case_digit = t % 3
    base = t // 3
    return base, case_digit

# ==================================================================
#   DICTIONARY REBUILD (frequency-based ranking)
# ==================================================================

def rebuild_word_dictionary():
    global word_to_id, id_to_word

    ranked = sorted(word_frequency.items(), key=lambda x: x[1], reverse=True)
    top_words = ranked[:WORD_LIMIT]

    word_to_id.clear()
    id_to_word.clear()

    for idx, (word, freq) in enumerate(top_words):
        word_to_id[word] = idx
        id_to_word[idx] = word

# ==================================================================
#   N-GRAM EXTRACTION
# ==================================================================

def extract_bigrams(words):
    return [words[i] + " " + words[i+1] for i in range(len(words)-1)]

def extract_trigrams(words):
    return [words[i] + " " + words[i+1] + " " + words[i+2] for i in range(len(words)-2)]

# ==================================================================
#   BIGRAM / TRIGRAM LEARNING
# ==================================================================

def update_auto_bigrams():
    global auto_bigrams
    sorted_bi = sorted(bigram_frequency.items(), key=lambda x: x[1], reverse=True)
    count = min(max(len(sorted_bi), BIGRAM_MIN), BIGRAM_MAX)
    auto_bigrams = {}

    for i in range(min(count, BIGRAM_MAX)):
        if i < len(sorted_bi):
            phrase = sorted_bi[i][0]
            auto_bigrams[phrase] = BIGRAM_BASE + i

def update_auto_trigrams():
    global auto_trigrams
    sorted_tri = sorted(trigram_frequency.items(), key=lambda x: x[1], reverse=True)
    count = min(max(len(sorted_tri), TRIGRAM_MIN), TRIGRAM_MAX)
    auto_trigrams = {}

    for i in range(min(count, TRIGRAM_MAX)):
        if i < len(sorted_tri):
            phrase = sorted_tri[i][0]
            auto_trigrams[phrase] = TRIGRAM_BASE + i

# ==================================================================
#   ENCODING PIPELINE
# ==================================================================

def encode_sentence(sentence):
    global encode_counter
    words = sentence.split()
    lower_words = [w.lower() for w in words]
    wlen = len(words)

    # update word freq
    for lw in lower_words:
        word_frequency[lw] = word_frequency.get(lw, 0) + 1

    # update n-grams
    for bg in extract_bigrams(lower_words):
        bigram_frequency[bg] = bigram_frequency.get(bg, 0) + 1
    for tg in extract_trigrams(lower_words):
        trigram_frequency[tg] = trigram_frequency.get(tg, 0) + 1

    update_auto_bigrams()
    update_auto_trigrams()

    tokens = []
    i = 0

    while i < wlen:
        # Try trigram first
        if i + 2 < wlen:
            tg = f"{lower_words[i]} {lower_words[i+1]} {lower_words[i+2]}"
            if tg in auto_trigrams:
                case_digit = detect_case(words[i])
                base = auto_trigrams[tg]
                tokens.append(pack_token(base, case_digit))
                i += 3
                continue

        # Bigram
        if i + 1 < wlen:
            bg = f"{lower_words[i]} {lower_words[i+1]}"
            if bg in auto_bigrams:
                case_digit = detect_case(words[i])
                base = auto_bigrams[bg]
                tokens.append(pack_token(base, case_digit))
                i += 2
                continue

        # Manual phrase
        lw = lower_words[i]
        case_digit = detect_case(words[i])

        if lw in word_to_id:
            base = word_to_id[lw]
        else:
            # fallback: make dynamic entry
            if len(word_to_id) < WORD_LIMIT:
                idx = len(word_to_id)
                word_to_id[lw] = idx
                id_to_word[idx] = lw
                base = idx
            else:
                # last resort: encode as individual letters
                base = word_to_id.get(lw, 0)

        tokens.append(pack_token(base, case_digit))
        i += 1

    encode_counter += 1
    if encode_counter % REBUILD_INTERVAL == 0:
        rebuild_word_dictionary()

    return tokens

# ==================================================================
#   DECODING PIPELINE
# ==================================================================

def decode_tokens(tokens):
    output_words = []

    # reverse maps ready
    inv_autobi = {v: k for k, v in auto_bigrams.items()}
    inv_autotri = {v: k for k, v in auto_trigrams.items()}

    for token in tokens:
        base, case_digit = unpack_token(token)

        if 0 <= base < WORD_LIMIT:
            word = id_to_word.get(base, "<?>")
        elif BIGRAM_BASE <= base < TRIGRAM_BASE:
            word = inv_autobi.get(base, "")
        elif TRIGRAM_BASE <= base < PHRASE_BASE:
            word = inv_autotri.get(base, "")
        elif base in manual_phrases.values():
            word = list(manual_phrases.keys())[list(manual_phrases.values()).index(base)]
        else:
            word = "<?>"

        # Apply casing to first word of phrase only
        if " " in word:
            parts = word.split()
            parts[0] = apply_case(parts[0], case_digit)
            output_words.extend(parts)
        else:
            output_words.append(apply_case(word, case_digit))

    return " ".join(output_words)

# ==================================================================
#   AES SAVE/LOAD
# ==================================================================

def pad_data(data: bytes) -> bytes:
    padding = 16 - len(data) % 16
    return data + bytes([padding]) * padding

def unpad_data(data: bytes) -> bytes:
    return data[:-data[-1]]

def aes_encrypt(raw_text: str, key: str) -> str:
    if len(key) != 32:
        raise ValueError("AES key must be 32 characters long.")

    iv = os.urandom(16)
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)

    data = pad_data(raw_text.encode())
    encrypted = cipher.encrypt(data)

    return base64.b64encode(iv + encrypted).decode()

def aes_decrypt(encoded: str, key: str) -> str:
    raw = base64.b64decode(encoded)
    iv, data = raw[:16], raw[16:]

    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data)

    return unpad_data(decrypted).decode()

def save_alpha_file(text, filename, key):
    tokens = encode_sentence(text)
    data = {
        "version": "1.0",
        "tokens": tokens,
        "word_dict": word_to_id
    }

    encrypted = aes_encrypt(json.dumps(data), key)

    with open(filename, "w") as f:
        f.write(encrypted)

def load_alpha_file(filename, key):
    encrypted = open(filename).read()
    decrypted = aes_decrypt(encrypted, key)
    data = json.loads(decrypted)

    # restore dictionary
    global word_to_id, id_to_word
    word_to_id = data["word_dict"]
    id_to_word = {v: k for k, v in word_to_id.items()}

    return decode_tokens(data["tokens"])
