import os, base64, hashlib, struct, json, zlib, re
from Crypto.Cipher import AES


class AlphaMap:

    MAGIC = b"AMAP"
    VERSION = 5   # Final merged version


    def __init__(self, key: str):

        # AES-256 key
        self.key = hashlib.sha256(key.encode()).digest()

        # Limits
        self.WORD_LIMIT = 600
        self.BIGRAM_BASE = 600
        self.SPELL = 999


        # Training data
        self.word_freq = {}
        self.bigram_freq = {}

        self.word_to_id = {}
        self.auto_bigrams = {}

        # Manual phrases
        self.manual = {
            "i am": 950,
            "thank you": 951,
            "good morning": 952
        }

        # Char maps
        self.char = {chr(i+96): i for i in range(1,27)}
        self.ichar = {i: chr(i+96) for i in range(1,27)}


    # =====================================================
    # VARINT
    # =====================================================

    def _encode_varint(self, n):

        out = bytearray()

        while n >= 0x80:
            out.append((n & 0x7F) | 0x80)
            n >>= 7

        out.append(n)

        return out


    def _decode_varint(self, data, pos):

        res = 0
        shift = 0

        while True:

            b = data[pos]
            pos += 1

            res |= (b & 0x7F) << shift

            if not (b & 0x80):
                return res, pos

            shift += 7


    # =====================================================
    # CASE HANDLING
    # =====================================================

    def _case(self, w):

        if w.isupper(): return 2
        if len(w) > 0 and w[0].isupper(): return 1

        return 0


    def _apply(self, w, c):

        if c == 2: return w.upper()
        if c == 1: return w.capitalize()

        return w.lower()


    def _pack(self, b, c):

        return b * 3 + c


    def _unpack(self, v):

        return v // 3, v % 3


    # =====================================================
    # TRAINING
    # =====================================================

    def train(self, text):

        tokens = re.findall(r'\S+|\s+', text)
        low = [x.lower() for x in tokens]


        # Word frequency
        for x in low:
            self.word_freq[x] = self.word_freq.get(x, 0) + 1


        # Bigram frequency
        for i in range(len(low)-1):

            bg = low[i] + low[i+1]

            self.bigram_freq[bg] = self.bigram_freq.get(bg, 0) + 1


        # Dictionary
        r = sorted(
            self.word_freq.items(),
            key=lambda x: x[1],
            reverse=True
        )[:self.WORD_LIMIT]


        self.word_to_id = {
            w: i for i, (w, _) in enumerate(r)
        }


        # Auto bigrams
        rb = sorted(
            self.bigram_freq.items(),
            key=lambda x: x[1],
            reverse=True
        )[:40]


        self.auto_bigrams = {
            p: self.BIGRAM_BASE + i
            for i, (p, _) in enumerate(rb)
        }


    # =====================================================
    # ENCODER
    # =====================================================

    def encode(self, text):

        words = re.findall(r'\S+|\s+', text)
        low = [x.lower() for x in words]

        t = []
        i = 0


        while i < len(words):

            c = self._case(words[i])


            # Manual + Bigram
            found = False

            if i+1 < len(words):

                p = low[i] + low[i+1]

                for d in (self.manual, self.auto_bigrams):

                    if p in d:

                        t.append(self._pack(d[p], c))
                        i += 2
                        found = True
                        break

            if found:
                continue


            lw = low[i]


            # Dictionary
            if lw in self.word_to_id:

                t.append(self._pack(self.word_to_id[lw], c))


            # Spell mode
            else:

                t.append(self._pack(self.SPELL, c))

                t.append(len(lw))

                for ch in lw:

                    v = self.char.get(ch, 0)

                    if v:
                        t.append(v + 970)
                    else:
                        t.append(ord(ch))


            i += 1


        return t


    # =====================================================
    # DECODER
    # =====================================================

    def decode(self, tokens, wd, bi):

        inv = {i: w for w, i in wd.items()}
        invb = {v: k for k, v in bi.items()}
        invm = {v: k for k, v in self.manual.items()}

        out = []
        it = iter(tokens)


        for v in it:

            b, c = self._unpack(v)


            if b == self.SPELL:

                ln = next(it)

                cs = []

                for _ in range(ln):

                    x = next(it)

                    if 971 <= x <= 996:
                        cs.append(self.ichar[x-970])
                    else:
                        cs.append(chr(x))

                w = "".join(cs)


            elif b in invm:
                w = invm[b]

            elif b in invb:
                w = invb[b]

            else:
                w = inv.get(b, "<?>")



            out.append(self._apply(w, c))


        return "".join(out)


    # =====================================================
    # SAVE (AES-GCM + VARINT)
    # =====================================================

    def save(self, text):

        if not self.word_to_id:
            self.train(text)


        tok = self.encode(text)


        bi = json.dumps(self.auto_bigrams).encode()
        wd = json.dumps(self.word_to_id).encode()


        # Varint tokens
        tokb = bytearray()

        for t in tok:
            tokb.extend(self._encode_varint(t))


        # Payload
        header = self.MAGIC + struct.pack("B", self.VERSION)

        body = b"".join([

            struct.pack("I", len(bi)), bi,

            struct.pack("I", len(tok)), tokb,

            struct.pack("I", len(wd)), wd
        ])


        payload = header + body


        # CRC
        payload += struct.pack("I", zlib.crc32(payload))


        # AES-GCM
        nonce = os.urandom(12)

        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)

        enc, tag = cipher.encrypt_and_digest(payload)


        return base64.b64encode(tag + nonce + enc).decode()


    # =====================================================
    # LOAD
    # =====================================================

    def load(self, blob):

        raw = base64.b64decode(blob)

        tag   = raw[:16]
        nonce = raw[16:28]
        data  = raw[28:]


        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)


        try:
            dec = cipher.decrypt_and_verify(data, tag)

        except Exception:
            raise PermissionError("Integrity Check Failed")


        # Header
        if dec[:4] != self.MAGIC:
            raise ValueError("Bad File")

        if dec[4] != self.VERSION:
            raise ValueError("Version Mismatch")


        ptr = 5


        # Bigrams
        l = struct.unpack_from("I", dec, ptr)[0]
        ptr += 4

        bi = json.loads(dec[ptr:ptr+l])
        ptr += l


        # Tokens
        n = struct.unpack_from("I", dec, ptr)[0]
        ptr += 4

        tok = []

        for _ in range(n):

            v, ptr = self._decode_varint(dec, ptr)

            tok.append(v)


        # Dictionary
        l = struct.unpack_from("I", dec, ptr)[0]
        ptr += 4

        wd = json.loads(dec[ptr:ptr+l])
        ptr += l


        # CRC
        crc = struct.unpack_from("I", dec, ptr)[0]


        if zlib.crc32(dec[:-4]) != crc:
            raise ValueError("Corrupted File")


        return self.decode(tok, wd, bi)



# =====================================================
# TEST
# =====================================================

if __name__ == "__main__":

    am = AlphaMap("amrita_cse_2026_secure")

    text = "Hello\tAmrita!   I am a Student.   This is   lossless."

    print("\n--- AlphaMap Unified v5 ---\n")

    print("Original:", repr(text))


    blob = am.save(text)

    print("Encrypted:", blob[:60], "...")


    dec = am.load(blob)

    print("Decoded :", repr(dec))

    print("Success :", dec == text)
