#!/usr/bin/env python3

import os, sys, io, re, json, time, struct, argparse, hashlib, zlib
from Crypto.Cipher import AES


# =====================================================
# BASE CORE
# =====================================================

class AlphaMapCore:

    MAGIC = b"AMPS"
    VERSION = 9

    WORD_LIMIT = 1000
    BIGRAM_BASE = 1000
    SPELL = 1999


    def __init__(self, key):

        self.key = hashlib.sha256(key.encode()).digest()

        self.word_to_id = {}
        self.auto_bigrams = {}

        self.manual = {
            "i am": 1950,
            "thank you": 1951,
            "good morning": 1952
        }

        self.char = {chr(i+96): i for i in range(1,27)}
        self.ichar = {i: chr(i+96) for i in range(1,27)}


    # ---------------- VARINT ----------------

    def encode_varint(self, n):

        out = bytearray()

        while n >= 0x80:
            out.append((n & 0x7F) | 0x80)
            n >>= 7

        out.append(n)
        return out


    def decode_varint(self, s):

        res = 0
        shift = 0

        while True:

            b = s.read(1)[0]

            res |= (b & 0x7F) << shift

            if not (b & 0x80):
                return res

            shift += 7


    # ---------------- TRAIN ----------------

    def train(self, text):

        tokens = re.findall(r'\S+|\s+', text.lower())

        wf, bf = {}, {}

        for i,x in enumerate(tokens):

            wf[x] = wf.get(x,0)+1

            if i<len(tokens)-1:

                bg = x + tokens[i+1]
                bf[bg] = bf.get(bg,0)+1


        r = sorted(wf.items(), key=lambda x:x[1], reverse=True)[:self.WORD_LIMIT]

        self.word_to_id = {w:i for i,(w,_) in enumerate(r)}


        rb = sorted(bf.items(), key=lambda x:x[1], reverse=True)[:100]

        self.auto_bigrams = {
            p:self.BIGRAM_BASE+i
            for i,(p,_) in enumerate(rb)
        }


    # ---------------- ENCODE ----------------

    def encode(self, text):

        words = re.findall(r'\S+|\s+', text)
        low   = [x.lower() for x in words]

        t = []
        i = 0


        while i<len(words):

            c = 2 if words[i].isupper() else 1 if words[i][:1].isupper() else 0


            found = False

            if i+1<len(words):

                p = low[i]+low[i+1]

                for d in (self.manual,self.auto_bigrams):

                    if p in d:

                        t.append(d[p]*3+c)
                        i+=2
                        found=True
                        break

            if found: continue


            lw = low[i]


            if lw in self.word_to_id:

                t.append(self.word_to_id[lw]*3+c)

            else:

                t.append(self.SPELL*3+c)
                t.append(len(lw))

                for ch in lw:

                    v = self.char.get(ch,0)
                    t.append(v+970 if v else ord(ch))


            i+=1


        return t


    # ---------------- DECODE ----------------

    def decode(self, tok, wd, bi):

        inv  = {i:w for w,i in wd.items()}
        invb = {v:k for k,v in bi.items()}
        invm = {v:k for k,v in self.manual.items()}

        out=[]
        it=iter(tok)


        for v in it:

            b,c=v//3,v%3


            if b==self.SPELL:

                ln=next(it)

                cs=[]

                for _ in range(ln):

                    x=next(it)

                    cs.append(
                        self.ichar[x-970] if 971<=x<=996 else chr(x)
                    )

                w="".join(cs)


            elif b in invm: w=invm[b]
            elif b in invb: w=invb[b]
            else: w=inv.get(b,"<?>")



            out.append(
                w.upper() if c==2 else
                w.capitalize() if c==1 else
                w.lower()
            )


        return "".join(out)



# =====================================================
# STREAM ENGINE
# =====================================================

class AlphaMapStream(AlphaMapCore):


    def encrypt_stream(self, text, out):

        if not self.word_to_id:
            self.train(text)


        tok = self.encode(text)

        bi = json.dumps(self.auto_bigrams).encode()
        wd = json.dumps(self.word_to_id).encode()


        buf=io.BytesIO()

        buf.write(self.MAGIC+struct.pack("B",self.VERSION))

        buf.write(struct.pack("I",len(bi))+bi)
        buf.write(struct.pack("I",len(wd))+wd)

        buf.write(struct.pack("I",len(tok)))

        for t in tok:
            buf.write(self.encode_varint(t))


        data=buf.getvalue()
        data+=struct.pack("I",zlib.crc32(data))


        nonce=os.urandom(12)

        cipher=AES.new(self.key,AES.MODE_GCM,nonce=nonce)

        enc,tag=cipher.encrypt_and_digest(data)


        out.write(tag+nonce+enc)



    def decrypt_stream(self, inp):

        tag=inp.read(16)
        nonce=inp.read(12)
        data=inp.read()


        cipher=AES.new(self.key,AES.MODE_GCM,nonce=nonce)

        dec=cipher.decrypt_and_verify(data,tag)


        crc=struct.unpack("I",dec[-4:])[0]

        if zlib.crc32(dec[:-4])!=crc:
            raise ValueError("Corrupt file")


        s=io.BytesIO(dec[:-4])


        if s.read(4)!=self.MAGIC:
            raise ValueError("Bad file")


        s.read(1)


        l=struct.unpack("I",s.read(4))[0]
        bi=json.loads(s.read(l))

        l=struct.unpack("I",s.read(4))[0]
        wd=json.loads(s.read(l))

        n=struct.unpack("I",s.read(4))[0]


        tok=[self.decode_varint(s) for _ in range(n)]


        return self.decode(tok,wd,bi)



# =====================================================
# PRO ENGINE (BITPACK + BINARY DICT)
# =====================================================

class AlphaMapPro:

    MAGIC=b"AMXP"
    VERSION=9

    SPELL_ID=0xFFFFFFFF


    def __init__(self,key):

        self.key=hashlib.sha256(key.encode()).digest()

        self.word_to_id={}
        self.id_to_word={}


    # ---------- DICT ----------

    def save_dictionary(self,path):

        with open(path,"wb") as f:

            for w,i in self.word_to_id.items():

                b=w.encode()

                f.write(struct.pack("II",i,len(b))+b)



    def load_dictionary(self,path):

        self.word_to_id={}

        with open(path,"rb") as f:

            while True:

                h=f.read(8)

                if not h: break

                i,l=struct.unpack("II",h)

                w=f.read(l).decode()

                self.word_to_id[w]=i


        self.id_to_word={i:w for w,i in self.word_to_id.items()}



    def train(self,text,limit=2000):

        tok=re.findall(r'\S+|\s+',text.lower())

        f={}

        for t in tok: f[t]=f.get(t,0)+1


        top=sorted(f.items(),key=lambda x:x[1],reverse=True)[:limit]

        self.word_to_id={w:i for i,(w,_) in enumerate(top)}

        self.id_to_word={i:w for w,i in self.word_to_id.items()}



    # ---------- TOKEN ----------

    def encode_token(self,w):

        case=2 if w.isupper() else 1 if w[:1].isupper() else 0

        wid=self.word_to_id.get(w.lower(),self.SPELL_ID)

        return (wid<<2)|case



    def decode_token(self,t):

        case=t&3
        wid=t>>2

        w=self.id_to_word.get(wid,"<?>")

        if case==2: return w.upper()
        if case==1: return w.capitalize()

        return w



    # ---------- STREAM ----------

    def process(self,inp,out,mode="e"):


        if mode=="e":

            nonce=os.urandom(12)

            cipher=AES.new(self.key,AES.MODE_GCM,nonce=nonce)


            with open(inp,"r",encoding="utf-8") as fin, open(out,"wb") as fout:

                fout.write(b"\x00"*16)
                fout.write(nonce)


                while True:

                    chunk=fin.read(65536)

                    if not chunk: break


                    words=re.findall(r'\S+|\s+',chunk)

                    buf=bytearray()


                    for w in words:

                        t=self.encode_token(w)

                        buf.extend(struct.pack("I",t))


                        if (t>>2)==self.SPELL_ID:

                            b=w.encode()

                            buf.extend(struct.pack("H",len(b))+b)


                    enc=cipher.encrypt(buf)

                    fout.write(enc)


                tag=cipher.digest()

                fout.seek(0)

                fout.write(tag)


        else:

            with open(inp,"rb") as fin, open(out,"w",encoding="utf-8") as fout:

                tag=fin.read(16)
                nonce=fin.read(12)

                enc=fin.read()


                cipher=AES.new(self.key,AES.MODE_GCM,nonce=nonce)

                dec=cipher.decrypt_and_verify(enc,tag)


                s=io.BytesIO(dec)


                while True:

                    b=s.read(4)

                    if not b: break


                    t=struct.unpack("I",b)[0]


                    if (t>>2)==self.SPELL_ID:

                        l=struct.unpack("H",s.read(2))[0]

                        w=s.read(l).decode()

                        case=t&3

                        if case==2: w=w.upper()
                        elif case==1: w=w.capitalize()

                        fout.write(w)


                    else:

                        fout.write(self.decode_token(t))



# =====================================================
# CLI
# =====================================================

def main():

    p=argparse.ArgumentParser("AlphaMap Ultimate v9")

    p.add_argument("engine",choices=["core","stream","pro"])
    p.add_argument("mode",choices=["train","e","d"])
    p.add_argument("input")
    p.add_argument("output")

    p.add_argument("-k","--key",required=True)
    p.add_argument("-d","--dict")

    a=p.parse_args()


    if a.engine=="pro":

        am=AlphaMapPro(a.key)

        if a.mode=="train":

            txt=open(a.input,"r",encoding="utf-8").read()

            am.train(txt)

            am.save_dictionary(a.output)

            print("Dictionary saved")


        else:

            if not a.dict:
                print("Need --dict")
                return

            am.load_dictionary(a.dict)

            am.process(a.input,a.output,a.mode)

            print("Done")


    else:

        am=AlphaMapStream(a.key)


        if a.mode=="e":

            txt=open(a.input,"r",encoding="utf-8").read()

            out=open(a.output,"wb")

            am.encrypt_stream(txt,out)

            print("Encrypted")


        elif a.mode=="d":

            inp=open(a.input,"rb")

            txt=am.decrypt_stream(inp)

            open(a.output,"w",encoding="utf-8").write(txt)

            print("Decrypted")


        else:

            txt=open(a.input,"r",encoding="utf-8").read()

            am.train(txt)

            open(a.output,"w").write("Trained")

            print("Trained")



if __name__=="__main__":

    try:
        main()
    except Exception as e:
        print("Error:",e)
