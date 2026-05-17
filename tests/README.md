# AlphaMap v11 — Secure Compression + Encryption Engine

AlphaMap is a **custom-built data transformation engine** that combines:

>  Compression +  Encoding +  Encryption
> into a **single optimized pipeline**

Unlike traditional systems where compression and encryption are separate, AlphaMap integrates them into a unified architecture for **efficiency, security, and experimentation**.

---

##  What Makes AlphaMap Unique

### 1. Bit-Level Encoding (Not Byte-Based)

* Uses **custom bit-packing** instead of naive byte storage
* Significantly reduces storage overhead
* Efficient token representation using calculated bit sizes

---

### 2. Dictionary-Based Compression Engine

* Learns frequent words and patterns
* Encodes them into compact IDs
* Preserves whitespace and structure

---

### 3. Smart Hybrid Compression

* Tries **AlphaMap compression**
* Falls back to **zlib** if it performs better

 This avoids worst-case scenarios where custom compression fails

---

### 4. Streaming Architecture

* Processes data in chunks (not full memory load)
* Scalable for large files
* More realistic system design

---

### 5. Secure Encryption (AES-GCM)

* AES-256 encryption using `pycryptodome`
* Authenticated encryption (ensures integrity + confidentiality)
* Uses:

  * PBKDF2 key derivation (200,000 rounds)
  * Random salt + nonce

---

### 6. Data Integrity Protection

* CRC32 checksum verification
* Detects:

  * File corruption
  * Tampering

---

### 7. Flexible Dictionary Handling

* Option to:

  * Embed dictionary inside file
  * Use external reusable dictionary

---

## File Format Design

AlphaMap defines a custom binary format:

```
[ MAGIC | VERSION | FLAGS | SALT | NONCE |
  HEADER_LEN | HEADER | COMPRESSED_DATA | TAG ]
```

### Key Features:

* Self-contained metadata
* Secure encryption layer
* Compression-aware decoding

---

## Installation

```bash
pip install pycryptodome
```

---

##  Usage

### Encrypt File

```bash
python alphamap_v11.py e input.txt output.am11 -k mypassword
```

---

### Decrypt File

```bash
python alphamap_v11.py d output.am11 output.txt -k mypassword
```

---

### Create Dictionary

```bash
python alphamap_v11.py train corpus.txt dict.json
```

---

### Advanced Usage

#### Use external dictionary:

```bash
python alphamap_v11.py e input.txt output.am11 -k pass --no-embed -d dict.json
```

#### Decrypt with dictionary:

```bash
python alphamap_v11.py d output.am11 output.txt -k pass -d dict.json
```

---

## Pipeline Overview

```
Input Text
   ↓
Tokenization
   ↓
Dictionary Encoding
   ↓
Bit Packing
   ↓
Compression (AlphaMap / zlib fallback)
   ↓
Checksum
   ↓
AES-GCM Encryption
   ↓
Output File (.am11)
```

---

## Example Output

* Original size → X bytes
* Compressed → Y bytes
* Final encrypted → Z bytes

(Printed automatically after execution)

---

## Limitations

* Optimized mainly for **text data**
* OOV (out-of-vocabulary) words increase size
* Not yet benchmarked against advanced compressors (e.g., Brotli, LZMA)

---

## Future Improvements (Currently Working On)

* Performance optimization (faster encoding/decoding)
* Benchmarking vs industry compression tools
* Web interface for file upload + processing
* Packaging as installable CLI tool (`pip install alphamap`)
* Adaptive / dynamic dictionary updates
* Visualization of compression efficiency
* Parallel processing support

---

## Engineering Highlights

This project demonstrates:

* Low-level **bit manipulation**
* Custom **file format design**
* Secure **cryptographic implementation**
* Hybrid **compression strategies**
* Real-world **system architecture thinking**

---

## Note on Development

Parts of the implementation were developed with **AI assistance**, but:

* Core idea
* Architecture design
* System integration

are independently designed and iterated.

---

## Author

**Shre Raam P J**

* GitHub: https://github.com/SHRE-RAAM-P-J
* LinkedIn: https://www.linkedin.com/in/shre-raam/

---

## ⭐ Final Thought

AlphaMap is an exploration into building a **next-generation data transformation pipeline** — combining compression and encryption into a single intelligent system.

If you find this interesting, consider ⭐ starring the repo!
