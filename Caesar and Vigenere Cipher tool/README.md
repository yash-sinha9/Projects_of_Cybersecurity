# Classical Cipher & Cryptanalysis Suite: Caesar and Vigenère

A classical cryptography engine and automated cryptanalysis suite built from scratch in Python and Modern Web Standards (HTML5 / Vanilla CSS / ES6 JavaScript).

---

## 🎯 Project Overview & Key Industry Competencies

As highlighted in the industry cryptography roadmap:
> *"Understanding classical ciphers builds the intuition for modern encryption. Building a tool that both encrypts and breaks ciphers shows programming and analytical skills together."*

This project demonstrates:
1. **Classical Cipher Algorithm Implementation**: Mathematical representation of monoalphabetic shift (Caesar) and polyalphabetic periodic shift (Vigenère).
2. **Frequency Analysis for Cipher Breaking**: Automated cryptanalysis using **Chi-Squared ($\chi^2$) Goodness-of-Fit** and the **Index of Coincidence (IoC)**.
3. **Python & Full-Stack Tool Development**: Standalone Python CLI engine with zero third-party dependencies, paired with an interactive cyber-themed Web Studio.
4. **Intuition for Modern Cryptography**: Deep appreciation of why **Shannon's Confusion and Diffusion** and modern primitives (AES-256, RSA, ECC) superseded classical schemes.

---

## 🚀 Key Features

### 1. Caesar Cipher Engine
- **Encryption & Decryption**: Modular arithmetic $C_i = (P_i + k) \pmod{26}$, preserving case and non-alphabetic punctuation.
- **Automated Cracker**: Computes Chi-Squared ($\chi^2$) statistic against standard English letter frequencies (ETAOIN...) across all 26 shifts to instantly crack the cipher without the key.

### 2. Vigenère Cipher Engine
- **Polyalphabetic Encryption**: Periodic substitution using an arbitrary alphabetic keyword $K$: $C_i = (P_i + K_{j \pmod L}) \pmod{26}$.
- **Automated Key Length Detection**: Calculates the average **Index of Coincidence (IoC)** across interleaved slices ($k \in [1, 16]$) to identify key length without manual inspection.
- **Coset Slicing & Auto-Key Recovery**: Partitions ciphertext into $L$ independent monoalphabetic streams, solves each via Caesar frequency analysis, and reconstructs the full keyword automatically.

### 3. Interactive Web Studio (`index.html`)
- Dark-mode glassmorphic interface with glowing cyber accents.
- Live letter frequency distribution spectrum comparing input text frequencies with natural English norms.
- Real-time **IoC** and **Chi-Squared** metric gauges.
- One-click **Auto-Crack** breakdown panel showing intermediate statistical evidence.
- Comprehensive **Interview Q&A Guide** embedded directly in the application.

---

## 📁 Repository Structure

```
Caesar and Vigenere Cipher tool/
├── cipher_tool.py    # Complete Python CLI & Cryptanalysis Engine
├── index.html        # Interactive Web Dashboard
├── style.css         # Modern Cyberpunk / Glassmorphism Stylesheet
├── app.js            # Client-side Cryptanalysis & Visualizer Logic
└── README.md         # Architecture, Mathematics & Interview Prep Guide
```

---

## 💻 Usage Instructions

### Running the Python Suite (`cipher_tool.py`)

#### Interactive Menu:
```bash
python cipher_tool.py --interactive
```

#### Automated Self-Test & Demonstration:
```bash
python cipher_tool.py --demo
```

#### Command-Line Operations:
```bash
# Encrypt with Caesar (shift 7):
python cipher_tool.py --cipher caesar --mode encrypt --text "CONFIDENTIAL MESSAGE" --shift 7

# Auto-crack a Caesar ciphertext:
python cipher_tool.py --cipher caesar --mode crack --text "JVUMPGLUAPHS TLZZHNL"

# Encrypt with Vigenère (key 'CIPHER'):
python cipher_tool.py --cipher vigenere --mode encrypt --text "SECURITY INTERVIEW DEMO" --key "CIPHER"

# Auto-crack a Vigenère ciphertext:
python cipher_tool.py --cipher vigenere --mode crack --text "UMRWBPAQ KQAMVCQGE LSTQ"

# Analyze Letter Frequency and Index of Coincidence:
python cipher_tool.py --mode analyze --text "YOUR CIPHERTEXT HERE"
```

### Running the Web Studio (`index.html`)
Simply double-click `index.html` or open it in any modern browser (Chrome, Edge, Firefox, Safari). No installation or build steps required.

---

## 📐 Mathematical Foundations

### 1. Chi-Squared ($\chi^2$) Goodness-of-Fit
$$\chi^2 = \sum_{i=\text{'A'}}^{\text{'Z'}} \frac{(O_i - E_i)^2}{E_i}$$
Where $O_i$ is the observed count of letter $i$, and $E_i = N \times f_{\text{English}}(i)$ is the expected frequency. The shift yielding the lowest $\chi^2$ corresponds to plain English.

### 2. Index of Coincidence (IoC)
$$\text{IoC} = \frac{\sum_{i=\text{'A'}}^{\text{'Z'}} f_i (f_i - 1)}{N (N - 1)}$$
- **Monolingual English Text**: $\text{IoC} \approx 0.0667$
- **Uniform Random / Heavy Polyalphabetic**: $\text{IoC} \approx 0.0385$

---

## 🛡️ Interview Talking Points: Classical vs Modern Ciphers

| Metric | Caesar / Monoalphabetic | Vigenère / Polyalphabetic | Modern Block Ciphers (AES-256) |
| :--- | :--- | :--- | :--- |
| **Key Space** | 26 shifts ($< 2^5$) | $26^L$ (typically $2^{20} - 2^{50}$) | $2^{256} \approx 1.15 \times 10^{77}$ |
| **Resistance to Frequency Attack** | Vulnerable ($\chi^2$ auto-crack) | Vulnerable via IoC & coset slicing | Immune (flat statistical distribution) |
| **Diffusion** | Zero ($1$ char change $\to 1$ char change) | Zero ($1$ char change $\to 1$ char change) | Full Avalanche Effect (1 bit changes $\sim 50\%$ of ciphertext) |
| **Confusion** | Linear shift ($x + k$) | Linear shift ($x + k_j$) | Non-linear S-Boxes and finite field inversion in $GF(2^8)$ |
