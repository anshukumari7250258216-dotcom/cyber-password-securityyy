# 🛡️ CyberShield // Advanced Password Security & Entropy Lab

[![BCA Academic Project](https://img.shields.io/badge/Academic%20Project-BCA%202nd%20Year-blue.svg?style=for-the-badge&logo=codeforces)](https://github.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-00f0ff.svg?style=for-the-badge)](LICENSE)
[![Zero-Knowledge](https://img.shields.io/badge/Privacy-100%25%20Client--Side-10b981.svg?style=for-the-badge&logo=shield)](https://github.com)
[![Web Cryptography API](https://img.shields.io/badge/CSPRNG-crypto.getRandomValues-purple.svg?style=for-the-badge)](https://w3.org/TR/WebCryptoAPI/)
[![Standards Aligned](https://img.shields.io/badge/Standards-NIST%20SP%20800--63B-orange.svg?style=for-the-badge)](https://pages.nist.gov/800-63-3/sp800-63b.html)

> **CyberShield** is a modern, responsive, and client-side password security web application engineered for a **BCA (Bachelor of Computer Applications) 2nd Year Cybersecurity & Web Development Project**. It demonstrates mathematical Shannon entropy heuristics, educational brute-force resistance calculations, pattern vulnerability diagnostics, and cryptographically secure pseudo-random password generation (CSPRNG).

---

## 📑 Table of Contents
1. [Project Overview & Motivation](#-project-overview--motivation)
2. [Key Features & Capabilities](#-key-features--capabilities)
3. [Mathematical & Cryptographic Architecture](#-mathematical--cryptographic-architecture)
4. [File Structure](#-file-structure)
5. [Technologies Used](#-technologies-used)
6. [Local Installation & Setup (VS Code)](#-local-installation--setup-vs-code)
7. [Testing & Quality Verification Guide](#-testing--quality-verification-guide)
8. [Step-by-Step GitHub Upload Guide](#-step-by-step-github-upload-guide)
9. [Publishing to GitHub Pages](#-publishing-to-github-pages)
10. [Troubleshooting Common Issues](#-troubleshooting-common-issues)
11. [Limitations & Cybersecurity Disclaimer](#-limitations--cybersecurity-disclaimer)
12. [Future Roadmap (Final Year Scope)](#-future-roadmap-final-year-scope)
13. [License](#-license)

---

## 🎯 Project Overview & Motivation

According to cybersecurity threat intelligence reports, **over 80% of confirmed data breaches** involve weak, recycled, stolen, or brute-forced credentials. Despite widespread advice, many end-users still rely on predictable substitutions (e.g., `P@ssw0rd1!`) or repeated keyboard walks (`qwerty`, `123456`).

This project was built to address these challenges through an interactive, visual learning platform:
- **Zero-Knowledge Privacy:** Evaluates credentials entirely inside browser RAM. No passwords ever traverse the network or touch local persistent storage (`localStorage`, cookies).
- **Shannon Entropy Heuristics:** Replaces arbitrary visual scoring rules with mathematical information entropy theory ($E = L \times \log_2(R)$).
- **CSPRNG Generation:** Implements unbiased hardware entropy via the W3C Web Cryptography API (`window.crypto.getRandomValues`) rather than pseudo-random functions like `Math.random()`.
- **NIST SP 800-63B Alignment:** Emphasizes passphrase length, character space diversity, and dictionary attack resistance.

---

## ⚡ Key Features & Capabilities

### 1. Real-Time Password Strength Diagnostic
- **Real-Time Input Evaluation:** Computes score immediately as the user types without lag or external API round-trips.
- **Show/Hide Visibility Toggle:** Accessible eye-icon button with live ARIA state changes.
- **Clear Button & Character Counter:** Quick-action reset with real-time length tracking.
- **5-Tier Visual Strength Meter:** Categorizes strength into:
  - `Very Weak` (Crimson Red `#f43f5e`, < 28 bits)
  - `Weak` (Amber Orange `#f59e0b`, 28–44 bits)
  - `Medium` (Gold Yellow `#eab308`, 45–61 bits)
  - `Strong` (Neon Cyan `#06b6d4`, 62–83 bits)
  - `Very Strong` (Emerald Green `#10b981`, 84+ bits)

### 2. Cryptographic Telemetry Dashboard
- **Information Entropy (bits):** Real-time Shannon entropy calculation penalized for structural vulnerabilities.
- **Offline Brute-Force Estimation:** Displays humanized cracking time (e.g., *Instant*, *4 minutes*, *82 days*, *3,400 years*) based on documented multi-GPU hashcat cluster metrics.
- **Active Character Pool Size ($R$):** Displays active search space (numbers, uppercase, lowercase, special ASCII symbols).
- **Pattern Vulnerability Detection:** Identifies repeated characters (`aaa`, `111`), keyboard sequences (`qwerty`, `123456`), and known breach dictionary terms (`password`, `admin`, `letmein`).

### 3. Interactive Security Checklist
- Real-time criteria checklist tracking 7 essential attributes:
  1. Minimum 12 characters (16+ recommended)
  2. Uppercase letters (A–Z)
  3. Lowercase letters (a–z)
  4. Numeric digits (0–9)
  5. Special characters (`!@#$%^&*...`)
  6. No repeated character sequences
  7. No common dictionary words or keyboard walks
- Updates live with green checkmarks (`✓`) and red crosses (`✕`).

### 4. Dynamic Smart Recommendations
- Contextual suggestions tailored to missing components (e.g., *"Add at least 4 more characters"*, *"Avoid keyboard walks like 'qwerty'"*, *"Mix uppercase and lowercase"*).

### 5. Cryptographically Secure Password Generator (CSPRNG)
- **Hardware-Seeded Randomness:** Utilizes `crypto.getRandomValues(new Uint32Array(1))`.
- **Modulo Bias Elimination:** Rejects integer values that cause statistical bias in modular arithmetic.
- **Fisher-Yates Shuffle:** Cryptographically shuffles character arrays to prevent positional predictability.
- **Customizable Length:** Slider from 8 to 64 characters (default: 18).
- **Customizable Character Sets:** Uppercase, Lowercase, Digits, Special Symbols, and Ambiguous Character Exclusion (`i, l, 1, L, o, 0, O`).
- **Quick Presets:** Max Security, Easy to Read, Numeric PIN (8 digits), and Memorable Passphrase.
- **One-Click Clipboard Copy:** Safe copy with fallback mechanism and animated status feedback (`Copied!`).
- **Test in Analyzer:** Single-click transfer into the Strength Checker to inspect its cryptographic score.

### 6. Defense-in-Depth Educational Insights & Comparison Table
- Covers Brute-Force & Dictionary Attacks, Rainbow Tables, Credential Stuffing, and Multi-Factor Authentication (MFA).
- Comprehensive comparison matrix comparing Weak, Simple Substitution, Passphrase, and CSPRNG keys.

---

## 🔬 Mathematical & Cryptographic Architecture

### 1. Shannon Information Entropy Formula
Information entropy measures the unpredictability of a password string:

$$E = L \times \log_2(R)$$

Where:
- $L$ = Length of the password (number of characters)
- $R$ = Character pool size (cardinality of the alphabet):
  - Numeric digits (`0-9`): $R = 10$
  - Lowercase (`a-z`): $R = 26$
  - Uppercase (`A-Z`): $R = 26$
  - Printable ASCII symbols: $R = 33$
  - Maximum composite printable pool: $R = 10 + 26 + 26 + 33 = 95$

#### Structural Vulnerability Penalties
Real-world password crackers do not brute force blindly; they prioritize dictionary leaks, common substitutions, and keyboard runs. CyberShield applies deterministic heuristic deductions:
- **Known Dictionary / Leak Match:** $-35$ bits penalty
- **Keyboard Sequence Walk (`qwerty`, `12345`):** $-18$ bits penalty
- **Consecutive Character Repetition (`aaa`, `999`):** $-14$ bits penalty
- **Single Character Set Only:** $-10$ bits penalty

### 2. Theoretical Brute-Force Estimation Formula
The average search space required to discover an unknown key in an offline exhaustive search:

$$\text{Average Guesses} = 2^{E - 1}$$

Assuming a modern offline cracking cluster (e.g., 8 $\times$ NVIDIA RTX 4090 GPUs running Hashcat attacking fast hashes such as MD5/NTLM) performing:

$$\text{Attack Rate} = 10^{11} \text{ hashes/sec} \quad (100 \text{ Billion guesses/sec})$$

$$\text{Crack Time (seconds)} = \frac{2^{E - 1}}{10^{11}}$$

> **Important Educational Note:** Real-world authentication systems use salted key-stretching functions (such as **Argon2id**, **bcrypt**, or **PBKDF2**) and server-side rate-limiting, which reduces attack throughput from billions of guesses per second down to thousands or tens per second.

### 3. Modulo Bias Elimination in CSPRNG
Using `Math.random() * pool.length` introduces statistical skew because standard pseudo-random generators use predictable seeds (Mersenne Twister / xoroshiro128+) and modular reduction over non-power-of-two lengths produces bias. 

CyberShield generates random integers using rejection sampling:
```javascript
const maxUint32 = 0xFFFFFFFF;
const limit = maxUint32 - (maxUint32 % poolLength);

while (true) {
  window.crypto.getRandomValues(randomBuffer);
  const randVal = randomBuffer[0];
  if (randVal < limit) {
    return pool[randVal % poolLength];
  }
}
```

---

## 📁 File Structure

```
cyber-password-security/
│
├── index.html           # Main semantic HTML5 markup, accessibility hooks, SVG icons
├── style.css            # Dark cyber theme, glassmorphism, responsive grid, animations
├── script.js            # Client-side entropy engine, CSPRNG generator, UI controllers
├── README.md            # Complete academic documentation and GitHub portfolio guide
├── .gitignore           # Ignores OS files, IDE settings, and build artifacts
└── LICENSE              # Open-source MIT License
```

---

## 💻 Technologies Used

| Technology | Purpose in Project |
| :--- | :--- |
| **HTML5** | Semantic structure, ARIA roles (`progressbar`, `aria-live`), accessibility landmarks |
| **CSS3** | Modern CSS Variables, Flexbox, CSS Grid, Glassmorphism (`backdrop-filter`), Responsive Breakpoints |
| **Vanilla JavaScript (ES6+)** | DOM manipulation, regex pattern matching, algorithmic entropy computation |
| **Web Cryptography API** | Hardware-entropy random generation via `window.crypto.getRandomValues` |
| **Inline Vector Graphics (SVG)** | Scalable, high-contrast shield logo and system icons without third-party dependencies |

---

## 🚀 Local Installation & Setup (VS Code)

Follow these steps to run the project locally on your machine:

### Option A: Open with VS Code Live Server (Recommended)
1. **Open Visual Studio Code.**
2. Click **File > Open Folder...** and select the project folder (`ssp` or `cyber-password-security`).
3. If you have the **Live Server** extension installed (by Ritwick Dey):
   - Right-click `index.html` in the Explorer sidebar.
   - Click **"Open with Live Server"**.
4. The site will launch automatically at `http://127.0.0.1:5500`.

### Option B: Python Local HTTP Server
If you have Python installed, open your terminal inside the project directory:
```bash
# Python 3.x
python -m http.server 8000
```
Open your browser and navigate to `http://localhost:8000`.

### Option C: Direct File Execution
You can also directly double-click `index.html` in File Explorer to open it in Chrome, Firefox, Edge, or Brave. (All features, including CSPRNG and clipboard copy, are fully functional).

---

## 🧪 Testing & Quality Verification Guide

Verify that all interactive features and edge cases behave correctly:

| Test Case | Input / Action | Expected Result |
| :--- | :--- | :--- |
| **1. Empty State** | Empty input | Meter is at 0%, badge shows *"Awaiting Input"*, checklist shows `0 / 7 Met`, crack time shows *"Instant"*. |
| **2. Short / Very Weak** | `12345` or `abc` | Meter indicates `Very Weak` (Red), detects sequence/dictionary match, warns user. |
| **3. Known Leak** | `password123` | Pattern penalty triggers ($-35$ bits), checklist flags dictionary leak, recommendation advises immediate change. |
| **4. Repeated Chars** | `aaaa1111!!!!` | Repetition rule flags continuous clusters, penalty applied. |
| **5. High-Entropy Passphrase** | `quantum-nexus-beacon-galaxy` | Length $\ge 24$, zero pattern penalties, crack time indicates Centuries/Millennia, checklist shows 6–7 met. |
| **6. Show/Hide Toggle** | Click Eye icon | Password changes between masked dots and plain readable text. Icon toggles. |
| **7. Generator Slider** | Drag slider from 8 to 32 | Number display updates live, password regenerates at exact selected length. |
| **8. Generator Presets** | Click "PIN (8 Digits)" | Slider sets to 8, only numbers enabled, generates 8-digit numeric PIN. |
| **9. Clipboard Copy** | Click "Copy" | Toast notification *"Password copied securely to clipboard!"* appears for 2.2s. |
| **10. Zero-Knowledge Audit** | Press `F12` > Network Tab | Type passwords and generate keys. Verify **0 network requests** are sent. |

---

## 📤 Step-by-Step GitHub Upload Guide

Execute the following commands in your terminal (Command Prompt, PowerShell, or Git Bash) inside the project folder:

### 1. Initialize Git Repository
```bash
git init
```

### 2. Configure Git Identity (If not set previously)
```bash
git config --global user.name "YourName"
git config --global user.email "your.email@example.com"
```

### 3. Stage All Project Files
```bash
git add .
```

### 4. Create Initial Commit
```bash
git commit -m "feat: complete responsive password security & entropy analyzer project"
```

### 5. Link Local Repository to GitHub
1. Go to [GitHub](https://github.com) and sign in.
2. Click the **"+"** icon in the top right corner and choose **"New repository"**.
3. Name your repository (e.g., `cyber-password-security` or `cybershield-authguard`).
4. Set visibility to **Public**.
5. Leave "Add a README file" **unchecked** (we already created one).
6. Click **Create repository**.
7. Copy your remote repository URL and run:

```bash
# Rename branch to main
git branch -M main

# Link remote origin (replace with your actual GitHub username and repository name)
git remote add origin https://github.com/YOUR_USERNAME/cyber-password-security.git

# Push files to GitHub
git push -u origin main
```

---

## 🌐 Publishing to GitHub Pages

Deploy your website online for free so anyone (including professors and interviewers) can test it:

1. Open your repository on **GitHub**.
2. Click on the **Settings** tab (gear icon at the top of the repository).
3. In the left-hand sidebar, click on **Pages** (under the "Code and automation" section).
4. Under **"Build and deployment"**:
   - Source: Select **"Deploy from a branch"**.
   - Branch: Select **`main`** and folder **`/ (root)`**.
   - Click **Save**.
5. Wait approximately 1–2 minutes for GitHub Actions to build and deploy.
6. Refresh the page. You will see a green banner:
   > *Your site is live at `https://YOUR_USERNAME.github.io/cyber-password-security/`*
7. Copy this URL and add it to your GitHub repository's "About" section as the live demo link.

---

## 🔧 Troubleshooting Common Issues

### Issue 1: "fatal: remote origin already exists"
If you previously configured a git remote:
```bash
git remote remove origin
git remote add origin https://github.com/YOUR_USERNAME/cyber-password-security.git
git push -u origin main
```

### Issue 2: Copy to Clipboard Does Not Work
- Modern browsers enforce that `navigator.clipboard` is only accessible over HTTPS or `localhost` (Secure Context).
- CyberShield includes an automated fallback (`document.execCommand('copy')`) so copying works even when opened directly from file system (`file:///`).

### Issue 3: CSS / JS Not Updating After Edits
- Browsers occasionally cache static files. Press `Ctrl + F5` (Windows) or `Cmd + Shift + R` (Mac) to perform a hard reload.

---

## ⚠️ Limitations & Cybersecurity Disclaimer

1. **Educational Heuristic Scope:** The Shannon entropy calculation and brute-force estimations are heuristic models intended for academic analysis. They provide an educational proxy of search space complexity, not a real-time intrusion prevention system (IPS).
2. **Key Stretching Variance:** Real authentication backends implement password hashing algorithms (e.g. **Argon2id**, **bcrypt**, **PBKDF2**) with configurable memory cost and work factors that exponentially increase hash computation time compared to raw MD5/NTLM GPU rates.
3. **Phishing & Social Engineering:** High entropy protects against guessing and brute-force attacks; however, it cannot prevent credential theft via phishing, keyloggers, session hijacking, or malicious browser extensions. Always utilize **Multi-Factor Authentication (MFA)**.

---

## 🔮 Future Roadmap (Final Year Scope)

If extending this project for a BCA 3rd Year / Final Year Capstone Project, consider:
- **HIBP Pwned Passwords Integration:** Implement k-Anonymity SHA-1 API checks to verify if a password has appeared in historical public data leaks without disclosing the plaintext.
- **WebAssembly Argon2 Benchmarking:** Compile the reference C implementation of Argon2 to WebAssembly (Wasm) to benchmark real-time key-stretching costs inside the client's browser.
- **Zxcvbn Entropy Modeling:** Integrate realistic dictionary pattern matching utilizing spatial pattern and l33t dictionary graphs.
- **Biometric WebAuthn / FIDO2 Playground:** Demonstrate passkey registration and public-key credential creation.

---

## 📄 License

This project is open-source and released under the **[MIT License](LICENSE)**.

```
Copyright (c) 2026 CyberShield Project Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

<div align="center">
  <sub>Developed for BCA 2nd Year Cybersecurity & Web Development Curriculum &bull; Designed with Security & Privacy in Mind</sub>
</div>
