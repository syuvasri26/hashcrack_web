# 🔴 HashCrack Web

> A real-time web-based password hash cracking tool built with Python Flask — developed as a Red Team Internship Project.

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.x-black?style=flat-square&logo=flask)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## 📌 About the Project

**HashCrack web** is a full-stack web application for password hash cracking, built using Python Flask (backend) and HTML/CSS/JavaScript (frontend). It features a hacker-themed dark dashboard, real-time live logs, multiple attack modes, and an export system — making it a professional-grade tool for security research and learning.

This project was built as part of a **15-day Red Team Cybersecurity Internship** to demonstrate knowledge of hashing algorithms, dictionary/brute-force attacks, web development, and security concepts.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔐 Login System | Session-based authentication with multiple user accounts |
| 📊 Live Dashboard | Real-time stats — hashes cracked, speed, success rate |
| ⚡ Wordlist Attack | Dictionary-based hash cracking using a wordlist file |
| 💥 Brute Force Attack | Try all character combinations up to a given length |
| 🔢 Multi-Hash Attack | Crack multiple hashes at once |
| ⚙️ Hash Generator | Generate MD5, SHA1, SHA256 hashes + batch generation |
| 📋 History Table | Full log of all past cracking sessions |
| 💾 Export Reports | Download results as TXT, CSV, or JSON |

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Backend | Python 3 | Core logic and server |
| Web Framework | Flask | Routes, sessions, API endpoints |
| Hashing | hashlib (built-in) | MD5, SHA1, SHA256, SHA512 |
| Threading | threading (built-in) | Background cracking jobs |
| Frontend | HTML5 + CSS3 + JavaScript | UI and real-time updates |
| Real-time | JavaScript fetch() + polling | Live log updates every 800ms |
| Styling | Custom CSS (dark hacker theme) | Dashboard UI |

---

## 📁 Project Structure

```
HashCrack_Pro_Web/
│
├── app.py                  ← Flask backend (all routes + API logic)
├── requirements.txt        ← Python dependencies
│
└── templates/
    ├── base.html           ← Sidebar layout + dark theme
    ├── login.html          ← Login page
    ├── dashboard.html      ← Stats dashboard
    ├── crack.html          ← Wordlist, Brute Force & Multi-Hash tabs
    ├── generator.html      ← Hash Generator + Batch Generator
    └── history.html        ← Full results history table
```

---

## 🚀 How to Run (Kali Linux)

### Step 1 — Clone the Repository
```bash
git clone https://github.com/syuvasri26/hashcrack_web.git
cd hashcrack_web
```

### Step 2 — Install Dependencies
```bash
pip install flask --break-system-packages
```

### Step 3 — Run the App
```bash
python3 app.py
```

### Step 4 — Open in Browser
```
http://127.0.0.1:5000
```

---

## 🔐 Login Credentials

| Username | Password |
|---|---|
| admin | admin123 |
| redteam | crack123 |

---

## ⚙️ How It Works

```
Browser (HTML/JS)
      │
      │  HTTP POST (hash + wordlist)
      ▼
Flask Backend (app.py)
      │
      │  Creates job ID → starts background thread
      ▼
Python Thread (hashlib cracking logic)
      │
      │  Updates active_jobs{} with live stats
      ▼
JavaScript Polling (every 800ms)
      │
      │  Fetches /status/<job_id> → parses JSON
      ▼
Browser updates live log + speed stats on screen
```

**Key concept:** Flask never blocks the browser. It starts a background thread for cracking and JavaScript polls for updates every 800ms — this is what makes it "real-time."

---

## 🧪 Quick Test

```bash
# Generate a test hash in terminal
echo -n "password123" | md5sum
```

Copy the output hash → paste into the Wordlist Attack tab → Load sample wordlist → Start Cracking!

---

## 🛡️ Supported Hash Types

- MD5
- SHA1
- SHA256
- SHA512
- Auto-detection by hash length

---

## 📊 Attack Modes

### 1. Wordlist Attack
Reads passwords from a `.txt` wordlist file, hashes each one, and compares it against the target hash.

### 2. Brute Force Attack
Generates every possible combination of characters (a-z, 0-9) up to a specified length and tries each one.

### 3. Multi-Hash Attack
Accepts multiple hashes at once and runs a wordlist attack against all of them simultaneously.

---

## 💡 Defense Concepts (What This Tool Teaches)

- **Why MD5/SHA1 are weak** — fast to compute = fast to crack
- **Use bcrypt/argon2** — slow hashing algorithms designed for passwords
- **Salting** — adds random data before hashing to defeat precomputed attacks
- **MFA** — even if password is cracked, second factor protects the account

---

## 🔮 Future Improvements

- [ ] Salted hash detection and cracking
- [ ] Hash rate benchmarking
- [ ] API integration with Hashcat (GPU-based cracking)
- [ ] Rainbow table support
- [ ] Docker containerization

---

## ⚠️ Disclaimer

This tool is built **strictly for educational purposes** as part of a cybersecurity internship. It is intended to demonstrate how hash cracking works and why strong password practices matter. **Do not use this tool against systems or accounts you do not own or have explicit permission to test.**


## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
