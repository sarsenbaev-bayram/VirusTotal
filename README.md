# 🔐 OWASP Security Scanner

> **Secure Web Applications Development: OWASP Security Criteria**
>
> A full-stack security scanner built with **FastAPI** + **Aiogram** (Telegram bot),
> powered by **VirusTotal** and **Google Gemini API**, following OWASP Top 10 principles.

---

## 📁 Project Structure

```
owasp-telegram-bot/
├── main.py                        # Entry point — runs bot + web concurrently
├── Dockerfile                     # Secure Docker image configuration
├── docker-compose.yml             # Orchestration for easy deployment
├── config.py                      # Centralized env-var config (OWASP A05)
├── requirements.txt
├── .env.example                   # Template — copy to .env and fill values
├── .gitignore
│
├── bot/                           # Telegram Bot (Aiogram v3)
│   ├── bot.py                     # Bot + dispatcher factory
│   ├── locales.py                 # Multi-language message strings (EN/UZ)
│   ├── handlers/
│   │   ├── start.py               # /start command
│   │   ├── scan_url.py            # /scan_url command
│   │   ├── scan_hash.py           # /scan_hash command
│   │   └── language.py            # /language command (EN/UZ switch)
│   └── middlewares/
│       ├── rate_limiter.py        # Per-user rate limiting middleware
│       └── i18n.py                # Internationalization middleware
│
├── web/                           # Web App (FastAPI)
│   ├── app.py                     # App factory + security headers middleware
│   ├── routers/
│   │   ├── scan.py                # POST /scan/url  POST /scan/hash
│   │   └── history.py             # GET /history
│   └── templates/
│       ├── base.html              # Dark-mode layout + navbar
│       ├── index.html             # Homepage with scan forms
│       ├── results.html           # Scan results with AI analysis
│       └── history.html          # Scan history dashboard
│
├── services/                      # Shared business logic
│   ├── validator.py               # Input validation & sanitization (OWASP A03)
│   ├── virustotal.py              # VirusTotal API v3 client (async)
│   ├── gemini_service.py          # Google Gemini integration
│   └── rate_limiter.py            # Sliding-window rate limiter (OWASP A04)
│
├── database/                      # SQLite persistence layer
│   ├── database.py                # Async SQLAlchemy engine + session
│   ├── models.py                  # ORM models (ScanResult, User)
│   └── crud.py                    # Save / read records (no raw SQL)
│
├── data/                          # Auto-created — SQLite database file
└── logs/                          # Auto-created — rotating log files
```

---

## 🌍 Multi-Language Support
The bot now supports both **Uzbek** and **English**. The language is automatically detected from Telegram settings upon first use, but can be manually changed.

- **Command**: `/language`
- **Output**: Interactive buttons to switch between 🇺🇿 O'zbekcha and 🇺🇸 English.
- **AI Analysis**: Gemini explanations are automatically generated in the user's selected language.

---

## 🐳 Docker Deployment
You can now deploy the entire system using Docker for better consistency and security.

1. **Configure Environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your real API keys
   ```

2. **Run with Docker Compose**:
   ```bash
   docker-compose up -d --build
   ```

The web app will be available at `http://localhost:8000` and the bot will start polling automatically.

---

## 🚀 Setup Instructions (Manual)

### Step 1 — Create a virtual environment
```powershell
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate     # macOS/Linux
```

### Step 2 — Install dependencies
```powershell
pip install -r requirements.txt
```

### Step 3 — Run the application
```powershell
python main.py
```

---

## 🤖 Telegram Bot Commands

| Command | Description |
|---|---|
| `/start` | Welcome message + instructions |
| `/scan_url` | Scan a URL for threats |
| `/scan_hash` | Scan a file hash (MD5/SHA1/SHA256) |
| `/language` | Change bot language (EN/UZ) |

---

## 🔐 OWASP Top 10 Security Measures

| OWASP | Risk | Mitigation Implemented |
|---|---|---|
| **A01** | Broken Access Control | Rate limiting blocks abuse |
| **A02** | Cryptographic Failures | All API keys in `.env` — never hardcoded |
| **A03** | Injection | Strict input validation; ORM only — zero raw SQL |
| **A04** | Insecure Design | Sliding-window rate limiter (5 req/min) |
| **A05** | Security Misconfiguration | OWASP security headers on every response |
| **A09** | Logging Failures | Structured logs with rotation |

---

## 📦 Tech Stack

| Component | Technology |
|---|---|
| Telegram Bot | Python + Aiogram v3 |
| Web Framework | FastAPI + Uvicorn |
| Threat Scanning | VirusTotal API v3 |
| AI Explanation | Google Gemini API (1.5 Flash) |
| Database | SQLite (async) |
