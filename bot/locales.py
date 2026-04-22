# ============================================================
# OWASP Security — bot/locales.py
# Centralized message strings for multi-language support.
# ============================================================

MESSAGES = {
    "uz": {
        "welcome": (
            "👋 <b>Assalomu alaykum, {name}!</b>\n\n"
            "🔐 <b>OWASP Xavfsizlik Skaneri Boti</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n\n"
            "Men URL manzilari va fayl hashlarini <b>VirusTotal</b> orqali zararli dasturlarga tekshiraman "
            "va natijalarni <b>Google Gemini AI</b> yordamida tahlil qilaman.\n\n"
            "📌 <b>Mavjud buyruqlar:</b>\n\n"
            "🌐 /scan_url — URLni xavf-xatarlarga skanerlash\n"
            "🔍 /scan_hash — Fayl hashini skanerlash (MD5/SHA1/SHA256)\n"
            "🌍 /language — Tilni o'zgartirish\n\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "⚡ Cheklov: <b>daqiqasiga 5 ta skanerlash</b>"
        ),
        "select_language": "Iltimos, tilni tanlang:",
        "language_changed": "Til muvaffaqiyatli o'zgartirildi! ✅",
        "scan_url_prompt": "🔗 Skanerlash uchun URL manzilini kiriting.\n<i>Misol: /scan_url https://google.com</i>",
        "scan_hash_prompt": "🔍 Skanerlash uchun fayl hashini kiriting.\n<i>Misol: /scan_hash d41d8cd98f00b204e9800998ecf8427e</i>",
        "invalid_url": "❌ Xato: Tilayotgan URL yoki format mos emas.",
        "invalid_hash": "❌ Xato: Noto'g'ri hash formati. MD5, SHA1 yoki SHA256 kiriting.",
        "scanning": "⏳ Skanerlanmoqda...",
        "error": "❌ Xatolik yuz berdi. Iltimos keyinroq qayta urinib ko'ring.",
        "rate_limit": "⚠️ Juda ko'p so'rov. Iltimos biroz kuting.",
        "risk_low": "🟢 Past xavf",
        "risk_medium": "🟡 O'rtacha xavf",
        "risk_high": "🔴 Yuqori xavf",
        "scan_result": (
            "📊 <b>Skanerlash natijasi</b>\n\n"
            "🎯 Nushon: <code>{target}</code>\n"
            "🛡 🤖 Skannerlar: {malicious}/{total}\n"
            "⚠️ Xavf darajasi: <b>{risk_level}</b>\n\n"
            "🤖 <b>AI Tahlili:</b>\n{ai_explanation}"
        ),
        "btn_url": "🌐 URL skanerlash",
        "btn_hash": "🔍 Hash skanerlash",
        "btn_history": "📋 Tarix",
        "btn_lang": "🌍 Tilni o'zgartirish",
    },
    "en": {
        "welcome": (
            "👋 <b>Welcome, {name}!</b>\n\n"
            "🔐 <b>OWASP Security Scanner Bot</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n\n"
            "I scan URLs and file hashes for malware via <b>VirusTotal</b> "
            "and analyze results using <b>Google Gemini AI</b>.\n\n"
            "📌 <b>Available Commands:</b>\n\n"
            "🌐 /scan_url — Scan a URL for risks\n"
            "🔍 /scan_hash — Scan a file hash (MD5/SHA1/SHA256)\n"
            "🌍 /language — Change language\n\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "⚡ Limit: <b>5 scans per minute</b>"
        ),
        "select_language": "Please select a language:",
        "language_changed": "Language successfully changed! ✅",
        "scan_url_prompt": "🔗 Enter a URL to scan.\n<i>Example: /scan_url https://google.com</i>",
        "scan_hash_prompt": "🔍 Enter a file hash to scan.\n<i>Example: /scan_hash d41d8cd98f00b204e9800998ecf8427e</i>",
        "invalid_url": "❌ Error: Invalid URL or format.",
        "invalid_hash": "❌ Error: Invalid hash format. Use MD5, SHA1, or SHA256.",
        "scanning": "⏳ Scanning...",
        "error": "❌ An error occurred. Please try again later.",
        "rate_limit": "⚠️ Too many requests. Please wait a bit.",
        "risk_low": "🟢 Low Risk",
        "risk_medium": "🟡 Medium Risk",
        "risk_high": "🔴 High Risk",
        "scan_result": (
            "📊 <b>Scan Result</b>\n\n"
            "🎯 Target: <code>{target}</code>\n"
            "🛡 Scanners: {malicious}/{total}\n"
            "⚠️ Risk Level: <b>{risk_level}</b>\n\n"
            "🤖 <b>AI Analysis:</b>\n{ai_explanation}"
        ),
        "btn_url": "🌐 Scan URL",
        "btn_hash": "🔍 Scan Hash",
        "btn_history": "📋 History",
        "btn_lang": "🌍 Change Language",
    }
}
