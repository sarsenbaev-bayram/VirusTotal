# ============================================================
# OWASP Security — services/gemini_service.py
# Google Gemini integration for threat explanation.
# OWASP A02: API key loaded from env only — never hardcoded
# ============================================================

import google.generativeai as genai
from config import settings
from loguru import logger

# ── Initialise client once ──────
genai.configure(api_key=settings.GEMINI_API_KEY)

# ── System prompt — defines the AI persona ────────────────────
_SYSTEM_PROMPT = """You are a cybersecurity expert assistant integrated into a security scanning tool. Your task is to explain VirusTotal scan results to non-technical users in a simple and understandable way.

Always follow this 3-section format:
1. 🔍 **Assessment** – Is it safe or dangerous? 
2. ⚠️ **Risk Details** – What was found and why is it risky?
3. 🛡️ **Recommendations** – What should the user do now?

Keep the response short (under 300 words). Use simple language.
The language of the response MUST be: {language}
"""

_model = genai.GenerativeModel(
    model_name="gemini-1.5-flash"
)

async def explain_scan_result(
    scan_type: str,
    target: str,
    malicious_count: int,
    total_engines: int,
    risk_level: str,
    raw_stats: dict,
    language: str = "uzbek",
) -> str:
    """Ask Gemini to explain a VirusTotal scan result in the specified language."""
    
    current_system_prompt = _SYSTEM_PROMPT.format(language=language)
    
    user_prompt = f"""
Scan Type: {scan_type.upper()}
Target: {target[:100]}
Risk Level: {risk_level}
Malicious/Suspicious Detections: {malicious_count} out of {total_engines} engines
VirusTotal Stats Breakdown: {raw_stats}

Please provide your cybersecurity assessment following the 3-section format.
"""

    try:
        logger.info(
            f"[GEMINI] Requesting explanation in {language} — type={scan_type} risk={risk_level}"
        )
        response = await _model.generate_content_async(
            [current_system_prompt, user_prompt],
            generation_config=genai.GenerationConfig(
                max_output_tokens=500,
                temperature=0.4,
            )
        )
        explanation = response.text.strip()
        logger.info("[GEMINI] Explanation received successfully.")
        return explanation

    except Exception as e:
        # OWASP A09: Log the error type but DON'T expose API response to user
        logger.error(f"[GEMINI] API error: {type(e).__name__} — {str(e)[:100]}")
        # Graceful fallback — never crash the scan because of AI failure
        return (
            f"🔍 **Assessment**: Risk level is **{risk_level}**.\n\n"
            f"⚠️ **Threat Details**: {malicious_count} out of {total_engines} "
            "security engines detected a potential threat.\n\n"
            "🛡️ **Recommendations**: If the risk level is Medium or High, "
            "avoid visiting this URL or executing this file. "
            "Run a full antivirus scan on your system.\n\n"
            "_(AI explanation unavailable — showing summary only)_"
        )
