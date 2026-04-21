# ============================================================
# OWASP Security — services/openai_service.py
# OpenAI ChatGPT integration for threat explanation.
# OWASP A02: API key loaded from env only — never hardcoded
# ============================================================

from openai import AsyncOpenAI
from config import settings
from loguru import logger

# ── Initialise async client once (reuse across requests) ──────
_client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

# ── System prompt — defines the AI persona ────────────────────
_SYSTEM_PROMPT = """You are a cybersecurity expert assistant integrated into 
a security scanning tool. Your job is to explain VirusTotal scan results to 
non-technical users in clear, simple language.

Always structure your response in exactly three sections:
1. 🔍 **Assessment** – Is this URL/file safe or dangerous?
2. ⚠️ **Threat Details** – What exactly was detected and why is it dangerous?
3. 🛡️ **Recommendations** – What should the user do right now?

Keep your response concise (under 300 words). Use plain language.
Never use technical jargon without explaining it.
"""


async def explain_scan_result(
    scan_type: str,
    target: str,
    malicious_count: int,
    total_engines: int,
    risk_level: str,
    raw_stats: dict,
) -> str:
    """Ask ChatGPT to explain a VirusTotal scan result.

    Args:
        scan_type:       'url' or 'hash'
        target:          The scanned URL or hash string
        malicious_count: Number of engines flagging as malicious/suspicious
        total_engines:   Total engines that scanned the target
        risk_level:      'Low', 'Medium', 'High', or 'Unknown'
        raw_stats:       Raw VirusTotal stats dict (harmless, malicious, etc.)

    Returns:
        AI-generated explanation string.
        Falls back to a safe default message on API errors.
    """
    # Build a clean, structured prompt — no raw user input injected
    # directly into prompt to reduce prompt-injection risk
    user_prompt = f"""
Scan Type: {scan_type.upper()}
Target: {target[:100]}  (truncated for safety)
Risk Level: {risk_level}
Malicious/Suspicious Detections: {malicious_count} out of {total_engines} engines
VirusTotal Stats Breakdown: {raw_stats}

Please provide your cybersecurity assessment following the 3-section format.
"""

    try:
        logger.info(
            f"[OPENAI] Requesting explanation — type={scan_type} risk={risk_level}"
        )
        response = await _client.chat.completions.create(
            model="gpt-3.5-turbo",          # Use gpt-4 if your plan allows
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=500,
            temperature=0.4,               # Lower = more consistent, factual
        )
        explanation = response.choices[0].message.content.strip()
        logger.info("[OPENAI] Explanation received successfully.")
        return explanation

    except Exception as e:
        # OWASP A09: Log the error type but DON'T expose API response to user
        logger.error(f"[OPENAI] API error: {type(e).__name__} — {str(e)[:100]}")
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
