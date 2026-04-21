# ============================================================
# OWASP Security — services/virustotal.py
# Async VirusTotal API v3 client.
# OWASP A02: Cryptographic Failures → API key in env only
# OWASP A10: SSRF → we send URLs to VT, not fetch them ourselves
# ============================================================

import httpx
import base64
from loguru import logger
from config import settings


# ── Internal helper ───────────────────────────────────────────

def _vt_headers() -> dict:
    """Build VirusTotal auth headers.
    Key is read from settings (env var) — never hardcoded."""
    return {
        "x-apikey": settings.VIRUSTOTAL_API_KEY,
        "Accept": "application/json",
    }


def _compute_risk(malicious: int, total: int) -> str:
    """Determine risk level from VirusTotal engine counts.

    Thresholds (industry-standard heuristic):
      - 0 detections            → Low
      - 1-3 detections          → Medium
      - 4+ detections           → High
    """
    if total == 0:
        return "Unknown"
    if malicious == 0:
        return "Low"
    if malicious <= 3:
        return "Medium"
    return "High"


# ── Public API functions ──────────────────────────────────────

async def scan_url(url: str) -> dict:
    """Submit a URL to VirusTotal for analysis and return results.

    VirusTotal URL scan flow:
      1. POST /urls  →  get analysis ID
      2. GET  /analyses/{id}  →  poll for completed results

    Returns a dict with keys:
      malicious_count, total_engines, risk_level, permalink, raw
    """
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            # Step 1 — Submit URL
            logger.info(f"[VT] Submitting URL scan: {url[:80]}")
            submit_resp = await client.post(
                f"{settings.VT_BASE_URL}/urls",
                headers=_vt_headers(),
                data={"url": url},
            )
            submit_resp.raise_for_status()
            analysis_id = submit_resp.json()["data"]["id"]

            # Step 2 — Wait a bit for analysis to progress (Heroku-friendly delay)
            await asyncio.sleep(5)

            # Step 3 — Fetch analysis report
            report_resp = await client.get(
                f"{settings.VT_BASE_URL}/analyses/{analysis_id}",
                headers=_vt_headers(),
            )
            report_resp.raise_for_status()
            data = report_resp.json()

            stats = data["data"]["attributes"].get("stats", {})
            status = data["data"]["attributes"].get("status")
            
            # If still queued, wait another 5 seconds
            if status != "completed":
                await asyncio.sleep(5)
                report_resp = await client.get(
                    f"{settings.VT_BASE_URL}/analyses/{analysis_id}",
                    headers=_vt_headers(),
                )
                data = report_resp.json()
                stats = data["data"]["attributes"].get("stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            # Count both malicious + suspicious as "bad"
            bad = malicious + suspicious
            total = sum(stats.values())
            risk = _compute_risk(bad, total)

            # Build a permalink to the VT report
            # VT uses base64url-encoded URL as the resource ID
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            permalink = f"https://www.virustotal.com/gui/url/{url_id}"

            logger.info(f"[VT] URL scan done — malicious={bad}/{total} risk={risk}")
            return {
                "malicious_count": bad,
                "total_engines": total,
                "risk_level": risk,
                "permalink": permalink,
                "raw": stats,
            }

        except httpx.HTTPStatusError as e:
            # Log status code but NOT the full URL (may contain PII)
            logger.error(f"[VT] HTTP error {e.response.status_code} on URL scan")
            raise RuntimeError(
                f"VirusTotal returned HTTP {e.response.status_code}. "
                "Check your API key or try again later."
            )
        except httpx.RequestError as e:
            logger.error(f"[VT] Network error on URL scan: {type(e).__name__}")
            raise RuntimeError("Could not reach VirusTotal. Check your internet connection.")


async def scan_hash(file_hash: str) -> dict:
    """Look up a file hash on VirusTotal.

    VirusTotal hash lookup flow:
      GET /files/{hash}  →  returns existing report (no upload needed)

    Returns same dict structure as scan_url().
    """
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            logger.info(f"[VT] Hash lookup: {file_hash}")
            resp = await client.get(
                f"{settings.VT_BASE_URL}/files/{file_hash}",
                headers=_vt_headers(),
            )

            if resp.status_code == 404:
                # Hash is not in VT database — that's not an error,
                # it means we have no data for it
                return {
                    "malicious_count": 0,
                    "total_engines": 0,
                    "risk_level": "Unknown",
                    "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
                    "raw": {},
                    "note": "Hash not found in VirusTotal database.",
                }

            resp.raise_for_status()
            data = resp.json()

            stats = data["data"]["attributes"].get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            bad = malicious + suspicious
            total = sum(stats.values())
            risk = _compute_risk(bad, total)

            permalink = f"https://www.virustotal.com/gui/file/{file_hash}"
            logger.info(f"[VT] Hash scan done — malicious={bad}/{total} risk={risk}")

            return {
                "malicious_count": bad,
                "total_engines": total,
                "risk_level": risk,
                "permalink": permalink,
                "raw": stats,
            }

        except httpx.HTTPStatusError as e:
            logger.error(f"[VT] HTTP error {e.response.status_code} on hash scan")
            raise RuntimeError(
                f"VirusTotal returned HTTP {e.response.status_code}. "
                "Check your API key or try again later."
            )
        except httpx.RequestError as e:
            logger.error(f"[VT] Network error on hash scan: {type(e).__name__}")
            raise RuntimeError("Could not reach VirusTotal. Check your internet connection.")
