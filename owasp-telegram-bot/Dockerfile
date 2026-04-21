# ============================================================
# OWASP Security Bot — Dockerfile
# Multi-stage builds or just optimized for security.
# ============================================================

# ── Base Image ─────────────────────────────────────────────
FROM python:3.11-slim-bookworm

# ── Environment Variables ──────────────────────────────────
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV APP_HOME=/app

WORKDIR $APP_HOME

# ── OS Dependencies ────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# ── Dependencies ───────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Copy Application ───────────────────────────────────────
COPY . .

# ── Security: RUN AS NON-ROOT ──────────────────────────────
# OWASP A04: Insecure Design - least privilege principle
RUN useradd -m appuser && \
    mkdir -p /app/data /app/logs && \
    chown -R appuser:appuser /app
USER appuser

# ── Persistence ────────────────────────────────────────────
VOLUME ["/app/data", "/app/logs"]

# ── Ports ──────────────────────────────────────────────────
EXPOSE 8000

# ── Start Command ──────────────────────────────────────────
# Runs both the web server and the bot via main.py
CMD ["python", "main.py"]
