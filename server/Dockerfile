FROM python:3.12-slim@sha256:646fb0bca3dd3ea1bcc6feb72c17ed16eed6e10cffc732fcc1478bd3e7f02d7b

WORKDIR /app

# Install dependencies first (layer caching)
COPY pyproject.toml README.md ./
COPY authgent_server/__init__.py authgent_server/__init__.py
RUN pip install --no-cache-dir ".[postgres,redis]"

# Copy full source
COPY authgent_server/ authgent_server/

# Non-root user for security
RUN addgroup --system authgent && adduser --system --ingroup authgent authgent \
    && chown -R authgent:authgent /app
USER authgent

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "authgent_server.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
