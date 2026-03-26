FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (layer caching)
COPY pyproject.toml README.md ./
COPY authgent_server/__init__.py authgent_server/__init__.py
RUN pip install --no-cache-dir .[postgres]

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
