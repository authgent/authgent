#!/bin/bash
# Deploy authgent demo to Oracle server
# Run as root or with sudo
#
# Prerequisites:
#   - Oracle Linux / Ubuntu server with public IP
#   - Domain demo.authgent.dev pointing to this server's IP
#   - Python 3.11+ installed
#
# Usage: sudo bash setup.sh

set -euo pipefail

echo "=== authgent demo deployment ==="

# ── 1. Install dependencies ──────────────────────────
echo "Installing system dependencies..."
if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y -qq nginx certbot python3-certbot-nginx python3-pip python3-venv
elif command -v dnf &>/dev/null; then
    dnf install -y nginx certbot python3-certbot-nginx python3-pip
fi

# ── 2. Create app directory ──────────────────────────
echo "Setting up /opt/authgent..."
mkdir -p /opt/authgent/playground
mkdir -p /opt/authgent/server
mkdir -p /opt/authgent/data

# ── 3. Install authgent-server ───────────────────────
echo "Installing authgent-server..."
python3 -m venv /opt/authgent/venv
/opt/authgent/venv/bin/pip install --quiet authgent-server

# ── 4. Initialize (first time only) ─────────────────
if [ ! -f /opt/authgent/data/.env ]; then
    echo "Initializing authgent-server..."
    cd /opt/authgent/data
    /opt/authgent/venv/bin/authgent-server init
fi

# ── 5. Copy playground files ─────────────────────────
echo "Copying playground..."
cp -r /opt/authgent/repo/playground/* /opt/authgent/playground/ 2>/dev/null || \
    echo "Note: Copy playground/index.html to /opt/authgent/playground/ manually"

# ── 6. Create systemd service ────────────────────────
echo "Creating systemd service..."
cat > /etc/systemd/system/authgent-demo.service << 'EOF'
[Unit]
Description=authgent demo server
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/opt/authgent/data
Environment=AUTHGENT_HOST=127.0.0.1
Environment=AUTHGENT_PORT=8000
Environment=AUTHGENT_REGISTRATION_POLICY=open
Environment=AUTHGENT_CONSENT_MODE=auto_approve
ExecStart=/opt/authgent/venv/bin/authgent-server run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# ── 7. Create hourly DB cleanup cron ─────────────────
echo "Setting up hourly DB cleanup..."
cat > /etc/cron.d/authgent-demo-cleanup << 'EOF'
# Wipe demo DB every hour (sandbox — no persistent data)
0 * * * * www-data rm -f /opt/authgent/data/authgent.db && /opt/authgent/venv/bin/authgent-server init --quiet 2>/dev/null
EOF

# ── 8. Set permissions ───────────────────────────────
chown -R www-data:www-data /opt/authgent

# ── 9. Setup nginx ───────────────────────────────────
echo "Configuring nginx..."
cp /opt/authgent/repo/playground/deploy/nginx.conf /etc/nginx/sites-available/authgent-demo 2>/dev/null || \
    echo "Note: Copy nginx.conf to /etc/nginx/sites-available/authgent-demo manually"

if [ -d /etc/nginx/sites-enabled ]; then
    ln -sf /etc/nginx/sites-available/authgent-demo /etc/nginx/sites-enabled/
fi

# ── 10. TLS certificate ─────────────────────────────
echo "Getting TLS certificate..."
certbot --nginx -d demo.authgent.dev --non-interactive --agree-tos --email admin@authgent.dev || \
    echo "Note: Run 'certbot --nginx -d demo.authgent.dev' manually after DNS is configured"

# ── 11. Start services ──────────────────────────────
echo "Starting services..."
systemctl daemon-reload
systemctl enable authgent-demo
systemctl start authgent-demo
systemctl reload nginx

echo ""
echo "=== Done! ==="
echo "  Playground: https://demo.authgent.dev/"
echo "  API docs:   https://demo.authgent.dev/docs"
echo "  Health:     https://demo.authgent.dev/health"
echo ""
echo "  DB resets every hour (sandbox mode)"
echo "  Rate limited: 10 req/min per IP"
