#!/bin/bash
# Publish authgent-server and authgent SDK to PyPI
# Usage: export PYPI_TOKEN="your-token-here" && ./publish.sh [server|sdk|both] [--bump major|minor|patch]
#
# Examples:
#   ./publish.sh both                  # publish both, auto-increment patch
#   ./publish.sh server --bump minor   # publish server only, bump minor version
#   ./publish.sh sdk                   # publish SDK only, auto-increment patch
#   ./publish.sh both --bump major     # publish both, bump major version

set -e

# ─── Config ─────────────────────────────────────────────────────────────────
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_DIR="$ROOT_DIR/server"
SDK_DIR="$ROOT_DIR/sdks/python"

SERVER_INIT="$SERVER_DIR/authgent_server/__init__.py"
SERVER_TOML="$SERVER_DIR/pyproject.toml"
SDK_INIT="$SDK_DIR/authgent/__init__.py"
SDK_TOML="$SDK_DIR/pyproject.toml"
CHANGELOG="$ROOT_DIR/CHANGELOG.md"

# ─── Args ───────────────────────────────────────────────────────────────────
TARGET="${1:-both}"     # server | sdk | both
BUMP_TYPE="patch"       # default

if [[ "$2" == "--bump" && -n "$3" ]]; then
    BUMP_TYPE="$3"
fi

if [[ "$TARGET" != "server" && "$TARGET" != "sdk" && "$TARGET" != "both" ]]; then
    echo "❌ Invalid target: $TARGET"
    echo "Usage: ./publish.sh [server|sdk|both] [--bump major|minor|patch]"
    exit 1
fi

if [[ "$BUMP_TYPE" != "major" && "$BUMP_TYPE" != "minor" && "$BUMP_TYPE" != "patch" ]]; then
    echo "❌ Invalid bump type: $BUMP_TYPE (must be major, minor, or patch)"
    exit 1
fi

# ─── Token check ────────────────────────────────────────────────────────────
if [ -z "$PYPI_TOKEN" ]; then
    echo "❌ PYPI_TOKEN environment variable not set"
    echo ""
    echo "Usage:"
    echo "  export PYPI_TOKEN=\"pypi-AgEIcH...\"  # set once per terminal session"
    echo "  ./publish.sh [server|sdk|both] [--bump major|minor|patch]"
    echo ""
    echo "Get a token at: https://pypi.org/manage/account/token/"
    exit 1
fi

# ─── Dependency check ───────────────────────────────────────────────────────
for cmd in python twine; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "❌ Missing dependency: $cmd"
        echo "   pip install build twine"
        exit 1
    fi
done

if ! python -c "import build" &>/dev/null; then
    echo "❌ Missing python 'build' module"
    echo "   pip install build"
    exit 1
fi

# ─── Version bump function ──────────────────────────────────────────────────
bump_version() {
    local current="$1"
    local bump="$2"

    IFS='.' read -r major minor patch <<< "$current"
    major="${major:-0}"
    minor="${minor:-0}"
    patch="${patch:-0}"

    case "$bump" in
        major) major=$((major + 1)); minor=0; patch=0 ;;
        minor) minor=$((minor + 1)); patch=0 ;;
        patch) patch=$((patch + 1)) ;;
    esac

    echo "${major}.${minor}.${patch}"
}

# ─── Read current version from server __init__.py (single source of truth) ──
CURRENT_VERSION=$(python -c "
import re
with open('$SERVER_INIT') as f:
    m = re.search(r'__version__\s*=\s*[\"'\''](.*?)[\"'\'']\s*', f.read())
    print(m.group(1) if m else '0.0.0')
")

NEW_VERSION=$(bump_version "$CURRENT_VERSION" "$BUMP_TYPE")

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  authgent publish                                           ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Target:   $TARGET"
echo "║  Version:  $CURRENT_VERSION → $NEW_VERSION ($BUMP_TYPE bump)"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ─── Confirm ────────────────────────────────────────────────────────────────
read -p "Proceed? (y/N) " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Aborted."
    exit 0
fi

# ─── Update all version strings ─────────────────────────────────────────────
echo ""
echo "📈 Bumping version $CURRENT_VERSION → $NEW_VERSION in all files..."

update_init_version() {
    local file="$1"
    python -c "
import re
with open('$file', 'r') as f:
    content = f.read()
content = re.sub(
    r'__version__\s*=\s*[\"'\''].*?[\"'\'']',
    '__version__ = \"$NEW_VERSION\"',
    content
)
with open('$file', 'w') as f:
    f.write(content)
"
    echo "   ✓ $file"
}

update_toml_version() {
    local file="$1"
    python -c "
import re
with open('$file', 'r') as f:
    content = f.read()
content = re.sub(
    r'^version = \"[^\"]+\"',
    'version = \"$NEW_VERSION\"',
    content,
    flags=re.MULTILINE
)
with open('$file', 'w') as f:
    f.write(content)
"
    echo "   ✓ $file"
}

# Always update all version files to keep them in sync
update_init_version "$SERVER_INIT"
update_toml_version "$SERVER_TOML"
update_init_version "$SDK_INIT"
update_toml_version "$SDK_TOML"
echo ""

# ─── Build & publish function ───────────────────────────────────────────────
publish_package() {
    local name="$1"
    local dir="$2"

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📦 Publishing $name v$NEW_VERSION"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Clean
    echo "🧹 Cleaning old builds..."
    rm -rf "$dir/dist/" "$dir/build/" "$dir"/*.egg-info
    echo ""

    # Build
    echo "🔨 Building..."
    python -m build "$dir"
    echo ""

    # Upload
    echo "📤 Uploading to PyPI..."
    python -m twine upload \
        --username __token__ \
        --password "${PYPI_TOKEN}" \
        --non-interactive \
        "$dir/dist/*"
    echo ""

    echo "✅ $name v$NEW_VERSION published!"
    echo "🔗 https://pypi.org/project/$name/$NEW_VERSION/"
    echo ""
}

# ─── Publish ────────────────────────────────────────────────────────────────
if [[ "$TARGET" == "server" || "$TARGET" == "both" ]]; then
    publish_package "authgent-server" "$SERVER_DIR"
fi

if [[ "$TARGET" == "sdk" || "$TARGET" == "both" ]]; then
    publish_package "authgent" "$SDK_DIR"
fi

# ─── Summary ────────────────────────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ Done!                                                    ║"
echo "╠══════════════════════════════════════════════════════════════╣"
if [[ "$TARGET" == "server" || "$TARGET" == "both" ]]; then
echo "║  📦 authgent-server  → https://pypi.org/project/authgent-server/"
fi
if [[ "$TARGET" == "sdk" || "$TARGET" == "both" ]]; then
echo "║  📦 authgent         → https://pypi.org/project/authgent/"
fi
echo "║  🏷️  Version: $NEW_VERSION"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "💡 Next steps:"
echo "   git add -A && git commit -m \"release: v$NEW_VERSION\" && git tag v$NEW_VERSION && git push --tags"
