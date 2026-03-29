#!/bin/bash
# Publish authgent TypeScript SDK to npm
# Usage: export NPM_TOKEN="your-token-here" && ./publish_npm.sh [--bump major|minor|patch]
#
# Examples:
#   ./publish_npm.sh                   # publish at current version (first time)
#   ./publish_npm.sh --bump patch      # bump patch and publish
#   ./publish_npm.sh --bump minor      # bump minor and publish

set -e

# ─── Config ─────────────────────────────────────────────────────────────────
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
SDK_DIR="$ROOT_DIR/sdks/typescript"
PACKAGE_JSON="$SDK_DIR/package.json"
PACKAGE_NAME="authgent"

# ─── Args ───────────────────────────────────────────────────────────────────
BUMP_TYPE=""
if [[ "$1" == "--bump" && -n "$2" ]]; then
    BUMP_TYPE="$2"
    if [[ "$BUMP_TYPE" != "major" && "$BUMP_TYPE" != "minor" && "$BUMP_TYPE" != "patch" ]]; then
        echo "❌ Invalid bump type: $BUMP_TYPE (must be major, minor, or patch)"
        exit 1
    fi
fi

# ─── Token check ────────────────────────────────────────────────────────────
if [ -z "$NPM_TOKEN" ]; then
    echo "❌ NPM_TOKEN environment variable not set"
    echo ""
    echo "Usage:"
    echo "  export NPM_TOKEN=\"npm_...\"  # set once per terminal session"
    echo "  ./publish_npm.sh [--bump major|minor|patch]"
    echo ""
    echo "Get a token at: https://www.npmjs.com/settings/~/tokens"
    exit 1
fi

# ─── Dependency check ───────────────────────────────────────────────────────
if ! command -v node &>/dev/null; then
    echo "❌ node not found"; exit 1
fi
if ! command -v npm &>/dev/null; then
    echo "❌ npm not found"; exit 1
fi

# ─── Safety: verify we're publishing the right package ──────────────────────
ACTUAL_NAME=$(node -p "require('$PACKAGE_JSON').name")
if [[ "$ACTUAL_NAME" != "$PACKAGE_NAME" ]]; then
    echo "❌ SAFETY CHECK FAILED"
    echo "   Expected package name: $PACKAGE_NAME"
    echo "   Found in package.json: $ACTUAL_NAME"
    echo "   Aborting to protect your other npm packages."
    exit 1
fi

# ─── Read current version ──────────────────────────────────────────────────
CURRENT_VERSION=$(node -p "require('$PACKAGE_JSON').version")

# ─── Bump version if requested ──────────────────────────────────────────────
if [[ -n "$BUMP_TYPE" ]]; then
    # Use node to bump — no npm version (avoids git tag side effects)
    NEW_VERSION=$(node -e "
        const [major, minor, patch] = '$CURRENT_VERSION'.split('.').map(Number);
        const bump = '$BUMP_TYPE';
        if (bump === 'major') console.log((major+1)+'.0.0');
        else if (bump === 'minor') console.log(major+'.'+(minor+1)+'.0');
        else console.log(major+'.'+minor+'.'+(patch+1));
    ")

    # Update package.json
    node -e "
        const fs = require('fs');
        const pkg = JSON.parse(fs.readFileSync('$PACKAGE_JSON', 'utf8'));
        pkg.version = '$NEW_VERSION';
        fs.writeFileSync('$PACKAGE_JSON', JSON.stringify(pkg, null, 2) + '\n');
    "

    # Also sync version to Python files (keep all versions in lockstep)
    PYTHON_SERVER_INIT="$ROOT_DIR/server/authgent_server/__init__.py"
    PYTHON_SERVER_TOML="$ROOT_DIR/server/pyproject.toml"
    PYTHON_SDK_INIT="$ROOT_DIR/sdks/python/authgent/__init__.py"
    PYTHON_SDK_TOML="$ROOT_DIR/sdks/python/pyproject.toml"

    for f in "$PYTHON_SERVER_INIT" "$PYTHON_SDK_INIT"; do
        if [ -f "$f" ]; then
            python3 -c "
import re
with open('$f', 'r') as fh:
    content = fh.read()
content = re.sub(r'__version__\s*=\s*[\"'\''].*?[\"'\'']', '__version__ = \"$NEW_VERSION\"', content)
with open('$f', 'w') as fh:
    fh.write(content)
"
        fi
    done
    for f in "$PYTHON_SERVER_TOML" "$PYTHON_SDK_TOML"; do
        if [ -f "$f" ]; then
            python3 -c "
import re
with open('$f', 'r') as fh:
    content = fh.read()
content = re.sub(r'^version = \"[^\"]+\"', 'version = \"$NEW_VERSION\"', content, flags=re.MULTILINE)
with open('$f', 'w') as fh:
    fh.write(content)
"
        fi
    done

    echo "📈 Version bumped: $CURRENT_VERSION → $NEW_VERSION ($BUMP_TYPE)"
else
    NEW_VERSION="$CURRENT_VERSION"
    echo "📦 Publishing at current version: $NEW_VERSION"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  authgent npm publish                                       ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Package:  $PACKAGE_NAME"
echo "║  Version:  $NEW_VERSION"
echo "║  Registry: https://registry.npmjs.org"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ─── Confirm ────────────────────────────────────────────────────────────────
read -p "Proceed? (y/N) " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Aborted."
    exit 0
fi

# ─── Install deps + build ──────────────────────────────────────────────────
echo ""
echo "📥 Installing dependencies..."
npm ci --prefix "$SDK_DIR"
echo ""

echo "🔨 Building..."
npm run build --prefix "$SDK_DIR"
echo ""

# ─── Run tests ──────────────────────────────────────────────────────────────
echo "🧪 Running tests..."
npm test --prefix "$SDK_DIR"
echo ""

# ─── Typecheck ──────────────────────────────────────────────────────────────
echo "🔍 Type checking..."
npm run typecheck --prefix "$SDK_DIR"
echo ""

# ─── Publish ────────────────────────────────────────────────────────────────
echo "📤 Publishing to npm..."

# Create a temporary .npmrc scoped to the SDK directory (not global — won't affect other packages)
echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > "$SDK_DIR/.npmrc"

# Publish from inside the SDK directory (avoids npm git resolution issues)
(cd "$SDK_DIR" && npm publish --access public --no-git-checks)

# Clean up the temporary .npmrc immediately
rm -f "$SDK_DIR/.npmrc"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ Published!                                               ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  📦 $PACKAGE_NAME@$NEW_VERSION"
echo "║  🔗 https://www.npmjs.com/package/$PACKAGE_NAME/v/$NEW_VERSION"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "💡 Install with: npm install $PACKAGE_NAME"
echo "💡 Next: git add -A && git commit -m \"release: v$NEW_VERSION\" && git tag v$NEW_VERSION && git push --tags"
