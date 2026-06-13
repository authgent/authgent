# Publishing this Action to GitHub Marketplace

The standalone Action repo (`authgent/mcp-lint-action`) needs to be
created on GitHub by the project owner. Marketplace publication
requires a click in the GitHub UI -- it cannot be automated. This file
documents the exact steps.

## Step 1 -- create the repo (5 minutes)

```bash
# Auth check
gh auth status   # ensure you're on the Dhruvagnihotri admin account

# Create the repo
gh repo create authgent/mcp-lint-action \
  --public \
  --description "GitHub Action: grade your MCP server's OAuth posture against the RFCs that matter (RFC 7591/7636/8414/8707/9207/9449/9728 + MCP spec)." \
  --homepage "https://github.com/authgent/authgent"

# Clone it locally
cd /tmp && gh repo clone authgent/mcp-lint-action && cd mcp-lint-action

# Copy in the Marketplace-ready content
cp /Users/dagnihotri/Personal/PersonalSynced/agentAuth/marketplace/mcp-lint-action/action.yml .
cp /Users/dagnihotri/Personal/PersonalSynced/agentAuth/marketplace/mcp-lint-action/README.md .
cp /Users/dagnihotri/Personal/PersonalSynced/agentAuth/marketplace/mcp-lint-action/LICENSE .

# First commit + tag v1
git add action.yml README.md LICENSE
git commit -m "feat: initial Marketplace release"
git tag -a v1 -m "Marketplace v1"
git push origin main --tags
```

## Step 2 -- publish to Marketplace (UI click)

1. Open <https://github.com/authgent/mcp-lint-action/releases/new>
2. Pick the `v1` tag.
3. Title: `v1 -- initial Marketplace release`.
4. Body: paste the README's "What it does" and "Quick start" sections.
5. Tick "Publish this Action to the GitHub Marketplace".
6. Categories: pick **Code quality** (primary) and **Security** (secondary).
7. Confirm the Marketplace policies and click "Publish release".

GitHub validates the action.yml against Marketplace requirements:
- The repo must be public (yes).
- `action.yml` must have `branding.icon` and `branding.color` (yes).
- The repo must contain a LICENSE file (yes, Apache 2.0).
- The repo name and Action name must be sufficiently distinct (yes).

## Step 3 -- verify

After publication:

```bash
# The Action should appear at:
open https://github.com/marketplace/actions/authgent-mcp-oauth-lint
```

The Marketplace listing also gets a unique URL slug derived from the
Action name; if GitHub picks a different slug than expected, it appears
in the publication confirmation page.

## Step 4 -- pin v1 to the latest commit

For users referencing `@v1`, the floating tag should track the latest
patch-compatible release. After cutting `v1.0.1` etc, force-update v1:

```bash
git tag -f v1
git push --force origin v1
```

(Or, on each release, add a `v1.X.Y` tag and update v1 to point at it.
The "force-push v1" pattern is the convention in `actions/checkout`,
`actions/setup-python`, etc.)

## Step 5 -- update the main authgent repo to reference the Marketplace version

The main repo's docs already mention `authgent/authgent/.github/actions/mcp-lint@v0.3.4`
as a fallback. Once the Marketplace version is live, swap that to
`authgent/mcp-lint-action@v1` in:

- `README.md`
- `docs/mcp-quickstart.md`
- `OUTREACH.md` examples
- `.github/actions/mcp-lint/README.md`

The main-repo Action stays as a backup so users who want to pin to a
specific authgent-server version can still reference it via the long
path.
