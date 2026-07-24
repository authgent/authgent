# awesome-mcp-servers PR Content

## Where to add it

Repository: https://github.com/punkpeye/awesome-mcp-servers  
Section: **Security & Compliance** (create if doesn't exist, or add to **Tools & Utilities**)

## Entry to add

```markdown
- [authgent](https://github.com/authgent/authgent) - Open-source MCP-OAuth compliance scanner. Grades servers A-F against 15 RFC checks (9728, 8414, 7636, 8707, etc.). CLI + hosted scanner + GitHub Action + embeddable badge. Catches PKCE advertise-drift and missing protected resource metadata.
```

## PR Title

```
Add authgent - MCP-OAuth compliance scanner
```

## PR Body

```markdown
### What

authgent is an open-source scanner that audits MCP servers' OAuth implementation against 15 RFC-mapped checks:
- RFC 9728 Protected Resource Metadata
- RFC 8414 AS Metadata  
- RFC 7636 PKCE (detects advertise-drift heuristic)
- RFC 8707 Resource Indicators
- RFC 9207 Authorization Server Issuer ID
- RFC 9449 DPoP
- MCP 2025-11-25 authorization spec
- Enterprise-Managed Authorization (EMA) readiness

### Why include it

- **51,311 MCP servers** deployed as of July 2026 (per Glama), most lack proper OAuth posture
- **Fills a gap**: No other tool audits MCP-OAuth compliance end-to-end
- **IETF reference implementation**: Cited in `draft-agnihotri-oauth-agent-impl-status` on IETF datatracker
- **Production-ready**: CLI (`authgent-server lint <url>`), GitHub Action, hosted scanner at authgent.dev/scan, embeddable badge

### Format

- Added to Security & Compliance section (or Tools if preferred)
- Follows existing entry format (name, link, short description)
- Highlights the unique value prop: RFC-mapped compliance checks + PKCE-drift heuristic

### Checklist

- [x] Entry follows existing format
- [x] Link goes to GitHub repo (not marketing site)
- [x] Description is concise and specific
- [x] Tool is open-source (Apache 2.0)
- [x] Tool is actively maintained (last commit within 7 days)
```

## Manual steps to submit PR

1. Fork https://github.com/punkpeye/awesome-mcp-servers
2. Clone your fork locally
3. Create branch: `git checkout -b add-authgent-scanner`
4. Find or create "Security & Compliance" section in README.md
5. Add the entry above in alphabetical order within section
6. Commit: `git commit -m "Add authgent - MCP-OAuth compliance scanner"`
7. Push: `git push origin add-authgent-scanner`
8. Open PR with title and body above
9. Tag @punkpeye in PR comment: "cc @punkpeye — would love your feedback on this addition"

## Alternative: Use GitHub web editor

1. Go to https://github.com/punkpeye/awesome-mcp-servers/edit/main/README.md
2. Click "Fork this repository"
3. Find Security section (or create it after ## Tools)
4. Paste the entry
5. Commit changes → "Create pull request"
6. Use PR title and body above
