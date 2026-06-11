# IETF Drafts authored from authgent

Markdown sources for Internet-Drafts that authgent maintainers are
authoring. The Markdown is designed to be processed with
[kramdown-rfc](https://github.com/cabo/kramdown-rfc) into the
xml2rfc / RFC formats accepted by datatracker.ietf.org.

## Drafts

| Draft | Status | Reference impl |
|---|---|---|
| [`draft-agnihotri-oauth-agent-action-transparency-00`](draft-agnihotri-oauth-agent-action-transparency-00.md) | not yet submitted | authgent (this repo) |

## Building xml2rfc output

```bash
gem install kramdown-rfc2629
kramdown-rfc draft-agnihotri-oauth-agent-action-transparency-00.md \
  > draft-agnihotri-oauth-agent-action-transparency-00.xml
```

Submit via <https://datatracker.ietf.org/submit/>.
