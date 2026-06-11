# IETF Drafts authored from authgent

Markdown sources for Internet-Drafts the maintainer is authoring or
preparing to submit. Each one is designed to be processed with
[kramdown-rfc](https://github.com/cabo/kramdown-rfc) into the xml2rfc /
RFC formats accepted by <https://datatracker.ietf.org/submit/>.

## Active drafts

| Draft | Status | Reference impl |
|---|---|---|
| [`draft-agnihotri-oauth-agent-impl-status-00`](draft-agnihotri-oauth-agent-impl-status-00.md) | submission planned | `authgent` (this repo) |

The intent of `impl-status` is narrow and high-leverage: the editors of
`draft-ietf-oauth-identity-chaining` and `draft-ietf-oauth-transaction-tokens`
both want implementation reports for their own draft's Implementation
Status appendix (per RFC 7942). Submitting a 3-page individual draft
that *is* the implementation report makes adoption-by-citation natural
without creating a new spec turf war.

## Parked

See [`../future-work/`](../future-work/) for drafts that exist as
material but aren't ready (or aren't strategically right) to submit.

## Building xml2rfc output

```bash
gem install kramdown-rfc2629
kramdown-rfc draft-agnihotri-oauth-agent-impl-status-00.md \
  > draft-agnihotri-oauth-agent-impl-status-00.xml
```

Submit via <https://datatracker.ietf.org/submit/>. After acceptance,
email the announcement to `oauth@ietf.org` and CC the editors of the
two drafts the report cites.
