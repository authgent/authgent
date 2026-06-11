# Future-work drafts

Material that's interesting but not yet ready for active outreach. The
explicit non-promise here is that nothing in this directory is
submitted, planned, or supported.

## Why not already on datatracker?

| Draft | Why parked |
|---|---|
| [`draft-agnihotri-oauth-agent-action-transparency-00.md`](draft-agnihotri-oauth-agent-action-transparency-00.md) | Conceptually overlaps with Sigstore Rekor and with `draft-nelson-agent-delegation-receipts-09` (which already ships a reference SDK + hosted service at `cloud.authproof.dev`). A reviewer's first question would be "why not a Rekor profile or a Nelson-receipts extension?" — and the honest answer ("I didn't know") is worse than not submitting. The Merkle-tree CT analog is also operationally heavy (signed tree heads, gossip, consistency proofs) and nobody in the agent-OAuth space is currently asking for it. Keeping it as a future-work artifact means I can come back if either the gap reopens or a WG-track ally surfaces. |

## What goes in `drafts/` instead

The active I-D plan is short individual submissions whose entire purpose
is to produce content that the **already-WG-track** drafts want for
their own Implementation Status appendix:

- "Implementation Status of draft-ietf-oauth-identity-chaining and
  draft-ietf-oauth-transaction-tokens" — 3-page report. Editors (Aaron
  Parecki, Atul Tulshibagwale) want this for their own draft's
  appendix; high citation rate; clean EB-1A artifact.

That's the move with 50× the leverage for 5% of the work, per the
external reviewer who flagged the original transparency draft as a
landmine.
