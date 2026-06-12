#!/usr/bin/env bash
# Render the I-D from kramdown-rfc Markdown to submission-ready XML + TXT.
#
# Output is idnits3 submission-mode clean. The two-pass flow (kramdown-rfc
# then xml2rfc --v2v3) is needed because:
#   - kramdown-rfc emits SYSTEM-entity references for bibxml (`&I-D...;`),
#     which idnits3 v3 cannot dereference.
#   - xml2rfc --v2v3 inlines those entities so the resulting XML is
#     self-contained and validates locally.
# We also strip the `<?line N?>` processing instructions kramdown-rfc adds
# for source mapping; idnits3 flags them as warnings.
#
# Requirements:
#   - rbenv-managed Ruby 3.3.x with kramdown-rfc gem installed
#   - python with xml2rfc 3.34+
#   - node with @ietf-tools/idnits installed globally (optional, for validation)

set -euo pipefail

cd "$(dirname "$0")"

NAME="draft-agnihotri-oauth-agent-impl-status-00"
KRAMDOWN_RFC="${KRAMDOWN_RFC:-/Users/dagnihotri/.gem/ruby/3.3.0/bin/kramdown-rfc}"

echo "==> kramdown-rfc -> XML"
RBENV_VERSION=3.3.6 "${KRAMDOWN_RFC}" "${NAME}.md" > "${NAME}.raw.xml"

echo "==> strip <?line N?> PIs"
sed '/<?line [0-9]*?>/d' "${NAME}.raw.xml" > "${NAME}.stripped.xml"

echo "==> xml2rfc --v2v3 (inline bibxml entities)"
xml2rfc --no-network --v2v3 "${NAME}.stripped.xml" -o "${NAME}.xml" 2>&1 | tail -3

echo "==> xml2rfc --text"
xml2rfc --text "${NAME}.xml" -o "${NAME}.txt" 2>&1 | tail -3

rm -f "${NAME}.raw.xml" "${NAME}.stripped.xml"

if command -v idnits >/dev/null 2>&1; then
    echo "==> idnits submission mode"
    idnits -m submission -o simple --no-color "${NAME}.xml" || true
    idnits -m submission -o simple --no-color "${NAME}.txt" || true
fi

echo "==> done. Upload ${NAME}.xml at https://datatracker.ietf.org/submit/"
