#!/usr/bin/env bash
# Render the I-D from kramdown-rfc Markdown to submission-ready XML + TXT.
#
# Output is idnits3 submission-mode clean. Pipeline:
#   1. kramdown-rfc -> v2 XML with bibxml SYSTEM entities (&I-D...; &RFC...;)
#   2. strip <?line N?> processing instructions kramdown-rfc adds
#   3. xml2rfc --v2v3 inlines bibxml entities, producing self-contained v3 XML
#   4. inject a BCP14 referencegroup + retarget RFC2119/RFC8174 cites to it
#      (kramdown-rfc 1.7.39's BCP14 fetch URL has bit-rotted; this satisfies
#      idnits3 PREFER_BCP14_REF without a network call)
#   5. xml2rfc --text produces the .txt
#
# Requirements:
#   - rbenv-managed Ruby 3.3.x with kramdown-rfc gem installed
#   - python3 with xml2rfc 3.34+
#   - node with @ietf-tools/idnits installed globally (optional)

set -euo pipefail
cd "$(dirname "$0")"

NAME="draft-agnihotri-oauth-agent-impl-status-00"
KRAMDOWN_RFC="${KRAMDOWN_RFC:-/Users/dagnihotri/.gem/ruby/3.3.0/bin/kramdown-rfc}"

echo "==> kramdown-rfc -> XML"
RBENV_VERSION=3.3.6 "${KRAMDOWN_RFC}" "${NAME}.md" > "${NAME}.raw.xml"

echo "==> strip line PIs"
sed '/<?line [0-9]*?>/d' "${NAME}.raw.xml" > "${NAME}.stripped.xml"

echo "==> xml2rfc --v2v3 (inline bibxml entities)"
xml2rfc --no-network --v2v3 "${NAME}.stripped.xml" -o "${NAME}.unref.xml" 2>&1 | tail -3

echo "==> inject BCP14 referencegroup"
python3 inject_bcp14.py "${NAME}.unref.xml" "${NAME}.xml"

echo "==> xml2rfc --text"
xml2rfc --text "${NAME}.xml" -o "${NAME}.txt" 2>&1 | tail -3

rm -f "${NAME}.raw.xml" "${NAME}.stripped.xml" "${NAME}.unref.xml"

if command -v idnits >/dev/null 2>&1; then
    echo "==> idnits submission mode"
    idnits -m submission -o simple --no-color "${NAME}.xml" || true
    idnits -m submission -o simple --no-color "${NAME}.txt" || true
fi

echo "==> done. Upload ${NAME}.xml at https://datatracker.ietf.org/submit/"
