#!/usr/bin/env python3
"""Post-process xml2rfc v3 output to add a BCP14 referencegroup.

kramdown-rfc 1.7.39 cannot fetch BCP14 from bibxml (the URL it tries
has bit-rotted), so we inject a self-contained referencegroup after
v2v3 conversion. This satisfies idnits3 PREFER_BCP14_REF without a
network dependency at render time.

We keep the original RFC2119 + RFC8174 references at top-level (renamed
inside the BCP14 group to avoid anchor clashes) so idnits3's normal-mode
boilerplate-pattern matcher still recognises the cites in the body.

Usage: inject_bcp14.py <input.xml> <output.xml>
"""

from __future__ import annotations

import re
import sys

BCP14_GROUP = '''
  <referencegroup anchor="BCP14" target="https://www.rfc-editor.org/info/bcp14">
    <reference anchor="BCP14_RFC2119" target="https://www.rfc-editor.org/info/rfc2119">
      <front>
        <title>Key words for use in RFCs to Indicate Requirement Levels</title>
        <author fullname="S. Bradner" initials="S." surname="Bradner"/>
        <date month="March" year="1997"/>
      </front>
      <seriesInfo name="BCP" value="14"/>
      <seriesInfo name="RFC" value="2119"/>
    </reference>
    <reference anchor="BCP14_RFC8174" target="https://www.rfc-editor.org/info/rfc8174">
      <front>
        <title>Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words</title>
        <author fullname="B. Leiba" initials="B." surname="Leiba"/>
        <date month="May" year="2017"/>
      </front>
      <seriesInfo name="BCP" value="14"/>
      <seriesInfo name="RFC" value="8174"/>
    </reference>
  </referencegroup>
'''


def main(src: str, dst: str) -> int:
    xml = open(src).read()

    # Replace boilerplate "BCP 14 [RFC2119] [RFC8174]" cites with
    # "BCP 14 [BCP14]" so the body references BCP14 directly.
    xml = re.sub(
        r'<xref target="RFC2119"\s*/>\s*<xref target="RFC8174"\s*/>',
        '<xref target="BCP14"/>',
        xml,
        count=1,
    )

    # Drop the now-orphan top-level RFC2119 / RFC8174 references; the
    # BCP14 referencegroup carries them under different anchors.
    xml = re.sub(
        r'\s*<reference anchor="RFC2119"[^>]*>.*?</reference>',
        '',
        xml,
        flags=re.DOTALL,
    )
    xml = re.sub(
        r'\s*<reference anchor="RFC8174"[^>]*>.*?</reference>',
        '',
        xml,
        flags=re.DOTALL,
    )

    # Insert the BCP14 referencegroup at the top of the Normative
    # References block. xml2rfc --v2v3 emits one <references> wrapper
    # in <back> with sub-<references> for normative + informative.
    xml = xml.replace(
        '<name>Normative References</name>',
        '<name>Normative References</name>' + BCP14_GROUP,
        1,
    )

    open(dst, 'w').write(xml)
    return 0


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('usage: inject_bcp14.py <input.xml> <output.xml>', file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
