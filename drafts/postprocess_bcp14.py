#!/usr/bin/env python3
"""Post-process the v3 RFC XML so it satisfies idnits3 structural checks.

Two transforms are applied in place on the v3 XML emitted by `xml2rfc --v2v3`:

Fix A -- BCP14 referencegroup (idnits3 MISSING_REQLEVEL_REF):
  Wrap the standalone RFC2119 and RFC8174 <reference> elements in a
  <referencegroup anchor="BCP14" target="https://www.rfc-editor.org/info/bcp14">
  and retarget the body boilerplate xrefs (RFC2119 + RFC8174) to a single
  <xref target="BCP14"/> so a reference to BCP14 itself is present and used.

Fix B -- references section naming (idnits3 INVALID_REFERENCES_NAME):
  Remove the outer <references anchor="sec-combined-references"><name>References</name>
  wrapper and promote the inner "Normative References" / "Informative References"
  <references> elements to top-level siblings under <back>, so the first
  references section's <name> is "Normative References".

Uses only the Python standard library (xml.etree.ElementTree). The v3 XML
xml2rfc emits has no default namespace, so element tags are unqualified.
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET

BCP14_TARGET = "https://www.rfc-editor.org/info/bcp14"
REQLEVEL_ANCHORS = ("RFC2119", "RFC8174")


def _find_parent(root: ET.Element, child: ET.Element) -> ET.Element | None:
    for parent in root.iter():
        for elem in list(parent):
            if elem is child:
                return parent
    return None


def fix_a_bcp14_group(root: ET.Element) -> None:
    """Group RFC2119/RFC8174 into a BCP14 referencegroup and retarget xrefs."""
    # Locate the two reqlevel <reference> elements and their shared parent.
    reqlevel_refs: dict[str, ET.Element] = {}
    parent: ET.Element | None = None
    for ref in root.iter("reference"):
        anchor = ref.get("anchor")
        if anchor in REQLEVEL_ANCHORS:
            reqlevel_refs[anchor] = ref
            p = _find_parent(root, ref)
            if p is not None:
                parent = p

    if set(reqlevel_refs) != set(REQLEVEL_ANCHORS) or parent is None:
        print(
            "  [Fix A] WARNING: RFC2119/RFC8174 references not found as a pair; "
            "skipping BCP14 grouping",
            file=sys.stderr,
        )
        return

    # Already grouped? (idempotent re-runs)
    if root.find(".//referencegroup[@anchor='BCP14']") is not None:
        print("  [Fix A] BCP14 referencegroup already present; skipping", file=sys.stderr)
        return

    # Build the referencegroup, preserving child order (RFC2119 then RFC8174),
    # and insert it where the first reqlevel reference currently sits.
    children = list(parent)
    first_idx = min(children.index(reqlevel_refs[a]) for a in REQLEVEL_ANCHORS)

    group = ET.Element(
        "referencegroup",
        {"anchor": "BCP14", "target": BCP14_TARGET},
    )
    for anchor in REQLEVEL_ANCHORS:
        ref = reqlevel_refs[anchor]
        parent.remove(ref)
        group.append(ref)

    parent.insert(first_idx, group)
    print("  [Fix A] created <referencegroup anchor='BCP14'> wrapping RFC2119+RFC8174")

    # Retarget the body boilerplate: the Conventions <t> cites BCP14 via
    # <xref target="RFC2119"/> <xref target="RFC8174"/>. Replace the first with
    # a single <xref target="BCP14"/> and drop the second, preserving tails.
    retargeted = False
    for t in root.iter("t"):
        xrefs = [x for x in t.findall("xref") if x.get("target") in REQLEVEL_ANCHORS]
        if len(xrefs) >= 2 and not retargeted:
            t_children = list(t)
            first = xrefs[0]
            second = xrefs[1]
            # Carry the second xref's tail onto the first so spacing survives.
            first.set("target", "BCP14")
            first.tail = second.tail
            # Remove the (now redundant) second reqlevel xref.
            # Preserve any text that preceded `second` by folding its preceding
            # sibling's tail handling: simplest robust path is just removing it.
            idx_first = t_children.index(first)
            idx_second = t_children.index(second)
            # If first xref's original tail was just whitespace between the two
            # xrefs, collapse it so we don't leave a double space.
            if idx_second == idx_first + 1:
                pass  # tail already replaced above
            t.remove(second)
            retargeted = True
            print("  [Fix A] retargeted body xref RFC2119+RFC8174 -> single BCP14 xref")
            break
    if not retargeted:
        print(
            "  [Fix A] WARNING: did not find paired RFC2119/RFC8174 body xrefs to retarget",
            file=sys.stderr,
        )


def fix_b_references_naming(root: ET.Element) -> None:
    """Promote inner Normative/Informative <references> to top-level siblings."""
    back = root.find("back")
    if back is None:
        print("  [Fix B] WARNING: no <back> element found; skipping", file=sys.stderr)
        return

    # Find the outer combined wrapper: a <references> directly under <back>
    # that itself contains child <references> elements.
    outer = None
    for ref in list(back):
        if ref.tag == "references" and ref.find("references") is not None:
            outer = ref
            break

    if outer is None:
        print(
            "  [Fix B] no combined-references wrapper found; structure already flat",
            file=sys.stderr,
        )
        return

    inner_sections = [c for c in list(outer) if c.tag == "references"]
    outer_idx = list(back).index(outer)
    back.remove(outer)
    for offset, section in enumerate(inner_sections):
        back.insert(outer_idx + offset, section)

    names = [
        (s.find("name").text if s.find("name") is not None else "?") for s in inner_sections
    ]
    print(
        f"  [Fix B] removed combined wrapper; promoted {len(inner_sections)} "
        f"top-level references sections: {names}"
    )


def main(path: str) -> int:
    tree = ET.parse(path)
    root = tree.getroot()

    fix_a_bcp14_group(root)
    fix_b_references_naming(root)

    # ElementTree preserves the input DOCTYPE poorly; xml2rfc --text re-parses
    # and only needs well-formed v3 XML, so a plain write is sufficient.
    tree.write(path, encoding="unicode", xml_declaration=False)
    # Re-prepend the XML declaration that ET drops with encoding="unicode".
    with open(path, encoding="utf-8") as fh:
        body = fh.read()
    if not body.startswith("<?xml"):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("<?xml version='1.0' encoding='utf-8'?>\n")
            fh.write(body)
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: postprocess_bcp14.py <v3-xml-file>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
