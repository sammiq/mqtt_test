#!/usr/bin/env python3
"""
Validate requirement-reference integrity for MQTT compliance tests.

Checks:
1) Every MQTT reference used in test `TestContext.refs` exists in REQUIREMENTS_TABLE.md.
2) Every "Implemented" requirement in REQUIREMENTS_TABLE.md is covered by at least one test ref,
   unless explicitly listed in scripts/requirements_implemented_waivers.txt.

Canonical-reference note from MQTT v5 spec:
- The prose uses MQTT-4.2-1, while the conformance statement table uses MQTT-4.2.0-1.
  Treat these as equivalent identifiers.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = ROOT / "src" / "tests"
REQ_TABLE = ROOT / "REQUIREMENTS_TABLE.md"
WAIVERS = ROOT / "scripts" / "requirements_implemented_waivers.txt"

REF_PATTERN = re.compile(r'MQTT-[0-9]+(?:\.[0-9]+)+(?:-[0-9]+)?')

# Spec alias: prose id <-> conformance statement id.
ALIASES = {
    "MQTT-4.2-1": "MQTT-4.2.0-1",
}


def normalize_ref(req_id: str) -> str:
    return ALIASES.get(req_id, req_id)


def load_canonical_requirements(table_text: str) -> set[str]:
    # Restrict canonical IDs to the requirements listed in REQUIREMENTS_TABLE.md.
    ids = set(REF_PATTERN.findall(table_text))
    return {normalize_ref(req_id) for req_id in ids}


def extract_test_refs() -> list[tuple[Path, str]]:
    refs: list[tuple[Path, str]] = []
    for path in sorted(TESTS_DIR.glob("*.rs")):
        content = path.read_text(encoding="utf-8")
        for match in re.finditer(r"refs:\s*&\[(.*?)\]", content, re.S):
            segment = match.group(1)
            for req_id in re.findall(r'"(MQTT-[^"]+)"', segment):
                refs.append((path, req_id))
    return refs


def extract_implemented_requirements(table_text: str) -> set[str]:
    implemented = set()
    line_re = re.compile(
        r"^\|\s*(MQTT-[^|]+?)\s*\|\s*(MUST|SHOULD|MAY)\s*\|\s*Implemented\s*\|"
    )
    for line in table_text.splitlines():
        match = line_re.match(line)
        if match:
            implemented.add(normalize_ref(match.group(1).strip()))
    return implemented


def load_waivers() -> set[str]:
    if not WAIVERS.exists():
        return set()
    waived = set()
    for line in WAIVERS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        waived.add(normalize_ref(line))
    return waived


def main() -> int:
    table_text = REQ_TABLE.read_text(encoding="utf-8")
    canonical = load_canonical_requirements(table_text)
    test_refs = extract_test_refs()

    unknown_refs = []
    for path, req_id in test_refs:
        normalized = normalize_ref(req_id)
        if normalized not in canonical:
            unknown_refs.append((path.relative_to(ROOT), req_id))

    used_refs = {normalize_ref(req_id) for _, req_id in test_refs}
    implemented = extract_implemented_requirements(table_text)
    waivers = load_waivers()
    missing_implemented = sorted((implemented - used_refs) - waivers)

    had_error = False
    if unknown_refs:
        had_error = True
        print("ERROR: Unknown requirement IDs used in test refs:")
        for path, req_id in unknown_refs:
            print(f"  - {path}: {req_id}")
        print()

    if missing_implemented:
        had_error = True
        print(
            "ERROR: Implemented requirements without test refs "
            "(and not waived in scripts/requirements_implemented_waivers.txt):"
        )
        for req_id in missing_implemented:
            print(f"  - {req_id}")
        print()

    if had_error:
        print("Requirement reference validation failed.")
        return 1

    print("Requirement reference validation passed.")
    print(f"- Canonical requirements in table: {len(canonical)}")
    print(f"- Requirement refs found in tests: {len(test_refs)}")
    print(f"- Waived implemented requirements: {len(waivers)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
