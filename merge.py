#!/usr/bin/env python3
"""merge.py: claims.jsonl from audit.jsonl and one witness file (SPEC.md 4b). Standard library only.

usage: python3 -I merge.py SNAPSHOT_DIR [--witness NAME]   # prints the merged rows; NAME defaults to the primary witness
       python3 -I merge.py SNAPSHOT_DIR --write             # rewrites claims.jsonl and claims_sha256 in manifest.json
The merge is check.merge_rows, so this script and the checker cannot drift."""
import json, pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check  # noqa: E402


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    snap = pathlib.Path(argv[1])
    M = json.loads((snap / "manifest.json").read_text(encoding="utf-8"))
    witnesses = M.get("grading", {}).get("witnesses") or []
    name = argv[argv.index("--witness") + 1] if "--witness" in argv else next((w["name"] for w in witnesses if w.get("primary")), None)
    w = next((w for w in witnesses if w.get("name") == name), None)
    if w is None:
        print(f"no witness {name!r} in manifest.grading.witnesses", file=sys.stderr)
        return 1
    audit = check.load_jsonl(snap / "audit.jsonl")
    _, rows = check.load_witness(snap / w["file"])
    text = check.dump_jsonl(check.merge_rows(audit, rows, name))
    if "--write" in argv:
        (snap / "claims.jsonl").write_text(text, encoding="utf-8")
        M["claims_sha256"] = check.sha256(snap / "claims.jsonl")
        (snap / "manifest.json").write_text(json.dumps(M, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(f"claims.jsonl written from audit.jsonl and witness {name!r}: {len(audit)} rows, sha256 {M['claims_sha256'][:12]}…")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
