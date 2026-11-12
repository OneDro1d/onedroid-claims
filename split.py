#!/usr/bin/env python3
"""split.py: a 0.2 or 0.3 snapshot as a new 0.4 snapshot folder (SPEC.md 4a, 4b): the grader's rows become the auditor's
part (audit.jsonl, no decisions) and one witness file holding the decisions; claims.jsonl is rebuilt by the merge.
The source folder is not touched (a published snapshot is immutable); the page, sources and manifest are copied.
Standard library only.

usage: python3 -I split.py SRC_DIR DST_DIR --auditor NAME --witness NAME [--witness-file SLUG] [--witness-model TEXT] [--witness-method TEXT] [--note TEXT]
The auditor and witness names are the people or sessions the manifest already describes in grading.grader; a self-audit
keeps grading.kind self-audit. Signatures, anchors and session records are added afterwards (sign.py, by hand)."""
import json, pathlib, re, shutil, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check  # noqa: E402

AUDIT_DROP = ("verdict", "confidence", "note", "history", "graded_by", "graded_at", "witness", "evidence_missing")


def arg(argv, flag, default=None):
    return argv[argv.index(flag) + 1] if flag in argv else default


def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60]


def main(argv):
    if len(argv) < 3 or "--auditor" not in argv or "--witness" not in argv:
        print(__doc__)
        return 2
    src, dst = pathlib.Path(argv[1]), pathlib.Path(argv[2])
    auditor, witness = arg(argv, "--auditor"), arg(argv, "--witness")
    if dst.exists():
        print(f"{dst} exists; a snapshot folder is never overwritten", file=sys.stderr)
        return 1
    M = json.loads((src / "manifest.json").read_text(encoding="utf-8"))
    if M.get("format") not in ("claims-snapshot/0.2", "claims-snapshot/0.3"):
        print(f"source format {M.get('format')!r} is not 0.2 or 0.3", file=sys.stderr)
        return 1
    claims = check.load_jsonl(src / "claims.jsonl")
    g = M["grading"]

    # copy everything but the files the split rebuilds
    dst.mkdir(parents=True)
    for p in src.rglob("*"):
        rel = p.relative_to(src)
        if p.is_dir():
            (dst / rel).mkdir(parents=True, exist_ok=True)
        elif rel.name not in ("claims.jsonl", "manifest.json", "CHECK.txt", "CHECK.json"):
            shutil.copy2(p, dst / rel)

    # the auditor's part: the row without its decision; audited_by / audited_at from the grader's record
    audit = []
    for c in claims:
        a = {k: v for k, v in c.items() if k not in AUDIT_DROP}
        a["audited_by"] = auditor
        a["audited_at"] = c.get("graded_at")
        audit.append(a)
    (dst / "audit.jsonl").write_text(check.dump_jsonl(audit), encoding="utf-8")
    audit_h = check.sha256(dst / "audit.jsonl")

    # the witness file: header over the audit hash, one decision per claim resting on every candidate the grader had
    wslug = slug(arg(argv, "--witness-file", witness))
    (dst / "witness").mkdir()
    header = {"witness": witness, "model": arg(argv, "--witness-model", g.get("model")), "method": arg(argv, "--witness-method", g.get("method")),
              "over": {"file": "audit.jsonl", "sha256": audit_h}, "started_at": g.get("graded_at"), "finished_at": g.get("graded_at"),
              "note": "Decisions converted from the grader's rows of the source snapshot by split.py; `on` names every candidate the grader recorded, because the source format did not say which one each decision rested on."}
    wrows = []
    for c in claims:
        wrows.append({"id": c["id"], "verdict": c.get("verdict"), "confidence": c.get("confidence"),
                      "on": {"proofs": list(range(len(c.get("proofs") or []))), "counter": list(range(len(c.get("counter") or [])))},
                      "note": c.get("note"), "history": c.get("history"), "graded_by": c.get("graded_by", "grader"), "graded_at": c.get("graded_at")})
    wfile = f"witness/{wslug}.jsonl"
    (dst / wfile).write_text(check.dump_jsonl([header] + wrows), encoding="utf-8")

    # the merge, the manifest
    merged = check.merge_rows(audit, wrows, witness)
    (dst / "claims.jsonl").write_text(check.dump_jsonl(merged), encoding="utf-8")
    sc = check.evidence_score(merged)
    M["format"] = "claims-snapshot/0.4"
    M["claims_sha256"] = check.sha256(dst / "claims.jsonl")
    g["auditor"] = {"name": auditor, "model": g.get("model"), "signer": None, "file": "audit.jsonl", "sha256": audit_h}
    g["witnesses"] = [{"name": witness, "model": header["model"], "method": header["method"], "signer": None, "file": wfile,
                       "sha256": check.sha256(dst / wfile), "primary": True,
                       "score": {"coverage_pct": sc["coverage_pct"], "contradiction_pct": sc["contradiction_pct"], "band": sc["band"]},
                       "missing_claims": 0}]
    g.setdefault("sessions", [])
    note = arg(argv, "--note")
    M["split_from"] = {"folder": str(src.name), "format": json.loads((src / "manifest.json").read_text(encoding="utf-8"))["format"],
                       "claims_sha256": json.loads((src / "manifest.json").read_text(encoding="utf-8")).get("claims_sha256"),
                       "note": note or "Format upgrade by split.py: same page text, sources and decisions as the source snapshot."}
    (dst / "manifest.json").write_text(json.dumps(M, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    # the merge must restore every decision of the source
    back = {r["id"]: (r.get("verdict"), r.get("confidence"), r.get("graded_by")) for r in merged}
    orig = {c["id"]: (c.get("verdict"), c.get("confidence"), c.get("graded_by")) for c in claims}
    assert back == orig, "the merge does not restore the source decisions"
    print(f"{dst}: audit.jsonl {len(audit)} rows (sha256 {audit_h[:12]}…), {wfile} {len(wrows)} decisions, claims.jsonl rebuilt, "
          f"score {sc['coverage_pct']}% / {sc['contradiction_pct']}% band {sc['band']}. Next: sign.py for each part, check.py --json.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
