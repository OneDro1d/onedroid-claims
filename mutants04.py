#!/usr/bin/env python3
"""mutants04.py: the test suite of the 0.4 checks (SPEC.md section 5, K11 to K15). Standard library only.

usage: python3 -I mutants04.py [SNAPSHOT_DIR]   # default: the first 0.4 snapshot in this folder
Each mutant copies the snapshot into a temporary folder, applies one change, reseals the hashes a publisher would
(manifest sha256 fields, the witness header, claims_sha256) WITHOUT re-signing, runs check.py and compares the statuses
of the checks that matter with the expected ones. Exit 0 when every mutant gives the expected statuses."""
import hashlib, json, pathlib, shutil, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
SRC = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else HERE / "snapshots/onedroid/business-models-in-the-agentic-age/2026-11-11"


def sha(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


def load(p):
    return [json.loads(l) for l in pathlib.Path(p).read_text(encoding="utf-8").splitlines() if l.strip()]


def dump(p, rows):
    pathlib.Path(p).write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")


def witness_file(d):
    M = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    return next(w["file"] for w in M["grading"]["witnesses"] if w.get("primary"))


def reseal(d, remerge=False, missing=None):
    wf = witness_file(d)
    M = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    g = M["grading"]
    ah = sha(d / "audit.jsonl")
    g["auditor"]["sha256"] = ah
    rows = load(d / wf)
    rows[0]["over"]["sha256"] = ah
    dump(d / wf, rows)
    (d / "manifest.json").write_text(json.dumps(M, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    if remerge:
        subprocess.run([sys.executable, "-I", str(HERE / "merge.py"), str(d), "--write"], capture_output=True, text=True, check=True)
        M = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
        g = M["grading"]
    g["witnesses"][0]["sha256"] = sha(d / wf)
    if missing is not None:
        g["witnesses"][0]["missing_claims"] = missing
    (d / "manifest.json").write_text(json.dumps(M, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def run(tmp, name, mutate, expect):
    d = tmp / name
    shutil.copytree(SRC, d)
    (d / "CHECK.json").unlink(missing_ok=True)
    mutate(d)
    r = subprocess.run([sys.executable, "-I", str(HERE / "check.py"), str(d)], capture_output=True, text=True)
    status, first, cur = {}, {}, None
    for l in r.stdout.splitlines():
        head = l.split(" ")[0] if l else ""
        if l and not l.startswith(" ") and ":" in l and (head.startswith("K") or head == "SUMMARY:"):
            cur = head.rstrip(":")
            status[cur] = l.split(" ")[1].rstrip(":")
        elif l.startswith("    ") and cur and cur not in first:
            first[cur] = l.strip()
    ok = all(status.get(k) == v for k, v in expect.items())
    print(f"{'as expected' if ok else 'MISMATCH'}  {name}: expected {expect}, got {{{', '.join(f'{k!r}: {status.get(k)!r}' for k in expect)}}}")
    for k in expect:
        if status.get(k) == "FAIL" and k in first:
            print(f"    {k}: {first[k][:140]}")
    if r.returncode not in (0, 1):
        print("    stderr:", r.stderr[-300:])
    return ok


def flip(d, remerge):
    wf = witness_file(d)
    rows = load(d / wf)
    rows[2]["verdict"] = "NO EVIDENCE PUBLISHED"
    rows[2]["on"] = {"proofs": [], "counter": []}
    dump(d / wf, rows)
    reseal(d, remerge=remerge)


def edit_witness_row(d, **changes):
    wf = witness_file(d)
    rows = load(d / wf)
    for k, v in changes.items():
        rows[2][k] = v
    dump(d / wf, rows)
    reseal(d)


def add_missing(d, on_page):
    wf = witness_file(d)
    page = (d / "page.txt").read_text(encoding="utf-8").splitlines()
    if on_page:
        text = next(l for l in page if len(l.strip()) > 40)
        row = {"id": "M-001", "verdict": "MISSING CLAIM", "text": text.strip(), "location": [{"file": "page.txt", "line": page.index(text) + 1}], "note": "the auditor did not list this sentence"}
    else:
        row = {"id": "M-001", "verdict": "MISSING CLAIM", "text": "The brief was audited by a Martian.", "location": [{"file": "page.txt", "line": 1}], "note": "x"}
    rows = load(d / wf) + [row]
    dump(d / wf, rows)
    reseal(d, missing=1)


def decision_in_audit(d):
    rows = load(d / "audit.jsonl")
    rows[0]["verdict"] = "EVIDENCED"
    dump(d / "audit.jsonl", rows)
    reseal(d, remerge=True)


def damage_sig(d):
    p = d / "audit.jsonl.sig"
    b = bytearray(p.read_bytes())
    b[len(b) // 2] ^= 1
    p.write_bytes(bytes(b))


def alter_line(d):
    sigs = json.loads((d / "signatures.json").read_text(encoding="utf-8"))
    sigs[0]["line"] = sigs[0]["line"].replace("auditor", "witness", 1)
    (d / "signatures.json").write_text(json.dumps(sigs, indent=1), encoding="utf-8")


def drop_decision(d):
    wf = witness_file(d)
    rows = [r for r in load(d / wf) if r.get("id") != "C-003"]
    dump(d / wf, rows)
    reseal(d, remerge=True)


def anchor(d, over):
    (d / "anchors.json").write_text(json.dumps([{"over": "sha256:" + over, "method": "argus-commitment", "ref": "hc_test", "time": "2026-11-11T09:00:00Z"}]), encoding="utf-8")


def session(d, entry):
    M = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    M["grading"]["sessions"] = [entry]
    (d / "manifest.json").write_text(json.dumps(M, indent=1), encoding="utf-8")


def main():
    if not (SRC / "audit.jsonl").exists():
        print(f"{SRC} is not a 0.4 snapshot", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        results = [
            run(tmp, "verdict-flipped-not-merged", lambda d: flip(d, False), {"K11": "PASS", "K12": "FAIL", "K13": "FAIL"}),
            run(tmp, "verdict-flipped-merged-score-stale", lambda d: flip(d, True), {"K8": "FAIL", "K11": "PASS", "K12": "FAIL"}),
            run(tmp, "on-index-out-of-range", lambda d: edit_witness_row(d, on={"proofs": [9], "counter": []}), {"K11": "FAIL"}),
            run(tmp, "evidenced-on-nothing", lambda d: edit_witness_row(d, on={"proofs": [], "counter": []}), {"K11": "FAIL"}),
            run(tmp, "missing-claim-not-on-page", lambda d: add_missing(d, False), {"K11": "FAIL"}),
            run(tmp, "missing-claim-right", lambda d: add_missing(d, True), {"K11": "PASS", "K12": "PASS", "K13": "FAIL"}),
            run(tmp, "decision-in-audit", decision_in_audit, {"K11": "FAIL"}),
            run(tmp, "signature-damaged", damage_sig, {"K13": "FAIL"}),
            run(tmp, "signed-line-altered", alter_line, {"K13": "FAIL"}),
            run(tmp, "no-allowed-signers", lambda d: (d / "allowed_signers").unlink(), {"K13": "WARN"}),
            run(tmp, "primary-left-one-undecided", drop_decision, {"K3": "FAIL", "K11": "FAIL"}),
            run(tmp, "anchor-over-no-file", lambda d: anchor(d, "0" * 64), {"K14": "FAIL"}),
            run(tmp, "anchor-bound", lambda d: anchor(d, sha(d / "audit.jsonl.sig")), {"K14": "PASS"}),
            run(tmp, "session-without-hash", lambda d: session(d, {"role": "auditor", "recorder": "onedroid-indie 0.1.0-dev (1df3805)", "session_id": "s1", "complete": True, "gaps": 0, "held_by": "x"}), {"K15": "FAIL"}),
            run(tmp, "session-with-gaps", lambda d: session(d, {"role": "auditor", "recorder": "onedroid-indie 0.1.0-dev (1df3805)", "session_id": "s1", "record_sha256": "a" * 64, "complete": False, "gaps": 2, "held_by": "x", "available": "on request"}), {"K15": "WARN"}),
        ]
    print(f"{sum(results)} of {len(results)} mutants gave the expected statuses")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
