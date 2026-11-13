#!/usr/bin/env python3
"""mutants06s.py: the test suite of the 0.6 checker cut of 13 Nov 2026 (NEXT-REVISION items 20, 21's neighbour and 22):

R1  load_jsonl splits on "\\n" only (a trailing "\\r" stripped), never str.splitlines(), which also cuts a line at U+2028, U+2029,
    U+0085, \\v, \\f and \\x1c to \\x1e; a raw U+2028 inside a claim's text is valid JSON that dump_jsonl writes as is, and the checker
    crashed on reading it back (the claims session's N4, 13 Nov 2026).
R2  K2 is complete and strict: it names, with their hashes, pages[].file, sources[].file, claims.jsonl (not pre-witness),
    grading.auditor.file with grading.auditor.sha256, every grading.witnesses[].file with its sha256, and the manifest's `files` in
    both shapes (a list of {file, sha256}, or an object file -> sha256, the kit's writer). A file named twice with one hash counts
    once; with two different hashes it is "X: named with two different sha256". A `files` entry naming a STRUCTURAL file
    (manifest.json, signatures.json, allowed_signers, anchors.json, CHECK.json, CHECK.txt) is refused, its hash unchecked.

Fixtures, built in a temporary folder from the published agent-work example with throwaway keys (no key leaves the folder):
  A   examples/agent-work-s-i10-2026-11-12 as published (0.5, complete). Its `files` is an OBJECT (the kit's writer). As the implementer
      found before the first run (13 Nov 2026 01:2xZ), the example AS FIRST PUBLISHED named allowed_signers, anchors.json and
      signatures.json by hash, so R2 failed K2 on the unchanged example and on examples/test-run-example-2026-11-12 (the same writer);
      the owner removed those three entries from both manifests in the same cut (neither manifest is signed or anchored: signatures.json
      holds the auditor and witness roles only, anchors.json is empty) and the fact is kept as case s11K below, which re-adds them.
  AL  A with `files` rewritten as a LIST of {file, sha256} over its content files only (what the brief's "A (list shape)" needs for
      s3 and s9; the structural entries dropped as add_witness.py does since item 22).
  B   the pre-witness copy of A made the way mutants06p.py makes its fixtures (to_pre: 0.6, grading.kind pre-witness, re-signed with
      the throwaway auditor key), then `files` REMOVED. The literal to_pre(A) is run too (B_literal_to_pre): since the owner's fix of
      to_pre in this cut it drops the structural entries and refreshes the re-signed audit.jsonl.sig, so it passes K2 (before the fix it
      kept the writer's object and failed K2 twice over, structural entries and a stale .sig hash).
  C   B with `files` rewritten as an OBJECT naming every content file by hash exactly as the kit's writer does
      (page.txt, sources/files/*.txt, audit.jsonl, audit.jsonl.sig; B has no witness file).

Cases and the statuses expected BEFORE the first run (s1 to s11 as the brief numbered them; two observed-fact cases added):
  s1  C unchanged: K2 PASS, "5 files named, hashes match" (page.txt, bye.txt, hello.txt, audit.jsonl, audit.jsonl.sig).
  s2  C + files["signatures.json"] (real hash): K2 FAIL naming it as structural.
  s3  AL + {file: CHECK.json, sha256: its real hash} appended to the list (a stub CHECK.json written first): K2 FAIL naming it.
  s4  C + files["allowed_signers"] + files["anchors.json"]: K2 FAIL naming both.
  s5  B, one byte of audit.jsonl changed, nothing else: K2 FAIL (audit.jsonl through grading.auditor), K11 FAIL, K13 FAIL.
  s6  B + one model witness (mutants06p.add_model_witness), one byte of the witness file changed: K2 FAIL, K13 FAIL (K11 FAIL too).
  s7  C with files["audit.jsonl"] set to a hash that differs from grading.auditor.sha256: K2 FAIL "named with two different sha256".
  s8  B with a raw U+2028 in a claim text, audit.jsonl re-written with check.dump_jsonl and re-signed, grading.auditor.sha256
      refreshed: a SUMMARY line (no exception), K1 PASS, K3 PASS, K8 WARN with the same row count as before the edit (3 claims).
  s9  AL with claims.jsonl re-written CRLF, claims_sha256 and the list entry for claims.jsonl refreshed, the auditor part untouched:
      K2 PASS, K3 and K4 and K12 as on AL (PASS).
  s10 B + one model witness, its file deleted from disk: K2 FAIL "missing" (K11 FAIL too).
  s11 A (repaired) under the committed checker (git HEAD:claims-standard/check.py, or --committed PATH) and the working one: every
      status equal, K2's text differing in its count only; both K2 lines printed. s11L does the same on AL. s11K re-adds the three
      structural entries the kit's writer wrote: the committed checker PASSes K2 (it skipped an object `files`), the working one FAILs
      naming them. (Against the committed checker the repaired A's K2 count also differs: it never counted the object's entries.)
  s12 C with `files` set to a string (a shape nobody writes): K2 FAIL "files: neither a list of {file, sha256} nor an object", no crash.
  B_fixture, B_literal_to_pre: the fixture sanity lines described under B.

usage: python3 -I mutants06s.py [--committed PATH_TO_COMMITTED_CHECK_PY | --committed none]
  (default: git HEAD:claims-standard/check.py of the notepad; `none` skips s11, s11L and s11K, for the public repository's CI)
Exit 0 only when every expectation holds; one line per case with expected and observed statuses; MISMATCH counted."""
import json, pathlib, shutil, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402
import mutants06 as m  # noqa: E402
import mutants06p as p  # noqa: E402

ARGS = sys.argv[1:]
_COMMITTED_ARG = ARGS[ARGS.index("--committed") + 1] if "--committed" in ARGS else None
SKIP_COMMITTED = _COMMITTED_ARG == "none"  # `--committed none`: no committed checker to compare with (CI of the public repository, whose HEAD is the cut itself)
COMMITTED = pathlib.Path(_COMMITTED_ARG).resolve() if _COMMITTED_ARG and not SKIP_COMMITTED else None
SRC_A = HERE / "examples/agent-work-s-i10-2026-11-12"
STRUCTURAL = ("manifest.json", "signatures.json", "allowed_signers", "anchors.json", "CHECK.json", "CHECK.txt")
WF = f"witness/{p.MW}.jsonl"


def content_files(d, M):
    """Every content file of the folder with its hash, as the kit's writer lists them: pages, sources, audit.jsonl and its .sig,
    claims.jsonl when present, witness files and their .sig."""
    names = [pg["file"] for pg in M.get("pages") or []] + [s["file"] for s in M.get("sources") or [] if s.get("file")]
    for f in ("audit.jsonl", "audit.jsonl.sig", "claims.jsonl"):
        if (d / f).exists():
            names.append(f)
    for w in (M.get("grading") or {}).get("witnesses") or []:
        if w.get("file") and (d / w["file"]).exists():
            names.append(w["file"])
            if (d / (w["file"] + ".sig")).exists():
                names.append(w["file"] + ".sig")
    out = {}
    for f in names:
        out.setdefault(f, m.sha(d / f))
    return out


def files_as_list(d):
    M = m.mload(d)
    M["files"] = [{"file": f, "sha256": h} for f, h in content_files(d, M).items()]
    m.msave(d, M)


def files_as_object(d):
    M = m.mload(d)
    M["files"] = content_files(d, M)
    m.msave(d, M)


def files_removed(d):
    M = m.mload(d)
    M.pop("files", None)
    m.msave(d, M)


def build(root):
    keydir = root / "keys"
    keydir.mkdir(parents=True)
    m.keygen(keydir)
    fx = {}
    fx["A"] = root / "fixtureA"
    shutil.copytree(SRC_A, fx["A"])
    (fx["A"] / "CHECK.json").unlink(missing_ok=True)
    fx["AL"] = root / "fixtureAL"
    shutil.copytree(fx["A"], fx["AL"])
    files_as_list(fx["AL"])
    fx["Blit"] = root / "fixtureB_literal"
    shutil.copytree(fx["A"], fx["Blit"])
    p.to_pre(fx["Blit"])
    fx["B"] = root / "fixtureB"
    shutil.copytree(fx["Blit"], fx["B"])
    files_removed(fx["B"])
    fx["C"] = root / "fixtureC"
    shutil.copytree(fx["B"], fx["C"])
    files_as_object(fx["C"])
    return fx


def mut(fn):
    def f(d):
        M = m.mload(d)
        fn(M, d)
        m.msave(d, M)
    return f


def add_struct(*names):
    def f(M, d):
        for n in names:
            M["files"][n] = m.sha(d / n)
    return mut(f)


def s3_check_json_in_list(d):
    (d / "CHECK.json").write_text('{"stub": "a CHECK.json so that the entry names a real hash"}\n', encoding="utf-8")
    M = m.mload(d)
    M["files"].append({"file": "CHECK.json", "sha256": m.sha(d / "CHECK.json")})
    m.msave(d, M)


def one_byte(d, f, old, new):
    t = (d / f).read_text(encoding="utf-8")
    assert t.count(old) == 1 and len(old) == len(new), (f, old, new)
    (d / f).write_text(t.replace(old, new), encoding="utf-8")


def s5_audit_byte(d):
    one_byte(d, "audit.jsonl", "hello.txt holds hi", "hello.txt holds ha")


def s6_witness_byte(d):
    p.add_model_witness(d)
    one_byte(d, WF, "fixture witness", "fixturE witness")


def s7_two_hashes(d):
    M = m.mload(d)
    M["files"]["audit.jsonl"] = "0" * 64
    m.msave(d, M)


def s8_u2028(d):
    rows = check.load_jsonl(d / "audit.jsonl")
    rows[0]["text"] = rows[0]["text"] + " (a raw U+2028 inside the claim text)"
    (d / "audit.jsonl").write_text(check.dump_jsonl(rows), encoding="utf-8")
    raw = (d / "audit.jsonl").read_bytes()
    assert " ".encode("utf-8") in raw and b"\\u2028" not in raw, "dump_jsonl must write the separator raw"
    assert raw.count(b"\n") == 3, raw.count(b"\n")
    p.resign_audit(d)


def s9_crlf(d):
    raw = (d / "claims.jsonl").read_bytes()
    assert b"\r\n" not in raw
    (d / "claims.jsonl").write_bytes(raw.replace(b"\n", b"\r\n"))
    M = m.mload(d)
    h = m.sha(d / "claims.jsonl")
    M["claims_sha256"] = h
    for e in M["files"]:
        if e["file"] == "claims.jsonl":
            e["sha256"] = h
    m.msave(d, M)


def s10_witness_deleted(d):
    p.add_model_witness(d)
    (d / WF).unlink()


def s11k_kit_structural_entries(d):
    """The example as the kit's writer first wrote it (Indie #71): allowed_signers, anchors.json and signatures.json in `files` by hash."""
    M = m.mload(d)
    for n in ("allowed_signers", "anchors.json", "signatures.json"):
        M["files"][n] = m.sha(d / n)
    m.msave(d, M)


def s12_files_string(d):
    M = m.mload(d)
    M["files"] = "garbage"
    m.msave(d, M)


def committed_checker(tmp):
    if COMMITTED is not None:
        return COMMITTED
    out = tmp / "check_committed.py"
    r = subprocess.run(["git", "-C", str(HERE), "show", "HEAD:claims-standard/check.py"], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("git show HEAD:claims-standard/check.py: " + r.stderr)
    out.write_text(r.stdout, encoding="utf-8")
    return out


def run_committed_vs_working(tmp, fx, name, committed, k2_expected_equal, mutate=None):
    """Every check's status under the committed checker and the working one; K2 is the one allowed difference."""
    d = tmp / name
    shutil.copytree(fx, d)
    (d / "CHECK.json").unlink(missing_ok=True)
    if mutate is not None:
        mutate(d)
    outs = {}
    for label, chk in (("committed", committed), ("working", HERE / "check.py")):
        r = subprocess.run([sys.executable, "-I", str(chk), str(d)], capture_output=True, text=True)
        outs[label] = (r.returncode, *m.statuses(r.stdout))
    sc, sw = outs["committed"][1], outs["working"][1]
    keys = sorted(set(sc) | set(sw), key=lambda k: (k != "SUMMARY", len(k), k))
    diff = [k for k in keys if sc.get(k) != sw.get(k)]
    k2c, k2w = sc.get("K2"), sw.get("K2")
    if k2_expected_equal:
        ok = not diff
        want = "every status equal (K2 text may differ)"
    else:
        # since the K2 cut was committed (13 Nov 2026 01:4xZ) the committed checker FAILs these entries too, so the case asserts the working
        # checker's refusal and that no OTHER status differs; the committed K2 status is printed, not asserted (it was PASS before the cut)
        ok = diff in ([], ["K2"]) and k2w == "FAIL" and "a structural file named by hash in files" in outs["working"][2].get("K2", "")
        want = "every status but K2 equal; working K2 FAIL naming a structural file (committed K2 printed, not asserted)"
    print(f"{'as expected' if ok else 'MISMATCH'}  {name}: expected {want}; observed differing {diff or 'none'}, "
          f"exit committed={outs['committed'][0]} working={outs['working'][0]}")
    print("    committed K2: " + outs["committed"][2].get("K2", "").splitlines()[0])
    print("    working   K2: " + outs["working"][2].get("K2", "").splitlines()[0])
    for l in outs["working"][2].get("K2", "").splitlines()[1:]:
        print("    working   K2 detail:" + l)
    for k in diff:
        if k != "K2":
            print(f"    {k}: committed {sc.get(k)!r} working {sw.get(k)!r}")
    return ok


def main():
    if not (SRC_A / "audit.jsonl").exists():
        print(f"{SRC_A} has no audit.jsonl: fixture A is the agent-work example of this folder", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        fx = build(tmp / "build")
        A, AL, B, Blit, C = fx["A"], fx["AL"], fx["B"], fx["Blit"], fx["C"]
        committed = None if SKIP_COMMITTED else committed_checker(tmp)
        n_rows = len(check.load_jsonl(B / "audit.jsonl"))
        base_pre = {"K1": "PASS", "K2": "PASS", "K3": "PASS", "K4": "PASS", "K5": "PASS", "K8": "WARN", "K11": "PASS", "K12": "WARN", "K13": "PASS"}
        structural_line = "a structural file named by hash in files"
        results = []
        # fixtures as built
        results.append(m.run(tmp, B, "B_fixture", lambda d: None, base_pre, has={"K1": "pre-witness: the auditor's part alone"}))
        results.append(m.run(tmp, Blit, "B_literal_to_pre", lambda d: None, dict(base_pre), has={"K2": "files named, hashes match"}))
        # s1 to s4: the object shape counted, structural files refused
        results.append(m.run(tmp, C, "s1_C_unchanged", lambda d: None, dict(base_pre), has={"K2": "5 files named, hashes match"}))
        results.append(m.run(tmp, C, "s2_C_signatures_json_in_files", add_struct("signatures.json"), {"K2": "FAIL"}, has={"K2": "signatures.json: " + structural_line}))
        results.append(m.run(tmp, AL, "s3_AL_CHECK_json_in_list", s3_check_json_in_list, {"K2": "FAIL"}, has={"K2": "CHECK.json: " + structural_line}))
        results.append(m.run(tmp, C, "s4_C_allowed_signers_and_anchors_in_files", add_struct("allowed_signers", "anchors.json"), {"K2": "FAIL"},
                             has={"K2": "allowed_signers: " + structural_line}))
        results.append(m.run(tmp, C, "s4b_C_anchors_named_too", add_struct("allowed_signers", "anchors.json"), {"K2": "FAIL"}, has={"K2": "anchors.json: " + structural_line}))
        # s5 to s7: the auditor part and the witness files are K2's too, one file one hash
        results.append(m.run(tmp, B, "s5_B_audit_byte", s5_audit_byte, {"K2": "FAIL", "K11": "FAIL", "K13": "FAIL"}, has={"K2": "audit.jsonl: sha256"}))
        results.append(m.run(tmp, B, "s6_B_witness_byte", s6_witness_byte, {"K2": "FAIL", "K13": "FAIL"}, has={"K2": WF + ": sha256"}))
        results.append(m.run(tmp, C, "s7_C_audit_two_hashes", s7_two_hashes, {"K2": "FAIL"}, has={"K2": "audit.jsonl: named with two different sha256"}))
        # s8, s9: rows split on "\n" only, CRLF still read
        results.append(m.run(tmp, B, "s8_B_raw_U2028_in_claim_text", s8_u2028, {"K1": "PASS", "K3": "PASS", "K8": "WARN", "K13": "PASS"},
                             has={"SUMMARY": "SUMMARY:", "K8": f"pre-witness: {n_rows} claims, {n_rows} checkable (counts agree)"}))
        results.append(m.run(tmp, AL, "s9_AL_claims_crlf", s9_crlf, {"K2": "PASS", "K3": "PASS", "K4": "PASS", "K12": "PASS"}))
        # s10: a listed witness file gone
        results.append(m.run(tmp, B, "s10_B_witness_file_deleted", s10_witness_deleted, {"K2": "FAIL", "K11": "FAIL"}, has={"K2": WF + ": missing"}))
        # s11: the committed checker beside the working one on the repaired example, on its list-shaped copy, and on the example as the
        # kit's writer first wrote it (the three structural entries re-added)
        if SKIP_COMMITTED:
            print("skipped      s11, s11L, s11K: --committed none, no committed checker to compare with (s2 to s4 cover the structural refusal)")
        else:
            results.append(run_committed_vs_working(tmp, A, "s11_A_unchanged_vs_committed", committed, k2_expected_equal=True))
            results.append(run_committed_vs_working(tmp, AL, "s11L_AL_unchanged_vs_committed", committed, k2_expected_equal=True))
            results.append(run_committed_vs_working(tmp, A, "s11K_A_as_the_kit_wrote_it_vs_committed", committed, k2_expected_equal=False, mutate=s11k_kit_structural_entries))
        # s12: files of a shape nobody writes
        results.append(m.run(tmp, C, "s12_C_files_is_a_string", s12_files_string, {"K2": "FAIL"}, has={"K2": "files: neither a list of {file, sha256} nor an object"}))
        mism = sum(1 for r in results if not r)
        print(f"{sum(results)} of {len(results)} cases gave the expected statuses; MISMATCH {mism}")
        return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
