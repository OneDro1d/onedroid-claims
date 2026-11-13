#!/usr/bin/env python3
"""mutants06p.py: the test suite of the 0.6 pre-witness stage (12 Nov 2026, SPEC.md section 14, "The pre-witness stage"): a folder
whose manifest says grading.kind "pre-witness" holds the auditor's part alone (no claims.jsonl, no score, no claims_sha256, no
grading.grader or grading.model; witnesses may be listed, none primary). K1 reads the declaration and refuses what the stage
forbids; K2 asks for no claims.jsonl; K3 and K4 run on the auditor's rows (no verdict fields); K5 tests every evidence pointer and
candidate quote without a verdict and still FAILs a quote missing from a copy published in the folder; K6 and K7 have nothing to test;
K8 recomputes counts.claims and counts.checkable and WARNs that no score exists; K11 asks for no primary; K12 WARNs that there is no
merge and recomputes each listed witness; K13 to K15 unchanged.

Two fixtures are BUILT here in a temporary folder, each the auditor's part cut from a published folder and re-signed with a throwaway
key (no key leaves the temporary folder): A, agent-work, from examples/agent-work-s-i10-2026-11-12 (three claims with evidence
pointers); B, cited-sources, from the 0.4 snapshot business-models-in-the-agentic-age/2026-11-11 (74 claims with candidate quotes).
Each mutant copies a fixture, applies one change, re-signs what a careful publisher would re-sign, runs check.py and compares the
statuses of the named checks with the expected ones (and, where named, a line that must be in a check's text). Exit 0 when every
case is as expected. Reuses mutants06.py's helpers (sha, load, dump, mload, msave, sign, keygen, statuses, run, add_model's shape).

usage: python3 -I mutants06p.py [--fixture-out DIR] [SNAPSHOT_DIR]
  SNAPSHOT_DIR    the 0.4 page-profile snapshot fixture B is cut from (default: the notepad's business-models-in-the-agentic-age/2026-11-11;
                  the public repository holds no snapshots, so there B is skipped with a line saying so unless one is passed)
  --fixture-out   build fixture A (and B when its source is at hand) into DIR (must not exist), print check.py on each, stop"""
import json, pathlib, shutil, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402
import mutants06 as m  # noqa: E402

ARGS = sys.argv[1:]
FIXTURE_OUT = pathlib.Path(ARGS[ARGS.index("--fixture-out") + 1]) if "--fixture-out" in ARGS else None
POS = [a for i, a in enumerate(ARGS) if not a.startswith("--") and not (i and ARGS[i - 1] == "--fixture-out")]
SRC_A = HERE / "examples/agent-work-s-i10-2026-11-12"
SRC_B = pathlib.Path(POS[0]).resolve() if POS else HERE / "snapshots/onedroid/business-models-in-the-agentic-age/2026-11-11"
AUDITOR = "fixture-auditor"
MW, MP, MM = "onedroid-witness-example-1", "onedroid-witness-example-1", "example/model-1.0"


def to_pre(d):
    """The published folder becomes its own pre-witness stage: the auditor's part, the pages, the sources, the anchors and
    sessions stay; the merge, the witnesses, their signatures, the score and the primary's names go; the auditor part is re-signed
    with the throwaway key (the published signer's private key is not at hand) so that K13 verifies."""
    (d / "claims.jsonl").unlink(missing_ok=True)
    (d / "CHECK.json").unlink(missing_ok=True)
    shutil.rmtree(d / "witness", ignore_errors=True)
    sigs = json.loads((d / "signatures.json").read_text(encoding="utf-8"))
    (d / "signatures.json").write_text(json.dumps([e for e in sigs if e.get("role") == "auditor"], indent=1) + "\n", encoding="utf-8")
    M = m.mload(d)
    M["format"] = "claims-snapshot/0.6"
    g = M["grading"]
    g["kind"] = "pre-witness"
    for k in ("grader", "model"):
        g.pop(k, None)
    g["witnesses"] = []
    for k in ("score", "claims_sha256"):
        M.pop(k, None)
    audit = m.load(d / "audit.jsonl")
    M["counts"] = {"claims": len(audit), "checkable": sum(1 for c in audit if c.get("checkable", True) and c.get("kind") != "promise")}
    if isinstance(M.get("files"), dict):
        M["files"] = {k: v for k, v in M["files"].items() if k != "claims.jsonl" and not k.startswith("witness/")}
    if isinstance(M.get("anchors"), list):
        M.pop("anchors")
    m.msave(d, M)
    if (d / "anchors.json").exists():
        present = {m.sha(p) for p in d.rglob("*") if p.is_file() and p.name not in ("anchors.json", "CHECK.json")}
        anchors = json.loads((d / "anchors.json").read_text(encoding="utf-8"))
        (d / "anchors.json").write_text(json.dumps([a for a in anchors if str(a.get("over", "")).removeprefix("sha256:") in present], indent=1) + "\n", encoding="utf-8")
    m.sign(d, "auditor", "auditor", AUDITOR, "audit.jsonl")
    M = m.mload(d)
    M["grading"]["auditor"]["sha256"] = m.sha(d / "audit.jsonl")
    M["grading"]["auditor"]["signer"] = AUDITOR
    if isinstance(M.get("files"), dict):
        # 13 Nov 2026 (NEXT-REVISION 22, the K2 cut): a writer names content only, never a structural file, and names the hashes of the
        # bytes it leaves behind, so the re-signed audit.jsonl.sig is refreshed here, as the real writer hashes after signing
        M["files"] = {k: m.sha(d / k) for k in M["files"] if k not in check.STRUCTURAL_FILES and (d / k).exists()}
    m.msave(d, M)


def build(root):
    keydir = root / "keys"
    keydir.mkdir(parents=True)
    m.keygen(keydir)
    out = {}
    for name, src in (("A", SRC_A), ("B", SRC_B)):
        if not (src / "audit.jsonl").exists():
            print(f"fixture {name} skipped: no 0.4 folder at {src} (pass SNAPSHOT_DIR)")
            continue
        d = root / f"fixture{name}"
        shutil.copytree(src, d)
        to_pre(d)
        out[name] = d
    return out


def resign_audit(d):
    """After a change to audit.jsonl: the manifest's auditor hash and the auditor signature, as a careful publisher would."""
    for e in json.loads((d / "signatures.json").read_text(encoding="utf-8")):
        pass
    (d / "signatures.json").write_text("[]\n", encoding="utf-8")
    m.sign(d, "auditor", "auditor", AUDITOR, "audit.jsonl")
    M = m.mload(d)
    M["grading"]["auditor"]["sha256"] = m.sha(d / "audit.jsonl")
    m.msave(d, M)


def add_model_witness(d):
    """One model witness over the auditor's rows (no primary to copy from): EVIDENCED on rows whose first pointer or candidate is
    a file at hand, NO EVIDENCE PUBLISHED on the rest; kind model, method classify, its own throwaway key, a manifest entry with
    primary false and the recomputed score, a key list line. The stage does not end: no primary is named."""
    audit = m.load(d / "audit.jsonl")
    rows = []
    for a in audit:
        ptrs = a.get("evidence") or a.get("proofs") or []
        if ptrs:
            rows.append({"id": a["id"], "verdict": "EVIDENCED", "confidence": None, "on": {"proofs": [0], "counter": []}, "note": "classified from the rendered candidates", "graded_by": "grader", "graded_at": "2026-11-12T23:00:00Z"})
        else:
            rows.append({"id": a["id"], "verdict": "NO EVIDENCE PUBLISHED", "confidence": None, "on": {"proofs": [], "counter": []}, "note": "no candidate", "graded_by": "grader", "graded_at": "2026-11-12T23:00:00Z"})
    header = {"witness": MW, "kind": "model", "model": MM, "method": "classify", "over": {"file": "audit.jsonl", "sha256": m.sha(d / "audit.jsonl")},
              "started_at": m.STARTED, "finished_at": "2026-11-12T23:05:00Z", "note": "fixture witness: prompt sha256 not applicable"}
    wf = f"witness/{MW}.jsonl"
    (d / "witness").mkdir(exist_ok=True)
    m.dump(d / wf, [header] + rows)
    sc = check.evidence_score(check.merge_rows(audit, rows, MW))
    M = m.mload(d)
    M["grading"]["witnesses"].append({"name": MW, "kind": "model", "model": MM, "method": "classify", "signer": MP, "file": wf, "sha256": m.sha(d / wf),
                                      "primary": False, "score": {k: sc[k] for k in ("coverage_pct", "contradiction_pct", "band")}, "missing_claims": 0, "undecided": 0})
    m.msave(d, M)
    pub = pathlib.Path(str(m.KEYS["model1"]) + ".pub").read_text(encoding="utf-8").strip()
    kl = d / m.KL
    kl.parent.mkdir(exist_ok=True)
    with kl.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"principal": MP, "model": MM, "key": pub, "valid_from": "2026-11-01T00:00:00Z", "valid_to": None, "note": "fixture"}) + "\n")
    m.sign(d, "witness", "model1", MP, wf)


def mut(fn):
    def f(d):
        M = m.mload(d)
        fn(M, d)
        m.msave(d, M)
    return f


def main():
    if not (SRC_A / "audit.jsonl").exists():
        print(f"{SRC_A} has no audit.jsonl: fixture A is the agent-work example of this folder", file=sys.stderr)
        return 2
    if FIXTURE_OUT is not None:
        if FIXTURE_OUT.exists():
            print(f"{FIXTURE_OUT} exists", file=sys.stderr)
            return 2
        FIXTURE_OUT.mkdir(parents=True)
        fx = build(FIXTURE_OUT)
        for name, d in fx.items():
            print(f"== fixture {name}: {d}")
            print(__import__("subprocess").run([sys.executable, "-I", str(HERE / "check.py"), str(d)], capture_output=True, text=True).stdout)
        return 0
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        fx = build(tmp / "build")
        A, B = fx["A"], fx.get("B")
        base = {"K1": "PASS", "K2": "PASS", "K3": "PASS", "K4": "PASS", "K5": "PASS", "K6": "PASS", "K7": "PASS", "K8": "WARN", "K9": "PASS", "K11": "PASS", "K12": "WARN", "K13": "PASS", "K15": "PASS"}
        results = []
        results.append(m.run(tmp, A, "A_fixture", lambda d: None, base, has={"K1": "pre-witness: the auditor's part alone", "K5": "3 auditor rows, 3 evidence pointer(s) or candidate quote(s): 2 hold in the folder, 1 not testable from it, 0 do not hold", "K8": "no score yet", "K12": "no primary witness named yet"}))
        # B's sources are hash-only or none (no text copy in the folder): its 18 testable candidates are quotes from the audited page
        if B is not None:
            results.append(m.run(tmp, B, "B_fixture", lambda d: None, {"K1": "PASS", "K2": "PASS", "K3": "PASS", "K4": "PASS", "K5": "PASS", "K8": "WARN", "K11": "PASS", "K12": "WARN", "K13": "PASS"},
                                 has={"K1": "pre-witness", "K5": "74 auditor rows, 109 evidence pointer(s) or candidate quote(s): 18 hold in the folder, 91 not testable from it, 0 do not hold"}))
        # the declaration is required and exclusive
        results.append(m.run(tmp, A, "A_undeclared_split_no_witness", mut(lambda M, d: M["grading"].__setitem__("kind", "split")), {"K1": "FAIL"}, has={"K1": "missing score, claims_sha256, grading.grader, grading.model"}))
        results.append(m.run(tmp, A, "A_pre_with_score", mut(lambda M, d: M.__setitem__("score", {"coverage_pct": 100, "contradiction_pct": 0, "band": "A", "formula": "evidence-score/1"})), {"K1": "FAIL"}, has={"K1": "carries score"}))
        results.append(m.run(tmp, A, "A_pre_with_claims_sha256", mut(lambda M, d: M.__setitem__("claims_sha256", "0" * 64)), {"K1": "FAIL"}, has={"K1": "carries claims_sha256"}))
        results.append(m.run(tmp, A, "A_pre_with_grader", mut(lambda M, d: M["grading"].__setitem__("grader", "alice")), {"K1": "FAIL"}, has={"K1": "carries grading.grader"}))
        results.append(m.run(tmp, A, "A_pre_with_claims_jsonl", lambda d: (d / "claims.jsonl").write_text("", encoding="utf-8"), {"K1": "FAIL"}, has={"K1": "holds claims.jsonl"}))
        results.append(m.run(tmp, A, "A_pre_on_0_5", mut(lambda M, d: M.__setitem__("format", "claims-snapshot/0.5")), {"K1": "FAIL"}, has={"K1": "the stage exists from claims-snapshot/0.6"}))
        results.append(m.run(tmp, A, "A_pre_witnesses_not_a_list", mut(lambda M, d: M["grading"].__setitem__("witnesses", None)), {"K1": "FAIL"}, has={"K1": "grading.witnesses must be a list"}))
        results.append(m.run(tmp, A, "A_pre_no_audit", lambda d: (d / "audit.jsonl").unlink(), {"K1": "FAIL"}, has={"K1": "has no audit.jsonl"}))
        # counts, pointers, published copies
        results.append(m.run(tmp, A, "A_counts_claims_off", mut(lambda M, d: M["counts"].__setitem__("claims", 4)), {"K8": "FAIL"}, has={"K8": "counts.claims: manifest 4 vs 3"}))
        results.append(m.run(tmp, A, "A_counts_checkable_off", mut(lambda M, d: M["counts"].__setitem__("checkable", 2)), {"K8": "FAIL"}, has={"K8": "counts.checkable: manifest 2 vs 3"}))

        def pointer_beyond_file(d):
            rows = m.load(d / "audit.jsonl")
            rows[0]["evidence"][0]["line"] = 99
            m.dump(d / "audit.jsonl", rows)
            resign_audit(d)
        results.append(m.run(tmp, A, "A_pointer_line_beyond_file", pointer_beyond_file, {"K5": "WARN", "K11": "PASS", "K13": "PASS"}, has={"K5": "1 do not hold"}))

        def quote_not_in_published_copy(d):
            """A candidate quote from the audited page (published in the folder) altered by a few words: the folder must carry what it quotes."""
            rows = m.load(d / "audit.jsonl")
            target = next(r for r in rows if any(p.get("file") == "page.txt" and p.get("quote") for p in r.get("proofs", [])))
            p = next(p for p in target["proofs"] if p.get("file") == "page.txt" and p.get("quote"))
            p["quote"] = p["quote"] + " and a word the page does not carry"
            m.dump(d / "audit.jsonl", rows)
            resign_audit(d)
        if B is not None:
            results.append(m.run(tmp, B, "B_candidate_quote_not_in_published_copy", quote_not_in_published_copy, {"K5": "FAIL", "K11": "PASS", "K13": "PASS"}, has={"K5": "missing from a copy published in this snapshot"}))
        # witnesses in the stage: listed without a primary passes and is recomputed; a primary mark ends the stage and fails the declaration
        results.append(m.run(tmp, A, "A_model_witness_no_primary", add_model_witness, {"K1": "PASS", "K11": "PASS", "K12": "WARN", "K13": "PASS"}, has={"K12": "1 witness file(s) recomputed below", "K13": "verified"}))

        def primary_marked(d):
            add_model_witness(d)
            M = m.mload(d)
            M["grading"]["witnesses"][0]["primary"] = True
            m.msave(d, M)
        results.append(m.run(tmp, A, "A_witness_marked_primary", primary_marked, {"K1": "FAIL"}, has={"K1": "marks a witness primary"}))

        def witness_score_off(d):
            add_model_witness(d)
            M = m.mload(d)
            M["grading"]["witnesses"][0]["score"]["coverage_pct"] = 1
            m.msave(d, M)
        results.append(m.run(tmp, A, "A_model_witness_score_off", witness_score_off, {"K12": "FAIL"}, has={"K12": "score.coverage_pct: manifest 1 vs"}))

        def witness_with_auditor_key(d):
            add_model_witness(d)
            m.sign(d, "witness", "auditor", AUDITOR, f"witness/{MW}.jsonl")
        results.append(m.run(tmp, A, "A_model_witness_signed_with_auditor_key", witness_with_auditor_key, {"K13": "FAIL"}, has={"K13": "the witness is never the auditor"}))
        n_fx = 2 if B is not None else 1
        print(f"{sum(results)} of {len(results)} checks gave the expected statuses ({n_fx} fixture(s) and {len(results) - n_fx} mutants" + ("" if B is not None else "; fixture B and its mutant skipped, no snapshot at hand") + ")")
        return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
