#!/usr/bin/env python3
"""mutants06e.py: the test suite of 0.6 erratum 1 (12 Nov 2026): in the page profiles a self-audit by an AGENT keeps one signer,
as a human self-audit does, when the manifest declares it (the witness is the primary, grading.kind is "self-audit" and
grading.gates records the holdout); K13 then reports it instead of failing. Everything else about the auditor-key rule stands:
a model witness never shares the auditor's key, a non-primary agent witness never does, and in agent-work and test-run no
witness does (VR-I11). Reuses mutants06.py's fixture builder and runner (the fixture is a 0.6 copy of the first 0.4 snapshot,
whose grading.kind is already "self-audit" with two recorded gates; its primary witness is human and signed with the auditor's
throwaway key). Standard library plus ssh-keygen. Exit 0 when every case gives the expected statuses.

usage: python3 -I mutants06e.py"""
import pathlib, shutil, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import mutants06 as m  # noqa: E402

TAG = "self-audit by an agent"


PNAME = "onedroid-claims-session"   # an agent witness's file is named for its manifest entry (0.6 K13), so the fixture's free-text primary name becomes this


def rename_primary(d):
    """The primary's manifest name and header name become the file's stem (the 0.6 file-name rule for agent and model witnesses)."""
    pf = m.primary_file(d)
    rows = m.load(d / pf)
    rows[0]["witness"] = PNAME
    m.dump(d / pf, rows)
    # claims.jsonl carries the primary's name on every merged row (merge_rows), so the published merge is renamed too and resealed
    merged = m.load(d / "claims.jsonl")
    for r in merged:
        r["witness"] = PNAME
    m.dump(d / "claims.jsonl", merged)
    M = m.mload(d)
    M["claims_sha256"] = m.sha(d / "claims.jsonl")
    for w in M["grading"]["witnesses"]:
        if w.get("primary"):
            w["name"] = PNAME
            w["sha256"] = m.sha(d / pf)
    m.msave(d, M)
    return pf


def agent_primary(d):
    """The primary witness becomes an agent (header and manifest entry), named for its file, still signed with the auditor's key."""
    pf = rename_primary(d)
    rows = m.load(d / pf)
    rows[0]["kind"] = "agent"
    m.dump(d / pf, rows)
    M = m.mload(d)
    for w in M["grading"]["witnesses"]:
        if w.get("primary"):
            w["kind"] = "agent"
            w["sha256"] = m.sha(d / pf)
    m.msave(d, M)
    m.sign(d, "witness", "auditor", m.AUDITOR, pf)
    m.sign_manifest(d)


def agent_primary_manifest_only(d):
    """The header carries no kind; the manifest entry says agent: the effective kind is agent."""
    pf = rename_primary(d)
    M = m.mload(d)
    for w in M["grading"]["witnesses"]:
        if w.get("primary"):
            w["kind"] = "agent"
    m.msave(d, M)
    m.sign(d, "witness", "auditor", m.AUDITOR, pf)
    m.sign_manifest(d)


def grading(d, **kw):
    def f(M):
        for k, v in kw.items():
            if v is None:
                M["grading"].pop(k, None)
            else:
                M["grading"][k] = v
    m.mut_manifest(d, f)


def e2(d):
    agent_primary(d)
    grading(d, kind="split")


def e3(d):
    agent_primary(d)
    grading(d, gates=None)


def e4(d):
    agent_primary(d)
    grading(d, gates=[])


def e5(d):
    """A non-primary agent witness signed with the auditor's key (the 0.6 gate's W16): still never."""
    wf = m.entry(d, m.N1)["file"]
    rows = m.load(d / wf)
    rows[0].update(kind="agent", method="read")
    m.dump(d / wf, rows)

    def f(M):
        for w in M["grading"]["witnesses"]:
            if w["name"] == m.N1:
                w.update(kind="agent", method="read", sha256=m.sha(d / wf))
    m.mut_manifest(d, f)
    m.sign(d, "witness", "auditor", "fixture-auditor-alias", wf)
    m.sign_manifest(d)


def e6(d):
    """The model witness signed with the auditor's key, in a declared self-audit: still never (a model is nobody's self)."""
    m.signed_with_auditor_key(d)


def e8(d):
    """An agent primary with the auditor's key but grading.kind missing altogether: not declared, so refused."""
    agent_primary(d)
    grading(d, kind=None)


def e9(d):
    """The model witness made the primary (K11 fails on its UNDECIDED rows, not under test here) and signed with the auditor's
    key in a declared self-audit: a model primary is still never the auditor."""
    m.model_primary(d, m.ADDER)
    m.signed_with_auditor_key(d)


def main():
    if not shutil.which("ssh-keygen"):
        print("ssh-keygen is not on PATH", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        fx = m.build(root)
        tmp = root / "e"
        tmp.mkdir()
        R = [
            m.run(tmp, fx, "E1 agent primary, one signer, grading.kind self-audit, 2 gates", agent_primary, {"K11": "PASS", "K13": "PASS"}, has={"K13": TAG}),
            m.run(tmp, fx, "E2 the same with grading.kind split", e2, {"K13": "FAIL"}, has={"K13": "signed with the auditor's key"}),
            m.run(tmp, fx, "E3 the same with grading.gates removed", e3, {"K13": "FAIL"}, has={"K13": "signed with the auditor's key"}),
            m.run(tmp, fx, "E4 the same with grading.gates empty", e4, {"K13": "FAIL"}, has={"K13": "signed with the auditor's key"}),
            m.run(tmp, fx, "E5 a non-primary agent witness with the auditor's key in a self-audit", e5, {"K13": "FAIL"}, has={"K13": "kind agent"}, lacks={"K13": TAG}),
            m.run(tmp, fx, "E6 the model witness with the auditor's key in a self-audit", e6, {"K13": "FAIL"}, has={"K13": "kind model"}, lacks={"K13": TAG}),
            m.run(tmp, fx, "E7 agent kind in the manifest entry only (header silent)", agent_primary_manifest_only, {"K13": "PASS"}, has={"K13": TAG}),
            m.run(tmp, fx, "E8 agent primary with grading.kind missing (the manifest check stops it before K13)", e8, {"K1": "FAIL"}, has={"K1": "grading.kind"}),
            m.run(tmp, fx, "E9 the model witness made primary (named by the adder who signed) and signed with the auditor's key", e9, {"K13": "FAIL"}, has={"K13": "kind model"}, lacks={"K13": TAG}),
        ]
    print(f"{sum(R)} of {len(R)} cases gave the expected statuses")
    return 0 if all(R) else 1


if __name__ == "__main__":
    sys.exit(main())
