#!/usr/bin/env python3
"""mutants06.py: the test suite of the 0.6 rules (SPEC.md section 14: K1 kind, K11 UNDECIDED / classify / primary_named_by,
K12 undecided and split lines, K13 key list / auditor key / file name / manifest signature). Standard library plus ssh-keygen.

usage: python3 -I mutants06.py [SNAPSHOT_DIR]            # default: the 0.4 snapshot business-models-in-the-agentic-age/2026-11-11
       python3 -I mutants06.py --fixture-out DIR [--split] [--answer-out] [SNAPSHOT_DIR]   # build the 0.6 fixture into DIR (must not exist), print check.py on it, stop
The fixture is BUILT here, in a temporary folder: a copy of the base snapshot, format 0.6, the auditor part and the primary
witness re-signed with a throwaway key, one model witness (kind model, method classify, a few UNDECIDED rows, a manifest entry
with `undecided`, a key list `keys/model-keys.jsonl`) signed with a second throwaway key, the manifest signed with a third. No key
leaves the temporary folder. Each mutant copies the fixture, applies one change, re-signs what a careful publisher would re-sign
(so the rule under test is the only thing broken), runs check.py and compares the statuses of the named checks with the
expected ones (and, where named, a line that must or must not be in a check's text). Exit 0 when every mutant is as expected."""
import hashlib, json, pathlib, shutil, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402  (the fixture's scores are computed with the checker's own evidence_score and merge_rows; the fixture must still check PASS from the outside)

ARGS = [a for a in sys.argv[1:]]
FIXTURE_OUT = pathlib.Path(ARGS[ARGS.index("--fixture-out") + 1]) if "--fixture-out" in ARGS else None
POS = [a for i, a in enumerate(ARGS) if not a.startswith("--") and not (i and ARGS[i - 1] == "--fixture-out")]
SRC = pathlib.Path(POS[0]).resolve() if POS else HERE / "snapshots/onedroid/business-models-in-the-agentic-age/2026-11-11"

N1, P1, MODEL1 = "onedroid-witness-example-1", "onedroid-witness-example-1", "example/model-1.0"
N2, P2, MODEL2 = "onedroid-witness-example-2", "onedroid-witness-example-2", "example/model-2.0"
AUDITOR, ADDER = "fixture-auditor", "fixture-adder"
STARTED = "2026-11-12T09:00:00Z"
KL = "keys/model-keys.jsonl"
KEYS = {}   # name -> private key path, set by build()


def sha(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


def load(p):
    return [json.loads(l) for l in pathlib.Path(p).read_text(encoding="utf-8").splitlines() if l.strip()]


def dump(p, rows):
    pathlib.Path(p).write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")


def mload(d):
    return json.loads((d / "manifest.json").read_text(encoding="utf-8"))


def msave(d, M):
    (d / "manifest.json").write_text(json.dumps(M, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def primary_file(d):
    return next(w["file"] for w in mload(d)["grading"]["witnesses"] if w.get("primary"))


def entry(d, name):
    return next(w for w in mload(d)["grading"]["witnesses"] if w["name"] == name)


def sign(d, role, key, ident, part=None):
    cmd = [sys.executable, "-I", str(HERE / "sign.py"), str(d), "--role", role, "--key", str(KEYS[key]), "--identity", ident]
    if part:
        cmd += ["--file", part]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"sign.py {role} {part}: {r.stdout} {r.stderr}")


def sign_manifest(d):
    sign(d, "manifest", "adder", ADDER)


def resign(d, name=N1, key="model1", ident=P1, wf=None):
    """The model witness's manifest hash, its own signature, then the manifest's (last: it covers the rest)."""
    M = mload(d)
    e = next(w for w in M["grading"]["witnesses"] if w["name"] == name)
    wf = wf or e["file"]
    e["file"], e["sha256"] = wf, sha(d / wf)
    msave(d, M)
    sign(d, "witness", key, ident, wf)
    sign_manifest(d)


def mut_manifest(d, fn):
    M = mload(d)
    fn(M)
    msave(d, M)
    sign_manifest(d)


def add_model(d, name, principal, model, key, undecided_at=(), flip=(), undecided_ids=()):
    """One model witness over the base's claims: the primary's verdicts, `undecided_at` row positions answered UNDECIDED, ids in
    `flip` answered NO EVIDENCE PUBLISHED, ids in `undecided_ids` answered UNDECIDED. Signed, listed in the manifest and the key list."""
    audit = load(d / "audit.jsonl")
    prim = load(d / primary_file(d))[1:]
    rows = []
    for i, pr in enumerate(prim):
        r = {"id": pr["id"], "verdict": pr["verdict"], "confidence": pr.get("confidence"), "on": pr.get("on"), "note": "classified from the rendered candidates",
             "graded_by": "grader", "graded_at": "2026-11-12T09:01:00Z"}
        if i in undecided_at or pr["id"] in undecided_ids:
            r = {"id": pr["id"], "verdict": "UNDECIDED", "note": "the candidates do not settle it", "graded_by": "grader", "graded_at": "2026-11-12T09:01:00Z"}
        elif pr["id"] in flip:
            r.update({"verdict": "NO EVIDENCE PUBLISHED", "confidence": None, "on": {"proofs": [], "counter": []}})
        rows.append(r)
    header = {"witness": name, "kind": "model", "model": model, "method": "classify", "over": {"file": "audit.jsonl", "sha256": sha(d / "audit.jsonl")},
              "started_at": STARTED, "finished_at": "2026-11-12T09:05:00Z", "note": "fixture witness: prompt sha256 not applicable"}
    wf = f"witness/{name}.jsonl"
    (d / "witness").mkdir(exist_ok=True)
    dump(d / wf, [header] + rows)
    sc = check.evidence_score([m for m in check.merge_rows(audit, rows, name) if m["verdict"] != "UNDECIDED"])
    M = mload(d)
    M["grading"]["witnesses"].append({"name": name, "kind": "model", "model": model, "method": "classify", "signer": "", "file": wf, "sha256": sha(d / wf),
                                      "primary": False, "score": {k: sc[k] for k in ("coverage_pct", "contradiction_pct", "band")}, "missing_claims": 0,
                                      "undecided": sum(1 for r in rows if r["verdict"] == "UNDECIDED")})
    msave(d, M)
    pub = pathlib.Path(str(KEYS[key]) + ".pub").read_text(encoding="utf-8").strip()
    kl = d / KL
    kl.parent.mkdir(exist_ok=True)
    with kl.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"principal": principal, "model": model, "key": pub, "valid_from": "2026-11-01T00:00:00Z", "valid_to": None, "note": "fixture"}) + "\n")
    resign(d, name, key, principal)


def keygen(root):
    for n in ("auditor", "adder", "model1", "model2"):
        p = root / n
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"fixture-{n}", "-f", str(p)], check=True, capture_output=True)
        KEYS[n] = p


def build(root):
    """The 0.6 fixture, in root/fixture."""
    fx = root / "fixture"
    keydir = root / "keys"
    keydir.mkdir()
    keygen(keydir)
    shutil.copytree(SRC, fx)
    (fx / "CHECK.json").unlink(missing_ok=True)
    M = mload(fx)
    M["format"] = "claims-snapshot/0.6"
    msave(fx, M)
    # the one-auditor cut (13 Nov 2026, NEXT-REVISION 32): sign.py refuses to re-sign audit.jsonl under another name than the existing
    # auditor entry's, so the published entry is dropped first; the throwaway auditor entry replaces it
    sp = fx / "signatures.json"
    sp.write_text(json.dumps([e for e in json.loads(sp.read_text(encoding="utf-8")) if e.get("role") != "auditor"], indent=1) + "\n", encoding="utf-8")
    sign(fx, "auditor", "auditor", AUDITOR, "audit.jsonl")
    sign(fx, "witness", "auditor", AUDITOR, primary_file(fx))
    add_model(fx, N1, P1, MODEL1, "model1", undecided_at=(3, 10, 20))
    return fx


def statuses(out):
    status, blocks, cur = {}, {}, None
    for l in out.splitlines():
        head = l.split(" ")[0] if l else ""
        if l and not l.startswith(" ") and ":" in l and (head.startswith("K") or head == "SUMMARY:"):
            cur = head.rstrip(":")
            status[cur] = l.split(" ")[1].rstrip(":")
            blocks[cur] = [l]
        elif cur:
            blocks[cur].append(l)
    return status, {k: "\n".join(v) for k, v in blocks.items()}


def run(tmp, fx, name, mutate, expect, args=None, has=None, lacks=None):
    d = tmp / name
    shutil.copytree(fx, d)
    (d / "CHECK.json").unlink(missing_ok=True)
    mutate(d)
    cmd = [sys.executable, "-I", str(HERE / "check.py"), str(d)] + (args(d) if args else [])
    r = subprocess.run(cmd, capture_output=True, text=True)
    status, blocks = statuses(r.stdout)
    ok = all(status.get(k) == v for k, v in expect.items())
    for k, sub in (has or {}).items():
        ok = ok and sub in blocks.get(k, "")
    for k, sub in (lacks or {}).items():
        ok = ok and sub not in blocks.get(k, "")
    print(f"{'as expected' if ok else 'MISMATCH'}  {name}: expected {expect}, got {{{', '.join(f'{k!r}: {status.get(k)!r}' for k in expect)}}}"
          + (f", line present {has}" if has else "") + (f", line absent {lacks}" if lacks else ""))
    for k in expect:
        if status.get(k) in ("FAIL", "WARN"):
            lines_ = blocks.get(k, "").splitlines()
            first = next((l.strip() for l in lines_[1:] if l.strip()), lines_[0] if lines_ else "")
            print(f"    {k}: {first[:150]}")
    if not ok:
        for k, sub in (has or {}).items():
            if sub not in blocks.get(k, ""):
                print(f"    {k} text lacks {sub!r}")
        for k, sub in (lacks or {}).items():
            if sub in blocks.get(k, ""):
                print(f"    {k} text carries {sub!r}")
    if r.returncode not in (0, 1):
        print("    stderr:", r.stderr[-300:])
    return ok


def keys_flag(d):
    return ["--keys", str(d / KL)]


def edit_klist(d, fn):
    rows = load(d / KL)
    fn(rows)
    dump(d / KL, rows)


# ---- mutations
def no_note(d):
    rows = load(d / entry(d, N1)["file"])
    next(r for r in rows[1:] if r["verdict"] == "UNDECIDED").pop("note")
    dump(d / entry(d, N1)["file"], rows)
    resign(d)


def undecided_in_primary(d):
    pf = primary_file(d)
    rows = load(d / pf)
    rows[2].update({"verdict": "UNDECIDED", "note": "x"})
    dump(d / pf, rows)
    mut_manifest(d, lambda M: [w.update(sha256=sha(d / pf)) for w in M["grading"]["witnesses"] if w.get("primary")])


def model_primary(d, named=None):
    def f(M):
        for w in M["grading"]["witnesses"]:
            w["primary"] = w["name"] == N1
        if named:
            M["grading"]["primary_named_by"] = named
    mut_manifest(d, f)


def undecided_count(d, delta):
    def f(M):
        e = next(w for w in M["grading"]["witnesses"] if w["name"] == N1)
        if delta is None:
            del e["undecided"]
        else:
            e["undecided"] += delta
    mut_manifest(d, f)


def klist_model(d):
    edit_klist(d, lambda rows: rows[0].update(model="example/model-9.9"))


def klist_window_ends(d):
    edit_klist(d, lambda rows: rows[0].update(valid_from="2026-10-01T00:00:00Z", valid_to="2026-11-01T00:00:00Z"))


def klist_window_starts(d):
    edit_klist(d, lambda rows: rows[0].update(valid_from="2026-12-01T00:00:00Z"))


def klist_key(d):
    pub = pathlib.Path(str(KEYS["model2"]) + ".pub").read_text(encoding="utf-8").strip()
    edit_klist(d, lambda rows: rows[0].update(key=pub))


def klist_other_principal(d):
    edit_klist(d, lambda rows: rows[0].update(principal="someone-else"))


def klist_none(d):
    shutil.rmtree(d / "keys")


def rename_witness(d):
    old = entry(d, N1)["file"]
    new = "witness/renamed-witness.jsonl"
    shutil.move(d / old, d / new)
    (d / (old + ".sig")).unlink()
    sigs = [s for s in json.loads((d / "signatures.json").read_text(encoding="utf-8")) if s.get("file") != old]
    (d / "signatures.json").write_text(json.dumps(sigs, indent=1) + "\n", encoding="utf-8")
    resign(d, wf=new)


def signed_with_auditor_key(d):
    sign(d, "witness", "auditor", "fixture-auditor-alias", entry(d, N1)["file"])
    sign_manifest(d)


def manifest_changed(d):
    M = mload(d)
    M["pages_note"] = "changed after the manifest was signed"
    msave(d, M)


def classify_on_human(d):
    pf = primary_file(d)
    rows = load(d / pf)
    rows[0]["method"] = "classify"
    dump(d / pf, rows)
    mut_manifest(d, lambda M: [w.update(sha256=sha(d / pf)) for w in M["grading"]["witnesses"] if w.get("primary")])


def kind_value(d, value, fmt=None):
    wf = entry(d, N1)["file"]
    rows = load(d / wf)
    rows[0]["kind"] = value
    dump(d / wf, rows)
    if fmt:
        M = mload(d)
        M["format"] = fmt
        msave(d, M)
    resign(d)


def kind_disagrees(d):
    def f(M):
        next(w for w in M["grading"]["witnesses"] if w["name"] == N1)["kind"] = "agent"
    mut_manifest(d, f)


def second_model(d, **kw):
    add_model(d, N2, P2, MODEL2, "model2", **kw)


def make_answer(full, ans):
    """An answer folder as section 5 of the contract has it, for model 2, cut from a folder that already carries it."""
    (ans / "witness").mkdir(parents=True)
    for suffix in ("", ".sig"):
        shutil.copyfile(full / f"witness/{N2}.jsonl{suffix}", ans / f"witness/{N2}.jsonl{suffix}")
    M = mload(full)
    (ans / "manifest-entry.json").write_text(json.dumps(next(w for w in M["grading"]["witnesses"] if w["name"] == N2), indent=1) + "\n", encoding="utf-8")
    sigs = json.loads((full / "signatures.json").read_text(encoding="utf-8"))
    (ans / "signatures-entry.json").write_text(json.dumps(next(s for s in sigs if s["file"] == f"witness/{N2}.jsonl"), indent=1) + "\n", encoding="utf-8")
    al = [l for l in (full / "allowed_signers").read_text(encoding="utf-8").splitlines() if l.startswith(P2 + " ")]
    (ans / "allowed_signers").write_text("\n".join(al) + "\n", encoding="utf-8")
    (ans / "service.json").write_text(json.dumps({"models_run": [N2], "models_skipped": [], "note": "fixture: not a real service run"}, indent=1) + "\n", encoding="utf-8")
    (ans / "split.jsonl").write_text(json.dumps({"id": "C-001", "primary": "EVIDENCED", "models": {N1: "EVIDENCED", N2: "NO EVIDENCE PUBLISHED"}}) + "\n", encoding="utf-8")


def main():
    if not (SRC / "audit.jsonl").exists():
        print(f"{SRC} is not a 0.4 snapshot", file=sys.stderr)
        return 2
    if not shutil.which("ssh-keygen"):
        print("ssh-keygen is not on PATH", file=sys.stderr)
        return 2
    if FIXTURE_OUT is not None:
        if FIXTURE_OUT.exists():
            print(f"{FIXTURE_OUT} exists", file=sys.stderr)
            return 2
        FIXTURE_OUT.mkdir(parents=True)
        fx = build(FIXTURE_OUT)
        if "--answer-out" in ARGS:   # also: DIR/fixture_with_2 (model 2 added) and DIR/answer, what a service would return for model 2
            shutil.copytree(fx, FIXTURE_OUT / "fixture_with_2")
            second_model(FIXTURE_OUT / "fixture_with_2", flip=("C-001",))
            make_answer(FIXTURE_OUT / "fixture_with_2", FIXTURE_OUT / "answer")
        if "--split" in ARGS:   # a second model witness answering NO EVIDENCE PUBLISHED where the first says EVIDENCED: the split line shows
            second_model(fx, flip=("C-001",))
        r = subprocess.run([sys.executable, "-I", str(HERE / "check.py"), str(fx)], capture_output=True, text=True)
        print(r.stdout, end="")
        print(f"exit {r.returncode}")
        return r.returncode
    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        fx = build(root)
        r = subprocess.run([sys.executable, "-I", str(HERE / "check.py"), str(fx)], capture_output=True, text=True)
        st, blocks = statuses(r.stdout)
        base_ok = r.returncode == 0 and "PASS" in blocks.get("SUMMARY", "") and st.get("K1") == st.get("K11") == st.get("K12") == st.get("K13") == "PASS"
        print(f"{'as expected' if base_ok else 'MISMATCH'}  fixture: K1, K11, K12, K13 PASS and the summary PASS (K14, K15 warn as the base does): got {st}")
        if not base_ok:
            print(r.stdout)
            return 1
        tmp = root / "m"
        tmp.mkdir()
        results = [base_ok,
            run(tmp, fx, "undecided-without-note", no_note, {"K11": "FAIL"}, has={"K11": "UNDECIDED without a note"}),
            run(tmp, fx, "undecided-in-primary", undecided_in_primary, {"K11": "FAIL"}, has={"K11": "a primary leaves nothing undecided"}),
            run(tmp, fx, "model-primary-without-primary_named_by", model_primary, {"K11": "FAIL"}, has={"K11": "grading.primary_named_by must name"}),
            run(tmp, fx, "model-primary-named-by-someone-who-did-not-sign", lambda d: model_primary(d, "someone-else"), {"K11": "FAIL"},
                has={"K11": "no manifest signature by primary_named_by 'someone-else'"}),
            run(tmp, fx, "model-primary-named-by-the-adder-who-signed", lambda d: model_primary(d, ADDER), {"K11": "FAIL", "K13": "PASS"},
                lacks={"K11": "primary_named_by"}),   # still FAIL: its UNDECIDED rows; the naming rule itself is met
            run(tmp, fx, "undecided-count-off-by-one", lambda d: undecided_count(d, 1), {"K12": "FAIL"}, has={"K12": "undecided: manifest 4 vs 3"}),
            run(tmp, fx, "undecided-count-missing-in-0.6", lambda d: undecided_count(d, None), {"K12": "FAIL"}, has={"K12": "no `undecided` count"}),
            run(tmp, fx, "keylist-bound-to-another-model", klist_model, {"K13": "FAIL"}, args=keys_flag, has={"K13": "the list binds it to model"}),
            run(tmp, fx, "keylist-bound-to-another-model-snapshot-list-only", klist_model, {"K13": "WARN"}),
            run(tmp, fx, "keylist-window-ends-before-started_at", klist_window_ends, {"K13": "FAIL"}, args=keys_flag, has={"K13": "is after valid_to"}),
            run(tmp, fx, "keylist-window-starts-after-started_at", klist_window_starts, {"K13": "FAIL"}, args=keys_flag, has={"K13": "is before valid_from"}),
            run(tmp, fx, "keylist-key-is-another-key", klist_key, {"K13": "FAIL"}, args=keys_flag, has={"K13": "not the key of this principal"}),
            run(tmp, fx, "principal-missing-from-keylist-with-keys", klist_other_principal, {"K13": "FAIL"}, args=keys_flag, has={"K13": "not in a published key list"}),
            run(tmp, fx, "principal-missing-from-keylist-without-keys", klist_other_principal, {"K13": "WARN"}, has={"K13": "not in a published key list"}),
            run(tmp, fx, "no-keylist-at-all", klist_none, {"K13": "WARN"}, has={"K13": "no --keys FILE and no keys/model-keys.jsonl"}),
            run(tmp, fx, "witness-file-name-differs-from-manifest-name", rename_witness, {"K13": "FAIL"}, has={"K13": "is not its manifest name"}),
            run(tmp, fx, "model-witness-signed-with-the-auditors-key", signed_with_auditor_key, {"K13": "FAIL"}, has={"K13": "signed with the auditor's key"}),
            run(tmp, fx, "manifest-changed-after-it-was-signed", manifest_changed, {"K13": "FAIL"}, has={"K13": "manifest.json"}),
            run(tmp, fx, "classify-on-a-human-witness", classify_on_human, {"K11": "FAIL"}, has={"K11": "'classify' is for a witness of kind 'model' only"}),
            run(tmp, fx, "kind-robot-in-0.6", lambda d: kind_value(d, "robot"), {"K1": "FAIL"}, has={"K1": "is not human, agent or model"}),
            run(tmp, fx, "kind-robot-in-0.5-only-warns", lambda d: kind_value(d, "robot", "claims-snapshot/0.5"), {"K1": "WARN"}, has={"K1": "is not human, agent or model"}),
            run(tmp, fx, "kind-header-and-manifest-disagree", kind_disagrees, {"K12": "FAIL"}, has={"K12": "kind: manifest entry 'agent' vs header 'model'"}),
            run(tmp, fx, "two-model-witnesses-split-on-one-claim", lambda d: second_model(d, flip=("C-001",)), {"K11": "PASS", "K12": "PASS", "K13": "PASS"},
                has={"K12": f"split on C-001: {N1} EVIDENCED, {N2} NO EVIDENCE PUBLISHED"}),
            run(tmp, fx, "two-model-witnesses-split-one-side-undecided", lambda d: second_model(d, undecided_ids=("C-001",)), {"K12": "PASS"},
                has={"K12": f"split on C-001: {N1} EVIDENCED, {N2} UNDECIDED"}),
            run(tmp, fx, "two-model-witnesses-agree-no-split-line", lambda d: second_model(d), {"K12": "PASS", "K13": "PASS"}, lacks={"K12": "split on C-001"}),
        ]
    print(f"{sum(results)} of {len(results)} checks gave the expected statuses (the fixture and {len(results) - 1} mutants)")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
