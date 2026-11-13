#!/usr/bin/env python3
"""mutants06c.py: the test suite of the carried cut of 13 Nov 2026 (NEXT-REVISION items 24, 25a, 25c and 26; the claims session's fifth
re-gate of the witness service, items H1 and H2):

R1  K11 reads a model witness header's `carried` {path: sha256}: a path the manifest does not list as a source (`sources[].file`, `sha256`)
    or a session record (`grading.sessions[].file`, `record_sha256`) FAILs by name; a sha256 that differs from the manifest's for that path
    FAILs by name ("the witness read other bytes than the record holds"); a `carried` that is not an object FAILs; a hash that is not 64 hex
    FAILs; `manifest_sha256`, when present, must be 64 hex (it is compared with nothing: the folder's manifest changed at insertion). A model
    witness over an evidence-shaped auditor part (agent-work, test-run, or any row with an `evidence` list) WITHOUT `carried` is a WARN
    naming it; a human or agent witness, or a model witness on a page profile without `evidence` rows, says nothing. Bound paths print no
    line, so every published folder's output stays byte-identical.
R2  add_witness.py refuses, before it writes anything, an answer whose witness header `carried` is not an object, names a path the
    snapshot's manifest does not list, or carries a differing sha256. The inventory is one helper, check.carried_inventory(M), used by both.
R3  K3 FAILs by name, never a traceback, on a row whose `on_request` is `true` or any other non-object (item 24).

Fixtures, built in a temporary folder with throwaway keys (mutants06.KEYS), nothing written into the repository:
  Fpre  examples/agent-work-s-i10-2026-11-12 turned pre-witness as mutants06p.to_pre does (the parent of F: no witness yet).
  F     Fpre + mutants06p.add_model_witness, then the header rewritten to carry `manifest_sha256` (the sha256 of the folder's manifest.json
        at that moment) and `carried` (every source file of the folder with the manifest's hash) after `over`, re-signed with the model key,
        the manifest entry's sha256 refreshed (add_carried below).
  T     examples/witness-service-tr4-2026-11-13 as published (REAL witnesses of the live service 0.1.6-dev: never re-signed here; a copy is
        mutated and K13 is expected to notice).

Cases (the expected statuses; `--committed PATH` names the committed checker for c5, c9, c11 and c12, `--committed none` skips those halves):
  c1   F unchanged: K11 PASS, K13 PASS or WARN, exit 0, no "carried" line in the K11 block.
  c2   F, one carried sha256 altered (last hex digit flipped), re-signed: K11 FAIL naming the path and "differs from the manifest's".
  c3   F, a carried path the manifest does not list (sources/files/nothing.txt, a real-looking hash): K11 FAIL "is not a page, source or session record".
  c4   F, `carried` removed, re-signed: K11 WARN naming the witness and "records no `carried`".
  c5   the 0.4 snapshot business-models-in-the-agentic-age/2026-11-11 + mutants06p.add_model_witness (no carried, cited-sources, no
       `evidence` list): no carried warning; the K11 block byte-equal under the committed checker and the cut.
  c6   F, `carried` a list: K11 FAIL "is not an object".
  c7   F, one carried hash "abc": K11 FAIL "is not 64 hex characters".
  c8   F, `manifest_sha256` "nope": K11 FAIL "manifest_sha256 'nope' is not 64 hex characters"; F with it removed: K11 PASS.
  c9   F with `"on_request": true` on one audit.jsonl row (pre-witness: K3 runs on the auditor's rows), re-signed; and the 0.3 snapshot
       onedroid-ai/2026-11-09 with `"on_request": true` on one claims.jsonl row of each verdict present (ON REQUEST, EVIDENCED, NO EVIDENCE
       PUBLISHED, CONTRADICTED), claims_sha256 refreshed: a SUMMARY line every time, no "Traceback" on stderr, K3 FAIL naming each id and
       "on_request is not an object". The committed checker's result on the same folders is printed beside (the ON REQUEST row crashes it).
  c10  add_witness.py: an answer made from F's witness inserted into a copy of Fpre: exit 0, "added 1 witness(es)", SUMMARY PASS; the same
       answer with one carried sha256 altered (re-signed with the model key, so K13 alone would pass): exit 1, "refused, nothing written"
       naming the path and "differs from the manifest's", every file of the parent folder unchanged by hash.
  c11  T copied unchanged: committed and cut give byte-identical whole output, both exit 0. T with one carried sha256 changed in the
       gpt-4-1-nano header (NOT re-signed): K11 FAIL naming the path, K13 FAIL, K2 FAIL.
  c12  every folder under snapshots/ and examples/: committed vs cut, whole output byte-identical, exit codes equal; one line per folder.

Bound cut amendments (the format owner, 13 Nov 2026 05:4xZ, after the seventh re-gate's U1): c1 and c8b now expect K11 WARN, since F records
`carried` and no `bound` (check.py R1(d) names it); c11a and c12 accept, for the two 0.1.6 example folders witness-service-aw4 and -tr4 only,
a committed-vs-cut diff that is exactly that WARN (the K11 status line, the SUMMARY warning count and one added note per model witness).
Every other published folder stays byte-identical. mutants06d.py holds the bound cut's own cases.

usage: python3 -I mutants06c.py [--committed PATH_TO_COMMITTED_CHECK_PY | --committed none]
  (default: git HEAD:claims-standard/check.py of the notepad)
Exit 0 only when every expectation holds; one line per case "ok/MISMATCH <case>: expected ... observed ...", the K3 and K11 blocks printed
indented under the cases that touch them."""
import hashlib, json, pathlib, shutil, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402
import mutants06 as m  # noqa: E402
import mutants06p as p  # noqa: E402

ARGS = sys.argv[1:]
_COMMITTED_ARG = ARGS[ARGS.index("--committed") + 1] if "--committed" in ARGS else None
SKIP_COMMITTED = _COMMITTED_ARG == "none"
COMMITTED = pathlib.Path(_COMMITTED_ARG).resolve() if _COMMITTED_ARG and not SKIP_COMMITTED else None
SRC_F = HERE / "examples/agent-work-s-i10-2026-11-12"
SRC_T = HERE / "examples/witness-service-tr4-2026-11-13"
SRC_04 = HERE / "snapshots/onedroid/business-models-in-the-agentic-age/2026-11-11"
SRC_OR = HERE / "snapshots/onedroid/onedroid-ai/2026-11-09"
WF = f"witness/{p.MW}.jsonl"
NANO_WF = "witness/onedroid-witness-openai-gpt-4-1-nano-2025-04-14.jsonl"
NANO_PATH = "sources/artefacts/corr-neg-seq.log"
NOTHING = "sources/files/nothing.txt"
ABSENT = object()
RESULTS = []


def inventory(M):
    """The suite's own reading of R1(a): sources by file and sha256, session records by file and record_sha256, nothing else.
    Written here on purpose, not read from check.carried_inventory, so the expectation does not run through the function under test."""
    inv = {s["file"]: s["sha256"] for s in (M.get("sources") or []) if s.get("file") and s.get("sha256")}
    for s in ((M.get("grading") or {}).get("sessions") or []):
        if s.get("file") and s.get("record_sha256"):
            inv[s["file"]] = s["record_sha256"]
    return inv


def flip_last(h):
    last = h[-1]
    return h[:-1] + ("0" if last != "0" else "1")


def set_header(d, fn, wf=WF, key="model1", ident=p.MP):
    """Rewrite a witness header (fn(header, d) returns the new one), re-dump, re-sign the witness with the throwaway key, refresh the
    manifest entry's sha256. F has no manifest signature (a pre-witness fixture of mutants06p's kind), so nothing else is re-signed."""
    rows = check.load_jsonl(d / wf)
    header = fn(rows[0], d)
    m.dump(d / wf, [header] + rows[1:])
    m.sign(d, "witness", key, ident, wf)
    M = m.mload(d)
    for w in M["grading"]["witnesses"]:
        if w.get("file") == wf:
            w["sha256"] = m.sha(d / wf)
    m.msave(d, M)


def after_over(header, manifest_sha256, carried):
    """The header with `manifest_sha256` and `carried` placed right after `over` (ABSENT leaves the key out)."""
    out = {}
    for k, v in header.items():
        if k in ("manifest_sha256", "carried"):
            continue
        out[k] = v
        if k == "over":
            if manifest_sha256 is not ABSENT:
                out["manifest_sha256"] = manifest_sha256
            if carried is not ABSENT:
                out["carried"] = carried
    return out


def add_carried(d, carried=None, manifest_sha256=None):
    """carried None = the inventory of R1(a) from the folder's manifest; manifest_sha256 None = the sha256 of manifest.json at this moment."""
    def fn(h, d_):
        ms = m.sha(d_ / "manifest.json") if manifest_sha256 is None else manifest_sha256
        c = inventory(m.mload(d_)) if carried is None else carried
        return after_over(h, ms, c)
    set_header(d, fn)


def refresh_files(d):
    M = m.mload(d)
    if isinstance(M.get("files"), dict):
        M["files"] = {k: m.sha(d / k) for k in M["files"] if (d / k).exists()}
    m.msave(d, M)


def build(root):
    keydir = root / "keys"
    keydir.mkdir(parents=True)
    m.keygen(keydir)
    fpre = root / "Fpre"
    shutil.copytree(SRC_F, fpre)
    (fpre / "CHECK.json").unlink(missing_ok=True)
    p.to_pre(fpre)
    f = root / "F"
    shutil.copytree(fpre, f)
    p.add_model_witness(f)
    add_carried(f)
    return fpre, f


def run_check(chk, d, args=()):
    r = subprocess.run([sys.executable, "-I", str(chk), str(d), *args], capture_output=True, text=True)
    st, blocks = m.statuses(r.stdout)
    return r, st, blocks


def report(name, ok, expected, observed, details=()):
    print(f"{'ok      ' if ok else 'MISMATCH'} {name}: expected {expected}; observed {observed}")
    for l in details:
        print("    " + l)
    RESULTS.append(ok)
    return ok


def block_lines(blocks, *ks):
    out = []
    for k in ks:
        for l in blocks.get(k, "").splitlines():
            out.append(f"{k}: {l.strip()}" if l.startswith(" ") else l)
    return out


def case(tmp, fx, name, mutate, expect, has=None, lacks=None, exit_in=None, show=("K11", "K3")):
    """One mutant: copy fx, mutate, run the working checker, compare statuses (a tuple = any of), required and forbidden substrings per
    block, the exit code; print the K11 and K3 blocks under it."""
    d = tmp / name
    shutil.copytree(fx, d)
    (d / "CHECK.json").unlink(missing_ok=True)
    mutate(d)
    r, st, blocks = run_check(HERE / "check.py", d)
    ok = all(st.get(k) in (v if isinstance(v, tuple) else (v,)) for k, v in expect.items())
    as_list = lambda v: list(v) if isinstance(v, (list, tuple)) else [v]  # noqa: E731
    missing = [(k, s) for k, subs in (has or {}).items() for s in as_list(subs) if s not in blocks.get(k, "")]
    present = [(k, s) for k, subs in (lacks or {}).items() for s in as_list(subs) if s in blocks.get(k, "")]
    ok = ok and not missing and not present and (exit_in is None or r.returncode in exit_in)
    obs = {k: st.get(k) for k in expect}
    details = block_lines(blocks, *show)
    details += [f"text lacks {s!r} in {k}" for k, s in missing] + [f"text carries {s!r} in {k}" for k, s in present]
    if r.returncode not in (0, 1) or "Traceback" in r.stderr:
        details.append("stderr: " + r.stderr.strip().splitlines()[-1][:200] if r.stderr.strip() else "stderr empty")
    return report(name, ok, f"{expect}" + (f", has {has}" if has else "") + (f", lacks {lacks}" if lacks else "") + (f", exit in {exit_in}" if exit_in else ""),
                  f"{obs}, exit {r.returncode}", details)


def bound_warn_only(old, new, n_witnesses):
    """The lines of a committed-vs-cut diff that the bound cut's R1(d) WARN does not explain (empty = the diff is exactly that WARN):
    removed lines may only be the K11 status line and the SUMMARY line; added lines may only be those two (re-stated) and exactly
    n_witnesses notes holding "records `carried` but no `bound`"."""
    import difflib
    extra, notes = [], 0
    for l in difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=0):
        if l.startswith(("---", "+++", "@@")):
            continue
        body = l[1:].strip()
        if l.startswith("-"):
            if not (body.startswith("K11 ") or body.startswith("SUMMARY:")):
                extra.append(l)
        elif l.startswith("+"):
            if "records `carried` but no `bound`" in body:
                notes += 1
            elif not (body.startswith("K11 ") or body.startswith("SUMMARY:")):
                extra.append(l)
    if notes != n_witnesses:
        extra.append(f"bound notes: {notes}, expected {n_witnesses}")
    return extra


# ---- the mutations ----

def c2_flip(d):
    inv = inventory(m.mload(d))
    path = sorted(inv)[0]
    inv[path] = flip_last(inv[path])
    add_carried(d, carried=inv)
    return path


def c3_unlisted(d):
    inv = inventory(m.mload(d))
    inv[NOTHING] = hashlib.sha256(b"nothing").hexdigest()
    add_carried(d, carried=inv)


def c4_no_carried(d):
    add_carried(d, carried=ABSENT)


def c6_list(d):
    inv = inventory(m.mload(d))
    add_carried(d, carried=[{"file": k, "sha256": v} for k, v in sorted(inv.items())])


def c7_abc(d):
    inv = inventory(m.mload(d))
    inv[sorted(inv)[0]] = "abc"
    add_carried(d, carried=inv)


def c8a_nope(d):
    add_carried(d, manifest_sha256="nope")


def c8b_none(d):
    add_carried(d, manifest_sha256=ABSENT)


def c9_f(d):
    rows = check.load_jsonl(d / "audit.jsonl")
    rows[0]["on_request"] = True
    (d / "audit.jsonl").write_text(check.dump_jsonl(rows), encoding="utf-8")
    p.resign_audit(d)  # auditor signature and grading.auditor.sha256; signatures.json is reset to the auditor's entry alone
    set_header(d, lambda h, d_: {**h, "over": {"file": "audit.jsonl", "sha256": m.sha(d_ / "audit.jsonl")}})  # the witness over the new bytes, its entry back
    refresh_files(d)
    return rows[0]["id"]


def c9_or(d):
    rows = check.load_jsonl(d / "claims.jsonl")
    hit = {}
    for v in ("EVIDENCE AVAILABLE ON REQUEST", "EVIDENCED", "NO EVIDENCE PUBLISHED", "CONTRADICTED", "WITHDRAWN"):
        r = next((r for r in rows if r.get("verdict") == v), None)
        if r is not None:
            r["on_request"] = True
            hit[v] = r["id"]
    (d / "claims.jsonl").write_text(check.dump_jsonl(rows), encoding="utf-8")
    M = m.mload(d)
    M["claims_sha256"] = m.sha(d / "claims.jsonl")
    if isinstance(M.get("files"), dict) and "claims.jsonl" in M["files"]:
        M["files"]["claims.jsonl"] = M["claims_sha256"]
    elif isinstance(M.get("files"), list):
        for e in M["files"]:
            if e.get("file") == "claims.jsonl":
                e["sha256"] = M["claims_sha256"]
    m.msave(d, M)
    return hit


def make_answer(full, ans, wf=WF, name=p.MW, principal=p.MP):
    """What the service returns for one model, taken from a folder that holds the witness: the pair under witness/, the allowed_signers
    fragment, the manifest entry and the signatures entry (add_witness.py's docstring)."""
    (ans / "witness").mkdir(parents=True)
    shutil.copyfile(full / wf, ans / wf)
    shutil.copyfile(full / (wf + ".sig"), ans / (wf + ".sig"))
    M = m.mload(full)
    e = next(w for w in M["grading"]["witnesses"] if w["name"] == name)
    (ans / "manifest-entry.json").write_text(json.dumps(e, indent=1) + "\n", encoding="utf-8")
    sigs = json.loads((full / "signatures.json").read_text(encoding="utf-8"))
    se = next(s for s in sigs if s.get("file") == wf and s.get("role") == "witness")
    (ans / "signatures-entry.json").write_text(json.dumps(se, indent=1) + "\n", encoding="utf-8")
    al = [l for l in (full / "allowed_signers").read_text(encoding="utf-8").splitlines() if l.startswith(principal + " ")]
    (ans / "allowed_signers").write_text("\n".join(al) + "\n", encoding="utf-8")


def tree_hashes(d):
    return {str(q.relative_to(d)): m.sha(q) for q in sorted(d.rglob("*")) if q.is_file()}


def run_add_witness(parent, ans):
    cmd = [sys.executable, "-I", str(HERE / "add_witness.py"), str(parent), str(ans), "--key", str(m.KEYS["adder"]), "--identity", m.ADDER]
    return subprocess.run(cmd, capture_output=True, text=True)


def nano_flip(d):
    """One carried sha256 of the REAL gpt-4-1-nano header changed in place, nothing re-signed (the keys are the service's)."""
    rows = check.load_jsonl(d / NANO_WF)
    h = rows[0]["carried"][NANO_PATH]
    raw = (d / NANO_WF).read_text(encoding="utf-8")
    assert raw.count(h) == 1, (NANO_PATH, raw.count(h))
    (d / NANO_WF).write_text(raw.replace(h, flip_last(h)), encoding="utf-8")


def committed_checker(tmp):
    if COMMITTED is not None:
        return COMMITTED
    out = tmp / "check_committed.py"
    r = subprocess.run(["git", "-C", str(HERE), "show", "HEAD:claims-standard/check.py"], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("git show HEAD:claims-standard/check.py: " + r.stderr)
    out.write_text(r.stdout, encoding="utf-8")
    return out


def both(committed, d):
    """(committed run, working run) on one folder."""
    return run_check(committed, d), run_check(HERE / "check.py", d)


def published_folders():
    out = []
    for base, depth in (("snapshots", "*/*/*"), ("examples", "*")):
        for q in sorted((HERE / base).glob(depth)):
            if q.is_dir() and (q / "manifest.json").exists():
                out.append(q.relative_to(HERE))
    return out


def main():
    if not (SRC_F / "audit.jsonl").exists() or not (SRC_T / "audit.jsonl").exists():
        print(f"fixture sources missing: {SRC_F} and {SRC_T} must be 0.4+ folders", file=sys.stderr)
        return 2
    if not shutil.which("ssh-keygen"):
        print("ssh-keygen is not on PATH", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        fpre, F = build(tmp / "build")
        committed = None if SKIP_COMMITTED else committed_checker(tmp)
        inv_f = inventory(m.mload(F))
        first_path = sorted(inv_f)[0]
        print(f"fixture F: carried over {len(inv_f)} path(s): {', '.join(sorted(inv_f))}; manifest_sha256 {check.load_jsonl(F / WF)[0]['manifest_sha256'][:12]}…")

        # c1
        # bound cut (13 Nov 2026): F records `carried` and no `bound`, so K11 WARNs by name (R1(d)); under the carried cut it was PASS with no carried line
        case(tmp, F, "c1_F_unchanged", lambda d: None, {"K11": "WARN", "K13": ("PASS", "WARN")}, has={"K11": "no `bound`"}, lacks={"K11": "differs"}, exit_in=(0,))
        # c2
        case(tmp, F, "c2_F_carried_sha256_flipped", c2_flip, {"K11": "FAIL"}, has={"K11": [f"carried {first_path!r}", "differs from the manifest's"]})
        # c3
        case(tmp, F, "c3_F_carried_path_unlisted", c3_unlisted, {"K11": "FAIL"}, has={"K11": [f"carried {NOTHING!r}", "source or session record"]})
        # c4
        case(tmp, F, "c4_F_carried_removed", c4_no_carried, {"K11": "WARN"}, has={"K11": [f"witness {p.MW!r}", "records no `carried`"]})
        # c5: the 0.4 page-profile snapshot with a model witness and no carried: no warning, the K11 block byte-equal to the committed checker's
        # (the public repository holds no snapshots/: skipped there, as mutants06p skips its fixture B)
        d5 = tmp / "c5_04_model_witness_no_carried"
        if not (SRC_04 / "audit.jsonl").exists():
            print(f"skipped  c5_04_model_witness_no_carried: no 0.4 snapshot at {SRC_04}")
            rw = stw = blw = None
        else:
            shutil.copytree(SRC_04, d5)
            (d5 / "CHECK.json").unlink(missing_ok=True)
            p.add_model_witness(d5)
            (rw, stw, blw) = run_check(HERE / "check.py", d5)
        if rw is None:
            pass
        elif SKIP_COMMITTED:
            report("c5_04_model_witness_no_carried", "carried" not in blw.get("K11", ""), "no carried line in K11 (committed comparison skipped: --committed none)",
                   f"K11 {stw.get('K11')}, 'carried' in K11 block: {'carried' in blw.get('K11', '')}", block_lines(blw, "K11"))
        else:
            (rc, stc, blc) = run_check(committed, d5)
            same_k11 = blc.get("K11") == blw.get("K11")
            same_all = rc.stdout == rw.stdout and rc.returncode == rw.returncode
            report("c5_04_model_witness_no_carried", same_k11 and "carried" not in blw.get("K11", ""),
                   "K11 block byte-equal under committed and cut, no 'carried' line",
                   f"K11 block equal: {same_k11}; whole output equal: {same_all}; K11 {stw.get('K11')}; 'carried' in K11: {'carried' in blw.get('K11', '')}; exit committed={rc.returncode} cut={rw.returncode}",
                   block_lines(blw, "K11"))
        # c6, c7, c8
        case(tmp, F, "c6_F_carried_is_a_list", c6_list, {"K11": "FAIL"}, has={"K11": "is not an object"})
        case(tmp, F, "c7_F_carried_hash_abc", c7_abc, {"K11": "FAIL"}, has={"K11": [f"carried {first_path!r}", "is not 64 hex characters"]})
        case(tmp, F, "c8a_F_manifest_sha256_nope", c8a_nope, {"K11": "FAIL"}, has={"K11": "manifest_sha256 'nope' is not 64 hex characters"})
        case(tmp, F, "c8b_F_manifest_sha256_removed", c8b_none, {"K11": "WARN"}, has={"K11": "no `bound`"}, lacks={"K11": "differs"})  # bound cut: the R1(d) WARN, nothing else
        # c9: on_request true, never a traceback
        for label, src, mut in (("c9F_on_request_true_pre_witness", F, c9_f), ("c9OR_on_request_true_each_verdict", SRC_OR, c9_or)):
            if not (src / "audit.jsonl").exists() and not (src / "claims.jsonl").exists():
                print(f"skipped  {label}: no snapshot at {src} (the public repository holds no snapshots/)")
                continue
            d = tmp / label
            shutil.copytree(src, d)
            (d / "CHECK.json").unlink(missing_ok=True)
            hit = mut(d)
            ids = list(hit.values()) if isinstance(hit, dict) else [hit]
            r, st, bl = run_check(HERE / "check.py", d)
            has_summary = "SUMMARY" in st
            no_tb = "Traceback" not in r.stderr
            named = [i for i in ids if f"{i}: on_request is not an object" in bl.get("K3", "")]
            orq_id = hit.get("EVIDENCE AVAILABLE ON REQUEST") if isinstance(hit, dict) else None
            orq_ok = orq_id is None or f"{orq_id}: on_request is not an object (holder, sha256, …)" in bl.get("K3", "")
            ok = has_summary and no_tb and st.get("K3") == "FAIL" and len(named) == len(ids) and orq_ok
            details = block_lines(bl, "K3") + [f"SUMMARY: {bl.get('SUMMARY', '(none)').splitlines()[0] if bl.get('SUMMARY') else '(none)'}", f"stderr has Traceback: {not no_tb}"]
            if not SKIP_COMMITTED:
                rc, stc, blc = run_check(committed, d)
                details.append(f"committed checker on the same folder: exit {rc.returncode}, SUMMARY line: {'yes' if 'SUMMARY' in stc else 'NO'}, Traceback on stderr: {'Traceback' in rc.stderr}"
                               + (f", last stderr line: {rc.stderr.strip().splitlines()[-1][:120]}" if rc.stderr.strip() else "") + f", K3: {stc.get('K3')}")
            report(label, ok, f"SUMMARY line, no Traceback, K3 FAIL naming {ids} with 'on_request is not an object'" + (" (the ON REQUEST row with '(holder, sha256, …)')" if orq_id else ""),
                   f"SUMMARY {has_summary}, Traceback {not no_tb}, K3 {st.get('K3')}, named {named}, exit {r.returncode}", details)
        # c10: add_witness.py accepts a bound answer and refuses a mismatch before writing
        ans = tmp / "c10_answer"
        make_answer(F, ans)
        parent = tmp / "c10_parent"
        shutil.copytree(fpre, parent)
        r = run_add_witness(parent, ans)
        rchk, stchk, blchk = run_check(HERE / "check.py", parent)
        summ_line = blchk.get("SUMMARY", "").splitlines()[0] if blchk.get("SUMMARY") else "(no SUMMARY)"
        ok = r.returncode == 0 and "added 1 witness(es)" in r.stdout and summ_line.rstrip().endswith(": PASS") and rchk.returncode == 0
        report("c10a_add_witness_bound_answer", ok, "exit 0, 'added 1 witness(es)', check.py SUMMARY PASS on the parent",
               f"exit {r.returncode}, added line: {'added 1 witness(es)' in r.stdout}, check.py {summ_line} exit {rchk.returncode}",
               [l for l in r.stdout.splitlines() if l.startswith(("added", "SUMMARY"))] + ([f"stderr: {r.stderr.strip()[-300:]}"] if r.stderr.strip() else []) + block_lines(blchk, "K11"))
        F2 = tmp / "c10_F_flipped"
        shutil.copytree(F, F2)
        path2 = c2_flip(F2)
        ans2 = tmp / "c10_answer_flipped"
        make_answer(F2, ans2)
        parent2 = tmp / "c10_parent_refused"
        shutil.copytree(fpre, parent2)
        before = tree_hashes(parent2)
        r2 = run_add_witness(parent2, ans2)
        after = tree_hashes(parent2)
        unchanged = before == after
        ok2 = r2.returncode == 1 and "refused, nothing written" in r2.stderr and f"carried {path2!r}" in r2.stderr and "differs from the manifest's" in r2.stderr and unchanged
        report("c10b_add_witness_carried_mismatch_refused", ok2, f"exit 1, stderr 'refused, nothing written' naming {path2!r} and 'differs from the manifest's', parent's {len(before)} files unchanged by hash",
               f"exit {r2.returncode}, refused line: {'refused, nothing written' in r2.stderr}, path named: {f'carried {path2!r}' in r2.stderr}, differs: {'differs from the manifest' + chr(39) + 's' in r2.stderr}, files unchanged: {unchanged} ({len(after)} hashed)",
               [f"stderr: {l}" for l in r2.stderr.strip().splitlines()] + ([f"stdout: {r2.stdout.strip()[:200]}"] if r2.stdout.strip() else []) + ([] if unchanged else [f"changed: {[k for k in before if before.get(k) != after.get(k)] + [k for k in after if k not in before]}"]))
        # c11: the real service output, unchanged and with one header hash changed under its signature
        d11 = tmp / "c11a_T_unchanged"
        shutil.copytree(SRC_T, d11)
        (d11 / "CHECK.json").unlink(missing_ok=True)
        if SKIP_COMMITTED:
            r, st, bl = run_check(HERE / "check.py", d11)
            # bound cut (13 Nov 2026): T's real 0.1.6 headers record `carried` and no `bound`, so K11 WARNs by name (R1(d)), exit 0
            report("c11a_T_unchanged", r.returncode == 0 and st.get("K11") == "WARN" and "no `bound`" in bl.get("K11", "") and "differs" not in bl.get("K11", ""),
                   "exit 0, K11 WARN with the bound note only (committed comparison skipped: --committed none)", f"exit {r.returncode}, K11 {st.get('K11')}", block_lines(bl, "K11"))
        else:
            (rc, stc, blc), (rw, stw, blw) = both(committed, d11)
            # bound cut (13 Nov 2026): T's two real 0.1.6 headers record `carried` and no `bound`, so the cut adds exactly the R1(d) WARN
            extra = bound_warn_only(rc.stdout, rw.stdout, 2)
            ok = extra == [] and rc.returncode == rw.returncode == 0
            report("c11a_T_unchanged", ok, "committed and cut differ by exactly the bound WARN (two notes), both exit 0",
                   f"unexplained diff lines: {extra[:6]}, exit committed={rc.returncode} cut={rw.returncode}, {len(rw.stdout.encode())} bytes", block_lines(blw, "K11"))
        case(tmp, SRC_T, "c11b_T_nano_carried_sha256_changed_unsigned", nano_flip, {"K11": "FAIL", "K13": "FAIL", "K2": "FAIL"},
             has={"K11": [f"carried {NANO_PATH!r}", "differs from the manifest's"], "K13": NANO_WF, "K2": NANO_WF}, show=("K2", "K11", "K13"))
        # c12: every published folder, committed vs cut
        if SKIP_COMMITTED:
            print("skipped  c12: --committed none, no committed checker to compare with")
        else:
            for rel in published_folders():
                (rc, _, _), (rw, _, _) = both(committed, HERE / rel)
                summ = next((l for l in rw.stdout.splitlines() if l.startswith("SUMMARY")), "(no SUMMARY)")
                if str(rel).replace("\\", "/").endswith(("examples/witness-service-aw4-2026-11-13", "examples/witness-service-tr4-2026-11-13")):
                    # bound cut (13 Nov 2026): the two 0.1.6 example folders gain exactly the R1(d) WARN (two model witnesses each)
                    extra = bound_warn_only(rc.stdout, rw.stdout, 2)
                    ok = extra == [] and rc.returncode == rw.returncode
                    report(f"c12_{str(rel).replace('/', '_')}", ok, "committed and cut differ by exactly the bound WARN, exit codes equal",
                           f"unexplained diff lines: {extra[:6]}, exit committed={rc.returncode} cut={rw.returncode}; {summ}")
                    continue
                ok = rc.stdout == rw.stdout and rc.returncode == rw.returncode
                report(f"c12_{str(rel).replace('/', '_')}", ok, "whole output byte-identical, exit codes equal",
                       f"identical: {rc.stdout == rw.stdout}, exit committed={rc.returncode} cut={rw.returncode}; {summ}")
        mism = sum(1 for r in RESULTS if not r)
        print(f"{sum(RESULTS)} of {len(RESULTS)} cases gave the expected result; MISMATCH {mism}")
        return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
