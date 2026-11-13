#!/usr/bin/env python3
"""mutants06d.py: the test suite of the bound cut of 13 Nov 2026 (the claims session's seventh re-gate of the witness service, item U1:
`carried` binds bytes, not which source entry a pointer resolved through, so a forger's manifest that names dev's genuine file under
prod's path makes the models read dev as prod, and every carried hash is genuine).

R1  K11 reads a witness header's `bound` {section: sha256}: not an object FAILs; a key set other than exactly the five bound sections
    (subject, sources, pages, grading.profile, grading.sessions) FAILs; a value that is not 64 hex FAILs; a value that differs from the
    sha256 of that section of THIS record's manifest in canonical JSON (json.dumps sort_keys, separators (",", ":"), ensure_ascii False,
    UTF-8; an absent section hashes as null) FAILs by name. A model witness with `carried` and no `bound` over an evidence-shaped auditor
    part WARNs by name (one WARN per header: a header without `carried` keeps the carried WARN alone). Matching sections print no line.
R2  for a witness whose header has `carried`, an EVIDENCED or CONTRADICTED decision whose named pointer (on.proofs / on.counter into the
    audit row's `evidence`) is a file pointer that resolves, by `path` through this record's manifest, to a source whose `file` is not a
    key of `carried` FAILs by name ("a file the witness did not carry").
R3  add_witness.py refuses, before it writes anything, an answer whose header `bound` fails any R1 rule against the snapshot's manifest
    (through check.bound_sections, one helper for both); a header without `bound` is accepted.

Fixtures, built in a temporary folder with throwaway keys (mutants06.KEYS), nothing written into the repository:
  Fpre, F  as mutants06c builds them (F: a model witness with `manifest_sha256` and `carried`).
  FB       F with `bound` placed after `carried` (the suite's own canonical form, not check.bound_sections, so the expectation does not run
           through the function under test), re-signed with the model key, the manifest entry refreshed.
  U2       fixtures/aw10-regate7-forged-insertion-u2-2026-11-13 copied unchanged (the gate's forged insertion, signed by the live service's keys).

Cases (`--committed PATH | none` names the committed check.py; `--committed-add-witness PATH` the committed add_witness.py, default git HEAD):
  d1   FB unchanged: K11 PASS, exit 0, no "bound" line in the K11 block.
  d2   FB, bound["sources"] last hex digit flipped: K11 FAIL naming 'sources' and "differs from this record's".
  d3   FB without the "pages" key: K11 FAIL "not the five bound sections".
  d4   FB with an extra key "files": K11 FAIL "not the five bound sections".
  d5   FB with bound a list; a string: K11 FAIL "is not an object" each.
  d6   FB with bound["subject"] = "abc": K11 FAIL "is not 64 hex characters".
  d7   F (carried, no bound): K11 WARN "records `carried` but no `bound`", exactly one K11 note; F with carried and bound removed: only the
       carried WARN, exactly one K11 note.
  d8   check.bound_sections(M) of fixtures/aw10-regate7-2026-11-13/manifest.json equals, per section, sha256 of the service's
       _canonical(_section(M, s)) (onedroid_witness.request, imported from the witness-service folder); both hash sets printed.
  d9   U2: the committed checker PASSES (15 checks, 0 failed, exit 0); the cut FAILS K11 with one line per witness naming 'C-005',
       "pointer [0]", 'prod/config.yaml' and "a file the witness did not carry" (two lines), plus the R1(d) WARN for both; exit non-zero.
  d10  add_witness.py: FB's answer into a copy of Fpre: exit 0, "added 1 witness(es)", SUMMARY PASS, K11 PASS; the same answer with
       bound["sources"] altered (re-signed): exit 1, "refused, nothing written" naming 'sources' and "differs from this snapshot's", the
       parent unchanged by hash; the same answer with "pages" missing: exit 1, "not the five bound sections".
  d11  the u2 shape rebuilt on Fpre: the forger's manifest re-aims source 2 (path hello.txt) at sources/files/bye.txt with bye's hash; the
       model witness decides EVIDENCED on C-001 (pointer [0] file hello.txt); carried = the forger's files, bound = the FORGER's sections.
       Inserted by the COMMITTED add_witness.py into a copy of the GENUINE Fpre (exit printed, expected 0), then the cut's check.py: K11 FAIL
       by R1(c) 'sources' AND by R2 (both lines); the cut's add_witness.py on the same answer: exit 1, "refused, nothing written" naming 'sources'.
  d12  every folder under snapshots/, examples/ and fixtures/aw10-regate7-2026-11-13: committed vs cut byte-identical, exit codes equal,
       EXCEPT examples/witness-service-aw4-2026-11-13 and examples/witness-service-tr4-2026-11-13, whose unified diff holds only the added
       R1(d) warning lines and, as their consequence, the changed K11 status line and SUMMARY warning count (printed; any other line is a MISMATCH).

usage: python3 -I mutants06d.py [--committed PATH | --committed none] [--committed-add-witness PATH]
Exit 0 only when every expectation holds; one line per case "ok/MISMATCH <case>: expected ... observed ...", the K11 blocks printed under
the cases that touch them."""
import difflib, hashlib, importlib, json, pathlib, shutil, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402
import mutants06 as m  # noqa: E402
import mutants06p as p  # noqa: E402
import mutants06c as c  # noqa: E402

ARGS = sys.argv[1:]
_CAW = ARGS[ARGS.index("--committed-add-witness") + 1] if "--committed-add-witness" in ARGS else None
COMMITTED_ADD_WITNESS = pathlib.Path(_CAW).resolve() if _CAW else None
SECTIONS = ("subject", "sources", "pages", "grading.profile", "grading.sessions")
SRC_G = HERE / "fixtures/aw10-regate7-2026-11-13"
SRC_U2 = HERE / "fixtures/aw10-regate7-forged-insertion-u2-2026-11-13"
SERVICE = pathlib.Path("/home/coder/code/providentiaww/notepads/trilix-onedroid-business/witness-service")
U2_WITNESSES = ("onedroid-witness-openai-gpt-4-1-mini-2025-04-14", "onedroid-witness-perplexity-pplx-decider-v1-2-20261016")
BOUND_WARN = "records `carried` but no `bound`"
NOT_CARRIED = "a file the witness did not carry"
WF = c.WF
ABSENT = c.ABSENT


def section(M, dotted):
    cur = M
    for k in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def suite_bound(M):
    """The suite's own reading of the canonical form (SPEC 5, K11 row): written here, not read from check.bound_sections."""
    return {s: hashlib.sha256(json.dumps(section(M, s), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest() for s in SECTIONS}


def with_bound(header, bound):
    """The header with `bound` placed right after `carried` (after `manifest_sha256` or `over` when there is no `carried`); ABSENT leaves it out."""
    anchor = "carried" if "carried" in header else ("manifest_sha256" if "manifest_sha256" in header else "over")
    out = {}
    for k, v in header.items():
        if k == "bound":
            continue
        out[k] = v
        if k == anchor and bound is not ABSENT:
            out["bound"] = bound
    return out


def add_bound(d, bound=None):
    """bound None = suite_bound of the folder's manifest at this moment; re-signed with the model key, the manifest entry refreshed."""
    c.set_header(d, lambda h, d_: with_bound(h, suite_bound(m.mload(d_)) if bound is None else bound))


def notes(blocks, k="K11"):
    return [l.strip() for l in blocks.get(k, "").splitlines() if l.startswith(" ")]


def report(name, ok, expected, observed, details=()):
    return c.report(name, ok, expected, observed, details)


def committed_tools(tmp):
    """A folder holding the committed check.py and add_witness.py beside a copy of sign.py (add_witness.py runs HERE/check.py and HERE/sign.py)."""
    out = tmp / "committed"
    out.mkdir(exist_ok=True)
    shutil.copyfile(c.committed_checker(tmp), out / "check.py")
    if COMMITTED_ADD_WITNESS is not None:
        shutil.copyfile(COMMITTED_ADD_WITNESS, out / "add_witness.py")
    else:
        r = subprocess.run(["git", "-C", str(HERE), "show", "HEAD:claims-standard/add_witness.py"], capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError("git show HEAD:claims-standard/add_witness.py: " + r.stderr)
        (out / "add_witness.py").write_text(r.stdout, encoding="utf-8")
    shutil.copyfile(HERE / "sign.py", out / "sign.py")
    return out


def run_add_witness_with(tool, parent, ans):
    cmd = [sys.executable, "-I", str(tool), str(parent), str(ans), "--key", str(m.KEYS["adder"]), "--identity", m.ADDER]
    return subprocess.run(cmd, capture_output=True, text=True)


# ---- the mutations ----

def d2_flip(d):
    b = suite_bound(m.mload(d))
    b["sources"] = c.flip_last(b["sources"])
    add_bound(d, b)


def d3_no_pages(d):
    b = suite_bound(m.mload(d))
    del b["pages"]
    add_bound(d, b)


def d4_extra_files(d):
    b = suite_bound(m.mload(d))
    b["files"] = hashlib.sha256(b"files").hexdigest()
    add_bound(d, b)


def d5_list(d):
    b = suite_bound(m.mload(d))
    add_bound(d, [{"section": k, "sha256": v} for k, v in b.items()])


def d5_string(d):
    add_bound(d, hashlib.sha256(b"bound").hexdigest())


def d6_abc(d):
    b = suite_bound(m.mload(d))
    b["subject"] = "abc"
    add_bound(d, b)


def d7_no_carried_no_bound(d):
    c.add_carried(d, carried=ABSENT)
    add_bound(d, ABSENT)


def d8_canonical():
    if not (SERVICE / "onedroid_witness" / "request.py").is_file():
        # the public repository holds the format alone: the cross-tool comparison runs where the witness service's tree is beside it (the owner's notepad)
        print("skipped  d8_canonical_form_equals_service: no witness-service folder beside this repository (the owner's notepad runs it)")
        return None
    try:
        sys.path.insert(0, str(SERVICE))
        req = importlib.import_module("onedroid_witness.request")
    except Exception as ex:  # noqa: BLE001
        return report("d8_canonical_form_equals_service", False, "onedroid_witness.request imported from the witness-service folder", f"import failed: {ex!r}")
    M = json.loads((SRC_G / "manifest.json").read_text(encoding="utf-8"))
    theirs = {s: hashlib.sha256(req._canonical(req._section(M, s)).encode("utf-8")).hexdigest() for s in req.BOUND_MANIFEST_SECTIONS}
    try:
        ours = check.bound_sections(M)
        sects = tuple(check.BOUND_SECTIONS)
    except AttributeError as ex:
        return report("d8_canonical_form_equals_service", False, "check.bound_sections equals the service's per section", f"check has no bound_sections: {ex}",
                      [f"service {s}: {h}" for s, h in theirs.items()])
    ok = sects == tuple(req.BOUND_MANIFEST_SECTIONS) and ours == theirs
    return report("d8_canonical_form_equals_service", ok, f"sections {list(req.BOUND_MANIFEST_SECTIONS)}, every hash equal",
                  f"sections {list(sects)}, equal: {ours == theirs}",
                  [f"service {s}: {theirs[s]}" for s in theirs] + [f"check   {s}: {ours.get(s)}" for s in sects])


def d7_case(tmp, fx, name, mutate, has):
    d = tmp / name
    shutil.copytree(fx, d)
    (d / "CHECK.json").unlink(missing_ok=True)
    mutate(d)
    r, st, bl = c.run_check(HERE / "check.py", d)
    ns = notes(bl)
    ok = st.get("K11") == "WARN" and len(ns) == 1 and has in bl.get("K11", "") and r.returncode == 0
    return report(name, ok, f"K11 WARN with exactly one note, carrying {has!r}, exit 0", f"K11 {st.get('K11')}, {len(ns)} note(s), carries: {has in bl.get('K11', '')}, exit {r.returncode}", c.block_lines(bl, "K11"))


def d9_u2(tmp, committed):
    d = tmp / "d9_u2_forged_insertion"
    shutil.copytree(SRC_U2, d)
    (d / "CHECK.json").unlink(missing_ok=True)
    rw, stw, blw = c.run_check(HERE / "check.py", d)
    k11 = blw.get("K11", "")
    r2 = [l for l in notes(blw) if "C-005" in l and "pointer [0]" in l and "'prod/config.yaml'" in l and NOT_CARRIED in l]
    named = sorted({w for w in U2_WITNESSES for l in r2 if f"witness {w!r}" in l})
    warns = [l for l in notes(blw) if BOUND_WARN in l]
    warn_named = sorted({w for w in U2_WITNESSES for l in warns if f"witness {w!r}" in l})
    ok = stw.get("K11") == "FAIL" and len(r2) == 2 and len(named) == 2 and len(warns) == 2 and len(warn_named) == 2 and rw.returncode != 0
    details = c.block_lines(blw, "K11") + [f"SUMMARY: {blw.get('SUMMARY', '(none)').splitlines()[0] if blw.get('SUMMARY') else '(none)'}"]
    if committed is not None:
        rc, stc, blc = c.run_check(committed, d)
        summ = blc.get("SUMMARY", "").splitlines()[0] if blc.get("SUMMARY") else "(no SUMMARY)"
        cok = rc.returncode == 0 and "15 checks, 0 failed" in summ and stc.get("K11") == "PASS"
        details.append(f"committed checker: exit {rc.returncode}, K11 {stc.get('K11')}, {summ}")
        ok = ok and cok
        exp_c = "; committed: exit 0, K11 PASS, '15 checks, 0 failed'"
        obs_c = f"; committed exit {rc.returncode}, K11 {stc.get('K11')}"
    else:
        exp_c = obs_c = " (committed comparison skipped: --committed none)"
    return report("d9_u2_forged_insertion_flips_to_FAIL", ok, "cut: K11 FAIL, two R2 lines naming C-005, pointer [0], 'prod/config.yaml', not carried (both witnesses), two bound WARNs, exit non-zero" + exp_c,
                  f"cut: K11 {stw.get('K11')}, R2 lines {len(r2)} naming {named}, bound WARNs {len(warns)} naming {warn_named}, exit {rw.returncode}" + obs_c, details)


def d10_add_witness(tmp, fpre, FB):
    ans = tmp / "d10_answer"
    c.make_answer(FB, ans)
    parent = tmp / "d10_parent"
    shutil.copytree(fpre, parent)
    r = c.run_add_witness(parent, ans)
    rchk, stchk, blchk = c.run_check(HERE / "check.py", parent)
    summ = blchk.get("SUMMARY", "").splitlines()[0] if blchk.get("SUMMARY") else "(no SUMMARY)"
    ok = r.returncode == 0 and "added 1 witness(es)" in r.stdout and summ.rstrip().endswith(": PASS") and rchk.returncode == 0 and stchk.get("K11") == "PASS"
    report("d10a_add_witness_bound_answer_accepted", ok, "exit 0, 'added 1 witness(es)', SUMMARY PASS, K11 PASS on the parent",
           f"exit {r.returncode}, added line: {'added 1 witness(es)' in r.stdout}, {summ}, K11 {stchk.get('K11')}, check exit {rchk.returncode}",
           [l for l in r.stdout.splitlines() if l.startswith(("added", "SUMMARY"))] + ([f"stderr: {r.stderr.strip()[-300:]}"] if r.stderr.strip() else []) + c.block_lines(blchk, "K11"))
    for label, mutate, want in (("d10b_add_witness_bound_sources_mismatch_refused", d2_flip, ["bound 'sources'", "differs from this snapshot's"]),
                                ("d10c_add_witness_bound_missing_pages_refused", d3_no_pages, ["not the five bound sections"])):
        FBx = tmp / (label + "_F")
        shutil.copytree(FB, FBx)
        mutate(FBx)
        ansx = tmp / (label + "_answer")
        c.make_answer(FBx, ansx)
        parentx = tmp / (label + "_parent")
        shutil.copytree(fpre, parentx)
        before = c.tree_hashes(parentx)
        rx = run_add_witness_with(HERE / "add_witness.py", parentx, ansx)
        after = c.tree_hashes(parentx)
        unchanged = before == after
        missing = [s for s in want if s not in rx.stderr]
        ok = rx.returncode == 1 and "refused, nothing written" in rx.stderr and not missing and unchanged
        report(label, ok, f"exit 1, stderr 'refused, nothing written' carrying {want}, parent's {len(before)} files unchanged by hash",
               f"exit {rx.returncode}, refused line: {'refused, nothing written' in rx.stderr}, lacking {missing}, files unchanged: {unchanged} ({len(after)} hashed)",
               [f"stderr: {l}" for l in rx.stderr.strip().splitlines()] + ([f"stdout: {rx.stdout.strip()[:200]}"] if rx.stdout.strip() else [])
               + ([] if unchanged else [f"changed: {[k for k in before if before.get(k) != after.get(k)] + [k for k in after if k not in before]}"]))


def d11_u2_rebuilt(tmp, fpre, committed_dir):
    forger = tmp / "d11_forger_parent"
    shutil.copytree(fpre, forger)
    M = m.mload(forger)
    src_by_path = {s["path"]: s for s in M["sources"] if s.get("path")}
    victim, donor = src_by_path["hello.txt"], src_by_path["bye.txt"]
    victim["file"], victim["sha256"] = donor["file"], donor["sha256"]
    m.msave(forger, M)
    p.add_model_witness(forger)
    c.add_carried(forger)   # the forger's files: sources/files/bye.txt alone (hello.txt's file is named by no entry now)
    add_bound(forger)       # the FORGER's sections
    hdr = check.load_jsonl(forger / WF)[0]
    ans = tmp / "d11_answer"
    c.make_answer(forger, ans)
    details = [f"forger carried: {sorted(hdr['carried'])}", f"forger bound sources: {hdr['bound']['sources'][:12]}…  genuine: {suite_bound(m.mload(fpre))['sources'][:12]}…"]
    # the committed add_witness.py (no bound rule) inserts it into a copy of the GENUINE parent
    if committed_dir is None:
        print("skipped  d11a_committed_add_witness_inserts: --committed none, no committed add_witness.py to insert with")
    else:
        genuine = tmp / "d11_genuine_parent"
        shutil.copytree(fpre, genuine)
        ri = run_add_witness_with(committed_dir / "add_witness.py", genuine, ans)
        report("d11a_committed_add_witness_inserts_the_forgers_answer", ri.returncode == 0 and "added 1 witness(es)" in ri.stdout, "exit 0 (the committed tool has no bound rule)",
               f"exit {ri.returncode}, added line: {'added 1 witness(es)' in ri.stdout}", details + [f"committed add_witness stdout: {l}" for l in ri.stdout.strip().splitlines()] + ([f"stderr: {ri.stderr.strip()[-300:]}"] if ri.stderr.strip() else []))
        rw, stw, blw = c.run_check(HERE / "check.py", genuine)
        ns = notes(blw)
        r1 = [l for l in ns if "bound 'sources'" in l and "differs from this record's" in l]
        r2 = [l for l in ns if "C-001" in l and "pointer [0] file 'hello.txt'" in l and "'sources/files/hello.txt'" in l and NOT_CARRIED in l]
        ok = stw.get("K11") == "FAIL" and len(r1) == 1 and len(r2) == 1 and rw.returncode != 0
        report("d11b_cut_checker_fails_R1c_and_R2", ok, "K11 FAIL with one R1(c) 'sources' line and one R2 line on C-001 pointer [0] file 'hello.txt' held at 'sources/files/hello.txt', exit non-zero",
               f"K11 {stw.get('K11')}, R1(c) lines {len(r1)}, R2 lines {len(r2)}, exit {rw.returncode}", c.block_lines(blw, "K11"))
    genuine2 = tmp / "d11_genuine_parent_cut_tool"
    shutil.copytree(fpre, genuine2)
    before = c.tree_hashes(genuine2)
    rr = run_add_witness_with(HERE / "add_witness.py", genuine2, ans)
    unchanged = before == c.tree_hashes(genuine2)
    named = "bound 'sources'" in rr.stderr
    ok = rr.returncode == 1 and "refused, nothing written" in rr.stderr and named and unchanged
    report("d11c_cut_add_witness_refuses_the_forgers_answer", ok, "exit 1, 'refused, nothing written' naming bound 'sources', parent unchanged",
           f"exit {rr.returncode}, refused: {'refused, nothing written' in rr.stderr}, sources named: {named}, unchanged: {unchanged}",
           [f"stderr: {l}" for l in rr.stderr.strip().splitlines()])


def d12_published(committed):
    if committed is None:
        print("skipped  d12: --committed none, no committed checker to compare with")
        return
    folders = c.published_folders() + [SRC_G.relative_to(HERE)]
    special = {pathlib.Path("examples/witness-service-aw4-2026-11-13"), pathlib.Path("examples/witness-service-tr4-2026-11-13")}
    for rel in folders:
        (rc, _, _), (rw, _, _) = c.both(committed, HERE / rel)
        label = f"d12_{str(rel).replace('/', '_')}"
        summ = next((l for l in rw.stdout.splitlines() if l.startswith("SUMMARY")), "(no SUMMARY)")
        if rel not in special:
            report(label, rc.stdout == rw.stdout and rc.returncode == rw.returncode, "whole output byte-identical, exit codes equal",
                   f"identical: {rc.stdout == rw.stdout}, exit committed={rc.returncode} cut={rw.returncode}; {summ}")
            continue
        diff = [l for l in difflib.unified_diff(rc.stdout.splitlines(), rw.stdout.splitlines(), "committed", "cut", lineterm="", n=0)]
        body = [l for l in diff[2:] if not l.startswith("@@")]
        added_warn = [l for l in body if l.startswith("+") and BOUND_WARN in l]
        other = [l for l in body if not (l.startswith("+") and BOUND_WARN in l) and not (l[:1] in "+-" and (l[1:].startswith("K11 ") or l[1:].startswith("SUMMARY:")))]
        ok = len(added_warn) >= 1 and not other and rc.returncode == rw.returncode
        report(label, ok, "diff = the added bound WARN line(s) plus the K11 status and SUMMARY count lines they change, nothing else; exit codes equal",
               f"{len(added_warn)} warning line(s) added, {len(other)} other line(s), exit committed={rc.returncode} cut={rw.returncode}; {summ}", ["diff: " + l for l in diff])


def main():
    if not (c.SRC_F / "audit.jsonl").exists() or not (SRC_G / "manifest.json").exists() or not (SRC_U2 / "manifest.json").exists():
        print(f"fixture sources missing: {c.SRC_F}, {SRC_G}, {SRC_U2}", file=sys.stderr)
        return 2
    if not shutil.which("ssh-keygen"):
        print("ssh-keygen is not on PATH", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        fpre, F = c.build(tmp / "build")
        FB = tmp / "build" / "FB"
        shutil.copytree(F, FB)
        add_bound(FB)
        committed = None if c.SKIP_COMMITTED else c.committed_checker(tmp)
        committed_dir = None if c.SKIP_COMMITTED else committed_tools(tmp)
        hb = check.load_jsonl(FB / WF)[0]["bound"]
        print(f"fixture FB: bound over {list(hb)}; sources {hb['sources'][:12]}…")
        c.case(tmp, FB, "d1_FB_unchanged", lambda d: None, {"K11": "PASS"}, lacks={"K11": "bound"}, exit_in=(0,))
        c.case(tmp, FB, "d2_FB_bound_sources_flipped", d2_flip, {"K11": "FAIL"}, has={"K11": ["bound 'sources'", "differs from this record's"]})
        c.case(tmp, FB, "d3_FB_bound_without_pages", d3_no_pages, {"K11": "FAIL"}, has={"K11": "not the five bound sections"})
        c.case(tmp, FB, "d4_FB_bound_extra_key_files", d4_extra_files, {"K11": "FAIL"}, has={"K11": "not the five bound sections"})
        c.case(tmp, FB, "d5a_FB_bound_is_a_list", d5_list, {"K11": "FAIL"}, has={"K11": "is not an object"})
        c.case(tmp, FB, "d5b_FB_bound_is_a_string", d5_string, {"K11": "FAIL"}, has={"K11": "is not an object"})
        c.case(tmp, FB, "d6_FB_bound_subject_abc", d6_abc, {"K11": "FAIL"}, has={"K11": ["bound 'subject'", "is not 64 hex characters"]})
        d7_case(tmp, F, "d7a_F_carried_no_bound_one_warn", lambda d: None, BOUND_WARN)
        d7_case(tmp, F, "d7b_F_no_carried_no_bound_only_carried_warn", d7_no_carried_no_bound, "records no `carried`")
        d8_canonical()
        d9_u2(tmp, committed)
        d10_add_witness(tmp, fpre, FB)
        d11_u2_rebuilt(tmp, fpre, committed_dir)
        d12_published(committed)
        mism = sum(1 for r in c.RESULTS if not r)
        print(f"{sum(c.RESULTS)} of {len(c.RESULTS)} cases gave the expected result; MISMATCH {mism}")
        return 0 if all(c.RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
