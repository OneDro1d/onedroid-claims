#!/usr/bin/env python3
"""mutants06f.py: the test suite of the sources cut of 13 Nov 2026 (NEXT-REVISION 25b; the format owner's design after the eighth re-gate of
the witness service PASSED). Since the bound cut every model witness header carries `bound`, the sha256 of the five bound manifest sections,
and K11 holds it to the record's own manifest; what bound those five sections to the AUDITOR was still the published copy and a reader's
trust in the service's key, because the `manifest` signature is re-signed by whoever last changed the folder.

The cut: a fifth signature role, `sources`. The auditor signs, with the key that signed audit.jsonl, the line
    claims-snapshot/0.4 sources manifest.json sha256:<bound digest>
where the bound digest is sha256 of the canonical JSON of {section: sha256} over subject, sources, pages, grading.profile and
grading.sessions (check.bound_digest, one helper for check.py, sign.py and add_witness.py). The entry's `sha256` IS the bound digest, so the
signature stays valid through every witness insertion; its file is `manifest.sources.sig`.

K13 rules under test (each with its message):
  R1  a `sources` entry is over manifest.json; over any other file it "is not a part of this snapshot".
  R2  its sha256 equals bound_digest of THIS record, else FAIL "... changed under the auditor".
  R3  its line is the prescribed one, its signature file exists and verifies; ok line "manifest.json: sources bound by <name>, verified".
  R4  the signer's key is one of the auditor's keys (allowed_signers, by type and base64), else FAIL "is not the auditor's key"; with no
      auditor entry at all FAIL "a sources signature with no auditor signature to match".
  R5  absence: an evidence-shaped auditor part AND at least one model witness AND no `sources` entry: WARN "no sources signature";
      otherwise nothing is printed.
  R6  more than one `sources` entry: each checked by R1 to R4.
sign.py --role sources: file manifest.json implied; refuses (exit 1, nothing written) a folder with no auditor entry ("sign audit.jsonl
first") and a key other than the auditor's ("use the key that signed audit.jsonl"); never touches the manifest.
add_witness.py: the `sources` entry is a non-manifest entry, kept in order; a `bound` mismatch against a snapshot with a verified sources
signature says "; the auditor signed these sections".

Fixtures, built in a temporary folder with throwaway keys (mutants06.KEYS), nothing written into the repository:
  Fpre, F  as mutants06c builds them; FB as mutants06d (F with `bound`).
  FS       FB plus a `sources` signature by the AUDITOR key (the key mutants06p used for audit.jsonl), via `sign.py --role sources`.
  FpreS    Fpre plus the same `sources` signature (the parent of s7's insertions).
The suite computes the bound digest ITSELF (suite_digest below, its own canonical form), so no expectation runs through check.bound_digest.

Cases (`--committed PATH | none` names the committed check.py; `--committed-add-witness PATH` the committed add_witness.py, default git HEAD):
  s1   FS: K13 PASS with the ok line "sources bound by", exit 0; no K11 bound WARN (bound present) and no R5 WARN.
  s2   FS with the entry's sha256 last hex digit flipped (not re-signed): K13 FAIL, one line "changed under the auditor".
  s3   FS with the manifest's sources[0].file re-aimed at another genuine file in the folder (the forger of round 7), nothing re-signed:
       K13 FAIL "changed under the auditor" AND K11 FAIL (bound 'sources' differs from this record's).
  s4   FS re-signed under `sources` with the MODEL key (allowed_signers holds it), by the suite's own ssh-keygen call: K13 FAIL "is not the auditor's key".
  s5   FS with the sources entry's file set to "audit.jsonl": K13 FAIL "is not a part of this snapshot".
  s6   F (no sources signature): exactly one K13 WARN "no sources signature"; Fpre: no such line; the 0.4 cited-sources snapshot plus
       mutants06p.add_model_witness (no evidence lists): no such line.
  s7   add_witness.py: FB's answer into a copy of FpreS: exit 0, the sources entry at the same index, manifest.sources.sig byte-identical,
       check.py PASS, no R5 WARN, the ok line present; the same with the answer's bound['sources'] altered: exit 1, refused, the refusal
       holding "the auditor signed these sections"; the COMMITTED add_witness.py on the first answer: exit 0, entry and .sig kept (nothing new to write).
  s8   sign.py --role sources: with the model key: exit 1 "use the key that signed audit.jsonl", no file written, signatures.json and
       allowed_signers unchanged; on a folder with no auditor entry: exit 1 "sign audit.jsonl first", nothing written; with the auditor key
       twice: exit 0 both, one entry, the second run's digest equal to the first's and to the suite's.
  s9   bound_digest: the suite's own digest of fixtures/aw10-regate7-2026-11-13/manifest.json equals check.bound_digest(M); both printed.
  s10  every folder under snapshots/, examples/ and fixtures/: committed vs cut byte-identical and exit codes equal, EXCEPT
       examples/witness-service-aw4-2026-11-13, examples/witness-service-tr4-2026-11-13 and fixtures/aw10-regate7-forged-insertion-u2-2026-11-13
       (the published folders with a model witness over an evidence-shaped part), whose unified diff holds exactly one added R5 WARN line and,
       as its consequence, the K13 status line and the SUMMARY warning count (printed; any other line is a MISMATCH). The brief of the cut
       also named fixtures/aw10-regate7-2026-11-13, but that fixture lists no witness (grading.witnesses []), so by R5 as written it prints
       nothing and this suite expects it byte-identical (said in the implementer's report).

usage: python3 -I mutants06f.py [--committed PATH | --committed none] [--committed-add-witness PATH]
Exit 0 only when every expectation holds; one line per case "ok/MISMATCH <case>: expected ... observed ...", the K13 (and K11) blocks
printed under the cases that touch them."""
import difflib, hashlib, json, pathlib, shutil, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402
import mutants06 as m  # noqa: E402
import mutants06p as p  # noqa: E402
import mutants06c as c  # noqa: E402
import mutants06d as dd  # noqa: E402

ARGS = sys.argv[1:]
_CAW = ARGS[ARGS.index("--committed-add-witness") + 1] if "--committed-add-witness" in ARGS else None
COMMITTED_ADD_WITNESS = pathlib.Path(_CAW).resolve() if _CAW else None
SECTIONS = ("subject", "sources", "pages", "grading.profile", "grading.sessions")
SRC_G = HERE / "fixtures/aw10-regate7-2026-11-13"
SIG = "manifest.sources.sig"
NAMESPACE = "claims-snapshot"
OK_LINE = "sources bound by"
R2_MSG = "changed under the auditor"
R4_MSG = "is not the auditor's key"
R5_MSG = "no sources signature"
NOT_PART = "is not a part of this snapshot"
PHRASE = "the auditor signed these sections"
REFUSE_KEY = "use the key that signed audit.jsonl"
REFUSE_FIRST = "sign audit.jsonl first"
SPECIAL = {pathlib.Path("examples/witness-service-aw4-2026-11-13"), pathlib.Path("examples/witness-service-tr4-2026-11-13"),
           pathlib.Path("fixtures/aw10-regate7-forged-insertion-u2-2026-11-13")}
WF = c.WF


def section(M, dotted):
    cur = M
    for k in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def canon(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def suite_digest(M):
    """The suite's own reading of the bound digest (SPEC 3a, the sources role): sha256 of the canonical JSON of {section: sha256 of the
    canonical JSON of that section}. Written here, not read from check.bound_digest, so the expectation does not run through the function under test."""
    secs = {s: hashlib.sha256(canon(section(M, s))).hexdigest() for s in SECTIONS}
    return hashlib.sha256(canon(secs)).hexdigest()


def sources_line(digest):
    return f"claims-snapshot/0.4 sources manifest.json sha256:{digest}"


def load_sigs(d):
    return json.loads((d / "signatures.json").read_text(encoding="utf-8"))


def save_sigs(d, sigs):
    (d / "signatures.json").write_text(json.dumps(sigs, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def sources_entries(sigs):
    return [(i, e) for i, e in enumerate(sigs) if isinstance(e, dict) and e.get("role") == "sources"]


def sign_sources(d, key="auditor", ident=p.AUDITOR, with_file=False):
    """sign.py --role sources with a throwaway key; the CompletedProcess, never an exception (the refusals are under test)."""
    cmd = [sys.executable, "-I", str(HERE / "sign.py"), str(d), "--role", "sources", "--key", str(m.KEYS[key]), "--identity", ident]
    if with_file:
        cmd += ["--file", "manifest.json"]
    return subprocess.run(cmd, capture_output=True, text=True)


def own_sign(d, key, ident):
    """The suite signs the prescribed sources line itself (ssh-keygen -Y sign), writes manifest.sources.sig and names the signer on the
    existing entry: a sources signature under another key than the auditor's (s4), which sign.py refuses to make."""
    digest = suite_digest(m.mload(d))
    line = sources_line(digest)
    with tempfile.TemporaryDirectory() as td:
        msg = pathlib.Path(td) / "line"
        msg.write_text(line, encoding="utf-8")
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(m.KEYS[key]), "-n", NAMESPACE, str(msg)], check=True, capture_output=True)
        (d / SIG).write_bytes((pathlib.Path(td) / "line.sig").read_bytes())
    fp = subprocess.run(["ssh-keygen", "-lf", str(m.KEYS[key]) + ".pub"], capture_output=True, text=True, check=True).stdout.split()[1]
    sigs = load_sigs(d)
    for _, e in sources_entries(sigs):
        e["signer"] = {"name": ident, "key_id": fp, "kind": "ssh-ed25519"}
        e["sha256"], e["line"] = digest, line
    save_sigs(d, sigs)


def notes(blocks, k="K13"):
    return [l.strip() for l in blocks.get(k, "").splitlines() if l.startswith(" ")]


def report(name, ok, expected, observed, details=()):
    return c.report(name, ok, expected, observed, details)


def run(d):
    return c.run_check(HERE / "check.py", d)


def summary(bl):
    return bl.get("SUMMARY", "").splitlines()[0] if bl.get("SUMMARY") else "(no SUMMARY)"


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


def copy_of(tmp, fx, name):
    d = tmp / name
    shutil.copytree(fx, d)
    (d / "CHECK.json").unlink(missing_ok=True)
    return d


# ---- fixtures ----

def build_signed(tmp, src, name):
    """src plus a sources signature by the auditor key through sign.py; None when sign.py refuses (the committed sign.py has no such role)."""
    d = copy_of(tmp, src, name)
    r = sign_sources(d)
    ok = r.returncode == 0 and (d / SIG).is_file() and len(sources_entries(load_sigs(d))) == 1
    ent = sources_entries(load_sigs(d))
    want = suite_digest(m.mload(d))
    digest_ok = bool(ent) and ent[0][1].get("sha256") == want and ent[0][1].get("line") == sources_line(want) and ent[0][1].get("signature") == SIG and ent[0][1].get("file") == "manifest.json"
    report(f"fixture_{name}_signed_by_sign_py", ok and digest_ok,
           f"sign.py --role sources exit 0, {SIG} written, one sources entry over manifest.json with sha256 = the suite's bound digest and the prescribed line",
           f"exit {r.returncode}, {SIG} present: {(d / SIG).is_file()}, sources entries: {len(ent)}, entry as expected: {digest_ok}",
           [f"stdout: {l}" for l in r.stdout.strip().splitlines()] + [f"stderr: {l}" for l in r.stderr.strip().splitlines()] + [f"suite digest: {want}"])
    return d if ok else None


def not_built(name, expected):
    report(name, False, expected, "the signed fixture was not built (sign.py --role sources failed)")


# ---- the mutations ----

def s2_flip(d):
    sigs = load_sigs(d)
    for _, e in sources_entries(sigs):
        e["sha256"] = c.flip_last(e["sha256"])
    save_sigs(d, sigs)


def s3_reaim(d):
    M = m.mload(d)
    victim = M["sources"][0]
    donor = next(s for s in M["sources"][1:] if s.get("file") and s.get("file") != victim.get("file"))
    victim["file"], victim["sha256"] = donor["file"], donor["sha256"]
    m.msave(d, M)
    return victim.get("path"), donor["file"]


def s5_audit(d):
    sigs = load_sigs(d)
    for _, e in sources_entries(sigs):
        e["file"] = "audit.jsonl"
    save_sigs(d, sigs)


def s8b_no_auditor(d):
    save_sigs(d, [e for e in load_sigs(d) if e.get("role") != "auditor"])


# ---- the cases ----

def s1(tmp, FS):
    if FS is None:
        return not_built("s1_FS_sources_signature_verified", "K13 PASS with the ok line, exit 0, no bound WARN, no R5 WARN")
    d = copy_of(tmp, FS, "s1_FS")
    r, st, bl = run(d)
    k13, k11 = bl.get("K13", ""), bl.get("K11", "")
    ok_lines = [l for l in notes(bl) if OK_LINE in l and f"by {p.AUDITOR}" in l and "verified" in l]
    ok = r.returncode == 0 and st.get("K13") == "PASS" and len(ok_lines) == 1 and R5_MSG not in k13 and "no `bound`" not in k11 and st.get("K11") == "PASS"
    report("s1_FS_sources_signature_verified", ok, f"exit 0, K13 PASS with one line '{OK_LINE} {p.AUDITOR}, verified', no '{R5_MSG}', K11 PASS without a bound WARN",
           f"exit {r.returncode}, K13 {st.get('K13')}, ok lines {len(ok_lines)}, R5 present: {R5_MSG in k13}, K11 {st.get('K11')}, bound WARN: {'no `bound`' in k11}",
           c.block_lines(bl, "K11", "K13"))


def s2(tmp, FS):
    if FS is None:
        return not_built("s2_FS_entry_sha256_flipped", f"K13 FAIL with one line '{R2_MSG}'")
    d = copy_of(tmp, FS, "s2_FS_flipped")
    s2_flip(d)
    r, st, bl = run(d)
    hits = [l for l in notes(bl) if R2_MSG in l]
    ok = st.get("K13") == "FAIL" and len(hits) == 1 and r.returncode != 0
    report("s2_FS_entry_sha256_flipped", ok, f"K13 FAIL with exactly one line '{R2_MSG}', exit non-zero",
           f"K13 {st.get('K13')}, lines {len(hits)}, exit {r.returncode}", c.block_lines(bl, "K13"))


def s3(tmp, FS):
    if FS is None:
        return not_built("s3_FS_sources_reaimed_under_the_auditor", f"K13 FAIL '{R2_MSG}' and K11 FAIL bound 'sources'")
    d = copy_of(tmp, FS, "s3_FS_reaimed")
    path_, donor = s3_reaim(d)
    r, st, bl = run(d)
    k13 = [l for l in notes(bl) if R2_MSG in l]
    k11 = [l for l in notes(bl, "K11") if "bound 'sources'" in l and "differs from this record's" in l]
    ok = st.get("K13") == "FAIL" and len(k13) == 1 and st.get("K11") == "FAIL" and len(k11) == 1 and r.returncode != 0
    report("s3_FS_sources_reaimed_under_the_auditor", ok, f"K13 FAIL with one '{R2_MSG}' line AND K11 FAIL with one bound 'sources' line, exit non-zero",
           f"K13 {st.get('K13')} ({len(k13)}), K11 {st.get('K11')} ({len(k11)}), exit {r.returncode}",
           [f"re-aimed: source path {path_!r} now names {donor!r}"] + c.block_lines(bl, "K11", "K13"))


def s4(tmp, FS):
    if FS is None:
        return not_built("s4_FS_resigned_with_the_model_key", f"K13 FAIL '{R4_MSG}'")
    d = copy_of(tmp, FS, "s4_FS_model_key")
    own_sign(d, "model1", p.MP)
    r, st, bl = run(d)
    hits = [l for l in notes(bl) if R4_MSG in l and f"by {p.MP!r}" in l]
    ok = st.get("K13") == "FAIL" and len(hits) == 1 and r.returncode != 0
    report("s4_FS_resigned_with_the_model_key", ok, f"K13 FAIL with one line '{R4_MSG}' naming {p.MP!r}, exit non-zero",
           f"K13 {st.get('K13')}, lines {len(hits)}, exit {r.returncode}", c.block_lines(bl, "K13"))


def s5(tmp, FS):
    if FS is None:
        return not_built("s5_FS_sources_entry_over_audit_jsonl", f"K13 FAIL '{NOT_PART}'")
    d = copy_of(tmp, FS, "s5_FS_over_audit")
    s5_audit(d)
    r, st, bl = run(d)
    hits = [l for l in notes(bl) if NOT_PART in l and "'sources'" in l and "'audit.jsonl'" in l]
    ok = st.get("K13") == "FAIL" and len(hits) == 1 and r.returncode != 0
    report("s5_FS_sources_entry_over_audit_jsonl", ok, f"K13 FAIL with one line \"'sources' over 'audit.jsonl' {NOT_PART}\", exit non-zero",
           f"K13 {st.get('K13')}, lines {len(hits)}, exit {r.returncode}", c.block_lines(bl, "K13"))


def s6(tmp, fpre, F):
    d = copy_of(tmp, F, "s6a_F_no_sources_signature")
    r, st, bl = run(d)
    hits = [l for l in notes(bl) if R5_MSG in l]
    ok = st.get("K13") == "WARN" and len(hits) == 1 and "sign.py --role sources" in (hits[0] if hits else "") and r.returncode == 0
    report("s6a_F_model_witness_no_sources_signature_warns", ok, f"K13 WARN with exactly one '{R5_MSG}' line naming sign.py --role sources, exit 0",
           f"K13 {st.get('K13')}, lines {len(hits)}, exit {r.returncode}", c.block_lines(bl, "K13"))
    d = copy_of(tmp, fpre, "s6b_Fpre")
    r, st, bl = run(d)
    ok = R5_MSG not in bl.get("K13", "") and st.get("K13") == "PASS" and r.returncode == 0
    report("s6b_Fpre_no_witness_no_R5_line", ok, f"no '{R5_MSG}' line, K13 PASS, exit 0", f"present: {R5_MSG in bl.get('K13', '')}, K13 {st.get('K13')}, exit {r.returncode}", c.block_lines(bl, "K13"))
    if not (c.SRC_04 / "audit.jsonl").exists():
        print(f"skipped  s6c_04_model_witness_no_evidence_no_R5_line: no 0.4 snapshot at {c.SRC_04}")
        return
    d = copy_of(tmp, c.SRC_04, "s6c_04_model_witness")
    p.add_model_witness(d)
    r, st, bl = run(d)
    ok = R5_MSG not in bl.get("K13", "") and "sources" not in bl.get("K13", "")
    report("s6c_04_model_witness_no_evidence_no_R5_line", ok, f"no '{R5_MSG}' line (page profile, no evidence lists), no 'sources' word in K13",
           f"present: {R5_MSG in bl.get('K13', '')}, K13 {st.get('K13')}, exit {r.returncode}", c.block_lines(bl, "K13"))


def s7(tmp, FB, FpreS, committed_dir):
    if FpreS is None:
        not_built("s7a_add_witness_keeps_the_sources_signature", "exit 0, entry at the same index, .sig identical, check PASS, no R5")
        not_built("s7b_add_witness_bound_mismatch_names_the_auditor", f"exit 1, refused, '{PHRASE}'")
        return
    ans = tmp / "s7_answer"
    c.make_answer(FB, ans)
    parent = copy_of(tmp, FpreS, "s7a_parent")
    idx_before = sources_entries(load_sigs(parent))[0][0]
    sig_before = (parent / SIG).read_bytes()
    r = run_add_witness_with(HERE / "add_witness.py", parent, ans)
    ent = sources_entries(load_sigs(parent))
    same_idx = len(ent) == 1 and ent[0][0] == idx_before
    same_sig = (parent / SIG).is_file() and (parent / SIG).read_bytes() == sig_before
    rchk, stchk, blchk = run(parent)
    summ = summary(blchk)
    k13 = blchk.get("K13", "")
    ok = r.returncode == 0 and "added 1 witness(es)" in r.stdout and same_idx and same_sig and summ.rstrip().endswith(": PASS") and rchk.returncode == 0 and R5_MSG not in k13 and OK_LINE in k13
    report("s7a_add_witness_keeps_the_sources_signature", ok, f"exit 0, 'added 1 witness(es)', the sources entry at index {idx_before}, {SIG} byte-identical, check.py PASS exit 0, no '{R5_MSG}', the ok line present",
           f"exit {r.returncode}, added: {'added 1 witness(es)' in r.stdout}, same index: {same_idx} ({[i for i, _ in ent]}), sig identical: {same_sig}, {summ} exit {rchk.returncode}, R5: {R5_MSG in k13}, ok line: {OK_LINE in k13}",
           [l for l in r.stdout.splitlines() if l.startswith(("added", "SUMMARY"))] + ([f"stderr: {r.stderr.strip()[-300:]}"] if r.stderr.strip() else []) + c.block_lines(blchk, "K13"))
    FBx = tmp / "s7b_FB_flipped"
    shutil.copytree(FB, FBx)
    dd.d2_flip(FBx)
    ansx = tmp / "s7b_answer"
    c.make_answer(FBx, ansx)
    parentx = copy_of(tmp, FpreS, "s7b_parent")
    before = c.tree_hashes(parentx)
    rx = run_add_witness_with(HERE / "add_witness.py", parentx, ansx)
    unchanged = before == c.tree_hashes(parentx)
    named = "bound 'sources'" in rx.stderr
    ok = rx.returncode == 1 and "refused, nothing written" in rx.stderr and named and PHRASE in rx.stderr and unchanged
    report("s7b_add_witness_bound_mismatch_names_the_auditor", ok, f"exit 1, 'refused, nothing written' naming bound 'sources' and '{PHRASE}', parent unchanged by hash",
           f"exit {rx.returncode}, refused: {'refused, nothing written' in rx.stderr}, sources named: {named}, phrase: {PHRASE in rx.stderr}, unchanged: {unchanged}",
           [f"stderr: {l}" for l in rx.stderr.strip().splitlines()])
    if committed_dir is None:
        print("skipped  s7c_committed_add_witness_keeps_the_sources_signature: --committed none")
        return
    # the committed add_witness.py keeps the entry and the .sig too (nothing new to write); its exit code is its own committed check.py's,
    # which does not know the role (K13 "not a part of this snapshot" there), so the exit is printed, not asserted
    parentc = copy_of(tmp, FpreS, "s7c_parent_committed_tool")
    rc = run_add_witness_with(committed_dir / "add_witness.py", parentc, ans)
    entc = sources_entries(load_sigs(parentc))
    okc = "added 1 witness(es)" in rc.stdout and len(entc) == 1 and entc[0][0] == idx_before and (parentc / SIG).is_file() and (parentc / SIG).read_bytes() == sig_before
    report("s7c_committed_add_witness_keeps_the_sources_signature", okc, f"the committed add_witness.py: 'added 1 witness(es)', the sources entry at index {idx_before}, {SIG} byte-identical (nothing new to write; its exit is the committed check.py's)",
           f"exit {rc.returncode}, added: {'added 1 witness(es)' in rc.stdout}, entries {[i for i, _ in entc]}, sig identical: {(parentc / SIG).is_file() and (parentc / SIG).read_bytes() == sig_before}",
           [l for l in rc.stdout.splitlines() if l.startswith(("added", "SUMMARY"))] + ([f"stderr: {rc.stderr.strip()[-300:]}"] if rc.stderr.strip() else []))


def s8(tmp, FB):
    d = copy_of(tmp, FB, "s8a_model_key")
    sigs_b, al_b = (d / "signatures.json").read_bytes(), (d / "allowed_signers").read_bytes()
    r = sign_sources(d, "model1", p.MP)
    unchanged = (d / "signatures.json").read_bytes() == sigs_b and (d / "allowed_signers").read_bytes() == al_b
    ok = r.returncode == 1 and REFUSE_KEY in r.stderr and not (d / SIG).exists() and unchanged
    report("s8a_sign_sources_with_the_model_key_refused", ok, f"exit 1, stderr '{REFUSE_KEY}', no {SIG}, signatures.json and allowed_signers unchanged",
           f"exit {r.returncode}, phrase: {REFUSE_KEY in r.stderr}, {SIG} written: {(d / SIG).exists()}, unchanged: {unchanged}",
           [f"stderr: {l}" for l in r.stderr.strip().splitlines()] + [f"stdout: {l}" for l in r.stdout.strip().splitlines()])
    d = copy_of(tmp, FB, "s8b_no_auditor_entry")
    s8b_no_auditor(d)
    sigs_b = (d / "signatures.json").read_bytes()
    r = sign_sources(d)
    unchanged = (d / "signatures.json").read_bytes() == sigs_b
    ok = r.returncode == 1 and REFUSE_FIRST in r.stderr and not (d / SIG).exists() and unchanged
    report("s8b_sign_sources_with_no_auditor_entry_refused", ok, f"exit 1, stderr '{REFUSE_FIRST}', no {SIG}, signatures.json unchanged",
           f"exit {r.returncode}, phrase: {REFUSE_FIRST in r.stderr}, {SIG} written: {(d / SIG).exists()}, unchanged: {unchanged}",
           [f"stderr: {l}" for l in r.stderr.strip().splitlines()] + [f"stdout: {l}" for l in r.stdout.strip().splitlines()])
    d = copy_of(tmp, FB, "s8c_auditor_key_twice")
    m_before = (d / "manifest.json").read_bytes()
    r1 = sign_sources(d)
    e1 = sources_entries(load_sigs(d)) if r1.returncode == 0 else []
    r2 = sign_sources(d, with_file=True)
    e2 = sources_entries(load_sigs(d)) if r2.returncode == 0 else []
    want = suite_digest(m.mload(d))
    ok = r1.returncode == 0 and r2.returncode == 0 and len(e1) == 1 and len(e2) == 1 and e1[0][1].get("sha256") == e2[0][1].get("sha256") == want and (d / "manifest.json").read_bytes() == m_before
    report("s8c_sign_sources_twice_one_entry_same_digest", ok, "exit 0 twice (the second with --file manifest.json), one sources entry, both digests equal to the suite's, manifest.json untouched",
           f"exit {r1.returncode}/{r2.returncode}, entries {len(e1)}/{len(e2)}, digests equal: {bool(e1) and bool(e2) and e1[0][1].get('sha256') == e2[0][1].get('sha256')}, equal to the suite's: {bool(e2) and e2[0][1].get('sha256') == want}, manifest untouched: {(d / 'manifest.json').read_bytes() == m_before}",
           [f"run 1: {(r1.stdout + r1.stderr).strip()[:200]}", f"run 2: {(r2.stdout + r2.stderr).strip()[:200]}", f"suite digest: {want}"])


def s9():
    M = json.loads((SRC_G / "manifest.json").read_text(encoding="utf-8"))
    ours = suite_digest(M)
    try:
        theirs = check.bound_digest(M)
    except AttributeError as ex:
        return report("s9_bound_digest_equals_the_suites", False, "check.bound_digest(M) equals the suite's digest", f"check has no bound_digest: {ex}", [f"suite: {ours}"])
    report("s9_bound_digest_equals_the_suites", ours == theirs, "check.bound_digest(M) of fixtures/aw10-regate7-2026-11-13 equals the suite's own digest",
           f"equal: {ours == theirs}", [f"suite: {ours}", f"check: {theirs}"])


def s10(committed):
    if committed is None:
        print("skipped  s10: --committed none, no committed checker to compare with")
        return
    folders = c.published_folders() + [q.relative_to(HERE) for q in sorted((HERE / "fixtures").glob("*")) if q.is_dir() and (q / "manifest.json").exists()]
    for rel in folders:
        (rc, _, _), (rw, _, _) = c.both(committed, HERE / rel)
        label = f"s10_{str(rel).replace('/', '_')}"
        summ = next((l for l in rw.stdout.splitlines() if l.startswith("SUMMARY")), "(no SUMMARY)")
        if rel not in SPECIAL:
            report(label, rc.stdout == rw.stdout and rc.returncode == rw.returncode, "whole output byte-identical, exit codes equal",
                   f"identical: {rc.stdout == rw.stdout}, exit committed={rc.returncode} cut={rw.returncode}; {summ}")
            continue
        diff = list(difflib.unified_diff(rc.stdout.splitlines(), rw.stdout.splitlines(), "committed", "cut", lineterm="", n=0))
        body = [l for l in diff[2:] if not l.startswith("@@")]
        added_warn = [l for l in body if l.startswith("+") and R5_MSG in l]
        other = [l for l in body if not (l.startswith("+") and R5_MSG in l) and not (l[:1] in "+-" and (l[1:].startswith("K13 ") or l[1:].startswith("SUMMARY:")))]
        ok = len(added_warn) == 1 and not other and rc.returncode == rw.returncode
        report(label, ok, "diff = exactly one added R5 WARN line plus the K13 status and SUMMARY count lines it changes, nothing else; exit codes equal",
               f"{len(added_warn)} warning line(s) added, {len(other)} other line(s), exit committed={rc.returncode} cut={rw.returncode}; {summ}", ["diff: " + l for l in diff])


def main():
    if not (c.SRC_F / "audit.jsonl").exists() or not (SRC_G / "manifest.json").exists():
        print(f"fixture sources missing: {c.SRC_F}, {SRC_G}", file=sys.stderr)
        return 2
    if not shutil.which("ssh-keygen"):
        print("ssh-keygen is not on PATH", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        fpre, F = c.build(tmp / "build")
        FB = tmp / "build" / "FB"
        shutil.copytree(F, FB)
        dd.add_bound(FB)
        committed = None if c.SKIP_COMMITTED else c.committed_checker(tmp)
        committed_dir = None if c.SKIP_COMMITTED else committed_tools(tmp)
        print(f"fixture FB: bound digest (the suite's) {suite_digest(m.mload(FB))[:12]}…; auditor key {p.AUDITOR}, model key {p.MP}")
        FS = build_signed(tmp, FB, "FS")
        FpreS = build_signed(tmp, fpre, "FpreS")
        s1(tmp, FS)
        s2(tmp, FS)
        s3(tmp, FS)
        s4(tmp, FS)
        s5(tmp, FS)
        s6(tmp, fpre, F)
        s7(tmp, FB, FpreS, committed_dir)
        s8(tmp, FB)
        s9()
        s10(committed)
        mism = sum(1 for r in c.RESULTS if not r)
        print(f"{sum(c.RESULTS)} of {len(c.RESULTS)} cases gave the expected result; MISMATCH {mism}")
        return 0 if all(c.RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
