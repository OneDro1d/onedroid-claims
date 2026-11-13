#!/usr/bin/env python3
"""mutants06g.py: the test suite of the auditor-key cut of 13 Nov 2026 (NEXT-REVISION 31; the format owner's design after the ninth re-gate
of the witness service PASSED with one format finding, S13). The sources cut's rule R4 compared keys BY PRINCIPAL NAME through
allowed_signers: a forger appended ONE line, its own key under the auditor's principal, signed `--role sources` with its key over a re-aimed
manifest's bound digest, and check.py 5ec50d48 printed "sources bound by <auditor>, verified" (ssh-keygen -Y verify -I <principal> accepts
any key listed under that principal). sign.py had the same hole.

The fact the cut rests on: an SSH signature file (SSHSIG) carries the SIGNER'S PUBLIC KEY inside its blob (magic SSHSIG, uint32 version,
string publickey, string namespace, string reserved, string hash_algorithm, string signature), so a checker reads which key made each
signature without ssh-keygen; the fingerprint ssh-keygen prints is "SHA256:" + base64(sha256(publickey blob)) without "=" padding.

The rules under test (check.py, K13):
  A1  one principal, one key: a principal listed in allowed_signers with more than one DISTINCT key FAILs
      "allowed_signers: principal '<name>' holds <n> keys: one principal, one key in a record (...)"; a repeated identical line is one key.
  A2  the sources key is the audit's key: the key embedded in manifest.sources.sig equals the key embedded in an auditor entry's signature
      file, else FAIL "the sources signature was made with key SHA256:<fp> and audit.jsonl with SHA256:<fp>: ..."; no readable auditor
      signature: FAIL "a sources signature with no readable auditor signature to match". With or without ssh-keygen.
  A3  every signature's embedded key is its principal's listed key, else FAIL "<file>: the signature's key SHA256:<fp> is not the key
      allowed_signers lists for '<name>'"; a file that does not parse: FAIL "<file>: signature file <sig> is not an SSH signature".
  A4  the witness is never the auditor, by the embedded key too (the VR-I11 block's key sets include the embedded keys).
sign.py: every role refuses an identity that already holds another key ("already holds another key in allowed_signers"); --role sources
needs the key EMBEDDED in the auditor entry's signature file ("use the key that signed audit.jsonl").
add_witness.py: refuses a fragment that would leave any principal with two keys ("would hold two keys in allowed_signers").

This suite reads the embedded key ITSELF (sshsig_key below, its own small parser, never check.sshsig_public_key) and takes every expected
fingerprint from `ssh-keygen -lf` on the matching public key, so no expectation runs through the function under test.

Fixtures, built in a temporary folder with throwaway keys (mutants06.KEYS) plus one fresh forger key (ssh-keygen -t ed25519 -N ''):
  Fpre, F, FB, FS  as mutants06c, mutants06d and mutants06f build them (FS = FB + the auditor's sources signature).

Cases (`--committed PATH | none` names the committed check.py; `--committed-add-witness PATH` the committed add_witness.py):
  g1   FS, the forger's key appended under the auditor principal, manifest.sources.sig re-made by the forger over the correct digest (the
       suite's own ssh-keygen call), the entry's key_id left as the auditor's (the S13 shape): K13 FAIL with the A1 line (holds 2 keys) AND
       the A2 line (both fingerprints as `ssh-keygen -lf` prints them), no "sources bound by" ok line; exit 1.
  g1b  g1 with ssh-keygen off PATH: the same A1 and A2 lines, and "present, not verified here (ssh-keygen not on PATH)" for the other entries.
  g2   FS with the auditor's allowed_signers line repeated verbatim: output byte-identical to FS (a duplicate line is one key).
  g3   FS with a second, different key under the MODEL principal: K13 FAIL with the A1 line naming that principal; the sources ok line present.
  g4   the S14 shape (allowed_signers line swapped to the forger key, audit.jsonl re-signed by the forger under the auditor's name, the
       sources re-signed): check.py PASS, every signature verified. EXPECTED: key anchoring is not a checker's to see; the published key
       list (Michal's step). The limit is on record, not hidden.
  g5   sign.py: --role witness with the forger key under the model principal: exit 1 "already holds another key", tree unchanged; --role
       sources with the forger key after its line was appended by hand under the auditor's name: exit 1 "use the key that signed audit.jsonl",
       tree unchanged (the committed sign.py exits 0 here: the RED).
  g6   add_witness.py: FB's answer whose fragment carries the auditor's principal with the forger key: exit 1 "would hold two keys", parent
       unchanged; a fragment with two different keys for the model principal: the same refusal; the committed add_witness.py on the first:
       exit 0 (RED, the hole on record).
  g7   the suite's parser against `ssh-keygen -lf`: every .sig under examples/, fixtures/ and snapshots/: the embedded key's fingerprint
       equals -lf of the signer's allowed_signers key and signatures.json's key_id where present; check.sshsig_public_key and
       check.sshsig_fingerprint agree with the suite's parser on every one; a body truncated by one line -> None; a text file -> None; a
       CRLF re-armour with a line of text after END -> the same key.
  g8   A3: FS with the auditor's allowed_signers key swapped for the forger's public key (signature files untouched): K13 FAIL with the A3
       line for audit.jsonl and for manifest.json, and ssh-keygen's "does NOT verify" lines.
  g9   A4: the model witness file re-signed with the auditor's key while the model principal's line keeps the model key: K13 FAIL with the
       A3 line AND the VR-I11 line (agent-work).
  g10  every folder under snapshots/, examples/ and fixtures/: committed vs cut byte-identical, exit codes equal.

usage: python3 -I mutants06g.py [--committed PATH | --committed none] [--committed-add-witness PATH]
Exit 0 only when every expectation holds; one line per case "ok/MISMATCH <case>: expected ... observed ...", the K13 blocks printed under
the cases that touch them."""
import base64, hashlib, json, os, pathlib, shutil, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402
import mutants06 as m  # noqa: E402
import mutants06p as p  # noqa: E402
import mutants06c as c  # noqa: E402
import mutants06d as dd  # noqa: E402
import mutants06f as f  # noqa: E402

SIG = f.SIG
NAMESPACE = f.NAMESPACE
WF = c.WF
OK_LINE = "sources bound by"
BEGIN, END = "-----BEGIN SSH SIGNATURE-----", "-----END SSH SIGNATURE-----"
A1_TAIL = "one principal, one key in a record (a second line under a name is a second key, not a second signer)"
A2_TAIL = "the sources list is bound to the key that signed the audit, not to a name in allowed_signers"
A2_NONE = "manifest.json: a sources signature with no readable auditor signature to match"
A3_MID = "is not the key allowed_signers lists for"
NOT_SSHSIG = "is not an SSH signature"
VR_I11 = "the witness is never the auditor"
NOT_VERIFIED = "present, not verified here (ssh-keygen not on PATH)"
REFUSE_HOLDS = "already holds another key in allowed_signers"
REFUSE_KEY = "use the key that signed audit.jsonl"
REFUSE_TWO = "would hold two keys in allowed_signers"
G4_NOTE = "key anchoring: not a checker's to see; the published key list (Michal's step)"
FORGER = "forger"


# ---- the suite's own SSHSIG reader (never check.sshsig_public_key) ----

def _rd(buf, off):
    if off + 4 > len(buf):
        raise ValueError("short")
    n = int.from_bytes(buf[off:off + 4], "big")
    if off + 4 + n > len(buf):
        raise ValueError("short")
    return buf[off + 4:off + 4 + n], off + 4 + n


def sshsig_key(path):
    """`<type> <base64>` of the public key inside an SSHSIG armoured file, read by this suite: text before BEGIN or any malformed byte -> None,
    text after END ignored, any line endings. The whole blob must parse (magic, version, five strings, nothing left over)."""
    try:
        text = pathlib.Path(path).read_bytes().decode("ascii")
    except (OSError, UnicodeDecodeError):
        return None
    lines = text.splitlines()
    if not lines or lines[0].strip() != BEGIN:
        return None
    try:
        end = next(i for i, l in enumerate(lines) if i > 0 and l.strip() == END)
    except StopIteration:
        return None
    try:
        blob = base64.b64decode("".join(l.strip() for l in lines[1:end]), validate=True)
    except (ValueError, TypeError):
        return None
    if blob[:6] != b"SSHSIG" or len(blob) < 10:
        return None
    off = 10
    try:
        pk, off = _rd(blob, off)
        for _ in range(4):
            _, off = _rd(blob, off)
        if off != len(blob):
            return None
        kt, _ = _rd(pk, 0)
    except ValueError:
        return None
    kt = kt.decode("ascii", errors="replace")
    if not kt.startswith(("ssh-", "ecdsa-", "sk-")):
        return None
    return kt + " " + base64.b64encode(pk).decode("ascii")


def suite_fp(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(key.split()[1])).digest()).decode("ascii").rstrip("=")


def lf_fingerprint(key_or_pubfile):
    """`ssh-keygen -lf` on a public key: a path, or a `<type> <base64>` written to a temporary file."""
    if isinstance(key_or_pubfile, pathlib.Path):
        return subprocess.run(["ssh-keygen", "-lf", str(key_or_pubfile)], capture_output=True, text=True, check=True).stdout.split()[1]
    with tempfile.TemporaryDirectory() as td:
        q = pathlib.Path(td) / "k.pub"
        q.write_text(key_or_pubfile + "\n", encoding="utf-8")
        return subprocess.run(["ssh-keygen", "-lf", str(q)], capture_output=True, text=True, check=True).stdout.split()[1]


def suite_allowed(path):
    """principal -> [keys] of an allowed_signers file, read by this suite (the key-type field and the one after it)."""
    out = {}
    for l in pathlib.Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        f_ = l.split()
        if len(f_) < 3 or l.lstrip().startswith("#"):
            continue
        kt = next((i for i, x in enumerate(f_) if i > 0 and x.startswith(("ssh-", "ecdsa-", "sk-"))), None)
        if kt is None or kt + 1 >= len(f_):
            continue
        for pn in f_[0].split(","):
            out.setdefault(pn, []).append(f_[kt] + " " + f_[kt + 1])
    return out


# ---- helpers ----

def pub_of(key):
    return pathlib.Path(str(key) + ".pub")


def pub_key(key):
    w = pub_of(key).read_text(encoding="utf-8").split()
    return w[0] + " " + w[1]


def allowed_line(ident, key):
    return f'{ident} namespaces="{NAMESPACE}" {pub_key(key)}\n'


def append_allowed(d, line):
    q = d / "allowed_signers"
    q.write_text(q.read_text(encoding="utf-8") + line, encoding="utf-8")


def swap_allowed(d, ident, key):
    q = d / "allowed_signers"
    out = [allowed_line(ident, key).rstrip("\n") if l.startswith(ident + " ") else l for l in q.read_text(encoding="utf-8").splitlines()]
    q.write_text("".join(l + "\n" for l in out), encoding="utf-8")


def own_sign_line(line, key):
    """ssh-keygen -Y sign over one line with a private key: the signature bytes."""
    with tempfile.TemporaryDirectory() as td:
        msg = pathlib.Path(td) / "line"
        msg.write_text(line, encoding="utf-8")
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", NAMESPACE, str(msg)], check=True, capture_output=True)
        return (pathlib.Path(td) / "line.sig").read_bytes()


def run_sign(d, args):
    return subprocess.run([sys.executable, "-I", str(HERE / "sign.py"), str(d), *args], capture_output=True, text=True)


def notes(bl, k="K13"):
    return [l.strip() for l in bl.get(k, "").splitlines() if l.startswith(" ")]


def report(name, ok, expected, observed, details=()):
    return c.report(name, ok, expected, observed, details)


def run(d):
    return c.run_check(HERE / "check.py", d)


def run_no_ssh_keygen(d, bindir):
    env = dict(os.environ)
    env["PATH"] = str(bindir)
    r = subprocess.run([sys.executable, "-I", str(HERE / "check.py"), str(d)], capture_output=True, text=True, env=env)
    st, bl = m.statuses(r.stdout)
    return r, st, bl


def committed_k13(committed, d):
    if committed is None:
        return []
    _, _, blc = c.run_check(committed, d)
    return ["committed checker: " + l for l in blc.get("K13", "").splitlines()]


def a1_line(name, n):
    return f"allowed_signers: principal '{name}' holds {n} keys: {A1_TAIL}"


def a2_line(fp_sources, fp_audit):
    return f"manifest.json: the sources signature was made with key {fp_sources} and audit.jsonl with {fp_audit}: {A2_TAIL}"


def a3_line(file, fp, name):
    return f"{file}: the signature's key {fp} {A3_MID} '{name}'"


def norm(out, *paths):
    for q in paths:
        out = out.replace(str(q), "<snap>")
    return out


# ---- the cases ----

def g1_forge(tmp, FS, forger, name):
    d = f.copy_of(tmp, FS, name)
    append_allowed(d, allowed_line(p.AUDITOR, forger))
    line = f.sources_line(f.suite_digest(m.mload(d)))
    (d / SIG).write_bytes(own_sign_line(line, forger))  # the entry's key_id stays the auditor's: the S13 shape
    return d


def g1(tmp, FS, forger, fps, committed):
    if FS is None:
        return f.not_built("g1_forger_key_under_the_auditor_principal", "K13 FAIL with the A1 and A2 lines, exit 1"), None
    d = g1_forge(tmp, FS, forger, "g1_S13")
    r, st, bl = run(d)
    ns = notes(bl)
    a1 = [l for l in ns if l == a1_line(p.AUDITOR, 2)]
    a2 = [l for l in ns if l == a2_line(fps[FORGER], fps["auditor"])]
    ok = st.get("K13") == "FAIL" and len(a1) == 1 and len(a2) == 1 and OK_LINE not in bl.get("K13", "") and r.returncode == 1
    report("g1_forger_key_under_the_auditor_principal", ok, f"K13 FAIL, exit 1, one A1 line ({p.AUDITOR} holds 2 keys), one A2 line with {fps[FORGER]} and {fps['auditor']} (ssh-keygen -lf), no '{OK_LINE}' line",
           f"K13 {st.get('K13')}, exit {r.returncode}, A1 lines {len(a1)}, A2 lines {len(a2)}, ok line present: {OK_LINE in bl.get('K13', '')}",
           [f"embedded key of {SIG} (the suite's parser): {suite_fp(sshsig_key(d / SIG))}; of audit.jsonl.sig: {suite_fp(sshsig_key(d / 'audit.jsonl.sig'))}"] + c.block_lines(bl, "K13") + committed_k13(committed, d))
    return ok, d


def g1b(tmp, d, fps):
    if d is None:
        return f.not_built("g1b_S13_without_ssh_keygen", "the same A1 and A2 lines, WARN present-not-verified for the other entries")
    bindir = tmp / "g1b_bin"
    bindir.mkdir()
    (bindir / "python3").symlink_to(sys.executable)
    r, st, bl = run_no_ssh_keygen(d, bindir)
    ns = notes(bl)
    a1 = [l for l in ns if l == a1_line(p.AUDITOR, 2)]
    a2 = [l for l in ns if l == a2_line(fps[FORGER], fps["auditor"])]
    nv = [l for l in ns if NOT_VERIFIED in l]
    ok = st.get("K13") == "FAIL" and len(a1) == 1 and len(a2) == 1 and len(nv) == 2 and "verified" not in "".join(l for l in ns if NOT_VERIFIED not in l) and r.returncode == 1
    report("g1b_S13_without_ssh_keygen", ok, f"K13 FAIL, exit 1, the same A1 and A2 lines, exactly two '{NOT_VERIFIED}' lines (audit.jsonl, the witness), no verified line",
           f"K13 {st.get('K13')}, exit {r.returncode}, A1 {len(a1)}, A2 {len(a2)}, not-verified lines {len(nv)}", [f"PATH={bindir} (python3 only)"] + c.block_lines(bl, "K13"))


def g2(tmp, FS):
    if FS is None:
        return f.not_built("g2_duplicate_auditor_line_is_one_key", "output byte-identical to FS")
    d = f.copy_of(tmp, FS, "g2_dup_line")
    dup = next(l for l in (d / "allowed_signers").read_text(encoding="utf-8").splitlines() if l.startswith(p.AUDITOR + " "))
    append_allowed(d, dup + "\n")
    r0, st0, bl0 = run(FS)
    r, st, bl = run(d)
    same = norm(r0.stdout, FS) == norm(r.stdout, d) and r0.returncode == r.returncode
    report("g2_duplicate_auditor_line_is_one_key", same and st.get("K13") == "PASS", "whole output byte-identical to FS (paths normalised), exit codes equal, K13 PASS",
           f"identical: {norm(r0.stdout, FS) == norm(r.stdout, d)}, exit FS={r0.returncode} dup={r.returncode}, K13 {st.get('K13')}", c.block_lines(bl, "K13"))


def g3(tmp, FS, forger):
    if FS is None:
        return f.not_built("g3_second_key_under_the_model_principal", "K13 FAIL with the A1 line naming the model principal, the sources ok line present")
    d = f.copy_of(tmp, FS, "g3_model_two_keys")
    append_allowed(d, allowed_line(p.MP, forger))
    r, st, bl = run(d)
    ns = notes(bl)
    a1 = [l for l in ns if l == a1_line(p.MP, 2)]
    okl = [l for l in ns if OK_LINE in l and f"by {p.AUDITOR}" in l and "verified" in l]
    ok = st.get("K13") == "FAIL" and len(a1) == 1 and len(okl) == 1 and r.returncode == 1 and not any(l.startswith(f"allowed_signers: principal '{p.AUDITOR}'") for l in ns)
    report("g3_second_key_under_the_model_principal", ok, f"K13 FAIL, exit 1, one A1 line naming {p.MP!r} (holds 2 keys), none naming the auditor, the '{OK_LINE}' ok line present",
           f"K13 {st.get('K13')}, exit {r.returncode}, A1 {len(a1)}, ok lines {len(okl)}", c.block_lines(bl, "K13"))


def g4(tmp, FS, forger):
    if FS is None:
        return f.not_built("g4_S14_key_replaced_everything_resigned_PASSES", "check.py PASS, every signature verified")
    d = f.copy_of(tmp, FS, "g4_S14")
    swap_allowed(d, p.AUDITOR, forger)
    r1 = run_sign(d, ["--role", "auditor", "--file", "audit.jsonl", "--key", str(forger), "--identity", p.AUDITOR])
    c.refresh_files(d)  # the forger republishes the folder: the manifest's `files` names audit.jsonl.sig by hash (K2), so its new hash goes in
    r2 = run_sign(d, ["--role", "sources", "--key", str(forger), "--identity", p.AUDITOR])
    r3 = None
    if any(e.get("role") == "manifest" for e in f.load_sigs(d)):
        r3 = run_sign(d, ["--role", "manifest", "--key", str(m.KEYS["adder"]), "--identity", m.ADDER])
    r, st, bl = run(d)
    ns = notes(bl)
    ver = [l for l in ns if l.endswith(", verified")]
    bad = [l for l in ns if "does NOT verify" in l or A3_MID in l or A2_TAIL in l or A1_TAIL in l]
    failed = [k for k, v in st.items() if v == "FAIL"]
    ok = r1.returncode == 0 and r2.returncode == 0 and (r3 is None or r3.returncode == 0) and r.returncode == 0 and st.get("K13") == "PASS" and len(ver) == 3 and not bad
    report("g4_S14_key_replaced_everything_resigned_PASSES", ok, "sign.py exit 0 for auditor and sources with the forger key, check.py exit 0, K13 PASS, three verified lines (audit.jsonl, the witness, sources), no A1/A2/A3 line",
           f"sign exits {r1.returncode}/{r2.returncode}" + (f"/{r3.returncode}" if r3 is not None else "") + f", check exit {r.returncode}, K13 {st.get('K13')}, verified {len(ver)}, bad lines {len(bad)}, FAIL checks {failed}",
           [f"EXPECTED PASS: {G4_NOTE}", f"audit.jsonl.sig embedded key fp {suite_fp(sshsig_key(d / 'audit.jsonl.sig'))} = forger {lf_fingerprint(pub_of(forger))}: {suite_fp(sshsig_key(d / 'audit.jsonl.sig')) == lf_fingerprint(pub_of(forger))}"]
           + [f"sign stderr: {l}" for l in (r1.stderr + r2.stderr).strip().splitlines()] + c.block_lines(bl, "K13", *failed))


def g5(tmp, FS, forger):
    if FS is None:
        f.not_built("g5a_sign_witness_with_a_second_key_refused", f"exit 1 '{REFUSE_HOLDS}', tree unchanged")
        f.not_built("g5b_sign_sources_with_the_forger_key_under_the_auditor_name_refused", f"exit 1 '{REFUSE_KEY}', tree unchanged")
        return
    d = f.copy_of(tmp, FS, "g5a_witness_second_key")
    before = c.tree_hashes(d)
    r = run_sign(d, ["--role", "witness", "--file", WF, "--identity", p.MP, "--key", str(forger)])
    after = c.tree_hashes(d)
    unchanged = before == after
    changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
    ok = r.returncode == 1 and REFUSE_HOLDS in r.stderr and unchanged
    report("g5a_sign_witness_with_a_second_key_refused", ok, f"exit 1, stderr '{REFUSE_HOLDS}', every file unchanged by hash (the committed sign.py exits 0 here)",
           f"exit {r.returncode}, phrase: {REFUSE_HOLDS in r.stderr}, unchanged: {unchanged}",
           [f"stderr: {l}" for l in r.stderr.strip().splitlines()] + [f"stdout: {l}" for l in r.stdout.strip().splitlines()] + ([] if unchanged else ["changed: " + ", ".join(changed)]))
    d = f.copy_of(tmp, FS, "g5b_sources_forger_under_auditor")
    append_allowed(d, allowed_line(p.AUDITOR, forger))
    before = c.tree_hashes(d)
    r = run_sign(d, ["--role", "sources", "--key", str(forger), "--identity", p.AUDITOR])
    unchanged = before == c.tree_hashes(d)
    ok = r.returncode == 1 and REFUSE_KEY in r.stderr and unchanged
    report("g5b_sign_sources_with_the_forger_key_under_the_auditor_name_refused", ok, f"exit 1, stderr '{REFUSE_KEY}', every file unchanged by hash (the committed sign.py exits 0 here)",
           f"exit {r.returncode}, phrase: {REFUSE_KEY in r.stderr}, unchanged: {unchanged}",
           [f"stderr: {l}" for l in r.stderr.strip().splitlines()] + [f"stdout: {l}" for l in r.stdout.strip().splitlines()])


def g6(tmp, fpre, FB, forger, committed_dir):
    ans = tmp / "g6a_answer"
    c.make_answer(FB, ans)
    append_allowed(ans, allowed_line(p.AUDITOR, forger))
    parent = f.copy_of(tmp, fpre, "g6a_parent")
    before = c.tree_hashes(parent)
    r = f.run_add_witness_with(HERE / "add_witness.py", parent, ans)
    unchanged = before == c.tree_hashes(parent)
    want = f"principal '{p.AUDITOR}' {REFUSE_TWO}: one principal, one key"
    ok = r.returncode == 1 and "refused, nothing written" in r.stderr and want in r.stderr and unchanged
    report("g6a_add_witness_fragment_puts_the_forger_under_the_auditor_refused", ok, f"exit 1, 'refused, nothing written' with \"{want}\", parent unchanged by hash",
           f"exit {r.returncode}, refused: {'refused, nothing written' in r.stderr}, phrase: {want in r.stderr}, unchanged: {unchanged}",
           [f"stderr: {l}" for l in r.stderr.strip().splitlines()] + [f"stdout: {l}" for l in r.stdout.strip().splitlines()[:3]])
    ans2 = tmp / "g6b_answer"
    c.make_answer(FB, ans2)
    append_allowed(ans2, allowed_line(p.MP, forger))
    parent2 = f.copy_of(tmp, fpre, "g6b_parent")
    before = c.tree_hashes(parent2)
    r2 = f.run_add_witness_with(HERE / "add_witness.py", parent2, ans2)
    unchanged = before == c.tree_hashes(parent2)
    want2 = f"principal '{p.MP}' {REFUSE_TWO}: one principal, one key"
    ok2 = r2.returncode == 1 and "refused, nothing written" in r2.stderr and want2 in r2.stderr and unchanged
    report("g6b_add_witness_fragment_with_two_model_keys_refused", ok2, f"exit 1, 'refused, nothing written' with \"{want2}\", parent unchanged by hash",
           f"exit {r2.returncode}, refused: {'refused, nothing written' in r2.stderr}, phrase: {want2 in r2.stderr}, unchanged: {unchanged}",
           [f"stderr: {l}" for l in r2.stderr.strip().splitlines()])
    if committed_dir is None:
        print("skipped  g6c_committed_add_witness_accepts_the_forger_line: --committed none")
        return
    parentc = f.copy_of(tmp, fpre, "g6c_parent_committed_tool")
    rc = f.run_add_witness_with(committed_dir / "add_witness.py", parentc, ans)
    held = suite_allowed(parentc / "allowed_signers").get(p.AUDITOR, [])
    okc = rc.returncode == 0 and "added 1 witness(es)" in rc.stdout and len(set(held)) == 2
    report("g6c_committed_add_witness_accepts_the_forger_line", okc, f"the committed add_witness.py: exit 0, 'added 1 witness(es)', {p.AUDITOR} then holds 2 keys (the hole, on record)",
           f"exit {rc.returncode}, added: {'added 1 witness(es)' in rc.stdout}, keys under {p.AUDITOR}: {len(set(held))}",
           [l for l in rc.stdout.splitlines() if l.startswith(("added", "SUMMARY"))] + ([f"stderr: {rc.stderr.strip()[-300:]}"] if rc.stderr.strip() else []))


def folder_of(q):
    cur = q.parent
    while cur != HERE and not (cur / "manifest.json").exists():
        cur = cur.parent
    return cur


def signer_of(folder, rel):
    for name in ("signatures.json", "service-signature.json"):
        q = folder / name
        if not q.exists():
            continue
        try:
            v = json.loads(q.read_text(encoding="utf-8"))
        except ValueError:
            continue
        for e in v if isinstance(v, list) else [v]:
            if isinstance(e, dict) and e.get("signature") == rel:
                return (e.get("signer") or {}).get("name"), (e.get("signer") or {}).get("key_id"), name
    return None, None, None


def g7(tmp):
    sigs = sorted(q for base in ("examples", "fixtures", "snapshots") for q in (HERE / base).rglob("*.sig") if q.is_file())
    for q in sigs:
        folder = folder_of(q)
        rel = str(q.relative_to(folder))
        label = f"g7_{str(q.relative_to(HERE)).replace('/', '_')}"
        key = sshsig_key(q)
        if key is None:
            report(label, False, "the suite's parser reads a key", "None")
            continue
        fp = suite_fp(key)
        name, key_id, src = signer_of(folder, rel)
        listed = suite_allowed(folder / "allowed_signers").get(name, []) if (folder / "allowed_signers").exists() and name else []
        lf = [lf_fingerprint(k) for k in listed]
        try:
            theirs, theirs_fp = check.sshsig_public_key(q), check.sshsig_fingerprint(key)
        except AttributeError as ex:
            theirs, theirs_fp = f"AttributeError: {ex}", None
        ok = fp in lf and (key_id is None or key_id == fp) and theirs == key and theirs_fp == fp
        report(label, ok, f"fingerprint = ssh-keygen -lf of {name!r}'s allowed_signers key, = key_id ({src}), check.sshsig_public_key and check.sshsig_fingerprint agree",
               f"{fp}; -lf {lf}; key_id {key_id}; check agrees: {theirs == key and theirs_fp == fp}" + ("" if theirs == key else f" (check: {str(theirs)[:60]})"))
    # the malformed shapes, on one published signature
    src = HERE / "fixtures/aw10-regate7-2026-11-13/audit.jsonl.sig"
    base = sshsig_key(src)
    lines = src.read_text(encoding="ascii").splitlines()
    end = next(i for i, l in enumerate(lines) if l.strip() == END)
    trunc = tmp / "g7_truncated.sig"
    trunc.write_text("\n".join(lines[:end - 1] + lines[end:]) + "\n", encoding="ascii")
    text = tmp / "g7_text.sig"
    text.write_text("this is not a signature\n", encoding="ascii")
    crlf = tmp / "g7_crlf.sig"
    crlf.write_bytes("\r\n".join(lines).encode("ascii") + b"\r\nsome text after the end line\r\n")

    def theirs(q):
        try:
            return check.sshsig_public_key(q)
        except AttributeError as ex:
            return f"AttributeError: {ex}"
    r_trunc, r_text, r_crlf = sshsig_key(trunc), sshsig_key(text), sshsig_key(crlf)
    t_trunc, t_text, t_crlf = theirs(trunc), theirs(text), theirs(crlf)
    report("g7_truncated_body_is_None", r_trunc is None and t_trunc is None, "the suite's parser and check.sshsig_public_key both None", f"suite {r_trunc}, check {str(t_trunc)[:60]}")
    report("g7_text_file_is_None", r_text is None and t_text is None, "both None", f"suite {r_text}, check {str(t_text)[:60]}")
    report("g7_crlf_and_text_after_END_same_key", r_crlf == base and t_crlf == base and base is not None, "both the same key as the original", f"suite same: {r_crlf == base}, check same: {t_crlf == base}")


def g8(tmp, FS, forger, fps):
    if FS is None:
        return f.not_built("g8_allowed_key_swapped_signature_files_untouched", "K13 FAIL with the A3 lines for audit.jsonl and manifest.json")
    d = f.copy_of(tmp, FS, "g8_A3")
    swap_allowed(d, p.AUDITOR, forger)
    r, st, bl = run(d)
    ns = notes(bl)
    a3a = [l for l in ns if l == a3_line("audit.jsonl", fps["auditor"], p.AUDITOR)]
    a3m = [l for l in ns if l == a3_line("manifest.json", fps["auditor"], p.AUDITOR)]
    nv = [l for l in ns if "does NOT verify" in l]
    ok = st.get("K13") == "FAIL" and len(a3a) == 1 and len(a3m) == 1 and len(nv) >= 2 and r.returncode == 1
    report("g8_allowed_key_swapped_signature_files_untouched", ok, f"K13 FAIL, exit 1, one A3 line for audit.jsonl and one for manifest.json (key {fps['auditor']}, principal {p.AUDITOR!r}), ssh-keygen's 'does NOT verify' lines (>= 2)",
           f"K13 {st.get('K13')}, exit {r.returncode}, A3 audit {len(a3a)}, A3 manifest {len(a3m)}, does-NOT-verify {len(nv)}", c.block_lines(bl, "K13"))


def g9(tmp, FS, fps):
    if FS is None:
        return f.not_built("g9_witness_resigned_with_the_auditor_key_by_embedded_key", "K13 FAIL with the A3 line and the VR-I11 line")
    d = f.copy_of(tmp, FS, "g9_A4")
    e = next(e for e in f.load_sigs(d) if e.get("role") == "witness" and e.get("file") == WF)
    (d / (WF + ".sig")).write_bytes(own_sign_line(e["line"], m.KEYS["auditor"]))  # the entry and allowed_signers untouched
    r, st, bl = run(d)
    ns = notes(bl)
    a3 = [l for l in ns if l == a3_line(WF, fps["auditor"], p.MP)]
    vr = [l for l in ns if VR_I11 in l and l.startswith(WF)]
    ok = st.get("K13") == "FAIL" and len(a3) == 1 and len(vr) == 1 and r.returncode == 1
    report("g9_witness_resigned_with_the_auditor_key_by_embedded_key", ok, f"K13 FAIL, exit 1, one A3 line for {WF} (key {fps['auditor']}, principal {p.MP!r}), one VR-I11 line for {WF}",
           f"K13 {st.get('K13')}, exit {r.returncode}, A3 {len(a3)}, VR-I11 {len(vr)}", c.block_lines(bl, "K13"))


def g10(committed):
    if committed is None:
        print("skipped  g10: --committed none, no committed checker to compare with")
        return
    folders = c.published_folders() + [q.relative_to(HERE) for q in sorted((HERE / "fixtures").glob("*")) if q.is_dir() and (q / "manifest.json").exists()]
    for rel in folders:
        (rc, _, _), (rw, _, _) = c.both(committed, HERE / rel)
        summ = next((l for l in rw.stdout.splitlines() if l.startswith("SUMMARY")), "(no SUMMARY)")
        report(f"g10_{str(rel).replace('/', '_')}", rc.stdout == rw.stdout and rc.returncode == rw.returncode and "Traceback" not in rw.stderr, "whole output byte-identical, exit codes equal, no exception",
               f"identical: {rc.stdout == rw.stdout}, exit committed={rc.returncode} cut={rw.returncode}, Traceback: {'Traceback' in rw.stderr}; {summ}")


def main():
    if not (c.SRC_F / "audit.jsonl").exists() or not (f.SRC_G / "manifest.json").exists():
        print(f"fixture sources missing: {c.SRC_F}, {f.SRC_G}", file=sys.stderr)
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
        forger = tmp / "build" / "keys" / FORGER
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "fixture-forger", "-f", str(forger)], check=True, capture_output=True)
        fps = {n: lf_fingerprint(pub_of(k)) for n, k in list(m.KEYS.items()) + [(FORGER, forger)]}
        committed = None if c.SKIP_COMMITTED else c.committed_checker(tmp)
        committed_dir = None if c.SKIP_COMMITTED else f.committed_tools(tmp)
        print(f"keys (ssh-keygen -lf): auditor {fps['auditor']}, model1 {fps['model1']}, forger {fps[FORGER]}; principals auditor {p.AUDITOR}, model {p.MP}")
        FS = f.build_signed(tmp, FB, "FS")
        _, d1 = g1(tmp, FS, forger, fps, committed)
        g1b(tmp, d1, fps)
        g2(tmp, FS)
        g3(tmp, FS, forger)
        g4(tmp, FS, forger)
        g5(tmp, FS, forger)
        g6(tmp, fpre, FB, forger, committed_dir)
        g7(tmp)
        g8(tmp, FS, forger, fps)
        g9(tmp, FS, fps)
        g10(committed)
        mism = sum(1 for r in c.RESULTS if not r)
        print(f"{sum(c.RESULTS)} of {len(c.RESULTS)} cases gave the expected result; MISMATCH {mism}")
        return 0 if all(c.RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
