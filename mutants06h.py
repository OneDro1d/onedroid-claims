#!/usr/bin/env python3
"""mutants06h.py: the test suite of the one-auditor cut of 13 Nov 2026 (NEXT-REVISION 32, with 30(a) adopted; the format owner's design
after the tenth re-gate of the witness service PASSED the service and did NOT PASS the format's auditor-key cut on one unsealed case, K16).
The auditor-key cut's A2 compared the key inside manifest.sources.sig with the key inside the signature file of ANY `auditor` entry, so a
forger added a SECOND `auditor` entry over the genuine audit.jsonl (its own principal, its own key, its own file audit.jsonl.forger.sig,
a genuine signature by its own key over the prescribed auditor line) and signed `--role sources` with that key over a re-aimed manifest:
every rule held (A1 one key per principal; A3 each signature's key is its principal's; the genuine auditor signature still verified) and
check.py 7a20c25a printed "manifest.json: sources bound by forger-ten, verified". The promise was "the key that signed audit.jsonl";
audit.jsonl has one signature file, audit.jsonl.sig, and the rule must read that one and no other.

The rules under test (check.py, K13):
  O1  one entry per fixed role: more than one `auditor`, `sources` or `manifest` entry FAILs
      "signatures.json: <n> <role> entries (<name1>, <name2>): one <role> signature in a record; <why>" (names in entry order; the entries
      are still verified below, the FAIL stands beside them).
  O2  the signature file is the prescribed one: manifest.sources.sig for `sources`, <file>.sig for every other role; another name FAILs
      "signatures[<i>]: signature file '<x>' is not the prescribed '<y>'" and that entry is not verified.
  O3  A2 reads audit.jsonl.sig alone: the sources key is compared with the key embedded in the auditor entry whose signature file is
      audit.jsonl.sig (the A2 FAIL text unchanged, one fingerprint after "audit.jsonl with"); none readable: the existing
      "a sources signature with no readable auditor signature to match".
  O4  the manifest names the auditor who signed: grading.auditor.signer is exactly "<principal> <SHA256:fp>" of audit.jsonl.sig's key, else
      FAIL "manifest.json: grading.auditor.signer is <repr or missing> and audit.jsonl.sig was made by '<name>' SHA256:<fp>: the manifest
      names another auditor than the one who signed".
check.py, K11 (30a): a model witness header with `carried` and no `bound` whose service version (header `service_version`, else the manifest
  witness entry's, else service.json's when the manifest lists it) parses as >= 0.1.8 FAILs "witness '<name>': a model witness of service
  version <v> records `carried` but no `bound`: 0.1.8 and later of the witness service write it; this header was not written by that
  service"; a version that does not parse WARNs "service_version '<v>' is not a version (major.minor.patch)" beside the existing WARN; no
  version anywhere: the existing WARN alone.
sign.py: --role auditor refuses a folder whose auditor entry is under another name ("one auditor: audit.jsonl is already signed by
  '<name>'; remove that entry first to re-sign under another name"); --role sources reads the key inside audit.jsonl.sig alone and refuses
  an auditor entry whose signature file is another name ("the auditor's signature file is audit.jsonl.sig, not '<x>'").
add_witness.py: refuses, before writing, a parent with more than one auditor, sources or manifest entry ("the snapshot's signatures.json
  holds <n> <role> entries: one <role> signature in a record") or an auditor entry whose file is not audit.jsonl.sig ("the snapshot's
  auditor signature file is '<x>', not audit.jsonl.sig").

Fixtures, built in a temporary folder with throwaway keys (mutants06.KEYS) plus one fresh forger key (ssh-keygen -t ed25519 -N ''):
  Fpre, F, FB, FS, FpreS  as mutants06c, mutants06d and mutants06f build them (FS = FB + the auditor's sources signature).
Every expected fingerprint comes from `ssh-keygen -lf`, never from check.sshsig_fingerprint. The fixture builders (mutants06p.to_pre,
mutants06.build) used to re-sign the audit part over the published auditor entry under a new name, and to_pre wrote the bare name into
grading.auditor.signer; the owner changed them with this cut (the published auditor entry is dropped before the throwaway one is made,
the signer string stays as sign.py writes it), so h4, h4b and h6a hold (the implementer had left O4 and the --role auditor refusal
out and reported it; the owner put them in, 13 Nov 2026 09:2xZ).

Cases (`--committed PATH | none` the committed check.py; `--committed-add-witness PATH` the committed add_witness.py;
`--committed-sign PATH` the committed sign.py; the defaults are git HEAD of the notepad):
  h1   the K16 shape on FS (a second auditor entry by the forger, audit.jsonl.forger.sig, the forger's line in allowed_signers, the sources
       signature re-made by the forger over the correct bound digest, the sources entry's signer the forger): K13 FAIL with the O1 auditor
       line (2 entries, both names), the O2 line for audit.jsonl.forger.sig and the A2 line (forger fp, auditor fp); no "sources bound by"
       line, no verified line for the forger's entry; exit 1. The committed checker's K13 block is printed (PASS: the RED).
  h1b  the same with ssh-keygen off PATH: the same three FAIL lines, exit 1.
  h2   FS with the auditor entry's signature file renamed to audit.jsonl.auditor.sig (file moved, entry updated): the O2 line naming both
       names and A2's "no readable auditor signature" line for the sources entry; exit 1. Committed: printed (PASS).
  h3   FS with the sources entry duplicated verbatim: the O1 sources line; FS manifest-signed by the adder and the manifest entry
       duplicated: the O1 manifest line. Committed: printed.
  h4   FS with grading.auditor.signer rewritten to the forger's "name <fp>" and the manifest re-signed by the adder: the O4 line with both
       names, the sources ok line still present; h4b: the signer field deleted: the O4 line with "missing". Committed: printed.
  h5   30a on F (carried, no bound): header service_version "0.1.8-dev" FAIL and no carried-no-bound WARN for that witness (committed:
       WARN only, printed); "0.1.10" FAIL; "0.1.7" the WARN alone; "dev" the two WARNs, no FAIL; the manifest entry's "0.1.9" alone FAIL;
       service.json {"service": "x", "service_version": "0.1.8"} listed in files alone FAIL; none anywhere: byte-identical to the committed.
  h6   sign.py on FS: --role auditor with the forger key and identity: exit 1 "one auditor", tree unchanged by hash (the committed sign.py:
       exit 0 and the tree changed, printed as the RED); --role sources with the auditor key after the auditor entry's signature name was
       changed: exit 1 "is audit.jsonl.sig, not", unchanged.
  h7   add_witness.py: FB's genuine answer into a copy of Fpre carrying the h1 second auditor entry: exit 1, "holds 2 auditor entries",
       parent unchanged by hash; into a copy of Fpre whose auditor signature file is renamed: exit 1, "not audit.jsonl.sig", unchanged; the
       committed add_witness.py on the first parent: the parent CHANGED (printed with its exit: the RED).
  h8   the genuine FS, and FpreS after one genuine insertion: no O line, the sources ok line present, exit 0.
  h9   every folder under snapshots/, examples/ and fixtures/: committed vs cut byte-identical, exit codes equal.

usage: python3 -I mutants06h.py [--committed PATH | --committed none] [--committed-add-witness PATH] [--committed-sign PATH]
Exit 0 only when every expectation holds; one line per case "ok/MISMATCH <case>: expected ... observed ...", the K13 and K11 blocks printed
under the cases that touch them."""
import json, os, pathlib, shutil, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402,F401
import mutants06 as m  # noqa: E402
import mutants06p as p  # noqa: E402
import mutants06c as c  # noqa: E402
import mutants06d as dd  # noqa: E402
import mutants06f as f  # noqa: E402

ARGS = sys.argv[1:]
_CS = ARGS[ARGS.index("--committed-sign") + 1] if "--committed-sign" in ARGS else None
COMMITTED_SIGN = pathlib.Path(_CS).resolve() if _CS else None
SIG = f.SIG
NAMESPACE = f.NAMESPACE
WF = c.WF
AUD_SIG = "audit.jsonl.sig"
FORGER_SIG = "audit.jsonl.forger.sig"
RENAMED_SIG = "audit.jsonl.auditor.sig"
OK_LINE = "sources bound by"
FORGER = "forger"
A2_TAIL = "the sources list is bound to the key that signed the audit, not to a name in allowed_signers"
A2_NONE = "manifest.json: a sources signature with no readable auditor signature to match"
O1_WHY = {"auditor": "a second entry over audit.jsonl is a second auditor, not a co-signer",
          "sources": "the auditor signs the sources list once",
          "manifest": "the manifest is signed once, by whoever last changed the folder"}
O1_MID = "signature in a record"
O2_MID = "is not the prescribed"
O4_TAIL = "the manifest names another auditor than the one who signed"
O5_TAIL = "0.1.8 and later of the witness service write it; this header was not written by that service"
BOUND_WARN = "a model witness records `carried` but no `bound`"
NOT_VERSION = "is not a version (major.minor.patch)"
NOT_VERIFIED = "present, not verified here (ssh-keygen not on PATH)"
SIGN_ONE = "one auditor: audit.jsonl is already signed by"
SIGN_FILE = "the auditor's signature file is audit.jsonl.sig, not"
AW_HOLDS = "the snapshot's signatures.json holds 2 auditor entries: one auditor signature in a record"
AW_FILE = f"the snapshot's auditor signature file is '{RENAMED_SIG}', not audit.jsonl.sig"
REFUSED = "refused, nothing written"


# ---- helpers ----

def pub_of(key):
    return pathlib.Path(str(key) + ".pub")


def pub_key(key):
    w = pub_of(key).read_text(encoding="utf-8").split()
    return w[0] + " " + w[1]


def lf_fingerprint(pubfile):
    """`ssh-keygen -lf` on a public key file: the fingerprint as the tool prints it."""
    return subprocess.run(["ssh-keygen", "-lf", str(pubfile)], capture_output=True, text=True, check=True).stdout.split()[1]


def allowed_line(ident, key):
    return f'{ident} namespaces="{NAMESPACE}" {pub_key(key)}\n'


def append_allowed(d, line):
    q = d / "allowed_signers"
    q.write_text(q.read_text(encoding="utf-8") + line, encoding="utf-8")


def own_sign_line(line, key):
    """ssh-keygen -Y sign over one line with a private key: the signature bytes."""
    with tempfile.TemporaryDirectory() as td:
        msg = pathlib.Path(td) / "line"
        msg.write_text(line, encoding="utf-8")
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", NAMESPACE, str(msg)], check=True, capture_output=True)
        return (pathlib.Path(td) / "line.sig").read_bytes()


def run_sign(d, args, tool_dir=HERE):
    return subprocess.run([sys.executable, "-I", str(tool_dir / "sign.py"), str(d), *args], capture_output=True, text=True)


def run(d):
    return c.run_check(HERE / "check.py", d)


def run_no_ssh_keygen(d, bindir):
    env = dict(os.environ)
    env["PATH"] = str(bindir)
    r = subprocess.run([sys.executable, "-I", str(HERE / "check.py"), str(d)], capture_output=True, text=True, env=env)
    st, bl = m.statuses(r.stdout)
    return r, st, bl


def notes(bl, k="K13"):
    return [l.strip() for l in bl.get(k, "").splitlines() if l.startswith(" ")]


def report(name, ok, expected, observed, details=()):
    return c.report(name, ok, expected, observed, details)


def committed_block(committed, d, k="K13"):
    if committed is None:
        return []
    rc, _, blc = c.run_check(committed, d)
    return [f"committed checker (exit {rc.returncode}): " + l.strip() for l in blc.get(k, "").splitlines()]


def committed_sign_dir(tmp):
    """A folder holding the committed check.py beside the committed sign.py (sign.py imports check from its own folder)."""
    out = tmp / "committed_sign"
    out.mkdir(exist_ok=True)
    shutil.copyfile(c.committed_checker(tmp), out / "check.py")
    if COMMITTED_SIGN is not None:
        shutil.copyfile(COMMITTED_SIGN, out / "sign.py")
    else:
        r = subprocess.run(["git", "-C", str(HERE), "show", "HEAD:claims-standard/sign.py"], capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError("git show HEAD:claims-standard/sign.py: " + r.stderr)
        (out / "sign.py").write_text(r.stdout, encoding="utf-8")
    return out


def o1_line(role, names):
    return f"signatures.json: {len(names)} {role} entries ({', '.join(names)}): one {role} signature in a record; {O1_WHY[role]}"


def o2_line(i, x, y):
    return f"signatures[{i}]: signature file '{x}' is not the prescribed '{y}'"


def a2_line(fp_sources, fp_audit):
    return f"manifest.json: the sources signature was made with key {fp_sources} and audit.jsonl with {fp_audit}: {A2_TAIL}"


def o4_line(signer, name, fp):
    return f"manifest.json: grading.auditor.signer is {signer} and audit.jsonl.sig was made by '{name}' {fp}: {O4_TAIL}"


def o5_line(name, v):
    return f"witness {name!r}: a model witness of service version {v} records `carried` but no `bound`: {O5_TAIL}"


def nv_line(name, v):
    return f"witness {name!r}: service_version '{v}' {NOT_VERSION}"


def o_lines(ns):
    """Every K13 line one of the cut's rules produced (O1, O2, O4)."""
    return [l for l in ns if (l.startswith("signatures.json:") and O1_MID in l) or (l.startswith("signatures[") and O2_MID in l) or O4_TAIL in l]


def auditor_index(d):
    return next(i for i, e in enumerate(f.load_sigs(d)) if e.get("role") == "auditor")


# ---- the mutations ----

def add_forger_auditor(d, forger, fp_forger):
    """The K16 shape's second auditor entry: the forger's line in allowed_signers, audit.jsonl.forger.sig made by the suite's own
    ssh-keygen -Y sign with the forger key over the prescribed auditor line (written here, not read from check.signed_line), the entry
    appended. Returns the new entry's index."""
    append_allowed(d, allowed_line(FORGER, forger))
    h = m.sha(d / "audit.jsonl")
    line = f"claims-snapshot/0.4 auditor audit.jsonl sha256:{h}"
    (d / FORGER_SIG).write_bytes(own_sign_line(line, forger))
    sigs = f.load_sigs(d)
    sigs.append({"role": "auditor", "file": "audit.jsonl", "sha256": h, "line": line,
                 "signer": {"name": FORGER, "key_id": fp_forger, "kind": "ssh-ed25519"},
                 "signed_at": "2026-11-13T08:40:00Z", "signature": FORGER_SIG, "commit": None})
    f.save_sigs(d, sigs)
    return len(sigs) - 1


def forge_sources(d, forger, fp_forger):
    """manifest.sources.sig re-made by the forger over the correct bound digest (the suite's own digest), the sources entry's signer the forger."""
    digest = f.suite_digest(m.mload(d))
    line = f.sources_line(digest)
    (d / SIG).write_bytes(own_sign_line(line, forger))
    sigs = f.load_sigs(d)
    for _, e in f.sources_entries(sigs):
        e["signer"] = {"name": FORGER, "key_id": fp_forger, "kind": "ssh-ed25519"}
        e["sha256"], e["line"] = digest, line
    f.save_sigs(d, sigs)


def k16(tmp, src, forger, fp_forger, name):
    d = f.copy_of(tmp, src, name)
    idx = add_forger_auditor(d, forger, fp_forger)
    forge_sources(d, forger, fp_forger)
    return d, idx


def rename_auditor_sig(d, new=RENAMED_SIG, move=True):
    """The auditor entry's signature file under another name: the entry updated, the file moved when `move` (the manifest's `files`
    refreshed, since the agent-work shape names audit.jsonl.sig by hash)."""
    if move:
        shutil.move(d / AUD_SIG, d / new)
    sigs = f.load_sigs(d)
    for e in sigs:
        if e.get("role") == "auditor":
            e["signature"] = new
    f.save_sigs(d, sigs)
    if move:
        c.refresh_files(d)


def dup_role(d, role):
    sigs = f.load_sigs(d)
    e = next(e for e in sigs if e.get("role") == role)
    sigs.append(json.loads(json.dumps(e)))
    f.save_sigs(d, sigs)


def set_signer(d, value):
    """grading.auditor.signer set (value None: the field deleted); the manifest re-signed by the adder so the manifest signature verifies."""
    M = m.mload(d)
    if value is None:
        M["grading"]["auditor"].pop("signer", None)
    else:
        M["grading"]["auditor"]["signer"] = value
    m.msave(d, M)
    return run_sign(d, ["--role", "manifest", "--key", str(m.KEYS["adder"]), "--identity", m.ADDER])


def set_version(d, header_v=c.ABSENT, entry_v=None, service_v=None):
    """F with a service version where the case puts it: the witness header (re-signed with the model key), the manifest witness entry,
    or service.json listed in the manifest's files."""
    if header_v is not c.ABSENT:
        c.set_header(d, lambda h, d_: {**h, "service_version": header_v})
    M = m.mload(d)
    if entry_v is not None:
        for w in M["grading"]["witnesses"]:
            if w.get("file") == WF:
                w["service_version"] = entry_v
    if service_v is not None:
        (d / "service.json").write_text(json.dumps({"service": "x", "service_version": service_v}, indent=1) + "\n", encoding="utf-8")
        h = m.sha(d / "service.json")
        if isinstance(M.get("files"), dict):
            M["files"]["service.json"] = h
        elif isinstance(M.get("files"), list):
            M["files"].append({"file": "service.json", "sha256": h})
        else:
            M["files"] = [{"file": "service.json", "sha256": h}]
    m.msave(d, M)


# ---- the cases ----

def h1(tmp, FS, forger, fps, committed):
    if FS is None:
        f.not_built("h1_K16_second_auditor_entry", "K13 FAIL with the O1, O2 and A2 lines, exit 1")
        return None
    d, idx = k16(tmp, FS, forger, fps[FORGER], "h1_K16")
    r, st, bl = run(d)
    ns = notes(bl)
    o1 = [l for l in ns if l == o1_line("auditor", [p.AUDITOR, FORGER])]
    o2 = [l for l in ns if l == o2_line(idx, FORGER_SIG, AUD_SIG)]
    a2 = [l for l in ns if l == a2_line(fps[FORGER], fps["auditor"])]
    forger_ok = [l for l in ns if l == f"audit.jsonl: signed by {FORGER}, verified"]
    ok = st.get("K13") == "FAIL" and len(o1) == 1 and len(o2) == 1 and len(a2) == 1 and OK_LINE not in bl.get("K13", "") and not forger_ok and r.returncode == 1
    report("h1_K16_second_auditor_entry", ok, f"K13 FAIL, exit 1, one O1 auditor line ({p.AUDITOR}, {FORGER}), one O2 line for signatures[{idx}] {FORGER_SIG}, one A2 line with {fps[FORGER]} and {fps['auditor']} (ssh-keygen -lf), no '{OK_LINE}' line, no verified line for the forger's entry",
           f"K13 {st.get('K13')}, exit {r.returncode}, O1 {len(o1)}, O2 {len(o2)}, A2 {len(a2)}, ok line present: {OK_LINE in bl.get('K13', '')}, forger verified lines: {len(forger_ok)}",
           c.block_lines(bl, "K13") + committed_block(committed, d))
    return d, idx


def h1b(tmp, built, fps):
    if built is None:
        return f.not_built("h1b_K16_without_ssh_keygen", "the same O1, O2 and A2 lines, exit 1")
    d, idx = built
    bindir = tmp / "h1b_bin"
    bindir.mkdir()
    (bindir / "python3").symlink_to(sys.executable)
    r, st, bl = run_no_ssh_keygen(d, bindir)
    ns = notes(bl)
    o1 = [l for l in ns if l == o1_line("auditor", [p.AUDITOR, FORGER])]
    o2 = [l for l in ns if l == o2_line(idx, FORGER_SIG, AUD_SIG)]
    a2 = [l for l in ns if l == a2_line(fps[FORGER], fps["auditor"])]
    nv = [l for l in ns if NOT_VERIFIED in l]
    ok = st.get("K13") == "FAIL" and len(o1) == 1 and len(o2) == 1 and len(a2) == 1 and "verified" not in "".join(l for l in ns if NOT_VERIFIED not in l) and r.returncode == 1
    report("h1b_K16_without_ssh_keygen", ok, "K13 FAIL, exit 1, the same O1, O2 and A2 lines, no verified line",
           f"K13 {st.get('K13')}, exit {r.returncode}, O1 {len(o1)}, O2 {len(o2)}, A2 {len(a2)}, not-verified lines {len(nv)}", [f"PATH={bindir} (python3 only)"] + c.block_lines(bl, "K13"))


def h2(tmp, FS, committed):
    if FS is None:
        return f.not_built("h2_auditor_signature_file_renamed", "the O2 line and the A2 no-readable line, exit 1")
    d = f.copy_of(tmp, FS, "h2_renamed_sig")
    idx = auditor_index(d)
    rename_auditor_sig(d, RENAMED_SIG, move=True)
    r, st, bl = run(d)
    ns = notes(bl)
    o2 = [l for l in ns if l == o2_line(idx, RENAMED_SIG, AUD_SIG)]
    a2n = [l for l in ns if l == A2_NONE]
    ok = st.get("K13") == "FAIL" and len(o2) == 1 and len(a2n) == 1 and OK_LINE not in bl.get("K13", "") and r.returncode == 1
    report("h2_auditor_signature_file_renamed", ok, f"K13 FAIL, exit 1, one O2 line for signatures[{idx}] ({RENAMED_SIG} vs {AUD_SIG}), one '{A2_NONE}' line, no '{OK_LINE}' line",
           f"K13 {st.get('K13')}, exit {r.returncode}, O2 {len(o2)}, A2-none {len(a2n)}, ok line present: {OK_LINE in bl.get('K13', '')}",
           c.block_lines(bl, "K13") + committed_block(committed, d))


def h3(tmp, FS, committed):
    if FS is None:
        f.not_built("h3a_sources_entry_duplicated", "the O1 sources line, exit 1")
        f.not_built("h3b_manifest_entry_duplicated", "the O1 manifest line, exit 1")
        return
    d = f.copy_of(tmp, FS, "h3a_dup_sources")
    dup_role(d, "sources")
    r, st, bl = run(d)
    ns = notes(bl)
    o1 = [l for l in ns if l == o1_line("sources", [p.AUDITOR, p.AUDITOR])]
    ok = st.get("K13") == "FAIL" and len(o1) == 1 and r.returncode == 1
    report("h3a_sources_entry_duplicated", ok, f"K13 FAIL, exit 1, one O1 sources line ({p.AUDITOR}, {p.AUDITOR})",
           f"K13 {st.get('K13')}, exit {r.returncode}, O1 {len(o1)}", c.block_lines(bl, "K13") + committed_block(committed, d))
    d = f.copy_of(tmp, FS, "h3b_dup_manifest")
    rs = run_sign(d, ["--role", "manifest", "--key", str(m.KEYS["adder"]), "--identity", m.ADDER])
    dup_role(d, "manifest")
    r, st, bl = run(d)
    ns = notes(bl)
    o1 = [l for l in ns if l == o1_line("manifest", [m.ADDER, m.ADDER])]
    ok = rs.returncode == 0 and st.get("K13") == "FAIL" and len(o1) == 1 and r.returncode == 1
    report("h3b_manifest_entry_duplicated", ok, f"sign.py --role manifest exit 0, then K13 FAIL, exit 1, one O1 manifest line ({m.ADDER}, {m.ADDER})",
           f"sign exit {rs.returncode}, K13 {st.get('K13')}, exit {r.returncode}, O1 {len(o1)}", c.block_lines(bl, "K13") + committed_block(committed, d))


def h4(tmp, FS, fps, committed):
    if FS is None:
        f.not_built("h4_signer_names_the_forger", "the O4 line with both names, the sources ok line, exit 1")
        f.not_built("h4b_signer_missing", "the O4 line with 'missing', exit 1")
        return
    d = f.copy_of(tmp, FS, "h4_signer_forger")
    forged = f"{FORGER} <{fps[FORGER]}>"
    rs = set_signer(d, forged)
    r, st, bl = run(d)
    ns = notes(bl)
    o4 = [l for l in ns if l == o4_line(repr(forged), p.AUDITOR, fps["auditor"])]
    okl = [l for l in ns if OK_LINE in l and f"by {p.AUDITOR}" in l and "verified" in l]
    ok = rs.returncode == 0 and st.get("K13") == "FAIL" and len(o4) == 1 and len(okl) == 1 and r.returncode == 1
    report("h4_signer_names_the_forger", ok, f"manifest re-signed (exit 0), K13 FAIL, exit 1, one O4 line ({forged!r} vs '{p.AUDITOR}' {fps['auditor']}), the '{OK_LINE}' ok line present",
           f"sign exit {rs.returncode}, K13 {st.get('K13')}, exit {r.returncode}, O4 {len(o4)}, ok lines {len(okl)}", c.block_lines(bl, "K13") + committed_block(committed, d))
    d = f.copy_of(tmp, FS, "h4b_signer_missing")
    rs = set_signer(d, None)
    r, st, bl = run(d)
    ns = notes(bl)
    o4 = [l for l in ns if l == o4_line("missing", p.AUDITOR, fps["auditor"])]
    ok = rs.returncode == 0 and st.get("K13") == "FAIL" and len(o4) == 1 and r.returncode == 1
    report("h4b_signer_missing", ok, f"manifest re-signed (exit 0), K13 FAIL, exit 1, one O4 line ('missing' vs '{p.AUDITOR}' {fps['auditor']})",
           f"sign exit {rs.returncode}, K13 {st.get('K13')}, exit {r.returncode}, O4 {len(o4)}", c.block_lines(bl, "K13") + committed_block(committed, d))


def h5(tmp, F, committed):
    def case(name, label, expect_fail, expect_nv, expect_warn, **kw):
        d = f.copy_of(tmp, F, name)
        set_version(d, **kw)
        r, st, bl = run(d)
        ns = notes(bl, "K11")
        v = kw["header_v"] if "header_v" in kw else (kw.get("entry_v") or kw.get("service_v"))
        fail = [l for l in ns if l == o5_line(p.MW, v)]
        nv = [l for l in ns if l == nv_line(p.MW, v)]
        warn = [l for l in ns if BOUND_WARN in l and l.startswith(f"witness {p.MW!r}")]
        ok = (len(fail) == (1 if expect_fail else 0) and len(nv) == (1 if expect_nv else 0) and len(warn) == (1 if expect_warn else 0)
              and st.get("K11") == ("FAIL" if expect_fail else "WARN") and r.returncode == (1 if expect_fail else 0))
        report(name, ok, f"{label}: K11 {'FAIL' if expect_fail else 'WARN'}, O5 line {'present' if expect_fail else 'absent'}, not-a-version line {'present' if expect_nv else 'absent'}, carried-no-bound WARN {'present' if expect_warn else 'absent'}, exit {1 if expect_fail else 0}",
               f"K11 {st.get('K11')}, exit {r.returncode}, O5 {len(fail)}, not-a-version {len(nv)}, carried-no-bound {len(warn)}", c.block_lines(bl, "K11") + (committed_block(committed, d, "K11") if name.startswith("h5a") else []))
    case("h5a_header_0_1_8_dev", "header service_version '0.1.8-dev'", True, False, False, header_v="0.1.8-dev")
    case("h5b_header_0_1_10", "header service_version '0.1.10'", True, False, False, header_v="0.1.10")
    case("h5c_header_0_1_7", "header service_version '0.1.7'", False, False, True, header_v="0.1.7")
    case("h5d_header_dev", "header service_version 'dev'", False, True, True, header_v="dev")
    case("h5e_manifest_entry_0_1_9", "no header version, the manifest witness entry's service_version '0.1.9'", True, False, False, entry_v="0.1.9")
    case("h5f_service_json_0_1_8", "neither, service.json {service: x, service_version: 0.1.8} listed in files", True, False, False, service_v="0.1.8")
    d = f.copy_of(tmp, F, "h5g_no_version_anywhere")
    r, st, bl = run(d)
    warn = [l for l in notes(bl, "K11") if BOUND_WARN in l]
    if committed is None:
        report("h5g_no_version_anywhere", st.get("K11") == "WARN" and len(warn) == 1 and r.returncode == 0, "K11 WARN with the carried-no-bound WARN alone (committed comparison skipped: --committed none)",
               f"K11 {st.get('K11')}, exit {r.returncode}, carried-no-bound {len(warn)}", c.block_lines(bl, "K11"))
    else:
        rc, _, _ = c.run_check(committed, d)
        report("h5g_no_version_anywhere", rc.stdout == r.stdout and rc.returncode == r.returncode == 0 and len(warn) == 1, "whole output byte-identical to the committed checker's, both exit 0, the carried-no-bound WARN alone",
               f"identical: {rc.stdout == r.stdout}, exit committed={rc.returncode} cut={r.returncode}, carried-no-bound {len(warn)}", c.block_lines(bl, "K11"))


def h6(tmp, FS, forger, committed_sign):
    if FS is None:
        f.not_built("h6a_sign_auditor_under_another_name_refused", f"exit 1 '{SIGN_ONE}', tree unchanged")
        f.not_built("h6b_sign_sources_with_a_renamed_auditor_signature_refused", f"exit 1 '{SIGN_FILE}', tree unchanged")
        return
    d = f.copy_of(tmp, FS, "h6a_sign_auditor_forger")
    before = c.tree_hashes(d)
    args = ["--role", "auditor", "--file", "audit.jsonl", "--key", str(forger), "--identity", FORGER]
    r = run_sign(d, args)
    after = c.tree_hashes(d)
    unchanged = before == after
    changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
    ok = r.returncode == 1 and SIGN_ONE in r.stderr and f"'{p.AUDITOR}'" in r.stderr and unchanged
    report("h6a_sign_auditor_under_another_name_refused", ok, f"exit 1, stderr '{SIGN_ONE} '{p.AUDITOR}''', every file unchanged by hash",
           f"exit {r.returncode}, phrase: {SIGN_ONE in r.stderr}, unchanged: {unchanged}",
           [f"stderr: {l}" for l in r.stderr.strip().splitlines()] + [f"stdout: {l}" for l in r.stdout.strip().splitlines()] + ([] if unchanged else ["changed: " + ", ".join(changed)]))
    if committed_sign is not None:
        dc = f.copy_of(tmp, FS, "h6a_committed_sign")
        before = c.tree_hashes(dc)
        rc = run_sign(dc, args, committed_sign)
        after = c.tree_hashes(dc)
        changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
        report("h6a_committed_sign_py_accepts_a_second_auditor_name", rc.returncode == 0 and before != after, "the committed sign.py: exit 0 and the tree changed (the hole, on record)",
               f"exit {rc.returncode}, changed: {changed}", [f"stdout: {l}" for l in rc.stdout.strip().splitlines()] + [f"stderr: {l}" for l in rc.stderr.strip().splitlines()])
    d = f.copy_of(tmp, FS, "h6b_sign_sources_renamed_entry")
    rename_auditor_sig(d, RENAMED_SIG, move=False)
    before = c.tree_hashes(d)
    r = run_sign(d, ["--role", "sources", "--key", str(m.KEYS["auditor"]), "--identity", p.AUDITOR])
    unchanged = before == c.tree_hashes(d)
    ok = r.returncode == 1 and SIGN_FILE in r.stderr and f"'{RENAMED_SIG}'" in r.stderr and unchanged
    report("h6b_sign_sources_with_a_renamed_auditor_signature_refused", ok, f"exit 1, stderr '{SIGN_FILE} '{RENAMED_SIG}''', every file unchanged by hash",
           f"exit {r.returncode}, phrase: {SIGN_FILE in r.stderr}, unchanged: {unchanged}",
           [f"stderr: {l}" for l in r.stderr.strip().splitlines()] + [f"stdout: {l}" for l in r.stdout.strip().splitlines()])


def h7(tmp, fpre, FB, forger, fps, committed_dir):
    ans = tmp / "h7_answer"
    c.make_answer(FB, ans)
    parent = f.copy_of(tmp, fpre, "h7a_parent_two_auditors")
    add_forger_auditor(parent, forger, fps[FORGER])
    before = c.tree_hashes(parent)
    r = f.run_add_witness_with(HERE / "add_witness.py", parent, ans)
    unchanged = before == c.tree_hashes(parent)
    ok = r.returncode == 1 and REFUSED in r.stderr and AW_HOLDS in r.stderr and unchanged
    report("h7a_add_witness_parent_with_two_auditor_entries_refused", ok, f"exit 1, '{REFUSED}' with \"{AW_HOLDS}\", parent unchanged by hash",
           f"exit {r.returncode}, refused: {REFUSED in r.stderr}, phrase: {AW_HOLDS in r.stderr}, unchanged: {unchanged}",
           [f"stderr: {l}" for l in r.stderr.strip().splitlines()] + [f"stdout: {l}" for l in r.stdout.strip().splitlines()[:3]])
    parent2 = f.copy_of(tmp, fpre, "h7b_parent_renamed_sig")
    rename_auditor_sig(parent2, RENAMED_SIG, move=True)
    before = c.tree_hashes(parent2)
    r2 = f.run_add_witness_with(HERE / "add_witness.py", parent2, ans)
    unchanged = before == c.tree_hashes(parent2)
    ok2 = r2.returncode == 1 and REFUSED in r2.stderr and AW_FILE in r2.stderr and unchanged
    report("h7b_add_witness_parent_with_a_renamed_auditor_signature_refused", ok2, f"exit 1, '{REFUSED}' with \"{AW_FILE}\", parent unchanged by hash",
           f"exit {r2.returncode}, refused: {REFUSED in r2.stderr}, phrase: {AW_FILE in r2.stderr}, unchanged: {unchanged}",
           [f"stderr: {l}" for l in r2.stderr.strip().splitlines()])
    if committed_dir is None:
        print("skipped  h7c_committed_add_witness_inserts_beside_two_auditors: --committed none")
        return
    parentc = f.copy_of(tmp, fpre, "h7c_parent_committed_tool")
    add_forger_auditor(parentc, forger, fps[FORGER])
    before = c.tree_hashes(parentc)
    rc = f.run_add_witness_with(committed_dir / "add_witness.py", parentc, ans)
    after = c.tree_hashes(parentc)
    changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
    report("h7c_committed_add_witness_inserts_beside_two_auditors", before != after, "the committed add_witness.py: the parent CHANGED (the hole, on record; its exit is printed)",
           f"exit {rc.returncode}, changed: {len(changed)} file(s): {', '.join(changed[:6])}",
           [l for l in rc.stdout.splitlines() if l.startswith(("added", "SUMMARY"))] + ([f"stderr: {rc.stderr.strip()[-300:]}"] if rc.stderr.strip() else []))


def h8(tmp, FS, FpreS, FB):
    if FS is None or FpreS is None:
        f.not_built("h8a_genuine_FS_no_O_line", "no O line, the sources ok line, exit 0")
        f.not_built("h8b_FpreS_after_one_genuine_insertion_no_O_line", "add_witness exit 0, then no O line, the sources ok line, exit 0")
        return
    d = f.copy_of(tmp, FS, "h8a_FS")
    r, st, bl = run(d)
    ns = notes(bl)
    o = o_lines(ns)
    okl = [l for l in ns if OK_LINE in l and f"by {p.AUDITOR}" in l and "verified" in l]
    report("h8a_genuine_FS_no_O_line", not o and len(okl) == 1 and r.returncode == 0, f"no O1/O2/O4 line, one '{OK_LINE} {p.AUDITOR}, verified' line, exit 0",
           f"O lines {len(o)}, ok lines {len(okl)}, exit {r.returncode}, K13 {st.get('K13')}", c.block_lines(bl, "K13"))
    ans = tmp / "h8_answer"
    c.make_answer(FB, ans)
    parent = f.copy_of(tmp, FpreS, "h8b_parent")
    ra = f.run_add_witness_with(HERE / "add_witness.py", parent, ans)
    r, st, bl = run(parent)
    ns = notes(bl)
    o = o_lines(ns)
    okl = [l for l in ns if OK_LINE in l and f"by {p.AUDITOR}" in l and "verified" in l]
    report("h8b_FpreS_after_one_genuine_insertion_no_O_line", ra.returncode == 0 and "added 1 witness(es)" in ra.stdout and not o and len(okl) == 1 and r.returncode == 0,
           f"add_witness exit 0 'added 1 witness(es)', then no O1/O2/O4 line, one '{OK_LINE} {p.AUDITOR}, verified' line, exit 0",
           f"add_witness exit {ra.returncode}, O lines {len(o)}, ok lines {len(okl)}, check exit {r.returncode}, K13 {st.get('K13')}",
           [l for l in ra.stdout.splitlines() if l.startswith(("added", "SUMMARY"))] + ([f"stderr: {ra.stderr.strip()[-300:]}"] if ra.stderr.strip() else []) + c.block_lines(bl, "K13"))


def h9(committed):
    if committed is None:
        print("skipped  h9: --committed none, no committed checker to compare with")
        return
    folders = c.published_folders() + [q.relative_to(HERE) for q in sorted((HERE / "fixtures").glob("*")) if q.is_dir() and (q / "manifest.json").exists()]
    for rel in folders:
        (rc, _, _), (rw, _, _) = c.both(committed, HERE / rel)
        summ = next((l for l in rw.stdout.splitlines() if l.startswith("SUMMARY")), "(no SUMMARY)")
        report(f"h9_{str(rel).replace('/', '_')}", rc.stdout == rw.stdout and rc.returncode == rw.returncode and "Traceback" not in rw.stderr, "whole output byte-identical, exit codes equal, no exception",
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
        committed_sign = None if c.SKIP_COMMITTED else committed_sign_dir(tmp)
        print(f"keys (ssh-keygen -lf): auditor {fps['auditor']}, adder {fps['adder']}, model1 {fps['model1']}, forger {fps[FORGER]}; principals auditor {p.AUDITOR}, adder {m.ADDER}, model {p.MP}, forger {FORGER}")
        FS = f.build_signed(tmp, FB, "FS")
        FpreS = f.build_signed(tmp, fpre, "FpreS")
        built = h1(tmp, FS, forger, fps, committed)
        h1b(tmp, built, fps)
        h2(tmp, FS, committed)
        h3(tmp, FS, committed)
        h4(tmp, FS, fps, committed)
        h5(tmp, F, committed)
        h6(tmp, FS, forger, committed_sign)
        h7(tmp, fpre, FB, forger, fps, committed_dir)
        h8(tmp, FS, FpreS, FB)
        h9(committed)
        mism = sum(1 for r in c.RESULTS if not r)
        print(f"{sum(c.RESULTS)} of {len(c.RESULTS)} cases gave the expected result; MISMATCH {mism}")
        return 0 if all(c.RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
