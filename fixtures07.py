#!/usr/bin/env python3
"""fixtures07.py: the shared helpers of the 0.7 suites (test07_compat.py, test07_links.py, test07_anchors.py, test07_export.py).
Standard library plus ssh-keygen on PATH. Not a suite of its own.

A fixture is BUILT in a temporary folder from the published agent-work example (examples/agent-work-s-i10-2026-11-12): its signatures
and allowed_signers are emptied, the format set (0.7 by default, 0.6 for the twin), the auditor part and the witness re-signed with
throwaway keys made here (no key leaves the temporary folder), the manifest's `files` hashes refreshed, and the auditor's `sources`
signature made with sign.py (so it covers whatever digest sign.py computes for the format). Each suite copies a fixture, changes one
thing, re-signs what a careful publisher would re-sign, runs check.py and compares statuses and lines."""
import hashlib, json, pathlib, re, shutil, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402

SRC_AW = HERE / "examples/agent-work-s-i10-2026-11-12"
AUDITOR, WITNESS, ADDER, BOB = "fixture-auditor", "fixture-witness", "fixture-adder", "fixture-bob"
F07, F06 = "claims-snapshot/0.7", "claims-snapshot/0.6"
KEYS = {}   # name -> private key path, set by keygen()
RESULTS = []


def report(name, ok, expected, observed, details=()):
    RESULTS.append((name, ok))
    print(f"{'ok      ' if ok else 'MISMATCH'} {name}: expected {expected}; observed {observed}")
    for d in details:
        print(f"    {d}")


def finish(title):
    n_bad = sum(1 for _, ok in RESULTS if not ok)
    print(f"{title}: {len(RESULTS) - n_bad} of {len(RESULTS)} cases gave the expected result; MISMATCH {n_bad}")
    return 0 if n_bad == 0 and RESULTS else 1


def case(name, fn):
    """Runs one case; an exception is a MISMATCH by name (a RED run of a missing feature must still report every case)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        report(name, False, "the case to run", f"{type(e).__name__}: {str(e)[:300]}")


def sha(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


def load(p):
    return [json.loads(l) for l in pathlib.Path(p).read_text(encoding="utf-8").split("\n") if l.strip()]


def dump(p, rows):
    pathlib.Path(p).write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")


def mload(d):
    return json.loads((pathlib.Path(d) / "manifest.json").read_text(encoding="utf-8"))


def msave(d, M):
    (pathlib.Path(d) / "manifest.json").write_text(json.dumps(M, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def keygen(root, names=("auditor", "witness", "adder", "bob", "other")):
    root = pathlib.Path(root)
    root.mkdir(parents=True, exist_ok=True)
    for n in names:
        p = root / n
        if not p.exists():
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"fixture-{n}", "-f", str(p)], check=True, capture_output=True)
        KEYS[n] = p


def pub(key):
    return pathlib.Path(str(KEYS[key]) + ".pub").read_text(encoding="utf-8").split()[:2]


def sign(d, role, key, ident, part=None):
    cmd = [sys.executable, "-I", str(HERE / "sign.py"), str(d), "--role", role, "--key", str(KEYS[key]), "--identity", ident]
    if part:
        cmd += ["--file", part]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"sign.py {role} {part}: {r.stdout} {r.stderr}")
    return r


def refresh_files(d):
    """The manifest's `files` object names the bytes the writer leaves behind (structural files never)."""
    M = mload(d)
    if isinstance(M.get("files"), dict):
        M["files"] = {k: sha(pathlib.Path(d) / k) for k in M["files"] if k not in check.STRUCTURAL_FILES and (pathlib.Path(d) / k).exists()}
    msave(d, M)


def resign_sources(d):
    sign(d, "sources", "auditor", AUDITOR)


def build(dst, fmt=F07, taken_at=None, sources=True, src=SRC_AW):
    """The agent-work example as a signed folder of format `fmt`, re-signed with the throwaway keys."""
    dst = pathlib.Path(dst)
    shutil.copytree(src, dst)
    (dst / "CHECK.json").unlink(missing_ok=True)
    (dst / "signatures.json").write_text("[]\n", encoding="utf-8")
    (dst / "allowed_signers").write_text("", encoding="utf-8")
    M = mload(dst)
    M["format"] = fmt
    if taken_at:
        M["taken_at"] = taken_at
    msave(dst, M)
    sign(dst, "auditor", "auditor", AUDITOR, "audit.jsonl")
    sign(dst, "witness", "witness", WITNESS, "witness/alice.jsonl")
    refresh_files(dst)
    if sources:
        resign_sources(dst)
    return dst


def resign_witness(d, wf="witness/alice.jsonl", key="witness", ident=WITNESS):
    """After a change to a witness file: its manifest hash, its signature, the files hashes."""
    M = mload(d)
    for w in M["grading"]["witnesses"]:
        if w["file"] == wf:
            w["sha256"] = sha(pathlib.Path(d) / wf)
    msave(d, M)
    sign(d, "witness", key, ident, wf)
    refresh_files(d)


def set_links(d, links, resign=True):
    M = mload(d)
    if links is None:
        M.pop("links", None)
    else:
        M["links"] = links
    msave(d, M)
    if resign:
        resign_sources(d)


def to_pre(d):
    """The folder as its own pre-witness stage (SPEC 14): no claims.jsonl, no witness, no score; the auditor part re-signed."""
    d = pathlib.Path(d)
    (d / "claims.jsonl").unlink(missing_ok=True)
    shutil.rmtree(d / "witness", ignore_errors=True)
    (d / "signatures.json").write_text("[]\n", encoding="utf-8")
    M = mload(d)
    g = M["grading"]
    g["kind"] = "pre-witness"
    for k in ("grader", "model"):
        g.pop(k, None)
    g["witnesses"] = []
    for k in ("score", "claims_sha256"):
        M.pop(k, None)
    audit = load(d / "audit.jsonl")
    M["counts"] = {"claims": len(audit), "checkable": sum(1 for c in audit if c.get("checkable", True) and c.get("kind") != "promise")}
    if isinstance(M.get("files"), dict):
        M["files"] = {k: v for k, v in M["files"].items() if k != "claims.jsonl" and not k.startswith("witness/")}
    msave(d, M)
    sign(d, "auditor", "auditor", AUDITOR, "audit.jsonl")
    refresh_files(d)
    resign_sources(d)


def witness_answer(d, ans, name="bob", key="bob", ident=BOB, kind="human", undecided_ids=(), entry_extra=None):
    """A witness answer for add_witness.py over the folder `d`: the primary's decisions (UNDECIDED on `undecided_ids`), signed with `key`."""
    d, ans = pathlib.Path(d), pathlib.Path(ans)
    (ans / "witness").mkdir(parents=True)
    audit_h = sha(d / "audit.jsonl")
    prim = load(d / "witness/alice.jsonl")[1:]
    rows = []
    for r in prim:
        r = dict(r)
        if r["id"] in undecided_ids:
            r = {"id": r["id"], "verdict": "UNDECIDED", "note": "the candidates do not settle it", "graded_by": "grader", "graded_at": r.get("graded_at")}
        rows.append(r)
    header = {"witness": name, "kind": kind, "model": "human", "method": "read", "over": {"file": "audit.jsonl", "sha256": audit_h},
              "started_at": "2026-11-14T09:00:00Z", "finished_at": "2026-11-14T09:05:00Z"}
    wf = f"witness/{name}.jsonl"
    dump(ans / wf, [header] + rows)
    h = sha(ans / wf)
    line = check.signed_line("witness", wf, h, audit_h)
    (ans / "line").write_text(line, encoding="utf-8")
    subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(KEYS[key]), "-n", check.SIGN_NAMESPACE, str(ans / "line")], check=True, capture_output=True)
    shutil.move(str(ans / "line.sig"), str(ans / (wf + ".sig")))
    (ans / "line").unlink()
    kt, kb = pub(key)
    fp = check.sshsig_fingerprint(f"{kt} {kb}")
    (ans / "allowed_signers").write_text(f'{ident} namespaces="{check.SIGN_NAMESPACE}" {kt} {kb}\n', encoding="utf-8")
    audit = load(d / "audit.jsonl")
    sc = check.evidence_score([m for m in check.merge_rows(audit, rows, name) if m.get("verdict") != "UNDECIDED"])
    entry = {"name": name, "kind": kind, "model": "human", "method": "read", "signer": f"{ident} <{fp}>", "file": wf, "sha256": h,
             "primary": False, "score": {k: sc[k] for k in ("coverage_pct", "contradiction_pct", "band")}, "missing_claims": 0}
    entry.update(entry_extra or {})
    (ans / "manifest-entry.json").write_text(json.dumps(entry, indent=1) + "\n", encoding="utf-8")
    (ans / "signatures-entry.json").write_text(json.dumps({"role": "witness", "file": wf, "sha256": h, "line": line,
                                                           "signer": {"name": ident, "key_id": fp, "kind": kt},
                                                           "signed_at": "2026-11-14T09:06:00Z", "signature": wf + ".sig", "commit": None}, indent=1) + "\n",
                                                encoding="utf-8")
    return ans


def add_witness(d, ans):
    return subprocess.run([sys.executable, "-I", str(HERE / "add_witness.py"), str(d), str(ans), "--key", str(KEYS["adder"]), "--identity", ADDER],
                          capture_output=True, text=True)


ROW = re.compile(r"^(K\w+) (PASS|WARN|FAIL): (.*)$")


class Run:
    """One check.py run: exit code, stdout, the status and the full text (line and details) of each check id."""

    def __init__(self, folder, *flags, checker=None, cwd=None):
        cmd = [sys.executable, "-I", str(checker or (HERE / "check.py")), str(folder)] + [str(f) for f in flags]
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
        self.rc, self.out, self.err = r.returncode, r.stdout, r.stderr
        self.status, self.text = {}, {}
        cur = None
        for l in self.out.splitlines():
            m = ROW.match(l)
            if m:
                cur = m.group(1)
                self.status[cur] = m.group(2)
                self.text[cur] = l
            elif l.startswith("    ") and cur:
                self.text[cur] += "\n" + l
            else:
                cur = None
        self.summary = next((l for l in self.out.splitlines() if l.startswith("SUMMARY:")), None)
        self.traceback = "Traceback" in self.out + self.err

    def has(self, k, needle):
        return needle in self.text.get(k, "")

    def brief(self, *ks):
        return {k: self.status.get(k) for k in ks}
