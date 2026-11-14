#!/usr/bin/env python3
"""export.py: the exports of one version of a claims snapshot (claims-snapshot 0.7, SPEC.md section 15), written OUTSIDE the folder.

usage: python3 -I export.py SNAPSHOT_DIR --key PRIVATE_KEY [--out DIR] [--location URL]
  PRIVATE_KEY  an OpenSSH Ed25519 private key without a passphrase: the key that last stood behind this version, that is the key inside
               manifest.json.sig when the version has a manifest signature, else the key inside audit.jsonl.sig
  --out DIR    where the three files go (default: <folder>.exports/<manifest sha256, first 16>/ beside the folder); never inside the folder
  --location   where a reader fetches the folder (a repository URL at a commit): recorded in the predicate and used for the credential's
               relatedResource and evidence ids; without it the ids are urn:sha256:<manifest sha256>/<file>

Writes:
  statement.intoto.json  an in-toto Statement v1: the subjects are manifest.json, signatures.json, the auditor's part, claims.jsonl when
                         there is one and every page file, by sha256; predicateType the 0.7 predicate URI; the predicate a summary of the
                         folder (check.export_predicate) and the checker's own result
  statement.dsse.json    the DSSE envelope over those exact bytes, payloadType application/vnd.in-toto+json, one raw Ed25519 signature
                         over PAE, keyid the OpenSSH SHA256 fingerprint (a hint only)
  credential.vc.json     a W3C VC 2.0 credential about this version (credentialSubject.id urn:sha256:<manifest sha256>), issuer the
                         key's did:key, relatedResource digestSRI for manifest.json, signatures.json and the auditor's part, with an
                         embedded Data Integrity proof, cryptosuite eddsa-jcs-2022 (RFC 8785 JCS, Ed25519)
Refuses, before writing anything (exit 1): a key that is not Ed25519, a key that is not the version's key, a folder check.py FAILs, an
output folder inside the snapshot folder, an output file that already exists. Exit 2: a usage error, or the `cryptography` package missing.
Every value is taken from check.py's own builders, so `check.py SNAPSHOT_DIR --export DIR` recomputes exactly what this wrote.
Dependency: the Python package `cryptography` (load an OpenSSH key, sign raw bytes: ssh-keygen has no raw-signature mode). check.py
needs none: it verifies Ed25519 with the standard library."""
import base64, datetime, json, pathlib, re, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402


def arg(argv, flag):
    return argv[argv.index(flag) + 1] if flag in argv and argv.index(flag) + 1 < len(argv) else None


def refuse(msg):
    print(f"refused, nothing written: {msg}", file=sys.stderr)
    return 1


def main(argv):
    if len(argv) < 2 or argv[1].startswith("--") or not arg(argv, "--key"):
        print(__doc__)
        return 2
    snap, key_p = pathlib.Path(argv[1]), pathlib.Path(arg(argv, "--key"))
    location = arg(argv, "--location")
    try:
        from cryptography.exceptions import UnsupportedAlgorithm
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        print("export.py needs the Python package cryptography (pip install cryptography); check.py needs nothing", file=sys.stderr)
        return 2
    if not (snap / "manifest.json").is_file():
        return refuse(f"{snap} holds no manifest.json")
    try:
        M = json.loads((snap / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as e:
        return refuse(f"manifest.json is unreadable ({type(e).__name__})")
    if not isinstance(M, dict):
        return refuse(f"manifest.json is a JSON {check.json_kind(M)}, not an object")
    try:
        priv = serialization.load_ssh_private_key(key_p.read_bytes(), password=None)
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as e:
        return refuse(f"the key is not an OpenSSH private key this tool can read without a passphrase ({type(e).__name__})")
    if not isinstance(priv, Ed25519PrivateKey):
        return refuse(f"the key is {type(priv).__name__.replace('PrivateKey', '').lstrip('_')}, not Ed25519: the DSSE signature and the eddsa-jcs-2022 proof are Ed25519")
    pub32 = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    vk = check.version_key(snap)
    if vk is None:
        return refuse("no readable manifest.json.sig or audit.jsonl.sig: the folder does not say whose key stands behind this version")
    if check.ssh_ed25519_raw(vk[0]) != pub32:
        return refuse(f"the key is not the key that signed this version ({check.sshsig_fingerprint(vk[0])}, the key inside {vk[1]})")
    msha = check.sha256(snap / "manifest.json")
    out = pathlib.Path(arg(argv, "--out")) if arg(argv, "--out") else snap.parent / (snap.name + ".exports") / msha[:16]
    snap_r, out_r = snap.resolve(), out.resolve()
    if out_r == snap_r or snap_r in out_r.parents:
        return refuse("the output folder is inside the folder: an export is written outside it (the folder never changes)")
    for n_ in check.EXPORT_FILES:
        if (out / n_).exists() or (out / n_).is_symlink():
            return refuse(f"{out / n_} exists: an export of a version is written once")
    r = subprocess.run([sys.executable, "-I", str(HERE / "check.py"), str(snap)], capture_output=True, text=True)
    summary = next((l for l in r.stdout.splitlines() if l.startswith("SUMMARY:")), None)
    if r.returncode != 0 or summary is None:
        return refuse(f"check.py FAILs this folder ({summary or 'no SUMMARY line'}): only a folder that passes is exported")
    m_ = re.search(r", ([0-9]+) warnings:", summary)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    check_block = {"checker_sha256": check.sha256(HERE / "check.py"), "result": "WARN" if (m_ and int(m_.group(1))) else "PASS", "ran_at": now}

    stmt = check.export_statement(snap, M, check_block, location)
    stmt_bytes = (json.dumps(stmt, ensure_ascii=False, indent=1) + "\n").encode("utf-8")
    sig = priv.sign(check.dsse_pae(check.DSSE_PAYLOAD_TYPE.encode("utf-8"), stmt_bytes))
    env = {"payloadType": check.DSSE_PAYLOAD_TYPE, "payload": base64.b64encode(stmt_bytes).decode("ascii"),
           "signatures": [{"keyid": check.sshsig_fingerprint(vk[0]), "sig": base64.b64encode(sig).decode("ascii")}]}

    valid_from = vk[2] if vk[1] == "manifest.json.sig" and check.parse_time(vk[2]) else M.get("taken_at")
    vc = check.export_credential(snap, M, check_block, location, pub32, valid_from)
    did_ = check.did_key(pub32)
    opts = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "created": now, "verificationMethod": did_ + "#" + did_[len("did:key:"):],
            "proofPurpose": "assertionMethod", "@context": list(vc["@context"])}
    try:
        hd = check.eddsa_jcs_hash_data(vc, opts)
    except ValueError as e:
        return refuse(f"the credential is not JCS-serialisable: {e}")
    vc["proof"] = dict(opts, proofValue="z" + check.b58encode(priv.sign(hd)))

    out.mkdir(parents=True, exist_ok=True)
    (out / "statement.intoto.json").write_bytes(stmt_bytes)
    (out / "statement.dsse.json").write_text(json.dumps(env, indent=1) + "\n", encoding="utf-8")
    (out / "credential.vc.json").write_text(json.dumps(vc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    r2 = subprocess.run([sys.executable, "-I", str(HERE / "check.py"), str(snap), "--export", str(out)], capture_output=True, text=True)
    kx = next((l for l in r2.stdout.splitlines() if l.startswith("KX ")), "no KX line")
    print(f"exported manifest sha256:{msha[:16]}… signed with {check.sshsig_fingerprint(vk[0])} ({vk[1]}) to {out}; check.py --export: {kx}")
    return 0 if kx.startswith("KX PASS") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
