#!/usr/bin/env python3
"""test07_export.py: the exports of claims-snapshot 0.7 (X1 to X8 of the 0.7 design's RED list, X5 and the independent half of X6 run
outside this suite): export.py writes an in-toto Statement v1, its DSSE envelope (a raw Ed25519 signature over PAE) and a W3C VC 2.0
credential with an eddsa-jcs-2022 Data Integrity proof, OUTSIDE the folder; check.py --export DIR verifies them against the folder
(the KX line). Needs the Python package `cryptography` (export.py's one dependency, and this suite's independent Ed25519) and ssh-keygen.

usage: python3 -I test07_export.py"""
import base64, hashlib, json, os, pathlib, secrets, shutil, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fixtures07 as f  # noqa: E402

LOCATION = "https://github.com/OneDro1d/onedroid-claims/tree/0000000000000000000000000000000000000000/examples/fixture"
PRED = "https://github.com/OneDro1d/onedroid-claims/blob/main/SPEC.md#claims-snapshot-v0.7"
FILES = ("statement.intoto.json", "statement.dsse.json", "credential.vc.json")


def crypto():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    return serialization, Ed25519PrivateKey, Ed25519PublicKey


def priv(key):
    serialization, _, _ = crypto()
    return serialization.load_ssh_private_key(pathlib.Path(f.KEYS[key]).read_bytes(), password=None)


def raw_pub(key):
    serialization, _, _ = crypto()
    return priv(key).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def pae(t, body):
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def export(d, key, out, *extra):
    cmd = [sys.executable, "-I", str(HERE / "export.py"), str(d), "--key", str(f.KEYS[key] if key in f.KEYS else key), "--out", str(out),
           "--location", LOCATION] + list(extra)
    return subprocess.run(cmd, capture_output=True, text=True)


def resign_env(out, stmt_bytes, key):
    """The envelope over `stmt_bytes`, signed by `key` with the independent library; the statement file rewritten to match."""
    (out / "statement.intoto.json").write_bytes(stmt_bytes)
    sig = priv(key).sign(pae(b"application/vnd.in-toto+json", stmt_bytes))
    env = json.loads((out / "statement.dsse.json").read_text())
    env["payload"] = base64.b64encode(stmt_bytes).decode()
    env["signatures"] = [{"keyid": env["signatures"][0]["keyid"], "sig": base64.b64encode(sig).decode()}]
    (out / "statement.dsse.json").write_text(json.dumps(env, indent=1) + "\n")


def main():
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        f.keygen(tmp / "keys")
        subprocess.run(["ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-N", "", "-f", str(tmp / "keys" / "rsa")], check=True, capture_output=True)
        subprocess.run(["ssh-keygen", "-q", "-t", "ecdsa", "-b", "256", "-N", "", "-f", str(tmp / "keys" / "ecdsa")], check=True, capture_output=True)
        F7 = f.build(tmp / "pub" / "f07")
        F6 = f.build(tmp / "pub" / "f06", fmt=f.F06)
        X1 = tmp / "exports" / "x1"

        def x1():
            r = export(F7, "auditor", X1)
            files = all((X1 / n).is_file() for n in FILES)
            inside = any((F7 / n).exists() for n in FILES)
            rc = f.Run(F7, "--export", X1)
            ok = r.returncode == 0 and files and not inside and rc.status.get("KX") == "PASS" and rc.rc == 0
            f.report("x1a_export_writes_three_files_and_check_passes", ok, "export.py exit 0, three files outside the folder, KX PASS, check exit 0",
                     f"export exit {r.returncode}, files {files}, inside {inside}, KX {rc.status.get('KX')}, check exit {rc.rc}",
                     (r.stderr.strip().splitlines()[-3:] + rc.text.get("KX", "").splitlines()[:6]))
            stmt = json.loads((X1 / "statement.intoto.json").read_text())
            env = json.loads((X1 / "statement.dsse.json").read_text())
            want = {n: f.sha(F7 / n) for n in ("manifest.json", "signatures.json", "audit.jsonl", "claims.jsonl", "page.txt")}
            got = {s["name"]: s["digest"]["sha256"] for s in stmt["subject"]}
            ok2 = (stmt["_type"] == "https://in-toto.io/Statement/v1" and stmt["predicateType"] == PRED and got == want
                   and env["payloadType"] == "application/vnd.in-toto+json" and base64.b64decode(env["payload"]) == (X1 / "statement.intoto.json").read_bytes()
                   and stmt["predicate"]["format"] == f.F07 and stmt["predicate"]["counts"] == f.mload(F7)["counts"])
            f.report("x1b_statement_shape", ok2, "in-toto Statement v1, our predicateType, the five subjects by sha256, the payload is the statement file's bytes",
                     f"_type {stmt.get('_type')}, predicateType {stmt.get('predicateType')}, subjects equal {got == want}, payloadType {env.get('payloadType')}")
        f.case("x1_export", x1)

        # X1c / X3b: a version with a manifest signature is the manifest signer's to export
        def x1c():
            Fm = tmp / "pub" / "f07m"
            shutil.copytree(F7, Fm)
            f.sign(Fm, "manifest", "adder", f.ADDER)
            r_a = export(Fm, "auditor", tmp / "exports" / "x1c-auditor")
            r_m = export(Fm, "adder", tmp / "exports" / "x1c-adder")
            rc = f.Run(Fm, "--export", tmp / "exports" / "x1c-adder")
            ok = r_a.returncode == 1 and not (tmp / "exports" / "x1c-auditor" / "statement.dsse.json").exists() and r_m.returncode == 0 and rc.status.get("KX") == "PASS"
            f.report("x1c_manifest_signed_version_is_the_manifest_signers", ok, "the auditor's key refused (exit 1, nothing written), the adder's key exported, KX PASS",
                     f"auditor exit {r_a.returncode}, adder exit {r_m.returncode}, KX {rc.status.get('KX')}", r_a.stderr.strip().splitlines()[-2:])
            # X3b: forge the envelope with the auditor's key on that version
            out = tmp / "exports" / "x3b"
            shutil.copytree(tmp / "exports" / "x1c-adder", out)
            resign_env(out, (out / "statement.intoto.json").read_bytes(), "auditor")
            rc2 = f.Run(Fm, "--export", out)
            f.report("x3b_manifest_version_signed_by_auditor_fails", rc2.status.get("KX") == "FAIL" and rc2.has("KX", "under the version's key"),
                     "KX FAIL: no signature verifies under the version's key", f"KX {rc2.status.get('KX')}", rc2.text.get("KX", "").splitlines()[:4])
        f.case("x1c_manifest_signed_version", x1c)

        def mut(name, fn, needle):
            out = tmp / "exports" / name
            shutil.copytree(X1, out)
            fn(out)
            rc = f.Run(F7, "--export", out)
            ok = rc.status.get("KX") == "FAIL" and rc.has("KX", needle) and rc.rc == 1 and not rc.traceback
            f.report(name, ok, f"KX FAIL naming {needle!r}, exit 1", f"KX {rc.status.get('KX')}, exit {rc.rc}", rc.text.get("KX", "").splitlines()[:5])

        def one_byte(out):
            b = bytearray((out / "statement.intoto.json").read_bytes())
            i = b.index(b'"predicate"')
            b[i + 1] = ord("P")
            (out / "statement.intoto.json").write_bytes(bytes(b))
        f.case("x2a", lambda: mut("x2a_one_byte_of_the_statement", one_byte, "statement.intoto.json is not the signed payload"))

        def subject_digest(out):
            s = json.loads((out / "statement.intoto.json").read_text())
            s["subject"][0]["digest"]["sha256"] = "0" * 64
            resign_env(out, (json.dumps(s, indent=1) + "\n").encode(), "auditor")
        f.case("x2b", lambda: mut("x2b_subject_digest_changed_and_resigned", subject_digest, "subject manifest.json"))

        def pred_count(out):
            s = json.loads((out / "statement.intoto.json").read_text())
            s["predicate"]["counts"]["evidenced"] += 1
            resign_env(out, (json.dumps(s, indent=1) + "\n").encode(), "auditor")
        f.case("x2c", lambda: mut("x2c_predicate_count_changed_and_resigned", pred_count, "predicate.counts"))

        def payload_type(out):
            env = json.loads((out / "statement.dsse.json").read_text())
            env["payloadType"] = "application/json"
            (out / "statement.dsse.json").write_text(json.dumps(env, indent=1) + "\n")
        f.case("x2d", lambda: mut("x2d_payload_type_changed", payload_type, "payloadType"))

        # X3: signed by a key that is not the version's, though the DSSE signature itself verifies
        def x3():
            out = tmp / "exports" / "x3"
            shutil.copytree(X1, out)
            body = (out / "statement.intoto.json").read_bytes()
            resign_env(out, body, "witness")
            _, _, Pub = crypto()
            env = json.loads((out / "statement.dsse.json").read_text())
            try:
                Pub.from_public_bytes(raw_pub("witness")).verify(base64.b64decode(env["signatures"][0]["sig"]), pae(b"application/vnd.in-toto+json", body))
                itself = True
            except Exception:  # noqa: BLE001
                itself = False
            rc = f.Run(F7, "--export", out)
            ok = itself and rc.status.get("KX") == "FAIL" and rc.has("KX", "under the version's key")
            f.report("x3a_signed_by_another_key_fails", ok, "the forged signature verifies under its own key, KX FAIL under the version's key",
                     f"verifies itself {itself}, KX {rc.status.get('KX')}", rc.text.get("KX", "").splitlines()[:4])
        f.case("x3_other_key", x3)

        # X4: PAE vector, and check.py's Ed25519 against the independent library
        def x4():
            vec = f.check.dsse_pae(b"http://example.com/HelloWorld", b"hello world")
            f.report("x4a_pae_test_vector", vec == b"DSSEv1 29 http://example.com/HelloWorld 11 hello world", "the DSSE protocol.md test vector's PAE", vec)
            _, Priv, _ = crypto()
            from cryptography.hazmat.primitives import serialization
            agree, total = 0, 0
            for i in range(40):
                k = Priv.generate()
                pk = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                msg = secrets.token_bytes(i * 7)
                sig = k.sign(msg)
                other = Priv.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                bad_sig = bytes([sig[0] ^ 1]) + sig[1:]
                bad_s = sig[:32] + bytes([sig[32] ^ 1]) + sig[33:]
                for p_, m_, s_ in ((pk, msg, sig), (pk, msg + b"x", sig), (pk, msg, bad_sig), (pk, msg, bad_s), (other, msg, sig)):
                    try:
                        k_pub = __import__("cryptography.hazmat.primitives.asymmetric.ed25519", fromlist=["x"]).Ed25519PublicKey.from_public_bytes(p_)
                        k_pub.verify(s_, m_)
                        lib = True
                    except Exception:  # noqa: BLE001
                        lib = False
                    total += 1
                    agree += f.check.ed25519_verify(p_, m_, s_) == lib
            f.report("x4b_ed25519_agrees_with_cryptography", agree == total == 200, "200 of 200 verdicts equal (valid, changed message, R byte, S byte, other key)", f"{agree} of {total}")
            env = json.loads((X1 / "statement.dsse.json").read_text())
            body = base64.b64decode(env["payload"])
            sig = base64.b64decode(env["signatures"][0]["sig"])
            mine = f.check.ed25519_verify(raw_pub("auditor"), f.check.dsse_pae(b"application/vnd.in-toto+json", body), sig)
            f.report("x4c_export_dsse_verifies_in_check_py", mine, "check.ed25519_verify over PAE with the auditor's key: True", mine)
        f.case("x4_ed25519", x4)

        # X6: relatedResource digests, the proof by the independent library, a changed count breaks the proof
        def x6():
            vc = json.loads((X1 / "credential.vc.json").read_text())
            sri = {r["id"].rsplit("/", 1)[1]: r["digestSRI"] for r in vc["relatedResource"]}
            want = {n: "sha256-" + base64.b64encode(hashlib.sha256((F7 / n).read_bytes()).digest()).decode() for n in ("manifest.json", "signatures.json", "audit.jsonl")}
            f.report("x6a_related_resource_digests", sri == want, want, sri)
            proof = dict(vc["proof"])
            pv = proof.pop("proofValue")
            doc = {k: v for k, v in vc.items() if k != "proof"}
            hd = hashlib.sha256(f.check.jcs(proof).encode()).digest() + hashlib.sha256(f.check.jcs(doc).encode()).digest()
            _, _, Pub = crypto()
            try:
                Pub.from_public_bytes(raw_pub("auditor")).verify(f.check.b58decode(pv[1:]), hd)
                lib = True
            except Exception:  # noqa: BLE001
                lib = False
            did = f.check.did_key(raw_pub("auditor"))
            ok = lib and vc["issuer"] == did and proof["verificationMethod"] == did + "#" + did[len("did:key:"):] and proof["cryptosuite"] == "eddsa-jcs-2022"
            f.report("x6b_proof_verifies_with_cryptography", ok, "the proof verifies under the issuer's did:key with the independent library", f"verified {lib}, issuer {vc['issuer'][:24]}…")
            out = tmp / "exports" / "x6c"
            shutil.copytree(X1, out)
            vc["credentialSubject"]["counts"]["evidenced"] += 1
            (out / "credential.vc.json").write_text(json.dumps(vc, indent=1) + "\n")
            rc = f.Run(F7, "--export", out)
            f.report("x6c_changed_count_breaks_the_proof", rc.status.get("KX") == "FAIL" and rc.has("KX", "the credential's proof does not verify"),
                     "KX FAIL: the credential's proof does not verify", f"KX {rc.status.get('KX')}", rc.text.get("KX", "").splitlines()[:5])
        f.case("x6_vc", x6)

        # X7: refusals
        def refuse(name, d, key, out, needle):
            r = export(d, key, out)
            nothing = not any((pathlib.Path(out) / n).exists() for n in FILES)
            ok = r.returncode == 1 and nothing and needle in r.stderr and "Traceback" not in r.stderr
            f.report(name, ok, f"exit 1, nothing written, stderr names {needle!r}", f"exit {r.returncode}, nothing written {nothing}", r.stderr.strip().splitlines()[-2:])
        f.case("x7a", lambda: refuse("x7a_rsa_key_refused", F7, str(tmp / "keys" / "rsa"), tmp / "exports" / "x7a", "not Ed25519"))
        f.case("x7b", lambda: refuse("x7b_ecdsa_key_refused", F7, str(tmp / "keys" / "ecdsa"), tmp / "exports" / "x7b", "not Ed25519"))

        def x7c():
            Fb = tmp / "pub" / "f07-broken"
            shutil.copytree(F7, Fb)
            (Fb / "page.txt").write_text((Fb / "page.txt").read_text() + "x")
            refuse("x7c_failing_folder_refused", Fb, "auditor", tmp / "exports" / "x7c", "check.py FAILs")
        f.case("x7c", x7c)
        f.case("x7d", lambda: refuse("x7d_out_inside_the_folder_refused", F7, "auditor", F7 / "exports", "inside the folder"))
        f.case("x7e", lambda: refuse("x7e_key_not_the_versions_refused", F7, "witness", tmp / "exports" / "x7e", "not the key that signed this version"))

        # X8: a 0.6 folder exported: allowed, predicateType names 0.7, format says 0.6
        def x8():
            out = tmp / "exports" / "x8"
            r = export(F6, "auditor", out)
            stmt = json.loads((out / "statement.intoto.json").read_text()) if (out / "statement.intoto.json").exists() else {}
            rc = f.Run(F6, "--export", out)
            ok = (r.returncode == 0 and stmt.get("predicateType") == PRED and stmt.get("predicate", {}).get("format") == f.F06
                  and rc.status.get("KX") == "PASS" and "K16" not in rc.status)
            f.report("x8_export_of_a_06_folder", ok, "exit 0, predicateType the 0.7 URI, predicate.format 0.6, KX PASS, no K16",
                     f"exit {r.returncode}, predicateType {stmt.get('predicateType')}, format {stmt.get('predicate', {}).get('format')}, KX {rc.status.get('KX')}",
                     r.stderr.strip().splitlines()[-2:])
        f.case("x8_06", x8)

    return f.finish("test07_export")


if __name__ == "__main__":
    sys.exit(main())
