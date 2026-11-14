#!/usr/bin/env python3
"""test07_anchors.py: the anchor side of claims-snapshot 0.7 (G5 and G6 of the 0.7 design's RED list). Standard library plus ssh-keygen.

G5, package.py: on a 0.7 input the anchors.json ref keeps the `signer` the anchor service answered (0x and 40 hex), and refuses a
malformed one with nothing recorded; on a 0.6 input it writes exactly today's four ref fields. Against test_package.py's fake /anchor.
G6, K14 on 0.7: an armarium ref without a signer WARNs, a malformed signer FAILs, a `gvui` that does not recompute from the ref FAILs
(gv1: "gv1" and the unpadded standard base32 of namespace "claims-snapshot", "anchor/<chain>/<block>", the correlation id and the
signer, then the anchor time as Unix seconds, colon-joined; gvuid 7311ea9 gvuid.go:30-33 and :73-82); a 0.6 folder's K14 is unchanged.

usage: python3 -I test07_anchors.py"""
import base64, calendar, datetime, json, pathlib, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fixtures07 as f  # noqa: E402
import test_package as tp  # noqa: E402  (its fake /anchor and the landed answer)

TOKEN = "fixture-anchor-token-value-7f3a"  # a test value, not a credential
SIGNER = "0x" + "11" * 20


def gv1(chain, block, corr, signer, time):
    b = lambda s: base64.b32encode(s.encode()).decode().rstrip("=")  # noqa: E731
    secs = calendar.timegm(datetime.datetime.strptime(time, "%Y-%m-%dT%H:%M:%SZ").timetuple())
    return ":".join(["gv1", b("claims-snapshot"), b(f"anchor/{chain}/{block}"), b(corr), b(signer), str(secs)])


def package(src, out, fake, tok):
    cmd = [sys.executable, "-I", str(HERE / "package.py"), str(src), "--out", str(out), "--key", str(f.KEYS["auditor"]), "--identity", f.AUDITOR,
           "--anchor-url", fake.url, "--anchor-chain", tp.CHAIN, "--anchor-token-file", str(tok), "--anchor-wait", "0", "--anchor-retries", "0",
           "--anchor-allow-http"]
    return subprocess.run(cmd, capture_output=True, text=True)


def anchors(d):
    p = pathlib.Path(d) / "anchors.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def main():
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        f.keygen(tmp / "keys")
        tok = tmp / "anchor.token"
        tok.write_text(TOKEN + "\n", encoding="utf-8")
        tok.chmod(0o600)
        F7 = f.build(tmp / "f07")
        F6 = f.build(tmp / "f06", fmt=f.F06)

        def landed_with(signer="keep"):
            def fn(key):
                a = tp.landed(key)
                if signer is None:
                    a.pop("signer", None)
                elif signer != "keep":
                    a["signer"] = signer
                return a
            return fn

        def with_fake(answer_fn, src, name):
            fake = tp.Fake([(200, {})])
            fake.script = [(200, None)]
            calls = fake.calls

            class Script(list):
                def __getitem__(self, i):
                    key = calls[-1]["body"].get("key") if calls else None
                    return (200, answer_fn(key))

                def __len__(self):
                    return 1
            fake.script = Script()
            try:
                out = tmp / f"out-{name}"
                r = package(src, out, fake, tok)
            finally:
                fake.close()
            return r, out

        # G5a: 0.7 keeps the signer
        def g5a():
            r, out = with_fake(landed_with(), F7, "g5a")
            a = anchors(out)
            ref = a[0]["ref"] if a else {}
            rc = f.Run(out)
            ok = (r.returncode == 0 and list(ref) == ["chain", "correlation_id", "block", "tx_hash", "signer"] and ref.get("signer") == SIGNER
                  and rc.status.get("K14") == "PASS" and TOKEN not in r.stdout + r.stderr)
            f.report("g5a_package_07_keeps_signer", ok, "exit 0, ref chain, correlation_id, block, tx_hash, signer (0x11…), K14 PASS, token not printed",
                     f"exit {r.returncode}, ref keys {list(ref)}, signer {ref.get('signer')}, K14 {rc.status.get('K14')}", r.stderr.strip().splitlines()[-3:])
        f.case("g5a_package_07_keeps_signer", g5a)

        # G5b: 0.6 writes exactly today's four fields
        def g5b():
            r, out = with_fake(landed_with(), F6, "g5b")
            a = anchors(out)
            ref = a[0]["ref"] if a else {}
            ok = r.returncode == 0 and list(ref) == ["chain", "correlation_id", "block", "tx_hash"]
            f.report("g5b_package_06_four_fields", ok, "exit 0, ref exactly chain, correlation_id, block, tx_hash", f"exit {r.returncode}, ref keys {list(ref)}",
                     r.stderr.strip().splitlines()[-3:])
        f.case("g5b_package_06_four_fields", g5b)

        # G5c: 0.7, a malformed signer from the service: nothing recorded, exit 1
        def g5c():
            r, out = with_fake(landed_with("0x12"), F7, "g5c")
            a = anchors(out)
            ok = r.returncode == 1 and a == [] and "signer" in r.stderr and "0x12" not in r.stderr
            f.report("g5c_package_07_malformed_signer_refused", ok, "exit 1, anchors.json [], stderr names the signer rule (not its value)",
                     f"exit {r.returncode}, anchors {a}", r.stderr.strip().splitlines()[-2:])
        f.case("g5c_package_07_malformed_signer_refused", g5c)

        # G5d: 0.7, the service sent no signer: recorded without one, K14 WARNs
        def g5d():
            r, out = with_fake(landed_with(None), F7, "g5d")
            a = anchors(out)
            ref = a[0]["ref"] if a else {}
            rc = f.Run(out)
            ok = r.returncode == 0 and list(ref) == ["chain", "correlation_id", "block", "tx_hash"] and rc.status.get("K14") == "WARN" and rc.has("K14", "names no signer")
            f.report("g5d_package_07_no_signer_warns", ok, "exit 0, the four fields, K14 WARN 'names no signer'",
                     f"exit {r.returncode}, ref keys {list(ref)}, K14 {rc.status.get('K14')}", rc.text.get("K14", "").splitlines()[:3])
        f.case("g5d_package_07_no_signer_warns", g5d)

        # G6: K14 on hand-written anchors.json
        ref = {"chain": "argus-dev-poa", "correlation_id": "c" * 32, "block": 4242, "tx_hash": "0x" + "ab" * 32}
        T = "2026-11-13T14:00:00Z"

        def k14(name, d, entry, want, needle):
            entry = dict({"over": "sha256:" + f.sha(d / "signatures.json"), "method": "armarium", "time": T, "proof_file": None}, **entry)
            (d / "anchors.json").write_text(json.dumps([entry], indent=1) + "\n", encoding="utf-8")
            r = f.Run(d)
            ok = r.status.get("K14") == want and (needle is None or r.has("K14", needle)) and not r.traceback
            f.report(name, ok, f"K14 {want}" + (f" with {needle!r}" if needle else ""), f"K14 {r.status.get('K14')}", r.text.get("K14", "").splitlines()[:4])

        f.case("g6a", lambda: k14("g6a_07_ref_without_signer_warns", F7, {"ref": ref}, "WARN", "names no signer"))
        f.case("g6b", lambda: k14("g6b_07_malformed_signer_fails", F7, {"ref": dict(ref, signer="0xZZ")}, "FAIL", "is not 0x and 40 hex"))
        f.case("g6c", lambda: k14("g6c_07_signer_and_gvui_pass", F7, {"ref": dict(ref, signer=SIGNER), "gvui": gv1("argus-dev-poa", 4242, "c" * 32, SIGNER, T)},
                                  "PASS", "gvui recomputes from the ref"))
        f.case("g6c2", lambda: k14("g6c2_07_gvui_line_is_not_a_binding", F7, {"ref": dict(ref, signer=SIGNER), "gvui": gv1("argus-dev-poa", 4242, "c" * 32, SIGNER, T)},
                                   "PASS", "K14 PASS: 1 anchor binding(s) hold"))
        f.case("g6d", lambda: k14("g6d_07_gvui_not_recomputing_fails", F7, {"ref": dict(ref, signer=SIGNER), "gvui": gv1("argus-dev-poa", 4242, "d" * 32, SIGNER, T)},
                                  "FAIL", "gvui does not recompute"))
        f.case("g6e", lambda: k14("g6e_07_gvui_other_signer_fails", F7, {"ref": dict(ref, signer=SIGNER), "gvui": gv1("argus-dev-poa", 4242, "c" * 32, "0x" + "22" * 20, T)},
                                  "FAIL", "gvui does not recompute"))
        f.case("g6f", lambda: k14("g6f_07_gvui_without_time_fails", F7, {"ref": dict(ref, signer=SIGNER), "time": None, "gvui": gv1("argus-dev-poa", 4242, "c" * 32, SIGNER, T)},
                                  "FAIL", "gvui does not recompute"))
        f.case("g6g", lambda: k14("g6g_07_eip55_case_signer_passes", F7, {"ref": dict(ref, signer="0xAbCdEf0123456789aBcDeF0123456789AbCdEf01")}, "PASS", None))
        f.case("g6h", lambda: k14("g6h_06_ref_without_signer_unchanged", F6, {"ref": ref}, "PASS", "binding holds"))
        f.case("g6i", lambda: k14("g6i_06_malformed_signer_not_read", F6, {"ref": dict(ref, signer="0xZZ")}, "PASS", "binding holds"))

        # G6j/G6k (gate-h2 F1, 14 Nov 2026): the checked folder's OWN anchors.json as a symbolic link, here to a valid file inside the
        # folder. 0.7: never followed, K14 FAIL (the K16 rule, DESIGN 1.3). 0.6: unchanged, the link is read as before.
        def own_link(name, d, want, needle):
            k14(name + "-setup", d, {"ref": ref}, "PASS" if d is F6 else "WARN", None)
            real = d / "anchors-real.json"
            (d / "anchors.json").rename(real)
            (d / "anchors.json").symlink_to("anchors-real.json")
            try:
                r = f.Run(d)
                ok = r.status.get("K14") == want and (needle is None or r.has("K14", needle)) and not r.traceback
                f.report(name, ok, f"K14 {want}" + (f" with {needle!r}" if needle else ""), f"K14 {r.status.get('K14')}", r.text.get("K14", "").splitlines()[:4])
            finally:
                (d / "anchors.json").unlink()
                real.rename(d / "anchors.json")

        f.case("g6j", lambda: own_link("g6j_07_own_anchors_symlink_fails", F7, "FAIL", "anchors.json is a symbolic link, not followed"))
        f.case("g6k", lambda: own_link("g6k_06_own_anchors_symlink_unchanged", F6, "PASS", "binding holds"))

    return f.finish("test07_anchors")


if __name__ == "__main__":
    sys.exit(main())
