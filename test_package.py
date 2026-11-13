"""package.py, the packager (step 1d of Michal's evidence tooling, mission M-20261112-EVIDENCE-STEP1 ticket 13539782694), tested first,
against a fake armarium /anchor that speaks the answer shapes of armarium-service's README at dev/ndim 4375ba30 ("The /anchor surface").

  p1  no anchor service named: the pre-witness folder plus one witness answer becomes a witnessed folder in --out; exit 0; check.py runs
      on it with no FAIL; anchors.json is [] and K14 says no anchor.
  p2  the anchor answers 200 landed: one POST /anchor/<chain>/records with a bearer token read from the token file, a key fixed by the
      signatures file's hash, format "claims-snapshot/anchor/1", payload = standard base64 of ONE compact JSON object of at most 2048 bytes
      naming "over" = "sha256:<hex of signatures.json>"; anchors.json holds exactly one entry {over, method "armarium", ref (chain,
      correlation_id, block, tx_hash), time = block_time, proof_file null}; check.py K14 PASS with "anchored by armarium"; exit 0.
  p3  202 in_doubt, then 200: the same request is repeated with the SAME key (the README: "never use a new key for it"); landed; exit 0.
  p4  503 not_sent every time: exit 3, the output kept, anchors.json [], stderr says it is not anchored yet and names the key to repeat.
  p5  403 no_grant: exit 1, stderr names the error, nothing anchored.
  p6  --out already exists: exit 2, the existing folder unchanged by hash.
  p7  an answer add_witness.py refuses: exit 1, add_witness's refusal relayed, no anchor call.
  p8  the token's value never appears in stdout or stderr, in any case above.
  p9  TLS as armarium-dev serves it (a private CA, a SAN naming the in-cluster service only), reached on 127.0.0.1 through a port-forward:
      with --anchor-ca and --anchor-server-name, landed, K14 PASS, exit 0.
  p10 the CA without the server name: refused by TLS at once, no request served, exit 1, stderr points at --anchor-server-name.
  p11 another CA: refused by TLS at once, no request served, exit 1.
  p12 --anchor-ca naming a missing file: exit 2, --out not created.
usage: python3 -I test_package.py"""
import base64
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import mutants06 as m  # noqa: E402
import mutants06c as c  # noqa: E402
import mutants06d as dd  # noqa: E402

TOKEN = "FIXTURE-TOKEN-NOT-A-SECRET"  # a test value; p8 checks it is never printed
CHAIN = "argus-dev-poa"
RESULTS = []


def report(name, ok, expected, observed, details=()):
    RESULTS.append(ok)
    print(f"{'ok      ' if ok else 'MISMATCH'} {name}: expected {expected}; observed {observed}")
    for d in details:
        print(f"    {d}")


class Fake:
    """A scripted /anchor: `script` is a list of (status, body) answered in order (the last repeats); `calls` records each request."""

    def __init__(self, script):
        self.script, self.calls = list(script), []
        fake = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n)
                fake.calls.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": json.loads(body or b"{}")})
                status, out = fake.script[min(len(fake.calls) - 1, len(fake.script) - 1)]
                data = json.dumps(out).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


def landed(key):
    return {"state": "landed", "key": key, "format": "claims-snapshot/anchor/1",
            "ref": {"chain": CHAIN, "correlation_id": "c" * 32, "block": 4242, "tx_hash": "0x" + "ab" * 32},
            "signer": "0x" + "11" * 20, "block_time": "2026-11-13T14:00:00Z"}


def sha256(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


def tree(d):
    return {str(q.relative_to(d)): sha256(q) for q in sorted(pathlib.Path(d).rglob("*")) if q.is_file()}


def run(parent, out, answers, tokfile=None, url=None, extra=()):
    cmd = [sys.executable, "-I", str(HERE / "package.py"), str(parent), "--out", str(out), "--key", str(m.KEYS["adder"]), "--identity", m.ADDER]
    for a in answers:
        cmd += ["--answer", str(a)]
    if url:
        cmd += ["--anchor-url", url, "--anchor-chain", CHAIN, "--anchor-token-file", str(tokfile), "--anchor-wait", "0"]
    cmd += list(extra)
    return subprocess.run(cmd, capture_output=True, text=True)


def summary(text):
    return next((l for l in text.splitlines() if l.startswith("SUMMARY")), None)


def no_token(name, r):
    leaked = TOKEN in r.stdout or TOKEN in r.stderr
    report(name + "_token_not_printed", not leaked, "the token value absent from stdout and stderr", f"present: {leaked}")


def main():
    if not (HERE / "package.py").exists():
        report("package_py_exists", False, "package.py beside this test", "missing")
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        fpre, F = c.build(tmp / "build")
        FB = tmp / "build" / "FB"
        shutil.copytree(F, FB)
        dd.add_bound(FB)
        ans = tmp / "answer"
        c.make_answer(FB, ans)
        tok = tmp / "anchor.token"
        tok.write_text(TOKEN + "\n", encoding="utf-8")
        tok.chmod(0o600)

        # p1
        out = tmp / "out-p1"
        r = run(fpre, out, [ans])
        anc = json.loads((out / "anchors.json").read_text()) if (out / "anchors.json").exists() else None
        s = summary(r.stdout)
        k14 = next((l for l in r.stdout.splitlines() if l.startswith("K14 ")), "")
        said = "not anchored: no --anchor-url given" in r.stdout
        ok = (r.returncode == 0 and (out / "witness").is_dir() and s is not None and "0 failed" in s and anc == []
              and "0 anchor binding(s) hold" in k14 and said)
        report("p1_no_anchor_service", ok, "exit 0, a witness/ folder, SUMMARY with 0 failed, anchors.json [], K14 '0 anchor binding(s) hold' "
               "(the format WARNs only for test-run), the packager saying it did not anchor",
               f"exit {r.returncode}, witness {(out / 'witness').is_dir()}, {s}, anchors {anc}, K14 line {k14!r}, said {said}",
               [f"stderr: {l}" for l in r.stderr.strip().splitlines()[-3:]])
        no_token("p1", r)

        # p2 to p5: a fake that answers each POST by a scripted status, with the shape the README gives for it and the key it was sent
        class LandedFake(Fake):
            def __init__(self):
                super().__init__([(200, {})])
                inner = self

                class H2(BaseHTTPRequestHandler):
                    def do_POST(self):
                        n = int(self.headers.get("Content-Length") or 0)
                        body = json.loads(self.rfile.read(n) or b"{}")
                        inner.calls.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
                        idx = len(inner.calls) - 1
                        status = inner.statuses[min(idx, len(inner.statuses) - 1)]
                        out_ = landed(body.get("key")) if status == 200 else ({"state": "in_doubt", "key": body.get("key")} if status == 202 else
                               ({"state": "not_sent", "key": body.get("key")} if status == 503 else {"error": "no_grant", "message": "no anchor grant for this chain"}))
                        data = json.dumps(out_).encode()
                        self.send_response(status)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)

                    def log_message(self, *a):
                        pass
                self.httpd.shutdown()
                self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H2)
                self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
                threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
                self.statuses = [200]

        def with_fake(statuses, name):
            fk = LandedFake()
            fk.statuses = statuses
            o = tmp / f"out-{name}"
            rr = run(fpre, o, [ans], tok, fk.url)
            fk.close()
            return fk, o, rr

        fk, out, r = with_fake([200], "p2")
        anc = json.loads((out / "anchors.json").read_text()) if (out / "anchors.json").exists() else None
        sig_h = sha256(out / "signatures.json") if (out / "signatures.json").exists() else None
        call = fk.calls[0] if fk.calls else {}
        b = call.get("body", {})
        try:
            raw = base64.b64decode(b.get("payload", ""), validate=True)
            pl = json.loads(raw)
            compact = raw == json.dumps(pl, separators=(",", ":"), ensure_ascii=False).encode() and len(raw) <= 2048
        except Exception:
            raw, pl, compact = b"", {}, False
        want_entry = {"over": f"sha256:{sig_h}", "method": "armarium", "ref": landed(b.get("key"))["ref"], "time": "2026-11-13T14:00:00Z", "proof_file": None}
        ok = (r.returncode == 0 and len(fk.calls) == 1 and call.get("path") == f"/anchor/{CHAIN}/records" and call.get("auth") == f"Bearer {TOKEN}"
              and b.get("format") == "claims-snapshot/anchor/1" and isinstance(b.get("key"), str) and 1 <= len(b["key"]) <= 200 and sig_h and sig_h[:32] in b["key"]
              and compact and pl.get("over") == f"sha256:{sig_h}" and anc == [want_entry]
              and "anchored by armarium" in r.stdout and "K14 PASS" in r.stdout)
        report("p2_landed", ok, "one POST with the bearer token, the hash-fixed key, the format, a compact payload naming over; anchors.json the one entry; K14 PASS",
               f"exit {r.returncode}, calls {len(fk.calls)}, path {call.get('path')}, auth ok {call.get('auth') == f'Bearer {TOKEN}'}, format {b.get('format')}, "
               f"key {b.get('key')}, compact {compact}, over ok {pl.get('over') == f'sha256:{sig_h}'}, anchors match {anc == [want_entry]}, K14 PASS {'K14 PASS' in r.stdout}",
               [f"anchors: {anc}", f"stderr: {r.stderr.strip()[-300:]}"])
        no_token("p2", r)

        # p3
        fk, out, r = with_fake([202, 200], "p3")
        keys = [x["body"].get("key") for x in fk.calls]
        anc = json.loads((out / "anchors.json").read_text()) if (out / "anchors.json").exists() else None
        ok = r.returncode == 0 and len(fk.calls) == 2 and len(set(keys)) == 1 and isinstance(anc, list) and len(anc) == 1
        report("p3_in_doubt_then_landed", ok, "two POSTs with the same key, one anchor entry, exit 0",
               f"exit {r.returncode}, calls {len(fk.calls)}, keys {keys}, anchors {len(anc) if isinstance(anc, list) else anc}")
        no_token("p3", r)

        # p4
        fk, out, r = with_fake([503], "p4")
        anc = json.loads((out / "anchors.json").read_text()) if (out / "anchors.json").exists() else None
        key = fk.calls[0]["body"].get("key") if fk.calls else None
        ok = r.returncode == 3 and out.is_dir() and anc == [] and "not anchored" in r.stderr and key and key in r.stderr
        report("p4_not_sent", ok, "exit 3, the output kept, anchors.json [], stderr 'not anchored' naming the key",
               f"exit {r.returncode}, out {out.is_dir()}, anchors {anc}, calls {len(fk.calls)}, stderr: {r.stderr.strip()[-200:]}")
        no_token("p4", r)

        # p5
        fk, out, r = with_fake([403], "p5")
        anc = json.loads((out / "anchors.json").read_text()) if (out / "anchors.json").exists() else None
        ok = r.returncode == 1 and "no_grant" in r.stderr and anc == []
        report("p5_no_grant", ok, "exit 1, stderr names no_grant, anchors.json []", f"exit {r.returncode}, anchors {anc}, stderr: {r.stderr.strip()[-200:]}")
        no_token("p5", r)

        # p6
        out = tmp / "out-p6"
        out.mkdir()
        (out / "keep.txt").write_text("x", encoding="utf-8")
        before = tree(out)
        r = run(fpre, out, [ans])
        ok = r.returncode == 2 and tree(out) == before
        report("p6_out_exists", ok, "exit 2, the existing folder unchanged", f"exit {r.returncode}, unchanged {tree(out) == before}, stderr: {r.stderr.strip()[-160:]}")

        # p7
        bad = tmp / "answer-bad"
        shutil.copytree(ans, bad)
        me = json.loads((bad / "manifest-entry.json").read_text(encoding="utf-8"))
        me["name"] = ["x"]
        (bad / "manifest-entry.json").write_text(json.dumps(me) + "\n", encoding="utf-8")
        fk = LandedFake()
        out = tmp / "out-p7"
        r = run(fpre, out, [bad], tok, fk.url)
        fk.close()
        ok = r.returncode == 1 and "refused" in r.stderr and len(fk.calls) == 0
        report("p7_answer_refused", ok, "exit 1, add_witness's refusal relayed, no anchor call", f"exit {r.returncode}, calls {len(fk.calls)}, stderr: {r.stderr.strip()[-200:]}")
        no_token("p7", r)

        # p9 to p11: TLS as armarium-dev serves it (13 Nov 2026): a private CA, a server certificate whose SAN names the in-cluster service
        # only (no IP, no localhost), reached through a port-forward on 127.0.0.1
        import ssl as ssl_
        pki = tmp / "pki"
        pki.mkdir()
        SNI = "armarium-service.armarium-dev.svc"

        def ossl(*a):
            subprocess.run(["openssl", *a], check=True, capture_output=True)

        def make_ca(name):
            ossl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
                 "-subj", f"/CN={name}", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                 "-keyout", str(pki / f"{name}.key"), "-out", str(pki / f"{name}.crt"))

        make_ca("test-ca")
        make_ca("other-ca")
        (pki / "san.ext").write_text(f"subjectAltName=critical,DNS:armarium-service,DNS:{SNI}\nbasicConstraints=critical,CA:FALSE\n"
                                     "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n", encoding="utf-8")
        ossl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-subj", "/", "-keyout", str(pki / "srv.key"),
             "-out", str(pki / "srv.csr"))
        ossl("x509", "-req", "-in", str(pki / "srv.csr"), "-CA", str(pki / "test-ca.crt"), "-CAkey", str(pki / "test-ca.key"),
             "-CAcreateserial", "-days", "2", "-extfile", str(pki / "san.ext"), "-out", str(pki / "srv.crt"))

        def tls_fake(statuses):
            fk_ = LandedFake()
            fk_.statuses = statuses
            sctx = ssl_.SSLContext(ssl_.PROTOCOL_TLS_SERVER)
            sctx.load_cert_chain(str(pki / "srv.crt"), str(pki / "srv.key"))
            fk_.httpd.socket = sctx.wrap_socket(fk_.httpd.socket, server_side=True)
            fk_.url = f"https://127.0.0.1:{fk_.httpd.server_address[1]}"
            return fk_

        def tls_run(name, extra, statuses=(200,)):
            fk_ = tls_fake(list(statuses))
            o = tmp / f"out-{name}"
            rr = run(fpre, o, [ans], tok, fk_.url, extra)
            fk_.close()
            return fk_, o, rr

        # p9: the CA and the in-cluster name given: landed, K14 PASS
        fk, out, r = tls_run("p9", ["--anchor-ca", str(pki / "test-ca.crt"), "--anchor-server-name", SNI])
        anc = json.loads((out / "anchors.json").read_text()) if (out / "anchors.json").exists() else None
        ok = r.returncode == 0 and len(fk.calls) == 1 and isinstance(anc, list) and len(anc) == 1 and "K14 PASS" in r.stdout
        report("p9_tls_private_ca_and_server_name", ok, "over TLS to 127.0.0.1 with --anchor-ca and --anchor-server-name: one POST, landed, one anchor entry, K14 PASS, exit 0",
               f"exit {r.returncode}, calls {len(fk.calls)}, anchors {len(anc) if isinstance(anc, list) else anc}, K14 PASS {'K14 PASS' in r.stdout}",
               [f"stderr: {r.stderr.strip()[-300:]}"])
        no_token("p9", r)

        # p10: the CA but no server name: the certificate does not name 127.0.0.1, so the call is refused by TLS, at once (no retries), exit 1,
        # and nothing reaches the service
        fk, out, r = tls_run("p10", ["--anchor-ca", str(pki / "test-ca.crt"), "--anchor-retries", "3"])
        anc = json.loads((out / "anchors.json").read_text()) if (out / "anchors.json").exists() else None
        mism = "IP address mismatch" in r.stderr or "Hostname mismatch" in r.stderr
        ok = r.returncode == 1 and len(fk.calls) == 0 and anc == [] and "TLS" in r.stderr and "--anchor-server-name" in r.stderr and mism
        report("p10_tls_name_mismatch_refused", ok, "exit 1 at once, no request served, anchors.json [], stderr names TLS, the NAME mismatch (not another verify error), and points at --anchor-server-name",
               f"exit {r.returncode}, calls {len(fk.calls)}, anchors {anc}, stderr: {r.stderr.strip()[-240:]}")
        no_token("p10", r)

        # p11: another CA: refused by TLS, exit 1, nothing sent
        fk, out, r = tls_run("p11", ["--anchor-ca", str(pki / "other-ca.crt"), "--anchor-server-name", SNI, "--anchor-retries", "3"])
        anc = json.loads((out / "anchors.json").read_text()) if (out / "anchors.json").exists() else None
        ok = r.returncode == 1 and len(fk.calls) == 0 and anc == [] and "TLS" in r.stderr and "unable to get local issuer certificate" in r.stderr
        report("p11_tls_wrong_ca_refused", ok, "exit 1 at once, no request served, anchors.json [], stderr names TLS and the issuer failure",
               f"exit {r.returncode}, calls {len(fk.calls)}, anchors {anc}, stderr: {r.stderr.strip()[-240:]}")
        no_token("p11", r)

        # p12: --anchor-ca names a file that does not exist: a usage error before anything is written
        out = tmp / "out-p12"
        r = run(fpre, out, [ans], tok, "https://127.0.0.1:9", ["--anchor-ca", str(pki / "missing.crt")])
        ok = r.returncode == 2 and not out.exists()
        report("p12_anchor_ca_missing", ok, "exit 2, --out not created", f"exit {r.returncode}, out exists {out.exists()}, stderr: {r.stderr.strip()[-160:]}")
    print(f"{sum(RESULTS)} of {len(RESULTS)} cases gave the expected result; MISMATCH {sum(1 for x in RESULTS if not x)}")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
