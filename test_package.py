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
  p13 to p26, the packager gate's findings (the claims session, 13 Nov 2026, gate/2026-11-13-packager-1d/RESULT.md):
      p13/p14 a service body echoing the Authorization header never puts the token on stderr (F1a); p15 a token file with an inner
      newline is refused at read, exit 2, no traceback (F1b); p16 plain http is refused without --anchor-allow-http; p17 a redirect is
      not followed and the second host gets nothing (F2); p18 --out inside the input is refused, the input unchanged (F3); p19 an
      input whose anchors.json lists an entry is refused (F4, the owner's rule); p20-p22 a landed answer with a ref that is not an
      object, a 200 that is not JSON or is a list: exit 1, named, no traceback; p23 a dangling symlink at --out, p24 a negative retry
      count or a wait that is negative or nan: exit 2 (F5); p25 a break after the request arrived is in doubt, repeated with the
      same key, exit 3, never "nothing was sent" (F6); p26 --anchor-ca with an http URL is refused; p27 (the owner's) a landed
      ref echoing the token never puts it on stdout.
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


def run(parent, out, answers, tokfile=None, url=None, extra=(), no_allow_http=False, chain=CHAIN, timeout=None):
    cmd = [sys.executable, "-I", str(HERE / "package.py"), str(parent), "--out", str(out), "--key", str(m.KEYS["adder"]), "--identity", m.ADDER]
    for a in answers:
        cmd += ["--answer", str(a)]
    if url:
        cmd += ["--anchor-url", url, "--anchor-chain", chain, "--anchor-token-file", str(tokfile), "--anchor-wait", "0"]
        if url.startswith("http://") and not no_allow_http:
            cmd += ["--anchor-allow-http"]  # the fakes speak plain http; a real run refuses it (p16)
    cmd += list(extra)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


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

        # p13 to p27: the packager gate's findings (the claims session, 13 Nov 2026, gate/2026-11-13-packager-1d/RESULT.md)
        import math  # noqa: F401
        import os as os_

        class ScriptFake:
            """Answers each request by `fn(n, method, path, headers, body) -> (status, bytes, headers)`; `calls` logs every request."""

            def __init__(self, fn, tls_ctx=None):
                self.calls = []
                me = self

                class H(BaseHTTPRequestHandler):
                    def _any(self):
                        n = int(self.headers.get("Content-Length") or 0)
                        body = self.rfile.read(n) if n else b""
                        me.calls.append({"method": self.command, "path": self.path, "auth": self.headers.get("Authorization")})
                        status, data, hdrs = fn(len(me.calls), self.command, self.path, self.headers, body)
                        if status is None:
                            self.close_connection = True
                            try:
                                self.connection.shutdown(2)
                            except OSError:
                                pass
                            return
                        self.send_response(status)
                        for k, v in (hdrs or {}).items():
                            self.send_header(k, v)
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)

                    do_POST = _any
                    do_GET = _any

                    def log_message(self, *a):
                        pass

                self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
                if tls_ctx is not None:
                    self.httpd.socket = tls_ctx.wrap_socket(self.httpd.socket, server_side=True)
                scheme = "https" if tls_ctx is not None else "http"
                self.url = f"{scheme}://127.0.0.1:{self.httpd.server_address[1]}"
                threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

            def close(self):
                self.httpd.shutdown()

        def js(o):
            return json.dumps(o).encode()

        def leaked(r):
            return TOKEN in r.stdout or TOKEN in r.stderr

        def tb(r):
            return "Traceback" in r.stderr

        # p13: a 401 whose body echoes the Authorization header (a proxy's debug page): the token never reaches stderr
        fk = ScriptFake(lambda n, m, p, h, b: (401, js({"error": "unauthorized", "message": "bad header: " + str(h.get("Authorization"))}), {}))
        out = tmp / "out-p13"
        r = run(fpre, out, [ans], tok, fk.url)
        fk.close()
        ok = r.returncode == 1 and not leaked(r) and not tb(r) and "401" in r.stderr
        report("p13_echoed_token_in_4xx_not_printed", ok, "exit 1, the status named, the token absent from stdout and stderr, no traceback",
               f"exit {r.returncode}, leaked {leaked(r)}, traceback {tb(r)}, stderr: {r.stderr.strip()[-200:].replace(TOKEN, '<TOKEN>')}")

        # p14: 503 with a state echoing the token, retries exhausted: exit 3 with the key, the token absent
        fk = ScriptFake(lambda n, m, p, h, b: (503, js({"state": "not_sent " + str(h.get("Authorization")), "error": str(h.get("Authorization"))}), {}))
        out = tmp / "out-p14"
        r = run(fpre, out, [ans], tok, fk.url, ["--anchor-retries", "1"])
        fk.close()
        ok = r.returncode == 3 and not leaked(r) and not tb(r) and "claims-snapshot-anchor-" in r.stderr
        report("p14_echoed_token_in_retry_state_not_printed", ok, "exit 3, the key named, the token absent, no traceback",
               f"exit {r.returncode}, leaked {leaked(r)}, traceback {tb(r)}, stderr: {r.stderr.strip()[-200:].replace(TOKEN, '<TOKEN>')}")

        # p15: a token file holding a newline inside the value: refused at read, exit 2, nothing written, no traceback, the token absent
        tok2 = tmp / "anchor-nl.token"
        tok2.write_text(TOKEN[:8] + "\n" + TOKEN[8:] + "\n", encoding="utf-8")
        out = tmp / "out-p15"
        fk = ScriptFake(lambda n, m, p, h, b: (200, js(landed("k")), {}))
        r = run(fpre, out, [ans], tok2, fk.url)
        fk.close()
        part_leak = TOKEN[:8] in r.stderr or TOKEN[8:] in r.stderr or TOKEN[8:] in r.stdout
        ok = r.returncode == 2 and not out.exists() and not tb(r) and not part_leak and len(fk.calls) == 0
        report("p15_token_with_inner_newline_refused", ok, "exit 2 before anything is written, no request, no traceback, no part of the token printed",
               f"exit {r.returncode}, out {out.exists()}, calls {len(fk.calls)}, traceback {tb(r)}, part printed {part_leak}")

        # p16: an http URL without --anchor-allow-http: refused, exit 2, no request
        fk = ScriptFake(lambda n, m, p, h, b: (200, js(landed("k")), {}))
        out = tmp / "out-p16"
        r = run(fpre, out, [ans], tok, fk.url, no_allow_http=True)
        fk.close()
        ok = r.returncode == 2 and len(fk.calls) == 0 and not out.exists() and "http" in r.stderr
        report("p16_plain_http_refused_by_default", ok, "exit 2, no request, --out not created, stderr names http",
               f"exit {r.returncode}, calls {len(fk.calls)}, out {out.exists()}, stderr: {r.stderr.strip()[-160:]}")

        # p17: a 302 to a second host: not followed, the second host gets nothing, no anchor entry, exit 1
        fk2 = ScriptFake(lambda n, m, p, h, b: (200, js(landed("k")), {}))
        fk = ScriptFake(lambda n, m, p, h, b: (302, b"", {"Location": fk2.url + "/anchor/argus-dev-poa/records"}))
        out = tmp / "out-p17"
        r = run(fpre, out, [ans], tok, fk.url)
        fk.close()
        fk2.close()
        anc = json.loads((out / "anchors.json").read_text()) if (out / "anchors.json").exists() else None
        ok = r.returncode == 1 and len(fk2.calls) == 0 and anc in ([], None) and not leaked(r) and "redirect" in r.stderr
        report("p17_redirect_not_followed", ok, "exit 1, the second host never called, no anchor entry, stderr says a redirect was not followed",
               f"exit {r.returncode}, first calls {len(fk.calls)}, second calls {len(fk2.calls)}, anchors {anc}, stderr: {r.stderr.strip()[-160:]}")

        # p18: --out inside the input folder: refused, exit 2, the input unchanged
        inp = tmp / "input-p18"
        shutil.copytree(fpre, inp)
        before = tree(inp)
        r = run(inp, inp / "pkg", [ans])
        ok = r.returncode == 2 and tree(inp) == before and not (inp / "pkg").exists()
        report("p18_out_inside_input_refused", ok, "exit 2, the input unchanged by hash, no pkg/ inside it",
               f"exit {r.returncode}, unchanged {tree(inp) == before}, pkg {(inp / 'pkg').exists()}, stderr: {r.stderr.strip()[-160:]}")

        # p19: an input whose anchors.json already lists an entry: refused, exit 2, nothing written (the owner's rule for F4)
        inp = tmp / "input-p19"
        shutil.copytree(fpre, inp)
        (inp / "anchors.json").write_text(json.dumps([{"over": "sha256:" + "0" * 64, "method": "armarium", "ref": {}, "time": None, "proof_file": None}]) + "\n",
                                          encoding="utf-8")
        out = tmp / "out-p19"
        r = run(inp, out, [ans])
        ok = r.returncode == 2 and not out.exists() and "anchors.json" in r.stderr
        report("p19_input_with_anchors_refused", ok, "exit 2, --out not created, stderr names anchors.json",
               f"exit {r.returncode}, out {out.exists()}, stderr: {r.stderr.strip()[-160:]}")

        # p20 to p22: a landed answer whose ref is not an object, a 200 whose body is not JSON, a 200 whose body is a JSON list: exit 1, named, no traceback
        for name, mk in (("p20_landed_ref_a_string", lambda: js(dict(landed("k"), ref="0xabc"))),
                         ("p20b_landed_ref_null", lambda: js(dict(landed("k"), ref=None))),
                         ("p21_200_body_not_json", lambda: b"<html>ok</html>"),
                         ("p22_200_body_a_list", lambda: js([landed("k")]))):
            fk = ScriptFake(lambda n, m, p, h, b, mk=mk: (200, mk(), {}))
            out = tmp / f"out-{name}"
            r = run(fpre, out, [ans], tok, fk.url)
            fk.close()
            anc = json.loads((out / "anchors.json").read_text()) if (out / "anchors.json").exists() else None
            ok = r.returncode == 1 and not tb(r) and anc in ([], None) and "claims-snapshot-anchor-" in r.stderr
            report(name, ok, "exit 1, no traceback, no anchor entry, stderr names the key to repeat",
                   f"exit {r.returncode}, traceback {tb(r)}, anchors {anc}, stderr: {r.stderr.strip()[-160:]}")

        # p23: a dangling symlink at --out: refused, exit 2, nothing written through it
        out = tmp / "out-p23"
        target = tmp / "p23-target-never"
        out.symlink_to(target)
        r = run(fpre, out, [ans])
        ok = r.returncode == 2 and not target.exists() and not tb(r)
        report("p23_dangling_symlink_out_refused", ok, "exit 2, the target never created, no traceback",
               f"exit {r.returncode}, target {target.exists()}, traceback {tb(r)}")

        # p24: bad retry arguments: exit 2 before anything is written
        for name, extra in (("p24_retries_negative", ["--anchor-retries", "-1"]), ("p24b_wait_nan", ["--anchor-wait", "nan"]),
                            ("p24c_wait_negative", ["--anchor-wait", "-1"])):
            out = tmp / f"out-{name}"
            r = run(fpre, out, [ans], tok, "http://127.0.0.1:9", [x for x in extra])
            ok = r.returncode == 2 and not out.exists() and not tb(r)
            report(name, ok, "exit 2, --out not created, no traceback", f"exit {r.returncode}, out {out.exists()}, traceback {tb(r)}")

        # p25: TLS completes, the request arrives, then the connection breaks: in doubt, repeated with the same key, exit 3, never "nothing was sent"
        sctx = ssl_.SSLContext(ssl_.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(str(pki / "srv.crt"), str(pki / "srv.key"))
        fk = ScriptFake(lambda n, m, p, h, b: (None, b"", {}), tls_ctx=sctx)
        out = tmp / "out-p25"
        r = run(fpre, out, [ans], tok, fk.url, ["--anchor-ca", str(pki / "test-ca.crt"), "--anchor-server-name", SNI, "--anchor-retries", "1"])
        fk.close()
        ok = r.returncode == 3 and len(fk.calls) == 2 and "nothing was sent" not in r.stderr and not tb(r)
        report("p25_break_after_request_is_in_doubt", ok, "two requests (the same key repeated), exit 3, stderr never says nothing was sent",
               f"exit {r.returncode}, calls {len(fk.calls)}, stderr: {r.stderr.strip()[-200:]}")

        # p26: --anchor-ca with an http URL: refused (it would be ignored), exit 2
        out = tmp / "out-p26"
        r = run(fpre, out, [ans], tok, "http://127.0.0.1:9", ["--anchor-ca", str(pki / "test-ca.crt")])
        ok = r.returncode == 2 and not out.exists()
        report("p26_ca_with_http_refused", ok, "exit 2, --out not created", f"exit {r.returncode}, out {out.exists()}, stderr: {r.stderr.strip()[-160:]}")

        # p27 (the owner's, after the fix's own review): a landed ref whose tx_hash and block echo the token: the "anchored on" line never prints it
        fk = ScriptFake(lambda n, m, p, h, b: (200, js(dict(landed("k"), ref={"chain": CHAIN, "block": str(h.get("Authorization")),
                                                                                   "tx_hash": str(h.get("Authorization"))})), {}))
        out = tmp / "out-p27"
        r = run(fpre, out, [ans], tok, fk.url)
        fk.close()
        ok = not leaked(r) and not tb(r)
        report("p27_echoed_token_in_landed_ref_not_printed", ok, "the token absent from stdout and stderr, no traceback",
               f"exit {r.returncode}, leaked {leaked(r)}, traceback {tb(r)}")

        # p28 to p37: the packager re-gate's findings (the claims session, 13 Nov 2026, gate/2026-11-13-packager-1d-regate/RESULT.md)
        def anchors_of(out):
            p = out / "anchors.json"
            return p.read_text(encoding="utf-8") if p.is_file() else ""

        # p28 (G01): a token made only of [a-z_] echoed as the error of a 401 and as the state of a 503: never printed, whole or in part
        wtok_v = "tok_" + "qwertyuiopasdfghjklzxcvbnmqwer"
        wtok = tmp / "anchor-word.token"
        wtok.write_text(wtok_v + "\n", encoding="utf-8")
        for name, script in (("p28_word_token_echoed_as_401_error", lambda n, m_, p, h, b: (401, js({"error": wtok_v}), {})),
                             ("p28b_word_token_echoed_as_503_state", lambda n, m_, p, h, b: (503, js({"state": wtok_v}), {})),
                             ("p28c_word_token_piece_echoed_as_error", lambda n, m_, p, h, b: (401, js({"error": wtok_v[4:20]}), {}))):
            fk = ScriptFake(script)
            out = tmp / f"out-{name}"
            r = run(fpre, out, [ans], wtok, fk.url, ["--anchor-retries", "1"])
            fk.close()
            lk = wtok_v in r.stdout + r.stderr or wtok_v[4:20] in r.stdout + r.stderr
            ok = r.returncode in (1, 3) and not lk and not tb(r)
            report(name, ok, "exit 1 or 3, the token and its pieces absent from stdout and stderr, no traceback",
                   f"exit {r.returncode}, leaked {lk}, traceback {tb(r)}")

        # p29 (X01): a 64-hex token echoed as the correlation_id or inside the tx_hash of a landed answer: refused, not recorded, not printed
        htok_v = "9f" * 32
        htok = tmp / "anchor-hex.token"
        htok.write_text(htok_v + "\n", encoding="utf-8")
        for name, ref in (("p29_hex_token_as_correlation_id", {"correlation_id": htok_v}),
                          ("p29b_hex_token_piece_as_correlation_id", {"correlation_id": htok_v[:32]}),
                          ("p29c_hex_token_as_tx_hash", {"tx_hash": "0x" + htok_v})):
            fk = ScriptFake(lambda n, m_, p, h, b, ref=ref: (200, js(dict(landed("k"), ref=dict(landed("k")["ref"], **ref))), {}))
            out = tmp / f"out-{name}"
            r = run(fpre, out, [ans], htok, fk.url)
            fk.close()
            piece = htok_v[:32]
            lk = piece in r.stdout + r.stderr or piece in anchors_of(out)
            ok = r.returncode == 1 and not lk and not tb(r) and "claims-snapshot-anchor-" in r.stderr
            report(name, ok, "exit 1, the key named, the token absent from stdout, stderr and anchors.json, no traceback",
                   f"exit {r.returncode}, leaked {lk}, traceback {tb(r)}, stderr: {r.stderr.strip()[-160:]}")

        # p30 (H05) and p31 (H04d): a URL with a query, a fragment, userinfo, no host, a bad port or a space: refused at read, exit 2, no request
        fk = ScriptFake(lambda n, m_, p, h, b: (200, js(landed("k")), {}))
        port = fk.url.rsplit(":", 1)[1]
        for name, u in (("p30_url_with_query", fk.url + "/base?x=1"), ("p30b_url_with_fragment", fk.url + "/base#f"),
                        ("p30c_url_with_userinfo", f"http://user:pw@127.0.0.1:{port}"), ("p31_url_no_host", "https:///no-host"),
                        ("p31b_url_port_no_host", f"https://:{port}"), ("p31c_url_bad_port", "https://127.0.0.1:abc"),
                        ("p31d_url_with_space", fk.url + "/a b")):
            out = tmp / f"out-{name}"
            r = run(fpre, out, [ans], tok, u)
            ok = r.returncode == 2 and not out.exists() and not tb(r)
            report(name, ok, "exit 2, --out not created, no traceback", f"exit {r.returncode}, out {out.exists()}, traceback {tb(r)}, stderr: {r.stderr.strip()[-160:]}")
        n_calls = len(fk.calls)
        fk.close()
        report("p31e_no_request_for_any_refused_url", n_calls == 0, "0 requests", f"{n_calls} requests")

        # p32 (H06): a chain outside armarium's name rule (pkg/armarium/engine/engine.go:202): refused at read, exit 2, no request
        fk = ScriptFake(lambda n, m_, p, h, b: (200, js(landed("k")), {}))
        for name, ch in (("p32_chain_with_slash", "argus/dev"), ("p32b_chain_dotdot", "../../evil"), ("p32c_chain_percent", "%2e%2e"),
                         ("p32d_chain_space", "a b"), ("p32e_chain_crlf", "a\r\nX: y"), ("p32f_chain_empty_leading_dash", "-x")):
            out = tmp / f"out-{name}"
            r = run(fpre, out, [ans], tok, fk.url, chain=ch)
            ok = r.returncode == 2 and not out.exists() and not tb(r)
            report(name, ok, "exit 2, --out not created, no traceback", f"exit {r.returncode}, out {out.exists()}, traceback {tb(r)}")
        n_calls = len(fk.calls)
        fk.close()
        report("p32g_no_request_for_any_refused_chain", n_calls == 0, "0 requests", f"{n_calls} requests")

        # p33 (Q02): the input's anchors.json as a directory, a FIFO, or a symlink: refused before reading, exit 2, nothing written
        outside = tmp / "p33-outside.json"
        outside.write_text("[]\n", encoding="utf-8")
        for name, mk in (("p33_anchors_a_directory", lambda p: p.mkdir()), ("p33b_anchors_a_fifo", lambda p: os_.mkfifo(p)),
                         ("p33c_anchors_a_symlink", lambda p: p.symlink_to(outside)),
                         ("p33d_anchors_a_dangling_symlink", lambda p: p.symlink_to(tmp / "p33-nowhere"))):
            inp = tmp / f"input-{name}"
            shutil.copytree(fpre, inp)
            (inp / "anchors.json").unlink(missing_ok=True)
            mk(inp / "anchors.json")
            out = tmp / f"out-{name}"
            try:
                r = run(inp, out, [ans], timeout=30)
                rc, t = r.returncode, tb(r)
            except subprocess.TimeoutExpired:
                rc, t = "timeout", False
            ok = rc == 2 and not out.exists() and not t
            report(name, ok, "exit 2 within 30 s, --out not created, no traceback", f"exit {rc}, out {out.exists()}, traceback {t}")

        # p34 (R04): a block_time with non-ASCII digits or an impossible date is recorded as null; a valid one is kept
        for name, bt, want in (("p34_block_time_fullwidth_digits", "２０２６-11-13T16:00:00Z", None),
                               ("p34b_block_time_arabic_indic_digits", "٢٠٢٦-11-13T16:00:00Z", None),
                               ("p34c_block_time_impossible_date", "2026-13-45T25:61:61Z", None),
                               ("p34d_block_time_valid_kept", "2026-11-13T16:00:00Z", "2026-11-13T16:00:00Z")):
            fk = ScriptFake(lambda n, m_, p, h, b, bt=bt: (200, js(dict(landed("k"), block_time=bt)), {}))
            out = tmp / f"out-{name}"
            r = run(fpre, out, [ans], tok, fk.url)
            fk.close()
            try:
                got = json.loads(anchors_of(out))[0].get("time")
            except (ValueError, IndexError, AttributeError):
                got = "(no entry)"
            ok = r.returncode == 0 and got == want and not tb(r)
            report(name, ok, f"exit 0, time {want!r}", f"exit {r.returncode}, time {got!r}, traceback {tb(r)}")

        # p35: a correlation_id outside armarium's shape (32 lowercase hex, anchor_routes.go:25 at dev/ndim): refused, exit 1, not recorded
        for name, cid in (("p35_correlation_id_upper_case", "C" * 32), ("p35b_correlation_id_one_char", "c"), ("p35c_correlation_id_64_hex", "c" * 64)):
            fk = ScriptFake(lambda n, m_, p, h, b, cid=cid: (200, js(dict(landed("k"), ref=dict(landed("k")["ref"], correlation_id=cid))), {}))
            out = tmp / f"out-{name}"
            r = run(fpre, out, [ans], tok, fk.url)
            fk.close()
            ok = r.returncode == 1 and cid not in anchors_of(out) and not tb(r)
            report(name, ok, "exit 1, the correlation id not recorded, no traceback", f"exit {r.returncode}, traceback {tb(r)}")

        # p36: armarium's 409 signer_unusable (PR #42) is final: exit 1 after one request, the word printed, no retry
        fk = ScriptFake(lambda n, m_, p, h, b: (409, js({"error": "signer_unusable", "message": "ARMARIUM_X is not a usable key"}), {}))
        out = tmp / "out-p36"
        r = run(fpre, out, [ans], tok, fk.url, ["--anchor-retries", "3"])
        fk.close()
        ok = r.returncode == 1 and len(fk.calls) == 1 and "409 signer_unusable" in r.stderr and "ARMARIUM_X" not in r.stderr
        report("p36_signer_unusable_is_final", ok, "exit 1, 1 request, stderr names 409 signer_unusable and not the message",
               f"exit {r.returncode}, calls {len(fk.calls)}, stderr: {r.stderr.strip()[-160:]}")

        # p37: the real armarium token shape arm1.<id>.<secret>: a landed answer with ordinary fields is still recorded (no false refusal)
        atok_v = "arm1." + "0123456789abcdef0123456789abcdef" + "." + "fedcba9876543210" * 4
        atok = tmp / "anchor-arm.token"
        atok.write_text(atok_v + "\n", encoding="utf-8")
        fk = ScriptFake(lambda n, m_, p, h, b: (200, js(landed("k")), {}))
        out = tmp / "out-p37"
        r = run(fpre, out, [ans], atok, fk.url)
        fk.close()
        ok = r.returncode == 0 and '"correlation_id": "' + "c" * 32 in anchors_of(out) and atok_v not in r.stdout + r.stderr
        report("p37_armarium_token_shape_lands", ok, "exit 0, the entry recorded, the token absent", f"exit {r.returncode}, stderr: {r.stderr.strip()[-160:]}")

        # p38 to p42: the packager's round 3 (the claims session, 13 Nov 2026, gate/2026-11-13-packager-1d-round3/RESULT.md)
        def longest_run(a, b):
            """The longest substring of b (case-insensitive) that also occurs in a."""
            a, b = a.lower(), b.lower()
            best = 0
            for i in range(len(b)):
                j = i + best + 1
                while j <= len(b) and b[i:j] in a:
                    best = j - i
                    j += 1
            return best

        secret = atok_v.rsplit(".", 1)[1]
        five11 = "0".join(secret[k * 11:(k + 1) * 11] for k in range(5))
        five11 = (five11 + "0" * 64)[:64]
        for name, ref in (("p38_secret_upper_cased_as_tx_hash", {"tx_hash": "0x" + secret.upper()}),
                          ("p38b_secret_in_11_char_pieces_as_tx_hash", {"tx_hash": "0x" + five11}),
                          ("p38c_secret_8_char_piece_in_correlation_id", {"correlation_id": secret[20:28] + "0" * 24}),
                          ("p38d_secret_upper_piece_in_correlation_id", {"correlation_id": secret[:32].upper()})):
            fk = ScriptFake(lambda n, m_, p, h, b, ref=ref: (200, js(dict(landed("k"), ref=dict(landed("k")["ref"], **ref))), {}))
            out = tmp / f"out-{name}"
            r = run(fpre, out, [ans], atok, fk.url)
            fk.close()
            run_len = longest_run(r.stdout + r.stderr + anchors_of(out), secret)
            ok = r.returncode == 1 and run_len < 8 and not tb(r)
            report(name, ok, "exit 1, no run of 8 or more secret characters in stdout, stderr or anchors.json (any case), no traceback",
                   f"exit {r.returncode}, longest run {run_len}, traceback {tb(r)}")

        # p39: URL shapes round 3 found: an unclosed IPv6 bracket, port 0, port 65536, a "%" or "_" in the host: exit 2 before anything
        for name, u in (("p39_url_unclosed_ipv6_bracket", "https://[::1:9443"), ("p39b_url_port_zero", "https://127.0.0.1:0"),
                        ("p39c_url_port_too_big", "https://127.0.0.1:65536"), ("p39d_url_percent_in_host", "https://12%7.0.0.1:9443"),
                        ("p39e_url_empty_port", "https://127.0.0.1:/")):
            out = tmp / f"out-{name}"
            r = run(fpre, out, [ans], atok, u)
            ok = r.returncode == 2 and not out.exists() and not tb(r)
            report(name, ok, "exit 2, --out not created, no traceback", f"exit {r.returncode}, out {out.exists()}, traceback {tb(r)}, stderr: {r.stderr.strip()[-160:]}")
        # an IPv6 literal and a host name stay usable (refused only by the plain-http rule here, never by the URL rule)
        for name, u in (("p39f_url_ipv6_literal_ok", "http://[::1]:9"), ("p39g_url_hostname_ok", "http://armarium-service.armarium-dev.svc:9")):
            out = tmp / f"out-{name}"
            r = run(fpre, out, [ans], atok, u, no_allow_http=True)
            ok = r.returncode == 2 and "plain http" in r.stderr and not tb(r)
            report(name, ok, "the URL rule passes it (the plain-http refusal is what stops it)", f"exit {r.returncode}, stderr: {r.stderr.strip()[-160:]}")

        # p40: a FIFO, a socket-like special file, or a symbolic link anywhere in the input: refused before the copy, exit 2, nothing written
        for name, rel, mk in (("p40_fifo_inside_input", "sources/files/pipe", lambda p: os_.mkfifo(p)),
                              ("p40b_symlink_to_outside_inside_input", "sources/files/leak.txt", lambda p: p.symlink_to(outside)),
                              ("p40c_symlinked_dir_inside_input", "sources/linked", lambda p: p.symlink_to(tmp, target_is_directory=True))):
            inp = tmp / f"input-{name}"
            shutil.copytree(fpre, inp)
            (inp / rel).parent.mkdir(parents=True, exist_ok=True)
            mk(inp / rel)
            out = tmp / f"out-{name}"
            try:
                r = run(inp, out, [ans], timeout=30)
                rc, t = r.returncode, tb(r)
            except subprocess.TimeoutExpired:
                rc, t = "timeout", False
            ok = rc == 2 and not out.exists() and not t
            report(name, ok, "exit 2 within 30 s, --out not created, no traceback", f"exit {rc}, out {out.exists()}, traceback {t}")

        # p41: with the real token shape, the service's plain words are still printed (no false refusal from the run rule)
        for name, st, w in (("p41_401_unauthorized_printed", 401, "unauthorized"), ("p41b_403_forbidden_printed", 403, "forbidden"),
                            ("p41c_409_signer_unusable_printed", 409, "signer_unusable")):
            fk = ScriptFake(lambda n, m_, p, h, b, st=st, w=w: (st, js({"error": w}), {}))
            out = tmp / f"out-{name}"
            r = run(fpre, out, [ans], atok, fk.url)
            fk.close()
            ok = r.returncode == 1 and f"{st} {w}" in r.stderr
            report(name, ok, f"exit 1, stderr names {st} {w}", f"exit {r.returncode}, stderr: {r.stderr.strip()[-160:]}")

        # p43 (round 4, S03/S04): an unreadable file or directory in the input: refused by name before the copy, exit 2, no traceback
        for name, rel, isdir in (("p43_unreadable_file_in_input", "sources/files/locked.txt", False),
                                 ("p43b_unreadable_dir_in_input", "sources/locked", True)):
            inp = tmp / f"input-{name}"
            shutil.copytree(fpre, inp)
            q = inp / rel
            if isdir:
                q.mkdir(parents=True)
                (q / "inside.txt").write_text("x\n", encoding="utf-8")
            else:
                q.write_text("x\n", encoding="utf-8")
            q.chmod(0)
            out = tmp / f"out-{name}"
            try:
                r = run(inp, out, [ans], timeout=30)
                rc, t, err = r.returncode, tb(r), r.stderr
            except subprocess.TimeoutExpired:
                rc, t, err = "timeout", False, ""
            q.chmod(0o700)
            ok = rc == 2 and not out.exists() and not t and "locked" in err
            report(name, ok, "exit 2, --out not created, no traceback, stderr names the path", f"exit {rc}, out {out.exists()}, traceback {t}, stderr: {err.strip()[-160:]}")

        # p44 (round 4, U01): a host with an empty or dash-edged label: refused at read, exit 2, no traceback
        for name, u in (("p44_host_empty_label", "https://a..b:9443"), ("p44b_host_only_dot", "https://.:9443"),
                        ("p44c_host_trailing_dot", "https://localhost.:9443"), ("p44d_host_label_leading_dash", "https://-a.b:9443"),
                        ("p44e_host_label_too_long", "https://" + "a" * 64 + ".b:9443")):
            out = tmp / f"out-{name}"
            r = run(fpre, out, [ans], atok, u)
            ok = r.returncode == 2 and not out.exists() and not tb(r)
            report(name, ok, "exit 2, --out not created, no traceback", f"exit {r.returncode}, out {out.exists()}, traceback {tb(r)}, stderr: {r.stderr.strip()[-160:]}")

        # p42: a tx_hash that shares a run of 7 hex with the secret by chance is still recorded (the run rule is 8)
        tx7 = (secret[:7] + "1" * 64)[:64]
        if longest_run(atok_v, tx7) == 7:
            fk = ScriptFake(lambda n, m_, p, h, b: (200, js(dict(landed("k"), ref=dict(landed("k")["ref"], tx_hash="0x" + tx7))), {}))
            out = tmp / "out-p42"
            r = run(fpre, out, [ans], atok, fk.url)
            fk.close()
            ok = r.returncode == 0 and tx7 in anchors_of(out)
            report("p42_seven_char_chance_run_still_recorded", ok, "exit 0, the tx_hash recorded", f"exit {r.returncode}, stderr: {r.stderr.strip()[-160:]}")
        else:
            report("p42_seven_char_chance_run_still_recorded", False, "a 7-run fixture", f"the fixture's run is {longest_run(atok_v, tx7)}")
    print(f"{sum(RESULTS)} of {len(RESULTS)} cases gave the expected result; MISMATCH {sum(1 for x in RESULTS if not x)}")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
