"""package.py: the packager (claims-snapshot 0.6; step 1d of the evidence tooling). It takes a published auditor folder (pre-witness or
complete), inserts each witness answer with add_witness.py, anchors the signatures file on an armarium anchor chain, writes anchors.json
(section 3a, K14) and runs check.py on the result. Nothing in the input folder is changed: the package is written to --out.

usage: python3 -I package.py <folder> --out <new folder> --key <ssh private key> --identity <principal> [--answer <answer>]...
                             [--anchor-url <armarium-service URL> --anchor-chain <chain> --anchor-token-file <file>]
                             [--anchor-ca <CA certificate file>] [--anchor-server-name <name in the certificate>]
                             [--anchor-retries N (default 5)] [--anchor-wait SECONDS (default 10)]

--key and --identity are the adder's, passed to add_witness.py (it re-signs the manifest). The token file holds the bearer token the
armarium service minted for this caller (scope anchor:write, the chain in its bind, an anchor grant); its value is never printed.

TLS (13 Nov 2026, armarium-dev): an https URL is verified against --anchor-ca (else the system's CAs), and the certificate must name
--anchor-server-name (else the URL's host). armarium-dev's certificate names armarium-service.armarium-dev.svc and no IP, so a caller on a
port-forward passes --anchor-url https://127.0.0.1:<port> --anchor-server-name armarium-service.armarium-dev.svc. A TLS refusal is final:
nothing was sent, no retry, exit 1.

The anchor (armarium-service README "The /anchor surface", dev/ndim 4375ba30): POST <url>/anchor/<chain>/records with
{"key", "format": "claims-snapshot/anchor/1", "payload": base64 of one compact JSON object of at most 2048 bytes}. The object names
"over": "sha256:<hex of signatures.json>" (the signatures file fixes every signature at once), the manifest's hash and the folder's
format. The key is fixed by the signatures file's hash, so a repeat of the same package is the same request: 202 in_doubt and 503
not_sent are repeated with the SAME key, as the service's contract asks; a landed key answers its stored result.

Exit codes: 0 packaged and check.py found no FAIL; 1 a step refused (add_witness, a 4xx from the anchor, check.py FAIL); 2 a usage error
or --out exists; 3 packaged but not anchored yet (in_doubt or not_sent after the retries): run the same command again on a fresh --out,
or repeat the named key."""
import base64
import hashlib
import http.client
import json
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
ANCHOR_FORMAT = "claims-snapshot/anchor/1"


def sha256(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


def arg(argv, name, default=None, many=False):
    vals = [argv[i + 1] for i, a in enumerate(argv) if a == name and i + 1 < len(argv)]
    if many:
        return vals
    return vals[-1] if vals else default


def check_summary(out):
    r = subprocess.run([sys.executable, "-I", str(HERE / "check.py"), str(out)], capture_output=True, text=True)
    print(r.stdout, end="")
    s = next((l for l in r.stdout.splitlines() if l.startswith("SUMMARY")), None)
    return r.returncode, s


class _Https(http.client.HTTPSConnection):
    """An HTTPS connection whose certificate is checked against `sni`, not the host it connects to (a port-forward)."""

    def __init__(self, host, port, ctx, sni, timeout):
        super().__init__(host, port, context=ctx, timeout=timeout)
        self._ctx, self._sni = ctx, sni

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._ctx.wrap_socket(sock, server_hostname=self._sni)


def post(url, token, body, tls=None):
    """(status, answer). status None: unreachable (retried); status "tls": the certificate was refused (final, nothing sent)."""
    u = urllib.parse.urlsplit(url)
    if u.scheme == "https":
        ctx, sni = tls if tls else (ssl.create_default_context(), None)
        conn = _Https(u.hostname, u.port or 443, ctx, sni or u.hostname, 60)
        try:
            conn.request("POST", u.path or "/", body=json.dumps(body).encode(),
                         headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
            r = conn.getresponse()
            data = r.read()
            try:
                return r.status, json.loads(data or b"{}")
            except ValueError:
                return r.status, {}
        except ssl.SSLError as e:
            return "tls", {"error": "tls", "message": f"{type(e).__name__}: {getattr(e, 'verify_message', None) or e.reason or e}"}
        except (OSError, http.client.HTTPException) as e:
            return None, {"error": "unreachable", "message": type(e).__name__}
        finally:
            conn.close()
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return None, {"error": "unreachable", "message": type(e).__name__}


def anchor(out, url, chain, token, retries, wait, tls=None):
    """Returns (exit code, the anchors.json entry or None). Never prints the token."""
    sig_h = sha256(out / "signatures.json")
    payload = {"over": f"sha256:{sig_h}", "file": "signatures.json", "manifest_sha256": sha256(out / "manifest.json")}
    try:
        payload["format"] = json.loads((out / "manifest.json").read_text(encoding="utf-8")).get("format")
    except (ValueError, AttributeError):
        pass
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    if len(raw) > 2048:
        print(f"not anchored: the anchor payload is {len(raw)} bytes, the service takes at most 2048", file=sys.stderr)
        return 1, None
    key = f"claims-snapshot-anchor-{sig_h[:40]}"
    body = {"key": key, "format": ANCHOR_FORMAT, "payload": base64.b64encode(raw).decode()}
    target = url.rstrip("/") + f"/anchor/{chain}/records"
    last = None
    for attempt in range(retries + 1):
        status, ans = post(target, token, body, tls)
        last = (status, ans)
        if status == "tls":
            print(f"not anchored: TLS refused the service's certificate ({ans.get('message')}); nothing was sent. Check --anchor-ca, and "
                  f"pass --anchor-server-name with the name the certificate holds when the URL's host is not that name (a port-forward)",
                  file=sys.stderr)
            return 1, None
        if status == 200 and ans.get("state") == "landed":
            ref = ans.get("ref") or {}
            return 0, {"over": f"sha256:{sig_h}", "method": "armarium", "ref": ref, "time": ans.get("block_time"), "proof_file": None}
        if status in (202, 503, None):
            if attempt < retries:
                time.sleep(wait)
            continue
        err = ans.get("error") or ans.get("state") or "error"
        print(f"not anchored: the service answered {status} {err}: {str(ans.get('message', ''))[:200]}", file=sys.stderr)
        return 1, None
    status, ans = last
    state = ans.get("state") or ans.get("error") or "no answer"
    print(f"not anchored yet: the service answered {status} {state} {retries + 1} time(s); repeat the same request with key {key} "
          f"(never a new key for it), or run this command again", file=sys.stderr)
    return 3, None


def main(argv):
    if len(argv) < 2 or argv[1].startswith("--"):
        print(__doc__)
        return 2
    src = pathlib.Path(argv[1])
    out_s, key, ident = arg(argv, "--out"), arg(argv, "--key"), arg(argv, "--identity")
    if not out_s or not key or not ident:
        print("usage: --out, --key and --identity are required (see the docstring)", file=sys.stderr)
        return 2
    out = pathlib.Path(out_s)
    if out.exists():
        print(f"refused: {out} exists; the package is written to a new folder, nothing changed", file=sys.stderr)
        return 2
    if not (src / "manifest.json").is_file():
        print(f"refused: {src} holds no manifest.json", file=sys.stderr)
        return 2
    url, chain, tokfile = arg(argv, "--anchor-url"), arg(argv, "--anchor-chain"), arg(argv, "--anchor-token-file")
    if url and not (chain and tokfile):
        print("usage: --anchor-url needs --anchor-chain and --anchor-token-file", file=sys.stderr)
        return 2
    token = None
    if url:
        try:
            token = pathlib.Path(tokfile).read_text(encoding="utf-8").strip()
        except OSError as e:
            print(f"refused: the token file is unreadable ({type(e).__name__}), nothing written", file=sys.stderr)
            return 2
        if not token:
            print("refused: the token file is empty, nothing written", file=sys.stderr)
            return 2
    tls = None
    ca, sni = arg(argv, "--anchor-ca"), arg(argv, "--anchor-server-name")
    if url and (ca or sni):
        try:
            tls = (ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context(), sni)
        except (OSError, ssl.SSLError) as e:
            print(f"refused: --anchor-ca is unreadable as a CA certificate ({type(e).__name__}), nothing written", file=sys.stderr)
            return 2
    try:
        retries, wait = int(arg(argv, "--anchor-retries", "5")), float(arg(argv, "--anchor-wait", "10"))
    except ValueError:
        print("usage: --anchor-retries is an integer and --anchor-wait a number of seconds", file=sys.stderr)
        return 2
    shutil.copytree(src, out)
    for p in (out / "CHECK.json", out / "CHECK.txt"):
        p.unlink(missing_ok=True)
    for a in arg(argv, "--answer", many=True):
        r = subprocess.run([sys.executable, "-I", str(HERE / "add_witness.py"), str(out), str(a), "--key", key, "--identity", ident],
                           capture_output=True, text=True)
        if r.returncode != 0:
            sys.stderr.write(r.stderr)
            print(f"stopped: add_witness.py exit {r.returncode} on {a}; the partial package is left in {out} for reading, nothing anchored", file=sys.stderr)
            return 1
        print(f"witness inserted from {a}")
    anc_p = out / "anchors.json"
    try:
        anchors = json.loads(anc_p.read_text(encoding="utf-8")) if anc_p.exists() else []
    except ValueError:
        print("refused: anchors.json in the folder is not JSON", file=sys.stderr)
        return 1
    if not isinstance(anchors, list):
        print("refused: anchors.json in the folder is not a list", file=sys.stderr)
        return 1
    rc_anchor = 0
    if url:
        rc_anchor, entry = anchor(out, url, chain, token, retries, wait, tls)
        if entry:
            anchors.append(entry)
            print(f"anchored on {chain}: block {entry['ref'].get('block')}, tx {entry['ref'].get('tx_hash')}")
    else:
        print("not anchored: no --anchor-url given; anchors.json lists no anchor for this package")
    anc_p.write_text(json.dumps(anchors, indent=1) + "\n", encoding="utf-8")
    rc_check, s = check_summary(out)
    if rc_anchor:
        return rc_anchor
    return 0 if rc_check == 0 and s and " 0 failed" in s else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
