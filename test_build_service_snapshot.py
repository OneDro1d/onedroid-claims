"""test_build_service_snapshot.py: E2E-P1 (mission M-20261120-EVIDENCE-E2E), written before the converter.

build_service_snapshot.py turns a finished onedroid-audit job directory (state "merged"; the argus-claims run folder inside it,
publisher-surfaces profile) into a claims-snapshot folder that check.py passes. This suite builds a fake job (a synthetic run of
twelve claims that covers every verdict path, the three confidence routes, an own-host and a third-party fetched body, a status-only
ref, a private bundle, a judge ruling, a withdrawn claim and a promise), converts it with a throwaway ed25519 key and checks:

  t01 check.py passes on the converted folder (exit 0, SUMMARY 0 failed, no FAIL line), CHECK.json written and not FAIL
  t02 audit.jsonl carries no decision field (verdict, confidence, note, history, graded_by, graded_at, witness, ...)
  t03 claims.jsonl verdicts and confidences equal the formula's rows (rows_from_run), withdrawn and promise rows included
  t04 the manifest score and counts equal the formula's (evidence_score_v1) and are not copied from a score.json
  t05 a quote of a fetched URL verifies against http-bodies (the sha of tool-fetches over http-cache) and against the copy
  t06 an own-host body is a text copy, a body of another host is hash-only (no file in sources/)
  t07 the input job is byte for byte unchanged
  t08 two conversions give identical audit.jsonl and witness bytes
  t09 a job whose state is not "merged" is refused, nothing is written
  t10 an existing --out is refused and left unchanged
  t11 the roles signed are auditor, witness, sources, manifest, and no private key or key material but the public key is in the folder
  t12 the witness is kind agent, the graders' model, primary, a self-audit in the manifest, its `on` indices inside the candidates
  t13 a grader quote that is not in the body is not published as a proof (the folder still passes)
  t14 the confidence of a contradiction: the structured field first, the note words only without it
  t15 a missing --key or --identity is a usage error (exit 2), nothing written
  t16 the development input (a real service job), when P1_DEV_RUN names its run folder: check.py passes
usage: python3 -I test_build_service_snapshot.py"""
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402

FORMULA = pathlib.Path(os.environ.get("ONEDROID_FORMULA") or "/home/coder/code/onedro1d/onedroid-score/formula/evidence_score.py")
CONVERTER = HERE / "build_service_snapshot.py"
JOB_ID = "0123456789abcdef0123456789abcdef"
IDENTITY = "onedroid-audit-test"
MODEL = "openai/gpt-6.1-terra"
DECISION_FIELDS = ("verdict", "confidence", "note", "history", "graded_by", "graded_at", "witness", "evidence_missing", "other_pass_note")

PAGE = [
    '<!doctype html>',
    '<html><head><title>Acme</title>',
    '<script type="application/ld+json">',
    '{"legalName": "Acme GmbH", "foundingDate": "2019"}',
    '</script>',
    '</head><body>',
    '<p>We have 500 customers.</p>',                          # 7  C-001
    '<p>Acme GmbH is registered in Berlin.</p>',              # 8  C-002
    '<p>We never lose data.</p>',                             # 9  C-003
    '<p>Founded in 2019.</p>',                                # 10 C-004
    '<p>Our uptime is 99.9 percent.</p>',                     # 11 C-005
    '<p>We will launch in 2027.</p>',                         # 12 C-006
    '<p>Audited by Third Party Auditors Ltd.</p>',            # 13 C-007
    '<p>Our security review is available on request.</p>',    # 14 C-008
    '<p>Our legal name is Acme GmbH.</p>',                    # 15 C-009
    '<p>Our offices have a view of the Spree.</p>',           # 16 C-010
    '<p>The team lives in Berlin.</p>',                       # 17 C-011
    '<p>Support answers within 4 hours.</p>',                 # 18 C-012
    '</body></html>',
]
PAGE_NAME = "acme.test-index.html"

BODIES = {
    "stats_old": ("https://acme.test/api/stats", b'{"customers":1,"old":true}'),
    "stats": ("https://acme.test/api/stats", b'{"customers":500,"since":"2019","support_hours":4}'),
    "status": ("https://acme.test/status", b"Incident log: data loss incident on 2026-03-02 affecting 12 customers.\n"),
    "about": ("https://acme.test/about", b"Acme was founded in 2021, in Berlin.\n"),
    "uptime": ("https://acme.test/uptime", b"Measured uptime over 12 months: 97.2 percent.\n"),
    "llms": ("https://acme.test/llms.txt", b"Acme GmbH is registered in Berlin.\n"),
    "audit": ("https://registers.example.org/audit", b"Third Party Auditors Ltd. audited Acme GmbH in 2026.\n"),
    "team": ("https://acme.test/team", b"<html><body><p>Our team of 12 lives in Berlin</p></body></html>\n"),
}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def line_of(text):
    return next(i + 1 for i, l in enumerate(PAGE) if text in l)


def page_ref(text, quote):
    return {"ref": f"sources/{PAGE_NAME}#L{line_of(text)}", "quote": quote}


def url_ref(key, quote, status=200):
    return {"ref": f"{BODIES[key][0]}#{status}", "quote": quote}


def write_jsonl(p, rows):
    pathlib.Path(p).write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")


def make_run(run):
    """The synthetic argus-claims run folder (the files of SPEC 'Input' of the E2E-P1 ticket)."""
    run = pathlib.Path(run)
    (run / "sources").mkdir(parents=True)
    (run / "http-bodies").mkdir()
    page_bytes = ("\n".join(PAGE) + "\n").encode()
    (run / "sources" / PAGE_NAME).write_bytes(page_bytes)
    (run / "sources.sha256").write_text(f"{sha(page_bytes)}  sources/{PAGE_NAME}\n", encoding="utf-8")
    for key, (_, body) in BODIES.items():
        (run / "http-bodies" / sha(body)).write_bytes(body)
    (run / "run.json").write_text(json.dumps({
        "run_id": JOB_ID, "publisher": "Acme", "domain": "acme.test", "front_door": "service", "exclusions": [], "previous_run": "none",
        "toolkit_version": "source", "models": {"prove": {"model": MODEL, "effort": "high"}, "disprove": {"model": MODEL, "effort": "high"}},
        "fetched_at": "2026-11-20T16:59:33Z", "hosts": ["acme.test"], "id_high_water": 12}, indent=1), encoding="utf-8")
    # http-cache: the page, and an OLD body for /api/stats that tool-fetches overrides (the later entry wins)
    (run / "http-cache.json").write_text(json.dumps({
        "https://acme.test/": {"bytes": len(page_bytes), "sha256": sha(page_bytes), "status": 200},
        "https://acme.test/api/stats": {"bytes": 26, "sha256": sha(BODIES["stats_old"][1]), "status": 200}}, indent=1), encoding="utf-8")
    fetches = []
    for i, key in enumerate(("stats", "status", "about", "uptime", "llms", "audit", "team")):
        url, body = BODIES[key]
        fetches.append({"url": url, "status": 200, "fetched_at": f"2026-11-20T17:00:{10 + i}Z", "sha256": sha(body), "bytes": len(body)})
    fetches.append({"url": "https://acme.test/missing", "status": 404, "fetched_at": "2026-11-20T17:00:30Z", "sha256": None, "bytes": 0})
    (run / "tool-fetches.json").write_text(json.dumps(fetches, indent=1), encoding="utf-8")
    (run / "request-sources.json").write_text(json.dumps([{"url": "https://acme.test/"}]), encoding="utf-8")

    texts = {"C-001": ("We have 500 customers.", "figure"), "C-002": ("Acme GmbH is registered in Berlin.", "status"),
             "C-003": ("We never lose data.", "negative"), "C-004": ("Founded in 2019.", "status"),
             "C-005": ("Our uptime is 99.9 percent.", "number"), "C-006": ("We will launch in 2027.", "promise"),
             "C-007": ("Audited by Third Party Auditors Ltd.", "status"), "C-008": ("Our security review is available on request.", "capability"),
             "C-009": ("Our legal name is Acme GmbH.", "status"), "C-010": ("Our offices have a view of the Spree.", "capability"),
             "C-011": ("The team lives in Berlin.", "status"), "C-012": ("Support answers within 4 hours.", "process")}
    claims = [{"id": cid, "claim": t, "sources": [{"url": "https://acme.test/", "locator": f"sources/{PAGE_NAME} L{line_of(t)}"}], "kind": k,
               "checkability": "A", "status": "new"} for cid, (t, k) in texts.items()]
    write_jsonl(run / "claims.jsonl", claims)
    prove = {
        "C-001": ("artefact", [url_ref("stats", '"customers":500')]),
        "C-002": ("restated", [url_ref("llms", "Acme GmbH is registered in Berlin.")]),
        "C-003": ("none", []), "C-004": ("none", []), "C-005": ("none", []), "C-006": ("none", []),
        "C-007": ("artefact", [url_ref("audit", "Third Party Auditors Ltd. audited Acme GmbH in 2026.")]),
        "C-008": ("none", []),
        "C-009": ("artefact", [page_ref("foundingDate", '"legalName": "Acme GmbH"')]),
        "C-010": ("none", [{"ref": "https://acme.test/missing#404", "quote": None}]),
        "C-011": ("restated", [url_ref("team", "Our team of 12 lives in Berlin")]),
        "C-012": ("artefact", [url_ref("stats", '"support_hours":4'), url_ref("stats", "this quote is not in the body at all")]),
    }
    write_jsonl(run / "prove.jsonl", [{"id": cid, "evidence": ev, "refs": refs, "note": f"prove note {cid}"} for cid, (ev, refs) in prove.items()])
    dis = {
        "C-003": ("yes", "high", [url_ref("status", "data loss incident on 2026-03-02")], "A low confidence date, the field says high."),
        "C-004": ("yes", "low", [url_ref("about", "Acme was founded in 2021")], "The about page says 2021."),
        "C-005": ("yes", None, [url_ref("uptime", "Measured uptime over 12 months: 97.2 percent")], "Measured differently, so low confidence."),
        "C-001": ("no", None, [page_ref("500 customers", "We have 500 customers.")], "consistent"),
    }
    rows = []
    for cid in texts:
        c, conf, refs, note = dis.get(cid, ("no", None, [], f"disprove note {cid}"))
        row = {"id": cid, "contradiction": c, "refs": refs, "note": note}
        if conf:
            row["confidence"] = conf
        rows.append(row)
    write_jsonl(run / "disprove.jsonl", rows)
    (run / "private-evidence.json").write_text(json.dumps({"C-008": {"holder": "Acme GmbH", "sha256": "ab" * 32, "shown": "2026-11-19",
                                                                       "seen_by": "orchestrator", "note": "the security review PDF"}}), encoding="utf-8")
    (run / "judge.json").write_text(json.dumps({"C-010": {"verdict": "WITHDRAWN", "note": "the page no longer says it"},
                                                 "C-011": {"verdict": "EVIDENCED", "note": "the team page states it"}}), encoding="utf-8")
    write_jsonl(run / "holdout.jsonl", [{"id": cid, "prove": ["restated"], "disprove": ["no"]} for cid in texts])
    (run / "gates.json").write_text(json.dumps({"version": 2, "outcome": "pass", "gates": []}), encoding="utf-8")
    write_jsonl(run / "checks.jsonl", [{"id": cid, "types": ["other"], "checks": []} for cid in texts])


def make_job(root, state="merged"):
    job = pathlib.Path(root) / JOB_ID
    job.mkdir(parents=True)
    (job / "api-job.json").write_text(json.dumps({"request": {"sources": ["https://acme.test/"], "profile": {"name": "acme", "publisher": "Acme", "domain": "acme.test"},
                                                                 "models": {}}, "received_at": "2026-11-20T16:58:00Z"}), encoding="utf-8")
    (job / "job.json").write_text(json.dumps({"state": state, "step": None, "spend_usd": 0.5, "failure": None}), encoding="utf-8")
    make_run(job / JOB_ID)
    return job


def tree(d):
    return {str(q.relative_to(d)): sha(q.read_bytes()) for q in sorted(pathlib.Path(d).rglob("*")) if q.is_file()}


def load_jsonl(p):
    return [json.loads(l) for l in pathlib.Path(p).read_text(encoding="utf-8").split("\n") if l.strip()]


def formula_module():
    spec = importlib.util.spec_from_file_location("evidence_score_under_test", FORMULA)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def convert(job, out, key, extra=("--own-host", "acme.test"), identity=IDENTITY):
    cmd = [sys.executable, "-I", str(CONVERTER), str(job), "--out", str(out), "--key", str(key), "--identity", identity] + list(extra)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=300)


def run_check(folder, *flags):
    return subprocess.run([sys.executable, "-I", str(HERE / "check.py"), str(folder), *flags], capture_output=True, text=True, timeout=300)


class Base(unittest.TestCase):
    tmp = None
    key = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="p1-test-"))
        cls.key = cls.tmp / "key" / "id_ed25519"
        cls.key.parent.mkdir()
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-q", "-f", str(cls.key), "-C", "p1-test-throwaway"], check=True)
        cls.job = make_job(cls.tmp / "jobs")
        cls.run_dir = cls.job / JOB_ID
        cls.before = tree(cls.job)
        cls.out = cls.tmp / "out1"
        cls.r = convert(cls.job, cls.out, cls.key)
        cls.M = json.loads((cls.out / "manifest.json").read_text(encoding="utf-8")) if (cls.out / "manifest.json").exists() else None

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def converted(self):
        self.assertEqual(self.r.returncode, 0, f"converter failed: {self.r.stderr[-800:]}{self.r.stdout[-800:]}")
        self.assertTrue((self.out / "manifest.json").exists())


class T(Base):
    def test_t01_check_passes(self):
        self.converted()
        r = run_check(self.out, "--json")
        self.assertEqual(r.returncode, 0, r.stdout[-3000:])
        self.assertIn(" 0 failed", r.stdout)
        self.assertFalse([l for l in r.stdout.splitlines() if " FAIL" in l], r.stdout[-3000:])
        cj = json.loads((self.out / "CHECK.json").read_text(encoding="utf-8"))
        self.assertIn(cj["result"], ("PASS", "WARN"))
        self.assertEqual(cj["manifest_sha256"], hashlib.sha256((self.out / "manifest.json").read_bytes()).hexdigest())

    def test_t02_audit_has_no_decisions(self):
        self.converted()
        audit = load_jsonl(self.out / "audit.jsonl")
        self.assertEqual(len(audit), 12)
        for row in audit:
            self.assertEqual([k for k in DECISION_FIELDS if k in row], [], row["id"])
            self.assertTrue(row.get("audited_by") and row.get("audited_at"), row["id"])

    def test_t03_verdicts_equal_formula(self):
        self.converted()
        f = formula_module()
        status = {r["id"]: r for r in f.rows_from_run(self.run_dir)}
        word = {"evidenced": "EVIDENCED", "contradicted": "CONTRADICTED", "no evidence published": "NO EVIDENCE PUBLISHED",
                "evidence private": "EVIDENCE AVAILABLE ON REQUEST"}
        claims = {r["id"]: r for r in load_jsonl(self.out / "claims.jsonl")}
        self.assertEqual(sorted(claims), [f"C-{i:03d}" for i in range(1, 13)])
        for cid, row in claims.items():
            if cid not in status:
                self.assertEqual(row["verdict"], "WITHDRAWN", cid)
            elif status[cid]["status"] == "promise":
                self.assertFalse(row["checkable"], cid)
                self.assertEqual(row["kind"], "promise", cid)
            else:
                self.assertEqual(row["verdict"], word[status[cid]["status"]], cid)
                if row["verdict"] == "CONTRADICTED":
                    self.assertEqual(row["confidence"], status[cid]["confidence"], cid)
        self.assertEqual(claims["C-010"]["verdict"], "WITHDRAWN")
        self.assertEqual(claims["C-011"]["verdict"], "EVIDENCED")      # the judge's ruling, over a prove pass that said restated
        self.assertEqual(claims["C-008"]["verdict"], "EVIDENCE AVAILABLE ON REQUEST")
        self.assertEqual(claims["C-008"]["on_request"]["holder"], "Acme GmbH")
        self.assertEqual(claims["C-008"]["on_request"]["sha256"], "ab" * 32)

    def test_t04_score_equals_formula(self):
        self.converted()
        f = formula_module()
        s = f.evidence_score_v1(f.rows_from_run(self.run_dir))
        M = self.M
        self.assertEqual((M["score"]["coverage_pct"], M["score"]["contradiction_pct"], M["score"]["band"], M["score"]["formula"]),
                         (s["coverage"], s["contradiction"], s["band"], "evidence-score/1"))
        for mk, sk in (("claims", None), ("checkable", "checkable"), ("evidenced", "evidenced"), ("on_request", "on_request"), ("no_evidence", "no_evidence"),
                       ("contradicted", "contradicted"), ("contradicted_high", "contradicted_high")):
            if sk:
                self.assertEqual(M["counts"][mk], s[sk], mk)
        self.assertEqual(M["counts"]["claims"], 12)
        self.assertEqual(M["counts"]["withdrawn"], 1)
        self.assertEqual((s["evidenced"], s["contradicted"], s["contradicted_high"], s["on_request"]), (5, 3, 1, 1))

    def test_t05_fetched_quotes_verify_against_bodies(self):
        self.converted()
        tf = {}
        for src in (json.loads((self.run_dir / "http-cache.json").read_text()), ):
            for u, e in src.items():
                tf[u] = e["sha256"]
        for e in json.loads((self.run_dir / "tool-fetches.json").read_text()):
            tf[e["url"]] = e["sha256"]                                 # the later entry wins
        seen = 0
        for row in load_jsonl(self.out / "audit.jsonl"):
            for p in (row.get("proofs") or []) + (row.get("counter") or []):
                if p.get("url") and p.get("quote") and not (p.get("file") or "").startswith("pages/"):
                    body = (self.run_dir / "http-bodies" / tf[p["url"]]).read_text(encoding="utf-8")
                    self.assertIn(check.norm(p["quote"]), check.norm(body), f"{row['id']} {p['quote']}")
                    seen += 1
        self.assertGreaterEqual(seen, 6)
        # the old body of /api/stats says customers 1: a quote of the new one must not have been matched against it
        stats = [p for r in load_jsonl(self.out / "audit.jsonl") if r["id"] == "C-001" for p in r["proofs"]]
        self.assertEqual([p["quote"] for p in stats], ['"customers":500'])

    def test_t06_own_host_text_other_host_hash_only(self):
        self.converted()
        by_url = {s["url"]: s for s in self.M["sources"]}
        own, other = by_url["https://acme.test/api/stats"], by_url["https://registers.example.org/audit"]
        self.assertEqual(own["copy"], "text")
        self.assertTrue(own["file"] and (self.out / own["file"]).exists())
        self.assertEqual(own["sha256"], hashlib.sha256((self.out / own["file"]).read_bytes()).hexdigest())
        self.assertEqual(own["body_sha256"], hashlib.sha256(BODIES["stats"][1]).hexdigest())
        self.assertEqual(other["copy"], "hash-only")
        self.assertIsNone(other["file"])
        self.assertTrue(other["sha256"])
        self.assertNotIn(b"Third Party Auditors Ltd. audited", b"".join(p.read_bytes() for p in (self.out / "sources").rglob("*") if p.is_file()))
        self.assertEqual(by_url["https://acme.test/missing"]["copy"], "none")
        self.assertEqual(by_url["https://acme.test/missing"]["status"], 404)
        self.assertTrue((self.out / "pages" / PAGE_NAME).exists())
        self.assertEqual((self.out / "pages" / PAGE_NAME).read_bytes(), (self.run_dir / "sources" / PAGE_NAME).read_bytes())

    def test_t07_input_unchanged(self):
        self.converted()
        self.assertEqual(tree(self.job), self.before)

    def test_t08_deterministic(self):
        self.converted()
        out2 = self.tmp / "out2"
        r = convert(self.job, out2, self.key)
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        self.assertEqual((out2 / "audit.jsonl").read_bytes(), (self.out / "audit.jsonl").read_bytes())
        w1 = sorted(p.name for p in (self.out / "witness").iterdir() if p.suffix == ".jsonl")
        w2 = sorted(p.name for p in (out2 / "witness").iterdir() if p.suffix == ".jsonl")
        self.assertEqual(w1, w2)
        for n in w1:
            self.assertEqual((out2 / "witness" / n).read_bytes(), (self.out / "witness" / n).read_bytes())
        self.assertEqual((out2 / "claims.jsonl").read_bytes(), (self.out / "claims.jsonl").read_bytes())

    def test_t09_not_merged_refused(self):
        job = make_job(self.tmp / "jobs-running", state="running")
        out = self.tmp / "out-running"
        r = convert(job, out, self.key)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(out.exists())
        self.assertIn("merged", (r.stderr + r.stdout))

    def test_t10_existing_out_refused(self):
        self.converted()
        out = self.tmp / "out-exists"
        out.mkdir()
        (out / "keep.txt").write_text("mine", encoding="utf-8")
        r = convert(self.job, out, self.key)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(sorted(p.name for p in out.iterdir()), ["keep.txt"])

    def test_t11_roles_and_no_private_key(self):
        self.converted()
        sigs = json.loads((self.out / "signatures.json").read_text(encoding="utf-8"))
        self.assertEqual(sorted(s["role"] for s in sigs), ["auditor", "manifest", "sources", "witness"])
        self.assertEqual({s["signer"]["name"] for s in sigs}, {IDENTITY})
        priv = self.key.read_bytes()
        for p in self.out.rglob("*"):
            if p.is_file():
                data = p.read_bytes()
                self.assertNotIn(b"PRIVATE KEY", data, str(p))
                self.assertNotIn(priv.strip().splitlines()[1], data, str(p))
        self.assertIn(self.key.with_suffix(".pub").read_text().split()[1], (self.out / "allowed_signers").read_text())
        self.assertTrue((self.out / "CHECK.json").exists())

    def test_t12_witness_is_the_graders_self_audit(self):
        self.converted()
        g = self.M["grading"]
        self.assertEqual(g["kind"], "self-audit")
        self.assertEqual(g["profile"], "publisher-surfaces")
        self.assertTrue(g["gates"])
        (w,) = g["witnesses"]
        self.assertTrue(w["primary"])
        self.assertEqual(w["kind"], "agent")
        self.assertEqual(w["model"], MODEL)
        rows = load_jsonl(self.out / w["file"])
        head, decisions = rows[0], rows[1:]
        self.assertEqual((head["kind"], head["model"], head["over"]["file"]), ("agent", MODEL, "audit.jsonl"))
        self.assertEqual(head["over"]["sha256"], hashlib.sha256((self.out / "audit.jsonl").read_bytes()).hexdigest())
        audit = {r["id"]: r for r in load_jsonl(self.out / "audit.jsonl")}
        self.assertEqual([d["id"] for d in decisions], list(audit))
        for d in decisions:
            for i in d["on"]["proofs"]:
                self.assertLess(i, len(audit[d["id"]].get("proofs") or []))
            for i in d["on"]["counter"]:
                self.assertLess(i, len(audit[d["id"]].get("counter") or []))
            if d["verdict"] == "EVIDENCED":
                self.assertTrue(d["on"]["proofs"], d["id"])
            if d["verdict"] == "CONTRADICTED":
                self.assertTrue(d["on"]["counter"], d["id"])
        self.assertEqual(self.M["format"], "claims-snapshot/0.7")

    def test_t13_unverifiable_quote_is_not_a_proof(self):
        self.converted()
        audit = {r["id"]: r for r in load_jsonl(self.out / "audit.jsonl")}
        self.assertEqual([p["quote"] for p in audit["C-012"]["proofs"]], ['"support_hours":4'])
        everything = json.dumps(audit["C-012"])
        self.assertNotIn("verified\": false", everything.replace('"verified": false, "note": "the quote', ""))
        for row in audit.values():
            for p in (row.get("proofs") or []) + (row.get("counter") or []):
                self.assertTrue(p.get("quote") or p.get("expect_status") or p.get("file"), row["id"])

    def test_t14_confidence_field_first(self):
        self.converted()
        claims = {r["id"]: r for r in load_jsonl(self.out / "claims.jsonl")}
        self.assertEqual(claims["C-003"]["confidence"], "high")   # the note says "low confidence", the field says high
        self.assertEqual(claims["C-004"]["confidence"], "low")    # field low
        self.assertEqual(claims["C-005"]["confidence"], "low")    # no field: the note words

    def test_t15_usage_errors(self):
        out = self.tmp / "out-usage"
        r = subprocess.run([sys.executable, "-I", str(CONVERTER), str(self.job), "--out", str(out)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("usage", (r.stderr + r.stdout).lower())
        self.assertFalse(out.exists())

    @unittest.skipUnless(os.environ.get("P1_DEV_RUN"), "P1_DEV_RUN names the development input's run folder")
    def test_t16_development_input(self):
        job = self.tmp / "dev" / JOB_ID
        job.mkdir(parents=True)
        (job / "api-job.json").write_text(json.dumps({"request": {"sources": ["https://optima.financial/"], "profile": {"name": "optima", "publisher": "Optima", "domain": "optima.financial"}, "models": {}}}), encoding="utf-8")
        (job / "job.json").write_text(json.dumps({"state": "merged"}), encoding="utf-8")
        shutil.copytree(os.environ["P1_DEV_RUN"], job / JOB_ID)
        out = self.tmp / "dev-out"
        r = convert(job, out, self.key, extra=())
        self.assertEqual(r.returncode, 0, r.stderr[-1500:] + r.stdout[-1500:])
        c = run_check(out)
        self.assertEqual(c.returncode, 0, c.stdout[-3000:])
        self.assertFalse([l for l in c.stdout.splitlines() if " FAIL" in l])
        if os.environ.get("P1_KEEP_DEV_OUT"):
            shutil.copytree(out, os.environ["P1_KEEP_DEV_OUT"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
