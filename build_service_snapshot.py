#!/usr/bin/env python3
"""build_service_snapshot.py: a finished onedroid-audit service job becomes a claims-snapshot folder (SPEC.md, format 0.7)
that check.py passes. E2E-P1 of mission M-20261120-EVIDENCE-E2E. Standard library plus ssh-keygen on PATH; nothing is fetched.

usage: python3 -I build_service_snapshot.py JOB_DIR --out FOLDER --key PRIVATE_KEY --identity PRINCIPAL [--own-host HOST]... [--formula FILE]

JOB_DIR  a onedroid-audit job: api-job.json (the request), job.json (state must be "merged") and the argus-claims run folder
         JOB_DIR/<job id>/ (publisher-surfaces profile): claims.jsonl, prove.jsonl, disprove.jsonl, run.json, sources/ with
         sources.sha256, http-cache.json, http-bodies/<sha256>, tool-fetches.json, holdout.jsonl, gates.json, and maybe
         private-evidence.json, judge.json. The job is only read.
FOLDER   the snapshot; it must not exist. It holds manifest.json, pages/, sources/, audit.jsonl (the auditor's part: claims and
         candidate evidence, no decisions), witness/<grader>.jsonl (the graders' decisions, primary), claims.jsonl (check.merge_rows),
         signatures.json with the .sig files and allowed_signers (sign.py: auditor, witness, sources, manifest) and CHECK.json.
KEY      an OpenSSH ed25519 private key (KEY.pub beside it). It signs every part: the grading is a self-audit (SPEC 1, 14 erratum 1)
         and the key never enters the folder.
HOSTS    a body fetched from the profile's domain, the run's hosts or an --own-host is published as a text copy; any other host's body
         is hash-only (SPEC 6).

The verdicts, the confidence of a contradiction and the score are the owned formula's (onedroid-score formula/evidence_score.py,
rows_from_run and evidence_score_v1), imported by path and never copied; the default path is below, --formula or the environment
variable ONEDROID_FORMULA names another. Exit codes: 0 check.py has no FAIL, 1 refused or failed, 2 usage, 3 the folder was written
and check.py FAILs (the folder is kept for inspection).

The choices a format owner may change are the constants below (SPEC 14 erratum 1 lets a declared agent self-audit keep one signer)."""
import hashlib
import importlib.util
import json
import pathlib
import re
import shutil
import subprocess
import sys
from urllib.parse import urlsplit

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402
from build_site_snapshot import KIND_MAP  # noqa: E402  (the lister-kind to snapshot-kind map the site converter uses)

FORMAT = "claims-snapshot/0.7"
PROFILE = "publisher-surfaces"
GRADING_KIND = "self-audit"
GRADER_NAME = "onedroid-audit"          # the witness's name; its file is witness/<name>.jsonl (K13 for kind agent)
WITNESS_KIND = "agent"
METHOD = "argus-claims publisher-surfaces, prove and disprove passes by the model named, merged by the onedroid-audit service"
DEFAULT_FORMULA = "/home/coder/code/onedro1d/onedroid-score/formula/evidence_score.py"
MAX_QUOTED_LINES = 6
MAX_QUOTE_CHARS = 400
WORD = {"evidenced": "EVIDENCED", "contradicted": "CONTRADICTED", "no evidence published": "NO EVIDENCE PUBLISHED",
        "evidence private": "EVIDENCE AVAILABLE ON REQUEST"}
PAGE_REF = re.compile(r"^sources/([^#\s]+)(?:#L(\d+)(?:-L?(\d+))?)?$")


class Refused(Exception):
    pass


def sha(b):
    return hashlib.sha256(b).hexdigest()


def read_json(p, default=None):
    p = pathlib.Path(p)
    if not p.is_file():
        return default
    return json.loads(p.read_text(encoding="utf-8"))


def read_jsonl(p):
    return [json.loads(l.rstrip("\r")) for l in pathlib.Path(p).read_text(encoding="utf-8").split("\n") if l.strip()]


def arg_values(argv, flag):
    return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == flag]


def load_formula(path):
    spec = importlib.util.spec_from_file_location("onedroid_evidence_score", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for need in ("rows_from_run", "evidence_score_v1"):
        if not hasattr(mod, need):
            raise Refused(f"the formula file {path} has no {need}")
    return mod


def find_run_folder(job):
    cand = job / job.name
    if (cand / "run.json").is_file():
        return cand
    subs = [d for d in sorted(job.iterdir()) if d.is_dir() and (d / "run.json").is_file()]
    if len(subs) == 1:
        return subs[0]
    raise Refused(f"no run folder {job.name}/ with a run.json inside {job}")


def host_of(url):
    return (urlsplit(url).hostname or "").lower()


def one_line(s, cap=MAX_QUOTE_CHARS):
    s = re.sub(r"\s+", " ", s).strip()
    return s[:cap].rstrip()


class Job:
    """Everything read from the job directory; nothing is written to it."""

    def __init__(self, job):
        self.job = pathlib.Path(job)
        if not self.job.is_dir():
            raise Refused(f"{job} is not a directory")
        state = (read_json(self.job / "job.json", {}) or {}).get("state")
        if state != "merged":
            raise Refused(f"job.json state is {state!r}: only a merged job (state 'merged') is converted")
        api = read_json(self.job / "api-job.json", {}) or {}
        req = api.get("request") if isinstance(api.get("request"), dict) else api
        self.profile = req.get("profile") if isinstance(req.get("profile"), dict) else {}
        self.run = find_run_folder(self.job)
        self.runj = read_json(self.run / "run.json", {})
        for need in ("claims.jsonl", "prove.jsonl", "disprove.jsonl", "holdout.jsonl"):
            if not (self.run / need).is_file():
                raise Refused(f"the run folder has no {need}")
        self.claims = read_jsonl(self.run / "claims.jsonl")
        self.prove = {r["id"]: r for r in read_jsonl(self.run / "prove.jsonl")}
        self.disprove = {r["id"]: r for r in read_jsonl(self.run / "disprove.jsonl")}
        self.judge = read_json(self.run / "judge.json", {}) or {}
        self.private = read_json(self.run / "private-evidence.json", {}) or {}
        self.fetched_at = self.runj.get("fetched_at")
        if not self.fetched_at:
            raise Refused("run.json has no fetched_at")
        self.domain = self.profile.get("domain") or self.runj.get("domain") or ""
        self.publisher = self.profile.get("publisher") or self.runj.get("publisher") or self.domain
        models = self.runj.get("models") or {}
        ms = []
        for k in ("prove", "disprove"):
            m = (models.get(k) or {}).get("model")
            if m and m not in ms:
                ms.append(m)
        self.model = " + ".join(ms) if ms else "unknown"
        # the graders' fetches: http-cache.json first, then tool-fetches.json, the later entry winning
        self.fetch = {}
        for url, e in (read_json(self.run / "http-cache.json", {}) or {}).items():
            self.fetch[url] = {"url": url, "status": e.get("status"), "sha256": e.get("sha256"), "fetched_at": None}
        for e in read_json(self.run / "tool-fetches.json", []) or []:
            if isinstance(e, dict) and e.get("url"):
                self.fetch[e["url"]] = {"url": e["url"], "status": e.get("status"), "sha256": e.get("sha256"), "fetched_at": e.get("fetched_at")}
        calls = self.run / "model-calls.jsonl"
        stamps = [r.get("created_at") for r in read_jsonl(calls) if r.get("created_at")] if calls.is_file() else []
        self.finished_at = max(stamps) if stamps else self.fetched_at
        self.pages = {}
        graded = {}
        sf = self.run / "sources.sha256"
        if sf.is_file():
            for l in sf.read_text(encoding="utf-8").splitlines():
                parts = l.split()
                if len(parts) == 2:
                    graded[parts[1].split("/")[-1]] = parts[0]
        for p in sorted((self.run / "sources").iterdir()):
            if p.is_file():
                raw = p.read_bytes()
                if graded.get(p.name) and graded[p.name] != sha(raw):
                    raise Refused(f"sources/{p.name}: sha256 differs from the run's sources.sha256")
                text = raw.decode("utf-8", errors="replace")
                render = check.page_text_of(p.name, text)
                self.pages[p.name] = {"raw": raw, "text": text, "render": render, "norm": check.norm(render), "html": check.is_html(p.name, text)}

    def fetch_for(self, url):
        for u in (url, url.rstrip("/"), url.rstrip("/") + "/"):
            if u in self.fetch:
                return self.fetch[u]
        return None

    def body(self, url):
        e = self.fetch_for(url)
        if e and e.get("sha256") and isinstance(e.get("status"), int) and 200 <= e["status"] < 300:
            p = self.run / "http-bodies" / e["sha256"]
            if p.is_file():
                return p.read_bytes()
        return None


def parse_ref(r):
    """A grader's evidence ref ({ref, quote} or a bare string) -> {kind page|url|other, ...}."""
    if isinstance(r, str):
        r = {"ref": r, "quote": None}
    ref, quote = str(r.get("ref", "")).strip(), r.get("quote")
    quote = quote if isinstance(quote, str) and quote.strip() else None
    m = PAGE_REF.match(ref)
    if m:
        return {"kind": "page", "name": m.group(1), "a": int(m.group(2)) if m.group(2) else None,
                "b": int(m.group(3) or m.group(2)) if m.group(2) else None, "quote": quote, "ref": ref}
    if re.match(r"^https?://", ref):
        url, _, tail = ref.rpartition("#")
        if url and re.fullmatch(r"\d{3}", tail):
            return {"kind": "url", "url": url, "status": int(tail), "quote": quote, "ref": ref}
        return {"kind": "url", "url": ref, "status": None, "quote": quote, "ref": ref}
    return {"kind": "other", "quote": quote, "ref": ref}


class Builder:
    def __init__(self, job, out, formula, own_hosts):
        self.j, self.out, self.f = job, pathlib.Path(out), formula
        self.own = {h.lower() for h in own_hosts if h} | {job.domain.lower()} | {str(h).lower() for h in job.runj.get("hosts") or []}
        self.own |= {"www." + h for h in list(self.own)}
        self.sources, self.by_url, self.warnings = [], {}, []

    # --- sources: every fetched URL a ref names, in order of first use ---------------------------------------------------
    def collect_urls(self, refs_by_url):
        """refs_by_url: {url: [quote, ...]} in order of first use -> source entries, text copies written."""
        for url, info in refs_by_url.items():
            n = len(self.sources) + 1
            fe = self.j.fetch_for(url)
            status = (fe or {}).get("status") if fe else info["status"]
            if status is None:
                status = info["status"]
            body = self.j.body(url)
            entry = {"n": n, "url": url, "file": None, "sha256": None, "copy": "none", "fetched_at": (fe or {}).get("fetched_at") or self.j.fetched_at,
                     "status": status, "body_sha256": (fe or {}).get("sha256")}
            if body is None:
                entry["note"] = ("answered %s; no body was saved" % status) if status is not None else "no fetch record: nothing saved"
                self.sources.append(entry)
                self.by_url[url] = {"entry": entry, "text": None}
                continue
            raw = body.decode("utf-8", errors="replace")
            variants = [("body", raw)]
            if check.is_html(url, raw):
                variants.append(("html", check.html_to_text(raw)))
            quotes = [check.norm(q) for q in info["quotes"] if q]
            best = max(variants, key=lambda v: (sum(1 for q in quotes if q and q in check.norm(v[1])), v[0] == "body"))
            text = best[1]
            data = text.encode("utf-8")
            own = host_of(url) in self.own
            entry.update({"sha256": sha(data), "copy": "text" if own else "hash-only", "text_copy_of": best[0]})
            if own:
                entry["file"] = f"sources/{n:03d}.txt"
                (self.out / "sources").mkdir(exist_ok=True)
                (self.out / entry["file"]).write_bytes(data)
            else:
                entry["copy_name"] = f"{n:03d}.txt"
                entry["note"] = "another host's page: the text copy is held by the auditor, its hash is published (SPEC 6)"
            self.sources.append(entry)
            self.by_url[url] = {"entry": entry, "text": text}

    # --- one ref -> a proof-shaped dict ------------------------------------------------------------------------------------
    def lines_quote(self, text, a, b):
        ls = text.split("\n")
        if a < 1 or b > len(ls) or b < a:
            return None, None
        if b - a + 1 > MAX_QUOTED_LINES:
            for l in ls[a - 1:b]:
                if l.strip():
                    return one_line(l), f"first line of the cited range L{a}-{b}; the file's hash covers the rest"
            return None, None
        q = one_line(" ".join(l.strip() for l in ls[a - 1:b]))
        return (q or None), None

    def make(self, ref, page_urls):
        """-> {ok, proof: {...}} or {ok: False, consulted: {...}}. ok means it may stand as a candidate proof or counter."""
        k = ref["kind"]
        if k == "other":
            return {"ok": False, "search": ref["ref"]}
        if k == "page":
            pg = self.j.pages.get(ref["name"])
            file = f"pages/{ref['name']}"
            if pg is None:
                return {"ok": False, "search": ref["ref"]}
            quote, note = ref["quote"], None
            if quote is None and ref["a"]:
                quote, note = self.lines_quote(pg["render"], ref["a"], ref["b"])
            if quote is None:
                return {"ok": False, "consulted": {"file": file, "url": page_urls.get(ref["name"]), "quote": None, "note": "cited without a quotable line: kept as a locator"}}
            if check.norm(quote) and check.norm(quote) in pg["norm"]:
                p = {"file": file, "url": page_urls.get(ref["name"]), "quote": quote, "verified": True}
                if ref["a"]:
                    p["line"] = ref["a"]
                if note:
                    p["note"] = note
                return {"ok": True, "proof": p}
            return {"ok": False, "consulted": {"file": file, "url": page_urls.get(ref["name"]), "quote": None,
                                               "note": "the grader's quote is not on the saved page (kept as a locator): " + one_line(quote, 200)}}
        # url
        src = self.by_url[ref["url"]]
        e = src["entry"]
        if src["text"] is None:
            p = {"file": None, "url": ref["url"], "quote": ref["quote"], "expect_status": e.get("status"), "verified": False}
            p["note"] = "fetched live by the grader; no body was saved, so the quote is not checkable offline" if ref["quote"] else "the status the grader saw is the record"
            return {"ok": True, "proof": {k_: v for k_, v in p.items() if v is not None or k_ == "quote"}}
        file = e["file"] or f"sources/{e['n']:03d}.txt"
        if ref["quote"] is None:
            return {"ok": True, "proof": {"file": file, "url": ref["url"], "quote": None, "verified": True,
                                          "note": "the saved copy of the page that answered is the artefact"}}
        if check.norm(ref["quote"]) and check.norm(ref["quote"]) in check.norm(src["text"]):
            return {"ok": True, "proof": {"file": file, "url": ref["url"], "quote": ref["quote"], "verified": True}}
        return {"ok": False, "consulted": {"file": file, "url": ref["url"], "quote": None,
                                           "note": "the grader's quote is not in the body that was fetched (kept as a locator): " + one_line(ref["quote"], 200)}}

    # --- the build ----------------------------------------------------------------------------------------------------------
    def build(self, key, identity):
        j, out, f = self.j, self.out, self.f
        out.mkdir(parents=True)
        (out / "pages").mkdir()
        # the formula's verdicts: the only place the rule lives
        status = {r["id"]: r for r in f.rows_from_run(j.run)}
        score = f.evidence_score_v1(list(status.values()))
        # pages and their urls
        page_urls = {}
        for c in j.claims:
            for s in c.get("sources", []):
                mm = re.match(r"^sources/(\S+)", s.get("locator", ""))
                if mm and s.get("url") and mm.group(1) not in page_urls:
                    page_urls[mm.group(1)] = s["url"]
        req_urls = [e.get("url") for e in (read_json(j.run / "request-sources.json", []) or []) if isinstance(e, dict)]
        if len(j.pages) == 1 and len(req_urls) == 1:
            page_urls.setdefault(next(iter(j.pages)), req_urls[0])
        pages = []
        for name, pg in j.pages.items():
            (out / "pages" / name).write_bytes(pg["raw"])
            pages.append({"file": f"pages/{name}", "url": page_urls.get(name), "sha256": sha(pg["raw"]), "lines": len(pg["text"].split("\n")),
                          "fetched_at": j.fetched_at, "read_as": "html-text" if pg["html"] else "as-served"})
            if not page_urls.get(name):
                self.warnings.append(f"page {name}: no url known")
        # every ref of every pass, parsed once; URL sources in order of first use
        parsed = {}
        refs_by_url = {}
        for c in j.claims:
            for tag, rows in (("prove", j.prove), ("disprove", j.disprove)):
                lst = [parse_ref(r) for r in (rows.get(c["id"], {}).get("refs") or [])]
                parsed[(c["id"], tag)] = lst
                for r in lst:
                    if r["kind"] == "url":
                        info = refs_by_url.setdefault(r["url"], {"quotes": [], "status": r["status"]})
                        info["quotes"].append(r["quote"])
                        if info["status"] is None:
                            info["status"] = r["status"]
        self.collect_urls(refs_by_url)

        audit, wrows = [], []
        for c in j.claims:
            cid = c["id"]
            pr, dp = j.prove.get(cid, {}), j.disprove.get(cid, {})
            if not pr or not dp:
                raise Refused(f"{cid}: missing a pass row")
            st = status.get(cid)
            if st is None:
                verdict = "WITHDRAWN"
            elif st["status"] == "promise":
                verdict = "NO EVIDENCE PUBLISHED"     # not checkable: kind promise leaves every denominator; the formula keeps no verdict for it
            else:
                verdict = WORD[st["status"]]
            conf = st.get("confidence") if st and st["status"] == "contradicted" else None
            kind = KIND_MAP.get(str(c.get("kind", "other")).lower(), "other")
            checkable = kind != "promise"
            made = {tag: [(r, self.make(r, page_urls)) for r in parsed[(cid, tag)]] for tag in ("prove", "disprove")}
            proofs, counter, consulted, searched = [], [], [], []
            for tag, items in made.items():
                for r, m in items:
                    if "search" in m:
                        searched.append(m["search"])
            allow_proofs = checkable and (verdict == "EVIDENCED" or (verdict == "CONTRADICTED" and pr.get("evidence") == "artefact"))
            allow_counter = checkable and verdict == "CONTRADICTED"
            for tag, items in made.items():
                for r, m in items:
                    if "search" in m:
                        continue
                    if m["ok"] and tag == "prove" and allow_proofs:
                        proofs.append(m["proof"])
                    elif m["ok"] and tag == "disprove" and allow_counter:
                        counter.append(m["proof"])
                    elif m["ok"]:
                        p = m["proof"]
                        consulted.append({"file": p.get("file"), "url": p.get("url"), "quote": p.get("quote"), **({"note": p["note"]} if p.get("note") else {})})
                    else:
                        consulted.append(m["consulted"])
            consulted = [{k_: v for k_, v in x.items() if v is not None or k_ == "quote"} for x in consulted]
            location, located = [], []
            for s in c.get("sources", []):
                mm = re.match(r"^sources/(\S+) L(\d+)(?:-L?(\d+))?", s.get("locator", ""))
                if mm and mm.group(1) in j.pages:
                    a, b = int(mm.group(2)), int(mm.group(3) or mm.group(2))
                    loc = {"file": f"pages/{mm.group(1)}", "line": a}
                    if loc not in location:
                        location.append(loc)
                        q, _ = self.lines_quote(j.pages[mm.group(1)]["render"], a, b)
                        if q:
                            located.append({"file": loc["file"], "quote": q})
            text = c["claim"]
            frags = [check.norm(x) for x in text.split("[...]") if check.norm(x)]
            if verdict != "WITHDRAWN" and not all(any(x in pg["norm"] for pg in j.pages.values()) for x in frags):
                self.warnings.append(f"{cid}: claim text not found verbatim on any audited page")
            row = {"id": cid, "text": text, "location": location, "kind": kind, "checkable": checkable,
                   "proofs": [{k_: v for k_, v in p.items() if v is not None or k_ == "quote"} for p in proofs],
                   "counter": [{k_: v for k_, v in p.items() if v is not None or k_ == "quote"} for p in counter],
                   "located": located, "consulted": consulted, "searched": searched}
            if verdict == "EVIDENCE AVAILABLE ON REQUEST":
                rec = j.private.get(cid) if isinstance(j.private.get(cid), dict) else {}
                row["on_request"] = {"holder": rec.get("holder") or "the publisher", "sha256": rec.get("sha256"), "shown": rec.get("shown"),
                                     "seen_by": rec.get("seen_by"), "what": rec.get("note")}
            row["lister"] = {"kind": c.get("kind"), "checkability": c.get("checkability"), "status": c.get("status")}
            row["audited_by"] = GRADER_NAME
            row["audited_at"] = j.fetched_at
            audit.append(row)
            note = str((dp if verdict == "CONTRADICTED" else pr).get("note", "")).strip()
            history = None
            if cid in j.judge and isinstance(j.judge[cid], dict):
                history = ("Ruled by the orchestrator after both passes: " + str(j.judge[cid].get("note", ""))).strip()
            if verdict == "EVIDENCE AVAILABLE ON REQUEST":
                history = (history + "; " if history else "") + "the publisher holds the evidence privately and showed it to the grader, who recorded its hash"
            wrows.append({"id": cid, "verdict": verdict, "confidence": conf,
                          "on": {"proofs": list(range(len(proofs))), "counter": list(range(len(counter)))},
                          "note": note, "history": history, "graded_by": "grader", "graded_at": j.finished_at})

        (out / "audit.jsonl").write_text(check.dump_jsonl(audit), encoding="utf-8")
        audit_h = check.sha256(out / "audit.jsonl")
        (out / "witness").mkdir()
        wfile = f"witness/{GRADER_NAME}.jsonl"
        header = {"witness": GRADER_NAME, "kind": WITNESS_KIND, "model": j.model, "method": METHOD,
                  "over": {"file": "audit.jsonl", "sha256": audit_h}, "started_at": j.fetched_at, "finished_at": j.finished_at,
                  "note": f"The decisions of onedroid-audit job {j.job.name}: the verdicts are the evidence-score formula's rows over the prove and disprove passes "
                          "(judge.json first, then private-evidence.json); `on` names every candidate the passes recorded for the claim."}
        (out / wfile).write_text(check.dump_jsonl([header] + wrows), encoding="utf-8")
        merged = check.merge_rows(audit, wrows, GRADER_NAME)
        (out / "claims.jsonl").write_text(check.dump_jsonl(merged), encoding="utf-8")
        sc = check.evidence_score(merged)
        counts = {k_: sc[k_] for k_ in ("claims", "checkable", "evidenced", "on_request", "no_evidence", "contradicted", "contradicted_high", "withdrawn", "author_read")}
        want = {"checkable": score["checkable"], "evidenced": score["evidenced"], "on_request": score["on_request"], "no_evidence": score["no_evidence"],
                "contradicted": score["contradicted"], "contradicted_high": score["contradicted_high"]}
        if {k_: counts[k_] for k_ in want} != want or (sc["coverage_pct"], sc["contradiction_pct"], sc["band"]) != (score["coverage"], score["contradiction"], score["band"]):
            raise Refused(f"the merged rows score {sc} but the formula says {score}: the converter and the formula disagree")
        mscore = {"coverage_pct": score["coverage"], "contradiction_pct": score["contradiction"], "band": score["band"], "formula": "evidence-score/1",
                  "formula_file_sha256": sha(pathlib.Path(f.__file__).read_bytes()),
                  "note": "from the owned formula (onedroid-score evidence_score_v1) over rows_from_run of the run folder, equal to check.py's recomputation"}
        hold = j.run / "holdout.jsonl"
        gates_json = read_json(j.run / "gates.json", {}) or {}
        outcome = str(gates_json.get("outcome") or "").strip() or "not recorded"
        verdict_word = "passed" if outcome == "pass" else ("failed" if outcome.startswith("fail") else outcome)
        gates = [{"run": "service holdout re-check", "size": len(read_jsonl(hold)), "sealed_sha256": sha(hold.read_bytes()), "sealed_at": j.fetched_at,
                  "first_gate": f"{verdict_word} (the harness gates, outcome {outcome})", "regraded_ids": [], "holdout_amended": False,
                  "amended_sha256": None, "final": f"{verdict_word} (the harness gates, outcome {outcome})"}]
        w_score = {"coverage_pct": sc["coverage_pct"], "contradiction_pct": sc["contradiction_pct"], "band": sc["band"]}
        manifest = {
            "format": FORMAT,
            "subject": {"title": j.domain or j.job.name, "url": f"https://{j.domain}/" if j.domain else None, "publisher": j.publisher,
                        "parts": [p["url"] for p in pages if p.get("url")]},
            "taken_at": j.fetched_at,
            "pages_note": f"the audited pages as saved by the onedroid-audit service's harness (job {j.job.name}), served as saved",
            "pages": pages,
            "sources": self.sources,
            "grading": {"kind": GRADING_KIND, "grader": GRADER_NAME, "model": j.model, "profile": PROFILE, "method": METHOD, "graded_at": j.finished_at,
                        "auditor": {"name": GRADER_NAME, "model": j.model, "signer": None, "file": "audit.jsonl", "sha256": audit_h},
                        "witnesses": [{"name": GRADER_NAME, "kind": WITNESS_KIND, "model": j.model, "method": METHOD, "signer": None, "file": wfile,
                                       "sha256": check.sha256(out / wfile), "primary": True, "score": w_score, "missing_claims": 0}],
                        "sessions": [], "gates": gates, "rounds": []},
            "counts": counts, "score": mscore, "claims_sha256": check.sha256(out / "claims.jsonl"),
        }
        (out / "manifest.json").write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        # signatures: the order matters, sign.py rewrites the manifest's signer fields for the auditor and the witness; the manifest goes last
        for role, extra in (("auditor", ["--file", "audit.jsonl"]), ("witness", ["--file", wfile]), ("sources", []), ("manifest", [])):
            r = subprocess.run([sys.executable, "-I", str(HERE / "sign.py"), str(out), "--role", role, *extra, "--key", str(key), "--identity", identity],
                               capture_output=True, text=True)
            if r.returncode != 0:
                raise Refused(f"sign.py --role {role} failed: {(r.stderr + r.stdout).strip()[-400:]}")
        return counts, mscore


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help") or any(f not in argv for f in ("--out", "--key", "--identity")):
        print(__doc__)
        return 2
    try:
        job_dir = pathlib.Path(argv[1])
        out = pathlib.Path(arg_values(argv, "--out")[-1])
        key = pathlib.Path(arg_values(argv, "--key")[-1])
        identity = arg_values(argv, "--identity")[-1]
    except IndexError:
        print(__doc__)
        return 2
    formula_path = (arg_values(argv, "--formula") or [None])[-1] or __import__("os").environ.get("ONEDROID_FORMULA") or DEFAULT_FORMULA
    try:
        if out.exists() or out.is_symlink():
            raise Refused(f"{out} exists; a snapshot folder is never overwritten")
        if any(ch.isspace() for ch in identity) or "," in identity or not identity:
            raise Refused("the identity is the principal in allowed_signers: no spaces or commas")
        if not key.is_file() or not pathlib.Path(str(key) + ".pub").is_file():
            raise Refused(f"{key} or {key}.pub is missing")
        if out.resolve() in key.resolve().parents:
            raise Refused("the private key would be inside the snapshot folder")
        if not pathlib.Path(formula_path).is_file():
            raise Refused(f"the formula file {formula_path} is not there (--formula or ONEDROID_FORMULA)")
        job = Job(job_dir)
        formula = load_formula(formula_path)
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    b = Builder(job, out, formula, arg_values(argv, "--own-host"))
    try:
        counts, score = b.build(key, identity)
    except Refused as e:
        shutil.rmtree(out, ignore_errors=True)
        print(f"refused: {e}", file=sys.stderr)
        return 1
    except Exception:
        shutil.rmtree(out, ignore_errors=True)
        raise
    for w in b.warnings:
        print("WARN", w, file=sys.stderr)
    r = subprocess.run([sys.executable, "-I", str(HERE / "check.py"), str(out), "--json"], capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    print(f"snapshot {out}: {counts['claims']} claims (E {counts['evidenced']}, on request {counts['on_request']}, C {counts['contradicted']} "
          f"({counts['contradicted_high']} high), N {counts['no_evidence']}, withdrawn {counts['withdrawn']}), {score['coverage_pct']}% / "
          f"{score['contradiction_pct']}% band {score['band']}; {len(b.sources)} sources; check.py exit {r.returncode}")
    return 0 if r.returncode == 0 else 3


if __name__ == "__main__":
    sys.exit(main(sys.argv))
