#!/usr/bin/env python3
"""build_site_snapshot.py: convert a claims-audit run of the PUBLISHER-SURFACES profile (a website: many audited
files under sources/, refs of the form sources/<file>#L<n> with no quote, a repo/ clone at a pinned commit, a fetched/
folder numbered by fetch order, unsaved worker GETs, private-evidence.json, optional judge.json and withdrawn.json)
into a claims snapshot (SPEC.md, format claims-snapshot/0.3).

usage: python3 -I build_site_snapshot.py CONFIG.json
CONFIG keys:
  run_dir, out_dir, subject {title, url, publisher}, taken_at (default run.json fetched_at), page_note,
  page_urls {sources file: url} (fills gaps the lister's locators leave),
  third_party_copy ("hash-only" | "text"), own_hosts [hosts whose fetched copies may be published as text],
  repos {"repo": {"github": "Org/name", "commit": "<sha>", "licence": "MIT", "copy": "text"}},
  webfetch_files {"ftc-webfetch.md": "https://..."}  (files of quotes from a summarising fetch, no saved body),
  private_evidence (path or null; default run_dir/private-evidence.json), judge (path or null), withdrawn (path or null),
  graded_at {"grade": iso, "on_request": iso, "judge": iso}, runs {"<prev run id>": iso} for carried rows,
  kind_map {lister kind: snapshot kind} (overrides the defaults below),
  grading {kind, grader, model, method, graded_at, gates [...], rounds [...]},
  extractors [paths of the scripts that made the fetched text copies].
The verdict rule, the score and the quote normalisation are check.py's (imported), so the converter and the checker
cannot drift. Standard library only. Nothing is fetched: the snapshot is built from the run's saved files alone."""
import collections, hashlib, json, pathlib, re, shutil, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from check import norm, evidence_score, html_to_text, is_html, page_text_of  # noqa: E402

FORMAT = "claims-snapshot/0.3"
KIND_MAP = {"capability": "other", "status": "other", "process": "process", "number": "figure", "figure": "figure",
            "conduct": "other", "licence": "rule", "rule": "rule", "comparison": "comparison", "date": "figure",
            "price": "figure", "quote": "quote", "citation": "citation", "negative": "negative", "promise": "promise",
            "arithmetic": "arithmetic", "page": "page-internal", "page-internal": "page-internal", "other": "other"}
LOW_WORD = re.compile(r"\blow\b", re.I)
CONFIDENCE_WORD = re.compile(r"confiden", re.I)
CARRIED = re.compile(r"^carried from ([\w.-]+):\s*", re.I)
MAX_QUOTED_LINES = 6
MAX_QUOTE_CHARS = 400
QUOTED = re.compile(r"[\"“]([^\"”]{3,}?)[\"”]|(?<![\w])'([^']{3,}?)'(?![\w])|‘([^’]{3,}?)’")
HEX = re.compile(r"0x[0-9a-fA-F]{6,}")
NUMBER = re.compile(r"(?<![\w.])\d{5,}(?![\w.])")
ISO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(p):
    return sha256_bytes(pathlib.Path(p).read_bytes())


def jl(p):
    return [json.loads(l) for l in pathlib.Path(p).read_text(encoding="utf-8").splitlines() if l.strip()]


def anchors(tail):
    """Verbatim fragments a free-text ref asserts about its source: quoted strings first, then hashes, long numbers and
    timestamps. A truncated hash ('0x9fccbd30…') keeps its prefix, which is still a verbatim substring."""
    out = []
    for m in QUOTED.finditer(tail):
        q = next(g for g in m.groups() if g)
        q = re.split(r"\.\.\.|…", q)[0].strip()
        if q and q not in out:
            out.append(q)
    if out:
        return out
    for pat in (HEX, ISO, NUMBER):
        for m in pat.finditer(tail):
            if m.group(0) not in out:
                out.append(m.group(0))
    return out


def lines_of(text):
    return text.split("\n")


class SiteRun:
    def __init__(self, cfg):
        self.cfg = cfg
        self.dir = pathlib.Path(cfg["run_dir"])
        self.run = json.loads((self.dir / "run.json").read_text(encoding="utf-8"))
        self.claims = jl(self.dir / "claims.jsonl")
        self.prove = {r["id"]: r for r in jl(self.dir / "prove.jsonl")}
        self.disprove = {r["id"]: r for r in jl(self.dir / "disprove.jsonl")}
        self.score = json.loads((self.dir / "score.json").read_text(encoding="utf-8")) if (self.dir / "score.json").exists() else None
        self.page_text = {}      # raw, as served: the lister's line numbers refer to these lines
        self.page_is_html = {}
        for p in sorted((self.dir / "sources").iterdir()):
            if p.is_file():
                self.page_text[p.name] = p.read_text(encoding="utf-8", errors="replace")
                self.page_is_html[p.name] = is_html(p.name, self.page_text[p.name])
        # as the lister read it (an HTML surface as rendered text, line for line): what claim texts and quotes are
        # matched against, and where quotes are taken from
        self.page_render = {k: page_text_of(k, v) for k, v in self.page_text.items()}
        self.page_norm = {k: norm(v) for k, v in self.page_render.items()}
        for k in self.page_text:
            if self.page_text[k].count("\n") != self.page_render[k].count("\n"):
                print(f"WARN {k}: rendered text has a different line count from the raw body; line refs may drift", file=sys.stderr)
        self.fetch_log = []
        if (self.dir / "fetch-log.json").exists():
            self.fetch_log = json.loads((self.dir / "fetch-log.json").read_text(encoding="utf-8"))
        self.graded_sha = {}
        if (self.dir / "sources.sha256").exists():
            for l in (self.dir / "sources.sha256").read_text(encoding="utf-8").splitlines():
                parts = l.split()
                if len(parts) == 2:
                    self.graded_sha[parts[1].split("/")[-1]] = parts[0]
        # fetched/ (third-party pages, numbered by fetch order)
        self.fetched_meta, self.fetched_index, self.fetched_text_index = {}, {}, {}
        fd = self.dir / "fetched"
        if (fd / "meta.json").exists():
            self.fetched_meta = json.loads((fd / "meta.json").read_text(encoding="utf-8"))
        if (fd / "index.json").exists():
            self.fetched_index = json.loads((fd / "index.json").read_text(encoding="utf-8"))
        if (fd / "text-index.json").exists():
            self.fetched_text_index = json.loads((fd / "text-index.json").read_text(encoding="utf-8"))
        self.fetched_at = self.fetched_meta.get("_fetched_at") or self.run.get("fetched_at")
        self.fetched_by_file = {}   # "005" -> url
        for url, m in self.fetched_meta.items():
            if isinstance(m, dict) and m.get("file"):
                self.fetched_by_file[m["file"].split(".")[0]] = url
        self.fetched_by_url = {u.split("#")[0]: m for u, m in self.fetched_meta.items() if isinstance(m, dict)}
        self.extractor = None
        if (fd / "text-extractor.json").exists():
            self.extractor = json.loads((fd / "text-extractor.json").read_text(encoding="utf-8"))
        self.http_cache = json.loads((self.dir / "http-cache.json").read_text(encoding="utf-8")) if (self.dir / "http-cache.json").exists() else {}
        self._text_cache = {}

    def fetched_text(self, nnn):
        """The visible-text copy of fetched page nnn (NNN.txt), else the raw body decoded."""
        if nnn in self._text_cache:
            return self._text_cache[nnn]
        t = None
        for name in (f"{nnn}.txt", f"{nnn}.body"):
            p = self.dir / "fetched" / name
            if p.exists() and p.stat().st_size > 0:
                t = p.read_text(encoding="utf-8", errors="replace")
                break
        self._text_cache[nnn] = t
        return t

    def repo_text(self, alias, path):
        key = (alias, path)
        if key in self._text_cache:
            return self._text_cache[key]
        p = self.dir / alias / path
        t = p.read_text(encoding="utf-8", errors="replace") if p.is_file() else None
        self._text_cache[key] = t
        return t


class Builder:
    def __init__(self, cfg):
        self.cfg = cfg
        self.run = SiteRun(cfg)
        self.out = pathlib.Path(cfg["out_dir"])
        self.repos = cfg.get("repos", {})
        self.sources = []            # manifest.sources entries, in order of first use
        self.source_by_key = {}      # ("repo", alias, path) / ("fetched", nnn) / ("http", url) / ("webfetch", name) -> entry
        self.warnings = []

    # --- sources ---------------------------------------------------------------------------------
    def repo_source(self, alias, path):
        key = ("repo", alias, path)
        if key in self.source_by_key:
            return self.source_by_key[key]
        spec = self.repos.get(alias)
        text = self.run.repo_text(alias, path)
        if spec is None or text is None:
            return None
        entry = {"n": len(self.sources) + 1,
                 "url": f"https://raw.githubusercontent.com/{spec['github']}/{spec['commit']}/{path}",
                 "file": f"sources/{alias}/{path}" if spec.get("copy", "text") == "text" else None,
                 "sha256": sha256_file(self.run.dir / alias / path),
                 "copy": "text" if spec.get("copy", "text") == "text" else "hash-only",
                 "fetched_at": self.run.run.get("fetched_at"),
                 "repo": {"github": spec["github"], "commit": spec["commit"], "path": path, "licence": spec.get("licence")},
                 "note": f"{spec['github']} at {spec['commit'][:8]} ({spec.get('licence', 'licence not stated')}): the grader read a read-only clone at that commit; the url is the file at that commit"}
        if entry["file"]:
            dest = self.out / entry["file"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.run.dir / alias / path, dest)
        self.sources.append(entry)
        self.source_by_key[key] = entry
        return entry

    def fetched_source(self, nnn):
        key = ("fetched", nnn)
        if key in self.source_by_key:
            return self.source_by_key[key]
        url = self.run.fetched_by_file.get(nnn)
        if url is None:
            return None
        meta = self.run.fetched_meta.get(url, {})
        text = self.run.fetched_text(nnn)
        host = re.sub(r"^https?://([^/]+).*$", r"\1", url)
        own = host in set(self.cfg.get("own_hosts", []))
        as_text = text is not None and meta.get("status") == 200 and (own or self.cfg.get("third_party_copy") == "text")
        n = len(self.sources) + 1
        txt_path = self.run.dir / "fetched" / f"{nnn}.txt"
        copy_of = "html" if txt_path.exists() else "body"
        entry = {"n": n, "url": url, "file": f"sources/{n:03d}.txt" if as_text else None,
                 "sha256": sha256_bytes(text.encode("utf-8")) if text is not None else None,
                 "copy": "text" if as_text else ("hash-only" if text is not None and meta.get("status") == 200 else "none"),
                 "copy_name": f"{nnn}.txt" if txt_path.exists() else f"{nnn}.body",
                 "fetched_at": self.run.fetched_at, "status": meta.get("status"), "body_sha256": meta.get("sha256"),
                 "text_copy_of": copy_of}
        if copy_of == "html" and self.run.extractor:
            entry["extractor"] = {"note": "visible text extracted from the fetched body by the grader's script; the hash is of the extraction, not the body",
                                  "files": [{"file": self.run.extractor.get("script"), "sha256": self.run.extractor.get("sha256")}]}
        if entry["copy"] == "none":
            entry["note"] = meta.get("error") or f"answered {meta.get('status')} to the scripted GET; nothing saved"
        if as_text:
            (self.out / "sources").mkdir(parents=True, exist_ok=True)
            (self.out / entry["file"]).write_text(text, encoding="utf-8")
        self.sources.append(entry)
        self.source_by_key[key] = entry
        return entry

    def http_source(self, url, status):
        key = ("http", url)
        if key in self.source_by_key:
            e = self.source_by_key[key]
            if e.get("status") is None and status is not None:
                e["status"] = status
            return e
        cached = self.run.http_cache.get(url) or {}
        entry = {"n": len(self.sources) + 1, "url": url, "file": None, "sha256": None, "copy": "none",
                 "fetched_at": self.run.run.get("fetched_at"), "status": status if status is not None else cached.get("status"),
                 "body_sha256": cached.get("sha256"),
                 "note": "fetched live by the grader's worker on the publisher's own hosts and not saved; the status code, and a body hash where the harness recorded one, are the record. Not checkable offline; --fetch compares the status"}
        self.sources.append(entry)
        self.source_by_key[key] = entry
        return entry

    def webfetch_source(self, name):
        key = ("webfetch", name)
        if key in self.source_by_key:
            return self.source_by_key[key]
        url = (self.cfg.get("webfetch_files") or {}).get(name)
        entry = {"n": len(self.sources) + 1, "url": url, "file": None, "sha256": None, "copy": "none", "status": None,
                 "note": f"quoted through a summarising fetch ({name} in the run), no saved body, so its quotes are not checkable"}
        if url and url.split("#")[0] in self.run.fetched_by_url:
            entry["status"] = self.run.fetched_by_url[url.split("#")[0]].get("status")
        self.sources.append(entry)
        self.source_by_key[key] = entry
        return entry

    # --- refs ------------------------------------------------------------------------------------
    def lines_quote(self, text, a, b):
        """The cited lines as one verbatim quote, taken from the text as the checker reads it (an HTML surface's rendered
        text, line for line with the raw body). A range longer than MAX_QUOTED_LINES is quoted by its first non-empty
        line (still verbatim, still inside the cited range; the file's hash covers the rest), and the caller notes it."""
        ls = lines_of(text)
        if a < 1 or b > len(ls) or b < a:
            return None
        if b - a + 1 > MAX_QUOTED_LINES:
            for l in ls[a - 1:b]:
                if l.strip():
                    return re.sub(r"\s+", " ", l).strip()
            return None
        q = re.sub(r"\s+", " ", " ".join(l.strip() for l in ls[a - 1:b])).strip()
        return q or None

    @staticmethod
    def range_note(a, b):
        return f"first line of the cited range L{a}-{b}; the file's hash covers the rest" if b - a + 1 > MAX_QUOTED_LINES else None

    @staticmethod
    def cap_quote(quote, tail_anchors):
        """A cited 'line' of a single-line JSON or minified JS file can be the whole file. Over MAX_QUOTE_CHARS the quote
        becomes the fragments the grader's text names when it names any, else the line's first MAX_QUOTE_CHARS characters
        (still verbatim, still inside the cited line; the file's hash covers the rest). Returns (quotes, note)."""
        if quote is None or len(quote) <= MAX_QUOTE_CHARS:
            return ([quote] if quote is not None else []), None
        if tail_anchors:
            return tail_anchors, f"the cited line is {len(quote)} characters long; quoted by the fragments the grader named"
        return [quote[:MAX_QUOTE_CHARS].rstrip()], f"first {MAX_QUOTE_CHARS} characters of the cited line ({len(quote)} characters, a single-line file); the file's hash covers the rest"

    def parse_ref(self, ref):
        """One grader ref -> list of proof-shaped dicts: {file, url, quote, note, expect_status, kind}, kind in
        page | repo | fetched | http | webfetch | note. A quote-less dict with a file is an existence proof; a quote-less
        dict with expect_status is a status proof; a dict with neither file nor url is a note only."""
        ref = ref.strip()
        m = re.match(r"^sources/([\w.-]+)(?:#L(\d+)(?:-L?(\d+))?)?(.*)$", ref)
        if m:
            name, a, b, tail = m.group(1), m.group(2), m.group(3), m.group(4).strip()
            if name not in self.run.page_text:
                return [{"kind": "note", "note": ref}]
            file = f"pages/{name}"
            out = []
            quote = None
            if a:
                quote = self.lines_quote(self.run.page_render[name], int(a), int(b or a))
            tail_anchors = anchors(tail) if tail else []
            if quote is not None:
                quotes, cap_note = self.cap_quote(quote, tail_anchors)
                rn = self.range_note(int(a), int(b or a))
                note = " ".join(x for x in (tail, rn, cap_note) if x) or None
                for q in quotes:
                    out.append({"kind": "page", "file": file, "url": None, "quote": q, "line": int(a), **({"note": note} if note else {})})
            elif tail_anchors:
                for q in tail_anchors:
                    out.append({"kind": "page", "file": file, "url": None, "quote": q, "note": tail})
            else:
                out.append({"kind": "page", "file": file, "url": None, "quote": None, "note": tail or ("cited without a line" if not a else "cited line out of range")})
            return out
        m = re.match(r"^(repo)/([\w./@-]+?)(?:#L(\d+)(?:-L?(\d+))?)?(?:#([^\s]*))?(\s.*)?$", ref)
        if m:
            alias, path, a, b, frag, tail = m.group(1), m.group(2).rstrip("/"), m.group(3), m.group(4), m.group(5), (m.group(6) or "").strip()
            src = self.repo_source(alias, path)
            if src is None:
                return [{"kind": "note", "note": ref}]
            text = self.run.repo_text(alias, path)
            quote = self.lines_quote(text, int(a), int(b or a)) if a else None
            tail_all = " ".join(x for x in (frag, tail) if x).strip()
            if quote is not None:
                quotes, cap_note = self.cap_quote(quote, anchors(tail_all) if tail_all else [])
                note = " ".join(x for x in (tail_all, self.range_note(int(a), int(b or a)), cap_note) if x) or None
                return [{"kind": "repo", "file": src["file"], "url": src["url"], "quote": q, "line": int(a), **({"note": note} if note else {})} for q in quotes]
            qs = anchors(tail_all) if tail_all else []
            if qs:
                return [{"kind": "repo", "file": src["file"], "url": src["url"], "quote": q, "note": tail_all} for q in qs]
            return [{"kind": "repo", "file": src["file"], "url": src["url"], "quote": None, "note": tail_all or "the file's presence at the pinned commit is the artefact"}]
        if ref.startswith("repo"):
            return [{"kind": "note", "note": ref}]
        m = re.match(r"^fetched/(\d{3})(?:\.(?:body|txt))?(?:#L\d+(?:-L?\d+)?)?(?:#)?(.*)$", ref)
        if m:
            nnn, tail = m.group(1), m.group(2).strip()
            src = self.fetched_source(nnn)
            if src is None:
                return [{"kind": "note", "note": ref}]
            file = f"sources/{src['n']:03d}.txt"
            qs = anchors(tail) if tail else []
            if qs:
                return [{"kind": "fetched", "file": file, "url": src["url"], "quote": q, "note": tail} for q in qs]
            return [{"kind": "fetched", "file": file, "url": src["url"], "quote": None, "note": tail or "the saved copy is the artefact"}]
        m = re.match(r"^fetched/([\w.-]+)(?:#L(\d+)(?:-L?(\d+))?)?(.*)$", ref)
        if m:
            name, a, b, tail = m.group(1), m.group(2), m.group(3), m.group(4).strip()
            if name in ("meta.json", "index.json", "sha256.txt", "text-index.json", "text-extractor.json"):
                return [{"kind": "note", "note": "the fetch record (" + ref + ")"}]
            src = self.webfetch_source(name)
            quote = None
            p = self.run.dir / "fetched" / name
            if a and p.exists():
                quote = self.lines_quote(p.read_text(encoding="utf-8", errors="replace"), int(a), int(b or a))
            return [{"kind": "webfetch", "file": None, "url": src["url"], "quote": quote, "note": (tail + " " if tail else "") + "via a summarising fetch, no saved copy"}]
        m = re.match(r"^(https?://\S+?)(?:#(.*))?$", ref, re.S)
        if m:
            url, tail = m.group(1), (m.group(2) or "").strip()
            url = url.rstrip(",.;")
            status = None
            sm = re.match(r"^(?:HTTP\s*)?(\d{3})\b(.*)$", tail, re.S)
            if sm:
                status, tail = int(sm.group(1)), sm.group(2).strip()
            fm = self.run.fetched_by_url.get(url)
            if fm and fm.get("file"):
                src = self.fetched_source(fm["file"].split(".")[0])
                file = f"sources/{src['n']:03d}.txt"
                qs = anchors(tail) if tail else []
                if qs:
                    return [{"kind": "fetched", "file": file, "url": url, "quote": q, "note": tail} for q in qs]
                return [{"kind": "fetched", "file": file, "url": url, "quote": None, "note": tail or "the saved copy is the artefact"}]
            src = self.http_source(url, status)
            qs = anchors(tail) if tail else []
            if qs:
                # a status proof that also names words seen on the live page: K10 fetches and looks for them
                return [{"kind": "http", "file": None, "url": url, "quote": q, "expect_status": src.get("status"), "note": tail} for q in qs]
            return [{"kind": "http", "file": None, "url": url, "quote": None, "expect_status": src.get("status"), "note": tail or None}]
        return [{"kind": "note", "note": ref}]

    def verify(self, p):
        """Set verified on a proof-shaped dict from the run's own copies (the checker repeats this on the snapshot)."""
        f = p.get("file")
        q = p.get("quote")
        if f is None:
            p["verified"] = False
            return
        if f.startswith("pages/"):
            text = self.run.page_norm.get(f[len("pages/"):])
        elif f.startswith("sources/repo/") or any(f.startswith(f"sources/{alias}/") for alias in self.repos):
            alias = f.split("/")[1]
            text = self.run.repo_text(alias, "/".join(f.split("/")[2:]))
            text = norm(text) if text is not None else None
        else:
            src = next((s for s in self.sources if s.get("file") == f or (s.get("copy_name") and f == f"sources/{s['n']:03d}.txt")), None)
            text = None
            if src and src.get("copy_name"):
                t = self.run.fetched_text(src["copy_name"].split(".")[0])
                text = norm(t) if t is not None else None
        if text is None:
            p["verified"] = False
        elif q is None:
            p["verified"] = True      # existence proof: the copy is at hand
        else:
            p["verified"] = bool(norm(q)) and norm(q) in text

    @staticmethod
    def strip_internal(d):
        return {k: v for k, v in d.items() if k not in ("kind",) and v is not None}

    # --- build -----------------------------------------------------------------------------------
    def build(self):
        cfg, run = self.cfg, self.run
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "pages").mkdir(exist_ok=True)
        ga = cfg.get("graded_at", {})
        kind_map = dict(KIND_MAP, **cfg.get("kind_map", {}))

        # pages: every audited surface, with its url from the lister's locators or the config
        page_urls = dict(cfg.get("page_urls", {}))
        for e in run.fetch_log:
            f = str(e.get("file", "")).split("/")[-1]
            if f and e.get("url") and f not in page_urls:
                page_urls[f] = e["url"]
        for c in run.claims:
            for s in c.get("sources", []):
                mm = re.match(r"^sources/(\S+)", s.get("locator", ""))
                if mm and s.get("url") and mm.group(1) not in page_urls:
                    page_urls[mm.group(1)] = s["url"]
        pages = []
        for name, text in run.page_text.items():
            shutil.copyfile(run.dir / "sources" / name, self.out / "pages" / name)
            h = sha256_file(self.out / "pages" / name)
            if run.graded_sha.get(name) and run.graded_sha[name] != h:
                raise SystemExit(f"{name}: hash differs from the run's sources.sha256")
            pages.append({"file": f"pages/{name}", "url": page_urls.get(name), "sha256": h, "lines": len(lines_of(text)),
                          "fetched_at": run.run.get("fetched_at"), "read_as": "html-text" if run.page_is_html[name] else "as-served"})
            if not page_urls.get(name):
                self.warnings.append(f"page {name}: no url known (add page_urls in the config)")

        private = {}
        pe = cfg.get("private_evidence", str(run.dir / "private-evidence.json"))
        if pe and pathlib.Path(pe).exists():
            private = json.loads(pathlib.Path(pe).read_text(encoding="utf-8"))
        judge = json.loads(pathlib.Path(cfg["judge"]).read_text(encoding="utf-8")) if cfg.get("judge") else {}
        withdrawn = json.loads(pathlib.Path(cfg["withdrawn"]).read_text(encoding="utf-8")) if cfg.get("withdrawn") else {}
        withdrawn = {k: v for k, v in withdrawn.items() if not k.startswith("_")}

        rows, page_only_ids, untestable_e = [], [], []
        for c in run.claims:
            cid = c["id"]
            pr, dp = run.prove.get(cid, {}), run.disprove.get(cid, {})
            if not pr or not dp:
                raise SystemExit(f"{cid}: missing a pass row")
            # verdict rule (the claims session's): C if disprove yes, else E if prove artefact, else N
            if dp.get("contradiction") == "yes":
                v = "CONTRADICTED"
            elif pr.get("evidence") == "artefact":
                v = "EVIDENCED"
            else:
                v = "NO EVIDENCE PUBLISHED"
            history, graded_at, carried_from = None, ga.get("grade"), None
            on_request = None
            cm = CARRIED.match(pr.get("note", "")) or CARRIED.match(dp.get("note", ""))
            if cm:
                carried_from = cm.group(1)
                graded_at = (cfg.get("runs") or {}).get(carried_from, graded_at)
                history = f"Carried unchanged from run {carried_from} (the cited lines and pages were found unchanged by the delta rule)"
            if cid in judge:
                jv = judge[cid]["verdict"].strip().upper()
                history = ("Ruled by the orchestrator after both passes: " + judge[cid].get("note", "")).strip()
                v = jv
                graded_at = ga.get("judge", graded_at)
            if cid in private and v == "NO EVIDENCE PUBLISHED":
                v = "EVIDENCE AVAILABLE ON REQUEST"
                rec = private[cid]
                on_request = {"holder": rec.get("holder"), "sha256": rec.get("sha256"), "shown": rec.get("shown"),
                              "seen_by": rec.get("seen_by"), "what": rec.get("note")}
                graded_at = ga.get("on_request", graded_at)
                history = (history + "; " if history else "") + "the publisher holds the evidence privately and showed it to the grader, who recorded its hash"
            elif cid in private:
                self.warnings.append(f"{cid}: in private-evidence.json but graded {v}; left as graded")
            if cid in withdrawn:
                v = "WITHDRAWN"
                history = "Withdrawn by the publisher: " + str(withdrawn[cid])
            kind = kind_map.get(str(c.get("kind", "other")).lower(), "other")
            conf = None
            if v == "CONTRADICTED":
                note_src = dp.get("note", "")
                conf = "low" if (LOW_WORD.search(note_src) and CONFIDENCE_WORD.search(note_src)) else "high"
            prove_refs = [p for r in pr.get("refs", []) for p in self.parse_ref(r)]
            dis_refs = [p for r in dp.get("refs", []) for p in self.parse_ref(r)]
            notes_only = [p["note"] for p in prove_refs + dis_refs if p.get("kind") == "note"]
            prove_refs = [p for p in prove_refs if p.get("kind") != "note"]
            dis_refs = [p for p in dis_refs if p.get("kind") != "note"]
            located = []
            location = []
            for s in c.get("sources", []):
                mm = re.match(r"^sources/(\S+) L(\d+)(?:-L?(\d+))?", s.get("locator", ""))
                if mm and mm.group(1) in run.page_text:
                    a, b = int(mm.group(2)), int(mm.group(3) or mm.group(2))
                    location.append({"file": f"pages/{mm.group(1)}", "line": a})
                    q = self.lines_quote(run.page_render[mm.group(1)], a, b)
                    if q:
                        qs, cap_note = self.cap_quote(q, [])
                        located.append({"file": f"pages/{mm.group(1)}", "quote": qs[0], **({"note": cap_note} if cap_note else {})})
            proofs, counter, consulted = [], [], []
            if v == "EVIDENCED":
                proofs = prove_refs
                consulted = dis_refs
            elif v == "CONTRADICTED":
                counter = dis_refs
                consulted = prove_refs
            else:
                consulted = prove_refs + dis_refs
            # a page of the publisher's own cited without a quotable line is a locator, never a proof or a counter
            for lst in (proofs, counter):
                for p in [p for p in lst if p.get("kind") == "page" and p.get("quote") is None]:
                    lst.remove(p)
                    consulted.append(p)
            for p in proofs + counter:
                self.verify(p)
            # a quote taken from one of the publisher's own pages that does not verify against that page as the checker
            # reads it is not published as a proof: it is a locator with the reason (never silently a failing quote)
            for lst in (proofs, counter):
                for p in [p for p in lst if p.get("kind") == "page" and p.get("quote") is not None and not p.get("verified")]:
                    lst.remove(p)
                    p.pop("verified", None)
                    p["note"] = ((p.get("note") + "; ") if p.get("note") else "") + "the cited line could not be quoted as the page's text; kept as a locator"
                    p["quote"] = None
                    consulted.append(p)
            if v == "EVIDENCED":
                if proofs and all(p.get("file", "").startswith("pages/") for p in proofs if p.get("file")) and not any(p.get("expect_status") for p in proofs):
                    page_only_ids.append(cid)
                if not any(p.get("verified") for p in proofs):
                    untestable_e.append(cid)
            for lst in (consulted,):
                for p in lst:
                    p.pop("verified", None)
            note = (dp.get("note", "") if v == "CONTRADICTED" else pr.get("note", "")).strip()
            if cm:
                note = CARRIED.sub("", note)
            other = (pr.get("note", "") if v == "CONTRADICTED" else dp.get("note", "")).strip()
            if cm:
                other = CARRIED.sub("", other)
            if on_request:
                note = (on_request["what"] + " " if on_request.get("what") else "") + "(" + note + ")" if note else (on_request.get("what") or "")
            text = c["claim"]
            frags = [norm(f) for f in text.split("[...]") if norm(f)]
            if not all(any(f in pn for pn in run.page_norm.values()) for f in frags):
                self.warnings.append(f"{cid}: claim text not found verbatim on any audited page")
            rows.append({
                "id": cid, "text": text, "location": location, "kind": kind, "checkable": kind != "promise",
                "verdict": v, "confidence": conf,
                "proofs": [self.strip_internal(p) for p in proofs],
                "counter": [self.strip_internal(p) for p in counter],
                "located": located,
                "consulted": [self.strip_internal(p) for p in consulted],
                "searched": notes_only,
                "note": note, "other_pass_note": other or None,
                "on_request": on_request,
                "history": history, "graded_by": "grader", "graded_at": graded_at, "carried_from": carried_from,
                "lister": {"kind": c.get("kind"), "checkability": c.get("checkability"), "status": c.get("status")},
            })
        claims_bytes = ("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n").encode("utf-8")
        (self.out / "claims.jsonl").write_bytes(claims_bytes)

        s = evidence_score(rows)
        counts = {k: s[k] for k in ("claims", "checkable", "evidenced", "on_request", "no_evidence", "contradicted", "contradicted_high", "withdrawn", "author_read")}
        counts["carried"] = sum(1 for r in rows if r.get("carried_from"))
        score = {"coverage_pct": s["coverage_pct"], "contradiction_pct": s["contradiction_pct"], "band": s["band"], "formula": "evidence-score/1",
                 "note": "computed on the rows of this snapshot by evidence-score/1 (coverage = evidenced plus on request over the checkable rows, contradiction over the same, rounded half to even; band A>=90 B>=75 C>=50 D>=25 else E, capped at C by a high-confidence contradiction and at D by contradiction above 5%)"}
        if run.score:
            exp = run.score
            got = {"evidenced": counts["evidenced"], "contradicted": counts["contradicted"], "contradicted_high": counts["contradicted_high"],
                   "no_evidence_plus_on_request": counts["no_evidence"] + counts["on_request"]}
            want = {"evidenced": exp.get("evidenced"), "contradicted": exp.get("contradicted"), "contradicted_high": exp.get("contradicted_high"),
                    "no_evidence_plus_on_request": (exp.get("no_evidence") or 0) + (exp.get("on_request") or 0)}
            if not judge and not withdrawn and got != want:
                raise SystemExit(f"verdict counts differ from the run's score.json: {got} vs {want}")
        extractors = []
        for x in cfg.get("extractors", []):
            px = pathlib.Path(x)
            extractors.append({"file": px.name, "sha256": sha256_file(px)})
        manifest = {
            "format": FORMAT,
            "subject": dict(cfg["subject"], parts=[p["url"] for p in pages if p.get("url")]),
            "taken_at": cfg.get("taken_at") or run.run.get("fetched_at"),
            "pages_note": cfg.get("page_note", ""),
            "pages": pages,
            "sources": self.sources,
            "grading": dict(cfg["grading"], profile="publisher-surfaces"),
            "counts": counts,
            "score": score,
            "claims_sha256": sha256_bytes(claims_bytes),
        }
        if extractors:
            manifest["extractors"] = extractors
        (self.out / "manifest.json").write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        by_copy = collections.Counter(s_["copy"] for s_ in self.sources)
        print(f"snapshot {self.out}: {counts['claims']} claims (E {counts['evidenced']}, on request {counts['on_request']}, C {counts['contradicted']} "
              f"({counts['contradicted_high']} high), N {counts['no_evidence']}, withdrawn {counts['withdrawn']}, carried {counts['carried']}), "
              f"{score['coverage_pct']}% / {score['contradiction_pct']}% band {score['band']}; {len(pages)} pages, {len(self.sources)} sources "
              f"({by_copy.get('text', 0)} text, {by_copy.get('hash-only', 0)} hash-only, {by_copy.get('none', 0)} none)")
        print(f"EVIDENCED rows whose every proof is a quote from the publisher's own pages: {len(page_only_ids)} {page_only_ids}")
        print(f"EVIDENCED rows with no proof verifiable from the run's copies: {len(untestable_e)} {untestable_e}")
        for w in self.warnings:
            print("WARN", w, file=sys.stderr)


if __name__ == "__main__":
    Builder(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))).build()
