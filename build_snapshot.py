#!/usr/bin/env python3
"""build_snapshot.py: convert a claims-audit run of the cited-sources profile (a brief: claims.jsonl, prove.jsonl,
disprove.jsonl, fetched/, cited-urls.txt, score.json) plus its delta re-grade and the author's corrections into a
claims snapshot (SPEC.md, format claims-snapshot/0.2).

usage: python3 -I build_snapshot.py CONFIG.json
CONFIG keys: run_dir, brief_dir (part-*.html, claims-after-audit.json, corrections.json), delta (path or null), out_dir,
  subject {title,url,publisher,parts}, taken_at, page_note, sources_fetched_at, copy ("hash-only"|"text"), own_hosts,
  page_internal_ids [ids whose claim is about the page itself: hand-reviewed, never inferred],
  grading {grader, model, method, graded_at, gates [...], rounds [...]},
  graded_at {r1, delta, corrections}  ISO times per grading step,
  extractors [paths of the scripts that made the PDF text copies].
Site runs (publisher-surfaces profile: many files, refs without quotes, unsaved worker GETs) are NOT converted by this
script yet; see SPEC.md section 10. Standard library only."""
import difflib, hashlib, json, pathlib, re, shutil, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools" / "claims-list"))
from claimslib import Run, norm, on_page_now, load_after  # noqa: E402

VERDICT_NAME = {"E": "EVIDENCED", "C": "CONTRADICTED", "N": "NO EVIDENCE PUBLISHED"}
VERDICT_LETTER = {"EVIDENCED": "E", "CONTRADICTED": "C", "NO EVIDENCE PUBLISHED": "N"}
KIND_MAP = {"figure": "figure", "number": "figure", "arithmetic": "arithmetic", "price": "figure", "date": "figure",
            "quote": "quote", "citation": "citation", "negative": "negative", "comparison": "comparison",
            "process": "process", "rule": "rule", "promise": "promise", "method": "other", "action": "other",
            "property": "other", "assertion": "other", "page": "page-internal", "self": "page-internal"}
LOW_WORD = re.compile(r"\blow\b", re.I)
CONFIDENCE_WORD = re.compile(r"confiden", re.I)
BANDS = [(90, "A"), (75, "B"), (50, "C"), (25, "D"), (0, "E")]


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def text_copy(run, n):
    """The grader's text copy of source n: the PDF extraction when the source was a PDF, else the HTML text copy."""
    for name in (f"{n:03d}.pdf-text.txt", f"{n:03d}.txt"):
        p = run.dir / "fetched" / name
        if p.exists() and p.stat().st_size > 0:
            return p
    return None


def parse_ref(ref, run, page_file, current_lines):
    """One grader ref -> list of dicts {file, url, quote, is_page}. Unsaved sources get file None. A bare page locator
    (sources/<brief>.txt#L<n>, no quote) takes the graded line and finds its best match on the CURRENT page, so the quote
    is verbatim on the page the snapshot publishes; a locator with no match is dropped with a warning."""
    ref = ref.strip()
    quotes = [q.strip() for q in re.findall(r'"([^"]+)"', ref) if q.strip()]
    where = ref.split('"')[0].strip()
    out = []
    if re.search(r"fetched/(?:meta|index|sha256|text-index|README)", where):
        return out
    if "webfetch" in where.lower():
        url = where.split("#")[0].strip() if where.startswith("http") else None
        for q in quotes or [""]:
            out.append({"file": None, "url": url, "quote": q, "note": "via a summarising fetch, no saved copy"})
        return out
    m = re.search(r"fetched/(\d{3})", where)
    if m:
        n = int(m.group(1))
        for q in quotes or [""]:
            out.append({"file": f"sources/{n:03d}.txt", "url": run.urls[n - 1] if n <= len(run.urls) else None, "quote": q})
        return out
    if "sources/" in where or ("part" in where and ".txt" in where) or where.startswith("L") or where == "":
        if not quotes:
            lm = re.search(r"#?L(\d+)", where)
            if lm and "sources/" in where and int(lm.group(1)) <= len(run.graded_lines):
                graded = run.graded_lines[int(lm.group(1)) - 1].strip()
                best, ratio = None, 0.0
                for cl in current_lines:
                    r = difflib.SequenceMatcher(None, norm(graded), norm(cl)).ratio()
                    if r > ratio:
                        best, ratio = cl, r
                if best is not None and ratio >= 0.6:
                    quotes = [best.strip()]
                else:
                    print(f"WARN locator {where}: graded line has no match on the current page (best ratio {ratio:.2f}); dropped", file=sys.stderr)
                    return out
        for q in quotes or [""]:
            out.append({"file": page_file, "url": None, "quote": q, "is_page": True})
        return out
    if where.startswith("http"):
        url = where.split("#")[0].split(" ")[0].strip()
        n = run.url_no.get(url)
        for q in quotes or [""]:
            out.append({"file": f"sources/{n:03d}.txt" if n else None, "url": url, "quote": q})
        return out
    for q in quotes:
        out.append({"file": page_file, "url": None, "quote": q, "is_page": True})
    return out


def score(rows):
    k = [r for r in rows if r["verdict"] != "WITHDRAWN" and r.get("checkable", True) and r["kind"] != "promise"]
    e = sum(r["verdict"] == "EVIDENCED" for r in k)
    on_req = sum(r["verdict"] == "EVIDENCE AVAILABLE ON REQUEST" for r in k)
    c = [r for r in k if r["verdict"] == "CONTRADICTED"]
    c_high = sum(r.get("confidence") == "high" for r in c)
    cov = round(100 * (e + on_req) / len(k))
    con = round(100 * len(c) / len(k))
    band = next(b for lo, b in BANDS if cov >= lo)
    if c_high and band in ("A", "B"):
        band = "C"
    if con > 5 and band in ("A", "B", "C"):
        band = "D"
    counts = {"claims": len(rows), "checkable": len(k), "evidenced": e, "on_request": on_req,
              "no_evidence": sum(r["verdict"] == "NO EVIDENCE PUBLISHED" for r in k), "contradicted": len(c),
              "contradicted_high": c_high, "withdrawn": sum(r["verdict"] == "WITHDRAWN" for r in rows),
              "author_read": sum(r.get("graded_by") == "author" for r in rows)}
    return counts, {"coverage_pct": cov, "contradiction_pct": con, "band": band, "formula": "evidence-score/1",
                    "note": "computed on the rows of this snapshot by evidence-score/1 (coverage and contradiction over the checkable rows, rounded half to even; band A>=90 B>=75 C>=50 D>=25 else E, capped at C by a high-confidence contradiction and at D by contradiction above 5%)"}


def main(cfg_path):
    cfg = json.loads(pathlib.Path(cfg_path).read_text(encoding="utf-8"))
    run = Run(cfg["run_dir"])
    brief = pathlib.Path(cfg["brief_dir"])
    out = pathlib.Path(cfg["out_dir"])
    out.mkdir(parents=True, exist_ok=True)
    (out / "sources").mkdir(exist_ok=True)
    page_file = "page.txt"
    ga = cfg.get("graded_at", {})
    page_internal = set(cfg.get("page_internal_ids", []))

    parts = sorted(brief.glob("part-*.html"), key=lambda p: int(re.search(r"part-(\d+)", p.name).group(1)))
    lines = []
    for p in parts:
        lines.append(f"=== {p.name} ===")
        lines.extend(run.html_to_text(p))
    page_text = "\n".join(lines) + "\n"
    (out / page_file).write_text(page_text, encoding="utf-8")
    page_norm = norm(page_text)

    after, _ = load_after(brief / "claims-after-audit.json")
    corrections = {k: v for k, v in json.loads((brief / "corrections.json").read_text(encoding="utf-8")).items() if not k.startswith("_")}
    delta = {}
    if cfg.get("delta"):
        for l in pathlib.Path(cfg["delta"]).read_text(encoding="utf-8").splitlines():
            if l.strip():
                d = json.loads(l)
                delta[d["id"]] = d

    # sources
    meta = json.loads((run.dir / "fetched" / "meta.json").read_text(encoding="utf-8"))
    own_hosts = set(cfg.get("own_hosts", []))
    extractors = [{"file": str(pathlib.Path(x).relative_to(run.dir)) if str(x).startswith(str(run.dir)) else x,
                   "sha256": sha256_bytes(pathlib.Path(x).read_bytes())} for x in cfg.get("extractors", [])]
    sources = []
    for i, url in enumerate(run.urls, 1):
        m = meta.get(url, {})
        txt = text_copy(run, i)
        host = re.sub(r"^https?://([^/]+).*$", r"\1", url)
        entry = {"n": i, "url": url, "file": None, "sha256": None, "copy": "none", "fetched_at": cfg.get("sources_fetched_at"),
                 "status": m.get("status"), "body_sha256": m.get("sha256")}
        if txt is not None and m.get("status") == 200:
            entry["sha256"] = sha256_bytes(txt.read_bytes())
            entry["text_copy_of"] = "pdf-text" if txt.name.endswith(".pdf-text.txt") else "html"
            if txt.name.endswith(".pdf-text.txt") and extractors:
                entry["extractor"] = {"note": "text extracted from the PDF by the grader's scripts; the hash is of the extraction, not the PDF", "files": extractors}
            if cfg.get("copy") == "text" or host in own_hosts:
                shutil.copyfile(txt, out / "sources" / f"{i:03d}.txt")
                entry["file"] = f"sources/{i:03d}.txt"
                entry["copy"] = "text"
            else:
                entry["copy"] = "hash-only"
        else:
            entry["note"] = m.get("error") or f"answered {m.get('status')} to the scripted GET; quotes from it are not checkable"
        sources.append(entry)

    rows, removed = [], 0
    for c in run.claims:
        cid = c["id"]
        note_after = after.get(cid, "")
        if note_after.lower().startswith("removed"):
            removed += 1
            continue
        kind = KIND_MAP.get(str(c.get("kind", "other")).lower(), "other")
        if cid in page_internal:
            kind = "page-internal"
        history, graded_by, graded_at = None, "grader", ga.get("r1")
        refs_in, note, conf = [], "", None
        if cid in corrections:
            cr = corrections[cid]
            text, v = cr["claim_now"], VERDICT_LETTER[cr["verdict"].strip().upper()]
            refs_in = cr.get("refs", [])
            note = cr.get("note", "")
            history = "Corrected 8 Nov 2026 and read against the source by the author's session, not re-graded"
            if v == "N" and run.verdict(cid) == "N":
                # the correction only removed a contradiction and the row falls back to the grader's own first reading
                # (no evidence found); the author found none either, so the grader decided it
                graded_by, graded_at = "grader", ga.get("r1")
                history += "; the verdict is the grader's first reading, restored"
            else:
                graded_by, graded_at = "author", ga.get("corrections")
        elif cid in delta:
            d = delta[cid]
            text, v = d["claim_now"], VERDICT_LETTER[d["verdict"].strip().upper()]
            refs_in = d.get("refs", [])
            note = d.get("note", "")
            history = "Re-graded 7 to 8 Nov 2026 on this wording"
            graded_at = ga.get("delta")
        else:
            text, v = c["claim"], run.verdict(cid)
            src = run.disprove if v == "C" else run.prove
            refs_in = src.get(cid, {}).get("refs", [])
            note = src.get(cid, {}).get("note", "")
            if note_after:
                history = "Reworded after the grade: " + note_after
        if v == "C":
            conf = "low" if (LOW_WORD.search(note) and CONFIDENCE_WORD.search(note)) else "high"
        parsed = []
        for r in refs_in:
            parsed += parse_ref(r, run, page_file, lines)
        parsed = [p for p in parsed if p.get("quote")]
        page_refs = [p for p in parsed if p.get("is_page")]
        src_refs = [p for p in parsed if not p.get("is_page")]
        proofs, counter, located, consulted = [], [], [], []
        if v == "E":
            proofs = src_refs + (page_refs if kind in ("page-internal", "arithmetic") else [])
            located = [] if kind in ("page-internal", "arithmetic") else page_refs
        elif v == "C":
            counter = src_refs + page_refs
        else:
            consulted, located = src_refs, page_refs
        for p in proofs + counter:
            if p.get("file") and p["file"].startswith("sources/"):
                tc = text_copy(run, int(p["file"].split("/")[-1][:3]))
                t = norm(tc.read_text(encoding="utf-8", errors="replace")) if tc else ""
                p["verified"] = norm(p["quote"]) in t if t else False
            elif p.get("file") == page_file:
                p["verified"] = norm(p["quote"]) in page_norm
            else:
                p["verified"] = False
        for lst in (proofs, counter, located, consulted):
            for p in lst:
                p.pop("is_page", None)
        for p in located + consulted:
            p.pop("verified", None)
        if not on_page_now(text, page_norm):
            print(f"WARN {cid}: text not on the current page; kept as graded", file=sys.stderr)
        loc = []
        for frag in [f for f in text.split("[...]") if norm(f)]:
            for i, l in enumerate(lines, 1):
                if norm(frag) in norm(l):
                    loc.append({"file": page_file, "line": i})
                    break
        rows.append({"id": cid, "text": text, "location": loc, "kind": kind, "checkable": kind != "promise",
                     "verdict": VERDICT_NAME[v], "confidence": conf, "proofs": proofs, "counter": counter,
                     "located": located, "consulted": consulted,
                     "note": run.clean_note_text(note) if note else "", "history": history,
                     "graded_by": graded_by, "graded_at": graded_at})
    claims_bytes = ("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n").encode("utf-8")
    (out / "claims.jsonl").write_bytes(claims_bytes)

    counts, sc = score(rows)
    counts["removed_since_grading"] = removed
    manifest = {
        "format": "claims-snapshot/0.2",
        "subject": cfg["subject"],
        "taken_at": cfg["taken_at"],
        "pages": [{"file": page_file, "sha256": sha256_bytes(page_text.encode("utf-8")), "lines": len(lines),
                   "fetched_at": cfg["taken_at"], "note": cfg.get("page_note", "")}],
        "sources": sources,
        "grading": dict(cfg["grading"], profile="cited-sources"),
        "counts": counts,
        "score": sc,
        "claims_sha256": sha256_bytes(claims_bytes),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"snapshot {out}: {counts['claims']} claims (E {counts['evidenced']}, C {counts['contradicted']}, N {counts['no_evidence']}; "
          f"{counts['author_read']} read by the author), {removed} removed since grading, {sc['coverage_pct']}% / {sc['contradiction_pct']}% band {sc['band']}, "
          f"{sum(1 for s in sources if s['copy'] == 'text')} text copies, {sum(1 for s in sources if s['copy'] == 'hash-only')} hash-only, page {len(lines)} lines")


if __name__ == "__main__":
    main(sys.argv[1])
