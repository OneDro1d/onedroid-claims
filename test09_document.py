#!/usr/bin/env python3
"""test09_document.py: the suite of claims-snapshot 0.9's `document` profile (SPEC.md section 17): a document as the subject, the
auditor's claimed verdicts, two witnesses (a quote-check script and a model). Standard library plus ssh-keygen on PATH.

A document folder is BUILT here, in a temporary folder, from one spec (default() below): the page, the subject, three claims with their
candidates and the auditor's `claimed` verdicts, a quote-check script witness (W1) whose rows this file recomputes on its own (holds(),
quote_check(): the fold table is written out here, not read from check.py) and a model witness (W2), the key list, the manifest and the
signatures made with throwaway keys (no key leaves the temporary folder). Each case changes ONE thing in the spec or in a hook (so every
hash, the scores, the agreement and the signatures stay consistent) and names the check line that must say so.

Case names start with the rule they cover: d01 .. d12 are the rules of the format decision (D-1 .. D-12), g the gating, a the tools.
  d01  format and profile: the profile is known from 0.9 only; every other profile reads as before.
  d02  the subject (K1): the six keys, the media types, sha256, url, commit.
  d03  the pages (K1): media_type, member, extractor.
  d04  the candidates (K11): `where`, `kind`, `quote`, the external source.
  d05  the auditor's claimed verdict (K11).
  d06  the auditor's score and counts (K12).
  d07  the stage (K1): always pre-witness, no primary, no top-level score.
  d08  witness kind script (K1 header shape, K11 rows).
  d09  quote-check recomputed (K12), with and without --copies.
  d10  agreement (K12).
  d11  the typographic fold (K4, K5, K6, K12): all 16 code points, and nothing else.
  d12  signatures and file names (K13).
  a    add_witness.py and merge.py refuse naming a primary; add_witness.py accepts a script witness.

usage: python3 -I test09_document.py"""
import hashlib, json, pathlib, re, shutil, subprocess, sys, tempfile
from fractions import Fraction

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fixtures07 as f  # noqa: E402

F09, F08 = "claims-snapshot/0.9", "claims-snapshot/0.8"
AT = "2026-11-22T09:00:00Z"
AT1, AT2 = "2026-11-22T09:10:00Z", "2026-11-22T09:20:00Z"
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
STATE = {"n": 0}
MODEL = "example-model-2026-11-01"
AUDITOR_MODEL = "example-auditor-2026-11-01"

# the 16 code points of the typographic fold, written out here (SPEC section 17), never read from check.py
FOLD16 = {0x2018: "'", 0x2019: "'", 0x201A: "'", 0x201B: "'", 0x2032: "'",
          0x201C: '"', 0x201D: '"', 0x201E: '"', 0x201F: '"', 0x2033: '"',
          0x2010: "-", 0x2011: "-", 0x2012: "-", 0x2013: "-", 0x2014: "-", 0x2212: "-"}
NOT_FOLDED = [0x2015, 0x00B4, 0x2035, 0x301D, 0x2E3A]   # look like the folded ones; must NOT be folded
PAGE = ("The Example Widget weighs 120 grams.\n"
        "The Example Widget ships in 3 days.\n"
        "The Example Widget is sold in 40 countries.\n"
        "Note: the sales table lists 12 countries.\n"
        "The Example Widget is certified by Example Labs.\n")


def sha(b):
    return hashlib.sha256(b if isinstance(b, bytes) else b.encode("utf-8")).hexdigest()


def tnorm(t):
    """The checker's existing normalisation, then this file's own fold."""
    return f.check.norm(t).translate(FOLD16)


def cand(quote, where="document", kind="artefact", file="page.md", url=None):
    c = {"where": where, "file": file, "kind": kind, "quote": quote}
    if url is not None:
        c["url"] = url
    return c


def claimed(verdict, proofs=(), counter=(), confidence=None, note="the auditor's reading (example)"):
    c = {"verdict": verdict, "on": {"proofs": list(proofs), "counter": list(counter)}, "note": note}
    if confidence:
        c["confidence"] = confidence
    return c


def default():
    return {
        "fmt": F09,
        "subject": {"kind": "document", "title": "The Example Widget guide", "media_type": "text/markdown", "sha256": "AUTO",
                    "url": "https://example.org/widget.md", "commit": None},
        "pages": [{"file": "page.md", "text": PAGE, "media_type": "text/markdown", "member": None, "extractor": None}],
        "sources": [],
        "claims": [
            {"id": "C-001", "text": "The Example Widget weighs 120 grams.", "kind": "figure", "line": 1,
             "proofs": [cand("weighs 120 grams")], "counter": [], "claimed": claimed("EVIDENCED", proofs=[0], confidence="high")},
            {"id": "C-002", "text": "The Example Widget ships in 3 days.", "kind": "figure", "line": 2,
             "proofs": [], "counter": [], "claimed": claimed("NO EVIDENCE PUBLISHED")},
            {"id": "C-003", "text": "The Example Widget is sold in 40 countries.", "kind": "figure", "line": 3,
             "proofs": [], "counter": [cand("the sales table lists 12 countries")],
             "claimed": claimed("CONTRADICTED", counter=[0], confidence="high")},
        ],
        "witnesses": [
            {"name": "quote-check", "kind": "script", "method": "quote-check", "rows": "quote-check", "key": "witness", "ident": f.WITNESS,
             "script": {"name": "quote-check.py", "sha256": sha("an example script, bytes not published"), "commit": None}},
            {"name": "model-reader", "kind": "model", "method": "classify", "rows": "agree", "key": "bob", "ident": f.BOB, "model": MODEL},
        ],
        "auditor": {"kind": "model", "model": AUDITOR_MODEL},
    }


def add_external(S, copy="text", url="https://example.org/spec.html", quote="certified by Example Labs", text=None):
    """A fourth claim proved by an external source: copy `text` (file in the folder) or `hash-only` (copy only with --copies)."""
    body = text if text is not None else "Example Labs certified the Example Widget in 2026: the Example Widget is certified by Example Labs."
    src = {"n": 1, "url": url, "file": "sources/001.txt" if copy == "text" else None, "sha256": sha(body), "copy": copy,
           "fetched_at": AT, "status": 200, "text_copy_of": "html", "_text": body}
    S["sources"].append(src)
    S["claims"].append({"id": "C-004", "text": "The Example Widget is certified by Example Labs.", "kind": "citation", "line": 5,
                        "proofs": [cand(quote, where="external", file=("sources/001.txt" if copy == "text" else None), url=url)], "counter": [],
                        "claimed": claimed("EVIDENCED", proofs=[0], confidence="high")})


def holds(S, c):
    """holds | untestable | fails: one candidate against the copies in the spec (a hash-only copy is not at hand)."""
    q = tnorm(c.get("quote") or "") if isinstance(c.get("quote"), str) else ""
    if not q:
        return "fails"
    if c.get("where") == "document":
        pg = next((p for p in S["pages"] if p["file"] == c.get("file")), None)
        return "fails" if pg is None else ("holds" if q in tnorm(pg["text"]) else "fails")
    srcs = [s for s in S["sources"] if s.get("url") == c.get("url")]
    if len(srcs) != 1 or srcs[0].get("copy") != "text" or srcs[0].get("_text") is None:
        return "untestable"
    return "holds" if q in tnorm(srcs[0]["_text"]) else "fails"


def quote_check(S, rows):
    """W1's rows, from the rule of SPEC section 17 (recomputed here independently of check.py)."""
    out = []
    for a in rows:
        cl = a.get("claimed")
        if not isinstance(cl, dict) or not a.get("checkable", True) or a.get("kind") == "promise":
            continue
        v, on = cl.get("verdict"), cl.get("on") or {}
        if v in ("EVIDENCED", "CONTRADICTED"):
            key = "proofs" if v == "EVIDENCED" else "counter"
            side = a.get(key) or []
            idx = [i for i in on.get(key, []) if isinstance(i, int) and 0 <= i < len(side) and (v == "CONTRADICTED" or side[i].get("kind") == "artefact")]
            st = {i: holds(S, side[i]) for i in idx}
            h = [i for i in idx if st[i] == "holds"]
            u = [i for i in idx if st[i] == "untestable"]
            if h:
                row = {"id": a["id"], "verdict": v, "on": {"proofs": h if key == "proofs" else [], "counter": h if key == "counter" else []},
                       "note": "the quote is in its copy", "graded_at": AT2}
                row["confidence"] = cl.get("confidence", "high") if v == "CONTRADICTED" else "high"
            elif u:
                row = {"id": a["id"], "verdict": "UNDECIDED", "note": "the copy is not at hand for the named candidate(s)", "graded_at": AT2}
            else:
                row = {"id": a["id"], "verdict": "NO EVIDENCE PUBLISHED", "confidence": "high", "on": {"proofs": [], "counter": []},
                       "note": "no named candidate holds", "graded_at": AT2}
        else:
            row = {"id": a["id"], "verdict": "NO EVIDENCE PUBLISHED", "confidence": "high", "on": {"proofs": [], "counter": []},
                   "note": "the auditor published no evidence", "graded_at": AT2}
        out.append(row)
    return out


def agree_rows(rows):
    """W2's rows: the model says what the auditor claimed."""
    out = []
    for a in rows:
        cl = a.get("claimed")
        if not isinstance(cl, dict) or "verdict" not in cl or not a.get("checkable", True) or a.get("kind") == "promise":
            continue
        r = {"id": a["id"], "verdict": cl["verdict"], "on": json.loads(json.dumps(cl.get("on") or {"proofs": [], "counter": []})),
             "note": "the model agrees (example)", "graded_at": AT2}
        r["confidence"] = cl.get("confidence", "high")
        out.append(r)
    return out


def pct(same, decided):
    return None if decided == 0 else int(round(Fraction(100 * same, decided)))


def build(dst, S=None, *, spec=None, audit=None, manifest=None, wit=None, entry=None, sign=True):
    """A document folder from the spec. Hooks (each changes what is built BEFORE hashes, scores and signatures are made):
    spec(S) the spec; audit(rows) the auditor's rows; wit(name, header, rows) a witness; entry(name, e) a witness's manifest entry;
    manifest(M) the manifest."""
    dst = pathlib.Path(dst)
    (dst / "witness").mkdir(parents=True)
    S = S or default()
    if spec:
        spec(S)
    files = {}
    for pg in S["pages"]:
        (dst / pg["file"]).parent.mkdir(parents=True, exist_ok=True)
        (dst / pg["file"]).write_bytes(pg["text"].encode("utf-8"))
    if S["subject"].get("sha256") == "AUTO":
        S["subject"]["sha256"] = sha(S["pages"][0]["text"])
    srcs = []
    for s in S["sources"]:
        s = {k: v for k, v in s.items() if not k.startswith("_")}
        srcs.append(s)
    for s in S["sources"]:
        if s.get("file") and s.get("_text") is not None:
            (dst / s["file"]).parent.mkdir(parents=True, exist_ok=True)
            (dst / s["file"]).write_bytes(s["_text"].encode("utf-8"))
    rows = []
    for c in S["claims"]:
        r = {"id": c["id"], "text": c["text"], "location": [{"file": S["pages"][0]["file"], "line": c.get("line", 1)}], "kind": c["kind"],
             "checkable": c.get("checkable", True), "proofs": c["proofs"], "counter": c["counter"], "located": [], "consulted": [],
             "searched": "", "audited_by": "auditor", "audited_at": AT}
        if "claimed" in c:
            r["claimed"] = c["claimed"]
        rows.append(r)
    if audit:
        audit(rows)
    f.dump(dst / "audit.jsonl", rows)
    audit_h = f.sha(dst / "audit.jsonl")
    (dst / "keys").mkdir()
    wents, klist = [], []
    cl_rows = [r for r in rows if isinstance(r.get("claimed"), dict) and "verdict" in r["claimed"] and r.get("checkable", True) and r.get("kind") != "promise"]
    for w in S["witnesses"]:
        hdr = {"witness": w["name"], "kind": w["kind"], "method": w["method"], "over": {"file": "audit.jsonl", "sha256": audit_h},
               "started_at": AT1, "finished_at": AT2}
        if w.get("model"):
            hdr["model"] = w["model"]
        if w.get("script"):
            hdr["script"] = w["script"]
        wr = quote_check(S, rows) if w["rows"] == "quote-check" else agree_rows(rows) if w["rows"] == "agree" else w["rows"](rows)
        if wit:
            wit(w["name"], hdr, wr)
        wf = f"witness/{w['name']}.jsonl"
        f.dump(dst / wf, [hdr] + wr)
        dec = [r for r in wr if r.get("verdict") not in ("UNDECIDED", "MISSING CLAIM")]
        cv = {a["id"]: a["claimed"]["verdict"] for a in cl_rows}
        same = sum(1 for r in dec if cv.get(r["id"]) == r["verdict"])
        decided = sum(1 for r in dec if r["id"] in cv)
        sc = f.check.evidence_score([m for m in f.check.merge_rows(rows, wr, w["name"]) if m.get("verdict") != "UNDECIDED"])
        e = {"name": w["name"], "kind": w["kind"], "method": w["method"], "file": wf, "sha256": f.sha(dst / wf), "primary": False,
             "score": {k: sc.get(k) for k in ("coverage_pct", "contradiction_pct", "band")}, "missing_claims": 0,
             "undecided": sum(1 for r in wr if r.get("verdict") == "UNDECIDED"),
             "agreement": {"with": "auditor", "decided": decided, "same": same, "pct": pct(same, decided)}}
        if w.get("model"):
            e["model"] = w["model"]
            kt, kb = f.pub(w["key"])
            klist.append({"principal": w["ident"], "model": w["model"], "key": f"{kt} {kb}", "valid_from": "2026-11-01T00:00:00Z",
                          "valid_to": None, "note": "a throwaway key made for this folder"})
        if entry:
            entry(w["name"], e)
        wents.append((w, e))
    f.dump(dst / "keys/model-keys.jsonl", klist)
    ev = [{"verdict": r["claimed"]["verdict"], "confidence": r["claimed"].get("confidence"), "checkable": True, "kind": r["kind"]} for r in cl_rows]
    asc = f.check.evidence_score(ev)
    aud = {"file": "audit.jsonl", "sha256": audit_h, "name": "example-document-auditor", "note": "a model that read the document (example)",
           "kind": S["auditor"].get("kind"), "model": S["auditor"].get("model"),
           "score": {k: asc.get(k) for k in ("coverage_pct", "contradiction_pct", "band")},
           "counts": {"evidenced": asc.get("evidenced", 0), "no_evidence": asc.get("no_evidence", 0), "contradicted": asc.get("contradicted", 0),
                      "contradicted_high": asc.get("contradicted_high", 0)}}
    for k in [k for k, v in aud.items() if v is None and k in ("kind", "model")]:
        del aud[k]
    pages = []
    for pg in S["pages"]:
        p = {"file": pg["file"], "sha256": sha(pg["text"]), "lines": pg["text"].count("\n"), "fetched_at": AT, "note": "the text of the document, one block per line"}
        for k in ("media_type", "member", "extractor"):
            if k in pg:
                p[k] = pg[k]
        pages.append(p)
    M = {"format": S["fmt"], "subject": S["subject"], "taken_at": AT, "pages": pages, "sources": srcs,
         "grading": {"kind": "pre-witness", "profile": "document", "graded_at": AT, "auditor": aud, "witnesses": [e for _, e in wents],
                     "sessions": [], "rounds": []},
         "counts": {"claims": len(rows), "checkable": len(cl_rows)}}
    if manifest:
        manifest(M)
    (dst / "signatures.json").write_text("[]\n", encoding="utf-8")
    (dst / "allowed_signers").write_text("", encoding="utf-8")
    (dst / "anchors.json").write_text("[]\n", encoding="utf-8")
    M["files"] = {k: f.sha(dst / k) for k in ["audit.jsonl", "keys/model-keys.jsonl"] + [pg["file"] for pg in S["pages"]]
                  + [e["file"] for _, e in wents if (dst / e["file"]).exists()] + [s["file"] for s in srcs if s.get("file") and (dst / s["file"]).exists()]}
    f.msave(dst, M)
    if sign:
        aid = S.get("auditor_ident", f.AUDITOR)
        f.sign(dst, "auditor", "auditor", aid, "audit.jsonl")
        for w, e in wents:
            f.sign(dst, "witness", w["key"], w["ident"], e["file"])
        f.sign(dst, "sources", "auditor", aid)
    return dst


def folder(tmp, **kw):
    STATE["n"] += 1
    return build(tmp / f"d{STATE['n']}", **kw)


def setp(path, value):
    """A mutator on a spec, a manifest or a row (value KeyError: delete). A path part that is a number indexes a list."""
    def go(d):
        *head, last = path.split(".")
        for k in head:
            d = d[int(k)] if isinstance(d, list) else d[k]
        if isinstance(d, list):
            d[int(last)] = value
        elif value is KeyError:
            d.pop(last, None)
        else:
            d[last] = value
    return go


def both(*fs):
    def go(x):
        for fn in fs:
            fn(x)
    return go


def no_trace(r):
    return not r.traceback and r.summary is not None


def variant(S, media, pages, commit=None):
    """A subject of another media type, with its pages (a list of dicts file, text, media_type, member, extractor)."""
    S["subject"]["media_type"] = media
    S["subject"]["commit"] = commit
    S["pages"] = pages
    for c in S["claims"]:
        for cd in c["proofs"] + c["counter"]:
            if cd.get("where") == "document":
                cd["file"] = pages[0]["file"]


def pg(file="page.md", text=PAGE, media_type="text/markdown", member=None, extractor=None):
    return {"file": file, "text": text, "media_type": media_type, "member": member, "extractor": extractor}


EXTR = {"name": "example-extractor", "sha256": "a" * 64}


def main():
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        f.keygen(tmp / "keys")

        def run(*flags, **kw):
            return f.Run(folder(tmp, **kw), *flags)

        def lines(r, *ks):
            return [r.text.get(k, "").split("\n")[0][:300] for k in ks if r.status.get(k) not in ("PASS", None)]

        def positive(name, what, kw, expect=None, extra=None, flags=()):
            def case():
                r = run(*flags, **kw)
                fails = [k for k, s in r.status.items() if s == "FAIL"]
                want = {"K1": "PASS", "K11": "PASS", "K12": "PASS", "K13": "PASS", **(expect or {})}
                got = {k: r.status.get(k) for k in want}
                ok = r.rc == 0 and not fails and no_trace(r) and got == want and r.has("K1", "document profile") and (extra is None or extra(r))
                f.report(name, ok, f"{what}: exit 0, no FAIL, {want}", f"exit {r.rc}, FAIL {fails}, {got}, {r.summary}", lines(r, "K1", "K5", "K11", "K12", "K13"))
            f.case(name, case)

        def negative(name, rule, cid, needle, kw, status="FAIL", flags=(), k1_pass=True, also=None):
            def case():
                r = run(*flags, **kw)
                rc_ok = (r.rc != 0) if status == "FAIL" else (r.rc == 0)
                ok = (rc_ok and r.status.get(cid) == status and r.has(cid, needle) and no_trace(r)
                      and (cid == "K1" or not k1_pass or r.status.get("K1") == "PASS") and not r.has("K1", "grading.profile='document'") and (also is None or also(r)))
                f.report(name, ok, f"{cid} {status}, exit {1 if status == 'FAIL' else 0}, the line names {needle!r} ({rule})",
                         f"exit {r.rc}, {cid} {r.status.get(cid)}, K1 {r.status.get('K1')}", [r.text.get(cid, "")[:420]])
            f.case(name, case)

        # ---- p: well-formed folders -------------------------------------------------------------------------------------------
        positive("p1_well_formed_markdown", "a markdown document, one page, three claims, W1 script and W2 model", {}, extra=lambda r: not r.has("K12", "majority"))
        positive("p2_pdf_with_extractor", "a pdf subject: the page is an extraction, its extractor named",
                 {"spec": lambda S: variant(S, "application/pdf", [pg("page.txt", media_type="application/pdf", extractor=EXTR)])})
        positive("p3_docx_with_extractor", "a docx subject with its extractor",
                 {"spec": lambda S: variant(S, DOCX, [pg("page.txt", media_type=DOCX, extractor=EXTR)])})
        positive("p4_zip_with_members", "a zip subject: each page a member, a page's own media type",
                 {"spec": lambda S: variant(S, "application/zip", [pg("a.md", member="docs/a.md"), pg("b.md", text="Another file.\n", member="docs/b.md")])})
        positive("p5_git_with_commit", "an application/x-git subject at a commit, pages by member",
                 {"spec": lambda S: variant(S, "application/x-git", [pg("a.md", member="README.md")], commit="b" * 40)})
        positive("p6_url_null", "a subject without a url", {"spec": setp("subject.url", None)})
        positive("p7_text_plain_and_html", "a text/plain subject", {"spec": lambda S: variant(S, "text/plain", [pg("page.txt", media_type="text/plain")])})
        positive("p8_external_text_copy", "an external proof: a source with its text copy in the folder, hash, time and url",
                 {"spec": lambda S: add_external(S, "text")}, expect={"K12": "PASS"})
        positive("p9_external_hash_only_untestable", "an external proof whose source is hash-only: not testable here, W1 says UNDECIDED, a WARN",
                 {"spec": lambda S: add_external(S, "hash-only")}, expect={"K12": "WARN"})
        positive("p10_gates_empty_and_human_witness", "grading.gates an empty list; a human witness (allowed) beside the two",
                 {"manifest": setp("grading.gates", []),
                  "spec": lambda S: S["witnesses"].append({"name": "human-reader", "kind": "human", "method": "read", "rows": "agree", "key": "adder", "ident": f.ADDER, "model": None})},
                 extra=lambda r: r.has("K12", "human-reader"))
        positive("p11_confidence_optional_on_evidenced", "claimed EVIDENCED without a confidence",
                 {"spec": lambda S: S["claims"][0]["claimed"].pop("confidence")})
        positive("p12_non_checkable_row_without_claimed", "a promise row carries no claimed and is not counted",
                 {"spec": lambda S: S["claims"].append({"id": "C-005", "text": "The Example Widget is sold in 40 countries.", "kind": "promise", "line": 3,
                                                        "proofs": [], "counter": [], "checkable": False})},
                 extra=lambda r: r.has("K8", "3 checkable") or r.has("K8", "checkable"))
        positive("p13_second_page_external_restatement_kind", "a restatement candidate beside an artefact one",
                 {"spec": lambda S: S["claims"][0]["proofs"].append(cand("The Example Widget weighs", kind="restatement"))})

        # ---- g: gating ---------------------------------------------------------------------------------------------------------
        def g1():
            r = f.Run(folder(tmp, spec=setp("fmt", F08)))
            ok = r.rc != 0 and r.status.get("K1") == "FAIL" and r.has("K1", "grading.profile='document'") and no_trace(r)
            f.report("d01_g1_document_profile_unknown_on_0_8", ok, "a 0.8 folder naming the profile document: K1 FAIL, unknown profile", f"exit {r.rc}, K1 {r.status.get('K1')}", [r.text.get("K1", "")[:300]])
        f.case("d01_g1_document_profile_unknown_on_0_8", g1)

        def g2():
            def norm_(out):
                return [l for l in out.replace("claims-snapshot/0.9", "claims-snapshot/0.7").splitlines() if not l.startswith("SUMMARY:")]
            a = f.Run(f.build(tmp / "g2-07", fmt=f.F07))
            b = f.Run(f.build(tmp / "g2-09", fmt=F09))
            ok = a.rc == b.rc == 0 and norm_(a.out) == norm_(b.out) and b.status.get("K1") == "PASS"
            f.report("d01_g2_other_profile_reads_on_0_9_as_on_0_7", ok, "the agent-work fixture on 0.9: the same lines as on 0.7 (format label aside), exit 0",
                     f"lines equal {norm_(a.out) == norm_(b.out)}, exits {a.rc}/{b.rc}")
        f.case("d01_g2_other_profile_reads_on_0_9_as_on_0_7", g2)

        def g3():
            ok = F09 in f.check.FORMATS and "document" not in f.check.PROFILES
            f.report("d01_g3_profile_set_of_0_2_to_0_7_unchanged", ok, "0.9 in FORMATS; PROFILES (the 0.2 to 0.7 set) does not hold document", f"document in PROFILES {'document' in f.check.PROFILES}")
        f.case("d01_g3_profile_set_of_0_2_to_0_7_unchanged", g3)

        def g4():
            d = f.build(tmp / "g4", fmt=F09)
            M = f.mload(d)
            M["grading"]["witnesses"][0]["kind"] = "script"
            f.msave(d, M)
            r = f.Run(d)
            ok = r.status.get("K1") == "FAIL" and r.has("K1", "script") and no_trace(r)
            f.report("d08_g4_kind_script_refused_outside_document", ok, "kind script on an agent-work 0.9 folder: K1 FAIL naming script", f"K1 {r.status.get('K1')}", [r.text.get("K1", "")[:300]])
        f.case("d08_g4_kind_script_refused_outside_document", g4)

        # ---- d02: the subject (K1) ---------------------------------------------------------------------------------------------
        for key in ("kind", "title", "media_type", "sha256", "url", "commit"):
            negative(f"d02_k1_subject_{key}_missing", "all six subject keys are present", "K1", f"subject.{key}", {"spec": setp(f"subject.{key}", KeyError)})
        negative("d02_k1_subject_kind_not_document", "subject.kind is document", "K1", "subject.kind", {"spec": setp("subject.kind", "test-run")})
        negative("d02_k1_subject_title_empty", "title is a non-empty string", "K1", "subject.title", {"spec": setp("subject.title", " ")})
        negative("d02_k1_subject_media_unknown", "media_type is one of the seven", "K1", "subject.media_type", {"spec": setp("subject.media_type", "text/csv")})
        negative("d02_k1_subject_media_case", "media_type is exact", "K1", "subject.media_type", {"spec": setp("subject.media_type", "Text/Markdown")})
        negative("d02_k1_subject_sha_not_hex", "sha256 is 64 lower hex", "K1", "subject.sha256", {"spec": setp("subject.sha256", "xyz")})
        negative("d02_k1_subject_sha_upper", "sha256 is lower case", "K1", "subject.sha256", {"spec": setp("subject.sha256", "A" * 64)})
        negative("d02_k1_subject_url_not_http", "url is null or http(s)", "K1", "subject.url", {"spec": setp("subject.url", "ftp://example.org/w.md")})
        negative("d02_k1_subject_url_bare_host", "url is null or http(s)", "K1", "subject.url", {"spec": setp("subject.url", "example.org/w.md")})
        negative("d02_k1_subject_url_not_a_string", "url is null or a string", "K1", "subject.url", {"spec": setp("subject.url", 7)})
        negative("d02_k1_subject_commit_on_markdown", "commit is null unless the media type is x-git", "K1", "subject.commit", {"spec": setp("subject.commit", "c" * 40)})
        negative("d02_k1_subject_git_without_commit", "an x-git subject has a 40 hex commit", "K1", "subject.commit",
                 {"spec": lambda S: variant(S, "application/x-git", [pg("a.md", member="README.md")], commit=None)})
        negative("d02_k1_subject_git_short_commit", "commit is 40 lower hex", "K1", "subject.commit",
                 {"spec": lambda S: variant(S, "application/x-git", [pg("a.md", member="README.md")], commit="abc1234")})
        negative("d02_k1_subject_git_upper_commit", "commit is lower hex", "K1", "subject.commit",
                 {"spec": lambda S: variant(S, "application/x-git", [pg("a.md", member="README.md")], commit="B" * 40)})

        # ---- d03: the pages (K1) -----------------------------------------------------------------------------------------------
        negative("d03_k1_page_media_type_missing", "each page names its own media type", "K1", "pages[0].media_type", {"spec": setp("pages.0.media_type", KeyError)})
        negative("d03_k1_page_media_differs_from_subject", "a single-file subject's page type equals the subject's", "K1", "pages[0].media_type",
                 {"spec": setp("pages.0.media_type", "text/plain")})
        negative("d03_k1_page_media_is_zip", "a page's type is never zip or x-git", "K1", "pages[0].media_type",
                 {"spec": lambda S: variant(S, "application/zip", [pg("a.md", member="docs/a.md", media_type="application/zip")])})
        negative("d03_k1_zip_page_without_member", "a zip page names its member", "K1", "pages[0].member",
                 {"spec": lambda S: variant(S, "application/zip", [pg("a.md")])})
        negative("d03_k1_git_page_member_empty", "member is non-empty", "K1", "pages[0].member",
                 {"spec": lambda S: variant(S, "application/x-git", [pg("a.md", member="")], commit="b" * 40)})
        for nm, mem in (("dotdot", "docs/../x.md"), ("leading_slash", "/docs/x.md"), ("backslash", "docs\\x.md"), ("dotdot_only", "..")):
            negative(f"d03_k1_member_{nm}", "member is relative, no .. component, no leading slash, no backslash", "K1", "pages[0].member",
                     {"spec": (lambda m: lambda S: variant(S, "application/zip", [pg("a.md", member=m)]))(mem)})
        negative("d03_k1_member_used_twice", "member paths are unique", "K1", "member",
                 {"spec": lambda S: variant(S, "application/zip", [pg("a.md", member="docs/a.md"), pg("b.md", text="Other.\n", member="docs/a.md")])})
        negative("d03_k1_member_on_single_file_subject", "member is null or absent on a single-file subject", "K1", "pages[0].member", {"spec": setp("pages.0.member", "docs/a.md")})
        negative("d03_k1_pdf_without_extractor", "a pdf page needs its extractor", "K1", "pages[0].extractor",
                 {"spec": lambda S: variant(S, "application/pdf", [pg("page.txt", media_type="application/pdf")])})
        negative("d03_k1_docx_without_extractor", "a docx page needs its extractor", "K1", "pages[0].extractor",
                 {"spec": lambda S: variant(S, DOCX, [pg("page.txt", media_type=DOCX)])})
        negative("d03_k1_extractor_sha_not_hex", "an extractor carries a 64 hex sha256", "K1", "pages[0].extractor",
                 {"spec": lambda S: variant(S, "application/pdf", [pg("page.txt", media_type="application/pdf", extractor={"name": "x", "sha256": "zz"})])})
        negative("d03_k1_extractor_without_name", "an extractor carries a name", "K1", "pages[0].extractor",
                 {"spec": lambda S: variant(S, "application/pdf", [pg("page.txt", media_type="application/pdf", extractor={"sha256": "a" * 64})])})
        negative("d03_k1_extractor_on_markdown", "extractor is null or absent on a text page", "K1", "pages[0].extractor", {"spec": setp("pages.0.extractor", EXTR)})

        # ---- d04: candidates (K11) ---------------------------------------------------------------------------------------------
        for side, key in (("proofs", "where"), ("proofs", "kind"), ("proofs", "quote"), ("counter", "where"), ("counter", "kind"), ("counter", "quote")):
            i = 0 if side == "proofs" else 2
            negative(f"d04_k11_{side}_{key}_missing", "every candidate carries where, kind and quote", "K11", f"{side}[0].{key}",
                     {"spec": setp(f"claims.{i}.{side}.0.{key}", KeyError)})
        negative("d04_k11_where_unknown", "where is document or external", "K11", "proofs[0].where", {"spec": setp("claims.0.proofs.0.where", "web")})
        negative("d04_k11_kind_unknown", "kind is artefact or restatement", "K11", "proofs[0].kind", {"spec": setp("claims.0.proofs.0.kind", "existence")})
        negative("d04_k11_quote_empty", "quote is a non-empty string", "K11", "proofs[0].quote", {"spec": setp("claims.0.proofs.0.quote", "  ")})
        negative("d04_k11_quote_null", "quote is a string (no existence proofs)", "K11", "proofs[0].quote", {"spec": setp("claims.0.proofs.0.quote", None)})
        negative("d04_k11_document_file_not_a_page", "where document: file is one of pages[].file", "K11", "proofs[0].file", {"spec": setp("claims.0.proofs.0.file", "other.md")})
        negative("d04_k11_document_file_absent", "where document: file is required", "K11", "proofs[0].file", {"spec": setp("claims.0.proofs.0.file", KeyError)})
        negative("d04_k11_external_url_no_source", "where external: the url is one source's", "K11", "proofs[0].url",
                 {"spec": both(lambda S: add_external(S, "text"), setp("claims.3.proofs.0.url", "https://example.org/other.html"))})
        negative("d04_k11_external_url_absent", "where external: a url is required", "K11", "proofs[0].url",
                 {"spec": both(lambda S: add_external(S, "text"), setp("claims.3.proofs.0.url", KeyError))})
        negative("d04_k11_external_url_two_sources", "where external: exactly one source holds the url", "K11", "proofs[0].url",
                 {"spec": both(lambda S: add_external(S, "text"), lambda S: S["sources"].append({**{k: v for k, v in S["sources"][0].items()}, "n": 2, "file": "sources/002.txt"}))})
        negative("d04_k11_external_source_sha_missing", "the source's sha256 is 64 hex", "K11", "source 1: sha256",
                 {"spec": both(lambda S: add_external(S, "text"), setp("sources.0.sha256", None))}, also=None)
        negative("d04_k11_external_source_without_fetched_at", "the source carries fetched_at", "K11", "source 1: fetched_at",
                 {"spec": both(lambda S: add_external(S, "text"), setp("sources.0.fetched_at", KeyError))})
        negative("d04_k11_external_source_copy_none", "the source's copy is text or hash-only", "K11", "source 1: copy",
                 {"spec": both(lambda S: add_external(S, "text"), setp("sources.0.copy", "none"))})
        negative("d04_k11_external_text_wrong_file", "a text source: the candidate's file is the source's file", "K11", "proofs[0].file",
                 {"spec": both(lambda S: add_external(S, "text"), setp("claims.3.proofs.0.file", "page.md"))})
        negative("d04_k11_external_counter_url_no_source", "a counter is a candidate too", "K11", "counter[0].url",
                 {"spec": both(lambda S: add_external(S, "text"),
                               lambda S: S["claims"][1].update({"counter": [cand("x", where="external", file=None, url="https://example.org/none.html")]}))})

        # ---- d05: the auditor's claimed verdict (K11) --------------------------------------------------------------------------
        negative("d05_k11_claimed_missing", "a checkable row carries claimed", "K11", "claimed", {"spec": setp("claims.0.claimed", KeyError)})
        negative("d05_k11_claimed_on_promise", "a non-checkable row (promise) carries no claimed", "K11", "not checkable",
                 {"spec": lambda S: S["claims"].append({"id": "C-005", "text": "The Example Widget ships in 3 days.", "kind": "promise", "line": 2, "proofs": [], "counter": [],
                                                       "claimed": claimed("NO EVIDENCE PUBLISHED")})})
        negative("d05_k11_claimed_on_checkable_false", "a row with checkable false carries no claimed", "K11", "not checkable",
                 {"spec": lambda S: S["claims"].append({"id": "C-005", "text": "The Example Widget ships in 3 days.", "kind": "figure", "line": 2, "proofs": [], "counter": [],
                                                       "checkable": False, "claimed": claimed("NO EVIDENCE PUBLISHED")})})
        for v in ("EVIDENCE AVAILABLE ON REQUEST", "WITHDRAWN", "UNDECIDED", "evidenced"):
            negative(f"d05_k11_claimed_verdict_{v.split()[0].lower()}", "the three verdicts only", "K11", "claimed.verdict", {"spec": (lambda x: setp("claims.1.claimed.verdict", x))(v)})
        negative("d05_k11_claimed_verdict_missing", "claimed has a verdict", "K11", "claimed.verdict", {"spec": setp("claims.1.claimed.verdict", KeyError)})
        negative("d05_k11_claimed_note_missing", "claimed has a note", "K11", "claimed.note", {"spec": setp("claims.1.claimed.note", KeyError)})
        negative("d05_k11_claimed_note_not_string", "claimed.note is a string", "K11", "claimed.note", {"spec": setp("claims.1.claimed.note", 3)})
        negative("d05_k11_claimed_on_missing", "claimed has an on object", "K11", "claimed.on", {"spec": setp("claims.1.claimed.on", KeyError)})
        negative("d05_k11_claimed_confidence_outside", "confidence is high or low", "K11", "claimed.confidence", {"spec": setp("claims.0.claimed.confidence", "medium")})
        negative("d05_k11_claimed_contradicted_without_confidence", "confidence is required on CONTRADICTED", "K11", "claimed.confidence", {"spec": setp("claims.2.claimed.confidence", KeyError)})
        negative("d05_k11_claimed_contradicted_without_counter", "CONTRADICTED names at least one counter", "K11", "claimed.on.counter", {"spec": setp("claims.2.claimed.on.counter", [])})
        negative("d05_k11_claimed_evidenced_without_proof", "EVIDENCED names at least one proof", "K11", "no artefact", {"spec": setp("claims.0.claimed.on.proofs", [])})
        negative("d05_k11_claimed_evidenced_on_restatement_only", "EVIDENCED names an artefact candidate, not a restatement", "K11", "no artefact",
                 {"spec": setp("claims.0.proofs.0.kind", "restatement")})
        negative("d05_k11_claimed_proof_index_outside", "an index that exists", "K11", "claimed.on.proofs", {"spec": setp("claims.0.claimed.on.proofs", [0, 5])})
        negative("d05_k11_claimed_counter_index_outside", "an index that exists", "K11", "claimed.on.counter", {"spec": setp("claims.2.claimed.on.counter", [0, 3])})
        negative("d05_k11_claimed_index_negative", "an index that exists", "K11", "claimed.on.proofs", {"spec": setp("claims.0.claimed.on.proofs", [-1, 0])})
        negative("d05_k11_claimed_index_not_an_integer", "an index is an integer", "K11", "claimed.on.proofs", {"spec": setp("claims.0.claimed.on.proofs", ["0"])})
        negative("d05_k11_audit_row_carries_a_verdict", "every other decision field stays forbidden on an audit row", "K11", "decision field",
                 {"audit": lambda rows: rows[0].update({"verdict": "EVIDENCED"})})
        negative("d05_k11_nep_naming_an_artefact_warns", "NO EVIDENCE PUBLISHED whose on.proofs names an artefact: a WARN", "K11", "names an artefact",
                 {"spec": both(setp("claims.0.claimed.verdict", "NO EVIDENCE PUBLISHED"), setp("claims.0.claimed.confidence", KeyError))}, status="WARN")

        # ---- d06: the auditor's score and counts (K12) ------------------------------------------------------------------------
        negative("d06_k12_auditor_kind_missing", "grading.auditor.kind is model", "K12", "grading.auditor.kind", {"manifest": setp("grading.auditor.kind", KeyError)})
        negative("d06_k12_auditor_kind_not_model", "grading.auditor.kind is model", "K12", "grading.auditor.kind", {"manifest": setp("grading.auditor.kind", "human")})
        negative("d06_k12_auditor_model_missing", "grading.auditor.model names the model", "K12", "grading.auditor.model", {"manifest": setp("grading.auditor.model", KeyError)})
        negative("d06_k12_auditor_model_empty", "grading.auditor.model is not empty", "K12", "grading.auditor.model", {"manifest": setp("grading.auditor.model", "")})
        negative("d06_k12_auditor_score_coverage_wrong", "the score is recomputed from the claimed verdicts", "K12", "grading.auditor.score",
                 {"manifest": setp("grading.auditor.score.coverage_pct", 90)})
        negative("d06_k12_auditor_score_band_wrong", "the band is recomputed", "K12", "grading.auditor.score", {"manifest": setp("grading.auditor.score.band", "A")})
        negative("d06_k12_auditor_score_missing", "the score is present", "K12", "grading.auditor.score", {"manifest": setp("grading.auditor.score", KeyError)})
        negative("d06_k12_auditor_counts_wrong", "the counts are recomputed", "K12", "grading.auditor.counts", {"manifest": setp("grading.auditor.counts.evidenced", 2)})
        negative("d06_k12_auditor_counts_high_wrong", "contradicted_high is recomputed", "K12", "grading.auditor.counts", {"manifest": setp("grading.auditor.counts.contradicted_high", 0)})
        negative("d06_k12_auditor_counts_missing", "the counts are present", "K12", "grading.auditor.counts", {"manifest": setp("grading.auditor.counts", KeyError)})

        def d06_recompute_follows_claimed():
            r = run(spec=both(setp("claims.1.claimed", claimed("EVIDENCED", proofs=[0])), setp("claims.1.proofs", [cand("ships in 3 days")])))
            ok = r.status.get("K12") == "PASS" and r.rc == 0 and no_trace(r)
            f.report("d06_k12_score_follows_the_claimed_verdicts", ok, "a changed claimed verdict with the recomputed score in the manifest: K12 PASS", f"K12 {r.status.get('K12')}", [r.text.get("K12", "")[:300]])
        f.case("d06_k12_score_follows_the_claimed_verdicts", d06_recompute_follows_claimed)

        # ---- d07: the stage (K1) -----------------------------------------------------------------------------------------------
        negative("d07_k1_kind_self_audit", "grading.kind is pre-witness, always", "K1", "grading.kind", {"manifest": setp("grading.kind", "self-audit")})
        negative("d07_k1_kind_split", "grading.kind is pre-witness, always", "K1", "grading.kind", {"manifest": setp("grading.kind", "split")})
        def d07_claims_jsonl():
            d = folder(tmp)
            (d / "claims.jsonl").write_text("", encoding="utf-8")
            r = f.Run(d)
            ok = r.rc != 0 and r.status.get("K1") == "FAIL" and r.has("K1", "claims.jsonl") and not r.has("K1", "grading.profile='document'") and no_trace(r)
            f.report("d07_k1_claims_jsonl_present", ok, "a claims.jsonl in the folder: K1 FAIL (no merge without a primary)", f"exit {r.rc}, K1 {r.status.get('K1')}", [r.text.get("K1", "")[:300]])
        f.case("d07_k1_claims_jsonl_present", d07_claims_jsonl)
        negative("d07_k1_top_level_score", "no top-level score", "K1", "score", {"manifest": setp("score", {"coverage_pct": 33, "contradiction_pct": 33, "band": "D", "formula": "evidence-score/1"})})
        negative("d07_k1_top_level_claims_sha256", "no claims_sha256", "K1", "claims_sha256", {"manifest": setp("claims_sha256", "0" * 64)})
        negative("d07_k1_grader", "no grading.grader", "K1", "grading.grader", {"manifest": setp("grading.grader", "someone")})
        negative("d07_k1_grading_model", "no grading.model", "K1", "grading.model", {"manifest": setp("grading.model", "x")})
        negative("d07_k1_gates_not_empty", "grading.gates absent or empty", "K1", "grading.gates", {"manifest": setp("grading.gates", [{"run": "x"}])})
        negative("d07_k1_witness_primary", "naming a primary is refused in this profile", "K1", "primary", {"entry": lambda n, e: e.update({"primary": True}) if n == "model-reader" else None})
        negative("d07_k1_script_witness_primary", "a script witness is never primary either", "K1", "primary", {"entry": lambda n, e: e.update({"primary": True}) if n == "quote-check" else None})

        # ---- d08: witness kind script (K1 header shape, K11 rows) ---------------------------------------------------------------
        def hdr(name, fn):
            return lambda n, h, rows: fn(h) if n == name else None

        def w1(fn):
            return {"wit": hdr("quote-check", fn)}

        negative("d08_k1_script_object_missing", "kind script needs a script object", "K1", "script", w1(lambda h: h.pop("script")))
        negative("d08_k1_script_sha_not_hex", "script.sha256 is 64 hex", "K1", "script.sha256", w1(lambda h: h["script"].update({"sha256": "abc"})))
        negative("d08_k1_script_name_missing", "script.name is a string", "K1", "script.name", w1(lambda h: h["script"].pop("name")))
        negative("d08_k1_script_commit_not_hex", "script.commit is hex or null", "K1", "script.commit", w1(lambda h: h["script"].update({"commit": "not-hex!"})))
        negative("d08_k1_script_commit_missing", "script.commit is present (hex or null)", "K1", "script.commit", w1(lambda h: h["script"].pop("commit")))
        negative("d08_k1_script_with_a_model_id", "model is absent or null for a script witness", "K1", "model", w1(lambda h: h.update({"model": "script"})))
        negative("d08_k1_script_with_method_read", "kind script only with quote-check", "K1", "quote-check", w1(lambda h: h.update({"method": "read"})))
        negative("d08_k1_model_with_quote_check", "quote-check only on kind script", "K1", "quote-check", {"wit": hdr("model-reader", lambda h: h.update({"method": "quote-check"}))})
        negative("d08_k1_script_object_on_a_model", "script is forbidden unless the kind is script", "K1", "script",
                 {"wit": hdr("model-reader", lambda h: h.update({"script": {"name": "x", "sha256": "a" * 64, "commit": None}}))})

        def d08_model_null_ok():
            r = run(wit=hdr("quote-check", lambda h: h.update({"model": None})))
            ok = r.rc == 0 and r.status.get("K1") == "PASS" and no_trace(r)
            f.report("d08_k1_script_with_model_null_ok", ok, "model null on a script witness: K1 PASS", f"exit {r.rc}, K1 {r.status.get('K1')}", [r.text.get("K1", "")[:300]])
        f.case("d08_k1_script_with_model_null_ok", d08_model_null_ok)

        def wrow(name, fn):
            return {"wit": lambda n, h, rows: fn(rows) if n == name else None}

        negative("d08_k11_witness_evidenced_on_restatement", "an EVIDENCED decision of any witness names an artefact candidate", "K11", "no artefact proof",
                 {"spec": setp("claims.0.proofs", [cand("weighs 120 grams", kind="restatement"), cand("weighs 120 grams")]),
                  "wit": lambda n, h, rows: rows[0].update({"on": {"proofs": [0], "counter": []}}) if n == "model-reader" else None})
        negative("d08_k11_witness_verdict_withdrawn", "the three verdicts plus UNDECIDED", "K11", "not a document-profile verdict", wrow("model-reader", lambda rows: rows[1].update({"verdict": "WITHDRAWN"})))
        negative("d08_k11_witness_verdict_on_request", "the three verdicts plus UNDECIDED", "K11", "not a document-profile verdict",
                 wrow("model-reader", lambda rows: rows[1].update({"verdict": "EVIDENCE AVAILABLE ON REQUEST"})))
        negative("d08_k11_undecided_without_note", "UNDECIDED needs a note", "K11", "UNDECIDED without a note",
                 wrow("model-reader", lambda rows: rows[1].update({"verdict": "UNDECIDED", "note": ""})))
        negative("d08_k11_witness_on_index_outside", "on names candidates that exist", "K11", "on.proofs index",
                 wrow("model-reader", lambda rows: rows[0].update({"on": {"proofs": [4], "counter": []}})))
        negative("d08_k11_live_not_an_object", "live is an object", "K11", "live", wrow("model-reader", lambda rows: rows[0].update({"live": "yes"})))

        def d08_live_object_ok():
            r = run(wit=lambda n, h, rows: rows[0].update({"live": {"status": 200, "found": True}}) if n == "quote-check" else None)
            ok = r.rc == 0 and r.status.get("K11") == "PASS" and r.status.get("K12") == "PASS" and no_trace(r)
            f.report("d08_k11_live_object_ok", ok, "a live object on a row: K11 PASS, not recomputed", f"exit {r.rc}, K11 {r.status.get('K11')}, K12 {r.status.get('K12')}")
        f.case("d08_k11_live_object_ok", d08_live_object_ok)

        def d08_undecided_ok():
            r = run(wit=lambda n, h, rows: rows[1].update({"verdict": "UNDECIDED", "note": "cannot tell", "on": {"proofs": [], "counter": []}}) if n == "model-reader" else None)
            ok = r.rc == 0 and r.status.get("K11") == "PASS" and r.status.get("K12") == "PASS" and no_trace(r)
            f.report("d08_k11_undecided_with_note_ok", ok, "UNDECIDED with a note: K11 PASS", f"exit {r.rc}, K11 {r.status.get('K11')}, K12 {r.status.get('K12')}")
        f.case("d08_k11_undecided_with_note_ok", d08_undecided_ok)

        # ---- d09: quote-check recomputed (K12) ---------------------------------------------------------------------------------
        q = lambda fn: {"wit": lambda n, h, rows: fn(rows) if n == "quote-check" else None}  # noqa: E731
        negative("d09_k12_evidenced_row_says_no_evidence", "the quote holds: the row is EVIDENCED", "K12", "C-001",
                 q(lambda rows: rows[0].update({"verdict": "NO EVIDENCE PUBLISHED", "on": {"proofs": [], "counter": []}})))
        negative("d09_k12_evidenced_row_says_contradicted", "the row's verdict is the recomputed one", "K12", "quote-check recomputes",
                 q(lambda rows: rows[0].update({"verdict": "CONTRADICTED", "on": {"proofs": [], "counter": [0]}})))
        negative("d09_k12_evidenced_row_on_wrong_proofs", "on.proofs is the named proofs that hold", "K12", "C-001",
                 q(lambda rows: rows[0].update({"on": {"proofs": [], "counter": []}})))
        negative("d09_k12_no_evidence_row_says_evidenced", "claimed NO EVIDENCE PUBLISHED gives NO EVIDENCE PUBLISHED", "K12", "C-002",
                 q(lambda rows: rows[1].update({"verdict": "EVIDENCED", "on": {"proofs": [0], "counter": []}})))
        negative("d09_k12_no_evidence_row_with_on", "NO EVIDENCE PUBLISHED has an empty on", "K12", "C-002",
                 q(lambda rows: rows[1].update({"on": {"proofs": [0], "counter": []}})))
        negative("d09_k12_contradicted_row_says_no_evidence", "a counter holds: the row is CONTRADICTED", "K12", "C-003",
                 q(lambda rows: rows[2].update({"verdict": "NO EVIDENCE PUBLISHED", "on": {"proofs": [], "counter": []}})))
        negative("d09_k12_contradicted_row_confidence_differs", "CONTRADICTED carries the claimed confidence", "K12", "C-003", q(lambda rows: rows[2].update({"confidence": "low"})))
        negative("d09_k12_contradicted_row_on_counter_wrong", "on.counter is the named counters that hold", "K12", "C-003",
                 q(lambda rows: rows[2].update({"on": {"proofs": [], "counter": []}})))
        negative("d09_k12_evidenced_includes_a_proof_that_does_not_hold", "on.proofs is only the proofs that hold", "K12", "C-001",
                 {"spec": both(lambda S: S["claims"][0]["proofs"].append(cand("weighs 999 grams")), setp("claims.0.claimed.on.proofs", [0, 1])),
                  "wit": lambda n, h, rows: rows[0].update({"on": {"proofs": [0, 1], "counter": []}}) if n == "quote-check" else None}, also=None)

        def d09_partial_proofs_ok():
            r = run(spec=both(lambda S: S["claims"][0]["proofs"].append(cand("weighs 999 grams")), setp("claims.0.claimed.on.proofs", [0, 1])))
            ok = r.status.get("K12") == "PASS" and no_trace(r)
            f.report("d09_k12_evidenced_with_one_proof_of_two_holding_ok", ok, "two named proofs, one holds: W1 EVIDENCED on [0]: K12 PASS (K5 fails: the published page lacks the quote)", f"K12 {r.status.get('K12')}", [r.text.get("K12", "")[:300]])
        f.case("d09_k12_evidenced_with_one_proof_of_two_holding_ok", d09_partial_proofs_ok)

        def d09_none_holds():
            r = run(spec=setp("claims.0.proofs.0.quote", "weighs 999 grams"))
            ok = r.status.get("K12") == "PASS" and r.status.get("K5") == "FAIL" and no_trace(r)
            f.report("d09_k12_nothing_holds_gives_no_evidence", ok, "a named proof that does not hold: W1 says NO EVIDENCE PUBLISHED and K12 agrees (K5 FAILs the published copy)",
                     f"K12 {r.status.get('K12')}, K5 {r.status.get('K5')}", [r.text.get("K12", "")[:300]])
        f.case("d09_k12_nothing_holds_gives_no_evidence", d09_none_holds)

        def d09_none_holds_but_row_says_evidenced():
            r = run(spec=setp("claims.0.proofs.0.quote", "weighs 999 grams"), wit=lambda n, h, rows: rows[0].update({"verdict": "EVIDENCED", "on": {"proofs": [0], "counter": []}}) if n == "quote-check" else None)
            ok = r.status.get("K12") == "FAIL" and r.has("K12", "C-001") and no_trace(r)
            f.report("d09_k12_nothing_holds_but_row_says_evidenced", ok, "W1 says EVIDENCED on a quote that does not hold: K12 FAIL", f"K12 {r.status.get('K12')}", [r.text.get("K12", "")[:300]])
        f.case("d09_k12_nothing_holds_but_row_says_evidenced", d09_none_holds_but_row_says_evidenced)

        def d09_restatement_not_counted():
            r = run(spec=both(setp("claims.0.proofs", [cand("weighs 120 grams", kind="restatement"), cand("weighs 120 grams")]), setp("claims.0.claimed.on.proofs", [0, 1])))
            ok = r.status.get("K12") == "PASS" and r.rc == 0 and no_trace(r)
            f.report("d09_k12_only_artefact_proofs_are_named", ok, "a restatement named beside an artefact: W1's on.proofs is the artefact alone: K12 PASS", f"K12 {r.status.get('K12')}", [r.text.get("K12", "")[:300]])
        f.case("d09_k12_only_artefact_proofs_are_named", d09_restatement_not_counted)

        def d09_model_rows_not_recomputed():
            r = run(wit=lambda n, h, rows: [x.update({"verdict": "NO EVIDENCE PUBLISHED", "on": {"proofs": [], "counter": []}}) for x in rows] if n == "model-reader" else None)
            ok = r.rc == 0 and r.status.get("K12") == "PASS" and r.has("K12", "model-reader") and no_trace(r)
            f.report("d09_k12_a_model_row_is_not_recomputed", ok, "a model witness may differ from the quotes: K12 PASS, an info line names it", f"exit {r.rc}, K12 {r.status.get('K12')}", [r.text.get("K12", "")[:400]])
        f.case("d09_k12_a_model_row_is_not_recomputed", d09_model_rows_not_recomputed)

        def d09_untestable_says_evidenced():
            r = run(spec=lambda S: add_external(S, "hash-only"), wit=lambda n, h, rows: rows[3].update({"verdict": "EVIDENCED", "on": {"proofs": [0], "counter": []}, "confidence": "high"}) if n == "quote-check" else None)
            ok = r.rc == 0 and r.status.get("K12") == "WARN" and r.has("K12", "cannot be recomputed") and no_trace(r)
            f.report("d09_k12_untestable_row_is_a_warn", ok, "a hash-only source, W1 says EVIDENCED (it fetched it live): K12 WARN, not FAIL", f"exit {r.rc}, K12 {r.status.get('K12')}", [r.text.get("K12", "")[:400]])
        f.case("d09_k12_untestable_row_is_a_warn", d09_untestable_says_evidenced)

        def d09_untestable_undecided_warn():
            r = run(spec=lambda S: add_external(S, "hash-only"))
            ok = r.rc == 0 and r.status.get("K12") == "WARN" and r.has("K12", "cannot be recomputed") and r.has("K12", "C-004") and no_trace(r) and not r.has("K12", "quote-check recomputes")
            f.report("d09_k12_untestable_undecided_is_consistent_warn", ok, "a hash-only source, W1 UNDECIDED: consistent, K12 WARN naming C-004", f"exit {r.rc}, K12 {r.status.get('K12')}", [r.text.get("K12", "")[:400]])
        f.case("d09_k12_untestable_undecided_is_consistent_warn", d09_untestable_undecided_warn)

        def with_copies(name, wit, status, needle, rc):
            def case():
                S = default()
                add_external(S, "hash-only")
                d = folder(tmp, S=S, wit=wit)
                cp = tmp / f"copies-{STATE['n']}"
                cp.mkdir()
                (cp / "001.txt").write_text(S["sources"][0]["_text"], encoding="utf-8")
                r = f.Run(d, "--copies", cp)
                ok = r.rc == rc and r.status.get("K12") == status and (needle is None or r.has("K12", needle)) and no_trace(r)
                f.report(name, ok, f"--copies resolves the hash-only copy as K5 does: K12 {status}, exit {rc}", f"exit {r.rc}, K12 {r.status.get('K12')}", [r.text.get("K12", "")[:400]])
            f.case(name, case)

        with_copies("d09_k12_copies_resolve_untestable_row_undecided_now_differs", None, "FAIL", "C-004", 1)
        with_copies("d09_k12_copies_resolve_untestable_row_evidenced_agrees",
                    lambda n, h, rows: rows[3].update({"verdict": "EVIDENCED", "on": {"proofs": [0], "counter": []}, "confidence": "high", "note": "held live"}) if n == "quote-check" else None,
                    "PASS", None, 0)

        # ---- d10: agreement (K12) ----------------------------------------------------------------------------------------------
        def ent(name, fn):
            return {"entry": lambda n, e: fn(e) if n == name else None}

        negative("d10_k12_agreement_missing", "every witness entry carries agreement", "K12", "agreement", ent("quote-check", lambda e: e.pop("agreement")))
        negative("d10_k12_agreement_same_wrong", "same is recomputed", "K12", "agreement", ent("quote-check", lambda e: e["agreement"].update({"same": 2})))
        negative("d10_k12_agreement_decided_wrong", "decided is recomputed", "K12", "agreement", ent("model-reader", lambda e: e["agreement"].update({"decided": 2})))
        negative("d10_k12_agreement_pct_wrong", "pct is recomputed", "K12", "agreement", ent("model-reader", lambda e: e["agreement"].update({"pct": 50})))
        negative("d10_k12_agreement_with_not_auditor", "agreement.with is auditor", "K12", "agreement", ent("model-reader", lambda e: e["agreement"].update({"with": "majority"})))
        negative("d10_k12_agreement_not_an_object", "agreement is an object", "K12", "agreement", ent("model-reader", lambda e: e.update({"agreement": "all"})))

        def d10_lines():
            r = run(wit=lambda n, h, rows: rows[1].update({"verdict": "EVIDENCED", "on": {"proofs": [0], "counter": []}}) if n == "model-reader" else None,
                    spec=setp("claims.1.proofs", [cand("ships in 3 days")]))
            ok = (r.rc == 0 and r.status.get("K12") == "PASS" and r.has("K12", "model-reader") and r.has("K12", "agrees with the auditor") and r.has("K12", "2 of 3")
                  and r.has("K12", "C-002") and not r.has("K12", "majority") and no_trace(r))
            f.report("d10_k12_info_lines_name_the_witness_and_the_claim", ok, "one info line per witness and one per differing claim, naming the witness, no majority line",
                     f"exit {r.rc}, K12 {r.status.get('K12')}", [r.text.get("K12", "")[:700]])
        f.case("d10_k12_info_lines_name_the_witness_and_the_claim", d10_lines)

        def d10_decided_zero():
            r = run(wit=lambda n, h, rows: [x.update({"verdict": "UNDECIDED", "note": "cannot tell"}) for x in rows] if n == "model-reader" else None)
            ok = r.rc == 0 and r.status.get("K12") == "PASS" and no_trace(r)
            f.report("d10_k12_pct_null_when_decided_is_zero", ok, "a witness that decided nothing: pct null, K12 PASS", f"exit {r.rc}, K12 {r.status.get('K12')}", [r.text.get("K12", "")[:300]])
        f.case("d10_k12_pct_null_when_decided_is_zero", d10_decided_zero)

        def d10_decided_zero_pct_zero():
            r = run(wit=lambda n, h, rows: [x.update({"verdict": "UNDECIDED", "note": "cannot tell"}) for x in rows] if n == "model-reader" else None,
                    entry=lambda n, e: e["agreement"].update({"pct": 0}) if n == "model-reader" else None)
            ok = r.rc != 0 and r.status.get("K12") == "FAIL" and r.has("K12", "agreement") and no_trace(r)
            f.report("d10_k12_pct_zero_is_not_null", ok, "decided 0 with pct 0: K12 FAIL (pct is null)", f"exit {r.rc}, K12 {r.status.get('K12')}", [r.text.get("K12", "")[:300]])
        f.case("d10_k12_pct_zero_is_not_null", d10_decided_zero_pct_zero)

        # half to even: 8 claims, the model says NO EVIDENCE PUBLISHED on `same` of them and EVIDENCED on the rest (every claim has an artefact candidate)
        def eight(same):
            def spec(S):
                S["pages"][0]["text"] = "".join(f"The Example Widget has feature {i}.\n" for i in range(1, 9))
                S["claims"] = [{"id": f"C-{i:03d}", "text": f"The Example Widget has feature {i}.", "kind": "figure", "line": i, "counter": [],
                                "proofs": [cand(f"has feature {i}")], "claimed": claimed("NO EVIDENCE PUBLISHED")} for i in range(1, 9)]
                S["witnesses"] = [S["witnesses"][1]]
                S["witnesses"][0]["rows"] = (lambda rows: [({"id": a["id"], "verdict": "NO EVIDENCE PUBLISHED", "confidence": "high", "on": {"proofs": [], "counter": []}, "note": "same", "graded_at": AT2}
                                                            if k < same else {"id": a["id"], "verdict": "EVIDENCED", "confidence": "high", "on": {"proofs": [0], "counter": []}, "note": "differs", "graded_at": AT2})
                                                           for k, a in enumerate(rows)])
            return spec

        def half_case(name, same, want, status):
            def case():
                r = run(spec=eight(same), entry=None) if status == "PASS" else run(spec=eight(same), entry=lambda n, e: e["agreement"].update({"pct": want}))
                ok = (r.rc == 0 and r.status.get("K12") == "PASS" and r.has("K12", f"{same} of 8")) if status == "PASS" else (r.rc != 0 and r.status.get("K12") == "FAIL" and r.has("K12", "agreement"))
                f.report(name, ok, f"agreement {same}/8: the builder's pct (half to even) is {'accepted' if status == 'PASS' else 'overridden by ' + str(want) + ' and refused'}",
                         f"exit {r.rc}, K12 {r.status.get('K12')}", [r.text.get("K12", "")[:300]])
            f.case(name, case)

        half_case("d10_k12_pct_12_5_rounds_to_12", 1, None, "PASS")
        half_case("d10_k12_pct_37_5_rounds_to_38", 3, None, "PASS")
        half_case("d10_k12_pct_62_5_rounds_to_62", 5, None, "PASS")
        half_case("d10_k12_pct_87_5_rounds_to_88", 7, None, "PASS")
        half_case("d10_k12_pct_12_5_half_up_refused", 1, 13, "FAIL")
        half_case("d10_k12_pct_62_5_half_up_refused", 5, 63, "FAIL")

        # ---- d11: the typographic fold -----------------------------------------------------------------------------------------
        cps = sorted(FOLD16)

        def fold_spec(side, cps_):
            """One claim per code point, odd ones EVIDENCED by a proof quote, even ones CONTRADICTED by a counter quote.
            side quote: the quote holds the typographic character, the page the ASCII one; page: the reverse; claim: the claim text."""
            def spec(S):
                page, claims = "", []
                for i, cp in enumerate(cps_, 1):
                    a, t = FOLD16.get(cp, "-"), chr(cp)
                    pg_, qu, ct = (f"x{a}y end {i}.", f"x{t}y end {i}", f"Line {i}: x{a}y end {i}.")
                    if side == "page":
                        pg_, qu, ct = f"x{t}y end {i}.", f"x{a}y end {i}", f"Line {i}: x{t}y end {i}."
                    if side == "claim":
                        qu, ct = f"x{a}y end {i}", f"Line {i}: x{t}y end {i}."
                        pg_ = f"x{a}y end {i}."
                    page += f"Line {i}: {pg_}\n"
                    odd = i % 2 == 1
                    claims.append({"id": f"C-{i:03d}", "text": ct, "kind": "figure", "line": i,
                                   "proofs": [cand(qu)] if odd else [], "counter": [] if odd else [cand(qu)],
                                   "claimed": claimed("EVIDENCED", proofs=[0], confidence="high") if odd else claimed("CONTRADICTED", counter=[0], confidence="high")})
                S["pages"][0]["text"], S["claims"] = page, claims
                S["witnesses"] = S["witnesses"][:1]
            return spec

        def fold_case(name, side, cps_, folded=True):
            def case():
                r = run(spec=fold_spec(side, cps_))
                if folded:
                    ok = (r.rc == 0 and not [k for k, s in r.status.items() if s == "FAIL"] and r.status.get("K4") == "PASS" and r.status.get("K5") == "PASS"
                          and r.status.get("K6") == "PASS" and r.status.get("K12") == "PASS" and no_trace(r))
                    f.report(name, ok, f"all {len(cps_)} code points of the fold (the {side} side): K4 K5 K6 K12 PASS, exit 0",
                             f"exit {r.rc}, FAIL {[k for k, s in r.status.items() if s == 'FAIL']}", [l for k in ("K1", "K4", "K5", "K6", "K11", "K12") for l in [r.text.get(k, "")[:500]] if r.status.get(k) not in ("PASS", None)])
                else:
                    ids = [f"C-{i:03d}" for i in range(1, len(cps_) + 1)]
                    bad_ids = [i for i in ids if side != "claim" and i in r.text.get("K5", "") + r.text.get("K6", "") or side == "claim" and i in r.text.get("K4", "")]
                    cid = "K4" if side == "claim" else "K5"
                    ok = r.rc != 0 and r.status.get(cid) == "FAIL" and len(bad_ids) == len(ids) and no_trace(r)
                    f.report(name, ok, f"a code point outside the 16 is not folded ({cid} FAIL naming every claim)", f"exit {r.rc}, {cid} {r.status.get(cid)}, named {len(bad_ids)} of {len(ids)}", [r.text.get(cid, "")[:600]])
            f.case(name, case)

        fold_case("d11_fold_16_code_points_quote_side", "quote", cps)
        fold_case("d11_fold_16_code_points_page_side", "page", cps)
        fold_case("d11_fold_16_code_points_claim_text_k4", "claim", cps)
        fold_case("d11_nothing_else_is_folded_quote_side", "quote", NOT_FOLDED, folded=False)

        def d11_not_in_other_profile():
            # the fold is the document profile's: the same typographic dash on an agent-work 0.9 folder reads exactly as on 0.7 (g2); here, the table's size
            ok = len(FOLD16) == 16
            f.report("d11_table_has_16_code_points", ok, "the fold table of this suite has exactly 16 code points", f"{len(FOLD16)}")
        f.case("d11_table_has_16_code_points", d11_not_in_other_profile)

        # ---- d12: signatures (K13) ---------------------------------------------------------------------------------------------
        def d12_script_signed_by_auditor():
            d = folder(tmp)
            f.sign(d, "witness", "auditor", f.AUDITOR, "witness/quote-check.jsonl")
            r = f.Run(d)
            ok = r.rc != 0 and r.status.get("K13") == "FAIL" and r.has("K13", "quote-check") and r.has("K13", "auditor's key") and no_trace(r)
            f.report("d12_k13_script_witness_signed_with_the_auditors_key", ok, "W1 signed with the auditor's key: K13 FAIL", f"exit {r.rc}, K13 {r.status.get('K13')}", [r.text.get("K13", "")[:400]])
        f.case("d12_k13_script_witness_signed_with_the_auditors_key", d12_script_signed_by_auditor)

        def d12_model_signed_by_auditor():
            d = folder(tmp)
            f.sign(d, "witness", "auditor", f.AUDITOR, "witness/model-reader.jsonl")
            r = f.Run(d)
            ok = r.rc != 0 and r.status.get("K13") == "FAIL" and r.has("K13", "auditor's key") and no_trace(r)
            f.report("d12_k13_model_witness_signed_with_the_auditors_key", ok, "W2 signed with the auditor's key: K13 FAIL (the 0.6 rule, kept)", f"exit {r.rc}, K13 {r.status.get('K13')}", [r.text.get("K13", "")[:400]])
        f.case("d12_k13_model_witness_signed_with_the_auditors_key", d12_model_signed_by_auditor)

        def d12_script_file_name():
            def mut(M):
                M["grading"]["witnesses"][0]["file"] = "witness/other-name.jsonl"
            d = folder(tmp)
            shutil.copy(d / "witness/quote-check.jsonl", d / "witness/other-name.jsonl")
            M = f.mload(d)
            M["grading"]["witnesses"][0]["file"] = "witness/other-name.jsonl"
            f.msave(d, M)
            f.sign(d, "witness", "witness", f.WITNESS, "witness/other-name.jsonl")
            r = f.Run(d)
            ok = r.status.get("K13") == "FAIL" and r.has("K13", "witness/<name>.jsonl") and no_trace(r)
            f.report("d12_k13_script_witness_file_is_named_for_its_entry", ok, "a script witness filed under another name: K13 FAIL naming witness/<name>.jsonl", f"K13 {r.status.get('K13')}", [r.text.get("K13", "")[:400]])
        f.case("d12_k13_script_witness_file_is_named_for_its_entry", d12_script_file_name)

        def d12_own_keys():
            r = run()
            ok = r.status.get("K13") == "PASS" and r.has("K13", "quote-check.jsonl: signed by") and r.has("K13", "model-reader.jsonl: signed by")
            f.report("d12_k13_each_service_signs_with_its_own_key", ok, "W1, W2 and the auditor each signed with their own key: K13 PASS, every signature verified", f"K13 {r.status.get('K13')}", [r.text.get("K13", "")[:500]])
        f.case("d12_k13_each_service_signs_with_its_own_key", d12_own_keys)

        # ---- a: the tools -------------------------------------------------------------------------------------------------------
        def tree(d):
            return {str(p.relative_to(d)): f.sha(p) for p in sorted(pathlib.Path(d).rglob("*")) if p.is_file()}

        def answer_from(src, name):
            """An answer folder for add_witness.py from witness `name` of the folder `src` (same audit.jsonl bytes, so the same line)."""
            ans = tmp / f"ans-{STATE['n']}-{name}"
            (ans / "witness").mkdir(parents=True)
            M = f.mload(src)
            e = next(w for w in M["grading"]["witnesses"] if w["name"] == name)
            for part in (e["file"], e["file"] + ".sig"):
                shutil.copy(src / part, ans / part)
            sg = next(s for s in json.loads((src / "signatures.json").read_text()) if s.get("file") == e["file"])
            (ans / "manifest-entry.json").write_text(json.dumps(e, indent=1) + "\n", encoding="utf-8")
            (ans / "signatures-entry.json").write_text(json.dumps(sg, indent=1) + "\n", encoding="utf-8")
            keyline = [l for l in (src / "allowed_signers").read_text().splitlines() if l.startswith(sg["signer"]["name"] + " ")]
            (ans / "allowed_signers").write_text("".join(l + "\n" for l in keyline), encoding="utf-8")
            return ans

        def a1():
            S = default()
            full = folder(tmp)
            part = folder(tmp, spec=lambda S_: S_["witnesses"].__delitem__(0))
            ans = answer_from(full, "quote-check")
            r = f.add_witness(part, ans)
            c = f.Run(part)
            names = [w["name"] for w in f.mload(part)["grading"]["witnesses"]]
            ok = r.returncode == 0 and "quote-check" in names and c.status.get("K12") == "PASS" and c.status.get("K13") == "PASS" and no_trace(c)
            f.report("a1_add_witness_accepts_a_script_witness_in_a_document_folder", ok, "a script witness added to a document folder: exit 0, K12 and K13 PASS",
                     f"exit {r.returncode}, witnesses {names}, K12 {c.status.get('K12')}, K13 {c.status.get('K13')}", [(r.stdout + r.stderr)[-300:]])
        f.case("a1_add_witness_accepts_a_script_witness_in_a_document_folder", a1)

        def a2():
            part = folder(tmp, spec=lambda S_: S_["witnesses"].__delitem__(0))
            full = folder(tmp)
            ans = answer_from(full, "quote-check")
            e = json.loads((ans / "manifest-entry.json").read_text())
            e["primary"] = True
            (ans / "manifest-entry.json").write_text(json.dumps(e, indent=1) + "\n", encoding="utf-8")
            before = tree(part)
            r = f.add_witness(part, ans)
            ok = r.returncode != 0 and "document" in r.stderr and "primary" in r.stderr and tree(part) == before
            f.report("a2_add_witness_refuses_a_primary_in_a_document_folder", ok, "an entry marked primary: refused before any write, the line names the document profile",
                     f"exit {r.returncode}, tree unchanged {tree(part) == before}", [r.stderr[-300:]])
        f.case("a2_add_witness_refuses_a_primary_in_a_document_folder", a2)

        def a3():
            d = folder(tmp)
            before = tree(d)
            r = subprocess.run([sys.executable, "-I", str(HERE / "merge.py"), str(d), "--witness", "quote-check", "--write"], capture_output=True, text=True)
            ok = r.returncode != 0 and tree(d) == before and not (d / "claims.jsonl").exists() and "document" in (r.stdout + r.stderr)
            f.report("a3_merge_refuses_to_write_a_merge_in_a_document_folder", ok, "merge.py --write on a document folder: refused, nothing written (no primary, no claims.jsonl)",
                     f"exit {r.returncode}, unchanged {tree(d) == before}, claims.jsonl {(d / 'claims.jsonl').exists()}", [(r.stdout + r.stderr)[-300:]])
        f.case("a3_merge_refuses_to_write_a_merge_in_a_document_folder", a3)

    return f.finish("test09_document")


if __name__ == "__main__":
    sys.exit(main())
