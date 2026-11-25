"""Builds examples/document-in-document-proof-2026-11-22 and examples/document-external-proof-2026-11-22 (SPEC.md section 17, the document
profile, claims-snapshot 0.9).

usage: python3 make_example09_document.py [CLONE]   (default: this file's folder)

Both folders are examples with INVENTED content: an example document about an example product at example.org. Nothing in them is a published
audit, and every claim's note says so. Each folder holds a three-claim record: one claim the document itself evidences, one with no evidence
published, one the document contradicts; the second folder's evidence for the first claim is an external source saved beside the record.
Witnesses: a quote-check script (W1, a witness script) and a model (W2), neither primary, each signed with its own key, never the auditor's.

Throwaway keys are made in a temporary folder and discarded. The public keys stay in the folder's allowed_signers (and the model's in
keys/model-keys.jsonl); the private keys never leave the temporary folder. So a rebuild is NOT byte-identical: new keys give new signatures
and a new manifest hash. What a rebuild must reproduce is the shape, and `python3 -I check.py <folder>` exiting 0.

The builder is test09_document.build, the one the suite uses, so the examples and the suite cannot drift."""
import pathlib
import shutil
import sys
import tempfile

CLONE = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else __file__).resolve()
if CLONE.is_file():
    CLONE = CLONE.parent
sys.path.insert(0, str(CLONE))
import fixtures07 as f  # noqa: E402
import test09_document as t  # noqa: E402

NOTE = "An example with invented content, not a real audit: "
THROWAWAY = "an example folder, signed with throwaway keys made for it and discarded"

PAGE_IN = ("# The Example Widget: a product note (an example)\n"
           "This is an example document about an example product. Nothing in it is real.\n"
           "The Example Widget weighs 120 grams.\n"
           "The Example Widget ships within 3 days.\n"
           "The Example Widget is sold in 40 countries.\n"
           "Specification table, row 1: weight 120 g.\n"
           "Sales table, total: 12 countries.\n")
PAGE_EXT = ("# The Example Widget: a product note (an example)\n"
            "This is an example document about an example product. Nothing in it is real.\n"
            "The Example Widget is certified by Example Labs.\n"
            "The Example Widget ships within 3 days.\n"
            "The Example Widget is sold in 40 countries.\n"
            "Sales table, total: 12 countries.\n")
SOURCE_EXT = ("Example Labs certificate page (an invented example page at example.org, not a real source).\n"
              "Example Labs certifies the Example Widget, model EW-1, in 2026: the Example Widget is certified by Example Labs.\n")
URL_EXT = "https://example.org/labs/certificate.html"
INFO_NOTE = "An example with invented content, not a real audit."


def claim(cid, text, line, proofs, counter, cl):
    return {"id": cid, "text": text, "kind": "figure", "line": line, "proofs": proofs, "counter": counter, "claimed": cl}


def base(page):
    S = t.default()
    S["subject"].update(title="The Example Widget: a product note (an example)", url="https://example.org/widget-note.md")
    S["pages"][0]["text"] = page
    S["auditor_ident"] = "example-auditor"
    S["auditor"] = {"kind": "model", "model": "example-auditor-model-2026-11-01"}
    S["witnesses"][0].update(ident="example-quote-check")
    S["witnesses"][1].update(ident="example-model-reader", model="example-reader-model-2026-11-01")
    return S


def spec_in(S_):
    S = base(PAGE_IN)
    S["claims"] = [
        claim("C-001", "The Example Widget weighs 120 grams.", 3, [t.cand("row 1: weight 120 g")], [],
              t.claimed("EVIDENCED", proofs=[0], confidence="high", note=NOTE + "the specification table in the document says 120 g.")),
        claim("C-002", "The Example Widget ships within 3 days.", 4, [], [],
              t.claimed("NO EVIDENCE PUBLISHED", note=NOTE + "the document gives no record of the shipping time besides the claim itself.")),
        claim("C-003", "The Example Widget is sold in 40 countries.", 5, [], [t.cand("Sales table, total: 12 countries")],
              t.claimed("CONTRADICTED", counter=[0], confidence="high", note=NOTE + "the sales table in the document totals 12 countries.")),
    ]
    S_.clear()
    S_.update(S)


def spec_ext(S_):
    S = base(PAGE_EXT)
    S["sources"] = [{"n": 1, "url": URL_EXT, "file": "sources/001.txt", "sha256": t.sha(SOURCE_EXT), "copy": "text", "fetched_at": "2026-11-22T08:50:00Z",
                     "status": 200, "text_copy_of": "html", "note": NOTE + "an invented page, saved as text", "_text": SOURCE_EXT}]
    S["claims"] = [
        claim("C-001", "The Example Widget is certified by Example Labs.", 3,
              [t.cand("the Example Widget is certified by Example Labs", where="external", file="sources/001.txt", url=URL_EXT)], [],
              t.claimed("EVIDENCED", proofs=[0], confidence="high", note=NOTE + "the certificate page, saved beside this record, says so in words.")),
        claim("C-002", "The Example Widget ships within 3 days.", 4, [], [],
              t.claimed("NO EVIDENCE PUBLISHED", note=NOTE + "neither the document nor a saved source records the shipping time.")),
        claim("C-003", "The Example Widget is sold in 40 countries.", 5, [], [t.cand("Sales table, total: 12 countries")],
              t.claimed("CONTRADICTED", counter=[0], confidence="high", note=NOTE + "the sales table in the document totals 12 countries.")),
    ]
    S_.clear()
    S_.update(S)


def wit(name, hdr, rows):
    """Every witness row says it is an example; the model witness disagrees with the auditor on C-003 (it did not weigh the sales table)."""
    for r in rows:
        r["note"] = INFO_NOTE + " " + r["note"]
    if name == "model-reader":
        for r in rows:
            if r["id"] == "C-003":
                r.update({"verdict": "NO EVIDENCE PUBLISHED", "confidence": "high", "on": {"proofs": [], "counter": []},
                          "note": INFO_NOTE + " the model did not find a counter in the text it read."})


def manifest(M):
    M["grading"]["rounds"] = [{"date": "2026-11-22", "what": THROWAWAY + "; the content is invented (an example document about an example product at example.org)"}]
    M["grading"]["auditor"]["note"] = INFO_NOTE + " " + THROWAWAY


def readme(title, evidence):
    return f"""# {title}

A claims-snapshot 0.9 example of the `document` profile (SPEC.md section 17), made on 22 Nov 2026 by `make_example09_document.py`.

The content is invented: an example document about an example product at example.org, with an example certificate page where one is used.
Nothing in this folder is a real audit, and each claim's note says so. The folder is {THROWAWAY}; the public keys are in `allowed_signers`
and in `keys/model-keys.jsonl`, the private keys are gone, so a rebuild is not byte-identical.

- Three claims: one evidenced ({evidence}), one with no evidence published, one contradicted by the document.
- `audit.jsonl` is the auditor's part (a model, `grading.auditor`), with `claimed`, its own verdict on each claim.
- Two witnesses, neither primary and each signed with its own key: `witness/quote-check.jsonl`, a witness script of kind `script` that checks every
  quote against the saved text (the checker recomputes its rows), and `witness/model-reader.jsonl`, a model that differs from the auditor on one claim.
- `manifest.json` has no top-level score and no primary witness; each witness entry carries `agreement` with the auditor's claimed verdicts.

Check it: `python3 -I check.py examples/{title.split()[0]}` from the root of this repository.
"""


def make(name, spec, evidence, readme_title):
    dst = CLONE / "examples" / name
    if dst.exists():
        shutil.rmtree(dst)
    with tempfile.TemporaryDirectory() as td:
        f.keygen(pathlib.Path(td) / "keys", names=("auditor", "witness", "bob"))
        S = t.default()
        t.build(dst, S, spec=spec, wit=wit, manifest=manifest)
    (dst / "README.md").write_text(readme(name, evidence), encoding="utf-8")
    print("built", dst.relative_to(CLONE))


def main():
    make("document-in-document-proof-2026-11-22", spec_in, "its artefact is a specification table in the document itself", "x")
    make("document-external-proof-2026-11-22", spec_ext, "its artefact is an external certificate page, saved beside the record with its hash and time", "x")
    return 0


if __name__ == "__main__":
    sys.exit(main())
