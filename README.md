# OneDroid verifiable claims standard

A document, a website or an agent makes claims. This standard publishes each claim with the proof for it, in a folder a script can check: the author does the expensive part once (lists the claims, grades them against the cited sources or the recorded work, with a strong model and a holdout) and publishes a snapshot at a point in time. Anyone can run the checker, which needs no model. A witness, with its own key, decides independently, and the checker reports how far the two agree.

This repository holds the standard, the checker, the converters and synthetic examples. It holds no audited content: a published snapshot is a record of the evidence catalogue (the bytes in blob storage as one self-contained folder, the record in Postgres, a public JSON copy per record on the website), not a file here. Third-party sources are never copied here: hashes and short quotes only.

Adopted on 12 Nov 2026: `SPEC.md` 0.5 and `check.py` (sha256 `be0db6f93781decafd1fce55feb6a903f613bd951389b64d61af0edba6113e48`). A plane or a kit that vendors the checker checks that hash before use; the workflow in `.github/workflows/` does the same. Changes after 0.5 are listed in `NEXT-REVISION.md` and change nothing until a revision is cut.

Licences: code Apache 2.0 (`LICENSE`), text CC BY 4.0 (`LICENSE-TEXT.md`).

## Files

- `SPEC.md`: the format, 0.5 (12 Nov 2026): the auditor's part and the witness files, signatures, anchors, session records and CHECK.json (0.4 of 11 Nov), the agent-work profile of section 12 (an agent's claims about its own work) and the test-run profile of section 13 (a test run as a claim record).
- `check.py`: the checker. `python3 -I check.py <snapshot> [--copies DIR] [--fetch] [--strict] [--json]`. Standard library only (K13 calls `ssh-keygen` when it is on PATH). Exit 0 when nothing failed. `--json` writes CHECK.json, the run as data.
- `merge.py`, `split.py`, `sign.py`: `claims.jsonl` from the auditor's part and the primary witness; a 0.2 or 0.3 snapshot as a new 0.4 folder; an SSH signature over one part. Each prints its usage without arguments.
- `mutants04.py`: the fifteen mutants the 0.4 checks were tested with (SPEC.md section 11).
- `build_snapshot.py`: converts a claims-audit run of a document (the cited-sources profile: a brief, one page, numbered sources) into a snapshot. `python3 -I build_snapshot.py <config.json>`.
- `build_site_snapshot.py`: converts a claims-audit run of a website (the publisher-surfaces profile: many surfaces, a pinned repository clone, outside pages fetched once, private evidence shown on request). Same call shape. Fetches nothing; builds from the run's saved files alone.
- `examples/agent-work-s-i10-2026-11-12/`: an agent-work (section 12) folder as the OneDroid Indie kit's `onedroid claims bundle` wrote it (three claims, one false; auditor signed by the machine's key, witness by a test key; example identities, not a published audit). `check.py` on it: K1 to K15 PASS.
- `examples/test-run-example-2026-11-12/`: a test-run (section 13) folder, synthetic: one scenario, one run, the result and artefacts by hash, a witness file signed by a test key. `check.py` on it: PASS with two WARN lines (no anchor yet, no session record).

## Read a snapshot

```
manifest.json     what was graded, when, by whom; counts and score; every file with its sha256
audit.jsonl       the auditor's part: one line per claim, text, where on the page, the evidence candidates
witness/*.jsonl   each witness's decisions, signed with that witness's key
claims.jsonl      the merge of the two: one line per claim with its verdict and proof quotes
signatures.json   who signed which part, with which key (allowed_signers)
anchors.json      where a hash of the folder was anchored, if anywhere
page.txt          the audited text, one block per line (a website: one file per surface under pages/)
sources/          text copies of cited sources where the licence allows; otherwise hash-only
CHECK.json        the checker's run as data, when the author ran it
```

Verdicts: EVIDENCED (a document: a source the page cites carries the same figure, date, entity, measure or words; a website: an independent, checkable artefact exists that would be false if the claim were false; an agent's work: the pointer resolves and shows it), CONTRADICTED (a cited source or the page itself says the opposite; with a confidence), NO EVIDENCE PUBLISHED, EVIDENCE AVAILABLE ON REQUEST (the publisher holds it privately and showed it to the grader, whose row carries the bundle's hash), WITHDRAWN. The score is coverage and contradiction; the band is computed from them, never copied.

## Check one

```
python3 -I check.py examples/agent-work-s-i10-2026-11-12
python3 -I check.py examples/test-run-example-2026-11-12
```

Without copies of third-party sources the checker verifies the structure, the hashes, the signatures, that every claim is on the page, the counts and the score, and warns that proof quotes from hash-only sources need `--copies` (the author's private copies) or `--fetch` (fetch each source now and look for the quotes).

## What this is not

Not a certificate and not an independent audit. A snapshot is a self-audit whose grader is named, with an independent witness where one signed, in a form that lets a machine check that nothing moved and a reader see where every claim is backed.
