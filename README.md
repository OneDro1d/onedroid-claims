# Claims snapshots

Publish the claims a document makes, with the proof for each, in a form a script can check. The author does the expensive part once (lists the claims, grades them against the sources the document cites, with a strong model and a holdout), and publishes a snapshot at a point in time. Anyone can then run the checker, which needs no model, and a small model can run the optional reading pass.

- `SPEC.md`: the format, draft 0.6 (12 Nov 2026): 0.4 of 11 Nov (the auditor's part and the witness files, signatures, anchors, session records and CHECK.json), the agent-work profile of section 12 and the test-run profile of section 13 (0.5, 12 Nov), and section 14 (0.6, the same day): the witness service on classifier models, a witness `kind`, the method `classify`, the witness-only verdict UNDECIDED, the signed key list, the `manifest` signature role and the one allowed change to a published folder (a witness file added, signed); revised 12 Nov 23:1xZ with the pre-witness stage (`grading.kind` `pre-witness`: the auditor's part published alone, no score until a human names the primary; naming the first primary is the second and last allowed change).
- `check.py`: the checker. `python3 -I check.py <snapshot> [--copies DIR] [--fetch] [--strict] [--json] [--keys FILE]`. Standard library only (K13 calls `ssh-keygen` when it is on PATH). Exit 0 when nothing failed. `--json` writes CHECK.json, the run as data. `--keys FILE` names the published key list a model witness's principal is checked against (0.6).
- `merge.py`, `split.py`, `sign.py` (0.4; `sign.py --role manifest` is 0.6): `claims.jsonl` from the auditor's part and the primary witness; a 0.2 or 0.3 snapshot as a new 0.4 folder; an SSH signature over one part or over the manifest. `add_witness.py <snapshot> <answer dir> --key K --identity I` (0.6): inserts a witness service's answer into a published folder the one allowed way and re-runs the checker. `mutants04.py` and `mutants06.py`: the suites of the 0.4 and 0.6 checks; `mutants06e.py`: the suite of 0.6 erratum 1 (12 Nov 2026: in the page profiles a declared self-audit by an agent keeps one signer, K13 reports it; a model witness, a non-primary agent witness, agent-work and test-run unchanged); `mutants06p.py`: the suite of the pre-witness stage (two fixtures cut from published folders, sixteen mutants). Each prints its usage without arguments.
- `build_snapshot.py`: converts a claims-audit run of a document (the cited-sources profile: a brief, one page, numbered sources) into a snapshot. `python3 -I build_snapshot.py configs/<name>.json`.
- `build_site_snapshot.py`: converts a claims-audit run of a website (the publisher-surfaces profile: many surfaces, a pinned repository clone, outside pages fetched once, private evidence shown on request). Same call shape. Fetches nothing; builds from the run's saved files alone.
- `snapshots/<publisher>/<subject>/<date>/`: the snapshots. The first two are OneDroid's public briefs of 7 to 9 Nov 2026 (format 0.2); the third is onedroid.ai from the claims session's seventh run of 7 Nov 2026 (format 0.3, 672 claims, 21 surfaces, 133 repository files as text copies); the fourth is optima.financial from the claims session's round 2 of 8 Nov 2026 (format 0.3, 200 claims, 43 surfaces), private until its owner consents to publication; the fifth is the first brief again as a 0.4 snapshot (`2026-11-11`: the same claims split into the auditor's part and one witness file, signed with a test key, said so in its manifest; header revised and re-signed on 11 Nov after the claims session's check, SPEC.md section 11).

## Read a snapshot

```
manifest.json   what was graded, when, by whom; counts and score; every file with its sha256
claims.jsonl    one line per claim: text, where on the page, verdict, proof quotes with the source each comes from
page.txt        the audited text, one block per line (a website: one file per surface under pages/, as served)
sources/        text copies of cited sources where the licence allows; otherwise hash-only (the quotes are still in claims.jsonl);
                a website's cited repository files under sources/repo/<path>, at the pinned commit
CHECK.txt       the checker's output when the author ran it
```

Verdicts: EVIDENCED (a document: a source the page cites carries the same figure, date, entity, measure or words; a website: an independent, checkable artefact exists that would be false if the claim were false), CONTRADICTED (a cited source or the page itself says the opposite; with a confidence), NO EVIDENCE PUBLISHED (nothing published backs it), EVIDENCE AVAILABLE ON REQUEST (the publisher holds it privately and showed it to the grader, whose row carries the bundle's hash), WITHDRAWN. The score is coverage (evidenced plus on request over the checkable claims) and contradiction; the band is computed from them, never copied.

## Check one

```
python3 -I check.py snapshots/onedroid/business-models-in-the-agentic-age/2026-11-09
python3 -I check.py snapshots/onedroid/business-models-in-the-agentic-age/2026-11-09 --fetch
python3 -I check.py snapshots/onedroid/onedroid-ai/2026-11-09 --fetch
```

Without copies of the third-party sources the checker verifies the structure, the hashes, that every claim is on the page, the counts and the score, and warns that the proof quotes from hash-only sources need `--copies` (the author's private copies) or `--fetch` (fetch each source now and look for the quotes). On a website snapshot `--fetch` also re-fetches every audited surface and reports each claim no longer on it, and compares the status of every URL the grader read live and did not save.

## What this is not

Not a certificate and not an independent audit. A snapshot is a self-audit whose grader is named, in a form that lets a machine check that nothing moved and a reader see where every claim is backed.
- `examples/agent-work-s-i10-2026-11-12/`: the first agent-work (0.5) folder, the kit's S-I10 bundle as `onedroid claims bundle` wrote it on 12 Nov 2026 (three claims, one false; auditor signed by the machine's key, witness by a test key; example identities, not a published audit). `check.py` on it: K1 to K15 PASS.
