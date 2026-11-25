# document-in-document-proof-2026-11-22

A claims-snapshot 0.9 example of the `document` profile (SPEC.md section 17), made on 22 Nov 2026 by `make_example09_document.py`.

The content is invented: an example document about an example product at example.org, with an example certificate page where one is used.
Nothing in this folder is a real audit, and each claim's note says so. The folder is an example folder, signed with throwaway keys made for it and discarded; the public keys are in `allowed_signers`
and in `keys/model-keys.jsonl`, the private keys are gone, so a rebuild is not byte-identical.

- Three claims: one evidenced (its artefact is a specification table in the document itself), one with no evidence published, one contradicted by the document.
- `audit.jsonl` is the auditor's part (a model, `grading.auditor`), with `claimed`, its own verdict on each claim.
- Two witnesses, neither primary and each signed with its own key: `witness/quote-check.jsonl`, a witness script of kind `script` that checks every
  quote against the saved text (the checker recomputes its rows), and `witness/model-reader.jsonl`, a model that differs from the auditor on one claim.
- `manifest.json` has no top-level score and no primary witness; each witness entry carries `agreement` with the auditor's claimed verdicts.

Check it: `python3 -I check.py examples/document-in-document-proof-2026-11-22` from the root of this repository.
