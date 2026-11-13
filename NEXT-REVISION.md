# claims-snapshot: open items for the revision after 0.5

Kept here so the adopted `SPEC.md` (0.6 with erratum 1, 12 Nov 2026 13:3xZ: sha256 c01aa365…; 0.6 as cut was f90e43f7…, 0.5 was 58221ef5…) and `check.py` (0495931b…; 0.6 as cut was 2bdd8ba9…, 0.5 was be0db6f9…) stay byte-stable until a revision is cut. Each line names
where it came from. The format's owner is trilix-onedroid-business; a line leaves this file when a revision adopts or rejects it.

1. **Signature bytes are never an identity** (gate of Indie #64, 12 Nov 2026, note V5). OpenSSH 10.2's `ssh-keygen -Y verify` accepts an
   ed25519 signature with S + L (non-canonical S); Go's `crypto/ed25519` refuses it. So two byte encodings of one signature verify under the
   reference checker. Nothing in the format may key on the bytes of a `.sig` (a hash of a `.sig` is a hash of one encoding). Say so in 3a.
2. **The test-run profile's run.json is outside the auditor's signature** (gate of Fleet #21, 12 Nov 2026, item F3 and the caveat). The
   signature covers `audit.jsonl`; run.json names audit's hash, not the reverse. machine_id, timestamps, environment name, locator and
   artefact list are unsigned statements. Options for the revision: the auditor also signs over run.json (a second `signatures.json` entry,
   role `runner`, file `run.json`), or audit.jsonl's first claim names run.json by sha256 as a source. Recommendation: the second entry.
3. **run.json carries the verdict and k-of-n as fields** (Fleet #21, observation O2). A plane holds a record to its pass-list line only if
   the verdict is a field, not a phrase inside C-001. Add `subject.verdict` (held | failed | broken) and `subject.k_of_n`.
4. **One record per pass-list line, or say why not** (Fleet #21, observation O3). A result with lines for two scenarios and one record is kept.
   The revision says whether a result that carries any records must carry one per line it reports, with an image-only SUT (0 records, a
   printed reason, Indie #60 WUb) as the stated exception.
5. **A plane compares a key by type and base64** (Fleet #21, item F2; already check.py's K13 rule). Write the rule into section 13 for any
   verifier, not only the checker: a trailing comment on a key line is not part of the key.
6. **A plane re-validates a run part with the writer's rules before keeping it** (Fleet #21, item F3): what the kit refuses to write, no
   centre keeps. Section 13, under what a plane checks.
7. **The auditor publishes its own verdict and score beside the evidence** (Michal, D71 A, 12 Nov 2026 08:5xZ). A `claimed`
   verdict per audit row and an auditor's score; the witness decides independently; the checker reports the agreement between
   the auditor's claimed verdicts and each witness. One section of 3/4b changes, K11 and K12 learn the comparison.
8. ~~A witness service on classifier models~~ **Adopted in 0.6 (12 Nov 2026, section 14)** with three changes from this line's first
   wording: the principal is hyphenated and traced by a signed key list (never `<service>/<model>`, which the spec's own rule forbids),
   UNDECIDED is a witness-only verdict with a required note and a fair score, and the one allowed change to a published folder is
   written down. Items 1 to 7 stand for the revision after 0.6.
9. **`grading.kind` is declared, not checked** (0.6 erratum 1, 12 Nov 2026). The checker reads `self-audit` to admit an agent primary
   under the auditor's key, but nothing checks the declaration against the signatures: `split` with one signer, or `self-audit` with two,
   both pass. The revision adds a K13 line: `self-audit` iff the auditor part and the primary witness verify under the same key
   (WARN first, FAIL once every published folder says it right).
10. **One root key for the witness service's model keys** (Talos, 12 Nov 2026, its D80 note item 7). Today every line of
   `keys/model-keys.jsonl` is in a commit signed by Michal's GitHub key, so every new model or rotation is his action. Cheaper: he signs
   one root line (`onedroid-witness-root`) once; the root signs each per-model line; K13 checks list ← root ← Michal. One action from
   him, ever, unless the root rotates. Needs a signature field per line and the root's own entry; a 0.7 checker rule.
11. **A sealed scenario's expected behaviour never reaches the tested agent** (Michal, 12 Nov 2026, the Swarm rule). For the
   test-run profile: the record should say where the verdict was computed (the machine or the centre) and whether the expectation was
   present on the machine during the run; a plane that keeps the holdout marks the record `verdict_at: centre`. Section 13 field.
12. **"Parse" is defined** (the first witness test, 12 Nov 2026, finding W-1; `argus/fleet-gate-evidence/2026-11-12-argus-claims-b69abd83-witness-probe/`).
   Section 14 and the contract say an answer the service cannot parse is UNDECIDED with the note `model answer not parseable` and is never
   retried with another prompt, but not what parsing is. Claude Haiku 4.5 through Bedrock wrapped every answer in a Markdown code fence
   despite the JSON response format: a strict parse made 74 of 74 rows UNDECIDED, the lenient one 16. The rule: the answer is the first
   JSON object in the text, a surrounding code fence stripped; anything else is unparseable. A parse rule, not a prompt change; the
   contract's draft v5 carries it, and the service records which rule it applied in `service.json`.
13. **A prompt note on the `citation` kind** (W-5, same test). Three citation claims (a URL resolves to what the page says it is) were
   called NO EVIDENCE PUBLISHED by one model as "the claim is a URL". The cited-sources prompt gains one sentence on what a citation
   claim asserts. A prompt change is a revision change (section 14), so it waits for the revision, with its new sha256.
14. **Citation-marker drift is invisible to K4** (the claims session, 12 Nov 2026 14:1xZ, reading the first witness test's split list; confirmed
   by the format owner on the files). In `snapshots/onedroid/business-models-in-the-agentic-age/2026-11-11`, `claims.jsonl` C-048 reads
   "sourced [4]" (the 7 Nov page, where EPAM was [3]) while the snapshot's `page.txt` lines 119 and 143 read "sourced [3]" and that part's
   source list numbers ICONIQ [3]: a reader following the snapshot's own page from the claim's marker lands on the wrong source. K4 passes
   because its `norm()` strips every `[n]` before matching (`check.py` lines 83 to 85). In the cited-sources profile the marker is the claim's
   pointer to its source, so this is not cosmetic. The revision: (a) for cited-sources K4 also compares the markers of a claim text with the
   page line that holds it (WARN first, FAIL once every published folder says it right), and the source a proof names must carry the number
   the page gives it; (b) `split.py` and `build_snapshot.py` rewrite a carried claim text to the audited page's numbering and say so in
   `history`. Also from the same reading: C-048 is page-internal and belongs in the hand-listed page-internal ids of the brief's converter
   configuration (today C-001, C-002, C-079). The sweep of the whole folder (`marker_drift.py`, in the 12 Nov evidence folder): 36 claim texts carry a marker, 23 match the page line that holds them, **13 drift** (C-009, C-010, C-011, C-015, C-016, C-031, C-035, C-036, C-038, C-040, C-046, C-048, C-054): every one graded on 7 Nov with a marker at or above the removed source. The published 11 Nov folder is not edited (section 14: only a witness may be added); the fix is a re-split of that brief with (b) applied, as a new dated folder, after the revision. Scope (14:3xZ): the 9 Nov folder of the same brief (0.2) carries the same 13; the verification brief `verifying-agentic-workflows-fleets-and-swarms/2026-11-09` has 80 marked texts and 0 drift. The claims session's own subset test (a claim's markers ⊆ the markers on its `location` lines) found 10 of the 13 and missed C-009, C-010, C-011, where the marker that vanished from the sentence (C-009 "[2][3]" became "[2]") still occurs on the located line for another source: K4 compares against the line that holds the text, not a subset over the located lines.
15. **A router is not a model identity** (the format owner, 12 Nov 2026 21:1xZ, second witness measurement). `typesafe/jev-router` answered
   74 claims through five different models (openai/gpt-6-luna 46, deepseek/deepseek-v4.1-flash-1017 24, anthropic/claude-sonnet-5.5 2,
   openai/gpt-6.1-sol 1, moonshotai/kimi-k3.1-pro 1), so one witness file in its name would hide five readers behind one header. Section 14
   already says the model id is the provider's id with its version, never an alias; the revision says it for routers too: **a witness file
   names the model that answered, never a router or an alias that resolves per request**, and the service refuses a router id (or splits
   its answers into one file per served model, each over the claims that model answered, each with `missing_claims` for the rest). The
   served model is read from the provider's answer (`model` in the response), which the service records per row in `service.json`.
16. **A reasoning model needs a token budget sized for its reasoning, and the contract must say what the service sets** (the format owner,
   12 Nov 2026 21:1xZ). At `max_tokens 400` (the first measurement's setting) seven of twelve chat models spent the budget on hidden
   reasoning and returned empty content: qwen3.7-flash 74 of 74 empty, nemotron-3-nano 57, deepseek-v4-flash 51, glm-5.3-flash 50,
   claude-haiku-5.5 35 (plus 20 truncated JSON texts), gpt-oss-120b 35; at 4,000 they answered (69, 48, 62, 49, 51, 65 rows in the
   vocabulary). An empty answer was recorded UNDECIDED "model answer not parseable", so the budget, not the model, decided the run.
   The service records `max_tokens` (and any reasoning setting) per model in `service.json`, sizes it per model from a smoke test, and
   an empty answer gets its own note (`no content returned (finish: length)`), distinct from an unparseable text. Cost note: with room
   to reason these models cost two to five times their 400-token run for the same claims.
17. **Three failures the first contract called "not parseable" get their own notes** (the format owner, 12 Nov 2026 21:1xZ). A verdict word
   outside the vocabulary (ministral-14b wrote `NO_EVIDENCE_PUBLISHED` nine times), a shape key outside the shape (glm-5.3-flash wrote
   `proof` for `proofs`), and a candidate index that does not exist (nova-micro twelve times, gpt-4.1-nano three, gemma-4 four:
   CONTRADICTED with `counter [0]` on a row with no AGAINST candidate, or EVIDENCED with `proofs [0]` on a row with none) are each
   UNDECIDED, as 3.3 says, with the note naming which: `verdict word not in the vocabulary: <word>`, `shape key not in the shape: <key>`,
   `named a candidate index that does not exist (…)`. No normalisation of near-misses: a model that cannot write the four words as given
   is not a reader of this format, and the note says so. The nonexistent-index case matters: it is a model pointing at FOR evidence to
   justify CONTRADICTED, a misread the shape rule now catches by name.
18. **Decision models as a second kind of model witness** (the format owner, 12 Nov 2026 21:3xZ). OpenRouter's Decisions API
   (`POST /api/alpha/decisions`; 40 models from 13 makers on 12 Nov: TypeSafe Jev 1.14, Kev 4B, GPT-6 Luna Decisions, Gemini Decision 1,
   Microsoft-Decision-1, Perplexity Decider, Cloudflare Clef, Liquid d1, Upstage Solar Decide, Nace Drex, Baseten, ScaleDown, Together,
   Morph, Respan) takes a state plus typed questions and returns a choice with a probability per option and a confidence, a yes/no
   probability (noul), or a position on a scale, and **no text**. Measured over the same 74 claims with one choice question (the four words
   as options with their rule as criteria) and one yes/no per candidate (`decision_probe.py`): twenty models answered every claim in
   0.25 to 9 s for $0.0007 to $0.018 per model, the best at 66 of 66 (Perplexity Decider v1.2), 66 of 68 (Gemini Decision 1), 65 of 67
   (Morph Reflex, Cloudflare Clef), 57 of 61 (Jev 1.14) agreeing with the primary on the claims they decided. What the format must say
   for them: (a) **the note is written by the service from the probabilities** (the model writes none), and the header says so;
   (b) **how a decision model names its candidate**: a fixed yes-probability threshold on each candidate (0.5 in the measurement) turned
   up to 29 of a model's decided verdicts into UNDECIDED (Clef Flash) because the per-candidate questions are independent of the verdict
   question; the rule for the revision is **argmax**: an EVIDENCED verdict names the FOR candidate with the highest yes-probability (a
   CONTRADICTED one the AGAINST candidate), and the probabilities of all candidates go in the note; a row with no candidate of the needed
   side stays UNDECIDED by the shape rule; (c) `confidence` on a CONTRADICTED row = `high` when the choice confidence is at or above a
   stated figure (0.8 in the measurement), else `low`; (d) the header names the dated snapshot the provider served (`typesafe/jev-1.14-20261014`),
   which is the provider id with version section 14 asks for; (e) the questions and criteria are part of the contract like a prompt, with
   their sha256 in the header (3d.1 and section 6 apply); (f) a web-grounded decision model (Parallel Decisions Fast "researches the live
   web") is not a classifier of the rendered candidates and is excluded by the "fetches nothing" rule of section 14. The twenty signed
   files inserted into a copy of the snapshot by `add_witness.py` pass `check.py` (the SUMMARY line is in the evidence README).
19. **A script that names the first primary** (the format owner, 12 Nov 2026 23:1xZ, with the pre-witness stage of section 14). The stage
   is in the checker and the kit's `onedroid claims snapshot` writes it (Indie #71), but nothing yet performs the second allowed change:
   `add_witness.py --primary <name> --key K --identity I` (or a `name_primary.py`) that marks one listed witness primary, writes
   `claims.jsonl` as the merge (`merge.py` has the rule), `claims_sha256`, `score`, the full `counts`, `grading.grader` and `grading.model`
   from the primary's entry, `grading.kind` by the signer rule, `grading.primary_named_by`, refreshes the manifest's hashes and signs the
   manifest, refusing a folder that already has a primary or whose `grading.kind` is not `pre-witness`, and re-runs the checker. Until it
   exists, a witnessed turn end is bundled complete by the kit (`onedroid claims bundle`) and a pre-witness folder stays pre-witness. The
   evidence service's version rule (Talos's design of the same night) follows the two allowed changes: `manifest.json`, `manifest.json.sig`
   (added by Talos on the first real pair: it appears with the first manifest signature and changes with every later allowed change),
   `signatures.json`, `allowed_signers` and `CHECK.json` may change between a parent and its version, `claims.jsonl` may appear once,
   everything else the parent lists is byte-identical, and a version of any other shape is refused.
20. **K2 names the auditor part and a dict-shaped `files`** (the gate of Indie #71, 12 Nov 2026 23:5xZ, withheld case W7). One byte of
   `audit.jsonl` changed after the write is caught by K11 (`grading.auditor.sha256`) and K13 (the signature), but K2 prints
   "PASS: 3 files named, hashes match": `check.py` K2 hashes `pages[].file`, `sources[].file`, `claims.jsonl` (not in pre-witness) and
   `files` only when it is a LIST (check.py 380 to 393), while the kit's writer (and the agent-work example) carry `files` as an OBJECT
   (file to sha256), so neither `audit.jsonl` nor the object's entries are in K2's list. No trust gap, a naming gap: the next checker cut
   reads `files` in both shapes, adds `audit.jsonl` through `grading.auditor.sha256` and the witness files through their entries, and
   says so in K2's text. It changes K2's count on every 0.4 and later folder, so it goes with the next cut and its repin, not alone.
   Also from the same gate: Indie's env var `ONEDROID_CHECK_PY` is a PATH to the checker, not its hash (18 tests fail with "can't open
   file" when given the hash); the kit's docs should say so.
