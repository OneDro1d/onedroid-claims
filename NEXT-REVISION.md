# claims-snapshot: open items for the revision after 0.5

Kept here so the adopted `SPEC.md` (0.6, 12 Nov 2026 11:0xZ: sha256 f90e43f7…; 0.5 was 58221ef5…) and `check.py` (2bdd8ba9…; 0.5 was be0db6f9…) stay byte-stable until a revision is cut. Each line names
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
