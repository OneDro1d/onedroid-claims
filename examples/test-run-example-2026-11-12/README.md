# Example of the test-run profile (claims-snapshot/0.5, SPEC.md section 13)

Made on 12 Nov 2026 02:4xZ with the real writer at OneDroid Indie dev e37493b4 (`go run ./cmd/onedroid record run | witness | bundle`, the script `argus/fleet-gate-evidence/2026-11-12-s13-record-indie59/example-run.sh` in this notepad). **It is synthetic and says so in every claim: no scenario was run, the one named check is a placeholder, and the record proves nothing about the system it names.** The system under test is a real commit (OneDroid Fleet dev 917612aa, the image app-dev ran as rev 13 on 12 Nov) so that the commit rule of C-003 binds to something that exists.

- `audit.jsonl`: the runner's three claims, signed by the enrolled key of a scratch `VALOR_HOME` (identity `trilix-gate-example-runner`).
- `witness/trilix-gate-witness.jsonl`: a `read` witness, signed with a scratch `ssh-keygen` key (identity `trilix-gate-witness-example`). Different key from the runner's, as the format requires.
- `sources/artefacts/`: the five artefacts by name and hash (`held_by: folder`).
- Both keys were made for this example and live only in the session's scratchpad: the signatures verify (`allowed_signers` carries the public keys) but nobody stands behind them. Do not cite this folder as a run.

`python3 -I check.py examples/test-run-example-2026-11-12/` at the adopted checker: K1 to K13 PASS, K14 and K15 WARN (no anchor, no session record), exit 0.
