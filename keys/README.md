# Model key list (claims-snapshot 0.6, SPEC.md section 14)

`model-keys.jsonl` is the published list that traces a witness service's signing key to a person: one line per key,
`{"principal", "model", "key", "valid_from", "valid_to", "note"}`. A key is never deleted; it gets a `valid_to`. The list is changed only
in a commit signed by its keeper (the OneDroid organisation's owner). `python3 -I check.py <snapshot> --keys keys/model-keys.jsonl`
checks a model witness's principal against it: present, bound to the header's `model`, inside its window, the same key as the snapshot's
`allowed_signers` line (by type and base64).

`anchor-signers.jsonl` (claims-snapshot 0.7, SPEC.md section 3a) is the published list that turns an anchor's recovered signer address into
a principal: one line per chain and address, `{"principal", "chain", "address", "valid_from", "valid_to", "note"}`, never deleted, only
closed with `valid_to`, changed only in a signed commit like the model key list. The anchor service allows one signer key per caller per
chain, which makes the mapping one-to-one. It is empty until the first anchor grant is listed; check.py does not read it yet (K14 checks the
signer's shape, a consumer of the bus notice checks the signer against this list, section 15).

The model key list is empty until the witness service of section 14 mints its first keys. A snapshot may carry a copy under its own
`keys/model-keys.jsonl` for offline readers; this file is the authority.
