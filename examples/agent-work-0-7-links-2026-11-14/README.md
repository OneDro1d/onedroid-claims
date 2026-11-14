# A claims-snapshot 0.7 example (14 Nov 2026)

This folder is the agent-work example `../agent-work-s-i10-2026-11-12` (the kit's S-I10 bundle, three claims, one false) relabelled
`claims-snapshot/0.7` and re-signed with throwaway keys that were made for it and discarded. It shows the three things 0.7 adds to a
folder, and nothing in it is a published audit:

- `links` in `manifest.json`: one `wasDerivedFrom` link to the 0.5 example, by the sha256 of its `manifest.json` and `signatures.json`,
  with its relative path and its location at commit 4be17f16. The auditor's `sources` signature covers it (the six-section digest).
- `anchors.json`: one armarium entry whose ref carries the `signer` (0.7) and a `gvui` derived from the ref. The chain name
  `example-chain`, the correlation id, the block, the transaction hash and the signer are ILLUSTRATIVE: no chain write was made, and
  K14 checks only the binding (the entry is over this folder's `signatures.json`) and the shapes, never the chain.
- An export, beside the folder in `../agent-work-0-7-links-2026-11-14.exports/<manifest sha256, first 16>/`: the in-toto Statement v1,
  its DSSE envelope and the W3C VC 2.0 credential, signed with the key inside `audit.jsonl.sig`.

Check it: `python3 -I check.py examples/agent-work-0-7-links-2026-11-14 --export examples/agent-work-0-7-links-2026-11-14.exports/<dir>`.
