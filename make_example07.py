"""Builds examples/agent-work-0-7-links-2026-11-14 and its export (gate-h2 F3, 14 Nov 2026: how the example was made, on record).

usage: python3 make_example07.py [CLONE]   (default: this file's folder; export.py needs the cryptography package)

Throwaway keys are made in a temporary folder and discarded. The public keys stay in the folder's allowed_signers; the private keys
never leave the temporary folder. So a rebuild is NOT byte-identical: new keys give new signatures, a new manifest sha256 and a new
export folder name. What a rebuild must reproduce is the shape: the same content files, one link, one anchor entry, an export that
`check.py <folder> --export <dir>` passes. After a rebuild, the export folder name in .github/workflows/check-examples.yml changes."""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

CLONE = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else __file__).resolve()
if CLONE.is_file():
    CLONE = CLONE.parent
sys.path.insert(0, str(CLONE))
import check  # noqa: E402
import fixtures07 as f  # noqa: E402

NAME = "agent-work-0-7-links-2026-11-14"
DST = CLONE / "examples" / NAME
SRC = CLONE / "examples" / "agent-work-s-i10-2026-11-12"
LOC_SRC = "https://github.com/OneDro1d/onedroid-claims/tree/4be17f16d8ff6b3bc636f5bb6b1b3e5163b9b236/examples/agent-work-s-i10-2026-11-12"
LOC_DST = f"https://github.com/OneDro1d/onedroid-claims/tree/main/examples/{NAME}"

README = """# A claims-snapshot 0.7 example (14 Nov 2026)

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
"""


def main():
    if DST.exists():
        shutil.rmtree(DST)
    for p in (CLONE / "examples").glob(NAME + ".exports"):
        shutil.rmtree(p)
    with tempfile.TemporaryDirectory() as td:
        f.keygen(pathlib.Path(td) / "keys", names=("auditor", "witness"))
        f.build(DST, fmt=f.F07, sources=False, src=SRC)
        (DST / "README.md").write_text(README, encoding="utf-8")
        link = {"rel": "wasDerivedFrom",
                "target": {"manifest_sha256": check.sha256(SRC / "manifest.json"), "signatures_sha256": check.sha256(SRC / "signatures.json"),
                           "path": "../agent-work-s-i10-2026-11-12", "location": LOC_SRC, "anchor": None},
                "note": "this folder is that 0.5 example relabelled claims-snapshot/0.7 and re-signed with throwaway keys"}
        f.set_links(DST, [link], resign=False)
        f.resign_sources(DST)
        entry = {"over": "sha256:" + check.sha256(DST / "signatures.json"), "method": "armarium",
                 "ref": {"chain": "example-chain", "correlation_id": "0123456789abcdef0123456789abcdef", "block": 1,
                         "tx_hash": "0x" + "00" * 31 + "01", "signer": "0x000000000000000000000000000000000000dEaD"},
                 "time": "2026-11-14T00:00:00Z", "proof_file": None}
        entry["gvui"] = check.gvui_of(entry)
        (DST / "anchors.json").write_text(json.dumps([entry], indent=1) + "\n", encoding="utf-8")
        msha = check.sha256(DST / "manifest.json")
        out = CLONE / "examples" / (NAME + ".exports") / msha[:16]
        r = subprocess.run([sys.executable, "-I", str(CLONE / "export.py"), str(DST), "--key", str(f.KEYS["auditor"]), "--out", str(out),
                            "--location", LOC_DST], capture_output=True, text=True)
        print(r.stdout, r.stderr)
        print("export dir", out.relative_to(CLONE))
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
