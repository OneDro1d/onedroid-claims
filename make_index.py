#!/usr/bin/env python3
"""make_index.py: write snapshots/index.json, the list of every published snapshot, for readers that list them (the OneDroid
app's BFF reads it at /bff/v1/public/v1/snapshots). Standard library only. Nothing is fetched.

usage: python3 -I make_index.py [--root DIR] [--check]
  --root DIR  the snapshots folder (default: snapshots/ next to this script); the index is DIR/index.json
  --check     write nothing; exit 1 when DIR/index.json is not byte-identical to what this script would write (CI)

A snapshot is a folder DIR/<org>/<slug>/<date>/ that holds manifest.json. Every field of its entry comes from that folder:
  org, slug, date      the folder's own path (org and slug lower-case names, ^[a-z0-9][a-z0-9._-]{0,63}$; date a calendar
                       date YYYY-MM-DD), the path a reader fetches the files under
  manifest_sha256      the sha256 of manifest.json's bytes
  format               manifest "format"
  title                manifest "subject"."title"
  kind, profile        manifest "grading"."kind" and "grading"."profile"
  anchor               anchors.json's first entry's ref {status "anchored", chain, block, tx_hash}; no anchors.json, or an
                       empty list, is {status "not anchored yet", chain null, block null, tx_hash null}
A missing or empty field, a malformed anchors.json, a folder the reader could not address, a date folder without
manifest.json or a symbolic link anywhere under DIR stops the script with exit 1 and nothing written. The output is
canonical (sorted keys, newest date first, then org/slug), so a re-run on the same folders writes the same bytes."""
import datetime, hashlib, json, pathlib, re, sys

HERE = pathlib.Path(__file__).resolve().parent
NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
NOT_ANCHORED = {"status": "not anchored yet", "chain": None, "block": None, "tx_hash": None}


class IndexError_(Exception):
    pass


def fail(where, why):
    raise IndexError_(f"{where}: {why}")


def text_field(obj, keys, where):
    v = obj
    for k in keys:
        if not isinstance(v, dict) or k not in v:
            fail(where, f"manifest.json has no {'.'.join(keys)}")
        v = v[k]
    if not isinstance(v, str) or not v.strip():
        fail(where, f"manifest.json {'.'.join(keys)} is not a non-empty string")
    return v


def anchor_of(folder, where):
    p = folder / "anchors.json"
    if not p.exists() and not p.is_symlink():
        return dict(NOT_ANCHORED)
    try:
        a = json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        fail(where, f"anchors.json is not JSON ({e.__class__.__name__})")
    if not isinstance(a, list):
        fail(where, "anchors.json is not a list")
    if not a:
        return dict(NOT_ANCHORED)
    ref = a[0].get("ref") if isinstance(a[0], dict) else None
    if not isinstance(ref, dict):
        fail(where, "anchors.json's first entry has no ref object")
    chain, block, tx = ref.get("chain"), ref.get("block"), ref.get("tx_hash")
    if not isinstance(chain, str) or not chain or not isinstance(tx, str) or not tx or not isinstance(block, int) or isinstance(block, bool):
        fail(where, "anchors.json's first ref needs chain (string), block (integer) and tx_hash (string)")
    return {"status": "anchored", "chain": chain, "block": block, "tx_hash": tx}


def entry(folder, org, slug, date):
    where = f"{org}/{slug}/{date}"
    m = folder / "manifest.json"
    if not m.is_file():
        fail(where, "no manifest.json")
    b = m.read_bytes()
    try:
        man = json.loads(b.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        fail(where, f"manifest.json is not JSON ({e.__class__.__name__})")
    if not isinstance(man, dict):
        fail(where, "manifest.json is not an object")
    return {"org": org, "slug": slug, "date": date, "manifest_sha256": hashlib.sha256(b).hexdigest(),
            "format": text_field(man, ["format"], where), "title": text_field(man, ["subject", "title"], where),
            "kind": text_field(man, ["grading", "kind"], where), "profile": text_field(man, ["grading", "profile"], where),
            "anchor": anchor_of(folder, where)}


def subdirs(d, where):
    """The folders in d, sorted. A file beside them (index.json itself, a README) is not a snapshot and is skipped."""
    out = []
    for p in sorted(d.iterdir()):
        if p.is_symlink():
            fail(where + p.name, "a symbolic link (never followed)")
        if p.is_dir():
            out.append(p)
    return out


def build(root):
    root = pathlib.Path(root)
    if root.is_symlink() or not root.is_dir():
        fail(str(root), "not a folder")
    rows = []
    for o in subdirs(root, ""):
        if not NAME.match(o.name):
            fail(o.name, "the org folder is not a lower-case name")
        for s in subdirs(o, o.name + "/"):
            if not NAME.match(s.name):
                fail(f"{o.name}/{s.name}", "the slug folder is not a lower-case name")
            for d in subdirs(s, f"{o.name}/{s.name}/"):
                where = f"{o.name}/{s.name}/{d.name}"
                if not DATE.match(d.name):
                    fail(where, "the date folder is not YYYY-MM-DD")
                try:
                    datetime.date.fromisoformat(d.name)
                except ValueError:
                    fail(where, "the date folder is not a calendar date")
                for p in d.rglob("*"):
                    if p.is_symlink():
                        fail(where, f"{p.relative_to(d)} is a symbolic link (never followed)")
                rows.append(entry(d, o.name, s.name, d.name))
    rows.sort(key=lambda e: (e["org"], e["slug"]))
    rows.sort(key=lambda e: e["date"], reverse=True)
    return (json.dumps({"snapshots": rows}, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def main(argv):
    args = list(argv)
    check = "--check" in args
    if check:
        args.remove("--check")
    root = HERE / "snapshots"
    if args[:1] == ["--root"] and len(args) == 2:
        root = pathlib.Path(args[1])
        args = []
    if args:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        out = build(root)
    except IndexError_ as e:
        print(f"make_index: {e}; nothing written", file=sys.stderr)
        return 1
    target = root / "index.json"
    if check:
        if target.is_symlink() or not target.is_file() or target.read_bytes() != out:
            print(f"make_index: {target} is stale or missing: run python3 -I make_index.py and commit the result", file=sys.stderr)
            return 1
        print(f"make_index: {target} is current ({len(json.loads(out)['snapshots'])} snapshot(s))")
        return 0
    if target.is_symlink():
        print(f"make_index: {target} is a symbolic link; nothing written", file=sys.stderr)
        return 1
    target.write_bytes(out)
    print(f"make_index: wrote {target} ({len(json.loads(out)['snapshots'])} snapshot(s), sha256 {hashlib.sha256(out).hexdigest()})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
