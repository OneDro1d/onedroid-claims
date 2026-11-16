#!/usr/bin/env python3
"""test_make_index.py: the suite of make_index.py, the snapshot index (snapshots/index.json). Standard library only.

I1 one snapshot: one entry, every field from the folder (path, manifest sha256, format, subject.title, grading.kind and
   .profile), the anchor "not anchored yet" for an empty anchors.json and for none.
I2 two snapshots: both listed, newest date first; an anchored one carries its first ref's chain, block and tx_hash.
I3 a missing or empty field fails loudly: exit 1, stderr names the field and the folder, no index.json written and an
   existing one left as it was. The same for a date folder without manifest.json, a malformed anchors.json, a folder name a
   reader cannot address, a date that is not a calendar date and a symbolic link.
I4 stable: a re-run writes byte-identical output, --check passes on it, and --check fails (exit 1, nothing written) on a
   stale or missing index.

usage: python3 -I test_make_index.py"""
import hashlib, json, pathlib, shutil, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
TOOL = HERE / "make_index.py"
RESULTS = []


def report(name, ok, expected, observed):
    RESULTS.append((name, ok))
    print(f"{'ok      ' if ok else 'MISMATCH'} {name}: expected {expected}; observed {observed}")


def case(name, fn):
    try:
        fn()
    except Exception as e:  # a crash in a case is a MISMATCH, never a silent pass
        report(name, False, "the case to run", f"{e.__class__.__name__}: {e}")


def run(root, *flags):
    return subprocess.run([sys.executable, "-I", str(TOOL), "--root", str(root), *flags], capture_output=True, text=True)


def manifest(title="A title", fmt="claims-snapshot/0.6", kind="pre-witness", profile="agent-work"):
    return {"format": fmt, "subject": {"title": title, "publisher": "p"}, "taken_at": "2026-11-13T16:58:55Z",
            "grading": {"kind": kind, "profile": profile}}


def snap(root, org, slug, date, man=None, anchors="[]"):
    d = root / org / slug / date
    d.mkdir(parents=True)
    b = (json.dumps(man if man is not None else manifest(), indent=2, sort_keys=True) + "\n").encode()
    (d / "manifest.json").write_bytes(b)
    if anchors is not None:
        (d / "anchors.json").write_text(anchors, encoding="utf-8")
    return hashlib.sha256(b).hexdigest()


def index(root):
    p = root / "index.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


NOT = {"status": "not anchored yet", "chain": None, "block": None, "tx_hash": None}
REF = {"chain": "argus-dev-poa", "correlation_id": "c" * 32, "block": 4242, "tx_hash": "0x" + "ab" * 32}


def main():
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        n = [0]

        def fresh():
            n[0] += 1
            r = tmp / f"r{n[0]}"
            r.mkdir()
            return r

        def i1():
            root = fresh()
            sha = snap(root, "onedroid", "packager-r03-fix", "2026-11-13")
            r = run(root)
            got = index(root)
            want = {"snapshots": [{"org": "onedroid", "slug": "packager-r03-fix", "date": "2026-11-13", "manifest_sha256": sha,
                                   "format": "claims-snapshot/0.6", "title": "A title", "kind": "pre-witness", "profile": "agent-work", "anchor": NOT}]}
            report("i1_one_snapshot", r.returncode == 0 and got == want, f"exit 0, {want}", f"exit {r.returncode}, {got}, {r.stderr.strip()}")
            root2 = fresh()
            snap(root2, "onedroid", "x", "2026-11-13", anchors=None)
            r = run(root2)
            got = index(root2)
            ok = r.returncode == 0 and got and got["snapshots"][0]["anchor"] == NOT
            report("i1b_no_anchors_file_is_not_anchored", bool(ok), f"exit 0, anchor {NOT}", f"exit {r.returncode}, {got}, {r.stderr.strip()}")
        case("i1", i1)

        def i2():
            root = fresh()
            a = snap(root, "onedroid", "older", "2026-11-12", manifest(title="Older"))
            entry = {"over": "sha256:" + "0" * 64, "method": "armarium", "ref": REF, "time": "2026-11-13T14:00:00Z", "proof_file": None}
            b = snap(root, "acme", "newer", "2026-11-14", manifest(title="Newer", fmt="claims-snapshot/0.7", kind="model", profile="test-run"),
                     anchors=json.dumps([entry]))
            r = run(root)
            got = index(root) or {"snapshots": []}
            rows = got["snapshots"]
            ok = (r.returncode == 0 and [(e["org"], e["slug"], e["date"]) for e in rows] == [("acme", "newer", "2026-11-14"), ("onedroid", "older", "2026-11-12")]
                  and rows[0]["manifest_sha256"] == b and rows[1]["manifest_sha256"] == a
                  and rows[0]["anchor"] == {"status": "anchored", "chain": "argus-dev-poa", "block": 4242, "tx_hash": "0x" + "ab" * 32}
                  and rows[0]["format"] == "claims-snapshot/0.7" and rows[0]["kind"] == "model" and rows[0]["profile"] == "test-run"
                  and rows[1]["anchor"] == NOT and rows[1]["title"] == "Older")
            report("i2_two_snapshots_newest_first_and_anchor", ok, "exit 0, acme/newer/2026-11-14 anchored (argus-dev-poa 4242) then onedroid/older not anchored",
                   f"exit {r.returncode}, {rows}, {r.stderr.strip()}")
        case("i2", i2)

        def refused(name, setup, needle):
            root = fresh()
            snap(root, "onedroid", "good", "2026-11-13")
            (root / "index.json").write_bytes(b"KEEP\n")
            setup(root)
            r = run(root)
            kept = (root / "index.json").read_bytes() == b"KEEP\n"
            ok = r.returncode == 1 and needle in r.stderr and "nothing written" in r.stderr and kept and "Traceback" not in r.stderr
            report(name, ok, f"exit 1, stderr names {needle!r}, nothing written, the old index kept", f"exit {r.returncode}, kept {kept}, {r.stderr.strip()}")

        def drop(path, empty=False):
            def setup(root):
                m = manifest()
                parent = m
                for k in path[:-1]:
                    parent = parent[k]
                if empty:
                    parent[path[-1]] = ""
                else:
                    del parent[path[-1]]
                snap(root, "onedroid", "broken", "2026-11-14", m)
            return setup

        for field in (["format"], ["subject", "title"], ["grading", "kind"], ["grading", "profile"]):
            dotted = ".".join(field)
            case(f"i3_{dotted}", lambda field=field, dotted=dotted: refused(f"i3_missing_{dotted}_fails", drop(field), f"onedroid/broken/2026-11-14: manifest.json has no {dotted}"))
            case(f"i3e_{dotted}", lambda field=field, dotted=dotted: refused(f"i3_empty_{dotted}_fails", drop(field, empty=True), f"manifest.json {dotted} is not a non-empty string"))
        case("i3_subject", lambda: refused("i3_missing_subject_fails", lambda root: snap(root, "onedroid", "broken", "2026-11-14", {k: v for k, v in manifest().items() if k != "subject"}),
                                           "manifest.json has no subject.title"))
        case("i3_nomanifest", lambda: refused("i3_date_folder_without_manifest_fails", lambda root: (root / "onedroid" / "broken" / "2026-11-14").mkdir(parents=True), "no manifest.json"))
        case("i3_badjson", lambda: refused("i3_manifest_not_json_fails", lambda root: (snap(root, "onedroid", "broken", "2026-11-14"),
                                                                                       (root / "onedroid" / "broken" / "2026-11-14" / "manifest.json").write_text("{", encoding="utf-8")),
                                           "manifest.json is not JSON"))
        case("i3_anchors_obj", lambda: refused("i3_anchors_not_a_list_fails", lambda root: snap(root, "onedroid", "broken", "2026-11-14", anchors="{}"), "anchors.json is not a list"))
        case("i3_anchors_ref", lambda: refused("i3_anchor_ref_without_block_fails",
                                               lambda root: snap(root, "onedroid", "broken", "2026-11-14", anchors=json.dumps([{"ref": {"chain": "c", "tx_hash": "0x1"}}])),
                                               "needs chain (string), block (integer) and tx_hash (string)"))
        case("i3_upper", lambda: refused("i3_org_not_lower_case_fails", lambda root: snap(root, "OneDroid", "x", "2026-11-14"), "the org folder is not a lower-case name"))
        case("i3_date", lambda: refused("i3_date_not_calendar_fails", lambda root: snap(root, "onedroid", "x", "2026-02-30"), "not a calendar date"))
        case("i3_datefmt", lambda: refused("i3_date_not_yyyy_mm_dd_fails", lambda root: snap(root, "onedroid", "x", "latest"), "not YYYY-MM-DD"))
        case("i3_link", lambda: refused("i3_symbolic_link_fails", lambda root: (root / "onedroid" / "good" / "2026-11-15").symlink_to("2026-11-13"), "symbolic link"))
        case("i3_link_in", lambda: refused("i3_symbolic_link_inside_a_snapshot_fails",
                                           lambda root: (root / "onedroid" / "good" / "2026-11-13" / "page.txt").symlink_to("manifest.json"), "page.txt is a symbolic link"))

        def i4():
            root = fresh()
            snap(root, "onedroid", "a", "2026-11-13")
            snap(root, "onedroid", "b", "2026-11-13")
            snap(root, "zeta", "c", "2026-11-13")
            (root / "README.md").write_text("not a snapshot\n", encoding="utf-8")
            r1 = run(root)
            first = (root / "index.json").read_bytes()
            r2 = run(root)
            second = (root / "index.json").read_bytes()
            c = run(root, "--check")
            order = [(e["org"], e["slug"]) for e in json.loads(first)["snapshots"]]
            ok = (r1.returncode == 0 and r2.returncode == 0 and first == second and c.returncode == 0 and first.endswith(b"}\n")
                  and order == [("onedroid", "a"), ("onedroid", "b"), ("zeta", "c")])
            report("i4_rerun_byte_identical_and_check_passes", ok, "two runs byte-identical, same date ordered by org/slug, --check exit 0",
                   f"identical {first == second}, order {order}, check exit {c.returncode} {c.stdout.strip()} {c.stderr.strip()}")
            m = root / "zeta" / "c" / "2026-11-13" / "manifest.json"
            m.write_bytes(m.read_bytes() + b"\n")
            c = run(root, "--check")
            unchanged = (root / "index.json").read_bytes() == first
            report("i4_check_fails_on_stale_index", c.returncode == 1 and "stale" in c.stderr and unchanged,
                   "--check exit 1 'stale', index untouched", f"exit {c.returncode}, untouched {unchanged}, {c.stderr.strip()}")
            (root / "index.json").unlink()
            c = run(root, "--check")
            report("i4_check_fails_on_missing_index", c.returncode == 1 and not (root / "index.json").exists(),
                   "--check exit 1, nothing written", f"exit {c.returncode}, written {(root / 'index.json').exists()}")
        case("i4", i4)

        def i4b():
            root = fresh()
            shutil.copytree(HERE / "snapshots", root / "s", symlinks=True)
            c = run(root / "s", "--check")
            report("i4b_committed_index_is_current", c.returncode == 0, "--check exit 0 on a copy of this repository's snapshots/",
                   f"exit {c.returncode}, {c.stdout.strip()} {c.stderr.strip()}")
        case("i4b", i4b)

    n_bad = sum(1 for _, ok in RESULTS if not ok)
    print(f"test_make_index: {len(RESULTS) - n_bad} of {len(RESULTS)} cases gave the expected result; MISMATCH {n_bad}")
    return 0 if n_bad == 0 and RESULTS else 1


if __name__ == "__main__":
    sys.exit(main())
