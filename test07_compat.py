#!/usr/bin/env python3
"""test07_compat.py: the compatibility suite of claims-snapshot 0.7 (C1 and C3 of the 0.7 design's RED list; C2 is every existing suite
run unchanged). Standard library plus ssh-keygen on PATH.

C1, the survey: every folder holding a manifest.json under snapshots/, examples/ and fixtures/ (and under each --also ROOT) is checked by
this check.py and by the committed one (--committed PATH, the previous adopted check.py); the output (stdout and stderr) and the exit
code must be byte-identical. A folder of format 0.7 or later is listed and not compared (the previous checker does not read it). Every
compared row must be a real checker result (a SUMMARY line from both), never an error. --survey-out FILE writes the table.
C3, the inheritance: a 0.7 folder carrying none of the new fields gives the same K1 to K15 lines as its 0.6 twin, plus K16 "no links";
and every rule keyed on 0.6 (the pre-witness stage, a witness kind outside the three, UNDECIDED rows without an `undecided` count, an
agent witness file not named for its entry) holds on 0.7 exactly as on 0.6, while 0.5 keeps its WARN.

usage: python3 -I test07_compat.py [--committed PATH | --committed none] [--also ROOT]... [--survey-out FILE]"""
import hashlib, json, pathlib, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fixtures07 as f  # noqa: E402

ARGS = sys.argv[1:]
COMMITTED = ARGS[ARGS.index("--committed") + 1] if "--committed" in ARGS else "none"
ALSO = [pathlib.Path(ARGS[i + 1]) for i, a in enumerate(ARGS) if a == "--also" and i + 1 < len(ARGS)]
SURVEY_OUT = pathlib.Path(ARGS[ARGS.index("--survey-out") + 1]) if "--survey-out" in ARGS else None


def norm(out):
    """A run's lines with the format label read as 0.6, the K16 line and its details and the SUMMARY line left out."""
    keep, skip = [], False
    for l in out.replace("claims-snapshot/0.7", "claims-snapshot/0.6").splitlines():
        if l.startswith("K16 "):
            skip = True
            continue
        if skip and l.startswith("    "):
            continue
        skip = False
        if l.startswith("SUMMARY:"):
            continue
        keep.append(l)
    return keep


def twin_pair(tmp, name, mutate=None, fmts=(f.F07, f.F06)):
    """The same mutation applied to a fixture of each format; returns the runs in `fmts` order."""
    runs = []
    for fmt in fmts:
        d = f.build(tmp / f"{name}-{fmt.rsplit('/', 1)[1]}", fmt=fmt)
        if mutate:
            mutate(d)
        runs.append(f.Run(d))
    return runs


def survey():
    roots = [HERE / "snapshots", HERE / "examples", HERE / "fixtures"] + ALSO
    folders = sorted({p.parent for r in roots if r.is_dir() for p in r.rglob("manifest.json")})
    rows, compared, differ, not_result, skipped07 = [], 0, 0, 0, []
    for d in folders:
        try:
            fmt = json.loads((d / "manifest.json").read_text(encoding="utf-8")).get("format")
        except Exception:  # noqa: BLE001
            fmt = None
        if isinstance(fmt, str) and f.check.fmt_at_least({"format": fmt}, "0.7"):
            skipped07.append(str(d))
            continue
        res = []
        for chk in (COMMITTED, str(HERE / "check.py")):
            r = subprocess.run([sys.executable, "-I", chk, str(d)], capture_output=True)
            blob = r.stdout + b"\x00" + r.stderr
            summary = next((l for l in r.stdout.decode("utf-8", "replace").splitlines() if l.startswith("SUMMARY:")), None)
            res.append((r.returncode, hashlib.sha256(blob).hexdigest(), summary))
        (rc_o, h_o, s_o), (rc_n, h_n, s_n) = res
        same = rc_o == rc_n and h_o == h_n
        real = s_o is not None and s_n is not None
        compared += 1
        differ += 0 if same else 1
        not_result += 0 if real else 1
        rows.append(f"{'same' if same else 'DIFFER'}  old exit {rc_o} sha256 {h_o}  new exit {rc_n} sha256 {h_n}  {s_n}  {d}")
    return rows, compared, differ, not_result, skipped07


def main():
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        f.keygen(tmp / "keys")

        # C1: the survey against the committed checker
        def c1():
            if COMMITTED == "none":
                print("skipped  c1_survey: --committed none, no committed checker to compare with")
                return
            rows, compared, differ, not_result, skipped07 = survey()
            text = "\n".join(rows + [f"0.7 or later, not compared: {s}" for s in skipped07]
                             + [f"compared {compared}, differ {differ}, rows that are not a checker result {not_result}"])
            if SURVEY_OUT:
                SURVEY_OUT.write_text(text + "\n", encoding="utf-8")
            f.report("c1_survey", compared > 0 and differ == 0 and not_result == 0,
                     "every folder byte-identical with an equal exit code, more than 0 compared, every row a checker result",
                     f"compared {compared}, differ {differ}, not a result {not_result}, 0.7 skipped {len(skipped07)}",
                     [r for r in rows if not r.startswith("same")][:10])
        f.case("c1_survey", c1)

        # C3a: no new fields, the same lines as the 0.6 twin plus K16 "no links"
        def c3a():
            r7, r6 = twin_pair(tmp, "c3a")
            ok = (norm(r7.out) == norm(r6.out) and r7.status.get("K16") == "PASS" and r7.has("K16", "no links") and "K16" not in r6.status
                  and r7.rc == r6.rc == 0 and not r7.traceback)
            f.report("c3a_no_new_fields_same_as_06_plus_k16", ok, "K1 to K15 lines equal to the 0.6 twin, K16 PASS 'no links', exit 0 both",
                     f"lines equal {norm(r7.out) == norm(r6.out)}, K16 {r7.status.get('K16')}, exits {r7.rc}/{r6.rc}, summary {r7.summary}",
                     [l for l in r7.out.splitlines() if l.startswith(("K1 ", "K16"))])
        f.case("c3a_no_new_fields_same_as_06_plus_k16", c3a)

        # C3b: a witness kind outside the three: FAIL on 0.6 and on 0.7 (fmt06 at check.py 8212c636:1314), WARN on 0.5
        def kind_robot(d):
            rows = f.load(d / "witness/alice.jsonl")
            rows[0]["kind"] = "robot"
            f.dump(d / "witness/alice.jsonl", rows)
            f.resign_witness(d)
        def c3b():
            r7, r6, r5 = twin_pair(tmp, "c3b", kind_robot, fmts=(f.F07, f.F06, "claims-snapshot/0.5"))
            ok = (r7.status.get("K1") == r6.status.get("K1") == "FAIL" and r5.status.get("K1") == "WARN" and r7.has("K1", "witness kind")
                  and norm(r7.out) == norm(r6.out))
            f.report("c3b_kind_outside_three_fails_on_07", ok, "K1 FAIL on 0.7 and 0.6 with the witness kind line, WARN on 0.5, lines equal",
                     f"K1 0.7 {r7.status.get('K1')}, 0.6 {r6.status.get('K1')}, 0.5 {r5.status.get('K1')}, lines equal {norm(r7.out) == norm(r6.out)}")
        f.case("c3b_kind_outside_three_fails_on_07", c3b)

        # C3c: the pre-witness stage exists from 0.6, so on 0.7 too (check.py 8212c636:623-624)
        def c3c():
            r7, r6 = twin_pair(tmp, "c3c", f.to_pre)
            ok = (r7.status.get("K1") == r6.status.get("K1") == "PASS" and r7.has("K1", "pre-witness: the auditor's part alone")
                  and not r7.has("K1", "the stage exists from") and norm(r7.out) == norm(r6.out) and r7.status.get("K16") == "PASS")
            f.report("c3c_pre_witness_on_07", ok, "K1 PASS pre-witness on 0.7 as on 0.6, lines equal, K16 PASS",
                     f"K1 0.7 {r7.status.get('K1')}, 0.6 {r6.status.get('K1')}, lines equal {norm(r7.out) == norm(r6.out)}",
                     [r7.text.get("K1", "")])
        f.case("c3c_pre_witness_on_07", c3c)

        # C3d: UNDECIDED rows and no `undecided` count: FAIL on 0.6 and 0.7 (fmt06 at :1351), WARN on 0.5
        def undecided(d):
            ans = f.witness_answer(d, d.parent / (d.name + "-ans"), undecided_ids=("C-001",))
            f.add_witness(d, ans)
        def c3d():
            r7, r6, r5 = twin_pair(tmp, "c3d", undecided, fmts=(f.F07, f.F06, "claims-snapshot/0.5"))
            needle = "has 1 UNDECIDED row(s) and its manifest entry has no `undecided` count"
            ok = (r7.status.get("K12") == r6.status.get("K12") == "FAIL" and r5.status.get("K12") == "WARN" and r7.has("K12", needle)
                  and norm(r7.out) == norm(r6.out))
            f.report("c3d_undecided_without_count_fails_on_07", ok, "K12 FAIL on 0.7 and 0.6 with the undecided line, WARN on 0.5, lines equal",
                     f"K12 0.7 {r7.status.get('K12')}, 0.6 {r6.status.get('K12')}, 0.5 {r5.status.get('K12')}, lines equal {norm(r7.out) == norm(r6.out)}")
        f.case("c3d_undecided_without_count_fails_on_07", c3d)

        # C3e: an agent witness whose file is not named for its manifest entry: FAIL on 0.6 and 0.7 (fmt06 at :1588), WARN on 0.5
        def agent_renamed(d):
            rows = f.load(d / "witness/alice.jsonl")
            rows[0]["kind"], rows[0]["witness"] = "agent", "alice2"
            f.dump(d / "witness/alice.jsonl", rows)
            M = f.mload(d)
            M["grading"]["witnesses"][0]["name"] = "alice2"
            f.msave(d, M)
            f.resign_witness(d)
        def c3e():
            r7, r6, r5 = twin_pair(tmp, "c3e", agent_renamed, fmts=(f.F07, f.F06, "claims-snapshot/0.5"))
            needle = "the witness file's name is not its manifest name"
            ok = (r7.status.get("K13") == r6.status.get("K13") == "FAIL" and r5.status.get("K13") == "WARN" and r7.has("K13", needle)
                  and norm(r7.out) == norm(r6.out))
            f.report("c3e_agent_file_name_fails_on_07", ok, "K13 FAIL on 0.7 and 0.6 with the file-name line, WARN on 0.5, lines equal",
                     f"K13 0.7 {r7.status.get('K13')}, 0.6 {r6.status.get('K13')}, 0.5 {r5.status.get('K13')}, lines equal {norm(r7.out) == norm(r6.out)}")
        f.case("c3e_agent_file_name_fails_on_07", c3e)

        # C3f: the version helper itself
        def c3f():
            fa = f.check.fmt_at_least
            got = [fa({"format": x}, "0.6") for x in ("claims-snapshot/0.5", "claims-snapshot/0.6", "claims-snapshot/0.7", "claims-snapshot/0.10", None, 7, "x/0.7")]
            got += [fa({"format": "claims-snapshot/0.6"}, "0.7"), fa({"format": "claims-snapshot/0.7"}, "0.7")]
            want = [False, True, True, True, False, False, False, False, True]
            f.report("c3f_fmt_at_least", got == want, want, got)
        f.case("c3f_fmt_at_least", c3f)

    return f.finish("test07_compat")


if __name__ == "__main__":
    sys.exit(main())
