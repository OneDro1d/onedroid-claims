#!/usr/bin/env python3
"""mutants06i.py: the test suite of the twelfth cut of 13 Nov 2026 (NEXT-REVISION 33; the format owner's design after the eleventh re-gate
of the witness service PASSED the one-auditor cut and 0.1.11-dev with two residuals, the claims session's
gate/2026-11-13-witness-s1-regate11/RESULT.md, O14 and O20, both reproduced by the owner on its own copies with check.py 96c6dbb2).

R1 (O14): K11 30a read the FIRST version string it found (the witness header's `service_version`, else the manifest witness entry's, else
service.json's) and judged that one. A header saying 0.1.7-dev beside a service.json saying 0.1.10-dev got the carried-no-bound WARN alone,
while the promise was "any recorded version of 0.1.8 or later FAILs". Not exploitable as tested (editing a service-signed header breaks K2
and K13), and no genuine service wrote service_version below 0.1.10; a wording residual, closed here.
R2 (O20): a signatures.json holding a non-object entry (a bare string, a number, null) crashed check.py with
`AttributeError: 'str' object has no attribute 'get'` at the auditor-name comprehension, no SUMMARY line, exit 1: a reader got a traceback,
not a verdict. The O1 loop skipped non-objects; the main loop and three later comprehensions did not.

The rules under test (check.py):
  V1  K11 30a reads every record: the header's `service_version`, the manifest witness entry's and service.json's (when the manifest's
      files lists it). Any string among them that parses `major.minor.patch` at 0.1.8 or later FAILs with the existing O5 text, naming the
      first such version in that record order; every string that does not parse WARNs "service_version '<v>' is not a version
      (major.minor.patch)" (each one, FAIL or not); no string at 0.1.8 or later keeps the carried-no-bound WARN.
  V2  K13: a signatures.json whose document is not a list FAILs "signatures.json: a JSON <object|string|number|boolean|null> is not a list
      of signature entries" and nothing is verified; an entry that is not an object FAILs "signatures[<i>]: entry <repr> is not an object
      (role, file, sha256, signer, signature)" and the object entries are still checked, verified and counted; never a traceback, always a
      SUMMARY line.

Fixtures, built in a temporary folder with throwaway keys (mutants06.KEYS): Fpre, F, FB, FS as mutants06c, mutants06d and mutants06f build
them (F = a model witness with `carried` and no `bound`; FS = FB + the auditor's sources signature).

Cases (`--committed PATH | none` the committed check.py; the default is git HEAD of the notepad):
  i1a  F, header service_version "0.1.7-dev" AND service.json "0.1.10-dev" listed in files (the O14 shape): K11 FAIL with the O5 line naming
       0.1.10-dev, no carried-no-bound WARN for that witness, no not-a-version line, exit 1. The committed checker's K11 block is printed
       (WARN only: the RED).
  i1b  header "0.1.7" and the manifest witness entry "0.1.9": FAIL naming 0.1.9, exit 1.
  i1c  header "dev" and service.json "0.1.8": FAIL naming 0.1.8 AND the not-a-version line for 'dev', no carried-no-bound WARN, exit 1.
  i1d  header "0.1.7" and service.json "zz": no FAIL; the carried-no-bound WARN and the not-a-version line for 'zz'; exit 0 (committed: the
       WARN alone, printed).
  i1e  header "0.1.10-dev" alone: FAIL naming 0.1.10-dev, exit 1; whole output byte-identical to the committed checker's.
  i2a  FS with "a string entry", 7, null and [] appended to signatures.json (the O20 shape plus a list): K13 FAIL, one V2 entry line per
       appended value at its index, the same number of "verified" lines as the clean FS run, a SUMMARY line, exit 1, no Traceback. The
       committed checker: Traceback, no SUMMARY (printed: the RED).
  i2b  FS with signatures.json replaced by {} : K13 FAIL "a JSON object is not a list of signature entries", no verified line, SUMMARY, exit 1.
  i2c  FS with signatures.json replaced by "x" : the same line with "string".
  i2d  FS with null inserted at index 0 (before the auditor entry): the V2 line for index 0, the auditor entry still verified, the sources
       ok line still present, exit 1.
  i2e  V2b (the twelfth re-gate's sealed Q06, 13 Nov 2026 10:3xZ: an OBJECT entry with a non-object `signer` or a non-string `signature` still
       crashed 5573fee2 with AttributeError or TypeError and no SUMMARY): FS with the auditor entry's signer replaced by the string
       "just-a-name"; a witness entry's signer replaced by 5; an extra object entry whose signer is ["n"]; the auditor entry's signature
       replaced by a list; a witness entry's role replaced by 7; an entry's sha256 replaced by null. Each: K13 FAIL with the V2b line
       "signatures[<i>]: field <f> is a JSON <kind>, not a <string|object> (role, file, sha256, line and signature are strings, signer an
       object): the entry is not checked", the other entries still verified (a damaged auditor entry also costs the sources entry its
       verified line: no auditor signature to match), a SUMMARY line, exit 1, no Traceback. The committed checker's SUMMARY and Traceback
       are printed (the RED).
  i2f  V2c (the thirteenth re-gate's sealed R05, 13 Nov 2026 10:4xZ: a signer that IS an object whose `name` is a number, a list or an
       object still crashed 2966678b at the key-list lookup (TypeError, unhashable) or at the ssh-keygen spawn (TypeError, not str), no
       SUMMARY, the same on 5573fee2): FS with a witness entry's signer.name 5; the auditor entry's signer.name ["n"]; an extra entry whose
       signer.name is {"k": 1}; a witness entry's signer.key_id a list; the auditor entry's signer.kind 7; a witness entry's signer.name null.
       Each: K13 FAIL with the V2c line "signatures[<i>]: field signer.<f> is a JSON <kind>, not a string (a signer's name, key_id and kind
       are strings): the entry is not checked", no V2b line, the other entries still verified (a damaged auditor entry costs two verified
       lines), a SUMMARY line, exit 1, no Traceback. Plus: an extra signer key of odd type ("principal": ["x"]) gives no V2b or V2c line and
       the same verified count and exit as the clean FS. The committed checker's SUMMARY and Traceback are printed (the RED).
  i4   the tools refuse a wrong-shaped signatures.json by name before writing (the thirteenth re-gate's residual 2: sign.py:92 and
       add_witness.py:95 read `(e.get("signer") or {}).get("name")`): i4a sign.py --role sources on FS with "junk" appended: exit 1, stderr
       names signatures[<n>] "is not an object" and "nothing written", every file unchanged by hash; i4b sign.py --role auditor on FS with the
       auditor's signer a string: exit 1, the V2b signer line, unchanged; i4c sign.py --role sources on FS with a witness signer.name 5: exit
       1, the V2c line, unchanged; i4d add_witness.py on a copy of Fpre whose auditor entry's signer is a string: exit 1, "refused, nothing
       written" with the V2b signer line, the parent unchanged; i4e add_witness.py on a copy of Fpre with "junk" appended: exit 1, "is not an
       object", unchanged. The committed sign.py and add_witness.py are run on the same copies and their exit, Traceback and tree change are
       printed (the RED: a traceback, or a tool that writes).
  i2g  V2d (the fourteenth re-gate's sealed C09, 13 Nov 2026 11:3xZ): an allowed_signers line `* <forger key>` and a witness file re-signed by
       the forger under the genuine name. b2962a18 FAILed the entry by the A3 line but ALSO printed "signed by <name>, verified" and counted it,
       because ssh-keygen reads a principal as a pattern. Now: K13 FAIL with "allowed_signers: principal '*' is a pattern (ssh-keygen reads *, ?
       and ! in a principal as a pattern; a record names its principals plainly)" and the A3 line, NO verified line for that file, one verified
       line fewer than the clean FS, exit 1, no Traceback. Plus a `a?b` principal line alone: the pattern line, the clean verified count. The
       committed checker's K13 block is printed (the RED: the verified line beside the FAIL).
  i4f  T02 and T05 of the same re-gate: sign.py on a signatures.json that is invalid JSON, or not UTF-8: exit 1, "signatures.json is
       unreadable" and "nothing written", no Traceback, every file unchanged (the committed sign.py: a traceback, printed); sign.py on `{}`:
       the message says "fix signatures.json before signing" (was "fix the file"); add_witness.py on a genuine parent with an answer whose
       signatures-entry.json has signer.name 5: exit 1, "refused, nothing written" with "the answer's signatures[0]: field signer.name is a
       JSON number", the parent unchanged by hash (the committed add_witness.py: the parent CHANGED, half-written, printed).
  i4g  T03 and T05b of the fifteenth re-gate (13 Nov 2026 11:5xZ): sign.py on a manifest.json that is valid JSON but not an object (a list in
       the sources role, a string in the auditor role, null in the manifest role), and on an object whose grading is a list, or whose
       grading.witnesses holds a string (auditor role): exit 1, "manifest.json: … is a JSON <kind>, not an object" and "nothing written", no
       Traceback, every file unchanged by hash (the committed sign.py: AttributeError AFTER writing signatures.json and the .sig, printed);
       add_witness.py on a parent whose manifest.json is a list: exit 1, "manifest.json is a JSON array, not an object", unchanged; on an
       answer whose manifest-entry.json name is ["x"]: exit 1, "refused, nothing written" with "the answer's manifest entry [0]: field name is
       a JSON array, not a string", unchanged (the committed add_witness.py: TypeError, unhashable list, printed).
  i2h  the sixteenth re-gate's checker finding (13 Nov 2026 13:2xZ): check.py on FB with grading.auditor a string, a list, a number;
       grading.auditor.file a number; grading.auditor.name a list; grading a list; grading null; the document a list; grading.witnesses an
       object; a string witness entry at index 0; a witness entry whose file is a number; a pages entry that is a string; a pages entry whose
       file is a number; a sources entry that is a string; sources an object: K1 FAIL whose detail lines are exactly the named
       "manifest.json: <path> is a JSON <kind>, not <want>" lines, a SUMMARY line, exit 1, no Traceback (the committed checker: Traceback, no
       SUMMARY, printed). Control: grading.auditor null and grading.witnesses null give no shape line.
  i4h  sign.py, presence not truthiness (the gate's residual 2): grading.auditor "" and grading.witnesses {} refused in the auditor role,
       a witness entry whose file is 5 refused, nothing written, no Traceback; add_witness.py on a parent whose grading.auditor is a string
       (the gate's A04: the committed tool wrote, then stopped): exit 1, "refused", the parent unchanged by hash.
  i2i  the seventeenth re-gate's finding B (13 Nov 2026 13:3xZ): check.py on FB with format a list; counts a list, a string; score a
       string; taken_at a number; grading.profile a list, an object; grading.sessions a string; grading.sessions [5]; grading.gates [5];
       sources[0].path a list; grading.witnesses[0].score a string: K1 FAIL with exactly the named shape line, a SUMMARY line, exit 1, no
       Traceback. Controls: sources[0].path null, grading.sessions null, grading.gates null and a witness score null give no shape line.
       The safety net: sources[0].n a list (no rule names it) gives "K0 FAIL: the checker stopped on a part of the folder it does not
       read (TypeError at check.py:<line>…", a SUMMARY line, exit 1, no Traceback (the committed checker: Traceback, no SUMMARY).
  i2j  the eighteenth re-gate's finding X (13 Nov 2026 14:0xZ): check.py --json on FB with CHECK.json a directory: exactly ONE SUMMARY
       line, ending FAIL, a K0 line naming "CHECK.json could not be written", exit 1, no Traceback (the committed checker: a PASS SUMMARY
       first, then a second). The honest --json run: one SUMMARY, CHECK.json written and holding the same result. The K0 text of the
       safety-net case (sources[0].n a list) names "<folder>", never the folder's absolute path.
  i2k  the nineteenth re-gate's U, J05, J03 and J04 (13 Nov 2026 14:3xZ): a lone surrogate (JSON \\ud800) in an audit row's text, pages[0].file,
       sources[0].path, format or subject.title, with and without --json: exactly one SUMMARY, exit 1 iff it ends FAIL, no Traceback, no
       'stopped after the report' line, and with --json a valid CHECK.json agreeing (the committed checker: no SUMMARY, a Traceback, a 0-byte
       CHECK.json). A stale CHECK.json saying PASS beside a K1 shape fault, an unreadable manifest, a missing field or a K0 net stop, run with
       --json: REWRITTEN with result FAIL (the committed checker: left saying PASS). CHECK.json a symlink to a file outside the folder: refused
       by a K0 line, the outside file unchanged (the committed checker: overwritten). CHECK.json a named pipe: refused within 20 s (the committed
       checker: blocked). CHECK.json mode 444: still a K0 'could not be written' FAIL. An honest --json run leaves no temporary file.
  i3   every folder under snapshots/, examples/ and fixtures/: committed vs cut byte-identical, exit codes equal, no exception.

usage: python3 -I mutants06i.py [--committed PATH | --committed none]
Exit 0 only when every expectation holds; one line per case "ok/MISMATCH <case>: expected ... observed ...", the K11 and K13 blocks
printed under the cases that touch them."""
import json, pathlib, shutil, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402,F401
import mutants06 as m  # noqa: E402
import mutants06p as p  # noqa: E402
import mutants06c as c  # noqa: E402
import mutants06d as dd  # noqa: E402
import mutants06f as f  # noqa: E402
import mutants06h as h  # noqa: E402

BOUND_WARN = h.BOUND_WARN
OK_LINE = h.OK_LINE
V2_TAIL = "is not an object (role, file, sha256, signer, signature)"
V2_DOC = "is not a list of signature entries"


def v2_line(i, value):
    return f"signatures[{i}]: entry {value!r} {V2_TAIL}"


def v2_doc(kind):
    return f"signatures.json: a JSON {kind} {V2_DOC}"


def report(name, ok, expected, observed, details=()):
    return c.report(name, ok, expected, observed, details)


def summary_of(r):
    return next((l for l in r.stdout.splitlines() if l.startswith("SUMMARY")), None)


def verified_lines(bl):
    return [l for l in h.notes(bl) if l.endswith("verified")]


# ---- the cases ----

def i1(tmp, F, committed):
    def case(name, label, expect_fail_v, expect_nv, expect_warn, **kw):
        d = f.copy_of(tmp, F, name)
        h.set_version(d, **kw)
        r, st, bl = h.run(d)
        ns = h.notes(bl, "K11")
        fail = [l for l in ns if l.startswith(f"witness {p.MW!r}: a model witness of service version")]
        want_fail = [h.o5_line(p.MW, expect_fail_v)] if expect_fail_v else []
        nv = [l for l in ns if h.NOT_VERSION in l]
        want_nv = [h.nv_line(p.MW, v) for v in expect_nv]
        warn = [l for l in ns if BOUND_WARN in l and l.startswith(f"witness {p.MW!r}")]
        ok = (fail == want_fail and sorted(nv) == sorted(want_nv) and len(warn) == (1 if expect_warn else 0)
              and st.get("K11") == ("FAIL" if expect_fail_v else "WARN") and r.returncode == (1 if expect_fail_v else 0))
        report(name, ok, f"{label}: K11 {'FAIL' if expect_fail_v else 'WARN'}, O5 line {'naming ' + expect_fail_v if expect_fail_v else 'absent'}, not-a-version lines {expect_nv}, carried-no-bound WARN {'present' if expect_warn else 'absent'}, exit {1 if expect_fail_v else 0}",
               f"K11 {st.get('K11')}, exit {r.returncode}, O5 {[l.split(' records ')[0].split('version ')[-1] for l in fail]}, not-a-version {[l.split(chr(39))[1] for l in nv]}, carried-no-bound {len(warn)}",
               c.block_lines(bl, "K11") + h.committed_block(committed, d, "K11"))
        return d, r
    case("i1a_header_0_1_7_dev_service_json_0_1_10_dev", "the O14 shape: header '0.1.7-dev', service.json '0.1.10-dev'", "0.1.10-dev", [], False, header_v="0.1.7-dev", service_v="0.1.10-dev")
    case("i1b_header_0_1_7_entry_0_1_9", "header '0.1.7', manifest witness entry '0.1.9'", "0.1.9", [], False, header_v="0.1.7", entry_v="0.1.9")
    case("i1c_header_dev_service_json_0_1_8", "header 'dev', service.json '0.1.8'", "0.1.8", ["dev"], False, header_v="dev", service_v="0.1.8")
    case("i1d_header_0_1_7_service_json_zz", "header '0.1.7', service.json 'zz'", None, ["zz"], True, header_v="0.1.7", service_v="zz")
    d, r = case("i1e_header_0_1_10_dev_alone", "header '0.1.10-dev' alone (unchanged behaviour)", "0.1.10-dev", [], False, header_v="0.1.10-dev")
    if committed is not None:
        rc, _, _ = c.run_check(committed, d)
        report("i1e_byte_identical_to_committed", rc.stdout == r.stdout and rc.returncode == r.returncode == 1, "whole output byte-identical to the committed checker's, both exit 1",
               f"identical: {rc.stdout == r.stdout}, exit committed={rc.returncode} cut={r.returncode}")


def i2(tmp, FS, committed):
    if FS is None:
        for n_ in ("i2a_non_object_entries_appended", "i2b_document_is_an_object", "i2c_document_is_a_string", "i2d_null_before_the_auditor_entry"):
            f.not_built(n_, "K13 FAIL by name, SUMMARY present, exit 1, no Traceback")
        return
    r0, st0, bl0 = h.run(FS)
    n_ok0 = len(verified_lines(bl0))
    # i2a
    d = f.copy_of(tmp, FS, "i2a_non_object_entries")
    sigs = f.load_sigs(d)
    n = len(sigs)
    extra = ["a string entry", 7, None, []]
    f.save_sigs(d, sigs + extra)
    r, st, bl = h.run(d)
    ns = h.notes(bl)
    want = [v2_line(n + k, v) for k, v in enumerate(extra)]
    got = [l for l in ns if V2_TAIL in l]
    ok = (got == want and st.get("K13") == "FAIL" and len(verified_lines(bl)) == n_ok0 and summary_of(r) is not None and r.returncode == 1
          and "Traceback" not in r.stderr)
    details = c.block_lines(bl, "K13")
    if committed is not None:
        rc, _, _ = c.run_check(committed, d)
        details += [f"committed checker (exit {rc.returncode}): SUMMARY {summary_of(rc)!r}, Traceback: {'Traceback' in rc.stderr}, last stderr line: {(rc.stderr.strip().splitlines() or [''])[-1][:160]}"]
    report("i2a_non_object_entries_appended", ok, f"K13 FAIL, the V2 lines for indices {n}..{n + len(extra) - 1} in order, {n_ok0} verified lines as the clean FS run, a SUMMARY line, exit 1, no Traceback",
           f"K13 {st.get('K13')}, V2 lines {len(got)} (match: {got == want}), verified {len(verified_lines(bl))}, SUMMARY {summary_of(r) is not None}, exit {r.returncode}, Traceback {'Traceback' in r.stderr}", details)
    # i2b, i2c
    for name, doc, kind in (("i2b_document_is_an_object", {}, "object"), ("i2c_document_is_a_string", "x", "string")):
        d = f.copy_of(tmp, FS, name)
        (d / "signatures.json").write_text(json.dumps(doc), encoding="utf-8")
        r, st, bl = h.run(d)
        ns = h.notes(bl)
        got = [l for l in ns if l == v2_doc(kind)]
        ok = (len(got) == 1 and st.get("K13") == "FAIL" and not verified_lines(bl) and summary_of(r) is not None and r.returncode == 1
              and "Traceback" not in r.stderr)
        report(name, ok, f"K13 FAIL with '{v2_doc(kind)}', no verified line, a SUMMARY line, exit 1, no Traceback",
               f"K13 {st.get('K13')}, line {len(got)}, verified {len(verified_lines(bl))}, SUMMARY {summary_of(r) is not None}, exit {r.returncode}, Traceback {'Traceback' in r.stderr}",
               c.block_lines(bl, "K13") + h.committed_block(committed, d))
    # i2d
    d = f.copy_of(tmp, FS, "i2d_null_first")
    sigs = f.load_sigs(d)
    f.save_sigs(d, [None] + sigs)
    r, st, bl = h.run(d)
    ns = h.notes(bl)
    got = [l for l in ns if V2_TAIL in l]
    aud = [l for l in ns if l.startswith("audit.jsonl: signed by") and l.endswith("verified")]
    okl = [l for l in ns if OK_LINE in l and l.endswith("verified")]
    ok = (got == [v2_line(0, None)] and st.get("K13") == "FAIL" and len(aud) == 1 and len(okl) == 1 and len(verified_lines(bl)) == n_ok0
          and summary_of(r) is not None and r.returncode == 1 and "Traceback" not in r.stderr)
    report("i2d_null_before_the_auditor_entry", ok, f"K13 FAIL with the V2 line for index 0 (None), the auditor still verified, the '{OK_LINE}' line present, {n_ok0} verified lines, SUMMARY, exit 1, no Traceback",
           f"K13 {st.get('K13')}, V2 {got}, auditor verified {len(aud)}, ok lines {len(okl)}, verified {len(verified_lines(bl))}, exit {r.returncode}, Traceback {'Traceback' in r.stderr}",
           c.block_lines(bl, "K13"))


V2B_TAIL = "(role, file, sha256, line and signature are strings, signer an object): the entry is not checked"


def v2b_line(i, field, kind, want):
    return f"signatures[{i}]: field {field} is a JSON {kind}, not {want} {V2B_TAIL}"


def i2e(tmp, FS, committed):
    if FS is None:
        f.not_built("i2e_object_entries_with_wrong_field_shapes", "K13 FAIL by field name, SUMMARY present, exit 1, no Traceback")
        return
    r0, st0, bl0 = h.run(FS)
    n_ok0 = len(verified_lines(bl0))
    sigs0 = f.load_sigs(FS)
    i_aud = next(i for i, e in enumerate(sigs0) if e.get("role") == "auditor")
    i_wit = next(i for i, e in enumerate(sigs0) if e.get("role") == "witness")

    def case(name, mutate, want_line, lost):
        """mutate(sigs) edits the list in place and returns nothing; lost = how many verified lines the damaged entry costs."""
        d = f.copy_of(tmp, FS, name)
        sigs = f.load_sigs(d)
        mutate(sigs)
        f.save_sigs(d, sigs)
        r, st, bl = h.run(d)
        ns = h.notes(bl)
        got = [l for l in ns if V2B_TAIL in l]
        ok = (got == [want_line] and st.get("K13") == "FAIL" and len(verified_lines(bl)) == n_ok0 - lost and summary_of(r) is not None
              and r.returncode == 1 and "Traceback" not in r.stderr)
        details = c.block_lines(bl, "K13")
        if committed is not None:
            rc, _, _ = c.run_check(committed, d)
            details += [f"committed checker (exit {rc.returncode}): SUMMARY {summary_of(rc)!r}, Traceback: {'Traceback' in rc.stderr}, last stderr line: {(rc.stderr.strip().splitlines() or [''])[-1][:160]}"]
        report(name, ok, f"K13 FAIL with exactly '{want_line}', {n_ok0 - lost} verified lines, a SUMMARY line, exit 1, no Traceback",
               f"K13 {st.get('K13')}, V2b lines {got}, verified {len(verified_lines(bl))}, SUMMARY {summary_of(r) is not None}, exit {r.returncode}, Traceback {'Traceback' in r.stderr}", details)

    def set_field(i, k, v):
        def m(sigs):
            sigs[i][k] = v
        return m

    def add_entry(v):
        def m(sigs):
            e = json.loads(json.dumps(sigs[i_wit]))
            e["signer"] = v
            sigs.append(e)
        return m
    # a damaged AUDITOR entry costs two verified lines: its own, and the sources entry's (no auditor signature to match it: the right outcome)
    case("i2e_auditor_signer_a_string", set_field(i_aud, "signer", "just-a-name"), v2b_line(i_aud, "signer", "string", "an object"), 2)
    case("i2e_witness_signer_a_number", set_field(i_wit, "signer", 5), v2b_line(i_wit, "signer", "number", "an object"), 1)
    case("i2e_extra_entry_signer_a_list", add_entry(["n"]), v2b_line(len(sigs0), "signer", "array", "an object"), 0)
    case("i2e_auditor_signature_a_list", set_field(i_aud, "signature", ["audit.jsonl.sig"]), v2b_line(i_aud, "signature", "array", "a string"), 2)
    case("i2e_witness_role_a_number", set_field(i_wit, "role", 7), v2b_line(i_wit, "role", "number", "a string"), 1)
    case("i2e_witness_sha256_null", set_field(i_wit, "sha256", None), v2b_line(i_wit, "sha256", "null", "a string"), 1)


V2C_TAIL = "(a signer's name, key_id and kind are strings): the entry is not checked"
JUNK = "junk"


def v2c_line(i, field, kind):
    return f"signatures[{i}]: field signer.{field} is a JSON {kind}, not a string {V2C_TAIL}"


def i2f(tmp, FS, committed):
    if FS is None:
        f.not_built("i2f_signer_inner_fields_with_wrong_shapes", "K13 FAIL by field signer.<f>, SUMMARY present, exit 1, no Traceback")
        return
    r0, st0, bl0 = h.run(FS)
    n_ok0 = len(verified_lines(bl0))
    sigs0 = f.load_sigs(FS)
    i_aud = next(i for i, e in enumerate(sigs0) if e.get("role") == "auditor")
    i_wit = next(i for i, e in enumerate(sigs0) if e.get("role") == "witness")

    def case(name, mutate, want_line, lost):
        d = f.copy_of(tmp, FS, name)
        sigs = f.load_sigs(d)
        mutate(sigs)
        f.save_sigs(d, sigs)
        r, st, bl = h.run(d)
        ns = h.notes(bl)
        got = [l for l in ns if V2C_TAIL in l]
        v2b = [l for l in ns if V2B_TAIL in l]
        ok = (got == [want_line] and not v2b and st.get("K13") == "FAIL" and len(verified_lines(bl)) == n_ok0 - lost and summary_of(r) is not None
              and r.returncode == 1 and "Traceback" not in r.stderr)
        details = c.block_lines(bl, "K13")
        if committed is not None:
            rc, _, _ = c.run_check(committed, d)
            details += [f"committed checker (exit {rc.returncode}): SUMMARY {summary_of(rc)!r}, Traceback: {'Traceback' in rc.stderr}, last stderr line: {(rc.stderr.strip().splitlines() or [''])[-1][:160]}"]
        report(name, ok, f"K13 FAIL with exactly '{want_line}', no V2b line, {n_ok0 - lost} verified lines, a SUMMARY line, exit 1, no Traceback",
               f"K13 {st.get('K13')}, V2c lines {got}, V2b lines {len(v2b)}, verified {len(verified_lines(bl))}, SUMMARY {summary_of(r) is not None}, exit {r.returncode}, Traceback {'Traceback' in r.stderr}", details)

    def set_signer_field(i, k, v):
        def m_(sigs):
            sigs[i]["signer"][k] = v
        return m_

    def add_entry_with_signer(signer):
        def m_(sigs):
            e = json.loads(json.dumps(sigs[i_wit]))
            e["signer"] = signer
            sigs.append(e)
        return m_
    case("i2f_witness_signer_name_a_number", set_signer_field(i_wit, "name", 5), v2c_line(i_wit, "name", "number"), 1)
    case("i2f_auditor_signer_name_a_list", set_signer_field(i_aud, "name", ["n"]), v2c_line(i_aud, "name", "array"), 2)
    case("i2f_extra_entry_signer_name_an_object", add_entry_with_signer({"name": {"k": 1}, "key_id": "SHA256:x", "kind": "ssh-ed25519"}), v2c_line(len(sigs0), "name", "object"), 0)
    case("i2f_witness_signer_key_id_a_list", set_signer_field(i_wit, "key_id", ["k"]), v2c_line(i_wit, "key_id", "array"), 1)
    case("i2f_auditor_signer_kind_a_number", set_signer_field(i_aud, "kind", 7), v2c_line(i_aud, "kind", "number"), 2)
    case("i2f_witness_signer_name_null", set_signer_field(i_wit, "name", None), v2c_line(i_wit, "name", "null"), 1)
    # an extra signer key of odd type is not a shape fault: no line, the clean run's verified count and exit
    d = f.copy_of(tmp, FS, "i2f_extra_signer_key_tolerated")
    sigs = f.load_sigs(d)
    sigs[i_wit]["signer"]["principal"] = ["x"]
    f.save_sigs(d, sigs)
    r, st, bl = h.run(d)
    ns = h.notes(bl)
    odd = [l for l in ns if V2C_TAIL in l or V2B_TAIL in l]
    ok = not odd and len(verified_lines(bl)) == n_ok0 and r.returncode == r0.returncode and st.get("K13") == st0.get("K13") and "Traceback" not in r.stderr
    report("i2f_extra_signer_key_tolerated", ok, f"no V2b or V2c line, {n_ok0} verified lines, K13 {st0.get('K13')}, exit {r0.returncode}, no Traceback",
           f"odd lines {odd}, verified {len(verified_lines(bl))}, K13 {st.get('K13')}, exit {r.returncode}, Traceback {'Traceback' in r.stderr}", c.block_lines(bl, "K13"))


def i4(tmp, fpre, FB, FS, committed_dir, committed_sign):
    if FS is None:
        f.not_built("i4_tools_refuse_wrong_shaped_signatures", "sign.py and add_witness.py exit 1 by name, nothing written")
        return
    sigs0 = f.load_sigs(FS)
    i_aud = next(i for i, e in enumerate(sigs0) if e.get("role") == "auditor")
    i_wit = next(i for i, e in enumerate(sigs0) if e.get("role") == "witness")
    sources_args = ["--role", "sources", "--key", str(m.KEYS["auditor"]), "--identity", p.AUDITOR]
    auditor_args = ["--role", "auditor", "--file", "audit.jsonl", "--key", str(m.KEYS["auditor"]), "--identity", p.AUDITOR]

    def sign_case(name, mutate, args, phrase):
        d = f.copy_of(tmp, FS, name)
        sigs = f.load_sigs(d)
        mutate(sigs)
        f.save_sigs(d, sigs)
        before = c.tree_hashes(d)
        r = h.run_sign(d, args)
        after = c.tree_hashes(d)
        unchanged = before == after
        changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
        ok = r.returncode == 1 and phrase in r.stderr and "nothing written" in r.stderr and "Traceback" not in r.stderr and unchanged
        details = [f"stderr: {l}" for l in r.stderr.strip().splitlines()[-3:]] + ([] if unchanged else ["changed: " + ", ".join(changed)])
        if committed_sign is not None:
            dc = f.copy_of(tmp, FS, name + "_committed")
            sigs = f.load_sigs(dc)
            mutate(sigs)
            f.save_sigs(dc, sigs)
            b2 = c.tree_hashes(dc)
            rc = h.run_sign(dc, args, committed_sign)
            a2 = c.tree_hashes(dc)
            details += [f"committed sign.py: exit {rc.returncode}, Traceback: {'Traceback' in rc.stderr}, tree changed: {b2 != a2}, last stderr line: {(rc.stderr.strip().splitlines() or [''])[-1][:160]}"]
        report(name, ok, f"sign.py exit 1, stderr with '{phrase}' and 'nothing written', no Traceback, every file unchanged by hash",
               f"exit {r.returncode}, phrase: {phrase in r.stderr}, nothing written: {'nothing written' in r.stderr}, Traceback: {'Traceback' in r.stderr}, unchanged: {unchanged}", details)

    def append_junk(sigs):
        sigs.append(JUNK)

    def auditor_signer_string(sigs):
        sigs[i_aud]["signer"] = "just-a-name"

    def witness_name_number(sigs):
        sigs[i_wit]["signer"]["name"] = 5
    sign_case("i4a_sign_refuses_a_non_object_entry", append_junk, sources_args, f"signatures[{len(sigs0)}]: entry {JUNK!r} is not an object")
    sign_case("i4b_sign_refuses_auditor_signer_a_string", auditor_signer_string, auditor_args, v2b_line(i_aud, "signer", "string", "an object"))
    sign_case("i4c_sign_refuses_witness_signer_name_a_number", witness_name_number, sources_args, v2c_line(i_wit, "name", "number"))

    ans = tmp / "i4_answer"
    c.make_answer(FB, ans)
    psigs = f.load_sigs(fpre)
    p_aud = next(i for i, e in enumerate(psigs) if e.get("role") == "auditor")

    def aw_case(name, mutate, phrase):
        parent = f.copy_of(tmp, fpre, name)
        sigs = f.load_sigs(parent)
        mutate(sigs)
        f.save_sigs(parent, sigs)
        before = c.tree_hashes(parent)
        r = f.run_add_witness_with(HERE / "add_witness.py", parent, ans)
        unchanged = before == c.tree_hashes(parent)
        ok = r.returncode == 1 and "refused, nothing written" in r.stderr and phrase in r.stderr and "Traceback" not in r.stderr and unchanged
        details = [f"stderr: {l}" for l in r.stderr.strip().splitlines()[-3:]]
        if committed_dir is not None:
            pc = f.copy_of(tmp, fpre, name + "_committed")
            sigs = f.load_sigs(pc)
            mutate(sigs)
            f.save_sigs(pc, sigs)
            b2 = c.tree_hashes(pc)
            rc = f.run_add_witness_with(committed_dir / "add_witness.py", pc, ans)
            a2 = c.tree_hashes(pc)
            details += [f"committed add_witness.py: exit {rc.returncode}, Traceback: {'Traceback' in rc.stderr}, tree changed: {b2 != a2}, last stderr line: {(rc.stderr.strip().splitlines() or [''])[-1][:160]}"]
        report(name, ok, f"add_witness.py exit 1, 'refused, nothing written' with '{phrase}', no Traceback, the parent unchanged by hash",
               f"exit {r.returncode}, refused: {'refused, nothing written' in r.stderr}, phrase: {phrase in r.stderr}, Traceback: {'Traceback' in r.stderr}, unchanged: {unchanged}", details)

    def parent_auditor_signer_string(sigs):
        sigs[p_aud]["signer"] = "just-a-name"
    aw_case("i4d_add_witness_refuses_parent_auditor_signer_a_string", parent_auditor_signer_string, "the snapshot's " + v2b_line(p_aud, "signer", "string", "an object"))
    aw_case("i4e_add_witness_refuses_parent_non_object_entry", append_junk, f"the snapshot's signatures[{len(psigs)}]: entry {JUNK!r} is not an object")


PATTERN_WHY = "(ssh-keygen reads *, ? and ! in a principal as a pattern; a record names its principals plainly)"
A3_PHRASE = "is not the key allowed_signers lists for"


def pattern_line(p):
    return f"allowed_signers: principal '{p}' is a pattern {PATTERN_WHY}"


def i2g(tmp, FS, forger, committed):
    if FS is None:
        f.not_built("i2g_star_principal_forger_resign", "K13 FAIL, the pattern line and the A3 line, no verified line for the file")
        return
    r0, st0, bl0 = h.run(FS)
    n_ok0 = len(verified_lines(bl0))
    sigs0 = f.load_sigs(FS)
    i_wit = next(i for i, e in enumerate(sigs0) if e.get("role") == "witness")
    wf, line = sigs0[i_wit]["file"], sigs0[i_wit]["line"]
    d = f.copy_of(tmp, FS, "i2g_star_principal_forger_resign")
    h.append_allowed(d, h.allowed_line("*", forger))
    (d / (wf + ".sig")).write_bytes(h.own_sign_line(line, forger))
    r, st, bl = h.run(d)
    ns = h.notes(bl)
    a3 = [l for l in ns if l.startswith(wf + ":") and A3_PHRASE in l]
    pat = [l for l in ns if l == pattern_line("*")]
    ver = [l for l in verified_lines(bl) if l.startswith(wf + ":")]
    ok = (len(a3) == 1 and len(pat) == 1 and not ver and st.get("K13") == "FAIL" and len(verified_lines(bl)) == n_ok0 - 1 and r.returncode == 1
          and "Traceback" not in r.stderr)
    report("i2g_star_principal_forger_resign", ok, f"K13 FAIL, one A3 line for {wf}, the pattern line for '*', no verified line for {wf}, {n_ok0 - 1} verified lines, exit 1, no Traceback",
           f"K13 {st.get('K13')}, A3 lines {len(a3)}, pattern lines {len(pat)}, verified lines for the file {len(ver)}, verified {len(verified_lines(bl))}, exit {r.returncode}, Traceback {'Traceback' in r.stderr}",
           c.block_lines(bl, "K13") + h.committed_block(committed, d))
    d2 = f.copy_of(tmp, FS, "i2g_question_mark_principal_alone")
    h.append_allowed(d2, h.allowed_line("a?b", forger))
    r, st, bl = h.run(d2)
    ns = h.notes(bl)
    pat = [l for l in ns if l == pattern_line("a?b")]
    ok = len(pat) == 1 and st.get("K13") == "FAIL" and len(verified_lines(bl)) == n_ok0 and r.returncode == 1 and "Traceback" not in r.stderr
    report("i2g_question_mark_principal_alone", ok, f"K13 FAIL with the pattern line for 'a?b', {n_ok0} verified lines (nothing re-signed), exit 1, no Traceback",
           f"K13 {st.get('K13')}, pattern lines {len(pat)}, verified {len(verified_lines(bl))}, exit {r.returncode}, Traceback {'Traceback' in r.stderr}",
           c.block_lines(bl, "K13") + h.committed_block(committed, d2))


def i4f(tmp, fpre, FB, FS, committed_dir, committed_sign):
    if FS is None:
        f.not_built("i4f_tools_unreadable_and_answer_shapes", "sign.py and add_witness.py exit 1 by name, nothing written")
        return
    sources_args = ["--role", "sources", "--key", str(m.KEYS["auditor"]), "--identity", p.AUDITOR]

    def sign_case(name, raw, phrases):
        d = f.copy_of(tmp, FS, name)
        (d / "signatures.json").write_bytes(raw)
        before = c.tree_hashes(d)
        r = h.run_sign(d, sources_args)
        unchanged = before == c.tree_hashes(d)
        ok = r.returncode == 1 and all(ph in r.stderr for ph in phrases) and "Traceback" not in r.stderr and unchanged
        details = [f"stderr: {l}" for l in r.stderr.strip().splitlines()[-3:]]
        if committed_sign is not None:
            dc = f.copy_of(tmp, FS, name + "_committed")
            (dc / "signatures.json").write_bytes(raw)
            b2 = c.tree_hashes(dc)
            rc = h.run_sign(dc, sources_args, committed_sign)
            details += [f"committed sign.py: exit {rc.returncode}, Traceback: {'Traceback' in rc.stderr}, tree changed: {b2 != c.tree_hashes(dc)}, last stderr line: {(rc.stderr.strip().splitlines() or [''])[-1][:160]}"]
        report(name, ok, f"sign.py exit 1, stderr with {phrases}, no Traceback, every file unchanged by hash",
               f"exit {r.returncode}, phrases: {[ph in r.stderr for ph in phrases]}, Traceback: {'Traceback' in r.stderr}, unchanged: {unchanged}", details)
    sign_case("i4f_sign_refuses_invalid_json", b"not json{", ["signatures.json is unreadable", "nothing written"])
    sign_case("i4f_sign_refuses_non_utf8", b"\xff\xfe[]", ["signatures.json is unreadable", "nothing written"])
    sign_case("i4f_sign_non_list_message_names_the_file", b"{}", ["is not a list of signature entries", "fix signatures.json before signing, nothing written"])

    ans = tmp / "i4f_answer"
    c.make_answer(FB, ans)
    se_p = ans / "signatures-entry.json"
    se = json.loads(se_p.read_text(encoding="utf-8"))
    se["signer"]["name"] = 5
    se_p.write_text(json.dumps(se, indent=1) + "\n", encoding="utf-8")
    phrase = "the answer's " + v2c_line(0, "name", "number")
    parent = f.copy_of(tmp, fpre, "i4f_parent_answer_signer_name_number")
    before = c.tree_hashes(parent)
    r = f.run_add_witness_with(HERE / "add_witness.py", parent, ans)
    unchanged = before == c.tree_hashes(parent)
    ok = r.returncode == 1 and "refused, nothing written" in r.stderr and phrase in r.stderr and "Traceback" not in r.stderr and unchanged
    details = [f"stderr: {l}" for l in r.stderr.strip().splitlines()[-3:]]
    if committed_dir is not None:
        pc = f.copy_of(tmp, fpre, "i4f_parent_committed")
        b2 = c.tree_hashes(pc)
        rc = f.run_add_witness_with(committed_dir / "add_witness.py", pc, ans)
        a2 = c.tree_hashes(pc)
        changed = sorted(k for k in set(b2) | set(a2) if b2.get(k) != a2.get(k))
        details += [f"committed add_witness.py: exit {rc.returncode}, Traceback: {'Traceback' in rc.stderr}, tree changed: {b2 != a2} ({len(changed)} file(s)), last stderr line: {(rc.stderr.strip().splitlines() or [''])[-1][:160]}"]
    report("i4f_add_witness_refuses_answer_signer_name_number", ok, f"add_witness.py exit 1, 'refused, nothing written' with '{phrase}', no Traceback, the parent unchanged by hash",
           f"exit {r.returncode}, refused: {'refused, nothing written' in r.stderr}, phrase: {phrase in r.stderr}, Traceback: {'Traceback' in r.stderr}, unchanged: {unchanged}", details)


def i4g(tmp, fpre, FB, FS, committed_dir, committed_sign):
    if FS is None:
        f.not_built("i4g_tools_refuse_manifest_shapes", "sign.py and add_witness.py exit 1 by name, nothing written")
        return
    sources_args = ["--role", "sources", "--key", str(m.KEYS["auditor"]), "--identity", p.AUDITOR]
    auditor_args = ["--role", "auditor", "--file", "audit.jsonl", "--key", str(m.KEYS["auditor"]), "--identity", p.AUDITOR]
    manifest_args = ["--role", "manifest", "--key", str(m.KEYS["adder"]), "--identity", m.ADDER]

    def sign_case(name, mutate, args, phrases):
        def prep(d):
            mp = d / "manifest.json"
            mp.write_text(json.dumps(mutate(json.loads(mp.read_text(encoding="utf-8"))), indent=1) + "\n", encoding="utf-8")
        d = f.copy_of(tmp, FS, name)
        prep(d)
        before = c.tree_hashes(d)
        r = h.run_sign(d, args)
        after = c.tree_hashes(d)
        unchanged = before == after
        changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
        ok = r.returncode == 1 and all(ph in r.stderr for ph in phrases) and "Traceback" not in r.stderr and unchanged
        details = [f"stderr: {l}" for l in r.stderr.strip().splitlines()[-2:]] + ([] if unchanged else ["changed: " + ", ".join(changed)])
        if committed_sign is not None:
            dc = f.copy_of(tmp, FS, name + "_committed")
            prep(dc)
            b2 = c.tree_hashes(dc)
            rc = h.run_sign(dc, args, committed_sign)
            a2 = c.tree_hashes(dc)
            ch2 = sorted(k for k in set(b2) | set(a2) if b2.get(k) != a2.get(k))
            details += [f"committed sign.py: exit {rc.returncode}, Traceback: {'Traceback' in rc.stderr}, changed: {ch2}, last stderr line: {(rc.stderr.strip().splitlines() or [''])[-1][:160]}"]
        report(name, ok, f"sign.py exit 1, stderr with {phrases}, no Traceback, every file unchanged by hash",
               f"exit {r.returncode}, phrases: {[ph in r.stderr for ph in phrases]}, Traceback: {'Traceback' in r.stderr}, unchanged: {unchanged}", details)

    def grading_list(M):
        M["grading"] = []
        return M

    def witness_string(M):
        M["grading"]["witnesses"] = ["a string"] + M["grading"]["witnesses"]
        return M
    nw = "nothing written"
    sign_case("i4g_sign_sources_manifest_a_list", lambda M: [], sources_args, ["manifest.json: a JSON array is not an object", nw])
    sign_case("i4g_sign_auditor_manifest_a_string", lambda M: "x", auditor_args, ["manifest.json: a JSON string is not an object", nw])
    sign_case("i4g_sign_manifest_role_manifest_null", lambda M: None, manifest_args, ["manifest.json: a JSON null is not an object", nw])
    sign_case("i4g_sign_auditor_grading_a_list", grading_list, auditor_args, ["manifest.json: grading is a JSON array, not an object", nw])
    sign_case("i4g_sign_auditor_witness_a_string", witness_string, auditor_args, ["manifest.json: grading.witnesses[0] is a JSON string, not an object", nw])

    ans = tmp / "i4g_answer"
    c.make_answer(FB, ans)

    def aw_case(name, prep_parent, answer, phrases):
        parent = f.copy_of(tmp, fpre, name)
        prep_parent(parent)
        before = c.tree_hashes(parent)
        r = f.run_add_witness_with(HERE / "add_witness.py", parent, answer)
        unchanged = before == c.tree_hashes(parent)
        ok = r.returncode == 1 and all(ph in r.stderr for ph in phrases) and "Traceback" not in r.stderr and unchanged
        details = [f"stderr: {l}" for l in r.stderr.strip().splitlines()[-2:]]
        if committed_dir is not None:
            pc = f.copy_of(tmp, fpre, name + "_committed")
            prep_parent(pc)
            b2 = c.tree_hashes(pc)
            rc = f.run_add_witness_with(committed_dir / "add_witness.py", pc, answer)
            details += [f"committed add_witness.py: exit {rc.returncode}, Traceback: {'Traceback' in rc.stderr}, tree changed: {b2 != c.tree_hashes(pc)}, last stderr line: {(rc.stderr.strip().splitlines() or [''])[-1][:160]}"]
        report(name, ok, f"add_witness.py exit 1, stderr with {phrases}, no Traceback, the parent unchanged by hash",
               f"exit {r.returncode}, phrases: {[ph in r.stderr for ph in phrases]}, Traceback: {'Traceback' in r.stderr}, unchanged: {unchanged}", details)

    def parent_manifest_list(d):
        (d / "manifest.json").write_text("[]\n", encoding="utf-8")
    aw_case("i4g_add_witness_parent_manifest_a_list", parent_manifest_list, ans, ["manifest.json is a JSON array, not an object"])
    ans2 = tmp / "i4g_answer_name_list"
    shutil.copytree(ans, ans2)
    me_p = ans2 / "manifest-entry.json"
    me = json.loads(me_p.read_text(encoding="utf-8"))
    me["name"] = ["x"]
    me_p.write_text(json.dumps(me, indent=1) + "\n", encoding="utf-8")
    aw_case("i4g_add_witness_answer_entry_name_a_list", lambda d: None, ans2,
            ["refused, nothing written", "the answer's manifest entry [0]: field name is a JSON array, not a string"])


SHAPE_HEAD = "manifest shape:"


def shape_line(path, kind, want):
    return f"manifest.json: {path} is a JSON {kind}, not {want}"


def i2h(tmp, FB, committed):
    def setg(k, v):
        def fn(M):
            M["grading"][k] = v
            return M
        return fn

    def seta(k, v):
        def fn(M):
            M["grading"]["auditor"][k] = v
            return M
        return fn

    def top(k, v):
        def fn(M):
            M[k] = v
            return M
        return fn

    def witness0(fn_):
        def fn(M):
            fn_(M["grading"]["witnesses"])
            return M
        return fn

    def pages0(v):
        def fn(M):
            M["pages"] = [v] + M["pages"]
            return M
        return fn

    def page0_file(M):
        M["pages"][0]["file"] = 5
        return M

    def source0(M):
        M["sources"] = ["x"] + M["sources"]
        return M

    cases = [
        ("i2h_auditor_a_string", setg("auditor", "a"), [shape_line("grading.auditor", "string", "an object")]),
        ("i2h_auditor_a_list", setg("auditor", ["a"]), [shape_line("grading.auditor", "array", "an object")]),
        ("i2h_auditor_a_number", setg("auditor", 7), [shape_line("grading.auditor", "number", "an object")]),
        ("i2h_auditor_file_a_number", seta("file", 5), [shape_line("grading.auditor.file", "number", "a string")]),
        ("i2h_auditor_name_a_list", seta("name", ["n"]), [shape_line("grading.auditor.name", "array", "a string")]),
        ("i2h_grading_a_list", top("grading", []), [shape_line("grading", "array", "an object")]),
        ("i2h_grading_null", top("grading", None), [shape_line("grading", "null", "an object")]),
        ("i2h_document_a_list", lambda M: [], ["manifest.json: a JSON array is not an object"]),
        ("i2h_witnesses_an_object", setg("witnesses", {"x": 1}), [shape_line("grading.witnesses", "object", "a list")]),
        ("i2h_witness_entry_a_string", witness0(lambda W: W.insert(0, "x")), [shape_line("grading.witnesses[0]", "string", "an object")]),
        ("i2h_witness_entry_file_a_number", witness0(lambda W: W[0].__setitem__("file", 5)), [shape_line("grading.witnesses[0].file", "number", "a string")]),
        ("i2h_pages_entry_a_string", pages0("x"), [shape_line("pages[0]", "string", "an object")]),
        ("i2h_pages_entry_file_a_number", page0_file, [shape_line("pages[0].file", "number", "a string")]),
        ("i2h_sources_entry_a_string", source0, [shape_line("sources[0]", "string", "an object")]),
        ("i2h_sources_an_object", top("sources", {"a": 1}), [shape_line("sources", "object", "a list")]),
    ]
    for name, fn, want in cases:
        d = f.copy_of(tmp, FB, name)
        mp = d / "manifest.json"
        mp.write_text(json.dumps(fn(json.loads(mp.read_text(encoding="utf-8"))), indent=1) + "\n", encoding="utf-8")
        r, st, bl = h.run(d)
        got = h.notes(bl, "K1")
        head = SHAPE_HEAD in bl.get("K1", "")
        ok = st.get("K1") == "FAIL" and head and got == want and summary_of(r) is not None and r.returncode == 1 and "Traceback" not in r.stderr
        details = [f"K1 block: {l}" for l in bl.get("K1", "").splitlines()[:4]] + [f"stderr: {l}" for l in r.stderr.strip().splitlines()[-1:]]
        if committed is not None:
            rc, _, _ = c.run_check(committed, d)
            details += [f"committed checker (exit {rc.returncode}): SUMMARY {summary_of(rc)!r}, Traceback: {'Traceback' in rc.stderr}, last stderr line: {(rc.stderr.strip().splitlines() or [''])[-1][:160]}"]
        report(name, ok, f"K1 FAIL '{SHAPE_HEAD} …' with exactly {want}, a SUMMARY line, exit 1, no Traceback",
               f"K1 {st.get('K1')}, head {head}, lines {got}, SUMMARY {summary_of(r) is not None}, exit {r.returncode}, Traceback {'Traceback' in r.stderr}", details)
    for name, k in (("i2h_control_auditor_null", "auditor"), ("i2h_control_witnesses_null", "witnesses")):
        d = f.copy_of(tmp, FB, name)
        mp = d / "manifest.json"
        M = json.loads(mp.read_text(encoding="utf-8"))
        M["grading"][k] = None
        mp.write_text(json.dumps(M, indent=1) + "\n", encoding="utf-8")
        r, st, bl = h.run(d)
        ok = SHAPE_HEAD not in r.stdout and summary_of(r) is not None and "Traceback" not in r.stderr
        report(name, ok, f"grading.{k} null is treated as absent: no '{SHAPE_HEAD}' line, a SUMMARY line, no Traceback",
               f"shape line {SHAPE_HEAD in r.stdout}, SUMMARY {summary_of(r)!r}, Traceback {'Traceback' in r.stderr}")


K0_HEAD = "K0 FAIL: the checker stopped on a part of the folder it does not read ("


def i2i(tmp, FB, committed):
    def top(k, v):
        def fn(M):
            M[k] = v
            return M
        return fn

    def gset(k, v):
        def fn(M):
            M["grading"][k] = v
            return M
        return fn

    def src0(k, v):
        def fn(M):
            M["sources"][0][k] = v
            return M
        return fn

    def wscore(v):
        def fn(M):
            M["grading"]["witnesses"][0]["score"] = v
            return M
        return fn

    def run_case(name, fn):
        d = f.copy_of(tmp, FB, name)
        mp = d / "manifest.json"
        mp.write_text(json.dumps(fn(json.loads(mp.read_text(encoding="utf-8"))), indent=1) + "\n", encoding="utf-8")
        r, st, bl = h.run(d)
        details = [f"stdout: {l}" for l in r.stdout.splitlines()[:3]] + [f"stderr: {l}" for l in r.stderr.strip().splitlines()[-1:]]
        if committed is not None:
            rc, _, _ = c.run_check(committed, d)
            details += [f"committed checker (exit {rc.returncode}): SUMMARY {summary_of(rc)!r}, Traceback: {'Traceback' in rc.stderr}, last stderr line: {(rc.stderr.strip().splitlines() or [''])[-1][:160]}"]
        return r, st, bl, details

    cases = [
        ("i2i_format_a_list", top("format", ["claims-snapshot/0.6"]), shape_line("format", "array", "a string")),
        ("i2i_counts_a_list", top("counts", []), shape_line("counts", "array", "an object")),
        ("i2i_counts_a_string", top("counts", "c"), shape_line("counts", "string", "an object")),
        ("i2i_score_a_string", top("score", "s"), shape_line("score", "string", "an object")),
        ("i2i_taken_at_a_number", top("taken_at", 5), shape_line("taken_at", "number", "a string")),
        ("i2i_profile_a_list", gset("profile", ["agent-work"]), shape_line("grading.profile", "array", "a string")),
        ("i2i_profile_an_object", gset("profile", {"p": 1}), shape_line("grading.profile", "object", "a string")),
        ("i2i_sessions_a_string", gset("sessions", "s"), shape_line("grading.sessions", "string", "a list")),
        ("i2i_sessions_holding_a_number", gset("sessions", [5]), shape_line("grading.sessions[0]", "number", "an object")),
        ("i2i_gates_holding_a_number", gset("gates", [5]), shape_line("grading.gates[0]", "number", "an object")),
        ("i2i_source_path_a_list", src0("path", ["p"]), shape_line("sources[0].path", "array", "a string or null")),
        ("i2i_witness_score_a_string", wscore("s"), shape_line("grading.witnesses[0].score", "string", "an object")),
    ]
    for name, fn, want in cases:
        r, st, bl, details = run_case(name, fn)
        got = h.notes(bl, "K1")
        ok = st.get("K1") == "FAIL" and got == [want] and summary_of(r) is not None and r.returncode == 1 and "Traceback" not in r.stderr
        report(name, ok, f"K1 FAIL with exactly ['{want}'], a SUMMARY line, exit 1, no Traceback",
               f"K1 {st.get('K1')}, lines {got}, SUMMARY {summary_of(r) is not None}, exit {r.returncode}, Traceback {'Traceback' in r.stderr}", details)
    for name, fn in (("i2i_control_source_path_null", src0("path", None)), ("i2i_control_sessions_null", gset("sessions", None)),
                     ("i2i_control_gates_null", gset("gates", None)), ("i2i_control_witness_score_null", wscore(None))):
        r, st, bl, details = run_case(name, fn)
        ok = SHAPE_HEAD not in r.stdout and K0_HEAD not in r.stdout and summary_of(r) is not None and "Traceback" not in r.stderr
        report(name, ok, f"no '{SHAPE_HEAD}' and no K0 line, a SUMMARY line, no Traceback",
               f"shape {SHAPE_HEAD in r.stdout}, K0 {K0_HEAD in r.stdout}, SUMMARY {summary_of(r)!r}, Traceback {'Traceback' in r.stderr}", details)
    r, st, bl, details = run_case("i2i_safety_net_source_n_a_list", src0("n", ["x"]))
    k0 = [l for l in r.stdout.splitlines() if l.startswith(K0_HEAD)]
    ok = len(k0) == 1 and "TypeError at check.py:" in k0[0] and summary_of(r) is not None and r.returncode == 1 and "Traceback" not in r.stderr
    report("i2i_safety_net_source_n_a_list", ok, f"one '{K0_HEAD}TypeError at check.py:<line>…' line, a SUMMARY line, exit 1, no Traceback",
           f"K0 lines {k0}, SUMMARY {summary_of(r) is not None}, exit {r.returncode}, Traceback {'Traceback' in r.stderr}", details)


def i2j(tmp, FB, committed):
    def summaries(text):
        return [l for l in text.splitlines() if l.startswith("SUMMARY")]

    d = f.copy_of(tmp, FB, "i2j_check_json_a_directory")
    (d / "CHECK.json").mkdir()
    r = subprocess.run([sys.executable, "-I", str(HERE / "check.py"), str(d), "--json"], capture_output=True, text=True)
    sm = summaries(r.stdout)
    k0 = [l for l in r.stdout.splitlines() if l.startswith("K0 FAIL") and "CHECK.json could not be written" in l]
    leaked = str(d) in r.stdout or str(d.resolve()) in r.stdout or str(tmp) in r.stdout
    ok = len(sm) == 1 and sm[0].endswith("FAIL") and len(k0) == 1 and r.returncode == 1 and "Traceback" not in r.stderr and not leaked
    details = [f"SUMMARY lines: {sm}", f"K0: {k0}", f"absolute path in stdout: {leaked}"]
    if committed is not None:
        rc = subprocess.run([sys.executable, "-I", str(committed), str(d), "--json"], capture_output=True, text=True)
        details.append(f"committed checker: SUMMARY lines {summaries(rc.stdout)}, exit {rc.returncode}")
    report("i2j_check_json_unwritable_one_summary", ok, "exactly one SUMMARY ending FAIL, one K0 'CHECK.json could not be written' line, exit 1, no Traceback",
           f"SUMMARY lines {len(sm)}, last {sm[-1] if sm else None}, K0 {len(k0)}, exit {r.returncode}, Traceback {'Traceback' in r.stderr}", details)

    d = f.copy_of(tmp, FB, "i2j_json_honest")
    r = subprocess.run([sys.executable, "-I", str(HERE / "check.py"), str(d), "--json"], capture_output=True, text=True)
    sm = summaries(r.stdout)
    try:
        cj = json.loads((d / "CHECK.json").read_text(encoding="utf-8"))
    except Exception:
        cj = {}
    res = sm[0].rsplit(": ", 1)[-1] if sm else None
    ok = len(sm) == 1 and cj.get("result") in ("PASS", "WARN", "FAIL") and (res == "FAIL") == (cj.get("result") == "FAIL") and "CHECK.json written" in r.stdout
    report("i2j_json_honest_one_summary", ok, "one SUMMARY, CHECK.json written, its result agreeing with the SUMMARY",
           f"SUMMARY lines {len(sm)}, SUMMARY result {res}, CHECK.json result {cj.get('result')}, written line {'CHECK.json written' in r.stdout}")

    d = f.copy_of(tmp, FB, "i2j_k0_text_names_no_path")
    mp = d / "manifest.json"
    M = json.loads(mp.read_text(encoding="utf-8"))
    M["sources"][0]["n"] = ["x"]
    mp.write_text(json.dumps(M, indent=1) + "\n", encoding="utf-8")
    r = subprocess.run([sys.executable, "-I", str(HERE / "check.py"), str(d)], capture_output=True, text=True)
    k0 = [l for l in r.stdout.splitlines() if l.startswith("K0 FAIL")]
    leaked = str(d) in r.stdout or str(d.resolve()) in r.stdout or str(tmp) in r.stdout
    ok = len(k0) == 1 and not leaked and len(summaries(r.stdout)) == 1
    report("i2j_k0_text_names_no_absolute_path", ok, "one K0 line, no absolute path of the folder or its parent in stdout, one SUMMARY",
           f"K0 {len(k0)}, path in stdout {leaked}, SUMMARY lines {len(summaries(r.stdout))}", k0)


def i2k(tmp, FB, FS, committed):
    """V2i (the nineteenth re-gate's U, J05, J03, J04, 13 Nov 2026 14:3xZ)."""
    import os
    import re as re_

    def summaries(text):
        return [l for l in text.splitlines() if l.startswith("SUMMARY")]

    def run(d, extra=(), exe=None, timeout=30):
        try:
            return subprocess.run([sys.executable, "-I", str(exe or (HERE / "check.py")), str(d), *extra], capture_output=True, text=True,
                                  errors="surrogateescape", timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def check_json(d):
        p_ = d / "CHECK.json"
        if p_.is_symlink() or not p_.is_file():
            return None
        try:
            return json.loads(p_.read_text(encoding="utf-8"))
        except Exception:
            return "NOT JSON"

    def committed_note(d, extra):
        if committed is None:
            return []
        rc = run(d, extra, committed)
        if rc is None:
            return ["committed checker: TIMEOUT (no output)"]
        return [f"committed checker (exit {rc.returncode}): SUMMARY lines {len(summaries(rc.stdout))}, Traceback {'Traceback' in rc.stderr}, "
                f"last stderr line {(rc.stderr.strip().splitlines() or [''])[-1][:140]!r}, CHECK.json {str(check_json(d))[:60]}"]

    def one_summary_ok(r, d, extra):
        sm = summaries(r.stdout)
        consistent = len(sm) == 1 and (r.returncode == 1) == sm[0].endswith("FAIL")
        ok = consistent and "Traceback" not in r.stderr and "stopped after the report was printed" not in r.stderr
        cj = None
        if extra:
            cj = check_json(d)
            ok = ok and isinstance(cj, dict) and (cj.get("result") == "FAIL") == sm[0].endswith("FAIL") and "CHECK.json written" in r.stdout
        return ok, sm, cj

    # U: a lone surrogate (JSON \ud800) that reaches a report line
    SUR = "\\" + "ud800"

    def man_raw(sub):
        def e(d):
            raw = (d / "manifest.json").read_text(encoding="utf-8")
            new = sub(raw)
            assert new != raw, "the edit did not apply"
            (d / "manifest.json").write_text(new, encoding="utf-8")
        return e

    def audit_text(d):
        lines = (d / "audit.jsonl").read_text(encoding="utf-8").split("\n")
        r0 = json.loads(lines[0])
        lines[0] = json.dumps(dict(r0, text="PLACEHOLDER-SURR")).replace("PLACEHOLDER-SURR", SUR)
        (d / "audit.jsonl").write_text("\n".join(lines), encoding="utf-8")
        M = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
        M["grading"]["auditor"]["sha256"] = check.sha256(d / "audit.jsonl")
        (d / "manifest.json").write_text(json.dumps(M, indent=1) + "\n", encoding="utf-8")

    u_cases = (
        ("i2k_audit_text_surrogate", FS, audit_text),
        ("i2k_page_file_surrogate", FB, man_raw(lambda raw: raw.replace('"file": "page.txt"', '"file": "page' + SUR + '.txt"', 1))),
        ("i2k_source_path_surrogate", FB, man_raw(lambda raw: re_.sub(r'"path": "([^"\\]*)"', lambda m_: '"path": "' + m_.group(1) + SUR + '"', raw, count=1))),
        ("i2k_format_surrogate", FB, man_raw(lambda raw: raw.replace('"claims-snapshot/0.6"', '"claims-snapshot/0.6' + SUR + '"', 1))),
        ("i2k_title_surrogate", FB, man_raw(lambda raw: re_.sub(r'"title": "[^"]*"', '"title": "t' + "\\\\" + 'ud800"', raw, count=1))),
    )
    for name, base, edit in u_cases:
        for extra in ((), ("--json",)):
            d = f.copy_of(tmp, base, name + ("_json" if extra else ""))
            edit(d)
            r = run(d, extra)
            ok, sm, cj = one_summary_ok(r, d, extra)
            report(name + ("_json" if extra else ""), ok,
                   "exactly one SUMMARY, exit 1 iff it ends FAIL, no Traceback, no 'stopped after the report' line" + ("; CHECK.json written, valid JSON, its result agreeing" if extra else ""),
                   f"SUMMARY lines {len(sm)}, exit {r.returncode}, Traceback {'Traceback' in r.stderr}, net line {'stopped after the report' in r.stderr}" + (f", CHECK.json {str(cj)[:40] if not isinstance(cj, dict) else cj.get('result')}" if extra else ""),
                   [l for l in r.stdout.splitlines() if "ud800" in l][:3] + committed_note(d, extra))

    # J05: every early exit with --json rewrites a stale CHECK.json that said PASS
    def setm(fn):
        def e(d):
            M = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
            fn(M)
            (d / "manifest.json").write_text(json.dumps(M, indent=1) + "\n", encoding="utf-8")
        return e

    def unreadable(d):
        (d / "manifest.json").write_text("{not json", encoding="utf-8")

    j_cases = (
        ("i2k_stale_check_json_k1_shape", setm(lambda M: M.__setitem__("format", ["claims-snapshot/0.6"]))),
        ("i2k_stale_check_json_k1_unreadable", unreadable),
        ("i2k_stale_check_json_k1_fields", setm(lambda M: M.pop("counts"))),
        ("i2k_stale_check_json_k0_net", setm(lambda M: M["sources"][0].__setitem__("n", ["x"]))),
    )
    for name, edit in j_cases:
        d = f.copy_of(tmp, FB, name)
        edit(d)
        (d / "CHECK.json").write_text(json.dumps({"result": "PASS", "note": "stale"}), encoding="utf-8")
        r = run(d, ("--json",))
        ok, sm, cj = one_summary_ok(r, d, ("--json",))
        ok = ok and sm[0].endswith("FAIL") and isinstance(cj, dict) and cj.get("result") == "FAIL" and cj.get("note") is None
        report(name, ok, "one SUMMARY ending FAIL, exit 1, CHECK.json REWRITTEN with result FAIL (the stale PASS gone), 'CHECK.json written (FAIL)'",
               f"SUMMARY {sm[-1] if sm else None}, exit {r.returncode}, CHECK.json {cj if not isinstance(cj, dict) else (cj.get('result'), cj.get('note'))}",
               committed_note(d, ("--json",)) if committed is not None else [])

    # J03: CHECK.json a symlink to a file outside the folder: refused, the outside file unchanged
    d = f.copy_of(tmp, FB, "i2k_check_json_symlink_out")
    outside = tmp / "i2k_outside_victim.txt"
    outside.write_text("victim\n", encoding="utf-8")
    (d / "CHECK.json").symlink_to(outside)
    r = run(d, ("--json",))
    sm = summaries(r.stdout)
    k0 = [l for l in r.stdout.splitlines() if l.startswith("K0 FAIL") and "CHECK.json" in l]
    ok = (outside.read_text(encoding="utf-8") == "victim\n" and len(sm) == 1 and sm[0].endswith("FAIL") and len(k0) == 1 and r.returncode == 1
          and "Traceback" not in r.stderr and (d / "CHECK.json").is_symlink())
    note = []
    if committed is not None:
        outside.write_text("victim\n", encoding="utf-8")
        rc = run(d, ("--json",), committed)
        note = [f"committed checker: the outside file {'UNCHANGED' if outside.read_text(encoding='utf-8') == 'victim' + chr(10) else 'OVERWRITTEN'}, exit {rc.returncode}"]
    report("i2k_check_json_symlink_out", ok, "the outside file unchanged, one K0 FAIL line naming CHECK.json, one SUMMARY ending FAIL, exit 1, the link left as it was",
           f"outside unchanged {outside.read_text(encoding='utf-8') == 'victim' + chr(10) if committed is None else '(see committed)'}, K0 {k0[:1]}, SUMMARY {sm[-1] if sm else None}, exit {r.returncode}", note)

    # J04: CHECK.json a named pipe: no hang, refused
    d = f.copy_of(tmp, FB, "i2k_check_json_fifo")
    os.mkfifo(d / "CHECK.json")
    r = run(d, ("--json",), timeout=20)
    if r is None:
        report("i2k_check_json_fifo", False, "returns within 20 s, one K0 FAIL naming CHECK.json, one SUMMARY ending FAIL, exit 1", "TIMEOUT: blocked on the open")
    else:
        sm = summaries(r.stdout)
        k0 = [l for l in r.stdout.splitlines() if l.startswith("K0 FAIL") and "CHECK.json" in l]
        ok = len(sm) == 1 and sm[0].endswith("FAIL") and len(k0) == 1 and r.returncode == 1 and "Traceback" not in r.stderr
        report("i2k_check_json_fifo", ok, "returns within 20 s, one K0 FAIL naming CHECK.json, one SUMMARY ending FAIL, exit 1",
               f"K0 {k0[:1]}, SUMMARY {sm[-1] if sm else None}, exit {r.returncode}")

    # J01 control: CHECK.json mode 444 in a writable folder stays a FAIL (an atomic replace must not slip past a read-only file)
    d = f.copy_of(tmp, FB, "i2k_check_json_readonly")
    (d / "CHECK.json").write_text(json.dumps({"result": "PASS", "note": "stale"}), encoding="utf-8")
    os.chmod(d / "CHECK.json", 0o444)
    r = run(d, ("--json",))
    sm = summaries(r.stdout)
    k0 = [l for l in r.stdout.splitlines() if l.startswith("K0 FAIL") and "CHECK.json could not be written" in l]
    ok = len(sm) == 1 and sm[0].endswith("FAIL") and len(k0) == 1 and r.returncode == 1 and json.loads((d / "CHECK.json").read_text(encoding="utf-8")).get("note") == "stale"
    report("i2k_check_json_readonly", ok, "one K0 'CHECK.json could not be written' line, one SUMMARY ending FAIL, exit 1, the read-only file unchanged",
           f"K0 {len(k0)}, SUMMARY {sm[-1] if sm else None}, exit {r.returncode}")
    os.chmod(d / "CHECK.json", 0o644)

    # no stray temporary file is left in an honest folder after --json
    d = f.copy_of(tmp, FB, "i2k_json_honest_no_temp")
    before = {p_.name for p_ in d.iterdir()}
    r = run(d, ("--json",))
    after = {p_.name for p_ in d.iterdir()}
    ok = after - before == {"CHECK.json"} and check_json(d) not in (None, "NOT JSON")
    report("i2k_json_honest_no_temp_left", ok, "after an honest --json run the folder gained CHECK.json and nothing else",
           f"new names {sorted(after - before)}")


def i4h(tmp, fpre, FS, committed_dir):
    if FS is None:
        f.not_built("i4h_presence_not_truthiness", "sign.py and add_witness.py refuse by name, nothing written")
        return
    auditor_args = ["--role", "auditor", "--file", "audit.jsonl", "--key", str(m.KEYS["auditor"]), "--identity", p.AUDITOR]
    nw = "nothing written"

    def sign_case(name, mutate, phrases):
        d = f.copy_of(tmp, FS, name)
        mp = d / "manifest.json"
        mp.write_text(json.dumps(mutate(json.loads(mp.read_text(encoding="utf-8"))), indent=1) + "\n", encoding="utf-8")
        before = c.tree_hashes(d)
        r = h.run_sign(d, auditor_args)
        unchanged = before == c.tree_hashes(d)
        ok = r.returncode == 1 and all(ph in r.stderr for ph in phrases) and "Traceback" not in r.stderr and unchanged
        report(name, ok, f"sign.py exit 1, stderr with {phrases}, no Traceback, every file unchanged by hash",
               f"exit {r.returncode}, phrases: {[ph in r.stderr for ph in phrases]}, Traceback: {'Traceback' in r.stderr}, unchanged: {unchanged}",
               [f"stderr: {l}" for l in r.stderr.strip().splitlines()[-2:]])

    def g(k, v):
        def fn(M):
            M["grading"][k] = v
            return M
        return fn

    def wfile(M):
        M["grading"]["witnesses"][0]["file"] = 5
        return M
    sign_case("i4h_sign_auditor_empty_string", g("auditor", ""), ["manifest.json: grading.auditor is a JSON string, not an object", nw])
    sign_case("i4h_sign_witnesses_empty_object", g("witnesses", {}), ["manifest.json: grading.witnesses is a JSON object, not a list", nw])
    sign_case("i4h_sign_witness_file_a_number", wfile, ["manifest.json: grading.witnesses[0].file is a JSON number, not a string", nw])

    ans = tmp / "i4h_answer"
    c.make_answer(tmp / "build" / "FB", ans)
    parent = f.copy_of(tmp, fpre, "i4h_add_witness_parent_auditor_a_string")
    mp = parent / "manifest.json"
    M = json.loads(mp.read_text(encoding="utf-8"))
    M["grading"]["auditor"] = "a"
    mp.write_text(json.dumps(M, indent=1) + "\n", encoding="utf-8")
    before = c.tree_hashes(parent)
    r = f.run_add_witness_with(HERE / "add_witness.py", parent, ans)
    unchanged = before == c.tree_hashes(parent)
    phrase = "grading.auditor is a JSON string, not an object"
    ok = r.returncode == 1 and "refused" in r.stderr and phrase in r.stderr and "Traceback" not in r.stderr and unchanged
    details = [f"stderr: {l}" for l in r.stderr.strip().splitlines()[-2:]]
    if committed_dir is not None:
        pc = f.copy_of(tmp, fpre, "i4h_add_witness_parent_auditor_a_string_committed")
        (pc / "manifest.json").write_text(mp.read_text(encoding="utf-8"), encoding="utf-8")
        b2 = c.tree_hashes(pc)
        rc = f.run_add_witness_with(committed_dir / "add_witness.py", pc, ans)
        details += [f"committed add_witness.py: exit {rc.returncode}, tree changed: {b2 != c.tree_hashes(pc)}, last stderr line: {(rc.stderr.strip().splitlines() or [''])[-1][:160]}"]
    report("i4h_add_witness_parent_auditor_a_string", ok, f"add_witness.py exit 1, 'refused' and '{phrase}', no Traceback, the parent unchanged by hash",
           f"exit {r.returncode}, refused {'refused' in r.stderr}, phrase {phrase in r.stderr}, Traceback {'Traceback' in r.stderr}, unchanged {unchanged}", details)


def i3(committed):
    if committed is None:
        print("skipped  i3: --committed none, no committed checker to compare with")
        return
    folders = c.published_folders() + [q.relative_to(HERE) for q in sorted((HERE / "fixtures").glob("*")) if q.is_dir() and (q / "manifest.json").exists()]
    for rel in folders:
        (rc, _, _), (rw, _, _) = c.both(committed, HERE / rel)
        summ = next((l for l in rw.stdout.splitlines() if l.startswith("SUMMARY")), "(no SUMMARY)")
        report(f"i3_{str(rel).replace('/', '_')}", rc.stdout == rw.stdout and rc.returncode == rw.returncode and "Traceback" not in rw.stderr, "whole output byte-identical, exit codes equal, no exception",
               f"identical: {rc.stdout == rw.stdout}, exit committed={rc.returncode} cut={rw.returncode}, Traceback: {'Traceback' in rw.stderr}; {summ}")


def main():
    if not (c.SRC_F / "audit.jsonl").exists() or not (f.SRC_G / "manifest.json").exists():
        print(f"fixture sources missing: {c.SRC_F}, {f.SRC_G}", file=sys.stderr)
        return 2
    if not shutil.which("ssh-keygen"):
        print("ssh-keygen is not on PATH", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        fpre, F = c.build(tmp / "build")
        FB = tmp / "build" / "FB"
        shutil.copytree(F, FB)
        dd.add_bound(FB)
        committed = None if c.SKIP_COMMITTED else c.committed_checker(tmp)
        FS = f.build_signed(tmp, FB, "FS")
        i1(tmp, F, committed)
        i2(tmp, FS, committed)
        i2e(tmp, FS, committed)
        i2f(tmp, FS, committed)
        committed_dir = None if c.SKIP_COMMITTED else f.committed_tools(tmp)
        committed_sign = None if c.SKIP_COMMITTED else h.committed_sign_dir(tmp)
        i4(tmp, fpre, FB, FS, committed_dir, committed_sign)
        forger = tmp / "build" / "keys" / "fixture-forger-i"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "fixture-forger-i", "-f", str(forger)], check=True, capture_output=True)
        i2g(tmp, FS, forger, committed)
        i4f(tmp, fpre, FB, FS, committed_dir, committed_sign)
        i4g(tmp, fpre, FB, FS, committed_dir, committed_sign)
        i2h(tmp, FB, committed)
        i2i(tmp, FB, committed)
        i2j(tmp, FB, committed)
        i2k(tmp, FB, FS, committed)
        i4h(tmp, fpre, FS, committed_dir)
        i3(committed)
        mism = sum(1 for r in c.RESULTS if not r)
        print(f"{sum(c.RESULTS)} of {len(c.RESULTS)} cases gave the expected result; MISMATCH {mism}")
        return 0 if all(c.RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
