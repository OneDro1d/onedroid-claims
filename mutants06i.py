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
        i3(committed)
        mism = sum(1 for r in c.RESULTS if not r)
        print(f"{sum(c.RESULTS)} of {len(c.RESULTS)} cases gave the expected result; MISMATCH {mism}")
        return 0 if all(c.RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
