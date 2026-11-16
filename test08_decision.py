#!/usr/bin/env python3
"""test08_decision.py: the suite of claims-snapshot 0.8's `decision` profile (SPEC.md section 16). Standard library plus ssh-keygen on PATH.

A decision folder is BUILT here, in a temporary folder, from the section 16 contract (build() below): three artefacts (the item, the
judgement and, with a ledger, the ledger event), the subject, the auditor's three claims C-001 to C-003, one `read` witness, the merge, and
the auditor's and the witness's signatures made with throwaway keys (no key leaves the temporary folder). Each case changes ONE thing in
the builder's inputs (so every hash, the score and the signatures stay consistent) and names the check line that must say so.

Cases (every one reports ok or MISMATCH by name, a RED run of the missing feature reports all of them):
  p1..p5  well-formed folders: with a ledger, a hash-only holder, no ledger, an override, a pipeline decider: no FAIL, exit 0.
  g1..g3  gating: the same folder as 0.7 is refused at K1 (the profile is 0.8's); a 0.8 folder of another profile reads as its 0.7 twin;
          the format is read.
  k1_*    one case per bullet of section 16's K1 rule (a missing field, a wrong type, the title, the ref pattern, the by.kind vocabulary,
          the override equation, taken_at, the ledger shape, the evidence locator).
  k11_*   one case per bullet of section 16's K11 rule (the three rows and their kinds, C-003's ruleset string, an override's reason,
          C-002 naming the ledger event, the witness method read or classify and nothing else).
  k5_*    K5 for `artefact` pointers is section 13's, unchanged.
  k13_*   an unsigned decision record fails K13 by design (section 16, Signing).

usage: python3 -I test08_decision.py"""
import hashlib, json, pathlib, shutil, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fixtures07 as f  # noqa: E402

F08 = "claims-snapshot/0.8"
RULES = ("claims-rules", "3")
RULES_DIGEST = hashlib.sha256(b"claims-rules 3 fixture").hexdigest()
AT = "2026-11-16T10:00:00Z"
STATE = {"n": 0}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def build(dst, fmt=F08, *, ledger=True, override=False, by_kind="person", held_by="folder", sign=True, subject=None, audit=None,
          locator=None, wmethod="read", wkind="human", ref="dkt-0042", manifest=None):
    """A decision folder of format `fmt`. `subject`, `audit` (rows), `locator` and `manifest` are functions that change the built
    value before it is written; the artefacts, the page, the witness, the merge, the counts and the signatures follow from the result."""
    dst = pathlib.Path(dst)
    (dst / "witness").mkdir(parents=True)
    names = ["item.json", "judgement.json"] + (["event.json"] if ledger else [])
    blobs = {n: json.dumps({"artefact": n, "note": "fixture bytes, no item content"}, sort_keys=True).encode() for n in names}
    hs = {n: sha(b) for n, b in blobs.items()}
    folder = held_by == "folder"
    if folder:
        (dst / "sources/artefacts").mkdir(parents=True)
        for n, b in blobs.items():
            (dst / "sources/artefacts" / n).write_bytes(b)
    rid, rver = RULES
    rec = "approve"
    value = "reject" if override else "approve"
    ptr = lambda n: {"artefact": n, "sha256": hs[n]}  # noqa: E731
    kt, kb = f.pub("auditor")
    S = {"kind": "decision", "title": f"decision on {ref}", "item": {"ref": ref, "sha256": hs["item.json"]},
         "decision": {"value": value, "override": override, "by": {"kind": by_kind, "principal": "enrolled-principal-7" if by_kind == "person" else "runner-pipe-3"},
                      "at": AT},
         "basis": {"recommendation": rec, "on": ptr("judgement.json"), "ruleset": {"id": rid, "version": rver, "digest": RULES_DIGEST}},
         "ledger": {"stream": "docket-ledger", "n": 17, "event": ptr("event.json")} if ledger else None}
    if subject:
        subject(S)
    rows = [
        {"id": "C-001", "text": f"Item {ref}, in the form hashed as item.json, was judged on judgement.json under rule set {rid}@{rver}.",
         "kind": "process", "evidence": [ptr("item.json"), ptr("judgement.json")]},
        {"id": "C-002", "text": f"The decision was {value}. The judgement recommended {rec}, and the decision is " + ("an override." if override else "not an override."),
         "kind": "figure", "evidence": [ptr("event.json") if ledger else ptr("judgement.json")]},
        {"id": "C-003", "text": (f"Decided under {rid}@{rver}, departing from the recommendation because the decider held a document the judgement had not seen."
                                 if override else f"Decided under {rid}@{rver}: the claim met every listed requirement."),
         "kind": "other", "evidence": [ptr("judgement.json")]},
    ]
    if audit:
        audit(rows)
    f.dump(dst / "audit.jsonl", rows)
    (dst / "page.txt").write_text("".join(r["text"] + "\n" for r in rows), encoding="utf-8")
    audit_h = f.sha(dst / "audit.jsonl")
    wrows = []
    for r in rows:
        ok = bool(r.get("evidence"))
        wrows.append({"id": r["id"], "verdict": "EVIDENCED" if ok else "NO EVIDENCE PUBLISHED", "confidence": "high",
                      "on": {"proofs": [0] if ok else [], "counter": []}, "note": "fixture witness: the pointer resolves and says what the row says",
                      "graded_at": "2026-11-16T11:00:00Z"})
    header = {"witness": "fixture-reader", "kind": wkind, "model": "human" if wkind == "human" else "fixture-model", "method": wmethod,
              "over": {"file": "audit.jsonl", "sha256": audit_h}, "started_at": "2026-11-16T10:30:00Z", "finished_at": "2026-11-16T10:35:00Z"}
    if wmethod is None:
        header.pop("method")
    f.dump(dst / "witness/fixture-reader.jsonl", [header] + wrows)
    merged = f.check.merge_rows(rows, wrows, "fixture-reader")
    (dst / "claims.jsonl").write_text(f.check.dump_jsonl(merged), encoding="utf-8")
    sc = f.check.evidence_score(merged)
    cnt = lambda v: sum(1 for m in merged if m.get("verdict") == v)  # noqa: E731
    srcs = []
    for i, n in enumerate(names, 1):
        s = {"artefact_role": n.split(".")[0], "copy": "text" if folder else "hash-only", "file": f"sources/artefacts/{n}" if folder else None,
             "n": i, "name": n, "role": "artefact", "sha256": hs[n], "url": None}
        srcs.append(s)
    loc = {"held_by": held_by, "where": None if folder else "decision-store://docket/" + ref, "expires_at": None,
           "note": "every artefact is in this folder" if folder else "the deciding organisation's own store"}
    if locator:
        locator(loc)
    fp = f.check.sshsig_fingerprint(f"{kt} {kb}")
    wkt, wkb = f.pub("witness")
    M = {"format": fmt, "subject": S, "taken_at": AT, "evidence_locator": loc,
         "pages": [{"file": "page.txt", "lines": len(rows), "note": "the claims' text as the system wrote it, one per line", "sha256": f.sha(dst / "page.txt")}],
         "sources": srcs,
         "grading": {"auditor": {"file": "audit.jsonl", "model": "fixture-docket 0.0.1", "name": "docket-app", "note": "the system that recorded the decision",
                                 "sha256": audit_h, "signer": f"{f.AUDITOR} <{fp}>"},
                     "gates": [], "graded_at": "2026-11-16T11:00:00Z", "grader": "fixture-reader", "kind": "split", "method": wmethod or "read",
                     "model": "human", "profile": "decision", "rounds": [], "sessions": [],
                     **({"primary_named_by": f.AUDITOR} if wkind == "model" else {}),
                     "witnesses": [{"file": "witness/fixture-reader.jsonl", "method": wmethod or "read", "missing_claims": 0, "model": header["model"],
                                    "name": "fixture-reader", "primary": True, "kind": wkind, "signer": f.WITNESS,
                                    "score": {"band": sc["band"], "contradiction_pct": sc["contradiction_pct"], "coverage_pct": sc["coverage_pct"]},
                                    "sha256": f.sha(dst / "witness/fixture-reader.jsonl")}]},
         "counts": {"author_read": 0, "checkable": len(merged), "claims": len(merged), "contradicted": cnt("CONTRADICTED"),
                    "contradicted_high": 0, "evidenced": cnt("EVIDENCED"), "no_evidence": cnt("NO EVIDENCE PUBLISHED"), "on_request": 0, "withdrawn": 0},
         "score": {"band": sc["band"], "contradiction_pct": sc["contradiction_pct"], "coverage_pct": sc["coverage_pct"], "formula": "evidence-score/1"},
         "claims_sha256": f.sha(dst / "claims.jsonl")}
    M["files"] = {k: f.sha(dst / k) for k in ["audit.jsonl", "claims.jsonl", "page.txt", "witness/fixture-reader.jsonl"] + [s["file"] for s in srcs if s["file"]]}
    if manifest:
        manifest(M)
    (dst / "signatures.json").write_text("[]\n", encoding="utf-8")
    (dst / "allowed_signers").write_text("", encoding="utf-8")
    (dst / "anchors.json").write_text("[]\n", encoding="utf-8")
    f.msave(dst, M)
    if sign:
        f.sign(dst, "auditor", "auditor", f.AUDITOR, "audit.jsonl")
        f.sign(dst, "witness", "witness", f.WITNESS, "witness/fixture-reader.jsonl")
        if wkind == "model":
            f.sign(dst, "manifest", "auditor", f.AUDITOR)  # the principal that chose a model as primary signs the manifest (K11, section 14)
    return dst


def folder(tmp, **kw):
    STATE["n"] += 1
    return build(tmp / f"d{STATE['n']}", **kw)


def setp(path, value):
    """A mutator setting a dotted path in a dict (value KeyError: delete it)."""
    def go(d):
        *head, last = path.split(".")
        for k in head:
            d = d[k]
        if value is KeyError:
            d.pop(last, None)
        else:
            d[last] = value
    return go


def no_trace(r):
    return not r.traceback and r.summary is not None


def main():
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        f.keygen(tmp / "keys")
        RUN = {}

        def run(name, **kw):
            RUN[name] = f.Run(folder(tmp, **kw))
            return RUN[name]

        # ---- p: well-formed folders --------------------------------------------------------------------------------------------
        def positive(name, what, kw, k5=("PASS",), extra=None):
            def case():
                r = run(name, **kw)
                fails = [k for k, s in r.status.items() if s == "FAIL"]
                ok = (r.rc == 0 and not fails and no_trace(r) and r.status.get("K1") == "PASS" and r.has("K1", "profile decision")
                      and r.status.get("K11") == "PASS" and r.status.get("K13") == "PASS" and r.status.get("K5") in k5
                      and (extra is None or extra(r)))
                f.report(name, ok, f"{what}: exit 0, no FAIL, K1 K11 K13 PASS, K5 {'/'.join(k5)}",
                         f"exit {r.rc}, FAIL {fails}, K1 {r.status.get('K1')} K5 {r.status.get('K5')} K11 {r.status.get('K11')} K13 {r.status.get('K13')}, {r.summary}",
                         [r.text.get(k, "").split("\n")[0] for k in ("K1", "K5", "K11", "K13") if r.status.get(k) not in ("PASS", None)])
            f.case(name, case)

        positive("p1_well_formed_with_ledger", "a person's decision, a ledger, every artefact in the folder", {})
        positive("p2_hash_only_holder", "the same record held by the deciding organisation (hash-only: untestable pointers warn)", {"held_by": "subject-org"},
                 k5=("WARN",))
        positive("p3_no_ledger", "a decision with no ledger (ledger null; C-002 names the judgement)", {"ledger": False})
        positive("p4_override", "an override with a reason in words beyond the rule set's name", {"override": True})
        positive("p5_pipeline_decider", "a pipeline's round (by.kind pipeline)", {"by_kind": "pipeline"})

        def p6():
            r = RUN["p1_well_formed_with_ledger"]
            ok = r.status.get("K14") in ("WARN", "PASS") and r.status.get("K16") == "PASS" and r.has("K1", "decision")
            f.report("p6_only_warnings_are_anchor_and_sessions", ok and all(s != "FAIL" for s in r.status.values()),
                     "K14 WARN (no anchor yet), K15 WARN, K16 PASS 'no links'", f"K14 {r.status.get('K14')}, K15 {r.status.get('K15')}, K16 {r.status.get('K16')}")
        f.case("p6_only_warnings_are_anchor_and_sessions", p6)

        # ---- g: gating on the format -------------------------------------------------------------------------------------------
        def g1():
            r = f.Run(folder(tmp, fmt=f.F07))
            ok = r.rc != 0 and r.status.get("K1") == "FAIL" and r.has("K1", "grading.profile='decision'") and no_trace(r) and "K11" not in r.status
            f.report("g1_decision_profile_refused_before_0_8", ok, "a 0.7 folder with profile decision: K1 FAIL naming the profile, nothing further, exit 1",
                     f"exit {r.rc}, K1 {r.status.get('K1')}, K11 {r.status.get('K11')}", [r.text.get("K1", "")[:240]])
        f.case("g1_decision_profile_refused_before_0_8", g1)

        def g2():
            def norm(out):
                return [l for l in out.replace("claims-snapshot/0.8", "claims-snapshot/0.7").splitlines() if not l.startswith("SUMMARY:")]
            a = f.Run(f.build(tmp / "g2-07", fmt=f.F07))
            b = f.Run(f.build(tmp / "g2-08", fmt=F08))
            ok = a.rc == b.rc == 0 and norm(a.out) == norm(b.out) and b.has("K1", "format claims-snapshot/0.8") and b.status.get("K16") == "PASS"
            f.report("g2_other_profile_reads_on_0_8_as_on_0_7", ok, "the agent-work fixture on 0.8: the same lines as on 0.7 (format label aside), K16 PASS, exit 0",
                     f"lines equal {norm(a.out) == norm(b.out)}, exits {a.rc}/{b.rc}, K1 {b.text.get('K1', '')[:120]}")
        f.case("g2_other_profile_reads_on_0_8_as_on_0_7", g2)

        def g3():
            ok = "claims-snapshot/0.8" in f.check.FORMATS and "claims-snapshot/0.7" in f.check.FORMATS and "decision" not in f.check.PROFILES
            f.report("g3_format_known_profile_not_in_the_old_set", ok, "0.8 in FORMATS; PROFILES (the 0.7 set) unchanged",
                     f"0.8 in FORMATS {'claims-snapshot/0.8' in f.check.FORMATS}, decision in PROFILES {'decision' in f.check.PROFILES}")
        f.case("g3_format_known_profile_not_in_the_old_set", g3)

        # ---- k1: one case per bullet ---------------------------------------------------------------------------------------------
        def k1case(name, bullet, needle, **kw):
            def case():
                r = run(name, **kw)
                ok = r.rc != 0 and r.status.get("K1") == "FAIL" and r.has("K1", needle) and no_trace(r)
                f.report(name, ok, f"K1 FAIL, exit 1, the line names {needle!r} ({bullet})", f"exit {r.rc}, K1 {r.status.get('K1')}",
                         [r.text.get("K1", "")[:300]])
            f.case(name, case)

        k1case("k1_a_missing_item", "every subject field present", "subject.item", subject=setp("item", KeyError))
        k1case("k1_a_missing_basis_ruleset", "every subject field present", "subject.basis.ruleset", subject=setp("basis.ruleset", KeyError))
        k1case("k1_a_missing_ledger_key", "every subject field present (ledger is null or an object, never absent)", "subject.ledger", subject=setp("ledger", KeyError))
        k1case("k1_a_wrong_kind", "subject.kind is decision", "subject.kind", subject=setp("kind", "test-run"))
        k1case("k1_a_item_sha_not_hex", "a field with its type: a sha256 is 64 hex", "subject.item.sha256", subject=setp("item.sha256", "not-a-hash"))
        k1case("k1_a_value_empty", "a field with its type: value is a token", "subject.decision.value", subject=setp("decision.value", ""))
        k1case("k1_a_override_not_bool", "a field with its type: override is a boolean", "subject.decision.override", subject=setp("decision.override", "no"))
        k1case("k1_a_at_not_a_time", "a field with its type: at is a time", "subject.decision.at", subject=setp("decision.at", "yesterday"))
        k1case("k1_b_title_not_fixed", "title is exactly decision on <item.ref>", "title", subject=setp("title", "Decision on a docket claim"))
        k1case("k1_c_ref_with_space", "item.ref matches its pattern", "item.ref", ref="dkt 0042", subject=setp("title", "decision on dkt 0042"))
        k1case("k1_c_ref_too_long", "item.ref is at most 64 characters", "item.ref", ref="r" * 65, subject=setp("title", "decision on " + "r" * 65))
        k1case("k1_d_by_kind_outside", "decision.by.kind is person or pipeline", "decision.by.kind", subject=setp("decision.by.kind", "committee"))
        k1case("k1_e_override_false_but_differs", "override equals (value != recommendation)", "override", subject=setp("decision.override", True))
        k1case("k1_e_override_true_but_equal", "override equals (value != recommendation), the other way", "override",
               subject=lambda S: S["decision"].update({"value": "approve", "override": True}))
        k1case("k1_f_taken_at_differs", "taken_at equals decision.at", "taken_at", manifest=setp("taken_at", "2026-11-16T10:00:01Z"))
        k1case("k1_g_ledger_n_zero", "ledger.n is an integer of 1 or more", "ledger.n", subject=setp("ledger.n", 0))
        k1case("k1_g_ledger_n_string", "ledger.n is an integer", "ledger.n", subject=setp("ledger.n", "17"))
        k1case("k1_g_ledger_n_bool", "ledger.n is an integer, not a boolean", "ledger.n", subject=setp("ledger.n", True))
        k1case("k1_g_ledger_without_stream", "ledger carries a stream", "ledger.stream", subject=setp("ledger.stream", KeyError))
        k1case("k1_g_ledger_event_without_sha", "ledger.event carries an artefact name and a sha256", "ledger.event.sha256", subject=setp("ledger.event.sha256", KeyError))
        k1case("k1_g_ledger_event_without_name", "ledger.event carries an artefact name", "ledger.event.artefact", subject=setp("ledger.event.artefact", ""))
        k1case("k1_h_locator_missing", "the evidence locator rules of section 13: the locator is present", "evidence_locator", manifest=setp("evidence_locator", KeyError))
        k1case("k1_h_locator_holder_outside", "held_by is in the vocabulary", "held_by", locator=setp("held_by", "elsewhere"))
        k1case("k1_h_locator_holder_without_where", "another holder than the folder names where", "where", held_by="subject-org", locator=setp("where", None))
        k1case("k1_h_locator_folder_without_copy", "held_by folder: every artefact source has its copy", "has no copy in the folder",
               manifest=lambda M: M["sources"][0].update({"file": "sources/artefacts/gone.json"}))
        k1case("k1_h_locator_expiry_not_a_time", "expires_at, when set, is a time", "expires_at", locator=setp("expires_at", "soon"))

        # ---- k11: one case per bullet --------------------------------------------------------------------------------------------
        def k11case(name, bullet, needle, **kw):
            def case():
                r = run(name, **kw)
                ok = (r.rc != 0 and r.status.get("K11") == "FAIL" and r.has("K11", needle) and r.status.get("K1") == "PASS" and no_trace(r))
                f.report(name, ok, f"K1 PASS, K11 FAIL, exit 1, the line names {needle!r} ({bullet})",
                         f"exit {r.rc}, K1 {r.status.get('K1')}, K11 {r.status.get('K11')}", [r.text.get("K11", "")[:360]])
            f.case(name, case)

        def drop(i):
            return lambda rows: rows.pop(i)

        k11case("k11_a_row_c003_missing", "exactly the rows C-001, C-002, C-003", "decision needs exactly", audit=drop(2))
        k11case("k11_a_extra_row", "exactly the rows: no fourth", "decision needs exactly",
                audit=lambda rows: rows.append({"id": "C-004", "text": "An extra claim.", "kind": "other", "evidence": rows[0]["evidence"][:1]}))
        k11case("k11_a_kind_of_c002", "C-002 is kind figure", "decision needs exactly", audit=lambda rows: rows[1].update({"kind": "process"}))
        k11case("k11_a_kind_of_c001", "C-001 is kind process", "decision needs exactly", audit=lambda rows: rows[0].update({"kind": "other"}))
        k11case("k11_b_c003_without_ruleset", "C-003 contains <id>@<version>", "C-003",
                audit=lambda rows: rows[2].update({"text": "Decided because the claim met every listed requirement."}))
        k11case("k11_b_c003_wrong_version", "C-003 contains <id>@<version> exactly", "C-003",
                audit=lambda rows: rows[2].update({"text": "Decided under claims-rules@2: the claim met every listed requirement."}))
        k11case("k11_c_override_reason_empty", "an override's C-003 with the string removed holds a letter", "override",
                override=True, audit=lambda rows: rows[2].update({"text": "claims-rules@3"}))
        k11case("k11_c_override_reason_only_marks", "an override's reason holds a letter beyond the string", "override",
                override=True, audit=lambda rows: rows[2].update({"text": "claims-rules@3 - 12, 34."}))
        k11case("k11_d_c002_without_ledger_event", "with a ledger, C-002's evidence names ledger.event", "ledger.event",
                audit=lambda rows: rows[1].update({"evidence": [rows[0]["evidence"][1]]}))
        k11case("k11_d_c002_names_event_by_wrong_hash", "C-002's pointer names the event by its name AND its sha256", "ledger.event",
                audit=lambda rows: rows[1].update({"evidence": [{"artefact": "event.json", "sha256": rows[0]["evidence"][0]["sha256"]}]}))
        k11case("k11_e_method_re_run", "a witness method outside read and classify: re-run is the test-run profile's, not this one", "method",
                wmethod="re-run")
        k11case("k11_e_method_other", "a witness method outside read and classify", "method", wmethod="inspect")
        k11case("k11_e_method_absent", "a witness header without a method", "method", wmethod=None)
        k11case("k11_e_classify_on_a_human", "classify is for a model witness (section 14), still held for this profile", "classify", wmethod="classify")

        def k11_classify_ok():
            r = run("k11_e_classify_model_ok", wmethod="classify", wkind="model")
            ok = r.status.get("K11") in ("PASS", "WARN") and r.status.get("K1") == "PASS" and not r.has("K11", "method") and no_trace(r)
            f.report("k11_e_classify_model_ok", ok, "a model witness with method classify (named primary, manifest signed): K11 PASS or WARN, nothing about the method",
                     f"K11 {r.status.get('K11')}", [r.text.get("K11", "")[:360]])
        f.case("k11_e_classify_model_ok", k11_classify_ok)

        # ---- k5: section 13's artefact rule, unchanged --------------------------------------------------------------------------
        def k5_unlisted():
            r = run("k5_unlisted_hash", audit=lambda rows: rows[0].update({"evidence": [{"artefact": "item.json", "sha256": "0" * 64}, {"artefact": "judgement.json", "sha256": "1" * 64}]}))
            ok = r.rc != 0 and r.status.get("K5") == "FAIL" and r.has("K5", "listed by no source") and no_trace(r)
            f.report("k5_unlisted_hash", ok, "a pointer to a hash no source lists: K5 FAIL (section 13)", f"exit {r.rc}, K5 {r.status.get('K5')}", [r.text.get("K5", "")[:300]])
        f.case("k5_unlisted_hash", k5_unlisted)

        def k5_other_name():
            r = run("k5_other_name", audit=lambda rows: rows[0].update({"evidence": [{"artefact": "judgement.json", "sha256": rows[0]["evidence"][0]["sha256"]}]}))
            ok = r.rc != 0 and r.status.get("K5") == "FAIL" and r.has("K5", "under another name") and no_trace(r)
            f.report("k5_other_name", ok, "a hash held under another name: K5 FAIL (section 13)", f"exit {r.rc}, K5 {r.status.get('K5')}", [r.text.get("K5", "")[:300]])
        f.case("k5_other_name", k5_other_name)

        # ---- k13: unsigned by design ---------------------------------------------------------------------------------------------
        def k13_unsigned():
            r = run("k13_unsigned", sign=False)
            ok = r.rc != 0 and r.status.get("K13") == "FAIL" and r.has("K13", "audit.jsonl: unsigned") and r.has("K13", "decision") and no_trace(r) and r.status.get("K11") == "PASS"
            f.report("k13_unsigned", ok, "an unsigned decision record: K13 FAIL by design, naming the profile", f"exit {r.rc}, K13 {r.status.get('K13')}", [r.text.get("K13", "")[:300]])
        f.case("k13_unsigned", k13_unsigned)

        def k13_witness_is_not_auditor():
            d = folder(tmp)
            # the witness's file re-signed with the auditor's key: never allowed (section 16, The witness; VR-I11)
            f.sign(d, "witness", "auditor", f.AUDITOR, "witness/fixture-reader.jsonl")
            r = f.Run(d)
            ok = r.rc != 0 and r.status.get("K13") == "FAIL" and no_trace(r)
            f.report("k13_witness_is_not_auditor", ok, "a witness signed with the auditor's key: K13 FAIL", f"exit {r.rc}, K13 {r.status.get('K13')}", [r.text.get("K13", "")[:300]])
        f.case("k13_witness_is_not_auditor", k13_witness_is_not_auditor)

    return f.finish("test08_decision")


if __name__ == "__main__":
    sys.exit(main())
