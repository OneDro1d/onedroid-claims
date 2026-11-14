#!/usr/bin/env python3
"""test07_links.py: the links suite of claims-snapshot 0.7 (L1 to L10 of the 0.7 design's RED list): the manifest field `links`, the
checker rule K16 (offline, `--links ROOT`), and the six-section sources digest (the auditor's `sources` signature covers `links` on 0.7,
exactly the five bound sections before). Standard library plus ssh-keygen on PATH.

The tree is built in a temporary folder: <tmp>/tree/pub/slug/2026-11-12 is the target (a 0.7 fixture), and each case is a 0.7 fixture
taken at 2026-11-14 in its own sibling folder, so a link's path is "../2026-11-12". A changed `links` is re-signed with the auditor's
key (sign.py --role sources) unless the case is about not re-signing.

usage: python3 -I test07_links.py [--committed PATH]   (PATH: the previous check.py, for L9's byte identity on 0.6; else the current
                                                      check.py's five-section digest is the reference)"""
import importlib.util, json, os, pathlib, shutil, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fixtures07 as f  # noqa: E402

ARGS = sys.argv[1:]
COMMITTED = ARGS[ARGS.index("--committed") + 1] if "--committed" in ARGS else "none"
LATER = "2026-11-14T09:00:00Z"


def canon(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def main():
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        f.keygen(tmp / "keys")
        slug = tmp / "tree" / "pub" / "slug"
        slug.mkdir(parents=True)
        T = f.build(slug / "2026-11-12")
        base = f.build(tmp / "base-this", taken_at=LATER)
        n = [0]

        def this(name):
            n[0] += 1
            d = slug / f"case-{n[0]:02d}-{name}"
            shutil.copytree(base, d)
            return d

        def tgt_hash(t=T):
            return f.sha(t / "manifest.json")

        def link(rel="supersedes", path="../2026-11-12", sig=True, anchor=None, t=T, **extra):
            tg = {"manifest_sha256": tgt_hash(t), "signatures_sha256": f.sha(t / "signatures.json") if sig else None, "path": path,
                  "location": None, "anchor": anchor}
            tg.update(extra)
            return {"rel": rel, "target": tg, "note": "test link"}

        def k16(name, links, want_status, needle, flags=(), resign=True, want_rc=None):
            d = this(name)
            f.set_links(d, links, resign=resign)
            r = f.Run(d, *flags)
            ok = r.status.get("K16") == want_status and (needle is None or r.has("K16", needle)) and r.summary is not None and not r.traceback
            if want_rc is not None:
                ok = ok and r.rc == want_rc
            f.report(name, ok, f"K16 {want_status}" + (f" with {needle!r}" if needle else "") + ", a SUMMARY line, no traceback",
                     f"K16 {r.status.get('K16')}, rc {r.rc}, summary {r.summary}, traceback {r.traceback}", r.text.get("K16", "").splitlines()[:6])
            return r

        # L1: no links
        f.case("l1_no_links", lambda: k16("l1_no_links", None, "PASS", "no links", want_rc=0))

        # L2: shapes, each a K16 FAIL by index and field
        f.case("l2a_links_an_object", lambda: k16("l2a_links_an_object", {}, "FAIL", "links is a JSON object, not a list", want_rc=1))
        f.case("l2b_entry_a_string", lambda: k16("l2b_entry_a_string", ["x"], "FAIL", "links[0] is a JSON string, not an object", want_rc=1))
        f.case("l2c_rel_a_number", lambda: k16("l2c_rel_a_number", [dict(link(), rel=7)], "FAIL", "links[0].rel is a JSON number, not a string", want_rc=1))
        f.case("l2d_target_a_list", lambda: k16("l2d_target_a_list", [dict(link(), target=[])], "FAIL", "links[0].target is a JSON array, not an object", want_rc=1))
        f.case("l2e_sha_63_hex", lambda: k16("l2e_sha_63_hex", [link(manifest_sha256="a" * 63)], "FAIL",
                                             "links[0].target.manifest_sha256 is not 64 lower-case hex", want_rc=1))
        f.case("l2f_sha_upper_hex", lambda: k16("l2f_sha_upper_hex", [link(manifest_sha256=tgt_hash().upper())], "FAIL",
                                                "links[0].target.manifest_sha256 is not 64 lower-case hex", want_rc=1))
        f.case("l2g_path_absolute", lambda: k16("l2g_path_absolute", [link(path=str(T))], "FAIL", "links[0].target.path is absolute", want_rc=1))
        f.case("l2h_path_escapes", lambda: k16("l2h_path_escapes", [link(path="../../../../../../etc")], "FAIL", "links[0].target.path leaves", want_rc=1))

        def l2i():
            (slug / "2026-11-12-symlink").symlink_to(T, target_is_directory=True)
            k16("l2i_path_through_symlink", [link(path="../2026-11-12-symlink")], "FAIL", "links[0].target.path passes through a symbolic link", want_rc=1)
        f.case("l2i_path_through_symlink", l2i)
        f.case("l2j_signatures_sha_not_hex", lambda: k16("l2j_signatures_sha_not_hex", [link(signatures_sha256="xyz")], "FAIL",
                                                         "links[0].target.signatures_sha256 is not 64 lower-case hex or null", want_rc=1))
        f.case("l2k_target_sha_missing", lambda: k16("l2k_target_sha_missing", [dict(link(), target={"path": "../2026-11-12"})], "FAIL",
                                                     "links[0].target.manifest_sha256 is missing", want_rc=1))

        # L3: duplicate (rel, manifest_sha256)
        f.case("l3_duplicate", lambda: k16("l3_duplicate", [link(), link()], "FAIL", "links[1]: a duplicate of links[0]", want_rc=1))

        # L4: unknown rel: WARN, still resolved
        def l4():
            r = k16("l4_unknown_rel_warns", [link(rel="obsoletes")], "WARN", "rel 'obsoletes' is not one of", want_rc=0)
            f.report("l4b_unknown_rel_still_resolved", r.has("K16", "resolved"), "the entry resolved", r.text.get("K16", ""))
        f.case("l4_unknown_rel_warns", l4)

        # L5: not at hand, then the same through --links ROOT
        def l5():
            d = this("l5_not_at_hand")
            f.set_links(d, [link(path=None)])
            r1 = f.Run(d)
            r2 = f.Run(d, "--links", tmp / "tree")
            ok1 = r1.status.get("K16") == "WARN" and r1.has("K16", "not at hand, hash recorded, not resolved") and r1.rc == 0
            ok2 = r2.status.get("K16") == "PASS" and r2.has("K16", "resolved") and r2.rc == 0
            f.report("l5a_target_not_at_hand_warns", ok1, "K16 WARN 'not at hand', exit 0", f"K16 {r1.status.get('K16')}, rc {r1.rc}", r1.text.get("K16", "").splitlines())
            f.report("l5b_same_target_via_links_root_passes", ok2, "K16 PASS 'resolved', exit 0", f"K16 {r2.status.get('K16')}, rc {r2.rc}", r2.text.get("K16", "").splitlines())
        f.case("l5_not_at_hand", l5)

        def l5c():
            other = f.build(slug / "2026-11-10", taken_at="2026-11-10T00:00:00Z")  # another version: its manifest bytes differ from the target's
            k16("l5c_path_holds_another_version", [link(path="../2026-11-10")], "WARN", "another manifest", want_rc=0)
            shutil.rmtree(other)
        f.case("l5c_path_holds_another_version", l5c)

        # L6: resolved, signatures_sha256 wrong; anchor not in the target's anchors.json; anchor present (control)
        f.case("l6a_signatures_sha_wrong", lambda: k16("l6a_signatures_sha_wrong", [link(signatures_sha256="0" * 64)], "FAIL",
                                                       "signatures.json", want_rc=1))
        ref = {"chain": "argus-dev-poa", "correlation_id": "c" * 32, "block": 4242, "tx_hash": "0x" + "ab" * 32}

        def l6():
            (T / "anchors.json").write_text(json.dumps([{"over": "sha256:" + f.sha(T / "signatures.json"), "method": "armarium", "ref": ref,
                                                          "time": "2026-11-12T02:00:00Z", "proof_file": None}], indent=1) + "\n", encoding="utf-8")
            k16("l6b_anchor_not_in_target", [link(anchor=dict(ref, block=4243))], "FAIL", "anchors.json has no entry whose ref", want_rc=1)
            k16("l6c_anchor_in_target_passes", [link(anchor=ref)], "PASS", "resolved", want_rc=0)
            # gate H2 (14 Nov 2026): an anchors.json that is a symbolic link, even to a file holding the right entry, is not
            # read (the same rule as signatures.json and the link path, DESIGN 1.3)
            outside = T.parent.parent / "outside-anchors.json"
            outside.write_text((T / "anchors.json").read_text(encoding="utf-8"), encoding="utf-8")
            (T / "anchors.json").unlink()
            (T / "anchors.json").symlink_to(outside)
            k16("l6d_anchor_file_is_a_symlink", [link(anchor=ref)], "FAIL", "anchors.json has no entry whose ref", want_rc=1)
            (T / "anchors.json").unlink()
            outside.unlink()
            (T / "anchors.json").write_text("[]\n", encoding="utf-8")
        f.case("l6_anchor", l6)

        # L7: a re-audit of another subject; a target not earlier
        def l7():
            T2 = f.build(slug / "2026-11-11")
            M = f.mload(T2)
            M["subject"]["title"] = "another subject"
            f.msave(T2, M)
            k16("l7a_supersedes_another_subject", [link(t=T2, path="../2026-11-11")], "FAIL", "a re-audit of another subject", want_rc=1)
            k16("l7b_reaudits_another_subject", [link(rel="reaudits", t=T2, path="../2026-11-11")], "FAIL", "a re-audit of another subject", want_rc=1)
            k16("l7c_derived_from_another_subject_passes", [link(rel="wasDerivedFrom", t=T2, path="../2026-11-11")], "PASS", "resolved", want_rc=0)
            T3 = f.build(slug / "2026-11-15", taken_at="2026-11-15T00:00:00Z")
            k16("l7d_supersedes_a_later_target", [link(t=T3, path="../2026-11-15")], "FAIL", "is not earlier than this record's", want_rc=1)
            T4 = f.build(slug / "2026-11-14-same", taken_at=LATER)
            k16("l7e_supersedes_an_equal_time_target", [link(t=T4, path="../2026-11-14-same")], "FAIL", "is not earlier than this record's", want_rc=1)
            k16("l7f_supersedes_and_reaudits_pass", [link(), link(rel="reaudits")], "PASS", "resolved", want_rc=0)
        f.case("l7_subject_and_time", l7)

        # L8: add_witness keeps links byte-identical; a hand edit after insertion fails K13 (the sources digest moves)
        def l8():
            d = this("l8_add_witness")
            f.set_links(d, [link()])
            before = canon(f.mload(d).get("links"))
            ans = f.witness_answer(d, tmp / "l8-answer")
            r = f.add_witness(d, ans)
            after = canon(f.mload(d).get("links"))
            rc = f.Run(d)
            ok = r.returncode == 0 and before == after and rc.status.get("K13") == "PASS" and rc.has("K13", "manifest.json: sources bound by fixture-auditor, verified") and rc.rc == 0
            f.report("l8a_add_witness_keeps_links", ok, "add_witness exit 0, links equal before and after, K13 PASS with the sources verified, check exit 0",
                     f"add_witness exit {r.returncode}, links equal {before == after}, K13 {rc.status.get('K13')}, check exit {rc.rc}",
                     (r.stderr.strip().splitlines() + rc.text.get("K13", "").splitlines())[:8])
            M = f.mload(d)
            M["links"][0]["note"] = "edited after the insertion"
            f.msave(d, M)
            f.sign(d, "manifest", "adder", f.ADDER)
            r2 = f.Run(d)
            ok2 = r2.status.get("K13") == "FAIL" and r2.has("K13", "the sources signature is over bound sections") and r2.has("K13", "links")
            f.report("l8b_links_edited_after_insertion_fails_k13", ok2, "K13 FAIL on the sources digest, naming links",
                     f"K13 {r2.status.get('K13')}", r2.text.get("K13", "").splitlines()[:6])
        f.case("l8_add_witness", l8)

        # L9: sign.py --role sources: six sections on 0.7, five on 0.6 (byte-identical to the committed checker's bound digest)
        def l9():
            d7 = this("l9_sign07")
            f.set_links(d7, [link()])
            M7 = f.mload(d7)
            e7 = next(e for e in json.loads((d7 / "signatures.json").read_text()) if e["role"] == "sources")
            want7 = f.check.sources_digest(M7)
            ok = (e7["sha256"] == want7 and want7 != f.check.bound_digest(M7)
                  and e7["line"] == f.check.signed_line("sources", "manifest.json", want7))
            f.report("l9a_sources_on_07_signs_six_sections", ok, "entry sha256 = sources_digest (six sections), not the five-section bound_digest",
                     f"entry {e7['sha256'][:12]}, sources_digest {want7[:12]}, bound_digest {f.check.bound_digest(M7)[:12]}")
            secs = dict(f.check.bound_sections(M7))
            secs["links"] = __import__("hashlib").sha256(canon(M7.get("links")).encode()).hexdigest()
            manual = __import__("hashlib").sha256(canon(secs).encode()).hexdigest()
            f.report("l9b_six_section_digest_recomputed_by_hand", manual == want7, "sha256 of the canonical six-section map", f"{manual[:12]} vs {want7[:12]}")
            d6 = f.build(tmp / "l9-06", fmt=f.F06)
            M6 = f.mload(d6)
            e6 = next(e for e in json.loads((d6 / "signatures.json").read_text()) if e["role"] == "sources")
            if COMMITTED != "none":
                spec = importlib.util.spec_from_file_location("check_committed", COMMITTED)
                old = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(old)
                ref6 = old.bound_digest(M6)
                label = "the committed checker's bound_digest"
            else:
                ref6, label = f.check.bound_digest(M6), "this checker's bound_digest"
            ok6 = e6["sha256"] == ref6 == f.check.sources_digest(M6) and e6["line"] == f.check.signed_line("sources", "manifest.json", ref6)
            f.report("l9c_sources_on_06_signs_five_sections", ok6, f"entry sha256 = {label} = sources_digest on 0.6", f"entry {e6['sha256'][:12]}, ref {ref6[:12]}")
            # links changed on 0.7 without re-signing: K13 FAIL; on 0.6 the field is not bound
            f.set_links(d7, [dict(link(), note="changed")], resign=False)
            r7 = f.Run(d7)
            M6["links"] = [link()]
            f.msave(d6, M6)
            r6 = f.Run(d6)
            f.report("l9d_links_unsigned_change_fails_on_07", r7.status.get("K13") == "FAIL" and r7.has("K13", "links"), "K13 FAIL on 0.7",
                     f"K13 {r7.status.get('K13')}", r7.text.get("K13", "").splitlines()[:3])
            f.report("l9e_links_not_bound_on_06", r6.status.get("K13") == "PASS" and "K16" not in r6.status, "K13 PASS and no K16 on 0.6",
                     f"K13 {r6.status.get('K13')}, K16 {r6.status.get('K16')}")
        f.case("l9_sign_sources", l9)

        # L10: a witness header `bound` naming six sections (links too): K11 FAIL as today; add_witness refuses it
        def l10():
            d = this("l10_bound_six")
            M = f.mload(d)
            rows = f.load(d / "witness/alice.jsonl")
            b5 = f.check.bound_sections(M)
            rows[0]["bound"] = dict(b5)
            f.dump(d / "witness/alice.jsonl", rows)
            f.resign_witness(d)
            r5 = f.Run(d)
            f.report("l10a_bound_five_passes", r5.status.get("K11") == "PASS", "K11 PASS with the five sections", f"K11 {r5.status.get('K11')}",
                     r5.text.get("K11", "").splitlines()[:3])
            rows[0]["bound"] = dict(b5, links=__import__("hashlib").sha256(b"null").hexdigest())
            f.dump(d / "witness/alice.jsonl", rows)
            f.resign_witness(d)
            r6 = f.Run(d)
            f.report("l10b_bound_six_fails_k11", r6.status.get("K11") == "FAIL" and r6.has("K11", "not the five bound sections"),
                     "K11 FAIL 'not the five bound sections'", f"K11 {r6.status.get('K11')}", r6.text.get("K11", "").splitlines()[:3])
            d2 = this("l10_answer_six")
            ans = f.witness_answer(d2, tmp / "l10-answer")
            wrows = f.load(ans / "witness/bob.jsonl")
            wrows[0]["bound"] = dict(f.check.bound_sections(f.mload(d2)), links=__import__("hashlib").sha256(b"null").hexdigest())
            f.dump(ans / "witness/bob.jsonl", wrows)
            ra = f.add_witness(d2, ans)
            f.report("l10c_add_witness_refuses_bound_six", ra.returncode == 1 and "not the five bound sections" in ra.stderr and not (d2 / "witness/bob.jsonl").exists(),
                     "add_witness exit 1, refused naming the five sections, nothing written", f"exit {ra.returncode}, written {(d2 / 'witness/bob.jsonl').exists()}",
                     ra.stderr.strip().splitlines()[:3])
        f.case("l10_bound", l10)

    return f.finish("test07_links")


if __name__ == "__main__":
    sys.exit(main())
