#!/usr/bin/env python3
"""test09_agent_decider.py: the suite of claims-snapshot 0.9's third decider (SPEC.md section 16, `decision.by.kind` `agent`).
Standard library plus ssh-keygen on PATH.

The folders are built by test08_decision.build (the section 16 contract, signed with throwaway keys), with the format and the decider
changed. Each case changes ONE thing and names the check line that must say so.

Cases (every one reports ok or MISMATCH by name):
  p1..p3  well-formed 0.9 folders: an agent's decision naming who enrolled it, an agent's break-glass reveal held by the deciding
          organisation (hash-only), a person's decision in the 0.8 shape: no FAIL, exit 0.
  k1_*    the 0.9 K1 rules: `agent` needs `enrolled_by` (present, a string, non-empty, not the agent's own principal); a person's or a
          pipeline's decider carries no `enrolled_by`; an unknown kind still fails, naming the 0.9 vocabulary.
  g1..g3  gating: `agent` on a 0.8 folder still fails K1 with the 0.8 vocabulary; a 0.8 folder with a stray `enrolled_by` reads as
          before (the 0.9 rules never run on 0.8); the format is known.

usage: python3 -I test09_agent_decider.py"""
import pathlib, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fixtures07 as f  # noqa: E402
import test08_decision as t8  # noqa: E402

F09 = "claims-snapshot/0.9"
AGENT = "agent-helpdesk-2"
ENROLLER = "enrolled-principal-7"


def by(**fields):
    """A subject mutator that sets decision.by's fields (value KeyError: delete that field)."""
    def go(S):
        for k, v in fields.items():
            if v is KeyError:
                S["decision"]["by"].pop(k, None)
            else:
                S["decision"]["by"][k] = v
    return go


def agent(**extra):
    return by(**{"kind": "agent", "principal": AGENT, "enrolled_by": ENROLLER, **extra})


def main():
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        f.keygen(tmp / "keys")

        def run(**kw):
            kw.setdefault("fmt", F09)
            return f.Run(t8.folder(tmp, **kw))

        def positive(name, what, kw, k5=("PASS",)):
            def case():
                r = run(**kw)
                fails = [k for k, s in r.status.items() if s == "FAIL"]
                ok = (r.rc == 0 and not fails and t8.no_trace(r) and r.status.get("K1") == "PASS" and r.has("K1", "profile decision")
                      and r.status.get("K11") == "PASS" and r.status.get("K13") == "PASS" and r.status.get("K5") in k5)
                f.report(name, ok, f"{what}: exit 0, no FAIL, K1 K11 K13 PASS", f"exit {r.rc}, FAIL {fails}, {r.summary}",
                         [r.text.get(k, "").split("\n")[0] for k in ("K1", "K5", "K11", "K13") if r.status.get(k) not in ("PASS", None)])
            f.case(name, case)

        positive("p1_agent_decider", "an agent's decision under its own principal, naming who enrolled it", {"subject": agent()})

        def reveal(S):
            agent()(S)
            S["decision"]["value"] = "revealed"
            S["basis"]["recommendation"] = "revealed"

        def reveal_rows(rows):
            rows[1]["text"] = rows[1]["text"].replace("was approve", "was revealed").replace("recommended approve", "recommended revealed")
        positive("p2_agent_break_glass_hash_only", "a break-glass reveal by an agent, held by the deciding organisation",
                 {"subject": reveal, "audit": reveal_rows, "held_by": "subject-org"}, k5=("WARN",))
        positive("p3_person_on_0_9", "a person's decision in the 0.8 shape, on 0.9", {})

        def k1case(name, rule, needle, kw):
            def case():
                r = run(**kw)
                ok = r.rc != 0 and r.status.get("K1") == "FAIL" and r.has("K1", needle) and t8.no_trace(r)
                f.report(name, ok, f"K1 FAIL, exit 1, the line names {needle!r} ({rule})", f"exit {r.rc}, K1 {r.status.get('K1')}",
                         [r.text.get("K1", "")[:300]])
            f.case(name, case)

        k1case("k1_agent_without_enrolled_by", "an agent's decider names who enrolled it", "subject.decision.by.enrolled_by",
               {"subject": agent(enrolled_by=KeyError)})
        k1case("k1_agent_enrolled_by_empty", "enrolled_by is non-empty", "subject.decision.by.enrolled_by empty", {"subject": agent(enrolled_by=" ")})
        k1case("k1_agent_enrolled_by_not_a_string", "enrolled_by is a string", "subject.decision.by.enrolled_by must be a string",
               {"subject": agent(enrolled_by=7)})
        k1case("k1_agent_enrolled_by_itself", "enrolled_by is never the agent's own principal", "the agent's own principal",
               {"subject": agent(enrolled_by=AGENT)})
        k1case("k1_agent_without_principal", "the agent's own principal is still required", "subject.decision.by.principal",
               {"subject": agent(principal=KeyError)})
        k1case("k1_person_with_enrolled_by", "only an agent's decider names who enrolled it", "enrolled_by is set on a person decider",
               {"subject": by(enrolled_by=ENROLLER)})
        k1case("k1_pipeline_with_enrolled_by", "only an agent's decider names who enrolled it", "enrolled_by is set on a pipeline decider",
               {"by_kind": "pipeline", "subject": by(enrolled_by=ENROLLER)})
        k1case("k1_unknown_kind_on_0_9", "an unknown kind still fails, naming the 0.9 vocabulary", "not in ['agent', 'person', 'pipeline']",
               {"subject": by(kind="committee")})
        k1case("k1_kind_case_sensitive", "the vocabulary is exact", "decision.by.kind='Agent'", {"subject": agent(kind="Agent")})

        def g1():
            r = run(fmt=t8.F08, subject=agent())
            ok = (r.rc != 0 and r.status.get("K1") == "FAIL" and r.has("K1", "decision.by.kind='agent' not in ['person', 'pipeline']")
                  and t8.no_trace(r))
            f.report("g1_agent_refused_on_0_8", ok, "a 0.8 folder naming agent: K1 FAIL with the 0.8 vocabulary", f"exit {r.rc}, K1 {r.status.get('K1')}",
                     [r.text.get("K1", "")[:300]])
        f.case("g1_agent_refused_on_0_8", g1)

        def g2():
            a = run(fmt=t8.F08)
            b = run(fmt=t8.F08, subject=by(enrolled_by=ENROLLER))
            fails = [k for k, s in b.status.items() if s == "FAIL"]
            ok = a.rc == b.rc == 0 and not fails and a.status == b.status
            f.report("g2_0_8_rules_unchanged", ok, "a 0.8 person decider with a stray enrolled_by: the same statuses as without it, exit 0",
                     f"exits {a.rc}/{b.rc}, FAIL {fails}")
        f.case("g2_0_8_rules_unchanged", g2)

        def g3():
            ok = F09 in f.check.FORMATS and t8.F08 in f.check.FORMATS and "decision" not in f.check.PROFILES and f.check.DECISION_DECIDERS == {"person", "pipeline"}
            f.report("g3_format_known", ok, "0.9 and 0.8 in FORMATS; PROFILES and the 0.8 deciders unchanged",
                     f"0.9 in FORMATS {F09 in f.check.FORMATS}, deciders {sorted(f.check.DECISION_DECIDERS)}")
        f.case("g3_format_known", g3)

    return f.finish("test09_agent_decider")


if __name__ == "__main__":
    sys.exit(main())
