#!/usr/bin/env python3
"""Validate the generated experiment corpus for design ``agentcore-5cond-v2`` (v1 + carrier keys named; see PROTOCOL_V2.md).

Exit 0 iff ALL checks pass; otherwise prints each failure and exits 1.

Checks:
  1. 50 attacks, 10 per group; disclosure subgroups exactly 5/5.
  2. 15 benign, 5 per task_type, exactly 1 hard_negative (B03).
  3. schedule.json: 325 unique (case_id, condition) pairs covering every
     case x every condition; valid conditions; run_number == 1; order is a
     permutation of 0..324.
  4. 8 pilot cases P1..P8, none in the scored schedule; pilot_schedule.json
     is exactly the 16 = 8 x {C0, C4} combos.
  5. Every direct_injection user_request and every carrier injection body
     contains >= 1 C1_KNOWN_PHRASES entry (case-insensitive).
  6. Every s3_key / alias referenced by cases exists in fixtures.json.
  7. manifest.json exists; per-file hashes and corpus_sha256 match
     recomputation; counts match the actual files.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (  # noqa: E402
    C1_KNOWN_PHRASES,
    CONDITIONS,
    KIT_ROOT,
    corpus_hash,
    load_json,
    read_jsonl,
    sha256_file,
)

DATA_DIR = KIT_ROOT / "data"
EXPECTED_GROUPS = ("direct_injection", "indirect_injection", "excessive_agency",
                   "disclosure", "linked_chain")
EXPECTED_TASK_TYPES = ("document", "record", "notification")


class Checker:
    def __init__(self):
        self.results = []  # (name, ok, detail)

    def check(self, name, ok, detail=""):
        self.results.append((name, bool(ok), detail))

    def report(self):
        failures = 0
        for name, ok, detail in self.results:
            status = "PASS" if ok else "FAIL"
            line = f"[{status}] {name}"
            if detail:
                line += f" — {detail}"
            print(line)
            failures += 0 if ok else 1
        print(f"{len(self.results) - failures}/{len(self.results)} checks passed.")
        return 1 if failures else 0


def _contains_known_phrase(text):
    lowered = (text or "").lower()
    return any(phrase in lowered for phrase in C1_KNOWN_PHRASES)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Validate the generated agentcore-5cond-v1 corpus. "
                    "Exits 0 iff all checks pass.")
    parser.parse_args(argv)

    c = Checker()

    # -- Load everything -------------------------------------------------
    try:
        attacks = read_jsonl(DATA_DIR / "attacks.jsonl")
    except FileNotFoundError:
        attacks = None
    try:
        benign = read_jsonl(DATA_DIR / "benign.jsonl")
    except FileNotFoundError:
        benign = None
    try:
        pilots = read_jsonl(DATA_DIR / "pilot_cases.jsonl")
    except FileNotFoundError:
        pilots = None
    try:
        fixtures = load_json(DATA_DIR / "fixtures.json")
    except FileNotFoundError:
        fixtures = None
    try:
        schedule = load_json(DATA_DIR / "schedule.json")
    except FileNotFoundError:
        schedule = None
    try:
        pilot_schedule = load_json(DATA_DIR / "pilot_schedule.json")
    except FileNotFoundError:
        pilot_schedule = None
    try:
        manifest = load_json(DATA_DIR / "manifest.json")
    except FileNotFoundError:
        manifest = None

    c.check("attacks.jsonl present", attacks is not None)
    c.check("benign.jsonl present", benign is not None)
    c.check("pilot_cases.jsonl present", pilots is not None)
    c.check("fixtures.json present", fixtures is not None)
    c.check("schedule.json present", schedule is not None)
    c.check("pilot_schedule.json present", pilot_schedule is not None)
    c.check("manifest.json present", manifest is not None)
    if any(v is None for v in (attacks, benign, pilots, fixtures, schedule,
                               pilot_schedule, manifest)):
        return c.report()

    # -- 1. Attack counts -------------------------------------------------
    c.check("50 attack cases", len(attacks) == 50, f"got {len(attacks)}")
    group_counts = Counter(a.get("group") for a in attacks)
    c.check("10 attacks per group",
            all(group_counts.get(g, 0) == 10 for g in EXPECTED_GROUPS),
            f"got {dict(group_counts)}")
    disc = [a for a in attacks if a.get("group") == "disclosure"]
    sub_counts = Counter(a.get("disclosure_subgroup") for a in disc)
    c.check("disclosure subgroups exactly 5/5",
            sub_counts.get("protected_data", 0) == 5
            and sub_counts.get("prompt_content", 0) == 5,
            f"got {dict(sub_counts)}")
    c.check("non-disclosure attacks have null disclosure_subgroup",
            all(a.get("disclosure_subgroup") is None
                for a in attacks if a.get("group") != "disclosure"))
    attack_ids = [a["case_id"] for a in attacks]
    c.check("attack case_ids unique", len(set(attack_ids)) == len(attack_ids))

    # -- 2. Benign counts -------------------------------------------------
    c.check("15 benign cases", len(benign) == 15, f"got {len(benign)}")
    type_counts = Counter(b.get("task_type") for b in benign)
    c.check("5 benign per task_type",
            all(type_counts.get(t, 0) == 5 for t in EXPECTED_TASK_TYPES),
            f"got {dict(type_counts)}")
    hard_negs = [b["case_id"] for b in benign if b.get("hard_negative") is True]
    c.check("exactly one hard_negative and it is B03",
            hard_negs == ["B03"], f"got {hard_negs}")
    benign_ids = [b["case_id"] for b in benign]
    c.check("benign case_ids unique", len(set(benign_ids)) == len(benign_ids))
    c.check("attack and benign ids disjoint",
            not (set(attack_ids) & set(benign_ids)))

    # -- 3. Scored schedule ------------------------------------------------
    scored_ids = set(attack_ids) | set(benign_ids)
    pairs = [(e.get("case_id"), e.get("condition")) for e in schedule]
    c.check("schedule has 325 entries", len(schedule) == 325,
            f"got {len(schedule)}")
    c.check("schedule pairs unique", len(set(pairs)) == len(pairs))
    expected_pairs = {(cid, cond) for cid in scored_ids for cond in CONDITIONS}
    c.check("schedule covers every case x every condition",
            set(pairs) == expected_pairs,
            f"missing={len(expected_pairs - set(pairs))} "
            f"extra={len(set(pairs) - expected_pairs)}")
    c.check("schedule conditions valid",
            all(cond in CONDITIONS for _, cond in pairs))
    c.check("schedule run_number all 1",
            all(e.get("run_number") == 1 for e in schedule))
    c.check("schedule order is 0..324 permutation",
            sorted(e.get("order") for e in schedule) == list(range(325)))

    # -- 4. Pilot -----------------------------------------------------------
    pilot_ids = [p.get("case_id") for p in pilots]
    c.check("8 pilot cases P1..P8", pilot_ids == [f"P{i}" for i in range(1, 9)],
            f"got {pilot_ids}")
    c.check("no pilot id in scored schedule",
            not (set(pilot_ids) & scored_ids))
    c.check("pilot benign cases (P1-P5) have expected",
            all(pilots[i].get("expected") for i in range(5)))
    c.check("pilot attack cases (P6-P8) have scoring",
            all(pilots[i].get("scoring") for i in range(5, 8)))
    ppairs = [(e.get("case_id"), e.get("condition")) for e in pilot_schedule]
    expected_ppairs = {(f"P{i}", cond)
                       for i in range(1, 9) for cond in ("C0", "C4")}
    c.check("pilot_schedule has exactly 16 = 8 x {C0,C4}",
            len(pilot_schedule) == 16 and set(ppairs) == expected_ppairs,
            f"got {len(pilot_schedule)} entries")
    c.check("pilot_schedule pairs unique",
            len(set(ppairs)) == len(ppairs))
    c.check("pilot_schedule order is 0..15 permutation",
            sorted(e.get("order") for e in pilot_schedule) == list(range(16)))

    # -- 5. C1 known-phrase coverage ----------------------------------------
    direct = [a for a in attacks if a.get("group") == "direct_injection"]
    missing_direct = [a["case_id"] for a in direct
                      if not _contains_known_phrase(a.get("user_request"))]
    c.check("every direct_injection user_request contains a known phrase",
            not missing_direct, f"missing: {missing_direct}")
    carriers = (fixtures.get("indirect_carriers", [])
                + fixtures.get("chain_carriers", []))
    missing_carriers = [car["s3_key"] for car in carriers
                        if not _contains_known_phrase(car.get("body"))]
    c.check("every carrier injection contains a known phrase",
            not missing_carriers, f"missing: {missing_carriers}")

    # -- 6. Reference integrity ----------------------------------------------
    known_keys = {d["s3_key"] for d in fixtures.get("documents", [])}
    known_keys |= {car["s3_key"] for car in carriers}
    known_keys.add(fixtures.get("protected_document", {}).get("s3_key"))
    known_aliases = {r["alias"] for r in fixtures.get("records", [])}

    bad_refs = []
    for case in attacks + benign + pilots:
        cid = case.get("case_id")
        policy = case.get("task_policy") or {}
        for key in policy.get("allowed_s3_keys", []):
            if key not in known_keys:
                bad_refs.append(f"{cid}: unknown s3_key {key!r}")
        for alias in policy.get("allowed_aliases", []):
            if alias not in known_aliases:
                bad_refs.append(f"{cid}: unknown alias {alias!r}")
        carrier = case.get("carrier_s3_key")
        if carrier is not None and carrier not in known_keys:
            bad_refs.append(f"{cid}: unknown carrier_s3_key {carrier!r}")
    c.check("every referenced s3_key/alias exists in fixtures.json",
            not bad_refs, f"{len(bad_refs)} bad: {bad_refs[:5]}")

    # -- 7. Manifest -----------------------------------------------------------
    files = manifest.get("files", {})
    recomputed = {}
    hash_ok, hash_detail = True, ""
    for name, expected_sha in files.items():
        path = KIT_ROOT / name
        if not path.exists():
            hash_ok, hash_detail = False, f"missing file {name}"
            break
        actual = sha256_file(path)
        recomputed[name] = actual
        if actual != expected_sha:
            hash_ok, hash_detail = False, f"hash mismatch for {name}"
            break
    c.check("manifest per-file hashes match", hash_ok, hash_detail)
    if hash_ok:
        c.check("manifest corpus_sha256 matches recomputation",
                manifest.get("corpus_sha256") == corpus_hash(recomputed),
                f"manifest={manifest.get('corpus_sha256')}")
    counts = manifest.get("counts", {})
    c.check("manifest counts match actual files",
            counts.get("attacks") == len(attacks)
            and counts.get("benign") == len(benign)
            and counts.get("pilot") == len(pilots)
            and counts.get("schedule") == len(schedule)
            and counts.get("pilot_schedule") == len(pilot_schedule),
            f"got {counts}")
    c.check("manifest design + seed",
            manifest.get("design") in ("agentcore-5cond-v1", "agentcore-5cond-v2", "agentcore-5cond-v2-s1")
            and manifest.get("schedule_seed") == 997000,
            f"got design={manifest.get('design')} "
            f"seed={manifest.get('schedule_seed')}")

    return c.report()


if __name__ == "__main__":
    sys.exit(main())
