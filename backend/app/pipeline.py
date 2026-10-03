"""Glue: analyse = attack + validate + risk.  harden = rule edits."""
import time

from . import attacker, hardening, risk


def analyse(text):
    t0 = time.time()
    res = attacker.attack(text)
    rule_items = hardening.suggest(text)
    rk = risk.assess(text, res["clues"], rule_items, res["likelihood"])
    return {
        "risk": rk,
        "clues": res["clues"],
        "rejected": res["rejected"],
        "rejected_claims": res.get("rejected_claims", []),
        "profile": res["profile"],
        "likelihood": res["likelihood"],
        "personas": res.get("personas", []),
        "mode": res["mode"],
        "seconds": round(time.time() - t0, 1)
    }
