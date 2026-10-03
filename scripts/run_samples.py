"""Runs the 3 synthetic samples through the REAL pipeline and writes docs/RESULTS.md with whatever happens.
Usage (Ollama running):   python scripts/run_samples.py
Nothing here is hard-coded: if the model fails, the failure is recorded. Mode STUB is labelled."""
import datetime
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "backend"))
from app import attacker, config, hardening, pii, pipeline  # noqa: E402


def one(s):
    row = {"id": s["id"], "title": s["title"]}
    anon = pii.anonymize(s["text"], s["names"])
    row["anon"] = anon["text"]
    try:
        before = pipeline.analyse(anon["text"])
        edits = hardening.suggest(anon["text"])
        hard = hardening.apply_edits(anon["text"], edits)
        after = pipeline.analyse(hard)
        row.update(hard=hard, before=before, after=after, edits=edits)
    except (attacker.LLMError, attacker.Busy) as e:
        row["error"] = str(e)
    return row


def main():
    samples = json.load(open(os.path.join(ROOT, "samples", "samples.json"), encoding="utf-8"))
    rows = [one(s) for s in samples]
    mode = "STUB (no model called — NOT real model results)" if config.fake_llm() else "ollama / " + config.LLM_MODEL
    out = ["# Sample run results", "", "Generated: %s  " % datetime.datetime.now().isoformat(timespec="seconds"), "Mode: **%s**  " % mode,
           "Synthetic data only. Heuristic risk scores, not validated. These are single runs, not a benchmark.", "",
           "| Sample | Risk before | Risk after | Edits | AI clues before → after | Rejected claims (b/a) | Time b/a (s) |", "|---|---|---|---|---|---|---|"]
    for r in rows:
        if "error" in r:
            out.append("| %s | ERROR | ERROR | - | - | - | - |" % r["id"])
            continue
        b, a = r["before"], r["after"]
        out.append("| %s | %s (%d) | %s (%d) | %d | %d → %d | %d/%d | %s/%s |" % (r["id"], b["risk"]["level"], b["risk"]["score"], a["risk"]["level"],
                   a["risk"]["score"], len(r["edits"]), len(b["clues"]), len(a["clues"]), b["rejected"], a["rejected"], b["seconds"], a["seconds"]))
    for r in rows:
        out += ["", "## %s" % r["title"], ""]
        if "error" in r:
            out += ["**Run failed:** " + r["error"]]
            continue
        out += ["**Anonymized:**", "", "> " + r["anon"], "", "**Hardened:**", "", "> " + r["hard"], "", "**Remaining items after hardening:**", ""]
        out += ["- %s: \"%s\" (%s)" % (i["category"], i["quote"], i["source"]) for i in r["after"]["risk"]["items"]] or ["- none found (not a guarantee)"]
    path = os.path.join(ROOT, "docs", "RESULTS.md")
    open(path, "w", encoding="utf-8").write("\n".join(out) + "\n")
    print("wrote", path)


if __name__ == "__main__":
    main()
