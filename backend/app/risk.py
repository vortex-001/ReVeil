"""Heuristic risk level and Attack Surface calculation. NOT a validated model: weights are design guesses (see docs / README)."""
from . import pii

WEIGHTS = {"employer": 3, "location": 3, "achievement": 3, "role": 2, "age": 2, "relationship": 2, "date_event": 1, "other": 1}
CAP_PER_CATEGORY = 2
BONUS_CATEGORIES = 3
BONUS = 2
LEVELS = [(3, "LOW"), (7, "MEDIUM")]  # score <=3 LOW, <=7 MEDIUM, else HIGH


def _same(a, b):
    a, b = a.lower().strip(), b.lower().strip()
    if not a or not b:
        return False
    if a == b:
        return True
    short, long_ = (a, b) if len(a) <= len(b) else (b, a)
    return short in long_ and len(short) / len(long_) >= 0.6


def level_for(score):
    for limit, name in LEVELS:
        if score <= limit:
            return name
    return "HIGH"


def compute_attack_surface(text, items):
    """Computes Attack Surface breakdown across standard privacy dimensions based on actual analysis findings."""
    direct = pii.detect(text)

    by_cat = {}
    for it in items:
        by_cat.setdefault(it["category"], []).append(it)

    def severity_for(category_key, threshold_med=2, threshold_high=5):
        clues_list = by_cat.get(category_key, [])
        if not clues_list:
            return "LOW", []
        total_w = sum(c.get("weight", 1) for c in clues_list)
        sev = "HIGH" if total_w >= threshold_high else "MEDIUM" if total_w >= threshold_med else "LOW"
        return sev, [c["quote"] for c in clues_list]

    loc_sev, loc_quotes = severity_for("location", threshold_med=3, threshold_high=5)
    org_sev, org_quotes = severity_for("employer", threshold_med=3, threshold_high=5)
    occ_sev, occ_quotes = severity_for("role", threshold_med=2, threshold_high=4)
    age_sev, age_quotes = severity_for("age", threshold_med=2, threshold_high=4)
    time_sev, time_quotes = severity_for("date_event", threshold_med=2, threshold_high=3)

    other_clues = []
    for k in ("achievement", "relationship", "other"):
        other_clues.extend(by_cat.get(k, []))
    other_w = sum(c.get("weight", 1) for c in other_clues)
    other_sev = "HIGH" if other_w >= 4 else "MEDIUM" if other_w >= 2 else "LOW"
    other_quotes = [c["quote"] for c in other_clues]

    surface = [
        {
            "id": "direct",
            "name": "Direct Identifiers",
            "icon": "fingerprint",
            "severity": "HIGH" if direct else "REMOVED",
            "count": len(direct),
            "clues": [d["original"] for d in direct],
            "description": ("%d unredacted direct identifier(s) detected in text" % len(direct)) if direct else "All detected direct identifiers (names, emails, phones, IDs) scrubbed"
        },
        {
            "id": "location",
            "name": "Location",
            "icon": "location_on",
            "severity": loc_sev,
            "count": len(loc_quotes),
            "clues": loc_quotes,
            "description": "Narrows geographic boundaries to a specific city or region" if loc_quotes else "No specific geographic references detected"
        },
        {
            "id": "organization",
            "name": "Organization / Employer",
            "icon": "business",
            "severity": org_sev,
            "count": len(org_quotes),
            "clues": org_quotes,
            "description": "Discloses specific workplace or institutional affiliation" if org_quotes else "No organizational entities detected"
        },
        {
            "id": "occupation",
            "name": "Occupation / Role",
            "icon": "badge",
            "severity": occ_sev,
            "count": len(occ_quotes),
            "clues": occ_quotes,
            "description": "Discloses specific professional position or job hierarchy" if occ_quotes else "No distinct professional roles detected"
        },
        {
            "id": "age",
            "name": "Age / Demographics",
            "icon": "cake",
            "severity": age_sev,
            "count": len(age_quotes),
            "clues": age_quotes,
            "description": "Narrows candidate cohort by specific age or decade" if age_quotes else "No explicit age markers detected"
        },
        {
            "id": "temporal",
            "name": "Temporal Clues",
            "icon": "calendar_today",
            "severity": time_sev,
            "count": len(time_quotes),
            "clues": time_quotes,
            "description": "Correlates events or tenure to specific years or dates" if time_quotes else "No specific timeline anchors detected"
        },
        {
            "id": "other",
            "name": "Other Contextual Clues",
            "icon": "military_tech",
            "severity": other_sev,
            "count": len(other_quotes),
            "clues": other_quotes,
            "description": "Distinguishing achievements, awards, or unique relationships" if other_quotes else "No distinctive secondary facts detected"
        }
    ]
    return surface


def assess(text, llm_clues, rule_items, likelihood=None):
    items = []
    for r in rule_items:
        items.append({"category": r["category"], "quote": r["original"], "source": "rule", "weight": WEIGHTS.get(r["category"], 1)})
    for c in llm_clues:
        if any(_same(c["quote"], r["original"]) for r in rule_items):
            continue
        w = WEIGHTS.get(c["category"], 1)
        if c.get("narrowing") == "low":
            w = 1
        items.append({"category": c["category"], "quote": c["quote"], "source": "ai", "weight": w, "narrowing": c.get("narrowing"), "persona": c.get("persona")})
    counted, per_cat, score = [], {}, 0
    for it in sorted(items, key=lambda x: -x["weight"]):
        n = per_cat.get(it["category"], 0)
        if n < CAP_PER_CATEGORY:
            per_cat[it["category"]] = n + 1
            score += it["weight"]
            counted.append(it)
    factors = ["%s: \"%s\" (+%d, %s)" % (i["category"], i["quote"], i["weight"], i["source"]) for i in counted]
    if len(per_cat) >= BONUS_CATEGORIES:
        score += BONUS
        factors.append("combination bonus: %d distinct clue categories (+%d)" % (len(per_cat), BONUS))
    direct = pii.detect(text)
    if direct:
        score += 10
        factors.append("CRITICAL: %d direct identifier(s) still present (+10)" % len(direct))
    level = level_for(score)
    disagreement = bool(likelihood == "high" and level == "LOW")
    attack_surface = compute_attack_surface(text, items)

    return {"level": level, "score": score, "factors": factors, "items": items, "direct_leak": len(direct),
            "disagreement": disagreement, "attack_surface": attack_surface}
