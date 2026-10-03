"""Rule-based quasi-identifier detection AND contextual hardening (generalisation) edits."""
import re

REGIONS = {
    "Northern India": ["Chandigarh", "Mohali", "Panchkula", "Ludhiana", "Amritsar", "Jalandhar", "Patiala", "New Delhi", "Delhi", "Gurgaon",
                       "Gurugram", "Noida", "Jaipur", "Lucknow", "Dehradun", "Shimla", "Srinagar", "Punjab", "Haryana", "Himachal Pradesh",
                       "Rajasthan", "Uttar Pradesh"],
    "Western India": ["Mumbai", "Pune", "Ahmedabad", "Surat", "Nagpur", "Goa", "Maharashtra", "Gujarat"],
    "Southern India": ["Bengaluru", "Bangalore", "Chennai", "Hyderabad", "Kochi", "Coimbatore", "Madurai", "Mysuru", "Thiruvananthapuram",
                       "Karnataka", "Tamil Nadu", "Kerala", "Telangana", "Andhra Pradesh"],
    "Eastern India": ["Kolkata", "Bhubaneswar", "Patna", "Guwahati", "Ranchi", "West Bengal", "Odisha", "Bihar"],
    "Central India": ["Bhopal", "Indore", "Raipur", "Madhya Pradesh", "Chhattisgarh"],
}
CITY_TO_REGION = {c: r for r, cs in REGIONS.items() for c in cs}
CITY_RE = re.compile(r"\b(?:%s)\b" % "|".join(sorted(map(re.escape, CITY_TO_REGION), key=len, reverse=True)))

ORG_TYPES = {"hospital": "a hospital", "clinic": "a clinic", "university": "a university", "college": "a college", "school": "a school",
             "institute": "an institute", "bank": "a bank", "studio": "a studio", "laboratory": "a laboratory", "labs": "a laboratory",
             "foundation": "a non-profit", "academy": "an academy", "corporation": "a company", "company": "a company",
             "ltd": "a company", "inc": "a company"}
ORG_RE = re.compile(r"\b((?:[A-Z][\w&.'’-]*\s+){1,3})(Hospital|Clinic|University|College|School|Institute|Bank|Studio|Laboratory|Labs|Foundation|"
                    r"Academy|Corporation|Company|Pvt\.?\s+Ltd|Ltd|Inc)(?![\w])")
STOP_LEAD = {"the", "then", "at", "in", "he", "she", "they", "my", "our", "his", "her", "i", "we", "a", "an", "this", "that", "after",
             "before", "when", "while", "now", "today", "and", "but", "of", "from", "for", "to", "with"}

MONTHS = "January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sept|Sep|Oct|Nov|Dec"
DATE_RE = re.compile(r"(?:\b\d{1,2}(?:st|nd|rd|th)?\s+)?\b(?:%s)\b\.?\s+(?:\d{1,2}(?:st|nd|rd|th)?,?\s+)?((?:19|20)\d{2})\b" % MONTHS)
YEAR_RE = re.compile(r"\b(?:19|20)\d{2}\b")

AGE_HYPHEN = re.compile(r"\b(\d{2})-year-old\b")
AGE_YEARS = re.compile(r"\b(\d{2})\s+years?\s+old\b")
AGE_AGED = re.compile(r"\baged\s+(\d{2})\b")
AGE_IM = re.compile(r"\b(I'm|I am)\s+(\d{2})\b")

ROLE_RE = re.compile(r"\b(?:senior|chief|head|lead|principal)\s+(?:[a-z]+\s+)?(surgeon|doctor|physician|engineer|professor|lawyer|manager|designer|"
                     r"developer|teacher|nurse|journalist|researcher|scientist|analyst|architect|consultant)\b")
WIN_RE = re.compile(r"\bwon\s+(?:the|a|an)\s+((?:(?!a\b|an\b|the\b)[A-Za-z'’-]+\s+){1,6}?)(competition|award|prize|championship|tournament|contest|medal)\b")


def era(year: int) -> str:
    d = (year // 10) * 10
    pos = year % 10
    return "the %s %ds" % ("early" if pos <= 3 else "mid" if pos <= 6 else "late", d)


def decade(age: int, first_person=False) -> str:
    if age < 20:
        return "in my teens" if first_person else "in their teens"
    return ("in my %ds" if first_person else "in their %ds") % ((age // 10) * 10)


def _cands(text):
    c = []

    def add(start, end, repl, rule, cat):
        c.append({"original": text[start:end], "replacement": repl, "rule": rule, "category": cat, "start": start, "end": end})

    for m in AGE_YEARS.finditer(text):
        if 13 <= int(m.group(1)) <= 99:
            add(m.start(), m.end(), decade(int(m.group(1))), "age -> decade", "age")
    for m in AGE_HYPHEN.finditer(text):
        if 13 <= int(m.group(1)) <= 99:
            add(m.start(), m.end(), "%d-something" % ((int(m.group(1)) // 10) * 10), "age -> decade", "age")
    for m in AGE_AGED.finditer(text):
        if 13 <= int(m.group(1)) <= 99:
            add(m.start(), m.end(), decade(int(m.group(1))), "age -> decade", "age")
    for m in AGE_IM.finditer(text):
        if 13 <= int(m.group(2)) <= 99:
            add(m.start(), m.end(), "%s %s" % (m.group(1), decade(int(m.group(2)), True)), "age -> decade", "age")
    for m in DATE_RE.finditer(text):
        add(m.start(), m.end(), era(int(m.group(1))), "date -> era", "date_event")
    for m in YEAR_RE.finditer(text):
        add(m.start(), m.end(), era(int(m.group(0))), "year -> era", "date_event")
    for m in CITY_RE.finditer(text):
        add(m.start(), m.end(), CITY_TO_REGION[m.group(0)], "location -> region", "location")
    for m in ORG_RE.finditer(text):
        lead = m.group(1)
        words = lead.split()
        skip = 0
        while skip < len(words) - 1 and words[skip].lower() in STOP_LEAD:
            skip += 1
        start = m.start() + lead.index(words[skip]) if skip else m.start()
        if skip:  # keep position of the first kept word (handle repeated words safely)
            start = m.start() + len(" ".join(words[:skip])) + 1
        suffix = m.group(2).split()[-1].lower().rstrip(".")
        add(start, m.end(), ORG_TYPES.get(suffix, "an organisation"), "organisation -> type", "employer")
    for m in ROLE_RE.finditer(text):
        add(m.start(), m.end(), m.group(1), "role -> generic", "role")
    for m in WIN_RE.finditer(text):
        add(m.start(), m.end(), "won a " + m.group(2), "achievement -> generic", "achievement")
    return c


def suggest(text):
    """Quasi-identifiers found by rules, each with a proposed generalisation. Overlaps resolved (longer wins)."""
    cands = sorted(_cands(text), key=lambda x: (x["start"], -(x["end"] - x["start"])))
    out, last = [], -1
    for e in cands:
        if e["start"] >= last:
            out.append(e)
            last = e["end"]
    for i, e in enumerate(out):
        e["id"] = i
    return out


def apply_edits(text, edits):
    """Apply accepted edits from end to start; skip any edit whose original no longer matches (stale)."""
    out = text
    for e in sorted(edits, key=lambda x: x["start"], reverse=True):
        if out[e["start"]:e["end"]] == e["original"]:
            out = out[: e["start"]] + e["replacement"] + out[e["end"]:]
    return out
