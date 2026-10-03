"""Stage 1-2: detect and remove DIRECT identifiers (regex + user name list + optional GLiNER)."""
import os
import re

DIRECT_PATTERNS = [
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("URL", re.compile(r"(?:https?://|www\.)[^\s<>()]+")),
    ("ID", re.compile(r"(?<!\d)\d{4}\s\d{4}\s\d{4}(?!\d)")),   # Aadhaar-like (4-4-4)
    ("ID", re.compile(r"(?<!\d)\d{12}(?!\d)")),               # Aadhaar-like (12 digits)
    ("ID", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),            # PAN-like
    ("PHONE", re.compile(r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")),
]
TITLE_NAME = re.compile(r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Shri|Smt)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?")
SKIP_TOKENS = {"the", "and", "mr", "mrs", "ms", "dr", "prof"}
_GLINER = None


def _resolve(spans):
    """Sort and drop overlaps (earlier start wins, then longer)."""
    spans = sorted(spans, key=lambda s: (s[1], -(s[2] - s[1])))
    out, last = [], -1
    for s in spans:
        if s[1] >= last:
            out.append(s)
            last = s[2]
    return out


def _name_spans(text, names):
    tokens = set()
    for n in names or []:
        n = n.strip()
        if len(n) < 2:
            continue
        tokens.add(n)
        for part in n.replace(".", " ").split():
            if len(part) >= 3 and part.lower() not in SKIP_TOKENS:
                tokens.add(part)
    spans = []
    for t in sorted(tokens, key=len, reverse=True):
        for m in re.finditer(r"(?<!\w)" + re.escape(t) + r"(?!\w)", text, re.I):
            spans.append(("NAME", m.start(), m.end(), "name-list"))
    for m in TITLE_NAME.finditer(text):
        spans.append(("NAME", m.start(), m.end(), "title-pattern"))
    return spans


def _gliner_spans(text):
    """OPTIONAL: set USE_GLINER=1 and `pip install gliner`. Untested on the target laptop."""
    global _GLINER
    if os.getenv("USE_GLINER") != "1":
        return []
    try:
        if _GLINER is None:
            from gliner import GLiNER
            _GLINER = GLiNER.from_pretrained(os.getenv("GLINER_MODEL", "urchade/gliner_multi_pii-v1"))
        ents = _GLINER.predict_entities(text, ["person"], threshold=0.5)
        return [("NAME", e["start"], e["end"], "gliner") for e in ents]
    except Exception:
        return []


def detect(text, names=None):
    spans = []
    for typ, rx in DIRECT_PATTERNS:
        for m in rx.finditer(text):
            spans.append((typ, m.start(), m.end(), "regex"))
    spans += _name_spans(text, names)
    spans += _gliner_spans(text)
    return [{"type": t, "start": s, "end": e, "original": text[s:e], "source": src} for t, s, e, src in _resolve(spans)]


def anonymize(text, names=None):
    ents = detect(text, names)
    out = text
    for e in sorted(ents, key=lambda x: x["start"], reverse=True):  # end -> start keeps offsets valid
        out = out[: e["start"]] + "[%s]" % e["type"] + out[e["end"]:]
    return {"text": out, "entities": ents}
