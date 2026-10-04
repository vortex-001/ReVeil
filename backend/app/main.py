"""ReVeil API (FastAPI). Serves the single-page UI too, so there is nothing else to run."""
import json
import os
import urllib.request

from fastapi import Body, FastAPI, HTTPException, UploadFile, File
from fastapi.responses import FileResponse

from . import attacker, config, extractor, hardening, pii, pipeline

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
app = FastAPI(title="ReVeil", description="Privacy stress-testing tool. Not a guarantee of anonymity.")


def _text(payload):
    text = payload.get("text", "")
    if not isinstance(text, str) or not text.strip():
        raise HTTPException(400, "Please provide some text.")
    if len(text) > config.MAX_INPUT_CHARS:
        raise HTTPException(400, "Text too long (max %d characters)." % config.MAX_INPUT_CHARS)
    return text


@app.get("/")
def index():
    return FileResponse(os.path.join(ROOT, "frontend", "index.html"))


@app.get("/reveil-logo.png")
def logo():
    return FileResponse(os.path.join(ROOT, "frontend", "reveil-logo.png"))


@app.get("/app.js")
def app_js():
    return FileResponse(os.path.join(ROOT, "frontend", "app.js"), media_type="application/javascript")


@app.get("/api/health")
def health():
    info = {"model": config.LLM_MODEL, "mode": "STUB" if config.fake_llm() else "ollama", "ollama": False, "model_ready": False,
            "max_chars": config.MAX_INPUT_CHARS}
    if not config.fake_llm():
        try:
            with urllib.request.urlopen(config.OLLAMA_URL + "/api/tags", timeout=3) as r:
                names = [m.get("name", "") for m in json.loads(r.read().decode()).get("models", [])]
            info["ollama"] = True
            info["model_ready"] = any(n == config.LLM_MODEL or n.startswith(config.LLM_MODEL + ":") or n.split(":")[0] == config.LLM_MODEL for n in names)
        except Exception:
            pass
    return info


@app.get("/api/samples")
def samples():
    with open(os.path.join(ROOT, "samples", "samples.json"), encoding="utf-8") as f:
        return json.load(f)


@app.post("/api/anonymize")
def anonymize(payload: dict = Body(...)):
    text = _text(payload)
    names = payload.get("names") or []
    names = [str(n) for n in names][:20] if isinstance(names, list) else []
    return pii.anonymize(text, names)


@app.post("/api/attack")
def attack(payload: dict = Body(...)):
    text = _text(payload)
    try:
        return pipeline.analyse(text)
    except attacker.Busy as e:
        raise HTTPException(429, str(e))
    except attacker.LLMError as e:
        raise HTTPException(502, str(e))


@app.get("/api/attack/progress")
def attack_progress():
    return attacker.get_progress()


@app.post("/api/harden")
def harden(payload: dict = Body(...)):
    return {"edits": hardening.suggest(_text(payload))}


@app.post("/api/apply")
def apply(payload: dict = Body(...)):
    text = _text(payload)
    edits = payload.get("edits") or []
    clean = []
    for e in edits if isinstance(edits, list) else []:
        try:
            clean.append({"original": str(e["original"]), "replacement": str(e["replacement"]), "start": int(e["start"]), "end": int(e["end"])})
        except Exception:
            continue
    return {"text": hardening.apply_edits(text, clean)}
 
 
@app.post("/api/extract")
async def extract_file(file: UploadFile = File(...)):
    try:
        content = await file.read()
        return extractor.extract_text_from_bytes(file.filename or "upload.txt", content)
    except extractor.ExtractionError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, f"Extraction failed: {str(e)}")
