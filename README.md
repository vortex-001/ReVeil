# ReVeil — AI-Powered Privacy Risk Analyzer

> *Reveal what anonymity hides.*

**ReVeil is a privacy stress-testing tool. It does NOT guarantee anonymity, privacy, or legal compliance.**
A “LOW” result means “our attacker found little” — never “this document is safe”.

## The question

After obvious personal information is removed from a document, can someone still figure out who it is about?

```
Original : Rahul Sharma is 25 years old and lives in Chandigarh. He works at ABC Hospital and won the photography competition in 2024.
Anonymized: [NAME] is 25 years old and lives in Chandigarh. He works at ABC Hospital and won the photography competition in 2024.
Hardened  : [NAME] is in their 20s and lives in Northern India. He works at a hospital and won a competition in the mid 2020s.
```
(Synthetic example — all people and organisations are fictional.)

## How it works

1. **Remove direct identifiers** — emails, phones, ID numbers, URLs (regex), names (your name list + title patterns; optional GLiNER).
2. **AI attack** — a small **open-weight LLM running locally** (default `qwen3:1.7b` via [Ollama](https://ollama.com)) lists details that could narrow down who the text is about.
3. **Quote-or-drop validation** — every clue must quote text that really exists in the document; invented clues are discarded and counted.
4. **Estimated risk** — a transparent heuristic (weights in `backend/app/risk.py`) over verified clues + rule-detected quasi-identifiers. *Not a validated model.*
5. **Contextual hardening** — rule-based generalisations (city → region, age → decade, year → era, employer → type…). You accept/reject each edit.
6. **Re-test** — the same attacker runs on the hardened text; the UI shows before vs after and exports a Markdown report.

Everything runs on your machine. Nothing is stored; no telemetry; no third-party API.

## Quick start (Windows)

Requirements: Python 3.11/3.12, [Ollama](https://ollama.com), Git.

```bat
ollama pull qwen3:1.7b
run.bat
```
Open http://127.0.0.1:8000. The chip at the top turns green when the model is ready.
`run_stub.bat` starts **STUB mode** (no model called; every result is labelled STUB) for UI testing only.

Settings (optional): copy `.env.example`; see variables `LLM_MODEL`, `OLLAMA_URL`, `LLM_TIMEOUT_S`, `MAX_INPUT_CHARS`, `NUM_PREDICT`.

## Tests and sample run

```bat
python backend\tests\test_core.py      :: unit tests (no model needed)
python scripts\run_samples.py          :: runs 3 synthetic docs through the real pipeline -> docs\RESULTS.md
```

## Security notes

- Uploaded text is treated as **untrusted**: delimited as data in the prompt, no tools for the model, strict JSON validation, plain-text rendering in the UI (no HTML injection), input length cap, one analysis at a time.
- Do **not** paste real sensitive documents into any hosted deployment of this tool.

## Limitations (please read)

- Small models have limited knowledge and can miss clues or return invalid output (we retry once, then show an error).
- Name removal relies on your name list, title patterns (Dr./Mr./…) and optional GLiNER — **unlisted names can be missed**. Review the anonymized text.
- Rules cover Indian cities/states and common patterns only; English text only.
- The risk score is a heuristic, uncalibrated. Results on 3 synthetic samples are **not a benchmark**; see `docs/RESULTS.md` for the actual run.
- Hardening reduces detail and cannot guarantee anonymity.

## Models and credits

| Component | Used for | License |
|---|---|---|
| Qwen3 (via Ollama) | AI attacker | check the model card on the Ollama library / Hugging Face |
| GLiNER (optional) | name detection | check the checkpoint's model card |
| FastAPI, Uvicorn | web server | see their repositories |

No model was trained or fine-tuned for this project.

## License

Apache-2.0 (see `LICENSE`).
