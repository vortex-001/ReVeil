"""Settings read from environment variables (see .env.example). No secrets are needed."""
import os

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
LLM_MODEL = os.getenv("LLM_MODEL", "qwen3:1.7b")
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT_S", "240"))
MAX_INPUT_CHARS = int(os.getenv("MAX_INPUT_CHARS", "6000"))
NUM_PREDICT = int(os.getenv("NUM_PREDICT", "600"))


def fake_llm() -> bool:
    """FAKE_LLM=1 -> STUB mode: no model is called. Results are labelled STUB everywhere."""
    return os.getenv("FAKE_LLM", "0") == "1"
