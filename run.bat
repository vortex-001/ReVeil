@echo off
REM ReVeil launcher (Windows). Run from the project folder:  run.bat
if not exist .venv (
  echo Creating virtual environment...
  python -m venv .venv
)
call .venv\Scripts\activate
pip install -q -r requirements.txt
echo.
echo ReVeil is starting at http://127.0.0.1:8000   (Ctrl+C to stop)
echo Make sure Ollama is running and you ran:  ollama pull qwen3:1.7b
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
