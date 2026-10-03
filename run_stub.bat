@echo off
REM STUB mode: no AI model is called (for UI testing / emergency fallback). Results are labelled STUB.
set FAKE_LLM=1
call run.bat
