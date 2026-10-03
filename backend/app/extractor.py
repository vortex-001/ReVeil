"""Document ingestion and text extraction module for ReVeil.

Supports:
- TXT, MD, JSON, LOG: Direct text reading with UTF-8 / Latin-1 fallback
- PDF: Selectable text extraction via pypdf
- DOCX: Paragraph and table text extraction via python-docx
- DOC: Graceful guidance to convert to DOCX/PDF
- PNG, JPG, JPEG: Local OCR via Tesseract (if locally installed) with clear guidance
"""
import io
import os
import shutil

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB limit


class ExtractionError(Exception):
    pass


def is_ocr_available() -> bool:
    """Check if local Tesseract OCR binary is available."""
    if shutil.which("tesseract"):
        return True
    common_paths = [
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        os.path.expanduser(r"~\AppData\Local\Programs\Tesseract-OCR\tesseract.exe"),
    ]
    return any(os.path.isfile(p) for p in common_paths)


def extract_text_from_bytes(filename: str, content: bytes) -> dict:
    """Extract readable text from uploaded file bytes without logging content or writing to disk.

    Returns:
        dict: {"text": str, "method": str, "char_count": int, "filename": str}
    """
    if not content:
        raise ExtractionError("Uploaded file is empty.")

    if len(content) > MAX_FILE_SIZE:
        raise ExtractionError("File size exceeds 10 MB limit.")

    ext = os.path.splitext(filename)[1].lower()

    if ext in [".txt", ".md", ".json", ".log"]:
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = content.decode("latin-1")
            except Exception as e:
                raise ExtractionError(f"Could not decode text file: {e}")
        clean_text = text.strip()
        if not clean_text:
            raise ExtractionError("Text document contains no readable text.")
        return {
            "text": clean_text,
            "method": "Direct Text Read",
            "char_count": len(clean_text),
            "filename": filename,
        }

    elif ext == ".pdf":
        try:
            import pypdf

            reader = pypdf.PdfReader(io.BytesIO(content))
            pages = []
            for page in reader.pages:
                t = page.extract_text()
                if t and t.strip():
                    pages.append(t.strip())
            full_text = "\n\n".join(pages).strip()
            if not full_text:
                raise ExtractionError(
                    "No selectable text found in PDF. If this is a scanned document, OCR is required."
                )
            return {
                "text": full_text,
                "method": "PDF Text Extraction",
                "char_count": len(full_text),
                "filename": filename,
            }
        except ExtractionError:
            raise
        except Exception as e:
            raise ExtractionError(f"Failed to extract text from PDF: {str(e)}")

    elif ext == ".docx":
        try:
            import docx

            doc = docx.Document(io.BytesIO(content))
            parts = [p.text.strip() for p in doc.paragraphs if p.text.strip()]
            for table in doc.tables:
                for row in table.rows:
                    row_txt = " | ".join(c.text.strip() for c in row.cells if c.text.strip())
                    if row_txt:
                        parts.append(row_txt)
            full_text = "\n\n".join(parts).strip()
            if not full_text:
                raise ExtractionError("No readable text found in DOCX document.")
            return {
                "text": full_text,
                "method": "DOCX Text Extraction",
                "char_count": len(full_text),
                "filename": filename,
            }
        except ExtractionError:
            raise
        except Exception as e:
            raise ExtractionError(f"Failed to extract text from DOCX: {str(e)}")

    elif ext == ".doc":
        raise ExtractionError(
            "Legacy binary .doc format is not supported directly. Please re-save as .docx, .pdf, or .txt, or paste the text directly."
        )

    elif ext in [".png", ".jpg", ".jpeg"]:
        if not is_ocr_available():
            raise ExtractionError(
                "Local OCR requires Tesseract installed on this machine (e.g. 'winget install UB-Mannheim.TesseractOCR'). "
                "Cloud OCR APIs are not used to guarantee privacy."
            )
        try:
            import pytesseract
            from PIL import Image

            common_paths = [
                r"C:\Program Files\Tesseract-OCR\tesseract.exe",
                r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
            ]
            for cp in common_paths:
                if os.path.isfile(cp):
                    pytesseract.pytesseract.tesseract_cmd = cp
                    break

            img = Image.open(io.BytesIO(content))
            text = pytesseract.image_to_string(img).strip()
            if not text:
                raise ExtractionError("Local OCR completed but found no text in image.")
            return {
                "text": text,
                "method": "Local OCR",
                "char_count": len(text),
                "filename": filename,
            }
        except Exception as e:
            raise ExtractionError(f"Local OCR processing error: {str(e)}")

    else:
        raise ExtractionError(
            f"Unsupported file format '{ext}'. Supported formats: TXT, PDF, DOCX, DOC, PNG, JPG."
        )
