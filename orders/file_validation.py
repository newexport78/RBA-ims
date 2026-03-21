"""PDF file validation: extension, MIME type, safe filename (Phase 6)."""
import os
import re

ALLOWED_PDF_MIME = ('application/pdf',)
ALLOWED_EXTENSIONS = ('.pdf',)


def sanitize_filename(name):
    """Return a safe filename: no path, only alphanumeric, dash, underscore, dot."""
    if not name or not name.strip():
        return 'document.pdf'
    base = os.path.basename(name).strip()
    # Remove any path components that might have been in the name
    base = base.replace('\\', '/').split('/')[-1]
    # Allow only safe chars: letters, digits, . - _
    safe = re.sub(r'[^\w.\-]', '_', base, flags=re.IGNORECASE)
    if not safe:
        return 'document.pdf'
    if not safe.lower().endswith('.pdf'):
        safe = safe + '.pdf'
    return safe[:200]  # reasonable max length


def validate_pdf_upload(uploaded_file):
    """
    Validate uploaded file is PDF (extension + content_type). Return (True, None) or (False, error_message).
    Does not check file size (per spec).
    """
    if not uploaded_file:
        return False, 'No file provided.'
    name = getattr(uploaded_file, 'name', '') or ''
    ext = os.path.splitext(name)[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, 'Only PDF files are allowed.'
    content_type = getattr(uploaded_file, 'content_type', '') or ''
    # Some browsers send application/pdf, others might send octet-stream with .pdf name
    if content_type and content_type not in ALLOWED_PDF_MIME and content_type != 'application/octet-stream':
        return False, 'File must be a PDF (application/pdf).'
    # Magic-bytes sniff: must start with "%PDF-"
    try:
        pos = uploaded_file.tell() if hasattr(uploaded_file, 'tell') else None
        header = uploaded_file.read(5)
        if pos is not None:
            uploaded_file.seek(pos)
        else:
            uploaded_file.seek(0)
    except Exception:
        header = b''
    if header and header != b'%PDF-':
        return False, 'File content does not look like a valid PDF.'
    return True, None
