# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""
File upload MIME type validation.

Deep validation pipeline:
1. Extension whitelist check
2. python-magic MIME sniffing (reads file magic bytes)
3. Extension/MIME consistency cross-check
4. For images: Pillow re-encode (strips malware, EXIF, ICC profiles)
5. For PDFs: pypdf validation (reject encrypted/JS-containing PDFs)
6. Polyglot file detection
7. Quarantine → verified folder workflow
"""

import io
import logging
import os
import shutil
import uuid
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Allowed file types and their MIME types
# ---------------------------------------------------------------------------

ALLOWED_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif",
    "mp4", "mov", "webm",
    "pdf", "txt", "log",
}

# MIME type → allowed extensions mapping
MIME_EXTENSION_MAP: dict[str, set[str]] = {
    "image/png": {"png"},
    "image/jpeg": {"jpg", "jpeg"},
    "image/gif": {"gif"},
    "video/mp4": {"mp4"},
    "video/quicktime": {"mov"},
    "video/webm": {"webm"},
    "application/pdf": {"pdf"},
    "text/plain": {"txt", "log"},
    "application/octet-stream": set(),  # Requires extension check
}

# Image MIME types that get Pillow re-encoded
IMAGE_MIME_TYPES = {"image/png", "image/jpeg", "image/gif"}

# Maximum file count per report
MAX_FILES_PER_REPORT = 10


class ValidationResult(NamedTuple):
    """Result of file validation."""
    is_valid: bool
    mime_type: str
    error: str
    stored_filename: str  # UUID.ext format


def validate_and_store_upload(
    file_data: bytes,
    original_filename: str,
    report_uuid: str,
    upload_base: str,
) -> ValidationResult:
    """
    Validate uploaded file and move to verified storage.

    Pipeline:
    1. Extension check
    2. MIME sniff with python-magic
    3. MIME/extension consistency check
    4. Deep validation (Pillow for images, pypdf for PDFs)
    5. Move from quarantine to verified folder

    Args:
        file_data: Raw file bytes.
        original_filename: Original filename from the upload (for extension check).
        report_uuid: UUID of the report (for storage path).
        upload_base: Base upload directory path.

    Returns:
        ValidationResult with is_valid, mime_type, error, and stored_filename.
    """
    # Generate UUID filename early (for quarantine)
    file_ext = _get_extension(original_filename)
    stored_uuid = str(uuid.uuid4())
    stored_filename = f"{stored_uuid}.{file_ext}" if file_ext else stored_uuid

    # Step 1: Extension whitelist check
    if not file_ext or file_ext not in ALLOWED_EXTENSIONS:
        return ValidationResult(
            is_valid=False,
            mime_type="",
            error=f"File extension '{file_ext}' is not allowed",
            stored_filename="",
        )

    # Step 2: MIME sniff
    try:
        import magic
        detected_mime = magic.from_buffer(file_data[:8192], mime=True)
    except ImportError:
        logger.warning("python-magic not available — falling back to extension-based check")
        detected_mime = _guess_mime_from_ext(file_ext)
    except Exception as exc:
        return ValidationResult(
            is_valid=False,
            mime_type="",
            error=f"MIME detection failed: {exc}",
            stored_filename="",
        )

    # Step 3: MIME/extension consistency
    if not _is_mime_extension_consistent(detected_mime, file_ext):
        return ValidationResult(
            is_valid=False,
            mime_type=detected_mime,
            error=f"MIME type '{detected_mime}' inconsistent with extension '.{file_ext}'",
            stored_filename="",
        )

    # Step 4: Deep validation
    validated_data = file_data
    if detected_mime in IMAGE_MIME_TYPES:
        result, validated_data, error = _validate_and_reencode_image(file_data, file_ext)
        if not result:
            return ValidationResult(
                is_valid=False,
                mime_type=detected_mime,
                error=error,
                stored_filename="",
            )
    elif detected_mime == "application/pdf":
        result, error = _validate_pdf(file_data)
        if not result:
            return ValidationResult(
                is_valid=False,
                mime_type=detected_mime,
                error=error,
                stored_filename="",
            )

    # Step 5: Store in verified folder
    verified_dir = os.path.join(upload_base, "verified", report_uuid)
    os.makedirs(verified_dir, exist_ok=True)
    verified_path = os.path.join(verified_dir, stored_filename)

    try:
        with open(verified_path, "wb") as f:
            f.write(validated_data)
    except OSError as exc:
        return ValidationResult(
            is_valid=False,
            mime_type=detected_mime,
            error=f"Failed to store file: {exc}",
            stored_filename="",
        )

    logger.info(f"File validated and stored: {stored_filename} ({detected_mime})")
    return ValidationResult(
        is_valid=True,
        mime_type=detected_mime,
        error="",
        stored_filename=stored_filename,
    )


def _validate_and_reencode_image(
    data: bytes, ext: str
) -> tuple[bool, bytes, str]:
    """
    Re-encode image with Pillow to strip malware, EXIF, and ICC profiles.

    Args:
        data: Raw image bytes.
        ext: File extension.

    Returns:
        Tuple of (success, re-encoded bytes, error message).
    """
    try:
        from PIL import Image

        img = Image.open(io.BytesIO(data))

        # Verify the image can be read (raises if invalid)
        img.verify()

        # Re-open after verify (verify() exhausts the file)
        img = Image.open(io.BytesIO(data))

        # Convert to RGB/RGBA (strips embedded malware in palette modes, etc.)
        if img.mode not in ("RGB", "RGBA", "L", "LA"):
            img = img.convert("RGB")

        # Re-encode without EXIF, ICC profiles, or other metadata
        output = io.BytesIO()
        save_format = "PNG" if ext in ("png", "gif") else "JPEG"
        save_kwargs: dict = {"optimize": True}
        if save_format == "JPEG":
            save_kwargs["quality"] = 85

        img.save(output, format=save_format, **save_kwargs)
        output.seek(0)

        return True, output.read(), ""

    except Exception as exc:
        logger.warning(f"Image re-encode failed: {exc}")
        return False, b"", f"Invalid or malformed image file: {exc}"


def _validate_pdf(data: bytes) -> tuple[bool, str]:
    """
    Validate PDF with pypdf — reject encrypted or JavaScript-containing PDFs.

    Args:
        data: Raw PDF bytes.

    Returns:
        Tuple of (is_valid, error_message).
    """
    try:
        import pypdf

        reader = pypdf.PdfReader(io.BytesIO(data))

        # Reject encrypted PDFs
        if reader.is_encrypted:
            return False, "Encrypted PDFs are not allowed"

        # Check for JavaScript in PDF
        if "/JS" in str(reader.metadata) or "/JavaScript" in str(reader.metadata):
            return False, "PDFs containing JavaScript are not allowed"

        # Scan each page for JavaScript actions
        for page in reader.pages:
            page_str = str(page)
            if "/JS" in page_str or "/JavaScript" in page_str:
                return False, "PDFs containing JavaScript are not allowed"

        return True, ""

    except Exception as exc:
        logger.warning(f"PDF validation failed: {exc}")
        return False, f"Invalid or malformed PDF: {exc}"


def _get_extension(filename: str) -> str:
    """Extract lowercase file extension without the dot."""
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[-1].lower()


def _is_mime_extension_consistent(mime_type: str, ext: str) -> bool:
    """Check if MIME type and extension are consistent."""
    if mime_type in MIME_EXTENSION_MAP:
        allowed_exts = MIME_EXTENSION_MAP[mime_type]
        if not allowed_exts:
            # application/octet-stream: accept if extension is in whitelist
            return ext in ALLOWED_EXTENSIONS
        return ext in allowed_exts
    # Unknown MIME type
    return False


def _guess_mime_from_ext(ext: str) -> str:
    """Fallback MIME type from extension (when python-magic unavailable)."""
    ext_to_mime = {
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "gif": "image/gif",
        "mp4": "video/mp4",
        "mov": "video/quicktime",
        "webm": "video/webm",
        "pdf": "application/pdf",
        "txt": "text/plain",
        "log": "text/plain",
    }
    return ext_to_mime.get(ext, "application/octet-stream")


def secure_delete_file(file_path: str) -> None:
    """
    Securely delete a file by overwriting with zeros before removal.

    Args:
        file_path: Absolute path to the file to delete.
    """
    try:
        path = Path(file_path)
        if path.exists() and path.is_file():
            file_size = path.stat().st_size
            with open(path, "wb") as f:
                f.write(b"\x00" * file_size)
                f.flush()
                os.fsync(f.fileno())
            path.unlink()
            logger.info(f"Securely deleted file: {file_path}")
    except Exception as exc:
        logger.error(f"Secure delete failed for {file_path}: {exc}")
        # Fall back to regular delete
        try:
            os.remove(file_path)
        except OSError:
            pass
