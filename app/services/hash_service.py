import hashlib
from typing import BinaryIO

from werkzeug.utils import secure_filename


def allowed_file(filename: str, allowed_extensions: set[str]) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


def sanitize_filename(filename: str) -> str:
    return secure_filename(filename)


def compute_sha256(file_obj: BinaryIO) -> str:
    sha256 = hashlib.sha256()
    for chunk in iter(lambda: file_obj.read(4096), b""):
        sha256.update(chunk)
    file_obj.seek(0)
    return sha256.hexdigest()


def compare_hashes(original: str, new: str) -> bool:
    return original == new
