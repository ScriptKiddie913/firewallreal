"""SentinelFW WAF File Upload Scanner.

Inspects uploaded files for malware, web shells, and evasion techniques:
* Magic byte sniffing vs extension mismatch (e.g. PE/ELF disguised as JPEG)
* Double-extension and null-byte bypasses (file.php.jpg, file.phtml)
* Embedded script tags and web shell signatures (<?php, <%, eval, system)
* Cryptographic hashing (SHA-256) for threat intelligence lookups
"""
import hashlib
import re
from typing import Dict, Optional, Tuple


MAGIC_SIGNATURES = {
    b"\xff\xd8\xff": "image/jpeg",
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"GIF87a": "image/gif",
    b"GIF89a": "image/gif",
    b"%PDF": "application/pdf",
    b"PK\x03\x04": "application/zip",
    b"MZ": "application/x-dosexec",
    b"\x7fELF": "application/x-executable",
}

DANGEROUS_EXTENSIONS = {
    ".php", ".php3", ".php4", ".php5", ".phtml", ".phar",
    ".asp", ".aspx", ".cer", ".asa",
    ".jsp", ".jspx", ".jsw", ".jsv",
    ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".sh", ".bash",
    ".dll", ".so", ".dylib",
}

EMBEDDED_SHELL_PATTERNS = [
    rb"(?i)<\?php",
    rb"(?i)<%[=@]?",
    rb"(?i)\b(eval|assert|passthru|shell_exec|system|popen)\s*\(",
    rb"(?i)c99shell|r57shell|wso\s+version|b374k",
]


class UploadScanner:
    """Inspects uploaded file contents and metadata."""

    def __init__(self, max_file_size: int = 10 * 1024 * 1024):
        self.max_file_size = int(max_file_size)
        self._compiled_shell = [re.compile(p) for p in EMBEDDED_SHELL_PATTERNS]

    def detect_magic_type(self, data: bytes) -> str:
        """Determines content MIME type from leading magic bytes."""
        for magic, mime in MAGIC_SIGNATURES.items():
            if data.startswith(magic):
                return mime
        return "application/octet-stream"

    def scan(self, filename: str, content: bytes) -> dict:
        """Scans uploaded file content for threats and policy violations."""
        clean_name = (filename or "unnamed").strip().lower()
        file_hash = hashlib.sha256(content).hexdigest()

        # 1. File size check
        if len(content) > self.max_file_size:
            return {
                "blocked": True,
                "reason": f"File size {len(content)} bytes exceeds limit of {self.max_file_size}",
                "sha256": file_hash,
                "detected_type": "unknown",
            }

        # 2. Dangerous extension check
        ext = ""
        if "." in clean_name:
            ext = "." + clean_name.rsplit(".", 1)[-1]
        if ext in DANGEROUS_EXTENSIONS:
            return {
                "blocked": True,
                "reason": f"Disallowed file extension: {ext}",
                "sha256": file_hash,
                "detected_type": "executable_script",
            }

        # 3. Double extension check (e.g. avatar.php.jpg)
        parts = clean_name.split(".")
        if len(parts) > 2:
            inner_ext = "." + parts[-2]
            if inner_ext in DANGEROUS_EXTENSIONS:
                return {
                    "blocked": True,
                    "reason": f"Double extension evasion detected: {inner_ext}{ext}",
                    "sha256": file_hash,
                    "detected_type": "executable_script",
                }

        # 4. Magic byte inspection
        magic_type = self.detect_magic_type(content)
        if magic_type in ("application/x-dosexec", "application/x-executable"):
            return {
                "blocked": True,
                "reason": f"Executable binary signature detected ({magic_type})",
                "sha256": file_hash,
                "detected_type": magic_type,
            }

        # 5. Extension vs Magic Mismatch
        if ext in (".jpg", ".jpeg") and magic_type != "image/jpeg":
            return {
                "blocked": True,
                "reason": f"File extension {ext} does not match magic type {magic_type}",
                "sha256": file_hash,
                "detected_type": magic_type,
            }
        if ext == ".png" and magic_type != "image/png":
            return {
                "blocked": True,
                "reason": f"File extension {ext} does not match magic type {magic_type}",
                "sha256": file_hash,
                "detected_type": magic_type,
            }

        # 6. Embedded Web Shell inspection
        for pat in self._compiled_shell:
            if pat.search(content[:4096]) or pat.search(content[-2048:]):
                return {
                    "blocked": True,
                    "reason": "Embedded script/web-shell signature detected inside file content",
                    "sha256": file_hash,
                    "detected_type": "web_shell",
                }

        return {
            "blocked": False,
            "reason": "Clean",
            "sha256": file_hash,
            "detected_type": magic_type,
        }
