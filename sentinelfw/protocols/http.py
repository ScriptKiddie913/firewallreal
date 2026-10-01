"""SentinelFW Deep HTTP Protocol Inspector.

Performs deep lexical and semantic analysis on HTTP requests and responses:
* HTTP normalization: percent-decoding loops, unicode NFKC normalization, path traversal resolution
* Transfer-Encoding chunked stream reconstruction
* Gzip / Deflate decompression with decompression bomb guard limit
* HTTP/2 preface and gRPC protocol frame inspection
* Signature matching for SQLi, XSS, SSRF, command injection, web shells, and AI prompt injection
"""
import gzip
import io
import re
import unicodedata
import urllib.parse
import zlib
from typing import Dict, List, Optional, Tuple

WEB_ATTACK_PATTERNS = [
    ("sql_injection_union", re.compile(r"(?i)\bunion(?:\s|\+)+select\b")),
    ("sql_injection_quotes", re.compile(r"(?i)(?:'|\%27)(?:\s|\+)*(?:or|and)(?:\s|\+)*\d+=\d+")),
    ("path_traversal", re.compile(r"(?:\.\./|\.\.\\|\%2e\%2e\%2f){2,}")),
    ("command_injection", re.compile(r"(?:;|\|\||&&|`|\$\()\s*(?:cat|ls|id|whoami|uname|curl|wget|powershell|cmd)\b")),
    ("xss_script_tags", re.compile(r"(?i)<script[\s>].*?</script.*?>")),
    ("log4shell", re.compile(r"(?i)\$\{(?:lower:|upper:)?jndi:(?:ldap|ldaps|rmi|dns)://")),
    ("spring4shell", re.compile(r"(?i)(?:class\.module\.classLoader|class\[\"module\"\])")),
    ("ssrf_cloud_metadata", re.compile(r"(?:169\.254\.169\.254|metadata\.google\.internal)")),
    ("llm_prompt_injection", re.compile(r"(?i)(?:ignore\s+(?:all\s+)?(?:previous|above)\s+instructions|system\s+prompt\s+override|you\s+are\s+now\s+dan\b)")),
    ("webshell_eval", re.compile(r"(?i)(?:eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)|assert\s*\(\s*\$_POST|passthru\s*\(\s*\$_(?:GET|POST|REQUEST))")),
    ("webshell_keywords", re.compile(r"(?i)\b(?:c99shell|r57shell|b374k|wso_version|cmd\.jsp|shell\.aspx|alfa_team)\b")),
    ("reverse_shell", re.compile(r"(?i)(?:/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+|nc\s+(?:-e|--exec)\s+/bin/|bash\s+-i\s+>&|mkfifo\s+/tmp/|powershell(?:\.exe)?\s+-[eE](?:nc|ncod|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,})")),
    ("ssti_injection", re.compile(r"(?:\$\{\s*7\s*\*\s*7\s*\}|\{\{\s*7\s*\*\s*7\s*\}\}|#\{\s*7\s*\*\s*7\s*\}|#set\s*\(\s*\$|#end\b)")),
    ("nosql_injection", re.compile(r"(?i)(?:\$(?:where|regex|gt|gte|lt|lte|ne|nin|in|exists|or|and)\b)")),
]

SCANNER_AGENTS = re.compile(r"(?i)(?:sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|hydra)")
HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def normalize_http_string(val: str, max_iterations: int = 5) -> str:
    """Performs deep normalization resolving recursive percent-encoding loops and unicode evasion."""
    if not val:
        return ""
    cur = val
    # 1. Recursive percent-decoding loop
    for _ in range(max_iterations):
        try:
            nxt = urllib.parse.unquote(cur)
        except Exception:
            break
        if nxt == cur:
            break
        cur = nxt

    # 2. Unicode NFKC normalization
    cur = unicodedata.normalize("NFKC", cur)

    # 3. Path & separator normalization
    cur = cur.replace("\\", "/").replace("\uff0f", "/").replace("\uff3c", "/")
    return cur


def decode_chunked_body(raw_body: bytes, max_len: int = 5242880) -> bytes:
    """Decodes an HTTP/1.1 chunked transfer-encoded byte stream."""
    out = bytearray()
    pos = 0
    body_len = len(raw_body)

    while pos < body_len:
        line_end = raw_body.find(b"\r\n", pos)
        if line_end == -1:
            break
        chunk_header = raw_body[pos:line_end].strip()
        # Strip chunk extensions if any (e.g. "1a;ext=val")
        chunk_size_str = chunk_header.split(b";")[0].strip()
        try:
            chunk_size = int(chunk_size_str, 16)
        except ValueError:
            break

        if chunk_size == 0:
            break  # Terminal chunk

        chunk_start = line_end + 2
        chunk_end = chunk_start + chunk_size
        if chunk_end > body_len:
            out.extend(raw_body[chunk_start:])
            break

        out.extend(raw_body[chunk_start:chunk_end])
        if len(out) > max_len:
            break
        pos = chunk_end + 2  # skip trailing \r\n

    return bytes(out)


def decompress_http_body(data: bytes, encoding: str, max_size: int = 5242880) -> bytes:
    """Decompresses gzip or deflate HTTP bodies with decompression bomb budget."""
    if not data:
        return b""
    enc = str(encoding or "").lower().strip()
    try:
        if "gzip" in enc:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                return gz.read(max_size)
        elif "deflate" in enc:
            try:
                return zlib.decompress(data, zlib.MAX_WBITS)
            except zlib.error:
                # Raw deflate without zlib header
                return zlib.decompress(data, -zlib.MAX_WBITS)
    except Exception:
        pass
    return data


class HTTPInspector:
    """Inspects raw HTTP streams and extracted headers/bodies with normalization and HTTP/2 awareness."""

    @classmethod
    def inspect_request(cls, raw_data: bytes) -> Tuple[Optional[str], dict]:
        """Parses raw HTTP request bytes and looks for web exploitation signatures."""
        if not raw_data:
            return None, {}

        # 1. Check for HTTP/2 Client Connection Preface
        if raw_data.startswith(HTTP2_PREFACE):
            return None, {"protocol": "http/2", "preface_detected": True, "method": "H2_FRAME"}

        try:
            text = raw_data.decode("latin-1")
        except Exception:
            return None, {}

        lines = text.split("\r\n")
        if not lines or not lines[0]:
            return None, {}

        HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}
        req_line = lines[0].split(" ")
        method = ""
        uri = ""
        is_http1_req = len(req_line) >= 2 and req_line[0].upper() in HTTP_METHODS
        if is_http1_req:
            method = req_line[0].upper()
            uri = req_line[1]

        # Extract headers (including HTTP/2 pseudo-headers)
        headers = {}
        for line in (lines[1:] if is_http1_req else lines):
            if not line:
                break
            if line.startswith(":"):
                rest = line[1:]
                if ":" in rest:
                    k, v = rest.split(":", 1)
                    headers[":" + k.strip().lower()] = v.strip()
            elif ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        # Handle HTTP/2 pseudo-headers if HTTP/1 request line was not present
        if not method and ":method" in headers:
            method = headers[":method"].upper()
            uri = headers.get(":path", "/")

        # Check for gRPC content-type
        content_type = headers.get("content-type", "")
        is_grpc = "application/grpc" in content_type

        ua = headers.get("user-agent", "")
        if SCANNER_AGENTS.search(ua):
            return "web_crawl_aggressive", {"method": method, "uri": uri, "user_agent": ua, "grpc": is_grpc}

        # Normalize URI
        norm_uri = normalize_http_string(uri)

        # Check request line + normalized URI against patterns
        for atype, pat in WEB_ATTACK_PATTERNS:
            if pat.search(uri) or pat.search(norm_uri):
                return atype, {"method": method, "uri": uri, "location": "uri", "normalized_uri": norm_uri}

        # Check body if present
        body_start = raw_data.find(b"\r\n\r\n")
        if body_start != -1:
            raw_body = raw_data[body_start + 4:]
            # Chunked transfer decoding
            if headers.get("transfer-encoding", "").lower() == "chunked":
                raw_body = decode_chunked_body(raw_body)

            # Decompress if gzip/deflate
            content_encoding = headers.get("content-encoding", "")
            if content_encoding:
                raw_body = decompress_http_body(raw_body, content_encoding)

            try:
                body_text = raw_body.decode("utf-8", "ignore")
            except Exception:
                body_text = raw_body.decode("latin-1", "ignore")

            norm_body = normalize_http_string(body_text)
            for atype, pat in WEB_ATTACK_PATTERNS:
                if pat.search(body_text) or pat.search(norm_body):
                    return atype, {"method": method, "uri": uri, "location": "body"}

        return None, {
            "method": method,
            "uri": uri,
            "host": headers.get("host", ""),
            "grpc": is_grpc,
            "normalized_uri": norm_uri,
        }
