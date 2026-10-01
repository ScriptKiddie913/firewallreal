"""SentinelFW Encrypted Secrets Vault.

Provides cross-platform encrypted secret storage:
- Windows: Hardware/User-bound DPAPI (CryptProtectData / CryptUnprotectData via ctypes)
- Linux: AES-256-GCM sealed with a 0600 root-only keyfile (/etc/sentinelfw/vault.key or <HOME>/vault.key)
- Automatic migration of legacy plaintext keys (VT, Sarvam, Telegram, Fleet, SIEM)
- Environment variable overrides take precedence over vault storage.
"""

import base64
import ctypes
import hashlib
import hmac
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .common import CONFIG_FILE, DATA_DIR, HOME, IS_WIN, atomic_write, event

# Vault file path
VAULT_FILE = HOME / "vault.enc"
LINUX_KEY_FILE = HOME / "vault.key"

# Mapping of vault keys to environment variables and legacy config paths
KEY_MAPPINGS = {
    "vt_api_key": {
        "env": "SFW_VT_KEY",
        "cfg_path": [("threat_intel", "virustotal_api_key"), ("virustotal_api_key",)],
    },
    "sarvam_api_key": {
        "env": "SFW_SARVAM_KEY",
        "cfg_path": [("sarvam", "api_key")],
    },
    "telegram_bot_token": {
        "env": "SFW_TELEGRAM_TOKEN",
        "cfg_path": [("telegram", "bot_token")],
    },
    "fleet_shared_key": {
        "env": "SFW_FLEET_KEY",
        "cfg_path": [("fleet", "shared_key")],
    },
    "siem_password": {
        "env": "SFW_SIEM_PASSWORD",
        "cfg_path": [("siem", "password"), ("elastic", "password")],
    },
}


# =====================================================================
# Windows DPAPI Implementation
# =====================================================================
if IS_WIN:
    import ctypes.wintypes

    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def _dpapi_encrypt(data: bytes) -> bytes:
        blob_in = _DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_char)))
        blob_out = _DATA_BLOB()
        # CRYPTPROTECT_UI_FORBIDDEN = 0x01
        if ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(blob_in), "sfw_vault", None, None, None, 0x01, ctypes.byref(blob_out)
        ):
            res = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
            return res
        raise RuntimeError("CryptProtectData failed")

    def _dpapi_decrypt(data: bytes) -> bytes:
        blob_in = _DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_char)))
        blob_out = _DATA_BLOB()
        if ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0x01, ctypes.byref(blob_out)
        ):
            res = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
            return res
        raise RuntimeError("CryptUnprotectData failed")


# =====================================================================
# Linux / POSIX AES-256-GCM / Sealed Keyfile Implementation
# =====================================================================
def _get_linux_master_key() -> bytes:
    """Retrieves or creates a 256-bit master key sealed in a 0600 keyfile."""
    key_path = LINUX_KEY_FILE
    try:
        if "/etc/sentinelfw" in str(HOME) and os.geteuid() == 0:
            key_path = Path("/etc/sentinelfw/vault.key")
    except AttributeError:
        pass

    if key_path.exists():
        try:
            return bytes.fromhex(key_path.read_text(encoding="utf-8").strip())
        except Exception:
            pass

    key_path.parent.mkdir(parents=True, exist_ok=True)
    new_key = secrets.token_bytes(32)
    atomic_write(key_path, new_key.hex() + "\n")
    if not IS_WIN:
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
    return new_key


def _linux_aes_gcm_encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypts data using AES-256-GCM via libcrypto or CTR+HMAC fallback."""
    iv = secrets.token_bytes(12)
    try:
        import ctypes.util
        libname = ctypes.util.find_library("crypto") or "libcrypto.so.3"
        lib = ctypes.CDLL(libname)
        ctx = lib.EVP_CIPHER_CTX_new()
        try:
            cipher = lib.EVP_aes_256_gcm()
            lib.EVP_EncryptInit_ex(ctx, cipher, None, None, None)
            lib.EVP_CIPHER_CTX_ctrl(ctx, 0x12, 12, None)  # EVP_CTRL_GCM_SET_IVLEN
            lib.EVP_EncryptInit_ex(ctx, None, None, key, iv)
            out = ctypes.create_string_buffer(len(data) + 16)
            out_len = ctypes.c_int()
            lib.EVP_EncryptUpdate(ctx, out, ctypes.byref(out_len), data, len(data))
            final_len = ctypes.c_int()
            lib.EVP_EncryptFinal_ex(ctx, ctypes.byref(out, out_len.value), ctypes.byref(final_len))
            tag = ctypes.create_string_buffer(16)
            lib.EVP_CIPHER_CTX_ctrl(ctx, 0x10, 16, tag)  # EVP_CTRL_GCM_GET_TAG
            ct = out.raw[:out_len.value + final_len.value]
            return iv + tag.raw + ct
        finally:
            lib.EVP_CIPHER_CTX_free(ctx)
    except Exception:
        # High-security fallback: AES-CTR emulation via SHA-256 counter + HMAC tag
        keystream = b""
        counter = 0
        while len(keystream) < len(data):
            keystream += hmac.new(key, iv + counter.to_bytes(4, "big"), hashlib.sha256).digest()
            counter += 1
        ct = bytes(a ^ b for a, b in zip(data, keystream[:len(data)]))
        tag = hmac.new(key, iv + ct, hashlib.sha256).digest()[:16]
        return iv + tag + ct


def _linux_aes_gcm_decrypt(data: bytes, key: bytes) -> bytes:
    if len(data) < 28:
        raise ValueError("Encrypted payload too short")
    iv = data[:12]
    tag = data[12:28]
    ct = data[28:]
    try:
        import ctypes.util
        libname = ctypes.util.find_library("crypto") or "libcrypto.so.3"
        lib = ctypes.CDLL(libname)
        ctx = lib.EVP_CIPHER_CTX_new()
        try:
            cipher = lib.EVP_aes_256_gcm()
            lib.EVP_DecryptInit_ex(ctx, cipher, None, None, None)
            lib.EVP_CIPHER_CTX_ctrl(ctx, 0x12, 12, None)
            lib.EVP_DecryptInit_ex(ctx, None, None, key, iv)
            out = ctypes.create_string_buffer(len(ct) + 16)
            out_len = ctypes.c_int()
            lib.EVP_DecryptUpdate(ctx, out, ctypes.byref(out_len), ct, len(ct))
            lib.EVP_CIPHER_CTX_ctrl(ctx, 0x11, 16, tag)  # EVP_CTRL_GCM_SET_TAG
            final_len = ctypes.c_int()
            rc = lib.EVP_DecryptFinal_ex(ctx, ctypes.byref(out, out_len.value), ctypes.byref(final_len))
            if rc > 0:
                return out.raw[:out_len.value + final_len.value]
        finally:
            lib.EVP_CIPHER_CTX_free(ctx)
    except Exception:
        pass

    # Counter fallback verification
    calc_tag = hmac.new(key, iv + ct, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(calc_tag, tag):
        raise ValueError("Invalid vault ciphertext or corrupted authentication tag")
    keystream = b""
    counter = 0
    while len(keystream) < len(ct):
        keystream += hmac.new(key, iv + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        counter += 1
    return bytes(a ^ b for a, b in zip(ct, keystream[:len(ct)]))


# =====================================================================
# Vault Main Controller
# =====================================================================
class Vault:
    """Encrypted Secrets Vault for SentinelFW."""

    def __init__(self, vault_path: Optional[Path] = None):
        self.path = vault_path or VAULT_FILE
        self._secrets: Dict[str, str] = {}
        self._load()

    def _seal(self, raw: bytes) -> bytes:
        if IS_WIN:
            return _dpapi_encrypt(raw)
        key = _get_linux_master_key()
        return _linux_aes_gcm_encrypt(raw, key)

    def _unseal(self, enc: bytes) -> bytes:
        if IS_WIN:
            return _dpapi_decrypt(enc)
        key = _get_linux_master_key()
        return _linux_aes_gcm_decrypt(enc, key)

    def _load(self):
        if not self.path.exists():
            self._secrets = {}
            return
        try:
            raw_enc = self.path.read_bytes()
            if not raw_enc:
                self._secrets = {}
                return
            dec = self._unseal(raw_enc)
            self._secrets = json.loads(dec.decode("utf-8"))
        except Exception as ex:
            event("vault_load_error", "warning", error=str(ex))
            self._secrets = {}

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        raw = json.dumps(self._secrets).encode("utf-8")
        sealed = self._seal(raw)
        atomic_write(self.path, sealed)
        if not IS_WIN:
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    def get(self, key: str, default: str = "") -> str:
        """Retrieves a secret, prioritizing environment variable overrides."""
        # 1. Environment variable override check
        mapping = KEY_MAPPINGS.get(key)
        if mapping:
            env_val = os.environ.get(mapping["env"], "").strip()
            if env_val:
                return env_val

        # 2. Vault stored value
        return self._secrets.get(key, default)

    def set(self, key: str, value: str):
        """Stores a secret encrypted in the vault."""
        self._secrets[key] = str(value)
        self._save()
        event("vault_secret_set", "info", key=key)

    def delete(self, key: str):
        """Removes a secret from the vault."""
        if key in self._secrets:
            del self._secrets[key]
            self._save()
            event("vault_secret_deleted", "info", key=key)

    def list_keys(self) -> List[str]:
        return list(self._secrets.keys())

    def migrate_plaintext_keys(self, cfg: dict) -> bool:
        """Discovers plaintext API keys in config, encrypts into vault, and blanks them in cfg."""
        migrated_any = False
        for vkey, info in KEY_MAPPINGS.items():
            # If overridden by environment variable, do not migrate in-memory value
            if os.environ.get(info["env"]):
                continue

            # Check if secret already in vault
            if vkey in self._secrets and self._secrets[vkey]:
                continue

            # Check config paths
            for path in info["cfg_path"]:
                curr = cfg
                found = True
                for seg in path[:-1]:
                    if isinstance(curr, dict) and seg in curr:
                        curr = curr[seg]
                    else:
                        found = False
                        break
                if found and isinstance(curr, dict) and path[-1] in curr:
                    val = str(curr.get(path[-1]) or "").strip()
                    if val and not val.startswith("vault:"):
                        # Found plaintext key -> migrate to vault
                        self._secrets[vkey] = val
                        curr[path[-1]] = f"vault:{vkey}"
                        migrated_any = True
                        event("key_migrated_to_vault", "info", key=vkey)
                        break

        if migrated_any:
            self._save()
        return migrated_any


# Singleton default vault instance
vault = Vault()
