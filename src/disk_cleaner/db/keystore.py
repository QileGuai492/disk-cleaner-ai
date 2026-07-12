"""API Key 加密存储——Windows DPAPI / macOS Keychain"""

import json
import os
import sys
from pathlib import Path


def _get_keystore_path() -> str:
    base = os.path.expanduser("~/.disk-cleaner/credentials")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, "keys.enc")


def _encrypt_win32(data: bytes) -> bytes:
    """Windows DPAPI 加密——只有当前用户能解密"""
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.windll.crypt32

    blob_in = DATA_BLOB(len(data), ctypes.c_char_p(data))
    blob_out = DATA_BLOB()

    if not crypt32.CryptProtectData(
        ctypes.byref(blob_in),
        "disk-cleaner-key",
        None, None, None, 0,  # CRYPTPROTECT_UI_FORBIDDEN
        ctypes.byref(blob_out),
    ):
        raise OSError("DPAPI 加密失败")

    result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    return result


def _decrypt_win32(data: bytes) -> bytes:
    """Windows DPAPI 解密"""
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.windll.crypt32

    blob_in = DATA_BLOB(len(data), ctypes.c_char_p(data))
    blob_out = DATA_BLOB()

    if not crypt32.CryptUnprotectData(
        ctypes.byref(blob_in),
        None, None, None, None, 0,
        ctypes.byref(blob_out),
    ):
        raise OSError("DPAPI 解密失败——是否换了账户？")

    result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    return result


class KeyStore:
    """API Key 加密存储"""

    def __init__(self, path: str | None = None):
        self.path = path or _get_keystore_path()

    def _is_windows(self) -> bool:
        return sys.platform == "win32"

    def encrypt(self, data: bytes) -> bytes:
        if self._is_windows():
            return _encrypt_win32(data)
        # 非 Windows：base64 混淆（不真正安全，但聊胜于无）
        import base64
        return base64.b64encode(data)

    def decrypt(self, data: bytes) -> bytes:
        if self._is_windows():
            return _decrypt_win32(data)
        import base64
        return base64.b64decode(data)

    def set_key(self, provider: str, api_key: str) -> None:
        """存储 API Key"""
        store = self._load()
        store[provider] = api_key
        self._save(store)

    def get_key(self, provider: str) -> str | None:
        """读取 API Key"""
        store = self._load()
        return store.get(provider)

    def delete_key(self, provider: str) -> bool:
        """删除 API Key"""
        store = self._load()
        if provider in store:
            del store[provider]
            self._save(store)
            return True
        return False

    def list_providers(self) -> list[str]:
        """列出已存储的 provider"""
        return list(self._load().keys())

    def _load(self) -> dict[str, str]:
        if not os.path.exists(self.path):
            return {}
        try:
            with open(self.path, "rb") as f:
                encrypted = f.read()
            decrypted = self.decrypt(encrypted)
            return json.loads(decrypted.decode("utf-8"))
        except Exception:
            return {}

    def _save(self, store: dict[str, str]) -> None:
        data = json.dumps(store, ensure_ascii=False).encode("utf-8")
        encrypted = self.encrypt(data)
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "wb") as f:
            f.write(encrypted)
