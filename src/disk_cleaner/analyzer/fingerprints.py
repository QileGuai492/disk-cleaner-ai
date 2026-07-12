"""应用指纹库——已知软件的文件分布模式"""

import fnmatch
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class AppFingerprint:
    """应用指纹——描述一个软件在磁盘上的文件分布"""

    app_name: str
    category: str  # ide / game / tool / media / browser / dev / system
    fingerprints: list[str]  # glob 模式列表
    cleanup_hint: str  # 清理建议
    total_size_estimate_mb: float = 0.0
    removable: bool = True  # 是否可以安全清理/搬迁


# 内置指纹库
BUILTIN_FINGERPRINTS: list[AppFingerprint] = [
    # IDE
    AppFingerprint(
        app_name="Visual Studio 2022 Preview",
        category="ide",
        fingerprints=[
            "*/Microsoft Visual Studio/2022/Preview/**",
            "*/VisualStudio/17.0*/ComponentModelCache/**",
        ],
        cleanup_hint="预览版可能已过期，正式版发布后可安全清理",
        removable=True,
    ),
    AppFingerprint(
        app_name="JetBrains IDE 缓存",
        category="ide",
        fingerprints=[
            "*/JetBrains/*/caches/**",
            "*/JetBrains/*/log/**",
            "*/JetBrains/*/tmp/**",
        ],
        cleanup_hint="IDE 缓存和日志，可以安全清理以释放空间",
        removable=True,
    ),
    # 游戏
    AppFingerprint(
        app_name="Steam 游戏库",
        category="game",
        fingerprints=[
            "*/Steam/steamapps/common/**",
            "*/Steam/steamapps/workshop/**",
            "*/Steam/steamapps/downloading/**",
        ],
        cleanup_hint="Steam 游戏文件，可在 Steam 设置中更换库文件夹后搬迁",
        removable=False,
    ),
    # 浏览器缓存
    AppFingerprint(
        app_name="Chrome 缓存",
        category="browser",
        fingerprints=[
            "*/Google/Chrome/User Data/*/Cache/**",
            "*/Google/Chrome/User Data/*/Code Cache/**",
            "*/Google/Chrome/User Data/*/Service Worker/**",
        ],
        cleanup_hint="Chrome 缓存文件，可安全清理。浏览器会自动重建",
        removable=True,
        total_size_estimate_mb=500,
    ),
    AppFingerprint(
        app_name="Edge 缓存",
        category="browser",
        fingerprints=[
            "*/Microsoft/Edge/User Data/*/Cache/**",
            "*/Microsoft/Edge/User Data/*/Code Cache/**",
        ],
        cleanup_hint="Edge 缓存文件，可安全清理",
        removable=True,
        total_size_estimate_mb=300,
    ),
    # 开发工具
    AppFingerprint(
        app_name="npm 缓存",
        category="dev",
        fingerprints=[
            "*/npm-cache/_cacache/**",
            "*/npm/_cacache/**",
        ],
        cleanup_hint="npm 包缓存，清理后重新安装时自动下载。`npm cache clean --force`",
        removable=True,
        total_size_estimate_mb=2000,
    ),
    AppFingerprint(
        app_name="Python 缓存",
        category="dev",
        fingerprints=[
            "**/__pycache__/**",
            "**/*.pyc",
            "**/.pytest_cache/**",
            "**/.mypy_cache/**",
        ],
        cleanup_hint="Python 字节码缓存，可安全清理。Python 会自动重建",
        removable=True,
    ),
    AppFingerprint(
        app_name="Android SDK",
        category="dev",
        fingerprints=[
            "*/Android/Sdk/system-images/**",
            "*/Android/Sdk/.temp/**",
            "*/Android/Sdk/emulator/**",
        ],
        cleanup_hint="Android SDK 系统镜像占用大，旧版本 API 可清理",
        removable=True,
        total_size_estimate_mb=5000,
    ),
    # 系统
    AppFingerprint(
        app_name="Windows 更新缓存",
        category="system",
        fingerprints=[
            "*/SoftwareDistribution/Download/**",
            "*/Windows/Temp/**",
        ],
        cleanup_hint="Windows 更新缓存，更新安装后可安全清理",
        removable=True,
        total_size_estimate_mb=2000,
    ),
    AppFingerprint(
        app_name="Windows 缩略图缓存",
        category="system",
        fingerprints=[
            "*/AppData/Local/Microsoft/Windows/Explorer/thumbcache_*.db",
            "*/AppData/Local/Microsoft/Windows/Explorer/iconcache_*.db",
        ],
        cleanup_hint="系统缩略图缓存，可安全清理",
        removable=True,
        total_size_estimate_mb=500,
    ),
    # 媒体
    AppFingerprint(
        app_name="微信文件",
        category="media",
        fingerprints=[
            "*/WeChat Files/*/FileStorage/File/**",
            "*/WeChat Files/*/FileStorage/Video/**",
            "*/WeChat Files/*/FileStorage/Image/**",
        ],
        cleanup_hint="微信接收的文件和媒体，建议确认后手动清理重要文件",
        removable=False,
        total_size_estimate_mb=10000,
    ),
    AppFingerprint(
        app_name="QQ 缓存",
        category="media",
        fingerprints=[
            "*/Tencent Files/*/Image/**",
            "*/Tencent Files/*/Video/**",
            "*/QQ/Cache/**",
        ],
        cleanup_hint="QQ 图片和视频缓存，可安全清理",
        removable=True,
        total_size_estimate_mb=5000,
    ),
]


class FingerprintDB:
    """应用指纹数据库"""

    def __init__(self, db_dir: Optional[str] = None):
        self.db_dir = db_dir or os.path.join(
            os.path.dirname(__file__), "..", "..", "fingerprints"
        )
        self._fingerprints: list[AppFingerprint] = list(BUILTIN_FINGERPRINTS)
        self._load_custom()

    def _load_custom(self) -> None:
        """加载自定义指纹"""
        if not os.path.isdir(self.db_dir):
            return
        for fname in os.listdir(self.db_dir):
            if not fname.endswith(".json"):
                continue
            try:
                path = os.path.join(self.db_dir, fname)
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        self._fingerprints.append(AppFingerprint(**item))
                elif isinstance(data, dict):
                    self._fingerprints.append(AppFingerprint(**data))
            except Exception:
                pass

    def match(self, path: str) -> list[AppFingerprint]:
        """查询路径匹配的应用指纹"""
        matches = []
        normalized = path.replace("\\", "/")
        for fp in self._fingerprints:
            for pattern in fp.fingerprints:
                normalized_pattern = pattern.replace("\\", "/")
                if fnmatch.fnmatch(normalized, normalized_pattern):
                    matches.append(fp)
                    break
        return matches

    def scan_directory(self, directory: str, max_files: int = 5000) -> dict[str, list[str]]:
        """扫描目录，返回匹配的应用→文件列表映射（最多扫描 max_files 个文件后停止）"""
        app_files: dict[str, list[str]] = {}
        count = 0
        for root, _, files in os.walk(directory):
            for fname in files:
                if count >= max_files:
                    return app_files
                count += 1
                fpath = os.path.join(root, fname)
                matches = self.match(fpath)
                for m in matches:
                    if m.app_name not in app_files:
                        app_files[m.app_name] = []
                    app_files[m.app_name].append(fpath)
        return app_files

    def get_cleanup_suggestions(self, directory: str) -> list[dict]:
        """获取清理建议列表"""
        app_files = self.scan_directory(directory)
        suggestions = []
        for app_name, paths in app_files.items():
            fp = next((f for f in self._fingerprints if f.app_name == app_name), None)
            if fp and fp.removable:
                total_size = sum(
                    os.path.getsize(p) for p in paths if os.path.exists(p)
                )
                suggestions.append({
                    "app_name": app_name,
                    "category": fp.category,
                    "file_count": len(paths),
                    "total_size_mb": round(total_size / (1024**2), 1),
                    "cleanup_hint": fp.cleanup_hint,
                    "sample_paths": paths[:5],
                })
        suggestions.sort(key=lambda s: s["total_size_mb"], reverse=True)
        return suggestions

    @property
    def app_count(self) -> int:
        return len(self._fingerprints)

    def add_fingerprint(self, fp: AppFingerprint) -> None:
        """添加自定义指纹"""
        self._fingerprints.append(fp)

    def save(self) -> None:
        """保存自定义指纹到文件"""
        os.makedirs(self.db_dir, exist_ok=True)
        custom = [fp for fp in self._fingerprints if fp not in BUILTIN_FINGERPRINTS]
        if custom:
            path = os.path.join(self.db_dir, "custom.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(
                    [{"app_name": fp.app_name, "category": fp.category,
                      "fingerprints": fp.fingerprints, "cleanup_hint": fp.cleanup_hint,
                      "removable": fp.removable}
                     for fp in custom],
                    f, ensure_ascii=False, indent=2,
                )
