"""系统托盘驻留 + Windows Toast 通知"""

import os
import subprocess
import sys
import threading
from io import BytesIO
from collections.abc import Callable
from typing import Optional


def show_toast(title: str, message: str, icon: str = "Info") -> None:
    """弹出 Windows Toast 通知（通过 PowerShell）"""
    if sys.platform != "win32":
        return

    script = f'''
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$textNodes = $template.GetElementsByTagName("text")
$textNodes.Item(0).AppendChild($template.CreateTextNode("{title}")) > $null
$textNodes.Item(1).AppendChild($template.CreateTextNode("{message}")) > $null
$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("disk-cleaner").Show($toast)
'''
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
    except Exception:
        pass


def _create_icon():
    """创建一个简单的托盘图标（绿色磁盘图案）"""
    try:
        from PIL import Image, ImageDraw

        size = 64
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        # 磁盘主体
        draw.rounded_rectangle([8, 8, 56, 56], radius=8, fill=(35, 134, 54))
        # 磁盘标签
        draw.rectangle([24, 22, 40, 30], fill=(255, 255, 255))
        draw.rectangle([24, 34, 40, 42], fill=(255, 255, 255, 180))
        # 读写头
        draw.rectangle([40, 10, 52, 20], fill=(200, 200, 200), outline=(100, 100, 100))

        return img
    except ImportError:
        return None


class SystemTray:
    """系统托盘管理器"""

    def __init__(self):
        self._tray_thread: Optional[threading.Thread] = None
        self._icon = None
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._scan_interval: float = 3600  # 默认每小时扫描一次

    def start(
        self,
        scan_paths: list[str] | None = None,
        scan_callback: Callable | None = None,
        on_quit: Callable | None = None,
    ):
        """启动系统托盘"""
        try:
            import pystray
        except ImportError:
            print("pystray 未安装，跳过托盘功能")
            return

        icon_img = _create_icon()
        if icon_img is None:
            print("Pillow 未安装，无法创建图标")
            return

        self._scan_paths = scan_paths or ["C:\\Users"]
        self._scan_callback = scan_callback
        self._on_quit = on_quit

        def _run_scan():
            if not scan_callback:
                show_toast("磁盘清理", "未配置扫描回调")
                return
            for p in self._scan_paths:
                try:
                    scan_callback(p)
                except Exception:
                    pass

        def do_scan():
            # 菜单回调不能阻塞托盘线程
            threading.Thread(target=_run_scan, daemon=True).start()

        def do_analyze():
            threading.Thread(target=_run_scan, daemon=True).start()

        def do_exit(icon, item):
            self.stop()
            icon.stop()
            if on_quit:
                on_quit()

        menu = pystray.Menu(
            pystray.MenuItem("立即扫描", do_scan, default=True),
            pystray.MenuItem("扫描 C 盘", do_analyze),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("退出", do_exit),
        )

        self._icon = pystray.Icon(
            "disk_cleaner",
            icon_img,
            "AI 磁盘清理",
            menu,
        )
        self._running = True

        # 启动后台扫描线程
        if scan_callback:
            self._monitor_thread = threading.Thread(
                target=self._background_scanner, daemon=True
            )
            self._monitor_thread.start()

        show_toast("AI 磁盘清理", "已在后台运行，右键托盘图标打开菜单")
        self._icon.run()

    def stop(self):
        """停止托盘"""
        self._running = False

    def _background_scanner(self):
        """后台定时扫描"""
        import time

        while self._running:
            time.sleep(self._scan_interval)
            if self._scan_callback and self._running:
                for p in self._scan_paths:
                    try:
                        self._scan_callback(p)
                    except Exception:
                        pass


def start_tray_app():
    """启动托盘应用——便捷入口"""
    from disk_cleaner.gui.tray import SystemTray, show_toast

    def on_scan(path: str):
        from disk_cleaner.scanner.walker import scan_directory
        from disk_cleaner.analyzer.rules import RuleEngine

        results = scan_directory(path, top_n=50, min_size=10 * 1024 * 1024)
        engine = RuleEngine()
        engine.add_builtin_rules()

        safe_count = 0
        safe_total_bytes = 0
        for r in results:
            match = engine.evaluate(r)
            if match and match.decision in ("safe_to_delete", "likely_safe"):
                safe_count += 1
                safe_total_bytes += r.size

        if safe_count > 0:
            total_mb = safe_total_bytes / (1024**2)
            show_toast(
                "磁盘清理",
                f"{path} 发现 {safe_count} 个可清理文件，约 {total_mb:.0f} MB",
            )

    tray = SystemTray()
    tray.start(scan_paths=["C:\\Users", os.path.expanduser("~\\Downloads")], scan_callback=on_scan)
