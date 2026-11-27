"""CLI 命令行入口"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime

import click

try:
    from importlib.metadata import version as _pkg_version
    _VERSION = _pkg_version("disk-cleaner")
except Exception:
    _VERSION = "0.6.6"

from disk_cleaner.scanner.walker import FileInfo, scan_directory
from disk_cleaner.analyzer.engine import AnalysisEngine
from disk_cleaner.db.models import Database


class StrippedPath(click.Path):
    """自动去除首尾引号的路径类型（兼容 Win11 复制路径带引号的问题）"""
    def convert(self, value, param, ctx):
        if isinstance(value, str):
            # 去除各种引号：英文双引号、中文双引号、单引号、中文单引号
            value = value.strip()
            for q in ('"', '“', '”', '‘', '’', "'"):
                value = value.strip(q)
            value = os.path.expanduser(value)
        return super().convert(value, param, ctx)


def _get_db_path() -> str:
    """获取数据库路径"""
    base = os.path.expanduser("~/.disk-cleaner")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, "cache.db")


@click.group()
@click.version_option(version=_VERSION, message="disk-cleaner v%(version)s")
def cli():
    """AI 驱动的磁盘清理工具"""


@cli.command()
@click.argument("path", type=StrippedPath(exists=True))
@click.option("--top", "-n", type=int, default=50, help="只显示最大的 N 个文件")
@click.option("--min-size", "-s", type=int, default=0, help="最小文件大小（字节）")
@click.option("--format", "-f", "output_format", type=click.Choice(["text", "json"]), default="text", help="输出格式")
@click.option("--skip-symlinks/--no-skip-symlinks", default=True, help="跳过符号链接")
@click.option("--recursive/--no-recursive", default=True, help="递归扫描子目录")
def scan(path: str, top: int, min_size: int, output_format: str, skip_symlinks: bool, recursive: bool):
    """扫描目录（或单文件），找出占用空间最大的文件"""
    if os.path.isfile(path):
        stat = os.stat(path)
        info = FileInfo(path=os.path.abspath(path), size=stat.st_size, mtime=stat.st_mtime)
        results, skipped = [info], []
    else:
        results, skipped = scan_directory(
        path,
        top_n=top,
        min_size=min_size,
        skip_symlinks=skip_symlinks,
        recursive=recursive,
        collect_errors=True,
    )

    if output_format == "json":
        output = [
            {
                "path": r.path,
                "size": r.size,
                "size_mb": r.size_mb,
                "size_gb": r.size_gb,
                "extension": r.extension,
                "mtime": r.mtime,
                "name": r.name,
            }
            for r in results
        ]
        click.echo(json.dumps(output, ensure_ascii=False, indent=2))
    else:
        if not results:
            click.echo("未找到任何文件。")
            return

        click.echo(f"\n{'路径':<80} {'大小':>10} {'修改时间':<20}")
        click.echo("-" * 112)
        for r in results:
            from datetime import datetime

            mtime_str = datetime.fromtimestamp(r.mtime).strftime("%Y-%m-%d %H:%M")
            if r.size_gb >= 1:
                size_str = f"{r.size_gb:.2f} GB"
            else:
                size_str = f"{r.size_mb:.1f} MB"
            display_path = r.path if len(r.path) <= 78 else "..." + r.path[-75:]
            click.echo(f"  {display_path:<78} {size_str:>10} {mtime_str:<20}")

        if skipped:
            click.echo(f"\n跳过了 {len(skipped)} 个文件/目录（权限不足或符号链接）")

        total_size = sum(r.size for r in results)
        if total_size >= 1_000_000_000:
            click.echo(f"\n共 {len(results)} 个文件，总大小 {total_size / (1024**3):.2f} GB")
        else:
            click.echo(f"\n共 {len(results)} 个文件，总大小 {total_size / (1024**2):.1f} MB")


@cli.command()
@click.argument("path", type=StrippedPath(exists=True))
@click.option("--provider", "-p", type=click.Choice(["openai", "claude", "ollama", "gemini", "deepseek"]), default="ollama", help="AI 后端")
@click.option("--model", "-m", default="gpt-4o-mini", help="模型名称")
@click.option("--api-key", envvar="OPENAI_API_KEY", help="API 密钥（或通过环境变量设置）")
@click.option("--preview/--no-preview", default=False, help="只预览不实际调用 AI")
@click.option("--force", "-f", is_flag=True, default=False, help="强制重新分析，忽略缓存")
@click.option("--recursive/--no-recursive", default=True, help="递归扫描子目录")
@click.option("--top", "-n", type=int, default=50, help="最多分析 N 个文件")
@click.option("--jobs", "-j", type=int, default=0, help="AI 并发数（0=使用配置；本地 provider 始终串行）")
def analyze(path: str, provider: str, model: str, api_key: str, preview: bool, force: bool, recursive: bool, top: int, jobs: int):
    """用 AI 分析扫描结果，判断哪些文件可清理"""
    db_path = _get_db_path()
    db = Database(db_path)
    db.initialize()

    try:
        engine = AnalysisEngine(
            db, ai_provider=provider, ai_model=model, api_key=api_key or "",
            ai_max_concurrency=jobs or None,
        )

        if preview:
            # 预览模式：只扫描不做 AI
            if os.path.isfile(path):
                fi = FileInfo(path=os.path.abspath(path), size=os.path.getsize(path), mtime=os.path.getmtime(path))
                file_infos = [fi]
            else:
                file_infos = scan_directory(path, top_n=top)
            click.echo(f"\n共 {len(file_infos)} 个文件待分析")
            rule_hits = sum(1 for fi in file_infos if engine.rules.evaluate(fi))
            click.echo(f"  规则可判定: ~{rule_hits} 个")
            click.echo(f"  需 AI 分析: ~{len(file_infos) - rule_hits} 个")
            click.echo("预览模式——未实际调用 AI")
            return

        results = engine.analyze_path(path, top_n=top, force=force, recursive=recursive)
        stats = engine.stats
        try:
            from disk_cleaner.db.models import ScanRecord
            records = ScanRecord(db)
            scan_id = records.start_scan(os.path.abspath(path), len(results))
            records.finish_scan(scan_id, len(results), 0, 0)
        except Exception:
            pass

        if not results:
            click.echo("没有找到需要分析的文件。")
            return

        # 显示统计
        click.echo(f"\n分析完成。共 {len(results)} 个文件：")
        click.echo(f"  缓存命中: {stats['cache_hits']} 个")
        click.echo(f"  规则判定: {stats['rule_hits']} 个")
        click.echo(f"  AI 分析:  {stats['ai_calls']} 个")

        # 分类汇总
        safe = [r for r in results if r["decision"] == "safe_to_delete"]
        likely = [r for r in results if r["decision"] == "likely_safe"]
        review = [r for r in results if r["decision"] == "needs_review"]
        keep = [r for r in results if r["decision"] in ("keep", "critical")]

        reclaimable = sum(r["size"] for r in safe + likely)
        if reclaimable >= 1_000_000_000:
            reclaim_str = f"{reclaimable / (1024**3):.2f} GB"
        else:
            reclaim_str = f"{reclaimable / (1024**2):.1f} MB"

        click.echo(f"\n{'='*80}")
        click.echo(f"  可安全清理: {len(safe)} 个")
        click.echo(f"  可能可清理: {len(likely)} 个")
        click.echo(f"  需要确认:   {len(review)} 个")
        click.echo(f"  建议保留:   {len(keep)} 个")
        click.echo(f"  预计可释放: {reclaim_str}")

        # 显示可清理文件列表
        if safe or likely:
            click.echo(f"\n{'='*80}")
            click.echo("建议清理的文件：")
            for r in (safe + likely)[:20]:
                icon = "✓" if r["decision"] == "safe_to_delete" else "?"
                src_label = {"cache": "缓存", "rule": "规则", "ai": "AI"}.get(r.get("source", ""), "")
                click.echo(
                    f"  [{icon}] {r['name']:<40} {r['size_mb']:>8.1f} MB  "
                    f"({src_label}: {r.get('reason', '')[:50]})"
                )

    except KeyboardInterrupt:
        click.echo("\n\n已取消分析。")
        click.echo(f"本次已分析 {engine.stats.get('cache_hits', 0) + engine.stats.get('rule_hits', 0) + engine.stats.get('ai_calls', 0)} 个文件，结果已缓存。")
    finally:
        db.close()


@cli.command()
def stats():
    """查看扫描历史与清理统计"""
    db_path = _get_db_path()
    if not os.path.exists(db_path):
        click.echo("尚无扫描记录。")
        return

    db = Database(db_path)
    db.initialize()
    from disk_cleaner.db.models import ScanRecord
    records = ScanRecord(db)
    history = records.get_history(limit=10)
    totals = records.get_total_stats()
    db.close()

    click.echo(f"\n累计统计：")
    click.echo(f"  总扫描次数: {totals.get('total_scans', 0)}")
    click.echo(f"  总扫描文件: {totals.get('total_files_scanned', 0):,}")
    click.echo(f"  已清理文件: {totals.get('total_files_cleaned', 0):,}")
    bytes_freed = totals.get("total_bytes_freed", 0)
    if bytes_freed > 1_000_000_000:
        click.echo(f"  总释放空间: {bytes_freed / (1024**3):.2f} GB")
    else:
        click.echo(f"  总释放空间: {bytes_freed / (1024**2):.1f} MB")

    if history:
        click.echo(f"\n最近扫描记录：")
        for h in history[:5]:
            from datetime import datetime
            dt = datetime.fromtimestamp(h["started_at"]).strftime("%Y-%m-%d %H:%M")
            click.echo(f"  {dt}  {h['scan_path']}  扫描 {h['file_count']:,} 文件")


@cli.command()
@click.argument("path", type=StrippedPath(exists=True))
@click.option("--target", "-t", default="D:\\Relocated", help="搬迁目标盘")
@click.option("--top", "-n", type=int, default=50, help="分析前 N 个大文件")
def migrate(path: str, target: str, top: int):
    """分析可搬迁到其他盘的大文件"""
    db_path = _get_db_path()
    db = Database(db_path)
    db.initialize()
    try:
        engine = AnalysisEngine(db, ai_provider="ollama")
        results = engine.relocate_analysis(path)
        if not results:
            click.echo("未找到可搬迁的文件。")
            return
        movable = [r for r in results if r["decision"] in ("movable_direct", "movable_with_junction")]
        risky = [r for r in results if r["decision"] == "movable_risky"]
        immovable = [r for r in results if r["decision"] == "immovable"]
        total_movable = sum(r["size"] for r in movable)
        click.echo(f"\n搬迁分析结果（目标: {target}）：")
        click.echo(f"  可安全搬迁: {len(movable)} 个 ({total_movable / (1024**2):.1f} MB)")
        click.echo(f"  有风险:     {len(risky)} 个")
        click.echo(f"  不可搬迁:   {len(immovable)} 个")
        if movable:
            click.echo(f"\n建议搬迁的文件：")
            for r in movable[:15]:
                icon = ">" if r["decision"] == "movable_direct" else "~"
                click.echo(f"  [{icon}] {r['name']:<45} {r['size_mb']:>8.1f} MB")
    finally:
        db.close()


@cli.command()
@click.argument("source", type=StrippedPath(exists=True))
@click.argument("target", type=StrippedPath())
@click.option("--junction/--no-junction", default=True, help="是否在原位置创建 Junction")
@click.option("--yes", "-y", is_flag=True, default=False, help="跳过确认")
def relocate(source: str, target: str, junction: bool, yes: bool):
    """搬迁目录到目标盘，并在原位置创建 Junction（失败自动回滚）"""
    from disk_cleaner.cleaner.junction import JunctionManager

    if not os.path.isdir(source):
        click.echo("源路径必须是目录。", err=True)
        return
    source_abs = os.path.abspath(source)
    target_abs = os.path.abspath(target)
    system_root = os.path.abspath(os.environ.get("SystemRoot", r"C:\Windows")).lower()
    if (
        source_abs.lower() == system_root
        or source_abs.lower().startswith(system_root + os.sep)
        or os.path.dirname(source_abs) == os.path.abspath(source_abs)
    ):
        click.echo("拒绝搬迁 Windows 系统目录或盘符根目录。", err=True)
        return
    try:
        if os.path.commonpath([source_abs, target_abs]) == source_abs:
            click.echo("目标路径不能位于源目录内部。", err=True)
            return
    except ValueError:
        pass

    click.echo(f"源目录: {source_abs}")
    click.echo(f"目标基础: {target_abs}")
    click.echo(f"创建 Junction: {'是' if junction else '否'}")
    if not yes and not click.confirm("确认搬迁？移动大目录可能需要较长时间"):
        click.echo("已取消。")
        return

    result = JunctionManager.relocate_directory(
        source_abs, target_abs, auto_junction=junction
    )
    try:
        from disk_cleaner.logging_utils import audit
        audit("relocate", source=source_abs, target=target_abs,
              junction=junction, success=result.success, error=result.error)
    except Exception:
        pass
    if result.success:
        click.echo(f"搬迁成功: {source_abs} -> {result.target}")
        if junction:
            click.echo(f"已创建 Junction: {source_abs} -> {result.target}")
    else:
        click.echo(f"搬迁失败: {result.error}", err=True)


@cli.command()
@click.argument("files", nargs=-1)
@click.option("--mode", "-m", type=click.Choice(["backup", "recycle", "permanent"]), default="backup", help="清理模式")
@click.option("--yes", "-y", is_flag=True, default=False, help="跳过确认直接执行")
def clean(files: tuple, mode: str, yes: bool):
    """执行清理操作（默认移到备份区）"""
    from disk_cleaner.cleaner.executor import CleanExecutor

    if not files:
        click.echo("请指定要清理的文件路径。", err=True)
        return

    executor = CleanExecutor()
    import glob

    file_list: list[str] = []
    for raw in files:
        cleaned = raw.strip()
        for q in ('"', '“', '”', '‘', '’', "'"):
            cleaned = cleaned.strip(q)
        cleaned = os.path.expanduser(cleaned)
        matches = glob.glob(cleaned)
        file_list.extend(matches if matches else [cleaned])

    # 预估释放空间
    total = executor.estimate_freed_space(file_list)
    if total >= 1_000_000_000:
        size_str = f"{total / (1024**3):.2f} GB"
    else:
        size_str = f"{total / (1024**2):.1f} MB"

    if not yes:
        click.echo(f"\n即将清理 {len(file_list)} 个文件")
        click.echo(f"预计释放: {size_str}")
        click.echo(f"清理模式: {mode}")
        if not click.confirm("\n确认执行？"):
            click.echo("已取消。")
            return

    results = executor.clean(file_list, mode=mode)
    summary = executor.get_summary(results)
    try:
        from disk_cleaner.db.models import Database, ScanRecord
        stat_db = Database(_get_db_path())
        stat_db.initialize()
        try:
            ScanRecord(stat_db).record_cleanup(
                summary["success_count"],
                summary.get("total_moved", 0),
                summary.get("total_freed_real", 0),
            )
        finally:
            stat_db.close()
    except Exception:
        pass

    click.echo(f"\n清理完成:")
    click.echo(f"  成功: {summary['success_count']} 个")
    if summary['failed_count'] > 0:
        click.echo(f"  失败/跳过: {summary['failed_count']} 个")
    moved = summary.get("total_moved", 0)
    freed = summary.get("total_freed_real", 0)
    if moved:
        click.echo(f"  移入备份: {moved / (1024**2):.1f} MB（删除备份后才真正释放）")
    if freed >= 1_000_000_000:
        click.echo(f"  实际释放: {freed / (1024**3):.2f} GB")
    else:
        click.echo(f"  实际释放: {freed / (1024**2):.1f} MB")
    if executor.last_batch_id:
        click.echo(f"  备份批次: {executor.last_batch_id}")
        click.echo(f"  恢复命令: disk-cleaner backup restore {executor.last_batch_id}")


@cli.command()
@click.argument("action", type=click.Choice(["list", "show", "restore", "delete", "prune"]))
@click.argument("batch_id", required=False)
def backup(action: str, batch_id: str | None):
    """管理备份区"""
    from disk_cleaner.cleaner.executor import BackupManager

    try:
        from disk_cleaner.config import load_config
        cfg = load_config()
        manager = BackupManager(cfg.backup.dir, cfg.backup.retention_days)
    except Exception:
        manager = BackupManager()

    if action == "list":
        batches = manager.list_batches()
        if not batches:
            click.echo("暂无备份批次。")
            return
        click.echo(f"\n{'批次ID':<30} {'标签':<15} {'文件数':<10} {'创建时间':<20}")
        click.echo("-" * 80)
        for b in batches:
            file_count = len(b.get("files", []))
            created = b.get("created_at", "")[:19]
            click.echo(f"  {b['batch_id']:<30} {b.get('label', ''):<15} {file_count:<10} {created:<20}")

    elif action == "show":
        if not batch_id:
            click.echo("请指定批次 ID", err=True)
            return
        batches = manager.list_batches()
        batch = next((b for b in batches if b["batch_id"] == batch_id), None)
        if not batch:
            click.echo(f"批次 {batch_id} 不存在。", err=True)
            return
        click.echo(f"\n批次 {batch_id}:")
        for f in batch.get("files", []):
            click.echo(f"  {f['original_path']} ({f['size'] / 1024:.1f} KB)")

    elif action == "restore":
        if not batch_id:
            click.echo("请指定批次 ID", err=True)
            return
        results = manager.restore_batch(batch_id)
        success = [r for r in results if r.success]
        click.echo(f"恢复了 {len(success)}/{len(results)} 个文件")

    elif action == "delete":
        if not batch_id:
            click.echo("请指定批次 ID", err=True)
            return
        if manager.delete_batch(batch_id):
            click.echo(f"批次 {batch_id} 已永久删除。")
        else:
            click.echo(f"批次 {batch_id} 不存在。", err=True)

    elif action == "prune":
        count = manager.prune_expired()
        click.echo(f"清理了 {count} 个过期批次。")


@cli.command()
@click.option("--min-size", "-s", type=int, default=10, help="最小文件大小（MB）")
@click.option("--duration", "-d", type=int, default=0, help="监控持续时间（秒），0 表示无限")
def monitor(min_size: int, duration: int):
    """启动实时文件监控"""
    from disk_cleaner.monitor.watcher import FileMonitor, MonitorConfig

    config = MonitorConfig(
        watch_paths=["C:\\", os.path.expanduser("~\\Downloads")],
        min_file_size_mb=min_size,
        cooldown_seconds=3,
        max_alerts_per_hour=20,
    )

    mon = FileMonitor(config)

    def on_event(event):
        size_mb = event.size / (1024**2)
        click.echo(f"\n[监控] {event.event_type}: {os.path.basename(event.path)} ({size_mb:.1f} MB)")
        click.echo(f"  路径: {event.path}")

    mon.set_callback(on_event)
    mon.start()

    click.echo(f"开始监控 C 盘新增大文件（>{min_size}MB）...")
    click.echo("按 Ctrl+C 停止")

    try:
        if duration > 0:
            time.sleep(duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        mon.stop()
        click.echo("\n监控已停止。")


@cli.command()
@click.argument("path", type=StrippedPath(exists=True))
def check_deps(path: str):
    """检查文件/目录的依赖关系，防止误删"""
    from disk_cleaner.analyzer.deps import DependencyAnalyzer

    analyzer = DependencyAnalyzer()
    if os.path.isfile(path):
        # 只检查目标文件自身永远查不到引用者：同时扫描其父目录。
        # 这仍然不是全盘依赖扫描，所以绝不能把“未发现引用”表述成“安全”。
        parent = os.path.dirname(os.path.abspath(path)) or "."
        analyzer.scan_imports(path)
        analyzer.scan_directory(parent, max_files=3000)
        report = analyzer.analyze(path)
        refs = report.referrers
        exe_refs = [r for r in refs if r.lower().endswith(".exe")]
        registry_refs = analyzer.find_registry_references(path)
        click.echo(f"\n扫描范围: {parent}")
        click.echo(f"已索引 PE 文件: {analyzer.get_stats()['pe_files']} 个")
        if registry_refs:
            click.echo(f"注册表引用: {len(registry_refs)} 处")
            for item in registry_refs[:5]:
                click.echo(f"  - {item['location']} / {item['value_name']}")
        if refs:
            click.echo(f"\n{report.dll_name} 被以下文件引用:")
            for r in refs:
                click.echo(f"  - {r}")
            click.echo(
                f"\n共 {len(refs)} 处引用（其中 {len(exe_refs)} 个 exe）。"
                "存在引用，不建议删除。"
            )
        else:
            click.echo(f"\n在已扫描的范围内未发现 {report.dll_name} 的 PE 引用。")
            click.echo("⚠ 这不等于安全：引用者可能位于其他目录、注册表、计划任务或服务中。")
            click.echo("   请勿仅凭此结果删除文件；建议先备份，或用完整扫描工具复核。")
    else:
        analyzer.scan_directory(path)
        stats = analyzer.get_stats()
        click.echo(f"\n目录 {path} 的依赖分析:")
        click.echo(f"  PE 文件: {stats['pe_files']} 个")
        click.echo(f"  唯一导入: {stats['unique_imports']} 个")
        click.echo(f"  引用关系: {stats['reverse_index_entries']} 条")
        click.echo("\n注意：目录模式只统计导入关系，不给出逐个文件的安全结论。")


@cli.command()
@click.argument("path", type=StrippedPath(exists=True))
@click.option("--format", "-f", "output_format", type=click.Choice(["text", "json", "html"]), default="text")
@click.option("--output", "-o", help="导出文件路径")
def report(path: str, output_format: str, output: str):
    """生成清理报告"""
    import html as html_module

    db_path = _get_db_path()
    db = Database(db_path)
    db.initialize()

    try:
        engine = AnalysisEngine(db, ai_provider="ollama")
        results = engine.analyze_path(path, top_n=100)
        fp_suggestions = engine.fingerprints.get_cleanup_suggestions(path)

        safe = [r for r in results if r["decision"] in ("safe_to_delete", "likely_safe")]
        keep = [r for r in results if r["decision"] in ("keep", "critical")]
        total_reclaimable = sum(r["size"] for r in safe)

        if output_format == "json":
            report_data = {
                "scan_path": path,
                "total_files": len(results),
                "safe_to_delete": len(safe),
                "should_keep": len(keep),
                "reclaimable_bytes": total_reclaimable,
                "fingerprint_matches": fp_suggestions,
                "files": [{"path": r["path"], "decision": r["decision"],
                           "size_mb": r["size_mb"], "reason": r.get("reason", "")}
                          for r in results[:50]],
            }
            content = json.dumps(report_data, ensure_ascii=False, indent=2)

        elif output_format == "html":
            reclaim_str = f"{total_reclaimable / (1024**3):.2f} GB" if total_reclaimable > 1e9 else f"{total_reclaimable / (1024**2):.1f} MB"
            rows = "\n".join(
                f"<tr><td>{r['name']}</td><td>{r['size_mb']:.1f} MB</td>"
                f"<td>{r['decision']}</td><td>{r.get('reason', '')[:60]}</td></tr>"
                for r in (safe + keep)[:30]
            )
            fp_rows = "\n".join(
                f"<tr><td>{s['app_name']}</td><td>{s['file_count']}</td>"
                f"<td>{s['total_size_mb']:.1f} MB</td><td>{s['cleanup_hint']}</td></tr>"
                for s in fp_suggestions[:10]
            )
            content = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>磁盘清理报告 - {path}</title>
<style>body{{font-family:system-ui;max-width:900px;margin:20px auto;padding:0 20px}}
h1{{color:#333}} table{{border-collapse:collapse;width:100%;margin:10px 0}}
th,td{{border:1px solid #ddd;padding:8px;text-align:left}} th{{background:#f0f0f0}}
.safe{{color:#22863a}} .keep{{color:#cb2431}}</style></head><body>
<h1>磁盘清理报告</h1><p>扫描路径: {path}</p>
<p>总文件: {len(results)} | 可清理: {len(safe)} | 预计释放: {reclaim_str}</p>
<h2>清理建议</h2><table><tr><th>文件</th><th>大小</th><th>判定</th><th>理由</th></tr>
{rows}</table>
<h2>应用指纹匹配</h2><table><tr><th>应用</th><th>文件数</th><th>大小</th><th>建议</th></tr>
{fp_rows}</table>
<p><em>由 disk-cleaner 生成</em></p></body></html>"""

        else:
            content = f"磁盘清理报告\n{'='*60}\n"
            content += f"扫描路径: {path}\n总文件: {len(results)}\n"
            content += f"可安全清理: {len(safe)} 个\n预计释放: "
            content += f"{total_reclaimable / (1024**3):.2f} GB\n\n" if total_reclaimable > 1e9 else f"{total_reclaimable / (1024**2):.1f} MB\n\n"
            content += "清理建议:\n"
            for r in safe[:20]:
                content += f"  [{r['decision']}] {r['name']:<40} {r['size_mb']:>8.1f} MB\n"
            if fp_suggestions:
                content += f"\n应用指纹匹配:\n"
                for s in fp_suggestions[:10]:
                    content += f"  {s['app_name']:<20} {s['file_count']:>4} 文件  {s['total_size_mb']:>8.1f} MB\n"

        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(content)
            click.echo(f"报告已保存到 {output}")
        else:
            click.echo(content)
    finally:
        db.close()


def _run_scheduled_scan(path: str, notify: bool = True) -> dict:
    """执行一次定时扫描，写入统计与最近结果。"""
    from disk_cleaner.db.models import ScanRecord
    from disk_cleaner.cli.scheduler import ScanScheduler

    db = Database(_get_db_path())
    db.initialize()
    try:
        engine = AnalysisEngine(db, ai_provider="local", ai_model="heuristic")
        results = engine.analyze_path(path, top_n=200, recursive=True)
        safe = [r for r in results if r["decision"] == "safe_to_delete"]
        likely = [r for r in results if r["decision"] == "likely_safe"]
        reclaim = sum(r["size"] for r in safe + likely)
        try:
            records = ScanRecord(db)
            scan_id = records.start_scan(os.path.abspath(path), len(results))
            records.finish_scan(scan_id, len(results), 0, 0)
        except Exception:
            pass

        summary = {
            "path": os.path.abspath(path),
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
            "total": len(results),
            "safe": len(safe),
            "likely": len(likely),
            "reclaimable_bytes": reclaim,
        }
        state_path = os.path.expanduser("~/.disk-cleaner/last_scan.json")
        try:
            os.makedirs(os.path.dirname(state_path), exist_ok=True)
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump(summary, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

        if notify and (safe or likely):
            try:
                from disk_cleaner.gui.tray import show_toast
                show_toast(
                    "磁盘清理",
                    f"{path} 发现 {len(safe) + len(likely)} 个可清理文件，"
                    f"约 {reclaim / (1024**2):.0f} MB",
                )
            except Exception:
                pass
        return summary
    finally:
        db.close()


@cli.command()
@click.argument(
    "action",
    type=click.Choice(["start", "stop", "status", "run", "daemon"]),
    default="status",
)
def schedule(action: str):
    """管理定时扫描"""
    from disk_cleaner.cli.scheduler import ScanScheduler

    sched = ScanScheduler()

    if action == "start":
        if sched.is_daemon_running():
            click.echo("定时扫描已在运行。")
            return
        sched.config.enabled = True
        sched._save_config()

        cmd = [sys.executable, "-m", "disk_cleaner.cli.main", "schedule", "daemon"]
        popen_kwargs = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "close_fds": True,
        }
        if os.name == "nt":
            popen_kwargs["creationflags"] = (
                subprocess.DETACHED_PROCESS
                | subprocess.CREATE_NEW_PROCESS_GROUP
                | subprocess.CREATE_NO_WINDOW
            )
        else:
            popen_kwargs["start_new_session"] = True
        proc = subprocess.Popen(cmd, **popen_kwargs)
        sched.write_pid(proc.pid)
        time.sleep(0.8)
        if proc.poll() is not None:
            sched.remove_pid()
            click.echo("定时扫描启动失败，请检查日志或直接运行 schedule daemon。", err=True)
            return
        click.echo(f"定时扫描已启动（间隔 {sched.config.interval_hours} 小时，PID {proc.pid}）")
        click.echo(f"扫描路径: {', '.join(sched.config.scan_paths)}")
        try:
            from disk_cleaner.logging_utils import audit
            audit("schedule_start", pid=proc.pid, paths=sched.config.scan_paths)
        except Exception:
            pass

    elif action == "daemon":
        if sched.is_daemon_running() and sched.read_pid() != os.getpid():
            click.echo("已有定时扫描进程在运行。")
            return
        sched.write_pid()
        sched.config.enabled = True
        sched.set_scan_function(
            lambda p: _run_scheduled_scan(p, notify=sched.config.notify_on_findings)
        )
        sched.start()
        try:
            while sched.is_running:
                time.sleep(2)
        except KeyboardInterrupt:
            pass
        finally:
            sched.stop()
            sched.remove_pid()

    elif action == "stop":
        pid = sched.read_pid()
        stopped = False
        if pid:
            try:
                import psutil
                proc = psutil.Process(pid)
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except psutil.TimeoutExpired:
                    proc.kill()
                stopped = True
            except Exception:
                pass
        sched.remove_pid()
        sched.config.enabled = False
        sched._save_config()
        click.echo("定时扫描已停止" if stopped else "没有正在运行的定时扫描进程。")
        try:
            from disk_cleaner.logging_utils import audit
            audit("schedule_stop", pid=pid, stopped=stopped)
        except Exception:
            pass

    elif action == "status":
        st = sched.status
        running = sched.is_daemon_running()
        click.echo(f"定时扫描: {'运行中' if running else '已停止'}")
        click.echo(f"上次扫描: {st['last_scan'] or '无'}")
        click.echo(f"下次扫描: {st['next_scan'] or '无'}")
        click.echo(f"扫描间隔: {st['config']['interval_hours']} 小时")
        click.echo(f"自动清理: {'是' if st['config']['auto_clean'] else '否'}")
        if st["config"]["auto_clean"]:
            click.echo("注意：自动清理当前不会直接删除文件，只生成扫描结果。")

    elif action == "run":
        click.echo("正在执行立即扫描...")
        sched.set_scan_function(
            lambda p: _run_scheduled_scan(p, notify=sched.config.notify_on_findings)
        )
        sched.run_once()
        click.echo("扫描完成。")


@cli.command()
@click.option("--port", "-p", type=int, default=None, help="Web 服务器端口（默认读取配置）")
@click.option("--no-browser", is_flag=True, default=False, help="不自动打开浏览器")
def gui(port: int | None, no_browser: bool):
    """启动 Web 图形界面"""
    from disk_cleaner.gui.app import start_gui
    from disk_cleaner.config import load_config

    try:
        resolved_port = port if port is not None else load_config().gui.port
    except Exception:
        resolved_port = port or 8765
    click.echo(f"启动 Web GUI 在 http://127.0.0.1:{resolved_port}")
    click.echo("按 Ctrl+C 停止")
    start_gui(port=port, open_browser=False if no_browser else None)


@cli.command()
def tray():
    """启动系统托盘驻留（后台运行）"""
    from disk_cleaner.gui.tray import start_tray_app

    click.echo("AI 磁盘清理工具已进入后台运行")
    click.echo("右键点击系统托盘图标打开菜单")
    start_tray_app()


@cli.group()
def config():
    """管理配置和 API Key"""


@config.command("path")
def config_path():
    """显示配置文件路径"""
    from disk_cleaner.config import get_config_path

    click.echo(str(get_config_path()))


@config.command("init")
@click.option("--force", is_flag=True, default=False, help="覆盖已有配置")
def config_init(force: bool):
    """生成默认配置文件"""
    from disk_cleaner.config import ensure_default_config

    path = ensure_default_config(force=force)
    click.echo(f"配置文件已生成: {path}")


@config.command("set-key")
@click.argument("provider", type=click.Choice(["openai", "claude", "deepseek", "gemini"]))
@click.argument("api_key")
def config_set_key(provider: str, api_key: str):
    """加密存储 API Key（只需设置一次）"""
    from disk_cleaner.db.keystore import KeyStore

    store = KeyStore()
    store.set_key(provider, api_key)
    click.echo(f"已加密存储 {provider} 的 API Key（Windows DPAPI 保护）")


@config.command("show")
def config_show():
    """查看已配置的 Key"""
    from disk_cleaner.db.keystore import KeyStore

    store = KeyStore()
    providers = store.list_providers()
    if not providers:
        click.echo("未配置任何 API Key。使用: disk-cleaner config set-key <provider> <key>")
        return
    for p in providers:
        key = store.get_key(p) or ""
        masked = key[:8] + "..." + key[-4:] if len(key) > 12 else "***"
        click.echo(f"  {p}: {masked}")


@config.command("delete-key")
@click.argument("provider", type=click.Choice(["openai", "claude", "deepseek", "gemini"]))
def config_delete_key(provider: str):
    """删除已存储的 API Key"""
    from disk_cleaner.db.keystore import KeyStore

    store = KeyStore()
    if store.delete_key(provider):
        click.echo(f"已删除 {provider} 的 API Key")
    else:
        click.echo(f"{provider} 未配置 Key")


def main():
    try:
        from disk_cleaner.logging_utils import setup_logging
        setup_logging()
    except Exception:
        pass
    cli()


if __name__ == "__main__":
    main()
