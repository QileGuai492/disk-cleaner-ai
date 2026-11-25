# AI 磁盘清理工具 - 使用手册

## 安装

```bash
pip install -e ".[dev]"
```

## 命令速查

| 命令 | 用途 | 示例 |
|------|------|------|
| `scan` | 扫描目录找大文件 | `disk-cleaner scan C:\Users --top 50` |
| `analyze` | AI 分析可清理性 | `disk-cleaner analyze C:\Users -p deepseek` |
| `migrate` | 分析哪些能搬到 D 盘 | `disk-cleaner migrate C:\ -t D:\Relocated` |
| `relocate` | 搬迁目录并创建 Junction | `disk-cleaner relocate "C:\Program Files\App" D:\Relocated` |
| `check-deps` | 检查 DLL 是否被引用 | `disk-cleaner check-deps C:\Program Files` |
| `clean` | 执行清理 | `disk-cleaner clean file1.tmp file2.log -m backup` |
| `backup` | 管理备份区 | `disk-cleaner backup list` |
| `monitor` | 实时监控 C 盘新文件 | `disk-cleaner monitor --min-size 10` |
| `report` | 导出清理报告 | `disk-cleaner report C:\ -f html -o report.html` |
| `schedule` | 定时扫描 | `disk-cleaner schedule start` |
| `stats` | 清理统计 | `disk-cleaner stats` |
| `gui` | Web 图形界面 | `disk-cleaner gui --port 8765` |
| `tray` | 系统托盘驻留 | `disk-cleaner tray` |
| `config` | 管理 API Key | `disk-cleaner config set-key deepseek <key>` |

---

## 详细说明

### 1. `scan` — 扫描目录

找出占用空间最大的文件。

```bash
disk-cleaner scan C:\Users               # 扫描用户目录，默认显示前 50
disk-cleaner scan C:\ --top 100          # 显示前 100
disk-cleaner scan D:\ --min-size 100000  # 只看 >100KB 的文件
disk-cleaner scan ~/Downloads -f json    # JSON 格式输出
```

### 2. `analyze` — AI 分析

三层分析流程：**缓存命中** → **规则引擎** → **AI 判断**。

```bash
# 预览模式（不调 AI，看有多少文件能被规则处理）
disk-cleaner analyze ~/Downloads --preview

# 用 OpenAI
disk-cleaner analyze C:\Users -p openai -m gpt-4o-mini

# 用本地模型（需先启动 Ollama）
disk-cleaner analyze C:\Users -p ollama -m qwen2.5:1.5b

# 强制重新分析（忽略缓存）
disk-cleaner analyze C:\Users --force
```

> 云端调用前会对路径脱敏；`.env`、`.pem`、`.key` 等扩展名不会上云。AI 未配置或调用失败时，来源会显示“本地降级”，不会伪装成 AI，也不会写入 AI 缓存。
> 连续 3 次失败会熔断；配置 `ai.budget_usd` 后，预算用尽也会显式降级。

输出示例：
```
分析完成。共 5000 个文件：
  缓存命中: 4200 个
  规则判定: 600 个
  AI 分析:  200 个

  可安全清理: 3800 个
  可能可清理: 800 个
  建议保留:   400 个
  预计可释放: 12.5 GB
```

### 3. `migrate` — 搬迁分析

分析 C 盘哪些文件可以搬到其他盘。

```bash
disk-cleaner migrate C:\                      # 分析 C 盘
disk-cleaner migrate C:\ -t E:\Relocated      # 指定目标盘
```

输出分级：
```
可安全搬迁: 5 个 (32.1 GB)     ← 直接搬走
有风险:     3 个               ← 搬走+创建 Junction
不可搬迁:   12 个              ← 硬绑 C 盘
```

### 3.1 `relocate` — 搬迁目录并创建 Junction

```bash
# 确认后搬迁整个目录，并在原位置创建 Junction
disk-cleaner relocate "C:\Program Files\WeChat" D:\Relocated

# 只移动，不创建链接
disk-cleaner relocate "D:\Games\OldGame" E:\Games --no-junction -y
```

搬迁采用“移动 → 创建链接 → 失败自动回滚”的顺序；如果 `mklink` 失败，目录会移回原位置。Windows 系统目录和盘符根目录会被拒绝。

### 4. `check-deps` — 依赖检查

检查文件是否被其他程序依赖，作为删除前的参考。

> 单文件模式只扫描目标文件所在父目录中的 PE 文件。**“未发现引用”不等于安全**：引用者可能在其它目录、注册表、计划任务或服务中。工具会明确提示这一点，请勿仅凭此结果删除。

```bash
disk-cleaner check-deps C:\Windows\System32\some.dll   # 单文件（扫描父目录）
disk-cleaner check-deps C:\Program Files\MyApp          # 整个目录（只统计）
```

### 5. `clean` — 执行清理

```bash
# 移到备份区（推荐）
disk-cleaner clean file1.tmp file2.log -m backup

# 移到回收站
disk-cleaner clean file1.tmp -m recycle

# 永久删除（不可恢复！）
disk-cleaner clean file1.tmp -m permanent

# 跳过确认
disk-cleaner clean file1.tmp -y
```

> 清理前会经过独立的安全策略：系统目录、用户关键目录、`.sys/.drv`、Junction/Symlink 等会被拒绝。
> 默认备份区在 `~/disk-cleaner-backup`。**如果备份区与待清理文件在同一个分区，移动到备份区不会立即释放空间**，需要删除备份后才释放。
> 清理结束会显示备份批次 ID，可用 `disk-cleaner backup restore <批次ID>` 恢复。

### 6. `backup` — 备份管理

```bash
disk-cleaner backup list                      # 查看所有批次
disk-cleaner backup show 2026-07-10_15-30     # 查看某批次
disk-cleaner backup restore 2026-07-10_15-30  # 恢复整个批次
disk-cleaner backup delete 2026-07-10_15-30   # 永久删除批次
disk-cleaner backup prune                     # 清理过期备份（30 天）
```

### 7. `monitor` — 实时监控

监控 C 盘新增大文件，弹窗提醒。

```bash
# 监控 >10MB 的新文件
disk-cleaner monitor --min-size 10

# 监控 60 秒后自动停止
disk-cleaner monitor --min-size 5 --duration 60
```

### 8. `report` — 导出报告

```bash
# 终端输出
disk-cleaner report C:\Users

# JSON 格式
disk-cleaner report C:\ -f json

# HTML 报告
disk-cleaner report C:\ -f html -o cleanup_report.html
```

### 9. `schedule` — 定时扫描

```bash
disk-cleaner schedule start     # 启动（默认每 24 小时）
disk-cleaner schedule status    # 查看状态
disk-cleaner schedule run       # 立即执行一次
disk-cleaner schedule stop      # 停止
```

> `start` 会启动独立后台进程，PID 写入 `~/.disk-cleaner/scheduler.pid`；`stop` 终止该进程。
> `auto_clean` 当前不会直接删除文件，只生成扫描结果；自动删除仍需人工确认。

配置文件 `~/.disk-cleaner/schedule.json` 可自定义：
```json
{
  "scan_paths": ["C:\\Users", "D:\\"],
  "interval_hours": 12,
  "auto_clean": false
}
```

### 10. `stats` — 统计

```bash
disk-cleaner stats
```

输出：
```
累计统计：
  总扫描次数: 15
  总扫描文件: 1,234,567
  已清理文件: 12,340
  总释放空间: 45.67 GB
```

### 11. `gui` — Web 界面

```bash
disk-cleaner gui                    # 启动并打开浏览器
disk-cleaner gui --port 9090        # 指定端口
disk-cleaner gui --no-browser       # 不自动打开浏览器
```

打开 `http://127.0.0.1:8765`，界面提供：
- 扫描输入框（带清空按钮）、AI 复选框（需先配置 Key）
- SSE 实时进度条、结果逐条呈现
- 筛选栏：大小、判定、文件名正则、理由正则
- 点击文件名在资源管理器中定位
- 清理顾问：单文件/文件夹/整次扫描问答，给证据和清理计划草案（不直接执行）
- 恢复备份：按批次恢复已清理文件
- 全选/批量清理、导出报告；`keep/critical` 行不可勾选
- 7 套主题切换（右上角下拉）

> GUI 只监听 `127.0.0.1`，并在启动时生成一次性会话 Token。请勿把端口转发到局域网或公网。
> 清理请求只接受“本次扫描结果”中的路径；页面刷新后需要重新扫描才能再次清理。

### 12. `tray` — 系统托盘

```bash
disk-cleaner tray
```

托盘图标右键菜单：
- **立即扫描** — 触发扫描
- **扫描 C 盘** — 用本地规则快速扫描
- **退出** — 停止托盘

后台每小时自动扫描一次，发现可清理文件时弹 Windows 通知。

---

## 环境变量

| 变量 | 说明 |
|------|------|
| `OPENAI_API_KEY` | OpenAI API 密钥 |
| `ANTHROPIC_API_KEY` | Claude API 密钥 |
| `GEMINI_API_KEY` | Gemini API 密钥 |
| `DEEPSEEK_API_KEY` | DeepSeek API 密钥 |

Ollama 本地模型不需要 API Key，启动 Ollama 服务后直接使用。

---

## 常用工作流

### 首次深度清理

```bash
# 1. 扫描 C 盘前 200 大文件
disk-cleaner scan C:\ --top 200

# 2. AI 预览（看看不需要 AI 能判多少）
disk-cleaner analyze C:\ --preview

# 3. 正式分析（用 OpenAI）
disk-cleaner analyze C:\ -p openai -m gpt-4o-mini

# 4. 检查依赖
disk-cleaner check-deps C:\

# 5. 导出报告
disk-cleaner report C:\ -f html -o report.html

# 6. 确认后清理
disk-cleaner clean <选中的文件> -m backup
```

### 日常维护

```bash
# 启动定时扫描
disk-cleaner schedule start

# 或启动托盘常驻
disk-cleaner tray

# 或启动实时监控
disk-cleaner monitor --min-size 10
```

### 搬迁到 D 盘

```bash
# 1. 分析搬迁机会
disk-cleaner migrate C:\ -t D:\Relocated

# 2. 检查依赖（确保搬迁不会破坏其他程序）
disk-cleaner check-deps <要搬迁的目录>

# 3. 确认后搬迁目录并创建 Junction
disk-cleaner relocate <要搬迁的目录> D:\Relocated
```

## 配置文件

```bash
disk-cleaner config init      # 生成 ~/.disk-cleaner/config.json
disk-cleaner config path      # 显示配置文件路径
```

常用配置（JSON，未写的字段使用默认值）：

```json
{
  "backup": { "dir": "~/disk-cleaner-backup", "retention_days": 30 },
  "scan": { "max_dirs": 5000, "skip_symlinks": true },
  "ai": {
    "provider": "local",
    "model": "",
    "max_retries": 3,
    "rate_limit_rpm": 30,
    "timeout_seconds": 30,
    "budget_usd": 0,
    "input_cost_per_million": 0,
    "output_cost_per_million": 0,
    "cloud_blocklist": []
  },
  "privacy": { "level": "strict" },
  "gui": { "port": 8765, "open_browser": true },
  "monitor": {
    "min_file_size_mb": 10,
    "cooldown_seconds": 3,
    "max_alerts_per_hour": 10,
    "max_files_per_scan": 10000
  },
  "log": { "level": "INFO" }
}
```

配置文件损坏时，CLI/GUI 会回退到默认值；可用 `disk-cleaner config init --force` 重新生成。

## 数据目录

所有数据存储在 `~/.disk-cleaner/`：
```
~/.disk-cleaner/
├── cache.db             # AI 分析缓存 + 规则库 + 扫描/清理记录
├── config.json          # 统一配置
├── schedule.json        # 定时任务配置
├── schedule_state.json  # 上次/下次扫描时间
├── scheduler.pid        # 定时进程 PID
├── last_scan.json       # 最近一次定时扫描摘要
├── logs/
│   ├── disk-cleaner.log # 轮转日志
│   └── audit.jsonl      # 清理/搬迁审计记录
└── credentials/
    └── keys.enc         # API Key（Windows DPAPI 加密）
```

备份区默认在 `~/disk-cleaner-backup/`；每次执行清理前会自动清理过期批次（默认 30 天）。

## 卸载

手动删除以下目录：
```
~/.disk-cleaner/
~/disk-cleaner-backup/
```

## 获取帮助

```bash
disk-cleaner --help              # 命令列表
disk-cleaner <命令> --help        # 命令详细帮助
```
