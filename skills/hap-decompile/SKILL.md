---
name: hap-decompile
description: >
  Decompile HarmonyOS/OpenHarmony HAP (`.hap`) application packages to Ark
  Assembly (`.asm`) bytecode and generate structured analysis reports.
  Automated — Claude runs the analysis script, reads the report, and presents
  findings rather than just listing manual steps.
tags: [harmonyos, ohos, ark, decompile, hap, abc, bytecode, reverse-engineering]
triggers:
  - "反编译 hap"
  - "分析 hap"
  - "hap decompile"
  - "hap 分析"
  - ".hap 文件"
  - "ark_disasm"
  - "abc 字节码"
  - "hap 逆向"
  - "hap 报告"
license: MIT
---

# HAP Decompilation Skill

自动反编译和分析 HarmonyOS/OpenHarmony `.hap` 包，生成结构化报告。

**与普通文档技能的区别**：本技能包含三个独立脚本（`hap_analyze.py` / `.ps1` / `.sh`），Claude 会自动选择适合当前平台的脚本执行分析，然后读取报告并向用户解读发现。

---

## 自动化流程

当用户提供 `.hap` 文件或要求分析 HAP 时，按以下流程自动执行：

### Step 1 — 选择脚本

根据用户的操作系统自动选择：

| 平台 | 脚本 | 依赖 |
|------|------|------|
| 跨平台 (Windows/Linux/macOS) | `hap_analyze.py` | Python 3 |
| Windows (PowerShell) | `hap_analyze.ps1` | PowerShell 5+ (内置) |
| macOS / Linux / Git Bash | `hap_analyze.sh` | Python 3, unzip, grep, sed |

**选择顺序**：优先用 Python 版（最完整）→ PowerShell 版（Windows 原生）→ Bash 版。

### Step 2 — 定位脚本并执行分析

首先找到 skill 脚本目录（在安装路径下）：

```bash
# 查找 skill 安装目录（项目级优先，回退到全局）
SKILL_DIR=$(find "$(pwd)/.claude/skills" "$HOME/.claude/skills" \
  -maxdepth 2 -name "hap-decompile" -type d 2>/dev/null | head -1)
SCRIPT_DIR="$SKILL_DIR/scripts"
```

然后根据用户平台选择脚本运行：

```bash
# Python (推荐，功能最全)
python3 "$SCRIPT_DIR/hap_analyze.py" <file.hap>
python3 "$SCRIPT_DIR/hap_analyze.py" <file.hap> -o report.txt
python3 "$SCRIPT_DIR/hap_analyze.py" --abc modules.abc
python3 "$SCRIPT_DIR/hap_analyze.py" <file.hap> --no-asm
python3 "$SCRIPT_DIR/hap_analyze.py" <file.hap> --json

# PowerShell (Windows)
powershell -File "$SCRIPT_DIR/hap_analyze.ps1" <file.hap>

# Bash (macOS/Linux/Git Bash)
bash "$SCRIPT_DIR/hap_analyze.sh" <file.hap>
```

### Step 3 — 读取并解读报告

脚本输出的报告包含：
- **📦 应用信息** — bundleName、版本、SDK、API 等级
- **🧩 模块信息** — 模块类型、设备类型、Abilities、页面路由
- **🔒 权限列表** — 按类别分组（NET/STORAGE/INSTALL/NOTIFY/BG/LOCATION 等）
- **📁 资源文件** — 媒体资源清单
- **⚙️ ASM 分析** — HarmonyOS API 调用、页面/组件、方法、网络请求

读取报告后，Claude 应自动向用户解读关键发现，例如：
- 应用使用了哪些敏感权限
- 调用了哪些系统 API
- 页面结构如何
- 是否有网络请求相关代码

### Step 4 — 深度分析

如果用户需要更深入的分析，可以针对性探查：

```bash
# 提取所有字符串（找 URL、API endpoint 等）
grep -oP 'string:"[^"]*"' output.asm | sort -u | grep -iE 'https?://|api|url'

# 聚焦特定模块 API
grep -n '@ohos:router\|@ohos:net\.http' output.asm

# 查找活动相关
grep -n 'aboutToAppear\|onPageShow\|constructor' output.asm | head -20

# 查找下载/安装逻辑
grep -n 'installHap\|DownLoad\|download' output.asm
```

---

## 前置条件

### ark_disasm.exe

DevEco Studio 安装后自带，通常位于：

```
<DevEco SDK>/openharmony/toolchains/ark_disasm.exe
```

典型路径（Windows）：
```
C:/Program Files/Huawei/DevEco Studio/sdk/default/openharmony/toolchains/
D:/Program Files/Huawei/DevEco Studio/sdk/default/openharmony/toolchains/
```

脚本会自动在 PATH 和常见安装路径下查找。如果找不到，分析脚本的 `--no-asm` 模式仍可解析配置信息。

### 其他依赖

| 工具 | Python 版 | PowerShell 版 | Bash 版 |
|------|-----------|---------------|---------|
| Python 3 | ✅ 必需 | ❌ | ✅ 必需 |
| unzip | ❌ (内置 zipfile) | ❌ | ✅ 必需 |
| PowerShell 5+ | ❌ | ✅ 内置 | ❌ |
| jq | ❌ | ❌ | ❌ (用 Python) |

---

## 输出报告解读

### 应用元数据

从 `module.json` 提取：

| 字段 | 含义 | 示例 |
|------|------|------|
| `bundleName` | 应用包名 | `com.superred.appstore` |
| `versionName` | 版本名 | `1.3.0` |
| `versionCode` | 版本号 | `1030000` |
| `compileSdkVersion` | 编译 SDK | `3.1.6.3` |
| `minAPIVersion` | 最低 API 等级 | `9` |
| `virtualMachine` | 虚拟机 | `ark 9.0.0.0` |

### HarmonyOS 系统 API 前缀

| 前缀 | 模块 |
|------|------|
| `@ohos:router` | 页面路由 |
| `@ohos:window` | 窗口/状态栏 |
| `@ohos:net.http` | HTTP 请求 |
| `@ohos:net.connection` | 网络状态 |
| `@ohos:request` | 系统下载任务 |
| `@ohos:bundle` / `@ohos:bundle.installer` | 包管理/安装卸载 |
| `@ohos:app.ability.common` | Ability 上下文 |
| `@ohos:app.ability.Want` | Want 意图 |
| `@ohos:hilog` | 日志 |
| `@ohos:prompt` | 对话框 |
| `@ohos:fileio` / `@ohos:file.fs` | 文件 I/O |
| `@ohos:account.os` | 设备账号 |
| `@ohos:util.HashMap` / `@ohos:util.LruCache` | 数据结构 |

### ArkUI 组件生命周期

| 方法 | 阶段 |
|------|------|
| `constructor` | 组件构造 |
| `aboutToAppear` | 首次渲染前 |
| `onPageShow` | 页面可见 |
| `initialRender` | 首次渲染 |
| `rerender` | 重新渲染 |
| `aboutToBeDeleted` | 组件销毁 |
| `onBackground` | 应用进入后台 |
| `onForeground` | 应用回到前台 |

### HAP 包结构

```
Appstore.hap
├── ets/
│   └── modules.abc              ← Ark 字节码（核心反汇编目标）
├── module.json                  ← 模块配置（包名、版本、权限、Ability）
├── pack.info                    ← 打包摘要
├── resources.index              ← 资源索引（二进制）
└── resources/base/
    ├── media/                   ← 图片、图标、SVG 等资源
    └── profile/
        └── main_pages.json      ← 页面路由注册
```

---

## 局限性

- ⚠️ **ark_disasm 只恢复汇编级字节码**，不是原始 ArkTS/TypeScript 源码
- 变量名、注释、原始代码结构在编译后丢失
- 逻辑必须从字节码指令推断
- 没有已知的工具可以从 `.abc` 恢复 ArkTS 源码
- 字符串字面量、类/函数名、API 引用因存储在常量区而保留
- **macOS/Linux**：`ark_disasm.exe` 是 Windows PE 二进制，不能直接运行。用 `--no-asm` 模式分析 HAP 配置，或在 Windows 上生成 `.asm` 文件后跨平台分析

---

## 脚本位置

三个脚本位于 skill 安装目录的 `scripts/` 子目录中：

项目级安装：`.claude/skills/hap-decompile/scripts/`
全局安装：`~/.claude/skills/hap-decompile/scripts/`

```
hap-decompile/
├── SKILL.md
└── scripts/
    ├── hap_analyze.py      # 跨平台 Python 版（推荐）
    ├── hap_analyze.ps1     # Windows PowerShell 版
    └── hap_analyze.sh      # macOS/Linux/Git Bash 版
```
