# ohos-develop-skills

HarmonyOS / OpenHarmony 开发辅助技能包 — 为 Claude Code、Cursor、Codex 等 AI 编程代理提供 HAP 安装部署、反编译分析能力。

## 技能一览

| 技能 | 功能 | 安装 |
|------|------|------|
| **hap-install** | 一键安装 HAP 到真机/模拟器 | `npx skills add hap-install` |
| **hap-decompile** | HAP 反编译分析与报告生成 | `npx skills add hap-decompile` |

## 安装

```bash
# 从 GitHub 安装（推荐）
npx skills add github:CodingGorit/ohos-develop-skills/skills/hap-install
npx skills add github:CodingGorit/ohos-develop-skills/skills/hap-decompile

# 或克隆后本地安装
git clone https://github.com/CodingGorit/ohos-develop-skills.git
npx skills add ./skills/hap-install ./skills/hap-decompile
```

> 本技能包使用通用的 Agent Skills 格式（`SKILL.md`），兼容 Claude Code、Cursor、Codex、Windsurf、Aider 等 40+ 种 AI 编程代理。
> 如需多代理共享，加 `--universal` 参数安装到 `.agent/skills/` 目录。

验证安装后，在对话中尝试：

> *"帮我安装 hap 到手机"* / *"分析这个 hap 包"*

## 技能说明

### 🚀 hap-install

自动分析项目结构（bundleName、模块、Ability、HAP 产物路径），通过 hdc 推送到设备并启动应用。

```
分析项目结构 → 检查设备 → 停止应用 → (卸载旧版) → 推送 HAP → bm install → 启动应用
```

### 🔍 hap-decompile

解压 `.hap` 包，解析 `module.json`/`pack.info`/`main_pages.json`，调用 `ark_disasm.exe` 将 `.abc` 反汇编为 `.asm`，输出结构化分析报告（权限、API、页面路由、网络请求等）。

## 依赖

| 工具 | 用途 | 来源 |
|------|------|------|
| **hdc** | 设备通信 | DevEco Studio SDK toolchains |
| **ark_disasm.exe** | 字节码反汇编 | DevEco Studio SDK（Windows PE，仅 Windows 可用） |
| **Python 3** | 分析脚本运行 | 系统安装 |

## License

MIT
