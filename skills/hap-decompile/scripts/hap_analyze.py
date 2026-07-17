#!/usr/bin/env python3
"""
HAP Analyzer — HarmonyOS/OpenHarmony HAP 包自动分析与反编译工具

功能:
  1. 解压 .hap (ZIP) 包
  2. 解析 module.json / pack.info / main_pages.json
  3. 列出资源文件
  4. 调用 ark_disasm.exe 将 .abc 反汇编为 .asm
  5. 对 .asm 进行结构化分析（字符串、API、类引用等）
  6. 生成结构化分析报告

用法:
  python3 hap_analyze.py Appstore.hap
  python3 hap_analyze.py Appstore.hap -o report.txt
  python3 hap_analyze.py --abc modules.abc              # 仅分析已有 .abc
  python3 hap_analyze.py Appstore.hap --no-asm          # 仅配置分析
  python3 hap_analyze.py Appstore.hap --json            # JSON 格式输出
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional


# ─── 数据结构 ──────────────────────────────────────────────────────────────


@dataclass
class AppMetadata:
    bundle_name: str = ""
    version_name: str = ""
    version_code: str = ""
    compile_sdk_type: str = ""
    compile_sdk_version: str = ""
    min_api_version: str = ""
    app_name: str = ""
    icon: str = ""
    vendor: str = ""


@dataclass
class ModuleInfo:
    name: str = ""
    module_type: str = ""
    device_types: list[str] = field(default_factory=list)
    virtual_machine: str = ""
    abilities: list[dict[str, str]] = field(default_factory=list)
    pages: list[str] = field(default_factory=list)


@dataclass
class PermissionInfo:
    name: str = ""
    reason: str = ""
    category: str = ""  # NET, STORAGE, INSTALL, NOTIFY, BG, LOCATION, CAMERA, MIC, etc.


@dataclass
class AsmAnalysis:
    string_literals: list[str] = field(default_factory=list)
    ohos_apis: list[str] = field(default_factory=list)
    bundle_refs: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    page_components: list[str] = field(default_factory=list)
    network_strings: list[str] = field(default_factory=list)
    lifecycle_methods: list[str] = field(default_factory=list)
    total_lines: int = 0
    record_count: int = 0
    method_count: int = 0


@dataclass
class HapReport:
    hap_file: str = ""
    extract_dir: str = ""
    metadata: AppMetadata = field(default_factory=AppMetadata)
    modules: list[ModuleInfo] = field(default_factory=list)
    permissions: list[PermissionInfo] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    asm_analysis: Optional[AsmAnalysis] = None
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ─── 主要分析器 ────────────────────────────────────────────────────────────


class HapAnalyzer:
    """HAP 包分析器：解压、解析、反汇编、分析一站式完成。"""

    # 已知的 ArkUI 生命周期方法
    LIFECYCLE_METHODS = frozenset({
        "constructor", "aboutToAppear", "aboutToBeDeleted",
        "onPageShow", "onPageHide", "onBackPress",
        "initialRender", "rerender",
        "setInitiallyProvidedValue", "updateStateVars",
        "purgeVariableDependenciesOnElmtId",
        "onBackground", "onForeground",
    })

    # 权限分类映射
    PERMISSION_CATEGORIES = {
        "network": "NET",
        "internet": "NET",
        "install": "INSTALL",
        "storage": "STORAGE",
        "write": "STORAGE",
        "read": "STORAGE",
        "notify": "NOTIFY",
        "notification": "NOTIFY",
        "background": "BG",
        "location": "LOCATION",
        "camera": "CAMERA",
        "microphone": "MIC",
        "bluetooth": "BT",
    }

    def __init__(
        self,
        hap_path: Optional[Path] = None,
        abc_path: Optional[Path] = None,
        output_dir: Optional[Path] = None,
        no_asm: bool = False,
        ark_disasm: Optional[str] = None,
    ):
        self.hap_path = Path(hap_path) if hap_path else None
        self.abc_path = Path(abc_path) if abc_path else None
        self.output_dir = Path(output_dir) if output_dir else Path.cwd()
        self.no_asm = no_asm
        self._ark_disasm = ark_disasm

        self._extract_dir: Optional[Path] = None
        self._temp_dir: Optional[tempfile.TemporaryDirectory] = None
        self._report = HapReport()

    # ── 属性 ──────────────────────────────────────────────────────────────

    @property
    def ark_disasm(self) -> Optional[str]:
        """定位 ark_disasm.exe 路径。"""
        if self._ark_disasm:
            return self._ark_disasm

        # 从 PATH 中查找
        exe = shutil.which("ark_disasm.exe")
        if exe:
            return exe

        # 常见 DevEco SDK 安装路径
        search_paths = [
            Path("C:/Program Files") / "Huawei" / "DevEco Studio" / "sdk" / "default" / "openharmony" / "toolchains",
            Path("D:/Program Files") / "Huawei" / "DevEco Studio" / "sdk" / "default" / "openharmony" / "toolchains",
            Path("C:/Users") / os.environ.get("USERNAME", "") / "AppData" / "Local" / "Huawei" / "DevEco Studio" / "sdk" / "default" / "openharmony" / "toolchains",
            Path("D:/Huawei") / "DevEco Studio" / "sdk" / "default" / "openharmony" / "toolchains",
        ]
        for p in search_paths:
            disasm = p / "ark_disasm.exe"
            if disasm.exists():
                return str(disasm)

        return None

    # ── 解压 ──────────────────────────────────────────────────────────────

    def _extract_hap(self) -> Path:
        """解压 .hap 文件到临时目录。"""
        if not self.hap_path or not self.hap_path.exists():
            raise FileNotFoundError(f"HAP 文件不存在: {self.hap_path}")

        self._temp_dir = tempfile.TemporaryDirectory(prefix="hap_")
        extract_dir = Path(self._temp_dir.name)
        self._report.hap_file = str(self.hap_path)

        try:
            with zipfile.ZipFile(self.hap_path, "r") as zf:
                zf.extractall(extract_dir)
            self._report.extract_dir = str(extract_dir)
            return extract_dir
        except zipfile.BadZipFile:
            raise ValueError(f"文件不是有效的 HAP/ZIP 格式: {self.hap_path}")

    # ── 配置解析 ──────────────────────────────────────────────────────────

    def _load_json(self, path: Path, label: str) -> Optional[dict]:
        """安全加载 JSON 文件，失败时记录警告。"""
        if not path.exists():
            self._report.warnings.append(f"{label} 不存在: {path}")
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            self._report.warnings.append(f"{label} 解析失败: {e}")
            return None

    def _parse_module_json(self, extract_dir: Path):
        """解析 module.json。"""
        data = self._load_json(extract_dir / "module.json", "module.json")
        if not data:
            return

        app = data.get("app", {})
        module = data.get("module", {})

        # App 元数据
        meta = self._report.metadata
        meta.bundle_name = app.get("bundleName", "")
        meta.version_name = app.get("versionName", "")
        meta.version_code = str(app.get("versionCode", ""))
        meta.compile_sdk_type = app.get("compileSdkType", "")
        meta.compile_sdk_version = app.get("compileSdkVersion", "")
        meta.min_api_version = str(app.get("minAPIVersion", ""))
        meta.app_name = app.get("appName", "")
        meta.icon = app.get("icon", "")
        meta.vendor = app.get("vendor", "")

        # Module 信息
        mod = ModuleInfo(
            name=module.get("name", ""),
            module_type=module.get("type", ""),
            device_types=module.get("deviceTypes", []),
            virtual_machine=module.get("virtualMachine", ""),
        )

        # Abilities
        for ab in module.get("abilities", []):
            mod.abilities.append({
                "name": ab.get("name", ""),
                "srcEntry": ab.get("srcEntry", ""),
                "description": ab.get("description", ""),
                "launchType": ab.get("launchType", ""),
            })

        self._report.modules.append(mod)

        # 权限
        for perm in module.get("requestPermissions", []):
            name = perm.get("name", "")
            p = PermissionInfo(
                name=name,
                reason=perm.get("reason", ""),
            )
            # 自动分类
            name_lower = name.lower()
            for keyword, cat in self.PERMISSION_CATEGORIES.items():
                if keyword in name_lower:
                    p.category = cat
                    break
            self._report.permissions.append(p)

    def _parse_pack_info(self, extract_dir: Path):
        """解析 pack.info。"""
        data = self._load_json(extract_dir / "pack.info", "pack.info")
        if not data:
            return
        # pack.info 可能包含额外的模块摘要信息 — 目前暂不扩充字段

    def _parse_main_pages(self, extract_dir: Path):
        """解析页面路由配置。"""
        pages_path = extract_dir / "resources" / "base" / "profile" / "main_pages.json"
        data = self._load_json(pages_path, "main_pages.json")
        if data and self._report.modules:
            self._report.modules[0].pages = data.get("src", [])

    def _list_resources(self, extract_dir: Path):
        """列出资源文件。"""
        res_dir = extract_dir / "resources"
        if not res_dir.exists():
            return
        resources = []
        for f in sorted(res_dir.rglob("*")):
            if f.is_file():
                rel = f.relative_to(extract_dir)
                resources.append(str(rel.as_posix()))
        self._report.resources = resources

    def _parse_configs(self, extract_dir: Path):
        """执行全部配置解析。"""
        self._parse_module_json(extract_dir)
        self._parse_pack_info(extract_dir)
        self._parse_main_pages(extract_dir)
        self._list_resources(extract_dir)

    # ── 反汇编 ────────────────────────────────────────────────────────────

    def _find_abc(self, extract_dir: Path) -> Optional[Path]:
        """在提取目录中查找 .abc 文件。"""
        # 优先查找 ets/modules.abc（最常见）
        candidates = [
            extract_dir / "ets" / "modules.abc",
        ]
        # 递归查找所有 .abc
        candidates.extend(sorted(extract_dir.rglob("*.abc")))
        seen = set()
        for c in candidates:
            if c.exists() and c not in seen:
                seen.add(c)
                return c
        return None

    def _run_ark_disasm(self, abc_file: Path, asm_file: Path) -> bool:
        """调用 ark_disasm.exe 反汇编 .abc → .asm。"""
        disasm = self.ark_disasm
        if not disasm:
            self._report.warnings.append(
                "未找到 ark_disasm.exe，无法反汇编。"
                "请确保 DevEco Studio 已安装且 toolchains 目录在 PATH 中。"
            )
            return False

        cmd = [disasm, str(abc_file), str(asm_file)]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                stderr = result.stderr.strip() or "未知错误"
                self._report.errors.append(f"ark_disasm 反汇编失败: {stderr}")
                return False
            return True
        except FileNotFoundError:
            self._report.errors.append(f"ark_disasm.exe 不可执行: {disasm}")
            return False
        except subprocess.TimeoutExpired:
            self._report.errors.append("ark_disasm 超时 (120s)")
            return False
        except Exception as e:
            self._report.errors.append(f"ark_disasm 异常: {e}")
            return False

    # ── ASM 分析 ──────────────────────────────────────────────────────────

    def _analyze_asm(self, asm_file: Path) -> AsmAnalysis:
        """分析 .asm 文件，提取结构化信息。"""
        analysis = AsmAnalysis()

        if not asm_file.exists():
            self._report.warnings.append(f".asm 文件不存在: {asm_file}")
            return analysis

        content = asm_file.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()
        analysis.total_lines = len(lines)

        # 收集字符串字面量
        for m in re.finditer(r'string:"([^"]*)"', content):
            s = m.group(1)
            if s and s not in analysis.string_literals:
                analysis.string_literals.append(s)
                if s in self.LIFECYCLE_METHODS:
                    analysis.lifecycle_methods.append(s)

        # 收集 @ohos API
        for m in re.finditer(r'@ohos:[\w.]+', content):
            api = m.group(0)
            if api not in analysis.ohos_apis:
                analysis.ohos_apis.append(api)

        # 收集 @bundle 引用
        for m in re.finditer(r'@bundle:[^\s"]+', content):
            ref = m.group(0)
            if ref not in analysis.bundle_refs:
                analysis.bundle_refs.append(ref)

        # 收集方法名（驼峰命名字符串）
        for m in re.finditer(r'string:"([a-z]+[A-Z][^"]*)"', content):
            method = m.group(1)
            if method and method not in analysis.methods:
                analysis.methods.append(method)

        # 收集页面/组件路径
        for m in re.finditer(r'string:"[^"]*\.#[0-9]+#"', content):
            page = m.group(0).removeprefix('string:"').removesuffix('"')
            if page and page not in analysis.page_components:
                analysis.page_components.append(page)

        # 收集网络相关字符串
        net_pattern = re.compile(
            r'string:"(https?://|api\.|url|get|post|put|delete|request|'
            r'download|upload|fetch|socket)[^"]*"',
            re.IGNORECASE,
        )
        for m in net_pattern.finditer(content):
            ns = m.group(0)
            if ns not in analysis.network_strings:
                analysis.network_strings.append(ns)

        # 统计 Records 和 methods 数量
        analysis.record_count = content.count("# Record ")
        method_matches = re.findall(r'method:\w+', content)
        analysis.method_count = len(set(method_matches))

        return analysis

    # ── 报告生成 ──────────────────────────────────────────────────────────

    def _build_text_report(self) -> str:
        """生成人类可读的文本报告。"""
        r = self._report
        lines = []
        sep = "─" * 64

        lines.append(f"{'=' * 64}")
        lines.append(f"  HAP 分析报告")
        lines.append(f"{'=' * 64}")
        lines.append(f"  文件: {r.hap_file or '(N/A)'}")
        lines.append(f"")

        # ── 应用元数据 ──
        m = r.metadata
        lines.append(f"📦 应用信息 {sep}")
        lines.append(f"  Bundle Name   : {m.bundle_name or '(未设置)'}")
        lines.append(f"  Version       : {m.version_name} ({m.version_code})")
        lines.append(f"  App Name      : {m.app_name or '(未设置)'}")
        lines.append(f"  Vendor        : {m.vendor or '(未设置)'}")
        lines.append(f"  Compile SDK   : {m.compile_sdk_type} {m.compile_sdk_version}")
        lines.append(f"  Min API       : {m.min_api_version}")
        lines.append(f"")

        # ── 模块信息 ──
        for mod in r.modules:
            lines.append(f"🧩 模块: {mod.name} ({mod.module_type}) {sep}")
            lines.append(f"  设备类型       : {', '.join(mod.device_types) if mod.device_types else '(未设置)'}")
            lines.append(f"  虚拟机         : {mod.virtual_machine or '(未设置)'}")
            if mod.abilities:
                lines.append(f"  Abilities:")
                for ab in mod.abilities:
                    lines.append(f"    - {ab['name']:30s} → {ab['srcEntry']}")
            else:
                lines.append(f"  Abilities      : (无)")
            if mod.pages:
                lines.append(f"  页面路由:")
                for p in mod.pages:
                    lines.append(f"    - {p}")
            lines.append(f"")

        # ── 权限 ──
        if r.permissions:
            lines.append(f"🔒 权限列表 {sep}")
            # 按类别分组
            by_cat: dict[str, list[PermissionInfo]] = {}
            for p in r.permissions:
                by_cat.setdefault(p.category, []).append(p)
            for cat in sorted(by_cat.keys()):
                perms = by_cat[cat]
                cat_label = cat if cat else "未分类"
                lines.append(f"  [{cat_label}] ({len(perms)} 项)")
                for p in perms:
                    short_name = p.name.split(".")[-1]  # 只显示最后一段
                    lines.append(f"    - {short_name:35s} {p.reason or ''}")
            lines.append(f"")

        # ── 资源 ──
        if r.resources:
            lines.append(f"📁 资源文件 ({len(r.resources)} 个) {sep}")
            media = [x for x in r.resources if not x.startswith("resources/base/profile")]
            for res in media[:30]:
                lines.append(f"    {res}")
            if len(media) > 30:
                lines.append(f"    ... 还有 {len(media) - 30} 个文件")
            lines.append(f"")

        # ── ASM 分析 ──
        if r.asm_analysis:
            a = r.asm_analysis
            lines.append(f"⚙️  ASM 反汇编分析 {sep}")
            lines.append(f"  总行数          : {a.total_lines}")
            lines.append(f"  Records 数      : {a.record_count}")
            lines.append(f"  方法数          : {a.method_count}")
            lines.append(f"")

            if a.ohos_apis:
                lines.append(f"  📡 HarmonyOS API 调用 ({len(a.ohos_apis)} 项):")
                for api in sorted(a.ohos_apis)[:40]:
                    lines.append(f"    - {api}")
                if len(a.ohos_apis) > 40:
                    lines.append(f"    ... 还有 {len(a.ohos_apis) - 40} 个")
                lines.append(f"")

            if a.page_components:
                lines.append(f"  📄 页面/组件 ({len(a.page_components)} 项):")
                for p in sorted(a.page_components)[:20]:
                    lines.append(f"    - {p}")
                if len(a.page_components) > 20:
                    lines.append(f"    ... 还有 {len(a.page_components) - 20} 个")
                lines.append(f"")

            if a.methods:
                lines.append(f"  🔧 自定义方法 ({len(a.methods)} 项):")
                for method in sorted(a.methods)[:20]:
                    lines.append(f"    - {method}")
                if len(a.methods) > 20:
                    lines.append(f"    ... 还有 {len(a.methods) - 20} 个")
                lines.append(f"")

            if a.lifecycle_methods:
                lines.append(f"  🔄 生命周期方法:")
                for lm in sorted(a.lifecycle_methods):
                    lines.append(f"    - {lm}")
                lines.append(f"")

            if a.network_strings:
                lines.append(f"  🌐 网络相关 ({len(a.network_strings)} 项):")
                for ns in sorted(a.network_strings)[:15]:
                    lines.append(f"    - {ns}")
                if len(a.network_strings) > 15:
                    lines.append(f"    ... 还有 {len(a.network_strings) - 15} 个")
                lines.append(f"")

            if a.string_literals:
                lines.append(f"  📝 字符串字面量 (前 30 / {len(a.string_literals)} 项):")
                for s in sorted(a.string_literals)[:30]:
                    lines.append(f"    \"{s}\"")
                if len(a.string_literals) > 30:
                    lines.append(f"    ... 还有 {len(a.string_literals) - 30} 个")
                lines.append(f"")

        # ── 警告与错误 ──
        if r.warnings:
            lines.append(f"⚠️  警告 {sep}")
            for w in r.warnings:
                lines.append(f"  - {w}")
            lines.append(f"")
        if r.errors:
            lines.append(f"❌ 错误 {sep}")
            for e in r.errors:
                lines.append(f"  - {e}")
            lines.append(f"")

        lines.append(f"{'=' * 64}")
        lines.append(f"  分析完成")
        lines.append(f"{'=' * 64}")

        return "\n".join(lines)

    def _build_json_report(self) -> dict:
        """生成 JSON 格式报告。"""
        r = self._report
        result = {
            "hap_file": r.hap_file,
            "metadata": asdict(r.metadata),
            "modules": [asdict(m) for m in r.modules],
            "permissions": [
                {
                    "name": p.name,
                    "reason": p.reason,
                    "category": p.category,
                }
                for p in r.permissions
            ],
            "resources": r.resources,
            "warnings": r.warnings,
            "errors": r.errors,
        }
        if r.asm_analysis:
            a = r.asm_analysis
            result["asm_analysis"] = {
                "total_lines": a.total_lines,
                "record_count": a.record_count,
                "method_count": a.method_count,
                "ohos_apis": sorted(a.ohos_apis),
                "bundle_refs": sorted(a.bundle_refs),
                "page_components": sorted(a.page_components),
                "methods": sorted(a.methods),
                "lifecycle_methods": sorted(a.lifecycle_methods),
                "network_strings": a.network_strings[:100],
                "string_literals": a.string_literals[:500],
                "total_string_literals": len(a.string_literals),
            }
        return result

    # ── 主流程 ────────────────────────────────────────────────────────────

    def analyze(self) -> HapReport:
        """执行完整的 HAP 分析流程并返回报告对象。"""
        # 1. 解压或使用已有目录
        if self.hap_path:
            extract_dir = self._extract_hap()
        else:
            extract_dir = self.output_dir

        # 2. 解析配置
        self._parse_configs(extract_dir)

        # 3. 定位 .abc
        abc_file = self.abc_path or self._find_abc(extract_dir)

        if abc_file and not self.no_asm:
            # 4. 反汇编
            asm_file = (self.output_dir / abc_file.stem).with_suffix(".asm")
            if self._run_ark_disasm(abc_file, asm_file):
                # 5. 分析 ASM
                self._report.asm_analysis = self._analyze_asm(asm_file)
            else:
                # 尝试在当前目录找已存在的 .asm
                fallback = self.output_dir / "output.asm"
                if fallback.exists():
                    self._report.asm_analysis = self._analyze_asm(fallback)
        elif not abc_file:
            self._report.warnings.append("未找到 .abc 字节码文件，跳过反汇编步骤。")

        return self._report

    def cleanup(self):
        """清理临时文件。"""
        if self._temp_dir:
            self._temp_dir.cleanup()
            self._temp_dir = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.cleanup()


# ─── 入口 ────────────────────────────────────────────────────────────────


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="HAP Analyzer — HarmonyOS/OpenHarmony HAP 包自动分析工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("hap", nargs="?", type=Path, default=None,
                        help=".hap 文件路径")
    parser.add_argument("--abc", type=Path, default=None,
                        help="直接指定 .abc 文件（跳过解压步骤）")
    parser.add_argument("-o", "--output", type=Path, default=None,
                        help="输出报告到文件（默认 stdout）")
    parser.add_argument("--no-asm", action="store_true",
                        help="跳过反汇编和 ASM 分析，仅解析配置")
    parser.add_argument("--json", action="store_true",
                        help="以 JSON 格式输出")
    parser.add_argument("--ark-disasm", type=str, default=None,
                        help="指定 ark_disasm.exe 路径")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # 参数校验：至少需要 .hap 或 --abc
    if not args.hap and not args.abc:
        print("错误: 请指定 .hap 文件或 --abc 文件。", file=sys.stderr)
        return 1

    with HapAnalyzer(
        hap_path=args.hap,
        abc_path=args.abc,
        output_dir=args.output.parent if args.output else None,
        no_asm=args.no_asm,
        ark_disasm=args.ark_disasm,
    ) as analyzer:
        report = analyzer.analyze()

        if args.json:
            output = json.dumps(analyzer._build_json_report(), ensure_ascii=False, indent=2)
        else:
            output = analyzer._build_text_report()

        if args.output:
            args.output.write_text(output, encoding="utf-8")
            print(f"报告已保存: {args.output}")
        else:
            print(output)

        # 若有错误，返回非零退出码
        if report.errors:
            return 2
        return 0


if __name__ == "__main__":
    sys.exit(main())
