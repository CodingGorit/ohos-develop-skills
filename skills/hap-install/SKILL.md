---
name: hap-install
description: HarmonyOS HAP 应用安装部署工具 — 自动分析项目结构，一键将 .hap 包通过 hdc 安装到真机/模拟器。
triggers:
  - "安装 hap"
  - "部署应用到手机"
  - "hdc install"
  - "hdc uninstall"
  - "bm install"
  - "hap 安装"
  - "运行到真机"
  - "部署到模拟器"
  - "安装 unsigned hap"
  - "部署 HAP"
  - "编译运行"
  - "部署调试"
tags:
  - harmonyos
  - openharmony
  - hdc
  - hap
  - deploy
  - install
  - device
  - automatic
license: MIT
---

# HAP 安装部署技能

自动分析当前 HarmonyOS 项目结构，提取 bundleName、模块、Ability、HAP 路径等信息，
然后将 `.hap` 包通过 hdc 安装到真机/模拟器并启动应用。

---

## 自动分析能力

脚本在执行时会自动读取项目中的关键文件：

| 信息 | 来源 |
|------|------|
| **bundleName** | `AppScope/app.json5` → `app.bundleName` |
| **模块列表** | 扫描所有 `src/main/module.json5`（排除 ohosTest） |
| **模块类型** | `module.json5` → `module.type`（entry / feature / har） |
| **主 Ability** | `module.json5` → `module.mainElement` |
| **所有 Ability** | `module.json5` → `module.abilities[].name` |
| **目标设备类型** | `module.json5` → `module.deviceTypes` |
| **HAP 产物路径** | 扫描 `*/build/*/outputs/default/*.hap`，优先选 unsigned |

---

## 使用方式

### 一键部署（单模块项目）

```bash
# 自动分析 -> 安装 -> 启动
bash /path/to/hdc-install.sh
```

### 多模块项目

```bash
# 先查看模块列表
bash hdc-install.sh --list

# 指定模块部署
bash hdc-install.sh -m feature
```

### 查看项目结构

```bash
bash hdc-install.sh --list
```

输出示例：
```
========== 项目分析结果 ==========
  bundleName:       cn.gorit.codetemplate
  [模块 1]
    名称:       entry (entry)
    目录:       ./entry
    mainElement: EntryAbility
    Ability 列表: EntryAbility
    目标设备:   default
    HAP 产物:   entry/build/default/outputs/default/entry-default-unsigned.hap
==================================
```

### 其他选项

```bash
# 覆盖 bundleName
bash hdc-install.sh -b com.example.app

# 指定 Ability
bash hdc-install.sh -a MainAbility

# 指定 HAP 路径
bash hdc-install.sh -h /path/to/app-signed.hap

# 首次安装（跳过卸载）
bash hdc-install.sh --no-uninstall

# 仅安装不启动
bash hdc-install.sh --no-start
```

---

## 安装流程

```
分析项目结构 → 检查设备连接 → 停止应用 → (卸载旧版) → 推送 HAP → bm install → 清理临时文件 → 启动应用
```

每一步都有错误处理：
- **停止/卸载**失败 → 忽略继续（未安装或未运行是正常情况）
- **推送/安装**失败 → 立即中止并给出排查提示
- **启动**失败 → 中止并显示详情

---

## 常见问题排查

### `hdc: command not found`
- Windows: `%USERPROFILE%\AppData\Local\Huawei\Sdk\openharmony\*\toolchains`
- macOS: `~/Library/Huawei/Sdk/openharmony/*/toolchains`
- 或在 DevEco Studio 中打开 Terminal 直接执行

### 未检测到设备
```bash
hdc kill
hdc start
hdc list targets
```

### 安装失败
- HAP 未编译 → 先用 DevEco Studio Build
- 设备空间不足 → 清理设备存储
- 签名问题 → unsigned HAP 仅用于 debug 设备和模拟器
- 应用已存在冲突 → 脚本自动先卸载

---

## 依赖

- **hdc** 命令行工具（DevEco Studio 自带）
- HarmonyOS 设备 / 模拟器（已连接）
