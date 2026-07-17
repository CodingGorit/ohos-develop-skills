<#
.SYNOPSIS
    HAP Analyzer — HarmonyOS/OpenHarmony HAP 包自动分析与反编译工具 (PowerShell 版)

.DESCRIPTION
    功能:
      1. 解压 .hap (ZIP) 包
      2. 解析 module.json / pack.info / main_pages.json
      3. 列出资源文件
      4. 调用 ark_disasm.exe 将 .abc 反汇编为 .asm
      5. 对 .asm 进行结构化分析
      6. 生成分析报告

.PARAMETER HapPath
    .hap 文件路径

.PARAMETER AbcPath
    直接指定 .abc 文件（跳过解压）

.PARAMETER OutputFile
    输出报告到文件（默认输出到终端）

.PARAMETER NoAsm
    跳过反汇编和 ASM 分析

.PARAMETER ArkDisasmPath
    指定 ark_disasm.exe 路径

.EXAMPLE
    .\hap_analyze.ps1 Appstore.hap
    .\hap_analyze.ps1 Appstore.hap -OutputFile report.txt
    .\hap_analyze.ps1 -AbcPath modules.abc
    .\hap_analyze.ps1 Appstore.hap -NoAsm
#>

param(
    [Parameter(Position = 0)]
    [string]$HapPath,

    [Parameter(Mandatory = $false)]
    [string]$AbcPath,

    [Parameter(Mandatory = $false)]
    [string]$OutputFile,

    [Parameter(Mandatory = $false)]
    [switch]$NoAsm,

    [Parameter(Mandatory = $false)]
    [string]$ArkDisasmPath
)

# ─── 辅助函数 ────────────────────────────────────────────────────────────

function Write-Report {
    param([string[]]$Lines)
    $output = $Lines -join "`n"
    if ($OutputFile) {
        $output | Out-File -FilePath $OutputFile -Encoding UTF8
        Write-Host "报告已保存: $OutputFile"
    } else {
        Write-Host $output
    }
}

function Get-Indented {
    param([string]$Text, [int]$Indent = 4)
    $prefix = " " * $Indent
    return ($Text -split "`n" | ForEach-Object { "$prefix$_" }) -join "`n"
}

# ─── 1. 解压 HAP ─────────────────────────────────────────────────────────

function Expand-Hap {
    param([string]$Path)
    $extractDir = Join-Path $env:TEMP "hap_$(Get-Random)"

    if (-not (Test-Path $Path)) {
        throw "HAP 文件不存在: $Path"
    }

    try {
        $null = New-Item -ItemType Directory -Path $extractDir -Force
        # PowerShell 5+ 的 Expand-Archive 可以解压 ZIP
        Expand-Archive -Path $Path -DestinationPath $extractDir -Force
        Write-Host "  已解压到: $extractDir"
        return $extractDir
    } catch {
        throw "解压失败: $_"
    }
}

# ─── 2. 解析配置 ─────────────────────────────────────────────────────────

function Get-JsonSafe {
    param([string]$Path, [string]$Label)
    if (-not (Test-Path $Path)) {
        return $null
    }
    try {
        return Get-Content $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        Write-Warning "$Label 解析失败: $_"
        return $null
    }
}

# 权限分类映射
$PERMISSION_CATEGORIES = @{
    "network"     = "NET"
    "internet"    = "NET"
    "install"     = "INSTALL"
    "storage"     = "STORAGE"
    "write"       = "STORAGE"
    "read"        = "STORAGE"
    "notify"      = "NOTIFY"
    "notification"= "NOTIFY"
    "background"  = "BG"
    "location"    = "LOCATION"
    "camera"      = "CAMERA"
    "microphone"  = "MIC"
    "bluetooth"   = "BT"
}

function Get-PermissionCategory {
    param([string]$Name)
    $lower = $Name.ToLower()
    foreach ($kv in $PERMISSION_CATEGORIES.GetEnumerator()) {
        if ($lower -match $kv.Key) {
            return $kv.Value
        }
    }
    return "未分类"
}

function Get-ShortName {
    param([string]$Name)
    $parts = $Name -split "\."
    return $parts[-1]
}

# ─── 3. 查找 ark_disasm ─────────────────────────────────────────────────

function Find-ArkDisasm {
    if ($ArkDisasmPath -and (Test-Path $ArkDisasmPath)) {
        return $ArkDisasmPath
    }

    # 从 PATH 查找
    $fromPath = Get-Command "ark_disasm.exe" -ErrorAction SilentlyContinue
    if ($fromPath) {
        return $fromPath.Source
    }

    # 常见 DevEco 安装路径
    $searchPaths = @(
        "C:\Program Files\Huawei\DevEco Studio\sdk\default\openharmony\toolchains",
        "D:\Program Files\Huawei\DevEco Studio\sdk\default\openharmony\toolchains",
        "$env:LOCALAPPDATA\Huawei\DevEco Studio\sdk\default\openharmony\toolchains",
        "D:\Huawei\DevEco Studio\sdk\default\openharmony\toolchains"
    )
    foreach ($p in $searchPaths) {
        $exe = Join-Path $p "ark_disasm.exe"
        if (Test-Path $exe) {
            return $exe
        }
    }
    return $null
}

# ─── 4. ASM 分析 ────────────────────────────────────────────────────────

function Analyze-Asm {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        Write-Warning ".asm 文件不存在: $Path"
        return $null
    }

    $content = Get-Content $Path -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
    if (-not $content) {
        return $null
    }

    $lines = $content -split "`n"
    $totalLines = $lines.Count

    # 字符串字面量
    $stringMatches = [regex]::Matches($content, 'string:"([^"]*)"')
    $stringLiterals = $stringMatches | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ } | Sort-Object -Unique

    # @ohos API
    $ohosMatches = [regex]::Matches($content, '@ohos:[\w.]+')
    $ohosApis = $ohosMatches | ForEach-Object { $_.Value } | Sort-Object -Unique

    # @bundle 引用
    $bundleMatches = [regex]::Matches($content, '@bundle:[^\s"]+')
    $bundleRefs = $bundleMatches | ForEach-Object { $_.Value } | Sort-Object -Unique

    # 方法名
    $methodMatches = [regex]::Matches($content, 'string:"([a-z]+[A-Z][^"]*)"')
    $methods = $methodMatches | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ } | Sort-Object -Unique

    # 页面/组件
    $pageMatches = [regex]::Matches($content, 'string:"[^"]*\.#[0-9]+#"')
    $pageComponents = $pageMatches | ForEach-Object { $_.Value.TrimStart('string:"').TrimEnd('"') } | Sort-Object -Unique

    # 网络相关
    $netRegex = [regex]'string:"(https?://|api\.|url|get|post|put|delete|request|download|upload|fetch|socket)[^"]*"'
    $networkMatches = $netRegex.Matches($content)
    $networkStrings = $networkMatches | ForEach-Object { $_.Value } | Sort-Object -Unique

    # 统计
    $recordCount = [regex]::Matches($content, '# Record ').Count
    $methodCount = ([regex]::Matches($content, 'method:\w+') | ForEach-Object { $_.Value } | Sort-Object -Unique).Count

    # 生命周期方法
    $lifecycleMethods = @("constructor","aboutToAppear","aboutToBeDeleted","onPageShow","onPageHide",
                          "onBackPress","initialRender","rerender","onBackground","onForeground")
    $foundLifecycle = $stringLiterals | Where-Object { $_ -in $lifecycleMethods }

    return @{
        TotalLines       = $totalLines
        RecordCount      = $recordCount
        MethodCount      = $methodCount
        OhosApis         = $ohosApis
        BundleRefs       = $bundleRefs
        Methods          = $methods
        PageComponents   = $pageComponents
        NetworkStrings   = $networkStrings
        StringLiterals   = $stringLiterals
        LifecycleMethods = $foundLifecycle
    }
}

# ─── 5. 报告生成 ─────────────────────────────────────────────────────────

function Format-Report {
    param(
        [string]$HapFile,
        [hashtable]$Metadata,
        [array]$Modules,
        [array]$Permissions,
        [array]$Resources,
        [hashtable]$AsmAnalysis
    )

    $out = @()
    $sep = "─" * 64

    $out += "=" * 64
    $out += "  HAP 分析报告"
    $out += "=" * 64
    $out += "  文件: $HapFile"
    $out += ""

    # ── 应用元数据 ──
    $out += "📦 应用信息 $sep"
    $out += "  Bundle Name   : $($Metadata.BundleName)"
    $out += "  Version       : $($Metadata.VersionName) ($($Metadata.VersionCode))"
    $out += "  App Name      : $($Metadata.AppName)"
    $out += "  Vendor        : $($Metadata.Vendor)"
    $out += "  Compile SDK   : $($Metadata.CompileSdk)"
    $out += "  Min API       : $($Metadata.MinApiVersion)"
    $out += ""

    # ── 模块信息 ──
    foreach ($mod in $Modules) {
        $out += "🧩 模块: $($mod.Name) ($($mod.Type)) $sep"
        $out += "  设备类型       : $($mod.DeviceTypes -join ', ')"
        $out += "  虚拟机         : $($mod.VirtualMachine)"
        $out += "  Abilities:"
        foreach ($ab in $mod.Abilities) {
            $out += "    - $($ab.name) → $($ab.srcEntry)"
        }
        if ($mod.Pages.Count -gt 0) {
            $out += "  页面路由:"
            foreach ($p in $mod.Pages) {
                $out += "    - $p"
            }
        }
        $out += ""
    }

    # ── 权限 ──
    if ($Permissions.Count -gt 0) {
        $out += "🔒 权限列表 $sep"
        $grouped = $Permissions | Group-Object Category
        foreach ($g in $grouped) {
            $out += "  [$($g.Name)] ($($g.Count) 项)"
            foreach ($p in $g.Group) {
                $short = Get-ShortName $p.Name
                $out += "    - $($short.PadRight(35)) $($p.Reason)"
            }
        }
        $out += ""
    }

    # ── 资源 ──
    if ($Resources.Count -gt 0) {
        $out += "📁 资源文件 ($($Resources.Count) 个) $sep"
        $media = $Resources | Where-Object { $_ -notlike "resources/base/profile/*" }
        $displayCount = [Math]::Min(30, $media.Count)
        for ($i = 0; $i -lt $displayCount; $i++) {
            $out += "    $($media[$i])"
        }
        if ($media.Count -gt 30) {
            $out += "    ... 还有 $($media.Count - 30) 个文件"
        }
        $out += ""
    }

    # ── ASM 分析 ──
    if ($AsmAnalysis) {
        $a = $AsmAnalysis
        $out += "⚙️  ASM 反汇编分析 $sep"
        $out += "  总行数            : $($a.TotalLines)"
        $out += "  Records 数        : $($a.RecordCount)"
        $out += "  方法数            : $($a.MethodCount)"
        $out += ""

        if ($a.OhosApis.Count -gt 0) {
            $out += "  📡 HarmonyOS API 调用 ($($a.OhosApis.Count) 项):"
            $display = $a.OhosApis | Select-Object -First 40
            foreach ($api in $display) {
                $out += "    - $api"
            }
            if ($a.OhosApis.Count -gt 40) {
                $out += "    ... 还有 $($a.OhosApis.Count - 40) 个"
            }
            $out += ""
        }

        if ($a.PageComponents.Count -gt 0) {
            $out += "  📄 页面/组件 ($($a.PageComponents.Count) 项):"
            $display = $a.PageComponents | Select-Object -First 20
            foreach ($p in $display) {
                $out += "    - $p"
            }
            if ($a.PageComponents.Count -gt 20) {
                $out += "    ... 还有 $($a.PageComponents.Count - 20) 个"
            }
            $out += ""
        }

        if ($a.Methods.Count -gt 0) {
            $out += "  🔧 自定义方法 ($($a.Methods.Count) 项):"
            $display = $a.Methods | Select-Object -First 20
            foreach ($m in $display) {
                $out += "    - $m"
            }
            if ($a.Methods.Count -gt 20) {
                $out += "    ... 还有 $($a.Methods.Count - 20) 个"
            }
            $out += ""
        }

        if ($a.LifecycleMethods.Count -gt 0) {
            $out += "  🔄 生命周期方法:"
            foreach ($lm in $a.LifecycleMethods) {
                $out += "    - $lm"
            }
            $out += ""
        }

        if ($a.NetworkStrings.Count -gt 0) {
            $out += "  🌐 网络相关 ($($a.NetworkStrings.Count) 项):"
            $display = $a.NetworkStrings | Select-Object -First 15
            foreach ($ns in $display) {
                $out += "    - $ns"
            }
            if ($a.NetworkStrings.Count -gt 15) {
                $out += "    ... 还有 $($a.NetworkStrings.Count - 15) 个"
            }
            $out += ""
        }

        if ($a.StringLiterals.Count -gt 0) {
            $out += "  📝 字符串字面量 (前 30 / $($a.StringLiterals.Count) 项):"
            $display = $a.StringLiterals | Select-Object -First 30
            foreach ($s in $display) {
                $out += '    "' + $s + '"'
            }
            if ($a.StringLiterals.Count -gt 30) {
                $out += "    ... 还有 $($a.StringLiterals.Count - 30) 个"
            }
            $out += ""
        }
    }

    $out += "=" * 64
    $out += "  分析完成"
    $out += "=" * 64

    return $out
}

# ─── 主流程 ──────────────────────────────────────────────────────────────

function Invoke-HapAnalysis {
    Write-Host "🔍 HAP 分析开始..." -ForegroundColor Cyan

    # ── 解压 ──
    $extractDir = $null
    try {
        if ($HapPath) {
            Write-Host "📦 解压 HAP..." -ForegroundColor Yellow
            $extractDir = Expand-Hap $HapPath
        } elseif (-not $AbcPath) {
            throw "请指定 .hap 文件路径或 --AbcPath"
        }
    } catch {
        Write-Host "❌ $_" -ForegroundColor Red
        return
    }

    # ── 解析配置 ──
    Write-Host "📋 解析配置..." -ForegroundColor Yellow

    $Metadata = @{
        BundleName    = ""
        VersionName   = ""
        VersionCode   = ""
        AppName       = ""
        Vendor        = ""
        CompileSdk    = ""
        MinApiVersion = ""
    }
    $Modules = @()
    $Permissions = @()

    $moduleJson = Get-JsonSafe (Join-Path $extractDir "module.json") "module.json"
    if ($moduleJson) {
        $Metadata.BundleName    = $moduleJson.app.bundleName
        $Metadata.VersionName   = $moduleJson.app.versionName
        $Metadata.VersionCode   = $moduleJson.app.versionCode
        $Metadata.AppName       = $moduleJson.app.appName
        $Metadata.Vendor        = $moduleJson.app.vendor
        $Metadata.CompileSdk    = "$($moduleJson.app.compileSdkType) $($moduleJson.app.compileSdkVersion)"
        $Metadata.MinApiVersion = $moduleJson.app.minAPIVersion

        $mod = $moduleJson.module
        $moduleInfo = @{
            Name           = $mod.name
            Type           = $mod.type
            DeviceTypes    = @($mod.deviceTypes)
            VirtualMachine = $mod.virtualMachine
            Abilities      = @()
            Pages          = @()
        }
        foreach ($ab in $mod.abilities) {
            $moduleInfo.Abilities += @{
                name     = $ab.name
                srcEntry = $ab.srcEntry
            }
        }

        # 页面路由
        $pagesPath = Join-Path $extractDir "resources\base\profile\main_pages.json"
        $pagesJson = Get-JsonSafe $pagesPath "main_pages.json"
        if ($pagesJson -and $pagesJson.src) {
            $moduleInfo.Pages = @($pagesJson.src)
        }

        $Modules += $moduleInfo

        # 权限
        foreach ($perm in $mod.requestPermissions) {
            $Permissions += @{
                Name     = $perm.name
                Reason   = $perm.reason
                Category = Get-PermissionCategory $perm.name
            }
        }
    }

    # ── 资源列表 ──
    $Resources = @()
    $resDir = Join-Path $extractDir "resources"
    if (Test-Path $resDir) {
        $Resources = Get-ChildItem $resDir -Recurse -File | ForEach-Object {
            $_.FullName.Substring($extractDir.Length + 1) -replace "\\", "/"
        } | Sort-Object
    }

    # ── 反汇编 ──
    $AsmAnalysis = $null
    if (-not $NoAsm) {
        # 定位 .abc
        $abcFile = $null
        if ($AbcPath -and (Test-Path $AbcPath)) {
            $abcFile = $AbcPath
        } elseif ($extractDir) {
            $abcCandidates = @(
                Join-Path $extractDir "ets\modules.abc"
            )
            $abcCandidates += Get-ChildItem $extractDir -Recurse -Filter "*.abc" | ForEach-Object { $_.FullName }
            $abcCandidates = $abcCandidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
            if ($abcCandidates.Count -gt 0) {
                $abcFile = $abcCandidates[0]
            }
        }

        if ($abcFile) {
            $disasm = Find-ArkDisasm
            if ($disasm) {
                Write-Host "⚙️  反汇编 $abcFile ..." -ForegroundColor Yellow
                $asmFile = Join-Path (Split-Path $abcFile -Parent) "$([System.IO.Path]::GetFileNameWithoutExtension($abcFile)).asm"
                try {
                    $proc = Start-Process -FilePath $disasm -ArgumentList "`"$abcFile`" `"$asmFile`"" -NoNewWindow -Wait -PassThru
                    if ($proc.ExitCode -eq 0 -and (Test-Path $asmFile)) {
                        Write-Host "  ASM 输出: $asmFile" -ForegroundColor Green
                        Write-Host "📊 分析 ASM..." -ForegroundColor Yellow
                        $AsmAnalysis = Analyze-Asm $asmFile
                    } else {
                        Write-Warning "ark_disasm 返回非零退出码: $($proc.ExitCode)"
                    }
                } catch {
                    Write-Warning "ark_disasm 执行失败: $_"
                }
            } else {
                Write-Warning "未找到 ark_disasm.exe，跳过反汇编。"
            }
        } else {
            Write-Warning "未找到 .abc 字节码文件。"
        }
    }

    # ── 生成报告 ──
    Write-Host "📄 生成报告..." -ForegroundColor Yellow
    $reportLines = Format-Report `
        -HapFile $HapPath `
        -Metadata $Metadata `
        -Modules $Modules `
        -Permissions $Permissions `
        -Resources $Resources `
        -AsmAnalysis $AsmAnalysis

    Write-Report -Lines $reportLines
    Write-Host "✅ 分析完成" -ForegroundColor Cyan
}

# ─── 执行 ─────────────────────────────────────────────────────────────────

Invoke-HapAnalysis
