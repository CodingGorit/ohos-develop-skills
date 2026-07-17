#!/usr/bin/env bash
#
# HAP Analyzer — HarmonyOS/OpenHarmony HAP 包自动分析与反编译工具 (Bash 版)
# 适用于 macOS / Linux / Git Bash (Windows)
#
# 功能:
#   1. 解压 .hap (ZIP) 包
#   2. 解析 module.json / pack.info / main_pages.json
#   3. 列出资源文件
#   4. 调用 ark_disasm.exe 将 .abc 反汇编为 .asm
#   5. 对 .asm 进行结构化分析
#   6. 生成分析报告
#
# 用法:
#   ./hap_analyze.sh Appstore.hap
#   ./hap_analyze.sh Appstore.hap -o report.txt
#   ./hap_analyze.sh --abc modules.abc
#   ./hap_analyze.sh Appstore.hap --no-asm
#   ./hap_analyze.sh --help

set -euo pipefail

# ─── 常量 ────────────────────────────────────────────────────────────────

SEP=$(printf '─%.0s' $(seq 1 64))

# 生命周期方法
LIFECYCLE_METHODS="constructor|aboutToAppear|aboutToBeDeleted|onPageShow|onPageHide|onBackPress|initialRender|rerender|onBackground|onForeground"

# ─── 颜色 ────────────────────────────────────────────────────────────────

if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

info()  { echo -e "${CYAN}ℹ${NC} $*"; }
ok()    { echo -e "${GREEN}✓${NC} $*"; }
warn()  { echo -e "${YELLOW}⚠${NC} $*" >&2; }
err()   { echo -e "${RED}✗${NC} $*" >&2; }

# ─── 参数解析 ────────────────────────────────────────────────────────────

HAP_PATH=""
ABC_PATH=""
OUTPUT_FILE=""
NO_ASM=false
ARK_DISASM=""

usage() {
    cat <<EOF
HAP Analyzer — HarmonyOS/OpenHarmony HAP 包自动分析工具

用法:
  $0 <hap-file>               分析 HAP 包
  $0 <hap-file> -o report     输出到文件
  $0 --abc <abc-file>         直接分析 .abc 文件
  $0 <hap-file> --no-asm      仅分析配置，跳过反汇编
  $0 --help                   显示此帮助

选项:
  -o, --output FILE   输出报告到文件
  --abc PATH          直接指定 .abc 文件路径
  --no-asm            跳过反汇编和 ASM 分析
  --ark-disasm PATH   指定 ark_disasm.exe 路径
  --help              显示帮助
EOF
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        -o|--output)      OUTPUT_FILE="$2"; shift 2 ;;
        --abc)            ABC_PATH="$2"; shift 2 ;;
        --no-asm)         NO_ASM=true; shift ;;
        --ark-disasm)     ARK_DISASM="$2"; shift 2 ;;
        --help)           usage ;;
        -*)
            err "未知选项: $1"
            usage
            ;;
        *)
            if [ -z "$HAP_PATH" ]; then
                HAP_PATH="$1"
            else
                err "多余的参数: $1"
                usage
            fi
            shift
            ;;
    esac
done

if [ -z "$HAP_PATH" ] && [ -z "$ABC_PATH" ]; then
    err "请指定 .hap 文件或 --abc 文件"
    usage
fi

# ─── 辅助函数 ────────────────────────────────────────────────────────────

# 安全读取 JSON 字段
get_json_field() {
    local file="$1"
    local field="$2"
    if [ ! -f "$file" ]; then
        echo ""
        return
    fi
    python3 -c "
import json, sys
try:
    with open('$file', 'r', encoding='utf-8') as f:
        data = json.load(f)
    val = data
    for part in '$field'.split('.'):
        val = val[part]
    if isinstance(val, list):
        print(' '.join(str(x) for x in val))
    elif isinstance(val, bool):
        print(str(val).lower())
    else:
        print(val)
except Exception:
    print('')
" 2>/dev/null || echo ""
}

# 获取 JSON 数组
get_json_array() {
    local file="$1"
    local field="$2"
    python3 -c "
import json, sys
try:
    with open('$file', 'r', encoding='utf-8') as f:
        data = json.load(f)
    val = data
    for part in '$field'.split('.'):
        val = val[part]
    for item in val:
        if isinstance(item, dict):
            print(json.dumps(item, ensure_ascii=False))
        else:
            print(item)
except Exception:
    pass
" 2>/dev/null
}

# 权限分类
classify_permission() {
    local name="$1"
    local lower
    lower=$(echo "$name" | tr '[:upper:]' '[:lower:]')
    case "$lower" in
        *network*|*internet*)     echo "NET" ;;
        *install*)               echo "INSTALL" ;;
        *storage*|*write*|*read*) echo "STORAGE" ;;
        *notif*)                 echo "NOTIFY" ;;
        *background*)            echo "BG" ;;
        *location*)              echo "LOCATION" ;;
        *camera*)                echo "CAMERA" ;;
        *microphone*|*mic*)      echo "MIC" ;;
        *bluetooth*)             echo "BT" ;;
        *)                        echo "未分类" ;;
    esac
}

# ─── 1. 解压 HAP ────────────────────────────────────────────────────────

EXTRACT_DIR=""

extract_hap() {
    local path="$1"
    local dir
    dir=$(mktemp -d 2>/dev/null || mktemp -d -t "hap_XXXXXX")

    if [ ! -f "$path" ]; then
        err "HAP 文件不存在: $path"
        exit 1
    fi

    info "解压 $path → $dir"
    if command -v unzip &>/dev/null; then
        unzip -q -o "$path" -d "$dir" || {
            err "解压失败（不是有效的 ZIP 格式）"
            exit 1
        }
    elif command -v python3 &>/dev/null; then
        python3 -c "
import zipfile, sys
with zipfile.ZipFile('$path', 'r') as z:
    z.extractall('$dir')
" || {
            err "解压失败"
            exit 1
        }
    else
        err "需要 unzip 或 python3 来解压 HAP"
        exit 1
    fi

    echo "$dir"
}

# ─── 2. 配置解析 ─────────────────────────────────────────────────────────

parse_configs() {
    local dir="$1"

    MODULE_JSON="$dir/module.json"
    PACK_INFO="$dir/pack.info"
    PAGES_JSON="$dir/resources/base/profile/main_pages.json"

    # 元数据
    BUNDLE_NAME=$(get_json_field "$MODULE_JSON" "app.bundleName")
    VERSION_NAME=$(get_json_field "$MODULE_JSON" "app.versionName")
    VERSION_CODE=$(get_json_field "$MODULE_JSON" "app.versionCode")
    APP_NAME=$(get_json_field "$MODULE_JSON" "app.appName")
    VENDOR=$(get_json_field "$MODULE_JSON" "app.vendor")
    COMPILE_SDK_TYPE=$(get_json_field "$MODULE_JSON" "app.compileSdkType")
    COMPILE_SDK_VER=$(get_json_field "$MODULE_JSON" "app.compileSdkVersion")
    MIN_API=$(get_json_field "$MODULE_JSON" "app.minAPIVersion")

    MOD_NAME=$(get_json_field "$MODULE_JSON" "module.name")
    MOD_TYPE=$(get_json_field "$MODULE_JSON" "module.type")

    if [ -f "$MODULE_JSON" ]; then
        info "解析 module.json"
    fi
}

# ─── 3. 查找 ark_disasm ─────────────────────────────────────────────────

find_ark_disasm() {
    if [ -n "$ARK_DISASM" ] && [ -f "$ARK_DISASM" ]; then
        echo "$ARK_DISASM"
        return
    fi

    # 从 PATH 查找
    local from_path
    from_path=$(command -v ark_disasm.exe 2>/dev/null || true)
    if [ -n "$from_path" ]; then
        echo "$from_path"
        return
    fi

    # 常见 DevEco SDK 路径
    local paths=(
        "/c/Program Files/Huawei/DevEco Studio/sdk/default/openharmony/toolchains"
        "/d/Program Files/Huawei/DevEco Studio/sdk/default/openharmony/toolchains"
        "$LOCALAPPDATA/Huawei/DevEco Studio/sdk/default/openharmony/toolchains"
        "/d/Huawei/DevEco Studio/sdk/default/openharmony/toolchains"
        "$HOME/AppData/Local/Huawei/DevEco Studio/sdk/default/openharmony/toolchains"
    )
    for p in "${paths[@]}"; do
        if [ -f "$p/ark_disasm.exe" ]; then
            echo "$p/ark_disasm.exe"
            return
        fi
    done

    echo ""
}

# ─── 4. ASM 分析 ────────────────────────────────────────────────────────

analyze_asm() {
    local asm_file="$1"

    if [ ! -f "$asm_file" ]; then
        warn ".asm 文件不存在: $asm_file"
        return 1
    fi

    local content
    content=$(cat "$asm_file")

    local total_lines
    total_lines=$(echo "$content" | wc -l)

    local record_count
    record_count=$(echo "$content" | grep -c '# Record ' || true)

    # 字符串字面量
    local string_literals
    string_literals=$(echo "$content" | grep -oP 'string:"[^"]*"' | sed 's/string:"//;s/"$//' | sort -u || true)

    # @ohos API
    local ohos_apis
    ohos_apis=$(echo "$content" | grep -oP '@ohos:[\w.]+' | sort -u || true)

    # @bundle 引用
    local bundle_refs
    bundle_refs=$(echo "$content" | grep -oP '@bundle:[^\s"]+' | sort -u || true)

    # 方法名（驼峰）
    local methods
    methods=$(echo "$content" | grep -oP 'string:"[a-z]+[A-Z][^"]*"' | sed 's/string:"//;s/"$//' | sort -u || true)

    # 页面组件
    local page_components
    page_components=$(echo "$content" | grep -oP 'string:"[^"]*\.#[0-9]+#"' | sed 's/string:"//;s/"$//' | sort -u || true)

    # 网络相关
    local network_strings
    network_strings=$(echo "$content" | grep -oiP 'string:"(https?://|api\.|url|get|post|put|delete|request|download|upload|fetch|socket)[^"]*"' | sort -u || true)

    # 生命周期方法
    local lifecycle
    lifecycle=$(echo "$string_literals" | grep -E "^($LIFECYCLE_METHODS)$" || true)

    local method_count
    method_count=$(echo "$content" | grep -oP 'method:\w+' | sort -u | wc -l)

    # 输出为可以用 source 导入的变量
    cat <<ASM_VARS
TOTAL_LINES=$total_lines
RECORD_COUNT=$record_count
METHOD_COUNT=$method_count
OHOS_APIS<<EOF
$ohos_apis
EOF
BUNDLE_REFS<<EOF
$bundle_refs
EOF
METHODS<<EOF
$methods
EOF
PAGE_COMPONENTS<<EOF
$page_components
EOF
NETWORK_STRINGS<<EOF
$network_strings
EOF
STRING_LITERALS<<EOF
$string_literals
EOF
LIFECYCLE<<EOF
$lifecycle
EOF
ASM_VARS
}

# ─── 5. 报告生成 ─────────────────────────────────────────────────────────

generate_report() {
    echo "================================================================"
    echo "  HAP 分析报告"
    echo "================================================================"
    echo "  文件: ${HAP_PATH:-N/A}"
    echo ""

    # 应用信息
    echo "📦 应用信息 ${SEP}"
    echo "  Bundle Name   : ${BUNDLE_NAME:-(未设置)}"
    echo "  Version       : ${VERSION_NAME:-(未设置)} (${VERSION_CODE:-?})"
    echo "  App Name      : ${APP_NAME:-(未设置)}"
    echo "  Vendor        : ${VENDOR:-(未设置)}"
    echo "  Compile SDK   : ${COMPILE_SDK_TYPE:-?} ${COMPILE_SDK_VER:-?}"
    echo "  Min API       : ${MIN_API:-?}"
    echo ""

    # 模块
    echo "🧩 模块: ${MOD_NAME:-(未设置)} (${MOD_TYPE:-?}) ${SEP}"

    # Abilities
    if [ -f "$MODULE_JSON" ]; then
        local has_abilities
        has_abilities=$(get_json_field "$MODULE_JSON" "module.abilities" 2>/dev/null)
        if [ -n "$has_abilities" ] && [ "$has_abilities" != "[]" ]; then
            echo "  Abilities:"
            local i=0
            while true; do
                local ab_name
                ab_name=$(get_json_field "$MODULE_JSON" "module.abilities[$i].name" 2>/dev/null)
                [ -z "$ab_name" ] && break
                local ab_entry
                ab_entry=$(get_json_field "$MODULE_JSON" "module.abilities[$i].srcEntry" 2>/dev/null)
                printf "    - %-30s → %s\n" "$ab_name" "$ab_entry"
                i=$((i + 1))
            done
        fi
    fi

    # 页面路由
    if [ -f "$PAGES_JSON" ]; then
        local pages
        pages=$(get_json_array "$PAGES_JSON" "src" 2>/dev/null || true)
        if [ -n "$pages" ]; then
            echo "  页面路由:"
            echo "$pages" | while IFS= read -r p; do
                echo "    - $p"
            done
        fi
    fi
    echo ""

    # 权限
    if [ -f "$MODULE_JSON" ]; then
        local perm_count
        perm_count=$(python3 -c "
import json
try:
    with open('$MODULE_JSON') as f:
        d = json.load(f)
    print(len(d.get('module',{}).get('requestPermissions',[])))
except: print(0)
" 2>/dev/null)

        if [ "$perm_count" -gt 0 ]; then
            echo "🔒 权限列表 ${SEP}"
            python3 -c "
import json
with open('$MODULE_JSON') as f:
    d = json.load(f)
perms = d.get('module',{}).get('requestPermissions',[])
cats = {}
for p in perms:
    name = p.get('name','')
    cat = '未分类'
    l = name.lower()
    for kw, c in [('network','NET'),('internet','NET'),('install','INSTALL'),
                  ('storage','STORAGE'),('write','STORAGE'),('read','STORAGE'),
                  ('notif','NOTIFY'),('background','BG'),('location','LOCATION'),
                  ('camera','CAMERA'),('microphone','MIC'),('bluetooth','BT')]:
        if kw in l:
            cat = c; break
    short = name.split('.')[-1]
    cats.setdefault(cat, []).append((short, p.get('reason','')))
for cat in sorted(cats.keys()):
    items = cats[cat]
    print(f'  [{cat}] ({len(items)} 项)')
    for s, r in items:
        print(f'    - {s:<35} {r}')
" 2>/dev/null
            echo ""
        fi
    fi

    # 资源
    if [ -d "$EXTRACT_DIR/resources" ]; then
        local res_count
        res_count=$(find "$EXTRACT_DIR/resources" -type f 2>/dev/null | wc -l)
        if [ "$res_count" -gt 0 ]; then
            echo "📁 资源文件 (${res_count} 个) ${SEP}"
            find "$EXTRACT_DIR/resources" -type f 2>/dev/null | head -30 | while IFS= read -r f; do
                local rel
                rel=$(echo "$f" | sed "s|$EXTRACT_DIR/||")
                echo "    $rel"
            done
            if [ "$res_count" -gt 30 ]; then
                echo "    ... 还有 $((res_count - 30)) 个文件"
            fi
            echo ""
        fi
    fi

    # ASM 分析
    if [ -n "${ASM_ANALYZED:-}" ] && [ "$ASM_ANALYZED" = "true" ]; then
        echo "⚙️  ASM 反汇编分析 ${SEP}"
        echo "  总行数            : ${TOTAL_LINES:-0}"
        echo "  Records 数        : ${RECORD_COUNT:-0}"
        echo "  方法数            : ${METHOD_COUNT:-0}"
        echo ""

        local api_count
        api_count=$(echo "${OHOS_APIS:-}" | wc -l)
        if [ "$api_count" -gt 0 ]; then
            echo "  📡 HarmonyOS API 调用 (${api_count} 项):"
            echo "${OHOS_APIS:-}" | head -40 | while IFS= read -r api; do
                [ -n "$api" ] && echo "    - $api"
            done
            if [ "$api_count" -gt 40 ]; then
                echo "    ... 还有 $((api_count - 40)) 个"
            fi
            echo ""
        fi

        local page_count
        page_count=$(echo "${PAGE_COMPONENTS:-}" | wc -l)
        if [ "$page_count" -gt 0 ]; then
            echo "  📄 页面/组件 (${page_count} 项):"
            echo "${PAGE_COMPONENTS:-}" | head -20 | while IFS= read -r p; do
                [ -n "$p" ] && echo "    - $p"
            done
            if [ "$page_count" -gt 20 ]; then
                echo "    ... 还有 $((page_count - 20)) 个"
            fi
            echo ""
        fi

        local method_list_count
        method_list_count=$(echo "${METHODS:-}" | wc -l)
        if [ "$method_list_count" -gt 0 ]; then
            echo "  🔧 自定义方法 (${method_list_count} 项):"
            echo "${METHODS:-}" | head -20 | while IFS= read -r m; do
                [ -n "$m" ] && echo "    - $m"
            done
            if [ "$method_list_count" -gt 20 ]; then
                echo "    ... 还有 $((method_list_count - 20)) 个"
            fi
            echo ""
        fi

        local lc_count
        lc_count=$(echo "${LIFECYCLE:-}" | wc -l)
        if [ "$lc_count" -gt 0 ]; then
            echo "  🔄 生命周期方法:"
            echo "${LIFECYCLE:-}" | while IFS= read -r lm; do
                [ -n "$lm" ] && echo "    - $lm"
            done
            echo ""
        fi

        local net_count
        net_count=$(echo "${NETWORK_STRINGS:-}" | wc -l)
        if [ "$net_count" -gt 0 ]; then
            echo "  🌐 网络相关 (${net_count} 项):"
            echo "${NETWORK_STRINGS:-}" | head -15 | while IFS= read -r ns; do
                [ -n "$ns" ] && echo "    - $ns"
            done
            if [ "$net_count" -gt 15 ]; then
                echo "    ... 还有 $((net_count - 15)) 个"
            fi
            echo ""
        fi

        local sl_count
        sl_count=$(echo "${STRING_LITERALS:-}" | wc -l)
        if [ "$sl_count" -gt 0 ]; then
            echo "  📝 字符串字面量 (前 30 / ${sl_count} 项):"
            echo "${STRING_LITERALS:-}" | head -30 | while IFS= read -r s; do
                [ -n "$s" ] && echo "    \"$s\""
            done
            if [ "$sl_count" -gt 30 ]; then
                echo "    ... 还有 $((sl_count - 30)) 个"
            fi
            echo ""
        fi
    fi

    echo "================================================================"
    echo "  分析完成"
    echo "================================================================"
}

# ─── 主流程 ──────────────────────────────────────────────────────────────

main() {
    echo -e "${CYAN}🔍 HAP 分析开始...${NC}"

    # 1. 解压
    if [ -n "$HAP_PATH" ]; then
        EXTRACT_DIR=$(extract_hap "$HAP_PATH")
    fi

    # 2. 解析配置
    if [ -n "$EXTRACT_DIR" ]; then
        echo -e "${YELLOW}📋 解析配置...${NC}"
        parse_configs "$EXTRACT_DIR"
    fi

    # 3. 反汇编
    ASM_ANALYZED=false
    if [ "$NO_ASM" = false ]; then
        ABC_FILE="$ABC_PATH"
        if [ -z "$ABC_FILE" ] && [ -n "$EXTRACT_DIR" ]; then
            # 查找 .abc
            ABC_FILE=$(find "$EXTRACT_DIR" -name "*.abc" 2>/dev/null | head -1)
        fi

        if [ -n "$ABC_FILE" ] && [ -f "$ABC_FILE" ]; then
            DISASM=$(find_ark_disasm)
            if [ -n "$DISASM" ]; then
                echo -e "${YELLOW}⚙️  反汇编 ${ABC_FILE}...${NC}"
                ASM_FILE="${ABC_FILE%.abc}.asm"
                if "$DISASM" "$ABC_FILE" "$ASM_FILE" 2>/dev/null; then
                    echo -e "${GREEN}  ASM 输出: ${ASM_FILE}${NC}"
                    echo -e "${YELLOW}📊 分析 ASM...${NC}"
                    eval "$(analyze_asm "$ASM_FILE")"
                    ASM_ANALYZED=true
                else
                    warn "ark_disasm 执行失败"
                fi
            else
                warn "未找到 ark_disasm.exe，跳过反汇编。可指定 --ark-disasm PATH"
            fi
        else
            warn "未找到 .abc 字节码文件"
        fi
    fi

    # 4. 生成报告
    echo -e "${YELLOW}📄 生成报告...${NC}"
    if [ -n "$OUTPUT_FILE" ]; then
        generate_report > "$OUTPUT_FILE"
        echo -e "${GREEN}报告已保存: ${OUTPUT_FILE}${NC}"
    else
        generate_report
    fi

    # 5. 清理
    if [ -n "$EXTRACT_DIR" ] && [ -d "$EXTRACT_DIR" ]; then
        rm -rf "$EXTRACT_DIR"
    fi

    echo -e "${CYAN}✅ 分析完成${NC}"
}

main
