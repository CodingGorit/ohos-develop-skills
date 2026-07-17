#!/usr/bin/env bash
#
# hdc-install.sh — 一键安装 HAP 到设备
# 用法:
#   bash hdc-install.sh              # 自动分析并部署
#   bash hdc-install.sh --list       # 查看项目信息
#   bash hdc-install.sh -b com.x -h app.hap -a MainAbility -m entry

set -euo pipefail

# ========== 颜色 ==========
BLUE='\033[0;34m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

# ========== 项目分析函数 ==========
get_val() { grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$1" 2>/dev/null | sed 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' | head -1 || echo ""; }

detect_bundle() { get_val "AppScope/app.json5" "bundleName"; }

detect_modules() {
  while IFS= read -r -d '' f; do
    local root="${f%/src/main/module.json5}"
    [[ "$root" == */ohosTest ]] && continue
    local name; name=$(get_val "$f" "name"); [ -n "$name" ] && echo "$name:$root"
  done < <(find . -path '*/src/main/module.json5' -print0 2>/dev/null)
}

detect_ability() { get_val "$1/src/main/module.json5" "mainElement"; }

detect_hap() {
  local hap; hap=$(find . -path "./$1/build/*/outputs/default/*-unsigned.hap" -type f 2>/dev/null | head -1 || echo "")
  [ -z "$hap" ] && hap=$(find . -path "./$1/build/*/outputs/default/*.hap" -type f 2>/dev/null | head -1 || echo "")
  echo "$hap"
}

# ========== 参数 ==========
BUNDLE=""; MODULE=""; ABILITY=""; HAP=""; NO_START=false; NO_UNINSTALL=false; MODE_LIST=false

usage() {
  echo "用法: bash hdc-install.sh [选项]"
  echo "  -m, --module <name>  指定模块（单模块自动选择）"
  echo "  -a, --ability <name> 指定 Ability（默认 mainElement）"
  echo "  -b, --bundle <name>  覆盖 bundleName"
  echo "  -h, --hap <path>     指定 HAP 路径"
  echo "      --no-start       仅安装不启动"
  echo "      --no-uninstall   首次安装跳过卸载"
  echo "      --list           查看项目模块信息"
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--module) MODULE="$2"; shift 2 ;;
    -a|--ability) ABILITY="$2"; shift 2 ;;
    -b|--bundle) BUNDLE="$2"; shift 2 ;;
    -h|--hap) HAP="$2"; shift 2 ;;
    --no-start) NO_START=true; shift ;;
    --no-uninstall) NO_UNINSTALL=true; shift ;;
    --list) MODE_LIST=true; shift ;;
    --help) usage ;;
    *) echo -e "${RED}未知参数: $1${NC}"; usage ;;
  esac
done

# ========== 项目分析 ==========
ROOT="$(pwd)"
[ -z "$BUNDLE" ] && BUNDLE=$(detect_bundle)
MODULES=(); while IFS= read -r line; do MODULES+=("$line"); done < <(detect_modules)

# 自动选模块
if [ -z "$MODULE" ]; then
  if [ ${#MODULES[@]} -eq 0 ]; then echo -e "${RED}[ERROR] 未找到 module.json5${NC}"; exit 1; fi
  if [ ${#MODULES[@]} -eq 1 ]; then
    MODULE="${MODULES[0]%%:*}"
    echo -e "${YELLOW}ℹ 自动选择模块: ${CYAN}$MODULE${NC}"
  else
    echo -e "${RED}多模块项目，请用 -m 指定：${NC}"
    for m in "${MODULES[@]}"; do echo "  ${CYAN}${m%%:*}${NC} (${m#*:})"; done; exit 1
  fi
fi

# 找模块路径
MODPATH=""; for m in "${MODULES[@]}"; do [ "${m%%:*}" = "$MODULE" ] && MODPATH="${m#*:}" && break; done
[ -z "$MODPATH" ] && echo -e "${RED}[ERROR] 模块 $MODULE 不存在${NC}" && exit 1
MODPATH="${MODPATH#./}"

[ -z "$ABILITY" ] && ABILITY=$(detect_ability "$MODPATH")
[ -z "$HAP" ] && HAP=$(detect_hap "$MODULE")

# --list 模式
if [ "$MODE_LIST" = true ]; then
  echo -e "\n${CYAN}========== 项目信息 ==========${NC}"
  echo -e "  bundleName: ${GREEN}$BUNDLE${NC}"
  for m in "${MODULES[@]}"; do
    n="${m%%:*}"; p="${m#*:}"; a=$(detect_ability "$p"); h=$(detect_hap "$n")
    echo -e "  [${CYAN}$n${NC}] 目录: $p  Ability: ${a:-N/A}"
    [ -n "$h" ] && echo -e "    HAP: ${GREEN}$h${NC}" || echo -e "    HAP: ${YELLOW}（未编译）${NC}"
  done
  echo -e "${CYAN}==============================${NC}"
  exit 0
fi

# ========== 检查 ==========
command -v hdc &>/dev/null || { echo -e "${RED}[ERROR] 未找到 hdc${NC}"; exit 1; }
[ -f "$HAP" ] || { echo -e "${RED}[ERROR] HAP 不存在: $HAP${NC}"; exit 1; }

DEVICES=$(hdc list targets 2>/dev/null | grep -cvE '^\s*$' || echo "0")
[ "$DEVICES" -eq 0 ] && { echo -e "${RED}[ERROR] 未检测到设备${NC}"; exit 1; }

# ========== 安装 ==========
echo -e "\n${GREEN}▶ 部署: $BUNDLE ($MODULE/$ABILITY)${NC}"
echo -e "  HAP: $HAP\n"

TMPDIR="hap_$(date +%s)"
REMOTE="data/local/tmp/$TMPDIR"

run() {
  local desc="$1" cmd="$2" ignore="${3:-false}"
  echo -e "${BLUE}$ ${cmd}${NC}"
  local out; out=$(eval "$cmd" 2>&1) || true
  if echo "$out" | grep -qiE 'error|failed' 2>/dev/null; then
    [ -n "$out" ] && echo "$out"
    if $ignore; then echo -e "${YELLOW}  ⚠ $desc 忽略${NC}"
    else echo -e "${RED}  ✗ $desc 失败${NC}"; exit 1; fi
  else
    [ -n "$out" ] && echo "$out"
    echo -e "${GREEN}  ✓${NC}"
  fi
}

run "停止应用" "hdc shell aa force-stop $BUNDLE" true
$NO_UNINSTALL || run "卸载" "hdc uninstall $BUNDLE" true
run "创建目录" "hdc shell mkdir -p $REMOTE"
# hdc file send 在 Windows 上需用 cygpath 转义
HAP_WIN="$(pwd)/$HAP"
command -v cygpath &>/dev/null && HAP_WIN="$(cygpath -w "$(pwd)/$HAP")"
run "推送 HAP" "hdc file send \"$HAP_WIN\" \"$REMOTE/\""
run "安装 HAP" "hdc shell bm install -p $REMOTE"
run "清理" "hdc shell rm -rf $REMOTE" true
$NO_START || run "启动" "hdc shell aa start -a $ABILITY -b $BUNDLE -m $MODULE"

echo -e "\n${GREEN}✅ $BUNDLE 部署完成${NC}"
