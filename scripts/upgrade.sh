#!/usr/bin/env bash
# ============================================================
# Server Monitor — One-click upgrade script
# 服务器监控 — 一键升级脚本
# ============================================================
# Usage / 用法:
#   curl -sSL https://raw.githubusercontent.com/tangshunpu/Server-Monitor/main/scripts/upgrade.sh | sudo bash
#   OR / 或者:
#   sudo bash scripts/upgrade.sh [server|agent|all]
# ============================================================

set -e

INSTALL_DIR="/opt/server-monitor"
REPO_URL="https://raw.githubusercontent.com/tangshunpu/Server-Monitor/main"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

download_file() {
    local url="$1"
    local dest="$2"
    if command -v curl &>/dev/null; then
        curl -sSL "$url" -o "$dest"
    elif command -v wget &>/dev/null; then
        wget -q "$url" -O "$dest"
    else
        error "Neither curl nor wget found / 未找到 curl 或 wget"
    fi
}

# --- Check root / 检查 root 权限 ---
if [ "$EUID" -ne 0 ]; then
    error "Please run as root (sudo) / 请使用 root 权限运行 (sudo)"
fi

if [ ! -d "$INSTALL_DIR" ]; then
    error "$INSTALL_DIR not found. Please install first.\n$INSTALL_DIR 未找到，请先安装。"
fi

# --- Detect installed components / 检测已安装组件 ---
HAS_SERVER=false
HAS_AGENT=false

if systemctl is-enabled server-monitor &>/dev/null; then
    HAS_SERVER=true
fi
if systemctl is-enabled server-monitor-agent &>/dev/null; then
    HAS_AGENT=true
fi

# --- Parse mode / 解析模式 ---
MODE="${1:-auto}"

if [ "$MODE" = "auto" ]; then
    if $HAS_SERVER && $HAS_AGENT; then
        MODE="all"
    elif $HAS_SERVER; then
        MODE="server"
    elif $HAS_AGENT; then
        MODE="agent"
    else
        warn "No services detected. Upgrading all files. / 未检测到服务，升级所有文件。"
        MODE="all"
    fi
fi

info "Upgrade mode: $MODE / 升级模式: $MODE"
echo ""

# --- Upgrade server / 升级主服务端 ---
if [ "$MODE" = "server" ] || [ "$MODE" = "all" ]; then
    info "Upgrading server components / 正在升级主服务端..."
    mkdir -p "$INSTALL_DIR/templates"

    download_file "$REPO_URL/app.py"                   "$INSTALL_DIR/app.py"
    download_file "$REPO_URL/requirements.txt"         "$INSTALL_DIR/requirements.txt"
    download_file "$REPO_URL/templates/login.html"     "$INSTALL_DIR/templates/login.html"
    download_file "$REPO_URL/templates/dashboard.html" "$INSTALL_DIR/templates/dashboard.html"
    download_file "$REPO_URL/templates/admin.html"     "$INSTALL_DIR/templates/admin.html"
    download_file "$REPO_URL/templates/register.html"  "$INSTALL_DIR/templates/register.html"
    download_file "$REPO_URL/templates/user.html"      "$INSTALL_DIR/templates/user.html"

    info "Installing/updating Python dependencies / 安装/更新依赖..."
    pip3 install -q flask pyyaml

    if $HAS_SERVER; then
        info "Restarting server-monitor service / 重启 server-monitor 服务..."
        systemctl restart server-monitor
    fi

    info "Server upgrade complete / 主服务端升级完成"
    echo ""
fi

# --- Upgrade agent / 升级 Agent ---
if [ "$MODE" = "agent" ] || [ "$MODE" = "all" ]; then
    info "Upgrading agent / 正在升级 Agent..."

    download_file "$REPO_URL/agent.py" "$INSTALL_DIR/agent.py"

    info "Installing/updating Python dependencies / 安装/更新依赖..."
    pip3 install -q psutil requests pyyaml

    if $HAS_AGENT; then
        info "Restarting server-monitor-agent service / 重启 server-monitor-agent 服务..."
        systemctl restart server-monitor-agent
    fi

    info "Agent upgrade complete / Agent 升级完成"
    echo ""
fi

# --- Summary / 汇总 ---
info "============================================"
info "  Upgrade complete! / 升级完成！"
info "============================================"

if $HAS_SERVER; then
    STATUS=$(systemctl is-active server-monitor 2>/dev/null || echo "unknown")
    info "  server-monitor:       $STATUS"
fi

if $HAS_AGENT; then
    STATUS=$(systemctl is-active server-monitor-agent 2>/dev/null || echo "unknown")
    info "  server-monitor-agent: $STATUS"
fi

info "============================================"
info "  Config files were NOT modified."
info "  配置文件未被修改。"
info "============================================"
