#!/usr/bin/env bash
# ============================================================
# Server Monitor — Uninstall script
# 服务器监控 — 卸载脚本
# ============================================================
# Usage / 用法:
#   sudo bash scripts/uninstall.sh [server|agent|all]
# ============================================================

set -e

INSTALL_DIR="/opt/server-monitor"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Please run as root (sudo) / 请使用 root 权限运行"
    exit 1
fi

MODE="${1:-all}"

stop_service() {
    local name="$1"
    if systemctl is-active --quiet "$name" 2>/dev/null; then
        info "Stopping $name / 正在停止 $name..."
        systemctl stop "$name"
    fi
    if [ -f "/etc/systemd/system/${name}.service" ]; then
        info "Removing $name service / 正在移除 $name 服务..."
        systemctl disable "$name" 2>/dev/null || true
        rm -f "/etc/systemd/system/${name}.service"
    fi
}

case "$MODE" in
    server)
        stop_service "server-monitor"
        info "Server service removed / 主服务已移除"
        ;;
    agent)
        stop_service "server-monitor-agent"
        info "Agent service removed / Agent 服务已移除"
        ;;
    all)
        stop_service "server-monitor"
        stop_service "server-monitor-agent"
        systemctl daemon-reload

        echo ""
        read -p "Also delete $INSTALL_DIR? (y/N) / 同时删除安装目录？(y/N) " CONFIRM
        if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
            rm -rf "$INSTALL_DIR"
            info "Install directory removed / 安装目录已删除"
        else
            info "Install directory kept / 安装目录已保留"
        fi
        ;;
    *)
        echo "Usage: $0 [server|agent|all]"
        echo "用法:  $0 [server|agent|all]"
        exit 1
        ;;
esac

systemctl daemon-reload
echo ""
info "Uninstall complete / 卸载完成"
