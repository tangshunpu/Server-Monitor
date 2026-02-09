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

find_preferred_conda_base_python() {
    local conda_bin=""
    local conda_base=""
    if command -v conda &>/dev/null; then
        conda_bin="$(command -v conda)"
        conda_base="$("$conda_bin" info --base 2>/dev/null || true)"
        if [ -n "$conda_base" ] && [ -x "$conda_base/bin/python" ]; then
            echo "$conda_base/bin/python|conda"
            return 0
        fi
    fi

    # Try common per-user conda locations when running via sudo.
    # 在 sudo 场景下尝试调用发起用户 home 下的 conda。
    local sudo_home=""
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        sudo_home="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)"
        [ -z "$sudo_home" ] && sudo_home="/home/$SUDO_USER"
        local conda_bins=(
            "$sudo_home/miniconda3/bin/conda"
            "$sudo_home/anaconda3/bin/conda"
            "$sudo_home/conda/bin/conda"
        )
        local cb
        for cb in "${conda_bins[@]}"; do
            if [ -x "$cb" ]; then
                conda_base="$("$cb" info --base 2>/dev/null || true)"
                if [ -n "$conda_base" ] && [ -x "$conda_base/bin/python" ]; then
                    echo "$conda_base/bin/python|conda"
                    return 0
                fi
            fi
        done
    fi

    local candidates=(
        "/opt/conda/bin/python|conda"
        "/root/miniconda3/bin/python|miniconda"
        "/root/anaconda3/bin/python|anaconda"
        "/usr/local/miniconda3/bin/python|miniconda"
        "/usr/local/anaconda3/bin/python|anaconda"
    )
    if [ -n "$sudo_home" ]; then
        candidates+=(
            "$sudo_home/miniconda3/bin/python|miniconda"
            "$sudo_home/anaconda3/bin/python|anaconda"
            "$sudo_home/conda/bin/python|conda"
        )
    fi
    local item path dist
    for item in "${candidates[@]}"; do
        path="${item%%|*}"
        dist="${item##*|}"
        if [ -x "$path" ]; then
            echo "$path|$dist"
            return 0
        fi
    done
    return 1
}

detect_runtime_from_python() {
    local pybin="$1"
    if [ -z "$pybin" ] || [ ! -x "$pybin" ]; then
        return 1
    fi
    local pyver
    local pyprefix
    pyver="$("$pybin" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)"
    pyprefix="$("$pybin" -c 'import sys; print(sys.prefix)' 2>/dev/null || true)"
    local pyruntime="system"
    local pyenvname=""
    if [[ "$pyprefix" == *"/conda"* || "$pyprefix" == *"/miniconda"* || "$pyprefix" == *"/anaconda"* ]]; then
        pyruntime="conda"
        pyenvname="$(basename "$pyprefix")"
    fi
    echo "${pyruntime}|${pyenvname}|${pyver}|${pyprefix}"
}

service_python_bin() {
    local service_name="$1"
    local service_file="/etc/systemd/system/${service_name}.service"
    if [ -f "$service_file" ]; then
        local execstart
        execstart="$(sed -n 's/^ExecStart=//p' "$service_file" | head -1)"
        if [ -n "$execstart" ]; then
            local pybin
            pybin="$(echo "$execstart" | awk '{print $1}')"
            if [ -x "$pybin" ]; then
                echo "$pybin"
                return 0
            fi
        fi
    fi
    if command -v python3 &>/dev/null; then
        command -v python3
        return 0
    fi
    return 1
}

select_python_bin() {
    local service_name="$1"
    local pybin=""
    pybin="$(service_python_bin "$service_name" || true)"
    if [ -n "$pybin" ] && [ -x "$pybin" ]; then
        echo "$pybin"
        return 0
    fi

    local conda_meta
    conda_meta="$(find_preferred_conda_base_python || true)"
    if [ -n "$conda_meta" ]; then
        echo "${conda_meta%%|*}"
        return 0
    fi

    if command -v python3 &>/dev/null; then
        command -v python3
        return 0
    fi
    return 1
}

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

if ! command -v python3 &>/dev/null; then
    error "Python3 is not installed. Please install Python 3.8+ first.\nPython3 未安装，请先安装 Python 3.8+"
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

    SERVER_PYTHON_BIN="$(select_python_bin server-monitor || true)"
    if [ -z "$SERVER_PYTHON_BIN" ]; then
        error "Cannot find Python interpreter for server upgrade / 无法确定主服务升级使用的 Python 解释器"
    fi
    SERVER_RUNTIME_META="$(detect_runtime_from_python "$SERVER_PYTHON_BIN" || true)"
    SERVER_RUNTIME="${SERVER_RUNTIME_META%%|*}"
    SERVER_REST="${SERVER_RUNTIME_META#*|}"
    SERVER_ENV_NAME="${SERVER_REST%%|*}"
    SERVER_REST="${SERVER_REST#*|}"
    SERVER_PY_VERSION="${SERVER_REST%%|*}"
    if [ "$SERVER_RUNTIME" = "conda" ]; then
        info "Server Python: conda (${SERVER_ENV_NAME:-unknown}) ${SERVER_PY_VERSION:-unknown} (${SERVER_PYTHON_BIN})"
    else
        info "Server Python: system ${SERVER_PY_VERSION:-unknown} (${SERVER_PYTHON_BIN})"
    fi

    download_file "$REPO_URL/app.py"                   "$INSTALL_DIR/app.py"
    download_file "$REPO_URL/requirements.txt"         "$INSTALL_DIR/requirements.txt"
    download_file "$REPO_URL/templates/login.html"     "$INSTALL_DIR/templates/login.html"
    download_file "$REPO_URL/templates/dashboard.html" "$INSTALL_DIR/templates/dashboard.html"
    download_file "$REPO_URL/templates/admin.html"     "$INSTALL_DIR/templates/admin.html"
    download_file "$REPO_URL/templates/register.html"  "$INSTALL_DIR/templates/register.html"
    download_file "$REPO_URL/templates/user.html"      "$INSTALL_DIR/templates/user.html"

    info "Installing/updating Python dependencies / 安装/更新依赖..."
    "$SERVER_PYTHON_BIN" -m pip install -q flask pyyaml

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

    AGENT_PYTHON_BIN="$(select_python_bin server-monitor-agent || true)"
    if [ -z "$AGENT_PYTHON_BIN" ]; then
        error "Cannot find Python interpreter for agent upgrade / 无法确定 Agent 升级使用的 Python 解释器"
    fi
    AGENT_RUNTIME_META="$(detect_runtime_from_python "$AGENT_PYTHON_BIN" || true)"
    AGENT_RUNTIME="${AGENT_RUNTIME_META%%|*}"
    AGENT_REST="${AGENT_RUNTIME_META#*|}"
    AGENT_ENV_NAME="${AGENT_REST%%|*}"
    AGENT_REST="${AGENT_REST#*|}"
    AGENT_PY_VERSION="${AGENT_REST%%|*}"
    if [ "$AGENT_RUNTIME" = "conda" ]; then
        info "Agent Python: conda (${AGENT_ENV_NAME:-unknown}) ${AGENT_PY_VERSION:-unknown} (${AGENT_PYTHON_BIN})"
    else
        info "Agent Python: system ${AGENT_PY_VERSION:-unknown} (${AGENT_PYTHON_BIN})"
    fi

    download_file "$REPO_URL/agent.py" "$INSTALL_DIR/agent.py"

    info "Installing/updating Python dependencies / 安装/更新依赖..."
    "$AGENT_PYTHON_BIN" -m pip install -q psutil requests pyyaml

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
